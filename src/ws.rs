/// Connessione WebSocket condivisa da tutti i target (firedog, cybershepherd,
/// sentinelcore). La verifica TLS per `wss://` dipende da `agent.ca_cert`:
/// - **con CA configurata** (Root CA Dognet): il certificato del server è
///   verificato contro quella CA — un MITM che presenti un certificato non
///   firmato dalla CA viene rifiutato. È la modalità consigliata.
/// - **senza CA**: `Config::validate` (src/config.rs) impedisce all'agent di
///   avviarsi su un target `wss://`, A MENO che `agent.allow_insecure_tls` non
///   sia impostato esplicitamente a `true` — in quel caso si ricade sul
///   verifier permissivo sotto, che accetta qualunque certificato
///   self-signed e protegge solo da chi origlia passivamente, non da un
///   attacker attivo. Non è più un default silenzioso: è un opt-in
///   deliberato e documentato in config.example.toml.
use anyhow::Result;
use std::path::Path;
use std::sync::{Arc, OnceLock};
use tokio::net::TcpStream;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};
use tracing::{info, warn};

/// Configurazione TLS condivisa, impostata una volta all'avvio da `init_tls`.
static TLS_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();

#[derive(Debug)]
struct NoCertVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        // ring provider di default di rustls 0.22: elenco schemi supportati
        // dal provider stesso, la firma non viene comunque mai controllata
        // per davvero (vedi verify_tls1{2,3}_signature sopra).
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Config permissiva (verifier che accetta qualunque cert) — comportamento
/// legacy per master self-signed senza CA configurata.
fn insecure_config() -> Arc<rustls::ClientConfig> {
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerification))
        .with_no_client_auth();
    Arc::new(config)
}

/// Config con verifica stretta del certificato server contro la Root CA Dognet
/// (PEM). Un MITM che presenti un certificato non firmato dalla CA viene
/// rifiutato dall'handshake TLS.
fn secure_config(ca_path: &Path) -> Result<Arc<rustls::ClientConfig>> {
    let pem = std::fs::read(ca_path)
        .map_err(|e| anyhow::anyhow!("lettura CA {}: {e}", ca_path.display()))?;
    let mut roots = rustls::RootCertStore::empty();
    let mut added = 0usize;
    for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
        roots.add(cert?)?;
        added += 1;
    }
    if added == 0 {
        anyhow::bail!("nessun certificato nel file CA {}", ca_path.display());
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Sceglie la config TLS. Con `ca_cert` configurata usa SOLO la verifica
/// stretta: se la CA non si carica (file mancante, PEM invalido) è un errore,
/// non un ripiego sul verifier permissivo — prima un errore di provisioning
/// della CA spegneva in silenzio la verifica (HIGH, seconda review 2026-11).
/// Senza `ca_cert` il verifier permissivo è ammesso solo con l'opt-in
/// esplicito `allow_insecure_tls`.
fn select_config(
    ca_cert: Option<&Path>,
    allow_insecure_tls: bool,
) -> Result<Arc<rustls::ClientConfig>> {
    match ca_cert {
        Some(path) => {
            let c = secure_config(path).map_err(|e| {
                anyhow::anyhow!(
                    "TLS: CA {} non caricabile ({e}); l'agent non si connette a target wss:// \
                     senza poter verificare il certificato del server",
                    path.display()
                )
            })?;
            info!("TLS: i certificati server sono verificati contro la CA {}", path.display());
            Ok(c)
        }
        None if allow_insecure_tls => {
            warn!(
                "TLS: agent.allow_insecure_tls è attivo — i certificati self-signed sono \
                 accettati senza verifica (MITM possibile su wss://). Configura agent.ca_cert \
                 per la verifica stretta."
            );
            Ok(insecure_config())
        }
        None => anyhow::bail!(
            "TLS: né agent.ca_cert né agent.allow_insecure_tls configurati per un target wss://"
        ),
    }
}

/// Inizializza la config TLS una volta all'avvio. Va chiamata solo se c'è
/// almeno un target `wss://`; in caso di errore il chiamante deve uscire.
pub fn init_tls(ca_cert: Option<&Path>, allow_insecure_tls: bool) -> Result<()> {
    let config = select_config(ca_cert, allow_insecure_tls)?;
    let _ = TLS_CONFIG.set(config);
    Ok(())
}

fn tls_config() -> Result<Arc<rustls::ClientConfig>> {
    // Nessun default: senza init_tls riuscito non si apre alcun wss://.
    TLS_CONFIG
        .get()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("TLS non inizializzato: connessione wss:// rifiutata"))
}

/// Come `tokio_tungstenite::connect_async`, ma per `wss://` usa la config
/// scelta da `init_tls` (CA Dognet, o verifier permissivo se c'è l'opt-in)
/// invece delle CA pubbliche. Per `ws://` è invariato.
pub async fn connect(url: &str) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>> {
    if url.starts_with("wss://") {
        let (ws, _) = tokio_tungstenite::connect_async_tls_with_config(
            url,
            None,
            false,
            Some(Connector::Rustls(tls_config()?)),
        )
        .await?;
        Ok(ws)
    } else {
        let (ws, _) = tokio_tungstenite::connect_async(url).await?;
        Ok(ws)
    }
}

#[cfg(test)]
mod tests {
    use super::{secure_config, select_config};
    use std::path::Path;

    #[test]
    fn ca_configurata_ma_non_caricabile_e_un_errore_anche_con_opt_in() {
        // Regressione (seconda review, 2026-11): una CA configurata ma
        // illeggibile ricadeva sul verifier permissivo (MITM possibile).
        let missing = Path::new("/non/esiste/dognet-ca.pem");
        assert!(select_config(Some(missing), false).is_err());
        assert!(select_config(Some(missing), true).is_err());
    }

    #[test]
    fn senza_ca_serve_l_opt_in() {
        assert!(select_config(None, false).is_err());
        assert!(select_config(None, true).is_ok());
    }

    #[test]
    fn secure_config_rifiuta_file_inesistente() {
        assert!(secure_config(Path::new("/non/esiste/dognet-ca.pem")).is_err());
    }

    #[test]
    fn secure_config_rifiuta_pem_senza_certificati() {
        let mut f = std::env::temp_dir();
        f.push(format!("dog-agent-test-ca-{}.pem", std::process::id()));
        std::fs::write(&f, b"-----BEGIN NON CERT-----\nxxx\n-----END NON CERT-----\n").unwrap();
        let r = secure_config(&f);
        let _ = std::fs::remove_file(&f);
        assert!(r.is_err(), "un PEM senza certificati deve essere rifiutato");
    }
}
