/// Connessione WebSocket condivisa da tutti i target (firedog, cybershepherd,
/// sentinelcore). La verifica TLS per `wss://` dipende da `agent.ca_cert`:
/// - **con CA configurata** (Root CA Dognet): il certificato del server è
///   verificato contro quella CA — un MITM che presenti un certificato non
///   firmato dalla CA viene rifiutato. È la modalità consigliata.
/// - **senza CA** (legacy): accetta qualunque certificato (self-signed),
///   proteggendo solo da chi origlia passivamente, non da un attacker attivo.
///   All'avvio `init_tls` logga un warning. Prima di tutto questo il traffico
///   agent — api_key, heartbeat, threat log — viaggiava in chiaro su `ws://`.
use anyhow::Result;
use std::path::Path;
use std::sync::{Arc, OnceLock};
use tokio::net::TcpStream;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};
use tracing::{error, info, warn};

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

/// Inizializza la config TLS una volta all'avvio. Con `ca_cert` presente usa la
/// verifica stretta contro la CA; altrimenti il verifier permissivo, avvisando
/// che i `wss://` self-signed restano vulnerabili a un MITM attivo.
pub fn init_tls(ca_cert: Option<&Path>) {
    let config = match ca_cert {
        Some(path) => match secure_config(path) {
            Ok(c) => {
                info!("TLS: i certificati server sono verificati contro la CA {}", path.display());
                c
            }
            Err(e) => {
                error!(
                    "TLS: CA {} non caricabile ({e}); fallback a verifier permissivo (MITM possibile)",
                    path.display()
                );
                insecure_config()
            }
        },
        None => {
            warn!(
                "TLS: nessun agent.ca_cert configurato — i certificati self-signed sono accettati \
                 senza verifica (MITM possibile su wss://). Configura agent.ca_cert per la verifica."
            );
            insecure_config()
        }
    };
    let _ = TLS_CONFIG.set(config);
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    // Se init_tls non è stato chiamato (es. nei test), default permissivo.
    TLS_CONFIG.get_or_init(insecure_config).clone()
}

/// Come `tokio_tungstenite::connect_async`, ma per `wss://` usa il verifier
/// permissivo sopra invece delle CA pubbliche (che rifiuterebbero sempre un
/// cert self-signed). Per `ws://` è invariato.
pub async fn connect(url: &str) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>> {
    if url.starts_with("wss://") {
        let (ws, _) = tokio_tungstenite::connect_async_tls_with_config(
            url,
            None,
            false,
            Some(Connector::Rustls(tls_config())),
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
    use super::secure_config;
    use std::path::Path;

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
