/// Connessione WebSocket condivisa da tutti i target (firedog, cybersheppard,
/// sentinelcore). Per `wss://` accetta certificati self-signed: il master
/// della suite genera un certificato self-signed di default (uso LAN, vedi
/// deploy/install.sh su FireDog/SentinelCore) — stessa fiducia già accettata
/// lato browser quando si clicca "continua, non sicuro" sullo stesso
/// certificato. Protegge da chi origlia passivamente sulla rete (prima di
/// questo, il traffico agent — api_key, heartbeat, threat log — viaggiava in
/// chiaro su ws://:80); non protegge da un attacker attivo in grado di
/// presentare un proprio certificato (richiederebbe pinning, non implementato
/// — vedi commento in TargetConfig::ws_url).
use anyhow::Result;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};

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

fn insecure_connector() -> Connector {
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerification))
        .with_no_client_auth();
    Connector::Rustls(Arc::new(config))
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
            Some(insecure_connector()),
        )
        .await?;
        Ok(ws)
    } else {
        let (ws, _) = tokio_tungstenite::connect_async(url).await?;
        Ok(ws)
    }
}
