use thiserror::Error;

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum AgentError {
    #[error("Errore WebSocket: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),

    #[error("Errore di serializzazione: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Pairing fallito: {0}")]
    PairingFailed(String),

    #[error("Autenticazione fallita: {0}")]
    AuthFailed(String),

    #[error("Connessione chiusa dal server")]
    ConnectionClosed,

    #[error("Timeout nella risposta del server")]
    Timeout,

    #[error("Errore firewall: {0}")]
    Firewall(String),

    #[error("Errore collector: {0}")]
    Collector(String),

    #[error("Errore I/O: {0}")]
    Io(#[from] std::io::Error),

    #[error("Errore generico: {0}")]
    Other(#[from] anyhow::Error),
}
