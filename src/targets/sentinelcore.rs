/// SentinelCore — stub predisposto per implementazione futura.
///
/// Per ora: si connette, logga che il sistema non è ancora implementato
/// e rimane in idle loop attendendo comandi (nessuno per ora).
/// Quando le specifiche API SentinelCore saranno disponibili,
/// basterà implementare questo modulo senza toccare il resto del codice.

use anyhow::Result;
use std::time::Duration;
use tracing::{info, warn};

use crate::config::TargetConfig;

pub async fn run(config: TargetConfig) -> Result<()> {
    warn!(
        "[{}] SentinelCore non è ancora implementato. \
        Il target è predisposto ma inattivo.",
        config.name
    );

    // Loop idle: si sveglierà ogni 60s per loggare lo stato.
    // Quando SentinelCore sarà implementato, questo loop verrà sostituito
    // con la stessa struttura connect → auth → main loop degli altri target.
    loop {
        info!(
            "[{}] SentinelCore in attesa di implementazione (url: {})",
            config.name,
            config.ws_url()
        );
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}
