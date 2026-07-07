mod cybersheppard;
mod firedog;
mod sentinelcore;

use crate::config::{SystemType, TargetConfig};
use tracing::{error, info};

/// Entry point per ogni target: seleziona il modulo corretto in base a `system_type`
/// e lo esegue in loop con reconnessione automatica.
pub async fn spawn_target(target: TargetConfig) {
    info!(
        "[{}] Task avviato — sistema: {}",
        target.name, target.system_type
    );

    let result = match target.system_type {
        SystemType::Firedog => firedog::run(target).await,
        SystemType::Cybersheppard => cybersheppard::run(target).await,
        SystemType::Sentinelcore => sentinelcore::run(target).await,
    };

    if let Err(e) = result {
        error!("Task terminato con errore: {}", e);
    }
}
