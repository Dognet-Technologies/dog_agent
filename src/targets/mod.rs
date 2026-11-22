mod cybershepherd;
mod laurel_cursor;
mod firedog;
pub(crate) mod hardening;
mod security_audit;
mod sentinelcore;

use crate::config::{SystemType, TargetConfig};
use std::time::Duration;
use tracing::{error, info};

/// Ritardo prima di respawnare un target dopo un panic — vedi `spawn_target`.
const PANIC_RESTART_DELAY: Duration = Duration::from_secs(5);

/// Entry point per ogni target: seleziona il modulo corretto in base a
/// `system_type` e lo esegue con reconnessione automatica (vedi
/// `firedog::run`/`cybershepherd::run`/`sentinelcore::run`, ognuno un loop
/// infinito per design — l'unico modo in cui finiscono è un panic). Questa
/// funzione SUPERVISIONA quel loop in un task tokio separato: se panica, lo
/// logga rumorosamente e lo RIAVVIA invece di lasciare il target morto per
/// sempre in silenzio (HIGH trovato in code review, 2026-11 — prima di
/// questo fix un panic in un unwrap/indexing qualsiasi lungo la call chain
/// del target uccideva monitoraggio/firewall per quel target senza alcun
/// log tracing, visibile solo come il panic message grezzo su stderr, e gli
/// altri target rimasti vivi mascheravano il problema).
pub async fn spawn_target(target: TargetConfig) {
    loop {
        let name = target.name.clone();
        let t = target.clone();
        let handle = tokio::spawn(async move { run_once(t).await });

        match handle.await {
            Ok(()) => {
                // run_once non ritorna mai in condizioni normali (i loop dei
                // singoli protocolli sono infiniti): se succede non è un
                // panic, ma resta un'uscita anomala che va comunque riavviata.
                error!(
                    "[{}] Task terminato senza panic ma inaspettatamente, riavvio tra {:?}",
                    name, PANIC_RESTART_DELAY
                );
            }
            Err(join_err) => {
                error!(
                    "[{}] Task PANICATO ({}), riavvio tra {:?}",
                    name, join_err, PANIC_RESTART_DELAY
                );
            }
        }
        tokio::time::sleep(PANIC_RESTART_DELAY).await;
    }
}

async fn run_once(target: TargetConfig) {
    info!(
        "[{}] Task avviato — sistema: {}",
        target.name, target.system_type
    );

    let result = match target.system_type {
        SystemType::Firedog => firedog::run(target).await,
        SystemType::Cybershepherd => cybershepherd::run(target).await,
        SystemType::Sentinelcore => sentinelcore::run(target).await,
    };

    if let Err(e) = result {
        error!("Task terminato con errore: {}", e);
    }
}
