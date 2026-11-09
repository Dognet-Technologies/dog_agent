use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

mod collectors;
mod compression;
mod config;
mod error;
mod firewall;
mod protocol;
mod reconnect;
mod targets;
mod threat;
mod ws;

use config::Config;
use targets::spawn_target;

#[derive(Parser, Debug)]
#[command(
    name = "dog-agent",
    about = "Dognet Unified Agent — FireDog | CyberShepherd | SentinelCore",
    version
)]
struct Args {
    /// Percorso del file di configurazione
    #[arg(short, long, default_value = "/etc/dog-agent/agent.conf")]
    config: PathBuf,

    /// Override del livello di log (debug, info, warn, error)
    #[arg(short, long)]
    log_level: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Carica la config prima di inizializzare il logging
    let config = Config::load(&args.config)?;

    // Inizializza logging
    let log_level = args
        .log_level
        .as_deref()
        .unwrap_or(&config.agent.log_level)
        .to_string();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_new(format!("dog_agent={log_level}"))
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    info!(
        "Dog Agent v{} avviato — {} target configurati",
        env!("CARGO_PKG_VERSION"),
        config.targets.len()
    );

    if config.targets.is_empty() {
        error!("Nessun [[targets]] configurato in {:?}, uscita", args.config);
        std::process::exit(1);
    }

    // Inizializza la verifica TLS (Root CA Dognet se configurata, altrimenti
    // verifier permissivo con warning). Una volta, prima di aprire connessioni.
    ws::init_tls(config.agent.ca_cert.as_deref());

    // L'api_key è in chiaro nel file di config: avvisa se è leggibile da altri.
    warn_if_config_insecure(&args.config);

    // Avvia un task tokio per ogni target
    let mut handles = Vec::new();
    for mut target in config.targets {
        target.config_path = args.config.clone();
        let name = target.name.clone();
        info!(
            "[{}] ambiente configurato: {}",
            name, target.environment
        );
        if target.ws_url().starts_with("ws://") {
            warn!(
                "[{}] endpoint in chiaro (ws://): l'api_key e i dati viaggiano non cifrati. Usa wss://.",
                name
            );
        }
        let handle = tokio::spawn(async move {
            spawn_target(target).await;
        });
        handles.push((name, handle));
    }

    // Attendi segnale di shutdown
    shutdown_signal().await;
    info!("Segnale di shutdown ricevuto, arresto in corso...");

    for (name, handle) in handles {
        handle.abort();
        info!("[{}] Task terminato", name);
    }

    info!("Dog Agent fermato.");
    Ok(())
}

/// Attende Ctrl-C (tutti i SO) oppure SIGTERM (Unix)
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Impossibile installare handler Ctrl-C");
    };

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        )
        .expect("Impossibile installare handler SIGTERM");

        tokio::select! {
            _ = ctrl_c => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await;
    }
}

/// Avvisa se il file di config — che contiene l'api_key in chiaro — è
/// accessibile a gruppo o altri utenti. Consigliato 0600.
#[cfg(unix)]
fn warn_if_config_insecure(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            warn!(
                "Il file di config {} ha permessi {:o} e contiene l'api_key in chiaro: \
                 restringilo a 0600 (chmod 600 {}).",
                path.display(),
                mode,
                path.display()
            );
        }
    }
}

#[cfg(not(unix))]
fn warn_if_config_insecure(_path: &std::path::Path) {}
