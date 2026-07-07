use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

mod collectors;
mod compression;
mod config;
mod error;
mod firewall;
mod protocol;
mod targets;
mod threat;

use config::Config;
use targets::spawn_target;

#[derive(Parser, Debug)]
#[command(
    name = "dog-agent",
    about = "Dognet Unified Agent — FireDog | CyberSheppard | SentinelCore",
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
            EnvFilter::try_new(format!("dog_agent={}", log_level))
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

    // Avvia un task tokio per ogni target
    let mut handles = Vec::new();
    for target in config.targets {
        let name = target.name.clone();
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
