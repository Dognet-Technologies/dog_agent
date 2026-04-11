/// Implementazione protocollo CyberSheppard.
///
/// Lifecycle:
///   connect → auth → [collect metrics → buffer → flush compresso ogni send_interval]
///   Se la connessione cade: riconnessione con backoff esponenziale.

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use tokio::time::interval;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{debug, error, info, warn};

use crate::collectors::{self, AllMetrics};
use crate::compression::compress_json;
use crate::config::TargetConfig;
use crate::protocol::cybersheppard::*;

pub async fn run(config: TargetConfig) -> Result<()> {
    let mut backoff = Duration::from_secs(config.reconnect.initial_backoff);

    loop {
        info!("[{}] Connessione a {}", config.name, config.ws_url());

        match session(&config).await {
            Ok(()) => {
                info!("[{}] Sessione chiusa, riconnessione...", config.name);
                backoff = Duration::from_secs(config.reconnect.initial_backoff);
            }
            Err(e) => {
                error!("[{}] Errore sessione: {}", config.name, e);
                warn!("[{}] Retry tra {:?}", config.name, backoff);
                tokio::time::sleep(backoff).await;
                backoff = next_backoff(backoff, &config);
            }
        }
    }
}

async fn session(config: &TargetConfig) -> Result<()> {
    let (ws, _) = connect_async(config.ws_url()).await?;
    let (mut tx, mut rx) = ws.split();

    let target_id = config.target_id.unwrap_or(0);
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    // ── Autenticazione ────────────────────────────────────────────────────────
    let auth = AgentMessage::Auth {
        target_id,
        timestamp: chrono::Utc::now().timestamp(),
        payload: AuthPayload {
            auth_token: config.api_key.clone(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            hostname: hostname.clone(),
        },
    };
    tx.send(Message::Text(serde_json::to_string(&auth)?)).await?;

    // Attendi AuthAck
    wait_auth_ack(&mut rx, &config.name).await?;
    info!("[{}] Autenticazione completata", config.name);

    // ── Setup timer ───────────────────────────────────────────────────────────
    let mut collect_timer = interval(Duration::from_secs(config.collection_interval));
    collect_timer.tick().await;

    let mut send_timer = interval(Duration::from_secs(config.send_interval));
    send_timer.tick().await;

    let mut buffer: Vec<AllMetrics> = Vec::new();

    // ── Main loop ─────────────────────────────────────────────────────────────
    loop {
        tokio::select! {
            _ = collect_timer.tick() => {
                match collectors::collect_all(config).await {
                    Ok(metrics) => {
                        buffer.push(metrics);
                        debug!("[{}] Metriche raccolte (buffer: {})", config.name, buffer.len());

                        // Flush forzato se buffer pieno
                        if buffer.len() >= config.max_buffer_size {
                            warn!("[{}] Buffer pieno, flush immediato", config.name);
                            flush_buffer(config, &mut tx, &mut buffer, target_id).await?;
                        }
                    }
                    Err(e) => {
                        error!("[{}] Errore raccolta metriche: {}", config.name, e);
                    }
                }
            }

            _ = send_timer.tick() => {
                if !buffer.is_empty() {
                    flush_buffer(config, &mut tx, &mut buffer, target_id).await?;
                }
            }

            msg = rx.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        handle_server_message(config, &mut tx, &text, target_id).await?;
                    }
                    Some(Ok(Message::Ping(data))) => {
                        tx.send(Message::Pong(data)).await?;
                    }
                    Some(Ok(Message::Close(_))) => {
                        info!("[{}] Server ha chiuso la connessione", config.name);
                        return Ok(());
                    }
                    Some(Err(e)) => return Err(e.into()),
                    None => return Ok(()),
                    _ => {}
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────

async fn wait_auth_ack<S>(rx: &mut S, name: &str) -> Result<()>
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let timeout = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match rx.next().await {
                Some(Ok(Message::Text(text))) => {
                    match serde_json::from_str::<ServerMessage>(&text) {
                        Ok(ServerMessage::AuthAck { success, message }) => {
                            if success {
                                return Ok(());
                            } else {
                                anyhow::bail!(
                                    "Autenticazione rifiutata: {}",
                                    message.unwrap_or_default()
                                );
                            }
                        }
                        Ok(_) => {}
                        Err(e) => warn!("[{}] Messaggio non parsato durante auth: {}", name, e),
                    }
                }
                Some(Ok(Message::Close(_))) => anyhow::bail!("Connessione chiusa durante auth"),
                Some(Err(e)) => return Err(e.into()),
                None => anyhow::bail!("Stream terminato durante auth"),
                _ => {}
            }
        }
    });

    timeout
        .await
        .map_err(|_| anyhow::anyhow!("Timeout autenticazione (30s)"))?
}

async fn flush_buffer<S>(
    config: &TargetConfig,
    tx: &mut S,
    buffer: &mut Vec<AllMetrics>,
    target_id: i32,
) -> Result<()>
where
    S: SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let compressed = compress_json(&*buffer, config.compression_level)?;

    info!(
        "[{}] Invio {} metriche — {} → {} byte ({:.1}% compressione)",
        config.name,
        buffer.len(),
        compressed.original_size,
        compressed.compressed_size,
        compressed.compression_ratio
    );

    let msg = AgentMessage::Metrics {
        target_id,
        timestamp: chrono::Utc::now().timestamp(),
        payload: compressed,
    };

    tx.send(Message::Text(serde_json::to_string(&msg)?)).await?;
    buffer.clear();
    Ok(())
}

async fn handle_server_message<S>(
    config: &TargetConfig,
    tx: &mut S,
    text: &str,
    target_id: i32,
) -> Result<()>
where
    S: SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let msg: ServerMessage = match serde_json::from_str(text) {
        Ok(m) => m,
        Err(e) => {
            warn!("[{}] Messaggio server non riconosciuto: {}", config.name, e);
            return Ok(());
        }
    };

    match msg {
        ServerMessage::MetricsAck => {
            debug!("[{}] metrics_ack ricevuto", config.name);
        }
        ServerMessage::Command { payload, .. } => {
            info!("[{}] Comando ricevuto: {}", config.name, payload.action);

            // CyberSheppard non gestisce firewall, i comandi riguardano
            // la configurazione dei collector o operazioni di sistema.
            let (success, output, error) = execute_command(&payload).await;

            let resp = AgentMessage::CommandResponse {
                target_id,
                timestamp: chrono::Utc::now().timestamp(),
                payload: CommandResponsePayload {
                    command_id: payload.command_id,
                    success,
                    output,
                    error,
                },
            };
            tx.send(Message::Text(serde_json::to_string(&resp)?)).await?;
        }
        ServerMessage::AuthAck { .. } => {
            // già gestito in wait_auth_ack
        }
    }

    Ok(())
}

async fn execute_command(cmd: &CommandPayload) -> (bool, Option<String>, Option<String>) {
    match cmd.action.as_str() {
        "ping" => (true, Some("pong".to_string()), None),
        "get_version" => (
            true,
            Some(env!("CARGO_PKG_VERSION").to_string()),
            None,
        ),
        other => {
            warn!("Comando CyberSheppard non supportato: {}", other);
            (false, None, Some(format!("Azione non supportata: {}", other)))
        }
    }
}

fn next_backoff(current: Duration, config: &TargetConfig) -> Duration {
    let next_secs = (current.as_secs() as f64 * config.reconnect.backoff_multiplier) as u64;
    Duration::from_secs(next_secs.min(config.reconnect.max_backoff))
}
