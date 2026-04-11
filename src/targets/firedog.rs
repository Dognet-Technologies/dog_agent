/// Implementazione protocollo FireDog.
///
/// Lifecycle:
///   connect → pair → [heartbeat loop + command handling + threat reporting]
///   Se la connessione cade: riconnessione con backoff esponenziale.

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use tokio::time::interval;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{debug, error, info, warn};

use crate::collectors::system;
use crate::config::TargetConfig;
use crate::firewall::FirewallManager;
use crate::protocol::firedog::*;
use crate::threat::ThreatDetector;

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

    // ── Fase 1 & 2: pairing ──────────────────────────────────────────────────
    let pair_msg = AgentMessage::PairRequest {
        api_key: config.api_key.clone(),
        ip: config.ip.clone().unwrap_or_default(),
        hostname: config.hostname.clone().unwrap_or_default(),
        mac: config.mac.clone().unwrap_or_default(),
    };
    tx.send(Message::Text(serde_json::to_string(&pair_msg)?))
        .await?;
    info!("[{}] pair_request inviato", config.name);

    // Attendi pairing_status con successo completo (fase 1 + fase 2)
    wait_pairing(&mut rx, &config.name).await?;
    info!("[{}] Pairing completato", config.name);

    // ── Setup ─────────────────────────────────────────────────────────────────
    let fw = FirewallManager::new();
    let mut threat_detector = ThreatDetector::new(config.threat_threshold, config.auto_block_threats);

    let mut hb_timer = interval(Duration::from_secs(config.heartbeat_interval));
    hb_timer.tick().await; // salta il tick immediato

    let mut threat_timer = interval(Duration::from_secs(60));
    threat_timer.tick().await;

    // ── Main loop ─────────────────────────────────────────────────────────────
    loop {
        tokio::select! {
            _ = hb_timer.tick() => {
                send_heartbeat(config, &mut tx, &fw).await?;
            }

            _ = threat_timer.tick() => {
                let threats = threat_detector.scan().await;
                if !threats.is_empty() {
                    let msg = AgentMessage::ThreatLog { threats };
                    tx.send(Message::Text(serde_json::to_string(&msg)?)).await?;
                    debug!("[{}] threat_log inviato", config.name);
                }
            }

            msg = rx.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        handle_server_message(config, &mut tx, &fw, &text).await?;
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

async fn wait_pairing<S>(rx: &mut S, name: &str) -> Result<()>
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    // Il pairing può richiedere due messaggi separati (fase 1, poi fase 2)
    // oppure uno solo con entrambe le fasi verificate.
    let mut phase1 = false;

    let timeout = tokio::time::timeout(Duration::from_secs(180), async {
        loop {
            match rx.next().await {
                Some(Ok(Message::Text(text))) => {
                    match serde_json::from_str::<ServerMessage>(&text) {
                        Ok(ServerMessage::PairingStatus { status, phase_1_verified, phase_2_verified, message, .. }) => {
                            if phase_1_verified {
                                phase1 = true;
                                info!("[{}] Fase 1 verificata (API key OK)", name);
                            }
                            if phase_2_verified && phase1 {
                                info!("[{}] Fase 2 verificata (identity hash OK)", name);
                                return Ok(());
                            }
                            if status == "failed" || status == "expired" {
                                anyhow::bail!(
                                    "Pairing fallito: {}",
                                    message.unwrap_or(status)
                                );
                            }
                        }
                        Ok(_) => {}
                        Err(e) => warn!("[{}] Messaggio non parsato durante pairing: {}", name, e),
                    }
                }
                Some(Ok(Message::Close(_))) => anyhow::bail!("Connessione chiusa durante pairing"),
                Some(Err(e)) => return Err(e.into()),
                None => anyhow::bail!("Stream terminato durante pairing"),
                _ => {}
            }
        }
    });

    timeout
        .await
        .map_err(|_| anyhow::anyhow!("Timeout pairing (180s)"))?
}

async fn send_heartbeat<S>(
    config: &TargetConfig,
    tx: &mut S,
    fw: &FirewallManager,
) -> Result<()>
where
    S: SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let sys = system::collect().await?;
    let rules = fw.active_rules_count();
    let blocked = fw.blocked_ips_count();

    let msg = AgentMessage::Heartbeat {
        timestamp: chrono::Utc::now().to_rfc3339(),
        system_stats: SystemStats {
            cpu_percent: sys.cpu_percent,
            memory_percent: sys.memory_percent,
            disk_percent: sys.disk_percent,
            bytes_sent: sys.bytes_sent,
            bytes_recv: sys.bytes_recv,
            active_rules_count: rules,
            blocked_ips_count: blocked,
            load_avg: sys.load_avg,
            uptime_seconds: sys.uptime_seconds,
        },
    };

    tx.send(Message::Text(serde_json::to_string(&msg)?)).await?;
    debug!("[{}] heartbeat inviato", config.name);
    Ok(())
}

async fn handle_server_message<S>(
    config: &TargetConfig,
    tx: &mut S,
    fw: &FirewallManager,
    text: &str,
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
        ServerMessage::HeartbeatAck => {
            debug!("[{}] heartbeat_ack ricevuto", config.name);
        }
        ServerMessage::ThreatAck => {
            debug!("[{}] threat_ack ricevuto", config.name);
        }
        ServerMessage::Command { command_id, action, payload } => {
            info!("[{}] Comando ricevuto: {:?}", config.name, action);
            let (status, output, error) =
                execute_command(config, fw, &command_id, action, payload).await;

            let resp = AgentMessage::CommandResponse {
                command_id,
                status,
                output,
                error,
            };
            tx.send(Message::Text(serde_json::to_string(&resp)?)).await?;
        }
        ServerMessage::Config { config: new_cfg } => {
            info!("[{}] Aggiornamento configurazione ricevuto: {:?}", config.name, new_cfg);
            // TODO: aggiornare config a runtime in versione futura
        }
        ServerMessage::PairingStatus { .. } => {
            // già gestito in wait_pairing, ignora duplicati
        }
    }

    Ok(())
}

async fn execute_command(
    config: &TargetConfig,
    fw: &FirewallManager,
    command_id: &str,
    action: CommandAction,
    payload: serde_json::Value,
) -> (CommandStatus, Option<String>, Option<String>) {
    let result = match action {
        CommandAction::AddRule => {
            match serde_json::from_value::<AddRulePayload>(payload) {
                Ok(p) => fw.add_rule(&p),
                Err(e) => Err(anyhow::anyhow!("Payload non valido: {}", e)),
            }
        }
        CommandAction::RemoveRule => {
            match serde_json::from_value::<RemoveRulePayload>(payload) {
                Ok(p) => fw.remove_rule(&p),
                Err(e) => Err(anyhow::anyhow!("Payload non valido: {}", e)),
            }
        }
        CommandAction::BlockIp => {
            match serde_json::from_value::<BlockIpPayload>(payload) {
                Ok(p) => fw.block_ip(&p.ip, &p.direction),
                Err(e) => Err(anyhow::anyhow!("Payload non valido: {}", e)),
            }
        }
        CommandAction::UnblockIp => {
            match serde_json::from_value::<BlockIpPayload>(payload) {
                Ok(p) => fw.unblock_ip(&p.ip, &p.direction),
                Err(e) => Err(anyhow::anyhow!("Payload non valido: {}", e)),
            }
        }
        CommandAction::SyncRules => {
            fw.sync_rules()
        }
        CommandAction::CheckIntegrity => {
            let paths = match serde_json::from_value::<CheckIntegrityPayload>(payload) {
                Ok(p) => p.paths.unwrap_or_else(|| config.integrity_paths.clone()),
                Err(_) => config.integrity_paths.clone(),
            };
            run_integrity_check(&paths).await
        }
        CommandAction::UpdateConfig => {
            // TODO: implementare aggiornamento config a runtime
            Ok("Config update scheduled".to_string())
        }
        CommandAction::Unknown => {
            Err(anyhow::anyhow!("Azione non riconosciuta"))
        }
    };

    match result {
        Ok(out) => (CommandStatus::Success, Some(out), None),
        Err(e) => {
            error!("[{}] Comando {} fallito: {}", config.name, command_id, e);
            (CommandStatus::Failed, None, Some(e.to_string()))
        }
    }
}

async fn run_integrity_check(paths: &[String]) -> Result<String> {
    use crate::collectors::files;
    let results = files::check_integrity(paths).await?;
    Ok(serde_json::to_string(&results)?)
}

fn next_backoff(current: Duration, config: &TargetConfig) -> Duration {
    let next_secs = (current.as_secs() as f64 * config.reconnect.backoff_multiplier) as u64;
    Duration::from_secs(next_secs.min(config.reconnect.max_backoff))
}
