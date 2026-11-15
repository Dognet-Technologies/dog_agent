//! Implementazione protocollo CyberShepherd.
//!
//! Lifecycle:
//!   connect → auth → [collect metrics → buffer → flush compresso ogni send_interval]
//!   Se la connessione cade: riconnessione a due livelli, vedi `reconnect.rs`.

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::time::interval;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, warn};

use crate::collectors::{self, AllMetrics};
use crate::compression::compress_json;
use crate::config::TargetConfig;
use crate::protocol::cybershepherd::*;
use crate::reconnect::Reconnect;

/// Coda verso il writer task della sessione.
type Out = tokio::sync::mpsc::Sender<Message>;

/// Attesa massima per un posto in coda prima di dare la connessione per
/// bloccata, per i messaggi che non si possono perdere.
const RELIABLE_SEND_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn run(config: TargetConfig) -> Result<()> {
    let mut reconnect = Reconnect::new(&config.reconnect);
    // Hardening, audit e remediation girano uno alla volta per target. Il
    // semaforo vive fuori dalla sessione: dopo un reconnect un nuovo comando
    // aspetta che finisca quello ancora in corso dalla sessione precedente.
    let long_cmds = Arc::new(Semaphore::new(1));

    loop {
        info!("[{}] Connessione a {}", config.name, config.ws_url());
        let started = Instant::now();
        let result = session(&config, &long_cmds).await;
        let elapsed = started.elapsed();

        match result {
            Ok(()) => info!("[{}] Sessione chiusa, riconnessione...", config.name),
            Err(e) => error!("[{}] Errore sessione: {}", config.name, e),
        }

        let delay = reconnect.next_delay(elapsed);
        warn!("[{}] Retry tra {:?}", config.name, delay);
        tokio::time::sleep(delay).await;
    }
}

async fn session(config: &TargetConfig, long_cmds: &Arc<Semaphore>) -> Result<()> {
    let ws = crate::ws::connect(&config.ws_url()).await?;
    let (mut ws_tx, mut rx) = ws.split();

    let target_id = config.target_id.unwrap_or(0);
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    // ── Autenticazione / Pairing ────────────────────────────────────────────────
    // Se l'identità (ip+hostname+mac) è configurata, si usa il pairing per-identità
    // stile FireDog; altrimenti si ricade sull'auth a token (legacy).
    let ip = config.ip.clone().unwrap_or_default();
    let cfg_hostname = config.hostname.clone().filter(|h| !h.is_empty()).unwrap_or_else(|| hostname.clone());
    let mac = config.mac.clone().unwrap_or_default();
    let use_pairing = !ip.is_empty() && !cfg_hostname.is_empty() && !mac.is_empty();

    if use_pairing {
        let pair = AgentMessage::PairRequest {
            target_id,
            timestamp: chrono::Utc::now().timestamp(),
            payload: PairRequestPayload {
                api_key: config.api_key.clone(),
                ip,
                hostname: cfg_hostname,
                mac,
                agent_version: env!("CARGO_PKG_VERSION").to_string(),
            },
        };
        ws_tx.send(Message::Text(serde_json::to_string(&pair)?)).await?;
        info!("[{}] pair_request inviato", config.name);
        wait_pairing(&mut rx, &config.name).await?;
        info!("[{}] Pairing completato", config.name);
    } else {
        let auth = AgentMessage::Auth {
            target_id,
            timestamp: chrono::Utc::now().timestamp(),
            payload: AuthPayload {
                auth_token: config.api_key.clone(),
                agent_version: env!("CARGO_PKG_VERSION").to_string(),
                hostname: hostname.clone(),
            },
        };
        ws_tx.send(Message::Text(serde_json::to_string(&auth)?)).await?;
        wait_auth_ack(&mut rx, &config.name).await?;
        info!("[{}] Autenticazione completata", config.name);
    }

    // ── Writer task dedicato ────────────────────────────────────────────────
    // I write eseguiti direttamente dal select! su uno SplitSink di
    // tokio-tungstenite non venivano "guidati" in modo affidabile quando non si
    // stava contemporaneamente pollando il read half: le risposte out-of-band
    // (es. esito hardening) restavano in coda per decine di secondi. Un task
    // dedicato che possiede il sink e lo polla di continuo elimina il ritardo.
    //
    // Canale CON bound (256): se la connessione si blocca la coda non deve
    // crescere senza limite in memoria. Due modi di inviare:
    // - `send_reliable` (esiti dei comandi, stato hardening, eventi di
    //   sicurezza): attende un posto fino a RELIABLE_SEND_TIMEOUT, poi errore.
    // - `send_best_effort` (metriche, progress intermedi, pong): se la coda
    //   è piena il messaggio si scarta con un warn.
    // Prima tutto passava da `try_send` + `?`: a coda piena si perdeva
    // l'esito finale di un hardening già applicato e cadeva la sessione
    // (HIGH, seconda review 2026-11).
    let (out, mut out_rx) = tokio::sync::mpsc::channel::<Message>(256);
    tokio::spawn(async move {
        while let Some(m) = out_rx.recv().await {
            if ws_tx.send(m).await.is_err() {
                break;
            }
        }
    });

    // ── Setup timer ───────────────────────────────────────────────────────────
    let mut collect_timer = interval(Duration::from_secs(config.collection_interval));
    collect_timer.tick().await;

    let mut send_timer = interval(Duration::from_secs(config.send_interval));
    send_timer.tick().await;

    let mut buffer: Vec<AllMetrics> = Vec::new();
    let mut laurel_offset: u64 = 0;

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
                            flush_buffer(config, &out, &mut buffer, target_id)?;
                        }
                        // Se la coda resta piena il buffer non va oltre il
                        // doppio del limite: si scartano le raccolte più vecchie.
                        let cap = config.max_buffer_size.saturating_mul(2).max(1);
                        if buffer.len() > cap {
                            let excess = buffer.len() - cap;
                            buffer.drain(..excess);
                            warn!("[{}] {} raccolte metriche scartate (coda WS piena)", config.name, excess);
                        }
                    }
                    Err(e) => {
                        error!("[{}] Errore raccolta metriche: {}", config.name, e);
                    }
                }
            }

            _ = send_timer.tick() => {
                if !buffer.is_empty() {
                    flush_buffer(config, &out, &mut buffer, target_id)?;
                }
                // Inoltro eventi Laurel (se configurato laurel_log_path)
                if let Some(path) = config.laurel_log_path.clone() {
                    let off = laurel_offset;
                    match tokio::task::spawn_blocking(move || read_laurel_events(&path, off)).await {
                        Ok((events, new_off)) => {
                            // L'offset avanza solo a invio riuscito: in caso
                            // di errore la sessione cade e gli eventi non
                            // risultano letti.
                            if !events.is_empty() {
                                flush_security_events(config, &out, events, target_id).await?;
                            }
                            laurel_offset = new_off;
                        }
                        Err(e) => error!("[{}] Errore lettura Laurel: {}", config.name, e),
                    }
                }
            }

            msg = rx.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        handle_server_message(config, &out, &text, target_id, long_cmds).await?;
                    }
                    Some(Ok(Message::Ping(data))) => {
                        send_best_effort(&out, Message::Pong(data), &config.name, "pong")?;
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

/// Attende l'esito del pairing per-identità (fino a 3 min, finestra server).
/// Ritorna Ok solo quando fase 1 (api_key) e fase 2 (identity hash) sono
/// entrambe verificate; fallisce su status "failed"/"expired".
async fn wait_pairing<S>(rx: &mut S, name: &str) -> Result<()>
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let mut phase1 = false;

    let timeout = tokio::time::timeout(Duration::from_secs(180), async {
        loop {
            match rx.next().await {
                Some(Ok(Message::Text(text))) => {
                    match serde_json::from_str::<ServerMessage>(&text) {
                        Ok(ServerMessage::PairingStatus {
                            status,
                            phase_1_verified,
                            phase_2_verified,
                            message,
                            ..
                        }) => {
                            if phase_1_verified {
                                phase1 = true;
                                info!("[{}] Fase 1 verificata (API key OK)", name);
                            }
                            if phase_2_verified && phase1 {
                                info!("[{}] Fase 2 verificata (identity hash OK)", name);
                                return Ok(());
                            }
                            if status == "failed" || status == "expired" {
                                anyhow::bail!("Pairing fallito: {}", message.unwrap_or(status));
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

/// Accoda un messaggio che non si può perdere, attendendo un posto fino a
/// `RELIABLE_SEND_TIMEOUT`. Errore se il writer è chiuso o la coda resta piena.
async fn send_reliable(out: &Out, msg: Message) -> Result<()> {
    send_within(out, msg, RELIABLE_SEND_TIMEOUT).await
}

async fn send_within(out: &Out, msg: Message, limit: Duration) -> Result<()> {
    match tokio::time::timeout(limit, out.send(msg)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => anyhow::bail!("writer WS chiuso"),
        Err(_) => anyhow::bail!(
            "coda WS piena da {}s, connessione bloccata",
            limit.as_secs_f32()
        ),
    }
}

/// Accoda senza attendere. `Ok(false)` se la coda è piena (messaggio
/// scartato), errore solo se il writer è chiuso.
fn send_best_effort(out: &Out, msg: Message, name: &str, what: &str) -> Result<bool> {
    use tokio::sync::mpsc::error::TrySendError;
    match out.try_send(msg) {
        Ok(()) => Ok(true),
        Err(TrySendError::Full(_)) => {
            warn!("[{name}] coda WS piena: {what} scartato");
            Ok(false)
        }
        Err(TrySendError::Closed(_)) => anyhow::bail!("writer WS chiuso"),
    }
}

/// Invia il buffer metriche; se la coda è piena lo lascia intatto per il
/// prossimo tentativo (il chiamante ne limita la crescita).
fn flush_buffer(
    config: &TargetConfig,
    out: &Out,
    buffer: &mut Vec<AllMetrics>,
    target_id: i32,
) -> Result<()> {
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

    let text = Message::Text(serde_json::to_string(&msg)?);
    if send_best_effort(out, text, &config.name, "batch metriche")? {
        buffer.clear();
    }
    Ok(())
}

/// Comprime e invia un batch di eventi Laurel come `SecurityEvents`.
/// Eventi di sicurezza: invio affidabile, non best-effort.
async fn flush_security_events(
    config: &TargetConfig,
    out: &Out,
    events: Vec<serde_json::Value>,
    target_id: i32,
) -> Result<()> {
    let compressed = compress_json(&events, config.compression_level)?;

    info!(
        "[{}] Invio {} eventi Laurel — {} → {} byte ({:.1}% compressione)",
        config.name,
        events.len(),
        compressed.original_size,
        compressed.compressed_size,
        compressed.compression_ratio
    );

    let msg = AgentMessage::SecurityEvents {
        target_id,
        timestamp: chrono::Utc::now().timestamp(),
        payload: compressed,
    };
    send_reliable(out, Message::Text(serde_json::to_string(&msg)?)).await
}

/// Tail del file JSON di Laurel: legge le righe nuove da `offset`, ne fa il
/// parse (una riga = un evento arricchito) e restituisce `(eventi, nuovo_offset)`.
/// Gestisce la rotazione (se il file è più corto di `offset`, riparte da 0).
/// Funzione bloccante: eseguirla in `spawn_blocking`.
fn read_laurel_events(path: &str, offset: u64) -> (Vec<serde_json::Value>, u64) {
    use std::io::{BufRead, BufReader, Seek, SeekFrom};

    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return (Vec::new(), offset),
    };
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let start = if len < offset { 0 } else { offset };
    if file.seek(SeekFrom::Start(start)).is_err() {
        return (Vec::new(), offset);
    }

    let reader = BufReader::new(file);
    let mut events = Vec::new();
    let mut pos = start;
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        pos += line.len() as u64 + 1; // +1 per il newline
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
            events.push(v);
        }
    }
    (events, pos)
}

async fn handle_server_message(
    config: &TargetConfig,
    out: &Out,
    text: &str,
    target_id: i32,
    long_cmds: &Arc<Semaphore>,
) -> Result<()> {
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

            if matches!(
                payload.action.as_str(),
                "execute_hardening" | "security_audit_scan" | "apply_remediation"
            ) {
                // Comandi lunghi: in un task a parte, così il loop della
                // sessione continua a rispondere ai ping e a leggere il
                // server mentre l'hardening gira (prima lo bloccava per
                // tutta la durata).
                spawn_long_command(
                    config.clone(),
                    out.clone(),
                    target_id,
                    payload.action.clone(),
                    payload.params.clone(),
                    Arc::clone(long_cmds),
                );
            } else {
                // Altri comandi (ping/get_version): risposta generica.
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
                send_reliable(out, Message::Text(serde_json::to_string(&resp)?)).await?;
            }
        }
        ServerMessage::AuthAck { .. } => {
            // già gestito in wait_auth_ack
        }
        ServerMessage::PairingStatus { .. } => {
            // già gestito in wait_pairing, ignora eventuali duplicati
        }
    }

    Ok(())
}

/// Esegue hardening / security audit / remediation in un task tokio,
/// serializzato da `gate` (un comando lungo alla volta per target: mutano
/// lo stesso sistema). Gli errori vengono registrati nel log locale.
fn spawn_long_command(
    config: TargetConfig,
    out: Out,
    target_id: i32,
    action: String,
    params: serde_json::Value,
    gate: Arc<Semaphore>,
) {
    tokio::spawn(async move {
        let Ok(_permit) = gate.acquire_owned().await else {
            return;
        };
        let result = match action.as_str() {
            // Applica (o simula) un template di hardening: stato come
            // command_response con payload HardeningResponse.
            "execute_hardening" => run_hardening_command(&config, &out, target_id, &params).await,
            // Linux-Security-Audit-Project vendorizzato, sola lettura.
            "security_audit_scan" => run_security_audit_command(&config, &out, target_id, &params).await,
            // UN task ad-hoc della DSL (remediation curata per un check),
            // mai il testo di remediation del tool esterno alla lettera.
            _ => run_apply_remediation_command(&config, &out, target_id, &params).await,
        };
        if let Err(e) = result {
            error!("[{}] Comando {} fallito: {e:#}", config.name, action);
        }
    });
}

/// Esegue (o simula) un template di hardening ricevuto via comando e riporta
/// lo stato al server come `command_response` con payload HardeningResponse.
/// L'esecuzione vera è bloccante → gira in spawn_blocking.
async fn run_hardening_command(
    config: &TargetConfig,
    out: &Out,
    target_id: i32,
    params: &serde_json::Value,
) -> Result<()> {
    let exec_id = params.get("execution_id").and_then(|v| v.as_i64()).unwrap_or(0);
    let mode = params
        .get("execution_mode")
        .and_then(|v| v.as_str())
        .unwrap_or("dry_run")
        .to_string();
    let template = params.get("template").cloned().unwrap_or_else(|| serde_json::json!({}));
    let total = template
        .get("hardening_steps")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0) as i32;
    // Fase B: control_id (slug YAML) esclusi per questo target, risolti
    // server-side da `target_hardening_exclusions` e allegati ai params.
    let excluded: Vec<String> = params
        .get("excluded_control_ids")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();

    info!(
        "[{}] Hardening exec {} ({}) — {} controlli, {} esclusi",
        config.name, exec_id, mode, total, excluded.len()
    );

    // Stato iniziale "running".
    send_reliable(
        out,
        hardening_status_msg(
            target_id, exec_id, "running",
            Some(serde_json::json!({ "total_controls": total, "successful_controls": 0, "failed_controls": 0 })),
            None,
        ),
    )
    .await?;

    // Esecuzione bloccante con streaming del progresso: dopo ogni controllo
    // l'executor emette un ProgressUpdate (con log parziale) che inoltriamo
    // subito al server come stato "running" → l'UI mostra cosa sta accadendo.
    let (ptx, mut prx) = tokio::sync::mpsc::unbounded_channel::<super::hardening::ProgressUpdate>();
    let handle = tokio::task::spawn_blocking(move || {
        super::hardening::run_hardening(&template, &mode, &excluded, move |u| {
            let _ = ptx.send(u);
        })
    });
    // Non usare `?` dentro questo loop: un fallimento nell'INVIO di un
    // progress update (sessione/writer già morti) non deve più far
    // ritornare la funzione PRIMA di aver atteso `handle` — altrimenti
    // l'esecuzione bloccante (che sta mutando file/systemctl sul sistema
    // reale) resta orfana, detached, mai letta né riportata, e un
    // reconnect potrebbe far ripartire lo stesso comando mentre quella
    // vecchia esecuzione gira ancora in parallelo (HIGH trovato in code
    // review, 2026-11). I progress sono best-effort: a coda piena si salta
    // quell'aggiornamento; a writer chiuso si smette di inviarne, ma si
    // continua a drenare il canale e si attende comunque l'esito finale.
    let mut send_failed = false;
    while let Some(u) = prx.recv().await {
        if send_failed {
            continue;
        }
        let msg = hardening_status_msg(
            target_id, exec_id, "running",
            Some(serde_json::json!({
                "total_controls": u.total,
                "successful_controls": u.successful,
                "failed_controls": u.failed,
                "current_control": u.current_control,
                "execution_log": u.log,
            })),
            None,
        );
        if let Err(e) = send_best_effort(out, msg, &config.name, "progress hardening") {
            warn!(
                "[{}] Hardening exec {}: invio progress fallito ({}), continuo ad attendere l'esecuzione",
                config.name, exec_id, e
            );
            send_failed = true;
        }
    }
    let outcome = handle.await.map_err(|e| anyhow::anyhow!("join hardening: {e}"))?;

    let progress = serde_json::json!({
        "total_controls": outcome.total_controls,
        "successful_controls": outcome.successful_controls,
        "failed_controls": outcome.failed_controls,
        "skipped_controls": outcome.skipped_controls,
        "execution_log": outcome.execution_log,
        "rollback_data": outcome.rollback_data,
        "control_results": outcome.control_results,
    });
    let final_msg = hardening_status_msg(target_id, exec_id, &outcome.status, Some(progress), outcome.error.as_deref());
    if let Err(e) = send_reliable(out, final_msg).await {
        // L'esecuzione È andata avanti e ha davvero mutato il sistema: se
        // anche l'invio dell'esito finale fallisce, l'unica traccia che
        // resta è questo log locale — meglio di perderla silenziosamente.
        error!(
            "[{}] Hardening exec {} completato ({}/{} controlli ok, {} falliti, stato={}) ma l'esito NON è stato riportato al server ({}): modifiche al sistema potrebbero non essere registrate lato master",
            config.name, exec_id, outcome.successful_controls, outcome.total_controls, outcome.failed_controls, outcome.status, e
        );
        return Err(e);
    }
    info!("[{}] Hardening exec {} → {}", config.name, exec_id, outcome.status);
    Ok(())
}

/// Esegue il security-audit vendorizzato (bloccante → spawn_blocking) e
/// riporta l'esito al server come `command_response` con payload
/// SecurityAuditResponse (chiave `security_audit_execution_id`, distinta da
/// `execution_id` di HardeningResponse così il server disambigua i due tipi
/// di risposta allo stesso modo già usato per l'hardening).
async fn run_security_audit_command(
    config: &TargetConfig,
    out: &Out,
    target_id: i32,
    params: &serde_json::Value,
) -> Result<()> {
    let exec_id = params.get("execution_id").and_then(|v| v.as_i64()).unwrap_or(0);
    let modules = params
        .get("modules")
        .and_then(|v| v.as_str())
        .unwrap_or("All")
        .to_string();

    info!("[{}] Security audit exec {} — moduli: {}", config.name, exec_id, modules);

    let outcome = tokio::task::spawn_blocking(move || super::security_audit::run_security_audit(&modules))
        .await
        .map_err(|e| anyhow::anyhow!("join security_audit: {e}"))?;

    let results_compressed = crate::compression::compress_json(&outcome.results, config.compression_level)
        .ok()
        .and_then(|c| serde_json::to_value(c).ok());

    let msg = serde_json::json!({
        "msg_type": "command_response",
        "target_id": target_id,
        "timestamp": chrono::Utc::now().timestamp(),
        "payload": {
            "security_audit_execution_id": exec_id,
            "status": outcome.status,
            "summary": outcome.summary,
            "results_compressed": results_compressed,
            "error": outcome.error,
        }
    });
    send_reliable(out, Message::Text(msg.to_string())).await?;

    info!("[{}] Security audit exec {} → {}", config.name, exec_id, outcome.status);
    Ok(())
}

/// Applica (bloccante → spawn_blocking) UN task ad-hoc della DSL — risoluzione
/// server-side di un check verso `security_audit_remediations`, mai
/// esecuzione diretta del testo di remediation del tool. Risposta con chiave
/// `remediation_execution_id`, distinta da `execution_id`/`security_audit_execution_id`
/// per il dispatch dual-shape lato server.
async fn run_apply_remediation_command(
    config: &TargetConfig,
    out: &Out,
    target_id: i32,
    params: &serde_json::Value,
) -> Result<()> {
    let apply_id = params.get("apply_id").and_then(|v| v.as_i64()).unwrap_or(0);
    let mode = params.get("mode").and_then(|v| v.as_str()).unwrap_or("apply").to_string();
    let task = params.get("task").cloned().unwrap_or_else(|| serde_json::json!({}));

    info!("[{}] Apply remediation {} — mode={}", config.name, apply_id, mode);

    let outcome = tokio::task::spawn_blocking(move || super::hardening::run_single_task(&task, &mode))
        .await
        .map_err(|e| anyhow::anyhow!("join apply_remediation: {e}"))?;

    let status = if outcome.ok { "completed" } else { "failed" };
    let msg = serde_json::json!({
        "msg_type": "command_response",
        "target_id": target_id,
        "timestamp": chrono::Utc::now().timestamp(),
        "payload": {
            "remediation_execution_id": apply_id,
            "status": status,
            "ok": outcome.ok,
            "log": outcome.log,
            "rollback_data": outcome.rollback_data,
            "error": outcome.error,
        }
    });
    send_reliable(out, Message::Text(msg.to_string())).await?;

    info!("[{}] Apply remediation {} → {}", config.name, apply_id, status);
    Ok(())
}

fn hardening_status_msg(
    target_id: i32,
    execution_id: i64,
    status: &str,
    progress: Option<serde_json::Value>,
    error: Option<&str>,
) -> Message {
    let msg = serde_json::json!({
        "msg_type": "command_response",
        "target_id": target_id,
        "timestamp": chrono::Utc::now().timestamp(),
        "payload": {
            "execution_id": execution_id,
            "status": status,
            "progress": progress,
            "error": error,
        }
    });
    Message::Text(msg.to_string())
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
            warn!("Comando CyberShepherd non supportato: {}", other);
            (false, None, Some(format!("Azione non supportata: {other}")))
        }
    }
}

#[cfg(test)]
mod send_tests {
    use super::*;

    fn text(s: &str) -> Message {
        Message::Text(s.to_string())
    }

    #[test]
    fn best_effort_scarta_a_coda_piena_senza_errore() {
        let (out, _rx) = tokio::sync::mpsc::channel::<Message>(1);
        assert!(send_best_effort(&out, text("a"), "t", "x").unwrap());
        // Coda piena: scartato, ma la sessione non deve cadere.
        assert!(!send_best_effort(&out, text("b"), "t", "x").unwrap());
    }

    #[test]
    fn best_effort_errore_a_writer_chiuso() {
        let (out, rx) = tokio::sync::mpsc::channel::<Message>(1);
        drop(rx);
        assert!(send_best_effort(&out, text("a"), "t", "x").is_err());
    }

    #[tokio::test]
    async fn reliable_attende_il_posto_invece_di_scartare() {
        // Regressione (seconda review, 2026-11): con try_send l'esito finale
        // di un hardening andava perso se la coda era piena in quell'istante.
        let (out, mut rx) = tokio::sync::mpsc::channel::<Message>(1);
        out.try_send(text("riempitivo")).unwrap();
        let drain = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let first = rx.recv().await.unwrap();
            let second = rx.recv().await.unwrap();
            (first, second)
        });
        send_reliable(&out, text("esito finale")).await.unwrap();
        let (_, second) = drain.await.unwrap();
        assert_eq!(second, text("esito finale"));
    }

    #[tokio::test]
    async fn reliable_errore_se_la_coda_resta_piena() {
        let (out, _rx) = tokio::sync::mpsc::channel::<Message>(1);
        out.try_send(text("riempitivo")).unwrap();
        let err = send_within(&out, text("x"), Duration::from_millis(50)).await.unwrap_err();
        assert!(err.to_string().contains("coda WS piena"));
    }

    #[tokio::test]
    async fn reliable_errore_a_writer_chiuso() {
        let (out, rx) = tokio::sync::mpsc::channel::<Message>(1);
        drop(rx);
        assert!(send_reliable(&out, text("x")).await.is_err());
    }
}
