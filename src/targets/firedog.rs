//! Implementazione protocollo FireDog.
//!
//! Lifecycle:
//!   connect → pair → [heartbeat loop + command handling + threat reporting]
//!   Se la connessione cade: riconnessione a due livelli, vedi `reconnect.rs`.

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use std::time::{Duration, Instant};
use tokio::time::interval;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, warn};

use crate::collectors::system;
use crate::config::TargetConfig;
use crate::firewall::FirewallManager;
use crate::protocol::firedog::*;
use crate::reconnect::Reconnect;
use crate::threat::{ThreatDetector, ThreatScoringConfig};

pub async fn run(config: TargetConfig) -> Result<()> {
    let mut reconnect = Reconnect::new(&config.reconnect);

    loop {
        info!("[{}] Connessione a {}", config.name, config.ws_url());
        let started = Instant::now();
        let result = session(&config).await;
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

async fn session(config: &TargetConfig) -> Result<()> {
    let ws = crate::ws::connect(&config.ws_url()).await?;
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
    let never_block = never_block_ips(config).await;
    let mut threat_detector = ThreatDetector::new(
        ThreatScoringConfig {
            auto_block_threshold: config.threat_threshold,
            auto_block_enabled: config.auto_block_threats,
            bruteforce_min_attempts: config.bruteforce_min_attempts,
            bruteforce_score_per_attempt: config.bruteforce_score_per_attempt,
            synflood_min_connections: config.synflood_min_connections,
            synflood_score_per_conn: config.synflood_score_per_conn,
        },
        never_block,
    );

    let mut hb_timer = interval(Duration::from_secs(config.heartbeat_interval));
    hb_timer.tick().await; // salta il tick immediato

    let mut threat_timer = interval(Duration::from_secs(60));
    threat_timer.tick().await;

    // Forward del file status.json prodotto da `firewall-manager --export-json` (cron).
    // Cadenza 60s: il file viene riscritto ogni 5 min, ma controllarlo più spesso
    // permette di intercettare snapshot fuori-banda (es. invocazione manuale).
    let mut fwstats_timer = interval(Duration::from_secs(60));
    fwstats_timer.tick().await;
    let fwstats_path = std::path::PathBuf::from("/opt/sentinelsuite/firedog/export/status.json");
    let mut last_fwstats_mtime: Option<std::time::SystemTime> = None;

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

            _ = fwstats_timer.tick() => {
                if let Err(e) = forward_firewall_stats(config, &mut tx, &fwstats_path, &mut last_fwstats_mtime).await {
                    warn!("[{}] firewall_stats forward fallito: {}", config.name, e);
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
            memory_total_kb: sys.memory_total_kb,
            memory_used_kb: sys.memory_used_kb,
            disk_total_kb: sys.disk_total_kb,
            disk_used_kb: sys.disk_used_kb,
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
        ServerMessage::FirewallStatsAck => {
            debug!("[{}] firewall_stats_ack ricevuto", config.name);
        }
        ServerMessage::Error { message } => {
            warn!("[{}] Errore dal server: {}", config.name, message);
        }
        ServerMessage::Command { command_id, action, payload } => {
            info!("[{}] Comando ricevuto: {:?}", config.name, action);
            // Tetto assoluto sull'intero dispatch: un comando che si blocca
            // (es. check_integrity su un path enorme/non terminante) non
            // deve più bloccare per sempre questa sessione — niente più
            // heartbeat/threat-report/reconnect per il target finché il
            // processo non viene ucciso a mano (HIGH trovato in code
            // review, 2026-11).
            const COMMAND_DISPATCH_TIMEOUT: Duration = Duration::from_secs(90);
            let (status, output, error) = match tokio::time::timeout(
                COMMAND_DISPATCH_TIMEOUT,
                execute_command(config, fw, &command_id, action, payload),
            )
            .await
            {
                Ok(r) => r,
                Err(_) => {
                    error!(
                        "[{}] Comando {} oltre il timeout di {:?}, abortito",
                        config.name, command_id, COMMAND_DISPATCH_TIMEOUT
                    );
                    (
                        CommandStatus::Failed,
                        None,
                        Some(format!("timeout dispatch dopo {COMMAND_DISPATCH_TIMEOUT:?}")),
                    )
                }
            };

            let resp = AgentMessage::CommandResponse {
                command_id,
                status,
                output,
                error,
            };
            tx.send(Message::Text(serde_json::to_string(&resp)?)).await?;
        }
        ServerMessage::Config { config: new_cfg } => {
            // Path storicamente inutilizzato: il push di config passa ora
            // esclusivamente per CommandAction::UpdateConfig (sotto), che a
            // differenza di questo messaggio fire-and-forget dà un ack di
            // successo/fallimento al backend via CommandResponse. Restiamo
            // in ascolto per compatibilità ma non applichiamo nulla da qui.
            debug!("[{}] ServerMessage::Config ricevuto (ignorato, vedi UpdateConfig): {:?}", config.name, new_cfg);
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
    let result = if matches!(action, CommandAction::CheckIntegrity) {
        // `paths` richiesti dal server sono SOLO un filtro, non possono
        // ampliare l'insieme configurato localmente in integrity_paths:
        // altrimenti il server potrebbe usare questo comando come
        // oracolo di lettura (hash/size/mtime) su qualunque file del
        // filesystem (CRITICAL trovato in code review, 2026-11).
        let requested = serde_json::from_value::<CheckIntegrityPayload>(payload)
            .ok()
            .and_then(|p| p.paths);
        let paths = filter_integrity_paths(requested, &config.integrity_paths);
        run_integrity_check(&paths).await
    } else {
        // Il resto (iptables, firewall-manager, scrittura config) è
        // bloccante: eseguito qui direttamente occupava il thread del
        // runtime e il timeout di dispatch non poteva mai scattare (scatta
        // solo a un .await). In spawn_blocking il timeout libera la
        // sessione; il processo figlio eventualmente bloccato resta loggato.
        let (cfg, fw) = (config.clone(), fw.clone());
        tokio::task::spawn_blocking(move || execute_blocking(&cfg, &fw, action, payload))
            .await
            .unwrap_or_else(|e| Err(anyhow::anyhow!("task del comando terminato: {e}")))
    };

    match result {
        Ok(out) => (CommandStatus::Success, Some(out), None),
        Err(e) => {
            error!("[{}] Comando {} fallito: {}", config.name, command_id, e);
            (CommandStatus::Failed, None, Some(e.to_string()))
        }
    }
}

/// Comandi FireDog sincroni (tutti tranne check_integrity).
fn execute_blocking(
    config: &TargetConfig,
    fw: &FirewallManager,
    action: CommandAction,
    payload: serde_json::Value,
) -> Result<String> {
    match action {
        CommandAction::AddRule => {
            match serde_json::from_value::<AddRulePayload>(payload) {
                Ok(p) => fw.add_rule(&p),
                Err(e) => Err(anyhow::anyhow!("Payload non valido: {e}")),
            }
        }
        CommandAction::RemoveRule => {
            match serde_json::from_value::<RemoveRulePayload>(payload) {
                Ok(p) => fw.remove_rule(&p),
                Err(e) => Err(anyhow::anyhow!("Payload non valido: {e}")),
            }
        }
        CommandAction::BlockIp => {
            match serde_json::from_value::<BlockIpPayload>(payload) {
                Ok(p) => fw.block_ip(&p.ip, &p.direction),
                Err(e) => Err(anyhow::anyhow!("Payload non valido: {e}")),
            }
        }
        CommandAction::UnblockIp => {
            match serde_json::from_value::<BlockIpPayload>(payload) {
                Ok(p) => fw.unblock_ip(&p.ip, &p.direction),
                Err(e) => Err(anyhow::anyhow!("Payload non valido: {e}")),
            }
        }
        CommandAction::SyncRules => {
            fw.sync_rules()
        }
        CommandAction::CheckIntegrity => {
            Err(anyhow::anyhow!("check_integrity gestito in execute_command"))
        }
        CommandAction::UpdateConfig => {
            match serde_json::from_value::<ThreatConfigUpdatePayload>(payload) {
                Ok(p) => update_threat_config(config, &p),
                Err(e) => Err(anyhow::anyhow!("Payload non valido: {e}")),
            }
        }
        CommandAction::UpdatePcapConfig => {
            match serde_json::from_value::<PcapConfigUpdatePayload>(payload) {
                Ok(p) => update_pcap_config(&p),
                Err(e) => Err(anyhow::anyhow!("Payload non valido: {e}")),
            }
        }
        CommandAction::Unknown => {
            Err(anyhow::anyhow!("Azione non riconosciuta"))
        }
    }
}

/// IP che l'auto-block non deve mai bloccare: quelli del server FireDog
/// (risolti dall'url del target) e l'IP configurato della macchina.
async fn never_block_ips(config: &TargetConfig) -> Vec<std::net::IpAddr> {
    let mut ips: Vec<std::net::IpAddr> = Vec::new();
    if let Some(ip) = config.ip.as_deref().and_then(|s| s.parse().ok()) {
        ips.push(ip);
    }
    if let Some(hp) = host_port(&config.ws_url()) {
        match tokio::net::lookup_host(hp.as_str()).await {
            Ok(addrs) => ips.extend(addrs.map(|a| a.ip())),
            Err(e) => warn!("[{}] risoluzione di {hp} per la whitelist auto-block: {e}", config.name),
        }
    }
    ips
}

/// `host:porta` da un URL ws(s)://, con la porta di default dello schema.
fn host_port(url: &str) -> Option<String> {
    let (rest, default_port) = if let Some(r) = url.strip_prefix("wss://") {
        (r, 443)
    } else {
        (url.strip_prefix("ws://")?, 80)
    };
    let authority = rest.split('/').next()?;
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if authority.is_empty() {
        return None;
    }
    // "[::1]:8443", "[::1]", "host:8443", "host"
    let has_port = match authority.rfind(']') {
        Some(end) => authority[end..].contains(':'),
        None => authority.contains(':'),
    };
    Some(if has_port { authority.to_string() } else { format!("{authority}:{default_port}") })
}

/// `requested` (dal server, via `CheckIntegrityPayload.paths`) è SOLO un
/// filtro sull'insieme configurato localmente in `integrity_paths` — non può
/// mai ampliarlo. Senza questo, il server potrebbe usare `check_integrity`
/// come oracolo di lettura (hash/size/mtime) su qualunque file del
/// filesystem (CRITICAL trovato in code review, 2026-11).
///
/// Il confronto NON è sulla stringa: `/etc/../root/.ssh` inizia con `/etc/`
/// ma il kernel lo risolve in `/root/.ssh`, e un symlink sotto una root
/// configurata (es. `/var/www/x -> /root`) porta fuori allo stesso modo.
/// Si scartano quindi i path con componenti `..` e si confrontano per
/// componenti i path canonicalizzati (symlink risolti); al walk passa il
/// path canonico, non quello richiesto. Un path inesistente viene scartato:
/// non c'è nulla da hashare.
fn filter_integrity_paths(requested: Option<Vec<String>>, configured: &[String]) -> Vec<String> {
    let Some(requested) = requested else {
        return configured.to_vec();
    };
    let allowed_roots: Vec<std::path::PathBuf> = configured
        .iter()
        .filter_map(|c| std::fs::canonicalize(c).ok())
        .collect();
    requested
        .into_iter()
        .filter_map(|r| resolve_within(&r, &allowed_roots))
        .collect()
}

/// Path canonico di `requested` se è assoluto, senza componenti `..` e,
/// a symlink risolti, dentro una delle `allowed_roots` (già canonicalizzate).
fn resolve_within(requested: &str, allowed_roots: &[std::path::PathBuf]) -> Option<String> {
    use std::path::{Component, Path};
    let path = Path::new(requested);
    let lexically_clean = path.is_absolute()
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)));
    if !lexically_clean {
        warn!("check_integrity: path '{requested}' rifiutato (non assoluto o con ..)");
        return None;
    }
    let canonical = std::fs::canonicalize(path).ok()?;
    if allowed_roots.iter().any(|root| canonical.starts_with(root)) {
        canonical.to_str().map(str::to_owned)
    } else {
        warn!("check_integrity: path '{requested}' fuori da integrity_paths, ignorato");
        None
    }
}

async fn run_integrity_check(paths: &[String]) -> Result<String> {
    use crate::collectors::files;
    let results = files::check_integrity(paths).await?;
    Ok(serde_json::to_string(&results)?)
}

/// Payload di `CommandAction::UpdateConfig` — corrisponde 1:1 ai nomi dei
/// campi `agentThreatScoring.*` lato backend Django (vedi Target.config_overrides
/// e agent_manager/views.py), stesso naming di TargetConfig qui sopra così
/// non serve una traduzione tra i due lati. Tutti opzionali: il backend
/// invia solo i campi che l'utente ha effettivamente cambiato.
#[derive(serde::Deserialize)]
struct ThreatConfigUpdatePayload {
    auto_block_threshold: Option<u32>,
    auto_block_enabled: Option<bool>,
    bruteforce_min_attempts: Option<u32>,
    bruteforce_score_per_attempt: Option<u32>,
    synflood_min_connections: Option<u32>,
    synflood_score_per_conn: Option<u32>,
}

/// Riscrive le chiavi cambiate nel blocco `[[targets]]` di `config.name`
/// dentro `config.config_path`, poi pianifica un `systemctl restart
/// dog-agent` (dog-agent non fa hot-reload, vedi threat/mod.rs — la nuova
/// config prende effetto solo al riavvio). Il restart è schedulato via
/// `systemd-run --on-active` invece che eseguito qui direttamente: gira
/// così FUORI dal cgroup del servizio dog-agent, altrimenti verrebbe ucciso
/// insieme al processo chiamante prima ancora di partire (KillMode
/// control-group di systemd, che uccide l'intero cgroup allo stop) — e
/// soprattutto dà il tempo alla CommandResponse di successo/fallimento di
/// essere spedita al server PRIMA che il processo muoia per il riavvio.
fn update_threat_config(config: &TargetConfig, p: &ThreatConfigUpdatePayload) -> Result<String> {
    let mut updates: Vec<(&str, String)> = Vec::new();
    if let Some(v) = p.auto_block_threshold { updates.push(("threat_threshold", v.to_string())); }
    if let Some(v) = p.auto_block_enabled { updates.push(("auto_block_threats", v.to_string())); }
    if let Some(v) = p.bruteforce_min_attempts { updates.push(("bruteforce_min_attempts", v.to_string())); }
    if let Some(v) = p.bruteforce_score_per_attempt { updates.push(("bruteforce_score_per_attempt", v.to_string())); }
    if let Some(v) = p.synflood_min_connections { updates.push(("synflood_min_connections", v.to_string())); }
    if let Some(v) = p.synflood_score_per_conn { updates.push(("synflood_score_per_conn", v.to_string())); }

    if updates.is_empty() {
        anyhow::bail!("Nessun campo da aggiornare nel payload");
    }
    if config.config_path.as_os_str().is_empty() {
        anyhow::bail!("config_path non popolato (bug interno: main.rs non l'ha impostato)");
    }

    update_target_config_file(&config.config_path, &config.name, &updates)?;

    // Nessun --unit fisso: systemd-run ne genera uno univoco ad ogni
    // invocazione (run-rXXXXXXXX.service). Con un nome fisso, due push di
    // config ravvicinati (<2s) fallirebbero il secondo `systemd-run` perché
    // l'unit del primo esisterebbe ancora in attesa di partire — la config
    // sul disco sarebbe comunque già scritta, ma il comando risulterebbe
    // fallito lato server. --collect resta: pulisce comunque l'unit
    // transiente a fine esecuzione (successo o fallimento).
    let output = std::process::Command::new("systemd-run")
        .args([
            "--on-active=2",
            "--collect",
            "systemctl",
            "restart",
            "dog-agent",
        ])
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "Config scritta ma impossibile schedulare il riavvio: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(format!(
        "Config aggiornata ({} campi), riavvio del servizio tra 2s",
        updates.len()
    ))
}

/// Riscrive `key = value` per le righe già presenti nel blocco `[[targets]]`
/// il cui campo `name` combacia con `target_name`; le chiavi assenti dal
/// blocco vengono aggiunte in fondo al blocco. Preserva tutto il resto del
/// file (commenti inclusi) invece di fare un round-trip via `toml::Value`,
/// che perderebbe la formattazione di un file pensato per essere editato a
/// mano.
fn update_target_config_file(
    path: &std::path::Path,
    target_name: &str,
    updates: &[(&str, String)],
) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Impossibile leggere {}", path.display()))?;
    let mut lines: Vec<String> = content.lines().map(String::from).collect();

    let mut block_start = None;
    let mut block_end = lines.len();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim_start().starts_with("[[targets]]") {
            let mut j = i + 1;
            let mut name_matches = false;
            while j < lines.len() && !lines[j].trim_start().starts_with("[[targets]]") {
                let trimmed = lines[j].trim_start();
                if trimmed.starts_with("name") && trimmed.contains(&format!("\"{target_name}\"")) {
                    name_matches = true;
                }
                j += 1;
            }
            if name_matches {
                block_start = Some(i);
                block_end = j;
                break;
            }
            i = j;
        } else {
            i += 1;
        }
    }

    let block_start = block_start.ok_or_else(|| {
        anyhow::anyhow!("Blocco [[targets]] '{}' non trovato in {}", target_name, path.display())
    })?;

    // `matched` è popolato controllando `updates` direttamente (non una
    // lista derivata separata che potrebbe divergere): un `.unwrap()` qui
    // dipendeva da un invariante non documentato tra due liste — una
    // futura modifica indipendente dell'una o dell'altra lo avrebbe reso
    // un panic raggiungibile da un messaggio del server (HIGH trovato in
    // code review, 2026-11; vedi anche la mancanza di supervisione sui
    // panic dei target, corretta separatamente in targets/mod.rs).
    let mut matched: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for line in &mut lines[block_start..block_end] {
        let trimmed = line.trim_start().to_string();
        for (key, value) in updates {
            if let Some(rest) = trimmed.strip_prefix(key) {
                if rest.trim_start().starts_with('=') {
                    *line = format!("{key} = {value}");
                    matched.insert(key);
                }
            }
        }
    }
    for (key, value) in updates {
        if !matched.contains(key) {
            lines.insert(block_end, format!("{key} = {value}"));
            block_end += 1;
        }
    }

    // agent.conf contiene l'api_key: 0600 se per qualche motivo non ha già
    // permessi propri da conservare.
    write_atomic(path, &(lines.join("\n") + "\n"), 0o600)
        .with_context(|| format!("Impossibile scrivere {}", path.display()))?;
    Ok(())
}

/// Scrittura atomica: file temporaneo nella stessa directory, con permessi
/// e proprietario dell'originale (`default_mode` se non esiste), fsync,
/// rename. Prima `std::fs::write` troncava e riscriveva sul posto: un crash
/// o un disco pieno a metà lasciava agent.conf vuoto o troncato, e l'agent
/// non ripartiva più.
fn write_atomic(path: &std::path::Path, content: &str, default_mode: u32) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let existing = std::fs::metadata(path).ok();
    let mode = existing.as_ref().map_or(default_mode, |m| m.mode() & 0o7777);
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("path senza nome file: {}", path.display()))?
        .to_string_lossy();
    let tmp = dir.join(format!(".{name}.tmp-{}", uuid::Uuid::new_v4()));

    let written = (|| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)?;
        if let Some(m) = &existing {
            // Best-effort: senza privilegi il chown a un altro gruppo
            // fallisce, e non è un motivo per non aggiornare la config.
            if let Err(e) = std::os::unix::fs::fchown(&f, Some(m.uid()), Some(m.gid())) {
                warn!("{}: proprietario originale non ripristinato: {e}", path.display());
            }
        }
        f.write_all(content.as_bytes())?;
        f.sync_all()
    })();
    let result = written.and_then(|()| std::fs::rename(&tmp, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.map_err(Into::into)
}

/// Path del file letto da `firewall-manager.py`/`traffic-analyzer.py`
/// (CONFIG['firedog_conf'] lato Python) — hardcoded su entrambi i lati,
/// stesso valore storico non reso configurabile.
const FIREDOG_CONF_PATH: &str = "/etc/firewall/firedog.conf";

/// Payload di `CommandAction::UpdatePcapConfig` — nomi 1:1 con le chiavi
/// `pcap*` di SystemSettings lato Django (vedi Settings.tsx/settings/views.py).
/// Tutti opzionali: il backend invia solo i campi cambiati.
/// `pcap_custom_filters`, se presente, SOSTITUISCE l'intera lista (una lista
/// vuota cancella tutti i filtri) — non ha senso "aggiornare" un filtro
/// preciso per indice dato che l'utente li riordina liberamente in UI.
#[derive(serde::Deserialize)]
struct PcapConfigUpdatePayload {
    pcap_save_path: Option<String>,
    pcap_analysis_tool: Option<String>,
    pcap_custom_filters: Option<Vec<String>>,
    pcap_threat_commands: Option<Vec<String>>,
}

const MAX_PCAP_FILTERS: usize = 5;

/// Chiavi dei comandi tcpdump curati per il pannello Dettagli minaccia (vedi
/// get_pcap_threat_detail in firewall-manager.py) — a differenza di
/// pcap_custom_filters, qui l'utente sceglie da un multi-select in Settings,
/// mai testo libero: niente filtro BPF arbitrario arriva su questo canale,
/// solo una di queste chiavi fisse. Validate comunque qui (whitelist) prima
/// di scrivere il file — difesa in profondità, stesso principio già
/// applicato a pcap_custom_filters.
const VALID_THREAT_COMMAND_KEYS: [&str; 5] =
    ["summary", "tcp_flags", "timing", "hex_dump", "icmp"];

/// Scrive le chiavi PCAP_* cambiate in `/etc/firewall/firedog.conf`. A
/// differenza di `update_threat_config`/agent.conf, qui non serve alcun
/// riavvio: `firewall-manager.py`/`traffic-analyzer.py` non sono demoni,
/// rileggono il file ad ogni invocazione (vedi `load_firedog_conf()` lato
/// Python, chiamata a livello di modulo). Il file può non esistere ancora
/// (installazioni esistenti pre-v1.1.0 non lo creano finché non serve).
fn update_pcap_config(p: &PcapConfigUpdatePayload) -> Result<String> {
    if let Some(ref tool) = p.pcap_analysis_tool {
        if tool != "tcpdump" && tool != "tshark" {
            anyhow::bail!("pcap_analysis_tool non valido: '{tool}' (atteso tcpdump|tshark)");
        }
    }
    if let Some(ref save_path) = p.pcap_save_path {
        reject_unsafe_conf_value("pcap_save_path", save_path)?;
        validate_pcap_save_path(save_path)?;
    }
    if let Some(ref filters) = p.pcap_custom_filters {
        for f in filters {
            reject_unsafe_conf_value("pcap_custom_filters", f)?;
        }
    }
    if let Some(ref commands) = p.pcap_threat_commands {
        for c in commands {
            if !VALID_THREAT_COMMAND_KEYS.contains(&c.as_str()) {
                anyhow::bail!("pcap_threat_commands: chiave sconosciuta '{c}'");
            }
        }
    }

    let path = std::path::Path::new(FIREDOG_CONF_PATH);
    let content = std::fs::read_to_string(path).unwrap_or_default();
    let mut lines: Vec<String> = content.lines().map(String::from).collect();

    let mut changed = 0usize;
    if let Some(ref save_path) = p.pcap_save_path {
        upsert_conf_line(&mut lines, "PCAP_SAVE_PATH", save_path);
        changed += 1;
    }
    if let Some(ref tool) = p.pcap_analysis_tool {
        upsert_conf_line(&mut lines, "PCAP_ANALYSIS_TOOL", tool);
        changed += 1;
    }
    if let Some(ref filters) = p.pcap_custom_filters {
        remove_conf_lines_with_prefix(&mut lines, "PCAP_FILTER_");
        for (i, filter) in filters.iter().take(MAX_PCAP_FILTERS).enumerate() {
            lines.push(format!("PCAP_FILTER_{}={}", i + 1, bash_single_quote(filter)));
        }
        changed += 1;
    }
    if let Some(ref commands) = p.pcap_threat_commands {
        remove_conf_lines_with_prefix(&mut lines, "PCAP_THREAT_CMD_");
        for (i, key) in commands.iter().take(VALID_THREAT_COMMAND_KEYS.len()).enumerate() {
            lines.push(format!("PCAP_THREAT_CMD_{}={}", i + 1, bash_single_quote(key)));
        }
        changed += 1;
    }

    if changed == 0 {
        anyhow::bail!("Nessun campo da aggiornare nel payload");
    }

    write_atomic(path, &(lines.join("\n") + "\n"), 0o644)
        .with_context(|| format!("Impossibile scrivere {}", path.display()))?;

    Ok(format!("Config pcap aggiornata ({changed} campi)"))
}

/// Racchiude `value` tra apici singoli, escapando gli apici letterali
/// (`'` → `'\''`, trucco standard di quoting bash) — stessa tecnica di
/// `shlex.quote()` lato Python. Necessario perché questo file viene
/// `source`-ato per intero da `firewall-init.sh` (non solo letto in modo
/// sicuro dal parser Python di `load_firedog_conf()`): un valore libero
/// scritto senza escape corretto (es. un filtro pcap con un apice o un `$(...)`
/// al suo interno) eseguirebbe comandi bash arbitrari al prossimo
/// `firewall-init.sh`/riavvio del firewall.
fn bash_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// Rifiuta un apice singolo o un newline nel valore prima ancora di provare
/// a scriverlo. `bash_single_quote` saprebbe tecnicamente escapare un apice
/// (`'\''`), ma `load_firedog_conf()` lato Python fa solo uno strip ingenuo
/// dell'apice più esterno (non un vero un-escaping bash) — un valore con
/// apice interno verrebbe scritto in modo sicuro per bash ma poi riletto
/// CORROTTO da firewall-manager.py/traffic-analyzer.py. Meglio rifiutare
/// esplicitamente (errore chiaro all'admin) che silenziosamente disallineare
/// i due lati. Un newline romperebbe comunque il formato una-riga-per-chiave
/// a prescindere dal quoting.
/// PCAP_SAVE_PATH è usato come root da firewall-manager.py/traffic-analyzer.py
/// per leggere e scrivere catture: deve essere assoluto, senza `..` e fuori
/// dalle directory di sistema. Default FireDog: /var/log/ulogd.
fn validate_pcap_save_path(value: &str) -> Result<()> {
    use std::path::{Component, Path};
    const SYSTEM_TREES: &[&str] = &[
        "/etc", "/bin", "/sbin", "/usr", "/lib", "/lib64", "/boot",
        "/root", "/proc", "/sys", "/dev", "/run",
    ];
    let p = Path::new(value);
    if !p.is_absolute() || p.components().any(|c| matches!(c, Component::ParentDir)) {
        anyhow::bail!("pcap_save_path deve essere un path assoluto senza '..': {value:?}");
    }
    if p.parent().is_none() || SYSTEM_TREES.iter().any(|t| p.starts_with(t)) {
        anyhow::bail!("pcap_save_path non può stare in una directory di sistema: {value:?}");
    }
    Ok(())
}

fn reject_unsafe_conf_value(field: &str, value: &str) -> Result<()> {
    if value.contains('\'') {
        anyhow::bail!("{field}: non può contenere l'apice singolo (')");
    }
    if value.contains('\n') || value.contains('\r') {
        anyhow::bail!("{field}: non può contenere newline");
    }
    Ok(())
}

/// Sostituisce la riga `KEY=value` esistente (se presente), altrimenti la
/// aggiunge in fondo. NIENTE spazi intorno a `=`, a differenza di
/// `update_target_config_file` (TOML): firedog.conf è `source`-ato da bash
/// in firewall-init.sh, che richiede `KEY=value` senza spazi per
/// riconoscerlo come assegnazione — `KEY = value` verrebbe interpretato come
/// tentativo di eseguire un comando chiamato `KEY`, rompendo il sourcing.
fn upsert_conf_line(lines: &mut Vec<String>, key: &str, value: &str) {
    let quoted = bash_single_quote(value);
    for line in lines.iter_mut() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix(key) {
            if rest.starts_with('=') {
                *line = format!("{key}={quoted}");
                return;
            }
        }
    }
    lines.push(format!("{key}={quoted}"));
}

/// Rimuove tutte le righe (non-commento) la cui chiave inizia con `prefix` —
/// usato per PCAP_FILTER_N: il conteggio cambia ad ogni salvataggio, quindi
/// si ricostruisce l'intero gruppo invece di aggiornare per indice.
fn remove_conf_lines_with_prefix(lines: &mut Vec<String>, prefix: &str) {
    lines.retain(|line| {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            return true;
        }
        !trimmed.starts_with(prefix)
    });
}

/// Legge il file `status.json` (output di `firewall-manager --export-json`) e lo
/// inoltra al server come messaggio `firewall_stats`. Salta l'invio se il file non
/// esiste o se mtime non è cambiato dall'ultimo invio.
async fn forward_firewall_stats<S>(
    config: &TargetConfig,
    tx: &mut S,
    path: &std::path::Path,
    last_mtime: &mut Option<std::time::SystemTime>,
) -> Result<()>
where
    S: futures_util::SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let metadata = match tokio::fs::metadata(path).await {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            debug!("[{}] status.json non presente ({})", config.name, path.display());
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    let mtime = metadata.modified()?;
    if Some(mtime) == *last_mtime {
        return Ok(()); // nessuna nuova snapshot dal cron
    }

    let raw = tokio::fs::read_to_string(path).await?;
    let payload: serde_json::Value = serde_json::from_str(&raw)?;
    let timestamp = chrono::Utc::now().to_rfc3339();
    let msg = AgentMessage::FirewallStats { timestamp, payload };
    tx.send(Message::Text(serde_json::to_string(&msg)?)).await?;
    info!("[{}] firewall_stats inviato (snapshot mtime={:?})", config.name, mtime);
    *last_mtime = Some(mtime);
    Ok(())
}

#[cfg(test)]
mod update_target_config_file_tests {
    use super::update_target_config_file;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn tmp_toml(content: &str) -> std::path::PathBuf {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "dog-agent-test-config-{}-{}.toml",
            std::process::id(),
            seq
        ));
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn aggiorna_chiave_esistente_e_aggiunge_chiave_assente() {
        let path = tmp_toml(
            "[[targets]]\nname = \"t1\"\nthreat_threshold = 75\n[[targets]]\nname = \"t2\"\n",
        );
        let updates = vec![
            ("threat_threshold", "90".to_string()),
            ("bruteforce_min_attempts", "12".to_string()),
        ];
        update_target_config_file(&path, "t1", &updates).unwrap();
        let out = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        assert!(out.contains("threat_threshold = 90"));
        assert!(out.contains("bruteforce_min_attempts = 12"));
        // Il blocco del secondo target non deve essere toccato.
        assert!(out.contains("name = \"t2\""));
        // La nuova chiave va aggiunta DENTRO il blocco di t1, non dopo t2.
        let t1_pos = out.find("name = \"t1\"").unwrap();
        let t2_pos = out.find("name = \"t2\"").unwrap();
        let new_key_pos = out.find("bruteforce_min_attempts").unwrap();
        assert!(t1_pos < new_key_pos && new_key_pos < t2_pos);
    }

    #[test]
    fn blocco_non_trovato_e_un_errore_non_un_panic() {
        let path = tmp_toml("[[targets]]\nname = \"t1\"\n");
        let err = update_target_config_file(&path, "non-esiste", &[("x", "1".to_string())])
            .unwrap_err();
        let _ = std::fs::remove_file(&path);
        assert!(err.to_string().contains("non trovato"));
    }
}

#[cfg(test)]
mod filter_integrity_paths_tests {
    use super::filter_integrity_paths;
    use std::path::PathBuf;

    /// Albero temporaneo: <base>/allowed/{file,sub/} e <base>/secret/key,
    /// più un symlink <base>/allowed/escape -> <base>/secret.
    struct Tree {
        base: PathBuf,
    }

    impl Tree {
        fn new(tag: &str) -> Self {
            let base = std::env::temp_dir()
                .join(format!("dog-agent-integrity-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(base.join("allowed/sub")).unwrap();
            std::fs::create_dir_all(base.join("secret")).unwrap();
            std::fs::write(base.join("allowed/file"), b"x").unwrap();
            std::fs::write(base.join("secret/key"), b"k").unwrap();
            std::os::unix::fs::symlink(base.join("secret"), base.join("allowed/escape")).unwrap();
            let base = std::fs::canonicalize(&base).unwrap();
            Tree { base }
        }
        fn p(&self, rel: &str) -> String {
            self.base.join(rel).to_string_lossy().into_owned()
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    #[test]
    fn nessuna_richiesta_usa_tutto_il_configurato() {
        let configured = vec!["/etc".to_string(), "/usr/bin".to_string()];
        assert_eq!(filter_integrity_paths(None, &configured), configured);
    }

    #[test]
    fn richiesta_fuori_dal_configurato_e_scartata() {
        // Regressione: il server non deve poter usare check_integrity come
        // oracolo di lettura su un path arbitrario fuori da quanto già
        // configurato localmente. Un sottopercorso di una root GIA'
        // configurata non è invece una nuova esposizione.
        let t = Tree::new("fuori");
        let configured = vec![t.p("allowed")];
        let requested = vec![t.p("allowed/sub"), t.p("secret"), "/dev/zero".to_string()];
        let out = filter_integrity_paths(Some(requested), &configured);
        assert_eq!(out, vec![t.p("allowed/sub")]);
    }

    #[test]
    fn richiesta_esattamente_uguale_a_un_path_configurato_e_accettata() {
        let t = Tree::new("uguale");
        let configured = vec![t.p("allowed")];
        let out = filter_integrity_paths(Some(vec![t.p("allowed")]), &configured);
        assert_eq!(out, vec![t.p("allowed")]);
    }

    #[test]
    fn prefisso_senza_separatore_non_basta() {
        // "<base>/allowedfoo" non è un sottopercorso di "<base>/allowed".
        let t = Tree::new("prefisso");
        std::fs::create_dir_all(t.base.join("allowedfoo")).unwrap();
        let configured = vec![t.p("allowed")];
        let out = filter_integrity_paths(Some(vec![t.p("allowedfoo")]), &configured);
        assert!(out.is_empty());
    }

    #[test]
    fn dot_dot_non_esce_dalla_root_configurata() {
        // Regressione (seconda review, 2026-11): il confronto per stringa
        // accettava "<allowed>/../secret" perché inizia con "<allowed>/".
        let t = Tree::new("dotdot");
        let configured = vec![t.p("allowed")];
        let requested = vec![t.p("allowed/../secret"), t.p("allowed/sub/../../secret/key")];
        assert!(filter_integrity_paths(Some(requested), &configured).is_empty());
    }

    #[test]
    fn symlink_sotto_la_root_non_porta_fuori() {
        let t = Tree::new("symlink");
        let configured = vec![t.p("allowed")];
        let requested = vec![t.p("allowed/escape"), t.p("allowed/escape/key")];
        assert!(filter_integrity_paths(Some(requested), &configured).is_empty());
    }

    #[test]
    fn path_relativo_e_scartato() {
        let t = Tree::new("relativo");
        let configured = vec![t.p("allowed")];
        assert!(filter_integrity_paths(Some(vec!["allowed/file".into()]), &configured).is_empty());
    }
}

#[cfg(test)]
mod host_port_tests {
    use super::host_port;

    #[test]
    fn porta_di_default_e_ipv6() {
        assert_eq!(host_port("wss://fd.example.com/ws/agent/").as_deref(), Some("fd.example.com:443"));
        assert_eq!(host_port("ws://10.0.0.5:8000/ws/agent/").as_deref(), Some("10.0.0.5:8000"));
        assert_eq!(host_port("wss://[2001:db8::1]/ws/agent/").as_deref(), Some("[2001:db8::1]:443"));
        assert_eq!(host_port("wss://[2001:db8::1]:8443/x").as_deref(), Some("[2001:db8::1]:8443"));
        assert_eq!(host_port("http://x"), None);
    }
}

#[cfg(test)]
mod conf_write_tests {
    use super::{validate_pcap_save_path, write_atomic};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn pcap_save_path_fuori_dalle_directory_di_sistema() {
        for ok in ["/var/log/ulogd", "/var/log/ulogd/input_dropped.pcap", "/data/pcap"] {
            assert!(validate_pcap_save_path(ok).is_ok(), "{ok} doveva essere accettato");
        }
        for bad in ["/", "var/log", "/var/log/../../etc/cron.d/x", "/etc/cron.d/x", "/usr/bin/x", "/root/p"] {
            assert!(validate_pcap_save_path(bad).is_err(), "{bad} doveva essere rifiutato");
        }
    }

    #[test]
    fn write_atomic_conserva_i_permessi_e_non_lascia_temporanei() {
        let dir = std::env::temp_dir().join(format!("dog-agent-atomic-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("agent.conf");
        std::fs::write(&conf, "vecchio\n").unwrap();
        std::fs::set_permissions(&conf, std::fs::Permissions::from_mode(0o640)).unwrap();

        write_atomic(&conf, "nuovo\n", 0o600).unwrap();
        let mode = std::fs::metadata(&conf).unwrap().permissions().mode() & 0o777;
        let content = std::fs::read_to_string(&conf).unwrap();
        let entries = std::fs::read_dir(&dir).unwrap().count();

        write_atomic(&dir.join("nuovo.conf"), "x", 0o600).unwrap();
        let new_mode = std::fs::metadata(dir.join("nuovo.conf")).unwrap().permissions().mode() & 0o777;
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!((mode, content.as_str(), entries), (0o640, "nuovo\n", 1));
        assert_eq!(new_mode, 0o600);
    }
}
