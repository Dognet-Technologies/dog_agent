//! Rilevamento minacce locale per FireDog.
//!
//! Analizza log di sistema per identificare pattern sospetti:
//! - Brute force SSH/FTP (tentativi falliti ripetuti)
//! - Port scan (molte connessioni a porte diverse dallo stesso IP)
//! - SYN flood (rilevato via /proc/net/tcp)
//!
//! Ogni minaccia riceve uno score 0-100.
//! Se score >= threshold e auto_block=true, applica blocco locale via iptables.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use tracing::{info, warn};

use crate::protocol::firedog::{ThreatEntry, ThreatType};

/// Parametri della formula di scoring, configurabili per-target via
/// `agent.conf` (vedi `TargetConfig` in `src/config.rs`) invece che
/// hardcoded. `auto_block_threshold`/`auto_block_enabled` decidono quando
/// scatta il blocco iptables; gli altri 4 campi decidono QUANTO viene
/// considerata grave una minaccia (soglia di innesco + punti per evento).
#[derive(Debug, Clone, Copy)]
pub struct ThreatScoringConfig {
    pub auto_block_threshold: u32,
    pub auto_block_enabled: bool,
    pub bruteforce_min_attempts: u32,
    pub bruteforce_score_per_attempt: u32,
    pub synflood_min_connections: u32,
    pub synflood_score_per_conn: u32,
}

pub struct ThreatDetector {
    config: ThreatScoringConfig,
    /// IP già bloccati (evita blocchi duplicati)
    blocked_ips: Vec<String>,
    /// IP che l'auto-block non deve mai bloccare (server della suite, IP
    /// della macchina stessa): la minaccia viene comunque riportata.
    never_block: Vec<IpAddr>,
}

impl ThreatDetector {
    pub fn new(config: ThreatScoringConfig, never_block: Vec<IpAddr>) -> Self {
        Self {
            config,
            blocked_ips: vec![],
            never_block,
        }
    }

    /// Loopback, unspecified, multicast e `never_block` non si bloccano mai:
    /// un IP "attaccante" ricavato da un log può essere stato iniettato
    /// apposta per far tagliare fuori il server o la macchina stessa.
    fn is_never_blocked(&self, ip: &str) -> bool {
        match ip.parse::<IpAddr>() {
            Ok(addr) => {
                addr.is_loopback()
                    || addr.is_unspecified()
                    || addr.is_multicast()
                    || self.never_block.contains(&addr)
            }
            Err(_) => true,
        }
    }

    /// Esegue una scansione e restituisce le minacce rilevate dall'ultimo scan.
    pub async fn scan(&mut self) -> Vec<ThreatEntry> {
        let mut threats = Vec::new();

        #[cfg(target_os = "linux")]
        {
            threats.extend(self.scan_auth_log().await);
            threats.extend(self.scan_port_connections().await);
        }

        // Applica blocco automatico per minacce sopra threshold
        if self.config.auto_block_enabled {
            for threat in &mut threats {
                if threat.score < self.config.auto_block_threshold
                    || self.blocked_ips.contains(&threat.src_ip)
                {
                    continue;
                }
                if self.is_never_blocked(&threat.src_ip) {
                    warn!(
                        "Blocco automatico NON applicato a {} (IP protetto: server della suite, \
                         macchina locale o loopback) — score {}",
                        threat.src_ip, threat.score
                    );
                    continue;
                }
                if let Err(e) = self.block_ip(&threat.src_ip) {
                    warn!("Blocco automatico fallito per {}: {}", threat.src_ip, e);
                } else {
                    info!(
                        "Blocco automatico: {} (score: {}, tipo: {})",
                        threat.src_ip, threat.score, threat.threat_type
                    );
                    threat.auto_blocked = true;
                    self.blocked_ips.push(threat.src_ip.clone());
                }
            }
        }

        threats
    }

    #[cfg(target_os = "linux")]
    async fn scan_auth_log(&mut self) -> Vec<ThreatEntry> {
        let min_attempts = self.config.bruteforce_min_attempts;
        let score_per_attempt = self.config.bruteforce_score_per_attempt;
        tokio::task::spawn_blocking(move || scan_auth_log_sync(min_attempts, score_per_attempt))
            .await
            .unwrap_or_else(|e| {
                warn!("scan_auth_log: spawn_blocking panicato: {e}");
                Vec::new()
            })
    }

    #[cfg(target_os = "linux")]
    async fn scan_port_connections(&mut self) -> Vec<ThreatEntry> {
        let min_connections = self.config.synflood_min_connections;
        let score_per_conn = self.config.synflood_score_per_conn;
        tokio::task::spawn_blocking(move || scan_connections_sync(min_connections, score_per_conn))
            .await
            .unwrap_or_else(|e| {
                warn!("scan_port_connections: spawn_blocking panicato: {e}");
                Vec::new()
            })
    }

    /// Stesso percorso dei blocchi manuali: iptables/ip6tables secondo la
    /// famiglia dell'IP e niente regole duplicate (`-C` prima di `-A`).
    fn block_ip(&self, ip: &str) -> anyhow::Result<()> {
        crate::firewall::drop_input_from(ip).map(|_| ())
    }
}

/// Byte finali di auth.log/secure analizzati a ogni scan: il file può
/// essere di centinaia di MB e prima veniva letto per intero in memoria
/// ogni 60s solo per guardarne le ultime 1000 righe.
#[cfg(target_os = "linux")]
const AUTH_LOG_TAIL_BYTES: u64 = 256 * 1024;

/// Ultimi `max` byte del file (la prima riga, probabilmente tagliata, si scarta).
#[cfg(target_os = "linux")]
fn read_tail(path: &str, max: u64) -> std::io::Result<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    let start = len.saturating_sub(max);
    f.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    f.take(max).read_to_end(&mut buf)?;
    let text = String::from_utf8_lossy(&buf).into_owned();
    if start == 0 {
        return Ok(text);
    }
    Ok(text.split_once('\n').map(|(_, rest)| rest.to_string()).unwrap_or_default())
}

// ─────────────────────────────────────────────────────────────────────────────
// Analisi accessi SSH falliti — brute force
// ─────────────────────────────────────────────────────────────────────────────

/// Solo i tentativi falliti degli ultimi 10 minuti contano. Prima si
/// contavano le ultime 1000 righe del log a qualunque età: un amministratore
/// che sbagliava la password in giorni diversi finiva comunque bloccato.
const BRUTEFORCE_WINDOW_SECS: i64 = 600;

/// Tetto di righe lette dal journal per scansione (memoria limitata anche
/// sotto un brute-force molto rumoroso).
#[cfg(target_os = "linux")]
const JOURNAL_MAX_LINES: &str = "5000";

/// Da OpenSSH 9.8 l'autenticazione la fa `sshd-session` (Debian 13): i
/// messaggi arrivano con quell'identificativo, non più con `sshd`.
#[cfg(target_os = "linux")]
const SSHD_JOURNAL_MATCHES: [&str; 2] = ["SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session"];

#[cfg(target_os = "linux")]
const AUTH_LOG_PATHS: [&str; 2] = ["/var/log/auth.log", "/var/log/secure"];

#[cfg(target_os = "linux")]
fn scan_auth_log_sync(min_attempts: u32, score_per_attempt: u32) -> Vec<ThreatEntry> {
    let lines = recent_sshd_lines(chrono::Local::now());
    let failures = count_auth_failures(lines.iter().map(String::as_str));
    threats_from_failures(failures, min_attempts, score_per_attempt)
}

/// Righe di sshd recenti: prima il journal, che è l'unica fonte su Debian 13
/// e sulle distro senza rsyslog (prima il rilevamento lì era cieco); se il
/// journal non c'è o è vuoto, auth.log/secure filtrati per età.
#[cfg(target_os = "linux")]
fn recent_sshd_lines(now: chrono::DateTime<chrono::Local>) -> Vec<String> {
    if let Some(lines) = journal_sshd_lines() {
        if !lines.is_empty() {
            return lines;
        }
    }
    for path in AUTH_LOG_PATHS {
        if let Ok(content) = read_tail(path, AUTH_LOG_TAIL_BYTES) {
            return content
                .lines()
                .filter(|line| syslog_line_is_recent(line, now))
                .map(str::to_string)
                .collect();
        }
    }
    Vec::new()
}

/// `None` se journalctl manca o fallisce: si passa ai file.
#[cfg(target_os = "linux")]
fn journal_sshd_lines() -> Option<Vec<String>> {
    let since = format!("-{BRUTEFORCE_WINDOW_SECS}s");
    let output = std::process::Command::new("journalctl")
        .args(["--no-pager", "-q", "-o", "cat", "--since", &since, "-n", JOURNAL_MAX_LINES])
        .args(SSHD_JOURNAL_MATCHES)
        .output()
        .ok()?;
    if !output.status.success() {
        warn!("journalctl ha fallito ({}): uso auth.log/secure", output.status);
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).lines().map(str::to_string).collect())
}

/// Età di una riga di auth.log/secure: timestamp RFC 3339 (rsyslog recente)
/// o classico `Nov 16 15:06:37` (senza anno: quello corrente, o il
/// precedente se cadrebbe nel futuro, a cavallo di capodanno). Una riga con
/// un formato non riconosciuto resta: meglio un falso positivo che perdere
/// un attacco per un formato di log diverso.
fn syslog_line_is_recent(line: &str, now: chrono::DateTime<chrono::Local>) -> bool {
    use chrono::{Datelike, Duration, NaiveDateTime, TimeZone};
    let window = Duration::seconds(BRUTEFORCE_WINDOW_SECS);
    let first = line.split_whitespace().next().unwrap_or("");
    if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(first) {
        return now.signed_duration_since(ts) <= window;
    }
    let Some(prefix) = line.get(..15) else { return true };
    let parse = |year: i32| {
        NaiveDateTime::parse_from_str(&format!("{year} {prefix}"), "%Y %b %e %H:%M:%S")
            .ok()
            .and_then(|naive| chrono::Local.from_local_datetime(&naive).earliest())
    };
    let Some(mut ts) = parse(now.year()) else { return true };
    if ts > now + Duration::days(1) {
        match parse(now.year() - 1) {
            Some(previous) => ts = previous,
            None => return true,
        }
    }
    now.signed_duration_since(ts) <= window
}

/// Tentativi falliti per IP. sshd scrive per un utente inesistente sia
/// "Invalid user X from IP port P" sia "Failed password for invalid user X
/// from IP port P": prima contavano entrambe, cioè ogni tentativo valeva
/// doppio. Ora ogni "Failed password" conta uno; un "Invalid user" conta
/// solo se su quella connessione non c'è stato nessun tentativo di password
/// (es. server con sole chiavi).
fn count_auth_failures<'a>(lines: impl Iterator<Item = &'a str>) -> HashMap<String, u32> {
    let mut failures: HashMap<String, u32> = HashMap::new();
    let mut invalid_user_conns: HashSet<(String, String)> = HashSet::new();
    let mut password_conns: HashSet<(String, String)> = HashSet::new();

    for line in lines {
        let failed_password = line.contains("Failed password");
        if !failed_password && !line.contains("Invalid user") {
            continue;
        }
        let Some((ip, port)) = extract_ip_port_from_log(line) else { continue };
        if failed_password {
            *failures.entry(ip.clone()).or_default() += 1;
            password_conns.insert((ip, port));
        } else {
            invalid_user_conns.insert((ip, port));
        }
    }
    for (ip, _) in invalid_user_conns.difference(&password_conns) {
        *failures.entry(ip.clone()).or_default() += 1;
    }
    failures
}

fn threats_from_failures(
    failures: HashMap<String, u32>,
    min_attempts: u32,
    score_per_attempt: u32,
) -> Vec<ThreatEntry> {
    failures
        .into_iter()
        .filter(|(_, count)| *count >= min_attempts)
        .map(|(ip, count)| {
            let score = count.saturating_mul(score_per_attempt).min(100);
            let classification = crate::protocol::firedog::classify_score(score);
            ThreatEntry {
                description: format!(
                    "Brute force ssh da {ip} — {count} tentativi in 10 minuti ({classification})"
                ),
                src_ip: ip,
                dst_ip: None,
                dst_port: Some(22),
                protocol: "tcp".to_string(),
                threat_type: ThreatType::BruteForce,
                score,
                timestamp: chrono::Utc::now().to_rfc3339(),
                auto_blocked: false,
            }
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn scan_connections_sync(min_connections: u32, score_per_conn: u32) -> Vec<ThreatEntry> {
    use std::collections::HashMap;
    // Legge /proc/net/tcp per rilevare IP con molte connessioni SYN_RECV
    // (indicativo di SYN flood)
    let mut syn_count: HashMap<String, u32> = HashMap::new();
    let mut threats = Vec::new();

    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 { continue; }

            // State 03 = SYN_RECV
            if parts[3] == "03" {
                let remote = parts[2];
                if let Some(ip) = parse_proc_ip(remote) {
                    *syn_count.entry(ip).or_insert(0) += 1;
                }
            }
        }
    }

    for (ip, count) in syn_count {
        if count >= min_connections {
            let score = (count * score_per_conn).min(100);
            threats.push(ThreatEntry {
                src_ip: ip.clone(),
                dst_ip: None,
                dst_port: None,
                protocol: "tcp".to_string(),
                threat_type: ThreatType::SynFlood,
                score,
                description: format!(
                    "SYN flood potenziale da {ip} — {count} SYN_RECV attivi"
                ),
                timestamp: chrono::Utc::now().to_rfc3339(),
                auto_blocked: false,
            });
        }
    }

    threats
}

/// IP sorgente di una riga sshd ("... from 203.0.113.5 port 4444 ssh2").
///
/// Si prende solo il `from <ip> port <n>` in CODA alla riga: lo username è
/// scelto dal client e finisce nel log prima di quel suffisso, quindi con
/// `ssh 'x from 10.0.0.1 port 1'@host` il primo " from " della riga è un IP
/// deciso dall'attaccante — prima veniva preso quello, e l'auto-block poteva
/// essere usato per far bloccare il master o il gateway (seconda review
/// 2026-11). Supporta anche IPv6.
#[cfg(test)]
fn extract_ip_from_log(line: &str) -> Option<String> {
    extract_ip_port_from_log(line).map(|(ip, _)| ip)
}

/// IP e porta sorgente dal suffisso `from <ip> port <n>`: la porta
/// distingue le connessioni (vedi count_auth_failures).
fn extract_ip_port_from_log(line: &str) -> Option<(String, String)> {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r" from (\S+) port (\d+)(?: ssh2)?(?: \[preauth\])?\s*$")
            .expect("regex statica")
    });
    let caps = re.captures(line)?;
    let ip = caps.get(1)?.as_str().parse::<IpAddr>().ok()?.to_string();
    Some((ip, caps.get(2)?.as_str().to_string()))
}

#[cfg(target_os = "linux")]
fn parse_proc_ip(hex: &str) -> Option<String> {
    let parts: Vec<&str> = hex.splitn(2, ':').collect();
    if parts.len() != 2 { return None; }
    match parts[0].len() {
        // /proc/net/tcp: 8 char hex, un u32 little-endian.
        8 => {
            let n = u32::from_str_radix(parts[0], 16).ok()?;
            let b = n.to_le_bytes();
            Some(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]))
        }
        // /proc/net/tcp6: 32 char hex — prima di questo fix ogni riga IPv6
        // falliva qui silenziosamente, azzerando la detection SYN-flood su
        // IPv6 senza alcun log (MEDIUM trovato in code review, 2026-11).
        32 => parse_proc_ipv6(parts[0]),
        _ => None,
    }
}

/// `/proc/net/tcp6`: 4 parole da 32 bit, ciascuna in ordine little-endian
/// (stessa convenzione del caso IPv4 sopra, applicata a ognuna delle 4
/// parole che compongono l'indirizzo a 128 bit).
#[cfg(target_os = "linux")]
fn parse_proc_ipv6(hex: &str) -> Option<String> {
    if hex.len() != 32 { return None; }
    let mut bytes = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(8).enumerate() {
        let word = u32::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
        bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    Some(std::net::Ipv6Addr::from(bytes).to_string())
}

#[cfg(test)]
mod auth_log_tests {
    use super::*;

    fn detector(never: &[&str]) -> ThreatDetector {
        ThreatDetector::new(
            ThreatScoringConfig {
                auto_block_threshold: 75,
                auto_block_enabled: true,
                bruteforce_min_attempts: 5,
                bruteforce_score_per_attempt: 10,
                synflood_min_connections: 20,
                synflood_score_per_conn: 3,
            },
            never.iter().map(|s| s.parse().unwrap()).collect(),
        )
    }

    #[test]
    fn ip_estratto_dalla_coda_della_riga() {
        let l = "sshd[1]: Failed password for root from 203.0.113.5 port 4444 ssh2";
        assert_eq!(extract_ip_from_log(l).as_deref(), Some("203.0.113.5"));
        let l = "sshd[1]: Invalid user bob from 2001:db8::7 port 50000";
        assert_eq!(extract_ip_from_log(l).as_deref(), Some("2001:db8::7"));
    }

    #[test]
    fn username_con_from_iniettato_non_sposta_l_ip() {
        // Regressione (seconda review, 2026-11): lo username è controllato
        // dal client; prima veniva preso il PRIMO " from " della riga.
        let l = "sshd[1]: Invalid user x from 10.0.0.1 port 1 from 203.0.113.5 port 4444";
        assert_eq!(extract_ip_from_log(l).as_deref(), Some("203.0.113.5"));
        let l = "sshd[1]: Invalid user x from 10.0.0.1 port 1";
        // Se il suffisso reale manca (riga troncata/anomala) l'unico match
        // in coda è comunque quello: resta il controllo never_block sotto.
        assert_eq!(extract_ip_from_log(l).as_deref(), Some("10.0.0.1"));
        assert_eq!(extract_ip_from_log("Failed password for root from host.example port 22"), None);
    }

    // Righe reali del journal di Debian 13 (OpenSSH 10, sshd-session),
    // lab-client1 2026-11-16, un solo tentativo verso un utente inesistente.
    const INVALID_USER_ATTEMPT: [&str; 3] = [
        "Invalid user utentenonesiste from 192.168.57.1 port 40040",
        "Failed password for invalid user utentenonesiste from 192.168.57.1 port 40040 ssh2",
        "Connection closed by invalid user utentenonesiste 192.168.57.1 port 40040 [preauth]",
    ];

    #[test]
    fn utente_inesistente_conta_un_tentativo_non_due() {
        // Regressione (review 2026-11-16): "Invalid user" + "Failed password"
        // della stessa connessione venivano contati come due tentativi.
        let counts = count_auth_failures(INVALID_USER_ATTEMPT.into_iter());
        assert_eq!(counts.get("192.168.57.1"), Some(&1));
    }

    #[test]
    fn ogni_password_sbagliata_conta() {
        let lines = [
            "Failed password for root from 203.0.113.5 port 4444 ssh2",
            "Failed password for root from 203.0.113.5 port 4444 ssh2",
            "Failed password for root from 203.0.113.5 port 4445 ssh2",
        ];
        assert_eq!(count_auth_failures(lines.into_iter()).get("203.0.113.5"), Some(&3));
    }

    #[test]
    fn utente_inesistente_senza_password_conta_uno() {
        // Server con sole chiavi: nessun "Failed password", la connessione
        // verso un utente inesistente è comunque un tentativo.
        let lines = ["Invalid user admin from 198.51.100.9 port 5000 [preauth]"];
        assert_eq!(count_auth_failures(lines.into_iter()).get("198.51.100.9"), Some(&1));
    }

    #[test]
    fn soglia_e_score_della_minaccia() {
        let failures = HashMap::from([("203.0.113.5".to_string(), 13), ("198.51.100.9".to_string(), 3)]);
        let threats = threats_from_failures(failures, 4, 7);
        assert_eq!(threats.len(), 1, "3 tentativi sono sotto la soglia di 4");
        assert_eq!(threats[0].src_ip, "203.0.113.5");
        assert_eq!(threats[0].score, 91);
        assert_eq!(threats[0].dst_port, Some(22));
        let capped = threats_from_failures(HashMap::from([("203.0.113.5".to_string(), 1000)]), 4, 7);
        assert_eq!(capped[0].score, 100);
    }

    #[test]
    fn righe_di_auth_log_filtrate_per_eta() {
        use chrono::TimeZone;
        let now = chrono::Local.with_ymd_and_hms(2026, 11, 16, 15, 10, 0).unwrap();
        let line_at = |t: chrono::DateTime<chrono::Local>| {
            format!("{} lab sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2", t.to_rfc3339())
        };
        assert!(syslog_line_is_recent(&line_at(now - chrono::Duration::minutes(3)), now));
        assert!(!syslog_line_is_recent(&line_at(now - chrono::Duration::hours(2)), now));
        // Formato classico, giorno su una cifra con doppio spazio.
        assert!(syslog_line_is_recent("Nov 16 15:05:00 lab sshd[1]: Failed password", now));
        assert!(!syslog_line_is_recent("Nov  6 15:05:00 lab sshd[1]: Failed password", now));
        // 31 dicembre letto il 1° gennaio: anno precedente, non futuro.
        let new_year = chrono::Local.with_ymd_and_hms(2027, 1, 1, 0, 3, 0).unwrap();
        assert!(syslog_line_is_recent("Dec 31 23:59:00 lab sshd[1]: Failed password", new_year));
        // Formato sconosciuto: la riga resta (meglio non perdere un attacco).
        assert!(syslog_line_is_recent("formato strano", now));
    }

    #[test]
    fn ip_protetti_mai_bloccati() {
        let d = detector(&["192.0.2.10"]);
        for ip in ["127.0.0.1", "::1", "0.0.0.0", "224.0.0.1", "192.0.2.10", "non-un-ip"] {
            assert!(d.is_never_blocked(ip), "{ip} doveva essere protetto");
        }
        assert!(!d.is_never_blocked("203.0.113.5"));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod proc_ip_tests {
    use super::parse_proc_ip;

    #[test]
    fn ipv4_formato_proc_net_tcp() {
        // 0100007F:0050 = 127.0.0.1:80 (little-endian, come /proc/net/tcp)
        assert_eq!(parse_proc_ip("0100007F:0050"), Some("127.0.0.1".to_string()));
    }

    #[test]
    fn ipv6_formato_proc_net_tcp6_non_e_piu_scartato() {
        // Regressione: prima del fix ogni riga di /proc/net/tcp6 falliva il
        // parse (richiedeva esattamente 8 char hex) e veniva scartata in
        // silenzio, azzerando la detection SYN-flood su IPv6.
        // ::1 = 00000000000000000000000001000000
        assert_eq!(parse_proc_ip("00000000000000000000000001000000:0050"), Some("::1".to_string()));
    }

    #[test]
    fn formato_non_riconosciuto_torna_none_non_panica() {
        assert_eq!(parse_proc_ip("ABC:0050"), None);
        assert_eq!(parse_proc_ip("senza-due-punti"), None);
    }
}
