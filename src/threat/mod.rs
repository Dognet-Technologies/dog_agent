//! Rilevamento minacce locale per FireDog.
//!
//! Analizza log di sistema per identificare pattern sospetti:
//! - Brute force SSH/FTP (tentativi falliti ripetuti)
//! - Port scan (molte connessioni a porte diverse dallo stesso IP)
//! - SYN flood (rilevato via /proc/net/tcp)
//!
//! Ogni minaccia riceve uno score 0-100.
//! Se score >= threshold e auto_block=true, applica blocco locale via iptables.

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
}

impl ThreatDetector {
    pub fn new(config: ThreatScoringConfig) -> Self {
        Self {
            config,
            blocked_ips: vec![],
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
                if threat.score >= self.config.auto_block_threshold
                    && !self.blocked_ips.contains(&threat.src_ip)
                {
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

    fn block_ip(&self, ip: &str) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let output = std::process::Command::new("iptables")
                .args(["-A", "INPUT", "-s", ip, "-j", "DROP"])
                .output()?;
            if !output.status.success() {
                anyhow::bail!(
                    "iptables fallito: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Analisi auth.log — brute force
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn scan_auth_log_sync(min_attempts: u32, score_per_attempt: u32) -> Vec<ThreatEntry> {
    use std::collections::HashMap;
    let mut ip_failures: HashMap<String, (u32, String)> = HashMap::new();
    let mut threats = Vec::new();

    let log_paths = ["/var/log/auth.log", "/var/log/secure"];

    for log_path in &log_paths {
        let content = match std::fs::read_to_string(log_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let lines: Vec<&str> = content.lines().collect();
        let start = lines.len().saturating_sub(1000);

        for line in &lines[start..] {
            if line.contains("Failed password") || line.contains("Invalid user") {
                if let Some(ip) = extract_ip_from_log(line) {
                    let service = if line.contains("sshd") { "ssh" } else { "unknown" };
                    let entry = ip_failures.entry(ip).or_insert((0, service.to_string()));
                    entry.0 += 1;
                }
            }
        }

        break;
    }

    for (ip, (count, service)) in ip_failures {
        if count >= min_attempts {
            let score = (count * score_per_attempt).min(100);
            let classification = crate::protocol::firedog::classify_score(score);

            threats.push(ThreatEntry {
                src_ip: ip.clone(),
                dst_ip: None,
                dst_port: Some(if service == "ssh" { 22 } else { 0 }),
                protocol: "tcp".to_string(),
                threat_type: ThreatType::BruteForce,
                score,
                description: format!(
                    "Brute force {service} da {ip} — {count} tentativi ({classification})"
                ),
                timestamp: chrono::Utc::now().to_rfc3339(),
                auto_blocked: false,
            });
        }
    }

    threats
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

fn extract_ip_from_log(line: &str) -> Option<String> {
    // "from 192.168.1.1 port"
    if let Some(pos) = line.find(" from ") {
        let rest = &line[pos + 6..];
        let ip = rest.split_whitespace().next()?;
        if is_valid_ip(ip) {
            return Some(ip.to_string());
        }
    }
    None
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

fn is_valid_ip(s: &str) -> bool {
    s.split('.').count() == 4 && s.split('.').all(|p| p.parse::<u8>().is_ok())
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
