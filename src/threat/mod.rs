/// Rilevamento minacce locale per FireDog.
///
/// Analizza log di sistema per identificare pattern sospetti:
/// - Brute force SSH/FTP (tentativi falliti ripetuti)
/// - Port scan (molte connessioni a porte diverse dallo stesso IP)
/// - SYN flood (rilevato via /proc/net/tcp)
///
/// Ogni minaccia riceve uno score 0-100.
/// Se score >= threshold e auto_block=true, applica blocco locale via iptables.

use tracing::{info, warn};

use crate::protocol::firedog::{ThreatEntry, ThreatType};

pub struct ThreatDetector {
    threshold: u32,
    auto_block: bool,
    /// IP già bloccati (evita blocchi duplicati)
    blocked_ips: Vec<String>,
}

impl ThreatDetector {
    pub fn new(threshold: u32, auto_block: bool) -> Self {
        Self {
            threshold,
            auto_block,
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
        if self.auto_block {
            for threat in &mut threats {
                if threat.score >= self.threshold && !self.blocked_ips.contains(&threat.src_ip) {
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
        tokio::task::spawn_blocking(scan_auth_log_sync)
            .await
            .unwrap_or_default()
    }

    #[cfg(target_os = "linux")]
    async fn scan_port_connections(&mut self) -> Vec<ThreatEntry> {
        tokio::task::spawn_blocking(scan_connections_sync)
            .await
            .unwrap_or_default()
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
fn scan_auth_log_sync() -> Vec<ThreatEntry> {
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
        if count >= 5 {
            // 5+ tentativi falliti → brute force
            let score = (count * 10).min(100) as u32;
            let classification = crate::protocol::firedog::classify_score(score);

            threats.push(ThreatEntry {
                src_ip: ip.clone(),
                dst_ip: None,
                dst_port: Some(if service == "ssh" { 22 } else { 0 }),
                protocol: "tcp".to_string(),
                threat_type: ThreatType::BruteForce,
                score,
                description: format!(
                    "Brute force {} da {} — {} tentativi ({})",
                    service, ip, count, classification
                ),
                timestamp: chrono::Utc::now().to_rfc3339(),
                auto_blocked: false,
            });
        }
    }

    threats
}

#[cfg(target_os = "linux")]
fn scan_connections_sync() -> Vec<ThreatEntry> {
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
        if count >= 20 {
            let score = (count * 3).min(100) as u32;
            threats.push(ThreatEntry {
                src_ip: ip.clone(),
                dst_ip: None,
                dst_port: None,
                protocol: "tcp".to_string(),
                threat_type: ThreatType::SynFlood,
                score,
                description: format!(
                    "SYN flood potenziale da {} — {} SYN_RECV attivi",
                    ip, count
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
    if parts.len() != 2 || parts[0].len() != 8 { return None; }
    let n = u32::from_str_radix(parts[0], 16).ok()?;
    let b = n.to_le_bytes();
    Some(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]))
}

fn is_valid_ip(s: &str) -> bool {
    s.split('.').count() == 4 && s.split('.').all(|p| p.parse::<u8>().is_ok())
}
