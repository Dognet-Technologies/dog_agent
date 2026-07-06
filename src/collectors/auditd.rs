use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditdMetrics {
    pub recent_events: Vec<AuditEvent>,
    pub failed_logins: u32,
    pub sudo_usage: Vec<SudoEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: String,
    pub event_type: String,
    pub user: Option<String>,
    pub result: String, // success | failed
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SudoEvent {
    pub timestamp: String,
    pub user: String,
    pub command: String,
    pub result: String,
}

pub async fn collect() -> Result<AuditdMetrics> {
    tokio::task::spawn_blocking(collect_sync)
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking error: {}", e))?
}

fn collect_sync() -> Result<AuditdMetrics> {
    #[cfg(not(target_os = "linux"))]
    return Ok(AuditdMetrics {
        recent_events: vec![],
        failed_logins: 0,
        sudo_usage: vec![],
    });

    #[cfg(target_os = "linux")]
    {
        let (failed_logins, auth_events) = parse_auth_log();
        let sudo_usage = parse_sudo_log();

        Ok(AuditdMetrics {
            recent_events: auth_events,
            failed_logins,
            sudo_usage,
        })
    }
}

#[cfg(target_os = "linux")]
fn parse_auth_log() -> (u32, Vec<AuditEvent>) {
    let mut events = Vec::new();
    let mut failed_count = 0u32;

    // Prova /var/log/auth.log (Debian/Ubuntu) o /var/log/secure (RHEL/CentOS)
    let log_paths = ["/var/log/auth.log", "/var/log/secure"];

    for log_path in &log_paths {
        if let Ok(content) = std::fs::read_to_string(log_path) {
            // Legge solo le ultime 500 righe per evitare file enormi
            let lines: Vec<&str> = content.lines().collect();
            let start = lines.len().saturating_sub(500);

            for line in &lines[start..] {
                if line.contains("Failed password") || line.contains("authentication failure") {
                    failed_count += 1;

                    let user = extract_user(line);
                    events.push(AuditEvent {
                        timestamp: extract_timestamp(line),
                        event_type: "failed_login".to_string(),
                        user,
                        result: "failed".to_string(),
                        details: line.to_string(),
                    });
                } else if line.contains("Accepted password")
                    || line.contains("Accepted publickey")
                {
                    let user = extract_user(line);
                    events.push(AuditEvent {
                        timestamp: extract_timestamp(line),
                        event_type: "successful_login".to_string(),
                        user,
                        result: "success".to_string(),
                        details: line.to_string(),
                    });
                }

                if events.len() >= 100 {
                    break;
                }
            }

            break; // usa il primo log trovato
        }
    }

    (failed_count, events)
}

#[cfg(target_os = "linux")]
fn parse_sudo_log() -> Vec<SudoEvent> {
    let mut events = Vec::new();

    let log_paths = ["/var/log/auth.log", "/var/log/secure"];

    for log_path in &log_paths {
        if let Ok(content) = std::fs::read_to_string(log_path) {
            let lines: Vec<&str> = content.lines().collect();
            let start = lines.len().saturating_sub(500);

            for line in &lines[start..] {
                if line.contains("sudo:") && line.contains("COMMAND=") {
                    let user = extract_sudo_user(line);
                    let command = extract_sudo_command(line);
                    let result = if line.contains("TTY=") { "executed" } else { "failed" };

                    events.push(SudoEvent {
                        timestamp: extract_timestamp(line),
                        user,
                        command,
                        result: result.to_string(),
                    });

                    if events.len() >= 50 {
                        break;
                    }
                }
            }
            break;
        }
    }

    events
}

fn extract_timestamp(line: &str) -> String {
    // Formato syslog: "Apr  6 14:22:33"
    let parts: Vec<&str> = line.splitn(4, ' ').collect();
    if parts.len() >= 3 {
        format!("{} {} {}", parts[0], parts[1], parts[2])
    } else {
        String::new()
    }
}

fn extract_user(line: &str) -> Option<String> {
    // "for user xxx" o "user=xxx"
    if let Some(pos) = line.find("for user ") {
        let rest = &line[pos + 9..];
        return Some(rest.split_whitespace().next().unwrap_or("").to_string());
    }
    if let Some(pos) = line.find("user=") {
        let rest = &line[pos + 5..];
        return Some(rest.split(|c: char| !c.is_alphanumeric() && c != '_' && c != '-').next().unwrap_or("").to_string());
    }
    None
}

fn extract_sudo_user(line: &str) -> String {
    // "sudo:   username :" o "sudo: username :"
    if let Some(pos) = line.find("sudo:") {
        let rest = line[pos + 5..].trim();
        return rest.split_whitespace().next().unwrap_or("").to_string();
    }
    String::new()
}

fn extract_sudo_command(line: &str) -> String {
    if let Some(pos) = line.find("COMMAND=") {
        return line[pos + 8..].to_string();
    }
    String::new()
}
