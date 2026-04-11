use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsersMetrics {
    pub system_users: Vec<SystemUser>,
    pub logged_in: Vec<LoggedInUser>,
    pub sudo_users: Vec<String>,
    pub root_login_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemUser {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggedInUser {
    pub username: String,
    pub tty: String,
    pub from_host: Option<String>,
    pub login_time: String,
}

pub async fn collect() -> Result<UsersMetrics> {
    tokio::task::spawn_blocking(collect_sync)
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking error: {}", e))?
}

fn collect_sync() -> Result<UsersMetrics> {
    let system_users = read_passwd();
    let sudo_users = read_sudo_users(&system_users);
    let logged_in = read_logged_in();
    let root_login_enabled = check_root_login();

    Ok(UsersMetrics {
        system_users,
        logged_in,
        sudo_users,
        root_login_enabled,
    })
}

fn read_passwd() -> Vec<SystemUser> {
    let mut users = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
            for line in content.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() < 7 {
                    continue;
                }
                let uid: u32 = parts[2].parse().unwrap_or(0);
                let gid: u32 = parts[3].parse().unwrap_or(0);

                users.push(SystemUser {
                    username: parts[0].to_string(),
                    uid,
                    gid,
                    home: parts[5].to_string(),
                    shell: parts[6].to_string(),
                    groups: vec![],
                });
            }
        }
    }

    users
}

fn read_sudo_users(_users: &[SystemUser]) -> Vec<String> {
    let mut sudo = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Utenti nel gruppo sudo/wheel
        if let Ok(content) = std::fs::read_to_string("/etc/group") {
            for line in content.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() < 4 {
                    continue;
                }
                let group_name = parts[0];
                if group_name == "sudo" || group_name == "wheel" || group_name == "admin" {
                    for member in parts[3].split(',') {
                        let m = member.trim();
                        if !m.is_empty() {
                            sudo.push(m.to_string());
                        }
                    }
                }
            }
        }
    }

    sudo
}

fn read_logged_in() -> Vec<LoggedInUser> {
    let mut logged = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Usa 'who' se disponibile
        if let Ok(output) = std::process::Command::new("who").output() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    logged.push(LoggedInUser {
                        username: parts[0].to_string(),
                        tty: parts[1].to_string(),
                        from_host: if parts.len() >= 5 {
                            Some(parts[4].trim_matches(|c| c == '(' || c == ')').to_string())
                        } else {
                            None
                        },
                        login_time: if parts.len() >= 4 {
                            format!("{} {}", parts[2], parts[3])
                        } else {
                            String::new()
                        },
                    });
                }
            }
        }
    }

    logged
}

fn check_root_login() -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/etc/ssh/sshd_config") {
            for line in content.lines() {
                let line = line.trim();
                if line.starts_with("PermitRootLogin") {
                    return !line.contains("no");
                }
            }
        }
        // Default: root login abilitato se non esplicitamente disabilitato
        return true;
    }

    #[cfg(not(target_os = "linux"))]
    false
}
