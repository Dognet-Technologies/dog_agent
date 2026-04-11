use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServicesMetrics {
    pub systemd_services: Vec<ServiceStatus>,
    pub docker_containers: Vec<ContainerStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub name: String,
    pub load_state: String,   // loaded | not-found | masked
    pub active_state: String, // active | inactive | failed | activating
    pub sub_state: String,    // running | dead | exited | ...
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerStatus {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,  // running | exited | paused | ...
    pub status: String, // "Up 2 hours" | "Exited (0) 5 minutes ago"
}

pub async fn collect() -> Result<ServicesMetrics> {
    tokio::task::spawn_blocking(collect_sync)
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking error: {}", e))?
}

fn collect_sync() -> Result<ServicesMetrics> {
    let systemd_services = collect_systemd();
    let docker_containers = collect_docker();

    Ok(ServicesMetrics {
        systemd_services,
        docker_containers,
    })
}

fn collect_systemd() -> Vec<ServiceStatus> {
    #[cfg(not(target_os = "linux"))]
    return vec![];

    #[cfg(target_os = "linux")]
    {
        let output = match std::process::Command::new("systemctl")
            .args(["list-units", "--type=service", "--no-pager", "--plain", "--no-legend"])
            .output()
        {
            Ok(o) => o,
            Err(_) => return vec![],
        };

        let text = String::from_utf8_lossy(&output.stdout);
        let mut services = Vec::new();

        for line in text.lines() {
            // Formato: "  unit.service  loaded  active  running  Description"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                continue;
            }

            services.push(ServiceStatus {
                name: parts[0].trim_end_matches(".service").to_string(),
                load_state: parts[1].to_string(),
                active_state: parts[2].to_string(),
                sub_state: parts[3].to_string(),
                description: parts[4..].join(" "),
            });
        }

        services
    }
}

fn collect_docker() -> Vec<ContainerStatus> {
    let output = match std::process::Command::new("docker")
        .args(["ps", "-a", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return vec![], // docker non installato o non raggiungibile
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut containers = Vec::new();

    for line in text.lines() {
        let parts: Vec<&str> = line.splitn(5, '\t').collect();
        if parts.len() < 5 {
            continue;
        }

        containers.push(ContainerStatus {
            id: parts[0].to_string(),
            name: parts[1].to_string(),
            image: parts[2].to_string(),
            state: parts[3].to_string(),
            status: parts[4].to_string(),
        });
    }

    containers
}
