pub mod auditd;
pub mod files;
pub mod network;
pub mod services;
pub mod system;
pub mod users;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::config::TargetConfig;

pub use auditd::AuditdMetrics;
pub use files::FilesMetrics;
pub use network::NetworkMetrics;
pub use services::ServicesMetrics;
pub use system::SystemMetrics;
pub use users::UsersMetrics;

/// Snapshot completo di tutte le metriche (CyberSheppard)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllMetrics {
    pub collected_at: i64,
    pub hostname: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<SystemMetrics>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkMetrics>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub users: Option<UsersMetrics>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<FilesMetrics>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<ServicesMetrics>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub auditd: Option<AuditdMetrics>,
}

/// Raccoglie tutte le metriche abilitate nella config
pub async fn collect_all(config: &TargetConfig) -> Result<AllMetrics> {
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let c = &config.collectors;

    // I collector vengono eseguiti in parallelo con tokio::join!
    // dove possibile; quelli che dipendono da I/O bloccante usano
    // spawn_blocking internamente.

    let sys_fut = async {
        if c.system { system::collect().await.ok() } else { None }
    };
    let net_fut = async {
        if c.network { network::collect().await.ok() } else { None }
    };
    let usr_fut = async {
        if c.users { users::collect().await.ok() } else { None }
    };
    let fil_fut = async {
        if c.files { files::collect().await.ok() } else { None }
    };
    let svc_fut = async {
        if c.services { services::collect().await.ok() } else { None }
    };
    let aud_fut = async {
        if c.auditd { auditd::collect().await.ok() } else { None }
    };

    let (system, network, users, files, services, auditd) =
        tokio::join!(sys_fut, net_fut, usr_fut, fil_fut, svc_fut, aud_fut);

    Ok(AllMetrics {
        collected_at: chrono::Utc::now().timestamp(),
        hostname,
        system,
        network,
        users,
        files,
        services,
        auditd,
    })
}
