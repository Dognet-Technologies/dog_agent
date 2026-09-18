use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::PathBuf;

// ─────────────────────────────────────────────────────────────────────────────
// Configurazione globale
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub agent: AgentSettings,

    pub targets: Vec<TargetConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentSettings {
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

impl Default for AgentSettings {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tipo di sistema backend
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SystemType {
    Firedog,
    Cybersheppard,
    Sentinelcore,
}

impl std::fmt::Display for SystemType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SystemType::Firedog => write!(f, "firedog"),
            SystemType::Cybersheppard => write!(f, "cybersheppard"),
            SystemType::Sentinelcore => write!(f, "sentinelcore"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Configurazione per ogni target
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct TargetConfig {
    /// Nome descrittivo del target (usato nei log)
    pub name: String,

    /// Sistema backend a cui connettersi
    pub system_type: SystemType,

    /// URL WebSocket del backend (es. wss://firedog.example.com)
    pub url: String,

    /// API key o auth token
    pub api_key: String,

    // ── FireDog ──────────────────────────────────────────────────────────────

    /// IP della macchina (fase 2 pairing: SHA512(ip+hostname+mac))
    pub ip: Option<String>,

    /// Hostname della macchina (fase 2 pairing)
    pub hostname: Option<String>,

    /// MAC address della macchina (fase 2 pairing)
    pub mac: Option<String>,

    /// Intervallo heartbeat in secondi (default: 30)
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval: u64,

    /// Blocco automatico locale quando score >= threat_threshold
    #[serde(default = "default_true")]
    pub auto_block_threats: bool,

    /// Soglia di score per blocco automatico (default: 75)
    #[serde(default = "default_threat_threshold")]
    pub threat_threshold: u32,

    /// Path monitorati per integrità file
    #[serde(default)]
    pub integrity_paths: Vec<String>,

    // ── CyberSheppard ─────────────────────────────────────────────────────────

    /// ID target assegnato dal backend CyberSheppard
    pub target_id: Option<i32>,

    /// Intervallo raccolta metriche in secondi (default: 30)
    #[serde(default = "default_collection_interval")]
    pub collection_interval: u64,

    /// Intervallo invio buffer metriche in secondi (default: 10)
    #[serde(default = "default_send_interval")]
    pub send_interval: u64,

    /// Livello compressione Zstd 1-22 (default: 3)
    #[serde(default = "default_compression_level")]
    pub compression_level: i32,

    /// Dimensione massima buffer prima del flush forzato (default: 10)
    #[serde(default = "default_max_buffer_size")]
    pub max_buffer_size: usize,

    /// Collector abilitati per CyberSheppard
    #[serde(default)]
    pub collectors: CollectorsConfig,

    /// Percorso del file JSON prodotto da Laurel (plugin auditd) sul target.
    /// Se impostato, l'agent lo tail-a e inoltra gli eventi arricchiti al server
    /// come `SecurityEvents`. Se `None`, l'inoltro eventi è disattivato.
    #[serde(default)]
    pub laurel_log_path: Option<String>,

    // ── Condiviso ─────────────────────────────────────────────────────────────

    /// Impostazioni di reconnessione con backoff esponenziale
    #[serde(default)]
    pub reconnect: ReconnectConfig,
}

impl TargetConfig {
    /// Restituisce l'URL WebSocket completo per il sistema configurato
    pub fn ws_url(&self) -> String {
        let base = self
            .url
            .replace("https://", "wss://")
            .replace("http://", "ws://");
        let base = base.trim_end_matches('/');

        match self.system_type {
            SystemType::Firedog => format!("{}/ws/agent/", base),
            SystemType::Cybersheppard => format!("{}/api/agents/ws", base),
            SystemType::Sentinelcore => format!("{}/ws/agent/", base),
        }
    }

    fn validate(&self) -> Result<()> {
        if self.url.is_empty() {
            anyhow::bail!("Target '{}': url non può essere vuoto", self.name);
        }
        if self.api_key.is_empty() {
            anyhow::bail!("Target '{}': api_key non può essere vuota", self.name);
        }

        match self.system_type {
            SystemType::Firedog => {
                if self.ip.is_none() {
                    anyhow::bail!("Target '{}' (firedog): ip è obbligatorio", self.name);
                }
                if self.hostname.is_none() {
                    anyhow::bail!(
                        "Target '{}' (firedog): hostname è obbligatorio",
                        self.name
                    );
                }
                if self.mac.is_none() {
                    anyhow::bail!("Target '{}' (firedog): mac è obbligatorio", self.name);
                }
            }
            SystemType::Cybersheppard => {
                if self.target_id.is_none() {
                    anyhow::bail!(
                        "Target '{}' (cybersheppard): target_id è obbligatorio",
                        self.name
                    );
                }
                if self.compression_level < 1 || self.compression_level > 22 {
                    anyhow::bail!(
                        "Target '{}' (cybersheppard): compression_level deve essere 1-22",
                        self.name
                    );
                }
            }
            SystemType::Sentinelcore => {
                // placeholder — nessuna validazione specifica per ora
            }
        }

        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Collector config (CyberSheppard)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct CollectorsConfig {
    #[serde(default = "default_true")]
    pub system: bool,
    #[serde(default = "default_true")]
    pub network: bool,
    #[serde(default = "default_true")]
    pub users: bool,
    #[serde(default = "default_true")]
    pub files: bool,
    #[serde(default = "default_true")]
    pub services: bool,
    #[serde(default = "default_true")]
    pub auditd: bool,
    #[serde(default = "default_true")]
    pub docker: bool,
}

impl Default for CollectorsConfig {
    fn default() -> Self {
        Self {
            system: true,
            network: true,
            users: true,
            files: true,
            services: true,
            auditd: true,
            docker: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Reconnect config
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct ReconnectConfig {
    /// Intervallo (secondi) tra i tentativi del livello veloce — usato subito
    /// dopo un avvio o dopo una sessione stabile (vedi `reconnect.rs`).
    #[serde(default = "default_fast_backoff_secs")]
    pub fast_backoff_secs: u64,
    /// Quanti tentativi al livello veloce prima di passare al livello lento.
    #[serde(default = "default_fast_max_attempts")]
    pub fast_max_attempts: u32,
    /// Intervallo (secondi) tra i tentativi del livello lento, quando il
    /// livello veloce si esaurisce senza riuscire a riconnettersi (server
    /// presumibilmente giù per un periodo prolungato).
    #[serde(default = "default_slow_backoff_secs")]
    pub slow_backoff_secs: u64,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            fast_backoff_secs: default_fast_backoff_secs(),
            fast_max_attempts: default_fast_max_attempts(),
            slow_backoff_secs: default_slow_backoff_secs(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Caricamento config
// ─────────────────────────────────────────────────────────────────────────────

impl Config {
    pub fn load(path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Impossibile leggere il file di config: {}", path.display()))?;

        let config: Config =
            toml::from_str(&content).context("Errore nel parsing del file di config")?;

        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.targets.is_empty() {
            anyhow::bail!("Nessun [[targets]] definito nella configurazione");
        }
        for target in &self.targets {
            target.validate()?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Default values
// ─────────────────────────────────────────────────────────────────────────────

fn default_heartbeat_interval() -> u64 { 30 }
fn default_collection_interval() -> u64 { 30 }
fn default_send_interval() -> u64 { 10 }
fn default_compression_level() -> i32 { 3 }
fn default_max_buffer_size() -> usize { 10 }
fn default_threat_threshold() -> u32 { 75 }
fn default_fast_backoff_secs() -> u64 { 5 }
fn default_fast_max_attempts() -> u32 { 20 }
fn default_slow_backoff_secs() -> u64 { 1800 }
fn default_true() -> bool { true }
