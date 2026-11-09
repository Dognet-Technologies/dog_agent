use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::PathBuf;

fn default_config_path() -> PathBuf {
    PathBuf::new()
}

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

    /// Certificato (PEM) della Root CA Dognet con cui sono firmati i certificati
    /// dei master. Se impostato, l'agent verifica il certificato del server
    /// contro questa CA su `wss://` (nessun MITM). Se assente, i certificati
    /// self-signed sono accettati senza verifica, con un warning all'avvio
    /// (comportamento legacy, solo LAN fidata).
    #[serde(default)]
    pub ca_cert: Option<PathBuf>,
}

impl Default for AgentSettings {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            ca_cert: None,
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
    // Il vecchio nome resta valido: gli agent.conf gia' installati lo usano.
    #[serde(alias = "cybersheppard")]
    Cybershepherd,
    Sentinelcore,
}

impl std::fmt::Display for SystemType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SystemType::Firedog => write!(f, "firedog"),
            SystemType::Cybershepherd => write!(f, "cybershepherd"),
            SystemType::Sentinelcore => write!(f, "sentinelcore"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Ambiente del target (produzione / clone di test)
// ─────────────────────────────────────────────────────────────────────────────

/// Ruolo di questo target nel ciclo di vita del deployment. Puramente
/// informativo: non altera alcun comportamento dell'agent, nessun campo
/// viene inviato ai backend. Serve a chi configura `linked_environments` su
/// un device SentinelCore (vedi
/// vulnerability-manager/migrations/159_device_linked_environments.sql) a
/// sapere a colpo d'occhio, leggendo agent.conf del target, se questa
/// istanza è il clone di testing/preproduzione o l'originale di produzione.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum AgentEnvironment {
    #[default]
    Production,
    Testing,
    Preproduction,
}


impl std::fmt::Display for AgentEnvironment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentEnvironment::Production => write!(f, "production"),
            AgentEnvironment::Testing => write!(f, "testing"),
            AgentEnvironment::Preproduction => write!(f, "preproduction"),
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

    /// Formula threat-score, configurabile (vedi src/threat/mod.rs). Default
    /// pari alle costanti storiche pre-v1.1.0, TRANNE dove indicato: gli
    /// utenti che aggiornano l'agent senza toccare agent.conf ereditano il
    /// comportamento ricalibrato, non quello originale — i default originali
    /// (5 tentativi/×10, 20 connessioni/×3) erano troppo aggressivi: un
    /// admin che sbaglia la password SSH ~8 volte finiva già in auto-block
    /// con threat_threshold=75.
    #[serde(default = "default_bruteforce_min_attempts")]
    pub bruteforce_min_attempts: u32,
    #[serde(default = "default_bruteforce_score_per_attempt")]
    pub bruteforce_score_per_attempt: u32,
    #[serde(default = "default_synflood_min_connections")]
    pub synflood_min_connections: u32,
    #[serde(default = "default_synflood_score_per_conn")]
    pub synflood_score_per_conn: u32,

    /// Path monitorati per integrità file
    #[serde(default)]
    pub integrity_paths: Vec<String>,

    // ── CyberShepherd ─────────────────────────────────────────────────────────

    /// ID target assegnato dal backend CyberShepherd
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

    /// Collector abilitati per CyberShepherd
    #[serde(default)]
    pub collectors: CollectorsConfig,

    /// Percorso del file JSON prodotto da Laurel (plugin auditd) sul target.
    /// Se impostato, l'agent lo tail-a e inoltra gli eventi arricchiti al server
    /// come `SecurityEvents`. Se `None`, l'inoltro eventi è disattivato.
    #[serde(default)]
    pub laurel_log_path: Option<String>,

    // ── Condiviso ─────────────────────────────────────────────────────────────

    /// Ruolo di questo target (production/testing/preproduction) — vedi
    /// `AgentEnvironment`. Default: production.
    #[serde(default)]
    pub environment: AgentEnvironment,

    /// Impostazioni di reconnessione con backoff esponenziale
    #[serde(default)]
    pub reconnect: ReconnectConfig,

    /// Path del file agent.conf da cui questo target è stato caricato — NON
    /// letto dal TOML (`skip`), popolato da main.rs dopo `Config::load()`.
    /// Serve a `CommandAction::UpdateConfig` (src/targets/firedog.rs) per
    /// sapere quale file riscrivere quando il server pusha una nuova
    /// configurazione threat-scoring.
    #[serde(skip, default = "default_config_path")]
    pub config_path: PathBuf,
}

impl TargetConfig {
    /// Restituisce l'URL WebSocket completo per il sistema configurato
    /// `url` in agent.conf può essere `ws://`, `wss://`, `http://` o
    /// `https://` — questi ultimi due normalizzati sullo scheme WS
    /// equivalente. Per `wss://`, la connessione (vedi `crate::ws::connect`)
    /// accetta certificati self-signed senza pinning: stessa fiducia già
    /// accettata lato browser per lo stesso certificato del master, non
    /// protegge da un MITM attivo. Aggiornare qui SE in futuro si aggiunge
    /// pinning (fingerprint del cert salvato al pairing).
    pub fn ws_url(&self) -> String {
        let base = self
            .url
            .replace("https://", "wss://")
            .replace("http://", "ws://");
        let base = base.trim_end_matches('/');

        match self.system_type {
            SystemType::Firedog => format!("{base}/ws/agent/"),
            SystemType::Cybershepherd => format!("{base}/api/agents/ws"),
            SystemType::Sentinelcore => format!("{base}/ws/agent/"),
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
            SystemType::Cybershepherd => {
                // target_id è obbligatorio SOLO sul percorso legacy ad auth-token:
                // col pairing per-identità (ip+hostname+mac tutti presenti) il
                // target viene risolto lato server dall'identity_hash — vedi
                // AgentMessage::PairRequest sopra ("target_id può essere 0,
                // ignorato") e targets/cybershepherd.rs::use_pairing. Prima di
                // questo fix la validazione lo richiedeva comunque, impedendo
                // di configurare un target nuovo (nessun target_id noto finché
                // non esiste ancora sul master) nonostante il pairing per
                // identità non ne avesse bisogno — trovato dal vivo, 2026-11-08.
                let has_identity = self.ip.as_deref().is_some_and(|v| !v.is_empty())
                    && self.hostname.as_deref().is_some_and(|v| !v.is_empty())
                    && self.mac.as_deref().is_some_and(|v| !v.is_empty());
                if self.target_id.is_none() && !has_identity {
                    anyhow::bail!(
                        "Target '{}' (cybershepherd): serve target_id oppure ip+hostname+mac (pairing per identità)",
                        self.name
                    );
                }
                if self.compression_level < 1 || self.compression_level > 22 {
                    anyhow::bail!(
                        "Target '{}' (cybershepherd): compression_level deve essere 1-22",
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
// Collector config (CyberShepherd)
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
// Ricalibrati in v1.1.0 (meno aggressivi dei valori storici 5/×10, 20/×3 —
// vedi commento su TargetConfig): 10 tentativi = score 70 (non ancora
// auto-block), 15 = 100. 35 connessioni SYN_RECV = 70, 50 = 100.
fn default_bruteforce_min_attempts() -> u32 { 10 }
fn default_bruteforce_score_per_attempt() -> u32 { 7 }
fn default_synflood_min_connections() -> u32 { 35 }
fn default_synflood_score_per_conn() -> u32 { 2 }
fn default_fast_backoff_secs() -> u64 { 5 }
fn default_fast_max_attempts() -> u32 { 20 }
fn default_slow_backoff_secs() -> u64 { 1800 }
fn default_true() -> bool { true }

#[cfg(test)]
mod system_type_tests {
    use super::SystemType;

    #[derive(serde::Deserialize)]
    struct Wrapper {
        system_type: SystemType,
    }

    fn parse(value: &str) -> SystemType {
        toml::from_str::<Wrapper>(&format!("system_type = \"{value}\""))
            .expect("system_type valido")
            .system_type
    }

    #[test]
    fn accepts_new_and_legacy_cybershepherd_names() {
        assert_eq!(parse("cybershepherd"), SystemType::Cybershepherd);
        assert_eq!(parse("cybersheppard"), SystemType::Cybershepherd);
    }
}

#[cfg(test)]
mod cybershepherd_validate_tests {
    use super::TargetConfig;

    fn target(extra: &str) -> TargetConfig {
        toml::from_str(&format!(
            "name = \"t\"\nsystem_type = \"cybershepherd\"\nurl = \"wss://x\"\napi_key = \"k\"\n{extra}"
        ))
        .expect("toml valido")
    }

    #[test]
    fn valido_con_solo_target_id() {
        assert!(target("target_id = 1").validate().is_ok());
    }

    // Regressione: prima del fix, un target configurato per il pairing per
    // identità (senza target_id, non ancora noto finché il master non crea
    // il target) veniva respinto da validate() pur essendo esattamente lo
    // scenario che AgentMessage::PairRequest supporta ("target_id può essere
    // 0, ignorato: il target è risolto per identità").
    #[test]
    fn valido_con_sola_identita_di_pairing_senza_target_id() {
        let t = target("ip = \"10.10.0.18\"\nhostname = \"h\"\nmac = \"aa:bb:cc:dd:ee:ff\"");
        assert!(t.target_id.is_none());
        assert!(t.validate().is_ok());
    }

    #[test]
    fn invalido_senza_target_id_ne_identita_completa() {
        assert!(target("").validate().is_err());
        // Identità parziale (manca mac) non basta neppure lei.
        assert!(target("ip = \"10.10.0.18\"\nhostname = \"h\"").validate().is_err());
    }
}
