/// Protocollo WebSocket FireDog — tipi di messaggio Agent ↔ Server.
///
/// Ogni messaggio è JSON con campo `"type"` come discriminante.
///
/// Flusso:
///   1. Agent invia `pair_request`
///   2. Server risponde con `pairing_status` (fase 1 + fase 2)
///   3. Agent entra nel loop: heartbeat ogni 30s, threat_log on-demand
///   4. Server invia `command`, agent risponde con `command_response`

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Messaggi Agent → Server
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentMessage {
    /// Fase 1 & 2 del pairing: invia api_key + identità macchina
    PairRequest {
        api_key: String,
        ip: String,
        hostname: String,
        mac: String,
    },

    /// Heartbeat periodico con statistiche di sistema
    Heartbeat {
        timestamp: String,
        system_stats: SystemStats,
    },

    /// Log minacce rilevate localmente
    ThreatLog { threats: Vec<ThreatEntry> },

    /// Snapshot completo firewall+system prodotto da `firewall-manager --export-json`.
    /// Il payload è il JSON grezzo del comando (vedi FirewallStats sul server).
    FirewallStats {
        timestamp: String,
        payload: serde_json::Value,
    },

    /// Risposta a un comando ricevuto dal server
    CommandResponse {
        command_id: String,
        status: CommandStatus,
        #[serde(skip_serializing_if = "Option::is_none")]
        output: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Messaggi Server → Agent
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// Risultato del pairing (fase 1 e/o fase 2)
    PairingStatus {
        /// "success" | "failed" | "verifying" | "expired"
        status: String,
        // Nei messaggi di fallimento il server omette i flag di fase e mette
        // il motivo nel campo `error` — tutti i campi devono essere opzionali
        // o il messaggio non viene parsato e il pairing muore in timeout.
        #[serde(default)]
        phase_1_verified: bool,
        #[serde(default)]
        phase_2_verified: bool,
        #[serde(default)]
        target_id: Option<i32>,
        #[serde(default, alias = "error")]
        message: Option<String>,
    },

    /// Conferma ricezione heartbeat
    HeartbeatAck,

    /// Conferma ricezione threat log
    ThreatAck,

    /// Conferma ricezione snapshot firewall_stats
    FirewallStatsAck,

    /// Errore generico inviato dal server (es. payload malformato, non paired, ecc.)
    Error { message: String },

    /// Comando da eseguire sull'agent
    Command {
        command_id: String,
        action: CommandAction,
        payload: serde_json::Value,
    },

    /// Aggiornamento configurazione agent
    Config { config: serde_json::Value },
}

// ─────────────────────────────────────────────────────────────────────────────
// Tipi condivisi
// ─────────────────────────────────────────────────────────────────────────────

/// Statistiche di sistema inviate nell'heartbeat
#[derive(Debug, Serialize, Deserialize)]
pub struct SystemStats {
    pub cpu_percent: f32,
    pub memory_percent: f32,
    pub disk_percent: f32,
    // Valori assoluti in KB — il server li persiste come colonne dedicate
    // così la UI non deve più derivare "Memory MB" dal solo percent.
    pub memory_total_kb: u64,
    pub memory_used_kb: u64,
    pub disk_total_kb: u64,
    pub disk_used_kb: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub active_rules_count: u32,
    pub blocked_ips_count: u32,
    pub load_avg: [f64; 3],
    pub uptime_seconds: u64,
}

/// Singola minaccia rilevata localmente
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ThreatEntry {
    pub src_ip: String,
    pub dst_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub protocol: String,
    pub threat_type: ThreatType,
    pub score: u32,
    pub description: String,
    pub timestamp: String,
    pub auto_blocked: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ThreatType {
    SynFlood,
    PortScan,
    BruteForce,
    UnknownTraffic,
}

impl std::fmt::Display for ThreatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatType::SynFlood => write!(f, "SYN_FLOOD"),
            ThreatType::PortScan => write!(f, "PORT_SCAN"),
            ThreatType::BruteForce => write!(f, "BRUTE_FORCE"),
            ThreatType::UnknownTraffic => write!(f, "UNKNOWN_TRAFFIC"),
        }
    }
}

/// Classificazione per score
pub fn classify_score(score: u32) -> &'static str {
    match score {
        80.. => "CRITICAL",
        60..=79 => "HIGH",
        40..=59 => "MEDIUM",
        20..=39 => "LOW",
        _ => "INFO",
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CommandStatus {
    Success,
    Failed,
    Timeout,
}

/// Azioni supportate dai comandi FireDog
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum CommandAction {
    AddRule,
    RemoveRule,
    SyncRules,
    BlockIp,
    UnblockIp,
    UpdateConfig,
    CheckIntegrity,
    #[serde(other)]
    Unknown,
}

// ─────────────────────────────────────────────────────────────────────────────
// Payload strutturati per i comandi
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AddRulePayload {
    pub chain: String,              // INPUT | OUTPUT | FORWARD
    pub protocol: Option<String>,   // tcp | udp | icmp
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub action: String,             // DROP | REJECT | ACCEPT | LOG
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RemoveRulePayload {
    pub chain: String,
    pub rule_num: Option<u32>,      // numero regola (iptables -D CHAIN N)
    pub protocol: Option<String>,
    pub src_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub action: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BlockIpPayload {
    pub ip: String,
    #[serde(default = "default_input")]
    pub direction: String,  // INPUT | OUTPUT | BOTH
}

fn default_input() -> String { "INPUT".to_string() }

#[derive(Debug, Deserialize)]
pub struct CheckIntegrityPayload {
    pub paths: Option<Vec<String>>,
}
