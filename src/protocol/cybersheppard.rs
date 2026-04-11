/// Protocollo WebSocket CyberSheppard — tipi di messaggio Agent ↔ Server.
///
/// Flusso:
///   1. Agent si connette e invia `Auth`
///   2. Server risponde con `AuthAck` (success=true)
///   3. Agent invia batch di metriche compresse (`Metrics`) ogni send_interval
///   4. Server può inviare comandi (`Command`), l'agent risponde (`CommandResponse`)

use serde::{Deserialize, Serialize};
use crate::compression::CompressedPayload;

// ─────────────────────────────────────────────────────────────────────────────
// Messaggi Agent → Server
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(tag = "msg_type", rename_all = "snake_case")]
pub enum AgentMessage {
    /// Autenticazione iniziale
    Auth {
        target_id: i32,
        timestamp: i64,
        payload: AuthPayload,
    },

    /// Batch di metriche compresse con Zstd
    Metrics {
        target_id: i32,
        timestamp: i64,
        payload: CompressedPayload,
    },

    /// Risposta a un comando del server
    CommandResponse {
        target_id: i32,
        timestamp: i64,
        payload: CommandResponsePayload,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Messaggi Server → Agent
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(tag = "msg_type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// Conferma autenticazione
    AuthAck {
        success: bool,
        #[serde(default)]
        message: Option<String>,
    },

    /// Comando da eseguire
    Command {
        target_id: i32,
        timestamp: i64,
        payload: CommandPayload,
    },

    /// Conferma ricezione metriche
    MetricsAck,
}

// ─────────────────────────────────────────────────────────────────────────────
// Payload
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct AuthPayload {
    pub auth_token: String,
    pub agent_version: String,
    pub hostname: String,
}

#[derive(Debug, Deserialize)]
pub struct CommandPayload {
    pub command_id: String,
    pub action: String,
    pub params: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct CommandResponsePayload {
    pub command_id: String,
    pub success: bool,
    pub output: Option<String>,
    pub error: Option<String>,
}
