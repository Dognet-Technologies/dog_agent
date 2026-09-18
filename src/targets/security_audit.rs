/// Esecutore lato agent del Linux-Security-Audit-Project vendorizzato (MIT,
/// vedi THIRD_PARTY_LICENSES.md alla radice del repo) — usato in **sola
/// lettura** (nessun flag di remediation) per popolare lo stato di compliance
/// dei target con verifiche reali, invece della sola inferenza dal dry-run di
/// hardening. Installato dal pacchetto in `/opt/dognet/linux-security-audit/`.
use serde_json::{json, Value};
use std::path::Path;

const AUDIT_SCRIPT: &str = "/opt/dognet/linux-security-audit/linux_security_audit.py";
/// Tetto di tempo per un audit completo: il tool dichiara 30-180s per un giro
/// completo sequenziale di tutti i moduli; margine ampio per hardware lento.
const AUDIT_TIMEOUT_SECS: u64 = 240;

pub struct SecurityAuditOutcome {
    pub status: String, // "completed" | "failed" | "unavailable"
    pub summary: Value, // {"total", "compliant", "non_compliant", "warning"}
    pub results: Vec<Value>, // AuditResult (dict) del tool, passthrough
    pub error: Option<String>,
}

/// Esegue il tool con i moduli richiesti (stringa comma-separated, formato
/// nativo del suo `-m`/`--modules`, es. "CIS,CORE,NIST" o "All") e ne
/// restituisce i risultati grezzi. Non applica mai `--remediate`.
pub fn run_security_audit(modules: &str) -> SecurityAuditOutcome {
    if !Path::new(AUDIT_SCRIPT).exists() {
        return unavailable(format!("{} non trovato sul target", AUDIT_SCRIPT));
    }
    if !python3_available() {
        return unavailable("python3 non disponibile sul target".to_string());
    }

    let out_path = format!("/tmp/security-audit-{}.json", std::process::id());
    let cmd = format!(
        "python3 {} -m {} -f JSON -o {} -q --no-cache",
        AUDIT_SCRIPT,
        shell_quote(modules),
        shell_quote(&out_path)
    );

    let (code, _output, timed_out) = super::hardening::run_shell(&cmd, AUDIT_TIMEOUT_SECS);
    if timed_out {
        return failed("timeout durante l'esecuzione del security audit".to_string());
    }

    let raw = match std::fs::read_to_string(&out_path) {
        Ok(s) => s,
        Err(e) => return failed(format!("lettura output fallita (exit {}): {}", code, e)),
    };
    let _ = std::fs::remove_file(&out_path);

    let parsed: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => return failed(format!("JSON non valido: {}", e)),
    };

    let results: Vec<Value> = parsed
        .get("results")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut compliant = 0i64;
    let mut non_compliant = 0i64;
    let mut warning = 0i64;
    for r in &results {
        match r.get("status").and_then(|v| v.as_str()) {
            Some("Pass") => compliant += 1,
            Some("Fail") => non_compliant += 1,
            Some("Warning") => warning += 1,
            _ => {}
        }
    }

    SecurityAuditOutcome {
        status: "completed".to_string(),
        summary: json!({
            "total": results.len(),
            "compliant": compliant,
            "non_compliant": non_compliant,
            "warning": warning,
        }),
        results,
        error: None,
    }
}

fn unavailable(msg: String) -> SecurityAuditOutcome {
    SecurityAuditOutcome {
        status: "unavailable".to_string(),
        summary: json!({}),
        results: Vec::new(),
        error: Some(msg),
    }
}

fn failed(msg: String) -> SecurityAuditOutcome {
    SecurityAuditOutcome {
        status: "failed".to_string(),
        summary: json!({}),
        results: Vec::new(),
        error: Some(msg),
    }
}

fn python3_available() -> bool {
    std::process::Command::new("python3")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Quoting POSIX per shell singola: racchiude in apici, raddoppiando ogni
/// apice interno (`'` → `'\''`). Sufficiente qui perché `modules`/`out_path`
/// sono generati/validati lato server (stringa di nomi modulo o path /tmp),
/// non input utente diretto.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_gestisce_apici_singoli() {
        assert_eq!(shell_quote("CIS,CORE"), "'CIS,CORE'");
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn script_assente_ritorna_unavailable() {
        // In questo ambiente di test lo script non è installato: verifica
        // che il fallback sia esplicito e non un errore generico.
        let outcome = run_security_audit("CORE");
        if !Path::new(AUDIT_SCRIPT).exists() {
            assert_eq!(outcome.status, "unavailable");
            assert!(outcome.error.is_some());
        }
    }
}
