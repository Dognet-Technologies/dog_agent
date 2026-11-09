//! Wrapper iptables per FireDog.
//!
//! Su Linux esegue comandi iptables tramite std::process::Command.
//! Su Windows restituisce errori (non applicabile).
//!
//! Il FirewallManager tiene traccia in memoria delle regole aggiunte
//! e degli IP bloccati durante la sessione corrente.

use anyhow::Result;
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};

use crate::protocol::firedog::{AddRulePayload, RemoveRulePayload};

#[derive(Debug, Clone)]
struct FwState {
    active_rules: Vec<RuleRecord>,
    blocked_ips: Vec<String>,
}

#[derive(Debug, Clone)]
struct RuleRecord {
    chain: String,
    rule_spec: String,
}

#[derive(Clone)]
pub struct FirewallManager {
    state: Arc<Mutex<FwState>>,
}

impl FirewallManager {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(FwState {
                active_rules: vec![],
                blocked_ips: vec![],
            })),
        }
    }

    pub fn active_rules_count(&self) -> u32 {
        self.state.lock().unwrap().active_rules.len() as u32
    }

    pub fn blocked_ips_count(&self) -> u32 {
        self.state.lock().unwrap().blocked_ips.len() as u32
    }

    // ── Comandi pubblici ──────────────────────────────────────────────────────

    pub fn add_rule(&self, p: &AddRulePayload) -> Result<String> {
        validate_fw_word("chain", &p.chain)?;
        validate_fw_word("action", &p.action)?;
        if let Some(ref v) = p.protocol { validate_fw_word("protocol", v)?; }
        if let Some(ref v) = p.interface { validate_fw_word("interface", v)?; }
        if let Some(ref v) = p.src_ip { validate_fw_ip(v)?; }
        if let Some(ref v) = p.dst_ip { validate_fw_ip(v)?; }
        // Costruisce args come vettore di token: Command::args li passa intatti
        // al processo (no shell, no split su whitespace). I commenti con spazi
        // restano un singolo argomento.
        let mut args: Vec<String> = vec!["-A".into(), p.chain.clone()];
        args.extend(build_rule_args(p));

        run_iptables(&args)?;

        let pretty = args
            .iter()
            .map(|a| if a.contains(' ') { format!("\"{a}\"") } else { a.clone() })
            .collect::<Vec<_>>()
            .join(" ");
        self.state.lock().unwrap().active_rules.push(RuleRecord {
            chain: p.chain.clone(),
            rule_spec: pretty.clone(),
        });

        info!("Regola aggiunta: iptables {}", pretty);
        Ok(format!("Regola aggiunta: iptables {pretty}"))
    }

    pub fn remove_rule(&self, p: &RemoveRulePayload) -> Result<String> {
        validate_fw_word("chain", &p.chain)?;
        if let Some(ref v) = p.protocol { validate_fw_word("protocol", v)?; }
        if let Some(ref v) = p.src_ip { validate_fw_ip(v)?; }
        if let Some(ref v) = p.action { validate_fw_word("action", v)?; }
        if let Some(n) = p.rule_num {
            run_iptables(&["-D".to_string(), p.chain.clone(), n.to_string()])?;
            info!("Regola rimossa: -D {} {}", p.chain, n);
            return Ok(format!("Regola rimossa: -D {} {}", p.chain, n));
        }

        // Rimozione per spec
        let mut args = vec!["-D".to_string(), p.chain.clone()];
        if let Some(ref proto) = p.protocol {
            args.extend(["-p".to_string(), proto.clone()]);
        }
        if let Some(ref src) = p.src_ip {
            args.extend(["-s".to_string(), src.clone()]);
        }
        if let Some(port) = p.dst_port {
            args.extend(["--dport".to_string(), port.to_string()]);
        }
        if let Some(ref action) = p.action {
            args.extend(["-j".to_string(), action.clone()]);
        }

        run_iptables(&args)?;

        // Rimuovi dalla lista interna se presente
        let spec = args[2..].join(" ");
        self.state
            .lock()
            .unwrap()
            .active_rules
            .retain(|r| r.chain != p.chain || r.rule_spec != spec);

        info!("Regola rimossa: -D {}", p.chain);
        Ok(format!("Regola rimossa dalla chain {}", p.chain))
    }

    pub fn block_ip(&self, ip: &str, direction: &str) -> Result<String> {
        validate_fw_ip(ip)?;
        match direction.to_uppercase().as_str() {
            "BOTH" => {
                run_iptables(&["-A".to_string(), "INPUT".to_string(), "-s".to_string(), ip.to_string(), "-j".to_string(), "DROP".to_string()])?;
                run_iptables(&["-A".to_string(), "OUTPUT".to_string(), "-d".to_string(), ip.to_string(), "-j".to_string(), "DROP".to_string()])?;
            }
            "OUTPUT" => {
                run_iptables(&["-A".to_string(), "OUTPUT".to_string(), "-d".to_string(), ip.to_string(), "-j".to_string(), "DROP".to_string()])?;
            }
            _ => {
                // default: INPUT
                run_iptables(&["-A".to_string(), "INPUT".to_string(), "-s".to_string(), ip.to_string(), "-j".to_string(), "DROP".to_string()])?;
            }
        }

        self.state.lock().unwrap().blocked_ips.push(ip.to_string());
        info!("IP bloccato: {} ({})", ip, direction);
        Ok(format!("IP {ip} bloccato ({direction})"))
    }

    pub fn unblock_ip(&self, ip: &str, direction: &str) -> Result<String> {
        validate_fw_ip(ip)?;
        match direction.to_uppercase().as_str() {
            "BOTH" => {
                let _ = run_iptables(&["-D".to_string(), "INPUT".to_string(), "-s".to_string(), ip.to_string(), "-j".to_string(), "DROP".to_string()]);
                let _ = run_iptables(&["-D".to_string(), "OUTPUT".to_string(), "-d".to_string(), ip.to_string(), "-j".to_string(), "DROP".to_string()]);
            }
            "OUTPUT" => {
                let _ = run_iptables(&["-D".to_string(), "OUTPUT".to_string(), "-d".to_string(), ip.to_string(), "-j".to_string(), "DROP".to_string()]);
            }
            _ => {
                let _ = run_iptables(&["-D".to_string(), "INPUT".to_string(), "-s".to_string(), ip.to_string(), "-j".to_string(), "DROP".to_string()]);
            }
        }

        self.state.lock().unwrap().blocked_ips.retain(|b| b != ip);
        info!("IP sbloccato: {}", ip);
        Ok(format!("IP {ip} sbloccato"))
    }

    pub fn sync_rules(&self) -> Result<String> {
        // "Sync" = rigenera lo snapshot completo via firewall-manager e
        // ritorna il JSON al server come output del comando. Il server lo
        // ingerisce nelle stesse tabelle che firewall_stats popola — la UI
        // vede le rule aggiornate immediatamente, senza aspettare il
        // prossimo tick del fwstats_timer (60s).
        //
        // L'implementazione precedente (flush + replay in-memory) era
        // pericolosa: avrebbe cancellato regole legittime se l'agent era
        // stato riavviato. Sostituita con un re-export non distruttivo.
        let export_path = "/opt/sentinelsuite/firedog/export/status.json";
        info!("sync_rules: rigenero snapshot via firewall-manager --export-json");

        let out = std::process::Command::new("firewall-manager")
            .args(["--export-json", export_path])
            .output()?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            anyhow::bail!("firewall-manager --export-json fallito: {}", stderr.trim());
        }

        // Restituisci il contenuto del file come stringa JSON: il server
        // legge `output` dal CommandResponse e lo ingerisce.
        let json = std::fs::read_to_string(export_path)?;
        Ok(json)
    }

}

// ─────────────────────────────────────────────────────────────────────────────
// Validazione dei token controllati dal server prima di passarli a iptables.
// `Command::args` NON usa una shell, quindi non c'è command injection; ma un
// valore che inizia con '-' verrebbe interpretato da iptables come un'opzione
// (es. "-F" = flush dell'intera chain): argument injection. Si valida al
// boundary — se un valore non è plausibile per il suo campo, si rifiuta la
// regola invece di eseguire iptables con input inatteso. (ASVS V5/input.)
// ─────────────────────────────────────────────────────────────────────────────

/// Token "a parola": chain, protocollo, target `-j`, interfaccia. Alfanumerici,
/// `_` e `-` interni; mai leading `-` (sarebbe letto come opzione di iptables).
fn validate_fw_word(kind: &str, v: &str) -> Result<()> {
    if v.is_empty() {
        anyhow::bail!("{kind} vuoto");
    }
    if v.starts_with('-') || !v.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        anyhow::bail!("{kind} non valido (atteso alfanumerico, no leading '-'): {v:?}");
    }
    Ok(())
}

/// IP o CIDR: cifre, esadecimali IPv6, `.`, `:`, `/`. Mai leading `-`.
fn validate_fw_ip(v: &str) -> Result<()> {
    if v.is_empty()
        || v.starts_with('-')
        || !v.chars().all(|c| c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '/'))
    {
        anyhow::bail!("indirizzo IP/CIDR non valido: {v:?}");
    }
    Ok(())
}

/// Costruisce gli argomenti iptables in formato vettoriale. Command::args li
/// passa intatti al processo (no shell, no quoting). I commenti con spazi
/// vengono mantenuti come singolo argomento.
fn build_rule_args(p: &AddRulePayload) -> Vec<String> {
    let mut args = Vec::new();

    // Interfaccia (vuota/assente = tutto l'host, comportamento storico).
    if let Some(ref iface) = p.interface {
        match p.chain.as_str() {
            "INPUT" => args.extend(["-i".into(), iface.clone()]),
            "OUTPUT" => args.extend(["-o".into(), iface.clone()]),
            // FORWARD: il backend non dovrebbe mai inviarla (validata a
            // monte), ma per sicurezza logga e ignora invece di applicare
            // una regola più larga di quanto l'operatore si aspetti.
            other => warn!(
                "interface '{}' ignorata su chain {}: non supportata (serve -i e -o)",
                iface, other
            ),
        }
    }

    if let Some(ref proto) = p.protocol {
        args.extend(["-p".into(), proto.clone()]);
    }
    if let Some(ref src) = p.src_ip {
        args.extend(["-s".into(), src.clone()]);
    }
    if let Some(ref dst) = p.dst_ip {
        args.extend(["-d".into(), dst.clone()]);
    }
    if let Some(port) = p.src_port {
        args.extend(["--sport".into(), port.to_string()]);
    }
    if let Some(port) = p.dst_port {
        args.extend(["--dport".into(), port.to_string()]);
    }
    if let Some(ref comment) = p.comment {
        args.extend([
            "-m".into(),
            "comment".into(),
            "--comment".into(),
            comment.clone(),
        ]);
    }
    args.extend(["-j".into(), p.action.clone()]);

    args
}

fn run_iptables(args: &[String]) -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        warn!("iptables non disponibile su questo sistema operativo");
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        debug!("iptables {}", args.join(" "));

        let output = std::process::Command::new("iptables")
            .args(args)
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("iptables fallito: {}", stderr.trim());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{validate_fw_ip, validate_fw_word};

    #[test]
    fn fw_word_accetta_valori_legittimi() {
        for v in ["INPUT", "OUTPUT", "FORWARD", "tcp", "udp", "DROP", "ACCEPT", "eth0", "my-chain", "br_lan0"] {
            assert!(validate_fw_word("campo", v).is_ok(), "{v} dovrebbe essere valido");
        }
    }

    #[test]
    fn fw_word_rifiuta_option_injection_e_metacaratteri() {
        for v in ["-F", "-j", "", "DROP; rm", "a b", "a|b", "$(x)", "--flush"] {
            assert!(validate_fw_word("campo", v).is_err(), "{v:?} doveva essere rifiutato");
        }
    }

    #[test]
    fn fw_ip_accetta_ip_e_cidr() {
        for v in ["10.0.0.1", "192.168.1.0/24", "fe80::1", "::1", "2001:db8::/32"] {
            assert!(validate_fw_ip(v).is_ok(), "{v} dovrebbe essere valido");
        }
    }

    #[test]
    fn fw_ip_rifiuta_option_like_e_metacaratteri() {
        for v in ["-s", "", "1.2.3.4 -j DROP", "$(id)", "1.2.3.4;ls", "10.0.0.0/8 --flush"] {
            assert!(validate_fw_ip(v).is_err(), "{v:?} doveva essere rifiutato");
        }
    }
}
