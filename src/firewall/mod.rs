/// Wrapper iptables per FireDog.
///
/// Su Linux esegue comandi iptables tramite std::process::Command.
/// Su Windows restituisce errori (non applicabile).
///
/// Il FirewallManager tiene traccia in memoria delle regole aggiunte
/// e degli IP bloccati durante la sessione corrente.

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
        // Costruisce args come vettore di token: Command::args li passa intatti
        // al processo (no shell, no split su whitespace). I commenti con spazi
        // restano un singolo argomento.
        let mut args: Vec<String> = vec!["-A".into(), p.chain.clone()];
        args.extend(build_rule_args(p));

        run_iptables(&args)?;

        let pretty = args
            .iter()
            .map(|a| if a.contains(' ') { format!("\"{}\"", a) } else { a.clone() })
            .collect::<Vec<_>>()
            .join(" ");
        self.state.lock().unwrap().active_rules.push(RuleRecord {
            chain: p.chain.clone(),
            rule_spec: pretty.clone(),
        });

        info!("Regola aggiunta: iptables {}", pretty);
        Ok(format!("Regola aggiunta: iptables {}", pretty))
    }

    pub fn remove_rule(&self, p: &RemoveRulePayload) -> Result<String> {
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
        Ok(format!("IP {} bloccato ({})", ip, direction))
    }

    pub fn unblock_ip(&self, ip: &str, direction: &str) -> Result<String> {
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
        Ok(format!("IP {} sbloccato", ip))
    }

    pub fn sync_rules(&self) -> Result<String> {
        warn!("sync_rules: flush completo e riapplicazione regole in-memory");
        // In una implementazione completa si salverebbe lo stato
        // su disco con iptables-save/restore.
        // Per ora flush delle chain e riscrittura da state.
        run_iptables(&["-F".to_string(), "INPUT".to_string()])?;
        run_iptables(&["-F".to_string(), "OUTPUT".to_string()])?;

        let state = self.state.lock().unwrap();
        for rule in &state.active_rules {
            let mut args = vec!["-A".to_string(), rule.chain.clone()];
            args.extend(rule.rule_spec.split_whitespace().map(String::from));
            let _ = run_iptables(&args);
        }

        for ip in &state.blocked_ips {
            let _ = run_iptables(&["-A".to_string(), "INPUT".to_string(), "-s".to_string(), ip.clone(), "-j".to_string(), "DROP".to_string()]);
        }

        Ok(format!(
            "Sync completato: {} regole, {} IP bloccati",
            state.active_rules.len(),
            state.blocked_ips.len()
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────

/// Costruisce gli argomenti iptables in formato vettoriale. Command::args li
/// passa intatti al processo (no shell, no quoting). I commenti con spazi
/// vengono mantenuti come singolo argomento.
fn build_rule_args(p: &AddRulePayload) -> Vec<String> {
    let mut args = Vec::new();

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
