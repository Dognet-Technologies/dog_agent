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

    /// Un panic DENTRO una delle sezioni critiche sotto (push/retain/len,
    /// improbabile ma non impossibile) avvelenerebbe il Mutex per il resto
    /// della vita di questo `FirewallManager`: senza recupero, ogni
    /// operazione firewall successiva su questo target panicherebbe a sua
    /// volta per sempre (MEDIUM trovato in code review, 2026-11 — si
    /// somma al fix di supervisione/restart in targets/mod.rs, ma qui è
    /// evitabile a monte).
    fn lock_state(&self) -> std::sync::MutexGuard<'_, FwState> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn active_rules_count(&self) -> u32 {
        self.lock_state().active_rules.len() as u32
    }

    pub fn blocked_ips_count(&self) -> u32 {
        self.lock_state().blocked_ips.len() as u32
    }

    // ── Comandi pubblici ──────────────────────────────────────────────────────

    pub fn add_rule(&self, p: &AddRulePayload) -> Result<String> {
        validate_fw_word("chain", &p.chain)?;
        validate_fw_word("action", &p.action)?;
        if let Some(ref v) = p.protocol { validate_fw_word("protocol", v)?; }
        if let Some(ref v) = p.interface { validate_fw_word("interface", v)?; }
        let src = p.src_ip.as_deref().map(parse_fw_ip).transpose()?;
        let dst = p.dst_ip.as_deref().map(parse_fw_ip).transpose()?;
        // Regola IPv6 → ip6tables. Senza IP resta iptables (comportamento storico).
        let family = match (src, dst) {
            (Some(a), Some(b)) if a != b => {
                anyhow::bail!("src_ip e dst_ip di famiglie diverse (IPv4/IPv6)")
            }
            (Some(f), _) | (_, Some(f)) => f,
            (None, None) => IpFamily::V4,
        };
        // Costruisce args come vettore di token: Command::args li passa intatti
        // al processo (no shell, no split su whitespace). I commenti con spazi
        // restano un singolo argomento.
        let spec = build_rule_args(p);
        let pretty = spec
            .iter()
            .map(|a| if a.contains(' ') { format!("\"{a}\"") } else { a.clone() })
            .collect::<Vec<_>>()
            .join(" ");

        if !add_once(family, &p.chain, &spec, Placement::BeforeFinalDrop)? {
            info!("Regola già presente: {} {} {}", family.bin(), p.chain, pretty);
            return Ok(format!("Regola già presente: {} {} {pretty}", family.bin(), p.chain));
        }
        self.lock_state().active_rules.push(RuleRecord {
            chain: p.chain.clone(),
            rule_spec: pretty.clone(),
        });

        info!("Regola aggiunta: {} {} {}", family.bin(), p.chain, pretty);
        Ok(format!("Regola aggiunta: {} {} {pretty}", family.bin(), p.chain))
    }

    pub fn remove_rule(&self, p: &RemoveRulePayload) -> Result<String> {
        validate_fw_word("chain", &p.chain)?;
        if let Some(ref v) = p.protocol { validate_fw_word("protocol", v)?; }
        let family = p.src_ip.as_deref().map(parse_fw_ip).transpose()?.unwrap_or(IpFamily::V4);
        if let Some(ref v) = p.action { validate_fw_word("action", v)?; }
        if let Some(n) = p.rule_num {
            run_fw(family, &["-D".to_string(), p.chain.clone(), n.to_string()])?;
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

        run_fw(family, &args)?;

        // Rimuovi dalla lista interna se presente
        let spec = args[2..].join(" ");
        self.lock_state()
            .active_rules
            .retain(|r| r.chain != p.chain || r.rule_spec != spec);

        info!("Regola rimossa: -D {}", p.chain);
        Ok(format!("Regola rimossa dalla chain {}", p.chain))
    }

    pub fn block_ip(&self, ip: &str, direction: &str) -> Result<String> {
        let family = parse_fw_ip(ip)?;
        match direction.to_uppercase().as_str() {
            "BOTH" => {
                add_once(family, "INPUT", &drop_spec("-s", ip), Placement::Top)?;
                add_once(family, "OUTPUT", &drop_spec("-d", ip), Placement::Top)?;
            }
            "OUTPUT" => {
                add_once(family, "OUTPUT", &drop_spec("-d", ip), Placement::Top)?;
            }
            _ => {
                // default: INPUT
                add_once(family, "INPUT", &drop_spec("-s", ip), Placement::Top)?;
            }
        }

        let mut state = self.lock_state();
        if !state.blocked_ips.iter().any(|b| b == ip) {
            state.blocked_ips.push(ip.to_string());
        }
        drop(state);
        info!("IP bloccato: {} ({})", ip, direction);
        Ok(format!("IP {ip} bloccato ({direction})"))
    }

    pub fn unblock_ip(&self, ip: &str, direction: &str) -> Result<String> {
        let family = parse_fw_ip(ip)?;
        // "BOTH" tenta la rimozione in entrambe le direzioni best-effort
        // (non si sa sempre quale fosse stata usata al momento del blocco,
        // e un retry idempotente su una regola già assente non deve essere
        // un errore fatale) — ma a differenza di prima, ogni fallimento è
        // loggato e, se TUTTI i tentativi applicabili falliscono, la
        // funzione ritorna un errore reale invece di affermare sempre
        // "sbloccato" (CRITICAL trovato in code review, 2026-11: con
        // iptables assente/permessi insufficienti/regola non trovata per
        // un motivo reale, il comando "unblock" tornava Success comunque,
        // lasciando l'IP ancora droppato senza alcuna traccia d'errore).
        let specs: Vec<Vec<String>> = match direction.to_uppercase().as_str() {
            "BOTH" => vec![
                vec!["-D".into(), "INPUT".into(), "-s".into(), ip.into(), "-j".into(), "DROP".into()],
                vec!["-D".into(), "OUTPUT".into(), "-d".into(), ip.into(), "-j".into(), "DROP".into()],
            ],
            "OUTPUT" => vec![vec!["-D".into(), "OUTPUT".into(), "-d".into(), ip.into(), "-j".into(), "DROP".into()]],
            _ => vec![vec!["-D".into(), "INPUT".into(), "-s".into(), ip.into(), "-j".into(), "DROP".into()]],
        };

        let mut failures: Vec<String> = Vec::new();
        for args in &specs {
            if let Err(e) = run_fw(family, args) {
                warn!("unblock_ip: rimozione regola fallita ({}): {}", args.join(" "), e);
                failures.push(e.to_string());
            }
        }

        self.lock_state().blocked_ips.retain(|b| b != ip);

        if failures.len() == specs.len() {
            anyhow::bail!(
                "unblock_ip {ip}: tutti i {} tentativi di rimozione sono falliti: {}",
                specs.len(),
                failures.join("; ")
            );
        }

        info!("IP sbloccato: {} ({}/{} rimozioni riuscite)", ip, specs.len() - failures.len(), specs.len());
        Ok(format!("IP {ip} sbloccato ({direction})"))
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

/// Famiglia di indirizzi di una regola: decide se usare iptables o ip6tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFamily {
    V4,
    V6,
}

impl IpFamily {
    fn bin(self) -> &'static str {
        match self {
            IpFamily::V4 => "iptables",
            IpFamily::V6 => "ip6tables",
        }
    }
}

/// IP o CIDR (`10.0.0.1`, `192.168.0.0/16`, `fe80::1`, `2001:db8::/32`),
/// verificato col parser di std e con il prefisso nel range della famiglia.
/// Prima era solo un controllo sui caratteri: un IPv6 finiva comunque a
/// `iptables`, che lo rifiuta (o peggio, in caso di regole miste).
fn parse_fw_ip(v: &str) -> Result<IpFamily> {
    let invalid = || anyhow::anyhow!("indirizzo IP/CIDR non valido: {v:?}");
    let (addr, prefix) = match v.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (v, None),
    };
    let ip: std::net::IpAddr = addr.parse().map_err(|_| invalid())?;
    let (family, max) = if ip.is_ipv4() { (IpFamily::V4, 32) } else { (IpFamily::V6, 128) };
    if let Some(p) = prefix {
        let n: u8 = p.parse().map_err(|_| invalid())?;
        if n > max {
            return Err(invalid());
        }
    }
    Ok(family)
}

#[cfg(test)]
fn validate_fw_ip(v: &str) -> Result<()> {
    parse_fw_ip(v).map(|_| ())
}

fn drop_spec(flag: &str, ip: &str) -> Vec<String> {
    vec![flag.into(), ip.into(), "-j".into(), "DROP".into()]
}

/// Dove mettere una regola nella catena.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placement {
    /// In cima (`-I chain 1`): i blocchi devono valere su tutto, anche sulle
    /// connessioni già stabilite e su SSH accettato più in basso.
    Top,
    /// Prima dello scarto finale della catena, se c'è (vedi
    /// `before_final_drop`), altrimenti in fondo.
    BeforeFinalDrop,
}

/// Aggiunge la regola solo se `-C chain spec` dice che non c'è già: prima
/// ogni blocco ripetuto (stesso IP, reconnect, auto-block) aggiungeva una
/// regola DROP duplicata. `Ok(false)` se era già presente.
///
/// Prima si usava sempre `-A` (in fondo). Sui target con firewall-manager la
/// catena INPUT finisce con `-j LOG_INPUT_DROP`, che scarta tutto ciò che
/// arriva fin lì: un DROP accodato dopo non fermava il traffico già accettato
/// più in alto (SSH sotto la soglia di SSH_PROTECT, porte sempre aperte,
/// connessioni stabilite) e un ACCEPT accodato non veniva mai raggiunto
/// (review 2026-11-16).
fn add_once(family: IpFamily, chain: &str, spec: &[String], placement: Placement) -> Result<bool> {
    let with = |op: &str, pos: Option<usize>| {
        let mut a = vec![op.to_string(), chain.to_string()];
        if let Some(n) = pos {
            a.push(n.to_string());
        }
        a.extend_from_slice(spec);
        a
    };
    if run_fw(family, &with("-C", None)).is_ok() {
        return Ok(false);
    }
    let position = match placement {
        Placement::Top => Some(1),
        Placement::BeforeFinalDrop => before_final_drop(&chain_rules(family, chain)?, chain),
    };
    match position {
        Some(n) => run_fw(family, &with("-I", Some(n)))?,
        None => run_fw(family, &with("-A", None))?,
    }
    Ok(true)
}

/// Regole della catena come le stampa `iptables -S <chain>`.
fn chain_rules(family: IpFamily, chain: &str) -> Result<Vec<String>> {
    let out = run_fw_output(family, &["-S".to_string(), chain.to_string()])?;
    Ok(out.lines().map(str::to_string).collect())
}

/// Posizione (1-based, per `-I`) dell'ultima regola se è uno scarto senza
/// condizioni (`-A CHAIN -j DROP|REJECT|LOG_*_DROP`), cioè il "tutto il
/// resto si scarta" di firewall-manager: la regola nuova va subito prima,
/// dopo le protezioni ma ancora raggiungibile. `None` se la catena non
/// finisce così (nessun firewall-manager): si accoda in fondo.
fn before_final_drop(rules: &[String], chain: &str) -> Option<usize> {
    let prefix = format!("-A {chain} ");
    let appended: Vec<&str> = rules.iter().map(String::as_str).filter(|r| r.starts_with(&prefix)).collect();
    let last = appended.last()?;
    let target = last.strip_prefix(&prefix)?.strip_prefix("-j ")?.trim();
    let is_final_drop = !target.contains(' ')
        && (target == "DROP" || target == "REJECT" || (target.starts_with("LOG_") && target.ends_with("_DROP")));
    is_final_drop.then_some(appended.len())
}

/// DROP in INPUT dal sorgente `ip`, idempotente; usato anche dall'auto-block
/// del threat detector. `Ok(false)` se il blocco c'era già.
pub fn drop_input_from(ip: &str) -> Result<bool> {
    let family = parse_fw_ip(ip)?;
    add_once(family, "INPUT", &drop_spec("-s", ip), Placement::Top)
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

/// Come `run_fw`, restituendo lo stdout (es. `iptables -S`).
fn run_fw_output(family: IpFamily, args: &[String]) -> Result<String> {
    let bin = family.bin();
    #[cfg(not(target_os = "linux"))]
    {
        warn!("{bin} non disponibile su questo sistema operativo ({})", args.join(" "));
        return Ok(String::new());
    }

    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new(bin).args(args).output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("{bin} fallito: {}", stderr.trim());
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

fn run_fw(family: IpFamily, args: &[String]) -> Result<()> {
    let bin = family.bin();
    #[cfg(not(target_os = "linux"))]
    {
        warn!("{bin} non disponibile su questo sistema operativo ({})", args.join(" "));
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        debug!("{bin} {}", args.join(" "));

        let output = std::process::Command::new(bin)
            .args(args)
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("{bin} fallito: {}", stderr.trim());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{before_final_drop, parse_fw_ip, validate_fw_ip, validate_fw_word, IpFamily};

    fn rules(lines: &[&str]) -> Vec<String> {
        lines.iter().map(|l| l.to_string()).collect()
    }

    #[test]
    fn regole_prima_dello_scarto_finale_di_firewall_manager() {
        // `iptables -S INPUT` reale di lab-client1 (firewall-manager), accorciato.
        let input = rules(&[
            "-P INPUT DROP",
            "-A INPUT -i lo -j ACCEPT",
            "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A INPUT -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -j SSH_PROTECT",
            "-A INPUT -p tcp -m tcp --dport 9000 -m conntrack --ctstate NEW -j ACCEPT",
            "-A INPUT -j LOG_INPUT_DROP",
        ]);
        // 5 regole, l'ultima è lo scarto: la nuova va in posizione 5.
        assert_eq!(before_final_drop(&input, "INPUT"), Some(5));
        let output = rules(&["-P OUTPUT DROP", "-A OUTPUT -o lo -j ACCEPT", "-A OUTPUT -j LOG_OUTPUT_DROP"]);
        assert_eq!(before_final_drop(&output, "OUTPUT"), Some(2));
        assert_eq!(before_final_drop(&rules(&["-P INPUT ACCEPT", "-A INPUT -j DROP"]), "INPUT"), Some(1));
    }

    #[test]
    fn senza_scarto_finale_si_accoda() {
        // Nessun firewall-manager: policy ACCEPT, catena vuota o con regole normali.
        assert_eq!(before_final_drop(&rules(&["-P INPUT ACCEPT"]), "INPUT"), None);
        let input = rules(&["-P INPUT ACCEPT", "-A INPUT -s 203.0.113.5/32 -j DROP"]);
        assert_eq!(before_final_drop(&input, "INPUT"), None, "un DROP con condizioni non è lo scarto finale");
        let input = rules(&["-P INPUT DROP", "-A INPUT -j SSH_PROTECT"]);
        assert_eq!(before_final_drop(&input, "INPUT"), None, "un salto a una catena qualsiasi non scarta tutto");
        // Righe di altre catene non contano.
        let mixed = rules(&["-A FORWARD -j DROP", "-A INPUT -i lo -j ACCEPT"]);
        assert_eq!(before_final_drop(&mixed, "INPUT"), None);
    }

    #[test]
    fn fw_ip_sceglie_la_famiglia_e_valida_il_prefisso() {
        assert_eq!(parse_fw_ip("10.0.0.1").unwrap(), IpFamily::V4);
        assert_eq!(parse_fw_ip("2001:db8::/32").unwrap(), IpFamily::V6);
        for v in ["10.0.0.0/33", "fe80::/129", "300.1.1.1", "1.2.3", "::ffff::1", "10.0.0.0/"] {
            assert!(parse_fw_ip(v).is_err(), "{v:?} doveva essere rifiutato");
        }
    }

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
