// ============================================================================
// Hardening executor (agent side) — applica un template CyberSheppard sul target
// ============================================================================
// Riceve `template_config` (JSON derivato dal YAML) e lo applica.
// Struttura: template.hardening_steps[] (= controlli) → step.tasks[] (azioni).
// Modalità: "dry_run" (nessuna modifica, solo piano) o "apply" (esecuzione reale
// con backup dei file e raccolta di rollback_data).
//
// SICUREZZA: in dry_run non viene eseguito nulla che modifichi il sistema
// (né comandi/script, né scritture file, né pacchetti/servizi).

use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use tracing::{info, warn};

pub struct HardeningOutcome {
    pub status: String, // "completed" | "failed"
    pub total_controls: i32,
    pub successful_controls: i32,
    pub failed_controls: i32,
    pub execution_log: String,
    pub rollback_data: Value,
    pub error: Option<String>,
    /// Esito per-controllo `[{"control_id": "<slug YAML>", "ok": bool}]`, usato
    /// dal server per aggiornare `target_control_status` via
    /// `hardening_template_controls`.
    pub control_results: Vec<Value>,
}

/// Aggiornamento di avanzamento emesso dopo ogni controllo, così il server/UI
/// mostra in tempo reale cosa sta accadendo (log parziale incluso).
#[derive(Clone)]
pub struct ProgressUpdate {
    pub total: i32,
    pub successful: i32,
    pub failed: i32,
    pub current_control: String,
    pub log: String,
}

/// Punto d'ingresso: applica (o simula) il template. Funzione bloccante:
/// va chiamata in `spawn_blocking`. `on_progress` è invocata dopo ogni controllo.
pub fn run_hardening(
    template: &Value,
    mode: &str,
    mut on_progress: impl FnMut(ProgressUpdate),
) -> HardeningOutcome {
    let dry = mode != "apply";
    let os_family = detect_os_family();
    let mut log = String::new();
    let mut file_backups: Vec<Value> = Vec::new();

    macro_rules! logln { ($($a:tt)*) => {{ log.push_str(&format!($($a)*)); log.push('\n'); }} }

    logln!("=== Hardening {} (os_family={}) ===", if dry { "DRY-RUN" } else { "APPLY" }, os_family);

    let steps = template.get("hardening_steps").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let total = steps.len() as i32;
    let mut ok_controls = 0i32;
    let mut failed_controls = 0i32;
    let mut control_results: Vec<Value> = Vec::with_capacity(steps.len());

    for step in &steps {
        let cname = step.get("control_id").and_then(|v| v.as_str())
            .or_else(|| step.get("name").and_then(|v| v.as_str()))
            .unwrap_or("control");
        logln!("\n--- Controllo: {} ---", cname);

        let tasks = step.get("tasks").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        let mut control_ok = true;

        for task in &tasks {
            let tname = task.get("name").and_then(|v| v.as_str()).unwrap_or("task");
            let action = task.get("action").and_then(|v| v.as_str());

            // Valuta condition (os_family/service_exists/mount_exists).
            if let Some(cond) = task.get("condition").and_then(|v| v.as_str()) {
                if !eval_condition(cond, &os_family) {
                    logln!("  [skip] {} (condizione non soddisfatta: {})", tname, cond);
                    continue;
                }
            }

            let action = match action {
                Some(a) => a,
                None => { logln!("  [skip] {} (nessuna action)", tname); continue; }
            };

            let tolerant = task.get("allow_failure").and_then(|v| v.as_bool()).unwrap_or(false)
                || task.get("failure_action").and_then(|v| v.as_str()) == Some("warn");

            let res = apply_task(action, task, dry, &mut file_backups);
            match res {
                Ok(msg) => logln!("  [ok] {} — {}", tname, msg),
                Err(e) => {
                    if tolerant {
                        logln!("  [warn] {} — {} (non bloccante)", tname, e);
                    } else {
                        logln!("  [FAIL] {} — {}", tname, e);
                        control_ok = false;
                    }
                }
            }
        }

        if control_ok { ok_controls += 1; } else { failed_controls += 1; }
        control_results.push(json!({ "control_id": cname, "ok": control_ok }));

        // Notifica l'avanzamento (log parziale) dopo ogni controllo.
        info!("Hardening: controllo '{}' → {}/{} ok, {} falliti", cname, ok_controls, total, failed_controls);
        on_progress(ProgressUpdate {
            total,
            successful: ok_controls,
            failed: failed_controls,
            current_control: cname.to_string(),
            log: log.clone(),
        });
    }

    // L'esecuzione è "completed" se è arrivata in fondo: i controlli falliti sono
    // riportati in failed_controls (dettaglio parziale), non un errore d'esecuzione.
    // "failed" è riservato a un errore catastrofico che impedisce di procedere.
    let status = "completed";
    logln!("\n=== Risultato: {}/{} controlli ok, {} falliti ===", ok_controls, total, failed_controls);
    info!("Hardening {}: {}/{} ok, {} falliti", if dry {"dry-run"} else {"apply"}, ok_controls, total, failed_controls);

    HardeningOutcome {
        status: status.to_string(),
        total_controls: total,
        successful_controls: ok_controls,
        failed_controls,
        execution_log: log,
        rollback_data: json!({ "mode": mode, "files": file_backups }),
        error: None,
        control_results,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Dispatch azioni
// ─────────────────────────────────────────────────────────────────────────────

fn apply_task(action: &str, task: &Value, dry: bool, backups: &mut Vec<Value>) -> Result<String, String> {
    match action {
        "file_content" | "file_section" => act_file_content(task, dry, backups),
        "file_copy" => act_file_copy(task, dry, backups),
        "file_line_present" => act_file_line_present(task, dry, backups),
        "file_line_replace" => act_file_line_replace(task, dry, backups),
        "file_section_update" => act_file_section_update(task, dry, backups),
        "sysctl_value" => act_sysctl(task, dry),
        "systemd_service" => act_systemd(task, dry),
        "package_install" => act_package_install(task, dry),
        "cron_entry" => act_cron(task, dry, backups),
        "fstab_entry" => act_fstab(task, dry, backups),
        "command" => act_command(task, dry),
        "script" => act_script(task, dry),
        other => Err(format!("action non supportata: {}", other)),
    }
}

// ── file helpers ─────────────────────────────────────────────────────────────

fn s<'a>(t: &'a Value, k: &str) -> Option<&'a str> { t.get(k).and_then(|v| v.as_str()) }

fn record_backup(backups: &mut Vec<Value>, path: &str) {
    let existed = std::path::Path::new(path).exists();
    let content = if existed { std::fs::read_to_string(path).ok() } else { None };
    backups.push(json!({ "path": path, "existed": existed, "content": content }));
    if existed {
        // copia .bak best-effort per ripristino manuale immediato
        let _ = std::fs::copy(path, format!("{}.cybersheppard.bak", path));
    }
}

fn apply_owner_mode(path: &str, task: &Value) -> Result<(), String> {
    if let Some(mode) = s(task, "mode") {
        // Modalità ottale tipo "0644"/"0750"; from_str_radix gestisce lo zero iniziale.
        if let Ok(m) = u32::from_str_radix(mode.trim().trim_start_matches("0o"), 8) {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(m));
        }
    }
    if let Some(owner) = s(task, "owner") {
        // chown user[:group]
        let status = Command::new("chown").arg(owner).arg(path).status()
            .map_err(|e| format!("chown: {}", e))?;
        if !status.success() { return Err(format!("chown {} {} fallito", owner, path)); }
    }
    Ok(())
}

fn act_file_content(task: &Value, dry: bool, backups: &mut Vec<Value>) -> Result<String, String> {
    let file = s(task, "file").ok_or("file mancante")?;
    let content = s(task, "content").ok_or("content mancante")?;
    if dry { return Ok(format!("scriverebbe {} ({} byte)", file, content.len())); }
    if let Some(parent) = std::path::Path::new(file).parent() { let _ = std::fs::create_dir_all(parent); }
    record_backup(backups, file);
    std::fs::write(file, content).map_err(|e| format!("write {}: {}", file, e))?;
    apply_owner_mode(file, task)?;
    Ok(format!("scritto {}", file))
}

fn act_file_copy(task: &Value, dry: bool, backups: &mut Vec<Value>) -> Result<String, String> {
    let src = s(task, "src").ok_or("src mancante")?;
    let dest = s(task, "dest").ok_or("dest mancante")?;
    if dry { return Ok(format!("copierebbe {} → {}", src, dest)); }
    if !std::path::Path::new(src).exists() {
        return Err(format!("src {} non presente sul target", src));
    }
    if let Some(parent) = std::path::Path::new(dest).parent() { let _ = std::fs::create_dir_all(parent); }
    record_backup(backups, dest);
    std::fs::copy(src, dest).map_err(|e| format!("copy: {}", e))?;
    apply_owner_mode(dest, task)?;
    Ok(format!("copiato → {}", dest))
}

/// Assicura che una o più righe siano presenti in un file. Supporta sia
/// `line` (singola) sia `lines` (array — es. le due righe PAM preauth+authfail
/// di pam_faillock, che vanno inserite insieme da un solo task) e, opzionali:
/// - `anchor`+`position` ("before"|"after"): inserisce vicino alla prima riga
///   che soddisfa il pattern regex `anchor`, invece che in fondo al file;
/// - `replace_regex`: se una riga esistente combacia, viene SOSTITUITA con la
///   nuova invece di aggiungerne una seconda (usato per parametri con default
///   già presenti nel file, es. PASS_MAX_DAYS in /etc/login.defs);
/// - `comment`: riga di commento inserita una volta sola sopra il blocco
///   aggiunto (ignorata se non si aggiunge nulla, es. tutto già presente).
fn act_file_line_present(task: &Value, dry: bool, backups: &mut Vec<Value>) -> Result<String, String> {
    let file = s(task, "file").ok_or("file mancante")?;

    let mut wanted: Vec<String> = Vec::new();
    if let Some(l) = s(task, "line") {
        wanted.push(l.to_string());
    }
    if let Some(arr) = task.get("lines").and_then(|v| v.as_array()) {
        wanted.extend(arr.iter().filter_map(|v| v.as_str()).map(str::to_string));
    }
    if wanted.is_empty() {
        return Err("line mancante".to_string());
    }

    let replace_regex = task.get("replace_regex").and_then(|v| v.as_str());
    let anchor_re = task
        .get("anchor")
        .and_then(|v| v.as_str())
        .and_then(|pat| regex::Regex::new(pat).ok());
    let position_before = task.get("position").and_then(|v| v.as_str()) == Some("before");
    let comment = task.get("comment").and_then(|v| v.as_str());

    let existing = std::fs::read_to_string(file).unwrap_or_default();
    let mut out: Vec<String> = existing.lines().map(str::to_string).collect();
    let mut inserted = 0usize;
    let mut replaced = 0usize;
    let mut already = 0usize;

    for want in &wanted {
        if out.iter().any(|l| l.trim() == want.trim()) {
            already += 1;
            continue;
        }

        if let Some(pattern) = replace_regex {
            // Il pattern è condiviso da tutte le `wanted` (es. una alternanza
            // "^(A|B|C)\s+.*" per un intero gruppo di parametri): non basta il
            // primo match, va anche la stessa "chiave" (prima parola) della
            // riga desiderata, altrimenti una entry rimpiazzerebbe quella di
            // un'altra chiave già sostituita in questo stesso giro.
            let key = want.split_whitespace().next();
            if let Ok(re) = regex::Regex::new(pattern) {
                let idx = out
                    .iter()
                    .position(|l| re.is_match(l) && l.split_whitespace().next() == key);
                if let Some(idx) = idx {
                    out[idx] = want.clone();
                    replaced += 1;
                    continue;
                }
            }
        }

        let mut insert_at = anchor_re
            .as_ref()
            .and_then(|re| out.iter().position(|l| re.is_match(l)))
            .map(|idx| if position_before { idx } else { idx + 1 })
            .unwrap_or(out.len());

        if inserted == 0 {
            if let Some(c) = comment {
                out.insert(insert_at.min(out.len()), c.to_string());
                insert_at += 1;
            }
        }
        out.insert(insert_at.min(out.len()), want.clone());
        inserted += 1;
    }

    if inserted == 0 && replaced == 0 {
        return Ok(format!("{} riga/e già presenti in {}", already, file));
    }
    if dry {
        return Ok(format!(
            "aggiornerebbe {} ({} da aggiungere, {} da sostituire)",
            file, inserted, replaced
        ));
    }
    record_backup(backups, file);
    let mut joined = out.join("\n");
    joined.push('\n');
    std::fs::write(file, joined).map_err(|e| format!("write {}: {}", file, e))?;
    Ok(format!(
        "{} ({} aggiunte, {} sostituite)",
        file, inserted, replaced
    ))
}

fn act_file_line_replace(task: &Value, dry: bool, backups: &mut Vec<Value>) -> Result<String, String> {
    let file = s(task, "file").ok_or("file mancante")?;
    let search = s(task, "search").ok_or("search mancante")?;
    let replace = s(task, "replace").unwrap_or("");
    let create_if_missing = task.get("create_if_missing").and_then(|v| v.as_bool()).unwrap_or(false);
    let re = regex::Regex::new(search).map_err(|e| format!("regex '{}': {}", search, e))?;
    let existing = std::fs::read_to_string(file).unwrap_or_default();
    let matched = existing.lines().any(|l| re.is_match(l));

    if dry {
        return Ok(if matched { format!("sostituirebbe in {}", file) }
                  else if create_if_missing { format!("aggiungerebbe (non trovato) in {}", file) }
                  else { format!("nessun match in {} (nessuna modifica)", file) });
    }
    record_backup(backups, file);
    let mut out: Vec<String> = Vec::new();
    for l in existing.lines() {
        if re.is_match(l) { out.push(replace.to_string()); } else { out.push(l.to_string()); }
    }
    if !matched && create_if_missing { out.push(replace.to_string()); }
    let mut joined = out.join("\n"); joined.push('\n');
    std::fs::write(file, joined).map_err(|e| format!("write {}: {}", file, e))?;
    Ok(format!("aggiornato {}", file))
}

fn act_file_section_update(task: &Value, dry: bool, backups: &mut Vec<Value>) -> Result<String, String> {
    // Gestione semplice: assicura che `content` (che include l'header di sezione)
    // sia presente nel file; se assente lo appende. Idempotente sul blocco.
    let file = s(task, "file").ok_or("file mancante")?;
    let content = s(task, "content").ok_or("content mancante")?;
    let existing = std::fs::read_to_string(file).unwrap_or_default();
    if existing.contains(content.trim()) {
        return Ok(format!("sezione già presente in {}", file));
    }
    if dry { return Ok(format!("aggiornerebbe sezione in {}", file)); }
    record_backup(backups, file);
    let mut new = existing;
    if !new.is_empty() && !new.ends_with('\n') { new.push('\n'); }
    new.push_str(content); new.push('\n');
    std::fs::write(file, new).map_err(|e| format!("write {}: {}", file, e))?;
    Ok(format!("sezione aggiornata in {}", file))
}

fn act_sysctl(task: &Value, dry: bool) -> Result<String, String> {
    let param = s(task, "parameter").ok_or("parameter mancante")?;
    let value = task.get("value").map(|v| v.to_string().trim_matches('"').to_string())
        .ok_or("value mancante")?;
    if dry { return Ok(format!("sysctl {}={}", param, value)); }
    // Persistente + runtime.
    let conf = format!("/etc/sysctl.d/99-cybersheppard-hardening.conf");
    let line = format!("{} = {}", param, value);
    let existing = std::fs::read_to_string(&conf).unwrap_or_default();
    if !existing.lines().any(|l| l.trim_start().starts_with(param)) {
        let mut new = existing;
        if !new.is_empty() && !new.ends_with('\n') { new.push('\n'); }
        new.push_str(&line); new.push('\n');
        let _ = std::fs::write(&conf, new);
    }
    let status = Command::new("sysctl").arg("-w").arg(format!("{}={}", param, value)).status()
        .map_err(|e| format!("sysctl: {}", e))?;
    if !status.success() { return Err(format!("sysctl -w {}={} fallito", param, value)); }
    Ok(format!("sysctl {}={}", param, value))
}

fn act_systemd(task: &Value, dry: bool) -> Result<String, String> {
    let svc = s(task, "service").ok_or("service mancante")?;
    let state = s(task, "state").unwrap_or("disabled");
    let args: Vec<&str> = match state {
        "disabled" | "disable" => vec!["disable", "--now"],
        "enabled" | "enable" => vec!["enable", "--now"],
        "masked" | "mask" => vec!["mask"],
        "stopped" | "stop" => vec!["stop"],
        "started" | "start" => vec!["start"],
        other => return Err(format!("state systemd sconosciuto: {}", other)),
    };
    if dry { return Ok(format!("systemctl {} {}", args.join(" "), svc)); }
    let status = Command::new("systemctl").args(&args).arg(svc).status()
        .map_err(|e| format!("systemctl: {}", e))?;
    if !status.success() { return Err(format!("systemctl {} {} fallito", args.join(" "), svc)); }
    Ok(format!("systemctl {} {}", args.join(" "), svc))
}

fn act_package_install(task: &Value, dry: bool) -> Result<String, String> {
    let pkgs: Vec<String> = task.get("packages").and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    if pkgs.is_empty() { return Err("packages vuoto".into()); }
    if dry { return Ok(format!("installerebbe: {}", pkgs.join(", "))); }
    let list = pkgs.join(" ");
    // Non-interattivo + timeout di rete, per non restare appesi (es. mirror
    // irraggiungibili). Il timeout complessivo del task fa da rete di sicurezza.
    let cmdline = match detect_pkg_mgr().as_str() {
        "apt" => format!(
            "DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 -o Dpkg::Lock::Timeout=30 install -y {}",
            list
        ),
        "zypper" => format!("zypper --non-interactive install {}", list),
        "dnf" => format!("dnf install -y --setopt=timeout=20 {}", list),
        m => return Err(format!("package manager non supportato: {}", m)),
    };
    let secs = task.get("timeout").and_then(|v| v.as_u64()).unwrap_or(180);
    let (code, out, timed_out) = run_shell(&cmdline, secs);
    if timed_out {
        return Err(format!("timeout install {} dopo {}s (mirror irraggiungibile?)", list, secs));
    }
    if code != 0 {
        return Err(format!("install {} fallito (exit {}): {}", list, code, out.lines().last().unwrap_or("")));
    }
    Ok(format!("installati: {}", list))
}

fn act_cron(task: &Value, dry: bool, backups: &mut Vec<Value>) -> Result<String, String> {
    let file = s(task, "cron_file").ok_or("cron_file mancante")?;
    let entry = s(task, "entry").ok_or("entry mancante")?;
    if dry { return Ok(format!("scriverebbe cron {}", file)); }
    record_backup(backups, file);
    let mut body = String::from("# CyberSheppard hardening\n");
    body.push_str(entry); body.push('\n');
    std::fs::write(file, body).map_err(|e| format!("write {}: {}", file, e))?;
    let _ = std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o644));
    Ok(format!("cron scritto {}", file))
}

fn act_fstab(task: &Value, dry: bool, backups: &mut Vec<Value>) -> Result<String, String> {
    let mount = s(task, "mount_point").ok_or("mount_point mancante")?;
    let options = s(task, "options").ok_or("options mancante")?;
    let fstab = "/etc/fstab";
    let existing = std::fs::read_to_string(fstab).unwrap_or_default();
    // Cerca la riga della mount esistente (2° campo = mount point).
    let has_line = existing.lines().any(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        f.len() >= 2 && f[1] == mount && !l.trim_start().starts_with('#')
    });
    if !has_line { return Err(format!("mount {} non presente in fstab (skip)", mount)); }
    if dry { return Ok(format!("aggiornerebbe opzioni fstab per {} → {}", mount, options)); }
    record_backup(backups, fstab);
    let mut out: Vec<String> = Vec::new();
    for l in existing.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() >= 4 && f[1] == mount && !l.trim_start().starts_with('#') {
            out.push(format!("{} {} {} {} {} {}", f[0], f[1], f[2], options,
                f.get(4).unwrap_or(&"0"), f.get(5).unwrap_or(&"0")));
        } else { out.push(l.to_string()); }
    }
    let mut joined = out.join("\n"); joined.push('\n');
    std::fs::write(fstab, joined).map_err(|e| format!("write fstab: {}", e))?;
    Ok(format!("fstab aggiornato per {}", mount))
}

fn act_command(task: &Value, dry: bool) -> Result<String, String> {
    let cmd = s(task, "command").ok_or("command mancante")?;
    let expected = task.get("expected_exit_code").and_then(|v| v.as_i64()).unwrap_or(0);
    if dry { return Ok(format!("eseguirebbe: {}", first_line(cmd))); }
    let secs = task.get("timeout").and_then(|v| v.as_u64()).unwrap_or(60);
    let (code, out, timed_out) = run_shell(cmd, secs);
    if timed_out {
        return Err(format!("timeout dopo {}s: {}", secs, first_line(cmd)));
    }
    if code as i64 != expected {
        return Err(format!("exit {} (atteso {}): {}", code, expected, out.lines().last().unwrap_or("")));
    }
    Ok(format!("comando ok (exit {})", code))
}

fn act_script(task: &Value, dry: bool) -> Result<String, String> {
    let script = s(task, "script").ok_or("script mancante")?;
    if dry { return Ok(format!("eseguirebbe script ({} righe)", script.lines().count())); }
    let secs = task.get("timeout").and_then(|v| v.as_u64()).unwrap_or(60);
    let (code, _out, timed_out) = run_shell(script, secs);
    if timed_out { return Err(format!("timeout dopo {}s", secs)); }
    if code != 0 { return Err(format!("script exit {}", code)); }
    Ok("script ok".into())
}

static SHELL_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Esegue un comando shell con timeout robusto. Punto chiave: l'output NON viene
/// convogliato in una pipe verso l'agent ma REINDIRIZZATO su un file, così i
/// figli orfani (es. i "method" di apt che sopravvivono al gruppo) non possono
/// bloccare la raccolta dell'output. Allo scadere del timeout si uccide il
/// process-group (best-effort) e comunque il processo diretto → l'agent prosegue.
/// Ritorna (exit_code, output, timed_out).
pub(crate) fn run_shell(cmd: &str, timeout_secs: u64) -> (i32, String, bool) {
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    // Tetto assoluto per non far bloccare un singolo task troppo a lungo
    // (es. template con timeout molto alti su operazioni di rete). Override via
    // HARDENING_TASK_MAX_SECS. Default 300s.
    let max_secs = std::env::var("HARDENING_TASK_MAX_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(300);
    let timeout_secs = timeout_secs.min(max_secs);

    let seq = SHELL_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = format!("/tmp/cs-hardening-{}-{}.out", std::process::id(), seq);
    // Redirect a file + stdin da /dev/null (niente prompt interattivi).
    let full = format!("{{ {} ; }} </dev/null >{} 2>&1", cmd, tmp);

    let spawn = Command::new("bash")
        .arg("-c")
        .arg(&full)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn();
    let mut child = match spawn {
        Ok(c) => c,
        Err(e) => return (-1, format!("spawn error: {}", e), false),
    };
    let pid = child.id() as i32;
    let start = Instant::now();
    let mut timed_out = false;
    let mut code = -1;
    loop {
        match child.try_wait() {
            Ok(Some(st)) => {
                code = st.code().unwrap_or(-1);
                break;
            }
            Ok(None) => {
                if start.elapsed() >= Duration::from_secs(timeout_secs) {
                    timed_out = true;
                    // Best-effort: uccide il gruppo (bash + figli); poi il diretto.
                    let _ = Command::new("kill").arg("-9").arg(format!("-{}", pid)).status();
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(_) => break,
        }
    }
    let out = std::fs::read_to_string(&tmp).unwrap_or_default();
    let _ = std::fs::remove_file(&tmp);
    (code, out, timed_out)
}

// ── util ─────────────────────────────────────────────────────────────────────

fn first_line(s: &str) -> String { s.lines().next().unwrap_or("").to_string() }

fn detect_os_family() -> String {
    let os = std::fs::read_to_string("/etc/os-release").unwrap_or_default().to_lowercase();
    if os.contains("debian") || os.contains("ubuntu") { "debian".into() }
    else if os.contains("rhel") || os.contains("centos") || os.contains("rocky") || os.contains("alma") || os.contains("fedora") { "rhel".into() }
    else if os.contains("suse") || os.contains("sles") { "sles".into() }
    else { "linux".into() }
}

fn detect_pkg_mgr() -> String {
    for (bin, name) in [("apt-get", "apt"), ("zypper", "zypper"), ("dnf", "dnf")] {
        if Command::new("which").arg(bin).output().map(|o| o.status.success()).unwrap_or(false) {
            return name.to_string();
        }
    }
    "unknown".to_string()
}

/// Valuta le condition del mini-DSL dei template.
fn eval_condition(cond: &str, os_family: &str) -> bool {
    let c = cond.trim();
    if let Some(rest) = c.strip_prefix("os_family") {
        // os_family == 'debian'
        if let Some(val) = rest.split(['=', '\'', '"']).find(|s| !s.trim().is_empty() && *s != " ") {
            let want = val.trim().trim_matches(|ch| ch == '\'' || ch == '"' || ch == ' ');
            return want == os_family;
        }
        return true;
    }
    if let Some(inner) = c.strip_prefix("service_exists(").and_then(|s| s.strip_suffix(")")) {
        let svc = inner.trim_matches(|ch| ch == '\'' || ch == '"');
        return Command::new("systemctl").arg("cat").arg(svc).output()
            .map(|o| o.status.success()).unwrap_or(false);
    }
    if let Some(inner) = c.strip_prefix("mount_exists(").and_then(|s| s.strip_suffix(")")) {
        let mp = inner.trim_matches(|ch| ch == '\'' || ch == '"');
        let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
        return mounts.lines().any(|l| l.split_whitespace().nth(1) == Some(mp));
    }
    // Condizione sconosciuta → non blocca (applica).
    warn!("condizione hardening non riconosciuta, la tratto come vera: {}", cond);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    /// File temporaneo che si autoelimina all'uscita dallo scope (Drop).
    struct TmpFile(String);
    impl Drop for TmpFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn tmp_file(content: &str) -> (TmpFile, String) {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join(format!("dog-agent-test-{}-{}", std::process::id(), seq))
            .to_str()
            .unwrap()
            .to_string();
        std::fs::write(&path, content).unwrap();
        (TmpFile(path.clone()), path)
    }

    #[test]
    fn inserisce_piu_righe_dallo_stesso_task_lines() {
        let (_f, path) = tmp_file("auth required pam_unix.so\n");
        let task = json!({
            "file": path,
            "lines": [
                "auth required pam_faillock.so preauth silent audit deny=5",
                "auth [default=die] pam_faillock.so authfail audit deny=5",
            ],
        });
        let mut backups = Vec::new();
        let msg = act_file_line_present(&task, false, &mut backups).unwrap();
        assert!(msg.contains("2 aggiunte"));
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("pam_faillock.so preauth"));
        assert!(content.contains("pam_faillock.so authfail"));

        // Idempotente: rieseguendo non aggiunge duplicati.
        let msg2 = act_file_line_present(&task, false, &mut backups).unwrap();
        assert!(msg2.contains("2 riga/e già presenti"));
    }

    #[test]
    fn sostituisce_righe_esistenti_con_replace_regex() {
        let (_f, path) = tmp_file("PASS_MAX_DAYS   99999\nPASS_MIN_DAYS   0\n");
        let task = json!({
            "file": path,
            "lines": ["PASS_MAX_DAYS    90", "PASS_MIN_DAYS    1", "PASS_WARN_AGE    14"],
            "replace_regex": "^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE)\\s+.*",
        });
        let mut backups = Vec::new();
        let msg = act_file_line_present(&task, false, &mut backups).unwrap();
        assert!(msg.contains("2 sostituite"));
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("PASS_MAX_DAYS    90"));
        assert!(content.contains("PASS_MIN_DAYS    1"));
        // PASS_WARN_AGE non esisteva già: niente da sostituire, va aggiunta in fondo.
        assert!(content.contains("PASS_WARN_AGE    14"));
    }

    #[test]
    fn inserisce_prima_dell_anchor_con_commento() {
        let (_f, path) = tmp_file("account [success=1] pam_unix.so\naccount requisite pam_deny.so\n");
        let task = json!({
            "file": path,
            "line": "account required pam_faillock.so",
            "anchor": "account.*pam_unix.so",
            "position": "before",
            "comment": "# hardening",
        });
        let mut backups = Vec::new();
        act_file_line_present(&task, false, &mut backups).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines[0], "# hardening");
        assert_eq!(lines[1], "account required pam_faillock.so");
        assert_eq!(lines[2], "account [success=1] pam_unix.so");
    }

    #[test]
    fn dry_run_non_scrive_nulla() {
        let (_f, path) = tmp_file("");
        let task = json!({ "file": path, "line": "test" });
        let mut backups = Vec::new();
        let msg = act_file_line_present(&task, true, &mut backups).unwrap();
        assert!(msg.contains("aggiornerebbe"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
    }
}
