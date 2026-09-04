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
}

/// Punto d'ingresso: applica (o simula) il template. Funzione bloccante:
/// va chiamata in `spawn_blocking`.
pub fn run_hardening(template: &Value, mode: &str) -> HardeningOutcome {
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

fn act_file_line_present(task: &Value, dry: bool, backups: &mut Vec<Value>) -> Result<String, String> {
    let file = s(task, "file").ok_or("file mancante")?;
    let line = s(task, "line").ok_or("line mancante")?;
    let existing = std::fs::read_to_string(file).unwrap_or_default();
    if existing.lines().any(|l| l.trim() == line.trim()) {
        return Ok(format!("riga già presente in {}", file));
    }
    if dry { return Ok(format!("aggiungerebbe riga a {}", file)); }
    record_backup(backups, file);
    let mut new = existing;
    if !new.is_empty() && !new.ends_with('\n') { new.push('\n'); }
    new.push_str(line); new.push('\n');
    std::fs::write(file, new).map_err(|e| format!("write {}: {}", file, e))?;
    Ok(format!("riga aggiunta a {}", file))
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
    let (bin, base): (&str, Vec<&str>) = match detect_pkg_mgr().as_str() {
        "apt" => ("apt-get", vec!["install", "-y"]),
        "zypper" => ("zypper", vec!["--non-interactive", "install"]),
        "dnf" => ("dnf", vec!["install", "-y"]),
        m => return Err(format!("package manager non supportato: {}", m)),
    };
    let mut cmd = Command::new(bin);
    cmd.args(&base);
    for p in &pkgs { cmd.arg(p); }
    let status = cmd.status().map_err(|e| format!("{}: {}", bin, e))?;
    if !status.success() { return Err(format!("install {} fallito", pkgs.join(", "))); }
    Ok(format!("installati: {}", pkgs.join(", ")))
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
    let out = Command::new("bash").arg("-c").arg(cmd).output().map_err(|e| format!("exec: {}", e))?;
    let code = out.status.code().unwrap_or(-1) as i64;
    if code != expected {
        return Err(format!("exit {} (atteso {}): {}", code, expected,
            String::from_utf8_lossy(&out.stderr).lines().next().unwrap_or("")));
    }
    Ok(format!("comando ok (exit {})", code))
}

fn act_script(task: &Value, dry: bool) -> Result<String, String> {
    let script = s(task, "script").ok_or("script mancante")?;
    if dry { return Ok(format!("eseguirebbe script ({} righe)", script.lines().count())); }
    let out = Command::new("bash").arg("-c").arg(script).output().map_err(|e| format!("exec: {}", e))?;
    if !out.status.success() {
        return Err(format!("script exit {}", out.status.code().unwrap_or(-1)));
    }
    Ok("script ok".into())
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
