use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServicesMetrics {
    pub systemd_services: Vec<ServiceStatus>,
    pub docker_containers: Vec<ContainerStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub name: String,
    pub load_state: String,   // loaded | not-found | masked
    pub active_state: String, // active | inactive | failed | activating
    pub sub_state: String,    // running | dead | exited | ...
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerStatus {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,  // running | exited | paused | ...
    pub status: String, // "Up 2 hours" | "Exited (0) 5 minutes ago"
}

pub async fn collect() -> Result<ServicesMetrics> {
    tokio::task::spawn_blocking(collect_sync)
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking error: {}", e))?
}

fn collect_sync() -> Result<ServicesMetrics> {
    let systemd_services = collect_systemd();
    let docker_containers = collect_docker();

    Ok(ServicesMetrics {
        systemd_services,
        docker_containers,
    })
}

fn collect_systemd() -> Vec<ServiceStatus> {
    #[cfg(not(target_os = "linux"))]
    return vec![];

    #[cfg(target_os = "linux")]
    {
        let output = match std::process::Command::new("systemctl")
            .args(["list-units", "--type=service", "--no-pager", "--plain", "--no-legend"])
            .output()
        {
            Ok(o) => o,
            Err(_) => return vec![],
        };

        let text = String::from_utf8_lossy(&output.stdout);
        let mut services = Vec::new();

        for line in text.lines() {
            // Formato: "  unit.service  loaded  active  running  Description"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                continue;
            }

            services.push(ServiceStatus {
                name: parts[0].trim_end_matches(".service").to_string(),
                load_state: parts[1].to_string(),
                active_state: parts[2].to_string(),
                sub_state: parts[3].to_string(),
                description: parts[4..].join(" "),
            });
        }

        services
    }
}

// Risultato di "docker è installato?" verificato una sola volta per tutta la
// vita del processo agent (non ad ogni ciclo di collection) — su un host
// senza Docker, lanciare comunque `docker ps` ogni 30s produceva un `execve`
// fallito che auditd/Laurel registrava come evento di sicurezza a tutti gli
// effetti: su un host reale senza Docker, migliaia di eventi di puro rumore
// al giorno, per sempre (bug trovato analizzando il volume reale di
// security_events sul lab: 18705 tentativi falliti accumulati in 17 giorni
// su un solo host). Il controllo di presenza qui sotto è un check sul
// filesystem (PATH), non uno spawn di processo: non genera a sua volta un
// evento di audit come farebbe anche solo un `docker --version`.
static DOCKER_AVAILABLE: OnceLock<bool> = OnceLock::new();

/// Vero se uno dei `dirs` contiene un file regolare chiamato `name` — stessa
/// logica di una ricerca in PATH, isolata dall'ambiente reale per essere
/// testabile senza mutare `PATH` del processo (condiviso tra i test).
fn binary_exists_in<'a>(mut dirs: impl Iterator<Item = &'a std::path::Path>, name: &str) -> bool {
    dirs.any(|dir| dir.join(name).is_file())
}

fn docker_binary_exists() -> bool {
    let Some(path_var) = std::env::var_os("PATH") else {
        return false;
    };
    let dirs: Vec<_> = std::env::split_paths(&path_var).collect();
    binary_exists_in(dirs.iter().map(|p| p.as_path()), "docker")
}

fn collect_docker() -> Vec<ContainerStatus> {
    if !*DOCKER_AVAILABLE.get_or_init(docker_binary_exists) {
        return vec![];
    }

    let output = match std::process::Command::new("docker")
        .args(["ps", "-a", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return vec![], // spawn fallito per un altro motivo (permessi, binario corrotto, ...)
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut containers = Vec::new();

    for line in text.lines() {
        let parts: Vec<&str> = line.splitn(5, '\t').collect();
        if parts.len() < 5 {
            continue;
        }

        containers.push(ContainerStatus {
            id: parts[0].to_string(),
            name: parts[1].to_string(),
            image: parts[2].to_string(),
            state: parts[3].to_string(),
            status: parts[4].to_string(),
        });
    }

    containers
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Directory temporanea isolata (sotto il pid del test runner + un contatore
    /// statico) invece di mutare `PATH`/usare una libreria esterna di tempdir —
    /// evitabile qui perché il repo non ha ancora `tempfile` tra le dipendenze.
    fn unique_tmp_dir(label: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("dog-agent-test-{label}-{}-{n}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn binary_exists_in_trova_un_file_regolare_in_una_delle_directory() {
        let dir = unique_tmp_dir("found");
        fs::write(dir.join("docker"), b"").unwrap();
        assert!(binary_exists_in(std::iter::once(dir.as_path()), "docker"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn binary_exists_in_false_se_nessuna_directory_contiene_il_file() {
        let dir = unique_tmp_dir("missing");
        assert!(!binary_exists_in(std::iter::once(dir.as_path()), "docker"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn binary_exists_in_ignora_una_directory_con_quel_nome_che_non_e_un_file() {
        // Caso reale che ha causato il bug originale a monte: una PATH con molte
        // directory dove "docker" non esiste in nessuna — qui si verifica che una
        // sotto-directory chiamata "docker" (non un file) non dia un falso positivo.
        let dir = unique_tmp_dir("subdir-not-file");
        fs::create_dir_all(dir.join("docker")).unwrap();
        assert!(!binary_exists_in(std::iter::once(dir.as_path()), "docker"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn docker_available_e_cache_una_sola_volta_per_lifetime_del_processo() {
        // DOCKER_AVAILABLE è condiviso dal processo di test: qui si verifica solo
        // che get_or_init non vada in panico e ritorni un bool coerente,
        // chiamandolo più volte — il punto del fix (lo spawn di `docker` non
        // avviene più ad ogni chiamata) non è osservabile da un test di unità
        // senza mockare il filesystem di sistema, vedi collect_docker().
        let first = *DOCKER_AVAILABLE.get_or_init(docker_binary_exists);
        let second = *DOCKER_AVAILABLE.get_or_init(docker_binary_exists);
        assert_eq!(first, second);
    }
}
