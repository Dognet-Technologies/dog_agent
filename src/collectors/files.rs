use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesMetrics {
    /// File con bit SUID impostato
    pub suid_files: Vec<String>,
    /// File world-writable
    pub world_writable: Vec<String>,
    /// Snapshot integrità (path → hash SHA512)
    pub integrity_snapshot: Vec<FileHash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHash {
    pub path: String,
    pub sha512: String,
    pub size_bytes: u64,
    pub modified_at: i64,
}

/// Collector standard: scansiona percorsi tipici di sistema
pub async fn collect() -> Result<FilesMetrics> {
    let paths = vec![
        "/usr/bin".to_string(),
        "/usr/sbin".to_string(),
        "/bin".to_string(),
        "/sbin".to_string(),
    ];
    collect_paths(&paths).await
}

/// Tempo massimo di un check_integrity: sotto il timeout di dispatch (90s)
/// del comando, così il walk si ferma da solo invece di continuare in un
/// thread bloccante dopo che il comando è già stato dato per fallito.
const INTEGRITY_CHECK_BUDGET: std::time::Duration = std::time::Duration::from_secs(75);

/// Verifica integrità su percorsi specifici (usata da comando check_integrity)
pub async fn check_integrity(paths: &[String]) -> Result<Vec<FileHash>> {
    let paths_owned = paths.to_vec();
    let deadline = std::time::Instant::now() + INTEGRITY_CHECK_BUDGET;
    tokio::task::spawn_blocking(move || hash_paths_until(&paths_owned, Some(deadline)))
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking error: {e}"))?
}

async fn collect_paths(paths: &[String]) -> Result<FilesMetrics> {
    let paths_owned = paths.to_vec();
    tokio::task::spawn_blocking(move || collect_sync(&paths_owned))
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking error: {e}"))?
}

fn collect_sync(paths: &[String]) -> Result<FilesMetrics> {
    let integrity_snapshot = hash_paths(paths)?;

    #[cfg(target_os = "linux")]
    let (suid_files, world_writable) = find_special_files(paths);

    #[cfg(not(target_os = "linux"))]
    let (suid_files, world_writable) = (vec![], vec![]);

    Ok(FilesMetrics {
        suid_files,
        world_writable,
        integrity_snapshot,
    })
}

fn hash_paths(paths: &[String]) -> Result<Vec<FileHash>> {
    hash_paths_until(paths, None)
}

/// Come `hash_paths`, ma oltre `deadline` si ferma con un errore invece di
/// continuare a girare in un thread bloccante.
fn hash_paths_until(paths: &[String], deadline: Option<std::time::Instant>) -> Result<Vec<FileHash>> {
    let mut hashes = Vec::new();

    for base in paths {
        for entry in WalkDir::new(base)
            .follow_links(false)
            .max_depth(3)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            if deadline.is_some_and(|d| std::time::Instant::now() >= d) {
                anyhow::bail!(
                    "check_integrity interrotto dopo {:?}: {} file verificati",
                    INTEGRITY_CHECK_BUDGET,
                    hashes.len()
                );
            }
            let path = entry.path();
            if let Ok(hash) = hash_file(path) {
                hashes.push(hash);
            }
        }
    }

    Ok(hashes)
}

/// Cap di dimensione prima di leggere un file interamente in memoria per
/// l'hash — senza questo, un path puntato su un file enorme (o un
/// "file" speciale che non termina mai la lettura) poteva bloccare/esaurire
/// la memoria del thread bloccante (HIGH trovato in code review, 2026-11).
const MAX_HASH_FILE_SIZE_BYTES: u64 = 100 * 1024 * 1024; // 100 MiB

fn hash_file(path: &Path) -> Result<FileHash> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > MAX_HASH_FILE_SIZE_BYTES {
        anyhow::bail!(
            "file {} troppo grande per l'hash ({} byte > {} byte)",
            path.display(),
            meta.len(),
            MAX_HASH_FILE_SIZE_BYTES
        );
    }
    // Hash a blocchi: prima il file (fino a 100 MiB) veniva letto tutto in
    // memoria, per ogni file del walk.
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let mut hasher = Sha512::new();
    std::io::copy(&mut file.take(MAX_HASH_FILE_SIZE_BYTES), &mut hasher)?;
    let digest = hex::encode(hasher.finalize());

    let modified_at = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    Ok(FileHash {
        path: path.to_string_lossy().to_string(),
        sha512: digest,
        size_bytes: meta.len(),
        modified_at,
    })
}

#[cfg(target_os = "linux")]
fn find_special_files(paths: &[String]) -> (Vec<String>, Vec<String>) {
    use std::os::unix::fs::PermissionsExt;

    let mut suid = Vec::new();
    let mut world_writable = Vec::new();

    for base in paths {
        for entry in WalkDir::new(base)
            .follow_links(false)
            .max_depth(5)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            if let Ok(meta) = entry.metadata() {
                let mode = meta.permissions().mode();
                let path = entry.path().to_string_lossy().to_string();

                // SUID bit: 0o4000
                if mode & 0o4000 != 0 {
                    suid.push(path.clone());
                }

                // World-writable: 0o002
                if mode & 0o002 != 0 {
                    world_writable.push(path);
                }
            }
        }
    }

    (suid, world_writable)
}
