// ============================================================================
// Posizione di lettura del log JSON di Laurel, persistita su disco.
//
// Prima l'offset era una variabile della sessione WebSocket e ripartiva da 0
// a ogni riconnessione al master: l'agent rileggeva e rispediva l'intero file
// dall'ultima rotazione. Sul master dell'ufficio (2026-11-16) 123.715 eventi
// su 418.197 erano copie, fino a 7 per record, e le regole di correlazione
// scattavano di nuovo sugli eventi rispediti.
//
// Ora la posizione (inode del file + offset) si salva dopo ogni invio riuscito
// e si ricarica a ogni sessione e a ogni riavvio. La rotazione si riconosce
// dal cambio di inode, non solo da un file più corto dell'offset; si leggono
// solo righe complete, mai quella che Laurel sta ancora scrivendo.
// ============================================================================

use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Cartella di stato dell'agent (StateDirectory=dog-agent nel servizio systemd).
pub const STATE_DIR: &str = "/var/lib/dog-agent";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Position {
    pub inode: u64,
    pub offset: u64,
}

/// Dove riprendere a leggere il file in `path`, dato lo stato salvato.
/// - nessuno stato (primo avvio): dalla fine del file, per non rispedire al
///   master giorni di log storico;
/// - inode diverso (il file è stato ruotato): dall'inizio del file nuovo;
/// - file più corto dell'offset (troncato): dall'inizio;
/// - altrimenti dall'offset salvato.
pub fn resume_position(saved: Option<Position>, current_inode: u64, current_len: u64) -> Position {
    match saved {
        None => Position { inode: current_inode, offset: current_len },
        Some(p) if p.inode != current_inode || current_len < p.offset => Position { inode: current_inode, offset: 0 },
        Some(p) => p,
    }
}

/// Legge le righe complete da `pos` e restituisce `(eventi, nuova_posizione)`.
/// Una riga senza newline finale non è ancora completa: resta per la lettura
/// successiva. Le righe non JSON si saltano.
pub fn read_complete_lines(path: &Path, saved: Option<Position>) -> std::io::Result<(Vec<serde_json::Value>, Position)> {
    let mut file = File::open(path)?;
    let meta = file.metadata()?;
    let start = resume_position(saved, meta.ino(), meta.len());
    file.seek(SeekFrom::Start(start.offset))?;

    let mut reader = BufReader::new(file);
    let mut events = Vec::new();
    let mut offset = start.offset;
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = reader.read_until(b'\n', &mut line)?;
        if read == 0 || line.last() != Some(&b'\n') {
            break; // fine file o riga ancora in scrittura
        }
        offset += read as u64;
        let text = String::from_utf8_lossy(&line);
        let trimmed = text.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
            events.push(v);
        }
    }
    Ok((events, Position { inode: start.inode, offset }))
}

/// File di stato per un target (un agent può servire più target).
pub fn state_file(state_dir: &Path, target_name: &str) -> PathBuf {
    let safe: String = target_name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    state_dir.join(format!("laurel-{safe}.json"))
}

pub fn load(path: &Path) -> Option<Position> {
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Scrittura atomica (file temporaneo + rename): un crash a metà non lascia
/// uno stato illeggibile.
pub fn save(path: &Path, pos: Position) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(&pos)?)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("laurel-cursor-test-{}-{}", std::process::id(), rand_suffix()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn rand_suffix() -> u128 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    }

    #[test]
    fn first_start_resumes_from_end_of_file() {
        let p = resume_position(None, 7, 1000);
        assert_eq!(p, Position { inode: 7, offset: 1000 });
    }

    #[test]
    fn rotation_or_truncation_restarts_from_zero() {
        let saved = Some(Position { inode: 7, offset: 500 });
        assert_eq!(resume_position(saved, 8, 9000).offset, 0, "inode cambiato: file ruotato");
        assert_eq!(resume_position(saved, 7, 100).offset, 0, "file troncato");
        assert_eq!(resume_position(saved, 7, 900).offset, 500);
    }

    #[test]
    fn reconnect_does_not_resend_already_sent_events() {
        let d = dir();
        let log = d.join("audit.log");
        std::fs::write(&log, "{\"ID\":\"1\"}\n{\"ID\":\"2\"}\n").unwrap();
        let start = resume_position(None, std::fs::metadata(&log).unwrap().ino(), 0);
        let (first, pos) = read_complete_lines(&log, Some(Position { offset: 0, ..start })).unwrap();
        assert_eq!(first.len(), 2);

        // Persistita e ricaricata come dopo una riconnessione o un riavvio.
        let state = state_file(&d, "cs-office");
        save(&state, pos).unwrap();
        let (again, _) = read_complete_lines(&log, load(&state)).unwrap();
        assert!(again.is_empty(), "nessuna copia dopo la riconnessione");

        let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        writeln!(f, "{{\"ID\":\"3\"}}").unwrap();
        let (new_events, _) = read_complete_lines(&log, load(&state)).unwrap();
        assert_eq!(new_events.len(), 1);
        assert_eq!(new_events[0]["ID"], "3");
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn a_line_still_being_written_is_left_for_the_next_read() {
        let d = dir();
        let log = d.join("audit.log");
        std::fs::write(&log, "{\"ID\":\"1\"}\n{\"ID\":\"2\"").unwrap();
        let ino = std::fs::metadata(&log).unwrap().ino();
        let (events, pos) = read_complete_lines(&log, Some(Position { inode: ino, offset: 0 })).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(pos.offset, "{\"ID\":\"1\"}\n".len() as u64);

        let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        writeln!(f, "}}").unwrap();
        let (rest, _) = read_complete_lines(&log, Some(pos)).unwrap();
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0]["ID"], "2");
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn state_file_name_is_safe() {
        assert_eq!(state_file(Path::new("/s"), "cs/../x y"), PathBuf::from("/s/laurel-cs____x_y.json"));
    }
}
