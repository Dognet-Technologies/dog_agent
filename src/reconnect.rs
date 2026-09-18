/// Strategia di riconnessione a due livelli, condivisa dai target che si
/// connettono via WebSocket (cybersheppard, firedog).
///
/// Il difetto del vecchio backoff esponenziale puro: un attacco/errore
/// isolato dopo una sessione lunga e sana ereditava il ritardo massimo
/// raggiunto da errori precedenti (anche di ore prima), perché il contatore
/// si resettava solo su chiusura "pulita" della sessione (`Ok(())`), mai su
/// errore — un riavvio brusco del server (comune in laboratorio) è sempre
/// un `Err`, quindi il backoff restava bloccato al tetto massimo.
///
/// Qui il segnale che conta è **quanto è durata la sessione appena chiusa**,
/// non se è terminata con `Ok` o `Err`: una sessione considerata "stabile"
/// (rimasta in piedi almeno [`STABLE_SESSION_SECS`]) dimostra che la
/// configurazione è valida e il server è raggiungibile, quindi il prossimo
/// tentativo riparte dal livello veloce indipendentemente da come è finita.
use std::time::Duration;

use crate::config::ReconnectConfig;

/// Sessioni più corte di questa soglia non "guadagnano" il reset del livello
/// veloce: un fallimento immediato (credenziali sbagliate, URL errato) resta
/// nel livello veloce finché non esaurisce i tentativi, poi passa al lento.
const STABLE_SESSION_SECS: u64 = 15;

pub struct Reconnect {
    fast_delay: Duration,
    fast_max_attempts: u32,
    slow_delay: Duration,
    fast_attempts: u32,
}

impl Reconnect {
    pub fn new(cfg: &ReconnectConfig) -> Self {
        Self {
            fast_delay: Duration::from_secs(cfg.fast_backoff_secs),
            fast_max_attempts: cfg.fast_max_attempts,
            slow_delay: Duration::from_secs(cfg.slow_backoff_secs),
            fast_attempts: 0,
        }
    }

    /// Da chiamare dopo ogni tentativo di sessione (chiusa con `Ok` o `Err`),
    /// passando quanto è durata. Ritorna l'attesa prima del prossimo tentativo.
    pub fn next_delay(&mut self, session_duration: Duration) -> Duration {
        if session_duration.as_secs() >= STABLE_SESSION_SECS {
            self.fast_attempts = 0;
        }

        if self.fast_attempts < self.fast_max_attempts {
            self.fast_attempts += 1;
            self.fast_delay
        } else {
            self.slow_delay
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ReconnectConfig {
        ReconnectConfig {
            fast_backoff_secs: 5,
            fast_max_attempts: 3,
            slow_backoff_secs: 1800,
        }
    }

    #[test]
    fn usa_il_livello_veloce_finche_non_esaurisce_i_tentativi() {
        let mut r = Reconnect::new(&cfg());
        let short = Duration::from_secs(1);
        assert_eq!(r.next_delay(short), Duration::from_secs(5));
        assert_eq!(r.next_delay(short), Duration::from_secs(5));
        assert_eq!(r.next_delay(short), Duration::from_secs(5));
    }

    #[test]
    fn passa_al_livello_lento_dopo_troppi_fallimenti_rapidi() {
        let mut r = Reconnect::new(&cfg());
        let short = Duration::from_secs(1);
        for _ in 0..3 {
            r.next_delay(short);
        }
        assert_eq!(r.next_delay(short), Duration::from_secs(1800));
        assert_eq!(r.next_delay(short), Duration::from_secs(1800));
    }

    #[test]
    fn una_sessione_stabile_resetta_il_livello_veloce_anche_dopo_un_errore() {
        let mut r = Reconnect::new(&cfg());
        let short = Duration::from_secs(1);
        for _ in 0..3 {
            r.next_delay(short);
        }
        assert_eq!(r.next_delay(short), Duration::from_secs(1800));

        // Una sessione durata >= STABLE_SESSION_SECS, anche se finita in errore,
        // dimostra che il server è raggiungibile: si riparte dal livello veloce.
        let stable = Duration::from_secs(20);
        assert_eq!(r.next_delay(stable), Duration::from_secs(5));
        assert_eq!(r.next_delay(short), Duration::from_secs(5));
    }
}
