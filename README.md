# Dog Agent

Agent unificato della Dognet Suite: un singolo binario Rust che si connette
via WebSocket a uno o più backend **FireDog**, **CyberSheppard** e
**SentinelCore** (predisposto), configurati come `[[targets]]` indipendenti
in `/etc/dog-agent/agent.conf`.

---

## Dipendenze di compilazione

| Strumento | Installazione | Serve per |
|---|---|---|
| Rust toolchain (≥ 1.75) | [rustup.rs](https://rustup.rs) | build |
| `cargo-deb` | `cargo install cargo-deb` | packaging `.deb` |
| `musl-tools` (`musl-gcc`) | `apt install musl-tools` | build statica musl |
| target musl | `rustup target add x86_64-unknown-linux-musl` | build statica musl |
| `cross` + Docker | `cargo install cross` | cross-compile arm64 / Windows |

Non servono librerie di sistema (OpenSSL ecc.): il TLS è **rustls** con root
CA webpki incluse, quindi il binario non ha dipendenze runtime.

## Compilazione

```bash
# Build di sviluppo
make build            # = cargo build

# Build release (glibc, dinamica)
make release          # = cargo build --release

# Build release STATICA (musl) — portabile su qualsiasi glibc
cargo build --release --target x86_64-unknown-linux-musl
```

> **Nota:** la build consigliata per il deploy è quella **musl statica**
> (vedi commit `1ed9996`): gira identica su Debian/Ubuntu/RHEL senza
> problemi di versione glibc. `.cargo/config.toml` pinna già `musl-gcc`
> come linker per quel target.

Controlli qualità:

```bash
make check            # cargo check + clippy -D warnings
make test             # cargo test
make fmt              # cargo fmt
```

## Packaging `.deb`

```bash
# glibc (usa target/release/dog-agent)
make deb              # = cargo build --release && cargo deb
# output: target/debian/dog-agent_<versione>_amd64.deb

# arm64 (richiede cross + Docker)
make deb-arm64
```

Il pacchetto contiene:

| File | Destinazione |
|---|---|
| binario | `/usr/bin/dog-agent` |
| config d'esempio | `/etc/dog-agent/agent.conf.example` |
| unit systemd | `/usr/lib/systemd/system/dog-agent.service` |
| tmpfiles | `/usr/lib/tmpfiles.d/dog-agent.conf` |

⚠️ La unit systemd **non** va aggiunta agli `assets` di `Cargo.toml`: la
feature `systemd-units` di cargo-deb la include già da `debian/`. Elencarla
due volte produce un pacchetto con due copie in conflitto
(`lib/systemd/system` e `usr/lib/systemd/system` sono lo stesso path sui
sistemi usr-merged).

⚠️ `make deb` impacchetta la build **glibc**. Se serve il `.deb` col binario
statico musl va passato il target sia a cargo sia a cargo-deb
(`cargo deb --target x86_64-unknown-linux-musl` + asset adeguato).

## Installazione sul target

Requisiti sul target: distro Debian-like con systemd; `iptables` per le
funzioni firewall di FireDog; l'agent gira come **root** (necessario per
iptables e per i collector che leggono `/proc` e i log di sistema).

```bash
# 1. Copia e installa il pacchetto
scp target/debian/dog-agent_*.deb utente@target:/tmp/
sudo dpkg -i /tmp/dog-agent_*.deb

# 2. Configura (il postinst copia l'esempio se agent.conf non esiste)
sudo nano /etc/dog-agent/agent.conf     # url, api_key, ip/hostname/mac, target_id…

# 3. Abilita e avvia
sudo systemctl enable --now dog-agent

# 4. Verifica
systemctl status dog-agent
sudo journalctl -u dog-agent -f
```

Il postinst crea l'utente di sistema `dog-agent` (owner della config, 640) e
lancia `systemd-tmpfiles --create` per creare subito `/run/xtables.lock`.

### Note su systemd (avvio robusto)

La unit usa `ProtectSystem=strict`; le path scrivibili sono gestite così:

- `/run/dog-agent` e `/var/log/dog-agent` → `RuntimeDirectory`/`LogsDirectory`
  (creati da systemd a ogni avvio, **non** vanno creati a mano);
- `/run/xtables.lock` → creato a ogni boot da `tmpfiles.d/dog-agent.conf`.
  Deve esistere **prima** dell'avvio o il mount namespace fallisce con
  `226/NAMESPACE`. Non usare `ExecStartPre=+touch`: su systemd ≥ 257 il
  prefisso `+` non esenta dal namespace della unit;
- `/opt/sentinelsuite/firedog/export` → scrivibile (prefisso `-`: ignorato se
  assente) perché `sync_rules` lancia `firewall-manager` come figlio
  dell'agent, che eredita il sandbox.

Se su una macchina esiste una copia manuale della unit in
`/etc/systemd/system/dog-agent.service`, quella ha precedenza sul pacchetto:
rimuoverla e fare `systemctl daemon-reload` (la riga `Loaded:` di
`systemctl status` mostra quale unit è caricata).

### Disinstallazione

```bash
sudo dpkg -r dog-agent        # rimuove (conserva /etc/dog-agent)
sudo dpkg -P dog-agent        # purge completo
```

## Configurazione

Vedi `config.example.toml`: ogni `[[targets]]` gira in un task tokio
indipendente con riconnessione a backoff esponenziale. Campi obbligatori per
FireDog: `ip`, `hostname`, `mac` (il server verifica
`SHA512(ip+hostname+mac)` nel pairing); per CyberSheppard: `target_id`.
