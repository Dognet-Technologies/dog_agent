# Nota di handoff — branch `fix/systemd-startup` (2026-07-02, PC di casa)

Nota per l'agent/sessione che riprende il lavoro dall'ufficio. Contesto:
Simone aveva segnalato che il pacchetto compilava e si installava ma il
servizio aveva problemi all'avvio, con "2 file/directory systemd in conflitto"
visti durante un'installazione manuale.

## Cosa è stato trovato e corretto (commit `9093c37` + `e104f59`)

1. **Unit systemd duplicata nel .deb** — `Cargo.toml` la elencava negli
   `assets` (→ `lib/systemd/system/`) mentre la feature `systemd-units` di
   cargo-deb la includeva già (→ `usr/lib/systemd/system/`). Su Debian
   usr-merged sono lo stesso path aliasato: era questo il conflitto.
   Rimossa dagli assets; ora nel .deb c'è una sola unit.

2. **Avvio fallito con `226/NAMESPACE`** — `ReadWritePaths=/run/xtables.lock`
   fallisce se il file non esiste, e a boot pulito `/run` è vuoto (il lock lo
   crea il primo iptables). Fix: `debian/dog-agent.tmpfiles` (installato in
   `usr/lib/tmpfiles.d/dog-agent.conf`) lo crea a ogni boot; il postinst lancia
   `systemd-tmpfiles --create` per il primo start post-install.
   ⚠️ NON usare `ExecStartPre=+touch`: su systemd 257 il prefisso `+` non
   esenta dal mount namespace della unit — già provato, fallisce uguale.

3. **`/opt` read-only sotto `ProtectSystem=strict`** — `sync_rules` lancia
   `firewall-manager --export-json /opt/sentinelsuite/firedog/export/...` come
   figlio dell'agent (eredita il namespace). Aggiunto
   `ReadWritePaths=-/opt/sentinelsuite/firedog/export` (il `-` lo ignora dove
   firewall-manager non è installato).

4. **postinst ripulito** — non crea più `/var/run/dog-agent` e
   `/var/log/dog-agent` (li gestisce systemd via RuntimeDirectory/
   LogsDirectory; l'ownership `dog-agent` confliggeva col servizio root).

## Verifica già fatta (VM Debian 13 pulita, systemd 257)

`dpkg -i` → `systemctl start` OK → `enable` + reboot → `active (running)`,
`/run/xtables.lock` creato da tmpfiles.d, entrambi i target avviati con
retry/backoff verso gli URL placeholder della config d'esempio.

## Da fare in ufficio

- [ ] Sulle macchine dove l'installazione era stata fatta a mano: controllare
      `systemctl status dog-agent` → riga "Loaded:". Se la unit caricata è
      `/etc/systemd/system/dog-agent.service` è una copia manuale stantia che
      ha precedenza sul pacchetto: rimuoverla e `systemctl daemon-reload`.
- [ ] Test di connessione reale ai backend FireDog/CyberSheppard con la config
      vera (da casa non raggiungibili).
- [ ] Decidere sul packaging musl: `make deb` usa la build glibc, ma il commit
      `1ed9996` prevede la build statica musl. Se serve il .deb statico va
      aggiunto un target che passi `--target x86_64-unknown-linux-musl` sia a
      cargo build sia a cargo-deb (e l'asset del binario va adeguato).
- [ ] Se tutto ok: merge di `fix/systemd-startup` in `Stable`.

Questa nota può essere rimossa al merge.
