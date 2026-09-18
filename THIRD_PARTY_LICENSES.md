# Attribuzioni di terze parti

## Linux-Security-Audit-Project

- **Autore**: Sandler73
- **Repository**: https://github.com/Sandler73/Linux-Security-Audit-Project
- **Licenza**: MIT (con termini aggiuntivi non-copyleft — vedi
  [`vendor/linux-security-audit/LICENSE`](vendor/linux-security-audit/LICENSE))
- **Commit vendorizzato**: vedi
  [`vendor/linux-security-audit/UPSTREAM_COMMIT.txt`](vendor/linux-security-audit/UPSTREAM_COMMIT.txt)

`dog-agent` include, invariato, il motore di audit di sicurezza Linux multi-framework
(`linux_security_audit.py` + `modules/` + `shared_components/`) sotto
`vendor/linux-security-audit/`, installato sul target in
`/opt/dognet/linux-security-audit/`. È usato in sola lettura (modalità audit, senza flag
`--remediate`) per popolare lo stato di compliance dei controlli (`security_audit_scan`).

La licenza MIT consente esplicitamente uso commerciale, modifica, distribuzione e
sublicenza anche all'interno di un prodotto chiuso a pagamento; l'unico obbligo è
mantenere questa nota di attribuzione e il testo della licenza. Se in futuro il codice
vendorizzato verrà modificato rispetto all'upstream, la modifica verrà segnalata qui con
la data, come richiesto dalla sezione 8(a) dei termini aggiuntivi della licenza.

**Modifiche rispetto all'upstream**: nessuna, ad oggi (2026-09-18).
