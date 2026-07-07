# Dog Agent — Makefile
# Comandi principali per build, package e cross-compilazione.
#
# Dipendenze:
#   - Rust toolchain (cargo)
#   - cargo-deb:  cargo install cargo-deb
#   - cross:      cargo install cross  (per cross-compilazione)
#   - Docker:     richiesto da cross

.PHONY: all build release deb deb-musl rpm exe clean fmt check

# ── Build ─────────────────────────────────────────────────────────────────────

all: build

build:
	cargo build

release:
	cargo build --release

# ── Packaging Linux (.deb) ────────────────────────────────────────────────────

deb: release
	cargo deb

# .deb con binario STATICO musl — portabile su qualsiasi glibc (Debian 12/13, RHEL…)
# cargo-deb riscrive da solo gli asset `target/release/` → `target/<triple>/release/`.
deb-musl:
	cargo deb --target x86_64-unknown-linux-musl

# Crea .deb per target arm64 (es. Raspberry Pi, server ARM)
deb-arm64:
	cross build --release --target aarch64-unknown-linux-gnu
	cargo deb --no-build --target aarch64-unknown-linux-gnu

# ── Packaging Linux (.rpm) ────────────────────────────────────────────────────

# .rpm (openSUSE/RHEL) col binario statico musl — richiede cargo-generate-rpm.
# Gli asset in [package.metadata.generate-rpm] puntano già alla build musl.
rpm:
	cargo build --release --target x86_64-unknown-linux-musl
	cargo generate-rpm
	@echo "Output: target/generate-rpm/"

# ── Packaging Windows (.exe) ──────────────────────────────────────────────────

exe:
	cross build --release --target x86_64-pc-windows-gnu
	@echo "Binary: target/x86_64-pc-windows-gnu/release/dog-agent.exe"

# ── Sviluppo ─────────────────────────────────────────────────────────────────

fmt:
	cargo fmt

check:
	cargo check
	cargo clippy -- -D warnings

test:
	cargo test

clean:
	cargo clean

# ── Info ─────────────────────────────────────────────────────────────────────

info:
	@echo "Targets disponibili:"
	@echo "  make build      — debug build"
	@echo "  make release    — release build"
	@echo "  make deb        — crea .deb per Linux x86_64"
	@echo "  make deb-arm64  — crea .deb per Linux arm64"
	@echo "  make exe        — crea .exe per Windows x86_64"
	@echo "  make check      — cargo check + clippy"
	@echo "  make clean      — pulizia artefatti"
