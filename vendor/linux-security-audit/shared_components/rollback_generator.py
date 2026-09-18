"""
rollback_generator.py - Inverse change-script generator for remediations.

SYNOPSIS
    Captures the pre-modification state of system configuration before
    a remediation runs, then emits a bash script that restores that
    state. Provides a safety net for automated remediation by giving
    operators a single command to undo the audit's changes.

DESCRIPTION
    Different remediation types require different rollback strategies.
    For idempotent text-line edits (e.g. sshd_config) the inverse
    operation is to restore the captured value. For service state
    changes the inverse is to set the service to its previous state.
    For sysctl writes the inverse is to write the previous numeric
    value or remove the configuration line entirely if there was no
    previous setting.

    The generator is invoked once per remediation operation by the
    orchestrator, accumulating capture records into a manifest. When
    remediation completes (or fails partway), generate_script() emits
    a single bash file that processes the manifest in reverse order.

    Safety properties:
        - The generated script uses 'set -euo pipefail' to halt on errors
        - Each operation logs its action to the script output
        - File-content rollback uses inline heredocs (no temp file race)
        - Permission rollback restores both mode and ownership
        - Service rollback respects the systemd active-state distinction
        - Generated scripts are written 0700 (root only)

PARAMETERS
    Public API:
        RollbackGenerator() - construct a generator
        capture_*() methods - record pre-modification state
        generate_script(path) - emit the rollback bash script

EXAMPLES
    >>> gen = RollbackGenerator()
    >>> gen.capture_file("/etc/ssh/sshd_config")
    >>> # ... apply remediation ...
    >>> gen.generate_script("/var/lib/audit/rollback-20260426-143000.sh")

NOTES
    Version: 3.0
    Stdlib only.
    Captured file contents are stored in memory (not on disk) until
    generate_script() runs. This avoids leaving capture state in /tmp
    if the audit process exits unexpectedly. Memory pressure: each
    captured file consumes its size in bytes plus base64 overhead.
"""

from __future__ import annotations

import base64
import datetime
import logging
import os
import re
import shutil
import stat
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("audit.rollback")


# Capture record types. Each represents one piece of state that can be
# rolled back. The script generator emits the appropriate inverse for
# each record type.

CAPTURE_FILE_CONTENT = "file_content"
CAPTURE_FILE_PERMISSIONS = "file_permissions"
CAPTURE_FILE_ABSENT = "file_absent"
CAPTURE_SYSCTL = "sysctl"
CAPTURE_SERVICE_STATE = "service_state"
CAPTURE_SERVICE_ENABLEMENT = "service_enabled"
CAPTURE_KERNEL_MODULE = "kernel_module"


@dataclass
class CaptureRecord:
    """A single captured pre-modification state element.

    Fields:
        record_type: One of CAPTURE_* constants
        target: Path, parameter name, or unit name being captured
        previous_value: The original state to be restored
        metadata: Auxiliary data needed for restoration (e.g. file mode)
        timestamp: ISO 8601 capture time
    """

    record_type: str
    target: str
    previous_value: str
    metadata: Dict[str, str] = field(default_factory=dict)
    timestamp: str = ""


# Maximum size of a captured file. Files larger than this are not
# captured and the operator is informed in the manifest. Most security-
# relevant config files are well under 1 MiB; this limit prevents
# accidental capture of large databases or logs.

_MAX_CAPTURE_BYTES = 1 * 1024 * 1024

# Validation patterns. All values that flow into generated bash code are
# either single-quoted with escaping or restricted to these patterns to
# prevent code injection in the rollback script.

_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9._/\-+@]+$")
_SAFE_UNIT_RE = re.compile(r"^[A-Za-z0-9@_.\-:]+$")
_SAFE_SYSCTL_RE = re.compile(r"^[a-z0-9_.\-]+$")
_SAFE_NUMERIC_RE = re.compile(r"^-?\d+(\.\d+)?$")


def _shell_quote(value: str) -> str:
    """Quote a string for safe inclusion in a single-quoted bash literal.

    The bash convention for embedding single quotes in a single-quoted
    string is to close the string, insert an escaped quote, and reopen.
    """
    return "'" + value.replace("'", "'\\''") + "'"


def _validate_path(path: str) -> bool:
    """Reject paths with shell-meaningful characters or traversal attempts."""
    if not path or not isinstance(path, str):
        return False
    if ".." in path.split("/"):
        return False
    return bool(_SAFE_PATH_RE.match(path))


def _validate_unit(unit: str) -> bool:
    if not unit or not isinstance(unit, str):
        return False
    return bool(_SAFE_UNIT_RE.match(unit))


def _validate_sysctl_key(key: str) -> bool:
    if not key or not isinstance(key, str):
        return False
    return bool(_SAFE_SYSCTL_RE.match(key))


def _now_iso() -> str:
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


class RollbackGenerator:
    """Accumulates capture records and emits a rollback bash script.

    Thread-safe: capture methods may be called from parallel module
    execution. Each capture appends a record under a lock; generation
    serialises the accumulated records into the script.
    """

    def __init__(self) -> None:
        self._records: List[CaptureRecord] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Capture methods
    # ------------------------------------------------------------------

    def capture_file(self, path: str) -> bool:
        """Snapshot a file's current contents and permissions.

        Returns True on successful capture. False is returned for missing
        files (use capture_file_absence to record that a file should be
        removed by rollback), oversized files, or paths that fail
        validation.
        """
        if not _validate_path(path):
            logger.warning("Refusing to capture file with unsafe path: %r", path)
            return False

        try:
            st = os.stat(path)
        except FileNotFoundError:
            # File doesn't exist - capture this fact so rollback can delete
            # any file that the remediation creates here.
            return self.capture_file_absence(path)
        except OSError as exc:
            logger.warning("Cannot stat %s: %s", path, exc)
            return False

        if st.st_size > _MAX_CAPTURE_BYTES:
            logger.warning(
                "File %s exceeds %d byte capture limit; not captured",
                path, _MAX_CAPTURE_BYTES,
            )
            return False

        try:
            with open(path, "rb") as f:
                content_bytes = f.read()
        except OSError as exc:
            logger.warning("Cannot read %s: %s", path, exc)
            return False

        encoded = base64.b64encode(content_bytes).decode("ascii")
        record = CaptureRecord(
            record_type=CAPTURE_FILE_CONTENT,
            target=path,
            previous_value=encoded,
            metadata={
                "mode": oct(stat.S_IMODE(st.st_mode))[2:].zfill(4),
                "uid": str(st.st_uid),
                "gid": str(st.st_gid),
                "size": str(st.st_size),
            },
            timestamp=_now_iso(),
        )
        with self._lock:
            self._records.append(record)
        return True

    def capture_file_absence(self, path: str) -> bool:
        """Record that a file did not exist before remediation.

        If remediation later creates the file, rollback will delete it.
        """
        if not _validate_path(path):
            return False

        record = CaptureRecord(
            record_type=CAPTURE_FILE_ABSENT,
            target=path,
            previous_value="",
            timestamp=_now_iso(),
        )
        with self._lock:
            self._records.append(record)
        return True

    def capture_file_permissions(self, path: str) -> bool:
        """Capture only the permissions and ownership of a file.

        Used when the remediation will not change file content but will
        change mode or owner.
        """
        if not _validate_path(path):
            return False
        try:
            st = os.stat(path)
        except OSError as exc:
            logger.warning("Cannot stat %s for perm capture: %s", path, exc)
            return False

        record = CaptureRecord(
            record_type=CAPTURE_FILE_PERMISSIONS,
            target=path,
            previous_value=oct(stat.S_IMODE(st.st_mode))[2:].zfill(4),
            metadata={
                "uid": str(st.st_uid),
                "gid": str(st.st_gid),
            },
            timestamp=_now_iso(),
        )
        with self._lock:
            self._records.append(record)
        return True

    def capture_sysctl(self, key: str) -> bool:
        """Capture the current sysctl value for a parameter.

        Reads /proc/sys/<dotted-key-as-path> directly to avoid the
        sysctl binary. Empty/unreadable values record an empty string,
        which the generated script treats as "remove the setting".
        """
        if not _validate_sysctl_key(key):
            logger.warning("Refusing to capture sysctl with unsafe key: %r", key)
            return False

        proc_path = "/proc/sys/" + key.replace(".", "/")
        try:
            with open(proc_path, "r", encoding="ascii", errors="replace") as f:
                value = f.read().strip()
        except OSError:
            value = ""

        record = CaptureRecord(
            record_type=CAPTURE_SYSCTL,
            target=key,
            previous_value=value,
            timestamp=_now_iso(),
        )
        with self._lock:
            self._records.append(record)
        return True

    def capture_service_state(self, unit: str) -> bool:
        """Capture whether a systemd unit is active.

        Stores the active-state string ('active', 'inactive', 'failed', etc.).
        Generated rollback uses systemctl start/stop based on this value.
        """
        if not _validate_unit(unit):
            return False

        systemctl = shutil.which("systemctl")
        if not systemctl:
            return False

        try:
            result = subprocess.run(
                [systemctl, "is-active", unit],
                capture_output=True, text=True, timeout=5.0, check=False,
            )
        except (subprocess.TimeoutExpired, OSError):
            return False

        state = (result.stdout or result.stderr or "").strip().lower() or "unknown"
        record = CaptureRecord(
            record_type=CAPTURE_SERVICE_STATE,
            target=unit,
            previous_value=state,
            timestamp=_now_iso(),
        )
        with self._lock:
            self._records.append(record)
        return True

    def capture_service_enablement(self, unit: str) -> bool:
        """Capture whether a systemd unit is enabled at boot.

        Stores 'enabled', 'disabled', 'masked', 'static', etc.
        """
        if not _validate_unit(unit):
            return False

        systemctl = shutil.which("systemctl")
        if not systemctl:
            return False

        try:
            result = subprocess.run(
                [systemctl, "is-enabled", unit],
                capture_output=True, text=True, timeout=5.0, check=False,
            )
        except (subprocess.TimeoutExpired, OSError):
            return False

        state = (result.stdout or result.stderr or "").strip().lower() or "unknown"
        record = CaptureRecord(
            record_type=CAPTURE_SERVICE_ENABLEMENT,
            target=unit,
            previous_value=state,
            timestamp=_now_iso(),
        )
        with self._lock:
            self._records.append(record)
        return True

    def capture_kernel_module(self, name: str) -> bool:
        """Capture whether a kernel module is currently loaded."""
        if not name or not re.match(r"^[A-Za-z0-9_-]+$", name):
            return False

        loaded = False
        try:
            with open("/proc/modules", "r", encoding="utf-8") as f:
                for line in f:
                    if line.split(" ", 1)[0] == name:
                        loaded = True
                        break
        except OSError:
            pass

        record = CaptureRecord(
            record_type=CAPTURE_KERNEL_MODULE,
            target=name,
            previous_value="loaded" if loaded else "not_loaded",
            timestamp=_now_iso(),
        )
        with self._lock:
            self._records.append(record)
        return True

    def record_count(self) -> int:
        """Number of captured records currently in the manifest."""
        with self._lock:
            return len(self._records)

    # ------------------------------------------------------------------
    # Script generation
    # ------------------------------------------------------------------

    def generate_script(self, output_path: str) -> str:
        """Write the rollback bash script to output_path and return path.

        The script is written 0700 (root-only) and is created atomically
        via a write-and-rename pattern. Returns the absolute output path.
        Raises OSError on filesystem errors.
        """
        if not output_path:
            raise ValueError("output_path is required")

        abs_out = os.path.abspath(os.path.expanduser(output_path))

        # Path traversal prevention: ensure the parent directory exists
        # and is writable. We don't enforce a specific parent because the
        # operator chose the location.
        parent = os.path.dirname(abs_out) or "."
        if not os.path.isdir(parent):
            raise OSError(f"Output directory does not exist: {parent}")

        with self._lock:
            records_snapshot = list(self._records)

        script = self._build_script(records_snapshot)

        # Atomic write: create tmp file with secure mode, write, fsync,
        # then rename to final path.
        tmp_path = abs_out + ".tmp"
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o700)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(script)
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

        os.rename(tmp_path, abs_out)
        return abs_out

    def _build_script(self, records: List[CaptureRecord]) -> str:
        """Construct the rollback bash script from the manifest.

        Records are emitted in reverse order (LIFO) so that dependencies
        are restored in the right sequence: e.g. if a remediation enabled
        a service after writing a config file, rollback should disable
        the service before reverting the config.
        """
        lines: List[str] = []
        timestamp = datetime.datetime.now().astimezone().isoformat(timespec="seconds")

        lines.append("#!/usr/bin/env bash")
        lines.append("#")
        lines.append("# Linux Security Audit - Remediation Rollback Script")
        lines.append(f"# Generated: {timestamp}")
        lines.append(f"# Records:   {len(records)}")
        lines.append("#")
        lines.append("# This script reverses the changes applied by the most")
        lines.append("# recent remediation run. Review carefully before executing.")
        lines.append("# Run as root.")
        lines.append("#")
        lines.append("")
        lines.append("set -euo pipefail")
        lines.append("")
        lines.append('if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then')
        lines.append('    echo "ERROR: rollback must run as root" >&2')
        lines.append('    exit 1')
        lines.append('fi')
        lines.append("")
        lines.append('rollback_log() { printf "[rollback] %s\\n" "$*"; }')
        lines.append('rollback_warn() { printf "[rollback WARN] %s\\n" "$*" >&2; }')
        lines.append("")

        # Process records in reverse order
        for idx, record in enumerate(reversed(records), start=1):
            lines.append(f"# ---- Record {idx} of {len(records)} ----")
            lines.append(f"# Type: {record.record_type}")
            lines.append(f"# Target: {record.target}")
            lines.append(f"# Captured: {record.timestamp}")
            handler = _RECORD_HANDLERS.get(record.record_type)
            if handler:
                snippet = handler(record)
                lines.extend(snippet)
            else:
                lines.append(
                    f'rollback_warn "Unknown record type {record.record_type}; skipping"'
                )
            lines.append("")

        lines.append('rollback_log "Rollback complete: '
                     f"{len(records)} records processed\"")
        lines.append("exit 0")

        return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Per-record handlers. Each takes a CaptureRecord and returns lines of bash.
# --------------------------------------------------------------------------

def _emit_file_content(record: CaptureRecord) -> List[str]:
    path = _shell_quote(record.target)
    encoded = record.previous_value
    mode = record.metadata.get("mode", "0644")
    uid = record.metadata.get("uid", "0")
    gid = record.metadata.get("gid", "0")

    return [
        f"rollback_log 'Restoring file content: {record.target}'",
        f"base64 -d > {path} <<'__BASE64_EOF__'",
        encoded,
        "__BASE64_EOF__",
        f"chmod {mode} {path}",
        f"chown {uid}:{gid} {path}",
    ]


def _emit_file_permissions(record: CaptureRecord) -> List[str]:
    path = _shell_quote(record.target)
    mode = record.previous_value
    uid = record.metadata.get("uid", "0")
    gid = record.metadata.get("gid", "0")
    return [
        f"rollback_log 'Restoring permissions: {record.target} -> {mode}'",
        f"if [[ -e {path} ]]; then",
        f"    chmod {mode} {path}",
        f"    chown {uid}:{gid} {path}",
        f"else",
        f"    rollback_warn 'File missing during permission rollback: {record.target}'",
        f"fi",
    ]


def _emit_file_absent(record: CaptureRecord) -> List[str]:
    path = _shell_quote(record.target)
    return [
        f"rollback_log 'Removing file that was created by remediation: {record.target}'",
        f"if [[ -e {path} ]]; then",
        f"    rm -f -- {path}",
        f"fi",
    ]


def _emit_sysctl(record: CaptureRecord) -> List[str]:
    key = record.target
    value = record.previous_value
    proc_path = "/proc/sys/" + key.replace(".", "/")
    if value and _SAFE_NUMERIC_RE.match(value):
        return [
            f"rollback_log 'Restoring sysctl {key} = {value}'",
            f"if [[ -w {_shell_quote(proc_path)} ]]; then",
            f"    printf '%s\\n' {_shell_quote(value)} > {_shell_quote(proc_path)} || rollback_warn 'sysctl write failed for {key}'",
            f"fi",
            "# Persistent: remove our drop-in line if present",
            f"if [[ -f /etc/sysctl.d/99-hardening.conf ]]; then",
            f"    sed -i {_shell_quote('/^' + re.escape(key) + r'\\s*=/d')} /etc/sysctl.d/99-hardening.conf || true",
            f"fi",
        ]
    # Empty captured value -> remove our drop-in line and fall back to default
    return [
        f"rollback_log 'Removing sysctl override for {key} (no prior explicit value)'",
        f"if [[ -f /etc/sysctl.d/99-hardening.conf ]]; then",
        f"    sed -i {_shell_quote('/^' + re.escape(key) + r'\\s*=/d')} /etc/sysctl.d/99-hardening.conf || true",
        f"fi",
    ]


def _emit_service_state(record: CaptureRecord) -> List[str]:
    unit = _shell_quote(record.target)
    state = record.previous_value
    lines = [f"rollback_log 'Restoring service {record.target} to state: {state}'"]
    if state == "active":
        lines.append(f"systemctl start {unit} || rollback_warn 'Failed to start {record.target}'")
    elif state in ("inactive", "failed", "deactivating"):
        lines.append(f"systemctl stop {unit} || rollback_warn 'Failed to stop {record.target}'")
    else:
        lines.append(f"rollback_warn 'Unknown previous state {state} for {record.target}; no action taken'")
    return lines


def _emit_service_enablement(record: CaptureRecord) -> List[str]:
    unit = _shell_quote(record.target)
    state = record.previous_value
    lines = [f"rollback_log 'Restoring service {record.target} enablement: {state}'"]
    if state == "enabled":
        lines.append(f"systemctl enable {unit} || rollback_warn 'enable failed for {record.target}'")
    elif state == "disabled":
        lines.append(f"systemctl disable {unit} || rollback_warn 'disable failed for {record.target}'")
    elif state == "masked":
        lines.append(f"systemctl mask {unit} || rollback_warn 'mask failed for {record.target}'")
    elif state == "static":
        lines.append(f"# Unit was static; no enablement change needed")
    else:
        lines.append(f"rollback_warn 'Unknown enablement state {state} for {record.target}'")
    return lines


def _emit_kernel_module(record: CaptureRecord) -> List[str]:
    name = record.target
    state = record.previous_value
    if not re.match(r"^[A-Za-z0-9_-]+$", name):
        return [f"rollback_warn 'Invalid module name in record: {name}'"]
    if state == "loaded":
        return [
            f"rollback_log 'Reloading kernel module: {name}'",
            f"modprobe {_shell_quote(name)} || rollback_warn 'modprobe failed for {name}'",
        ]
    return [
        f"rollback_log 'Unloading kernel module that was not previously loaded: {name}'",
        f"modprobe -r {_shell_quote(name)} || rollback_warn 'rmmod failed for {name}'",
    ]


_RECORD_HANDLERS: Dict[str, callable] = {
    CAPTURE_FILE_CONTENT: _emit_file_content,
    CAPTURE_FILE_PERMISSIONS: _emit_file_permissions,
    CAPTURE_FILE_ABSENT: _emit_file_absent,
    CAPTURE_SYSCTL: _emit_sysctl,
    CAPTURE_SERVICE_STATE: _emit_service_state,
    CAPTURE_SERVICE_ENABLEMENT: _emit_service_enablement,
    CAPTURE_KERNEL_MODULE: _emit_kernel_module,
}
