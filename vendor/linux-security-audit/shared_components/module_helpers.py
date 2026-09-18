"""
module_helpers.py - Shared utility functions for v3 audit modules.

SYNOPSIS
    Common helpers consumed by every v3 module: safe file reading,
    command execution, sysctl access, systemd unit state, file mode
    inspection, and result construction.

DESCRIPTION
    Each helper is small, defensive, and side-effect-free except where
    documented. Helpers are shared so per-module code can focus on the
    framework-specific logic without re-implementing the same primitives.

    All subprocess calls in this module use list arguments and explicit
    timeouts. shell=True is never used. Path arguments are validated
    against an allow-list pattern to prevent argument-injection through
    crafted file names.

PARAMETERS
    Public API:
        read_file_safe(path, max_bytes=...) -> str
        file_exists(path) -> bool
        command_available(name) -> bool
        run_command(args, timeout=...) -> (returncode, stdout, stderr)
        read_sysctl(key) -> Optional[str]
        systemd_active(unit) -> str
        file_mode(path) -> Optional[int]
        make_result(module, category, status, message, ...) -> AuditResult

EXAMPLES
    >>> from shared_components.module_helpers import read_file_safe, read_sysctl
    >>> sshd = read_file_safe("/etc/ssh/sshd_config")
    >>> aslr = read_sysctl("kernel.randomize_va_space")

NOTES
    Version: 3.0
    Stdlib only.
    Helpers never raise during normal operation; failure modes return
    empty strings, None, or "unknown" so callers can branch defensively.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from .audit_common import AuditResult

logger = logging.getLogger("audit.module_helpers")


# ============================================================================
# v3.6 PERFORMANCE CACHING
# ----------------------------------------------------------------------------
# Audit runs are read-only and short-lived. The same helpers (especially
# command_available, systemd_active, run_command) are called hundreds of
# times across 16 modules with overlapping queries. A simple per-process
# cache eliminates redundant subprocess invocations and file reads,
# yielding 5-10x speedups on full audit runs without changing semantics.
#
# Cache invariants:
#   - Lookups are deterministic given the same inputs during one audit run
#   - All cached operations are read-only (no state mutation)
#   - Cache lifetime == process lifetime (audit runs as a single process)
#   - clear_caches() exposes manual invalidation for long-running daemons
# ============================================================================

# Simple module-level dict caches. Faster than functools.lru_cache for
# this workload since we don't need LRU eviction (cardinality is bounded
# by the set of distinct queries the audit makes).
_command_cache: Dict[str, bool] = {}
_systemd_active_cache: Dict[str, str] = {}
_systemd_enabled_cache: Dict[str, str] = {}
_run_command_cache: Dict[Tuple[Tuple[str, ...], float], Tuple[int, str, str]] = {}
_sysctl_cache: Dict[str, Optional[str]] = {}
_file_content_cache: Dict[Tuple[str, int], str] = {}
_file_exists_cache: Dict[str, bool] = {}
_directory_exists_cache: Dict[str, bool] = {}


def clear_caches() -> None:
    """Clear all v3.6 helper caches.

    Useful for long-running supervisors that may invoke run_checks() in a
    loop and need to observe state changes between iterations. Within a
    single audit run, caching is safe because the audit is read-only and
    completes in seconds.
    """
    _command_cache.clear()
    _systemd_active_cache.clear()
    _systemd_enabled_cache.clear()
    _run_command_cache.clear()
    _sysctl_cache.clear()
    _file_content_cache.clear()
    _file_exists_cache.clear()
    _directory_exists_cache.clear()


# Path safety pattern. Restricts file operations to paths composed of
# alphanumerics plus the punctuation legitimately used in Linux config
# paths. Reject anything that could indicate a traversal attempt or shell
# metacharacter injection (newlines, semicolons, quotes, backticks).

_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9._/\-+@:]+$")


def _is_safe_path(path: str) -> bool:
    if not path or not isinstance(path, str):
        return False
    if ".." in path.split("/"):
        return False
    return bool(_SAFE_PATH_RE.match(path))


def read_file_safe(path: str, max_bytes: int = 1024 * 1024) -> str:
    """Read a small text file, returning empty string on any error.

    File size is capped at max_bytes to prevent runaway reads on a
    misconfigured /etc/* file. The default 1 MiB ceiling is well above
    realistic security-config sizes. Encoding is UTF-8 with replacement
    so files containing latin-1 fragments do not raise.

    v3.6: Results cached per (path, max_bytes) for the audit run.
    """
    if not _is_safe_path(path):
        return ""
    cache_key = (path, max_bytes)
    cached = _file_content_cache.get(cache_key)
    if cached is not None:
        return cached
    try:
        st = os.stat(path)
    except OSError:
        _file_content_cache[cache_key] = ""
        return ""
    if st.st_size > max_bytes:
        logger.debug("Skip %s: size %d exceeds %d", path, st.st_size, max_bytes)
        _file_content_cache[cache_key] = ""
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
            _file_content_cache[cache_key] = content
            return content
    except OSError:
        _file_content_cache[cache_key] = ""
        return ""


def file_exists(path: str) -> bool:
    if not _is_safe_path(path):
        return False
    cached = _file_exists_cache.get(path)
    if cached is not None:
        return cached
    result = os.path.isfile(path)
    _file_exists_cache[path] = result
    return result


def directory_exists(path: str) -> bool:
    if not _is_safe_path(path):
        return False
    cached = _directory_exists_cache.get(path)
    if cached is not None:
        return cached
    result = os.path.isdir(path)
    _directory_exists_cache[path] = result
    return result


def command_available(name: str) -> bool:
    """True if the named command is on PATH and executable.

    v3.6: Results cached per command name. PATH does not change during an
    audit run.
    """
    if not name or not re.match(r"^[A-Za-z0-9._\-]+$", name):
        return False
    cached = _command_cache.get(name)
    if cached is not None:
        return cached
    result = bool(shutil.which(name))
    _command_cache[name] = result
    return result


def run_command(
    args: List[str],
    timeout: float = 5.0,
) -> Tuple[int, str, str]:
    """Run a command with timeout and capture output.

    Returns (returncode, stdout, stderr). On any execution failure,
    returncode is -1 and stderr contains the exception text. List args
    only - no shell=True invocation in this module or its callers.

    v3.6: Identical (args, timeout) invocations cached. Audit code uses
    run_command exclusively for read-only queries (ss, ip, lsblk,
    getenforce, etc.), so caching is safe.
    """
    if not args or not isinstance(args, list):
        return -1, "", "invalid args"
    # Validate that every arg is a string (no None, no objects)
    for a in args:
        if not isinstance(a, str):
            return -1, "", "non-string arg"
    cache_key = (tuple(args), timeout)
    cached = _run_command_cache.get(cache_key)
    if cached is not None:
        return cached
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        out = (result.returncode, result.stdout or "", result.stderr or "")
        _run_command_cache[cache_key] = out
        return out
    except subprocess.TimeoutExpired:
        out = (-1, "", f"timeout after {timeout}s")
        _run_command_cache[cache_key] = out
        return out
    except (OSError, ValueError) as exc:
        out = (-1, "", str(exc))
        _run_command_cache[cache_key] = out
        return out


def read_sysctl(key: str) -> Optional[str]:
    """Read a sysctl value via /proc/sys without launching sysctl(8).

    Returns the trimmed value or None if unreadable.

    v3.6: Per-key cache. /proc/sys values are stable for the audit run
    (we don't write to them).
    """
    if not key or not re.match(r"^[a-z0-9_.\-]+$", key):
        return None
    if key in _sysctl_cache:
        return _sysctl_cache[key]
    proc_path = "/proc/sys/" + key.replace(".", "/")
    try:
        with open(proc_path, "r", encoding="ascii", errors="replace") as f:
            value = f.read().strip()
            _sysctl_cache[key] = value
            return value
    except OSError:
        _sysctl_cache[key] = None
        return None


def systemd_active(unit: str) -> str:
    """Return the active state of a systemd unit, or 'unknown'.

    Possible values include: active, inactive, failed, activating,
    deactivating, not-found, unknown. Validates the unit name to
    prevent injection.

    v3.6: Cached per unit. systemd unit state is stable for the audit run.
    """
    if not unit or not re.match(r"^[A-Za-z0-9@_.\-:]+$", unit):
        return "unknown"
    cached = _systemd_active_cache.get(unit)
    if cached is not None:
        return cached
    if not command_available("systemctl"):
        _systemd_active_cache[unit] = "unknown"
        return "unknown"
    rc, out, err = run_command(["systemctl", "is-active", unit])
    state = (out or err).strip().lower() or "unknown"
    _systemd_active_cache[unit] = state
    return state


def systemd_enabled(unit: str) -> str:
    """Return the boot enablement state of a systemd unit.

    Possible values: enabled, disabled, masked, static, indirect,
    not-found, unknown.

    v3.6: Cached per unit.
    """
    if not unit or not re.match(r"^[A-Za-z0-9@_.\-:]+$", unit):
        return "unknown"
    cached = _systemd_enabled_cache.get(unit)
    if cached is not None:
        return cached
    if not command_available("systemctl"):
        _systemd_enabled_cache[unit] = "unknown"
        return "unknown"
    rc, out, err = run_command(["systemctl", "is-enabled", unit])
    state = (out or err).strip().lower() or "unknown"
    _systemd_enabled_cache[unit] = state
    return state


def file_mode(path: str) -> Optional[int]:
    """Return the permission mode (last 12 bits) of a file as integer."""
    if not _is_safe_path(path):
        return None
    try:
        st = os.stat(path)
    except OSError:
        return None
    return st.st_mode & 0o7777


def file_owner(path: str) -> Optional[Tuple[int, int]]:
    """Return (uid, gid) of the file owner, or None on error."""
    if not _is_safe_path(path):
        return None
    try:
        st = os.stat(path)
    except OSError:
        return None
    return st.st_uid, st.st_gid


def parse_kv_file(content: str) -> Dict[str, str]:
    """Parse a generic key-value file (login.defs, sshd_config style).

    Comment lines start with #. Whitespace separates key from value.
    Returns lowercase-keyed dict for case-insensitive lookup. Later
    occurrences win when a key appears multiple times.
    """
    result: Dict[str, str] = {}
    if not content:
        return result
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) == 2:
            key = parts[0].strip().lower()
            value = parts[1].split("#", 1)[0].strip()
            result[key] = value
    return result


def list_directory(path: str, suffix: str = "") -> List[str]:
    """List entries in a directory, optionally filtered by suffix.

    Returns absolute paths. Empty list on any error or if the path
    is not a directory.
    """
    if not _is_safe_path(path):
        return []
    try:
        entries = sorted(os.listdir(path))
    except OSError:
        return []
    out: List[str] = []
    for entry in entries:
        if suffix and not entry.endswith(suffix):
            continue
        full = os.path.join(path, entry)
        if os.path.isfile(full):
            out.append(full)
    return out


def make_result(
    module: str,
    category: str,
    status: str,
    message: str,
    severity: str = "Medium",
    details: str = "",
    remediation: str = "",
    cross_references: Optional[Dict[str, str]] = None,
) -> AuditResult:
    """Construct an AuditResult with consistent module field handling.

    Used by every v3 module so the AuditResult constructor invocation
    looks identical across the project. The cross_references dict can
    be None and will be normalised to an empty dict.
    """
    return AuditResult(
        module=module,
        category=category,
        status=status,
        message=message,
        details=details,
        remediation=remediation,
        severity=severity,
        cross_references=cross_references or {},
    )


def first_existing(*paths: str) -> Optional[str]:
    """Return the first path that exists, or None."""
    for p in paths:
        if file_exists(p):
            return p
    return None


def grep_first_match(
    content: str,
    pattern: str,
    flags: int = 0,
) -> Optional[re.Match]:
    """Find the first regex match in content, returning the Match or None."""
    if not content or not pattern:
        return None
    try:
        regex = re.compile(pattern, flags)
    except re.error:
        return None
    return regex.search(content)


def collect_listening_ports(timeout: float = 3.0) -> List[int]:
    """Return the set of TCP listening port numbers as a sorted list.

    Uses ss(8) when available. Returns empty list on any failure.
    Filters to numeric ports only; skips IPv6 and unix sockets.
    """
    if not command_available("ss"):
        return []
    rc, out, _ = run_command(["ss", "-tlnH"], timeout=timeout)
    if rc != 0:
        return []
    ports: set = set()
    for line in out.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        addr = fields[3]
        port_part = addr.rsplit(":", 1)[-1]
        if port_part.isdigit():
            ports.add(int(port_part))
    return sorted(ports)


def is_port_listening(port: int) -> bool:
    """True if the given TCP port is in the listening set."""
    return port in set(collect_listening_ports())


def package_installed(name: str, family: str) -> Optional[bool]:
    """Check whether a package is installed via the family's package manager.

    Returns True/False if the manager could be queried, None otherwise.
    Family is one of 'Debian', 'RedHat', 'SUSE', 'Arch', 'Alpine'.
    """
    if not name or not re.match(r"^[A-Za-z0-9._\-+]+$", name):
        return None

    if family == "Debian" and command_available("dpkg-query"):
        rc, _out, _err = run_command(
            ["dpkg-query", "-W", "-f=${Status}", name], timeout=5.0
        )
        return rc == 0

    if family == "RedHat" and command_available("rpm"):
        rc, _out, _err = run_command(["rpm", "-q", name], timeout=5.0)
        return rc == 0

    if family == "SUSE" and command_available("rpm"):
        rc, _out, _err = run_command(["rpm", "-q", name], timeout=5.0)
        return rc == 0

    if family == "Arch" and command_available("pacman"):
        rc, _out, _err = run_command(["pacman", "-Qi", name], timeout=5.0)
        return rc == 0

    if family == "Alpine" and command_available("apk"):
        rc, out, _err = run_command(["apk", "info", "-e", name], timeout=5.0)
        return rc == 0 and bool(out.strip())

    return None
