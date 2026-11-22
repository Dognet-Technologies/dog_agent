#!/usr/bin/env python3
"""
audit_common.py
Shared Utilities and Data Cache for Linux Security Audit Modules

Version: 2.0

SYNOPSIS:
    Consolidated library of common utilities, OS detection, command execution
    with caching, and shared helper functions used across all audit modules.

DESCRIPTION:
    This module eliminates code duplication across the 8 security audit modules
    by providing a single, authoritative implementation of:

    - OS Detection & Classification (OSInfo, detect_os)
    - Command Execution with Caching (run_command, CachedCommand)
    - File Reading with Caching (read_file_safe, CachedFile)
    - SharedDataCache - Pre-reads common config files and command outputs
    - Service Management Checks (check_service_enabled, check_service_active)
    - Package Management Checks (check_package_installed)
    - File Permission & Ownership Checks (get_file_permissions, get_file_owner_group)
    - Kernel Parameter Checks (check_kernel_parameter)
    - Security Subsystem Status (SELinux, AppArmor, firewall, FIPS)
    - SSH Configuration Parsing (get_ssh_config_value, get_ssh_config_all)
    - Network Utilities (get_listening_ports, check_ipv6_enabled)
    - PAM Module Checks (check_pam_module, get_password_policy)
    - User Account Utilities (get_user_accounts, get_system_users)
    - Safe Parsing Helpers (safe_int_parse, safe_float_parse)
    - Structured Logging Integration (get_module_logger)

    Performance Benefits:
    - SharedDataCache reads common files ONCE and shares across all modules
    - Command execution cache prevents duplicate subprocess calls
    - Thread-safe design for parallel module execution
    - Lazy initialization for expensive operations

PARAMETERS:
    None (library module, imported by audit modules)

USAGE:
    In any audit module:
        from audit_common import (
            AuditResult, OSInfo, detect_os, SharedDataCache,
            run_command, read_file_safe, command_exists,
            check_service_enabled, check_service_active,
            check_package_installed, get_file_permissions,
            get_file_owner_group, check_kernel_parameter,
            safe_int_parse, get_module_logger
        )

    With SharedDataCache:
        cache = shared_data.get('cache')
        sshd_config = cache.get_file('/etc/ssh/sshd_config')
        login_defs = cache.get_file('/etc/login.defs')
        sysctl_output = cache.get_command('sysctl -a')

NOTES:
    Version: 2.0
    Python: 3.6+
    Dependencies: Python standard library only
    Thread Safety: All public functions are thread-safe
    Backward Compatibility: Modules can import from here OR use inline copies
"""

import os
import sys
import re
import subprocess
import pwd
import grp
import glob
import shutil
import socket
import platform
import threading
import logging
import time
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict, field
from datetime import datetime
from functools import lru_cache
from collections import OrderedDict

# ============================================================================
# Constants & Configuration
# ============================================================================

# Valid status values for audit results
VALID_STATUS_VALUES = ["Pass", "Fail", "Warning", "Info", "Error"]

# Severity levels for risk scoring (higher = more severe)
SEVERITY_LEVELS = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Informational": 0
}

# Default command execution timeout (seconds)
DEFAULT_COMMAND_TIMEOUT = 30

# Maximum cache entries for command results
MAX_COMMAND_CACHE_SIZE = 500

# Common configuration file paths that are read by multiple modules
COMMON_CONFIG_FILES = [
    "/etc/ssh/sshd_config",
    "/etc/login.defs",
    "/etc/security/pwquality.conf",
    "/etc/pam.d/common-password",
    "/etc/pam.d/common-auth",
    "/etc/pam.d/system-auth",
    "/etc/pam.d/password-auth",
    "/etc/default/grub",
    "/etc/audit/auditd.conf",
    "/etc/audit/audit.rules",
    "/etc/sysctl.conf",
    "/etc/fstab",
    "/etc/hosts.allow",
    "/etc/hosts.deny",
    "/etc/securetty",
    "/etc/security/limits.conf",
    "/etc/crontab",
    "/etc/issue",
    "/etc/issue.net",
    "/etc/motd",
    "/etc/profile",
    "/etc/bashrc",
    "/etc/bash.bashrc",
    "/proc/cmdline",
    # Direct /proc reads replace subprocess equivalents (mount, lsmod, etc.)
    "/etc/passwd",
    "/etc/group",
    "/etc/os-release",
    "/proc/mounts",
    "/proc/modules",
]

# Common commands that are run by multiple modules
# NOTE: /etc/passwd, /etc/group, /etc/os-release, mount, lsmod moved to direct file reads
COMMON_COMMANDS = [
    "sysctl -a 2>/dev/null",
    "systemctl list-unit-files --type=service 2>/dev/null",
    "systemctl list-units --type=service --state=running 2>/dev/null",
    "ss -tuln 2>/dev/null",
    "df -hT 2>/dev/null",
    "uname -a 2>/dev/null",
    "id 2>/dev/null",
    "last -n 20 2>/dev/null",
]

# ============================================================================
# Structured Logging
# ============================================================================

# Module-level logger registry to avoid duplicate handlers
_logger_registry: Dict[str, logging.Logger] = {}
_logger_lock = threading.Lock()

# Global log level (can be set by main script)
_global_log_level = logging.INFO

# Global log file handler (shared across all module loggers)
_global_file_handler: Optional[logging.FileHandler] = None


def configure_logging(log_level: int = logging.INFO,
                      log_file: Optional[str] = None,
                      json_format: bool = False) -> None:
    """
    Configure the global logging system for the entire audit framework.

    This should be called ONCE from the main script before any modules run.
    It sets up the log level, optional file logging, and format.

    Args:
        log_level: Python logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to write log file. If None, no file logging.
        json_format: If True, use JSON structured log format for SIEM ingestion.
    """
    global _global_log_level, _global_file_handler

    _global_log_level = log_level

    if log_file:
        try:
            # Create log directory if needed
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)

            if json_format:
                formatter = logging.Formatter(
                    '{"timestamp":"%(asctime)s","level":"%(levelname)s",'
                    '"module":"%(name)s","message":"%(message)s"}'
                )
            else:
                formatter = logging.Formatter(
                    '%(asctime)s [%(levelname)-8s] [%(name)-12s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )

            _global_file_handler = logging.FileHandler(log_file, encoding='utf-8')
            _global_file_handler.setLevel(logging.DEBUG)  # File always gets everything
            _global_file_handler.setFormatter(formatter)
        except Exception as e:
            print(f"[WARNING] Could not create log file {log_file}: {e}")
            _global_file_handler = None


def get_module_logger(module_name: str) -> logging.Logger:
    """
    Get or create a logger for a specific audit module.

    Each module gets its own named logger with consistent formatting.
    All loggers share the global file handler if configured.

    Args:
        module_name: Name of the audit module (e.g., 'CIS', 'NIST', 'CORE')

    Returns:
        Configured logging.Logger instance
    """
    with _logger_lock:
        if module_name in _logger_registry:
            return _logger_registry[module_name]

        logger = logging.getLogger(f"audit.{module_name}")
        logger.setLevel(_global_log_level)

        # Prevent duplicate handlers if logger already exists
        if not logger.handlers:
            # Console handler with color-aware formatting
            console_handler = logging.StreamHandler()
            console_handler.setLevel(_global_log_level)
            console_formatter = logging.Formatter(
                f'[%(levelname)-8s] [{module_name:12s}] %(message)s'
            )
            console_handler.setFormatter(console_formatter)
            logger.addHandler(console_handler)

            # Add global file handler if configured
            if _global_file_handler:
                logger.addHandler(_global_file_handler)

        # Prevent propagation to root logger (avoids duplicate output)
        logger.propagate = False

        _logger_registry[module_name] = logger
        return logger


# ============================================================================
# AuditResult Data Class (Canonical Definition)
# ============================================================================

@dataclass(slots=True)
class AuditResult:
    """
    Represents a single audit check result.

    This is the canonical definition used by all modules. Modules should
    import this from audit_common rather than from the main script.

    Attributes:
        module: Name of the audit module (e.g., 'CIS', 'NIST', 'CORE')
        category: Check category within the module (e.g., 'CIS 5.2 - SSH')
        status: Result status - must be one of VALID_STATUS_VALUES
        message: Human-readable description of what was checked
        details: Technical details of the finding
        remediation: Command or steps to fix the issue (if applicable)
        severity: Risk severity level (Critical/High/Medium/Low/Informational)
        cross_references: Cross-framework control IDs (e.g., {'NIST': 'AC-2', 'CIS': '5.2.1'})
        timestamp: When the check was performed
    """
    module: str
    category: str
    status: str
    message: str
    details: str = ""
    remediation: str = ""
    severity: str = "Medium"
    cross_references: Dict[str, str] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return asdict(self)

    def validate(self) -> Tuple[bool, List[str]]:
        """
        Validate the result object for completeness and correctness.

        Returns:
            Tuple of (is_valid: bool, list_of_issues: List[str])
        """
        issues = []

        if not self.module:
            issues.append("Missing: module")
        if not self.category:
            issues.append("Missing: category")
        if not self.message:
            issues.append("Missing: message")
        if not self.status:
            issues.append("Missing: status")
        elif self.status not in VALID_STATUS_VALUES:
            issues.append(f"Invalid Status: '{self.status}'")
        if self.severity and self.severity not in SEVERITY_LEVELS:
            issues.append(f"Invalid Severity: '{self.severity}'")

        return len(issues) == 0, issues


# ============================================================================
# OS Detection and Classification
# ============================================================================

class OSInfo:
    """
    Store and manage comprehensive OS information.

    This is detected once at startup and shared across all modules via
    the SharedDataCache. All modules should use this single instance
    rather than running their own detection.

    Attributes:
        family: OS family ('debian', 'redhat', 'suse', 'arch', 'unknown')
        distro: Specific distribution ('ubuntu', 'debian', 'rhel', 'centos', etc.)
        version: Full version string
        version_id: Numeric version ID (e.g., '24.04')
        codename: Version codename (e.g., 'noble')
        package_manager: Package manager command ('apt', 'yum', 'dnf', 'zypper', 'pacman')
        init_system: Init system ('systemd', 'sysvinit', 'upstart')
        architecture: CPU architecture (e.g., 'x86_64', 'aarch64')
        kernel_version: Linux kernel version string
    """

    __slots__ = [
        'family', 'distro', 'version', 'version_id', 'codename',
        'package_manager', 'init_system', 'architecture', 'kernel_version'
    ]

    def __init__(self):
        self.family: str = "Unknown"
        self.distro: str = "Unknown"
        self.version: str = "Unknown"
        self.version_id: str = "Unknown"
        self.codename: str = "Unknown"
        self.package_manager: str = "Unknown"
        self.init_system: str = "Unknown"
        self.architecture: str = platform.machine()
        self.kernel_version: str = platform.release()

    def __str__(self) -> str:
        return f"{self.distro} {self.version} ({self.family})"

    @property
    def distro_id(self) -> str:
        """Compatibility alias for the os_detection.OSInfo API.

        os_detection.OSInfo exposes the distribution identifier as
        `.distro_id`; this class historically stored it as `.distro`. Some
        cross-module code (e.g. DistBaseline's per-distro dispatch) reads
        `.distro_id` regardless of which OSInfo variant it receives, so we
        expose it here too. Returns the lowercased distro id for consistency
        with os_detection (which normalizes os-release ID to lowercase).
        """
        d = (self.distro or "").lower()
        return "" if d in ("", "unknown") else d

    @property
    def distro_version(self) -> str:
        """Compatibility alias: os_detection exposes distro_version."""
        return self.version

    @property
    def pretty_name(self) -> str:
        """Compatibility alias for os_detection.OSInfo.pretty_name."""
        return f"{self.distro} {self.version}".strip()

    def __repr__(self) -> str:
        return (
            f"OSInfo(family={self.family!r}, distro={self.distro!r}, "
            f"version={self.version!r}, pkg_mgr={self.package_manager!r})"
        )

    def is_debian_based(self) -> bool:
        """Check if this is a Debian-based distribution"""
        return self.family == 'debian'

    def is_redhat_based(self) -> bool:
        """Check if this is a Red Hat-based distribution"""
        return self.family == 'redhat'

    def is_suse_based(self) -> bool:
        """Check if this is a SUSE-based distribution"""
        return self.family == 'suse'

    def is_arch_based(self) -> bool:
        """Check if this is an Arch-based distribution"""
        return self.family == 'arch'

    # v3.7 compatibility aliases - mirror os_detection.OSInfo's
    # `is_<family>_family()` naming so the two OSInfo implementations are
    # interchangeable wherever an instance flows between layers.
    def is_debian_family(self) -> bool:
        return self.is_debian_based()

    def is_redhat_family(self) -> bool:
        return self.is_redhat_based()

    def is_suse_family(self) -> bool:
        return self.is_suse_based()

    def is_arch_family(self) -> bool:
        return self.is_arch_based()

    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary for serialization"""
        return {
            'family': self.family,
            'distro': self.distro,
            'version': self.version,
            'version_id': self.version_id,
            'codename': self.codename,
            'package_manager': self.package_manager,
            'init_system': self.init_system,
            'architecture': self.architecture,
            'kernel_version': self.kernel_version
        }


def detect_os() -> OSInfo:
    """
    Comprehensive OS detection with multi-method fallback.

    Detection methods (in order of priority):
    1. /etc/os-release parsing (standard on modern Linux)
    2. Distribution-specific files (/etc/debian_version, /etc/redhat-release)
    3. Package manager detection (apt-get, dnf, yum, zypper, pacman)
    4. Init system detection (systemd, sysvinit, upstart)

    Returns:
        Populated OSInfo object with all detected information
    """
    os_info = OSInfo()

    # ---------- Method 1: Parse /etc/os-release ----------
    if os.path.exists("/etc/os-release"):
        try:
            with open("/etc/os-release", 'r', encoding='utf-8', errors='ignore') as f:
                os_release = {}
                for line in f:
                    line = line.strip()
                    if '=' in line:
                        key, value = line.split('=', 1)
                        os_release[key] = value.strip('"').strip("'")

            os_info.distro = os_release.get('ID', 'unknown').lower()
            os_info.version = os_release.get('VERSION', 'unknown')
            os_info.version_id = os_release.get('VERSION_ID', 'unknown')
            os_info.codename = os_release.get('VERSION_CODENAME', 'unknown')

            # Determine OS family from ID and ID_LIKE
            id_like = os_release.get('ID_LIKE', '').lower()
            distro_id = os_info.distro

            if distro_id in ('ubuntu', 'debian', 'linuxmint', 'kali', 'pop',
                             'elementary', 'zorin', 'raspbian') or 'debian' in id_like:
                os_info.family = 'debian'
            elif distro_id in ('rhel', 'centos', 'fedora', 'rocky', 'almalinux',
                               'ol', 'scientific', 'amzn') or 'rhel' in id_like or 'fedora' in id_like:
                os_info.family = 'redhat'
            elif distro_id in ('sles', 'opensuse', 'opensuse-leap',
                               'opensuse-tumbleweed') or 'suse' in id_like:
                os_info.family = 'suse'
            elif distro_id in ('arch', 'manjaro', 'endeavouros') or 'arch' in id_like:
                os_info.family = 'arch'
        except Exception:
            pass  # Fall through to backup methods

    # ---------- Method 2: Fallback distribution-specific files ----------
    if os_info.family == "Unknown":
        if os.path.exists("/etc/debian_version"):
            os_info.family = 'debian'
            if os_info.distro == "Unknown":
                os_info.distro = 'debian'
            try:
                with open("/etc/debian_version", 'r') as f:
                    os_info.version_id = f.read().strip()
            except Exception:
                pass

        elif os.path.exists("/etc/redhat-release"):
            os_info.family = 'redhat'
            try:
                with open("/etc/redhat-release", 'r') as f:
                    content = f.read().lower()
                    if 'centos' in content:
                        os_info.distro = 'centos'
                    elif 'red hat' in content or 'rhel' in content:
                        os_info.distro = 'rhel'
                    elif 'fedora' in content:
                        os_info.distro = 'fedora'
                    elif 'rocky' in content:
                        os_info.distro = 'rocky'
                    elif 'alma' in content:
                        os_info.distro = 'almalinux'
                    os_info.version = content.strip()
            except Exception:
                pass

        elif os.path.exists("/etc/SuSE-release"):
            os_info.family = 'suse'
            if os_info.distro == "Unknown":
                os_info.distro = 'sles'

        elif os.path.exists("/etc/arch-release"):
            os_info.family = 'arch'
            if os_info.distro == "Unknown":
                os_info.distro = 'arch'

    # ---------- Method 3: Detect package manager ----------
    if shutil.which('apt-get'):
        os_info.package_manager = 'apt'
    elif shutil.which('dnf'):
        os_info.package_manager = 'dnf'
    elif shutil.which('yum'):
        os_info.package_manager = 'yum'
    elif shutil.which('zypper'):
        os_info.package_manager = 'zypper'
    elif shutil.which('pacman'):
        os_info.package_manager = 'pacman'

    # ---------- Method 4: Detect init system ----------
    if os.path.exists("/run/systemd/system"):
        os_info.init_system = 'systemd'
    elif os.path.exists("/sbin/init") and os.path.islink("/sbin/init"):
        try:
            link_target = os.readlink("/sbin/init")
            if 'systemd' in link_target:
                os_info.init_system = 'systemd'
            elif 'upstart' in link_target:
                os_info.init_system = 'upstart'
            else:
                os_info.init_system = 'sysvinit'
        except Exception:
            os_info.init_system = 'sysvinit'
    else:
        os_info.init_system = 'sysvinit'

    return os_info


# ============================================================================
# Command Execution (with Caching)
# ============================================================================

# Thread-safe command result cache
_command_cache: Dict[str, subprocess.CompletedProcess] = {}
_command_cache_lock = threading.Lock()
_command_cache_hits = 0
_command_cache_misses = 0


def run_command(command: str,
                check: bool = False,
                timeout: int = DEFAULT_COMMAND_TIMEOUT,
                use_cache: bool = True) -> subprocess.CompletedProcess:
    """
    Execute a shell command and return the result, with optional caching.

    Cached results are shared across all modules, preventing duplicate
    subprocess calls for frequently-used commands.

    Args:
        command: Shell command string to execute
        check: If True, raise CalledProcessError on non-zero return code
        timeout: Maximum execution time in seconds (default: 30)
        use_cache: If True, cache and reuse results for identical commands

    Returns:
        subprocess.CompletedProcess with returncode, stdout, stderr
    """
    global _command_cache_hits, _command_cache_misses

    # Check cache first (thread-safe)
    if use_cache:
        with _command_cache_lock:
            if command in _command_cache:
                _command_cache_hits += 1
                return _command_cache[command]

    # Execute the command
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            check=check,
            timeout=timeout
        )
    except subprocess.TimeoutExpired:
        result = subprocess.CompletedProcess(
            args=command, returncode=-1, stdout="", stderr="Command timeout"
        )
    except subprocess.CalledProcessError as e:
        # Re-raise if check=True was requested
        raise
    except Exception as e:
        result = subprocess.CompletedProcess(
            args=command, returncode=-1, stdout="", stderr=str(e)
        )

    # Store in cache (thread-safe)
    if use_cache:
        with _command_cache_lock:
            _command_cache_misses += 1
            # Enforce cache size limit
            if len(_command_cache) >= MAX_COMMAND_CACHE_SIZE:
                # Remove oldest 10% of entries
                remove_count = MAX_COMMAND_CACHE_SIZE // 10
                keys_to_remove = list(_command_cache.keys())[:remove_count]
                for key in keys_to_remove:
                    del _command_cache[key]
            _command_cache[command] = result

    return result


def get_cache_statistics() -> Dict[str, int]:
    """
    Get command cache performance statistics.

    Returns:
        Dictionary with 'hits', 'misses', 'entries', and 'hit_rate' keys
    """
    with _command_cache_lock:
        total = _command_cache_hits + _command_cache_misses
        hit_rate = (_command_cache_hits / total * 100) if total > 0 else 0.0
        return {
            'hits': _command_cache_hits,
            'misses': _command_cache_misses,
            'entries': len(_command_cache),
            'hit_rate': round(hit_rate, 1)
        }


def clear_command_cache() -> None:
    """Clear the command result cache (useful between audit runs)"""
    global _command_cache_hits, _command_cache_misses
    with _command_cache_lock:
        _command_cache.clear()
        _command_cache_hits = 0
        _command_cache_misses = 0


# ============================================================================
# File Reading (with Caching)
# ============================================================================

# Thread-safe file content cache
_file_cache: Dict[str, str] = {}
_file_cache_lock = threading.Lock()


def read_file_safe(filepath: str, use_cache: bool = True) -> str:
    """
    Safely read a file's contents, returning empty string on any error.

    Cached results are shared across modules so that common configuration
    files (sshd_config, login.defs, etc.) are read from disk only once.

    Args:
        filepath: Absolute path to the file to read
        use_cache: If True, cache and reuse file contents

    Returns:
        File contents as string, or empty string on error
    """
    # Check cache first
    if use_cache:
        with _file_cache_lock:
            if filepath in _file_cache:
                return _file_cache[filepath]

    # Read the file
    content = ""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except PermissionError:
        # Silently return empty for permission errors (non-root execution)
        pass
    except Exception:
        pass

    # Store in cache
    if use_cache:
        with _file_cache_lock:
            _file_cache[filepath] = content

    return content


def clear_file_cache() -> None:
    """Clear the file content cache"""
    with _file_cache_lock:
        _file_cache.clear()


# ============================================================================
# SharedDataCache - Pre-read Common Data
# ============================================================================

class SharedDataCache:
    """
    Centralized data cache that pre-reads commonly-accessed configuration
    files and command outputs at startup, then provides them to all modules.

    This dramatically reduces I/O and subprocess calls since most modules
    need to read the same files (sshd_config, login.defs, sysctl, etc.)
    and run the same commands (systemctl, ss, mount, etc.).

    Usage:
        # In main script, create once:
        cache = SharedDataCache()
        cache.warm_up()

        # Pass to modules via shared_data:
        shared_data['cache'] = cache

        # In modules, retrieve cached data:
        cache = shared_data.get('cache')
        sshd_config = cache.get_file('/etc/ssh/sshd_config')
        sysctl_all = cache.get_command('sysctl -a 2>/dev/null')

    Thread Safety:
        All methods are thread-safe for parallel module execution.
    """

    def __init__(self, os_info: Optional[OSInfo] = None):
        """
        Initialize the SharedDataCache.

        Args:
            os_info: Pre-detected OSInfo object. If None, detect_os() is called.
        """
        self._os_info = os_info or detect_os()
        self._files: Dict[str, str] = {}
        self._commands: Dict[str, subprocess.CompletedProcess] = {}
        self._parsed_data: Dict[str, Any] = {}
        self._lock = threading.Lock()
        self._warm = False
        self._timing: Dict[str, float] = {}
        self._logger = get_module_logger("CACHE")

    @property
    def os_info(self) -> OSInfo:
        """Get the detected OS information"""
        return self._os_info

    def warm_up(self) -> Dict[str, float]:
        """
        Pre-read all common configuration files and run common commands.

        This should be called ONCE before audit modules execute. It populates
        the cache with frequently-accessed data, eliminating redundant I/O
        during the audit.

        Returns:
            Dictionary mapping operation name to time taken (seconds)
        """
        start_total = time.monotonic()
        timing = {}

        self._logger.info("Warming up shared data cache...")

        # ---------- Pre-read common configuration files ----------
        start = time.monotonic()
        files_read = 0
        for filepath in COMMON_CONFIG_FILES:
            content = read_file_safe(filepath, use_cache=True)
            if content:
                files_read += 1
                self._files[filepath] = content
        elapsed = time.monotonic() - start
        timing['config_files'] = round(elapsed, 3)
        self._logger.info(f"  Config files: {files_read}/{len(COMMON_CONFIG_FILES)} "
                          f"read in {elapsed:.3f}s")

        # Also read /etc/pam.d/ directory configs
        start = time.monotonic()
        pam_files_read = 0
        pam_dir = "/etc/pam.d"
        if os.path.isdir(pam_dir):
            try:
                for pam_file in os.listdir(pam_dir):
                    pam_path = os.path.join(pam_dir, pam_file)
                    if os.path.isfile(pam_path):
                        content = read_file_safe(pam_path, use_cache=True)
                        if content:
                            pam_files_read += 1
                            self._files[pam_path] = content
            except PermissionError:
                pass
        elapsed = time.monotonic() - start
        timing['pam_files'] = round(elapsed, 3)
        self._logger.info(f"  PAM files: {pam_files_read} read in {elapsed:.3f}s")

        # Also read /etc/sysctl.d/ directory configs
        start = time.monotonic()
        sysctl_files_read = 0
        sysctl_dir = "/etc/sysctl.d"
        if os.path.isdir(sysctl_dir):
            try:
                for sysctl_file in sorted(os.listdir(sysctl_dir)):
                    sysctl_path = os.path.join(sysctl_dir, sysctl_file)
                    if os.path.isfile(sysctl_path) and sysctl_file.endswith('.conf'):
                        content = read_file_safe(sysctl_path, use_cache=True)
                        if content:
                            sysctl_files_read += 1
                            self._files[sysctl_path] = content
            except PermissionError:
                pass
        elapsed = time.monotonic() - start
        timing['sysctl_files'] = round(elapsed, 3)
        self._logger.info(f"  Sysctl files: {sysctl_files_read} read in {elapsed:.3f}s")

        # Also read audit rules from /etc/audit/rules.d/
        start = time.monotonic()
        audit_files_read = 0
        audit_rules_dir = "/etc/audit/rules.d"
        if os.path.isdir(audit_rules_dir):
            try:
                for audit_file in sorted(os.listdir(audit_rules_dir)):
                    audit_path = os.path.join(audit_rules_dir, audit_file)
                    if os.path.isfile(audit_path) and audit_file.endswith('.rules'):
                        content = read_file_safe(audit_path, use_cache=True)
                        if content:
                            audit_files_read += 1
                            self._files[audit_path] = content
            except PermissionError:
                pass
        elapsed = time.monotonic() - start
        timing['audit_rule_files'] = round(elapsed, 3)
        self._logger.info(f"  Audit rule files: {audit_files_read} read in {elapsed:.3f}s")

        # ---------- Pre-run common commands ----------
        start = time.monotonic()
        commands_run = 0
        for cmd in COMMON_COMMANDS:
            result = run_command(cmd, use_cache=True)
            self._commands[cmd] = result
            commands_run += 1
        elapsed = time.monotonic() - start
        timing['common_commands'] = round(elapsed, 3)
        self._logger.info(f"  Common commands: {commands_run} run in {elapsed:.3f}s")

        # ---------- Parse commonly-used structured data ----------
        start = time.monotonic()
        self._parse_common_data()
        elapsed = time.monotonic() - start
        timing['data_parsing'] = round(elapsed, 3)
        self._logger.info(f"  Data parsing completed in {elapsed:.3f}s")

        # ---------- Summary ----------
        total_time = time.monotonic() - start_total
        timing['total'] = round(total_time, 3)
        self._timing = timing
        self._warm = True

        self._logger.info(
            f"Cache warm-up complete: {files_read + pam_files_read + sysctl_files_read + audit_files_read} files, "
            f"{commands_run} commands in {total_time:.3f}s"
        )

        return timing

    def _parse_common_data(self) -> None:
        """
        Parse commonly-needed structured data from cached files and commands.

        Pre-parses:
        - sysctl key-value pairs
        - SSH configuration parameters
        - Service unit files (enabled/disabled)
        - Running services
        - Listening ports
        - Mounted filesystems
        - Loaded kernel modules
        - Password policy settings from login.defs
        """
        # Parse sysctl output into dict
        sysctl_output = self.get_command("sysctl -a 2>/dev/null")
        sysctl_dict = {}
        if sysctl_output and sysctl_output.returncode == 0:
            for line in sysctl_output.stdout.splitlines():
                if '=' in line:
                    parts = line.split('=', 1)
                    if len(parts) == 2:
                        sysctl_dict[parts[0].strip()] = parts[1].strip()
        self._parsed_data['sysctl'] = sysctl_dict

        # Parse SSH configuration into dict
        sshd_content = self.get_file('/etc/ssh/sshd_config')
        ssh_config = {}
        if sshd_content:
            for line in sshd_content.splitlines():
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                # Parse key-value pairs
                parts = line.split(None, 1)
                if len(parts) == 2:
                    key = parts[0]
                    # Remove inline comments
                    value = parts[1].split('#')[0].strip()
                    ssh_config[key.lower()] = value
        self._parsed_data['ssh_config'] = ssh_config

        # Parse service unit files into sets of enabled/disabled
        service_units_output = self.get_command(
            "systemctl list-unit-files --type=service 2>/dev/null"
        )
        enabled_services = set()
        disabled_services = set()
        if service_units_output and service_units_output.returncode == 0:
            for line in service_units_output.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    svc_name = parts[0].replace('.service', '')
                    state = parts[1].lower()
                    if state == 'enabled':
                        enabled_services.add(svc_name)
                    elif state == 'disabled':
                        disabled_services.add(svc_name)
        self._parsed_data['enabled_services'] = enabled_services
        self._parsed_data['disabled_services'] = disabled_services

        # Parse running services into set
        running_output = self.get_command(
            "systemctl list-units --type=service --state=running 2>/dev/null"
        )
        running_services = set()
        if running_output and running_output.returncode == 0:
            for line in running_output.stdout.splitlines():
                parts = line.strip().split()
                if parts and '.service' in parts[0]:
                    svc_name = parts[0].replace('.service', '').lstrip('*').strip()
                    running_services.add(svc_name)
        self._parsed_data['running_services'] = running_services

        # Parse listening ports
        ss_output = self.get_command("ss -tuln 2>/dev/null")
        listening_ports = set()
        if ss_output and ss_output.returncode == 0:
            for line in ss_output.stdout.splitlines():
                if 'LISTEN' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        # Extract port from address:port format
                        addr = parts[4]
                        port_match = re.search(r':(\d+)$', addr)
                        if port_match:
                            try:
                                listening_ports.add(int(port_match.group(1)))
                            except ValueError:
                                pass
        self._parsed_data['listening_ports'] = listening_ports

        # Parse mounted filesystems from /proc/mounts (direct read, no subprocess)
        mount_content = self.get_file("/proc/mounts")
        mounts = {}
        if mount_content:
            for line in mount_content.splitlines():
                # Format: device mountpoint fstype options dump pass
                parts = line.split()
                if len(parts) >= 4:
                    mounts[parts[1]] = {
                        'device': parts[0],
                        'type': parts[2],
                        'options': parts[3].split(',')
                    }
        else:
            # Fallback to mount command if /proc/mounts unavailable
            mount_output = self.get_command("mount 2>/dev/null")
            if mount_output and mount_output.returncode == 0:
                for line in mount_output.stdout.splitlines():
                    match = re.match(r'(.+?)\s+on\s+(.+?)\s+type\s+(\S+)\s+\((.+?)\)', line)
                    if match:
                        mounts[match.group(2)] = {
                            'device': match.group(1),
                            'type': match.group(3),
                            'options': match.group(4).split(',')
                        }
        self._parsed_data['mounts'] = mounts

        # Parse loaded kernel modules from /proc/modules (direct read, no subprocess)
        modules_content = self.get_file("/proc/modules")
        loaded_modules = set()
        if modules_content:
            for line in modules_content.splitlines():
                parts = line.split()
                if parts:
                    loaded_modules.add(parts[0])
        else:
            # Fallback to lsmod command
            lsmod_output = self.get_command("lsmod 2>/dev/null")
            if lsmod_output and lsmod_output.returncode == 0:
                for line in lsmod_output.stdout.splitlines()[1:]:
                    parts = line.split()
                    if parts:
                        loaded_modules.add(parts[0])
        self._parsed_data['loaded_modules'] = loaded_modules

        # Parse login.defs into dict
        login_defs_content = self.get_file('/etc/login.defs')
        login_defs = {}
        if login_defs_content:
            for line in login_defs_content.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    login_defs[parts[0]] = parts[1].strip()
        self._parsed_data['login_defs'] = login_defs

        # Parse /etc/passwd from direct file read (no subprocess needed)
        passwd_content = self.get_file("/etc/passwd")
        users = []
        if passwd_content:
            for line in passwd_content.splitlines():
                parts = line.strip().split(':')
                if len(parts) >= 7:
                    users.append({
                        'username': parts[0],
                        'uid': int(parts[2]) if parts[2].isdigit() else -1,
                        'gid': int(parts[3]) if parts[3].isdigit() else -1,
                        'gecos': parts[4],
                        'home': parts[5],
                        'shell': parts[6]
                    })
        self._parsed_data['users'] = users

    def get_file(self, filepath: str) -> str:
        """
        Get cached file contents, reading from disk if not yet cached.

        Args:
            filepath: Absolute path to the file

        Returns:
            File contents as string, or empty string if unreadable
        """
        with self._lock:
            if filepath in self._files:
                return self._files[filepath]

        # Not in cache - read and cache it
        content = read_file_safe(filepath, use_cache=True)
        with self._lock:
            self._files[filepath] = content
        return content

    def get_command(self, command: str) -> subprocess.CompletedProcess:
        """
        Get cached command output, executing if not yet cached.

        Args:
            command: Shell command string

        Returns:
            subprocess.CompletedProcess with stdout, stderr, returncode
        """
        with self._lock:
            if command in self._commands:
                return self._commands[command]

        # Not in cache - execute and cache it
        result = run_command(command, use_cache=True)
        with self._lock:
            self._commands[command] = result
        return result

    def get_parsed(self, key: str) -> Any:
        """
        Get pre-parsed structured data.

        Available keys:
            'sysctl'            - Dict[str, str] of sysctl parameters
            'ssh_config'        - Dict[str, str] of SSH config (lowercase keys)
            'enabled_services'  - Set[str] of enabled service names
            'disabled_services' - Set[str] of disabled service names
            'running_services'  - Set[str] of running service names
            'listening_ports'   - Set[int] of listening TCP/UDP ports
            'mounts'            - Dict[str, Dict] of mounted filesystems
            'loaded_modules'    - Set[str] of loaded kernel module names
            'login_defs'        - Dict[str, str] of login.defs settings
            'users'             - List[Dict] of user accounts from /etc/passwd

        Args:
            key: Name of the parsed data structure

        Returns:
            Parsed data, or None if key not found
        """
        return self._parsed_data.get(key)

    def get_sysctl_value(self, parameter: str) -> Optional[str]:
        """
        Get a specific sysctl parameter value from the pre-parsed cache.

        This is much faster than calling `sysctl <param>` as a subprocess.

        Args:
            parameter: Full sysctl parameter name (e.g., 'net.ipv4.ip_forward')

        Returns:
            Parameter value as string, or None if not found
        """
        sysctl_data = self._parsed_data.get('sysctl', {})
        return sysctl_data.get(parameter)

    def get_ssh_config_value(self, parameter: str) -> Optional[str]:
        """
        Get a specific SSH configuration value from the pre-parsed cache.

        This is much faster than re-reading and parsing sshd_config.

        Args:
            parameter: SSH config parameter name (case-insensitive)

        Returns:
            Parameter value as string, or None if not set
        """
        ssh_data = self._parsed_data.get('ssh_config', {})
        return ssh_data.get(parameter.lower())

    def get_login_defs_value(self, parameter: str) -> Optional[str]:
        """
        Get a specific login.defs value from the pre-parsed cache.

        Args:
            parameter: login.defs parameter name (e.g., 'PASS_MAX_DAYS')

        Returns:
            Parameter value as string, or None if not set
        """
        login_defs = self._parsed_data.get('login_defs', {})
        return login_defs.get(parameter)

    def is_service_enabled(self, service_name: str) -> bool:
        """Check if a service is enabled from cached service list"""
        enabled = self._parsed_data.get('enabled_services', set())
        return service_name in enabled

    def is_service_running(self, service_name: str) -> bool:
        """Check if a service is running from cached service list"""
        running = self._parsed_data.get('running_services', set())
        return service_name in running

    def is_port_listening(self, port: int) -> bool:
        """Check if a port is listening from cached port list"""
        ports = self._parsed_data.get('listening_ports', set())
        return port in ports

    def is_module_loaded(self, module_name: str) -> bool:
        """Check if a kernel module is loaded from cached module list"""
        modules = self._parsed_data.get('loaded_modules', set())
        return module_name in modules

    def has_mount_option(self, mount_point: str, option: str) -> bool:
        """Check if a mount point has a specific option from cached mount data"""
        mounts = self._parsed_data.get('mounts', {})
        mount_info = mounts.get(mount_point)
        if mount_info:
            return option in mount_info.get('options', [])
        return False

    @property
    def is_warm(self) -> bool:
        """Check if the cache has been warmed up"""
        return self._warm

    @property
    def timing(self) -> Dict[str, float]:
        """Get cache warm-up timing data"""
        return self._timing

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of cached data for reporting"""
        return {
            'files_cached': len(self._files),
            'commands_cached': len(self._commands),
            'parsed_datasets': len(self._parsed_data),
            'is_warm': self._warm,
            'warm_up_time': self._timing.get('total', 0),
            'command_cache_stats': get_cache_statistics(),
            'os_info': self._os_info.to_dict()
        }


# ============================================================================
# Common Utility Functions (Consolidated from all modules)
# ============================================================================

def command_exists(command: str) -> bool:
    """
    Check if a command is available on the system.

    Uses shutil.which() (faster than subprocess-based 'which' command).

    Args:
        command: Command name to check (e.g., 'systemctl', 'iptables')

    Returns:
        True if the command is found in PATH
    """
    return shutil.which(command) is not None


def check_service_enabled(service_name: str,
                          cache: Optional[SharedDataCache] = None) -> bool:
    """
    Check if a systemd service is enabled.

    Uses cached data if available, falls back to subprocess.

    Args:
        service_name: Service name (with or without .service suffix)
        cache: Optional SharedDataCache for faster lookup

    Returns:
        True if the service is enabled
    """
    # Strip .service suffix for cache lookup
    clean_name = service_name.replace('.service', '')

    if cache:
        return cache.is_service_enabled(clean_name)

    result = run_command(f"systemctl is-enabled {service_name} 2>/dev/null")
    return result.returncode == 0 and result.stdout.strip() == "enabled"


def check_service_active(service_name: str,
                         cache: Optional[SharedDataCache] = None) -> bool:
    """
    Check if a systemd service is currently active (running).

    Uses cached data if available, falls back to subprocess.

    Args:
        service_name: Service name (with or without .service suffix)
        cache: Optional SharedDataCache for faster lookup

    Returns:
        True if the service is active/running
    """
    clean_name = service_name.replace('.service', '')

    if cache:
        return cache.is_service_running(clean_name)

    result = run_command(f"systemctl is-active {service_name} 2>/dev/null")
    return result.returncode == 0 and result.stdout.strip() == "active"


def check_package_installed(package_name: str,
                            os_info: Optional[OSInfo] = None) -> bool:
    """
    Check if a package is installed, with OS-aware detection.

    Tries the appropriate package manager based on detected OS family.
    Falls back to trying both dpkg and rpm if OS is unknown.

    Args:
        package_name: Package name to check
        os_info: Optional OSInfo for OS-aware checking

    Returns:
        True if the package is installed
    """
    if os_info and os_info.is_debian_based():
        result = run_command(f"dpkg -l {package_name} 2>/dev/null | grep -q '^ii'")
        return result.returncode == 0
    elif os_info and os_info.is_redhat_based():
        result = run_command(f"rpm -q {package_name} 2>/dev/null")
        return result.returncode == 0
    elif os_info and os_info.is_suse_based():
        result = run_command(f"rpm -q {package_name} 2>/dev/null")
        return result.returncode == 0
    elif os_info and os_info.is_arch_based():
        result = run_command(f"pacman -Q {package_name} 2>/dev/null")
        return result.returncode == 0
    else:
        # Fallback: try dpkg first, then rpm
        result = run_command(f"dpkg -l {package_name} 2>/dev/null | grep -q '^ii'")
        if result.returncode == 0:
            return True
        result = run_command(f"rpm -q {package_name} 2>/dev/null")
        return result.returncode == 0


def get_file_permissions(filepath: str) -> Optional[str]:
    """
    Get file permissions as a 3-digit or 4-digit octal string.

    Args:
        filepath: Absolute path to the file

    Returns:
        Permission string (e.g., '644', '755'), or None if file doesn't exist
    """
    try:
        stat_info = os.stat(filepath)
        return oct(stat_info.st_mode)[-3:]
    except (FileNotFoundError, PermissionError, OSError):
        return None


def get_file_permissions_full(filepath: str) -> Optional[str]:
    """
    Get file permissions as a 4-digit octal string (includes setuid/setgid/sticky).

    Args:
        filepath: Absolute path to the file

    Returns:
        Permission string (e.g., '0644', '4755'), or None if file doesn't exist
    """
    try:
        stat_info = os.stat(filepath)
        return oct(stat_info.st_mode)[-4:]
    except (FileNotFoundError, PermissionError, OSError):
        return None


def get_file_owner_group(filepath: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Get the owner username and group name of a file.

    Args:
        filepath: Absolute path to the file

    Returns:
        Tuple of (owner_name, group_name), or (None, None) on error
    """
    try:
        stat_info = os.stat(filepath)
        owner = pwd.getpwuid(stat_info.st_uid).pw_name
        group = grp.getgrgid(stat_info.st_gid).gr_name
        return owner, group
    except (FileNotFoundError, PermissionError, KeyError, OSError):
        return None, None


def check_kernel_parameter(parameter: str,
                           cache: Optional[SharedDataCache] = None) -> Tuple[bool, str]:
    """
    Check a kernel parameter value via sysctl.

    Lookup order: 1) SharedDataCache  2) /proc/sys direct read  3) sysctl subprocess

    Args:
        parameter: Kernel parameter name (e.g., 'net.ipv4.ip_forward')
        cache: Optional SharedDataCache for faster lookup

    Returns:
        Tuple of (exists: bool, value: str)
    """
    # Try cache first (fastest - pre-parsed sysctl -a output)
    if cache:
        value = cache.get_sysctl_value(parameter)
        if value is not None:
            return True, value
        # Cache miss - parameter may not exist, fall through to direct read

    # Try /proc/sys direct read (fast - no subprocess overhead)
    proc_path = "/proc/sys/" + parameter.replace('.', '/')
    try:
        if os.path.exists(proc_path):
            with open(proc_path, 'r') as f:
                value = f.read().strip()
            return True, value
    except (PermissionError, IOError, OSError):
        pass  # Fall through to subprocess

    # Final fallback: sysctl subprocess
    result = run_command(f"sysctl {parameter} 2>/dev/null")
    if result.returncode == 0:
        match = re.search(r'=\s*(.+)', result.stdout)
        if match:
            return True, match.group(1).strip()
    return False, ""


def check_file_exists(filepath: str) -> bool:
    """
    Check if a file exists.

    Args:
        filepath: Path to check

    Returns:
        True if the file exists
    """
    return os.path.exists(filepath)


def check_mount_option(mount_point: str, option: str,
                       cache: Optional[SharedDataCache] = None) -> bool:
    """
    Check if a mount point has a specific mount option.

    Args:
        mount_point: Mount point path (e.g., '/tmp', '/var')
        option: Mount option to check (e.g., 'noexec', 'nosuid', 'nodev')
        cache: Optional SharedDataCache for faster lookup

    Returns:
        True if the mount point has the specified option
    """
    if cache:
        return cache.has_mount_option(mount_point, option)

    result = run_command(f"mount | grep ' on {mount_point} '")
    if result.returncode == 0:
        return option in result.stdout
    return False


def check_pam_module(module_name: str,
                     cache: Optional[SharedDataCache] = None) -> bool:
    """
    Check if a PAM module is configured in any PAM configuration file.

    Args:
        module_name: PAM module name (e.g., 'pam_faillock', 'pam_pwquality')
        cache: Optional SharedDataCache for faster lookup

    Returns:
        True if the module is referenced in PAM configuration
    """
    pam_files_to_check = [
        "/etc/pam.d/common-password",
        "/etc/pam.d/common-auth",
        "/etc/pam.d/system-auth",
        "/etc/pam.d/password-auth",
        "/etc/pam.d/login",
    ]

    for pam_file in pam_files_to_check:
        content = ""
        if cache:
            content = cache.get_file(pam_file)
        else:
            content = read_file_safe(pam_file)

        if content and module_name in content:
            return True

    return False


# ============================================================================
# Safe Parsing Helpers
# ============================================================================

def safe_int_parse(value: str, default: int = 0) -> int:
    """
    Safely parse a string to integer, handling edge cases.

    Handles: whitespace, multi-line output, non-numeric strings.

    Args:
        value: String to parse
        default: Default value if parsing fails

    Returns:
        Parsed integer or default value
    """
    try:
        if not value:
            return default
        # Strip whitespace and take first line only
        clean_value = value.strip().split('\n')[0].strip()
        if clean_value:
            # Handle negative numbers and normal integers
            return int(clean_value)
        return default
    except (ValueError, AttributeError, IndexError):
        return default


def safe_float_parse(value: str, default: float = 0.0) -> float:
    """
    Safely parse a string to float.

    Args:
        value: String to parse
        default: Default value if parsing fails

    Returns:
        Parsed float or default value
    """
    try:
        if not value:
            return default
        clean_value = value.strip().split('\n')[0].strip()
        if clean_value:
            return float(clean_value)
        return default
    except (ValueError, AttributeError, IndexError):
        return default


# ============================================================================
# Security Subsystem Status Functions
# ============================================================================

def get_selinux_status(os_info: Optional[OSInfo] = None,
                       cache: Optional[SharedDataCache] = None) -> Dict[str, Any]:
    """
    Get comprehensive SELinux status.

    Args:
        os_info: Optional OSInfo for package checking
        cache: Optional SharedDataCache

    Returns:
        Dictionary with keys: installed, enabled, enforcing, mode, policy
    """
    status = {
        'installed': False,
        'enabled': False,
        'enforcing': False,
        'mode': 'disabled',
        'policy': 'unknown'
    }

    # Check if SELinux is installed
    if check_package_installed("selinux-policy", os_info) or \
       os.path.exists("/etc/selinux/config"):
        status['installed'] = True

    # Check current status via getenforce
    if command_exists("getenforce"):
        result = run_command("getenforce")
        if result.returncode == 0:
            mode = result.stdout.strip().lower()
            status['mode'] = mode
            status['enabled'] = mode in ('enforcing', 'permissive')
            status['enforcing'] = mode == 'enforcing'

    # Check policy type via sestatus
    if command_exists("sestatus"):
        result = run_command("sestatus")
        if result.returncode == 0:
            match = re.search(r'Loaded policy name:\s*(\w+)', result.stdout)
            if match:
                status['policy'] = match.group(1)

    return status


def get_apparmor_status(cache: Optional[SharedDataCache] = None) -> Dict[str, Any]:
    """
    Get comprehensive AppArmor status.

    Args:
        cache: Optional SharedDataCache

    Returns:
        Dictionary with keys: installed, enabled, profiles_loaded,
                              profiles_enforcing, profiles_complain
    """
    status = {
        'installed': False,
        'enabled': False,
        'profiles_loaded': 0,
        'profiles_enforcing': 0,
        'profiles_complain': 0
    }

    # Check if AppArmor service is active
    is_active = check_service_active("apparmor", cache)
    if is_active:
        status['installed'] = True
        status['enabled'] = True

        # Get profile statistics
        if command_exists("apparmor_status"):
            result = run_command("apparmor_status 2>/dev/null")
            if result.returncode == 0:
                loaded = re.search(r'(\d+) profiles? are loaded', result.stdout)
                enforcing = re.search(r'(\d+) profiles? are in enforce mode', result.stdout)
                complain = re.search(r'(\d+) profiles? are in complain mode', result.stdout)

                if loaded:
                    status['profiles_loaded'] = int(loaded.group(1))
                if enforcing:
                    status['profiles_enforcing'] = int(enforcing.group(1))
                if complain:
                    status['profiles_complain'] = int(complain.group(1))

    return status


def get_firewall_status(cache: Optional[SharedDataCache] = None) -> Dict[str, bool]:
    """
    Get comprehensive firewall status across all common firewall tools.

    Args:
        cache: Optional SharedDataCache

    Returns:
        Dictionary with keys: ufw, firewalld, iptables, nftables, any_active
    """
    status = {
        'ufw': False,
        'firewalld': False,
        'iptables': False,
        'nftables': False,
        'any_active': False
    }

    # Check UFW
    if command_exists("ufw"):
        result = run_command("ufw status 2>/dev/null | grep -q 'Status: active'")
        status['ufw'] = result.returncode == 0

    # Check firewalld
    status['firewalld'] = check_service_active("firewalld", cache)

    # Check iptables (has rules beyond defaults)
    if command_exists("iptables"):
        result = run_command("iptables -L -n 2>/dev/null | grep -c 'Chain'")
        if result.returncode == 0:
            chain_count = safe_int_parse(result.stdout, 0)
            status['iptables'] = chain_count > 0

    # Check nftables
    if command_exists("nft"):
        result = run_command("nft list ruleset 2>/dev/null | grep -q 'table'")
        status['nftables'] = result.returncode == 0

    status['any_active'] = any([
        status['ufw'], status['firewalld'],
        status['iptables'], status['nftables']
    ])

    return status


def check_fips_mode() -> bool:
    """
    Check if FIPS 140-2/3 mode is enabled.

    Checks both /proc/sys/crypto/fips_enabled and kernel command line.

    Returns:
        True if FIPS mode is enabled
    """
    # Check /proc/sys/crypto/fips_enabled
    fips_file = "/proc/sys/crypto/fips_enabled"
    if os.path.exists(fips_file):
        content = read_file_safe(fips_file).strip()
        if content == "1":
            return True

    # Check kernel command line
    cmdline = read_file_safe("/proc/cmdline")
    if "fips=1" in cmdline:
        return True

    return False


def check_ipv6_enabled() -> bool:
    """
    Check if IPv6 is enabled on the system.

    Returns:
        True if IPv6 is enabled
    """
    if not os.path.exists("/proc/sys/net/ipv6"):
        return False
    exists, value = check_kernel_parameter("net.ipv6.conf.all.disable_ipv6")
    return exists and value != "1"


# ============================================================================
# SSH Configuration Helpers
# ============================================================================

def get_ssh_config_value(parameter: str,
                         config_file: str = "/etc/ssh/sshd_config",
                         cache: Optional[SharedDataCache] = None) -> Optional[str]:
    """
    Get a specific SSH configuration parameter value.

    Uses cached parsed SSH config if available.

    Args:
        parameter: SSH config parameter name (case-insensitive)
        config_file: Path to sshd_config (default: /etc/ssh/sshd_config)
        cache: Optional SharedDataCache for faster lookup

    Returns:
        Parameter value as string, or None if not set
    """
    # Try cache first (only for default config file)
    if cache and config_file == "/etc/ssh/sshd_config":
        return cache.get_ssh_config_value(parameter)

    # Fall back to file parsing
    content = read_file_safe(config_file)
    if not content:
        return None

    # Case-insensitive match, skip comments
    pattern = rf'^\s*{re.escape(parameter)}\s+(.+?)(?:\s*#.*)?$'
    match = re.search(pattern, content, re.MULTILINE | re.IGNORECASE)

    if match:
        return match.group(1).strip()
    return None


def get_ssh_config_all(config_file: str = "/etc/ssh/sshd_config",
                       cache: Optional[SharedDataCache] = None) -> Dict[str, str]:
    """
    Get all SSH configuration parameters as a dictionary.

    Args:
        config_file: Path to sshd_config
        cache: Optional SharedDataCache

    Returns:
        Dictionary of parameter_name (lowercase) -> value
    """
    if cache and config_file == "/etc/ssh/sshd_config":
        parsed = cache.get_parsed('ssh_config')
        if parsed:
            return parsed

    content = read_file_safe(config_file)
    config = {}
    if content:
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                key = parts[0]
                value = parts[1].split('#')[0].strip()
                config[key.lower()] = value

    return config


# ============================================================================
# Network Utilities
# ============================================================================

def get_listening_ports(cache: Optional[SharedDataCache] = None) -> List[int]:
    """
    Get list of listening TCP/UDP ports.

    Args:
        cache: Optional SharedDataCache for faster lookup

    Returns:
        Sorted list of listening port numbers
    """
    if cache:
        ports = cache.get_parsed('listening_ports')
        if ports is not None:
            return sorted(ports)

    result = run_command(
        "ss -tuln 2>/dev/null | grep LISTEN | awk '{print $5}' | "
        "grep -oE '[0-9]+$' | sort -un"
    )
    if result.returncode == 0:
        try:
            return sorted(int(p) for p in result.stdout.strip().split('\n')
                          if p.strip().isdigit())
        except ValueError:
            pass
    return []


def get_loaded_kernel_modules(cache: Optional[SharedDataCache] = None) -> List[str]:
    """
    Get list of currently loaded kernel modules.

    Args:
        cache: Optional SharedDataCache

    Returns:
        List of module names
    """
    if cache:
        modules = cache.get_parsed('loaded_modules')
        if modules is not None:
            return sorted(modules)

    result = run_command("lsmod 2>/dev/null | awk 'NR>1 {print $1}'")
    if result.returncode == 0:
        return sorted(result.stdout.strip().split('\n'))
    return []


# ============================================================================
# User Account Utilities
# ============================================================================

def get_user_accounts(cache: Optional[SharedDataCache] = None) -> List[Dict[str, Any]]:
    """
    Get all user accounts from /etc/passwd.

    Args:
        cache: Optional SharedDataCache

    Returns:
        List of user dictionaries with keys: username, uid, gid, gecos, home, shell
    """
    if cache:
        users = cache.get_parsed('users')
        if users is not None:
            return users

    users = []
    try:
        with open('/etc/passwd', 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 7:
                    users.append({
                        'username': parts[0],
                        'uid': int(parts[2]) if parts[2].isdigit() else -1,
                        'gid': int(parts[3]) if parts[3].isdigit() else -1,
                        'gecos': parts[4],
                        'home': parts[5],
                        'shell': parts[6]
                    })
    except (PermissionError, FileNotFoundError):
        pass
    return users


def get_system_users(cache: Optional[SharedDataCache] = None) -> List[str]:
    """
    Get list of system user accounts (UID < 1000, excluding root).

    Args:
        cache: Optional SharedDataCache

    Returns:
        List of system usernames
    """
    users = get_user_accounts(cache)
    return [u['username'] for u in users
            if 0 < u['uid'] < 1000 and u['username'] != 'root']


def get_human_users(cache: Optional[SharedDataCache] = None) -> List[str]:
    """
    Get list of human (regular) user accounts (UID >= 1000).

    Args:
        cache: Optional SharedDataCache

    Returns:
        List of human usernames
    """
    users = get_user_accounts(cache)
    nologin_shells = ('/usr/sbin/nologin', '/bin/false', '/sbin/nologin')
    return [u['username'] for u in users
            if u['uid'] >= 1000 and u['shell'] not in nologin_shells]


# ============================================================================
# Password Policy Helpers
# ============================================================================

def get_password_policy(cache: Optional[SharedDataCache] = None) -> Dict[str, Any]:
    """
    Get comprehensive password policy settings from login.defs and PAM.

    Args:
        cache: Optional SharedDataCache

    Returns:
        Dictionary with password policy settings
    """
    policy = {
        'pass_max_days': 99999,
        'pass_min_days': 0,
        'pass_min_len': 5,
        'pass_warn_age': 7,
        'encrypt_method': 'SHA512',
        'login_retries': 5,
        'login_timeout': 60,
        'pam_pwquality': False,
        'pam_faillock': False,
        'pam_tally2': False,
        'minlen': 0,
        'dcredit': 0,
        'ucredit': 0,
        'lcredit': 0,
        'ocredit': 0,
    }

    # Parse login.defs
    if cache:
        login_defs = cache.get_parsed('login_defs') or {}
        policy['pass_max_days'] = safe_int_parse(
            login_defs.get('PASS_MAX_DAYS', ''), 99999)
        policy['pass_min_days'] = safe_int_parse(
            login_defs.get('PASS_MIN_DAYS', ''), 0)
        policy['pass_min_len'] = safe_int_parse(
            login_defs.get('PASS_MIN_LEN', ''), 5)
        policy['pass_warn_age'] = safe_int_parse(
            login_defs.get('PASS_WARN_AGE', ''), 7)
        policy['encrypt_method'] = login_defs.get('ENCRYPT_METHOD', 'SHA512')
        policy['login_retries'] = safe_int_parse(
            login_defs.get('LOGIN_RETRIES', ''), 5)
        policy['login_timeout'] = safe_int_parse(
            login_defs.get('LOGIN_TIMEOUT', ''), 60)
    else:
        login_defs_content = read_file_safe('/etc/login.defs')
        if login_defs_content:
            for line in login_defs_content.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    key, val = parts[0], parts[1].strip()
                    if key == 'PASS_MAX_DAYS':
                        policy['pass_max_days'] = safe_int_parse(val, 99999)
                    elif key == 'PASS_MIN_DAYS':
                        policy['pass_min_days'] = safe_int_parse(val, 0)
                    elif key == 'PASS_MIN_LEN':
                        policy['pass_min_len'] = safe_int_parse(val, 5)
                    elif key == 'PASS_WARN_AGE':
                        policy['pass_warn_age'] = safe_int_parse(val, 7)
                    elif key == 'ENCRYPT_METHOD':
                        policy['encrypt_method'] = val
                    elif key == 'LOGIN_RETRIES':
                        policy['login_retries'] = safe_int_parse(val, 5)
                    elif key == 'LOGIN_TIMEOUT':
                        policy['login_timeout'] = safe_int_parse(val, 60)

    # Check PAM modules
    policy['pam_pwquality'] = check_pam_module('pam_pwquality', cache)
    policy['pam_faillock'] = check_pam_module('pam_faillock', cache)
    policy['pam_tally2'] = check_pam_module('pam_tally2', cache)

    # Parse pwquality.conf for password complexity
    pwquality_content = ""
    if cache:
        pwquality_content = cache.get_file('/etc/security/pwquality.conf')
    else:
        pwquality_content = read_file_safe('/etc/security/pwquality.conf')

    if pwquality_content:
        for line in pwquality_content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                key, val = line.split('=', 1)
                key = key.strip().lower()
                val = val.strip()
                if key == 'minlen':
                    policy['minlen'] = safe_int_parse(val, 0)
                elif key == 'dcredit':
                    policy['dcredit'] = safe_int_parse(val, 0)
                elif key == 'ucredit':
                    policy['ucredit'] = safe_int_parse(val, 0)
                elif key == 'lcredit':
                    policy['lcredit'] = safe_int_parse(val, 0)
                elif key == 'ocredit':
                    policy['ocredit'] = safe_int_parse(val, 0)

    return policy


# ============================================================================
# Miscellaneous Shared Helpers
# ============================================================================

def get_grub_cmdline(cache: Optional[SharedDataCache] = None) -> str:
    """
    Get the GRUB command line default parameters.

    Args:
        cache: Optional SharedDataCache

    Returns:
        GRUB_CMDLINE_LINUX_DEFAULT value, or empty string
    """
    grub_content = ""
    if cache:
        grub_content = cache.get_file('/etc/default/grub')
    else:
        grub_content = read_file_safe('/etc/default/grub')

    if grub_content:
        match = re.search(
            r'GRUB_CMDLINE_LINUX_DEFAULT\s*=\s*"([^"]*)"', grub_content
        )
        if match:
            return match.group(1)

        # Also check GRUB_CMDLINE_LINUX (without DEFAULT)
        match = re.search(
            r'GRUB_CMDLINE_LINUX\s*=\s*"([^"]*)"', grub_content
        )
        if match:
            return match.group(1)

    return ""


def check_grub_parameter(parameter: str,
                         cache: Optional[SharedDataCache] = None) -> bool:
    """
    Check if a specific parameter exists in GRUB command line.

    Args:
        parameter: Parameter to search for (e.g., 'audit=1')
        cache: Optional SharedDataCache

    Returns:
        True if the parameter is present in GRUB configuration
    """
    cmdline = get_grub_cmdline(cache)
    return parameter in cmdline


def get_audit_rules(cache: Optional[SharedDataCache] = None) -> str:
    """
    Get all configured audit rules (combined from all sources).

    Args:
        cache: Optional SharedDataCache

    Returns:
        Combined audit rules as a single string
    """
    rules = ""

    # Get active rules via auditctl
    result = run_command("auditctl -l 2>/dev/null")
    if result.returncode == 0:
        rules += result.stdout

    # Also read from rules files
    if cache:
        audit_rules = cache.get_file('/etc/audit/audit.rules')
        if audit_rules:
            rules += "\n" + audit_rules
    else:
        rules_content = read_file_safe('/etc/audit/audit.rules')
        if rules_content:
            rules += "\n" + rules_content

    # Read from rules.d directory
    rules_dir = "/etc/audit/rules.d"
    if os.path.isdir(rules_dir):
        try:
            for rules_file in sorted(os.listdir(rules_dir)):
                if rules_file.endswith('.rules'):
                    filepath = os.path.join(rules_dir, rules_file)
                    if cache:
                        content = cache.get_file(filepath)
                    else:
                        content = read_file_safe(filepath)
                    if content:
                        rules += "\n" + content
        except PermissionError:
            pass

    return rules


def get_available_updates(os_info: OSInfo) -> int:
    """
    Get number of available system updates (OS-aware).

    Args:
        os_info: Detected OS information

    Returns:
        Number of available updates, or -1 if unable to determine
    """
    if os_info.is_debian_based():
        result = run_command(
            "apt list --upgradable 2>/dev/null | grep -c upgradable",
            use_cache=False
        )
        if result.returncode == 0:
            return safe_int_parse(result.stdout, 0)
    elif os_info.is_redhat_based():
        if os_info.package_manager == 'dnf':
            result = run_command(
                "dnf check-update --quiet 2>/dev/null | grep -c '^[a-zA-Z]'",
                use_cache=False
            )
        else:
            result = run_command(
                "yum check-update --quiet 2>/dev/null | grep -c '^[a-zA-Z]'",
                use_cache=False
            )
        if result.returncode in (0, 100):
            return safe_int_parse(result.stdout, 0)
    elif os_info.is_suse_based():
        result = run_command(
            "zypper list-updates 2>/dev/null | grep -c '|'",
            use_cache=False
        )
        if result.returncode == 0:
            count = safe_int_parse(result.stdout, 0)
            return max(0, count - 2)  # Subtract header lines
    elif os_info.is_arch_based():
        result = run_command(
            "pacman -Qu 2>/dev/null | wc -l",
            use_cache=False
        )
        if result.returncode == 0:
            return safe_int_parse(result.stdout, 0)

    return -1


def get_security_updates(os_info: OSInfo) -> int:
    """
    Get number of available security updates (OS-aware).

    Args:
        os_info: Detected OS information

    Returns:
        Number of security updates, or -1 if unable to determine
    """
    if os_info.is_debian_based():
        result = run_command(
            "apt list --upgradable 2>/dev/null | grep -ic security",
            use_cache=False
        )
        if result.returncode == 0:
            return safe_int_parse(result.stdout, 0)
    elif os_info.is_redhat_based():
        if os_info.package_manager == 'dnf':
            result = run_command(
                "dnf updateinfo list security 2>/dev/null | grep -c 'security'",
                use_cache=False
            )
        else:
            result = run_command(
                "yum updateinfo list security 2>/dev/null | grep -c 'security'",
                use_cache=False
            )
        if result.returncode == 0:
            return safe_int_parse(result.stdout, 0)

    return -1


# ============================================================================
# ID Generator Helpers (Unified pattern for all modules)
# ============================================================================

def generate_check_id(framework: str, category: str, number: int) -> str:
    """
    Generate a standardized check ID for any framework.

    Format: FRAMEWORK-CATEGORY-NNN

    Args:
        framework: Framework name (e.g., 'CIS', 'NIST', 'STIG', 'NSA')
        category: Category abbreviation (e.g., 'AC', 'IA', 'MAC')
        number: Sequential check number within category

    Returns:
        Formatted check ID string (e.g., 'NIST-AC-001', 'NSA-MAC-005')
    """
    return f"{framework}-{category}-{number:03d}"


# ============================================================================
# Module Information / Version
# ============================================================================

COMMON_LIB_VERSION = "2.0"
COMMON_LIB_NAME = "audit_common"


def get_library_info() -> Dict[str, Any]:
    """
    Get information about this shared library for diagnostics.

    Returns:
        Dictionary with library version, capabilities, and cache status
    """
    return {
        'name': COMMON_LIB_NAME,
        'version': COMMON_LIB_VERSION,
        'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        'platform': platform.platform(),
        'command_cache_stats': get_cache_statistics(),
        'functions_exported': len([
            name for name in dir(sys.modules[__name__])
            if callable(getattr(sys.modules[__name__], name, None))
            and not name.startswith('_')
        ])
    }
