#!/usr/bin/env python3
"""
linux_security_audit.py
Linux Security Audit Script - Orchestrator
Version: 3.9
GitHub: https://github.com/Sandler73/Linux-Security-Audit-Project.git
License: MIT
Maintained by: Sandler73

SYNOPSIS:
    Module-based Linux security and compliance audit orchestrator supporting
    16 security frameworks, five output formats, cross-framework correlation,
    risk scoring, an attack-surface assessment, per-framework split reports,
    per-distribution profiles, and automated/interactive remediation with
    rollback generation.

DESCRIPTION:
    This orchestrator discovers and runs the framework modules in modules/,
    aggregates their AuditResult objects, runs the post-execution pipeline
    (validation, cross-framework correlation, risk scoring, compliance
    scoring, optional baseline diff), and produces reports. It audits Linux
    systems against the following 16 frameworks:

    - Core         : Foundational Linux security baseline + attack surface
    - CIS          : CIS Benchmarks + CIS Controls v8 IG3
    - CISA         : CISA CPGs, ZTMM, KEV, Stop Ransomware, Secure by Design
    - ENISA        : ENISA guidelines + NIS2 + Cyber Resilience Act + DORA
    - ISO27001     : ISO/IEC 27001:2022 Annex A (+ 27017/27018/27701)
    - NIST         : NIST 800-53 R5, CSF 2.0, 800-171, 800-207, SSDF 800-218
    - NSA          : NSA guidance + CNSA 2.0 + K8s hardening + encrypted DNS
    - STIG         : DISA STIGs (V-numbers) + SRG-APP families
    - ACSC         : ACSC Essential Eight (ML1-ML3) + ISM
    - CMMC         : CMMC 2.0 (L1/L2/L3) + NIST 800-171/800-172 + DFARS
    - DistBaseline : Per-distribution hardening (Debian/RHEL/SUSE/Arch)
    - EDR          : EDR posture + MITRE ATT&CK technique coverage
    - GDPR         : GDPR Article 32 technical measures + breach detection
    - HIPAA        : HIPAA Security Rule (45 CFR Part 164) + 405(d) HICP
    - PCI-DSS      : PCI DSS v4.0.1 (Requirements 1-12)
    - SOC2         : AICPA SOC 2 Trust Services Criteria (CC1-CC9 + A/C/PI/P)

    Features:
    - Five output formats: HTML, CSV, JSON, XML, Console (+ companion JSON)
    - Interactive HTML report (dark/light theme, filtering, sorting, column
      controls, client-side search, and CSV/JSON/XML export)
    - Per-module summary tiles and priority-ranked top findings in HTML
    - Three compliance scores (simple, status-weighted, severity-adjusted)
      with a configurable pass/fail threshold
    - Cross-framework control correlation (correlation registry, 158 topics)
    - Risk prioritization (1-100 risk scoring with asset criticality)
    - Attack-surface assessment report (10 exposure domains) via
      --attack-surface
    - Per-framework split reports via --split-reports / --split-only
    - Per-distribution audit profiles (18 built-in) via --profile
    - Canonical cross-framework remediation normalization
    - Automated and interactive remediation, remediation bundles, and
      generated rollback scripts
    - Baseline drift comparison between audit runs
    - SharedDataCache and a per-process helper cache for performance
    - Parallel module execution
    - Structured logging (console + file, optional JSON for SIEM)
    - Zero external dependencies (Python standard library only)

PARAMETERS:
    Module selection and output:
    -m, --modules LIST     : Comma-separated modules to run, or All (default:
                             All). Accepts module names and aliases, e.g.
                             Core,CIS,NIST,STIG,NSA,CISA,PCIDSS,HIPAA,SOC2
    --list-modules         : List all discovered modules and exit
    -f, --output-format FMT: HTML | CSV | JSON | XML | Console (default: HTML)
    -o, --output-path PATH : Output file path (default: auto-generated)

    Reports:
    --split-reports        : Also write one focused report per framework into
                             reports/by-framework/, alongside the combined one
    --split-only           : Write only the per-framework reports
    --attack-surface       : Generate the attack-surface assessment report
                             (HTML + JSON) synthesizing exposure across domains

    Profiles and performance:
    --profile NAME         : Apply a per-distribution audit profile (e.g.
                             generic, rhel9, rhel8, ubuntu24, ubuntu22,
                             debian12, alpine, suse15, fedora, rocky, ...)
    --list-profiles        : List all available --profile values and exit
    --parallel             : Execute modules in parallel
    --workers N            : Number of parallel workers (default: auto)
    --no-cache             : Disable the shared/helper caches (debugging)
    --perf-profile         : Show per-module timing/performance breakdown
                             (alias: --profile-perf)

    Scoring, correlation, and validation:
    --threshold PCT        : Compliance pass/fail threshold (default: 70.0)
    --asset-criticality N  : Asset criticality 1-10 for risk scoring
                             (default: 5)
    --show-risk-priority   : Print the risk-prioritized findings list
    --show-correlations    : Include cross-framework correlations in output
    --validate-results     : Run strict result validation in the pipeline

    Remediation, bundles, baseline, rollback:
    --remediate            : Interactively remediate failed checks
    --remediate-fail       : Remediate only FAIL status issues
    --remediate-warning    : Remediate only WARNING status issues
    --remediate-info       : Remediate only INFO status issues
    --auto-remediate       : Remediate without prompting (with safety checks)
    --remediation-file F   : JSON file listing specific issues to remediate
    --remediation-bundle B : Apply a predefined remediation bundle
    --list-bundles         : List available remediation bundles and exit
    --baseline PATH        : Prior audit JSON to compare against (drift report)
    --rollback-path PATH   : Path to write the generated rollback script

    Logging:
    --log-level LEVEL      : DEBUG | INFO | WARNING | ERROR (default: INFO)
    --log-file PATH        : Write a detailed log to this file
    --json-log             : Use JSON-structured log output (for SIEM)
    -v, --verbose          : Verbose output (log level DEBUG)
    -q, --quiet            : Suppress non-essential output (log level WARNING)

EXAMPLES:
    python3 linux_security_audit.py
        Run all modules with default HTML output

    sudo python3 linux_security_audit.py -m Core,NIST,CISA -f CSV
        Run specific modules and output to CSV

    sudo python3 linux_security_audit.py --parallel --workers 8
        Run all modules in parallel with 8 workers

    sudo python3 linux_security_audit.py --profile rhel9 --threshold 80
        Apply the RHEL 9 profile and require 80% to pass

    sudo python3 linux_security_audit.py --modules CIS,STIG,PCIDSS --split-reports
        Produce the combined report plus one report per framework

    sudo python3 linux_security_audit.py --attack-surface
        Generate the attack-surface assessment report

    sudo python3 linux_security_audit.py --baseline prior-audit.json
        Compare this run against a previous audit and report drift

    sudo python3 linux_security_audit.py --auto-remediate --remediation-file selected.json
        Automatically remediate specific issues exported from a report

NOTES:
    Requires: Linux, Python 3.7+ (uses dataclasses). Zero external
    dependencies (standard library only).
    Run with sudo/root for complete results and for remediation.

    PERFORMANCE:
    The SharedDataCache pre-reads common configuration files and commands
    once and shares them across modules; a per-process helper cache further
    deduplicates command/file/sysctl lookups. Together these substantially
    reduce execution time on multi-module runs.

    REMEDIATION WORKFLOW:
    1. Run the audit and review the HTML report.
    2. Select specific findings and use "Export Selected" to write a JSON file.
    3. Apply fixes: python3 linux_security_audit.py --auto-remediate
       --remediation-file <exported>.json
    4. A rollback script can be generated (--rollback-path) to reverse changes.
"""

import os
import sys
import re
import json
import csv
import argparse
import subprocess
import platform
import socket
import datetime
import time
import html
import logging
import concurrent.futures
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict, field

# ============================================================================
# Shared Library Integration
# ============================================================================
# Import the consolidated shared library for caching, OS detection, and logging.
# Tries shared_components/ package first, then flat-file layout, then falls back.
try:
    sys.path.insert(0, str(Path(__file__).parent.absolute()))
    from shared_components.audit_common import (
        SharedDataCache, OSInfo, detect_os as common_detect_os,
        configure_logging as common_configure_logging,
        get_module_logger, get_cache_statistics,
        clear_command_cache, COMMON_LIB_VERSION,
        AuditResult as CommonAuditResult,
    )
    HAS_COMMON_LIB = True
except ImportError:
    try:
        from audit_common import (
            SharedDataCache, OSInfo, detect_os as common_detect_os,
            configure_logging as common_configure_logging,
            get_module_logger, get_cache_statistics,
            clear_command_cache, COMMON_LIB_VERSION,
            AuditResult as CommonAuditResult,
        )
        HAS_COMMON_LIB = True
    except ImportError:
        HAS_COMMON_LIB = False

# ============================================================================
# Configuration
# ============================================================================
SCRIPT_VERSION = "3.9"
SCRIPT_PATH = Path(__file__).parent.absolute()
LOG_DIR = SCRIPT_PATH / "logs"
REPORT_DIR = SCRIPT_PATH / "reports"
VALID_STATUS_VALUES = ["Pass", "Fail", "Warning", "Info", "Error"]

# Performance defaults
DEFAULT_PARALLEL_WORKERS = 4
MAX_PARALLEL_WORKERS = 16


def get_safe_hostname() -> str:
    """
    Get the system hostname sanitized for safe use in filenames.

    Strips any characters that are not alphanumeric, hyphens, underscores,
    or dots to prevent filesystem issues. Falls back to 'unknown-host' if
    hostname cannot be determined or results in an empty string.

    Returns:
        Sanitized hostname string safe for use in file paths
    """
    try:
        raw = socket.gethostname()
        # Strip anything that is not filename-safe
        safe = re.sub(r'[^\w.\-]', '', raw)
        return safe if safe else 'unknown-host'
    except Exception:
        return 'unknown-host'


def get_system_ip_addresses() -> List[str]:
    """
    Retrieve non-loopback IP addresses for the local system.

    Enumerates network interfaces and collects their IPv4 and IPv6
    addresses, excluding loopback (127.x.x.x, ::1) and link-local
    (169.254.x.x, fe80::) addresses. Uses socket-based methods with
    subprocess fallback for maximum compatibility across distributions.

    Enhancement 2 - provides paired identification (hostname + OS + IPs)
    for accurate attribution in SIEMs and multi-host environments.

    Returns:
        Sorted list of unique IP address strings. Returns ['N/A'] if
        no usable addresses can be determined.
    """
    addresses = set()

    # --- Method 1: Parse /proc/net/if_inet6 for IPv6 addresses ---
    try:
        import ipaddress as _ipaddress
        with open('/proc/net/if_inet6', 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 4:
                    hex_addr = parts[0]
                    groups = [hex_addr[i:i+4] for i in range(0, 32, 4)]
                    ipv6_str = ':'.join(groups)
                    try:
                        addr = _ipaddress.ip_address(ipv6_str)
                        if not addr.is_loopback and not addr.is_link_local:
                            addresses.add(str(addr))
                    except ValueError:
                        pass
    except (FileNotFoundError, PermissionError, OSError, ImportError):
        pass

    # --- Method 2: socket.getaddrinfo for hostname resolution ---
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            addr = info[4][0]
            if addr and not addr.startswith('127.') and addr != '::1' \
                    and not addr.startswith('169.254.') and not addr.startswith('fe80:'):
                addresses.add(addr)
    except (socket.gaierror, socket.herror, OSError):
        pass

    # --- Method 3: Subprocess fallback (hostname -I) ---
    if not addresses:
        try:
            result = subprocess.run(
                ['hostname', '-I'], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                for addr in result.stdout.strip().split():
                    addr = addr.strip()
                    if addr and not addr.startswith('127.') and addr != '::1' \
                            and not addr.startswith('169.254.') and not addr.startswith('fe80:'):
                        addresses.add(addr)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

    # --- Method 4: ip addr show fallback ---
    if not addresses:
        try:
            result = subprocess.run(
                ['ip', '-o', 'addr', 'show'], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.strip().splitlines():
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if p in ('inet', 'inet6') and i + 1 < len(parts):
                            addr = parts[i + 1].split('/')[0]
                            if addr and not addr.startswith('127.') and addr != '::1' \
                                    and not addr.startswith('169.254.') and not addr.startswith('fe80:'):
                                addresses.add(addr)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

    return sorted(addresses) if addresses else ['N/A']


# ============================================================================
# Data Classes
# ============================================================================
@dataclass
class AuditResult:
    """Represents a single audit check result"""
    module: str
    category: str
    status: str
    message: str
    details: str = ""
    remediation: str = ""
    severity: str = "Medium"
    cross_references: Dict[str, str] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)
    
    def validate(self) -> Tuple[bool, List[str]]:
        """Validate the result object"""
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
        
        return len(issues) == 0, issues

@dataclass
class ExecutionInfo:
    """
    Information about the audit execution.

    Stores host identification (hostname, OS, IPs), timing, module list,
    result counts, and compliance scores for reporting and export.
    """
    hostname: str
    os_version: str
    ip_addresses: List[str]
    scan_date: str
    duration: str
    modules_run: List[str]
    total_checks: int
    pass_count: int
    fail_count: int
    warning_count: int
    info_count: int
    error_count: int
    compliance_scores: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)

@dataclass
class ComplianceScore:
    """
    Compliance scoring for a module or overall audit (Phase 3.5).

    Scoring methods:
      3.5.1 - simple_pct:           Pass / Applicable * 100
      3.5.2 - weighted_pct:         (Pass*1.0 + Warn*0.5) / Applicable * 100
      3.5.3 - (overall instance)    Aggregated across all modules
      3.5.4 - severity_weighted_pct: Adjusted by severity impact factors
      3.5.5 - threshold_result:      PASS/FAIL against configurable threshold

    Severity impact factors: Critical=5.0, High=3.0, Medium=1.5, Low=0.5
    Info checks excluded from applicable count (informational-only).
    """
    module_name: str
    total_checks: int
    passed: int
    failed: int
    warnings: int
    info: int
    errors: int
    simple_pct: float = 0.0
    weighted_pct: float = 0.0
    severity_weighted_pct: float = 0.0
    threshold: float = 70.0
    threshold_result: str = "N/A"

    def compute(self, severity_distribution: Dict[str, int] = None):
        """
        Compute all compliance scores.

        Args:
            severity_distribution: Dict of {severity_name: count} for
                severity-weighted scoring.
        """
        # 3.5.1: Simple pass percentage (exclude Info)
        applicable = self.total_checks - self.info
        if applicable > 0:
            self.simple_pct = round(self.passed / applicable * 100, 2)
        else:
            self.simple_pct = 100.0

        # 3.5.2: Weighted scoring (Pass=1.0, Warn=0.5, Fail=0, Error=0)
        if applicable > 0:
            weighted_sum = (self.passed * 1.0) + (self.warnings * 0.5)
            self.weighted_pct = round(weighted_sum / applicable * 100, 2)
        else:
            self.weighted_pct = 100.0

        # 3.5.4: Severity-weighted compliance score
        if severity_distribution and applicable > 0:
            severity_weights = {
                'Critical': 5.0, 'High': 3.0, 'Medium': 1.5,
                'Low': 0.5, 'Informational': 0.0,
            }
            total_weight = sum(
                severity_weights.get(sev, 1.0) * count
                for sev, count in severity_distribution.items()
                if sev != 'Informational'
            )
            if total_weight > 0:
                fail_rate = (self.failed + self.errors) / applicable
                crit_high_weight = (
                    severity_weights['Critical'] * severity_distribution.get('Critical', 0) +
                    severity_weights['High'] * severity_distribution.get('High', 0)
                )
                severity_factor = 1.0 + (crit_high_weight / total_weight)
                adjusted_fail_rate = min(1.0, fail_rate * severity_factor)
                self.severity_weighted_pct = round((1.0 - adjusted_fail_rate) * 100, 2)
                self.severity_weighted_pct = max(0.0, min(100.0, self.severity_weighted_pct))
            else:
                self.severity_weighted_pct = self.simple_pct
        else:
            self.severity_weighted_pct = self.weighted_pct

        # 3.5.5: Threshold determination
        self.threshold_result = "PASS" if self.weighted_pct >= self.threshold else "FAIL"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for export"""
        return asdict(self)

@dataclass
class ModuleStatistics:
    """Statistics for a single module"""
    total: int
    passed: int
    failed: int
    warnings: int
    info: int
    errors: int

class Statistics:
    """Global statistics tracker"""
    def __init__(self):
        self.validation_issues: List[Dict[str, Any]] = []
        self.normalized_results: int = 0
        self.module_stats: Dict[str, ModuleStatistics] = {}
    
    def add_validation_issue(self, module: str, issues: List[str]):
        """Add validation issues"""
        self.validation_issues.append({
            "module": module,
            "issues": "; ".join(issues),
            "timestamp": datetime.datetime.now().isoformat()
        })
    
    def increment_normalized(self):
        """Increment normalized results counter"""
        self.normalized_results += 1

# Global statistics instance
statistics = Statistics()

# ============================================================================
# Color Output Functions
# ============================================================================
class Colors:
    """ANSI color codes for terminal output"""
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    GRAY = '\033[90m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# Module-level logger for structured logging alongside colored console output
logger = logging.getLogger('audit')

# Map ANSI color codes to logging levels for hybrid output
_COLOR_LOG_LEVEL = {
    Colors.RED: logging.ERROR,
    Colors.YELLOW: logging.WARNING,
    Colors.GREEN: logging.INFO,
    Colors.CYAN: logging.INFO,
    Colors.WHITE: logging.INFO,
    Colors.MAGENTA: logging.INFO,
    Colors.GRAY: logging.DEBUG,
}

def print_colored(text: str, color: str = Colors.WHITE, bold: bool = False):
    """Print colored text to console"""
    style = Colors.BOLD if bold else ""
    print(f"{style}{color}{text}{Colors.RESET}")

def log_and_print(text: str, color: str = Colors.WHITE, bold: bool = False,
                  level: int = None):
    """
    Hybrid output: print colored to console AND log to structured log file.

    Maintains the full console UX with ANSI colors while simultaneously
    writing a clean (color-stripped) message to the log file at the
    appropriate severity level. Use for operational events that should be
    captured in both places (module start/stop, errors, remediation, exports).

    Args:
        text: Message text (may contain ANSI codes or brackets like [+] [!])
        color: ANSI color code for console output
        bold: Whether to bold the console output
        level: Explicit logging level; auto-detected from color if None
    """
    # Print to console with colors
    style = Colors.BOLD if bold else ""
    print(f"{style}{color}{text}{Colors.RESET}")
    # Log to file without ANSI codes
    clean_text = text.strip()
    if not clean_text:
        return
    log_level = level if level is not None else _COLOR_LOG_LEVEL.get(color, logging.INFO)
    logger.log(log_level, clean_text)

def print_banner():
    """Display the script banner"""
    print()
    print_colored("=" * 100, Colors.CYAN)
    print_colored(f"                     Linux Security Audit Script v{SCRIPT_VERSION}", Colors.CYAN)
    print_colored("                  Multi-Framework Security Assessment", Colors.CYAN)
    print_colored("=" * 100, Colors.CYAN)
    print_colored("\nSupported Frameworks:", Colors.WHITE, bold=True)
    print_colored("  - Core Security Baseline", Colors.GRAY)
    print_colored("  - CIS Benchmarks", Colors.GRAY)
    print_colored("  - CISA Best Practices", Colors.GRAY)
    print_colored("  - DISA STIGs", Colors.GRAY)
    print_colored("  - ENISA Cybersecurity Guidelines", Colors.GRAY)
    print_colored("  - ISO/IEC 27001 Information Security Management", Colors.GRAY)
    print_colored("  - NIST Cybersecurity Framework", Colors.GRAY)
    print_colored("  - NSA Cybersecurity Guidance", Colors.GRAY)
    print_colored("  - PCI DSS v4.0.1", Colors.GRAY)
    print_colored("  - ACSC Essential Eight + ISM (Australia)", Colors.GRAY)
    print_colored("  - CMMC 2.0 + DFARS (US DoD)", Colors.GRAY)
    print_colored("  - GDPR Article 32 + ePrivacy (EU)", Colors.GRAY)
    print_colored("  - HIPAA Security Rule + 405(d) HICP (US)", Colors.GRAY)
    print_colored("  - SOC 2 Type II Trust Services", Colors.GRAY)
    print_colored("  - Distribution Hardening Baseline (Ubuntu USG/RHEL/SUSE/Arch)", Colors.GRAY)
    print_colored("  - Linux EDR Equivalent (Falco/Wazuh/Auditbeat/CS/S1/MDE)", Colors.GRAY)
    if HAS_COMMON_LIB:
        print_colored(f"\n  Shared Library: v{COMMON_LIB_VERSION} (caching, parallel execution enabled)", Colors.GREEN)
    print_colored("\n" + "=" * 100 + "\n", Colors.CYAN)

# ============================================================================
# Prerequisites Check
# ============================================================================
def check_prerequisites(require_root: bool = False) -> Tuple[bool, bool]:
    """
    Check system prerequisites
    
    Args:
        require_root: If True, return False when not running as root
        
    Returns:
        Tuple of (prerequisites_met: bool, is_root: bool)
    """
    print_colored("[*] Checking prerequisites...", Colors.YELLOW)
    
    # Check Python version
    py_version = sys.version_info
    if py_version.major < 3 or (py_version.major == 3 and py_version.minor < 6):
        log_and_print(f"[!] Python 3.6+ required. Current: {py_version.major}.{py_version.minor}", Colors.RED)
        return False, False
    log_and_print(f"[+] Python version: {py_version.major}.{py_version.minor}.{py_version.micro}", Colors.GREEN)
    
    # Check if running as root
    is_root = os.geteuid() == 0
    if not is_root:
        log_and_print("[!] INFO: Not running as root/sudo", Colors.CYAN)
        print_colored("    Some checks may be limited or unavailable", Colors.CYAN)
        print_colored("    Remediation features will be disabled", Colors.CYAN)
        if require_root:
            print_colored("[!] ERROR: Remediation requires root privileges", Colors.RED)
            print_colored("    Run with: sudo python3 linux_security_audit.py --remediate", Colors.YELLOW)
            return False, False
    else:
        log_and_print("[+] Running with root privileges", Colors.GREEN)
        print_colored("    All checks and remediation available", Colors.GREEN)
    
    # Check OS - use os_detection for accurate distribution identification
    # rather than platform.system()/release() which yields "Linux X-generic".
    try:
        from shared_components.os_detection import detect_os as _detect_os
        _os_info = _detect_os()
        os_info = _os_info.pretty_name or str(_os_info)
        if _os_info.detection_source:
            log_and_print(
                f"[+] Operating System: {os_info} "
                f"(family: {_os_info.family}, kernel: {_os_info.kernel.raw or 'n/a'})",
                Colors.GREEN,
            )
        else:
            log_and_print(f"[+] Operating System: {os_info}", Colors.GREEN)
    except Exception:
        # Fallback only if os_detection fails entirely
        os_info = f"{platform.system()} {platform.release()}"
        log_and_print(f"[+] Operating System: {os_info}", Colors.GREEN)
    
    # Check for required commands
    required_commands = ['grep', 'awk']  # Basic commands
    recommended_commands = ['systemctl']  # Useful but not critical
    
    missing_required = []
    missing_recommended = []
    
    for cmd in required_commands:
        if not which(cmd):
            missing_required.append(cmd)
    
    for cmd in recommended_commands:
        if not which(cmd):
            missing_recommended.append(cmd)
    
    # Check for network tools (ss OR netstat - at least one should be available)
    has_ss = which('ss') is not None
    has_netstat = which('netstat') is not None
    if not has_ss and not has_netstat:
        missing_recommended.append('ss or netstat')
    
    if missing_required:
        log_and_print(f"[!] ERROR: Missing required commands: {', '.join(missing_required)}", Colors.RED)
        return False, is_root
    
    if missing_recommended:
        log_and_print(f"[!] INFO: Missing recommended commands: {', '.join(missing_recommended)}", Colors.CYAN)
        print_colored("    Some checks may be skipped", Colors.CYAN)
    
    return True, is_root

def which(command: str) -> Optional[str]:
    """Check if command exists (uses shutil.which for performance)"""
    import shutil
    return shutil.which(command)

# ============================================================================
# Result Validation and Normalization
# ============================================================================
def validate_result(result: AuditResult, module_name: str) -> bool:
    """Validate a result object"""
    is_valid, issues = result.validate()
    
    if not is_valid:
        statistics.add_validation_issue(module_name, issues)
    
    return is_valid

def normalize_result(result: AuditResult, module_name: str) -> AuditResult:
    """Normalize and repair a result object"""
    normalized = False
    
    # Ensure module exists
    if not result.module:
        result.module = module_name
        normalized = True
    
    # Ensure category exists
    if not result.category:
        result.category = "Uncategorized"
        normalized = True
    
    # Ensure message exists
    if not result.message:
        result.message = "No message"
        normalized = True
    
    # Normalize status value (case-insensitive matching)
    if result.status:
        matched_status = None
        for valid_status in VALID_STATUS_VALUES:
            if result.status.lower() == valid_status.lower():
                matched_status = valid_status
                break
        
        if matched_status and result.status != matched_status:
            result.status = matched_status
            normalized = True
        elif not matched_status:
            result.status = "Error"
            normalized = True
    else:
        result.status = "Error"
        normalized = True
    
    if normalized:
        statistics.increment_normalized()
    
    return result

def get_validated_results(results: List[AuditResult], module_name: str) -> List[AuditResult]:
    """Validate and normalize a list of results"""
    if not results:
        log_and_print(f"[!] Module {module_name} returned no results", Colors.YELLOW)
        return []
    
    validated_results = []
    for result in results:
        if validate_result(result, module_name):
            validated_results.append(result)
        else:
            repaired_result = normalize_result(result, module_name)
            if validate_result(repaired_result, module_name):
                validated_results.append(repaired_result)
    
    return validated_results

# ============================================================================
# Module Statistics
# ============================================================================
def calculate_module_statistics(results: List[AuditResult]) -> ModuleStatistics:
    """Calculate statistics for a module's results"""
    return ModuleStatistics(
        total=len(results),
        passed=sum(1 for r in results if r.status == "Pass"),
        failed=sum(1 for r in results if r.status == "Fail"),
        warnings=sum(1 for r in results if r.status == "Warning"),
        info=sum(1 for r in results if r.status == "Info"),
        errors=sum(1 for r in results if r.status == "Error")
    )

# ============================================================================
# Module Management
# ============================================================================
def get_available_modules() -> Dict[str, Path]:
    """
    Dynamically discover and return available modules from the modules directory
    
    Scans the modules/ directory for Python files that follow the module pattern:
    - Filename: module_*.py
    - Contains: run_checks() function
    - Contains: MODULE_NAME variable
    
    Returns:
        Dictionary mapping module names to their file paths
    """
    modules_dir = SCRIPT_PATH / "modules"
    available_modules = {}
    
    if not modules_dir.exists():
        print_colored(f"[!] WARNING: Modules directory not found: {modules_dir}", Colors.YELLOW)
        return available_modules
    
    # Scan for module files
    module_files = sorted(modules_dir.glob("module_*.py"))
    
    for module_file in module_files:
        # Extract module name from filename (e.g., module_core.py -> Core)
        module_name_raw = module_file.stem.replace("module_", "")
        module_name = module_name_raw.title()  # Fallback capitalization

        # Authoritative source: read the module's declared MODULE_NAME so the
        # discovery key EXACTLY matches the `module` field on every AuditResult
        # the module emits. This is critical: per-module compliance scoring and
        # report grouping match results by `r.module == discovery_name`. A
        # mismatch (e.g. discovery "Pci" vs result.module "PCI") silently
        # yields 0 checks and a vacuous 100% score for that module.
        try:
            with open(module_file, 'r', encoding='utf-8') as f:
                head = f.read()
            import re as _re
            m = _re.search(r'^MODULE_NAME\s*=\s*["\']([^"\']+)["\']',
                           head, _re.MULTILINE)
            if m:
                module_name = m.group(1)
            else:
                # Legacy fallback: special-case known acronyms
                if module_name_raw.upper() in ['CIS', 'NIST', 'STIG', 'NSA',
                                               'CISA', 'ENISA']:
                    module_name = module_name_raw.upper()
                elif module_name_raw.lower() == 'iso27001':
                    module_name = 'ISO27001'
        except Exception:
            pass

        # Validate module has required structure
        try:
            # Quick validation: check if file contains required elements
            with open(module_file, 'r', encoding='utf-8') as f:
                content = f.read()
                if 'def run_checks(' in content:
                    available_modules[module_name] = module_file
                else:
                    print_colored(f"[!] WARNING: Skipping {module_file.name} - missing run_checks() function", Colors.YELLOW)
        except Exception as e:
            print_colored(f"[!] WARNING: Could not validate module {module_file.name}: {e}", Colors.YELLOW)
    
    return available_modules

def list_available_modules():
    """List all available modules to the console"""
    modules = get_available_modules()
    
    if not modules:
        print_colored("[!] No modules found in modules/ directory", Colors.YELLOW)
        return
    
    print_colored("\n[*] Available Modules:", Colors.CYAN, bold=True)
    for module_name, module_path in sorted(modules.items()):
        # Try to read module docstring for description
        try:
            with open(module_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                description = "No description available"
                
                # Look for SYNOPSIS in docstring
                in_docstring = False
                for line in lines[:50]:  # Check first 50 lines
                    if '"""' in line or "'''" in line:
                        in_docstring = not in_docstring
                    elif in_docstring and 'SYNOPSIS' in line.upper():
                        # Get next non-empty line
                        idx = lines.index(line)
                        for next_line in lines[idx+1:idx+5]:
                            desc = next_line.strip()
                            if desc and not desc.startswith('"""') and not desc.startswith("'''"):
                                description = desc
                                break
                        break
                
                print_colored(f"  - {module_name.ljust(12)} - {description}", Colors.WHITE)
        except:
            print_colored(f"  - {module_name}", Colors.WHITE)
    
    print_colored(f"\nTotal modules found: {len(modules)}\n", Colors.CYAN)

def check_module_exists(module_name: str) -> bool:
    """Check if a module file exists"""
    available_modules = get_available_modules()
    if module_name not in available_modules:
        return False
    
    module_path = available_modules[module_name]
    return module_path.exists()

def execute_security_module(module_name: str, shared_data: Dict[str, Any]) -> List[AuditResult]:
    """Execute a security audit module"""
    available_modules = get_available_modules()
    module_path = available_modules.get(module_name)
    
    if not module_path or not module_path.exists():
        log_and_print(f"[!] Module not found: {module_name}", Colors.RED)
        return []
    
    try:
        log_and_print(f"\n[*] Executing module: {module_name}", Colors.CYAN)
        module_start = time.time()
        
        # Import and execute the module
        import importlib.util
        load_start = time.time()
        spec = importlib.util.spec_from_file_location(f"module_{module_name.lower()}", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        load_elapsed = time.time() - load_start
        logger.info(f"Module {module_name} loaded in {load_elapsed:.3f}s from {module_path}")
        
        # Call the module's main function
        if hasattr(module, 'run_checks'):
            check_start = time.time()
            results = module.run_checks(shared_data)
            check_elapsed = time.time() - check_start
            logger.info(f"Module {module_name} run_checks() executed in {check_elapsed:.3f}s")
        else:
            log_and_print(f"[!] Module {module_name} missing run_checks function", Colors.RED)
            return []
        
        # Validate and normalize results
        validated_results = get_validated_results(results, module_name)
        
        # Calculate and display module statistics
        stats = calculate_module_statistics(validated_results)
        statistics.module_stats[module_name] = stats
        
        module_elapsed = time.time() - module_start
        log_and_print(f"[+] Module {module_name} completed: {stats.total} checks in {module_elapsed:.1f}s", Colors.GREEN)
        print_colored(f"    Pass: {stats.passed} | Fail: {stats.failed} | Warning: {stats.warnings} | Info: {stats.info} | Error: {stats.errors}", Colors.GRAY)
        
        return validated_results
        
    except Exception as e:
        log_and_print(f"[!] Error executing module {module_name}: {e}", Colors.RED)
        logger.error(f"Module {module_name} exception details", exc_info=True)
        import traceback
        traceback.print_exc()
        return []

# ============================================================================
# Remediation Functions
# ============================================================================
def invoke_remediation(results: List[AuditResult], args: argparse.Namespace):
    """Handle remediation of issues"""
    auto_mode = args.auto_remediate
    remediate_all = args.remediate
    remediate_fail = args.remediate_fail
    remediate_warning = args.remediate_warning
    remediate_info = args.remediate_info
    remediation_file = args.remediation_file
    
    print_colored("\n" + "=" * 100, Colors.YELLOW)
    print_colored("                                REMEDIATION MODE", Colors.YELLOW, bold=True)
    print_colored("=" * 100, Colors.YELLOW)
    
    remediable_results = []
    
    # Check if using remediation file
    if remediation_file:
        if not os.path.exists(remediation_file):
            log_and_print(f"[!] ERROR: Remediation file not found: {remediation_file}", Colors.RED)
            print_colored("=" * 100 + "\n", Colors.YELLOW)
            return
        
        try:
            with open(remediation_file, 'r') as f:
                remediation_data = json.load(f)
            
            if 'modules' not in remediation_data:
                log_and_print("[!] ERROR: Invalid remediation file format. Expected 'modules' array.", Colors.RED)
                print_colored("=" * 100 + "\n", Colors.YELLOW)
                return
            
            # Match results from remediation file
            targeted_checks = []
            for module_data in remediation_data['modules']:
                module_name = module_data['moduleName']
                for result_data in module_data['results']:
                    for result in results:
                        if (result.module == module_name and
                            result.category == result_data.get('Category') and
                            result.message == result_data.get('Finding') and
                            result.remediation):
                            targeted_checks.append(result)
                            break
            
            if not targeted_checks:
                log_and_print("[!] No matching remediable issues found in remediation file.", Colors.YELLOW)
                print_colored("=" * 100 + "\n", Colors.YELLOW)
                return
            
            print_colored(f"[*] Found {len(targeted_checks)} targeted issue(s) to remediate", Colors.CYAN)
            remediable_results = targeted_checks
            
        except Exception as e:
            log_and_print(f"[!] ERROR: Failed to parse remediation file: {e}", Colors.RED)
            print_colored("=" * 100 + "\n", Colors.YELLOW)
            return
    else:
        # Standard mode - filter by status
        statuses_to_remediate = []
        if remediate_all:
            statuses_to_remediate = ["Fail", "Warning", "Info"]
            print_colored("[*] Mode: Remediate ALL issues (Fail, Warning, Info)", Colors.CYAN)
        else:
            if remediate_fail:
                statuses_to_remediate.append("Fail")
            if remediate_warning:
                statuses_to_remediate.append("Warning")
            if remediate_info:
                statuses_to_remediate.append("Info")
            print_colored(f"[*] Mode: Remediate {', '.join(statuses_to_remediate)} issues only", Colors.CYAN)
        
        remediable_results = [r for r in results if r.status in statuses_to_remediate and r.remediation]
        
        if not remediable_results:
            print_colored("\n[*] No remediable issues found for selected status types.", Colors.CYAN)
            print_colored("=" * 100 + "\n", Colors.YELLOW)
            return
        
        print_colored(f"[*] Found {len(remediable_results)} issue(s) with remediation available", Colors.YELLOW)
    
    # Auto-remediation safety confirmation
    if auto_mode:
        print_colored("\n+" + "-" * 98 + "+", Colors.RED)
        print_colored("|" + " " * 34 + "WARNING - AUTO-REMEDIATION" + " " * 37 + "|", Colors.RED)
        print_colored("+" + "-" * 98 + "+", Colors.RED)
        print_colored("|" + " " * 98 + "|", Colors.RED)
        print_colored(f"| This will automatically apply {str(len(remediable_results)).ljust(3)} remediation(s) WITHOUT prompting for each one." + " " * (98 - 76 - len(str(len(remediable_results)))) + "|", Colors.RED)
        print_colored("|" + " " * 98 + "|", Colors.RED)
        print_colored("| RISKS:" + " " * 91 + "|", Colors.RED)
        print_colored("| - System configuration will be modified automatically" + " " * 44 + "|", Colors.RED)
        print_colored("| - Changes may affect system functionality or applications" + " " * 39 + "|", Colors.RED)
        print_colored("| - Some changes may require system restart" + " " * 56 + "|", Colors.RED)
        print_colored("| - Automated remediation may have unintended consequences" + " " * 41 + "|", Colors.RED)
        print_colored("|" + " " * 98 + "|", Colors.RED)
        print_colored("| RECOMMENDATION: Review each remediation in interactive mode first" + " " * 31 + "|", Colors.RED)
        print_colored("|" + " " * 98 + "|", Colors.RED)
        print_colored("+" + "-" * 98 + "+", Colors.RED)
        print()
        
        print_colored("Issues to be remediated:", Colors.YELLOW)
        for result in remediable_results:
            print_colored(f"  - [{result.status}] {result.module} - {result.message}", Colors.GRAY)
        print()
        
        # First confirmation
        first_confirm = input(print_colored("Do you want to proceed with AUTO-REMEDIATION? Type 'YES' to continue: ", Colors.YELLOW, bold=True) or "")
        
        if first_confirm != 'YES':
            print_colored("\n[*] Auto-remediation cancelled by user.", Colors.YELLOW)
            print_colored("=" * 100 + "\n", Colors.YELLOW)
            return
        
        # Second confirmation with countdown
        print_colored("\nFinal confirmation required. Type 'CONFIRM' within 10 seconds to proceed: ", Colors.RED, bold=True, end='')
        import select
        
        timeout = 10
        start_time = time.time()
        second_confirm = None
        
        # Platform-specific input with timeout
        if sys.platform != 'win32':
            i, o, e = select.select([sys.stdin], [], [], timeout)
            if i:
                second_confirm = sys.stdin.readline().strip()
        else:
            # Windows fallback (no timeout)
            second_confirm = input()
        
        if second_confirm != 'CONFIRM':
            print_colored("\n[*] Auto-remediation cancelled (timeout or incorrect confirmation).", Colors.YELLOW)
            print_colored("=" * 100 + "\n", Colors.YELLOW)
            return
        
        print_colored("\n[*] AUTO-REMEDIATION CONFIRMED - Beginning automated remediation...", Colors.GREEN)
        time.sleep(2)
    else:
        print_colored("[*] Interactive mode (will prompt for each remediation)", Colors.CYAN)
    
    print()
    
    remediated_count = 0
    skipped_count = 0
    failed_remediation_count = 0
    remediation_log = []
    
    for result in remediable_results:
        print_colored(f"[*] Issue: {result.message}", Colors.CYAN)
        print_colored(f"    Module: {result.module} | Status: {result.status} | Category: {result.category}", Colors.GRAY)
        print_colored(f"    Remediation: {result.remediation}", Colors.GRAY)
        
        should_remediate = False
        
        if auto_mode:
            should_remediate = True
            log_and_print("    [AUTO] Applying remediation...", Colors.YELLOW)
        else:
            response = input("    Apply remediation? (Y/N/S=Skip remaining): ")
            if response.upper() == 'S':
                print_colored("    [*] Skipping all remaining remediations", Colors.YELLOW)
                skipped_count += (len(remediable_results) - remediated_count - failed_remediation_count - skipped_count)
                break
            should_remediate = response.upper() == 'Y'
        
        if should_remediate:
            try:
                # Execute remediation command
                result_code = subprocess.run(result.remediation, shell=True, capture_output=True, text=True)
                
                if result_code.returncode == 0:
                    log_and_print("    [+] Remediation applied successfully", Colors.GREEN)
                    remediated_count += 1
                    
                    remediation_log.append({
                        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "module": result.module,
                        "status": result.status,
                        "category": result.category,
                        "message": result.message,
                        "remediation": result.remediation,
                        "outcome": "Success"
                    })
                else:
                    log_and_print(f"    [!] Remediation failed: {result_code.stderr}", Colors.RED)
                    failed_remediation_count += 1
                    
                    remediation_log.append({
                        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "module": result.module,
                        "status": result.status,
                        "category": result.category,
                        "message": result.message,
                        "remediation": result.remediation,
                        "outcome": f"Failed: {result_code.stderr}"
                    })
                    
            except Exception as e:
                log_and_print(f"    [!] Remediation error: {e}", Colors.RED)
                failed_remediation_count += 1
                
                remediation_log.append({
                    "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "module": result.module,
                    "status": result.status,
                    "category": result.category,
                    "message": result.message,
                    "remediation": result.remediation,
                    "outcome": f"Error: {e}"
                })
        else:
            print_colored("    [*] Skipped", Colors.YELLOW)
            skipped_count += 1
        
        print()
    
    # Save remediation log
    if remediation_log:
        LOG_DIR.mkdir(mode=0o755, exist_ok=True)
        log_path = LOG_DIR / f"remediation-log-{get_safe_hostname()}-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        with open(log_path, 'w') as f:
            json.dump(remediation_log, f, indent=2)
        
        # Set readable permissions
        try:
            os.chmod(log_path, 0o644)
            
            # If running as root, try to change ownership to the user who invoked sudo
            if os.geteuid() == 0:
                sudo_user = os.environ.get('SUDO_USER')
                if sudo_user:
                    try:
                        import pwd
                        user_info = pwd.getpwnam(sudo_user)
                        os.chown(log_path, user_info.pw_uid, user_info.pw_gid)
                    except:
                        pass
        except:
            pass
        
        print_colored(f"[*] Remediation log saved to: {log_path}", Colors.CYAN)
    
    # Summary
    print_colored("=" * 100, Colors.YELLOW)
    print_colored("                             REMEDIATION SUMMARY", Colors.YELLOW, bold=True)
    print_colored("=" * 100, Colors.YELLOW)
    print_colored(f"  Total remediable issues: {len(remediable_results)}", Colors.WHITE)
    print_colored(f"  Successfully remediated: {remediated_count}", Colors.GREEN)
    print_colored(f"  Failed remediations: {failed_remediation_count}", Colors.RED)
    print_colored(f"  Skipped: {skipped_count}", Colors.YELLOW)
    
    if remediated_count > 0:
        success_rate = round((remediated_count / len(remediable_results)) * 100, 1)
        print_colored(f"  Success rate: {success_rate}%", Colors.CYAN)
    
    print_colored("=" * 100 + "\n", Colors.YELLOW)
    
    if remediated_count > 0 and not auto_mode:
        print_colored("[*] Some settings may require a system restart to take effect.", Colors.YELLOW)
        restart = input("Would you like to restart now? (Y/N): ")
        if restart.upper() == 'Y':
            print_colored("[*] Restarting system in 10 seconds... Press Ctrl+C to cancel", Colors.YELLOW)
            time.sleep(3)
            subprocess.run(['sudo', 'shutdown', '-r', '+1', 'System restart after security remediation'])
    elif remediated_count > 0 and auto_mode:
        print_colored("[*] Auto-remediation complete. Some settings may require a restart.", Colors.YELLOW)

# ============================================================================
# HTML Report Generation
# ============================================================================
def generate_html_report(all_results: List[AuditResult], execution_info: ExecutionInfo, subtitle: str = "Multi-Framework Security Assessment") -> str:
    """
    Generate comprehensive interactive HTML security audit report.

    Features (Phase 3.2 complete):
      - 3.2.1:  Executive summary dashboard with SVG donut chart
      - 3.2.2:  Per-module compliance score (percentage pass)
      - 3.2.3:  Severity distribution (Critical/High/Medium/Low/Informational)
      - 3.2.5:  Cross-framework compliance matrix
      - 3.2.6:  Remediation priority ranking (by severity)
      - 3.2.7:  Print-friendly CSS (@media print)
      - 3.2.8:  Table of contents with anchor links
      - 3.2.9:  Category-level statistics per module
      - 3.2.10: Global search/filter with include/exclude modes
      - 3.2.11: Column visibility toggles per module
      - 3.2.12: Row selection with selection-based export
      - 3.2.13: CSV/JSON/XML export per module AND globally
      - 3.2.15: Proper Unicode collapse/expand icons (chevrons)
      - 3.2.16: Dark blue gradient for both light and dark themes
      - 3.2.17: Full page width header/banner
      - 3.2.18: Garamond default font throughout
      - 3.2.19: Column resizing via drag handles
      - 3.2.20: In-column filtering inputs in every column header

    Args:
        all_results: List of all AuditResult objects from all modules
        execution_info: ExecutionInfo with scan metadata and statistics

    Returns:
        Complete self-contained HTML string
    """

    # ----------------------------------------------------------------
    # Pre-compute data for dashboard, charts, and tables
    # ----------------------------------------------------------------
    modules_data = {}
    for result in all_results:
        if result.module not in modules_data:
            modules_data[result.module] = []
        modules_data[result.module].append(result)

    # Per-module compliance scores
    module_scores = {}
    for mod_name, mod_results in modules_data.items():
        stats = calculate_module_statistics(mod_results)
        # Compliance = (Pass + Info) / Total * 100  (Info checks are informational, not failures)
        applicable = stats.total - stats.info if stats.total > stats.info else stats.total
        score = (stats.passed / applicable * 100) if applicable > 0 else 100.0
        module_scores[mod_name] = {
            'score': score,
            'stats': stats,
            'total': stats.total,
        }

    # Severity distribution across all results
    severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
    for r in all_results:
        sev = r.severity if r.severity in severity_counts else 'Medium'
        severity_counts[sev] += 1

    # Category-level statistics per module
    category_stats = {}
    for mod_name, mod_results in modules_data.items():
        cats = {}
        for r in mod_results:
            if r.category not in cats:
                cats[r.category] = {'total': 0, 'pass': 0, 'fail': 0, 'warning': 0, 'info': 0, 'error': 0}
            cats[r.category]['total'] += 1
            cats[r.category][r.status.lower()] += 1
        category_stats[mod_name] = cats

    # Remediation priority list (failed/warning items sorted by severity)
    severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Informational': 4}
    remediation_items = [r for r in all_results if r.status.lower() in ('fail', 'warning') and r.remediation]
    remediation_items.sort(key=lambda r: (severity_order.get(r.severity, 2), r.status.lower() != 'fail'))

    # SVG donut chart data
    total = execution_info.total_checks or 1
    donut_segments = [
        ('Pass', execution_info.pass_count, '#28a745'),
        ('Fail', execution_info.fail_count, '#dc3545'),
        ('Warning', execution_info.warning_count, '#fd7e14'),
        ('Info', execution_info.info_count, '#17a2b8'),
        ('Error', execution_info.error_count, '#6f42c1'),
    ]

    # Build SVG donut with stroke-dasharray - clickable segments (Enhancement 1)
    circumference = 2 * 3.14159 * 45  # radius=45
    donut_svg_parts = []
    offset = 0
    for label, count, color in donut_segments:
        if count > 0:
            segment_len = (count / total) * circumference
            donut_svg_parts.append(
                f'<circle cx="60" cy="60" r="45" fill="none" stroke="{color}" '
                f'stroke-width="20" stroke-dasharray="{segment_len:.2f} {circumference:.2f}" '
                f'stroke-dashoffset="{-offset:.2f}" style="cursor:pointer" '
                f"onclick=\"dashboardFilter('status','{label}')\" "
                f'data-filter-value="{label}"><title>{label}: {count}</title></circle>'
            )
            offset += segment_len
    donut_svg = '\n'.join(donut_svg_parts)

    # Build donut legend - clickable items (Enhancement 1)
    donut_legend = []
    for label, count, color in donut_segments:
        pct = (count / total * 100) if total > 0 else 0
        donut_legend.append(
            f'<div class="legend-item clickable-filter" '
                f"onclick=\"dashboardFilter('status','{label}')\" "
            f'data-filter-value="{label}">'
            f'<span class="legend-dot" style="background:{color}"></span>'
            f'{label}: {count} ({pct:.1f}%)</div>'
        )
    donut_legend_html = '\n'.join(donut_legend)

    # Module compliance bars - use weighted scores from ComplianceScore (3.5)
    module_bars = []
    compliance_data = execution_info.compliance_scores.get('modules', {})
    for mod_name in sorted(module_scores.keys()):
        if mod_name in compliance_data:
            score = compliance_data[mod_name].get('weighted_pct', module_scores[mod_name]['score'])
            threshold_result = compliance_data[mod_name].get('threshold_result', 'N/A')
        else:
            score = module_scores[mod_name]['score']
            threshold_result = 'N/A'
        color = '#28a745' if score >= 80 else '#fd7e14' if score >= 60 else '#dc3545'
        badge = f' <span style="font-size:0.85em;color:{color}">[{threshold_result}]</span>' if threshold_result != 'N/A' else ''
        module_bars.append(
            f'<div class="bar-row">'
            f'<span class="bar-label">{html.escape(mod_name)}</span>'
            f'<div class="bar-track">'
            f'<div class="bar-fill" style="width:{score:.1f}%;background:{color}"></div>'
            f'</div>'
            f'<span class="bar-value">{score:.1f}%{badge}</span>'
            f'</div>'
        )
    module_bars_html = '\n'.join(module_bars)

    # Cross-framework compliance matrix - use weighted scores + threshold (3.5)
    matrix_rows = []
    status_types = ['Pass', 'Fail', 'Warning', 'Info', 'Error']
    for mod_name in sorted(modules_data.keys()):
        sc = module_scores[mod_name]
        s = sc['stats']
        if mod_name in compliance_data:
            w_score = compliance_data[mod_name].get('weighted_pct', sc['score'])
            t_result = compliance_data[mod_name].get('threshold_result', '')
        else:
            w_score = sc['score']
            t_result = ''
        t_class = 'matrix-threshold-pass' if t_result == 'PASS' else 'matrix-threshold-fail'
        t_badge = f' <span class="{t_class}">[{t_result}]</span>' if t_result else ''
        matrix_rows.append(
            f'<tr>'
            f'<td class="matrix-module">{html.escape(mod_name)}</td>'
            f'<td class="matrix-total">{s.total}</td>'
            f'<td class="matrix-pass">{s.passed}</td>'
            f'<td class="matrix-fail">{s.failed}</td>'
            f'<td class="matrix-warn">{s.warnings}</td>'
            f'<td class="matrix-info">{s.info}</td>'
            f'<td class="matrix-err">{s.errors}</td>'
            f'<td class="matrix-score" style="font-weight:700">{w_score:.1f}%{t_badge}</td>'
            f'</tr>'
        )
    matrix_html = '\n'.join(matrix_rows)

    # ----------------------------------------------------------------
    # v3.7: Per-module summary tiles
    # ----------------------------------------------------------------
    # A grid of compact "tiles" - one per module - showing at a glance:
    #   - module name
    #   - total checks
    #   - pass/fail/warn/info/error split as colored numbers
    #   - compliance score percentage
    #   - top severity present (Critical > High > Medium > Low > Info)
    #   - top-N findings link
    # Tiles are color-banded by health: green (>=90% pass), yellow (70-90),
    # orange (50-70), red (<50). This complements the numeric matrix below
    # by giving a visual "at-a-glance" summary that's faster to scan.
    severity_rank = {
        "Critical": 5, "High": 4, "Medium": 3,
        "Low": 2, "Informational": 1, "": 0,
    }
    rollup_tiles = []
    for mod_name in sorted(modules_data.keys()):
        sc = module_scores[mod_name]
        s = sc["stats"]
        score_value = sc["score"]
        if mod_name in compliance_data:
            score_value = compliance_data[mod_name].get(
                "weighted_pct", score_value,
            )
        # Find top severity among non-pass results in this module
        top_sev = ""
        top_rank = 0
        for r in modules_data[mod_name]:
            if r.status == "Pass":
                continue
            sev_norm = (r.severity or "").strip().capitalize()
            if sev_norm == "Informational":
                pass  # already capitalized
            r_rank = severity_rank.get(sev_norm, 0)
            if r_rank > top_rank:
                top_rank = r_rank
                top_sev = sev_norm
        # Health band class (CSS-driven coloring)
        if score_value >= 90:
            health_class = "tile-health-green"
        elif score_value >= 70:
            health_class = "tile-health-yellow"
        elif score_value >= 50:
            health_class = "tile-health-orange"
        else:
            health_class = "tile-health-red"
        sev_badge = ""
        if top_sev:
            sev_class = f"tile-sev-{top_sev.lower()}"
            sev_badge = (
                f'<span class="tile-sev {sev_class}">'
                f'{html.escape(top_sev)}</span>'
            )
        # Anchor link to module section
        anchor = f"module-{mod_name.lower().replace(' ', '-')}"
        rollup_tiles.append(
            f'<a href="#{anchor}" class="rollup-tile {health_class}" '
            f'data-module="{html.escape(mod_name)}">'
            f'  <div class="tile-header">'
            f'    <span class="tile-name">{html.escape(mod_name)}</span>'
            f'    {sev_badge}'
            f'  </div>'
            f'  <div class="tile-score">{score_value:.0f}%</div>'
            f'  <div class="tile-counts">'
            f'    <span class="count-pass">{s.passed}P</span> '
            f'    <span class="count-fail">{s.failed}F</span> '
            f'    <span class="count-warn">{s.warnings}W</span> '
            f'    <span class="count-info">{s.info}I</span>'
            f'    {f"<span class=\"count-err\">{s.errors}E</span>" if s.errors else ""}'
            f'  </div>'
            f'  <div class="tile-total">{s.total} checks</div>'
            f'</a>'
        )
    rollup_tiles_html = '\n'.join(rollup_tiles)

    # ----------------------------------------------------------------
    # v3.7: Priority-driven executive summary
    # ----------------------------------------------------------------
    # The top 10 findings sorted by:
    #   1. Severity rank (Critical > High > Medium > Low > Informational)
    #   2. Status priority (Fail > Warning > Info)
    #   3. Module name (stable order for ties)
    # Each entry shows the severity badge, module, category, and message.
    # This sits ABOVE the per-module detail tables so report consumers
    # see the most important findings first without scanning everything.
    status_rank = {"Fail": 3, "Critical": 3, "Warning": 2, "Info": 1}
    priority_findings = []
    for idx, r in enumerate(all_results):
        if r.status == "Pass":
            continue
        sev_norm = (r.severity or "Medium").strip().capitalize()
        if sev_norm not in severity_rank:
            sev_norm = "Medium"
        priority_findings.append((
            -severity_rank.get(sev_norm, 0),
            -status_rank.get(r.status, 0),
            r.module,
            r.category,
            idx,  # tie-breaker (stable, hashable, orderable); never compared to objects
            r,
        ))
    priority_findings.sort()
    top_priority = priority_findings[:10]
    priority_rows = []
    if top_priority:
        for _, _, _, _, _, r in top_priority:
            sev_norm = (r.severity or "Medium").strip().capitalize()
            sev_class = f"prio-sev-{sev_norm.lower()}"
            status_class = f"prio-status-{r.status.lower()}"
            msg_truncated = r.message
            if len(msg_truncated) > 140:
                msg_truncated = msg_truncated[:137] + "..."
            priority_rows.append(
                f'<tr>'
                f'<td><span class="prio-sev {sev_class}">'
                f'{html.escape(sev_norm)}</span></td>'
                f'<td><span class="prio-status {status_class}">'
                f'{html.escape(r.status)}</span></td>'
                f'<td>{html.escape(r.module)}</td>'
                f'<td>{html.escape(r.category)}</td>'
                f'<td>{html.escape(msg_truncated)}</td>'
                f'</tr>'
            )
    priority_findings_html = '\n'.join(priority_rows)
    priority_findings_count = len(top_priority)

    # Table of contents entries
    toc_entries = []
    toc_entries.append('<a href="#dashboard">Executive Dashboard</a>')
    toc_entries.append('<a href="#compliance-matrix">Compliance Matrix</a>')
    toc_entries.append('<a href="#module-rollup">Module Summary</a>')
    toc_entries.append('<a href="#priority-findings">Top Priority Findings</a>')
    for mod_name in sorted(modules_data.keys()):
        safe_id = mod_name.lower().replace(' ', '-')
        toc_entries.append(f'<a href="#module-{safe_id}">{html.escape(mod_name)}</a>')
    if remediation_items:
        toc_entries.append('<a href="#remediation-priority">Remediation Priority</a>')
    toc_html = '\n'.join(toc_entries)

    # Remediation priority table rows
    remediation_rows = []
    for idx, r in enumerate(remediation_items[:50], 1):  # Top 50
        sev_class = r.severity.lower()
        status_class = r.status.lower()
        remediation_rows.append(
            f'<tr>'
            f'<td>{idx}</td>'
            f'<td><span class="severity-badge sev-{sev_class}">{html.escape(r.severity)}</span></td>'
            f'<td><span class="status status-{status_class}">{html.escape(r.status)}</span></td>'
            f'<td>{html.escape(r.module)}</td>'
            f'<td>{html.escape(r.message)}</td>'
            f'<td class="remediation-cmd">{html.escape(r.remediation)}</td>'
            f'</tr>'
        )
    remediation_table_html = '\n'.join(remediation_rows)

    # Overall compliance score display (Phase 3.5)
    overall_data = execution_info.compliance_scores.get('overall', {})
    o_weighted = overall_data.get('weighted_pct', 0)
    o_simple = overall_data.get('simple_pct', 0)
    o_severity = overall_data.get('severity_weighted_pct', 0)
    o_threshold = overall_data.get('threshold_result', 'N/A')
    o_color = '#28a745' if o_weighted >= 80 else '#fd7e14' if o_weighted >= 60 else '#dc3545'
    o_class = 'cpass' if o_weighted >= 80 else 'cwarn' if o_weighted >= 60 else 'cfail'
    t_badge_class = 'badge-pass' if o_threshold == 'PASS' else 'badge-fail'
    compliance_overview_html = (
        f'<div class="compliance-overview" id="compliance-overview">'
        f'<h3>Overall Compliance</h3>'
        f'<div class="compliance-metric {o_class}">'
        f'<div class="metric-value" style="color:{o_color}">{o_weighted:.1f}%</div>'
        f'<div class="metric-label">Weighted</div></div>'
        f'<div class="compliance-metric {o_class}">'
        f'<div class="metric-value" style="color:{o_color}">{o_simple:.1f}%</div>'
        f'<div class="metric-label">Simple</div></div>'
        f'<div class="compliance-metric {o_class}">'
        f'<div class="metric-value" style="color:{o_color}">{o_severity:.1f}%</div>'
        f'<div class="metric-label">Severity-Adj.</div></div>'
        f'<span class="compliance-threshold-badge {t_badge_class}">Threshold: {o_threshold}</span>'
        f'</div>'
    )

    # ----------------------------------------------------------------
    # Build module section HTML
    # ----------------------------------------------------------------
    module_sections = []
    for mod_name in sorted(modules_data.keys()):
        mod_results = modules_data[mod_name]
        stats = module_scores[mod_name]['stats']
        safe_id = mod_name.lower().replace(' ', '-')
        score = module_scores[mod_name]['score']

        # Category stats for this module
        cat_stats_html = ''
        if mod_name in category_stats:
            cat_rows = []
            for cat_name, cs in sorted(category_stats[mod_name].items()):
                cat_score = (cs['pass'] / (cs['total'] - cs['info']) * 100) if (cs['total'] - cs['info']) > 0 else 100
                cat_color = '#28a745' if cat_score >= 80 else '#fd7e14' if cat_score >= 60 else '#dc3545'
                cat_rows.append(
                    f'<div class="cat-stat-row">'
                    f'<span class="cat-name">{html.escape(cat_name)}</span>'
                    f'<span class="cat-counts">'
                    f'<span class="cat-p">{cs["pass"]}P</span> '
                    f'<span class="cat-f">{cs["fail"]}F</span> '
                    f'<span class="cat-w">{cs["warning"]}W</span>'
                    f'</span>'
                    f'<span class="cat-score" style="color:{cat_color}">{cat_score:.0f}%</span>'
                    f'</div>'
                )
            cat_stats_html = '<div class="category-stats">' + '\n'.join(cat_rows) + '</div>'

        # Table rows for this module
        result_rows = []
        for r in mod_results:
            status_class = f"status-{r.status.lower()}"
            sev_class = f"sev-{r.severity.lower()}" if r.severity else "sev-medium"
            finding_html = f'<strong>{html.escape(r.message)}</strong>'
            if r.details:
                finding_html += f'<div class="details">{html.escape(r.details)}</div>'
            if r.remediation:
                finding_html += f'<div class="remediation"><strong>REMEDIATION:</strong> {html.escape(r.remediation)}</div>'
            result_rows.append(
                f'<tr>'
                f'<td><input type="checkbox" class="row-checkbox"></td>'
                f'<td><span class="status {status_class}">{html.escape(r.status)}</span></td>'
                f'<td><span class="severity-badge {sev_class}">{html.escape(r.severity)}</span></td>'
                f'<td>{html.escape(r.category)}</td>'
                f'<td class="finding-cell">{finding_html}</td>'
                f'</tr>'
            )
        rows_html = '\n'.join(result_rows)

        module_sections.append(f'''
            <div class="module-section" id="module-{safe_id}">
                <div class="module-header" onclick="toggleModule(this)">
                    <div class="module-header-left">
                        <span class="collapse-icon">&#9660;</span>
                        <span class="module-name">{html.escape(mod_name)}</span>
                        <span class="module-score-badge" style="background:{'#28a745' if score >= 80 else '#fd7e14' if score >= 60 else '#dc3545'}">{score:.0f}%</span>
                    </div>
                    <span class="module-stats">P:{stats.passed} F:{stats.failed} W:{stats.warnings} I:{stats.info} E:{stats.errors} | Total:{stats.total}</span>
                </div>
                <div class="module-content">
                    {cat_stats_html}
                    <div class="module-controls">
                        <div class="col-visibility" id="colvis-{safe_id}"></div>
                    </div>
                    <div class="table-wrapper">
                        <table id="table-{safe_id}" class="audit-table" data-module="{html.escape(mod_name)}">
                            <thead>
                                <tr class="header-row">
                                    <th class="col-check" data-col="0"><input type="checkbox" class="select-all" onchange="toggleSelectAll(this)"></th>
                                    <th class="col-status resizable" data-col="1" onclick="sortTable(this)">Status<span class="resize-handle"></span></th>
                                    <th class="col-severity resizable" data-col="2" onclick="sortTable(this)">Severity<span class="resize-handle"></span></th>
                                    <th class="col-category resizable" data-col="3" onclick="sortTable(this)">Category<span class="resize-handle"></span></th>
                                    <th class="col-finding resizable" data-col="4" onclick="sortTable(this)">Finding<span class="resize-handle"></span></th>
                                </tr>
                                <tr class="filter-row">
                                    <td></td>
                                    <td><input type="text" class="col-filter" placeholder="Filter..." data-col="1" oninput="filterColumn(this)"></td>
                                    <td><input type="text" class="col-filter" placeholder="Filter..." data-col="2" oninput="filterColumn(this)"></td>
                                    <td><input type="text" class="col-filter" placeholder="Filter..." data-col="3" oninput="filterColumn(this)"></td>
                                    <td><input type="text" class="col-filter" placeholder="Filter..." data-col="4" oninput="filterColumn(this)"></td>
                                </tr>
                            </thead>
                            <tbody>
                                {rows_html}
                            </tbody>
                        </table>
                    </div>
                    <div class="module-export-bar">
                        <button class="export-btn" onclick='showExportModal("module", "table-{safe_id}")'>Export Module</button>
                        <button class="export-btn secondary" onclick='showExportModal("module-selected", "table-{safe_id}")'>Export Selected</button>
                    </div>
                </div>
            </div>
        ''')

    modules_html = '\n'.join(module_sections)

    # ----------------------------------------------------------------
    # Assemble complete HTML document
    # ----------------------------------------------------------------
    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report - {html.escape(execution_info.hostname)}</title>
    <style>
        /* ============================================================
           CSS RESET & VARIABLES
           3.2.16: Dark blue gradient for both themes
           3.2.18: Garamond as default font
           ============================================================ */
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        :root {{
            --bg-primary: #ffffff;
            --bg-secondary: #f4f6f9;
            --bg-tertiary: #e8ecf1;
            --text-primary: #1a1a2e;
            --text-secondary: #4a4a6a;
            --border-color: #d0d5dd;
            --card-shadow: rgba(0,0,0,0.08);
            --gradient-start: #0a1628;
            --gradient-mid: #162d50;
            --gradient-end: #1e3a5f;
            --accent: #2563eb;
            --accent-hover: #1d4ed8;
            --header-hover: #1e3a5f;
            --row-hover: #f0f4ff;
            --row-alt: #f8fafc;
        }}

        [data-theme="dark"] {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-tertiary: #334155;
            --text-primary: #e2e8f0;
            --text-secondary: #94a3b8;
            --border-color: #475569;
            --card-shadow: rgba(0,0,0,0.3);
            --gradient-start: #020617;
            --gradient-mid: #0f172a;
            --gradient-end: #1e293b;
            --accent: #3b82f6;
            --accent-hover: #60a5fa;
            --header-hover: #1e3a5f;
            --row-hover: #1e293b;
            --row-alt: #162032;
        }}

        /* ============================================================
           BASE STYLES
           ============================================================ */
        body {{
            font-family: Garamond, 'Times New Roman', Georgia, serif;
            background: var(--bg-secondary);
            color: var(--text-primary);
            line-height: 1.6;
            transition: background 0.3s, color 0.3s;
        }}

        input, button, select, textarea {{
            font-family: Garamond, 'Times New Roman', Georgia, serif;
        }}

        a {{ color: var(--accent); text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}

        /* ============================================================
           3.2.17: FULL-WIDTH HEADER/BANNER
           ============================================================ */
        .page-header {{
            background: linear-gradient(135deg, var(--gradient-start) 0%, var(--gradient-mid) 50%, var(--gradient-end) 100%);
            color: #ffffff;
            padding: 50px 40px 40px;
            text-align: center;
            width: 100%;
            position: relative;
        }}
        .page-header h1 {{
            font-size: 2.6em;
            font-weight: 700;
            letter-spacing: 1px;
            margin-bottom: 8px;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }}
        .page-header .subtitle {{
            font-size: 1.3em;
            opacity: 0.85;
            font-weight: 400;
        }}

        /* Theme toggle */
        .theme-toggle {{
            position: fixed;
            top: 16px;
            right: 16px;
            z-index: 9999;
            background: var(--bg-primary);
            border: 2px solid var(--border-color);
            border-radius: 25px;
            padding: 8px 18px;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.95em;
            color: var(--text-primary);
            box-shadow: 0 2px 8px var(--card-shadow);
            transition: all 0.3s;
        }}
        .theme-toggle:hover {{ background: var(--accent); color: #fff; }}

        /* ============================================================
           LAYOUT CONTAINER
           ============================================================ */
        .container {{
            max-width: 1500px;
            margin: 0 auto;
            padding: 0 20px 40px;
        }}

        /* ============================================================
           3.2.8: TABLE OF CONTENTS
           ============================================================ */
        .toc {{
            background: var(--bg-primary);
            border-radius: 10px;
            padding: 24px 30px;
            margin: 24px 0;
            box-shadow: 0 2px 12px var(--card-shadow);
        }}
        .toc h2 {{
            font-size: 1.3em;
            margin-bottom: 12px;
            color: var(--accent);
        }}
        .toc-links {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px 20px;
        }}
        .toc-links a {{
            padding: 6px 14px;
            background: var(--bg-secondary);
            border-radius: 6px;
            font-size: 0.95em;
            transition: all 0.2s;
        }}
        .toc-links a:hover {{
            background: var(--accent);
            color: #fff;
            text-decoration: none;
        }}

        /* ============================================================
           INFO CARDS ROW
           ============================================================ */
        .info-section {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin: 24px 0;
        }}
        .info-card {{
            background: var(--bg-primary);
            padding: 18px 20px;
            border-radius: 10px;
            box-shadow: 0 2px 8px var(--card-shadow);
            border-left: 4px solid var(--accent);
        }}
        .info-card h3 {{
            font-size: 0.8em;
            text-transform: uppercase;
            color: var(--text-secondary);
            letter-spacing: 0.5px;
            margin-bottom: 6px;
        }}
        .info-card p {{
            font-size: 1.1em;
            font-weight: 600;
        }}

        /* ============================================================
           3.2.1: EXECUTIVE DASHBOARD
           ============================================================ */
        .dashboard {{
            display: grid;
            grid-template-columns: 280px 1fr;
            gap: 24px;
            margin: 24px 0;
        }}
        .donut-container {{
            background: var(--bg-primary);
            border-radius: 10px;
            padding: 24px;
            box-shadow: 0 2px 12px var(--card-shadow);
            text-align: center;
        }}
        .donut-container h3 {{ margin-bottom: 16px; color: var(--accent); }}
        .donut-svg {{ margin: 0 auto; }}
        .donut-legend {{
            display: flex;
            flex-direction: column;
            gap: 6px;
            margin-top: 16px;
            font-size: 0.95em;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .legend-dot {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
            flex-shrink: 0;
        }}
        .dashboard-right {{
            display: flex;
            flex-direction: column;
            gap: 20px;
        }}

        /* Summary cards */
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
            gap: 12px;
        }}
        .summary-card {{
            text-align: center;
            padding: 18px 12px;
            border-radius: 10px;
            box-shadow: 0 2px 8px var(--card-shadow);
            transition: transform 0.2s;
        }}
        .summary-card:hover {{ transform: translateY(-2px); }}
        .summary-card h3 {{ font-size: 2.2em; margin-bottom: 4px; }}
        .summary-card p {{ font-size: 0.85em; text-transform: uppercase; font-weight: 600; opacity: 0.8; }}
        .sc-total {{ background: #dbeafe; border-left: 4px solid #2563eb; color: #1e40af; }}
        .sc-pass  {{ background: #d1fae5; border-left: 4px solid #28a745; color: #065f46; }}
        .sc-fail  {{ background: #fee2e2; border-left: 4px solid #dc3545; color: #991b1b; }}
        .sc-warn  {{ background: #ffedd5; border-left: 4px solid #fd7e14; color: #9a3412; }}
        .sc-info  {{ background: #cffafe; border-left: 4px solid #17a2b8; color: #155e75; }}
        .sc-err   {{ background: #ede9fe; border-left: 4px solid #6f42c1; color: #5b21b6; }}
        [data-theme="dark"] .sc-total {{ background: #1e3a5f; color: #93c5fd; }}
        [data-theme="dark"] .sc-pass  {{ background: #14532d; color: #86efac; }}
        [data-theme="dark"] .sc-fail  {{ background: #450a0a; color: #fca5a5; }}
        [data-theme="dark"] .sc-warn  {{ background: #431407; color: #fed7aa; }}
        [data-theme="dark"] .sc-info  {{ background: #164e63; color: #67e8f9; }}
        [data-theme="dark"] .sc-err   {{ background: #2e1065; color: #c4b5fd; }}

        /* 3.2.2: Module compliance bars */
        .compliance-bars {{
            background: var(--bg-primary);
            border-radius: 10px;
            padding: 20px 24px;
            box-shadow: 0 2px 12px var(--card-shadow);
        }}
        .compliance-bars h3 {{ margin-bottom: 14px; color: var(--accent); }}
        .bar-row {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }}
        .bar-label {{ width: 100px; font-size: 0.9em; font-weight: 600; text-align: right; }}
        .bar-track {{ flex: 1; height: 22px; background: var(--bg-tertiary); border-radius: 11px; overflow: hidden; }}
        .bar-fill {{ height: 100%; border-radius: 11px; transition: width 0.6s ease; min-width: 2px; }}
        .bar-value {{ width: 55px; font-size: 0.9em; font-weight: 700; }}

        /* ============================================================
           3.2.5: COMPLIANCE MATRIX
           ============================================================ */
        .matrix-section {{
            background: var(--bg-primary);
            border-radius: 10px;
            padding: 24px;
            margin: 24px 0;
            box-shadow: 0 2px 12px var(--card-shadow);
        }}
        .matrix-section h2 {{ margin-bottom: 16px; color: var(--accent); }}
        .matrix-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        .matrix-table th {{
            background: linear-gradient(135deg, var(--gradient-start), var(--gradient-end));
            color: #fff;
            padding: 10px 14px;
            text-align: center;
            font-size: 0.9em;
        }}
        .matrix-table th:first-child {{ text-align: left; }}
        .matrix-table td {{
            padding: 10px 14px;
            border-bottom: 1px solid var(--border-color);
            text-align: center;
            font-size: 0.95em;
        }}
        .matrix-table td:first-child {{ text-align: left; font-weight: 600; }}
        .matrix-table tr:hover {{ background: var(--row-hover); }}
        .matrix-pass {{ color: #28a745; font-weight: 600; }}
        .matrix-fail {{ color: #dc3545; font-weight: 600; }}
        .matrix-warn {{ color: #fd7e14; font-weight: 600; }}
        .matrix-info {{ color: #17a2b8; }}
        .matrix-err {{ color: #6f42c1; }}
        .matrix-threshold-pass {{ color: #28a745; font-weight: 700; font-size: 0.85em; }}
        .matrix-threshold-fail {{ color: #dc3545; font-weight: 700; font-size: 0.85em; }}

        /* Enhancement 1: Clickable dashboard filters */
        .clickable-filter {{ cursor: pointer; transition: all 0.2s; position: relative; }}
        .clickable-filter:hover {{ transform: translateY(-2px); box-shadow: 0 4px 16px var(--card-shadow); }}
        .clickable-filter.active-filter {{
            outline: 3px solid var(--accent); outline-offset: 2px;
            transform: translateY(-2px); box-shadow: 0 4px 16px rgba(37, 99, 235, 0.3);
        }}
        .clickable-filter.active-filter::after {{
            content: '\2715'; position: absolute; top: 4px; right: 8px;
            font-size: 0.7em; color: var(--accent); font-weight: 700;
        }}
        .legend-item.clickable-filter {{ padding: 4px 8px; border-radius: 4px; }}
        .legend-item.clickable-filter:hover {{ background: var(--bg-tertiary); }}
        .legend-item.clickable-filter.active-filter {{ background: var(--bg-tertiary); outline: 2px solid var(--accent); }}
        .legend-item.clickable-filter.active-filter::after {{ position: static; margin-left: 6px; }}
        svg circle[style*="cursor:pointer"]:hover {{ stroke-width: 24; filter: brightness(1.1); }}
        .filter-notification {{
            display: none; background: var(--accent); color: #fff;
            padding: 10px 20px; border-radius: 8px; margin: 16px 0;
            text-align: center; font-weight: 600; align-items: center;
            justify-content: center; gap: 12px;
        }}
        .filter-notification.visible {{ display: flex; }}
        .filter-notification button {{
            background: rgba(255,255,255,0.2); color: #fff;
            border: 1px solid rgba(255,255,255,0.4); border-radius: 4px;
            padding: 4px 12px; cursor: pointer; font-weight: 600;
        }}
        .filter-notification button:hover {{ background: rgba(255,255,255,0.3); }}

        /* Phase 3.5: Compliance score overview */
        .compliance-overview {{
            background: var(--bg-primary); border-radius: 10px; padding: 20px 24px;
            margin: 24px 0; box-shadow: 0 2px 12px var(--card-shadow);
            display: flex; flex-wrap: wrap; gap: 20px; align-items: center;
        }}
        .compliance-overview h3 {{ color: var(--accent); margin-right: 8px; }}
        .compliance-metric {{
            text-align: center; padding: 12px 20px; border-radius: 8px;
            background: var(--bg-secondary); min-width: 120px;
        }}
        .compliance-metric .metric-value {{ font-size: 1.8em; font-weight: 700; }}
        .compliance-metric .metric-label {{ font-size: 0.8em; text-transform: uppercase; color: var(--text-secondary); font-weight: 600; }}
        .compliance-metric.cpass {{ border-top: 3px solid #28a745; }}
        .compliance-metric.cwarn {{ border-top: 3px solid #fd7e14; }}
        .compliance-metric.cfail {{ border-top: 3px solid #dc3545; }}
        .compliance-threshold-badge {{
            display: inline-block; padding: 4px 12px; border-radius: 4px;
            font-weight: 700; font-size: 0.9em;
        }}
        .compliance-threshold-badge.badge-pass {{ background: #d1fae5; color: #065f46; }}
        .compliance-threshold-badge.badge-fail {{ background: #fee2e2; color: #991b1b; }}
        [data-theme="dark"] .compliance-threshold-badge.badge-pass {{ background: #14532d; color: #86efac; }}
        [data-theme="dark"] .compliance-threshold-badge.badge-fail {{ background: #450a0a; color: #fca5a5; }}

        /* ============================================================
           3.2.3: SEVERITY DISTRIBUTION
           ============================================================ */
        .severity-dist {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-bottom: 16px;
        }}
        .sev-card {{
            flex: 1;
            min-width: 100px;
            text-align: center;
            padding: 12px;
            border-radius: 8px;
            font-weight: 600;
        }}
        .sev-card.critical {{ background: #fee2e2; color: #991b1b; border-top: 3px solid #dc3545; }}
        .sev-card.high {{ background: #ffedd5; color: #9a3412; border-top: 3px solid #f97316; }}
        .sev-card.medium {{ background: #fef9c3; color: #854d0e; border-top: 3px solid #eab308; }}
        .sev-card.low {{ background: #d1fae5; color: #065f46; border-top: 3px solid #22c55e; }}
        .sev-card.informational {{ background: #dbeafe; color: #1e40af; border-top: 3px solid #3b82f6; }}
        [data-theme="dark"] .sev-card.critical {{ background: #450a0a; color: #fca5a5; }}
        [data-theme="dark"] .sev-card.high {{ background: #431407; color: #fed7aa; }}
        [data-theme="dark"] .sev-card.medium {{ background: #422006; color: #fde68a; }}
        [data-theme="dark"] .sev-card.low {{ background: #14532d; color: #86efac; }}
        [data-theme="dark"] .sev-card.informational {{ background: #1e3a5f; color: #93c5fd; }}
        .sev-card .sev-count {{ font-size: 1.8em; }}
        .sev-card .sev-label {{ font-size: 0.8em; text-transform: uppercase; }}

        /* ============================================================
           GLOBAL CONTROLS
           3.2.10: Global search with include/exclude
           ============================================================ */
        .global-controls {{
            background: var(--bg-primary);
            border-radius: 10px;
            padding: 20px 24px;
            margin: 24px 0;
            box-shadow: 0 2px 12px var(--card-shadow);
            display: flex;
            flex-wrap: wrap;
            gap: 16px;
            align-items: center;
        }}
        .global-controls h3 {{ margin-right: 8px; color: var(--accent); }}
        .search-group {{
            display: flex;
            gap: 8px;
            align-items: center;
            flex-wrap: wrap;
        }}
        .search-group input[type="text"] {{
            padding: 8px 14px;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            background: var(--bg-secondary);
            color: var(--text-primary);
            font-size: 0.95em;
            width: 260px;
        }}
        .search-group select {{
            padding: 8px 10px;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            background: var(--bg-secondary);
            color: var(--text-primary);
        }}
        .search-group button {{
            padding: 8px 14px;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            background: var(--bg-secondary);
            color: var(--text-primary);
            cursor: pointer;
        }}
        .search-group button:hover {{ background: var(--accent); color: #fff; }}
        .global-export-btns {{
            margin-left: auto;
            display: flex;
            gap: 8px;
        }}

        /* ============================================================
           MODULE SECTIONS
           3.2.15: Proper collapse/expand icons (Unicode chevrons)
           ============================================================ */
        .module-section {{
            margin-bottom: 20px;
            background: var(--bg-primary);
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 12px var(--card-shadow);
        }}
        .module-header {{
            background: linear-gradient(135deg, var(--gradient-start), var(--gradient-end));
            color: #fff;
            padding: 16px 24px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            user-select: none;
            transition: background 0.2s;
        }}
        .module-header:hover {{ background: linear-gradient(135deg, var(--gradient-mid), var(--gradient-end)); }}
        .module-header-left {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .collapse-icon {{
            font-size: 0.9em;
            transition: transform 0.3s;
            display: inline-block;
        }}
        .module-section.collapsed .collapse-icon {{
            transform: rotate(-90deg);
        }}
        .module-section.collapsed .module-content {{
            display: none;
        }}
        .module-name {{ font-size: 1.3em; font-weight: 700; }}
        .module-score-badge {{
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.8em;
            color: #fff;
            font-weight: 700;
        }}
        .module-stats {{
            font-size: 0.85em;
            opacity: 0.9;
        }}
        .module-content {{ padding: 20px 24px; }}

        /* 3.2.9: Category-level statistics */
        .category-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 8px;
            margin-bottom: 16px;
            padding: 12px;
            background: var(--bg-secondary);
            border-radius: 8px;
        }}
        .cat-stat-row {{
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 4px 8px;
            font-size: 0.88em;
        }}
        .cat-name {{ flex: 1; font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
        .cat-counts {{ font-size: 0.85em; color: var(--text-secondary); }}
        .cat-p {{ color: #28a745; }}
        .cat-f {{ color: #dc3545; }}
        .cat-w {{ color: #fd7e14; }}
        .cat-score {{ font-weight: 700; min-width: 36px; text-align: right; }}

        /* Module controls (column visibility) */
        .module-controls {{
            margin-bottom: 12px;
        }}
        .col-visibility {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            font-size: 0.88em;
        }}
        .col-visibility label {{
            display: flex;
            align-items: center;
            gap: 4px;
            cursor: pointer;
        }}

        /* ============================================================
           TABLE STYLES
           3.2.19: Column resizing
           3.2.20: In-column filtering
           ============================================================ */
        .table-wrapper {{
            overflow-x: auto;
        }}
        .audit-table {{
            width: 100%;
            border-collapse: collapse;
            table-layout: auto;
        }}
        .audit-table thead {{
            background: linear-gradient(135deg, var(--gradient-start), var(--gradient-end));
            color: #fff;
        }}
        .audit-table th {{
            padding: 10px 12px;
            text-align: left;
            font-weight: 600;
            cursor: pointer;
            user-select: none;
            position: relative;
            white-space: nowrap;
        }}
        .audit-table th:hover {{ background: rgba(255,255,255,0.1); }}
        .audit-table th.asc::after {{ content: ' \\25B2'; font-size: 0.7em; }}
        .audit-table th.desc::after {{ content: ' \\25BC'; font-size: 0.7em; }}
        .col-check {{ width: 40px; cursor: default; }}

        /* 3.2.19: Resize handle */
        .resize-handle {{
            position: absolute;
            right: 0;
            top: 0;
            bottom: 0;
            width: 5px;
            cursor: col-resize;
            background: transparent;
        }}
        .resize-handle:hover, .resize-handle.active {{
            background: rgba(255,255,255,0.3);
        }}

        /* 3.2.20: In-column filter inputs */
        .filter-row td {{
            padding: 4px 6px;
            background: var(--bg-tertiary);
        }}
        .col-filter {{
            width: 100%;
            padding: 6px 8px;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            background: var(--bg-primary);
            color: var(--text-primary);
            font-size: 0.88em;
        }}

        .audit-table td {{
            padding: 10px 12px;
            border-bottom: 1px solid var(--border-color);
            word-wrap: break-word;
            overflow-wrap: break-word;
            vertical-align: top;
        }}
        .audit-table tbody tr:nth-child(even) {{ background: var(--row-alt); }}
        .audit-table tbody tr:hover {{ background: var(--row-hover); }}

        /* Status badges */
        .status {{
            padding: 4px 10px;
            border-radius: 4px;
            font-weight: 700;
            text-transform: uppercase;
            font-size: 0.8em;
            display: inline-block;
            letter-spacing: 0.5px;
        }}
        .status-pass {{ background: #28a745; color: #fff; }}
        .status-fail {{ background: #dc3545; color: #fff; }}
        .status-warning {{ background: #fd7e14; color: #fff; }}
        .status-info {{ background: #17a2b8; color: #fff; }}
        .status-error {{ background: #6f42c1; color: #fff; }}

        /* Severity badges */
        .severity-badge {{
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.78em;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .sev-critical {{ background: #fee2e2; color: #991b1b; }}
        .sev-high {{ background: #ffedd5; color: #9a3412; }}
        .sev-medium {{ background: #fef9c3; color: #854d0e; }}
        .sev-low {{ background: #d1fae5; color: #065f46; }}
        .sev-informational {{ background: #dbeafe; color: #1e40af; }}
        [data-theme="dark"] .sev-critical {{ background: #450a0a; color: #fca5a5; }}
        [data-theme="dark"] .sev-high {{ background: #431407; color: #fed7aa; }}
        [data-theme="dark"] .sev-medium {{ background: #422006; color: #fde68a; }}
        [data-theme="dark"] .sev-low {{ background: #14532d; color: #86efac; }}
        [data-theme="dark"] .sev-informational {{ background: #1e3a5f; color: #93c5fd; }}

        /* Details and remediation blocks */
        .details {{
            margin-top: 6px;
            padding: 6px 10px;
            background: var(--bg-secondary);
            border-left: 3px solid var(--accent);
            font-size: 0.9em;
            color: var(--text-secondary);
        }}
        .remediation {{
            margin-top: 6px;
            padding: 6px 10px;
            background: #fffbeb;
            border-left: 3px solid #fd7e14;
            font-size: 0.9em;
            font-family: 'Courier New', monospace;
        }}
        [data-theme="dark"] .remediation {{
            background: #431407;
            color: #fed7aa;
        }}

        .finding-cell {{ min-width: 300px; }}

        /* Module export buttons */
        .module-export-bar {{
            margin-top: 14px;
            display: flex;
            gap: 8px;
        }}

        /* ============================================================
           3.2.6: REMEDIATION PRIORITY RANKING
           ============================================================ */
        .remediation-section {{
            background: var(--bg-primary);
            border-radius: 10px;
            padding: 24px;
            margin: 24px 0;
            box-shadow: 0 2px 12px var(--card-shadow);
        }}
        .remediation-section h2 {{ margin-bottom: 16px; color: var(--accent); }}
        .remediation-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.92em;
        }}
        .remediation-table th {{
            background: linear-gradient(135deg, var(--gradient-start), var(--gradient-end));
            color: #fff;
            padding: 10px 12px;
            text-align: left;
        }}
        .remediation-table td {{
            padding: 8px 12px;
            border-bottom: 1px solid var(--border-color);
            vertical-align: top;
        }}
        .remediation-table tr:hover {{ background: var(--row-hover); }}
        .remediation-cmd {{ font-family: 'Courier New', monospace; font-size: 0.88em; word-break: break-all; }}

        /* ============================================================
           BUTTONS
           ============================================================ */
        .export-btn {{
            padding: 8px 18px;
            background: var(--accent);
            color: #fff;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.92em;
            transition: all 0.2s;
        }}
        .export-btn:hover {{
            background: var(--accent-hover);
            transform: translateY(-1px);
            box-shadow: 0 2px 8px var(--card-shadow);
        }}
        .export-btn.secondary {{
            background: #6b7280;
        }}
        .export-btn.secondary:hover {{
            background: #4b5563;
        }}

        /* ============================================================
           MODAL
           ============================================================ */
        .modal {{
            display: none;
            position: fixed;
            z-index: 10000;
            left: 0; top: 0;
            width: 100%; height: 100%;
            background: rgba(0,0,0,0.5);
            backdrop-filter: blur(2px);
        }}
        .modal-content {{
            background: var(--bg-primary);
            margin: 12% auto;
            padding: 30px;
            border-radius: 12px;
            width: 90%;
            max-width: 460px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.4);
        }}
        .modal-header {{
            font-size: 1.4em;
            font-weight: 700;
            margin-bottom: 18px;
        }}
        .format-option {{
            padding: 14px 18px;
            margin: 8px 0;
            background: var(--bg-secondary);
            border: 2px solid var(--border-color);
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.2s;
            color: var(--text-primary);
        }}
        .format-option:hover {{
            background: var(--accent);
            color: #fff;
            border-color: var(--accent);
        }}
        .modal-close {{
            float: right;
            font-size: 24px;
            cursor: pointer;
            color: var(--text-secondary);
            line-height: 1;
        }}
        .modal-close:hover {{ color: var(--text-primary); }}

        /* ============================================================
           FOOTER
           ============================================================ */
        .footer {{
            background: var(--bg-primary);
            padding: 20px;
            text-align: center;
            color: var(--text-secondary);
            border-top: 2px solid var(--border-color);
            margin-top: 40px;
            border-radius: 0 0 10px 10px;
        }}

        /* ============================================================
           3.2.7: PRINT-FRIENDLY CSS
           ============================================================ */
        @media print {{
            body {{ background: #fff; color: #000; font-size: 10pt; }}
            .theme-toggle, .global-controls, .module-export-bar,
            .global-export-btns, .filter-row, .col-filter,
            .module-controls, .resize-handle, .modal {{ display: none !important; }}
            .page-header {{
                background: #1e3a5f !important;
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }}
            .module-section {{ page-break-inside: avoid; break-inside: avoid; }}
            .module-section.collapsed .module-content {{ display: block !important; }}
            .audit-table {{ font-size: 9pt; }}
            .summary-card, .sev-card {{
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }}
            .status, .severity-badge {{
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }}
        }}

        /* ============================================================
           RESPONSIVE
           ============================================================ */
        @media (max-width: 900px) {{
            .dashboard {{ grid-template-columns: 1fr; }}
            .module-header {{ flex-direction: column; gap: 8px; }}
        }}

        /* ============================================================
           v3.7 PER-MODULE SUMMARY TILES + PRIORITY FINDINGS
           ============================================================ */

        /* Section wrappers - same visual weight as matrix-section */
        .rollup-section, .priority-section {{
            margin: 24px 0;
            padding: 18px;
            background: var(--card-bg);
            border-radius: 10px;
            border: 1px solid var(--border);
            box-shadow: 0 2px 6px rgba(0,0,0,0.08);
        }}
        .rollup-section h2, .priority-section h2 {{
            margin: 0 0 14px 0;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--accent);
            color: var(--accent);
            font-size: 1.25em;
        }}

        /* Tile grid */
        .rollup-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 12px;
        }}
        .rollup-tile {{
            display: block;
            text-decoration: none;
            color: inherit;
            padding: 12px 14px;
            border-radius: 8px;
            border: 1px solid var(--border);
            background: var(--bg);
            transition: transform 0.1s, box-shadow 0.15s;
            position: relative;
        }}
        .rollup-tile:hover {{
            transform: translateY(-1px);
            box-shadow: 0 4px 10px rgba(0,0,0,0.15);
        }}
        .rollup-tile.tile-health-green   {{ border-left: 5px solid #2e7d32; }}
        .rollup-tile.tile-health-yellow  {{ border-left: 5px solid #fbc02d; }}
        .rollup-tile.tile-health-orange  {{ border-left: 5px solid #ef6c00; }}
        .rollup-tile.tile-health-red     {{ border-left: 5px solid #c62828; }}

        .tile-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 6px;
        }}
        .tile-name {{
            font-weight: 700;
            font-size: 0.95em;
        }}
        .tile-sev {{
            font-size: 0.72em;
            padding: 1px 6px;
            border-radius: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .tile-sev-critical      {{ background: #c62828; color: white; }}
        .tile-sev-high          {{ background: #ef6c00; color: white; }}
        .tile-sev-medium        {{ background: #fbc02d; color: #333; }}
        .tile-sev-low           {{ background: #66bb6a; color: white; }}
        .tile-sev-informational {{ background: #90a4ae; color: white; }}

        .tile-score {{
            font-size: 1.85em;
            font-weight: 800;
            line-height: 1.0;
            margin: 4px 0;
            color: var(--accent);
        }}
        .tile-counts {{
            font-size: 0.82em;
            font-family: 'Courier New', monospace;
            margin: 4px 0;
        }}
        .tile-counts .count-pass {{ color: #2e7d32; font-weight: 700; }}
        .tile-counts .count-fail {{ color: #c62828; font-weight: 700; }}
        .tile-counts .count-warn {{ color: #ef6c00; font-weight: 700; }}
        .tile-counts .count-info {{ color: #1565c0; font-weight: 700; }}
        .tile-counts .count-err  {{ color: #6a1b9a; font-weight: 700; }}
        .tile-total {{
            font-size: 0.78em;
            color: var(--text-muted, #666);
            margin-top: 2px;
        }}

        /* Priority findings table */
        .priority-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.93em;
        }}
        .priority-table th {{
            background: var(--accent);
            color: white;
            padding: 8px 10px;
            text-align: left;
            font-weight: 700;
        }}
        .priority-table td {{
            padding: 7px 10px;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }}
        .priority-table tr:hover td {{
            background: rgba(0, 0, 0, 0.02);
        }}
        .prio-sev, .prio-status {{
            font-size: 0.78em;
            padding: 2px 8px;
            border-radius: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            white-space: nowrap;
        }}
        .prio-sev-critical      {{ background: #c62828; color: white; }}
        .prio-sev-high          {{ background: #ef6c00; color: white; }}
        .prio-sev-medium        {{ background: #fbc02d; color: #333; }}
        .prio-sev-low           {{ background: #66bb6a; color: white; }}
        .prio-sev-informational {{ background: #90a4ae; color: white; }}
        .prio-status-fail       {{ background: #c62828; color: white; }}
        .prio-status-warning    {{ background: #ef6c00; color: white; }}
        .prio-status-info       {{ background: #1565c0; color: white; }}
        .prio-status-error      {{ background: #6a1b9a; color: white; }}

        .priority-empty {{
            font-style: italic;
            color: var(--text-muted, #666);
            text-align: center;
            padding: 20px;
        }}
    </style>
</head>
<body>
    <button class="theme-toggle" onclick="toggleTheme()" title="Toggle dark/light mode">&#9790; Theme</button>

    <!-- 3.2.17: Full-width header -->
    <div class="page-header">
        <h1>Linux Security Audit Report</h1>
        <div class="subtitle">{subtitle}</div>
    </div>

    <div class="container">

        <!-- 3.2.8: Table of Contents -->
        <div class="toc">
            <h2>Table of Contents</h2>
            <div class="toc-links">
                {toc_html}
            </div>
        </div>

        <!-- System Info (Enhancement 2: IP Address identification) -->
        <div class="info-section">
            <div class="info-card"><h3>Hostname</h3><p>{html.escape(execution_info.hostname)}</p></div>
            <div class="info-card"><h3>IP Address(es)</h3><p>{html.escape(', '.join(execution_info.ip_addresses))}</p></div>
            <div class="info-card"><h3>Operating System</h3><p>{html.escape(execution_info.os_version)}</p></div>
            <div class="info-card"><h3>Scan Date</h3><p>{html.escape(execution_info.scan_date)}</p></div>
            <div class="info-card"><h3>Duration</h3><p>{html.escape(execution_info.duration)}</p></div>
            <div class="info-card"><h3>Total Checks</h3><p>{execution_info.total_checks}</p></div>
            <div class="info-card"><h3>Modules</h3><p>{html.escape(', '.join(execution_info.modules_run))}</p></div>
        </div>

        <!-- 3.2.1: Executive Dashboard -->
        <div class="dashboard" id="dashboard">
            <div class="donut-container">
                <h3>Result Distribution</h3>
                <svg class="donut-svg" width="120" height="120" viewBox="0 0 120 120">
                    {donut_svg}
                    <text x="60" y="56" text-anchor="middle" font-size="22" font-weight="700" fill="var(--text-primary)">{execution_info.total_checks}</text>
                    <text x="60" y="72" text-anchor="middle" font-size="10" fill="var(--text-secondary)">TOTAL</text>
                </svg>
                <div class="donut-legend">
                    {donut_legend_html}
                </div>
            </div>
            <div class="dashboard-right">
                <!-- Summary cards - clickable for filtering (Enhancement 1) -->
                <div class="summary-grid">
                    <div class="summary-card sc-total clickable-filter" onclick="dashboardFilter('status','all')" data-filter-value="all"><h3>{execution_info.total_checks}</h3><p>Total</p></div>
                    <div class="summary-card sc-pass clickable-filter" onclick="dashboardFilter('status','Pass')" data-filter-value="Pass"><h3>{execution_info.pass_count}</h3><p>Passed</p></div>
                    <div class="summary-card sc-fail clickable-filter" onclick="dashboardFilter('status','Fail')" data-filter-value="Fail"><h3>{execution_info.fail_count}</h3><p>Failed</p></div>
                    <div class="summary-card sc-warn clickable-filter" onclick="dashboardFilter('status','Warning')" data-filter-value="Warning"><h3>{execution_info.warning_count}</h3><p>Warnings</p></div>
                    <div class="summary-card sc-info clickable-filter" onclick="dashboardFilter('status','Info')" data-filter-value="Info"><h3>{execution_info.info_count}</h3><p>Info</p></div>
                    <div class="summary-card sc-err clickable-filter" onclick="dashboardFilter('status','Error')" data-filter-value="Error"><h3>{execution_info.error_count}</h3><p>Errors</p></div>
                </div>
                <!-- 3.2.3: Severity distribution - clickable for filtering (Enhancement 1) -->
                <div class="severity-dist">
                    <div class="sev-card critical clickable-filter" onclick="dashboardFilter('severity','Critical')" data-filter-value="Critical"><div class="sev-count">{severity_counts['Critical']}</div><div class="sev-label">Critical</div></div>
                    <div class="sev-card high clickable-filter" onclick="dashboardFilter('severity','High')" data-filter-value="High"><div class="sev-count">{severity_counts['High']}</div><div class="sev-label">High</div></div>
                    <div class="sev-card medium clickable-filter" onclick="dashboardFilter('severity','Medium')" data-filter-value="Medium"><div class="sev-count">{severity_counts['Medium']}</div><div class="sev-label">Medium</div></div>
                    <div class="sev-card low clickable-filter" onclick="dashboardFilter('severity','Low')" data-filter-value="Low"><div class="sev-count">{severity_counts['Low']}</div><div class="sev-label">Low</div></div>
                    <div class="sev-card informational clickable-filter" onclick="dashboardFilter('severity','Informational')" data-filter-value="Informational"><div class="sev-count">{severity_counts['Informational']}</div><div class="sev-label">Informational</div></div>
                </div>
                <!-- 3.2.2: Module compliance bars -->
                <div class="compliance-bars">
                    <h3>Module Compliance Scores</h3>
                    {module_bars_html}
                </div>
            </div>
        </div>

        <!-- 3.2.5: Cross-framework Compliance Matrix -->
        <div class="matrix-section" id="compliance-matrix">
            <h2>Cross-Framework Compliance Matrix</h2>
            <table class="matrix-table">
                <thead>
                    <tr>
                        <th>Framework</th><th>Total</th><th>Pass</th><th>Fail</th>
                        <th>Warning</th><th>Info</th><th>Error</th><th>Score</th>
                    </tr>
                </thead>
                <tbody>
                    {matrix_html}
                </tbody>
            </table>
        </div>

        <!-- v3.7: Per-module Summary Tiles (rollup metrics) -->
        <div class="rollup-section" id="module-rollup">
            <h2>Module Summary (At-a-Glance)</h2>
            <div class="rollup-grid">
                {rollup_tiles_html}
            </div>
        </div>

        <!-- v3.7: Priority-Driven Top Findings -->
        <div class="priority-section" id="priority-findings">
            <h2>Top Priority Findings ({priority_findings_count})</h2>
            {f'<table class="priority-table"><thead><tr><th>Severity</th><th>Status</th><th>Module</th><th>Category</th><th>Finding</th></tr></thead><tbody>{priority_findings_html}</tbody></table>' if priority_findings_count > 0 else '<div class="priority-empty">No non-Pass findings &#x2014; all checks succeeded.</div>'}
        </div>

        <!-- Phase 3.5: Overall Compliance Score -->
        {compliance_overview_html}

        <!-- Enhancement 1: Dashboard filter notification -->
        <div class="filter-notification" id="filterNotification">
            <span id="filterNotificationText">Filtered by: &#8212;</span>
            <button onclick="clearDashboardFilter()">Clear Filter</button>
        </div>

        <!-- 3.2.10: Global controls -->
        <div class="global-controls">
            <h3>Search &amp; Export</h3>
            <div class="search-group">
                <input type="text" id="globalSearch" placeholder="Search all results..." oninput="globalFilter()">
                <select id="globalSearchMode" onchange="globalFilter()">
                    <option value="include">Include matches</option>
                    <option value="exclude">Exclude matches</option>
                </select>
                <button onclick="clearGlobalSearch()">Clear</button>
            </div>
            <div class="global-export-btns">
                <button class="export-btn" onclick='showExportModal("all")'>Export All</button>
                <button class="export-btn secondary" onclick='showExportModal("selected")'>Export Selected</button>
            </div>
        </div>

        <!-- Module Sections -->
        {modules_html}

        <!-- 3.2.6: Remediation Priority Ranking -->
        {"" if not remediation_items else f"""
        <div class="remediation-section" id="remediation-priority">
            <h2>Remediation Priority Ranking (Top {min(len(remediation_items), 50)})</h2>
            <table class="remediation-table">
                <thead>
                    <tr><th>#</th><th>Severity</th><th>Status</th><th>Module</th><th>Finding</th><th>Remediation</th></tr>
                </thead>
                <tbody>
                    {remediation_table_html}
                </tbody>
            </table>
        </div>
        """}

        <!-- Footer -->
        <div class="footer">
            Generated by Linux Security Audit Script v{SCRIPT_VERSION} |
            <a href="https://github.com/Sandler73/Linux-Security-Audit-Project.git">GitHub Repository</a>
        </div>

    </div>

    <!-- Export Modal -->
    <div id="exportModal" class="modal">
        <div class="modal-content">
            <span class="modal-close" onclick="closeExportModal()">&times;</span>
            <div class="modal-header">Select Export Format</div>
            <div class="format-option" onclick='executeExport("csv")'>CSV (Comma-Separated Values)</div>
            <div class="format-option" onclick='executeExport("excel")'>Excel (XLS)</div>
            <div class="format-option" onclick='executeExport("json")'>JSON (Structured Data)</div>
            <div class="format-option" onclick='executeExport("xml")'>XML (SIEM-Compatible)</div>
            <div class="format-option" onclick='executeExport("txt")'>TXT (Plain Text)</div>
        </div>
    </div>

    <script>
        /* ==============================================================
           THEME MANAGEMENT
           ============================================================== */
        function toggleTheme() {{
            const el = document.documentElement;
            const next = el.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
            el.setAttribute('data-theme', next);
            try {{ localStorage.setItem('audit-theme', next); }} catch(e) {{}}
        }}
        document.addEventListener('DOMContentLoaded', () => {{
            try {{
                const saved = localStorage.getItem('audit-theme');
                if (saved) document.documentElement.setAttribute('data-theme', saved);
            }} catch(e) {{}}
            initColumnVisibility();
            initResizeHandles();
        }});

        /* ==============================================================
           3.2.15: MODULE COLLAPSE/EXPAND (proper icons)
           ============================================================== */
        function toggleModule(header) {{
            header.closest('.module-section').classList.toggle('collapsed');
        }}

        /* ==============================================================
           ROW SELECTION
           ============================================================== */
        function toggleSelectAll(cb) {{
            const table = cb.closest('table');
            table.querySelectorAll('tbody .row-checkbox').forEach(c => c.checked = cb.checked);
        }}

        /* ==============================================================
           TABLE SORTING
           ============================================================== */
        function sortTable(th) {{
            if (th.classList.contains('col-check')) return;
            const table = th.closest('table');
            const tbody = table.querySelector('tbody');
            const colIndex = parseInt(th.dataset.col);
            const rows = Array.from(tbody.querySelectorAll('tr'));
            const isAsc = th.classList.contains('asc');

            // Clear sort indicators on sibling headers
            th.closest('tr').querySelectorAll('th').forEach(h => h.classList.remove('asc', 'desc'));
            th.classList.add(isAsc ? 'desc' : 'asc');

            rows.sort((a, b) => {{
                const aText = (a.cells[colIndex]?.textContent || '').trim();
                const bText = (b.cells[colIndex]?.textContent || '').trim();
                return isAsc ? bText.localeCompare(aText) : aText.localeCompare(bText);
            }});
            rows.forEach(row => tbody.appendChild(row));
        }}

        /* ==============================================================
           3.2.20: IN-COLUMN FILTERING
           ============================================================== */
        function filterColumn(input) {{
            const table = input.closest('table');
            const colIndex = parseInt(input.dataset.col);
            const value = input.value.toLowerCase();
            applyAllFilters(table);
        }}

        function applyAllFilters(table) {{
            const filters = {{}};
            table.querySelectorAll('.col-filter').forEach(inp => {{
                const col = parseInt(inp.dataset.col);
                const val = inp.value.toLowerCase().trim();
                if (val) filters[col] = val;
            }});
            table.querySelectorAll('tbody tr').forEach(row => {{
                let show = true;
                for (const [col, val] of Object.entries(filters)) {{
                    const cellText = (row.cells[col]?.textContent || '').toLowerCase();
                    if (!cellText.includes(val)) {{ show = false; break; }}
                }}
                // Also respect global filter
                if (show && window._globalFilterActive) {{
                    const gval = window._globalFilterValue;
                    const mode = window._globalFilterMode;
                    if (gval) {{
                        const rowText = row.textContent.toLowerCase();
                        const match = rowText.includes(gval);
                        show = mode === 'include' ? match : !match;
                    }}
                }}
                // Also respect dashboard filter (Enhancement 1)
                if (show && window._dashFilterType && window._dashFilterValue) {{
                    const colIdx = window._dashFilterType === 'status' ? 1 : 2;
                    const cellText = (row.cells[colIdx]?.textContent || '').trim();
                    if (cellText !== window._dashFilterValue) show = false;
                }}
                row.style.display = show ? '' : 'none';
            }});
        }}

        /* ==============================================================
           3.2.10: GLOBAL SEARCH / FILTER
           ============================================================== */
        window._globalFilterActive = false;
        window._globalFilterValue = '';
        window._globalFilterMode = 'include';

        function globalFilter() {{
            const val = document.getElementById('globalSearch').value.toLowerCase().trim();
            const mode = document.getElementById('globalSearchMode').value;
            window._globalFilterActive = !!val;
            window._globalFilterValue = val;
            window._globalFilterMode = mode;
            // Re-apply all table filters
            document.querySelectorAll('.audit-table').forEach(t => applyAllFilters(t));
        }}
        function clearGlobalSearch() {{
            document.getElementById('globalSearch').value = '';
            window._globalFilterActive = false;
            window._globalFilterValue = '';
            document.querySelectorAll('.audit-table').forEach(t => applyAllFilters(t));
        }}

        /* ==============================================================
           ENHANCEMENT 1: DASHBOARD FILTER (donut/cards/severity)
           ============================================================== */
        // Track current dashboard filter state
        window._dashFilterType = null;  // 'status' or 'severity'
        window._dashFilterValue = null; // e.g. 'Pass', 'Critical'

        function dashboardFilter(filterType, filterValue) {{
            // Toggle behavior: click same filter again to deselect
            if (window._dashFilterType === filterType && window._dashFilterValue === filterValue) {{
                clearDashboardFilter();
                return;
            }}
            // 'all' = clear filter
            if (filterValue === 'all') {{
                clearDashboardFilter();
                return;
            }}
            window._dashFilterType = filterType;
            window._dashFilterValue = filterValue;

            // Update active states on all clickable elements
            document.querySelectorAll('.clickable-filter').forEach(el => {{
                el.classList.remove('active-filter');
            }});
            // Highlight matching elements
            document.querySelectorAll('.clickable-filter').forEach(el => {{
                if (el.dataset.filterValue === filterValue) {{
                    el.classList.add('active-filter');
                }}
            }});
            // Highlight matching donut segment
            document.querySelectorAll('svg circle[data-filter-value]').forEach(c => {{
                if (c.dataset.filterValue === filterValue) {{
                    c.setAttribute('stroke-width', '24');
                }} else {{
                    c.setAttribute('stroke-width', '20');
                }}
            }});

            // Show notification bar
            const notif = document.getElementById('filterNotification');
            document.getElementById('filterNotificationText').textContent =
                'Filtered by ' + filterType + ': ' + filterValue;
            notif.classList.add('visible');

            // Apply filter across ALL module tables
            // Status column = index 1, Severity column = index 2
            const colIdx = filterType === 'status' ? 1 : 2;
            document.querySelectorAll('.audit-table').forEach(table => {{
                table.querySelectorAll('tbody tr').forEach(row => {{
                    const cellText = (row.cells[colIdx]?.textContent || '').trim();
                    row.style.display = cellText === filterValue ? '' : 'none';
                }});
            }});
        }}

        function clearDashboardFilter() {{
            window._dashFilterType = null;
            window._dashFilterValue = null;
            // Remove all active states
            document.querySelectorAll('.clickable-filter').forEach(el => {{
                el.classList.remove('active-filter');
            }});
            // Reset donut segment widths
            document.querySelectorAll('svg circle[data-filter-value]').forEach(c => {{
                c.setAttribute('stroke-width', '20');
            }});
            // Hide notification
            document.getElementById('filterNotification').classList.remove('visible');
            // Show all rows and re-apply column/global filters
            document.querySelectorAll('.audit-table').forEach(table => {{
                table.querySelectorAll('tbody tr').forEach(row => {{
                    row.style.display = '';
                }});
                applyAllFilters(table);
            }});
        }}

        /* ==============================================================
           3.2.11: COLUMN VISIBILITY
           ============================================================== */
        function initColumnVisibility() {{
            document.querySelectorAll('.audit-table').forEach(table => {{
                const section = table.closest('.module-section');
                const safeId = section.id.replace('module-', '');
                const container = document.getElementById('colvis-' + safeId);
                if (!container) return;
                const headers = table.querySelectorAll('.header-row th');
                const colNames = ['Select', 'Status', 'Severity', 'Category', 'Finding'];
                headers.forEach((th, i) => {{
                    if (i === 0) return; // skip checkbox column
                    const lbl = document.createElement('label');
                    const cb = document.createElement('input');
                    cb.type = 'checkbox';
                    cb.checked = true;
                    cb.addEventListener('change', () => toggleColumnVisibility(table, i, cb.checked));
                    lbl.appendChild(cb);
                    lbl.append(' ' + (colNames[i] || 'Col ' + i));
                    container.appendChild(lbl);
                }});
            }});
        }}
        function toggleColumnVisibility(table, colIndex, visible) {{
            table.querySelectorAll('tr').forEach(row => {{
                if (row.cells[colIndex]) {{
                    row.cells[colIndex].style.display = visible ? '' : 'none';
                }}
            }});
        }}

        /* ==============================================================
           3.2.19: COLUMN RESIZING
           ============================================================== */
        function initResizeHandles() {{
            document.querySelectorAll('.resize-handle').forEach(handle => {{
                handle.addEventListener('mousedown', (e) => {{
                    e.preventDefault();
                    e.stopPropagation();
                    const th = handle.parentElement;
                    const startX = e.clientX;
                    const startWidth = th.offsetWidth;
                    handle.classList.add('active');

                    function onMove(ev) {{
                        const newWidth = Math.max(60, startWidth + (ev.clientX - startX));
                        th.style.width = newWidth + 'px';
                        th.style.minWidth = newWidth + 'px';
                    }}
                    function onUp() {{
                        handle.classList.remove('active');
                        document.removeEventListener('mousemove', onMove);
                        document.removeEventListener('mouseup', onUp);
                    }}
                    document.addEventListener('mousemove', onMove);
                    document.addEventListener('mouseup', onUp);
                }});
            }});
        }}

        /* ==============================================================
           EXPORT FUNCTIONS
           ============================================================== */
        let currentExportMode = null;
        let currentTableId = null;

        function showExportModal(mode, tableId) {{
            currentExportMode = mode;
            currentTableId = tableId || null;
            document.getElementById('exportModal').style.display = 'block';
        }}
        function closeExportModal() {{
            document.getElementById('exportModal').style.display = 'none';
        }}
        function executeExport(format) {{
            switch(currentExportMode) {{
                case 'all': exportAll(format); break;
                case 'selected': exportSelected(format); break;
                case 'module': exportModule(currentTableId, format); break;
                case 'module-selected': exportModuleSelected(currentTableId, format); break;
            }}
            closeExportModal();
        }}

        function getCellText(cell) {{
            let text = '';
            const strong = cell.querySelector('strong');
            if (strong) text += strong.textContent.trim() + '\\n';
            const det = cell.querySelector('.details');
            if (det) text += 'Details: ' + det.textContent.trim() + '\\n';
            const rem = cell.querySelector('.remediation');
            if (rem) text += rem.textContent.trim() + '\\n';
            return text.trim() || cell.textContent.trim();
        }}

        function getTableData(tableId, selectedOnly) {{
            const table = document.getElementById(tableId);
            if (!table) return null;
            const moduleName = table.dataset.module || tableId;
            const headers = ['Status', 'Severity', 'Category', 'Finding'];
            let rows;
            if (selectedOnly) {{
                const sel = table.querySelectorAll('tbody .row-checkbox:checked');
                rows = Array.from(sel).map(cb => cb.closest('tr'));
            }} else {{
                rows = Array.from(table.querySelectorAll('tbody tr')).filter(r => r.style.display !== 'none');
            }}
            const data = rows.map(row => {{
                const cells = Array.from(row.cells).slice(1); // skip checkbox
                return cells.map((cell, i) => {{
                    if (i === 0) return cell.querySelector('.status')?.textContent?.trim() || cell.textContent.trim();
                    if (i === 1) return cell.querySelector('.severity-badge')?.textContent?.trim() || cell.textContent.trim();
                    if (i === 3) return getCellText(cell);
                    return cell.textContent.trim();
                }});
            }});
            return {{ moduleName, headers, data }};
        }}

        function exportModule(tableId, format) {{
            const td = getTableData(tableId, false);
            if (td) exportData([td], td.moduleName + '-Report', format);
        }}
        function exportModuleSelected(tableId, format) {{
            const td = getTableData(tableId, true);
            if (!td || td.data.length === 0) {{ alert('No rows selected'); return; }}
            exportData([td], td.moduleName + '-Selected', format);
        }}
        function exportAll(format) {{
            const all = [];
            document.querySelectorAll('.audit-table').forEach(t => {{
                const td = getTableData(t.id, false);
                if (td && td.data.length > 0) all.push(td);
            }});
            if (all.length === 0) {{ alert('No data to export'); return; }}
            exportData(all, 'Full-Security-Audit-Report', format);
        }}
        function exportSelected(format) {{
            const all = [];
            document.querySelectorAll('.audit-table').forEach(t => {{
                const td = getTableData(t.id, true);
                if (td && td.data.length > 0) all.push(td);
            }});
            if (all.length === 0) {{ alert('No rows selected'); return; }}
            exportData(all, 'Selected-Security-Audit-Report', format);
        }}

        function exportData(moduleDataArray, filename, format) {{
            switch(format) {{
                case 'csv':   exportToCSV(moduleDataArray, filename + '.csv'); break;
                case 'excel': exportToExcel(moduleDataArray, filename + '.xls'); break;
                case 'json':  exportToJSON(moduleDataArray, filename + '.json'); break;
                case 'xml':   exportToXML(moduleDataArray, filename + '.xml'); break;
                case 'txt':   exportToTXT(moduleDataArray, filename + '.txt'); break;
            }}
        }}

        function exportToCSV(mda, fn) {{
            let csv = '';
            mda.forEach((m, i) => {{
                if (i > 0) csv += '\\r\\n\\r\\n';
                csv += '=== ' + m.moduleName + ' ===\\r\\n';
                csv += m.headers.map(h => '"' + h.replace(/"/g, '""') + '"').join(',') + '\\r\\n';
                m.data.forEach(row => {{
                    csv += row.map(c => '"' + (c||'').replace(/"/g, '""').replace(/\\r?\\n/g, ' ') + '"').join(',') + '\\r\\n';
                }});
            }});
            downloadFile(csv, fn, 'text/csv;charset=utf-8;');
        }}

        function exportToExcel(mda, fn) {{
            let h = '<html><head><meta charset="utf-8"></head><body>';
            mda.forEach(m => {{
                h += '<table><tr><td colspan="' + m.headers.length + '" style="font-weight:bold;font-size:14pt;background:#1e3a5f;color:white;padding:10px;">' + esc(m.moduleName) + '</td></tr>';
                h += '<tr>' + m.headers.map(hd => '<th style="background:#2563eb;color:white;padding:8px;">' + esc(hd) + '</th>').join('') + '</tr>';
                m.data.forEach(row => {{
                    h += '<tr>' + row.map(c => '<td style="padding:5px;border:1px solid #ddd;white-space:pre-wrap;">' + esc(c||'') + '</td>').join('') + '</tr>';
                }});
                h += '</table><br>';
            }});
            h += '</body></html>';
            downloadFile(h, fn, 'application/vnd.ms-excel');
        }}

        function exportToJSON(mda, fn) {{
            const obj = {{
                exportDate: new Date().toISOString(),
                modules: mda.map(m => ({{
                    moduleName: m.moduleName,
                    headers: m.headers,
                    results: m.data.map(row => {{
                        const o = {{}};
                        m.headers.forEach((hd, i) => o[hd] = row[i] || '');
                        return o;
                    }})
                }}))
            }};
            downloadFile(JSON.stringify(obj, null, 2), fn, 'application/json');
        }}

        function exportToXML(mda, fn) {{
            let x = '<?xml version="1.0" encoding="UTF-8"?>\\r\\n<security_audit>\\r\\n';
            x += '  <metadata><export_date>' + new Date().toISOString() + '</export_date>';
            x += '<total_modules>' + mda.length + '</total_modules></metadata>\\r\\n  <events>\\r\\n';
            mda.forEach(m => {{
                m.data.forEach(row => {{
                    x += '    <event><module>' + escXml(m.moduleName) + '</module>';
                    m.headers.forEach((hd, i) => {{
                        const tag = hd.replace(/\\s+/g, '_').toLowerCase();
                        x += '<' + tag + '>' + escXml(row[i]||'') + '</' + tag + '>';
                    }});
                    x += '</event>\\r\\n';
                }});
            }});
            x += '  </events>\\r\\n</security_audit>';
            downloadFile(x, fn, 'application/xml');
        }}

        function exportToTXT(mda, fn) {{
            let t = 'LINUX SECURITY AUDIT REPORT\\r\\n' + '='.repeat(60) + '\\r\\nExport: ' + new Date().toLocaleString() + '\\r\\n\\r\\n';
            mda.forEach(m => {{
                t += '='.repeat(60) + '\\r\\nMODULE: ' + m.moduleName + '\\r\\n' + '='.repeat(60) + '\\r\\n\\r\\n';
                m.data.forEach(row => {{
                    t += row.map((c,i) => m.headers[i] + ': ' + (c||'').replace(/\\r?\\n/g, ' | ')).join('\\r\\n') + '\\r\\n---\\r\\n';
                }});
            }});
            downloadFile(t, fn, 'text/plain');
        }}

        function downloadFile(content, filename, mime) {{
            const el = document.createElement('a');
            el.href = 'data:' + mime + ';charset=utf-8,' + encodeURIComponent(content);
            el.download = filename;
            el.style.display = 'none';
            document.body.appendChild(el);
            el.click();
            document.body.removeChild(el);
        }}

        function esc(s) {{
            const d = document.createElement('div');
            d.textContent = s;
            return d.innerHTML;
        }}
        function escXml(s) {{
            return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
        }}

        window.onclick = function(e) {{
            if (e.target === document.getElementById('exportModal')) closeExportModal();
        }};
    </script>
</body>
</html>'''

    return html_content


# ============================================================================
# Export Functions
# ============================================================================
def export_to_csv(results: List[AuditResult], filepath: Path):
    """
    Export results to CSV format.

    Uses lowercase field names matching AuditResult.to_dict() output.
    Includes all fields: module, category, status, message, details,
    remediation, severity, cross_references, and timestamp.
    """
    fieldnames = ['module', 'category', 'status', 'severity', 'message',
                  'details', 'remediation', 'cross_references', 'timestamp']
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            row = result.to_dict()
            # Convert cross_references dict to string for CSV compatibility
            if isinstance(row.get('cross_references'), dict):
                row['cross_references'] = json.dumps(row['cross_references']) if row['cross_references'] else ''
            writer.writerow(row)
    
    # Set readable permissions
    try:
        os.chmod(filepath, 0o644)
    except:
        pass
    
    log_and_print(f"\n[+] CSV report saved to: {filepath}", Colors.GREEN)

def export_to_json(results: List[AuditResult], execution_info: ExecutionInfo,
                   filepath: Path, silent: bool = False):
    """
    Export results to JSON format (SIEM-compatible structured data).

    Args:
        results: List of all audit check results
        execution_info: Execution metadata
        filepath: Destination file path
        silent: If True, suppress console output (used for companion JSON)
    """
    data = {
        "executionInfo": execution_info.to_dict(),
        "results": [r.to_dict() for r in results]
    }
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    
    # Set readable permissions
    try:
        os.chmod(filepath, 0o644)
    except:
        pass
    
    if not silent:
        log_and_print(f"\n[+] JSON report saved to: {filepath}", Colors.GREEN)

def export_to_xml(results: List[AuditResult], execution_info: ExecutionInfo, filepath: Path):
    """
    Export results to XML format (SIEM-compatible structured data).

    Includes full audit metadata and all result fields including severity
    and cross-framework reference mappings.
    """
    root = ET.Element('security_audit')
    
    # Metadata
    metadata = ET.SubElement(root, 'metadata')
    ET.SubElement(metadata, 'export_date').text = datetime.datetime.utcnow().isoformat()
    ET.SubElement(metadata, 'hostname').text = execution_info.hostname
    ET.SubElement(metadata, 'ip_addresses').text = ', '.join(execution_info.ip_addresses)
    ET.SubElement(metadata, 'operating_system').text = execution_info.os_version
    ET.SubElement(metadata, 'scan_date').text = execution_info.scan_date
    ET.SubElement(metadata, 'duration').text = execution_info.duration
    ET.SubElement(metadata, 'total_checks').text = str(execution_info.total_checks)
    ET.SubElement(metadata, 'pass_count').text = str(execution_info.pass_count)
    ET.SubElement(metadata, 'fail_count').text = str(execution_info.fail_count)
    ET.SubElement(metadata, 'warning_count').text = str(execution_info.warning_count)
    ET.SubElement(metadata, 'info_count').text = str(execution_info.info_count)
    ET.SubElement(metadata, 'error_count').text = str(execution_info.error_count)
    
    # Events
    events = ET.SubElement(root, 'events')
    for result in results:
        event = ET.SubElement(events, 'event')
        ET.SubElement(event, 'timestamp').text = result.timestamp
        ET.SubElement(event, 'module').text = result.module
        ET.SubElement(event, 'status').text = result.status
        ET.SubElement(event, 'severity').text = result.severity
        ET.SubElement(event, 'category').text = result.category
        ET.SubElement(event, 'message').text = result.message
        if result.details:
            ET.SubElement(event, 'details').text = result.details
        if result.remediation:
            ET.SubElement(event, 'remediation').text = result.remediation
        # Cross-references as sub-elements
        if result.cross_references:
            xrefs = ET.SubElement(event, 'cross_references')
            for framework, ref_id in result.cross_references.items():
                ref = ET.SubElement(xrefs, 'reference')
                ref.set('framework', framework)
                ref.text = ref_id
    
    tree = ET.ElementTree(root)
    ET.indent(tree, space='  ')
    tree.write(filepath, encoding='utf-8', xml_declaration=True)
    
    # Set readable permissions
    try:
        os.chmod(filepath, 0o644)
    except:
        pass
    
    log_and_print(f"\n[+] XML report saved to: {filepath}", Colors.GREEN)

def export_split_reports(all_results: List[AuditResult],
                         base_execution_info: ExecutionInfo,
                         output_format: str,
                         module_compliance: Dict[str, Any] = None) -> List:
    """Generate a separate report per framework/module.

    v3.8: When many frameworks are audited together, the combined report is
    comprehensive but can be cumbersome. This produces one focused report per
    module so each audience (e.g. the PCI team, the HIPAA team) receives only
    the data relevant to them, alongside the combined all-in-one report.

    Args:
        all_results: Every AuditResult from the run.
        base_execution_info: The combined ExecutionInfo (host/timing reused).
        output_format: HTML/CSV/JSON/XML (Console is skipped).
        module_compliance: Optional per-module compliance score dict.

    Returns:
        List of Paths to the per-framework reports written.
    """
    if output_format == "Console":
        return []

    # Group results by module, preserving first-seen order
    modules_in_order = []
    by_module: Dict[str, List[AuditResult]] = {}
    for r in all_results:
        if r.module not in by_module:
            by_module[r.module] = []
            modules_in_order.append(r.module)
        by_module[r.module].append(r)

    if len(modules_in_order) <= 1:
        # Nothing to split - a single module's combined report already
        # is its per-framework report.
        return []

    hostname = get_safe_hostname()
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    split_dir = REPORT_DIR / "by-framework"
    split_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    extension = {
        "HTML": "html", "CSV": "csv", "JSON": "json", "XML": "xml",
    }.get(output_format, "txt")

    written = []
    for mod_name in modules_in_order:
        mod_results = by_module[mod_name]
        # Build the per-module compliance score in the SAME structure the
        # HTML generator expects: {"overall": {...}, "modules": {name: {...}}}.
        # For a split report the module's own score IS the overall score.
        mod_compliance = {}
        if module_compliance and mod_name in module_compliance:
            sc = module_compliance[mod_name]
            sc_dict = sc.to_dict() if hasattr(sc, "to_dict") else sc
            mod_compliance = {
                "overall": sc_dict,
                "modules": {mod_name: sc_dict},
            }
        mod_info = ExecutionInfo(
            hostname=base_execution_info.hostname,
            os_version=base_execution_info.os_version,
            ip_addresses=base_execution_info.ip_addresses,
            scan_date=base_execution_info.scan_date,
            duration=base_execution_info.duration,
            modules_run=[mod_name],
            total_checks=len(mod_results),
            pass_count=sum(1 for r in mod_results if r.status == "Pass"),
            fail_count=sum(1 for r in mod_results if r.status == "Fail"),
            warning_count=sum(1 for r in mod_results if r.status == "Warning"),
            info_count=sum(1 for r in mod_results if r.status == "Info"),
            error_count=sum(1 for r in mod_results if r.status == "Error"),
            compliance_scores=mod_compliance,
        )
        safe_mod = re.sub(r'[^A-Za-z0-9_-]', '_', mod_name)
        out_path = split_dir / (
            f"{safe_mod}-Audit-{hostname}-{timestamp}.{extension}"
        )
        if output_format == "HTML":
            content = generate_html_report(
                mod_results, mod_info,
                subtitle=f"{mod_name}-Oriented Security Assessment")
            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(content)
        elif output_format == "CSV":
            export_to_csv(mod_results, out_path)
        elif output_format == "JSON":
            export_to_json(mod_results, mod_info, out_path, silent=True)
        elif output_format == "XML":
            export_to_xml(mod_results, mod_info, out_path)
        try:
            os.chmod(out_path, 0o644)
        except OSError:
            pass
        written.append(out_path)

    return written


def export_results(results: List[AuditResult], execution_info: ExecutionInfo, 
                  output_format: str, output_path: str = ""):
    """
    Main export function that delegates to specific format handlers.

    Always generates a companion JSON report alongside the primary format
    to support SIEM ingest, dashboard integration, and remediation workflows.
    The companion JSON uses the same base filename with .json extension.

    Args:
        results: List of all audit check results
        execution_info: Execution metadata (hostname, timing, counts)
        output_format: Primary output format (HTML, CSV, JSON, XML, Console)
        output_path: Optional explicit output path; auto-generated if empty

    Returns:
        Path to the primary report file, or None for Console-only output
    """
    hostname = get_safe_hostname()
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")

    if not output_path:
        # Ensure reports/ directory exists (auto-create if missing)
        REPORT_DIR.mkdir(mode=0o755, exist_ok=True)
        extension = {
            "HTML": "html",
            "CSV": "csv",
            "JSON": "json",
            "XML": "xml"
        }.get(output_format, "txt")
        output_path = REPORT_DIR / f"Security-Audit-Report-{hostname}-{timestamp}.{extension}"
    else:
        output_path = Path(output_path)
    
    if output_format == "HTML":
        html_content = generate_html_report(results, execution_info)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        log_and_print(f"\n[+] HTML report saved to: {output_path}", Colors.GREEN)
    elif output_format == "CSV":
        export_to_csv(results, output_path)
    elif output_format == "JSON":
        export_to_json(results, execution_info, output_path)
    elif output_format == "XML":
        export_to_xml(results, execution_info, output_path)
    elif output_format == "Console":
        print_colored("\n[+] Console output complete", Colors.GREEN)
        return None
    
    # ----------------------------------------------------------------
    # Always generate companion JSON alongside primary format
    # ----------------------------------------------------------------
    # Skip if primary format is already JSON (avoid duplicate)
    if output_format != "JSON":
        json_companion_path = output_path.with_suffix('.json')
        export_to_json(results, execution_info, json_companion_path, silent=True)
        log_and_print(f"[+] Companion JSON saved to: {json_companion_path}", Colors.GREEN)
    
    # Fix file permissions to make it readable by all users
    try:
        os.chmod(output_path, 0o644)
        
        # If running as root, try to change ownership to the user who invoked sudo
        if os.geteuid() == 0:
            sudo_user = os.environ.get('SUDO_USER')
            if sudo_user:
                try:
                    import pwd
                    user_info = pwd.getpwnam(sudo_user)
                    os.chown(output_path, user_info.pw_uid, user_info.pw_gid)
                    # Also fix companion JSON ownership
                    if output_format != "JSON":
                        json_companion = output_path.with_suffix('.json')
                        if json_companion.exists():
                            os.chown(json_companion, user_info.pw_uid, user_info.pw_gid)
                    print_colored(f"[+] File ownership set to: {sudo_user}", Colors.CYAN)
                except Exception as e:
                    pass  # If ownership change fails, at least permissions are set
    except Exception as e:
        print_colored(f"[!] Warning: Could not set file permissions: {e}", Colors.YELLOW)
    
    return output_path

# ============================================================================
# Main Execution
# ============================================================================
def main():
    """Main execution function"""
    # v3.6: Clear helper caches at the start of each audit run. This is
    # a no-op for one-shot CLI invocations (the process exits anyway), but
    # matters for long-running supervisors that call main() in a loop and
    # need to observe state changes between iterations.
    try:
        from shared_components.module_helpers import clear_caches
        clear_caches()
    except ImportError:
        pass  # Older module_helpers without v3.6 caches; harmless.

    parser = argparse.ArgumentParser(
        description='Linux Security Audit Script - multi-framework Linux security and compliance assessment',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    # Module selection
    parser.add_argument('-m', '--modules', type=str, default='All',
                       help='Comma-separated list of modules (use --list-modules to see available)')
    parser.add_argument('--list-modules', action='store_true',
                       help='List all available modules and exit')
    
    # Output options
    parser.add_argument('-f', '--output-format', type=str, default='HTML',
                       choices=['HTML', 'CSV', 'JSON', 'XML', 'Console'],
                       help='Output format')
    parser.add_argument('-o', '--output-path', type=str, default='',
                       help='Path for output file')
    
    # Remediation options
    parser.add_argument('--remediate', action='store_true',
                       help='Interactively remediate failed checks')
    parser.add_argument('--remediate-fail', action='store_true',
                       help='Remediate only FAIL status issues')
    parser.add_argument('--remediate-warning', action='store_true',
                       help='Remediate only WARNING status issues')
    parser.add_argument('--remediate-info', action='store_true',
                       help='Remediate only INFO status issues')
    parser.add_argument('--auto-remediate', action='store_true',
                       help='Automatically remediate without prompting')
    parser.add_argument('--remediation-file', type=str, default='',
                       help='JSON file with specific issues to remediate')
    
    # Performance options (NEW in v2.0)
    parser.add_argument('--parallel', action='store_true',
                       help='Execute modules in parallel for faster audit completion')
    parser.add_argument('--workers', type=int, default=DEFAULT_PARALLEL_WORKERS,
                       help=f'Number of parallel workers (default: {DEFAULT_PARALLEL_WORKERS}, max: {MAX_PARALLEL_WORKERS})')
    parser.add_argument('--no-cache', action='store_true',
                       help='Disable shared data caching (slower, for debugging)')
    parser.add_argument('--perf-profile', '--profile-perf', action='store_true',
                       help='Show detailed timing/performance breakdown')

    # v3.7: Per-distribution audit profiles. Filters which modules and
    # categories run based on the target distribution. SUBTRACTIVE only
    # (never adds checks). See shared_components/profiles.py for design.
    parser.add_argument('--profile', type=str, default='',
                       metavar='NAME',
                       help='Apply a per-distribution audit profile '
                            '(e.g., rhel9, ubuntu24, debian12). Use '
                            '--list-profiles to see all options.')
    parser.add_argument('--list-profiles', action='store_true',
                       help='List all available --profile values and exit')

    # v3.8: Per-framework split reports + attack surface report
    parser.add_argument('--split-reports', action='store_true',
                       help='Generate a separate report per framework/module '
                            'in reports/by-framework/, in addition to the '
                            'combined all-in-one report')
    parser.add_argument('--split-only', action='store_true',
                       help='Generate only the per-framework split reports '
                            '(implies --split-reports; skips the combined '
                            'report)')
    parser.add_argument('--attack-surface', action='store_true',
                       help='Generate an attack-surface assessment report '
                            '(HTML + JSON) synthesizing exposure-relevant '
                            'findings across all selected frameworks')
    
    # Logging options (NEW in v2.0)
    parser.add_argument('--log-level', type=str, default='INFO',
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       help='Logging verbosity level (default: INFO)')
    parser.add_argument('--log-file', type=str, default='',
                       help='Write detailed log to file')
    parser.add_argument('--json-log', action='store_true',
                       help='Use JSON format for log file (for SIEM ingestion)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output (sets log level to DEBUG)')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Suppress informational output (sets log level to WARNING)')
    
    # ================================================================
    # v3.0 Pipeline Flags
    # ================================================================
    parser.add_argument('--baseline', type=str, default='',
                       help='Compare current results against a previous baseline JSON file')
    parser.add_argument('--rollback-path', type=str, default='',
                       help='Generate a rollback bash script at the given path during remediation')
    parser.add_argument('--remediation-bundle', type=str, default='',
                       help='Apply a named remediation bundle (e.g. HardenSSH, HardenKernel)')
    parser.add_argument('--asset-criticality', type=int, default=5, choices=range(1, 11),
                       metavar='1-10',
                       help='Asset criticality 1-10 for risk priority scoring (default: 5)')
    parser.add_argument('--show-risk-priority', action='store_true',
                       help='Display risk priority scores for failed/warning findings')
    parser.add_argument('--show-correlations', action='store_true',
                       help='Display cross-framework control correlations for each result')
    parser.add_argument('--validate-results', action='store_true',
                       help='Run strict result validation and report defects')
    parser.add_argument('--list-bundles', action='store_true',
                       help='List available remediation bundles and exit')
    parser.add_argument('--threshold', type=float, default=70.0,
                       help='Compliance score pass/fail threshold (default: 70.0)')
    
    args = parser.parse_args()
    
    # If just listing modules, do that and exit
    if args.list_modules:
        print_banner()
        list_available_modules()
        return

    # v3.7: --list-profiles enumerates all built-in distribution profiles
    if getattr(args, 'list_profiles', False):
        try:
            from shared_components import profiles as _profiles
            print_banner()
            print("\nAvailable Distribution Profiles:\n")
            for prof_name in _profiles.list_profiles():
                prof = _profiles.get_profile(prof_name)
                print(_profiles.describe_profile(prof))
                print()
            print(
                "Usage: --profile NAME (e.g., --profile rhel9)\n"
                "Profiles are SUBTRACTIVE filters: they may exclude modules "
                "or category prefixes that\n"
                "are not applicable to the target distribution. They never "
                "add or modify checks."
            )
        except Exception as exc:  # noqa: BLE001
            print_colored(
                f"[!] Error listing profiles: {exc!r}", Colors.RED,
            )
            return
        return

    # v3.7: Validate --profile NAME if supplied. Strict input validation
    # is enforced in shared_components/profiles.py (regex ^[a-z][a-z0-9_-]{0,30}$).
    selected_profile = None
    if args.profile:
        try:
            from shared_components import profiles as _profiles
            selected_profile = _profiles.get_profile(args.profile)
        except (ValueError, ImportError) as exc:
            print_colored(
                f"[!] Invalid --profile value: {exc}", Colors.RED, bold=True,
            )
            print_colored(
                "    Use --list-profiles to see valid profile names.",
                Colors.YELLOW,
            )
            sys.exit(2)
    
    # If just listing remediation bundles, do that and exit
    if getattr(args, 'list_bundles', False):
        try:
            from shared_components.remediation_bundles import (
                list_bundles as v3_list_bundles, get_bundle, format_bundle_summary,
            )
            print_banner()
            print("\nAvailable Remediation Bundles:\n")
            for bundle_name in v3_list_bundles():
                bundle = get_bundle(bundle_name)
                if bundle:
                    print(format_bundle_summary(bundle))
                    print()
            return
        except ImportError as exc:
            print(f"[!] Bundle listing requires v3.0 components: {exc}")
            return
    
    start_time = datetime.datetime.now()
    
    # ================================================================
    # Initialize Logging (NEW in v2.0)
    # ================================================================
    log_level_str = args.log_level
    if args.verbose:
        log_level_str = 'DEBUG'
    elif args.quiet:
        log_level_str = 'WARNING'
    
    log_level = getattr(logging, log_level_str, logging.INFO)
    
    # Set up structured logging if shared library is available
    log_file_path = args.log_file
    if not log_file_path and not args.quiet:
        # Ensure logs/ directory exists (auto-create if missing)
        LOG_DIR.mkdir(mode=0o755, exist_ok=True)
        hostname = get_safe_hostname()
        log_file_path = str(LOG_DIR / f"audit-{hostname}-{start_time.strftime('%Y%m%d-%H%M%S')}.log")
    
    if HAS_COMMON_LIB:
        common_configure_logging(
            log_level=log_level,
            log_file=log_file_path if log_file_path else None,
            json_format=args.json_log
        )
        # Attach shared library file handler to main script logger so that
        # log_and_print() messages also appear in the log file.
        from shared_components.audit_common import _global_file_handler as _gfh
        if _gfh and _gfh not in logger.handlers:
            logger.setLevel(log_level)
            logger.addHandler(_gfh)
            logger.propagate = False
    
    print_banner()
    
    # ================================================================
    # Prerequisites Check
    # ================================================================
    # Check if remediation requires root
    require_root = (args.remediate or args.remediate_fail or args.remediate_warning or 
                   args.remediate_info or args.auto_remediate)
    
    prerequisites_ok, is_root = check_prerequisites(require_root)
    if not prerequisites_ok:
        return
    
    # ================================================================
    # Initialize SharedDataCache (NEW in v2.0)
    # ================================================================
    cache = None
    cache_timing = {}
    module_timings = {}
    
    if HAS_COMMON_LIB and not args.no_cache:
        print_colored("[*] Initializing shared data cache...", Colors.YELLOW)
        try:
            os_info = common_detect_os()
            cache = SharedDataCache(os_info)
            cache_timing = cache.warm_up()
            
            cache_stats = cache.get_summary()
            print_colored(
                f"[+] Cache ready: {cache_stats['files_cached']} files, "
                f"{cache_stats['commands_cached']} commands cached in "
                f"{cache_timing.get('total', 0):.2f}s",
                Colors.GREEN
            )
            print_colored(
                f"    OS detected: {os_info}",
                Colors.GRAY
            )
        except Exception as e:
            print_colored(f"[!] Cache initialization failed, continuing without cache: {e}", Colors.YELLOW)
            cache = None
    elif not HAS_COMMON_LIB:
        print_colored("[!] Shared library (audit_common.py) not found - running without caching", Colors.YELLOW)
        print_colored("    Place audit_common.py in the same directory for better performance", Colors.YELLOW)
    
    # ================================================================
    # Module Discovery and Validation
    # ================================================================
    # Get available modules dynamically
    available_modules = get_available_modules()
    
    if not available_modules:
        print_colored("[!] No modules found. Cannot proceed.", Colors.RED)
        return
    
    # Determine modules to run
    if args.modules == 'All':
        modules_to_run = sorted(available_modules.keys())
    else:
        requested_modules = [m.strip() for m in args.modules.split(',')]
        modules_to_run = []

        # Module name aliases: map user-friendly/legacy selectors to the
        # canonical MODULE_NAME used by discovery. Comparison is
        # case-insensitive and ignores hyphens, so "PCIDSS", "pci-dss", and
        # "PCI" all resolve to the canonical "PCI-DSS".
        module_aliases = {
            'pcidss': 'PCI-DSS',
            'pci': 'PCI-DSS',
        }

        def _normalize(name):
            return name.lower().replace('-', '').replace('_', '')

        # Validate requested modules exist
        for module in requested_modules:
            # Try alias resolution first, then case-insensitive matching
            matched = False
            alias_target = module_aliases.get(_normalize(module))
            for available_module in available_modules.keys():
                if (module.lower() == available_module.lower() or
                        _normalize(module) == _normalize(available_module) or
                        (alias_target and alias_target.lower() ==
                         available_module.lower())):
                    if available_module not in modules_to_run:
                        modules_to_run.append(available_module)
                    matched = True
                    break

            if not matched:
                print_colored(f"[!] WARNING: Module '{module}' not found", Colors.YELLOW)
        
        if not modules_to_run:
            print_colored("[!] No valid modules specified. Use --list-modules to see available modules.", Colors.RED)
            return
    
    # v3.7: Apply distribution profile module filter (subtractive only).
    if selected_profile is not None:
        original_count = len(modules_to_run)
        modules_to_run = _profiles.apply_profile(
            selected_profile, modules_to_run,
        )
        excluded = original_count - len(modules_to_run)
        if excluded > 0:
            print_colored(
                f"[*] Profile '{selected_profile.name}' excluded "
                f"{excluded} module(s) from execution",
                Colors.CYAN,
            )
        if not modules_to_run:
            print_colored(
                f"[!] Profile '{selected_profile.name}' excluded all "
                f"selected modules. Nothing to run.",
                Colors.RED,
            )
            return

    print_colored(f"\n[*] Modules to execute: {', '.join(modules_to_run)}", Colors.CYAN)
    if selected_profile is not None:
        print_colored(
            f"[*] Distribution profile: {selected_profile.name} "
            f"({selected_profile.description.split('.')[0]})",
            Colors.CYAN,
        )
    
    # Validate parallel worker count
    workers = min(args.workers, MAX_PARALLEL_WORKERS)
    if args.parallel:
        workers = min(workers, len(modules_to_run))
        print_colored(f"[*] Parallel execution: {workers} workers", Colors.CYAN)
    
    # ================================================================
    # Prepare Shared Data (passed to all modules)
    # ================================================================
    # Determine OS version display string from os_detection (pretty_name) so
    # downstream reports show "Ubuntu 24.04.4 LTS" rather than the kernel-
    # derived "Linux 6.x.x-generic" string.
    try:
        from shared_components.os_detection import detect_os as _detect_os
        _detected_os = _detect_os()
        _os_version_str = (
            _detected_os.pretty_name or str(_detected_os)
            or f"{platform.system()} {platform.release()}"
        )
    except Exception:
        _detected_os = None
        _os_version_str = f"{platform.system()} {platform.release()}"

    shared_data = {
        "hostname": socket.gethostname(),
        "os_version": _os_version_str,
        "os_info": _detected_os,
        "ip_addresses": get_system_ip_addresses(),
        "scan_date": start_time,
        "is_root": is_root,
        "script_path": SCRIPT_PATH,
        "cache": cache,  # SharedDataCache instance (may be None for backward compat)
    }

    # v3.7: Cross-module correlation. Compute the canonical HostFacts record
    # once at audit start. Modules that opt in read from
    # shared_data["host_facts"] instead of re-deriving from raw helpers.
    # This reduces duplicate logic across modules and standardizes the
    # interpretation of facts (e.g., "FIM is present" means the same thing
    # across HIPAA, PCI, ISO27001, GDPR).
    try:
        from shared_components import host_facts as _host_facts_mod
        from shared_components import module_helpers as _module_helpers_mod
        if _detected_os is not None:
            shared_data["host_facts"] = _host_facts_mod.compute_host_facts(
                _detected_os, _module_helpers_mod,
            )
    except Exception as _hf_exc:  # noqa: BLE001
        # Host facts are an optimization; on any failure, modules fall back
        # to raw helpers (which still benefit from v3.6 caching).
        log_and_print(
            f"[!] HostFacts computation failed (modules will fall back "
            f"to raw helpers): {_hf_exc!r}",
            Colors.YELLOW,
        )
    
    # ================================================================
    # Execute Modules (Sequential or Parallel)
    # ================================================================
    all_results = []
    successful_modules = []
    
    if args.parallel and len(modules_to_run) > 1:
        # ---- Parallel Execution ----
        print_colored(f"\n[*] Executing {len(modules_to_run)} modules in parallel "
                      f"({workers} workers)...", Colors.CYAN)
        
        completed_count = 0
        total_modules = len(modules_to_run)
        module_start_times = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            # Submit all modules and track start time
            future_to_module = {}
            for module in modules_to_run:
                future = executor.submit(execute_security_module, module, shared_data)
                future_to_module[future] = module
                module_start_times[module] = time.monotonic()
            
            # Collect results as they complete with progress reporting
            for future in concurrent.futures.as_completed(future_to_module):
                module = future_to_module[future]
                elapsed = time.monotonic() - module_start_times[module]
                try:
                    module_results = future.result()
                    if module_results:
                        all_results.extend(module_results)
                        successful_modules.append(module)
                except Exception as e:
                    print_colored(f"[!] Failed to execute module {module}: {e}", Colors.RED)
                module_timings[module] = elapsed
                completed_count += 1
                print_colored(f"  [{completed_count}/{total_modules}] {module} completed "
                              f"({elapsed:.1f}s)", Colors.WHITE)
    else:
        # ---- Sequential Execution ----
        for module in modules_to_run:
            module_start = time.monotonic()
            try:
                module_results = execute_security_module(module, shared_data)
                if module_results:
                    all_results.extend(module_results)
                    successful_modules.append(module)
            except Exception as e:
                print_colored(f"[!] Failed to execute module {module}: {e}", Colors.RED)
            module_timings[module] = time.monotonic() - module_start
    
    # Sort results by module
    all_results.sort(key=lambda r: r.module)

    # v3.9: Normalize remediation guidance across frameworks. The same
    # underlying fix (e.g. enable ASLR, disable IP forwarding, no
    # world-writable files) must read identically regardless of which
    # framework module raised it. This replaces a check's remediation with
    # the canonical, most-detailed version ONLY when the check is classified
    # with high confidence into a value-independent topic; framework-specific
    # values (e.g. PASS_MAX_DAYS) are left untouched.
    try:
        from shared_components.canonical_remediations import normalize_remediation
        _norm_count = 0
        for _r in all_results:
            _orig = _r.remediation or ""
            _new = normalize_remediation(_r.message or "", _r.category or "", _orig)
            if _new != _orig:
                _r.remediation = _new
                _norm_count += 1
        if _norm_count:
            logger.info(f"Normalized remediation guidance on {_norm_count} "
                        f"findings for cross-framework consistency")
    except Exception as _exc:  # noqa: BLE001
        logger.warning(f"Remediation normalization skipped: {_exc!r}")
    
    if not all_results:
        print_colored("\n[!] No results generated", Colors.RED)
        return
    
    # ================================================================
    # v3.0 Audit Pipeline (correlation enrichment, risk scoring, drift)
    # ================================================================
    pipeline_outcome = None
    try:
        from shared_components.v3_pipeline import (
            AuditPipeline, render_pipeline_summary, resolve_bundle_to_findings,
            build_metadata, export_json_v3,
        )
        from shared_components.os_detection import detect_os
        from shared_components.remediation_bundles import (
            list_bundles as v3_list_bundles, format_bundle_summary, get_bundle,
        )

        # Handle --list-bundles short-circuit
        if getattr(args, 'list_bundles', False):
            print_banner()
            print("\nAvailable Remediation Bundles:\n")
            for bundle_name in v3_list_bundles():
                bundle = get_bundle(bundle_name)
                if bundle:
                    print(format_bundle_summary(bundle))
                    print()
            return

        os_info_v3 = detect_os()
        pipeline = AuditPipeline(
            threshold=getattr(args, 'threshold', 70.0),
            validation_strict=getattr(args, 'validate_results', False),
        )
        pipeline_outcome = pipeline.run_pipeline(
            results=all_results,
            os_info=os_info_v3,
            baseline_path=getattr(args, 'baseline', '') or '',
            asset_criticality=getattr(args, 'asset_criticality', 5),
        )

        # Replace all_results with the enriched (cross-references applied)
        # version so report generators see the correlations
        all_results = pipeline_outcome.results

        # Display pipeline summary unless quiet
        if not getattr(args, 'quiet', False):
            print()
            print(render_pipeline_summary(pipeline_outcome))

        # Optional risk priority display
        if getattr(args, 'show_risk_priority', False):
            top = sorted(
                pipeline_outcome.risk_scores.items(),
                key=lambda kv: kv[1].total, reverse=True
            )[:25]
            if top:
                print("\nTop 25 findings by risk priority:")
                print("-" * 78)
                for idx, score in top:
                    if idx >= len(all_results):
                        continue
                    r = all_results[idx]
                    print(f"  [{score.total:>3}] {r.severity:>13} {r.module:>10} | {r.message[:55]}")
                print()

        # Optional cross-correlation display
        if getattr(args, 'show_correlations', False):
            print("\nCross-framework correlations:")
            print("-" * 78)
            shown = 0
            for r in all_results:
                if r.cross_references and shown < 50:
                    print(f"  [{r.module}] {r.message[:60]}")
                    for fw, cid in sorted(r.cross_references.items()):
                        print(f"      {fw}: {cid}")
                    shown += 1
            if shown >= 50:
                print(f"  ... output truncated at 50 results")
            print()

        # Drift report display
        if pipeline_outcome.drift_report and not getattr(args, 'quiet', False):
            from shared_components.baseline_compare import format_console_summary
            print(format_console_summary(pipeline_outcome.drift_report))

        # Bundle resolution feedback
        if getattr(args, 'remediation_bundle', ''):
            bundle, matched = resolve_bundle_to_findings(
                args.remediation_bundle, all_results
            )
            if bundle is None:
                print_colored(
                    f"\n[!] Unknown remediation bundle: {args.remediation_bundle}",
                    Colors.RED,
                )
                print("    Run with --list-bundles to see available bundles.")
            else:
                print(f"\n[*] Bundle '{bundle.name}' matched {len(matched)} findings")
                if bundle.impact.ssh_continuity_risk:
                    print_colored(
                        "    *** WARNING: This bundle may disrupt SSH sessions ***",
                        Colors.YELLOW,
                    )
                if bundle.impact.reboot_required:
                    print_colored(
                        "    *** Reboot required for full effect ***",
                        Colors.YELLOW,
                    )

    except ImportError as exc:
        # v3 pipeline modules unavailable; fall through to v2.x behaviour
        if not getattr(args, 'quiet', False):
            print(f"[note] v3.0 pipeline unavailable: {exc}; using v2.x flow")

    # v3.7: Apply distribution profile category filter (subtractive only).
    # This drops AuditResult entries whose category starts with any of the
    # profile's exclude_categories prefixes. Modules execute fully; the
    # filter only affects what's reported and counted in statistics.
    if selected_profile is not None and selected_profile.exclude_categories:
        before = len(all_results)
        all_results = _profiles.filter_results(selected_profile, all_results)
        dropped = before - len(all_results)
        if dropped > 0 and not getattr(args, 'quiet', False):
            print_colored(
                f"[*] Profile '{selected_profile.name}' filtered "
                f"{dropped} result(s) by category prefix",
                Colors.CYAN,
            )

    # Calculate execution info
    end_time = datetime.datetime.now()
    duration = end_time - start_time
    
    execution_info = ExecutionInfo(
        hostname=shared_data["hostname"],
        os_version=shared_data["os_version"],
        ip_addresses=shared_data["ip_addresses"],
        scan_date=start_time.strftime("%Y-%m-%d %H:%M:%S"),
        duration=str(duration).split('.')[0],
        modules_run=successful_modules,
        total_checks=len(all_results),
        pass_count=sum(1 for r in all_results if r.status == "Pass"),
        fail_count=sum(1 for r in all_results if r.status == "Fail"),
        warning_count=sum(1 for r in all_results if r.status == "Warning"),
        info_count=sum(1 for r in all_results if r.status == "Info"),
        error_count=sum(1 for r in all_results if r.status == "Error")
    )

    # ================================================================
    # Compliance Scoring (Phase 3.5)
    # ================================================================
    module_compliance = {}
    for mod_name in successful_modules:
        mod_results = [r for r in all_results if r.module == mod_name]
        mod_stats = calculate_module_statistics(mod_results)
        sev_dist = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
        for r in mod_results:
            sev = r.severity if r.severity in sev_dist else 'Medium'
            sev_dist[sev] += 1
        score = ComplianceScore(
            module_name=mod_name,
            total_checks=mod_stats.total,
            passed=mod_stats.passed,
            failed=mod_stats.failed,
            warnings=mod_stats.warnings,
            info=mod_stats.info,
            errors=mod_stats.errors,
        )
        score.compute(severity_distribution=sev_dist)
        module_compliance[mod_name] = score

    # Overall compliance score (3.5.3)
    overall_sev_dist = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
    for r in all_results:
        sev = r.severity if r.severity in overall_sev_dist else 'Medium'
        overall_sev_dist[sev] += 1
    overall_score = ComplianceScore(
        module_name="Overall",
        total_checks=execution_info.total_checks,
        passed=execution_info.pass_count,
        failed=execution_info.fail_count,
        warnings=execution_info.warning_count,
        info=execution_info.info_count,
        errors=execution_info.error_count,
    )
    overall_score.compute(severity_distribution=overall_sev_dist)

    # Store in execution_info for export/reporting
    execution_info.compliance_scores = {
        "overall": overall_score.to_dict(),
        "modules": {name: sc.to_dict() for name, sc in module_compliance.items()}
    }
    
    # Display summary
    print_colored("\n" + "=" * 100, Colors.CYAN)
    print_colored("                                 AUDIT SUMMARY", Colors.CYAN, bold=True)
    print_colored("=" * 100, Colors.CYAN)
    print_colored(f"Hostname:        {execution_info.hostname}", Colors.WHITE)
    print_colored(f"IP Address(es):  {', '.join(execution_info.ip_addresses)}", Colors.WHITE)
    print_colored(f"Operating System:{execution_info.os_version}", Colors.WHITE)
    print_colored(f"Execution Mode:  {'ROOT (Full Access)' if is_root else 'NON-ROOT (Limited)'}", Colors.GREEN if is_root else Colors.CYAN)
    print_colored(f"Total Checks:    {execution_info.total_checks}", Colors.WHITE)
    print_colored(f"Passed:          {execution_info.pass_count}", Colors.GREEN)
    print_colored(f"Failed:          {execution_info.fail_count}", Colors.RED)
    print_colored(f"Warnings:        {execution_info.warning_count}", Colors.YELLOW)
    print_colored(f"Info:            {execution_info.info_count}", Colors.CYAN)
    print_colored(f"Errors:          {execution_info.error_count}", Colors.MAGENTA)
    print_colored(f"Duration:        {execution_info.duration}", Colors.WHITE)

    # Compliance scores in console summary
    print_colored("\n  Compliance Scores:", Colors.WHITE, bold=True)
    oc = Colors.GREEN if overall_score.weighted_pct >= 80 else Colors.YELLOW if overall_score.weighted_pct >= 60 else Colors.RED
    print_colored(f"    Overall:           {overall_score.weighted_pct:.1f}% (weighted) | "
                  f"{overall_score.simple_pct:.1f}% (simple) | "
                  f"{overall_score.severity_weighted_pct:.1f}% (severity-adjusted) | "
                  f"[{overall_score.threshold_result}]", oc)
    for mod_name in sorted(module_compliance.keys()):
        sc = module_compliance[mod_name]
        mc = Colors.GREEN if sc.weighted_pct >= 80 else Colors.YELLOW if sc.weighted_pct >= 60 else Colors.RED
        print_colored(f"    {mod_name:16s}  {sc.weighted_pct:6.1f}%  [{sc.threshold_result}]", mc)
    
    if statistics.normalized_results > 0:
        print_colored(f"\nValidation: {statistics.normalized_results} results normalized", Colors.YELLOW)
    
    # ================================================================
    # Performance Profile (NEW in v2.0)
    # ================================================================
    if args.perf_profile or args.verbose:
        print_colored("\n  Performance Profile:", Colors.WHITE, bold=True)
        
        # Cache statistics
        if cache:
            cache_stats = get_cache_statistics()
            print_colored(f"    Cache warm-up:      {cache_timing.get('total', 0):.3f}s", Colors.GRAY)
            print_colored(f"    Cache hit rate:     {cache_stats['hit_rate']}% "
                         f"({cache_stats['hits']} hits / {cache_stats['misses']} misses)", Colors.GRAY)
        
        # Module timing breakdown
        if module_timings:
            print_colored("    Module timings:", Colors.GRAY)
            for mod_name in sorted(module_timings.keys()):
                mod_time = module_timings[mod_name]
                mod_checks = statistics.module_stats.get(mod_name)
                checks_str = f" ({mod_checks.total} checks)" if mod_checks else ""
                print_colored(f"      {mod_name:12s}: {mod_time:.3f}s{checks_str}", Colors.GRAY)
        
        # Execution mode
        if args.parallel and len(modules_to_run) > 1:
            print_colored(f"    Execution mode:    Parallel ({workers} workers)", Colors.GRAY)
        else:
            print_colored(f"    Execution mode:    Sequential", Colors.GRAY)
    
    # Log file notification
    if log_file_path and not args.quiet:
        print_colored(f"\n  Log file:     {log_file_path}", Colors.GRAY)
    
    if not is_root:
        print_colored("\n[!] Note: Some checks may be limited without root privileges", Colors.CYAN)
        print_colored("    Run with 'sudo' for complete security assessment", Colors.CYAN)
    
    print_colored("=" * 100 + "\n", Colors.CYAN)
    
    # Handle remediation if requested
    if args.remediate or args.remediate_fail or args.remediate_warning or args.remediate_info:
        if not is_root:
            print_colored("[!] ERROR: Remediation requires root privileges", Colors.RED)
            print_colored("    Run with: sudo python3 linux_security_audit.py --remediate", Colors.YELLOW)
        else:
            invoke_remediation(all_results, args)
    
    # Export results
    if args.output_format != "Console":
        split_reports_requested = (
            getattr(args, 'split_reports', False) or
            getattr(args, 'split_only', False)
        )
        # Combined all-in-one report (unless --split-only)
        if not getattr(args, 'split_only', False):
            output_path = export_results(all_results, execution_info, args.output_format, args.output_path)
            if output_path and output_path.exists():
                print_colored(f"[*] Report saved to: {output_path.absolute()}", Colors.CYAN)

        # v3.8: Per-framework split reports
        if split_reports_requested:
            split_paths = export_split_reports(
                all_results, execution_info, args.output_format,
                module_compliance=module_compliance,
            )
            if split_paths:
                print_colored(
                    f"[*] {len(split_paths)} per-framework report(s) saved to: "
                    f"{(REPORT_DIR / 'by-framework').absolute()}",
                    Colors.CYAN,
                )
                for p in split_paths:
                    print_colored(f"      - {p.name}", Colors.GRAY)
            elif getattr(args, 'split_only', False):
                print_colored(
                    "[!] --split-only: only one framework was selected; "
                    "no split needed (use the combined report).",
                    Colors.YELLOW,
                )

    # v3.8: Attack-surface assessment report
    if getattr(args, 'attack_surface', False):
        try:
            from shared_components import attack_surface as _as_mod
            surface = _as_mod.build_attack_surface(
                all_results, shared_data.get("host_facts"),
            )
            hostname = get_safe_hostname()
            timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            REPORT_DIR.mkdir(mode=0o755, exist_ok=True)
            as_html_path = REPORT_DIR / (
                f"Attack-Surface-{hostname}-{timestamp}.html"
            )
            as_json_path = REPORT_DIR / (
                f"Attack-Surface-{hostname}-{timestamp}.json"
            )
            with open(as_html_path, 'w', encoding='utf-8') as f:
                f.write(_as_mod.render_attack_surface_html(
                    surface, execution_info))
            import json as _json
            with open(as_json_path, 'w', encoding='utf-8') as f:
                _json.dump(_as_mod.attack_surface_to_dict(surface), f, indent=2)
            for p in (as_html_path, as_json_path):
                try:
                    os.chmod(p, 0o644)
                except OSError:
                    pass
            print_colored(
                f"[*] Attack-surface assessment: "
                f"{surface.overall_rating} exposure "
                f"({surface.overall_score:.0f}/100)",
                Colors.CYAN,
            )
            print_colored(
                f"[*] Attack-surface report saved to: {as_html_path.absolute()}",
                Colors.CYAN,
            )
        except Exception as exc:  # noqa: BLE001
            print_colored(
                f"[!] Attack-surface report generation failed: {exc!r}",
                Colors.YELLOW,
            )

    log_and_print("\n[+] Audit completed successfully!", Colors.GREEN)
    if not is_root:
        print_colored("[*] Tip: Run with 'sudo' for complete security assessment and remediation", Colors.CYAN)
    print_colored("[*] GitHub: https://github.com/Sandler73/Linux-Security-Audit-Project.git", Colors.CYAN)

# ============================================================================
# Script Entry Point
# ============================================================================
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_colored("\n\n[!] Audit interrupted by user", Colors.YELLOW)
        sys.exit(1)
    except Exception as e:
        print_colored(f"\n[!] Fatal error: {e}", Colors.RED)
        import traceback
        print_colored("\nStack Trace:", Colors.YELLOW)
        traceback.print_exc()
        sys.exit(1)
