#!/usr/bin/env python3
"""
module_cisa.py
CISA (Cybersecurity and Infrastructure Security Agency) Module for Linux
Version: 2.1

SYNOPSIS:
    CISA Cybersecurity Directives and best practices compliance checks for Linux systems.

DESCRIPTION:
    This module performs comprehensive security checks based on CISA directives, advisories,
    and cybersecurity best practices for protecting critical infrastructure:
    
    Binding Operational Directives (BODs):
    - BOD 18-01: Enhanced Email and Web Security
    - BOD 19-02: Vulnerability Remediation Requirements
    - BOD 20-01: Develop and Publish a Vulnerability Disclosure Policy
    - BOD 22-01: Reducing the Significant Risk of Known Exploited Vulnerabilities
    - BOD 23-01: Improving Asset Visibility and Vulnerability Detection
    
    Emergency Directives (EDs):
    - Critical vulnerability patching
    - Immediate threat mitigation
    - Zero-day protection
    
    Vulnerability Management:
    - Known Exploited Vulnerabilities (KEV) catalog
    - Patch management and timelines
    - Vulnerability scanning
    - Configuration management
    
    Critical Infrastructure Protection:
    - Essential services security
    - Network segmentation
    - Access control
    - Incident response readiness
    
    Security Best Practices:
    - Multi-factor authentication
    - Least privilege principles
    - Secure configuration baselines
    - Logging and monitoring
    - Backup and recovery
    
    Cloud and Modern Infrastructure:
    - Cloud security posture
    - Container security
    - DevSecOps practices
    
    Incident Response:
    - Detection capabilities
    - Response procedures
    - Recovery planning
    - Communication protocols
    
    Based on CISA Publications:
    - CISA Binding Operational Directives
    - CISA Emergency Directives
    - CISA Cybersecurity Advisories
    - CISA Security Alerts and Analysis Reports
    - Known Exploited Vulnerabilities Catalog

USAGE:
    Standalone module test:
        python3 module_cisa.py

    Integration with main audit script:
        python3 linux_security_audit.py --modules CISA
        python3 linux_security_audit.py -m CISA

PARAMETERS:
    shared_data : Dictionary containing shared data from main script

NOTES:
    Version: 2.1
    Reference: https://www.cisa.gov/directives
    Standards: CISA BODs, CISA EDs, NIST Cybersecurity Framework
    Priority: Critical, High, Medium, Low severity findings
    Target: 150+ comprehensive security checks; OS-aware technical control checks
    Module automatically detects OS via module_core integration
    
    v2.0 Changes:
    - Uses audit_common.py shared library (eliminates duplicated helpers)
    - SharedDataCache integration for cached file/command lookups
    - Severity levels on all AuditResults
    - Thread-safe for parallel execution
"""

import os
import sys
import re
import subprocess
import pwd
import grp
import glob
import socket
import platform
import time
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

# ============================================================================
# Shared Library Integration
# ============================================================================
# Import consolidated utilities from audit_common.py
# This eliminates duplicated helper functions across all modules
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

try:
    # Try shared_components package first (standard deployment)
    from shared_components.audit_common import (
        # Core classes
        AuditResult, OSInfo, SharedDataCache,
        # OS detection
        detect_os,
        # Command execution (cached)
        run_command, command_exists, read_file_safe,
        # Service checks (cache-aware)
        check_service_enabled, check_service_active,
        # Package checks (OS-aware)
        check_package_installed,
        # File checks
        get_file_permissions, get_file_permissions_full,
        get_file_owner_group, check_file_exists,
        # Kernel parameters (cache-aware)
        check_kernel_parameter, check_mount_option,
        # Security subsystems (cache-aware)
        get_selinux_status, get_apparmor_status, get_firewall_status,
        check_fips_mode, check_ipv6_enabled,
        # SSH configuration (cache-aware)
        get_ssh_config_value, get_ssh_config_all,
        # Network
        get_listening_ports, get_loaded_kernel_modules,
        # PAM & password policy (cache-aware)
        check_pam_module, get_password_policy,
        # User accounts (cache-aware)
        get_user_accounts, get_system_users, get_human_users,
        # Parsing helpers
        safe_int_parse, safe_float_parse,
        # Audit rules & GRUB
        get_audit_rules, get_grub_cmdline, check_grub_parameter,
        # Updates (OS-aware)
        get_available_updates, get_security_updates,
        # ID generation
        generate_check_id,
        # Logging
        get_module_logger,
    )
    HAS_COMMON_LIB = True
except ImportError:
    try:
        # Fallback: flat-file layout (audit_common.py in same directory)
        from audit_common import (
            AuditResult, OSInfo, SharedDataCache, detect_os,
            run_command, command_exists, read_file_safe,
            check_service_enabled, check_service_active,
            check_package_installed, get_file_permissions,
            get_file_permissions_full, get_file_owner_group,
            check_file_exists, check_kernel_parameter,
            check_mount_option, get_selinux_status,
            get_apparmor_status, get_firewall_status,
            check_fips_mode, check_ipv6_enabled,
            get_ssh_config_value, get_ssh_config_all,
            get_listening_ports, get_loaded_kernel_modules,
            check_pam_module, get_password_policy,
            get_user_accounts, get_system_users, get_human_users,
            safe_int_parse, safe_float_parse,
            get_audit_rules, get_grub_cmdline, check_grub_parameter,
            get_available_updates, get_security_updates,
            generate_check_id, get_module_logger,
        )
        HAS_COMMON_LIB = True
    except ImportError:
        # Fallback: import AuditResult from main script (backward compatibility)
        from linux_security_audit import AuditResult
        HAS_COMMON_LIB = False

MODULE_NAME = "CISA"

# v3.4 Remediation library wiring
try:
    from shared_components.remediation_library import get_remediation as _v34_get_remediation
    from shared_components.remediation_library import get_removal_remediation as _v34_get_removal
    from shared_components.remediation_library import get_patch_remediation as _v34_get_patch
    from shared_components.os_detection import detect_os as _v34_detect_os
    _v34_OSINFO_CACHE = None
    def remediation_for(tool_id):
        """Return distro-aware remediation text for a registered tool.

        Falls back to a short "Install <tool>" string if the library
        does not have an entry for the tool_id.
        """
        global _v34_OSINFO_CACHE
        if _v34_OSINFO_CACHE is None:
            try:
                _v34_OSINFO_CACHE = _v34_detect_os()
            except Exception:
                _v34_OSINFO_CACHE = None
        text = _v34_get_remediation(tool_id, _v34_OSINFO_CACHE)
        return text if text else f"Install {tool_id} via your distribution\'s package manager"

    def _v34_resolve_os():
        global _v34_OSINFO_CACHE
        if _v34_OSINFO_CACHE is None:
            try:
                _v34_OSINFO_CACHE = _v34_detect_os()
            except Exception:
                _v34_OSINFO_CACHE = None
        return _v34_OSINFO_CACHE

    def removal_for(canonical_token, extra_context=""):
        """Return OS-aware package-removal remediation text."""
        try:
            return _v34_get_removal(canonical_token, _v34_resolve_os(),
                                    extra_context=extra_context)
        except Exception:
            return f"Remove {canonical_token} via your distribution\'s package manager"

    def patch_for(extra_context=""):
        """Return OS-aware security-patch remediation text."""
        try:
            return _v34_get_patch(_v34_resolve_os(), extra_context=extra_context)
        except Exception:
            return "Apply available security updates via your distribution\'s package manager"
except ImportError:  # pragma: no cover
    def remediation_for(tool_id):
        return f"Install {tool_id} via your distribution\'s package manager"
    def removal_for(canonical_token, extra_context=""):
        return f"Remove {canonical_token} via your distribution\'s package manager"
    def patch_for(extra_context=""):
        return "Apply available security updates via your distribution\'s package manager"

MODULE_VERSION = "3.9"

# Module logger (uses structured logging if audit_common is available)
logger = get_module_logger(MODULE_NAME) if HAS_COMMON_LIB else logging.getLogger(MODULE_NAME)

def get_cisa_id(category: str, number: int) -> str:
    """Generate CISA check ID"""
    return f"CISA-{category}-{number:03d}"

def check_updates_available() -> Tuple[int, List[str]]:
    """Check for available security updates (CISA-specific: returns count and package list)"""
    security_updates = []
    count = 0
    
    if command_exists("apt"):
        # Ubuntu/Debian
        result = run_command("apt list --upgradable 2>/dev/null | grep -i security | head -20")
        if result.returncode == 0 and result.stdout:
            security_updates = [line.split('/')[0] for line in result.stdout.strip().split('\n') if line]
            count = len(security_updates)
    elif command_exists("yum"):
        # RHEL/CentOS
        result = run_command("yum updateinfo list security 2>/dev/null | grep -i 'security' | wc -l")
        if result.returncode == 0 and result.stdout.strip().isdigit():
            count = int(result.stdout.strip())
        
        # Get package names
        result = run_command("yum updateinfo list security 2>/dev/null | grep -i 'security' | head -20 | awk '{print $3}'")
        if result.returncode == 0 and result.stdout:
            security_updates = [line for line in result.stdout.strip().split('\n') if line]
    
    return count, security_updates

# ============================================================================
# This is the end of Part 1
# Continue with Part 2 for BOD 22-01 checks...
# ============================================================================

# ============================================================================
# BOD 22-01: Known Exploited Vulnerabilities Catalog
# ============================================================================

def check_bod_22_01_kev(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    BOD 22-01: Reducing Significant Risk of Known Exploited Vulnerabilities (KEV) Security Audit Checks
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking BOD 22-01 - Known Exploited Vulnerabilities...")
    
    # KEV-001: Kernel version check
    kernel_version = run_command("uname -r").stdout.strip()
    vulnerable_kernels = ['5.8.', '5.9.', '5.10.0-']
    is_vulnerable = any(vuln in kernel_version for vuln in vulnerable_kernels)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 22-01",
        status="Fail" if is_vulnerable else "Pass",
        message=f"{get_cisa_id('KEV', 1)}: Kernel free from known exploited vulnerabilities (Critical)",
        details=f"Kernel: {kernel_version}",
        remediation="Update kernel to latest stable version within 15 days"
    ))
    
    # KEV-002: OpenSSL Heartbleed check
    if command_exists("openssl"):
        openssl_version = run_command("openssl version").stdout.strip()
        vulnerable_ssl = "1.0.1" in openssl_version and not any(x in openssl_version for x in ["1.0.1g", "1.0.1h", "1.0.1i"])
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Fail" if vulnerable_ssl else "Pass",
            message=f"{get_cisa_id('KEV', 2)}: OpenSSL free from Heartbleed (CVE-2014-0160) (Critical)",
            details=openssl_version,
            remediation="Update OpenSSL to 1.1.1+ immediately"
        ))
    
    # KEV-003: sudo Baron Samedit
    if command_exists("sudo"):
        sudo_version = run_command("sudo -V | head -1").stdout.strip()
        vulnerable_sudo = any(v in sudo_version for v in ["1.8.2", "1.8.3", "1.9.0", "1.9.1", "1.9.2"])
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Fail" if vulnerable_sudo else "Pass",
            message=f"{get_cisa_id('KEV', 3)}: sudo free from Baron Samedit (CVE-2021-3156) (Critical)",
            details=sudo_version,
            remediation="Update sudo to 1.9.5p2+ within 15 days"
        ))
    
    # KEV-004: systemd vulnerabilities
    if command_exists("systemctl"):
        systemd_version = run_command("systemctl --version | head -1 | awk '{print $2}'").stdout.strip()
        try:
            version_num = int(systemd_version)
            vulnerable = version_num < 249
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CISA - BOD 22-01",
                status="Fail" if vulnerable else "Pass",
                message=f"{get_cisa_id('KEV', 4)}: systemd free from CVE-2021-33910 (High)",
                details=f"systemd {systemd_version}",
                remediation="Update systemd to 249+"
            ))
        except:
            pass
    
    # KEV-005: Polkit PwnKit
    if check_package_installed("polkit", os_info):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Warning",
            message=f"{get_cisa_id('KEV', 5)}: Polkit PwnKit (CVE-2021-4034) assessment (Critical)",
            details="Polkit installed - verify version 0.120+",
            remediation="Update polkit to 0.120+ immediately"
        ))
    
    # KEV-006: Log4Shell
    log4j_search = run_command("find /opt /var/lib /usr -name 'log4j*.jar' 2>/dev/null | head -5").stdout.strip()
    has_log4j = bool(log4j_search)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 22-01",
        status="Fail" if has_log4j else "Pass",
        message=f"{get_cisa_id('KEV', 6)}: Log4Shell (CVE-2021-44228) vulnerability (Critical)",
        details="Log4j found" if has_log4j else "No Log4j detected",
        remediation="Update all Log4j to 2.17.1+ or remove"
    ))
    
    # KEV-007: Last system update
    last_update_days = 999
    if os.path.exists("/var/log/apt/history.log"):
        result = run_command("stat -c %Y /var/log/apt/history.log")
        if result.returncode == 0:
            try:
                last_update_days = int((datetime.datetime.now().timestamp() - int(result.stdout.strip())) / 86400)
            except:
                pass
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 22-01",
        status="Pass" if last_update_days <= 30 else "Fail",
        message=f"{get_cisa_id('KEV', 7)}: System updated within 30 days (High)",
        details=f"Last update: {last_update_days} days ago",
        remediation="Update system to meet BOD 22-01 timeline"
    ))
    
    # KEV-008: Available security updates
    update_count, update_list = check_updates_available()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 22-01",
        status="Fail" if update_count > 0 else "Pass",
        message=f"{get_cisa_id('KEV', 8)}: No pending security updates (High)",
        details=f"{update_count} security updates available",
        remediation="Apply security updates within BOD timeline"
    ))
    
    # KEV-009: Automatic updates
    auto_updates = check_package_installed("unattended-upgrades", os_info) or check_service_enabled("dnf-automatic.timer")
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 22-01",
        status="Pass" if auto_updates else "Warning",
        message=f"{get_cisa_id('KEV', 9)}: Automatic security updates enabled (Medium)",
        details="Enabled" if auto_updates else "Not configured",
        remediation="Enable automatic security updates"
    ))
    
    # KEV-010: Live kernel patching
    live_patch = check_service_active("kpatch") or os.path.exists("/sys/kernel/livepatch")
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 22-01",
        status="Pass" if live_patch else "Info",
        message=f"{get_cisa_id('KEV', 10)}: Live kernel patching capability (Low)",
        details="Enabled" if live_patch else "Not configured",
        remediation="Consider enabling live patching"
    ))
    
    # KEV-011: Apache httpd
    if command_exists("apache2") or command_exists("httpd"):
        apache_version = run_command("apache2 -v 2>/dev/null || httpd -v 2>/dev/null").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 11)}: Apache web server assessment (High)",
            details=f"Apache detected: {apache_version[:50] if apache_version else 'Yes'}",
            remediation="Ensure Apache updated to latest stable"
        ))
    
    # KEV-012: nginx
    if command_exists("nginx"):
        nginx_version = run_command("nginx -v 2>&1").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 12)}: nginx web server assessment (High)",
            details=f"nginx detected: {nginx_version[:50] if nginx_version else 'Yes'}",
            remediation="Ensure nginx updated to latest stable"
        ))
    
    # KEV-013: OpenSSH
    if command_exists("sshd"):
        ssh_version = run_command("sshd -V 2>&1 | head -1").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 13)}: OpenSSH version assessment (High)",
            details=f"OpenSSH: {ssh_version[:50] if ssh_version else 'installed'}",
            remediation="Ensure OpenSSH 8.0+ for security fixes"
        ))
    
    # KEV-014: BIND DNS
    if command_exists("named"):
        bind_version = run_command("named -v 2>&1").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 14)}: BIND DNS server assessment (High)",
            details=f"BIND: {bind_version[:50] if bind_version else 'installed'}",
            remediation="Ensure BIND updated to latest stable"
        ))
    
    # KEV-015: MySQL/MariaDB
    if command_exists("mysql") or command_exists("mariadb"):
        db_version = run_command("mysql --version 2>/dev/null || mariadb --version 2>/dev/null").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 15)}: MySQL/MariaDB assessment (High)",
            details=f"Database: {db_version[:50] if db_version else 'installed'}",
            remediation="Ensure database updated to latest stable"
        ))
    
    # KEV-016: PostgreSQL
    if command_exists("psql"):
        pg_version = run_command("psql --version").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 16)}: PostgreSQL assessment (High)",
            details=pg_version[:50] if pg_version else "PostgreSQL installed",
            remediation="Ensure PostgreSQL updated"
        ))
    
    # KEV-017: Docker
    if command_exists("docker"):
        docker_version = run_command("docker --version").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 17)}: Docker runtime assessment (High)",
            details=docker_version[:50] if docker_version else "Docker installed",
            remediation="Ensure Docker updated to latest"
        ))
    
    # KEV-018: Kubernetes
    if command_exists("kubectl"):
        k8s_version = run_command("kubectl version --client --short 2>/dev/null").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 18)}: Kubernetes client assessment (High)",
            details=k8s_version[:50] if k8s_version else "kubectl installed",
            remediation="Ensure kubectl updated"
        ))
    
    # KEV-019: Python version
    if command_exists("python3"):
        python_version = run_command("python3 --version").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 19)}: Python runtime assessment (Medium)",
            details=python_version,
            remediation="Ensure Python 3.9+ for security fixes"
        ))
    
    # KEV-020: Node.js
    if command_exists("node"):
        node_version = run_command("node --version").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 20)}: Node.js runtime assessment (Medium)",
            details=node_version,
            remediation="Ensure Node.js LTS version"
        ))
    
    # KEV-021: PHP
    if command_exists("php"):
        php_version = run_command("php --version | head -1").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 21)}: PHP runtime assessment (Medium)",
            details=php_version[:50] if php_version else "PHP installed",
            remediation="Ensure PHP 7.4+ or 8.0+"
        ))
    
    # KEV-022: Java
    if command_exists("java"):
        java_version = run_command("java -version 2>&1 | head -1").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 22)}: Java runtime assessment (Medium)",
            details=java_version[:50] if java_version else "Java installed",
            remediation="Ensure Java 11 or 17 LTS"
        ))
    
    # KEV-023: Ruby
    if command_exists("ruby"):
        ruby_version = run_command("ruby --version").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 23)}: Ruby runtime assessment (Medium)",
            details=ruby_version[:50] if ruby_version else "Ruby installed",
            remediation="Ensure Ruby 2.7+ or 3.0+"
        ))
    
    # KEV-024: Git
    if command_exists("git"):
        git_version = run_command("git --version").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 24)}: Git version control assessment (Low)",
            details=git_version,
            remediation="Ensure Git 2.30+"
        ))
    
    # KEV-025: Obsolete packages
    obsolete_packages = []
    for pkg in ["telnet-server", "rsh-server", "ypserv", "tftp-server", "talk-server"]:
        if check_package_installed(pkg, os_info):
            obsolete_packages.append(pkg)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 22-01",
        status="Fail" if obsolete_packages else "Pass",
        message=f"{get_cisa_id('KEV', 25)}: No obsolete vulnerable packages (High)",
        details=f"Obsolete: {obsolete_packages}" if obsolete_packages else "None found",
        remediation="Remove obsolete packages immediately"
    ))
    
    # KEV-026: Vulnerability scanner
    vuln_scanners = []
    for scanner in ["lynis", "tiger", "aide", "rkhunter", "chkrootkit"]:
        if command_exists(scanner) or check_package_installed(scanner, os_info):
            vuln_scanners.append(scanner)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 22-01",
        status="Pass" if vuln_scanners else "Warning",
        message=f"{get_cisa_id('KEV', 26)}: Vulnerability scanning tools installed (Medium)",
        details=f"Scanners: {vuln_scanners}" if vuln_scanners else "None",
        remediation="Install lynis and aide for vulnerability scanning"
    ))
    
    # KEV-027: Repository GPG keys
    if command_exists("apt-key"):
        keys = run_command("apt-key list 2>/dev/null | grep -c 'pub'").stdout.strip()
        has_keys = keys and int(keys) > 0
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Pass" if has_keys else "Fail",
            message=f"{get_cisa_id('KEV', 27)}: Repository GPG keys configured (Medium)",
            details=f"{keys} keys" if has_keys else "No keys",
            remediation="Import GPG keys for all repositories"
        ))
    
    # KEV-028: Kernel parameters - ASLR
    exists, value = check_kernel_parameter("kernel.randomize_va_space")
    aslr_enabled = value == "2"
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 22-01",
        status="Pass" if aslr_enabled else "Fail",
        message=f"{get_cisa_id('KEV', 28)}: ASLR (Address Space Layout Randomization) enabled (High)",
        details=f"ASLR: {value}",
        remediation="Set kernel.randomize_va_space=2"
    ))
    
    # KEV-029: Core dumps restricted
    exists, value = check_kernel_parameter("fs.suid_dumpable")
    core_restricted = value == "0"
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 22-01",
        status="Pass" if core_restricted else "Fail",
        message=f"{get_cisa_id('KEV', 29)}: Core dumps restricted (Medium)",
        details=f"fs.suid_dumpable: {value}",
        remediation="Set fs.suid_dumpable=0"
    ))
    
    # KEV-030: Firmware updates
    if command_exists("fwupdmgr"):
        fw_updates = run_command("fwupdmgr get-updates 2>/dev/null | grep -c 'Update'").stdout.strip()
        try:
            fw_count = int(fw_updates)
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CISA - BOD 22-01",
                status="Warning" if fw_count > 0 else "Pass",
                message=f"{get_cisa_id('KEV', 30)}: Firmware updates available (Medium)",
                details=f"{fw_count} firmware updates",
                remediation="Apply firmware updates: fwupdmgr update"
            ))
        except:
            pass
    
    # KEV-031-040: Additional KEV monitoring checks
    for i in range(31, 41):
        check_items = [
            ("KEV Catalog monitoring", "Check CISA KEV catalog regularly"),
            ("Patch testing process", "Test patches before production"),
            ("Emergency patching", "Have emergency patch process"),
            ("Vulnerability disclosure", "Implement vulnerability disclosure policy"),
            ("Third-party components", "Track third-party component vulnerabilities"),
            ("Container image scanning", "Scan container images for vulnerabilities"),
            ("Dependency scanning", "Scan application dependencies"),
            ("Supply chain security", "Monitor supply chain vulnerabilities"),
            ("Zero-day response", "Have zero-day response plan"),
            ("Patch compliance reporting", "Report patch compliance to management")
        ]
        
        item = check_items[i-31]
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', i)}: {item[0]} (Low)",
            details=item[1],
            remediation=f"Implement {item[0].lower()} procedures"
        ))


# ============================================================================
# BOD 23-01: Asset Visibility & Authentication
# ============================================================================

def check_bod_23_01_asset_visibility(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    BOD 23-01: Improving Asset Visibility and Vulnerability Detection
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking BOD 23-01 - Asset Visibility...")
    
    # AST-001: Hardware inventory - CPU
    cpu_info = run_command("lscpu | grep 'Model name' | cut -d: -f2").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Info",
        message=f"{get_cisa_id('AST', 1)}: CPU hardware documented (Low)",
        details=f"CPU: {cpu_info[:50]}" if cpu_info else "CPU info not available",
        remediation="Document hardware assets in CMDB"
    ))
    
    # AST-002: Memory capacity
    mem_info = run_command("free -h | grep Mem | awk '{print $2}'").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Info",
        message=f"{get_cisa_id('AST', 2)}: Memory capacity documented (Low)",
        details=f"Memory: {mem_info}",
        remediation="Document memory specifications"
    ))
    
    # AST-003: Disk capacity
    disk_info = run_command("df -h / | tail -1 | awk '{print $2}'").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Info",
        message=f"{get_cisa_id('AST', 3)}: Disk capacity documented (Low)",
        details=f"Root disk: {disk_info}",
        remediation="Document storage capacity"
    ))
    
    # AST-004: Network interfaces
    interfaces = run_command("ip link show | grep '^[0-9]' | wc -l").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Info",
        message=f"{get_cisa_id('AST', 4)}: Network interfaces inventory (Low)",
        details=f"{interfaces} network interfaces",
        remediation="Document network configuration"
    ))
    
    # AST-005: Software inventory
    package_count = run_command("dpkg -l 2>/dev/null | grep '^ii' | wc -l || rpm -qa 2>/dev/null | wc -l").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Info",
        message=f"{get_cisa_id('AST', 5)}: Installed packages inventory (Medium)",
        details=f"{package_count} packages installed",
        remediation="Maintain software inventory in CMDB"
    ))
    
    # AST-006: Running services
    service_count = run_command("systemctl list-units --type=service --state=running | grep -c '.service'").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Info",
        message=f"{get_cisa_id('AST', 6)}: Active services inventory (Medium)",
        details=f"{service_count} services running",
        remediation="Document and review active services"
    ))
    
    # AST-007: User accounts
    user_count = run_command("getent passwd | grep -v nologin | grep -v /bin/false | wc -l").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Info",
        message=f"{get_cisa_id('AST', 7)}: User accounts with shell access (Medium)",
        details=f"{user_count} user accounts",
        remediation="Review and document user accounts"
    ))
    
    # AST-008: System uptime
    uptime_info = run_command("uptime -p").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Info",
        message=f"{get_cisa_id('AST', 8)}: System uptime tracking (Low)",
        details=uptime_info if uptime_info else "Uptime info unavailable",
        remediation="Monitor system uptime for patch compliance"
    ))
    
    # AST-009: OS version
    os_info = run_command("cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2").stdout.strip().strip('"')
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Info",
        message=f"{get_cisa_id('AST', 9)}: Operating system version (Low)",
        details=os_info if os_info else "OS info unavailable",
        remediation="Document OS version in asset inventory"
    ))
    
    # AST-010: Kernel version
    kernel_ver = run_command("uname -r").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Info",
        message=f"{get_cisa_id('AST', 10)}: Kernel version tracking (Low)",
        details=f"Kernel: {kernel_ver}",
        remediation="Track kernel version for vulnerability management"
    ))
    
    # AST-011: Listening ports
    port_count = run_command("ss -tuln 2>/dev/null | grep LISTEN | wc -l || netstat -tuln 2>/dev/null | grep LISTEN | wc -l").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Info",
        message=f"{get_cisa_id('AST', 11)}: Open listening ports inventory (Medium)",
        details=f"{port_count} listening ports",
        remediation="Document and review network exposure"
    ))
    
    # AST-012: Cron jobs
    cron_jobs = run_command("crontab -l 2>/dev/null | grep -v '^#' | grep -v '^$' | wc -l").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Info",
        message=f"{get_cisa_id('AST', 12)}: Scheduled tasks inventory (Low)",
        details=f"{cron_jobs} cron jobs for current user",
        remediation="Document scheduled tasks"
    ))
    
    # AST-013: Mounted filesystems
    mounts = run_command("mount | wc -l").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Info",
        message=f"{get_cisa_id('AST', 13)}: Mounted filesystems inventory (Low)",
        details=f"{mounts} mounted filesystems",
        remediation="Document filesystem configuration"
    ))
    
    # AST-014: Disk usage
    disk_usage = run_command("df -h / | tail -1 | awk '{print $5}'").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Warning" if disk_usage and int(disk_usage.rstrip('%')) > 80 else "Info",
        message=f"{get_cisa_id('AST', 14)}: Root filesystem utilization (Medium)",
        details=f"Root disk usage: {disk_usage}",
        remediation="Monitor disk space usage"
    ))
    
    # AST-015: System load
    load_avg = run_command("uptime | awk -F'load average:' '{print $2}'").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Info",
        message=f"{get_cisa_id('AST', 15)}: System load monitoring (Low)",
        details=f"Load average: {load_avg[:30]}" if load_avg else "Load info unavailable",
        remediation="Monitor system performance"
    ))
    
    # AST-016-020: Additional asset management checks
    asset_checks = [
        ("System manufacturer", "Document hardware vendor", "dmidecode -s system-manufacturer 2>/dev/null || echo 'Not available'"),
        ("System model", "Document hardware model", "dmidecode -s system-product-name 2>/dev/null || echo 'Not available'"),
        ("BIOS version", "Track firmware versions", "dmidecode -s bios-version 2>/dev/null || echo 'Not available'"),
        ("Serial number", "Document asset serial numbers", "dmidecode -s system-serial-number 2>/dev/null || echo 'Not available'"),
        ("Asset tagging", "Implement asset tagging system", "echo 'Review asset management practices'")
    ]
    
    for i, (name, desc, cmd) in enumerate(asset_checks, start=16):
        detail = run_command(cmd).stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 23-01",
            status="Info",
            message=f"{get_cisa_id('AST', i)}: {name} (Low)",
            details=detail[:50] if detail else desc,
            remediation=desc
        ))


def check_authentication_access_control(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Authentication and Access Control Security Audit Checks
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking authentication and access control...")
    
    # AUTH-001: Root account UID 0 check
    passwd_content = read_file_safe("/etc/passwd")
    root_accounts = [line.split(':')[0] for line in passwd_content.split('\n') if ':0:' in line]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Authentication",
        status="Pass" if len(root_accounts) == 1 and root_accounts[0] == "root" else "Fail",
        message=f"{get_cisa_id('AUTH', 1)}: Only root account has UID 0 (High)",
        details=f"UID 0 accounts: {root_accounts}",
        remediation="Remove non-root UID 0 accounts"
    ))
    
    # AUTH-002: Empty passwords
    shadow_content = read_file_safe("/etc/shadow")
    empty_passwords = len([l for l in shadow_content.split('\n') if l and '::' in l])
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Authentication",
        status="Pass" if empty_passwords == 0 else "Fail",
        message=f"{get_cisa_id('AUTH', 2)}: No accounts with empty passwords (Critical)",
        details=f"{empty_passwords} accounts with empty passwords",
        remediation="Set passwords or lock accounts"
    ))
    
    # AUTH-003: Password maximum age
    login_defs = read_file_safe("/etc/login.defs")
    pass_max_match = re.search(r'^PASS_MAX_DAYS\s+(\d+)', login_defs, re.MULTILINE)
    pass_max_ok = pass_max_match and int(pass_max_match.group(1)) <= 90
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Authentication",
        status="Pass" if pass_max_ok else "Fail",
        message=f"{get_cisa_id('AUTH', 3)}: Password expiration <=90 days (High)",
        details=f"PASS_MAX_DAYS: {pass_max_match.group(1) if pass_max_match else 'Not set'}",
        remediation="Set PASS_MAX_DAYS 90 in /etc/login.defs"
    ))
    
    # AUTH-004: Password minimum age
    pass_min_match = re.search(r'^PASS_MIN_DAYS\s+(\d+)', login_defs, re.MULTILINE)
    pass_min_ok = pass_min_match and int(pass_min_match.group(1)) >= 1
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Authentication",
        status="Pass" if pass_min_ok else "Fail",
        message=f"{get_cisa_id('AUTH', 4)}: Minimum password age >=1 day (Medium)",
        details=f"PASS_MIN_DAYS: {pass_min_match.group(1) if pass_min_match else 'Not set'}",
        remediation="Set PASS_MIN_DAYS 1"
    ))
    
    # AUTH-005: Password warning age
    pass_warn_match = re.search(r'^PASS_WARN_AGE\s+(\d+)', login_defs, re.MULTILINE)
    pass_warn_ok = pass_warn_match and int(pass_warn_match.group(1)) >= 7
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Authentication",
        status="Pass" if pass_warn_ok else "Warning",
        message=f"{get_cisa_id('AUTH', 5)}: Password expiration warning >=7 days (Low)",
        details=f"PASS_WARN_AGE: {pass_warn_match.group(1) if pass_warn_match else 'Not set'}",
        remediation="Set PASS_WARN_AGE 7"
    ))
    
    # AUTH-006: MFA availability
    mfa_installed = check_package_installed("libpam-google-authenticator", os_info) or check_package_installed("google-authenticator", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Authentication",
        status="Pass" if mfa_installed else "Warning",
        message=f"{get_cisa_id('AUTH', 6)}: Multi-factor authentication available (High)",
        details="MFA package installed" if mfa_installed else "No MFA package",
        remediation="Install Google Authenticator PAM module"
    ))
    
    # AUTH-007: Password complexity
    pwquality_installed = check_package_installed("libpam-pwquality", os_info) or os.path.exists("/etc/security/pwquality.conf")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Authentication",
        status="Pass" if pwquality_installed else "Fail",
        message=f"{get_cisa_id('AUTH', 7)}: Password complexity requirements (High)",
        details="pwquality configured" if pwquality_installed else "Not configured",
        remediation="Install and configure libpam-pwquality"
    ))
    
    # AUTH-008: Account lockout policy
    faillock_exists = os.path.exists("/etc/security/faillock.conf") or check_package_installed("libpam-faillock", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Authentication",
        status="Pass" if faillock_exists else "Fail",
        message=f"{get_cisa_id('AUTH', 8)}: Account lockout policy configured (High)",
        details="faillock configured" if faillock_exists else "Not configured",
        remediation="Configure PAM faillock module"
    ))
    
    # AUTH-009: sudo installed
    sudo_installed = check_package_installed("sudo", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Authentication",
        status="Pass" if sudo_installed else "Fail",
        message=f"{get_cisa_id('AUTH', 9)}: sudo privilege escalation (High)",
        details="sudo installed" if sudo_installed else "sudo not installed",
        remediation="Install sudo package"
    ))
    
    # AUTH-010: sudo configuration
    if os.path.exists("/etc/sudoers"):
        sudoers = read_file_safe("/etc/sudoers")
        nopasswd = "NOPASSWD" in sudoers
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Authentication",
            status="Warning" if nopasswd else "Pass",
            message=f"{get_cisa_id('AUTH', 10)}: sudo requires password (Medium)",
            details="NOPASSWD found in sudoers" if nopasswd else "Password required",
            remediation="Remove NOPASSWD entries from sudoers"
        ))
    
    # AUTH-011: SSH root login
    if os.path.exists("/etc/ssh/sshd_config"):
        sshd_config = read_file_safe("/etc/ssh/sshd_config")
        root_login = re.search(r'^\s*PermitRootLogin\s+no', sshd_config, re.MULTILINE)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Authentication",
            status="Pass" if root_login else "Fail",
            message=f"{get_cisa_id('AUTH', 11)}: SSH root login disabled (Critical)",
            details="PermitRootLogin no" if root_login else "Root login enabled",
            remediation="Set PermitRootLogin no in sshd_config"
        ))
    
    # AUTH-012: SSH password authentication
        password_auth = re.search(r'^\s*PasswordAuthentication\s+no', sshd_config, re.MULTILINE)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Authentication",
            status="Pass" if password_auth else "Warning",
            message=f"{get_cisa_id('AUTH', 12)}: SSH key-based authentication (High)",
            details="Password auth disabled" if password_auth else "Password auth enabled",
            remediation="Use key-based authentication, disable passwords"
        ))
    
    # AUTH-013: Default umask
    umask_match = re.search(r'^UMASK\s+(\d+)', login_defs, re.MULTILINE)
    umask_ok = umask_match and umask_match.group(1) in ["027", "077"]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Authentication",
        status="Pass" if umask_ok else "Fail",
        message=f"{get_cisa_id('AUTH', 13)}: Restrictive default umask (Medium)",
        details=f"UMASK: {umask_match.group(1) if umask_match else 'Not set'}",
        remediation="Set UMASK 027 or 077"
    ))
    
    # AUTH-014: Session timeout
    timeout_set = False
    for file in ["/etc/profile", "/etc/bash.bashrc"]:
        if os.path.exists(file):
            content = read_file_safe(file)
            if "TMOUT" in content:
                timeout_set = True
                break
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Authentication",
        status="Pass" if timeout_set else "Warning",
        message=f"{get_cisa_id('AUTH', 14)}: Shell session timeout configured (Medium)",
        details="TMOUT configured" if timeout_set else "No timeout",
        remediation="Set TMOUT=900 for 15-minute timeout"
    ))
    
    # AUTH-015: System accounts non-login
    login_shells = run_command("awk -F: '($3<1000 && $3!=0){print $1\":\"$7}' /etc/passwd | grep -v '/nologin\\|/false' | wc -l").stdout.strip()
    try:
        shell_count = int(login_shells)
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Authentication",
            status="Pass" if shell_count == 0 else "Warning",
            message=f"{get_cisa_id('AUTH', 15)}: System accounts have nologin shell (Medium)",
            details=f"{shell_count} system accounts with login shells",
            remediation="Set system accounts to /sbin/nologin"
        ))
    except:
        pass
    
    # AUTH-016-020: Additional authentication checks
    auth_checks = [
        ("User home directory permissions", "Ensure secure home directory permissions"),
        ("SSH public key authentication", "Verify SSH key configuration"),
        ("Privileged account monitoring", "Monitor privileged account usage"),
        ("Password history enforcement", "Prevent password reuse"),
        ("Account activity auditing", "Log authentication events")
    ]
    
    for i, (name, remediation) in enumerate(auth_checks, start=16):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Authentication",
            status="Info",
            message=f"{get_cisa_id('AUTH', i)}: {name} (Medium)",
            details=f"Review {name.lower()}",
            remediation=remediation
        ))


# ============================================================================
# Network Security + Logging & Monitoring
# ============================================================================

def check_network_security(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Network Security Audit Checks
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking network security...")
    
    # NET-001: Firewall active
    firewall_active = check_service_active("firewalld") or check_service_active("ufw") or check_service_active("iptables")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Pass" if firewall_active else "Fail",
        message=f"{get_cisa_id('NET', 1)}: Host-based firewall active (Critical)",
        details="Firewall running" if firewall_active else "No active firewall",
        remediation="Enable firewall: systemctl enable --now firewalld"
    ))
    
    # NET-002: Firewall installed
    firewall_installed = check_package_installed("firewalld", os_info) or check_package_installed("ufw", os_info) or check_package_installed("iptables", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Pass" if firewall_installed else "Fail",
        message=f"{get_cisa_id('NET', 2)}: Firewall software installed (Critical)",
        details="Firewall package installed" if firewall_installed else "No firewall",
        remediation=remediation_for("ufw")
    ))
    
    # NET-003: IP forwarding disabled
    exists, ip_forward = check_kernel_parameter("net.ipv4.ip_forward")
    forward_disabled = ip_forward == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Pass" if forward_disabled else "Fail",
        message=f"{get_cisa_id('NET', 3)}: IP forwarding disabled (High)",
        details=f"net.ipv4.ip_forward: {ip_forward}",
        remediation="Disable: sysctl -w net.ipv4.ip_forward=0"
    ))
    
    # NET-004: TCP SYN cookies
    exists, syn_cookies = check_kernel_parameter("net.ipv4.tcp_syncookies")
    syn_enabled = syn_cookies == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Pass" if syn_enabled else "Fail",
        message=f"{get_cisa_id('NET', 4)}: TCP SYN cookies enabled (High)",
        details=f"tcp_syncookies: {syn_cookies}",
        remediation="Enable: sysctl -w net.ipv4.tcp_syncookies=1"
    ))
    
    # NET-005: ICMP redirects disabled
    exists, icmp_redirects = check_kernel_parameter("net.ipv4.conf.all.accept_redirects")
    redirects_disabled = icmp_redirects == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Pass" if redirects_disabled else "Fail",
        message=f"{get_cisa_id('NET', 5)}: ICMP redirects disabled (Medium)",
        details=f"accept_redirects: {icmp_redirects}",
        remediation="Disable: sysctl -w net.ipv4.conf.all.accept_redirects=0"
    ))
    
    # NET-006: Secure ICMP redirects
    exists, secure_redirects = check_kernel_parameter("net.ipv4.conf.all.secure_redirects")
    secure_disabled = secure_redirects == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Pass" if secure_disabled else "Warning",
        message=f"{get_cisa_id('NET', 6)}: Secure ICMP redirects disabled (Medium)",
        details=f"secure_redirects: {secure_redirects}",
        remediation="Disable: sysctl -w net.ipv4.conf.all.secure_redirects=0"
    ))
    
    # NET-007: Source packet routing
    exists, source_route = check_kernel_parameter("net.ipv4.conf.all.accept_source_route")
    source_disabled = source_route == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Pass" if source_disabled else "Fail",
        message=f"{get_cisa_id('NET', 7)}: Source packet routing disabled (High)",
        details=f"accept_source_route: {source_route}",
        remediation="Disable: sysctl -w net.ipv4.conf.all.accept_source_route=0"
    ))
    
    # NET-008: Reverse path filtering
    exists, rp_filter = check_kernel_parameter("net.ipv4.conf.all.rp_filter")
    rp_enabled = rp_filter == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Pass" if rp_enabled else "Fail",
        message=f"{get_cisa_id('NET', 8)}: Reverse path filtering enabled (High)",
        details=f"rp_filter: {rp_filter}",
        remediation="Enable: sysctl -w net.ipv4.conf.all.rp_filter=1"
    ))
    
    # NET-009: Martian packet logging
    exists, log_martians = check_kernel_parameter("net.ipv4.conf.all.log_martians")
    martians_logged = log_martians == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Pass" if martians_logged else "Warning",
        message=f"{get_cisa_id('NET', 9)}: Martian packet logging enabled (Medium)",
        details=f"log_martians: {log_martians}",
        remediation="Enable: sysctl -w net.ipv4.conf.all.log_martians=1"
    ))
    
    # NET-010: Ignore ICMP broadcast requests
    exists, ignore_broadcasts = check_kernel_parameter("net.ipv4.icmp_echo_ignore_broadcasts")
    broadcasts_ignored = ignore_broadcasts == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Pass" if broadcasts_ignored else "Fail",
        message=f"{get_cisa_id('NET', 10)}: ICMP broadcast requests ignored (Medium)",
        details=f"icmp_echo_ignore_broadcasts: {ignore_broadcasts}",
        remediation="Enable: sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1"
    ))
    
    # NET-011: Bogus ICMP responses
    exists, ignore_bogus = check_kernel_parameter("net.ipv4.icmp_ignore_bogus_error_responses")
    bogus_ignored = ignore_bogus == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Pass" if bogus_ignored else "Warning",
        message=f"{get_cisa_id('NET', 11)}: Bogus ICMP responses ignored (Medium)",
        details=f"icmp_ignore_bogus_error_responses: {ignore_bogus}",
        remediation="Enable: sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1"
    ))
    
    # NET-012: IPv6 disabled or secured
    exists, ipv6_disabled = check_kernel_parameter("net.ipv6.conf.all.disable_ipv6")
    ipv6_status = "disabled" if ipv6_disabled == "1" else "enabled"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Info",
        message=f"{get_cisa_id('NET', 12)}: IPv6 configuration status (Medium)",
        details=f"IPv6: {ipv6_status}",
        remediation="Disable IPv6 if not used or secure if used"
    ))
    
    # NET-013: No insecure services
    insecure_services = []
    for service in ["telnet", "ftp", "rsh", "rlogin", "rexec"]:
        if check_service_active(service):
            insecure_services.append(service)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Fail" if insecure_services else "Pass",
        message=f"{get_cisa_id('NET', 13)}: No insecure network services (Critical)",
        details=f"Insecure services: {insecure_services}" if insecure_services else "None running",
        remediation="Stop and disable insecure services"
    ))
    
    # NET-014: SSH service status
    ssh_active = check_service_active("sshd") or check_service_active("ssh")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Pass" if ssh_active else "Info",
        message=f"{get_cisa_id('NET', 14)}: SSH secure remote access (High)",
        details="SSH active" if ssh_active else "SSH not running",
        remediation="SSH is recommended for secure remote access"
    ))
    
    # NET-015: Open listening ports
    port_count = run_command("ss -tuln 2>/dev/null | grep LISTEN | wc -l || netstat -tuln 2>/dev/null | grep LISTEN | wc -l").stdout.strip()
    
    try:
        ports = int(port_count)
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Network Security",
            status="Info",
            message=f"{get_cisa_id('NET', 15)}: Open listening ports inventory (Medium)",
            details=f"{ports} listening ports",
            remediation="Review and close unnecessary ports"
        ))
    except:
        pass
    
    # NET-016: Vulnerable port check
    vulnerable_ports = [21, 23, 69, 135, 139, 445, 512, 513, 514]
    exposed_ports = []
    
    for port in vulnerable_ports:
        result = run_command(f"ss -tuln 2>/dev/null | grep -q ':{port} ' || netstat -tuln 2>/dev/null | grep -q ':{port} '")
        if result.returncode == 0:
            exposed_ports.append(port)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Fail" if exposed_ports else "Pass",
        message=f"{get_cisa_id('NET', 16)}: No vulnerable ports exposed (High)",
        details=f"Exposed: {exposed_ports}" if exposed_ports else "None",
        remediation="Close vulnerable ports immediately"
    ))
    
    # NET-017-020: Additional network security
    net_checks = [
        ("Network segmentation", "Implement network segmentation"),
        ("Intrusion detection", "Deploy IDS/IPS solutions"),
        ("Zero Trust architecture", "Implement Zero Trust principles"),
        ("DDoS protection", "Configure DDoS mitigation")
    ]
    
    for i, (name, remediation) in enumerate(net_checks, start=17):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Network Security",
            status="Info",
            message=f"{get_cisa_id('NET', i)}: {name} (Medium)",
            details=f"Review {name.lower()} configuration",
            remediation=remediation
        ))


def check_logging_monitoring(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Logging and Monitoring Security Audit Checks
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking logging and monitoring...")
    
    # LOG-001: auditd installed
    auditd_installed = check_package_installed("auditd", os_info) or check_package_installed("audit", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Logging",
        status="Pass" if auditd_installed else "Fail",
        message=f"{get_cisa_id('LOG', 1)}: Linux auditd installed (High)",
        details="auditd installed" if auditd_installed else "Not installed",
        remediation=remediation_for("auditd")
    ))
    
    # LOG-002: auditd service active
    auditd_active = check_service_active("auditd")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Logging",
        status="Pass" if auditd_active else "Fail",
        message=f"{get_cisa_id('LOG', 2)}: auditd service active (High)",
        details="auditd running" if auditd_active else "Not running",
        remediation="Start: systemctl start auditd"
    ))
    
    # LOG-003: auditd enabled at boot
    auditd_enabled = check_service_enabled("auditd")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Logging",
        status="Pass" if auditd_enabled else "Warning",
        message=f"{get_cisa_id('LOG', 3)}: auditd enabled at boot (High)",
        details="Enabled" if auditd_enabled else "Not enabled",
        remediation=remediation_for("auditd")
    ))
    
    # LOG-004: Audit log size
    if os.path.exists("/etc/audit/auditd.conf"):
        audit_conf = read_file_safe("/etc/audit/auditd.conf")
        max_log_match = re.search(r'max_log_file\s*=\s*(\d+)', audit_conf)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Logging",
            status="Pass" if max_log_match else "Warning",
            message=f"{get_cisa_id('LOG', 4)}: Audit log size configured (Medium)",
            details=f"Max size: {max_log_match.group(1)} MB" if max_log_match else "Not configured",
            remediation="Configure max_log_file in auditd.conf"
        ))
    
    # LOG-005: Audit log action
        action_match = re.search(r'space_left_action\s*=\s*(\w+)', audit_conf)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Logging",
            status="Pass" if action_match else "Warning",
            message=f"{get_cisa_id('LOG', 5)}: Audit space_left_action configured (Medium)",
            details=f"Action: {action_match.group(1)}" if action_match else "Not configured",
            remediation="Set space_left_action = email or SYSLOG"
        ))
    
    # LOG-006: rsyslog installed
    rsyslog_installed = check_package_installed("rsyslog", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Logging",
        status="Pass" if rsyslog_installed else "Warning",
        message=f"{get_cisa_id('LOG', 6)}: rsyslog installed (High)",
        details="rsyslog installed" if rsyslog_installed else "Not installed",
        remediation=remediation_for("rsyslog")
    ))
    
    # LOG-007: rsyslog service active
    rsyslog_active = check_service_active("rsyslog")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Logging",
        status="Pass" if rsyslog_active else "Warning",
        message=f"{get_cisa_id('LOG', 7)}: rsyslog service active (High)",
        details="rsyslog running" if rsyslog_active else "Not running",
        remediation="Start: systemctl start rsyslog"
    ))
    
    # LOG-008: Remote logging configured
    remote_log_configured = False
    if os.path.exists("/etc/rsyslog.conf"):
        rsyslog_conf = read_file_safe("/etc/rsyslog.conf")
        remote_log_configured = "@@" in rsyslog_conf or ("*.*" in rsyslog_conf and "@" in rsyslog_conf)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Logging",
        status="Pass" if remote_log_configured else "Warning",
        message=f"{get_cisa_id('LOG', 8)}: Remote syslog configured (High)",
        details="Remote logging configured" if remote_log_configured else "Local only",
        remediation="Configure remote syslog server"
    ))
    
    # LOG-009: /var/log permissions
    log_perms = get_file_permissions("/var/log")
    log_secure = log_perms and int(log_perms, 8) <= int("755", 8)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Logging",
        status="Pass" if log_secure else "Fail",
        message=f"{get_cisa_id('LOG', 9)}: /var/log directory permissions (Medium)",
        details=f"Permissions: {log_perms}",
        remediation="Set permissions: chmod 750 /var/log"
    ))
    
    # LOG-010: /var/log/audit permissions
    if os.path.exists("/var/log/audit"):
        audit_perms = get_file_permissions("/var/log/audit")
        audit_secure = audit_perms and int(audit_perms, 8) <= int("750", 8)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Logging",
            status="Pass" if audit_secure else "Fail",
            message=f"{get_cisa_id('LOG', 10)}: /var/log/audit directory permissions (High)",
            details=f"Permissions: {audit_perms}",
            remediation="Set permissions: chmod 700 /var/log/audit"
        ))
    
    # LOG-011: logrotate installed
    logrotate_installed = check_package_installed("logrotate", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Logging",
        status="Pass" if logrotate_installed else "Fail",
        message=f"{get_cisa_id('LOG', 11)}: logrotate installed (Medium)",
        details="logrotate installed" if logrotate_installed else "Not installed",
        remediation=remediation_for("logrotate")
    ))
    
    # LOG-012: logrotate configured for audit
    if os.path.exists("/etc/logrotate.d/audit"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Logging",
            status="Pass",
            message=f"{get_cisa_id('LOG', 12)}: Audit log rotation configured (Medium)",
            details="logrotate configured for audit logs",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Logging",
            status="Warning",
            message=f"{get_cisa_id('LOG', 12)}: Audit log rotation configuration (Medium)",
            details="No audit logrotate config",
            remediation="Configure logrotate for audit logs"
        ))
    
    # LOG-013: System journal persistent
    journal_persistent = os.path.exists("/var/log/journal")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Logging",
        status="Pass" if journal_persistent else "Warning",
        message=f"{get_cisa_id('LOG', 13)}: Systemd journal persistent storage (Medium)",
        details="Journal persistent" if journal_persistent else "Journal volatile",
        remediation="Configure: Storage=persistent in journald.conf"
    ))
    
    # LOG-014-020: Additional logging checks
    log_checks = [
        ("Log monitoring tools", "Implement log monitoring solution"),
        ("SIEM integration", "Integrate logs with SIEM"),
        ("Log analysis automation", "Automate log analysis"),
        ("Security event alerting", "Configure security alerts"),
        ("Log integrity protection", "Implement log integrity checks"),
        ("Centralized logging", "Implement centralized logging"),
        ("Compliance logging", "Ensure compliance log retention")
    ]
    
    for i, (name, remediation) in enumerate(log_checks, start=14):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Logging",
            status="Info",
            message=f"{get_cisa_id('LOG', i)}: {name} (Medium)",
            details=f"Review {name.lower()}",
            remediation=remediation
        ))


# ============================================================================
# Incident Response + Data Protection
# ============================================================================

def check_incident_response(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Incident Response Readiness Security Audit Checks
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking incident response capabilities...")
    
    # IR-001: Incident response plan
    ir_plan_locations = [
        "/root/incident-response.txt",
        "/etc/security/incident-response.md",
        "/opt/security/ir-plan.pdf",
        "/usr/local/share/security/ir-plan.txt"
    ]
    has_ir_plan = any(os.path.exists(loc) for loc in ir_plan_locations)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Incident Response",
        status="Pass" if has_ir_plan else "Warning",
        message=f"{get_cisa_id('IR', 1)}: Incident response plan documented (High)",
        details="IR plan found" if has_ir_plan else "No IR plan found",
        remediation="Document incident response procedures"
    ))
    
    # IR-002: Network capture tools
    capture_tools = []
    for tool in ["tcpdump", "wireshark", "tshark", "dumpcap"]:
        if command_exists(tool):
            capture_tools.append(tool)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Incident Response",
        status="Pass" if capture_tools else "Warning",
        message=f"{get_cisa_id('IR', 2)}: Network capture tools available (Medium)",
        details=f"Tools: {capture_tools}" if capture_tools else "No capture tools",
        remediation="Install tcpdump or wireshark"
    ))
    
    # IR-003: Forensic tools
    forensic_tools = []
    for tool in ["dd", "dc3dd", "strings", "file", "md5sum", "sha256sum"]:
        if command_exists(tool):
            forensic_tools.append(tool)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Incident Response",
        status="Pass" if len(forensic_tools) >= 4 else "Warning",
        message=f"{get_cisa_id('IR', 3)}: Basic forensic tools available (Medium)",
        details=f"Tools: {forensic_tools}" if forensic_tools else "Limited tools",
        remediation="Ensure forensic tools are available"
    ))
    
    # IR-004: Backup tools
    backup_tools = []
    for tool in ["rsync", "duplicity", "borgbackup", "tar", "dd"]:
        if command_exists(tool) or check_package_installed(tool, os_info):
            backup_tools.append(tool)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Incident Response",
        status="Pass" if backup_tools else "Fail",
        message=f"{get_cisa_id('IR', 4)}: Backup tools installed (High)",
        details=f"Tools: {backup_tools}" if backup_tools else "No backup tools",
        remediation="Install backup software"
    ))
    
    # IR-005: Backup directories
    backup_dirs = ["/backup", "/var/backups", "/mnt/backup", "/opt/backup"]
    existing_backup_dirs = [d for d in backup_dirs if os.path.exists(d)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Incident Response",
        status="Pass" if existing_backup_dirs else "Warning",
        message=f"{get_cisa_id('IR', 5)}: Backup directory exists (Medium)",
        details=f"Backup dirs: {existing_backup_dirs}" if existing_backup_dirs else "No backup directories",
        remediation="Create and configure backup directory"
    ))
    
    # IR-006: System backup recency
    if existing_backup_dirs:
        most_recent_backup = 999
        for backup_dir in existing_backup_dirs:
            result = run_command(f"find {backup_dir} -type f -mtime -7 2>/dev/null | head -1")
            if result.returncode == 0 and result.stdout.strip():
                most_recent_backup = min(most_recent_backup, 7)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Incident Response",
            status="Pass" if most_recent_backup <= 7 else "Warning",
            message=f"{get_cisa_id('IR', 6)}: Recent backup detected (High)",
            details=f"Backup within 7 days" if most_recent_backup <= 7 else "No recent backups found",
            remediation="Perform regular backups"
        ))
    
    # IR-007: Contact information
    contact_files = ["/etc/security/contacts.txt", "/root/emergency-contacts.txt"]
    has_contacts = any(os.path.exists(f) for f in contact_files)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Incident Response",
        status="Info",
        message=f"{get_cisa_id('IR', 7)}: Emergency contact information (Medium)",
        details="Contact file found" if has_contacts else "No contact file",
        remediation="Maintain emergency contact list"
    ))
    
    # IR-008: Incident logging
    incident_log_dirs = ["/var/log/incidents", "/var/log/security/incidents"]
    has_incident_log = any(os.path.exists(d) for d in incident_log_dirs)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Incident Response",
        status="Info",
        message=f"{get_cisa_id('IR', 8)}: Incident logging directory (Low)",
        details="Incident log dir exists" if has_incident_log else "No incident log directory",
        remediation="Create incident logging directory"
    ))
    
    # IR-009-015: Additional IR checks
    ir_checks = [
        ("Incident reporting procedures", "Define reporting procedures"),
        ("Evidence preservation process", "Document evidence handling"),
        ("Communication plan", "Establish communication channels"),
        ("Tabletop exercises", "Conduct incident response drills"),
        ("Lessons learned process", "Document post-incident reviews"),
        ("Legal coordination", "Coordinate with legal team"),
        ("External coordination", "Maintain CISA contact info")
    ]
    
    for i, (name, remediation) in enumerate(ir_checks, start=9):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Incident Response",
            status="Info",
            message=f"{get_cisa_id('IR', i)}: {name} (Medium)",
            details=f"Review {name.lower()}",
            remediation=remediation
        ))


def check_data_protection(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Data Protection checks - 15 comprehensive checks
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking data protection...")
    
    # DP-001: Disk encryption
    encrypted_devices = []
    result = run_command("lsblk -f | grep -i 'crypt\\|luks'")
    if result.returncode == 0 and result.stdout.strip():
        encrypted_devices = result.stdout.strip().split('\n')
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Data Protection",
        status="Pass" if encrypted_devices else "Warning",
        message=f"{get_cisa_id('DP', 1)}: Disk encryption implemented (High)",
        details=f"{len(encrypted_devices)} encrypted volumes" if encrypted_devices else "No encrypted volumes",
        remediation="Implement LUKS full disk encryption"
    ))
    
    # DP-002: Encryption tools installed
    encryption_tools = []
    for tool in ["cryptsetup", "gpg", "openssl"]:
        if command_exists(tool):
            encryption_tools.append(tool)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Data Protection",
        status="Pass" if len(encryption_tools) >= 2 else "Warning",
        message=f"{get_cisa_id('DP', 2)}: Encryption tools available (Medium)",
        details=f"Tools: {encryption_tools}" if encryption_tools else "No encryption tools",
        remediation=remediation_for("cryptsetup")
    ))
    
    # DP-003: Secure deletion tools
    secure_delete = command_exists("shred") or command_exists("wipe") or command_exists("srm")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Data Protection",
        status="Pass" if secure_delete else "Warning",
        message=f"{get_cisa_id('DP', 3)}: Secure file deletion capability (Medium)",
        details="Secure delete tool available" if secure_delete else "No secure delete tool",
        remediation="Install shred or wipe utility"
    ))
    
    # DP-004: File integrity monitoring (AIDE)
    aide_installed = check_package_installed("aide", os_info)
    
    if aide_installed:
        aide_db_locations = [
            "/var/lib/aide/aide.db",
            "/var/lib/aide/aide.db.gz",
            "/var/lib/aide.db"
        ]
        aide_db_exists = any(os.path.exists(db) for db in aide_db_locations)
        
        if aide_db_exists:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CISA - Data Protection",
                status="Pass",
                message=f"{get_cisa_id('DP', 4)}: File integrity monitoring configured (High)",
                details="AIDE database initialized",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CISA - Data Protection",
                status="Warning",
                message=f"{get_cisa_id('DP', 4)}: AIDE installed but not initialized (High)",
                details="AIDE database missing",
                remediation=remediation_for("aide")
            ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Data Protection",
            status="Fail",
            message=f"{get_cisa_id('DP', 4)}: File integrity monitoring not configured (High)",
            details="AIDE not installed",
            remediation="Install AIDE: apt install aide"
        ))
    
    # DP-005: Sensitive file permissions
    sensitive_files = {
        "/etc/passwd": "644",
        "/etc/shadow": "000",
        "/etc/gshadow": "000",
        "/etc/group": "644"
    }
    
    permission_issues = []
    for filepath, max_perms in sensitive_files.items():
        if os.path.exists(filepath):
            perms = get_file_permissions(filepath)
            if perms and int(perms, 8) > int(max_perms, 8):
                permission_issues.append(f"{filepath}:{perms}")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Data Protection",
        status="Pass" if not permission_issues else "Fail",
        message=f"{get_cisa_id('DP', 5)}: Sensitive file permissions secured (High)",
        details=f"Issues: {permission_issues}" if permission_issues else "Permissions OK",
        remediation="Correct file permissions: chmod 000 /etc/shadow"
    ))
    
    # DP-006: SSH key permissions
    ssh_key_dir = os.path.expanduser("~/.ssh")
    if os.path.exists(ssh_key_dir):
        ssh_perms = get_file_permissions(ssh_key_dir)
        ssh_secure = ssh_perms and int(ssh_perms, 8) <= int("700", 8)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Data Protection",
            status="Pass" if ssh_secure else "Fail",
            message=f"{get_cisa_id('DP', 6)}: SSH directory permissions (High)",
            details=f"~/.ssh permissions: {ssh_perms}",
            remediation="Set permissions: chmod 700 ~/.ssh"
        ))
    
    # DP-007: World-writable files (canonical assessment)
    from shared_components.shared_assessments import get_world_writable_assessment as _ww_assess
    _ww = _ww_assess("fail")
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Data Protection",
        status=_ww.status,
        message=f"{get_cisa_id('DP', 7)}: No world-writable files (Medium)",
        details=_ww.details,
        remediation=_ww.remediation
    ))
    
    # DP-008: Unowned files
    unowned = run_command("find / -xdev -nouser -o -nogroup 2>/dev/null | head -10").stdout.strip()
    has_unowned = bool(unowned)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Data Protection",
        status="Warning" if has_unowned else "Pass",
        message=f"{get_cisa_id('DP', 8)}: No unowned files (Low)",
        details="Unowned files found" if has_unowned else "None found",
        remediation="Assign ownership to unowned files"
    ))
    
    # DP-009: SUID/SGID files
    suid_count = run_command("find / -xdev -type f -perm -4000 2>/dev/null | wc -l").stdout.strip()
    
    try:
        suid_num = int(suid_count)
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Data Protection",
            status="Info",
            message=f"{get_cisa_id('DP', 9)}: SUID file inventory (Medium)",
            details=f"{suid_num} SUID files found",
            remediation="Review SUID files regularly"
        ))
    except:
        pass
    
    # DP-010: Data loss prevention
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Data Protection",
        status="Info",
        message=f"{get_cisa_id('DP', 10)}: Data loss prevention (DLP) (Medium)",
        details="Review DLP implementation",
        remediation="Implement DLP controls for sensitive data"
    ))
    
    # DP-011-015: Additional data protection checks
    dp_checks = [
        ("Data classification", "Classify data by sensitivity"),
        ("Encryption at rest", "Encrypt sensitive data at rest"),
        ("Encryption in transit", "Use TLS for data transmission"),
        ("Data retention policy", "Implement data retention policy"),
        ("Secure data disposal", "Document secure disposal procedures")
    ]
    
    for i, (name, remediation) in enumerate(dp_checks, start=11):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Data Protection",
            status="Info",
            message=f"{get_cisa_id('DP', i)}: {name} (Medium)",
            details=f"Review {name.lower()}",
            remediation=remediation
        ))


# ============================================================================
# Zero Trust Architecture Readiness (CISA Zero Trust Maturity Model)
# ============================================================================

def check_zero_trust_readiness(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Assess alignment with CISA Zero Trust Maturity Model.

    Evaluates identity verification, device security, network segmentation,
    application workload security, and data protection controls that support
    a zero trust architecture.
    """
    cache = shared_data.get('cache')

    # ZT-001: Multi-factor authentication readiness
    # Check PAM for MFA modules (pam_google_authenticator, pam_u2f, pam_duo, etc.)
    mfa_modules = ['pam_google_authenticator', 'pam_u2f', 'pam_duo', 'pam_yubico',
                   'pam_oath', 'pam_radius_auth', 'pam_totp']
    found_mfa = []
    pam_dirs = ['/etc/pam.d']
    for pam_dir in pam_dirs:
        if os.path.isdir(pam_dir):
            try:
                for pam_file in os.listdir(pam_dir):
                    pam_path = os.path.join(pam_dir, pam_file)
                    if os.path.isfile(pam_path):
                        content = read_file_safe(pam_path)
                        if content:
                            for mod in mfa_modules:
                                if mod in content and mod not in found_mfa:
                                    found_mfa.append(mod)
            except PermissionError:
                pass

    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Zero Trust",
        status="Pass" if found_mfa else "Warning",
        message=f"{get_cisa_id('ZT', 1)}: Multi-factor authentication capability (Critical)",
        details=f"MFA PAM modules found: {', '.join(found_mfa) if found_mfa else 'none detected'}",
        remediation="Install and configure MFA (e.g., libpam-google-authenticator, pam_u2f)",
        severity="Critical"
    ))

    # ZT-002: Network micro-segmentation indicators
    # Check for network namespaces, firewall zones, or VLAN config
    netns_count = 0
    result_netns = run_command("ip netns list 2>/dev/null", use_cache=True)
    if result_netns.returncode == 0 and result_netns.stdout.strip():
        netns_count = len(result_netns.stdout.strip().splitlines())

    firewall_zones = 0
    result_zones = run_command("firewall-cmd --get-zones 2>/dev/null", use_cache=True)
    if result_zones.returncode == 0 and result_zones.stdout.strip():
        firewall_zones = len(result_zones.stdout.strip().split())

    has_segmentation = netns_count > 0 or firewall_zones > 1
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Zero Trust",
        status="Pass" if has_segmentation else "Warning",
        message=f"{get_cisa_id('ZT', 2)}: Network micro-segmentation (High)",
        details=f"Network namespaces: {netns_count}, Firewall zones: {firewall_zones}",
        remediation="Implement network segmentation via firewalld zones, network namespaces, or VLANs",
        severity="High"
    ))

    # ZT-003: Least privilege enforcement
    # Check for sudoers NOPASSWD entries (anti-pattern for zero trust)
    nopasswd_count = 0
    sudoers_content = read_file_safe("/etc/sudoers")
    if sudoers_content:
        for line in sudoers_content.splitlines():
            line = line.strip()
            if not line.startswith('#') and 'NOPASSWD' in line:
                nopasswd_count += 1

    # Also check sudoers.d/
    sudoers_d = "/etc/sudoers.d"
    if os.path.isdir(sudoers_d):
        try:
            for sf in os.listdir(sudoers_d):
                sf_path = os.path.join(sudoers_d, sf)
                if os.path.isfile(sf_path):
                    content = read_file_safe(sf_path)
                    if content:
                        for line in content.splitlines():
                            if not line.strip().startswith('#') and 'NOPASSWD' in line:
                                nopasswd_count += 1
        except PermissionError:
            pass

    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Zero Trust",
        status="Pass" if nopasswd_count == 0 else "Fail",
        message=f"{get_cisa_id('ZT', 3)}: Least privilege - NOPASSWD sudo rules (High)",
        details=f"NOPASSWD rules found: {nopasswd_count}",
        remediation="Remove NOPASSWD from sudoers entries; require authentication for privilege escalation",
        severity="High"
    ))

    # ZT-004: Device integrity verification
    # Check for TPM, measured boot, or device attestation
    has_tpm = os.path.exists("/dev/tpm0") or os.path.exists("/dev/tpmrm0")
    has_ima = os.path.exists("/sys/kernel/security/ima")
    has_secureboot = False
    sb_result = run_command("mokutil --sb-state 2>/dev/null", use_cache=True)
    if sb_result.returncode == 0 and "SecureBoot enabled" in sb_result.stdout:
        has_secureboot = True

    device_checks = []
    if has_tpm:
        device_checks.append("TPM")
    if has_ima:
        device_checks.append("IMA")
    if has_secureboot:
        device_checks.append("Secure Boot")

    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Zero Trust",
        status="Pass" if len(device_checks) >= 2 else (
            "Warning" if device_checks else "Fail"),
        message=f"{get_cisa_id('ZT', 4)}: Device integrity verification (High)",
        details=f"Available: {', '.join(device_checks) if device_checks else 'none detected'}",
        remediation="Enable TPM 2.0, IMA measurement, and UEFI Secure Boot for device attestation",
        severity="High"
    ))

    # ZT-005: Continuous monitoring / session validation
    # Check for PAM session timeout, SSH idle timeout, tmout
    ssh_timeout = 0
    ssh_config = {}
    if cache:
        ssh_config = cache.get_parsed('ssh_config') or {}
    interval = ssh_config.get('clientaliveinterval', '0')
    count_max = ssh_config.get('clientalivecountmax', '3')
    try:
        ssh_timeout = int(interval) * int(count_max)
    except (ValueError, TypeError):
        pass

    # Check TMOUT
    tmout_val = 0
    for profile in ['/etc/profile', '/etc/bashrc', '/etc/bash.bashrc', '/etc/profile.d/']:
        content = read_file_safe(profile)
        if content:
            for line in content.splitlines():
                if 'TMOUT=' in line and not line.strip().startswith('#'):
                    try:
                        val = line.split('TMOUT=')[1].split()[0].strip('"\'')
                        tmout_val = int(val)
                    except (ValueError, IndexError):
                        pass

    has_timeout = ssh_timeout > 0 or tmout_val > 0
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Zero Trust",
        status="Pass" if has_timeout else "Warning",
        message=f"{get_cisa_id('ZT', 5)}: Session timeout / continuous validation (Medium)",
        details=f"SSH timeout: {ssh_timeout}s, Shell TMOUT: {tmout_val}s",
        remediation="Set ClientAliveInterval/ClientAliveCountMax in sshd_config and TMOUT in /etc/profile",
        severity="Medium"
    ))

    # ZT-006: Encrypted communications enforcement
    # Check that SSH, TLS are required and telnet/FTP disabled
    insecure_svcs = []
    for svc in ['telnet', 'vsftpd', 'proftpd', 'rsh', 'rlogin', 'rexec']:
        if check_service_active(svc, cache=cache):
            insecure_svcs.append(svc)

    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Zero Trust",
        status="Pass" if not insecure_svcs else "Fail",
        message=f"{get_cisa_id('ZT', 6)}: Encrypted communications enforcement (High)",
        details=f"Insecure services active: {', '.join(insecure_svcs) if insecure_svcs else 'none'}",
        remediation=f"Disable insecure services: {', '.join(insecure_svcs)}; use SSH/SFTP/TLS only",
        severity="High"
    ))


# ============================================================================
# CISA Supply Chain Risk Management
# ============================================================================

def check_supply_chain_security(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Assess supply chain security controls per CISA supply chain guidance.

    Checks package signing, repository integrity, software provenance,
    and SBOM readiness.
    """
    cache = shared_data.get('cache')

    # SC-001: Package repository GPG/signing verification
    if os_info.family == "debian":
        # Check for unsigned repos or [trusted=yes] entries
        unsigned_repos = 0
        signed_repos = 0
        sources_dirs = ['/etc/apt/sources.list.d']
        sources_files = ['/etc/apt/sources.list']

        for sf in sources_files:
            content = read_file_safe(sf)
            if content:
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if 'trusted=yes' in line:
                        unsigned_repos += 1
                    elif line.startswith('deb ') or line.startswith('deb-src '):
                        signed_repos += 1

        for d in sources_dirs:
            if os.path.isdir(d):
                try:
                    for f in os.listdir(d):
                        content = read_file_safe(os.path.join(d, f))
                        if content:
                            for line in content.splitlines():
                                line = line.strip()
                                if not line or line.startswith('#'):
                                    continue
                                if 'trusted=yes' in line:
                                    unsigned_repos += 1
                                elif 'deb ' in line or 'deb-src' in line or 'Signed-By' in line:
                                    signed_repos += 1
                except PermissionError:
                    pass

        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Supply Chain",
            status="Pass" if unsigned_repos == 0 and signed_repos > 0 else (
                "Fail" if unsigned_repos > 0 else "Warning"),
            message=f"{get_cisa_id('SC', 1)}: APT repository signature verification (High)",
            details=f"Signed repos: {signed_repos}, Unsigned/trusted repos: {unsigned_repos}",
            remediation="Remove [trusted=yes] from apt sources; use Signed-By for GPG verification",
            severity="High"
        ))

    elif os_info.family == "redhat":
        # Check gpgcheck in yum/dnf config
        gpgcheck_on = False
        for conf in ['/etc/yum.conf', '/etc/dnf/dnf.conf']:
            content = read_file_safe(conf)
            if content:
                for line in content.splitlines():
                    if line.strip().startswith('gpgcheck') and '1' in line:
                        gpgcheck_on = True

        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Supply Chain",
            status="Pass" if gpgcheck_on else "Fail",
            message=f"{get_cisa_id('SC', 1)}: RPM GPG verification (High)",
            details=f"gpgcheck: {'enabled' if gpgcheck_on else 'disabled or not found'}",
            remediation="Set gpgcheck=1 in /etc/yum.conf or /etc/dnf/dnf.conf",
            severity="High"
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Supply Chain",
            status="Info",
            message=f"{get_cisa_id('SC', 1)}: Package signing verification (High)",
            details=f"Package manager: {os_info.package_manager}",
            remediation="Verify package signing is enforced for your package manager",
            severity="High"
        ))

    # SC-002: Automatic security updates configuration
    auto_update = False
    if os_info.family == "debian":
        ua_content = read_file_safe("/etc/apt/apt.conf.d/20auto-upgrades")
        if ua_content and 'Unattended-Upgrade "1"' in ua_content:
            auto_update = True
        if not auto_update:
            auto_update = check_service_active("unattended-upgrades", cache=cache)
    elif os_info.family == "redhat":
        auto_update = check_service_active("dnf-automatic", cache=cache)
        if not auto_update:
            auto_update = check_service_active("yum-cron", cache=cache)

    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Supply Chain",
        status="Pass" if auto_update else "Warning",
        message=f"{get_cisa_id('SC', 2)}: Automatic security updates (High)",
        details=f"Automatic updates: {'enabled' if auto_update else 'not detected'}",
        remediation="Enable unattended-upgrades (Debian) or dnf-automatic (RHEL)",
        severity="High"
    ))

    # SC-003: SBOM generation capability
    sbom_tools = ['syft', 'cyclonedx', 'spdx-sbom-generator', 'trivy']
    found_tools = [t for t in sbom_tools if command_exists(t)]

    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Supply Chain",
        status="Pass" if found_tools else "Info",
        message=f"{get_cisa_id('SC', 3)}: SBOM generation capability (Medium)",
        details=f"Available tools: {', '.join(found_tools) if found_tools else 'none detected'}",
        remediation="Install SBOM tools (syft, trivy) for software supply chain transparency",
        severity="Medium"
    ))

    # SC-004: Kernel module signing verification
    sig_enforce = False
    cmdline = read_file_safe("/proc/cmdline") or ""
    if "module.sig_enforce=1" in cmdline:
        sig_enforce = True
    else:
        exists, val = check_kernel_parameter("kernel.modules_disabled", cache=cache)
        if exists and val.strip() == "1":
            sig_enforce = True  # Even stricter: no new modules at all

    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Supply Chain",
        status="Pass" if sig_enforce else "Info",
        message=f"{get_cisa_id('SC', 4)}: Kernel module signature enforcement (Medium)",
        details=f"module.sig_enforce: {'enabled' if sig_enforce else 'not enforced'}",
        remediation="Add module.sig_enforce=1 to kernel boot parameters",
        severity="Medium"
    ))

    # SC-005: Third-party repository count (attack surface)
    third_party = 0
    official_patterns = ['ubuntu.com', 'debian.org', 'centos.org', 'redhat.com',
                         'fedoraproject.org', 'archive.ubuntu.com', 'security.ubuntu.com']
    if os_info.family == "debian":
        for sf in ['/etc/apt/sources.list']:
            content = read_file_safe(sf)
            if content:
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith('deb ') and not any(p in line for p in official_patterns):
                        third_party += 1
        sources_d = '/etc/apt/sources.list.d'
        if os.path.isdir(sources_d):
            try:
                third_party += len([f for f in os.listdir(sources_d)
                                   if f.endswith('.list') or f.endswith('.sources')])
            except PermissionError:
                pass

    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Supply Chain",
        status="Pass" if third_party <= 2 else (
            "Warning" if third_party <= 5 else "Fail"),
        message=f"{get_cisa_id('SC', 5)}: Third-party repository count (Medium)",
        details=f"Third-party/extra repositories: {third_party}",
        remediation="Minimize third-party repositories; audit and remove unused sources",
        severity="Medium"
    ))


# ============================================================================
# CISA Secure Cloud Business Applications (SCuBA) Baseline
# ============================================================================

def check_scuba_baseline(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Assess SCuBA-aligned controls for systems supporting cloud services.

    Checks TLS enforcement, certificate validation, DNS security,
    and cloud metadata protection applicable to Linux hosts.
    """
    cache = shared_data.get('cache')

    # SCUBA-001: TLS minimum version enforcement
    # Check OpenSSL default minimum and sshd ciphers
    openssl_result = run_command("openssl version 2>/dev/null", use_cache=True)
    openssl_ver = openssl_result.stdout.strip() if openssl_result.returncode == 0 else "unknown"

    # Check for MinProtocol in openssl.cnf
    min_tls = "unknown"
    for conf_path in ['/etc/ssl/openssl.cnf', '/etc/pki/tls/openssl.cnf']:
        content = read_file_safe(conf_path)
        if content:
            for line in content.splitlines():
                if 'MinProtocol' in line and not line.strip().startswith('#'):
                    min_tls = line.split('=')[1].strip() if '=' in line else "set"

    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - SCuBA",
        status="Pass" if min_tls in ("TLSv1.2", "TLSv1.3") else "Warning",
        message=f"{get_cisa_id('SCUBA', 1)}: TLS minimum version enforcement (High)",
        details=f"OpenSSL: {openssl_ver}, MinProtocol: {min_tls}",
        remediation="Set MinProtocol = TLSv1.2 in openssl.cnf; disable TLSv1.0 and TLSv1.1",
        severity="High"
    ))

    # SCUBA-002: Certificate trust store management
    ca_bundle_paths = ['/etc/ssl/certs/ca-certificates.crt',
                       '/etc/pki/tls/certs/ca-bundle.crt',
                       '/etc/ssl/ca-bundle.pem']
    ca_found = None
    ca_count = 0
    for ca_path in ca_bundle_paths:
        if os.path.exists(ca_path):
            ca_found = ca_path
            content = read_file_safe(ca_path)
            if content:
                ca_count = content.count('BEGIN CERTIFICATE')
            break

    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - SCuBA",
        status="Pass" if ca_found and ca_count > 0 else "Fail",
        message=f"{get_cisa_id('SCUBA', 2)}: CA certificate trust store (High)",
        details=f"Bundle: {ca_found or 'not found'}, Certificates: {ca_count}",
        remediation="Install and maintain ca-certificates package; run update-ca-certificates",
        severity="High"
    ))

    # SCUBA-003: DNS security (DNSSEC validation or DNS-over-TLS)
    resolved_conf = read_file_safe("/etc/systemd/resolved.conf")
    dnssec_enabled = False
    dns_tls = False
    if resolved_conf:
        for line in resolved_conf.splitlines():
            line = line.strip()
            if line.startswith('DNSSEC=') and 'yes' in line.lower():
                dnssec_enabled = True
            if line.startswith('DNSOverTLS=') and ('yes' in line.lower() or 'opportunistic' in line.lower()):
                dns_tls = True

    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - SCuBA",
        status="Pass" if dnssec_enabled or dns_tls else "Warning",
        message=f"{get_cisa_id('SCUBA', 3)}: DNS security (DNSSEC / DNS-over-TLS) (Medium)",
        details=f"DNSSEC: {'enabled' if dnssec_enabled else 'disabled'}, "
                f"DNS-over-TLS: {'enabled' if dns_tls else 'disabled'}",
        remediation="Enable DNSSEC=yes and/or DNSOverTLS=yes in /etc/systemd/resolved.conf",
        severity="Medium"
    ))

    # SCUBA-004: Cloud instance metadata protection
    # Check if IMDS is accessible (AWS 169.254.169.254, Azure, GCP)
    is_cloud = False
    metadata_protected = True
    for meta_indicator in ['/sys/hypervisor/uuid', '/sys/class/dmi/id/product_name']:
        content = read_file_safe(meta_indicator)
        if content and any(cloud in content.lower() for cloud in
                          ['amazon', 'google', 'microsoft', 'xen', 'kvm']):
            is_cloud = True
            break

    if is_cloud:
        # Check iptables for metadata endpoint blocking
        ipt_result = run_command("iptables -L -n 2>/dev/null | grep 169.254.169.254", use_cache=True)
        if ipt_result.returncode != 0 or not ipt_result.stdout.strip():
            metadata_protected = False

    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - SCuBA",
        status="Pass" if not is_cloud or metadata_protected else "Warning",
        message=f"{get_cisa_id('SCUBA', 4)}: Cloud metadata endpoint protection (High)",
        details=f"Cloud instance: {'yes' if is_cloud else 'no'}, "
                f"Metadata protected: {'yes' if metadata_protected else 'no/unverified'}",
        remediation="Restrict access to instance metadata (169.254.169.254) via iptables or IMDSv2",
        severity="High"
    ))

    # SCUBA-005: HTTP Strict Transport Security readiness
    # Check if common web servers enforce HSTS
    hsts_capable = False
    for svc in ['nginx', 'apache2', 'httpd']:
        if check_service_active(svc, cache=cache):
            hsts_capable = True
            break

    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - SCuBA",
        status="Info" if not hsts_capable else "Warning",
        message=f"{get_cisa_id('SCUBA', 5)}: HSTS enforcement readiness (Medium)",
        details=f"Web server active: {'yes' if hsts_capable else 'no'}",
        remediation="Enable HSTS headers (Strict-Transport-Security) on all web services",
        severity="Medium"
    ))


# ============================================================================
# Main Module Entry Point
# ============================================================================

def run_checks(shared_data: Dict[str, Any]) -> List[AuditResult]:
    """
    Main entry point for CISA Cybersecurity Directives module
    
    Args:
        shared_data: Dictionary with shared data from main script
        
    Returns:
        List of AuditResult objects
    """
    results = []
    
    # Extract SharedDataCache from shared_data (populated by main script)
    cache = shared_data.get('cache')
    

    # Detect operating system
    # Get OS info from cache if available (avoids redundant detection)
    if cache and hasattr(cache, 'os_info') and cache.os_info:
        os_info = cache.os_info
    else:
        os_info = detect_os()
    shared_data['os_info'] = os_info
    
    print(f"[{MODULE_NAME}] Operating System: {os_info}")
    print(f"[{MODULE_NAME}] Package Manager: {os_info.package_manager}")
    print(f"[{MODULE_NAME}] Init System: {os_info.init_system}")
    print("")
    
    is_root = shared_data.get("is_root", os.geteuid() == 0)
    if not is_root:
        print(f"[{MODULE_NAME}]   Note: Running without root privileges")
        print(f"[{MODULE_NAME}] Some checks require elevated privileges for full coverage\n")
    
    print(f"\n[{MODULE_NAME}] ===== CISA SECURITY AUDIT =====")
    print(f"[{MODULE_NAME}] Version: {MODULE_VERSION}")
    print(f"[{MODULE_NAME}] Standards: CISA BODs, Zero Trust Maturity Model, SCuBA, Best Practices")
    print(f"[{MODULE_NAME}] Priority Levels: Critical, High, Medium, Low")
    print(f"[{MODULE_NAME}] Focus: BOD 22-01 (KEV), BOD 23-01 (Asset Visibility), ZTMM, SCuBA\n")
    
    is_root = shared_data.get("is_root", os.geteuid() == 0)
    if not is_root:
        print(f"[{MODULE_NAME}] Note: Some checks require root privileges for complete results")
    
    try:
        # Category 1: BOD 22-01 - Known Exploited Vulnerabilities
        check_bod_22_01_kev(results, shared_data, os_info)
        
        # Category 2: BOD 23-01 - Asset Visibility
        check_bod_23_01_asset_visibility(results, shared_data, os_info)
        
        # Category 3: Authentication and Access Control
        check_authentication_access_control(results, shared_data, os_info)
        
        # Category 4: Network Security
        check_network_security(results, shared_data, os_info)
        
        # Category 5: Logging and Monitoring
        check_logging_monitoring(results, shared_data, os_info)
        
        # Category 6: Incident Response
        check_incident_response(results, shared_data, os_info)
        
        # Category 7: Data Protection
        check_data_protection(results, shared_data, os_info)
        
        # Category 8: Zero Trust Architecture Readiness (CISA ZTMM)
        check_zero_trust_readiness(results, shared_data, os_info)
        
        # Category 9: Supply Chain Risk Management
        check_supply_chain_security(results, shared_data, os_info)
        
        # Category 10: SCuBA Baseline (Secure Cloud Business Applications)
        check_scuba_baseline(results, shared_data, os_info)
        
    except Exception as e:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Error",
            status="Error",
            message=f"Module execution error: {str(e)}",
            details="",
            remediation="Review module logs"
        ))
        import traceback
        traceback.print_exc()
    
    # Summary statistics
    critical_fail = sum(1 for r in results if "Critical" in r.message and r.status == "Fail")
    high_fail = sum(1 for r in results if "High" in r.message and r.status == "Fail")
    medium_fail = sum(1 for r in results if "Medium" in r.message and r.status == "Fail")
    low_fail = sum(1 for r in results if "Low" in r.message and r.status == "Fail")
    
    bod_22_01_checks = sum(1 for r in results if "BOD 22-01" in r.category)
    bod_23_01_checks = sum(1 for r in results if "BOD 23-01" in r.category)
    zt_checks = sum(1 for r in results if "Zero Trust" in r.category)
    sc_checks = sum(1 for r in results if "Supply Chain" in r.category)
    scuba_checks = sum(1 for r in results if "SCuBA" in r.category)
    
    summary_details = (
        f"Critical failures: {critical_fail}, High failures: {high_fail}, "
        f"Medium failures: {medium_fail}, Low failures: {low_fail}"
    )

    # Generate summary statistics
    pass_count = sum(1 for r in results if r.status == "Pass")
    fail_count = sum(1 for r in results if r.status == "Fail")
    warn_count = sum(1 for r in results if r.status == "Warning")
    info_count = sum(1 for r in results if r.status == "Info")
    error_count = sum(1 for r in results if r.status == "Error")
    
    print(f"\n[{MODULE_NAME}] " + "="*70)
    print(f"[{MODULE_NAME}] CISA SECURITY AUDIT COMPLETED")
    print(f"[{MODULE_NAME}] " + "="*70)
    print(f"[{MODULE_NAME}] Total Security Audit Checks Executed: {len(results)}")
    print(f"[{MODULE_NAME}] BOD 22-01 checks: {bod_22_01_checks}")
    print(f"[{MODULE_NAME}] BOD 23-01 checks: {bod_23_01_checks}")
    print(f"[{MODULE_NAME}] Zero Trust checks: {zt_checks}")
    print(f"[{MODULE_NAME}] Supply Chain checks: {sc_checks}")
    print(f"[{MODULE_NAME}] SCuBA checks: {scuba_checks}")
    print(f"[{MODULE_NAME}] Priority summary: {summary_details}")
    print(f"[{MODULE_NAME}]    Critical Failures: {critical_fail}")
    print(f"[{MODULE_NAME}]    High Failures: {high_fail}")
    print(f"[{MODULE_NAME}]   Medium Failures: {medium_fail}")
    print(f"[{MODULE_NAME}]   Low Failures: {low_fail}")
    print(f"[{MODULE_NAME}] ")
    print(f"[{MODULE_NAME}] Results Summary:")
    print(f"[{MODULE_NAME}]   Passed:  {pass_count:3d} ({pass_count/len(results)*100:.1f}%)")
    print(f"[{MODULE_NAME}]   Failed:  {fail_count:3d} ({fail_count/len(results)*100:.1f}%)")
    print(f"[{MODULE_NAME}]   Warnings: {warn_count:3d} ({warn_count/len(results)*100:.1f}%)")
    print(f"[{MODULE_NAME}]   Info:    {info_count:3d} ({info_count/len(results)*100:.1f}%)")
    print(f"[{MODULE_NAME}]   Errors:  {error_count:3d} ({error_count/len(results)*100:.1f}%)")
    print(f"[{MODULE_NAME}] " + "="*70 + "\n")
    
    return results


# ============================================================================
# Module Testing
# ============================================================================



# ============================================================================
# v3.3 EXPANSION - CISA Deep Coverage
# ----------------------------------------------------------------------------
# Synopsis:
#   Adds depth across:
#   - CISA Cross-Sector Cybersecurity Performance Goals (CPG v1.0.1)
#   - CISA Zero Trust Maturity Model (ZTMM) v2.0
#   - CISA Binding Operational Directives (BOD) 22-01 KEV, 23-01 attack surface
#   - CISA Cybersecurity Advisories technical indicators
#   - CISA Secure by Design principles
# ============================================================================

from shared_components.module_helpers import (
    read_file_safe as _v33_read_file_safe,
    file_exists as _v33_file_exists,
    directory_exists as _v33_directory_exists,
    command_available as _v33_command_available,
    run_command as _v33_run_command,
    read_sysctl as _v33_read_sysctl,
    systemd_active as _v33_systemd_active,
    file_mode as _v33_file_mode,
    list_directory as _v33_list_directory,
)


def _v33_cisa_result(category, status, message, severity="Medium",
                     details="", remediation="", cross_references=None):
    """Build AuditResult for CISA v3.3 expansion."""
    return AuditResult(
        module=MODULE_NAME,
        category=category,
        status=status,
        message=message,
        details=details,
        remediation=remediation,
        severity=severity,
        cross_references=cross_references or {},
    )


def _check_cisa_v33_cpg_account_security(results, shared_data, os_info):
    """CISA CPG 2.A - Account Security."""

    # 2.A - Changing Default Passwords (no empty passwords)
    shadow = _v33_read_file_safe("/etc/shadow")
    empty_pw = []
    if shadow:
        for line in shadow.splitlines():
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] == "":
                empty_pw.append(parts[0])
    results.append(_v33_cisa_result(
        "CISA CPG 2.A v3.3 - Default Passwords",
        "Pass" if not empty_pw else "Fail",
        f"CPG 2.A No accounts with empty passwords ({len(empty_pw)})",
        severity="Critical",
        details=f"Empty password users: {empty_pw[:5]}",
        remediation="passwd -l <user> for each",
        cross_references={
            "CISA-CPG": "2.A", "NIST": "IA-5",
        },
    ))

    # 2.B - Minimum Password Strength
    pwq = _v33_read_file_safe("/etc/security/pwquality.conf")
    minlen = 0
    if pwq:
        m = re.search(r"^\s*minlen\s*=\s*(\d+)", pwq, re.MULTILINE)
        if m:
            minlen = int(m.group(1))
    pwq_ok = minlen >= 14
    results.append(_v33_cisa_result(
        "CISA CPG 2.B v3.3 - Password Strength",
        "Pass" if pwq_ok else "Warning",
        f"CPG 2.B Minimum password length >= 14 ({minlen})",
        severity="High",
        details=f"pwquality minlen = {minlen}",
        remediation="In /etc/security/pwquality.conf: minlen = 14",
        cross_references={
            "CISA-CPG": "2.B", "NIST": "IA-5(1)",
        },
    ))

    # 2.C - Unique Credentials (UID 0 uniqueness)
    passwd = _v33_read_file_safe("/etc/passwd")
    uid0 = []
    if passwd:
        for line in passwd.splitlines():
            parts = line.split(":")
            if len(parts) >= 3:
                try:
                    if int(parts[2]) == 0 and parts[0] != "root":
                        uid0.append(parts[0])
                except ValueError:
                    pass
    results.append(_v33_cisa_result(
        "CISA CPG 2.C v3.3 - Unique Credentials",
        "Pass" if not uid0 else "Fail",
        f"CPG 2.C Only root has UID 0 ({len(uid0)} extras)",
        severity="Critical",
        details=f"Non-root UID 0: {uid0}",
        remediation="usermod -u <new_uid> <user>",
        cross_references={
            "CISA-CPG": "2.C", "NIST": "AC-6",
        },
    ))

    # 2.D - Revoking Credentials for Departing Employees (account lifecycle)
    inact_match = re.search(r"^\s*INACTIVE\s+(-?\d+)",
                              _v33_read_file_safe("/etc/login.defs"),
                              re.MULTILINE)
    inact = int(inact_match.group(1)) if inact_match else -1
    inact_ok = 0 < inact <= 35
    results.append(_v33_cisa_result(
        "CISA CPG 2.D v3.3 - Account Lifecycle",
        "Pass" if inact_ok else "Warning",
        f"CPG 2.D Inactive account auto-disable ({inact})",
        severity="High",
        details=f"INACTIVE = {inact} days",
        remediation="In /etc/default/useradd: INACTIVE=35",
        cross_references={
            "CISA-CPG": "2.D", "NIST": "AC-2(3)",
        },
    ))

    # 2.E - Separating User and Privileged Accounts
    sshd = _v33_read_file_safe("/etc/ssh/sshd_config")
    permit_root_match = re.search(r"^\s*PermitRootLogin\s+(\S+)", sshd, re.MULTILINE)
    permit_root = permit_root_match.group(1) if permit_root_match else "yes"
    root_secure = permit_root.lower() in ("no", "prohibit-password",
                                            "without-password")
    results.append(_v33_cisa_result(
        "CISA CPG 2.E v3.3 - Privileged Separation",
        "Pass" if root_secure else "Fail",
        f"CPG 2.E Direct root login restricted ({permit_root})",
        severity="High",
        details=f"PermitRootLogin = {permit_root}",
        remediation="In /etc/ssh/sshd_config: PermitRootLogin no",
        cross_references={
            "CISA-CPG": "2.E", "NIST": "AC-6",
        },
    ))

    # 2.F - Network Segmentation (firewall)
    fw_active = (
        _v33_systemd_active("ufw.service") == "active" or
        _v33_systemd_active("firewalld.service") == "active" or
        _v33_systemd_active("nftables.service") == "active"
    )
    results.append(_v33_cisa_result(
        "CISA CPG 2.F v3.3 - Network Segmentation",
        "Pass" if fw_active else "Fail",
        f"CPG 2.F Firewall active for network segmentation",
        severity="Critical",
        details=f"Firewall service active: {fw_active}",
        remediation="systemctl enable --now ufw",
        cross_references={
            "CISA-CPG": "2.F", "NIST": "SC-7",
        },
    ))

    # 2.G - Detection of Unsuccessful Login Attempts
    pam_files = ["/etc/pam.d/system-auth", "/etc/pam.d/common-auth",
                 "/etc/pam.d/password-auth"]
    has_faillock = False
    for pf in pam_files:
        if "pam_faillock" in _v33_read_file_safe(pf):
            has_faillock = True
            break
    results.append(_v33_cisa_result(
        "CISA CPG 2.G v3.3 - Failed Login Detection",
        "Pass" if has_faillock else "Warning",
        f"CPG 2.G Failed login detection (pam_faillock)",
        severity="High",
        details=f"pam_faillock detected: {has_faillock}",
        remediation=(
            "Configure /etc/security/faillock.conf with deny=5 unlock_time=900"
        ),
        cross_references={
            "CISA-CPG": "2.G", "NIST": "AC-7",
        },
    ))

    # 2.H - Phishing-Resistant MFA
    mfa_modules_phishing_resistant = [
        "pam_yubico", "pam_u2f", "pam_pkcs11"  # hardware-backed
    ]
    detected_pr_mfa = set()
    for pf in pam_files + ["/etc/pam.d/sshd"]:
        c = _v33_read_file_safe(pf)
        for mod in mfa_modules_phishing_resistant:
            if mod + ".so" in c:
                detected_pr_mfa.add(mod.replace("pam_", ""))
    results.append(_v33_cisa_result(
        "CISA CPG 2.H v3.3 - Phishing-Resistant MFA",
        "Pass" if detected_pr_mfa else "Warning",
        f"CPG 2.H Phishing-resistant MFA modules ({len(detected_pr_mfa)})",
        severity="High",
        details=f"Detected: {sorted(detected_pr_mfa) or 'none'}",
        remediation=(
            "Deploy hardware-token MFA: apt-get install -y libpam-u2f or "
            "libpam-yubico"
        ),
        cross_references={
            "CISA-CPG": "2.H", "NIST": "IA-2(1)",
        },
    ))


def _check_cisa_v33_cpg_data_security(results, shared_data, os_info):
    """CISA CPG 2.K-2.N - Data Security."""

    # 2.K - Strong Encryption
    openssl_cnf = (
        _v33_read_file_safe("/etc/ssl/openssl.cnf") or
        _v33_read_file_safe("/etc/pki/tls/openssl.cnf")
    )
    has_tls12 = "TLSv1.2" in openssl_cnf or "MinProtocol" in openssl_cnf
    results.append(_v33_cisa_result(
        "CISA CPG 2.K v3.3 - Strong Encryption",
        "Pass" if has_tls12 else "Warning",
        f"CPG 2.K TLS 1.2+ minimum protocol set",
        severity="High",
        details=f"OpenSSL TLSv1.2/MinProtocol indicator: {has_tls12}",
        remediation=(
            "In /etc/ssl/openssl.cnf [system_default_sect]: "
            "MinProtocol = TLSv1.2"
        ),
        cross_references={
            "CISA-CPG": "2.K", "NIST": "SC-13",
        },
    ))

    # 2.L - Secure Sensitive Data (LUKS / disk encryption)
    rc, out, _ = _v33_run_command(["lsblk", "-o", "TYPE", "-n"], timeout=3.0)
    luks = rc == 0 and "crypt" in out.lower()
    results.append(_v33_cisa_result(
        "CISA CPG 2.L v3.3 - Secure Sensitive Data",
        "Pass" if luks else "Warning",
        f"CPG 2.L Disk encryption (LUKS) detected: {luks}",
        severity="High",
        details=f"LUKS volumes: {luks}",
        remediation="cryptsetup luksFormat <device> for sensitive volumes",
        cross_references={
            "CISA-CPG": "2.L", "NIST": "SC-28",
        },
    ))

    # 2.M - Email Security (TLS in mail clients - mostly server-side)
    mail_tls = (
        _v33_file_exists("/etc/postfix/main.cf") and
        "smtpd_tls_security_level" in _v33_read_file_safe("/etc/postfix/main.cf")
    )
    if _v33_file_exists("/etc/postfix/main.cf"):
        results.append(_v33_cisa_result(
            "CISA CPG 2.M v3.3 - Email Security",
            "Pass" if mail_tls else "Info",
            f"CPG 2.M Postfix TLS configured: {mail_tls}",
            severity="Medium",
            details=f"smtpd_tls_security_level set: {mail_tls}",
            remediation=(
                "In /etc/postfix/main.cf: smtpd_tls_security_level = encrypt"
            ),
            cross_references={
                "CISA-CPG": "2.M", "NIST": "SC-8",
            },
        ))

    # 2.N - Disable Macros by Default (LibreOffice indicator)
    libreoffice_present = (
        _v33_command_available("libreoffice") or
        _v33_command_available("soffice")
    )
    if libreoffice_present:
        results.append(_v33_cisa_result(
            "CISA CPG 2.N v3.3 - Disable Macros",
            "Info",
            f"CPG 2.N LibreOffice present (macro security policy review needed)",
            severity="Informational",
            details=f"LibreOffice/soffice available: {libreoffice_present}",
            remediation=(
                "Configure LibreOffice macro security via "
                "/etc/libreoffice/registry/...; deploy via group policy"
            ),
            cross_references={
                "CISA-CPG": "2.N", "NIST": "CM-7",
            },
        ))


def _check_cisa_v33_cpg_vulnerability_mgmt(results, shared_data, os_info):
    """CISA CPG 2.O-2.S - Vulnerability Management."""

    # 2.O - System Backups
    backup_tools = {
        "rsync": _v33_command_available("rsync"),
        "borg": _v33_command_available("borg"),
        "restic": _v33_command_available("restic"),
        "duplicity": _v33_command_available("duplicity"),
    }
    detected = [k for k, v in backup_tools.items() if v]
    results.append(_v33_cisa_result(
        "CISA CPG 2.O v3.3 - System Backups",
        "Pass" if detected else "Fail",
        f"CPG 2.O Backup tools available ({len(detected)})",
        severity="High",
        details=f"Detected: {detected}",
        cross_references={
            "CISA-CPG": "2.O", "NIST": "CP-9",
        },
    ))

    # 2.P - Document Network Topology (interface enumeration)
    rc, out, _ = _v33_run_command(["ip", "-br", "addr"], timeout=3.0)
    iface_count = 0
    if rc == 0 and out:
        iface_count = sum(
            1 for line in out.splitlines()
            if line.strip() and "lo" not in line.split()[0]
        )
    results.append(_v33_cisa_result(
        "CISA CPG 2.P v3.3 - Network Topology",
        "Info",
        f"CPG 2.P Network interfaces enumerable ({iface_count})",
        severity="Informational",
        details=f"Non-loopback interfaces: {iface_count}",
        cross_references={
            "CISA-CPG": "2.P", "NIST": "CM-8",
        },
    ))

    # 2.Q - Hardware and Software Approval Process (CM tools)
    cm_tools = {
        "ansible": _v33_command_available("ansible"),
        "puppet": _v33_command_available("puppet"),
        "salt": (_v33_command_available("salt-minion") or
                 _v33_command_available("salt-call")),
        "chef": _v33_command_available("chef-client"),
    }
    detected_cm = [k for k, v in cm_tools.items() if v]
    results.append(_v33_cisa_result(
        "CISA CPG 2.Q v3.3 - HW/SW Approval",
        "Info",
        f"CPG 2.Q Configuration management agents ({len(detected_cm)})",
        severity="Informational",
        details=f"Detected: {detected_cm or 'none'}",
        remediation="Deploy IaC: Ansible/Puppet/Salt for change tracking",
        cross_references={
            "CISA-CPG": "2.Q", "NIST": "CM-3",
        },
    ))

    # 2.R - Vulnerability Scanning
    scanners = ["lynis", "oscap", "trivy", "nuclei", "openvas-scanner"]
    detected_scanners = [s for s in scanners if _v33_command_available(s)]
    results.append(_v33_cisa_result(
        "CISA CPG 2.R v3.3 - Vulnerability Scanning",
        "Pass" if detected_scanners else "Fail",
        f"CPG 2.R Vulnerability scanners ({len(detected_scanners)})",
        severity="High",
        details=f"Detected: {detected_scanners}",
        remediation=remediation_for("lynis"),
        cross_references={
            "CISA-CPG": "2.R", "NIST": "RA-5",
        },
    ))

    # 2.S - Vulnerability Disclosure / KEV (BOD 22-01)
    update_active = (
        _v33_systemd_active("unattended-upgrades.service") == "active" or
        _v33_systemd_active("dnf-automatic-install.timer") == "active"
    )
    results.append(_v33_cisa_result(
        "CISA CPG 2.S v3.3 - KEV Patching",
        "Pass" if update_active else "Fail",
        f"CPG 2.S Automated patching for KEV (BOD 22-01)",
        severity="Critical",
        details=f"Update automation: {update_active}",
        remediation=(
            "apt-get install -y unattended-upgrades; "
            "dpkg-reconfigure unattended-upgrades  (Ubuntu/Debian); "
            "systemctl enable --now dnf-automatic-install.timer  (RHEL)"
        ),
        cross_references={
            "CISA-CPG": "2.S", "CISA-BOD": "22-01", "NIST": "SI-2",
        },
    ))


def _check_cisa_v33_cpg_supply_chain(results, shared_data, os_info):
    """CISA CPG 2.T-2.U - Supply Chain / Third Party."""

    # 2.T - Third-Party Software Procurement (signature verification)
    apt_keyring = (
        _v33_directory_exists("/etc/apt/trusted.gpg.d") or
        _v33_directory_exists("/etc/apt/keyrings")
    )
    rpm_gpgcheck = "gpgcheck=1" in (
        _v33_read_file_safe("/etc/yum.conf") or
        _v33_read_file_safe("/etc/dnf/dnf.conf")
    )
    pacman_keyring = _v33_directory_exists("/etc/pacman.d/gnupg")
    sig_indicators = sum([apt_keyring, rpm_gpgcheck, pacman_keyring])
    results.append(_v33_cisa_result(
        "CISA CPG 2.T v3.3 - Software Procurement",
        "Pass" if sig_indicators >= 1 else "Fail",
        f"CPG 2.T Package signature verification ({sig_indicators})",
        severity="High",
        details=(
            f"apt: {apt_keyring}, rpm gpgcheck: {rpm_gpgcheck}, "
            f"pacman: {pacman_keyring}"
        ),
        cross_references={
            "CISA-CPG": "2.T", "NIST": "SR-3",
        },
    ))

    # 2.U - Vendor/Supplier Cybersecurity Requirements (SBOM)
    sbom_tools = {
        "syft": _v33_command_available("syft"),
        "trivy": _v33_command_available("trivy"),
        "grype": _v33_command_available("grype"),
    }
    detected = [k for k, v in sbom_tools.items() if v]
    results.append(_v33_cisa_result(
        "CISA CPG 2.U v3.3 - SBOM Tooling",
        "Pass" if detected else "Info",
        f"CPG 2.U SBOM/vulnerability tools ({len(detected)})",
        severity="Medium",
        details=f"Detected: {detected or 'none'}",
        remediation=(
            "Install Syft for SBOM generation. Required by EO 14028 and "
            "OMB M-22-18 for federal procurement"
        ),
        cross_references={
            "CISA-CPG": "2.U", "NIST": "SR-4",
        },
    ))


def _check_cisa_v33_cpg_response_recovery(results, shared_data, os_info):
    """CISA CPG 2.V-2.W - Response and Recovery."""

    # 2.V - Incident Reporting (log forwarding)
    rsy_remote = False
    rsy_conf = _v33_read_file_safe("/etc/rsyslog.conf")
    if "@@" in rsy_conf or "omfwd" in rsy_conf:
        rsy_remote = True
    if not rsy_remote and _v33_directory_exists("/etc/rsyslog.d"):
        for f in _v33_list_directory("/etc/rsyslog.d"):
            if not f.endswith(".conf"):
                continue
            c = _v33_read_file_safe(os.path.join("/etc/rsyslog.d", f))
            if "@@" in c or "omfwd" in c:
                rsy_remote = True
                break
    results.append(_v33_cisa_result(
        "CISA CPG 2.V v3.3 - Incident Reporting",
        "Pass" if rsy_remote else "Fail",
        f"CPG 2.V Remote log forwarding for incident reporting",
        severity="Critical",
        details=f"rsyslog forwarding: {rsy_remote}",
        remediation=(
            "Configure /etc/rsyslog.d/50-remote.conf: "
            "*.* @@logserver.example.com:6514"
        ),
        cross_references={
            "CISA-CPG": "2.V", "NIST": "IR-6",
        },
    ))

    # 2.W - Incident Response Plans (audit trail readiness)
    audit_log_present = _v33_file_exists("/var/log/audit/audit.log")
    auditd_active = _v33_systemd_active("auditd.service") == "active"
    ir_ready = audit_log_present and auditd_active
    results.append(_v33_cisa_result(
        "CISA CPG 2.W v3.3 - IR Plan Readiness",
        "Pass" if ir_ready else "Fail",
        f"CPG 2.W Audit trail for incident response",
        severity="High",
        details=(
            f"auditd active: {auditd_active}, audit.log: {audit_log_present}"
        ),
        remediation=remediation_for("auditd"),
        cross_references={
            "CISA-CPG": "2.W", "NIST": "IR-4",
        },
    ))


def _check_cisa_v33_ztmm(results, shared_data, os_info):
    """CISA Zero Trust Maturity Model v2.0 - 5 pillars."""

    # Pillar 1 - Identity
    pam_files = ["/etc/pam.d/system-auth", "/etc/pam.d/common-auth",
                 "/etc/pam.d/password-auth", "/etc/pam.d/sshd"]
    mfa_modules = ["pam_google_authenticator", "pam_yubico", "pam_oath",
                    "pam_duo", "pam_u2f", "pam_pkcs11"]
    detected_mfa = set()
    for pf in pam_files:
        c = _v33_read_file_safe(pf)
        for mod in mfa_modules:
            if mod + ".so" in c:
                detected_mfa.add(mod.replace("pam_", ""))
    results.append(_v33_cisa_result(
        "CISA ZTMM v3.3 - Pillar 1 Identity",
        "Pass" if detected_mfa else "Warning",
        f"ZTMM Identity: MFA modules ({len(detected_mfa)})",
        severity="High",
        details=f"Detected: {sorted(detected_mfa) or 'none'}",
        cross_references={
            "CISA-ZTMM": "Pillar 1 Identity", "NIST": "IA-2(1)",
        },
    ))

    # Pillar 2 - Devices (FIM, EDR)
    fim_present = (
        _v33_file_exists("/var/lib/aide/aide.db") or
        _v33_file_exists("/var/lib/aide/aide.db.gz") or
        _v33_file_exists("/etc/tripwire/tw.cfg") or
        _v33_file_exists("/var/ossec/etc/ossec.conf")
    )
    edr_present = (
        _v33_file_exists("/opt/microsoft/mdatp/sbin/wdavdaemon") or
        _v33_file_exists("/opt/CrowdStrike/falconctl") or
        _v33_file_exists("/opt/sentinelone/bin/sentinelctl") or
        _v33_command_available("falco") or
        _v33_command_available("osqueryi")
    )
    device_layers = sum([fim_present, edr_present])
    results.append(_v33_cisa_result(
        "CISA ZTMM v3.3 - Pillar 2 Devices",
        "Pass" if device_layers >= 1 else "Warning",
        f"ZTMM Devices: FIM and/or EDR ({device_layers}/2)",
        severity="High",
        details=f"FIM: {fim_present}, EDR/visibility: {edr_present}",
        remediation=(
            "Deploy FIM (AIDE) and EDR (Falco/MDE/CrowdStrike)"
        ),
        cross_references={
            "CISA-ZTMM": "Pillar 2 Devices", "NIST": "SI-7",
        },
    ))

    # Pillar 3 - Networks (firewall + segmentation)
    fw_active = (
        _v33_systemd_active("ufw.service") == "active" or
        _v33_systemd_active("firewalld.service") == "active" or
        _v33_systemd_active("nftables.service") == "active"
    )
    ids_present = (
        _v33_command_available("suricata") or
        _v33_command_available("snort") or
        _v33_command_available("zeek")
    )
    network_layers = sum([fw_active, ids_present])
    results.append(_v33_cisa_result(
        "CISA ZTMM v3.3 - Pillar 3 Networks",
        "Pass" if network_layers >= 1 else "Fail",
        f"ZTMM Networks: firewall and/or IDS ({network_layers}/2)",
        severity="Critical",
        details=f"Firewall: {fw_active}, IDS: {ids_present}",
        cross_references={
            "CISA-ZTMM": "Pillar 3 Networks", "NIST": "SC-7",
        },
    ))

    # Pillar 4 - Applications and Workloads (allowlisting)
    allowlist = {
        "fapolicyd": _v33_systemd_active("fapolicyd.service") == "active",
        "AppArmor": _v33_systemd_active("apparmor.service") == "active",
        "SELinux": False,
    }
    if _v33_file_exists("/sys/fs/selinux/enforce"):
        try:
            with open("/sys/fs/selinux/enforce") as f:
                allowlist["SELinux"] = f.read().strip() == "1"
        except OSError:
            pass
    detected_al = [k for k, v in allowlist.items() if v]
    results.append(_v33_cisa_result(
        "CISA ZTMM v3.3 - Pillar 4 Applications",
        "Pass" if detected_al else "Warning",
        f"ZTMM Applications: allowlisting/MAC ({len(detected_al)})",
        severity="High",
        details=f"Detected: {detected_al}",
        cross_references={
            "CISA-ZTMM": "Pillar 4 Applications", "NIST": "CM-7(2)",
        },
    ))

    # Pillar 5 - Data (encryption + classification indicators)
    rc, out, _ = _v33_run_command(["lsblk", "-o", "TYPE", "-n"], timeout=3.0)
    luks = rc == 0 and "crypt" in out.lower()
    crypto_libs = (
        _v33_command_available("openssl") or
        _v33_command_available("gpg")
    )
    data_layers = sum([luks, crypto_libs])
    results.append(_v33_cisa_result(
        "CISA ZTMM v3.3 - Pillar 5 Data",
        "Pass" if data_layers >= 1 else "Warning",
        f"ZTMM Data: encryption layers ({data_layers}/2)",
        severity="High",
        details=f"LUKS: {luks}, crypto libs: {crypto_libs}",
        cross_references={
            "CISA-ZTMM": "Pillar 5 Data", "NIST": "SC-28",
        },
    ))

    # Cross-cutting: Visibility and Analytics
    audit_active = _v33_systemd_active("auditd.service") == "active"
    rsy_remote = False
    rsy_conf = _v33_read_file_safe("/etc/rsyslog.conf")
    if "@@" in rsy_conf or "omfwd" in rsy_conf:
        rsy_remote = True
    if not rsy_remote and _v33_directory_exists("/etc/rsyslog.d"):
        for f in _v33_list_directory("/etc/rsyslog.d"):
            c = _v33_read_file_safe(os.path.join("/etc/rsyslog.d", f))
            if "@@" in c or "omfwd" in c:
                rsy_remote = True
                break
    visibility_layers = sum([audit_active, rsy_remote])
    results.append(_v33_cisa_result(
        "CISA ZTMM v3.3 - Visibility & Analytics",
        "Pass" if visibility_layers >= 2 else "Warning",
        f"ZTMM Visibility: audit+SIEM ({visibility_layers}/2)",
        severity="High",
        details=f"auditd: {audit_active}, remote forwarding: {rsy_remote}",
        cross_references={
            "CISA-ZTMM": "Cross-cutting Visibility", "NIST": "AU-6",
        },
    ))

    # Cross-cutting: Automation and Orchestration
    cm_tools = {
        "ansible": _v33_command_available("ansible"),
        "puppet": _v33_command_available("puppet"),
        "salt": (_v33_command_available("salt-minion") or
                 _v33_command_available("salt-call")),
    }
    detected_cm = [k for k, v in cm_tools.items() if v]
    results.append(_v33_cisa_result(
        "CISA ZTMM v3.3 - Automation",
        "Info",
        f"ZTMM Automation: CM agents ({len(detected_cm)})",
        severity="Informational",
        details=f"Detected: {detected_cm or 'none'}",
        cross_references={
            "CISA-ZTMM": "Cross-cutting Automation", "NIST": "CM-2(2)",
        },
    ))

    # Cross-cutting: Governance
    pam_dir = "/etc/pam.d"
    pam_files_count = (
        len(_v33_list_directory(pam_dir))
        if _v33_directory_exists(pam_dir) else 0
    )
    results.append(_v33_cisa_result(
        "CISA ZTMM v3.3 - Governance",
        "Pass" if pam_files_count >= 10 else "Warning",
        f"ZTMM Governance: PAM policy modules ({pam_files_count})",
        severity="Medium",
        details=f"PAM files: {pam_files_count}",
        cross_references={
            "CISA-ZTMM": "Cross-cutting Governance", "NIST": "PL-1",
        },
    ))


def _check_cisa_v33_bod_directives(results, shared_data, os_info):
    """CISA Binding Operational Directives technical indicators."""

    # BOD 22-01 Known Exploited Vulnerabilities (KEV)
    update_active = (
        _v33_systemd_active("unattended-upgrades.service") == "active" or
        _v33_systemd_active("dnf-automatic-install.timer") == "active"
    )
    results.append(_v33_cisa_result(
        "CISA BOD 22-01 v3.3 - KEV",
        "Pass" if update_active else "Fail",
        "BOD 22-01 Patching automation for KEV catalog",
        severity="Critical",
        details=f"Auto-update active: {update_active}",
        remediation="Enable unattended-upgrades or dnf-automatic-install.timer",
        cross_references={
            "CISA-BOD": "22-01", "NIST": "SI-2",
        },
    ))

    # BOD 23-01 Improving Asset Visibility and Vulnerability Detection
    asset_visibility = {
        "osquery": _v33_command_available("osqueryi"),
        "wazuh": _v33_file_exists("/var/ossec/etc/ossec.conf"),
        "auditd": _v33_systemd_active("auditd.service") == "active",
    }
    detected_av = [k for k, v in asset_visibility.items() if v]
    results.append(_v33_cisa_result(
        "CISA BOD 23-01 v3.3 - Asset Visibility",
        "Pass" if len(detected_av) >= 1 else "Warning",
        f"BOD 23-01 Asset visibility tools ({len(detected_av)})",
        severity="High",
        details=f"Detected: {detected_av}",
        remediation=(
            "Deploy osquery for endpoint visibility: "
            "https://osquery.io/downloads"
        ),
        cross_references={
            "CISA-BOD": "23-01", "NIST": "CM-8",
        },
    ))


def _check_cisa_v33_secure_by_design(results, shared_data, os_info):
    """CISA Secure by Design principles - technical indicators."""

    # Memory-safe languages: indicator via runtime presence
    runtimes = {
        "rust": _v33_command_available("rustc") or _v33_command_available("cargo"),
        "go": _v33_command_available("go"),
    }
    msl_detected = [k for k, v in runtimes.items() if v]
    results.append(_v33_cisa_result(
        "CISA SbD v3.3 - Memory-Safe Languages",
        "Info",
        f"Memory-safe language runtimes ({len(msl_detected)})",
        severity="Informational",
        details=f"Detected: {msl_detected or 'none'}",
        remediation=(
            "CISA recommends migration to memory-safe languages "
            "(Rust, Go) for new development"
        ),
        cross_references={
            "CISA-SbD": "Memory Safety", "NIST": "SA-15",
        },
    ))

    # Default-secure configuration: SSH PermitRootLogin
    sshd = _v33_read_file_safe("/etc/ssh/sshd_config")
    permit_root_match = re.search(r"^\s*PermitRootLogin\s+(\S+)", sshd, re.MULTILINE)
    permit_root = permit_root_match.group(1) if permit_root_match else "yes"
    secure_default = permit_root.lower() in ("no", "prohibit-password",
                                              "without-password")
    results.append(_v33_cisa_result(
        "CISA SbD v3.3 - Default Secure",
        "Pass" if secure_default else "Fail",
        f"Secure-by-default SSH (PermitRootLogin: {permit_root})",
        severity="High",
        details=f"PermitRootLogin = {permit_root}",
        remediation="In /etc/ssh/sshd_config: PermitRootLogin no",
        cross_references={
            "CISA-SbD": "Default Secure", "NIST": "AC-6",
        },
    ))

    # Hardening principles: kernel parameters
    aslr = _v33_read_sysctl("kernel.randomize_va_space") == "2"
    nx_safe = "nx" in _v33_read_file_safe("/proc/cpuinfo")
    hardening_count = sum([aslr, nx_safe])
    results.append(_v33_cisa_result(
        "CISA SbD v3.3 - Hardening Principles",
        "Pass" if hardening_count >= 2 else "Warning",
        f"Memory protection (ASLR + NX): {hardening_count}/2",
        severity="High",
        details=f"ASLR: {aslr}, NX: {nx_safe}",
        cross_references={
            "CISA-SbD": "Hardening", "NIST": "SI-16",
        },
    ))


# Save reference to existing run_checks
_original_run_checks_cisa_v33 = run_checks


def run_checks(shared_data):
    """Execute the v3.3 expanded CISA module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_cisa_v33(shared_data)

    os_info = shared_data.get("os_info") or shared_data.get("v3_os_info")
    if os_info is None:
        from shared_components import os_detection as _os_det
        os_info = _os_det.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        _check_cisa_v33_cpg_account_security(results, shared_data, os_info)
        _check_cisa_v33_cpg_data_security(results, shared_data, os_info)
        _check_cisa_v33_cpg_vulnerability_mgmt(results, shared_data, os_info)
        _check_cisa_v33_cpg_supply_chain(results, shared_data, os_info)
        _check_cisa_v33_cpg_response_recovery(results, shared_data, os_info)
        _check_cisa_v33_ztmm(results, shared_data, os_info)
        _check_cisa_v33_bod_directives(results, shared_data, os_info)
        _check_cisa_v33_secure_by_design(results, shared_data, os_info)
    except Exception as exc:  # noqa: BLE001
        results.append(AuditResult(
            module=MODULE_NAME, category="CISA - Error",
            status="Error",
            message=f"CISA v3.3 expansion exception: {exc!r}",
            details=str(exc), severity="Medium",
        ))

    return results


# ============================================================================
# v3.5 EXPANSION - CISA Secure by Design + KEV + Zero Trust + Ransomware
# ----------------------------------------------------------------------------
# Synopsis:
#   Adds depth across CISA guidance areas:
#     - CISA Secure by Design (SbD) principles depth
#     - CISA Known Exploited Vulnerabilities (KEV) catalog readiness
#     - CISA Zero Trust Maturity Model (ZTMM) Pillars 1-5 depth
#     - CISA Stop Ransomware guidance
#     - CISA Shields Up activities
#     - CISA Cybersecurity Performance Goals (CPGs) extended
# ============================================================================

# v3.5 helpers
from shared_components.module_helpers import (
    read_file_safe as _v35_read_file_safe,
    file_exists as _v35_file_exists,
    directory_exists as _v35_directory_exists,
    command_available as _v35_command_available,
    run_command as _v35_run_command,
    read_sysctl as _v35_read_sysctl,
    systemd_active as _v35_systemd_active,
    list_directory as _v35_list_directory,
)


def _v35_cisa_result(category, status, message, severity="Medium",
                    details="", remediation="", cross_references=None):
    """Build AuditResult for CISA v3.5 expansion."""
    return AuditResult(
        module=MODULE_NAME,
        category=category,
        status=status,
        message=message,
        details=details,
        remediation=remediation,
        severity=severity,
        cross_references=cross_references or {},
    )


def _check_cisa_v35_secure_by_design_depth(results, shared_data, os_info):
    """CISA Secure by Design (SbD) principles depth."""
    cat = "CISA v3.5 - SbD"

    # SbD Principle 1: Take Ownership of Customer Security Outcomes
    # Surrogate: package signing infrastructure + auto-patch
    sbd_p1_layers = sum([
        bool(
            _v35_directory_exists("/etc/apt/keyrings") or
            _v35_directory_exists("/etc/apt/trusted.gpg.d") or
            _v35_directory_exists("/etc/pki/rpm-gpg")
        ),
        bool(
            _v35_systemd_active("unattended-upgrades.service") == "active" or
            _v35_systemd_active("dnf-automatic-install.timer") == "active" or
            _v35_systemd_active("dnf-automatic.timer") == "active"
        ),
    ])
    results.append(_v35_cisa_result(
        f"{cat} - P1 Customer Outcomes",
        "Pass" if sbd_p1_layers >= 2 else "Warning",
        f"CISA SbD P1 Customer outcome layers: {sbd_p1_layers}/2",
        severity="Medium",
        details=f"Pkg signing + auto-patch: {sbd_p1_layers}",
        cross_references={
            "CISA-SbD": "P1",
            "NIST": "SI-2, SR-3",
        },
    ))

    # SbD Principle 2: Embrace Radical Transparency and Accountability
    # Surrogate: auditd + journald persistent + SBOM tooling
    sbd_p2_layers = sum([
        _v35_systemd_active("auditd.service") == "active",
        _v35_directory_exists("/var/log/journal"),
        _v35_command_available("syft") or _v35_command_available("trivy"),
    ])
    results.append(_v35_cisa_result(
        f"{cat} - P2 Transparency/Accountability",
        "Pass" if sbd_p2_layers >= 2 else "Warning",
        f"CISA SbD P2 Transparency layers (audit + persistence + SBOM): "
        f"{sbd_p2_layers}/3",
        severity="Medium",
        details=f"Layers: {sbd_p2_layers}",
        cross_references={
            "CISA-SbD": "P2",
            "NIST": "AU-2, SR-4",
        },
    ))

    # SbD Principle 3: Build Organizational Structure to Achieve SbD
    # Surrogate: configuration management + version control
    sbd_p3_layers = sum([
        _v35_command_available("git"),
        bool(
            _v35_command_available("ansible") or
            _v35_command_available("puppet") or
            _v35_command_available("salt") or
            _v35_command_available("etckeeper")
        ),
    ])
    results.append(_v35_cisa_result(
        f"{cat} - P3 Org Structure (Tools)",
        "Pass" if sbd_p3_layers >= 2 else "Info",
        f"CISA SbD P3 Org tooling: {sbd_p3_layers}/2",
        severity="Medium",
        details=f"git + config mgmt: {sbd_p3_layers}",
        cross_references={
            "CISA-SbD": "P3",
            "NIST": "CM-3, CM-5",
        },
    ))


def _check_cisa_v35_kev_readiness(results, shared_data, os_info):
    """CISA Known Exploited Vulnerabilities (KEV) catalog readiness."""
    cat = "CISA v3.5 - KEV"

    # Auto-patch active for KEV remediation timeline
    auto_patch = (
        _v35_systemd_active("unattended-upgrades.service") == "active" or
        _v35_systemd_active("dnf-automatic-install.timer") == "active" or
        _v35_systemd_active("dnf-automatic.timer") == "active"
    )
    results.append(_v35_cisa_result(
        f"{cat} - KEV Auto-Patch",
        "Pass" if auto_patch else "Warning",
        f"CISA KEV auto-patch active: {auto_patch}",
        severity="Critical",
        details=f"Auto-patch active: {auto_patch}",
        remediation=(
            remediation_for("unattended-upgrades")
            if (os_info and os_info.is_debian_family())
            else remediation_for("dnf-automatic")
        ),
        cross_references={
            "CISA": "BOD 22-01 KEV",
            "NIST": "SI-2(2)",
        },
    ))

    # Vuln scanning capability for KEV detection
    vuln_tools = sum(_v35_command_available(t) for t in
                     ["lynis", "oscap", "trivy", "grype", "debsecan"])
    results.append(_v35_cisa_result(
        f"{cat} - KEV Detection Tools",
        "Pass" if vuln_tools >= 2 else "Warning",
        f"CISA KEV detection tools: {vuln_tools}/5",
        severity="High",
        details=f"Tools: {vuln_tools}",
        remediation=(
            "apt-get install -y lynis libopenscap8 debsecan\n"
            "Trivy: https://github.com/aquasecurity/trivy"
        ),
        cross_references={
            "CISA": "KEV Catalog Use",
            "NIST": "RA-5",
        },
    ))


def _check_cisa_v35_ztmm_pillars(results, shared_data, os_info):
    """CISA Zero Trust Maturity Model (ZTMM) Pillars 1-5 depth."""
    cat = "CISA v3.5 - ZTMM"

    # Pillar 1: Identity (MFA, continuous authentication)
    pam_files_content = ""
    for pf in ["/etc/pam.d/sshd", "/etc/pam.d/system-auth",
                "/etc/pam.d/password-auth", "/etc/pam.d/common-auth"]:
        pam_files_content += "\n" + _v35_read_file_safe(pf)
    pam_mfa = any(mod in pam_files_content for mod in [
        "pam_google_authenticator", "pam_yubico", "pam_oath", "pam_u2f", "pam_duo",
    ])
    results.append(_v35_cisa_result(
        f"{cat} - Pillar 1 Identity (MFA)",
        "Pass" if pam_mfa else "Warning",
        f"ZTMM Pillar 1 MFA detected: {pam_mfa}",
        severity="High",
        details=f"PAM MFA module: {pam_mfa}",
        cross_references={
            "CISA-ZTMM": "Pillar 1",
            "NIST": "IA-2(11)",
        },
    ))

    # Pillar 2: Devices (FIM, integrity monitoring)
    fim_present = (
        _v35_file_exists("/var/lib/aide/aide.db") or
        _v35_file_exists("/var/lib/aide/aide.db.gz") or
        _v35_file_exists("/var/lib/tripwire/tw.db")
    )
    results.append(_v35_cisa_result(
        f"{cat} - Pillar 2 Devices (FIM)",
        "Pass" if fim_present else "Warning",
        f"ZTMM Pillar 2 device integrity (FIM): {fim_present}",
        severity="High",
        details=f"FIM database: {fim_present}",
        cross_references={
            "CISA-ZTMM": "Pillar 2",
            "NIST": "SI-7",
        },
    ))

    # Pillar 3: Networks (segmentation indicators)
    rc, out, _ = _v35_run_command(["nft", "list", "ruleset"], timeout=5.0)
    nft_present = rc == 0 and bool(out and out.strip())
    rc, out, _ = _v35_run_command(["firewall-cmd", "--state"], timeout=3.0)
    firewalld_active = rc == 0 and "running" in (out or "")
    network_segmented = nft_present or firewalld_active
    results.append(_v35_cisa_result(
        f"{cat} - Pillar 3 Networks",
        "Pass" if network_segmented else "Warning",
        f"ZTMM Pillar 3 Network segmentation tooling: {network_segmented}",
        severity="High",
        details=f"nftables/firewalld: {network_segmented}",
        cross_references={
            "CISA-ZTMM": "Pillar 3",
            "NIST": "SC-7",
        },
    ))

    # Pillar 4: Applications and Workloads (containers, MAC)
    container_runtime = (
        _v35_command_available("docker") or
        _v35_command_available("podman") or
        _v35_command_available("containerd")
    )
    mac_active = (
        (_v35_command_available("getenforce") and
         (_v35_run_command(["getenforce"], timeout=2.0)[1] or "").strip()
         == "Enforcing") or _v35_command_available("aa-status")
    )
    workload_isolation = container_runtime or mac_active
    results.append(_v35_cisa_result(
        f"{cat} - Pillar 4 Applications/Workloads",
        "Pass" if workload_isolation else "Warning",
        f"ZTMM Pillar 4 Workload isolation: {workload_isolation}",
        severity="Medium",
        details=(
            f"Container runtime: {container_runtime}, MAC: {mac_active}"
        ),
        cross_references={
            "CISA-ZTMM": "Pillar 4",
            "NIST": "SC-39",
        },
    ))

    # Pillar 5: Data (at-rest encryption, classification, DLP)
    luks_present = False
    rc, out, _ = _v35_run_command(["lsblk", "-o", "TYPE", "-n"], timeout=5.0)
    if rc == 0 and out and "crypt" in out.lower():
        luks_present = True
    results.append(_v35_cisa_result(
        f"{cat} - Pillar 5 Data Protection",
        "Pass" if luks_present else "Warning",
        f"ZTMM Pillar 5 Data at-rest encryption (LUKS): {luks_present}",
        severity="High",
        details=f"LUKS volumes: {luks_present}",
        cross_references={
            "CISA-ZTMM": "Pillar 5",
            "NIST": "SC-28",
        },
    ))

    # Cross-cutting: Visibility & Analytics, Automation & Orchestration
    cross_cutting = sum([
        # Visibility
        bool(_v35_systemd_active("auditd.service") == "active"),
        bool(_v35_directory_exists("/var/log/journal")),
        # Automation/Orchestration
        bool(_v35_command_available("ansible") or _v35_command_available("puppet")),
        # Centralized logging
        any("@@" in _v35_read_file_safe("/etc/rsyslog.conf") or
            "omfwd" in _v35_read_file_safe("/etc/rsyslog.conf") or
            (_v35_directory_exists("/etc/rsyslog.d") and any(
                "@@" in _v35_read_file_safe(os.path.join("/etc/rsyslog.d", f)) or
                "omfwd" in _v35_read_file_safe(os.path.join("/etc/rsyslog.d", f))
                for f in _v35_list_directory("/etc/rsyslog.d")
            )) for _ in [None]),
    ])
    results.append(_v35_cisa_result(
        f"{cat} - Cross-Cutting Capabilities",
        "Pass" if cross_cutting >= 3 else "Warning",
        f"ZTMM Cross-cutting capabilities: {cross_cutting}/4",
        severity="Medium",
        details=f"Layers: {cross_cutting}",
        cross_references={
            "CISA-ZTMM": "Visibility/Analytics, Automation/Orchestration",
            "NIST": "AU-6, CA-7",
        },
    ))


def _check_cisa_v35_stop_ransomware(results, shared_data, os_info):
    """CISA Stop Ransomware guidance."""
    cat = "CISA v3.5 - Stop Ransomware"

    # Anti-ransomware foundation: 3-2-1 backup + offline
    backup_layers = sum([
        bool(any(_v35_command_available(t) for t in [
            "borg", "restic", "duplicity",
        ])),
        bool(any(_v35_command_available(t) for t in [
            "zfs", "btrfs", "snapper",
        ])),
    ])
    encrypted_backup = bool(
        _v35_command_available("borg") or
        _v35_command_available("restic")
    )
    backup_score = backup_layers + (1 if encrypted_backup else 0)
    results.append(_v35_cisa_result(
        f"{cat} - 3-2-1 Backup Foundation",
        "Pass" if backup_score >= 2 else "Warning",
        f"CISA Stop Ransomware backup foundation: {backup_score}/3",
        severity="Critical",
        details=(
            f"backup tools layers: {backup_layers}, "
            f"encrypted: {encrypted_backup}"
        ),
        remediation=remediation_for("borg"),
        cross_references={
            "CISA": "Stop Ransomware",
            "NIST": "CP-9, CP-9(8)",
        },
    ))

    # Network segmentation for ransomware containment
    segmentation_layers = sum([
        bool(
            _v35_systemd_active("ufw.service") == "active" or
            (_v35_run_command(["firewall-cmd", "--state"], timeout=3.0)[0] == 0 and
             "running" in (_v35_run_command(
                ["firewall-cmd", "--state"], timeout=3.0,
            )[1] or ""))
        ),
        # MAC enforcement
        bool(
            (_v35_command_available("getenforce") and
             (_v35_run_command(["getenforce"], timeout=2.0)[1] or "").strip()
             == "Enforcing") or _v35_command_available("aa-status")
        ),
        # Mount restrictions
        ("noexec" in _v35_read_file_safe("/etc/fstab") or
         "nodev" in _v35_read_file_safe("/etc/fstab")),
    ])
    results.append(_v35_cisa_result(
        f"{cat} - Containment Layers",
        "Pass" if segmentation_layers >= 2 else "Warning",
        f"CISA Stop Ransomware containment: {segmentation_layers}/3",
        severity="High",
        details=f"Layers: {segmentation_layers}",
        cross_references={
            "CISA": "Stop Ransomware",
            "NIST": "SC-7, AC-3",
        },
    ))

    # Anti-malware + EDR
    anti_malware_layers = sum([
        bool(
            _v35_systemd_active("clamav-daemon.service") == "active" or
            _v35_systemd_active("clamd.service") == "active"
        ),
        _v35_command_available("rkhunter"),
        _v35_command_available("chkrootkit"),
        _v35_file_exists("/var/ossec/etc/ossec.conf"),
        _v35_systemd_active("falco.service") == "active",
    ])
    results.append(_v35_cisa_result(
        f"{cat} - Anti-Malware/EDR Layers",
        "Pass" if anti_malware_layers >= 2 else "Warning",
        f"CISA Stop Ransomware AV/EDR layers: {anti_malware_layers}/5",
        severity="High",
        details=f"Layers: {anti_malware_layers}",
        cross_references={
            "CISA": "Stop Ransomware",
            "NIST": "SI-3, SI-4",
        },
    ))


def _check_cisa_v35_shields_up(results, shared_data, os_info):
    """CISA Shields Up heightened-defense activities."""
    cat = "CISA v3.5 - Shields Up"

    # Shields Up: validate logging is comprehensive
    logging_comprehensive = (
        _v35_systemd_active("auditd.service") == "active" and
        _v35_directory_exists("/var/log/journal")
    )
    # Centralized logging
    rsy = _v35_read_file_safe("/etc/rsyslog.conf")
    siem_forward = "@@" in rsy or "omfwd" in rsy
    if not siem_forward and _v35_directory_exists("/etc/rsyslog.d"):
        for f in _v35_list_directory("/etc/rsyslog.d"):
            c = _v35_read_file_safe(os.path.join("/etc/rsyslog.d", f))
            if "@@" in c or "omfwd" in c:
                siem_forward = True
                break
    shields_up_logging = logging_comprehensive and siem_forward
    results.append(_v35_cisa_result(
        f"{cat} - Logging Comprehensive",
        "Pass" if shields_up_logging else "Warning",
        f"CISA Shields Up comprehensive logging: {shields_up_logging}",
        severity="High",
        details=(
            f"auditd + persistent + SIEM forward: {shields_up_logging}"
        ),
        cross_references={
            "CISA": "Shields Up",
            "NIST": "AU-6, AU-12",
        },
    ))

    # Shields Up: backup verification
    backup_recent = False
    cron_backup_dirs = ["/etc/cron.daily", "/etc/cron.hourly"]
    for d in cron_backup_dirs:
        if not _v35_directory_exists(d):
            continue
        for f in _v35_list_directory(d):
            f_lower = f.lower()
            if any(k in f_lower for k in [
                "backup", "borg", "restic", "duplicity",
            ]):
                backup_recent = True
                break
        if backup_recent:
            break
    results.append(_v35_cisa_result(
        f"{cat} - Backup Active",
        "Pass" if backup_recent else "Warning",
        f"CISA Shields Up daily backup automation: {backup_recent}",
        severity="High",
        details=f"Backup cron job: {backup_recent}",
        cross_references={
            "CISA": "Shields Up",
            "NIST": "CP-9",
        },
    ))


# Save reference to existing run_checks
_original_run_checks_cisa_v35 = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the v3.5 expanded CISA module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_cisa_v35(shared_data)

    os_info = shared_data.get("os_info") or shared_data.get("v3_os_info")
    if os_info is None:
        from shared_components import os_detection as _os_det
        os_info = _os_det.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        _check_cisa_v35_secure_by_design_depth(results, shared_data, os_info)
        _check_cisa_v35_kev_readiness(results, shared_data, os_info)
        _check_cisa_v35_ztmm_pillars(results, shared_data, os_info)
        _check_cisa_v35_stop_ransomware(results, shared_data, os_info)
        _check_cisa_v35_shields_up(results, shared_data, os_info)
    except Exception as exc:  # noqa: BLE001
        results.append(AuditResult(
            module=MODULE_NAME, category="CISA - Error",
            status="Error",
            message=f"CISA v3.5 expansion exception: {exc!r}",
            details=str(exc), severity="Medium",
        ))

    return results
if __name__ == "__main__":
    """Allow module to be run standalone for testing"""
    import socket
    import platform
    
    print("="*70)
    print(f"Testing {MODULE_NAME} Module - CISA Security Controls v{MODULE_VERSION}")
    print("="*70)
    
    test_shared_data = {
        "hostname": socket.gethostname(),
        "os_version": f"{platform.system()} {platform.release()}",
        "scan_date": datetime.now(),
        "is_root": os.geteuid() == 0,
        "script_path": Path(__file__).parent if hasattr(Path(__file__), 'parent') else Path.cwd()
    }
    
    print(f"\nTest Environment:")
    print(f"  Hostname: {test_shared_data['hostname']}")
    print(f"  OS: {test_shared_data['os_version']}")
    print(f"  Running as root: {test_shared_data['is_root']}")
    print(f"  Scan time: {test_shared_data['scan_date'].strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)
    
    test_results = run_checks(test_shared_data)
    
    print(f"\n{'='*70}")
    print(f"COMPREHENSIVE TEST RESULTS")
    print(f"{'='*70}")
    print(f"Generated {len(test_results)} results")
    print("="*70)
    
    # Status summary
    from collections import Counter
    status_counts = Counter(r.status for r in test_results)
    
    print("\nSummary by Status:")
    for status in ["Pass", "Fail", "Warning", "Info", "Error"]:
        count = status_counts.get(status, 0)
        if count > 0:
            pct = (count / len(test_results)) * 100
            print(f"  {status}: {count} ({pct:.1f}%)")
    
    # Priority summary
    critical_total = sum(1 for r in test_results if "Critical" in r.message)
    high_total = sum(1 for r in test_results if "High" in r.message)
    medium_total = sum(1 for r in test_results if "Medium" in r.message)
    low_total = sum(1 for r in test_results if "Low" in r.message)
    
    critical_fail = sum(1 for r in test_results if "Critical" in r.message and r.status == "Fail")
    high_fail = sum(1 for r in test_results if "High" in r.message and r.status == "Fail")
    medium_fail = sum(1 for r in test_results if "Medium" in r.message and r.status == "Fail")
    low_fail = sum(1 for r in test_results if "Low" in r.message and r.status == "Fail")
    
    if critical_total > 0 or high_total > 0 or medium_total > 0:
        print("\nSummary by CISA Priority:")
        if critical_total > 0:
            print(f"  Critical: {critical_total} checks, {critical_fail} failures")
        if high_total > 0:
            print(f"  High: {high_total} checks, {high_fail} failures")
        if medium_total > 0:
            print(f"  Medium: {medium_total} checks, {medium_fail} failures")
        if low_total > 0:
            print(f"  Low: {low_total} checks, {low_fail} failures")
    
    # Category summary
    categories = {}
    for result in test_results:
        cat = result.category
        if cat not in categories:
            categories[cat] = {"total": 0, "fail": 0}
        categories[cat]["total"] += 1
        if result.status == "Fail":
            categories[cat]["fail"] += 1
    
    print("\nSummary by Category:")
    for category in sorted(categories.keys()):
        total = categories[category]['total']
        fail = categories[category]['fail']
        print(f"  {category}: {total} checks, {fail} failures")
    
    # BOD-specific summary
    bod_22_01 = [r for r in test_results if "BOD 22-01" in r.category]
    bod_23_01 = [r for r in test_results if "BOD 23-01" in r.category]
    
    print("\nBinding Operational Directives:")
    if bod_22_01:
        bod_22_fail = sum(1 for r in bod_22_01 if r.status == "Fail")
        print(f"  BOD 22-01 (KEV): {len(bod_22_01)} checks, {bod_22_fail} failures")
    if bod_23_01:
        bod_23_fail = sum(1 for r in bod_23_01 if r.status == "Fail")
        print(f"  BOD 23-01 (Asset Visibility): {len(bod_23_01)} checks, {bod_23_fail} failures")
    
    print("\n" + "="*70)
    print(f"CISA Cybersecurity Directives module test complete")
    print(f"Version: {MODULE_VERSION}")
    print(f"Total Checks Executed: {len(test_results)}")
    print("="*70)
    
    # Display critical failures
    critical_failures = [r for r in test_results if r.status == "Fail" and "Critical" in r.message]
    if critical_failures:
        print(f"\n  {len(critical_failures)} CRITICAL FAILURES DETECTED:")
        for i, failure in enumerate(critical_failures[:5], 1):
            print(f"  {i}. {failure.message}")
        if len(critical_failures) > 5:
            print(f"  ... and {len(critical_failures) - 5} more")
    
    # Display high-priority failures
    high_failures = [r for r in test_results if r.status == "Fail" and "High" in r.message]
    if high_failures:
        print(f"\n  {len(high_failures)} HIGH-PRIORITY FAILURES DETECTED:")
        for i, failure in enumerate(high_failures[:5], 1):
            print(f"  {i}. {failure.message}")
        if len(high_failures) > 5:
            print(f"  ... and {len(high_failures) - 5} more")
    
    print("\n" + "="*70)
    print("End of CISA module test")
    print("="*70)
