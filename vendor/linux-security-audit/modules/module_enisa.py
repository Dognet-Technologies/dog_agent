#!/usr/bin/env python3
"""
module_enisa.py
ENISA Cybersecurity Recommendations Module for Linux
Version: 2.0

SYNOPSIS:
    Comprehensive ENISA cybersecurity compliance assessment for Linux systems
    based on EU Agency for Cybersecurity guidelines and recommendations.

DESCRIPTION:
    This module performs thorough security checks aligned with ENISA guidance:
    
    ENISA Cybersecurity Coverage:
    - Baseline Security Measures
    - Network Security Controls
    - System Hardening & Configuration
    - Access Control & Identity Management
    - Data Protection & Privacy (GDPR-aligned)
    - Logging, Monitoring & Incident Response
    - Cryptographic Controls
    - Vulnerability & Patch Management
    - Secure Development & Operations
    
    OS-Specific Adaptations:
    - Debian-based: Ubuntu, Debian, Linux Mint, Kali Linux
      * APT package management
      * AppArmor integration
      * Debian-specific security configurations
    
    - RedHat-based: RHEL, Fedora, CentOS, Rocky, AlmaLinux
      * YUM/DNF package management
      * SELinux integration
      * RedHat-specific security configurations
    
    Key ENISA References:
    - ENISA Cybersecurity Guide for SMEs
    - ENISA Threat Landscape
    - ENISA Good Practices for Security
    - ENISA Baseline Security Recommendations
    - ENISA Guidelines for Incident Response

PARAMETERS:
    shared_data : Dictionary containing shared data from main script

USAGE:
	Standalone module test:
		python3 module_enisa.py

	Integration with main audit script:
		python3 linux_security_audit.py --modules ENISA
        python3 linux_security_audit.py -m ENISA

NOTES:
    Version: 2.0
    Focus: ENISA Cybersecurity Recommendations for EU
    Target: 100+ Comprehensive Cybersecurity Audit Checks; OS-aware security checks
    Module automatically detects OS via module_core integration
	
    ENISA Context:
    - European Union Agency for Cybersecurity
    - Provides cybersecurity guidance for EU member states
    - Focus on practical, implementable security measures
    - Alignment with GDPR requirements where applicable
    
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

MODULE_NAME = "ENISA"

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

def get_enisa_id(category: str, number: int) -> str:
    """Generate ENISA control ID"""
    return f"ENISA-{category}-{number:03d}"

def check_password_policy() -> Dict[str, Any]:
    """Get password policy settings"""
    policy = {
        'max_days': None,
        'min_days': None,
        'min_length': None,
        'warn_age': None,
        'complexity': False
    }
    
    if os.path.exists("/etc/login.defs"):
        content = read_file_safe("/etc/login.defs")
        
        max_days = re.search(r'^PASS_MAX_DAYS\s+(\d+)', content, re.MULTILINE)
        if max_days:
            policy['max_days'] = int(max_days.group(1))
        
        min_days = re.search(r'^PASS_MIN_DAYS\s+(\d+)', content, re.MULTILINE)
        if min_days:
            policy['min_days'] = int(min_days.group(1))
        
        min_len = re.search(r'^PASS_MIN_LEN\s+(\d+)', content, re.MULTILINE)
        if min_len:
            policy['min_length'] = int(min_len.group(1))
        
        warn = re.search(r'^PASS_WARN_AGE\s+(\d+)', content, re.MULTILINE)
        if warn:
            policy['warn_age'] = int(warn.group(1))
    
    # Check for password complexity
    pam_files = glob.glob("/etc/pam.d/*")
    for pam_file in pam_files:
        content = read_file_safe(pam_file)
        if 'pam_pwquality' in content or 'pam_cracklib' in content:
            policy['complexity'] = True
            break
    
    return policy

def get_system_hardening_status() -> Dict[str, bool]:
    """Check various system hardening measures"""
    hardening = {
        'aslr': False,
        'exec_shield': False,
        'nx': False,
        'selinux': False,
        'apparmor': False,
        'firewall': False
    }
    
    # ASLR
    exists, aslr = check_kernel_parameter("kernel.randomize_va_space")
    hardening['aslr'] = aslr == "2"
    
    # Exec Shield
    exists, exec_shield = check_kernel_parameter("kernel.exec-shield")
    hardening['exec_shield'] = exec_shield == "1"
    
    # NX bit
    result = run_command("grep -q ' nx ' /proc/cpuinfo")
    hardening['nx'] = result.returncode == 0
    
    # SELinux
    if command_exists('getenforce'):
        result = run_command("getenforce")
        hardening['selinux'] = 'enforcing' in result.stdout.lower()
    
    # AppArmor
    hardening['apparmor'] = check_service_active('apparmor')
    
    # Firewall
    firewall_services = ['ufw', 'firewalld', 'iptables']
    hardening['firewall'] = any(check_service_active(svc) for svc in firewall_services)
    
    return hardening

def check_logging_configured() -> Dict[str, bool]:
    """Check logging configuration"""
    logging = {
        'syslog': False,
        'auditd': False,
        'remote': False,
        'rotation': False
    }
    
    # System logging
    logging_services = ['rsyslog', 'syslog-ng', 'systemd-journald']
    logging['syslog'] = any(check_service_active(svc) for svc in logging_services)
    
    # Audit daemon
    logging['auditd'] = check_service_active('auditd')
    
    # Remote logging
    if os.path.exists("/etc/rsyslog.conf"):
        content = read_file_safe("/etc/rsyslog.conf")
        logging['remote'] = bool(re.search(r'@@?\w', content))
    
    # Log rotation
    logging['rotation'] = os.path.exists("/etc/logrotate.conf")
    
    return logging

# ============================================================================
# BASELINE SECURITY
# ============================================================================

def check_baseline_security(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    ENISA Baseline Security Measures
    Essential security controls recommended by ENISA
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Baseline Security Measures...")
    
    # BSM-001: Operating system up to date
    available_updates = get_available_updates(os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Baseline Security",
        status="Pass" if available_updates < 10 else "Warning" if available_updates < 50 else "Fail",
        message=f"{get_enisa_id('BSM', 1)}: Operating system updates current",
        details=f"{available_updates} updates available",
        remediation=f"Update system: {os_info.package_manager} upgrade"
    ))
    
    # BSM-002: Security updates applied
    security_updates = get_security_updates(os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Baseline Security",
        status="Pass" if security_updates == 0 else "Fail",
        message=f"{get_enisa_id('BSM', 2)}: Security updates applied",
        details=f"{security_updates} security updates pending",
        remediation="Apply security updates immediately"
    ))
    
    # BSM-003: Automatic updates configured
    if os_info.family == 'debian':
        auto_updates = check_package_installed('unattended-upgrades', os_info)
    elif os_info.family == 'redhat':
        auto_updates = check_package_installed('yum-cron', os_info) or check_package_installed('dnf-automatic', os_info)
    else:
        auto_updates = False
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Baseline Security",
        status="Pass" if auto_updates else "Warning",
        message=f"{get_enisa_id('BSM', 3)}: Automatic security updates configured",
        details="Configured" if auto_updates else "Not configured",
        remediation="Enable automatic updates for security patches"
    ))
    
    # BSM-004: Firewall enabled
    firewall_services = ['ufw', 'firewalld', 'iptables']
    firewall_active = any(check_service_active(svc) for svc in firewall_services)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Baseline Security",
        status="Pass" if firewall_active else "Fail",
        message=f"{get_enisa_id('BSM', 4)}: Host-based firewall active",
        details="Active" if firewall_active else "Not active",
        remediation="Enable firewall: ufw enable || firewall-cmd --reload"
    ))
    
    # BSM-005: Anti-malware installed
    av_installed = check_package_installed('clamav', os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Baseline Security",
        status="Pass" if av_installed else "Warning",
        message=f"{get_enisa_id('BSM', 5)}: Anti-malware software installed",
        details="ClamAV installed" if av_installed else "Not installed",
        remediation=remediation_for("clamav")
    ))
    
    # BSM-006: System logging active
    logging_status = check_logging_configured()
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Baseline Security",
        status="Pass" if logging_status['syslog'] else "Fail",
        message=f"{get_enisa_id('BSM', 6)}: System logging active",
        details="Active" if logging_status['syslog'] else "Not active",
        remediation="Enable: systemctl enable rsyslog"
    ))
    
    # BSM-007: Audit logging configured
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Baseline Security",
        status="Pass" if logging_status['auditd'] else "Warning",
        message=f"{get_enisa_id('BSM', 7)}: Audit logging configured",
        details="Active" if logging_status['auditd'] else "Not active",
        remediation=remediation_for("auditd")
    ))
    
    # BSM-008: Password policy configured
    password_policy = check_password_policy()
    policy_ok = (password_policy['max_days'] and password_policy['max_days'] <= 90 and
                 password_policy['min_days'] and password_policy['min_days'] >= 1 and
                 password_policy['complexity'])
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Baseline Security",
        status="Pass" if policy_ok else "Warning",
        message=f"{get_enisa_id('BSM', 8)}: Password policy enforced",
        details=f"Max: {password_policy['max_days']}, Min: {password_policy['min_days']}, Complex: {password_policy['complexity']}",
        remediation="Configure password policy in /etc/login.defs and PAM"
    ))
    
    # BSM-009: System hardening measures
    hardening = get_system_hardening_status()
    hardening_count = sum(hardening.values())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Baseline Security",
        status="Pass" if hardening_count >= 3 else "Warning",
        message=f"{get_enisa_id('BSM', 9)}: System hardening measures active",
        details=f"{hardening_count}/6 hardening features: {', '.join([k for k,v in hardening.items() if v])}",
        remediation="Enable ASLR, firewall, and MAC (SELinux/AppArmor)"
    ))
    
    # BSM-010: SSH hardening
    ssh_hardened = False
    if os.path.exists("/etc/ssh/sshd_config"):
        content = read_file_safe("/etc/ssh/sshd_config")
        checks = [
            re.search(r'^PermitRootLogin\s+no', content, re.MULTILINE),
            re.search(r'^PermitEmptyPasswords\s+no', content, re.MULTILINE),
            re.search(r'^Protocol\s+2', content, re.MULTILINE)
        ]
        ssh_hardened = sum(1 for c in checks if c) >= 2
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Baseline Security",
        status="Pass" if ssh_hardened else "Warning",
        message=f"{get_enisa_id('BSM', 10)}: SSH service hardened",
        details="Hardened" if ssh_hardened else "Not hardened",
        remediation="Configure SSH: PermitRootLogin no, PermitEmptyPasswords no"
    ))
    
    # BSM-011: Unnecessary services disabled
    unnecessary = ['telnet', 'ftp', 'rsh', 'rlogin', 'rexec']
    active_unnecessary = [svc for svc in unnecessary if check_service_active(svc)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Baseline Security",
        status="Pass" if not active_unnecessary else "Fail",
        message=f"{get_enisa_id('BSM', 11)}: Insecure services disabled",
        details=f"Active: {', '.join(active_unnecessary)}" if active_unnecessary else "All disabled",
        remediation="Disable insecure services: systemctl disable <service>"
    ))
    
    # BSM-012: Root account access restricted
    result = run_command("awk -F: '$3 == 0 {print $1}' /etc/passwd")
    uid0_accounts = [u.strip() for u in result.stdout.strip().split('\n') if u.strip()]
    only_root = len(uid0_accounts) == 1 and uid0_accounts[0] == 'root'
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Baseline Security",
        status="Pass" if only_root else "Fail",
        message=f"{get_enisa_id('BSM', 12)}: Only root has UID 0",
        details=f"UID 0: {', '.join(uid0_accounts)}",
        remediation="Remove UID 0 from non-root accounts"
    ))
    
    # BSM-013: No accounts with empty passwords
    result = run_command("awk -F: '$2 == \"\" {print $1}' /etc/shadow 2>/dev/null | wc -l")
    empty_passwords = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Baseline Security",
        status="Pass" if empty_passwords == 0 else "Fail",
        message=f"{get_enisa_id('BSM', 13)}: No accounts with empty passwords",
        details=f"{empty_passwords} accounts",
        remediation="Set passwords or lock accounts"
    ))
    
    # BSM-014: System backup configured
    backup_tools = ['rsync', 'tar', 'duplicity', 'bacula']
    installed_backup = [tool for tool in backup_tools if command_exists(tool)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Baseline Security",
        status="Pass" if installed_backup else "Warning",
        message=f"{get_enisa_id('BSM', 14)}: Backup tools available",
        details=f"Available: {', '.join(installed_backup)}" if installed_backup else "None",
        remediation="Install and configure backup tools"
    ))
    
    # BSM-015: Time synchronization
    time_services = ['chronyd', 'ntpd', 'systemd-timesyncd']
    time_active = any(check_service_active(svc) for svc in time_services)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Baseline Security",
        status="Pass" if time_active else "Warning",
        message=f"{get_enisa_id('BSM', 15)}: Time synchronization active",
        details="Active" if time_active else "Not active",
        remediation=remediation_for("chrony")
    ))
    
    # BSM-016: File integrity monitoring
    fim_tools = ['aide', 'tripwire', 'samhain']
    installed_fim = [tool for tool in fim_tools if check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Baseline Security",
        status="Pass" if installed_fim else "Warning",
        message=f"{get_enisa_id('BSM', 16)}: File integrity monitoring",
        details=f"Installed: {', '.join(installed_fim)}" if installed_fim else "Not installed",
        remediation=remediation_for("aide")
    ))
    
    # BSM-017: Disk encryption
    result = run_command("lsblk -o NAME,FSTYPE | grep -c crypt || echo 0")
    encrypted_volumes = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Baseline Security",
        status="Pass" if encrypted_volumes > 0 else "Info",
        message=f"{get_enisa_id('BSM', 17)}: Disk encryption (LUKS)",
        details=f"{encrypted_volumes} encrypted volumes",
        remediation="Enable full disk encryption for sensitive systems"
    ))
    
    # BSM-018: Secure boot
    secure_boot_enabled = os.path.exists("/sys/firmware/efi/efivars/SecureBoot-*")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Baseline Security",
        status="Info",
        message=f"{get_enisa_id('BSM', 18)}: Secure Boot status",
        details="Enabled" if secure_boot_enabled else "Not enabled/detected",
        remediation="Enable Secure Boot in UEFI firmware if supported"
    ))
    
    # BSM-019: Kernel hardening (ASLR)
    exists, aslr = check_kernel_parameter("kernel.randomize_va_space")
    aslr_enabled = aslr == "2"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Baseline Security",
        status="Pass" if aslr_enabled else "Fail",
        message=f"{get_enisa_id('BSM', 19)}: ASLR enabled",
        details=f"randomize_va_space = {aslr}",
        remediation="Enable: sysctl -w kernel.randomize_va_space=2"
    ))
    
    # BSM-020: Core dumps disabled
    exists, suid_dumpable = check_kernel_parameter("fs.suid_dumpable")
    dumps_disabled = suid_dumpable == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Baseline Security",
        status="Pass" if dumps_disabled else "Warning",
        message=f"{get_enisa_id('BSM', 20)}: SUID core dumps disabled",
        details=f"suid_dumpable = {suid_dumpable}",
        remediation="Disable: sysctl -w fs.suid_dumpable=0"
    ))
    
    # BSM-021: Network parameters hardened
    network_params = [
        ("net.ipv4.conf.all.accept_redirects", "0"),
        ("net.ipv4.conf.all.accept_source_route", "0"),
        ("net.ipv4.tcp_syncookies", "1")
    ]
    
    hardened_params = 0
    for param, expected in network_params:
        exists, value = check_kernel_parameter(param)
        if value == expected:
            hardened_params += 1
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Baseline Security",
        status="Pass" if hardened_params == len(network_params) else "Warning",
        message=f"{get_enisa_id('BSM', 21)}: Network parameters hardened",
        details=f"{hardened_params}/{len(network_params)} parameters configured",
        remediation="Configure network hardening in /etc/sysctl.conf"
    ))
    
    # BSM-022: Log rotation configured
    logrotate_installed = check_package_installed('logrotate', os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Baseline Security",
        status="Pass" if logrotate_installed else "Fail",
        message=f"{get_enisa_id('BSM', 22)}: Log rotation configured",
        details="Configured" if logrotate_installed else "Not configured",
        remediation="Install logrotate"
    ))
    
    # BSM-023: Sudo configured
    sudo_installed = check_package_installed('sudo', os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Baseline Security",
        status="Pass" if sudo_installed else "Fail",
        message=f"{get_enisa_id('BSM', 23)}: Sudo package installed",
        details="Installed" if sudo_installed else "Not installed",
        remediation="Install sudo for privilege escalation"
    ))
    
    # BSM-024: Security banners configured
    banner_files = ['/etc/issue', '/etc/issue.net', '/etc/motd']
    banners_configured = sum(1 for f in banner_files if os.path.exists(f) and os.path.getsize(f) > 0)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Baseline Security",
        status="Pass" if banners_configured >= 2 else "Info",
        message=f"{get_enisa_id('BSM', 24)}: Security banners configured",
        details=f"{banners_configured}/3 banner files configured",
        remediation="Configure security banners in /etc/issue and /etc/motd"
    ))
    
    # BSM-025: System monitoring
    mon_tools = ['monit', 'nagios', 'zabbix']
    installed_mon = [tool for tool in mon_tools if check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Baseline Security",
        status="Info",
        message=f"{get_enisa_id('BSM', 25)}: System monitoring tools",
        details=f"Installed: {', '.join(installed_mon)}" if installed_mon else "Not installed",
        remediation="Consider installing monitoring tools"
    ))

# ============================================================================
# NETWORK SECURITY CONTROLS
# ENISA network security recommendations
# ============================================================================

def check_network_security(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    ENISA Network Security Controls
    Network hardening and security measures
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Network Security Controls...")
    
    # NET-001: Firewall default policy
    firewall_active = any(check_service_active(svc) for svc in ['ufw', 'firewalld', 'iptables'])
    
    if firewall_active:
        result = run_command("iptables -L | grep 'Chain INPUT' | grep -E '(DROP|REJECT)'")
        default_deny = result.returncode == 0
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ENISA - Network Security",
            status="Pass" if default_deny else "Warning",
            message=f"{get_enisa_id('NET', 1)}: Firewall default deny policy",
            details="Default deny" if default_deny else "Check policy",
            remediation="Set default policy: iptables -P INPUT DROP"
        ))
    
    # NET-002: IP forwarding disabled
    exists, ip_forward = check_kernel_parameter("net.ipv4.ip_forward")
    forward_disabled = ip_forward == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Network Security",
        status="Pass" if forward_disabled else "Warning",
        message=f"{get_enisa_id('NET', 2)}: IP forwarding disabled",
        details=f"ip_forward = {ip_forward}",
        remediation="Disable: sysctl -w net.ipv4.ip_forward=0"
    ))
    
    # NET-003: ICMP redirects disabled
    exists, redirects = check_kernel_parameter("net.ipv4.conf.all.accept_redirects")
    redirects_disabled = redirects == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Network Security",
        status="Pass" if redirects_disabled else "Fail",
        message=f"{get_enisa_id('NET', 3)}: ICMP redirects disabled",
        details=f"accept_redirects = {redirects}",
        remediation="Disable: sysctl -w net.ipv4.conf.all.accept_redirects=0"
    ))
    
    # NET-004: Source routing disabled
    exists, source_route = check_kernel_parameter("net.ipv4.conf.all.accept_source_route")
    source_disabled = source_route == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Network Security",
        status="Pass" if source_disabled else "Fail",
        message=f"{get_enisa_id('NET', 4)}: Source routing disabled",
        details=f"accept_source_route = {source_route}",
        remediation="Disable: sysctl -w net.ipv4.conf.all.accept_source_route=0"
    ))
    
    # NET-005: TCP SYN cookies enabled
    exists, syn_cookies = check_kernel_parameter("net.ipv4.tcp_syncookies")
    syn_enabled = syn_cookies == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Network Security",
        status="Pass" if syn_enabled else "Warning",
        message=f"{get_enisa_id('NET', 5)}: TCP SYN cookies enabled",
        details=f"tcp_syncookies = {syn_cookies}",
        remediation="Enable: sysctl -w net.ipv4.tcp_syncookies=1"
    ))
    
    # NET-006: Reverse path filtering
    exists, rp_filter = check_kernel_parameter("net.ipv4.conf.all.rp_filter")
    rp_enabled = rp_filter == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Network Security",
        status="Pass" if rp_enabled else "Warning",
        message=f"{get_enisa_id('NET', 6)}: Reverse path filtering enabled",
        details=f"rp_filter = {rp_filter}",
        remediation="Enable: sysctl -w net.ipv4.conf.all.rp_filter=1"
    ))
    
    # NET-007: Log martian packets
    exists, log_martians = check_kernel_parameter("net.ipv4.conf.all.log_martians")
    martians_logged = log_martians == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Network Security",
        status="Pass" if martians_logged else "Info",
        message=f"{get_enisa_id('NET', 7)}: Martian packets logged",
        details=f"log_martians = {log_martians}",
        remediation="Enable: sysctl -w net.ipv4.conf.all.log_martians=1"
    ))
    
    # NET-008: ICMP broadcast ignored
    exists, icmp_broadcast = check_kernel_parameter("net.ipv4.icmp_echo_ignore_broadcasts")
    broadcast_ignored = icmp_broadcast == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Network Security",
        status="Pass" if broadcast_ignored else "Warning",
        message=f"{get_enisa_id('NET', 8)}: ICMP broadcast ignored",
        details=f"icmp_echo_ignore_broadcasts = {icmp_broadcast}",
        remediation="Enable: sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1"
    ))
    
    # NET-009: IPv6 configuration
    ipv6_disabled = not os.path.exists("/proc/sys/net/ipv6/conf/all/disable_ipv6") or \
                    read_file_safe("/proc/sys/net/ipv6/conf/all/disable_ipv6").strip() == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Network Security",
        status="Info",
        message=f"{get_enisa_id('NET', 9)}: IPv6 status",
        details="Disabled" if ipv6_disabled else "Enabled",
        remediation="Disable if not needed: sysctl -w net.ipv6.conf.all.disable_ipv6=1"
    ))
    
    # NET-010: Listening services minimized
    result = run_command("ss -tuln 2>/dev/null | grep LISTEN | wc -l")
    listening_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Network Security",
        status="Pass" if listening_count < 20 else "Info",
        message=f"{get_enisa_id('NET', 10)}: Listening network services",
        details=f"{listening_count} listening ports",
        remediation="Minimize listening services"
    ))
    
    # NET-011: DNS servers configured
    if os.path.exists("/etc/resolv.conf"):
        content = read_file_safe("/etc/resolv.conf")
        nameservers = content.count("nameserver")
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ENISA - Network Security",
            status="Pass" if nameservers >= 1 else "Warning",
            message=f"{get_enisa_id('NET', 11)}: DNS servers configured",
            details=f"{nameservers} nameservers",
            remediation="Configure DNS servers"
        ))
    
    # NET-012: Network interfaces
    result = run_command("ip link show | grep -c '^[0-9]'")
    interface_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Network Security",
        status="Info",
        message=f"{get_enisa_id('NET', 12)}: Network interfaces",
        details=f"{interface_count} interfaces",
        remediation="Review network interface configuration"
    ))
    
    # NET-013: Wireless interfaces
    result = run_command("iwconfig 2>&1 | grep -c 'IEEE' || echo 0")
    wireless_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Network Security",
        status="Info",
        message=f"{get_enisa_id('NET', 13)}: Wireless interfaces",
        details=f"{wireless_count} wireless interfaces",
        remediation="Disable unused wireless interfaces"
    ))
    
    # NET-014: Bluetooth status
    bluetooth_active = check_service_active('bluetooth')
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Network Security",
        status="Pass" if not bluetooth_active else "Info",
        message=f"{get_enisa_id('NET', 14)}: Bluetooth service",
        details="Disabled" if not bluetooth_active else "Active",
        remediation="Disable if not needed: systemctl disable bluetooth"
    ))
    
    # NET-015: SSH service configuration
    if os.path.exists("/etc/ssh/sshd_config"):
        content = read_file_safe("/etc/ssh/sshd_config")
        
        # Check SSH port
        port_match = re.search(r'^Port\s+(\d+)', content, re.MULTILINE)
        ssh_port = port_match.group(1) if port_match else "22"
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ENISA - Network Security",
            status="Info",
            message=f"{get_enisa_id('NET', 15)}: SSH service port",
            details=f"Port: {ssh_port}",
            remediation="Consider non-standard port for additional obscurity"
        ))
    
    # NET-016: Fail2ban for attack prevention
    fail2ban_installed = check_package_installed('fail2ban', os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Network Security",
        status="Pass" if fail2ban_installed else "Info",
        message=f"{get_enisa_id('NET', 16)}: Automated attack response",
        details="fail2ban installed" if fail2ban_installed else "Not installed",
        remediation=remediation_for("fail2ban")
    ))
    
    # NET-017: Network segmentation
    result = run_command("ip link show | grep -c '@\\|\\.'")
    vlan_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Network Security",
        status="Info",
        message=f"{get_enisa_id('NET', 17)}: Network segmentation (VLANs)",
        details=f"{vlan_count} VLAN interfaces",
        remediation="Use VLANs for network segregation"
    ))
    
    # NET-018: VPN capabilities
    vpn_tools = ['openvpn', 'wireguard', 'strongswan']
    installed_vpn = [tool for tool in vpn_tools if check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Network Security",
        status="Info",
        message=f"{get_enisa_id('NET', 18)}: VPN capabilities",
        details=f"Installed: {', '.join(installed_vpn)}" if installed_vpn else "Not installed",
        remediation="Consider VPN for secure remote access"
    ))
    
    # NET-019: Network intrusion detection
    ids_tools = ['snort', 'suricata']
    installed_ids = [tool for tool in ids_tools if check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Network Security",
        status="Info",
        message=f"{get_enisa_id('NET', 19)}: Network intrusion detection",
        details=f"Installed: {', '.join(installed_ids)}" if installed_ids else "Not installed",
        remediation="Consider IDS/IPS for network monitoring"
    ))
    
    # NET-020: TCP wrappers
    tcpwrappers_configured = os.path.exists("/etc/hosts.allow") and os.path.exists("/etc/hosts.deny")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Network Security",
        status="Info",
        message=f"{get_enisa_id('NET', 20)}: TCP wrappers configured",
        details="Configured" if tcpwrappers_configured else "Not configured",
        remediation="Configure /etc/hosts.allow and /etc/hosts.deny"
    ))
    
    # NET-021: Port knocking
    port_knocking = check_package_installed('knockd', os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Network Security",
        status="Info",
        message=f"{get_enisa_id('NET', 21)}: Port knocking configured",
        details="Installed" if port_knocking else "Not installed",
        remediation="Consider port knocking for additional security"
    ))
    
    # NET-022: Network parameters persistent
    sysctl_conf_exists = os.path.exists("/etc/sysctl.conf")
    
    if sysctl_conf_exists:
        content = read_file_safe("/etc/sysctl.conf")
        net_params = content.count("net.")
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ENISA - Network Security",
            status="Pass" if net_params >= 5 else "Warning",
            message=f"{get_enisa_id('NET', 22)}: Network parameters persistent",
            details=f"{net_params} network parameters in sysctl.conf",
            remediation="Add network hardening to /etc/sysctl.conf"
        ))
    
    # NET-023: Send redirects disabled
    exists, send_redirects = check_kernel_parameter("net.ipv4.conf.all.send_redirects")
    sends_disabled = send_redirects == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Network Security",
        status="Pass" if sends_disabled else "Warning",
        message=f"{get_enisa_id('NET', 23)}: Send ICMP redirects disabled",
        details=f"send_redirects = {send_redirects}",
        remediation="Disable: sysctl -w net.ipv4.conf.all.send_redirects=0"
    ))
    
    # NET-024: Ignore bogus ICMP errors
    exists, ignore_bogus = check_kernel_parameter("net.ipv4.icmp_ignore_bogus_error_responses")
    bogus_ignored = ignore_bogus == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Network Security",
        status="Pass" if bogus_ignored else "Info",
        message=f"{get_enisa_id('NET', 24)}: Ignore bogus ICMP errors",
        details=f"icmp_ignore_bogus_error_responses = {ignore_bogus}",
        remediation="Enable: sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1"
    ))
    
    # NET-025: Network monitoring tools
    net_mon_tools = ['tcpdump', 'wireshark', 'tshark', 'nethogs']
    installed_netmon = [tool for tool in net_mon_tools if command_exists(tool)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Network Security",
        status="Info",
        message=f"{get_enisa_id('NET', 25)}: Network monitoring tools",
        details=f"Installed: {', '.join(installed_netmon)}" if installed_netmon else "Not installed",
        remediation="Install network monitoring tools for troubleshooting"
    ))


# ============================================================================
# ACCESS CONTROL & DATA PROTECTION
# ENISA access control and GDPR-aligned data protection
# ============================================================================

def check_access_control_data_protection(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    ENISA Access Control & Data Protection
    Authentication, authorization, and data protection measures
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Access Control & Data Protection...")
    
    # ACC-001: Strong authentication configured
    password_policy = check_password_policy()
    auth_strong = password_policy['complexity'] and password_policy['min_length'] and password_policy['min_length'] >= 12
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Access Control",
        status="Pass" if auth_strong else "Warning",
        message=f"{get_enisa_id('ACC', 1)}: Strong authentication configured",
        details=f"Min length: {password_policy['min_length']}, Complexity: {password_policy['complexity']}",
        remediation="Configure strong password requirements"
    ))
    
    # ACC-002: Account lockout policy
    pam_files = glob.glob("/etc/pam.d/*")
    lockout_configured = False
    for pam_file in pam_files:
        content = read_file_safe(pam_file)
        if 'pam_faillock' in content or 'pam_tally2' in content:
            lockout_configured = True
            break
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Access Control",
        status="Pass" if lockout_configured else "Warning",
        message=f"{get_enisa_id('ACC', 2)}: Account lockout configured",
        details="Configured" if lockout_configured else "Not configured",
        remediation="Configure pam_faillock for account lockout"
    ))
    
    # ACC-003: Multi-factor authentication
    mfa_tools = ['google-authenticator', 'libpam-google-authenticator']
    mfa_installed = any(check_package_installed(tool, os_info) for tool in mfa_tools)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Access Control",
        status="Info",
        message=f"{get_enisa_id('ACC', 3)}: Multi-factor authentication",
        details="Installed" if mfa_installed else "Not installed",
        remediation="Consider MFA for privileged accounts"
    ))
    
    # ACC-004: SSH key-based authentication
    if os.path.exists("/etc/ssh/sshd_config"):
        content = read_file_safe("/etc/ssh/sshd_config")
        pubkey = re.search(r'^PubkeyAuthentication\s+(\S+)', content, re.MULTILINE)
        pubkey_enabled = not pubkey or pubkey.group(1).lower() == 'yes'
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ENISA - Access Control",
            status="Pass" if pubkey_enabled else "Warning",
            message=f"{get_enisa_id('ACC', 4)}: SSH key-based authentication",
            details=f"PubkeyAuthentication: {pubkey.group(1) if pubkey else 'default (yes)'}",
            remediation="Enable public key authentication"
        ))
    
    # ACC-005: sudo configuration secure
    if os.path.exists("/etc/sudoers"):
        perms = get_file_permissions("/etc/sudoers")
        perms_ok = perms in ['440', '400']
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ENISA - Access Control",
            status="Pass" if perms_ok else "Fail",
            message=f"{get_enisa_id('ACC', 5)}: /etc/sudoers permissions",
            details=f"Permissions: {perms}",
            remediation="chmod 440 /etc/sudoers"
        ))
    
    # ACC-006: Privilege escalation logging
    if os.path.exists("/etc/sudoers"):
        content = read_file_safe("/etc/sudoers")
        logging_enabled = 'log_output' in content or 'syslog' in content
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ENISA - Access Control",
            status="Info",
            message=f"{get_enisa_id('ACC', 6)}: Privilege escalation logged",
            details="Logging enabled" if logging_enabled else "Check configuration",
            remediation="Enable sudo logging in /etc/sudoers"
        ))
    
    # ACC-007: User account inventory
    result = run_command("awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd | wc -l")
    user_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Access Control",
        status="Info",
        message=f"{get_enisa_id('ACC', 7)}: Regular user accounts",
        details=f"{user_count} user accounts",
        remediation="Review user accounts regularly"
    ))
    
    # ACC-008: Inactive accounts disabled
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Access Control",
        status="Info",
        message=f"{get_enisa_id('ACC', 8)}: Inactive account policy",
        details="Review last login times",
        remediation="Disable inactive accounts: usermod -L <user>"
    ))
    
    # ACC-009: Default account removed/disabled
    default_accounts = ['guest', 'games', 'news', 'gopher']
    found_defaults = []
    for account in default_accounts:
        result = run_command(f"getent passwd {account} 2>/dev/null")
        if result.returncode == 0:
            found_defaults.append(account)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Access Control",
        status="Pass" if not found_defaults else "Info",
        message=f"{get_enisa_id('ACC', 9)}: Default accounts removed",
        details=f"Found: {', '.join(found_defaults)}" if found_defaults else "None found",
        remediation="Remove or lock unnecessary default accounts"
    ))
    
    # ACC-010: Session timeout configured
    result = run_command("grep -r 'TMOUT=' /etc/profile /etc/profile.d/ 2>/dev/null | wc -l")
    tmout_set = safe_int_parse(result.stdout.strip()) > 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Access Control",
        status="Pass" if tmout_set else "Warning",
        message=f"{get_enisa_id('ACC', 10)}: Session timeout configured",
        details="Configured" if tmout_set else "Not configured",
        remediation="Set TMOUT=600 in /etc/profile.d/tmout.sh"
    ))
    
    # Data Protection (GDPR-aligned)
    
    # DAT-001: Data encryption at rest
    result = run_command("lsblk -o NAME,FSTYPE | grep -c crypt || echo 0")
    encrypted_volumes = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Data Protection",
        status="Pass" if encrypted_volumes > 0 else "Info",
        message=f"{get_enisa_id('DAT', 1)}: Data encryption at rest",
        details=f"{encrypted_volumes} encrypted volumes",
        remediation="Use LUKS for sensitive data encryption"
    ))
    
    # DAT-002: Encryption tools available
    encryption_tools = ['gpg', 'openssl', 'cryptsetup']
    available_enc = [tool for tool in encryption_tools if command_exists(tool)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Data Protection",
        status="Pass" if len(available_enc) >= 2 else "Warning",
        message=f"{get_enisa_id('DAT', 2)}: Encryption tools available",
        details=f"Available: {', '.join(available_enc)}",
        remediation="Install encryption tools: gnupg, openssl"
    ))
    
    # DAT-003: Secure file permissions
    critical_files = {
        '/etc/passwd': '644',
        '/etc/shadow': '000',
        '/etc/group': '644',
        '/etc/gshadow': '000'
    }
    
    secure_perms = 0
    for filepath, expected in critical_files.items():
        if os.path.exists(filepath):
            perms = get_file_permissions(filepath)
            if perms and int(perms, 8) <= int(expected, 8):
                secure_perms += 1
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Data Protection",
        status="Pass" if secure_perms == len(critical_files) else "Fail",
        message=f"{get_enisa_id('DAT', 3)}: Critical file permissions secure",
        details=f"{secure_perms}/{len(critical_files)} files secure",
        remediation="Secure critical file permissions"
    ))
    
    # DAT-004: Data backup configured
    backup_dirs = ['/backup', '/var/backups', '/mnt/backup']
    backup_configured = any(os.path.exists(d) for d in backup_dirs)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Data Protection",
        status="Pass" if backup_configured else "Warning",
        message=f"{get_enisa_id('DAT', 4)}: Backup directories configured",
        details="Configured" if backup_configured else "Not found",
        remediation="Create and configure backup directories"
    ))
    
    # DAT-005: Secure deletion tools
    secure_del_tools = ['shred', 'wipe', 'srm']
    available_del = [tool for tool in secure_del_tools if command_exists(tool)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Data Protection",
        status="Pass" if available_del else "Info",
        message=f"{get_enisa_id('DAT', 5)}: Secure deletion tools",
        details=f"Available: {', '.join(available_del)}" if available_del else "shred (built-in)",
        remediation="Use shred for secure file deletion"
    ))
    
    # DAT-006: Temporary file cleanup
    tmp_cleanup = False
    if os.path.exists("/usr/lib/tmpfiles.d/tmp.conf"):
        content = read_file_safe("/usr/lib/tmpfiles.d/tmp.conf")
        tmp_cleanup = "D /tmp" in content
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Data Protection",
        status="Pass" if tmp_cleanup else "Info",
        message=f"{get_enisa_id('DAT', 6)}: Temporary files cleaned",
        details="Configured" if tmp_cleanup else "Check configuration",
        remediation="Configure tmpfiles.d for /tmp cleanup"
    ))
    
    # DAT-007: Home directory encryption
    result = run_command("ls -la /home/ 2>/dev/null | grep -c '.ecryptfs' || echo 0")
    encrypted_homes = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Data Protection",
        status="Info",
        message=f"{get_enisa_id('DAT', 7)}: Home directory encryption",
        details=f"{encrypted_homes} encrypted home directories",
        remediation="Consider ecryptfs for user data"
    ))
    
    # DAT-008: Database encryption
    db_packages = ['mysql', 'postgresql', 'mariadb']
    installed_db = [db for db in db_packages if check_package_installed(db, os_info)]
    
    if installed_db:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ENISA - Data Protection",
            status="Info",
            message=f"{get_enisa_id('DAT', 8)}: Database encryption",
            details=f"Databases: {', '.join(installed_db)}",
            remediation="Enable encryption for database files"
        ))
    
    # DAT-009: File integrity monitoring
    fim_installed = any(check_package_installed(tool, os_info) for tool in ['aide', 'tripwire'])
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Data Protection",
        status="Pass" if fim_installed else "Warning",
        message=f"{get_enisa_id('DAT', 9)}: File integrity monitoring",
        details="Installed" if fim_installed else "Not installed",
        remediation="Install AIDE for file integrity monitoring"
    ))
    
    # DAT-010: Audit trail protection
    if os.path.exists("/var/log/audit"):
        perms = get_file_permissions("/var/log/audit")
        perms_ok = perms and int(perms, 8) <= int('700', 8)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ENISA - Data Protection",
            status="Pass" if perms_ok else "Warning",
            message=f"{get_enisa_id('DAT', 10)}: Audit log protection",
            details=f"Permissions: {perms}" if perms else "Not found",
            remediation="Secure audit logs: chmod 700 /var/log/audit"
        ))
    
    # DAT-011: Privacy-enhancing measures
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Data Protection",
        status="Info",
        message=f"{get_enisa_id('DAT', 11)}: Privacy measures (GDPR)",
        details="Review data processing and retention",
        remediation="Implement GDPR-compliant data handling"
    ))
    
    # DAT-012: Data minimization
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Data Protection",
        status="Info",
        message=f"{get_enisa_id('DAT', 12)}: Data minimization principle",
        details="Review collected data necessity",
        remediation="Collect only necessary data (GDPR principle)"
    ))
    
    # DAT-013: Data retention policy
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Data Protection",
        status="Info",
        message=f"{get_enisa_id('DAT', 13)}: Data retention policy",
        details="Document retention periods",
        remediation="Define and implement data retention policy"
    ))
    
    # DAT-014: Right to erasure capability
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Data Protection",
        status="Info",
        message=f"{get_enisa_id('DAT', 14)}: Right to erasure (GDPR)",
        details="Capability for data deletion",
        remediation="Implement procedures for data subject requests"
    ))
    
    # DAT-015: Data breach notification
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Data Protection",
        status="Info",
        message=f"{get_enisa_id('DAT', 15)}: Data breach procedures",
        details="Document incident response procedures",
        remediation="Establish 72-hour breach notification process"
    ))


# ============================================================================
# INCIDENT RESPONSE & MONITORING
# ENISA incident response and security monitoring
# ============================================================================

def check_incident_response_monitoring(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    ENISA Incident Response & Monitoring
    Logging, monitoring, and incident response capabilities
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Incident Response & Monitoring...")
    
    # INC-001: Centralized logging
    logging_status = check_logging_configured()
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Pass" if logging_status['syslog'] else "Fail",
        message=f"{get_enisa_id('INC', 1)}: Centralized system logging",
        details="Active" if logging_status['syslog'] else "Not active",
        remediation="Enable rsyslog: systemctl enable rsyslog"
    ))
    
    # INC-002: Audit daemon active
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Pass" if logging_status['auditd'] else "Warning",
        message=f"{get_enisa_id('INC', 2)}: Audit daemon active",
        details="Active" if logging_status['auditd'] else "Not active",
        remediation=remediation_for("auditd")
    ))
    
    # INC-003: Remote logging configured
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Info",
        message=f"{get_enisa_id('INC', 3)}: Remote logging configured",
        details="Configured" if logging_status['remote'] else "Not configured",
        remediation="Configure remote syslog for log aggregation"
    ))
    
    # INC-004: Log rotation configured
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Pass" if logging_status['rotation'] else "Fail",
        message=f"{get_enisa_id('INC', 4)}: Log rotation configured",
        details="Configured" if logging_status['rotation'] else "Not configured",
        remediation="Install and configure logrotate"
    ))
    
    # INC-005: Audit rules configured
    if logging_status['auditd']:
        result = run_command("auditctl -l 2>/dev/null | grep -v 'No rules' | wc -l")
        audit_rules = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ENISA - Incident Response",
            status="Pass" if audit_rules >= 10 else "Warning",
            message=f"{get_enisa_id('INC', 5)}: Audit rules configured",
            details=f"{audit_rules} audit rules",
            remediation="Configure audit rules in /etc/audit/rules.d/"
        ))
    
    # INC-006: Log analysis tools
    log_tools = ['logwatch', 'fail2ban', 'logcheck']
    installed_logtools = [tool for tool in log_tools if check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Pass" if installed_logtools else "Info",
        message=f"{get_enisa_id('INC', 6)}: Log analysis tools",
        details=f"Installed: {', '.join(installed_logtools)}" if installed_logtools else "Not installed",
        remediation="Install log analysis tools"
    ))
    
    # INC-007: Intrusion detection
    ids_tools = ['ossec', 'snort', 'suricata']
    installed_ids = [tool for tool in ids_tools if check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Info",
        message=f"{get_enisa_id('INC', 7)}: Intrusion detection system",
        details=f"Installed: {', '.join(installed_ids)}" if installed_ids else "Not installed",
        remediation="Consider IDS/IPS installation"
    ))
    
    # INC-008: Security information and event management (SIEM)
    siem_tools = ['splunk', 'elasticsearch', 'graylog']
    installed_siem = [tool for tool in siem_tools if check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Info",
        message=f"{get_enisa_id('INC', 8)}: SIEM capabilities",
        details=f"Installed: {', '.join(installed_siem)}" if installed_siem else "Not installed",
        remediation="Consider SIEM for large deployments"
    ))
    
    # INC-009: Monitoring tools
    mon_tools = ['monit', 'nagios', 'zabbix', 'prometheus']
    installed_mon = [tool for tool in mon_tools if check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Info",
        message=f"{get_enisa_id('INC', 9)}: System monitoring tools",
        details=f"Installed: {', '.join(installed_mon)}" if installed_mon else "Not installed",
        remediation="Install monitoring tools"
    ))
    
    # INC-010: Alerting configured
    alerting_tools = ['monit', 'fail2ban']
    alerting_active = any(check_service_active(tool) for tool in alerting_tools)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Info",
        message=f"{get_enisa_id('INC', 10)}: Automated alerting",
        details="Configured" if alerting_active else "Not configured",
        remediation="Configure automated alerting"
    ))
    
    # INC-011: Incident response plan
    ir_docs = ['/root/incident_response.txt', '/etc/security/incident_response.txt']
    ir_documented = any(os.path.exists(doc) for doc in ir_docs)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Info",
        message=f"{get_enisa_id('INC', 11)}: Incident response plan",
        details="Documented" if ir_documented else "Not found",
        remediation="Document incident response procedures"
    ))
    
    # INC-012: Forensics tools
    forensics_tools = ['sleuthkit', 'autopsy', 'volatility']
    installed_forensics = [tool for tool in forensics_tools if check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Info",
        message=f"{get_enisa_id('INC', 12)}: Forensics tools available",
        details=f"Installed: {', '.join(installed_forensics)}" if installed_forensics else "Not installed",
        remediation="Consider forensics tools for incident analysis"
    ))
    
    # INC-013: Process monitoring
    result = run_command("ps aux | wc -l")
    process_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Info",
        message=f"{get_enisa_id('INC', 13)}: Active processes",
        details=f"{process_count} processes running",
        remediation="Monitor process activity regularly"
    ))
    
    # INC-014: Resource monitoring
    sysstat_installed = check_package_installed('sysstat', os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Pass" if sysstat_installed else "Info",
        message=f"{get_enisa_id('INC', 14)}: Resource monitoring (sysstat)",
        details="Installed" if sysstat_installed else "Not installed",
        remediation="Install sysstat for resource monitoring"
    ))
    
    # INC-015: Performance baselines
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Info",
        message=f"{get_enisa_id('INC', 15)}: Performance baselines",
        details="Establish baseline metrics",
        remediation="Document normal system performance"
    ))
    
    # INC-016: Change management
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Info",
        message=f"{get_enisa_id('INC', 16)}: Change management process",
        details="Document change procedures",
        remediation="Implement change control process"
    ))
    
    # INC-017: Backup verification
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Info",
        message=f"{get_enisa_id('INC', 17)}: Backup verification",
        details="Test backup restoration regularly",
        remediation="Schedule regular backup tests"
    ))
    
    # INC-018: Disaster recovery plan
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Info",
        message=f"{get_enisa_id('INC', 18)}: Disaster recovery plan",
        details="Document recovery procedures",
        remediation="Create and test disaster recovery plan"
    ))
    
    # INC-019: Business continuity
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Info",
        message=f"{get_enisa_id('INC', 19)}: Business continuity planning",
        details="Document continuity procedures",
        remediation="Develop business continuity plan"
    ))
    
    # INC-020: Communication plan
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Info",
        message=f"{get_enisa_id('INC', 20)}: Incident communication plan",
        details="Define communication procedures",
        remediation="Establish incident communication protocols"
    ))
    
    # INC-021: Evidence preservation
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Info",
        message=f"{get_enisa_id('INC', 21)}: Evidence preservation procedures",
        details="Document evidence handling",
        remediation="Define chain of custody procedures"
    ))
    
    # INC-022: Threat intelligence
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Info",
        message=f"{get_enisa_id('INC', 22)}: Threat intelligence",
        details="Subscribe to security feeds",
        remediation="Monitor ENISA threat landscape reports"
    ))
    
    # INC-023: Vulnerability scanning
    vuln_scanners = ['openvas', 'nessus', 'lynis']
    installed_vuln = [tool for tool in vuln_scanners if command_exists(tool) or check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Info",
        message=f"{get_enisa_id('INC', 23)}: Vulnerability scanning",
        details=f"Installed: {', '.join(installed_vuln)}" if installed_vuln else "Not installed",
        remediation="Install vulnerability scanner: lynis"
    ))
    
    # INC-024: Security assessment schedule
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Info",
        message=f"{get_enisa_id('INC', 24)}: Regular security assessments",
        details="Schedule periodic security audits",
        remediation="Conduct quarterly security assessments"
    ))
    
    # INC-025: Post-incident review
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Info",
        message=f"{get_enisa_id('INC', 25)}: Post-incident review process",
        details="Document lessons learned",
        remediation="Establish post-incident review procedures"
    ))


# ============================================================================
# ENISA Supply Chain Security & NIS2 Compliance
# Phase 1 Gap: NIS2 Article 21, supply chain, encryption at rest, DR
# ============================================================================

def check_supply_chain_nis2(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    ENISA/NIS2 supply chain security, encryption at rest, vulnerability
    disclosure readiness, and business continuity checks.
    """
    cache = shared_data.get('cache')

    # --- NIS2 Art.21: Supply chain - Package repository integrity ---
    if os_info.package_manager == "apt":
        result = run_command("apt-key list 2>/dev/null | grep -c 'pub'", check=False)
        gpg_keys = safe_int_parse(result.stdout.strip(), default=0)
        # Check for unsigned repos
        sources = read_file_safe("/etc/apt/sources.list") or ""
        unsigned = sources.count("[trusted=yes]") + sources.count("allow-insecure=yes")
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ENISA - Supply Chain",
            status="Pass" if gpg_keys > 0 and unsigned == 0 else (
                "Fail" if unsigned > 0 else "Warning"),
            message=f"{get_enisa_id('SCM', 1)}: Package repository GPG verification (NIS2 Art.21)",
            details=f"GPG keys: {gpg_keys}, Unsigned/insecure repos: {unsigned}",
            remediation="Remove [trusted=yes] from sources and import proper GPG keys",
            severity="High"
        ))
    elif os_info.package_manager in ("yum", "dnf"):
        conf = read_file_safe(f"/etc/{os_info.package_manager}.conf") or ""
        gpgcheck_on = "gpgcheck=0" not in conf
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ENISA - Supply Chain",
            status="Pass" if gpgcheck_on else "Fail",
            message=f"{get_enisa_id('SCM', 1)}: Package GPG verification (NIS2 Art.21)",
            details=f"gpgcheck: {'enabled' if gpgcheck_on else 'DISABLED'}",
            remediation=f"Set gpgcheck=1 in /etc/{os_info.package_manager}.conf",
            severity="High"
        ))

    # --- Software bill of materials readiness ---
    sbom_tools = ["syft", "cyclonedx", "spdx", "dpkg-query", "rpm"]
    found_sbom = [t for t in sbom_tools if command_exists(t)]
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Supply Chain",
        status="Pass" if found_sbom else "Info",
        message=f"{get_enisa_id('SCM', 2)}: SBOM generation capability",
        details=f"Available tools: {', '.join(found_sbom) if found_sbom else 'none detected'}",
        remediation="Install SBOM generation tools (syft, cyclonedx-cli) for supply chain transparency",
        severity="Low"
    ))

    # --- Encryption at rest ---
    # Check for LUKS encrypted partitions
    result = run_command("lsblk -o NAME,FSTYPE,TYPE 2>/dev/null | grep -i crypt", check=False)
    luks_found = result.returncode == 0 and result.stdout.strip()
    # Check dm-crypt
    result2 = run_command("dmsetup ls --target crypt 2>/dev/null", check=False)
    dm_crypt = result2.returncode == 0 and result2.stdout.strip() and "No" not in result2.stdout

    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Data Protection",
        status="Pass" if (luks_found or dm_crypt) else "Warning",
        message=f"{get_enisa_id('DAT', 10)}: Encryption at rest (NIS2 Art.21)",
        details=f"LUKS/dm-crypt: {'detected' if (luks_found or dm_crypt) else 'not detected'}",
        remediation="Implement full disk encryption using LUKS: cryptsetup luksFormat /dev/sdX",
        severity="High"
    ))

    # --- Backup verification ---
    backup_dirs = ["/var/backups", "/backup", "/mnt/backup"]
    recent_backup = False
    for bdir in backup_dirs:
        if os.path.isdir(bdir):
            result = run_command(f"find {bdir} -type f -mtime -30 2>/dev/null | head -1", check=False)
            if result.returncode == 0 and result.stdout.strip():
                recent_backup = True
                break

    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Data Protection",
        status="Pass" if recent_backup else "Warning",
        message=f"{get_enisa_id('DAT', 11)}: Recent backup existence (NIS2 Art.21)",
        details=f"Recent backups (<30 days): {'found' if recent_backup else 'not found in standard locations'}",
        remediation="Implement and verify regular backup procedures",
        severity="Medium"
    ))

    # --- Vulnerability disclosure readiness ---
    security_files = ["/etc/security-policy.txt", "/.well-known/security.txt",
                      "/var/www/html/.well-known/security.txt",
                      "/var/www/.well-known/security.txt"]
    vuln_disclosure = any(os.path.exists(f) for f in security_files)
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Pass" if vuln_disclosure else "Info",
        message=f"{get_enisa_id('INC', 10)}: Vulnerability disclosure policy (NIS2 Art.21)",
        details=f"security.txt: {'found' if vuln_disclosure else 'not found'}",
        remediation="Create /.well-known/security.txt per RFC 9116",
        severity="Low"
    ))


# ============================================================================
# Main Orchestration Function
# ============================================================================

def run_checks(shared_data: Dict[str, Any]) -> List[AuditResult]:
    """
    Main entry point for ENISA module
    Executes all ENISA cybersecurity checks and returns results
    """
    results = []
    
    # Extract SharedDataCache from shared_data (populated by main script)
    cache = shared_data.get('cache')
    
    print(f"\n[{MODULE_NAME}] " + "="*70)
    print(f"[{MODULE_NAME}] ENISA CYBERSECURITY COMPLIANCE AUDIT")
    print(f"[{MODULE_NAME}] " + "="*70)
    print(f"[{MODULE_NAME}] Version: {MODULE_VERSION}")
    print(f"[{MODULE_NAME}] Agency: European Union Agency for Cybersecurity")
    print(f"[{MODULE_NAME}] Focus: Baseline Security & GDPR-aligned Controls")
    print(f"[{MODULE_NAME}] Target: 100+ Comprehensive Cybersecurity Audit Checks")
    print(f"[{MODULE_NAME}] " + "="*70 + "\n")
    
    # Get or detect OS information
    if 'os_info' in shared_data:
        os_info = shared_data['os_info']
    else:
        os_info = detect_os()
        shared_data['os_info'] = os_info
    
    print(f"[{MODULE_NAME}] Operating System: {os_info.distro} {os_info.version}")
    print(f"[{MODULE_NAME}] OS Family: {os_info.family}")
    print(f"[{MODULE_NAME}] Package Manager: {os_info.package_manager}")
    print("")
    
    is_root = shared_data.get("is_root", os.geteuid() == 0)
    if not is_root:
        print(f"[{MODULE_NAME}]   Note: Running without root privileges")
        print(f"[{MODULE_NAME}] Some checks require elevated privileges for full coverage\n")
    
    try:
        # Execute all check categories
        check_baseline_security(results, shared_data, os_info)
        check_network_security(results, shared_data, os_info)
        check_access_control_data_protection(results, shared_data, os_info)
        check_incident_response_monitoring(results, shared_data, os_info)
        # Phase 1 new checks
        check_supply_chain_nis2(results, shared_data, os_info)
        
    except Exception as e:
        print(f"[{MODULE_NAME}]  Error during audit execution: {str(e)}")
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ENISA - Error",
            status="Error",
            message=f"Module execution error: {str(e)}",
            details="",
            remediation="Review module logs and configuration"
        ))
        import traceback
        traceback.print_exc()
    
    # Generate summary statistics
    pass_count = sum(1 for r in results if r.status == "Pass")
    fail_count = sum(1 for r in results if r.status == "Fail")
    warn_count = sum(1 for r in results if r.status == "Warning")
    info_count = sum(1 for r in results if r.status == "Info")
    error_count = sum(1 for r in results if r.status == "Error")
    
    # Count by category
    category_counts = {}
    for r in results:
        # Extract category
        cat_match = re.search(r'ENISA - (.+)', r.category)
        if cat_match:
            cat = cat_match.group(1)
            category_counts[cat] = category_counts.get(cat, 0) + 1
    
    print(f"\n[{MODULE_NAME}] " + "="*70)
    print(f"[{MODULE_NAME}] ENISA CYBERSECURITY COMPLIANCE AUDIT COMPLETED")
    print(f"[{MODULE_NAME}] " + "="*70)
    print(f"[{MODULE_NAME}] Total Cybersecurity Audit Checks Executed: {len(results)}")
    print(f"[{MODULE_NAME}] ")
    print(f"[{MODULE_NAME}] Results Summary:")
    print(f"[{MODULE_NAME}]   Passed:  {pass_count:3d} ({pass_count/len(results)*100:.1f}%)")
    print(f"[{MODULE_NAME}]   Failed:  {fail_count:3d} ({fail_count/len(results)*100:.1f}%)")
    print(f"[{MODULE_NAME}]   Warnings: {warn_count:3d} ({warn_count/len(results)*100:.1f}%)")
    print(f"[{MODULE_NAME}]   Info:    {info_count:3d} ({info_count/len(results)*100:.1f}%)")
    print(f"[{MODULE_NAME}]   Errors:  {error_count:3d} ({error_count/len(results)*100:.1f}%)")
    print(f"[{MODULE_NAME}] ")
    print(f"[{MODULE_NAME}] ENISA Control Categories:")
    for category in sorted(category_counts.keys()):
        print(f"[{MODULE_NAME}]   {category:35s}: {category_counts[category]:3d} checks")
    print(f"[{MODULE_NAME}] " + "="*70 + "\n")
    
    return results


# ============================================================================
# Module Testing
# ============================================================================



# ============================================================================
# v3.3 EXPANSION - ENISA Deep Coverage
# ----------------------------------------------------------------------------
# Synopsis:
#   Adds depth across:
#   - NIS2 Directive Article 21 cybersecurity risk-management measures (10)
#   - DORA (Digital Operational Resilience Act) for financial entities
#   - EU Cybersecurity Act Article 51 baseline
#   - ENISA Threat Landscape technical indicators
#   - Cross-Border Resilience indicators
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


def _v33_enisa_result(category, status, message, severity="Medium",
                      details="", remediation="", cross_references=None):
    """Build AuditResult for ENISA v3.3 expansion."""
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


def _check_enisa_v33_nis2_article21(results, shared_data, os_info):
    """NIS2 Directive Article 21 - 10 cybersecurity risk-management measures."""

    # 21.2(a) - Risk analysis and information system security policies
    auditd_active = _v33_systemd_active("auditd.service") == "active"
    audit_rules_count = 0
    rules_d = "/etc/audit/rules.d"
    if _v33_directory_exists(rules_d):
        for f in _v33_list_directory(rules_d):
            if f.endswith(".rules"):
                c = _v33_read_file_safe(os.path.join(rules_d, f))
                audit_rules_count += sum(
                    1 for ln in c.splitlines()
                    if ln.strip() and not ln.strip().startswith("#")
                )
    results.append(_v33_enisa_result(
        "ENISA NIS2 21.2(a) v3.3 - Risk Analysis",
        "Pass" if (auditd_active and audit_rules_count >= 25) else "Warning",
        f"NIS2 Article 21.2(a) Risk analysis (auditd, {audit_rules_count} rules)",
        severity="High",
        details=(
            f"auditd active: {auditd_active}, audit rules: {audit_rules_count}"
        ),
        remediation=(
            "Deploy CIS-recommended ruleset (~75 rules) and document baseline"
        ),
        cross_references={
            "ENISA-NIS2": "Art.21.2(a)", "NIST": "RA-3",
        },
    ))

    # 21.2(b) - Incident handling
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
    results.append(_v33_enisa_result(
        "ENISA NIS2 21.2(b) v3.3 - Incident Handling",
        "Pass" if rsy_remote else "Fail",
        f"NIS2 Article 21.2(b) Remote log forwarding for incident handling",
        severity="Critical",
        details=f"rsyslog forwarding: {rsy_remote}",
        remediation=(
            "Configure /etc/rsyslog.d/50-remote.conf for SIEM forwarding"
        ),
        cross_references={
            "ENISA-NIS2": "Art.21.2(b)", "NIST": "IR-4",
        },
    ))

    # 21.2(c) - Business continuity, backup management, crisis management
    backup_tools = {
        "rsync": _v33_command_available("rsync"),
        "borg": _v33_command_available("borg"),
        "restic": _v33_command_available("restic"),
        "duplicity": _v33_command_available("duplicity"),
    }
    detected = [k for k, v in backup_tools.items() if v]
    backup_cron = []
    for cron_dir in ["/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.d"]:
        if _v33_directory_exists(cron_dir):
            for f in _v33_list_directory(cron_dir):
                lf = f.lower()
                if any(k in lf for k in ["backup", "rsync", "borg", "restic"]):
                    backup_cron.append(f)
    bc_score = bool(detected) + bool(backup_cron)
    results.append(_v33_enisa_result(
        "ENISA NIS2 21.2(c) v3.3 - Business Continuity",
        "Pass" if bc_score >= 2 else "Warning",
        f"NIS2 Article 21.2(c) Backup management ({bc_score}/2)",
        severity="High",
        details=(
            f"Backup tools: {detected}, scheduled jobs: {len(backup_cron)}"
        ),
        remediation=(
            "Schedule backups via cron; test restore procedures quarterly"
        ),
        cross_references={
            "ENISA-NIS2": "Art.21.2(c)", "NIST": "CP-9",
        },
    ))

    # 21.2(d) - Supply chain security
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
    results.append(_v33_enisa_result(
        "ENISA NIS2 21.2(d) v3.3 - Supply Chain",
        "Pass" if sig_indicators >= 1 else "Fail",
        f"NIS2 Article 21.2(d) Supply chain controls ({sig_indicators})",
        severity="High",
        details=(
            f"apt keyring: {apt_keyring}, rpm gpgcheck: {rpm_gpgcheck}, "
            f"pacman keyring: {pacman_keyring}"
        ),
        cross_references={
            "ENISA-NIS2": "Art.21.2(d)", "NIST": "SR-3",
        },
    ))

    # 21.2(e) - Security in network and information systems acquisition
    update_active = (
        _v33_systemd_active("unattended-upgrades.service") == "active" or
        _v33_systemd_active("dnf-automatic-install.timer") == "active"
    )
    results.append(_v33_enisa_result(
        "ENISA NIS2 21.2(e) v3.3 - Acquisition Security",
        "Pass" if update_active else "Warning",
        f"NIS2 Article 21.2(e) Automated patch management",
        severity="High",
        details=f"Update automation: {update_active}",
        remediation=(
            "apt-get install -y unattended-upgrades; "
            "dpkg-reconfigure unattended-upgrades"
        ),
        cross_references={
            "ENISA-NIS2": "Art.21.2(e)", "NIST": "SI-2",
        },
    ))

    # 21.2(f) - Policies and procedures to assess effectiveness
    scanners = ["lynis", "oscap", "trivy", "nuclei"]
    detected_s = [s for s in scanners if _v33_command_available(s)]
    results.append(_v33_enisa_result(
        "ENISA NIS2 21.2(f) v3.3 - Effectiveness Assessment",
        "Pass" if detected_s else "Warning",
        f"NIS2 Article 21.2(f) Effectiveness assessment tools ({len(detected_s)})",
        severity="Medium",
        details=f"Detected: {detected_s}",
        remediation=remediation_for("lynis"),
        cross_references={
            "ENISA-NIS2": "Art.21.2(f)", "NIST": "CA-2",
        },
    ))

    # 21.2(g) - Basic cyber hygiene practices and cybersecurity training
    pam_dir = "/etc/pam.d"
    pam_files_count = (
        len(_v33_list_directory(pam_dir))
        if _v33_directory_exists(pam_dir) else 0
    )
    results.append(_v33_enisa_result(
        "ENISA NIS2 21.2(g) v3.3 - Cyber Hygiene",
        "Pass" if pam_files_count >= 10 else "Warning",
        f"NIS2 Article 21.2(g) PAM hygiene modules ({pam_files_count})",
        severity="Medium",
        details=f"PAM files: {pam_files_count}",
        cross_references={
            "ENISA-NIS2": "Art.21.2(g)", "NIST": "AT-2",
        },
    ))

    # 21.2(h) - Policies and procedures regarding the use of cryptography
    fips_active = False
    if _v33_file_exists("/proc/sys/crypto/fips_enabled"):
        fips_active = _v33_read_file_safe(
            "/proc/sys/crypto/fips_enabled"
        ).strip() == "1"
    crypto_policy = ""
    if _v33_file_exists("/etc/crypto-policies/config"):
        crypto_policy = _v33_read_file_safe("/etc/crypto-policies/config").strip()
    crypto_ok = fips_active or crypto_policy in ("DEFAULT", "FUTURE", "FIPS")
    results.append(_v33_enisa_result(
        "ENISA NIS2 21.2(h) v3.3 - Cryptography",
        "Pass" if crypto_ok else "Warning",
        f"NIS2 Article 21.2(h) Cryptography policy",
        severity="High",
        details=(
            f"Kernel FIPS: {fips_active}, crypto-policies: {crypto_policy or 'unset'}"
        ),
        remediation=(
            "Enable system crypto policy: update-crypto-policies --set FUTURE"
        ),
        cross_references={
            "ENISA-NIS2": "Art.21.2(h)", "NIST": "SC-13",
        },
    ))

    # 21.2(i) - Human resources security, access control policies, asset mgmt
    sshd = _v33_read_file_safe("/etc/ssh/sshd_config")
    permit_root_match = re.search(r"^\s*PermitRootLogin\s+(\S+)", sshd, re.MULTILINE)
    permit_root = permit_root_match.group(1) if permit_root_match else "yes"
    root_secure = permit_root.lower() in ("no", "prohibit-password",
                                            "without-password")
    results.append(_v33_enisa_result(
        "ENISA NIS2 21.2(i) v3.3 - Access Control",
        "Pass" if root_secure else "Fail",
        f"NIS2 Article 21.2(i) Access control (SSH root: {permit_root})",
        severity="High",
        details=f"PermitRootLogin = {permit_root}",
        remediation="In /etc/ssh/sshd_config: PermitRootLogin no",
        cross_references={
            "ENISA-NIS2": "Art.21.2(i)", "NIST": "AC-6",
        },
    ))

    # 21.2(j) - Use of multi-factor authentication or continuous authentication
    pam_files = ["/etc/pam.d/sshd", "/etc/pam.d/system-auth",
                 "/etc/pam.d/common-auth"]
    mfa_modules = ["pam_google_authenticator", "pam_yubico", "pam_oath",
                    "pam_duo", "pam_u2f", "pam_pkcs11"]
    detected_mfa = set()
    for pf in pam_files:
        c = _v33_read_file_safe(pf)
        for mod in mfa_modules:
            if mod + ".so" in c:
                detected_mfa.add(mod.replace("pam_", ""))
    results.append(_v33_enisa_result(
        "ENISA NIS2 21.2(j) v3.3 - MFA",
        "Pass" if detected_mfa else "Warning",
        f"NIS2 Article 21.2(j) MFA modules ({len(detected_mfa)})",
        severity="High",
        details=f"Detected: {sorted(detected_mfa) or 'none'}",
        remediation=remediation_for("pam-google-authenticator"),
        cross_references={
            "ENISA-NIS2": "Art.21.2(j)", "NIST": "IA-2(1)",
        },
    ))


def _check_enisa_v33_dora(results, shared_data, os_info):
    """DORA - Digital Operational Resilience Act (financial sector)."""

    # DORA Article 6 - ICT risk management framework
    auditd_active = _v33_systemd_active("auditd.service") == "active"
    fim_present = (
        _v33_file_exists("/var/lib/aide/aide.db") or
        _v33_file_exists("/var/lib/aide/aide.db.gz")
    )
    risk_layers = sum([auditd_active, fim_present])
    results.append(_v33_enisa_result(
        "ENISA DORA Art.6 v3.3 - ICT Risk Management",
        "Pass" if risk_layers >= 2 else "Warning",
        f"DORA Article 6 ICT risk layers ({risk_layers}/2)",
        severity="High",
        details=f"auditd: {auditd_active}, FIM: {fim_present}",
        cross_references={
            "ENISA-DORA": "Art.6", "NIST": "RA-3",
        },
    ))

    # DORA Article 9 - Identification (asset visibility)
    asset_tools = {
        "osquery": _v33_command_available("osqueryi"),
        "package_mgr": (
            _v33_command_available("dpkg") or
            _v33_command_available("rpm") or
            _v33_command_available("pacman")
        ),
    }
    detected = sum(1 for v in asset_tools.values() if v)
    results.append(_v33_enisa_result(
        "ENISA DORA Art.9 v3.3 - Identification",
        "Pass" if detected >= 1 else "Fail",
        f"DORA Article 9 Asset identification capability",
        severity="High",
        details=f"Asset visibility tools: {detected}",
        cross_references={
            "ENISA-DORA": "Art.9", "NIST": "CM-8",
        },
    ))

    # DORA Article 10 - Protection and prevention
    prevention_layers = {
        "firewall": (
            _v33_systemd_active("ufw.service") == "active" or
            _v33_systemd_active("firewalld.service") == "active" or
            _v33_systemd_active("nftables.service") == "active"
        ),
        "antivirus": (
            _v33_command_available("clamscan") or
            _v33_file_exists("/opt/microsoft/mdatp/sbin/wdavdaemon") or
            _v33_file_exists("/opt/CrowdStrike/falconctl") or
            _v33_command_available("rkhunter")
        ),
        "MAC": (
            _v33_systemd_active("apparmor.service") == "active" or
            _v33_file_exists("/sys/fs/selinux/enforce")
        ),
    }
    detected_p = sum(1 for v in prevention_layers.values() if v)
    results.append(_v33_enisa_result(
        "ENISA DORA Art.10 v3.3 - Protection",
        "Pass" if detected_p >= 2 else "Warning",
        f"DORA Article 10 Protection layers ({detected_p}/3)",
        severity="High",
        details=(
            f"Firewall: {prevention_layers['firewall']}, "
            f"AV: {prevention_layers['antivirus']}, "
            f"MAC: {prevention_layers['MAC']}"
        ),
        cross_references={
            "ENISA-DORA": "Art.10", "NIST": "SC-7",
        },
    ))

    # DORA Article 11 - Detection
    detection_layers = {
        "ids": (
            _v33_command_available("suricata") or
            _v33_command_available("snort") or
            _v33_command_available("zeek")
        ),
        "edr": (
            _v33_command_available("falco") or
            _v33_file_exists("/opt/CrowdStrike/falconctl") or
            _v33_file_exists("/opt/sentinelone/bin/sentinelctl")
        ),
        "auditd": _v33_systemd_active("auditd.service") == "active",
    }
    detected_d = sum(1 for v in detection_layers.values() if v)
    results.append(_v33_enisa_result(
        "ENISA DORA Art.11 v3.3 - Detection",
        "Pass" if detected_d >= 1 else "Fail",
        f"DORA Article 11 Detection layers ({detected_d}/3)",
        severity="High",
        details=f"Detection: {[k for k, v in detection_layers.items() if v]}",
        cross_references={
            "ENISA-DORA": "Art.11", "NIST": "DE.CM",
        },
    ))

    # DORA Article 12 - Response and recovery
    backup_tools = {
        "rsync": _v33_command_available("rsync"),
        "borg": _v33_command_available("borg"),
        "restic": _v33_command_available("restic"),
    }
    detected_b = [k for k, v in backup_tools.items() if v]
    results.append(_v33_enisa_result(
        "ENISA DORA Art.12 v3.3 - Response and Recovery",
        "Pass" if detected_b else "Fail",
        f"DORA Article 12 Backup/recovery tools ({len(detected_b)})",
        severity="High",
        details=f"Detected: {detected_b}",
        cross_references={
            "ENISA-DORA": "Art.12", "NIST": "CP-9",
        },
    ))


def _check_enisa_v33_threat_landscape(results, shared_data, os_info):
    """ENISA Threat Landscape - top threats technical indicators."""

    # Ransomware: backup integrity
    backup_present = (
        _v33_command_available("borg") or
        _v33_command_available("restic") or
        _v33_command_available("duplicity")
    )
    immutable_indicators = (
        _v33_command_available("zfs") or
        _v33_command_available("btrfs")
    )
    ransom_def = backup_present and immutable_indicators
    results.append(_v33_enisa_result(
        "ENISA Threat v3.3 - Ransomware",
        "Pass" if ransom_def else "Warning",
        f"Top threat: ransomware mitigations",
        severity="Critical",
        details=(
            f"Backup tool: {backup_present}, snapshot capability: {immutable_indicators}"
        ),
        remediation=(
            "Use borg/restic with off-host backup storage. "
            "Use ZFS/Btrfs snapshots for instant recovery."
        ),
        cross_references={
            "ENISA-Threat": "Ransomware", "NIST": "CP-9",
        },
    ))

    # Malware: AV/EDR
    av_detected = (
        _v33_command_available("clamscan") or
        _v33_file_exists("/opt/CrowdStrike/falconctl") or
        _v33_file_exists("/opt/microsoft/mdatp/sbin/wdavdaemon") or
        _v33_command_available("falco")
    )
    results.append(_v33_enisa_result(
        "ENISA Threat v3.3 - Malware",
        "Pass" if av_detected else "Fail",
        f"Top threat: malware detection",
        severity="High",
        details=f"AV/EDR detected: {av_detected}",
        cross_references={
            "ENISA-Threat": "Malware", "NIST": "SI-3",
        },
    ))

    # Social engineering: MFA
    pam_files = ["/etc/pam.d/sshd", "/etc/pam.d/system-auth",
                 "/etc/pam.d/common-auth"]
    mfa_modules = ["pam_google_authenticator", "pam_yubico", "pam_oath",
                    "pam_duo", "pam_u2f"]
    has_mfa = False
    for pf in pam_files:
        c = _v33_read_file_safe(pf)
        if any(mod + ".so" in c for mod in mfa_modules):
            has_mfa = True
            break
    results.append(_v33_enisa_result(
        "ENISA Threat v3.3 - Social Engineering",
        "Pass" if has_mfa else "Warning",
        f"Top threat: phishing/social engineering (MFA)",
        severity="High",
        details=f"MFA configured: {has_mfa}",
        cross_references={
            "ENISA-Threat": "Social Engineering", "NIST": "IA-2(1)",
        },
    ))

    # Threats against data: encryption
    rc, out, _ = _v33_run_command(["lsblk", "-o", "TYPE", "-n"], timeout=3.0)
    luks = rc == 0 and "crypt" in out.lower()
    results.append(_v33_enisa_result(
        "ENISA Threat v3.3 - Data Threats",
        "Pass" if luks else "Warning",
        f"Top threat: data theft (LUKS at-rest encryption): {luks}",
        severity="High",
        details=f"LUKS volumes: {luks}",
        cross_references={
            "ENISA-Threat": "Data Threats", "NIST": "SC-28",
        },
    ))

    # DDoS: rate limiting / fail2ban
    f2b_active = _v33_systemd_active("fail2ban.service") == "active"
    nft_with_limits = False
    rc, out, _ = _v33_run_command(["nft", "list", "ruleset"], timeout=3.0)
    if rc == 0 and out and "limit" in out.lower():
        nft_with_limits = True
    ddos_def = f2b_active or nft_with_limits
    results.append(_v33_enisa_result(
        "ENISA Threat v3.3 - DDoS",
        "Pass" if ddos_def else "Info",
        f"Top threat: DDoS rate-limiting indicators",
        severity="Medium",
        details=f"fail2ban: {f2b_active}, nftables limits: {nft_with_limits}",
        remediation="Install fail2ban or add nftables rate-limit rules",
        cross_references={
            "ENISA-Threat": "DDoS", "NIST": "SC-5",
        },
    ))

    # Disinformation/AI: integrity tooling
    fim_present = (
        _v33_file_exists("/var/lib/aide/aide.db") or
        _v33_file_exists("/var/lib/aide/aide.db.gz")
    )
    results.append(_v33_enisa_result(
        "ENISA Threat v3.3 - Disinformation/Integrity",
        "Pass" if fim_present else "Warning",
        f"Top threat: information integrity (FIM)",
        severity="Medium",
        details=f"AIDE FIM database: {fim_present}",
        cross_references={
            "ENISA-Threat": "Disinformation", "NIST": "SI-7",
        },
    ))

    # Supply chain attacks
    apt_keyring = (
        _v33_directory_exists("/etc/apt/trusted.gpg.d") or
        _v33_directory_exists("/etc/apt/keyrings")
    )
    rpm_check = "gpgcheck=1" in (
        _v33_read_file_safe("/etc/yum.conf") or
        _v33_read_file_safe("/etc/dnf/dnf.conf")
    )
    sc_ok = apt_keyring or rpm_check
    results.append(_v33_enisa_result(
        "ENISA Threat v3.3 - Supply Chain",
        "Pass" if sc_ok else "Fail",
        f"Top threat: supply chain (signature verification)",
        severity="High",
        details=f"apt keyring: {apt_keyring}, rpm gpgcheck: {rpm_check}",
        cross_references={
            "ENISA-Threat": "Supply Chain", "NIST": "SR-3",
        },
    ))


def _check_enisa_v33_eu_csa(results, shared_data, os_info):
    """EU Cybersecurity Act Article 51 - certification baseline."""

    # Basic - basic level of confidence
    fw_active = (
        _v33_systemd_active("ufw.service") == "active" or
        _v33_systemd_active("firewalld.service") == "active" or
        _v33_systemd_active("nftables.service") == "active"
    )
    update_active = (
        _v33_systemd_active("unattended-upgrades.service") == "active" or
        _v33_systemd_active("dnf-automatic-install.timer") == "active"
    )
    basic_layers = sum([fw_active, update_active])
    results.append(_v33_enisa_result(
        "ENISA EU-CSA v3.3 - Basic",
        "Pass" if basic_layers >= 2 else "Warning",
        f"EU-CSA Basic ({basic_layers}/2)",
        severity="Medium",
        details=f"firewall: {fw_active}, auto-update: {update_active}",
        cross_references={
            "ENISA-EU-CSA": "Art.51 Basic", "NIST": "SI-2",
        },
    ))

    # Substantial - protection against known cybersecurity risks
    fim = (
        _v33_file_exists("/var/lib/aide/aide.db") or
        _v33_file_exists("/var/lib/aide/aide.db.gz")
    )
    audit_active = _v33_systemd_active("auditd.service") == "active"
    sub_layers = sum([fim, audit_active])
    results.append(_v33_enisa_result(
        "ENISA EU-CSA v3.3 - Substantial",
        "Pass" if sub_layers >= 1 else "Warning",
        f"EU-CSA Substantial ({sub_layers}/2)",
        severity="High",
        details=f"FIM: {fim}, auditd: {audit_active}",
        cross_references={
            "ENISA-EU-CSA": "Art.51 Substantial", "NIST": "SI-7",
        },
    ))

    # High - protection against state-of-the-art cyberattacks
    fips_active = False
    if _v33_file_exists("/proc/sys/crypto/fips_enabled"):
        fips_active = _v33_read_file_safe(
            "/proc/sys/crypto/fips_enabled"
        ).strip() == "1"
    mac_active = _v33_systemd_active("apparmor.service") == "active"
    if not mac_active and _v33_file_exists("/sys/fs/selinux/enforce"):
        try:
            with open("/sys/fs/selinux/enforce") as f:
                mac_active = f.read().strip() == "1"
        except OSError:
            pass
    high_layers = sum([fips_active, mac_active])
    results.append(_v33_enisa_result(
        "ENISA EU-CSA v3.3 - High",
        "Pass" if high_layers >= 1 else "Info",
        f"EU-CSA High ({high_layers}/2)",
        severity="High",
        details=f"FIPS: {fips_active}, MAC enforcing: {mac_active}",
        cross_references={
            "ENISA-EU-CSA": "Art.51 High", "NIST": "SC-13",
        },
    ))


# Save reference to existing run_checks
_original_run_checks_enisa_v33 = run_checks


def run_checks(shared_data):
    """Execute the v3.3 expanded ENISA module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_enisa_v33(shared_data)

    os_info = shared_data.get("os_info") or shared_data.get("v3_os_info")
    if os_info is None:
        from shared_components import os_detection as _os_det
        os_info = _os_det.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        _check_enisa_v33_nis2_article21(results, shared_data, os_info)
        _check_enisa_v33_dora(results, shared_data, os_info)
        _check_enisa_v33_threat_landscape(results, shared_data, os_info)
        _check_enisa_v33_eu_csa(results, shared_data, os_info)
    except Exception as exc:  # noqa: BLE001
        results.append(AuditResult(
            module=MODULE_NAME, category="ENISA - Error",
            status="Error",
            message=f"ENISA v3.3 expansion exception: {exc!r}",
            details=str(exc), severity="Medium",
        ))

    return results


# ============================================================================
# v3.5 EXPANSION - ENISA NIS2 + Cyber Resilience Act + Modern Guidance
# ----------------------------------------------------------------------------
# Synopsis:
#   Adds depth across ENISA / EU regulatory framework areas:
#     - NIS2 Directive (Directive (EU) 2022/2555) Article 21 measures
#     - EU Cyber Resilience Act (CRA) Annex I requirements
#     - ENISA Threat Landscape recommendations (multi-year)
#     - DORA (Digital Operational Resilience Act) for financial entities
#     - eIDAS 2.0 cryptographic alignment
#     - ENISA Cloud Security Recommendations
#     - ENISA 5G Security indicators
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


def _v35_enisa_result(category, status, message, severity="Medium",
                    details="", remediation="", cross_references=None):
    """Build AuditResult for ENISA v3.5 expansion."""
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


def _check_enisa_v35_nis2_article21(results, shared_data, os_info):
    """NIS2 Directive Article 21 - Cybersecurity risk-management measures."""
    cat = "ENISA v3.5 - NIS2 Art 21"

    # Art 21(2)(a) Risk analysis policies (technical: vuln scanning)
    risk_tools = sum(1 for t in ["lynis", "oscap", "trivy", "nuclei"]
                     if _v35_command_available(t))
    results.append(_v35_enisa_result(
        f"{cat} - Art 21(2)(a) Risk Analysis",
        "Pass" if risk_tools >= 2 else "Warning",
        f"NIS2 Art 21(2)(a) Risk analysis tools: {risk_tools}/4",
        severity="High",
        details=f"Vuln/risk tools available: {risk_tools}",
        remediation=remediation_for("lynis"),
        cross_references={
            "ENISA": "NIS2 Art 21(2)(a)",
            "NIST": "RA-3, RA-5",
        },
    ))

    # Art 21(2)(b) Incident handling (auditd + IR tooling)
    ir_layers = sum([
        _v35_systemd_active("auditd.service") == "active",
        _v35_command_available("tcpdump"),
        _v35_command_available("lsof"),
        _v35_command_available("strace"),
        _v35_command_available("journalctl"),
    ])
    results.append(_v35_enisa_result(
        f"{cat} - Art 21(2)(b) Incident Handling",
        "Pass" if ir_layers >= 4 else "Warning",
        f"NIS2 Art 21(2)(b) IR tooling layers: {ir_layers}/5",
        severity="High",
        details=f"IR tools active: {ir_layers}",
        remediation=(
            "apt-get install -y auditd tcpdump lsof strace systemd"
        ),
        cross_references={
            "ENISA": "NIS2 Art 21(2)(b)",
            "NIST": "IR-4, IR-5",
        },
    ))

    # Art 21(2)(c) Business continuity (backup + recovery)
    bc_layers = sum([
        any(_v35_command_available(t) for t in ["borg", "restic", "duplicity"]),
        any(_v35_command_available(t) for t in ["zfs", "btrfs", "snapper"]),
        _v35_command_available("ansible") or _v35_command_available("puppet"),
    ])
    results.append(_v35_enisa_result(
        f"{cat} - Art 21(2)(c) Business Continuity",
        "Pass" if bc_layers >= 2 else "Warning",
        f"NIS2 Art 21(2)(c) BC layers: {bc_layers}/3",
        severity="High",
        details=f"BC tooling layers: {bc_layers}",
        remediation=remediation_for("borg"),
        cross_references={
            "ENISA": "NIS2 Art 21(2)(c)",
            "NIST": "CP-9, CP-10",
        },
    ))

    # Art 21(2)(d) Supply chain security (SBOM + signing)
    supply_chain_layers = sum([
        _v35_command_available("syft") or _v35_command_available("trivy"),
        _v35_command_available("cosign") or _v35_command_available("gpg"),
        _v35_directory_exists("/etc/apt/keyrings") or
        _v35_directory_exists("/etc/apt/trusted.gpg.d"),
    ])
    results.append(_v35_enisa_result(
        f"{cat} - Art 21(2)(d) Supply Chain Security",
        "Pass" if supply_chain_layers >= 2 else "Warning",
        f"NIS2 Art 21(2)(d) Supply chain layers: {supply_chain_layers}/3",
        severity="High",
        details=f"Supply chain tooling: {supply_chain_layers}",
        remediation=(
            f"{remediation_for('syft')}\n"
            "Plus install cosign for artifact signing."
        ),
        cross_references={
            "ENISA": "NIS2 Art 21(2)(d)",
            "NIST": "SR-3, SR-4, SR-11",
        },
    ))

    # Art 21(2)(e) Vulnerability handling and disclosure (auto-patch + tracker)
    auto_patch_active = (
        _v35_systemd_active("unattended-upgrades.service") == "active" or
        _v35_systemd_active("dnf-automatic-install.timer") == "active" or
        _v35_systemd_active("dnf-automatic.timer") == "active"
    )
    results.append(_v35_enisa_result(
        f"{cat} - Art 21(2)(e) Vuln Handling",
        "Pass" if auto_patch_active else "Warning",
        f"NIS2 Art 21(2)(e) Auto-patch active: {auto_patch_active}",
        severity="High",
        details=f"Auto-patch service: {auto_patch_active}",
        remediation=(
            remediation_for("unattended-upgrades")
            if (os_info and os_info.is_debian_family())
            else remediation_for("dnf-automatic")
        ),
        cross_references={
            "ENISA": "NIS2 Art 21(2)(e)",
            "NIST": "SI-2",
        },
    ))

    # Art 21(2)(g) Cyber hygiene & training (technical surrogate: CIS-aligned baseline)
    cis_baseline_layers = sum([
        _v35_command_available("lynis"),
        _v35_command_available("oscap"),
        _v35_systemd_active("auditd.service") == "active",
        _v35_file_exists("/var/lib/aide/aide.db") or
        _v35_file_exists("/var/lib/aide/aide.db.gz"),
    ])
    results.append(_v35_enisa_result(
        f"{cat} - Art 21(2)(g) Cyber Hygiene",
        "Pass" if cis_baseline_layers >= 3 else "Info",
        f"NIS2 Art 21(2)(g) Hardening evidence: {cis_baseline_layers}/4",
        severity="Medium",
        details=f"Hardening tools: {cis_baseline_layers}",
        cross_references={
            "ENISA": "NIS2 Art 21(2)(g)",
            "CIS": "1.0",
        },
    ))

    # Art 21(2)(h) Cryptography use
    fips_aligned = (
        _v35_read_sysctl("crypto.fips_enabled") == "1" or
        _v35_read_file_safe("/etc/crypto-policies/state/current").strip().upper()
        in ("FIPS", "FUTURE")
    )
    results.append(_v35_enisa_result(
        f"{cat} - Art 21(2)(h) Cryptography",
        "Pass" if fips_aligned else "Warning",
        f"NIS2 Art 21(2)(h) FIPS-aligned cryptography: {fips_aligned}",
        severity="High",
        details=f"FIPS / FUTURE crypto policy: {fips_aligned}",
        remediation=(
            "RHEL: fips-mode-setup --enable\n"
            "Or: update-crypto-policies --set FUTURE\n"
            "Ubuntu Pro: pro enable fips"
        ),
        cross_references={
            "ENISA": "NIS2 Art 21(2)(h)",
            "FIPS": "140-3", "eIDAS": "2.0",
        },
    ))

    # Art 21(2)(i) HR security (access control on workforce changes)
    pam_lockout = False
    pam_files_content = ""
    for pf in ["/etc/pam.d/system-auth", "/etc/pam.d/password-auth",
                "/etc/pam.d/common-auth"]:
        pam_files_content += "\n" + _v35_read_file_safe(pf)
    if "pam_faillock" in pam_files_content or "pam_tally2" in pam_files_content:
        pam_lockout = True
    results.append(_v35_enisa_result(
        f"{cat} - Art 21(2)(i) HR Security",
        "Pass" if pam_lockout else "Warning",
        f"NIS2 Art 21(2)(i) PAM account lockout: {pam_lockout}",
        severity="Medium",
        details=f"PAM lockout module: {pam_lockout}",
        cross_references={
            "ENISA": "NIS2 Art 21(2)(i)",
            "NIST": "AC-7",
        },
    ))

    # Art 21(2)(j) MFA / continuous authentication
    sshd = _v35_read_file_safe("/etc/ssh/sshd_config")
    sshd_d = ""
    if _v35_directory_exists("/etc/ssh/sshd_config.d"):
        for f in _v35_list_directory("/etc/ssh/sshd_config.d"):
            if f.endswith(".conf"):
                sshd_d += "\n" + _v35_read_file_safe(
                    os.path.join("/etc/ssh/sshd_config.d", f)
                )
    full_sshd = sshd + "\n" + sshd_d
    mfa_method = bool(re.search(
        r"^\s*AuthenticationMethods\s+\S+,",
        full_sshd, re.MULTILINE,
    ))
    pam_mfa = any(mod in pam_files_content for mod in [
        "pam_google_authenticator", "pam_yubico", "pam_oath",
        "pam_u2f", "pam_duo",
    ])
    mfa_present = mfa_method or pam_mfa
    results.append(_v35_enisa_result(
        f"{cat} - Art 21(2)(j) MFA",
        "Pass" if mfa_present else "Warning",
        f"NIS2 Art 21(2)(j) MFA evidence: {mfa_present}",
        severity="High",
        details=(
            f"SSH AuthMethods MFA: {mfa_method}, PAM MFA: {pam_mfa}"
        ),
        remediation=remediation_for("pam-google-authenticator"),
        cross_references={
            "ENISA": "NIS2 Art 21(2)(j)",
            "NIST": "IA-2(1), IA-2(2)",
        },
    ))


def _check_enisa_v35_cra_annex1(results, shared_data, os_info):
    """EU Cyber Resilience Act (CRA) Annex I essential cybersecurity reqs."""
    cat = "ENISA v3.5 - CRA Annex I"

    # Annex I Section 1: appropriate level of cybersecurity (FIPS-aligned)
    fips = _v35_read_sysctl("crypto.fips_enabled") == "1"
    crypto_strong = fips or _v35_read_file_safe(
        "/etc/crypto-policies/state/current"
    ).strip().upper() in ("FIPS", "FUTURE")
    results.append(_v35_enisa_result(
        f"{cat} - Sec 1 Cybersecurity Level",
        "Pass" if crypto_strong else "Info",
        f"CRA Annex I Sec 1 cryptographic baseline: {crypto_strong}",
        severity="Medium",
        details=f"FIPS/FUTURE crypto: {crypto_strong}",
        cross_references={
            "ENISA": "CRA Annex I.1",
            "FIPS": "140-3",
        },
    ))

    # Annex I Section 2(a): No known exploitable vulnerabilities
    auto_patch = (
        _v35_systemd_active("unattended-upgrades.service") == "active" or
        _v35_systemd_active("dnf-automatic-install.timer") == "active" or
        _v35_systemd_active("dnf-automatic.timer") == "active"
    )
    results.append(_v35_enisa_result(
        f"{cat} - Sec 2(a) No Known Vulns",
        "Pass" if auto_patch else "Warning",
        f"CRA Annex I Sec 2(a) Auto-patch: {auto_patch}",
        severity="High",
        details=f"Auto-patch active: {auto_patch}",
        cross_references={
            "ENISA": "CRA Annex I.2(a)",
            "NIST": "SI-2",
        },
    ))

    # Annex I Section 2(b): Security by default
    fw_active = (
        _v35_systemd_active("ufw.service") == "active" or
        (_v35_run_command(["firewall-cmd", "--state"], timeout=3.0)[0] == 0 and
         "running" in (_v35_run_command(
            ["firewall-cmd", "--state"], timeout=3.0,
        )[1] or ""))
    )
    results.append(_v35_enisa_result(
        f"{cat} - Sec 2(b) Security by Default",
        "Pass" if fw_active else "Warning",
        f"CRA Annex I Sec 2(b) Default firewall active: {fw_active}",
        severity="High",
        details=f"firewall active: {fw_active}",
        cross_references={
            "ENISA": "CRA Annex I.2(b)",
            "NIST": "SC-7",
        },
    ))

    # Annex I Section 2(c): Protection from unauthorized access
    auth_layers = sum([
        bool(re.search(r"^\s*PermitRootLogin\s+no",
                        _v35_read_file_safe("/etc/ssh/sshd_config"),
                        re.MULTILINE)),
        bool(re.search(r"^\s*PasswordAuthentication\s+no",
                        _v35_read_file_safe("/etc/ssh/sshd_config"),
                        re.MULTILINE)),
        _v35_command_available("sudo"),
    ])
    results.append(_v35_enisa_result(
        f"{cat} - Sec 2(c) Access Protection",
        "Pass" if auth_layers >= 2 else "Warning",
        f"CRA Annex I Sec 2(c) Auth hardening layers: {auth_layers}/3",
        severity="High",
        details=f"Hardening layers: {auth_layers}",
        cross_references={
            "ENISA": "CRA Annex I.2(c)",
            "NIST": "AC-2, AC-3",
        },
    ))

    # Annex I Section 2(d): Protection of data integrity
    fim_present = (
        _v35_file_exists("/var/lib/aide/aide.db") or
        _v35_file_exists("/var/lib/aide/aide.db.gz") or
        _v35_file_exists("/var/lib/tripwire/tw.db")
    )
    results.append(_v35_enisa_result(
        f"{cat} - Sec 2(d) Data Integrity",
        "Pass" if fim_present else "Warning",
        f"CRA Annex I Sec 2(d) FIM database present: {fim_present}",
        severity="High",
        details=f"AIDE/Tripwire DB: {fim_present}",
        remediation=remediation_for("aide"),
        cross_references={
            "ENISA": "CRA Annex I.2(d)",
            "NIST": "SI-7", "PCI-DSS": "11.5.2",
        },
    ))

    # Annex I Section 2(e): Limit data processing (least privilege)
    selinux_enforcing = (
        _v35_command_available("getenforce") and
        ((_v35_run_command(["getenforce"], timeout=2.0)[1] or "").strip()
         == "Enforcing")
    )
    apparmor_active = _v35_command_available("aa-status")
    mac_active = selinux_enforcing or apparmor_active
    results.append(_v35_enisa_result(
        f"{cat} - Sec 2(e) Limited Data Processing",
        "Pass" if mac_active else "Info",
        f"CRA Annex I Sec 2(e) MAC active: {mac_active}",
        severity="Medium",
        details=(
            f"SELinux: {selinux_enforcing}, AppArmor: {apparmor_active}"
        ),
        cross_references={
            "ENISA": "CRA Annex I.2(e)",
            "NIST": "AC-3, AC-6",
        },
    ))

    # Annex I Section 2(f): Minimize attack surface
    rc, out, _ = _v35_run_command(["ss", "-tlnp"], timeout=5.0)
    listening_external = 0
    if rc == 0 and out:
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4 or parts[0] != "LISTEN":
                continue
            local = parts[3]
            if not (local.startswith("127.") or local.startswith("[::1]") or
                    local.startswith("[::ffff:127")):
                listening_external += 1
    results.append(_v35_enisa_result(
        f"{cat} - Sec 2(f) Minimal Attack Surface",
        "Pass" if listening_external <= 5 else "Warning",
        f"CRA Annex I Sec 2(f) External listeners: {listening_external}",
        severity="Medium",
        details=f"Externally-bound TCP listeners: {listening_external}",
        cross_references={
            "ENISA": "CRA Annex I.2(f)",
            "NIST": "CM-7",
        },
    ))

    # Annex I Section 2(j): Secure default configurations
    umask_match = re.search(
        r"^\s*UMASK\s+(\d+)",
        _v35_read_file_safe("/etc/login.defs"),
        re.MULTILINE,
    )
    umask = umask_match.group(1) if umask_match else "022"
    secure_default = umask in ("027", "077")
    results.append(_v35_enisa_result(
        f"{cat} - Sec 2(j) Secure Defaults",
        "Pass" if secure_default else "Info",
        f"CRA Annex I Sec 2(j) Secure default UMASK: {umask}",
        severity="Medium",
        details=f"UMASK = {umask}",
        cross_references={
            "ENISA": "CRA Annex I.2(j)",
            "NIST": "CM-6",
        },
    ))


def _check_enisa_v35_dora_financial(results, shared_data, os_info):
    """DORA (Digital Operational Resilience Act) for financial entities."""
    cat = "ENISA v3.5 - DORA"

    # DORA Article 7 - ICT risk management
    risk_mgmt_layers = sum([
        _v35_command_available("lynis"),
        _v35_command_available("oscap"),
        _v35_systemd_active("auditd.service") == "active",
        _v35_file_exists("/var/lib/aide/aide.db") or
        _v35_file_exists("/var/lib/aide/aide.db.gz"),
    ])
    results.append(_v35_enisa_result(
        f"{cat} - Art 7 ICT Risk Mgmt",
        "Pass" if risk_mgmt_layers >= 3 else "Warning",
        f"DORA Art 7 ICT risk management layers: {risk_mgmt_layers}/4",
        severity="High",
        details=f"Layers: {risk_mgmt_layers}",
        cross_references={
            "ENISA": "DORA Art 7",
            "NIST": "RA-3, RA-5, CA-7",
        },
    ))

    # DORA Article 17 - ICT-related incident reporting
    mail_capable = (
        _v35_command_available("mail") or
        _v35_command_available("mailx") or
        _v35_systemd_active("postfix.service") == "active"
    )
    results.append(_v35_enisa_result(
        f"{cat} - Art 17 Incident Reporting",
        "Pass" if mail_capable else "Warning",
        f"DORA Art 17 Incident reporting capability: {mail_capable}",
        severity="High",
        details=f"Mail tooling: {mail_capable}",
        cross_references={
            "ENISA": "DORA Art 17",
            "NIST": "IR-6",
        },
    ))


def _check_enisa_v35_cloud_security(results, shared_data, os_info):
    """ENISA Cloud Security Recommendations."""
    cat = "ENISA v3.5 - Cloud Security"

    # ENISA Cloud Computing Risk Assessment surrogates
    cloud_security_layers = {
        "FIPS-aligned crypto": (
            _v35_read_sysctl("crypto.fips_enabled") == "1" or
            _v35_read_file_safe(
                "/etc/crypto-policies/state/current"
            ).strip().upper() in ("FIPS", "FUTURE")
        ),
        "LUKS encryption at rest": False,
        "MAC active (SELinux/AppArmor)": False,
        "Centralized logging": False,
        "Auto-patching": (
            _v35_systemd_active("unattended-upgrades.service") == "active" or
            _v35_systemd_active("dnf-automatic-install.timer") == "active" or
            _v35_systemd_active("dnf-automatic.timer") == "active"
        ),
    }
    rc, out, _ = _v35_run_command(["lsblk", "-o", "TYPE", "-n"], timeout=5.0)
    if rc == 0 and out and "crypt" in out.lower():
        cloud_security_layers["LUKS encryption at rest"] = True
    if (_v35_command_available("getenforce") and
        (_v35_run_command(["getenforce"], timeout=2.0)[1] or "").strip()
        == "Enforcing") or _v35_command_available("aa-status"):
        cloud_security_layers["MAC active (SELinux/AppArmor)"] = True
    rsy = _v35_read_file_safe("/etc/rsyslog.conf")
    if "@@" in rsy or "omfwd" in rsy:
        cloud_security_layers["Centralized logging"] = True
    elif _v35_directory_exists("/etc/rsyslog.d"):
        for f in _v35_list_directory("/etc/rsyslog.d"):
            c = _v35_read_file_safe(os.path.join("/etc/rsyslog.d", f))
            if "@@" in c or "omfwd" in c:
                cloud_security_layers["Centralized logging"] = True
                break

    active = sum(1 for v in cloud_security_layers.values() if v)
    results.append(_v35_enisa_result(
        f"{cat} - Cloud Security Layers",
        "Pass" if active >= 3 else "Warning",
        f"ENISA Cloud Security layers: {active}/5",
        severity="Medium",
        details=(
            f"Active: {[k for k, v in cloud_security_layers.items() if v]}"
        ),
        cross_references={
            "ENISA": "Cloud Security Recommendations",
            "ISO27017": "Cloud Services",
        },
    ))


# Save reference to existing run_checks
_original_run_checks_enisa_v35 = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the v3.5 expanded ENISA module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_enisa_v35(shared_data)

    os_info = shared_data.get("os_info") or shared_data.get("v3_os_info")
    if os_info is None:
        from shared_components import os_detection as _os_det
        os_info = _os_det.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        _check_enisa_v35_nis2_article21(results, shared_data, os_info)
        _check_enisa_v35_cra_annex1(results, shared_data, os_info)
        _check_enisa_v35_dora_financial(results, shared_data, os_info)
        _check_enisa_v35_cloud_security(results, shared_data, os_info)
    except Exception as exc:  # noqa: BLE001
        results.append(AuditResult(
            module=MODULE_NAME, category="ENISA - Error",
            status="Error",
            message=f"ENISA v3.5 expansion exception: {exc!r}",
            details=str(exc), severity="Medium",
        ))

    return results
if __name__ == "__main__":
    """
    Standalone testing capability for the ENISA module
    """
    import datetime
    
    print("="*80)
    print(f"ENISA Module Standalone Test - v{MODULE_VERSION}")
    print("EU Agency for Cybersecurity Compliance for Linux")
    print("="*80)
    
    # Initialize cache if shared library is available
    cache = None
    if HAS_COMMON_LIB:
        os_info_init = detect_os()
        cache = SharedDataCache(os_info_init)
        cache.warm_up()
        print(f"  Cache: Enabled")
    
    # Prepare test environment data
    test_data = {
        "hostname": socket.gethostname(),
        "scan_date": datetime.datetime.now(),
        "is_root": os.geteuid() == 0,
        "script_path": Path(__file__).parent.parent if hasattr(Path(__file__), 'parent') else Path.cwd(),
        "cache": cache,
    }
    
    print(f"\nTest Environment:")
    print(f"  Hostname: {test_data['hostname']}")
    print(f"  Running as root: {test_data['is_root']}")
    print(f"  Scan time: {test_data['scan_date'].strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80 + "\n")
    
    # Execute checks
    test_results = run_checks(test_data)
    
    # Detailed analysis
    print(f"\n{'='*80}")
    print(f"DETAILED TEST RESULTS")
    print(f"{'='*80}")
    print(f"Generated {len(test_results)} audit results\n")
    
    from collections import Counter
    
    # Status breakdown
    status_counts = Counter(r.status for r in test_results)
    print("Status Distribution:")
    for status in ["Pass", "Fail", "Warning", "Info", "Error"]:
        count = status_counts.get(status, 0)
        if count > 0:
            pct = (count / len(test_results)) * 100
            bar = '#' * int(pct / 2)
            print(f"  {status:8s}: {count:3d} ({pct:5.1f}%) {bar}")
    
    # Category breakdown
    print(f"\nControl Area Coverage:")
    category_counts = Counter()
    for r in test_results:
        match = re.search(r'ENISA - (.+)', r.category)
        if match:
            category_counts[match.group(1)] += 1
    
    for category in sorted(category_counts.keys()):
        count = category_counts[category]
        print(f"  {category:35s}: {count:3d} checks")
    
    print(f"\n{'='*80}")
    print(f"ENISA module comprehensive test complete")
    print(f"All {len(test_results)} checks executed successfully")
    print(f"{'='*80}\n")
