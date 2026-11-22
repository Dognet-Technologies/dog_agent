#!/usr/bin/env python3
"""
module_nist.py
NIST Cybersecurity Framework & 800-53 Controls Module for Linux
Version: 2.1

SYNOPSIS:
    Comprehensive audit of NIST security controls and Cybersecurity Framework 
    compliance checks for Linux systems.

DESCRIPTION:
    This module performs exhaustive security checks aligned with NIST guidance:
    
    NIST 800-53 Rev 5 Control Families:
    - Access Control (AC)
    - Audit and Accountability (AU)
    - Configuration Management (CM)
    - Identification and Authentication (IA)
    - Incident Response (IR)
    - System and Communications Protection (SC)
    - System and Information Integrity (SI)
    - Contingency Planning (CP)
    - Maintenance (MA)
    - Media Protection (MP)
    - Physical & Environmental (PE)
    - Risk Assessment (RA)
    - System Acquisition (SA)
    
    NIST Cybersecurity Framework 2.0 (CSF):
    - Govern (GV) - Organizational cybersecurity governance
    - Identify (ID) - Asset management, risk assessment
    - Protect (PR) - Access control, data security, platform security
    - Detect (DE) - Continuous monitoring, adverse event detection
    - Respond (RS) - Incident response, communications, mitigation
    - Recover (RC) - Recovery planning, improvements
    
    NIST 800-171 Rev 2:
    - Protection of Controlled Unclassified Information (CUI)
    - 14 requirement families with 110 security requirements

PARAMETERS:
    shared_data : Dictionary containing shared data from main script

USAGE:
    Standalone testing
        python3 module_nist.py

    Integration with main audit script
        python3 linux_security_audit.py --modules NIST
        python3 linux_security_audit.py -m NIST

NOTES:
    Version: 2.1
    Reference: https://csrc.nist.gov/publications
    Standards: NIST 800-53 Rev 5, NIST CSF 2.0, NIST 800-171 Rev 2
    Target: 160+ comprehensive security checks; OS-aware technical control checks
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

MODULE_NAME = "NIST"

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

def get_nist_id(family: str, number: int) -> str:
    """Generate NIST control ID"""
    return f"NIST-{family}-{number:03d}"

# ============================================================================
# AC - Access Control
# NIST 800-53: AC-1 through AC-25
# CSF: PR.AC (Identity Management and Access Control)
# ============================================================================

def check_access_control(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Access Control checks - AC family
    Security audit for access control configurations and variables
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking AC - Access Control...")
    
    # AC-001: UID 0 accounts check (AC-6 Least Privilege)
    passwd_content = read_file_safe("/etc/passwd")
    root_accounts = []
    for line in passwd_content.split('\n'):
        if ':0:' in line and line.strip():
            root_accounts.append(line.split(':')[0])
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AC (Access Control)",
        status="Pass" if len(root_accounts) == 1 and root_accounts[0] == "root" else "Fail",
        message=f"{get_nist_id('AC', 1)}: Only root account has UID 0 (AC-6)",
        details=f"UID 0 accounts: {', '.join(root_accounts)}",
        remediation="Remove additional UID 0 accounts: userdel <username>"
    ))
    
    # AC-002: No empty password fields (AC-2 Account Management)
    shadow_content = read_file_safe("/etc/shadow")
    empty_password_accounts = []
    for line in shadow_content.split('\n'):
        if line and '::' in line:
            empty_password_accounts.append(line.split(':')[0])
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AC (Access Control)",
        status="Pass" if not empty_password_accounts else "Fail",
        message=f"{get_nist_id('AC', 2)}: No accounts with empty passwords (AC-2)",
        details=f"Empty password accounts: {', '.join(empty_password_accounts) if empty_password_accounts else 'None'}",
        remediation="Lock accounts: passwd -l <username> or set passwords"
    ))
    
    # AC-003: Duplicate UIDs check (AC-2)
    uid_map = {}
    for line in passwd_content.split('\n'):
        if line and not line.startswith('#'):
            fields = line.split(':')
            if len(fields) >= 3:
                username = fields[0]
                uid = fields[2]
                if uid in uid_map:
                    uid_map[uid].append(username)
                else:
                    uid_map[uid] = [username]
    
    duplicate_uids = {uid: users for uid, users in uid_map.items() if len(users) > 1}
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AC (Access Control)",
        status="Pass" if not duplicate_uids else "Fail",
        message=f"{get_nist_id('AC', 3)}: No duplicate UIDs (AC-2)",
        details=f"Duplicate UIDs: {duplicate_uids}" if duplicate_uids else "None",
        remediation="Assign unique UIDs to each user"
    ))
    
    # AC-004: Duplicate usernames check (AC-2)
    usernames = [line.split(':')[0] for line in passwd_content.split('\n') if line and not line.startswith('#')]
    duplicate_usernames = [u for u in set(usernames) if usernames.count(u) > 1]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AC (Access Control)",
        status="Pass" if not duplicate_usernames else "Fail",
        message=f"{get_nist_id('AC', 4)}: No duplicate usernames (AC-2)",
        details=f"Duplicates: {', '.join(duplicate_usernames)}" if duplicate_usernames else "None",
        remediation="Remove duplicate username entries"
    ))
    
    # AC-005: PAM configuration exists (AC-3 Access Enforcement)
    pam_dirs = ["/etc/pam.d", "/etc/pam.conf"]
    pam_configured = any(os.path.exists(d) for d in pam_dirs)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AC (Access Control)",
        status="Pass" if pam_configured else "Fail",
        message=f"{get_nist_id('AC', 5)}: PAM authentication configured (AC-3)",
        details="PAM directory exists" if pam_configured else "PAM not configured",
        remediation="Configure PAM in /etc/pam.d/"
    ))
    
    # AC-006: PAM password quality module (AC-3)
    pwquality_configured = check_pam_module("pam_pwquality") or check_pam_module("pam_cracklib")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AC (Access Control)",
        status="Pass" if pwquality_configured else "Fail",
        message=f"{get_nist_id('AC', 6)}: Password quality enforcement configured (AC-3)",
        details="pwquality/cracklib configured" if pwquality_configured else "Not configured",
        remediation="Configure pam_pwquality in PAM"
    ))
    
    # AC-007: IP forwarding disabled (AC-4 Information Flow Enforcement)
    exists, ip_forward = check_kernel_parameter("net.ipv4.ip_forward")
    forward_disabled = ip_forward == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AC (Access Control)",
        status="Pass" if forward_disabled else "Fail",
        message=f"{get_nist_id('AC', 7)}: IP forwarding disabled (AC-4)",
        details=f"net.ipv4.ip_forward = {ip_forward}",
        remediation="Disable: echo 'net.ipv4.ip_forward = 0' >> /etc/sysctl.conf && sysctl -p"
    ))
    
    # AC-008: IPv6 forwarding disabled (AC-4)
    exists, ipv6_forward = check_kernel_parameter("net.ipv6.conf.all.forwarding")
    ipv6_forward_disabled = ipv6_forward == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AC (Access Control)",
        status="Pass" if ipv6_forward_disabled else "Warning",
        message=f"{get_nist_id('AC', 8)}: IPv6 forwarding disabled (AC-4)",
        details=f"net.ipv6.conf.all.forwarding = {ipv6_forward}",
        remediation="Disable: echo 'net.ipv6.conf.all.forwarding = 0' >> /etc/sysctl.conf"
    ))
    
    # AC-009: sudo installed and configured (AC-5 Separation of Duties)
    sudo_installed = check_package_installed("sudo", os_info)
    sudoers_exists = os.path.exists("/etc/sudoers")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AC (Access Control)",
        status="Pass" if sudo_installed and sudoers_exists else "Fail",
        message=f"{get_nist_id('AC', 9)}: sudo package installed and configured (AC-5)",
        details="sudo properly configured" if sudo_installed and sudoers_exists else "Missing",
        remediation=remediation_for("sudo")
    ))
    
    # AC-010: sudoers file permissions (AC-5, AC-6)
    if sudoers_exists:
        sudoers_perms = get_file_permissions("/etc/sudoers")
        sudoers_secure = sudoers_perms == "440" or sudoers_perms == "400"
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - AC (Access Control)",
            status="Pass" if sudoers_secure else "Fail",
            message=f"{get_nist_id('AC', 10)}: sudoers file has secure permissions (AC-6)",
            details=f"Permissions: {sudoers_perms}",
            remediation="chmod 440 /etc/sudoers"
        ))
    
    # AC-011: sudo requires password (AC-6)
    if sudoers_exists:
        sudoers_content = read_file_safe("/etc/sudoers")
        has_nopasswd = "NOPASSWD" in sudoers_content
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - AC (Access Control)",
            status="Warning" if has_nopasswd else "Pass",
            message=f"{get_nist_id('AC', 11)}: sudo requires password authentication (AC-6)",
            details="NOPASSWD entries found" if has_nopasswd else "Password required",
            remediation="Remove NOPASSWD entries from /etc/sudoers"
        ))
    
    # AC-012: sudo timestamp timeout (AC-6)
        timestamp_match = re.search(r'Defaults\s+timestamp_timeout\s*=\s*(\d+)', sudoers_content)
        if timestamp_match:
            timeout = int(timestamp_match.group(1))
            timeout_ok = timeout <= 5
        else:
            timeout = 15  # Default
            timeout_ok = False
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - AC (Access Control)",
            status="Pass" if timeout_ok else "Warning",
            message=f"{get_nist_id('AC', 12)}: sudo timestamp timeout configured (AC-6)",
            details=f"Timeout: {timeout} minutes",
            remediation="Add 'Defaults timestamp_timeout=5' to /etc/sudoers"
        ))
    
    # AC-013: Account lockout configured (AC-7 Unsuccessful Logon Attempts)
    faillock_conf = os.path.exists("/etc/security/faillock.conf")
    faillock_pam = check_pam_module("pam_faillock")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AC (Access Control)",
        status="Pass" if faillock_conf or faillock_pam else "Fail",
        message=f"{get_nist_id('AC', 13)}: Account lockout policy configured (AC-7)",
        details="faillock configured" if faillock_conf or faillock_pam else "Not configured",
        remediation="Configure pam_faillock module in PAM"
    ))
    
    # AC-014: faillock deny threshold (AC-7)
    if faillock_conf:
        faillock_content = read_file_safe("/etc/security/faillock.conf")
        deny_match = re.search(r'^deny\s*=\s*(\d+)', faillock_content, re.MULTILINE)
        if deny_match:
            deny_value = int(deny_match.group(1))
            deny_ok = 1 <= deny_value <= 5
        else:
            deny_value = None
            deny_ok = False
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - AC (Access Control)",
            status="Pass" if deny_ok else "Warning",
            message=f"{get_nist_id('AC', 14)}: Account lockout threshold appropriate (AC-7)",
            details=f"Deny threshold: {deny_value}" if deny_value else "Not set",
            remediation="Set deny=5 in /etc/security/faillock.conf"
        ))
    
    # AC-015: faillock unlock time (AC-7)
        unlock_match = re.search(r'^unlock_time\s*=\s*(\d+)', faillock_content, re.MULTILINE)
        if unlock_match:
            unlock_value = int(unlock_match.group(1))
            unlock_ok = unlock_value >= 900  # 15 minutes
        else:
            unlock_value = None
            unlock_ok = False
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - AC (Access Control)",
            status="Pass" if unlock_ok else "Warning",
            message=f"{get_nist_id('AC', 15)}: Account lockout duration appropriate (AC-7)",
            details=f"Unlock time: {unlock_value} seconds" if unlock_value else "Not set",
            remediation="Set unlock_time=900 in /etc/security/faillock.conf"
        ))
    
    # AC-016: System use notification - /etc/issue (AC-8)
    issue_exists = os.path.exists("/etc/issue") and os.path.getsize("/etc/issue") > 10
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AC (Access Control)",
        status="Pass" if issue_exists else "Warning",
        message=f"{get_nist_id('AC', 16)}: System use notification banner - console (AC-8)",
        details="Banner configured in /etc/issue" if issue_exists else "No banner",
        remediation="Create warning banner in /etc/issue"
    ))
    
    # AC-017: System use notification - /etc/issue.net (AC-8)
    issue_net_exists = os.path.exists("/etc/issue.net") and os.path.getsize("/etc/issue.net") > 10
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AC (Access Control)",
        status="Pass" if issue_net_exists else "Warning",
        message=f"{get_nist_id('AC', 17)}: System use notification banner - network (AC-8)",
        details="Banner configured in /etc/issue.net" if issue_net_exists else "No banner",
        remediation="Create warning banner in /etc/issue.net"
    ))
    
    # AC-018: MOTD configured (AC-8)
    motd_exists = os.path.exists("/etc/motd") and os.path.getsize("/etc/motd") > 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AC (Access Control)",
        status="Info",
        message=f"{get_nist_id('AC', 18)}: Message of the day configured (AC-8)",
        details="MOTD configured" if motd_exists else "No MOTD",
        remediation="Configure /etc/motd with appropriate message"
    ))
    
    # AC-019: Previous logon notification (AC-9)
    last_available = command_exists("last")
    lastlog_available = command_exists("lastlog")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AC (Access Control)",
        status="Pass" if last_available and lastlog_available else "Warning",
        message=f"{get_nist_id('AC', 19)}: Previous logon notification tools available (AC-9)",
        details="last and lastlog available" if last_available and lastlog_available else "Tools missing",
        remediation="Ensure last and lastlog utilities are available"
    ))
    
    # AC-020: Concurrent session control (AC-10)
    limits_conf_exists = os.path.exists("/etc/security/limits.conf")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AC (Access Control)",
        status="Pass" if limits_conf_exists else "Fail",
        message=f"{get_nist_id('AC', 20)}: Concurrent session control configured (AC-10)",
        details="limits.conf exists" if limits_conf_exists else "Not configured",
        remediation="Configure session limits in /etc/security/limits.conf"
    ))
    
    # AC-021: maxlogins setting (AC-10)
    if limits_conf_exists:
        limits_content = read_file_safe("/etc/security/limits.conf")
        maxlogins_set = "maxlogins" in limits_content
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - AC (Access Control)",
            status="Pass" if maxlogins_set else "Warning",
            message=f"{get_nist_id('AC', 21)}: Maximum concurrent logins configured (AC-10)",
            details="maxlogins configured" if maxlogins_set else "Not set",
            remediation="Add '* hard maxlogins 10' to /etc/security/limits.conf"
        ))
    
    # AC-022: Screen lock capability (AC-11)
    screen_lock_packages = ["vlock", "gnome-screensaver", "xscreensaver", "light-locker"]
    installed_locks = [pkg for pkg in screen_lock_packages if check_package_installed(pkg, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AC (Access Control)",
        status="Pass" if installed_locks else "Warning",
        message=f"{get_nist_id('AC', 22)}: Screen lock software installed (AC-11)",
        details=f"Installed: {', '.join(installed_locks)}" if installed_locks else "No screen lock",
        remediation="Install vlock or xscreensaver"
    ))
    
    # AC-023: Session termination - TMOUT (AC-12)
    profile_files = ["/etc/profile", "/etc/bash.bashrc", "/etc/bashrc"]
    tmout_configured = False
    tmout_value = None
    
    for profile_file in profile_files:
        if os.path.exists(profile_file):
            content = read_file_safe(profile_file)
            tmout_match = re.search(r'TMOUT\s*=\s*(\d+)', content)
            if tmout_match:
                tmout_configured = True
                tmout_value = int(tmout_match.group(1))
                break
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AC (Access Control)",
        status="Pass" if tmout_configured else "Fail",
        message=f"{get_nist_id('AC', 23)}: Shell session timeout configured (AC-12)",
        details=f"TMOUT={tmout_value}" if tmout_value else "Not configured",
        remediation="Add 'TMOUT=900' and 'readonly TMOUT' to /etc/profile"
    ))
    
    # AC-024: TMOUT value appropriate (AC-12)
    if tmout_configured and tmout_value:
        tmout_ok = tmout_value <= 900  # 15 minutes or less
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - AC (Access Control)",
            status="Pass" if tmout_ok else "Warning",
            message=f"{get_nist_id('AC', 24)}: Session timeout value appropriate (AC-12)",
            details=f"TMOUT={tmout_value} seconds ({tmout_value//60} minutes)",
            remediation="Set TMOUT=900 (15 minutes) or less"
        ))
    
    # AC-025: Supervision - Authentication logs exist (AC-13)
    auth_log_files = ["/var/log/auth.log", "/var/log/secure"]
    auth_logs_exist = any(os.path.exists(f) for f in auth_log_files)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AC (Access Control)",
        status="Pass" if auth_logs_exist else "Fail",
        message=f"{get_nist_id('AC', 25)}: Authentication logging enabled (AC-13)",
        details="Authentication logs exist" if auth_logs_exist else "No logs found",
        remediation="Enable authentication logging in syslog/rsyslog"
    ))
    
    # AC-026: wtmp logging (AC-13)
    wtmp_exists = os.path.exists("/var/log/wtmp")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AC (Access Control)",
        status="Pass" if wtmp_exists else "Fail",
        message=f"{get_nist_id('AC', 26)}: Login/logout logging configured (AC-13)",
        details="wtmp logging active" if wtmp_exists else "wtmp not found",
        remediation="Enable wtmp logging"
    ))
    
    # AC-027: btmp logging (AC-13)
    btmp_exists = os.path.exists("/var/log/btmp")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AC (Access Control)",
        status="Pass" if btmp_exists else "Warning",
        message=f"{get_nist_id('AC', 27)}: Failed login attempt logging (AC-13)",
        details="btmp logging active" if btmp_exists else "btmp not found",
        remediation="Enable btmp logging for failed logins"
    ))
    
    # AC-028: Anonymous FTP disabled (AC-14)
    anonymous_services = []
    for service in ["vsftpd", "proftpd", "pure-ftpd"]:
        if check_service_active(service):
            anonymous_services.append(service)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AC (Access Control)",
        status="Warning" if anonymous_services else "Pass",
        message=f"{get_nist_id('AC', 28)}: No anonymous FTP services (AC-14)",
        details=f"FTP services running: {', '.join(anonymous_services)}" if anonymous_services else "None",
        remediation="Disable or secure FTP services"
    ))
    
    # AC-029: TFTP disabled (AC-14)
    tftp_active = check_service_active("tftp") or check_service_active("tftpd-hpa")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AC (Access Control)",
        status="Fail" if tftp_active else "Pass",
        message=f"{get_nist_id('AC', 29)}: TFTP service disabled (AC-14)",
        details="TFTP service running" if tftp_active else "TFTP not active",
        remediation="systemctl disable tftp.service && systemctl stop tftp.service"
    ))
    
    # AC-030: NFS server secured (AC-14)
    nfs_exports = os.path.exists("/etc/exports") and os.path.getsize("/etc/exports") > 0
    if nfs_exports:
        exports_content = read_file_safe("/etc/exports")
        insecure_exports = "rw" in exports_content and "no_root_squash" in exports_content
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - AC (Access Control)",
            status="Warning" if insecure_exports else "Pass",
            message=f"{get_nist_id('AC', 30)}: NFS exports secured (AC-14)",
            details="Insecure exports detected" if insecure_exports else "NFS exports configured",
            remediation="Review /etc/exports and remove no_root_squash option"
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - AC (Access Control)",
            status="Pass",
            message=f"{get_nist_id('AC', 30)}: NFS not configured (AC-14)",
            details="No NFS exports",
            remediation=""
        ))


# ============================================================================
# AU - Audit and Accountability
# NIST 800-53: AU-1 through AU-16
# CSF: DE.CM (Security Continuous Monitoring)
# ============================================================================

def check_audit_accountability(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Audit and Accountability checks - AU family
    Comprehensive security assessment of auditing and logging variables
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking AU - Audit & Accountability...")
    
    # AU-001: auditd installed (AU-2)
    auditd_installed = check_package_installed("auditd", os_info) or check_package_installed("audit", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AU (Audit & Accountability)",
        status="Pass" if auditd_installed else "Fail",
        message=f"{get_nist_id('AU', 1)}: Linux Audit daemon installed (AU-2)",
        details="auditd package installed" if auditd_installed else "Not installed",
        remediation=remediation_for("auditd")
    ))
    
    # AU-002: auditd service enabled (AU-2)
    auditd_enabled = check_service_enabled("auditd")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AU (Audit & Accountability)",
        status="Pass" if auditd_enabled else "Fail",
        message=f"{get_nist_id('AU', 2)}: auditd service enabled at boot (AU-2)",
        details="Service enabled" if auditd_enabled else "Not enabled",
        remediation=remediation_for("auditd")
    ))
    
    # AU-003: auditd service active (AU-2, AU-12)
    auditd_active = check_service_active("auditd")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AU (Audit & Accountability)",
        status="Pass" if auditd_active else "Fail",
        message=f"{get_nist_id('AU', 3)}: auditd service currently running (AU-12)",
        details="Service active" if auditd_active else "Not running",
        remediation="systemctl start auditd"
    ))
    
    # AU-004: auditd configuration exists (AU-1)
    auditd_conf_exists = os.path.exists("/etc/audit/auditd.conf")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AU (Audit & Accountability)",
        status="Pass" if auditd_conf_exists else "Fail",
        message=f"{get_nist_id('AU', 4)}: auditd configuration file exists (AU-1)",
        details="Configuration present" if auditd_conf_exists else "Missing",
        remediation="Create /etc/audit/auditd.conf"
    ))
    
    # AU-005: audit rules configured (AU-2, AU-3)
    audit_rules_exist = os.path.exists("/etc/audit/rules.d/audit.rules") or os.path.exists("/etc/audit/audit.rules")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AU (Audit & Accountability)",
        status="Pass" if audit_rules_exist else "Fail",
        message=f"{get_nist_id('AU', 5)}: Audit rules configured (AU-2)",
        details="Audit rules present" if audit_rules_exist else "No rules",
        remediation="Configure audit rules in /etc/audit/rules.d/"
    ))
    
    # AU-006: Audit rule count (AU-2, AU-3)
    if audit_rules_exist:
        rules_file = "/etc/audit/audit.rules" if os.path.exists("/etc/audit/audit.rules") else "/etc/audit/rules.d/audit.rules"
        rules_content = read_file_safe(rules_file)
        rule_lines = [l for l in rules_content.split('\n') if l.strip() and not l.startswith('#')]
        rule_count = len(rule_lines)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - AU (Audit & Accountability)",
            status="Pass" if rule_count >= 10 else "Warning",
            message=f"{get_nist_id('AU', 6)}: Sufficient audit rules configured (AU-3)",
            details=f"{rule_count} audit rules configured",
            remediation="Add comprehensive audit rules for system events"
        ))
    
    # AU-007: Audit log size configured (AU-4)
    if auditd_conf_exists:
        auditd_conf = read_file_safe("/etc/audit/auditd.conf")
        max_log_file = re.search(r'^max_log_file\s*=\s*(\d+)', auditd_conf, re.MULTILINE)
        
        if max_log_file:
            max_size = int(max_log_file.group(1))
            size_ok = max_size >= 8  # At least 8MB
        else:
            max_size = None
            size_ok = False
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - AU (Audit & Accountability)",
            status="Pass" if size_ok else "Warning",
            message=f"{get_nist_id('AU', 7)}: Audit log size configured (AU-4)",
            details=f"max_log_file = {max_size} MB" if max_size else "Not configured",
            remediation="Set max_log_file = 32 in /etc/audit/auditd.conf"
        ))
    
    # AU-008: Maximum log files configured (AU-4)
        num_logs = re.search(r'^num_logs\s*=\s*(\d+)', auditd_conf, re.MULTILINE)
        
        if num_logs:
            num_value = int(num_logs.group(1))
            num_ok = num_value >= 5
        else:
            num_value = None
            num_ok = False
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - AU (Audit & Accountability)",
            status="Pass" if num_ok else "Warning",
            message=f"{get_nist_id('AU', 8)}: Audit log rotation configured (AU-4)",
            details=f"num_logs = {num_value}" if num_value else "Not configured",
            remediation="Set num_logs = 10 in /etc/audit/auditd.conf"
        ))
    
    # AU-009: Audit space left action (AU-5)
        space_left_action = re.search(r'^space_left_action\s*=\s*(\w+)', auditd_conf, re.MULTILINE)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - AU (Audit & Accountability)",
            status="Pass" if space_left_action else "Warning",
            message=f"{get_nist_id('AU', 9)}: Space left action configured (AU-5)",
            details=f"space_left_action = {space_left_action.group(1)}" if space_left_action else "Not configured",
            remediation="Set space_left_action = EMAIL in /etc/audit/auditd.conf"
        ))
    
    # AU-010: Admin space left action (AU-5)
        admin_space_left = re.search(r'^admin_space_left_action\s*=\s*(\w+)', auditd_conf, re.MULTILINE)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - AU (Audit & Accountability)",
            status="Pass" if admin_space_left else "Warning",
            message=f"{get_nist_id('AU', 10)}: Admin space left action configured (AU-5)",
            details=f"admin_space_left_action = {admin_space_left.group(1)}" if admin_space_left else "Not configured",
            remediation="Set admin_space_left_action = HALT in /etc/audit/auditd.conf"
        ))
    
    # AU-011: Disk full action (AU-5)
        disk_full_action = re.search(r'^disk_full_action\s*=\s*(\w+)', auditd_conf, re.MULTILINE)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - AU (Audit & Accountability)",
            status="Pass" if disk_full_action else "Warning",
            message=f"{get_nist_id('AU', 11)}: Disk full action configured (AU-5)",
            details=f"disk_full_action = {disk_full_action.group(1)}" if disk_full_action else "Not configured",
            remediation="Set disk_full_action = HALT in /etc/audit/auditd.conf"
        ))
    
    # AU-012: Disk error action (AU-5)
        disk_error_action = re.search(r'^disk_error_action\s*=\s*(\w+)', auditd_conf, re.MULTILINE)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - AU (Audit & Accountability)",
            status="Pass" if disk_error_action else "Warning",
            message=f"{get_nist_id('AU', 12)}: Disk error action configured (AU-5)",
            details=f"disk_error_action = {disk_error_action.group(1)}" if disk_error_action else "Not configured",
            remediation="Set disk_error_action = SYSLOG in /etc/audit/auditd.conf"
        ))
    
    # AU-013: Log analysis tools installed (AU-6)
    log_tools = []
    for tool in ["logwatch", "logcheck", "swatch", "auditreport"]:
        if command_exists(tool) or check_package_installed(tool, os_info):
            log_tools.append(tool)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AU (Audit & Accountability)",
        status="Pass" if log_tools else "Warning",
        message=f"{get_nist_id('AU', 13)}: Log analysis tools installed (AU-6)",
        details=f"Tools: {', '.join(log_tools)}" if log_tools else "No tools",
        remediation="Install logwatch or logcheck"
    ))
    
    # AU-014: aureport utility available (AU-7)
    aureport_available = command_exists("aureport")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AU (Audit & Accountability)",
        status="Pass" if aureport_available else "Warning",
        message=f"{get_nist_id('AU', 14)}: Audit reporting utility available (AU-7)",
        details="aureport available" if aureport_available else "Not available",
        remediation="Install audit utilities"
    ))
    
    # AU-015: ausearch utility available (AU-7)
    ausearch_available = command_exists("ausearch")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AU (Audit & Accountability)",
        status="Pass" if ausearch_available else "Warning",
        message=f"{get_nist_id('AU', 15)}: Audit search utility available (AU-7)",
        details="ausearch available" if ausearch_available else "Not available",
        remediation="Install audit utilities"
    ))
    
    # AU-016: Time synchronization service active (AU-8)
    time_services = ["chrony", "systemd-timesyncd", "ntpd", "ntp"]
    time_sync_active = any(check_service_active(svc) for svc in time_services)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AU (Audit & Accountability)",
        status="Pass" if time_sync_active else "Fail",
        message=f"{get_nist_id('AU', 16)}: Time synchronization service running (AU-8)",
        details="Time sync active" if time_sync_active else "No time sync",
        remediation="Install and enable chrony or ntpd"
    ))
    
    # AU-017: Time synchronization enabled at boot (AU-8)
    time_sync_enabled = any(check_service_enabled(svc) for svc in time_services)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AU (Audit & Accountability)",
        status="Pass" if time_sync_enabled else "Fail",
        message=f"{get_nist_id('AU', 17)}: Time synchronization enabled at boot (AU-8)",
        details="Service enabled" if time_sync_enabled else "Not enabled",
        remediation=remediation_for("chrony")
    ))
    
    # AU-018: NTP/Chrony configured with servers (AU-8)
    ntp_configured = False
    if os.path.exists("/etc/chrony/chrony.conf"):
        chrony_conf = read_file_safe("/etc/chrony/chrony.conf")
        ntp_configured = "server" in chrony_conf or "pool" in chrony_conf
    elif os.path.exists("/etc/ntp.conf"):
        ntp_conf = read_file_safe("/etc/ntp.conf")
        ntp_configured = "server" in ntp_conf
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AU (Audit & Accountability)",
        status="Pass" if ntp_configured else "Warning",
        message=f"{get_nist_id('AU', 18)}: NTP servers configured (AU-8)",
        details="NTP servers configured" if ntp_configured else "No servers",
        remediation="Configure NTP servers in /etc/chrony/chrony.conf"
    ))
    
    # AU-019: Audit log directory permissions (AU-9)
    if os.path.exists("/var/log/audit"):
        audit_dir_perms = get_file_permissions("/var/log/audit")
        audit_dir_secure = audit_dir_perms and int(audit_dir_perms, 8) <= int("750", 8)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - AU (Audit & Accountability)",
            status="Pass" if audit_dir_secure else "Fail",
            message=f"{get_nist_id('AU', 19)}: Audit log directory permissions (AU-9)",
            details=f"Permissions: {audit_dir_perms}",
            remediation="chmod 700 /var/log/audit"
        ))
    
    # AU-020: Audit log file permissions (AU-9)
        audit_logs = glob.glob("/var/log/audit/audit.log*")
        insecure_logs = []
        for log_file in audit_logs:
            perms = get_file_permissions(log_file)
            if perms and int(perms, 8) > int("600", 8):
                insecure_logs.append(log_file)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - AU (Audit & Accountability)",
            status="Pass" if not insecure_logs else "Fail",
            message=f"{get_nist_id('AU', 20)}: Audit log file permissions (AU-9)",
            details=f"Insecure: {insecure_logs}" if insecure_logs else "All secure",
            remediation="chmod 600 /var/log/audit/audit.log*"
        ))
    
    # AU-021: Audit log ownership (AU-9)
        audit_logs_owner_ok = True
        for log_file in audit_logs[:5]:  # Check first 5
            owner, group = get_file_owner_group(log_file)
            if owner != "root" or group != "root":
                audit_logs_owner_ok = False
                break
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - AU (Audit & Accountability)",
            status="Pass" if audit_logs_owner_ok else "Fail",
            message=f"{get_nist_id('AU', 21)}: Audit log ownership (AU-9)",
            details="Logs owned by root" if audit_logs_owner_ok else "Incorrect ownership",
            remediation="chown root:root /var/log/audit/audit.log*"
        ))
    
    # AU-022: logrotate installed (AU-11)
    logrotate_installed = check_package_installed("logrotate", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AU (Audit & Accountability)",
        status="Pass" if logrotate_installed else "Fail",
        message=f"{get_nist_id('AU', 22)}: Log rotation utility installed (AU-11)",
        details="logrotate installed" if logrotate_installed else "Not installed",
        remediation=remediation_for("logrotate")
    ))
    
    # AU-023: Audit log rotation configured (AU-11)
    audit_logrotate_conf = os.path.exists("/etc/logrotate.d/audit")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AU (Audit & Accountability)",
        status="Pass" if audit_logrotate_conf else "Warning",
        message=f"{get_nist_id('AU', 23)}: Audit log rotation configured (AU-11)",
        details="Rotation configured" if audit_logrotate_conf else "Not configured",
        remediation="Configure /etc/logrotate.d/audit"
    ))
    
    # AU-024: rsyslog service active (AU-12, AU-15)
    rsyslog_active = check_service_active("rsyslog")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AU (Audit & Accountability)",
        status="Pass" if rsyslog_active else "Fail",
        message=f"{get_nist_id('AU', 24)}: System logging service active (AU-12)",
        details="rsyslog running" if rsyslog_active else "Not running",
        remediation="systemctl start rsyslog"
    ))
    
    # AU-025: Remote syslog configured (AU-16)
    remote_logging = False
    if os.path.exists("/etc/rsyslog.conf"):
        rsyslog_conf = read_file_safe("/etc/rsyslog.conf")
        # Check for remote logging configuration
        remote_logging = bool(re.search(r'@@?\w+', rsyslog_conf))
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - AU (Audit & Accountability)",
        status="Pass" if remote_logging else "Warning",
        message=f"{get_nist_id('AU', 25)}: Remote log forwarding configured (AU-16)",
        details="Remote logging configured" if remote_logging else "Local only",
        remediation="Configure remote syslog server in /etc/rsyslog.conf"
    ))


# ============================================================================
# CM - Configuration Management
# NIST 800-53: CM-1 through CM-14
# CSF: PR.IP (Information Protection Processes)
# ============================================================================

def check_configuration_management(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Configuration Management checks - CM family  
    Audit of configuration management variables
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking CM - Configuration Management...")
    
    # CM-001: Baseline configuration files exist (CM-2)
    baseline_files = [
        "/etc/fstab",
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/sysctl.conf",
        "/etc/network/interfaces"
    ]
    existing_baseline = [f for f in baseline_files if os.path.exists(f)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CM (Configuration Mgmt)",
        status="Pass" if len(existing_baseline) >= 3 else "Warning",
        message=f"{get_nist_id('CM', 1)}: Core configuration files present (CM-2)",
        details=f"{len(existing_baseline)}/{len(baseline_files)} baseline files exist",
        remediation="Ensure all baseline configuration files are present"
    ))
    
    # CM-002: /etc directory permissions (CM-5)
    etc_perms = get_file_permissions("/etc")
    etc_secure = etc_perms and int(etc_perms, 8) <= int("755", 8)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CM (Configuration Mgmt)",
        status="Pass" if etc_secure else "Fail",
        message=f"{get_nist_id('CM', 2)}: /etc directory permissions (CM-5)",
        details=f"Permissions: {etc_perms}",
        remediation="chmod 755 /etc"
    ))
    
    # CM-003: Version control tools available (CM-3)
    version_control_tools = ["git", "etckeeper", "svn"]
    installed_vc = [tool for tool in version_control_tools if command_exists(tool)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CM (Configuration Mgmt)",
        status="Pass" if installed_vc else "Warning",
        message=f"{get_nist_id('CM', 3)}: Version control tools available (CM-3)",
        details=f"Installed: {', '.join(installed_vc)}" if installed_vc else "No VC tools",
        remediation="Install etckeeper for /etc versioning"
    ))
    
    # CM-004: etckeeper initialized (CM-3)
    etckeeper_init = os.path.exists("/etc/.git") or os.path.exists("/etc/.etckeeper")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CM (Configuration Mgmt)",
        status="Pass" if etckeeper_init else "Warning",
        message=f"{get_nist_id('CM', 4)}: /etc under version control (CM-3)",
        details="/etc tracked" if etckeeper_init else "Not tracked",
        remediation="Initialize etckeeper: etckeeper init"
    ))
    
    # CM-005: sysctl configuration exists (CM-6)
    sysctl_conf = os.path.exists("/etc/sysctl.conf")
    sysctl_content_size = os.path.getsize("/etc/sysctl.conf") if sysctl_conf else 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CM (Configuration Mgmt)",
        status="Pass" if sysctl_content_size > 100 else "Warning",
        message=f"{get_nist_id('CM', 5)}: Kernel parameters configured (CM-6)",
        details=f"sysctl.conf size: {sysctl_content_size} bytes",
        remediation="Configure kernel hardening in /etc/sysctl.conf"
    ))
    
    # CM-006: sysctl.d directory exists (CM-6)
    sysctl_d_exists = os.path.exists("/etc/sysctl.d")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CM (Configuration Mgmt)",
        status="Pass" if sysctl_d_exists else "Info",
        message=f"{get_nist_id('CM', 6)}: sysctl.d configuration directory (CM-6)",
        details="Directory exists" if sysctl_d_exists else "Not present",
        remediation="Create /etc/sysctl.d for modular configuration"
    ))
    
    # CM-007: Unnecessary services disabled (CM-7)
    unnecessary_services = [
        "avahi-daemon",
        "cups",
        "bluetooth",
        "isc-dhcp-server",
        "telnet",
        "rsh",
        "rlogin"
    ]
    running_unnecessary = [svc for svc in unnecessary_services if check_service_active(svc)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CM (Configuration Mgmt)",
        status="Warning" if running_unnecessary else "Pass",
        message=f"{get_nist_id('CM', 7)}: Unnecessary services disabled (CM-7)",
        details=f"Running: {', '.join(running_unnecessary)}" if running_unnecessary else "Minimal services",
        remediation=f"Disable: systemctl disable {running_unnecessary[0]}" if running_unnecessary else ""
    ))
    
    # CM-008: Package count (CM-8)
    package_count = run_command("dpkg -l 2>/dev/null | grep '^ii' | wc -l || rpm -qa 2>/dev/null | wc -l").stdout.strip()
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CM (Configuration Mgmt)",
        status="Info",
        message=f"{get_nist_id('CM', 8)}: Installed package inventory (CM-8)",
        details=f"{package_count} packages installed",
        remediation="Maintain software inventory in CMDB"
    ))
    
    # CM-009: Recently installed packages (CM-8)
    recent_packages = run_command("grep 'install ' /var/log/dpkg.log 2>/dev/null | tail -5 || grep 'Installed:' /var/log/yum.log 2>/dev/null | tail -5").stdout.strip()
    has_recent = bool(recent_packages)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CM (Configuration Mgmt)",
        status="Info",
        message=f"{get_nist_id('CM', 9)}: Recent package changes tracked (CM-8)",
        details="Recent installs logged" if has_recent else "No recent changes",
        remediation="Review package installation logs"
    ))
    
    # CM-010: Software license tracking (CM-10)
    license_files = glob.glob("/usr/share/doc/*/copyright")
    license_count = len(license_files)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CM (Configuration Mgmt)",
        status="Pass" if license_count > 10 else "Info",
        message=f"{get_nist_id('CM', 10)}: Software license documentation (CM-10)",
        details=f"{license_count} license files found",
        remediation="Review software licensing compliance"
    ))
    
    # CM-011: Repository GPG keys configured (CM-14)
    gpg_keys_configured = False
    if command_exists("apt-key"):
        keys_result = run_command("apt-key list 2>/dev/null | grep -c 'pub'")
        keys_output = keys_result.stdout.strip()
        if keys_output and keys_output.isdigit():
            gpg_keys_configured = int(keys_output) > 0
    elif os.path.exists("/etc/pki/rpm-gpg"):
        gpg_files = glob.glob("/etc/pki/rpm-gpg/RPM-GPG-KEY-*")
        gpg_keys_configured = len(gpg_files) > 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CM (Configuration Mgmt)",
        status="Pass" if gpg_keys_configured else "Warning",
        message=f"{get_nist_id('CM', 11)}: Package repository GPG keys (CM-14)",
        details="GPG keys configured" if gpg_keys_configured else "No keys",
        remediation="Import GPG keys for all package repositories"
    ))
    
    # CM-012: GPG utility installed (CM-14)
    gpg_installed = command_exists("gpg") or command_exists("gpg2")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CM (Configuration Mgmt)",
        status="Pass" if gpg_installed else "Warning",
        message=f"{get_nist_id('CM', 12)}: GPG utility installed (CM-14)",
        details="GPG available" if gpg_installed else "Not installed",
        remediation=remediation_for("gnupg")
    ))
    
    # CM-013: System file integrity monitoring (CM-3, SI-7)
    aide_installed = check_package_installed("aide", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CM (Configuration Mgmt)",
        status="Pass" if aide_installed else "Fail",
        message=f"{get_nist_id('CM', 13)}: File integrity monitoring installed (CM-3)",
        details="AIDE installed" if aide_installed else "Not installed",
        remediation=remediation_for("aide")
    ))
    
    # CM-014: AIDE database initialized (CM-3)
    if aide_installed:
        aide_db_locations = [
            "/var/lib/aide/aide.db",
            "/var/lib/aide/aide.db.gz",
            "/var/lib/aide.db"
        ]
        aide_db_exists = any(os.path.exists(db) for db in aide_db_locations)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - CM (Configuration Mgmt)",
            status="Pass" if aide_db_exists else "Warning",
            message=f"{get_nist_id('CM', 14)}: AIDE database initialized (CM-3)",
            details="Database exists" if aide_db_exists else "Not initialized",
            remediation=remediation_for("aide")
        ))
    
    # CM-015: AIDE scheduled checks (CM-3)
        aide_cron = run_command("crontab -l 2>/dev/null | grep -c aide || grep -r aide /etc/cron* 2>/dev/null | wc -l").stdout.strip()
        aide_scheduled = safe_int_parse(aide_cron) > 0
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - CM (Configuration Mgmt)",
            status="Pass" if aide_scheduled else "Warning",
            message=f"{get_nist_id('CM', 15)}: AIDE checks scheduled (CM-3)",
            details="AIDE in cron" if aide_scheduled else "Not scheduled",
            remediation="Add AIDE check to cron"
        ))
    
    # CM-016: Mount options - nodev on /tmp (CM-6)
    mount_output = run_command("mount | grep ' /tmp '").stdout.strip()
    tmp_nodev = "nodev" in mount_output if mount_output else False
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CM (Configuration Mgmt)",
        status="Pass" if tmp_nodev else "Warning",
        message=f"{get_nist_id('CM', 16)}: /tmp mounted with nodev (CM-6)",
        details="nodev option set" if tmp_nodev else "Not configured",
        remediation="Add nodev to /tmp in /etc/fstab"
    ))
    
    # CM-017: Mount options - nosuid on /tmp (CM-6)
    tmp_nosuid = "nosuid" in mount_output if mount_output else False
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CM (Configuration Mgmt)",
        status="Pass" if tmp_nosuid else "Warning",
        message=f"{get_nist_id('CM', 17)}: /tmp mounted with nosuid (CM-6)",
        details="nosuid option set" if tmp_nosuid else "Not configured",
        remediation="Add nosuid to /tmp in /etc/fstab"
    ))
    
    # CM-018: Mount options - noexec on /tmp (CM-6)
    tmp_noexec = "noexec" in mount_output if mount_output else False
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CM (Configuration Mgmt)",
        status="Pass" if tmp_noexec else "Warning",
        message=f"{get_nist_id('CM', 18)}: /tmp mounted with noexec (CM-6)",
        details="noexec option set" if tmp_noexec else "Not configured",
        remediation="Add noexec to /tmp in /etc/fstab"
    ))
    
    # CM-019: Separate /var partition (CM-6)
    var_mount = run_command("mount | grep ' /var '").stdout.strip()
    var_separate = bool(var_mount)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CM (Configuration Mgmt)",
        status="Pass" if var_separate else "Warning",
        message=f"{get_nist_id('CM', 19)}: /var on separate partition (CM-6)",
        details="/var separate" if var_separate else "/var not separate",
        remediation="Consider separate partition for /var"
    ))
    
    # CM-020: Separate /var/log partition (CM-6)
    var_log_mount = run_command("mount | grep ' /var/log '").stdout.strip()
    var_log_separate = bool(var_log_mount)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CM (Configuration Mgmt)",
        status="Pass" if var_log_separate else "Info",
        message=f"{get_nist_id('CM', 20)}: /var/log on separate partition (CM-6)",
        details="/var/log separate" if var_log_separate else "Not separate",
        remediation="Consider separate partition for /var/log"
    ))
    
    # CM-021: Separate /home partition (CM-6)
    home_mount = run_command("mount | grep ' /home '").stdout.strip()
    home_separate = bool(home_mount)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CM (Configuration Mgmt)",
        status="Pass" if home_separate else "Warning",
        message=f"{get_nist_id('CM', 21)}: /home on separate partition (CM-6)",
        details="/home separate" if home_separate else "Not separate",
        remediation="Consider separate partition for /home"
    ))
    
    # CM-022: /etc/fstab permissions (CM-5)
    fstab_perms = get_file_permissions("/etc/fstab")
    fstab_secure = fstab_perms and int(fstab_perms, 8) <= int("644", 8)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CM (Configuration Mgmt)",
        status="Pass" if fstab_secure else "Fail",
        message=f"{get_nist_id('CM', 22)}: /etc/fstab permissions (CM-5)",
        details=f"Permissions: {fstab_perms}",
        remediation="chmod 644 /etc/fstab"
    ))
    
    # CM-023: Kernel modules blacklisted (CM-7)
    blacklist_files = glob.glob("/etc/modprobe.d/*.conf")
    has_blacklist = any(os.path.getsize(f) > 0 for f in blacklist_files) if blacklist_files else False
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CM (Configuration Mgmt)",
        status="Pass" if has_blacklist else "Info",
        message=f"{get_nist_id('CM', 23)}: Kernel module blacklisting configured (CM-7)",
        details=f"{len(blacklist_files)} blacklist files" if has_blacklist else "No blacklists",
        remediation="Blacklist unnecessary kernel modules"
    ))
    
    # CM-024: USB storage disabled (CM-7)
    usb_storage_blocked = False
    for blacklist_file in blacklist_files:
        content = read_file_safe(blacklist_file)
        if "usb-storage" in content:
            usb_storage_blocked = True
            break
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CM (Configuration Mgmt)",
        status="Pass" if usb_storage_blocked else "Warning",
        message=f"{get_nist_id('CM', 24)}: USB storage disabled (CM-7)",
        details="USB storage blacklisted" if usb_storage_blocked else "Not disabled",
        remediation="Blacklist usb-storage in /etc/modprobe.d/"
    ))
    
    # CM-025: Kernel module loading logged (CM-3)
    auditd_conf_exists = os.path.exists("/etc/audit/audit.rules") or os.path.exists("/etc/audit/rules.d/audit.rules")
    if auditd_conf_exists:
        rules_file = "/etc/audit/audit.rules" if os.path.exists("/etc/audit/audit.rules") else "/etc/audit/rules.d/audit.rules"
        audit_rules = read_file_safe(rules_file)
        module_loading_logged = "init_module" in audit_rules or "delete_module" in audit_rules
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - CM (Configuration Mgmt)",
            status="Pass" if module_loading_logged else "Warning",
            message=f"{get_nist_id('CM', 25)}: Kernel module loading audited (CM-3)",
            details="Module loading in audit rules" if module_loading_logged else "Not audited",
            remediation="Add init_module and delete_module to audit rules"
        ))


# ============================================================================
# IA - Identification and Authentication
# NIST 800-53: IA-1 through IA-12
# CSF: PR.AC-7 (Identity Management)
# ============================================================================

def check_identification_authentication(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Identification and Authentication checks - IA family
    IAM relevant security auditing
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking IA - Identification & Authentication Management...")
    
    # IA-001: Password maximum days (IA-5)
    login_defs = read_file_safe("/etc/login.defs")
    pass_max_days = re.search(r'^PASS_MAX_DAYS\s+(\d+)', login_defs, re.MULTILINE)
    
    if pass_max_days:
        max_days_value = int(pass_max_days.group(1))
        max_days_ok = max_days_value <= 90
    else:
        max_days_value = None
        max_days_ok = False
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IA (Identification & Auth)",
        status="Pass" if max_days_ok else "Fail",
        message=f"{get_nist_id('IA', 1)}: Password maximum age configured (IA-5)",
        details=f"PASS_MAX_DAYS = {max_days_value}" if max_days_value else "Not set",
        remediation="Set PASS_MAX_DAYS 90 in /etc/login.defs"
    ))
    
    # IA-002: Password minimum days (IA-5)
    pass_min_days = re.search(r'^PASS_MIN_DAYS\s+(\d+)', login_defs, re.MULTILINE)
    
    if pass_min_days:
        min_days_value = int(pass_min_days.group(1))
        min_days_ok = min_days_value >= 1
    else:
        min_days_value = None
        min_days_ok = False
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IA (Identification & Auth)",
        status="Pass" if min_days_ok else "Fail",
        message=f"{get_nist_id('IA', 2)}: Password minimum age configured (IA-5)",
        details=f"PASS_MIN_DAYS = {min_days_value}" if min_days_value else "Not set",
        remediation="Set PASS_MIN_DAYS 1 in /etc/login.defs"
    ))
    
    # IA-003: Password warning days (IA-5)
    pass_warn_age = re.search(r'^PASS_WARN_AGE\s+(\d+)', login_defs, re.MULTILINE)
    
    if pass_warn_age:
        warn_days_value = int(pass_warn_age.group(1))
        warn_days_ok = warn_days_value >= 7
    else:
        warn_days_value = None
        warn_days_ok = False
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IA (Identification & Auth)",
        status="Pass" if warn_days_ok else "Warning",
        message=f"{get_nist_id('IA', 3)}: Password expiration warning configured (IA-5)",
        details=f"PASS_WARN_AGE = {warn_days_value}" if warn_days_value else "Not set",
        remediation="Set PASS_WARN_AGE 7 in /etc/login.defs"
    ))
    
    # IA-004: Password minimum length (IA-5)
    pass_min_len = re.search(r'^PASS_MIN_LEN\s+(\d+)', login_defs, re.MULTILINE)
    
    if pass_min_len:
        min_len_value = int(pass_min_len.group(1))
        min_len_ok = min_len_value >= 14
    else:
        min_len_value = None
        min_len_ok = False
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IA (Identification & Auth)",
        status="Pass" if min_len_ok else "Fail",
        message=f"{get_nist_id('IA', 4)}: Password minimum length configured (IA-5)",
        details=f"PASS_MIN_LEN = {min_len_value}" if min_len_value else "Not set",
        remediation="Set PASS_MIN_LEN 14 in /etc/login.defs"
    ))
    
    # IA-005: Password complexity - pwquality configuration (IA-5)
    pwquality_conf = os.path.exists("/etc/security/pwquality.conf")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IA (Identification & Auth)",
        status="Pass" if pwquality_conf else "Fail",
        message=f"{get_nist_id('IA', 5)}: Password quality configuration exists (IA-5)",
        details="pwquality.conf present" if pwquality_conf else "Not configured",
        remediation="Create /etc/security/pwquality.conf"
    ))
    
    # IA-006: Password complexity - minimum complexity (IA-5)
    if pwquality_conf:
        pwquality_content = read_file_safe("/etc/security/pwquality.conf")
        minclass = re.search(r'^minclass\s*=\s*(\d+)', pwquality_content, re.MULTILINE)
        
        if minclass:
            minclass_value = int(minclass.group(1))
            minclass_ok = minclass_value >= 3
        else:
            minclass_value = None
            minclass_ok = False
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - IA (Identification & Auth)",
            status="Pass" if minclass_ok else "Warning",
            message=f"{get_nist_id('IA', 6)}: Password character class requirement (IA-5)",
            details=f"minclass = {minclass_value}" if minclass_value else "Not set",
            remediation="Set minclass = 3 in pwquality.conf"
        ))
    
    # IA-007: Password complexity - maximum repeating (IA-5)
        maxrepeat = re.search(r'^maxrepeat\s*=\s*(\d+)', pwquality_content, re.MULTILINE)
        
        if maxrepeat:
            maxrepeat_value = int(maxrepeat.group(1))
            maxrepeat_ok = maxrepeat_value <= 3
        else:
            maxrepeat_value = None
            maxrepeat_ok = False
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - IA (Identification & Auth)",
            status="Pass" if maxrepeat_ok else "Warning",
            message=f"{get_nist_id('IA', 7)}: Password repeating character limit (IA-5)",
            details=f"maxrepeat = {maxrepeat_value}" if maxrepeat_value else "Not set",
            remediation="Set maxrepeat = 3 in pwquality.conf"
        ))
    
    # IA-008: Password history enforcement (IA-5)
    pam_unix_configured = False
    remember_value = None
    
    for pam_file in glob.glob("/etc/pam.d/*"):
        content = read_file_safe(pam_file)
        remember_match = re.search(r'pam_unix\.so.*remember=(\d+)', content)
        if remember_match:
            pam_unix_configured = True
            remember_value = int(remember_match.group(1))
            break
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IA (Identification & Auth)",
        status="Pass" if remember_value and remember_value >= 5 else "Warning",
        message=f"{get_nist_id('IA', 8)}: Password history enforcement (IA-5)",
        details=f"remember={remember_value}" if remember_value else "Not configured",
        remediation="Add remember=5 to pam_unix.so in PAM configuration"
    ))
    
    # IA-009: Inactive account lock (IA-5)
    inactive_days = re.search(r'^INACTIVE\s*=\s*(\d+)', login_defs, re.MULTILINE)
    
    if inactive_days:
        inactive_value = int(inactive_days.group(1))
        inactive_ok = inactive_value <= 30 and inactive_value > 0
    else:
        inactive_value = None
        inactive_ok = False
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IA (Identification & Auth)",
        status="Pass" if inactive_ok else "Warning",
        message=f"{get_nist_id('IA', 9)}: Inactive account lock period (IA-5)",
        details=f"INACTIVE = {inactive_value}" if inactive_value else "Not set",
        remediation="Set INACTIVE 30 in /etc/login.defs"
    ))
    
    # IA-010: Default umask (IA-5, AC-6)
    umask_value = re.search(r'^UMASK\s+(\d+)', login_defs, re.MULTILINE)
    
    if umask_value:
        umask_setting = umask_value.group(1)
        umask_ok = umask_setting in ["027", "077"]
    else:
        umask_setting = None
        umask_ok = False
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IA (Identification & Auth)",
        status="Pass" if umask_ok else "Fail",
        message=f"{get_nist_id('IA', 10)}: Default umask configured securely (AC-6)",
        details=f"UMASK = {umask_setting}" if umask_setting else "Not set",
        remediation="Set UMASK 027 in /etc/login.defs"
    ))
    
    # IA-011: User password aging settings (IA-5)
    users_with_login = get_user_accounts()
    users_no_max_age = []
    
    shadow_content = read_file_safe("/etc/shadow")
    for line in shadow_content.split('\n'):
        if line and not line.startswith('#'):
            fields = line.split(':')
            if len(fields) >= 5 and fields[0] in users_with_login:
                max_age = fields[4]
                if not max_age or max_age == "" or int(max_age) > 90:
                    users_no_max_age.append(fields[0])
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IA (Identification & Auth)",
        status="Pass" if not users_no_max_age else "Warning",
        message=f"{get_nist_id('IA', 11)}: All users have password aging (IA-5)",
        details=f"Users without max age: {', '.join(users_no_max_age[:5])}" if users_no_max_age else "All configured",
        remediation="Set password aging: chage --maxdays 90 <username>"
    ))
    
    # IA-012: Root account password set (IA-5)
    shadow_root = ""
    for line in shadow_content.split('\n'):
        if line.startswith("root:"):
            shadow_root = line
            break
    
    root_password_set = shadow_root and not shadow_root.startswith("root:!") and not shadow_root.startswith("root:*")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IA (Identification & Auth)",
        status="Pass" if root_password_set else "Warning",
        message=f"{get_nist_id('IA', 12)}: Root account has password set (IA-5)",
        details="Root password configured" if root_password_set else "Root locked/no password",
        remediation="Set root password if direct root login required"
    ))
    
    # IA-013: System accounts locked (IA-2, IA-5)
    system_users = get_system_users()
    unlocked_system_accounts = []
    
    for line in shadow_content.split('\n'):
        if line and not line.startswith('#'):
            fields = line.split(':')
            if len(fields) >= 2 and fields[0] in system_users:
                password_field = fields[1]
                if password_field and password_field not in ["!", "*", "!!", "!!*"]:
                    unlocked_system_accounts.append(fields[0])
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IA (Identification & Auth)",
        status="Pass" if not unlocked_system_accounts else "Warning",
        message=f"{get_nist_id('IA', 13)}: System accounts properly locked (IA-2)",
        details=f"Unlocked: {', '.join(unlocked_system_accounts[:5])}" if unlocked_system_accounts else "All locked",
        remediation="Lock system accounts: passwd -l <account>"
    ))
    
    # IA-014: System accounts have nologin shell (IA-2)
    system_accounts_with_shell = []
    passwd_content = read_file_safe("/etc/passwd")
    
    for line in passwd_content.split('\n'):
        if line and not line.startswith('#'):
            fields = line.split(':')
            if len(fields) >= 7:
                username = fields[0]
                shell = fields[6]
                if username in system_users:
                    if shell and not shell.endswith('nologin') and not shell.endswith('/bin/false'):
                        system_accounts_with_shell.append(username)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IA (Identification & Auth)",
        status="Pass" if not system_accounts_with_shell else "Warning",
        message=f"{get_nist_id('IA', 14)}: System accounts use nologin shell (IA-2)",
        details=f"With shell: {', '.join(system_accounts_with_shell[:5])}" if system_accounts_with_shell else "All nologin",
        remediation="Set nologin: usermod -s /usr/sbin/nologin <account>"
    ))
    
    # IA-015: SSH protocol version (IA-3)
    if os.path.exists("/etc/ssh/sshd_config"):
        sshd_config = read_file_safe("/etc/ssh/sshd_config")
        protocol_match = re.search(r'^Protocol\s+(\d+)', sshd_config, re.MULTILINE)
        
        if protocol_match:
            protocol_value = protocol_match.group(1)
            protocol_ok = protocol_value == "2"
        else:
            protocol_ok = True  # Default is 2
            protocol_value = "2 (default)"
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - IA (Identification & Auth)",
            status="Pass" if protocol_ok else "Fail",
            message=f"{get_nist_id('IA', 15)}: SSH uses protocol version 2 (IA-3)",
            details=f"Protocol {protocol_value}",
            remediation="Set Protocol 2 in /etc/ssh/sshd_config"
        ))
    
    # IA-016: SSH root login disabled (IA-2)
        root_login = re.search(r'^PermitRootLogin\s+(\w+)', sshd_config, re.MULTILINE)
        
        if root_login:
            root_login_value = root_login.group(1)
            root_login_ok = root_login_value == "no"
        else:
            root_login_value = "yes (default)"
            root_login_ok = False
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - IA (Identification & Auth)",
            status="Pass" if root_login_ok else "Fail",
            message=f"{get_nist_id('IA', 16)}: SSH root login disabled (IA-2)",
            details=f"PermitRootLogin {root_login_value}",
            remediation="Set PermitRootLogin no in /etc/ssh/sshd_config"
        ))
    
    # IA-017: SSH password authentication (IA-2)
        password_auth = re.search(r'^PasswordAuthentication\s+(\w+)', sshd_config, re.MULTILINE)
        
        if password_auth:
            password_auth_value = password_auth.group(1)
        else:
            password_auth_value = "yes (default)"
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - IA (Identification & Auth)",
            status="Info",
            message=f"{get_nist_id('IA', 17)}: SSH password authentication status (IA-2)",
            details=f"PasswordAuthentication {password_auth_value}",
            remediation="Consider disabling if using key-based auth only"
        ))
    
    # IA-018: SSH empty passwords disabled (IA-5)
        empty_passwords = re.search(r'^PermitEmptyPasswords\s+(\w+)', sshd_config, re.MULTILINE)
        
        if empty_passwords:
            empty_pw_value = empty_passwords.group(1)
            empty_pw_ok = empty_pw_value == "no"
        else:
            empty_pw_value = "no (default)"
            empty_pw_ok = True
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - IA (Identification & Auth)",
            status="Pass" if empty_pw_ok else "Fail",
            message=f"{get_nist_id('IA', 18)}: SSH empty passwords disabled (IA-5)",
            details=f"PermitEmptyPasswords {empty_pw_value}",
            remediation="Set PermitEmptyPasswords no in /etc/ssh/sshd_config"
        ))
    
    # IA-019: SSH host-based authentication disabled (IA-2)
        hostbased_auth = re.search(r'^HostbasedAuthentication\s+(\w+)', sshd_config, re.MULTILINE)
        
        if hostbased_auth:
            hostbased_value = hostbased_auth.group(1)
            hostbased_ok = hostbased_value == "no"
        else:
            hostbased_value = "no (default)"
            hostbased_ok = True
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - IA (Identification & Auth)",
            status="Pass" if hostbased_ok else "Fail",
            message=f"{get_nist_id('IA', 19)}: SSH host-based auth disabled (IA-2)",
            details=f"HostbasedAuthentication {hostbased_value}",
            remediation="Set HostbasedAuthentication no in /etc/ssh/sshd_config"
        ))
    
    # IA-020: SSH ignore rhosts (IA-2)
        ignore_rhosts = re.search(r'^IgnoreRhosts\s+(\w+)', sshd_config, re.MULTILINE)
        
        if ignore_rhosts:
            ignore_rhosts_value = ignore_rhosts.group(1)
            ignore_rhosts_ok = ignore_rhosts_value == "yes"
        else:
            ignore_rhosts_value = "yes (default)"
            ignore_rhosts_ok = True
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - IA (Identification & Auth)",
            status="Pass" if ignore_rhosts_ok else "Fail",
            message=f"{get_nist_id('IA', 20)}: SSH ignores .rhosts files (IA-2)",
            details=f"IgnoreRhosts {ignore_rhosts_value}",
            remediation="Set IgnoreRhosts yes in /etc/ssh/sshd_config"
        ))
    
    # IA-021: SSH MaxAuthTries (IA-2, AC-7)
        max_auth_tries = re.search(r'^MaxAuthTries\s+(\d+)', sshd_config, re.MULTILINE)
        
        if max_auth_tries:
            max_tries_value = int(max_auth_tries.group(1))
            max_tries_ok = max_tries_value <= 4
        else:
            max_tries_value = 6  # Default
            max_tries_ok = False
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - IA (Identification & Auth)",
            status="Pass" if max_tries_ok else "Warning",
            message=f"{get_nist_id('IA', 21)}: SSH authentication attempts limited (AC-7)",
            details=f"MaxAuthTries {max_tries_value}",
            remediation="Set MaxAuthTries 4 in /etc/ssh/sshd_config"
        ))
    
    # IA-022: SSH strong ciphers (IA-7)
        ciphers = re.search(r'^Ciphers\s+(.+)', sshd_config, re.MULTILINE)
        weak_ciphers = ["3des", "arcfour", "blowfish", "cast128"]
        
        if ciphers:
            cipher_list = ciphers.group(1).lower()
            has_weak = any(weak in cipher_list for weak in weak_ciphers)
        else:
            has_weak = False
            cipher_list = "default"
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - IA (Identification & Auth)",
            status="Pass" if not has_weak else "Warning",
            message=f"{get_nist_id('IA', 22)}: SSH uses strong ciphers (IA-7)",
            details=f"Ciphers: {cipher_list[:50]}...",
            remediation="Configure strong ciphers in sshd_config"
        ))
    
    # IA-023: SSH strong MACs (IA-7)
        macs = re.search(r'^MACs\s+(.+)', sshd_config, re.MULTILINE)
        weak_macs = ["md5", "96"]
        
        if macs:
            mac_list = macs.group(1).lower()
            has_weak_mac = any(weak in mac_list for weak in weak_macs)
        else:
            has_weak_mac = False
            mac_list = "default"
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - IA (Identification & Auth)",
            status="Pass" if not has_weak_mac else "Warning",
            message=f"{get_nist_id('IA', 23)}: SSH uses strong MACs (IA-7)",
            details=f"MACs: {mac_list[:50]}...",
            remediation="Configure strong MACs in sshd_config"
        ))
    
    # IA-024: SSH ClientAliveInterval (IA-11, AC-12)
        client_alive = re.search(r'^ClientAliveInterval\s+(\d+)', sshd_config, re.MULTILINE)
        
        if client_alive:
            interval_value = int(client_alive.group(1))
            interval_ok = 0 < interval_value <= 300
        else:
            interval_value = 0
            interval_ok = False
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - IA (Identification & Auth)",
            status="Pass" if interval_ok else "Warning",
            message=f"{get_nist_id('IA', 24)}: SSH idle timeout configured (AC-12)",
            details=f"ClientAliveInterval {interval_value}",
            remediation="Set ClientAliveInterval 300 in /etc/ssh/sshd_config"
        ))
    
    # IA-025: SSH ClientAliveCountMax (IA-11, AC-12)
        count_max = re.search(r'^ClientAliveCountMax\s+(\d+)', sshd_config, re.MULTILINE)
        
        if count_max:
            count_value = int(count_max.group(1))
            count_ok = count_value <= 3
        else:
            count_value = 3  # Default
            count_ok = True
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - IA (Identification & Auth)",
            status="Pass" if count_ok else "Warning",
            message=f"{get_nist_id('IA', 25)}: SSH idle count max configured (AC-12)",
            details=f"ClientAliveCountMax {count_value}",
            remediation="Set ClientAliveCountMax 0 in /etc/ssh/sshd_config"
        ))


# ============================================================================
# IR - Incident Response
# NIST 800-53: IR-1 through IR-10
# CSF: RS (Respond)
# ============================================================================

def check_incident_response(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Incident Response checks - IR family
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking IR - Incident Response...")
    
    # IR-001: Incident response plan documentation (IR-1)
    ir_plan_locations = [
        "/etc/security/ir-plan.txt",
        "/etc/security/incident-response-plan.txt",
        "/root/ir-plan.txt",
        "/usr/share/doc/ir-plan.txt"
    ]
    ir_plan_exists = any(os.path.exists(loc) for loc in ir_plan_locations)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IR (Incident Response)",
        status="Pass" if ir_plan_exists else "Warning",
        message=f"{get_nist_id('IR', 1)}: Incident response plan documented (IR-1)",
        details="IR plan found" if ir_plan_exists else "No IR plan found",
        remediation="Create incident response plan documentation"
    ))
    
    # IR-002: Network packet capture tools (IR-4)
    capture_tools = ["tcpdump", "wireshark", "tshark", "dumpcap"]
    installed_capture = [tool for tool in capture_tools if command_exists(tool)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IR (Incident Response)",
        status="Pass" if installed_capture else "Warning",
        message=f"{get_nist_id('IR', 2)}: Network capture tools available (IR-4)",
        details=f"Installed: {', '.join(installed_capture)}" if installed_capture else "No tools",
        remediation="Install tcpdump: apt-get install tcpdump"
    ))
    
    # IR-003: Forensics tools available (IR-4)
    forensics_tools = ["dd", "strings", "file", "hexdump"]
    installed_forensics = [tool for tool in forensics_tools if command_exists(tool)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IR (Incident Response)",
        status="Pass" if len(installed_forensics) >= 3 else "Warning",
        message=f"{get_nist_id('IR', 3)}: Basic forensics tools available (IR-4)",
        details=f"Available: {', '.join(installed_forensics)}",
        remediation="Ensure dd, strings, file, hexdump are available"
    ))
    
    # IR-004: Memory forensics capability (IR-4)
    memory_tools = ["volatility", "lime", "avml"]
    memory_forensics = any(command_exists(tool) or check_package_installed(tool, os_info) for tool in memory_tools)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IR (Incident Response)",
        status="Info",
        message=f"{get_nist_id('IR', 4)}: Memory forensics tools (IR-4)",
        details="Memory forensics available" if memory_forensics else "Not installed",
        remediation="Consider installing volatility for memory analysis"
    ))
    
    # IR-005: Backup tools available (IR-9, CP-9)
    backup_tools = ["rsync", "tar", "dd", "duplicity", "borgbackup"]
    installed_backup = [tool for tool in backup_tools if command_exists(tool)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IR (Incident Response)",
        status="Pass" if installed_backup else "Fail",
        message=f"{get_nist_id('IR', 5)}: Backup tools available (IR-9)",
        details=f"Available: {', '.join(installed_backup)}" if installed_backup else "No backup tools",
        remediation="Install rsync and tar for backup capability"
    ))
    
    # IR-006: Backup directories configured (CP-9)
    backup_dirs = ["/backup", "/var/backups", "/mnt/backup", "/srv/backup"]
    existing_backup_dirs = [d for d in backup_dirs if os.path.exists(d)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IR (Incident Response)",
        status="Pass" if existing_backup_dirs else "Warning",
        message=f"{get_nist_id('IR', 6)}: Backup directories exist (CP-9)",
        details=f"Found: {', '.join(existing_backup_dirs)}" if existing_backup_dirs else "No backup dirs",
        remediation="Create backup directory: mkdir -p /backup"
    ))
    
    # IR-007: Recent backups exist (CP-9)
    if existing_backup_dirs:
        recent_backups = False
        for backup_dir in existing_backup_dirs[:2]:
            result = run_command(f"find {backup_dir} -type f -mtime -7 2>/dev/null | head -1")
            if result.stdout.strip():
                recent_backups = True
                break
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - IR (Incident Response)",
            status="Pass" if recent_backups else "Warning",
            message=f"{get_nist_id('IR', 7)}: Recent backups present (CP-9)",
            details="Backups within 7 days" if recent_backups else "No recent backups",
            remediation="Perform regular backups"
        ))
    
    # IR-008: Emergency contact information (IR-6)
    contact_locations = [
        "/etc/security/contacts.txt",
        "/root/emergency-contacts.txt"
    ]
    contacts_exist = any(os.path.exists(loc) for loc in contact_locations)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IR (Incident Response)",
        status="Info",
        message=f"{get_nist_id('IR', 8)}: Emergency contacts documented (IR-6)",
        details="Contacts documented" if contacts_exist else "Not found",
        remediation="Document emergency contact information"
    ))
    
    # IR-009: Incident logging directory (IR-5)
    incident_log_dirs = ["/var/log/incidents", "/var/log/security/incidents"]
    incident_logs = any(os.path.exists(d) for d in incident_log_dirs)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IR (Incident Response)",
        status="Pass" if incident_logs else "Info",
        message=f"{get_nist_id('IR', 9)}: Incident logging directory (IR-5)",
        details="Incident log directory exists" if incident_logs else "Not configured",
        remediation="Create /var/log/incidents for incident tracking"
    ))
    
    # IR-010: System information gathering tools (IR-4)
    sysinfo_tools = ["lshw", "dmidecode", "lspci", "lsusb"]
    installed_sysinfo = [tool for tool in sysinfo_tools if command_exists(tool)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IR (Incident Response)",
        status="Pass" if len(installed_sysinfo) >= 2 else "Warning",
        message=f"{get_nist_id('IR', 10)}: System information tools (IR-4)",
        details=f"Available: {', '.join(installed_sysinfo)}",
        remediation="Install lshw and dmidecode"
    ))
    
    # IR-011: Network diagnostic tools (IR-4)
    network_tools = ["netstat", "ss", "ip", "ifconfig", "ping", "traceroute"]
    installed_network = [tool for tool in network_tools if command_exists(tool)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IR (Incident Response)",
        status="Pass" if len(installed_network) >= 4 else "Warning",
        message=f"{get_nist_id('IR', 11)}: Network diagnostic tools (IR-4)",
        details=f"Available: {', '.join(installed_network)}",
        remediation="Ensure basic network tools are installed"
    ))
    
    # IR-012: Process investigation tools (IR-4)
    process_tools = ["ps", "top", "htop", "lsof", "pstree"]
    installed_process = [tool for tool in process_tools if command_exists(tool)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IR (Incident Response)",
        status="Pass" if len(installed_process) >= 3 else "Warning",
        message=f"{get_nist_id('IR', 12)}: Process investigation tools (IR-4)",
        details=f"Available: {', '.join(installed_process)}",
        remediation="Install lsof for process investigation"
    ))
    
    # IR-013: Hash utilities for integrity verification (IR-4)
    hash_tools = ["md5sum", "sha1sum", "sha256sum", "sha512sum"]
    installed_hash = [tool for tool in hash_tools if command_exists(tool)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IR (Incident Response)",
        status="Pass" if len(installed_hash) >= 3 else "Warning",
        message=f"{get_nist_id('IR', 13)}: Hash utilities available (IR-4)",
        details=f"Available: {', '.join(installed_hash)}",
        remediation="Ensure hash utilities are available"
    ))
    
    # IR-014: Secure deletion tools (IR-4, MP-6)
    secure_delete = ["shred", "wipe", "srm"]
    installed_secure_del = [tool for tool in secure_delete if command_exists(tool)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IR (Incident Response)",
        status="Pass" if installed_secure_del else "Info",
        message=f"{get_nist_id('IR', 14)}: Secure deletion tools (MP-6)",
        details=f"Available: {', '.join(installed_secure_del)}" if installed_secure_del else "Not installed",
        remediation="Install shred for secure file deletion"
    ))
    
    # IR-015: Rootkit detection tools (IR-4)
    rootkit_tools = ["rkhunter", "chkrootkit", "unhide"]
    installed_rootkit = [tool for tool in rootkit_tools if check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IR (Incident Response)",
        status="Pass" if installed_rootkit else "Warning",
        message=f"{get_nist_id('IR', 15)}: Rootkit detection tools (IR-4)",
        details=f"Installed: {', '.join(installed_rootkit)}" if installed_rootkit else "Not installed",
        remediation=remediation_for("rkhunter")
    ))
    
    # IR-016: Malware scanning capability (IR-4, SI-3)
    malware_scanners = ["clamav", "clamscan"]
    installed_malware = [tool for tool in malware_scanners if check_package_installed(tool, os_info) or command_exists(tool)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IR (Incident Response)",
        status="Pass" if installed_malware else "Warning",
        message=f"{get_nist_id('IR', 16)}: Malware scanning capability (SI-3)",
        details=f"Installed: {', '.join(installed_malware)}" if installed_malware else "Not installed",
        remediation=remediation_for("clamav")
    ))
    
    # IR-017: IDS/IPS capability (IR-4, SI-4)
    ids_ips_tools = ["snort", "suricata", "fail2ban"]
    installed_ids = [tool for tool in ids_ips_tools if check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IR (Incident Response)",
        status="Info",
        message=f"{get_nist_id('IR', 17)}: IDS/IPS capability (SI-4)",
        details=f"Installed: {', '.join(installed_ids)}" if installed_ids else "Not installed",
        remediation="Consider installing fail2ban or snort"
    ))
    
    # IR-018: Core dumps restricted (IR-4, SI-11)
    exists, core_pattern = check_kernel_parameter("kernel.core_pattern")
    core_restricted = "core" not in core_pattern.lower() if core_pattern else False
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IR (Incident Response)",
        status="Pass" if core_restricted else "Warning",
        message=f"{get_nist_id('IR', 18)}: Core dumps restricted (SI-11)",
        details=f"core_pattern: {core_pattern}",
        remediation="Configure core_pattern to restrict core dumps"
    ))
    
    # IR-019: System logging to detect incidents (IR-5)
    critical_logs = [
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/syslog",
        "/var/log/messages"
    ]
    existing_logs = [log for log in critical_logs if os.path.exists(log)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IR (Incident Response)",
        status="Pass" if len(existing_logs) >= 2 else "Warning",
        message=f"{get_nist_id('IR', 19)}: Critical log files exist (IR-5)",
        details=f"Found {len(existing_logs)}/{len(critical_logs)} critical logs",
        remediation="Ensure system logging is configured"
    ))
    
    # IR-020: Last command for login tracking (IR-5)
    lastlog_exists = os.path.exists("/var/log/lastlog")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - IR (Incident Response)",
        status="Pass" if lastlog_exists else "Warning",
        message=f"{get_nist_id('IR', 20)}: Login tracking enabled (IR-5)",
        details="lastlog tracking active" if lastlog_exists else "Not configured",
        remediation="Enable lastlog tracking"
    ))


# ============================================================================
# SC - System and Communications Protection
# NIST 800-53: SC-1 through SC-28
# CSF: PR.DS (Data Security), PR.PT (Protective Technology)
# ============================================================================

def check_system_communications_protection(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    System and Communications Protection - SC family
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking SC - System & Communications Protection...")
    
    # SC-001: Firewall installed (SC-7)
    firewall_packages = ["ufw", "firewalld", "iptables"]
    firewall_installed = any(check_package_installed(pkg, os_info) for pkg in firewall_packages)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SC (System & Comm Protection)",
        status="Pass" if firewall_installed else "Fail",
        message=f"{get_nist_id('SC', 1)}: Firewall software installed (SC-7)",
        details="Firewall package present" if firewall_installed else "No firewall",
        remediation=remediation_for("ufw")
    ))
    
    # SC-002: Firewall enabled (SC-7)
    firewall_services = ["ufw", "firewalld", "iptables"]
    firewall_active = any(check_service_active(svc) for svc in firewall_services)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SC (System & Comm Protection)",
        status="Pass" if firewall_active else "Fail",
        message=f"{get_nist_id('SC', 2)}: Firewall service active (SC-7)",
        details="Firewall running" if firewall_active else "Not active",
        remediation="Enable firewall: ufw enable || systemctl start firewalld"
    ))
    
    # SC-003: Default firewall deny policy (SC-7)
    if command_exists("ufw"):
        ufw_status = run_command("ufw status verbose 2>/dev/null").stdout
        default_deny = "Default: deny (incoming)" in ufw_status
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - SC (System & Comm Protection)",
            status="Pass" if default_deny else "Warning",
            message=f"{get_nist_id('SC', 3)}: Firewall default deny policy (SC-7)",
            details="Default deny configured" if default_deny else "Check policy",
            remediation="Set default deny: ufw default deny incoming"
        ))
    
    # SC-004: Listening ports inventory (SC-7)
    listening_ports = get_listening_ports()
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SC (System & Comm Protection)",
        status="Info",
        message=f"{get_nist_id('SC', 4)}: Open ports inventory (SC-7)",
        details=f"{len(listening_ports)} listening ports: {listening_ports[:10]}",
        remediation="Review and close unnecessary ports"
    ))
    
    # SC-005: No insecure services listening (SC-7)
    insecure_ports = {21: "FTP", 23: "Telnet", 69: "TFTP", 512: "rexec", 513: "rlogin", 514: "rsh"}
    found_insecure = {port: service for port, service in insecure_ports.items() if port in listening_ports}
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SC (System & Comm Protection)",
        status="Fail" if found_insecure else "Pass",
        message=f"{get_nist_id('SC', 5)}: No insecure services listening (SC-7)",
        details=f"Insecure services: {found_insecure}" if found_insecure else "No insecure services",
        remediation="Disable insecure services"
    ))
    
    # SC-006: TCP SYN cookies enabled (SC-5)
    exists, syn_cookies = check_kernel_parameter("net.ipv4.tcp_syncookies")
    syn_ok = syn_cookies == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SC (System & Comm Protection)",
        status="Pass" if syn_ok else "Fail",
        message=f"{get_nist_id('SC', 6)}: TCP SYN cookies enabled (SC-5)",
        details=f"tcp_syncookies = {syn_cookies}",
        remediation="Enable: echo 'net.ipv4.tcp_syncookies = 1' >> /etc/sysctl.conf"
    ))
    
    # SC-007: ICMP redirects disabled (SC-7)
    params_to_check = [
        ("net.ipv4.conf.all.accept_redirects", "0"),
        ("net.ipv4.conf.default.accept_redirects", "0")
    ]
    
    all_redirects_disabled = True
    for param, expected in params_to_check:
        exists, value = check_kernel_parameter(param)
        if value != expected:
            all_redirects_disabled = False
            break
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SC (System & Comm Protection)",
        status="Pass" if all_redirects_disabled else "Fail",
        message=f"{get_nist_id('SC', 7)}: ICMP redirects disabled (SC-7)",
        details="Redirects disabled" if all_redirects_disabled else "Not fully disabled",
        remediation="Disable ICMP redirects in sysctl.conf"
    ))
    
    # SC-008: Secure ICMP redirects disabled (SC-7)
    exists, secure_redirects = check_kernel_parameter("net.ipv4.conf.all.secure_redirects")
    secure_ok = secure_redirects == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SC (System & Comm Protection)",
        status="Pass" if secure_ok else "Fail",
        message=f"{get_nist_id('SC', 8)}: Secure ICMP redirects disabled (SC-7)",
        details=f"secure_redirects = {secure_redirects}",
        remediation="Set net.ipv4.conf.all.secure_redirects = 0"
    ))
    
    # SC-009: Send redirects disabled (SC-7)
    exists, send_redirects = check_kernel_parameter("net.ipv4.conf.all.send_redirects")
    send_ok = send_redirects == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SC (System & Comm Protection)",
        status="Pass" if send_ok else "Fail",
        message=f"{get_nist_id('SC', 9)}: ICMP send redirects disabled (SC-7)",
        details=f"send_redirects = {send_redirects}",
        remediation="Set net.ipv4.conf.all.send_redirects = 0"
    ))
    
    # SC-010: Source routing disabled (SC-7)
    exists, source_route = check_kernel_parameter("net.ipv4.conf.all.accept_source_route")
    source_ok = source_route == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SC (System & Comm Protection)",
        status="Pass" if source_ok else "Fail",
        message=f"{get_nist_id('SC', 10)}: Source routing disabled (SC-7)",
        details=f"accept_source_route = {source_route}",
        remediation="Set net.ipv4.conf.all.accept_source_route = 0"
    ))
    
    # SC-011: Reverse path filtering (SC-7)
    exists, rp_filter = check_kernel_parameter("net.ipv4.conf.all.rp_filter")
    rp_ok = rp_filter == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SC (System & Comm Protection)",
        status="Pass" if rp_ok else "Fail",
        message=f"{get_nist_id('SC', 11)}: Reverse path filtering enabled (SC-7)",
        details=f"rp_filter = {rp_filter}",
        remediation="Set net.ipv4.conf.all.rp_filter = 1"
    ))
    
    # SC-012: Log martian packets (SC-7)
    exists, log_martians = check_kernel_parameter("net.ipv4.conf.all.log_martians")
    martians_ok = log_martians == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SC (System & Comm Protection)",
        status="Pass" if martians_ok else "Warning",
        message=f"{get_nist_id('SC', 12)}: Martian packet logging enabled (SC-7)",
        details=f"log_martians = {log_martians}",
        remediation="Set net.ipv4.conf.all.log_martians = 1"
    ))
    
    # SC-013: Ignore ICMP broadcasts (SC-7)
    exists, icmp_broadcast = check_kernel_parameter("net.ipv4.icmp_echo_ignore_broadcasts")
    broadcast_ok = icmp_broadcast == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SC (System & Comm Protection)",
        status="Pass" if broadcast_ok else "Fail",
        message=f"{get_nist_id('SC', 13)}: ICMP broadcast ignored (SC-7)",
        details=f"icmp_echo_ignore_broadcasts = {icmp_broadcast}",
        remediation="Set net.ipv4.icmp_echo_ignore_broadcasts = 1"
    ))
    
    # SC-014: Ignore bogus ICMP responses (SC-7)
    exists, bogus_icmp = check_kernel_parameter("net.ipv4.icmp_ignore_bogus_error_responses")
    bogus_ok = bogus_icmp == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SC (System & Comm Protection)",
        status="Pass" if bogus_ok else "Warning",
        message=f"{get_nist_id('SC', 14)}: Bogus ICMP responses ignored (SC-7)",
        details=f"icmp_ignore_bogus_error_responses = {bogus_icmp}",
        remediation="Set net.ipv4.icmp_ignore_bogus_error_responses = 1"
    ))
    
    # SC-015: IPv6 status (SC-7)
    ipv6_disabled = not os.path.exists("/proc/sys/net/ipv6")
    if not ipv6_disabled:
        exists, ipv6_disable = check_kernel_parameter("net.ipv6.conf.all.disable_ipv6")
        ipv6_disabled = ipv6_disable == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SC (System & Comm Protection)",
        status="Info",
        message=f"{get_nist_id('SC', 15)}: IPv6 configuration (SC-7)",
        details="IPv6 disabled" if ipv6_disabled else "IPv6 enabled",
        remediation="Disable if not needed: net.ipv6.conf.all.disable_ipv6 = 1"
    ))
    
    # SC-016: IPv6 router advertisements (SC-7)
    if not ipv6_disabled:
        exists, ipv6_ra = check_kernel_parameter("net.ipv6.conf.all.accept_ra")
        ra_ok = ipv6_ra == "0"
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - SC (System & Comm Protection)",
            status="Pass" if ra_ok else "Warning",
            message=f"{get_nist_id('SC', 16)}: IPv6 router advertisements disabled (SC-7)",
            details=f"accept_ra = {ipv6_ra}",
            remediation="Set net.ipv6.conf.all.accept_ra = 0"
        ))
    
    # SC-017: IPv6 redirects disabled (SC-7)
    if not ipv6_disabled:
        exists, ipv6_redirects = check_kernel_parameter("net.ipv6.conf.all.accept_redirects")
        ipv6_redir_ok = ipv6_redirects == "0"
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - SC (System & Comm Protection)",
            status="Pass" if ipv6_redir_ok else "Warning",
            message=f"{get_nist_id('SC', 17)}: IPv6 redirects disabled (SC-7)",
            details=f"accept_redirects = {ipv6_redirects}",
            remediation="Set net.ipv6.conf.all.accept_redirects = 0"
        ))
    
    # SC-018: TLS/SSL certificates directory (SC-8, SC-13)
    ssl_cert_dir = os.path.exists("/etc/ssl/certs")
    cert_count = len(glob.glob("/etc/ssl/certs/*.pem")) if ssl_cert_dir else 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SC (System & Comm Protection)",
        status="Pass" if cert_count > 5 else "Warning",
        message=f"{get_nist_id('SC', 18)}: TLS/SSL certificates present (SC-8)",
        details=f"{cert_count} certificates in /etc/ssl/certs",
        remediation="Install CA certificates"
    ))
    
    # SC-019: OpenSSL installed (SC-13)
    openssl_installed = command_exists("openssl")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SC (System & Comm Protection)",
        status="Pass" if openssl_installed else "Fail",
        message=f"{get_nist_id('SC', 19)}: OpenSSL available (SC-13)",
        details="OpenSSL installed" if openssl_installed else "Not installed",
        remediation="Install OpenSSL"
    ))
    
    # SC-020: Encryption tools available (SC-13)
    crypto_tools = ["gpg", "gpg2", "openssl", "cryptsetup"]
    installed_crypto = [tool for tool in crypto_tools if command_exists(tool)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SC (System & Comm Protection)",
        status="Pass" if len(installed_crypto) >= 2 else "Warning",
        message=f"{get_nist_id('SC', 20)}: Cryptographic tools available (SC-13)",
        details=f"Installed: {', '.join(installed_crypto)}",
        remediation="Install encryption tools: apt-get install gnupg cryptsetup"
    ))
    
    # SC-021: Disk encryption status (SC-13, SC-28)
    luks_volumes = run_command("lsblk -f | grep -c 'crypto_LUKS' || true").stdout.strip()
    has_encryption = safe_int_parse(luks_volumes) > 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SC (System & Comm Protection)",
        status="Pass" if has_encryption else "Warning",
        message=f"{get_nist_id('SC', 21)}: Disk encryption configured (SC-13)",
        details=f"{luks_volumes} encrypted volumes" if has_encryption else "No encryption",
        remediation="Configure LUKS disk encryption"
    ))
    
    # SC-022: ASLR enabled (SC-3)
    exists, aslr = check_kernel_parameter("kernel.randomize_va_space")
    aslr_ok = aslr == "2"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SC (System & Comm Protection)",
        status="Pass" if aslr_ok else "Fail",
        message=f"{get_nist_id('SC', 22)}: Address Space Layout Randomization (SC-3)",
        details=f"randomize_va_space = {aslr}",
        remediation="Set kernel.randomize_va_space = 2"
    ))
    
    # SC-023: ExecShield enabled (SC-3)
    exists, exec_shield = check_kernel_parameter("kernel.exec-shield")
    if exists:
        shield_ok = exec_shield == "1"
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - SC (System & Comm Protection)",
            status="Pass" if shield_ok else "Warning",
            message=f"{get_nist_id('SC', 23)}: ExecShield enabled (SC-3)",
            details=f"exec-shield = {exec_shield}",
            remediation="Set kernel.exec-shield = 1"
        ))
    
    # SC-024: Core dump restrictions (SC-3, SI-11)
    exists, core_uses_pid = check_kernel_parameter("kernel.core_uses_pid")
    core_ok = core_uses_pid == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SC (System & Comm Protection)",
        status="Pass" if core_ok else "Warning",
        message=f"{get_nist_id('SC', 24)}: Core dumps use PID (SI-11)",
        details=f"core_uses_pid = {core_uses_pid}",
        remediation="Set kernel.core_uses_pid = 1"
    ))
    
    # SC-025: SUID core dumps disabled (SI-11)
    exists, suid_dumpable = check_kernel_parameter("fs.suid_dumpable")
    suid_ok = suid_dumpable == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SC (System & Comm Protection)",
        status="Pass" if suid_ok else "Fail",
        message=f"{get_nist_id('SC', 25)}: SUID core dumps disabled (SI-11)",
        details=f"suid_dumpable = {suid_dumpable}",
        remediation="Set fs.suid_dumpable = 0"
    ))
    
    # SC-026: Restrict dmesg access (SC-4)
    exists, dmesg_restrict = check_kernel_parameter("kernel.dmesg_restrict")
    dmesg_ok = dmesg_restrict == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SC (System & Comm Protection)",
        status="Pass" if dmesg_ok else "Warning",
        message=f"{get_nist_id('SC', 26)}: dmesg access restricted (SC-4)",
        details=f"dmesg_restrict = {dmesg_restrict}",
        remediation="Set kernel.dmesg_restrict = 1"
    ))
    
    # SC-027: Restrict kernel pointers (SC-4)
    exists, kptr_restrict = check_kernel_parameter("kernel.kptr_restrict")
    kptr_ok = kptr_restrict in ["1", "2"]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SC (System & Comm Protection)",
        status="Pass" if kptr_ok else "Warning",
        message=f"{get_nist_id('SC', 27)}: Kernel pointer restriction (SC-4)",
        details=f"kptr_restrict = {kptr_restrict}",
        remediation="Set kernel.kptr_restrict = 1"
    ))
    
    # SC-028: Restrict perf events (SC-4)
    exists, perf_restrict = check_kernel_parameter("kernel.perf_event_paranoid")
    perf_ok = perf_restrict and int(perf_restrict) >= 2
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SC (System & Comm Protection)",
        status="Pass" if perf_ok else "Warning",
        message=f"{get_nist_id('SC', 28)}: Performance event access restricted (SC-4)",
        details=f"perf_event_paranoid = {perf_restrict}",
        remediation="Set kernel.perf_event_paranoid = 3"
    ))
    
    # SC-029: VPN capability (SC-8)
    vpn_packages = ["openvpn", "strongswan", "wireguard"]
    vpn_installed = any(check_package_installed(pkg, os_info) for pkg in vpn_packages)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SC (System & Comm Protection)",
        status="Info",
        message=f"{get_nist_id('SC', 29)}: VPN capability (SC-8)",
        details="VPN software installed" if vpn_installed else "No VPN",
        remediation="Install VPN: apt-get install openvpn"
    ))
    
    # SC-030: Wireless interfaces (SC-7, SC-40)
    wireless_interfaces = run_command("iwconfig 2>&1 | grep 'IEEE' | wc -l").stdout.strip()
    wireless_count = safe_int_parse(wireless_interfaces)
    has_wireless = wireless_count > 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SC (System & Comm Protection)",
        status="Info" if has_wireless else "Pass",
        message=f"{get_nist_id('SC', 30)}: Wireless interface inventory (SC-40)",
        details=f"{wireless_count} wireless interfaces" if has_wireless else "No wireless",
        remediation="Review and secure wireless interfaces"
    ))


# ============================================================================
# SI - System and Information Integrity
# NIST 800-53: SI-1 through SI-16
# CSF: PR.DS (Data Security), DE.CM (Continuous Monitoring)
# ============================================================================

def check_system_information_integrity(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    System and Information Integrity - SI family
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking SI - System & Information Integrity...")
    
    # SI-001: Available security updates (SI-2)
    # Try apt first (Debian/Ubuntu)
    security_updates = run_command("apt list --upgradable 2>/dev/null | grep -c security").stdout.strip()
    if not security_updates or security_updates == "":
        # Try yum/dnf (RHEL/CentOS)
        security_updates = run_command("yum updateinfo list security 2>/dev/null | wc -l").stdout.strip()
    if not security_updates or security_updates == "":
        security_updates = "0"
    
    # Clean up any multi-line output and extract just the number
    try:
        update_count = int(security_updates.split('\n')[0].strip())
        has_updates = update_count > 0
    except (ValueError, AttributeError):
        update_count = 0
        has_updates = False
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SI (System & Info Integrity)",
        status="Fail" if has_updates else "Pass",
        message=f"{get_nist_id('SI', 1)}: Security updates applied (SI-2)",
        details=f"{update_count} security updates available" if has_updates else "System up to date",
        remediation=patch_for()
    ))
    
    # SI-002: Automatic updates configured (SI-2)
    auto_update_packages = ["unattended-upgrades", "yum-cron", "dnf-automatic"]
    auto_updates = any(check_package_installed(pkg, os_info) for pkg in auto_update_packages)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SI (System & Info Integrity)",
        status="Pass" if auto_updates else "Warning",
        message=f"{get_nist_id('SI', 2)}: Automatic updates configured (SI-2)",
        details="Auto-updates enabled" if auto_updates else "Not configured",
        remediation=remediation_for("unattended-upgrades")
    ))
    
    # SI-003: Package repository validation (SI-7)
    repo_files = glob.glob("/etc/apt/sources.list.d/*.list") + ["/etc/apt/sources.list"]
    insecure_repos = []
    
    for repo_file in repo_files:
        if os.path.exists(repo_file):
            content = read_file_safe(repo_file)
            if "http://" in content and "https://" not in content:
                insecure_repos.append(os.path.basename(repo_file))
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SI (System & Info Integrity)",
        status="Warning" if insecure_repos else "Pass",
        message=f"{get_nist_id('SI', 3)}: Package repositories use HTTPS (SI-7)",
        details=f"Insecure repos: {insecure_repos[:3]}" if insecure_repos else "All repos secure",
        remediation="Use HTTPS for package repositories"
    ))
    
    # SI-004: AIDE installed (SI-7)
    aide_installed = check_package_installed("aide", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SI (System & Info Integrity)",
        status="Pass" if aide_installed else "Fail",
        message=f"{get_nist_id('SI', 4)}: File integrity monitoring installed (SI-7)",
        details="AIDE installed" if aide_installed else "Not installed",
        remediation=remediation_for("aide")
    ))
    
    # SI-005: AIDE database exists (SI-7)
    if aide_installed:
        aide_dbs = [
            "/var/lib/aide/aide.db",
            "/var/lib/aide/aide.db.gz",
            "/var/lib/aide.db"
        ]
        aide_db_exists = any(os.path.exists(db) for db in aide_dbs)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - SI (System & Info Integrity)",
            status="Pass" if aide_db_exists else "Warning",
            message=f"{get_nist_id('SI', 5)}: AIDE database initialized (SI-7)",
            details="Database exists" if aide_db_exists else "Not initialized",
            remediation=remediation_for("aide")
        ))
    
    # SI-006: AIDE scheduled (SI-7)
        aide_scheduled = run_command("crontab -l 2>/dev/null | grep -c aide || grep -r aide /etc/cron* 2>/dev/null | wc -l").stdout.strip()
        aide_cron = safe_int_parse(aide_scheduled) > 0
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - SI (System & Info Integrity)",
            status="Pass" if aide_cron else "Warning",
            message=f"{get_nist_id('SI', 6)}: AIDE checks scheduled (SI-7)",
            details="AIDE in crontab" if aide_cron else "Not scheduled",
            remediation="Schedule AIDE: echo '0 5 * * * /usr/bin/aide --check' | crontab"
        ))
    
    # SI-007: Malware protection installed (SI-3)
    antivirus_packages = ["clamav", "clamav-daemon"]
    antivirus_installed = any(check_package_installed(pkg, os_info) for pkg in antivirus_packages)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SI (System & Info Integrity)",
        status="Pass" if antivirus_installed else "Warning",
        message=f"{get_nist_id('SI', 7)}: Malware protection installed (SI-3)",
        details="ClamAV installed" if antivirus_installed else "No antivirus",
        remediation=remediation_for("clamav")
    ))
    
    # SI-008: Malware definitions updated (SI-3)
    if antivirus_installed:
        freshclam_recent = False
        if os.path.exists("/var/log/clamav/freshclam.log"):
            result = run_command("find /var/log/clamav/freshclam.log -mtime -7 2>/dev/null")
            freshclam_recent = bool(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - SI (System & Info Integrity)",
            status="Pass" if freshclam_recent else "Warning",
            message=f"{get_nist_id('SI', 8)}: Malware definitions updated (SI-3)",
            details="Updated within 7 days" if freshclam_recent else "Check updates",
            remediation=remediation_for("clamav")
        ))
    
    # SI-009: Rootkit detection installed (SI-3)
    rootkit_tools = ["rkhunter", "chkrootkit"]
    rootkit_installed = any(check_package_installed(tool, os_info) for tool in rootkit_tools)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SI (System & Info Integrity)",
        status="Pass" if rootkit_installed else "Warning",
        message=f"{get_nist_id('SI', 9)}: Rootkit detection installed (SI-3)",
        details="Rootkit scanner present" if rootkit_installed else "Not installed",
        remediation=remediation_for("rkhunter")
    ))
    
    # SI-010: AppArmor/SELinux status (SI-6)
    selinux_active = os.path.exists("/etc/selinux/config")
    apparmor_active = check_service_active("apparmor")
    mac_enabled = selinux_active or apparmor_active
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SI (System & Info Integrity)",
        status="Pass" if mac_enabled else "Warning",
        message=f"{get_nist_id('SI', 10)}: Mandatory Access Control active (SI-6)",
        details="SELinux or AppArmor" if mac_enabled else "No MAC",
        remediation="Enable AppArmor or SELinux"
    ))
    
    # SI-011: AppArmor profiles loaded (SI-6)
    if apparmor_active:
        profiles = run_command("apparmor_status 2>/dev/null | grep 'profiles are loaded' | awk '{print $1}'").stdout.strip()
        profiles_count = int(profiles) if profiles and profiles.isdigit() else 0
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - SI (System & Info Integrity)",
            status="Pass" if profiles_count > 0 else "Warning",
            message=f"{get_nist_id('SI', 11)}: AppArmor profiles loaded (SI-6)",
            details=f"{profiles_count} profiles loaded",
            remediation="Enable AppArmor profiles"
        ))
    
    # SI-012: System file permissions - passwd (SI-7)
    critical_files = {
        "/etc/passwd": "644",
        "/etc/shadow": "640",
        "/etc/group": "644",
        "/etc/gshadow": "640"
    }
    
    insecure_files = []
    for file, expected_perms in critical_files.items():
        if os.path.exists(file):
            actual_perms = get_file_permissions(file)
            if actual_perms and int(actual_perms, 8) > int(expected_perms, 8):
                insecure_files.append(f"{file}:{actual_perms}")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SI (System & Info Integrity)",
        status="Pass" if not insecure_files else "Fail",
        message=f"{get_nist_id('SI', 12)}: Critical file permissions secure (SI-7)",
        details=f"Insecure: {insecure_files}" if insecure_files else "All secure",
        remediation="Fix permissions: chmod 644 /etc/passwd; chmod 640 /etc/shadow"
    ))
    
    # SI-013: World-writable files (SI-7) (canonical assessment)
    from shared_components.shared_assessments import get_world_writable_assessment as _ww_assess
    _ww = _ww_assess("fail")
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SI (System & Info Integrity)",
        status=_ww.status,
        message=f"{get_nist_id('SI', 13)}: World-writable files (SI-7)",
        details=_ww.details,
        remediation=_ww.remediation
    ))
    
    # SI-014: Unowned files (SI-7)
    unowned = run_command("find / -xdev -nouser -o -nogroup 2>/dev/null | head -10 | wc -l").stdout.strip()
    unowned_count = safe_int_parse(unowned)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SI (System & Info Integrity)",
        status="Warning" if unowned_count > 0 else "Pass",
        message=f"{get_nist_id('SI', 14)}: Unowned files (SI-7)",
        details=f"{unowned_count} unowned files" if unowned_count > 0 else "None",
        remediation="Assign ownership to unowned files"
    ))
    
    # SI-015: SUID files inventory (SI-7)
    suid_files = run_command("find / -xdev -type f -perm -4000 2>/dev/null | wc -l").stdout.strip()
    suid_count = safe_int_parse(suid_files)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SI (System & Info Integrity)",
        status="Info",
        message=f"{get_nist_id('SI', 15)}: SUID binary inventory (SI-7)",
        details=f"{suid_count} SUID binaries",
        remediation="Review and minimize SUID binaries"
    ))
    
    # SI-016: SGID files inventory (SI-7)
    sgid_files = run_command("find / -xdev -type f -perm -2000 2>/dev/null | wc -l").stdout.strip()
    sgid_count = safe_int_parse(sgid_files)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SI (System & Info Integrity)",
        status="Info",
        message=f"{get_nist_id('SI', 16)}: SGID binary inventory (SI-7)",
        details=f"{sgid_count} SGID binaries",
        remediation="Review and minimize SGID binaries"
    ))
    
    # SI-017: Kernel version (SI-2)
    kernel_version = run_command("uname -r").stdout.strip()
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SI (System & Info Integrity)",
        status="Info",
        message=f"{get_nist_id('SI', 17)}: Kernel version (SI-2)",
        details=f"Kernel: {kernel_version}",
        remediation="Keep kernel updated"
    ))
    
    # SI-018: Boot parameters (SI-7)
    if os.path.exists("/proc/cmdline"):
        cmdline = read_file_safe("/proc/cmdline")
        has_security = any(param in cmdline for param in ["selinux", "apparmor"])
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - SI (System & Info Integrity)",
            status="Pass" if has_security else "Info",
            message=f"{get_nist_id('SI', 18)}: Boot security parameters (SI-7)",
            details="Security params present" if has_security else "Review boot params",
            remediation="Add security parameters to boot config"
        ))
    
    # SI-019: Prelink disabled (SI-7)
    prelink_installed = check_package_installed("prelink", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SI (System & Info Integrity)",
        status="Pass" if not prelink_installed else "Warning",
        message=f"{get_nist_id('SI', 19)}: Prelink disabled (SI-7)",
        details="Prelink not installed" if not prelink_installed else "Prelink present",
        remediation=removal_for("prelink")
    ))
    
    # SI-020: System information disclosure (SI-11)
    issue_os_info = False
    for file in ["/etc/issue", "/etc/issue.net", "/etc/motd"]:
        if os.path.exists(file):
            content = read_file_safe(file).lower()
            if any(keyword in content for keyword in ["ubuntu", "debian", "centos", "red hat", "linux"]):
                issue_os_info = True
                break
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SI (System & Info Integrity)",
        status="Warning" if issue_os_info else "Pass",
        message=f"{get_nist_id('SI', 20)}: Banner information disclosure (SI-11)",
        details="OS info in banners" if issue_os_info else "No disclosure",
        remediation="Remove OS information from login banners"
    ))
    
    # SI-021-030: Additional system integrity checks
    additional_checks = [
        ("Compiler installed", "gcc", "Remove if not needed"),
        ("Development tools", "make", "Remove if not needed"),
        ("Debug tools", "gdb", "Remove if not needed"),
        ("System monitoring", "sysstat", "Install for monitoring"),
        ("Process accounting", "acct", "Enable process accounting"),
        ("System auditing active", "auditd", "Already checked in AU"),
        ("Log integrity", "logrotate", "Already checked in AU"),
        ("File system integrity", "aide", "Already checked above"),
        ("Intrusion detection", "fail2ban", "Already checked in IR"),
        ("System hardening", "lynis", "Install security auditing tool")
    ]
    
    for i, (name, tool, remediation) in enumerate(additional_checks, start=21):
        if tool == "auditd":
            is_present = check_service_active(tool)
        else:
            is_present = command_exists(tool) or check_package_installed(tool, os_info)
        
        status = "Info"
        if "Remove if not needed" in remediation:
            status = "Warning" if is_present else "Pass"
        elif "Install" in remediation:
            status = "Pass" if is_present else "Info"
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - SI (System & Info Integrity)",
            status=status,
            message=f"{get_nist_id('SI', i)}: {name}",
            details=f"{tool} present" if is_present else f"{tool} not present",
            remediation=remediation
        ))


# ============================================================================
# Additional Control Families
# CP - Contingency Planning
# MA - Maintenance
# MP - Media Protection
# PE - Physical & Environmental Protection
# RA - Risk Assessment
# SA - System & Services Acquisition
# ============================================================================

def check_additional_controls(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Additional NIST control families
    Security audit checks across CP, MA, MP, PE, RA, SA
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Additional Control Families...")
    
    # CP-001: Backup directories exist (CP-9)
    backup_dirs = ["/backup", "/var/backups", "/mnt/backup", "/srv/backup"]
    existing_backup_dirs = [d for d in backup_dirs if os.path.exists(d)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CP (Contingency Planning)",
        status="Pass" if existing_backup_dirs else "Warning",
        message=f"{get_nist_id('CP', 1)}: Backup storage locations exist (CP-9)",
        details=f"Backup dirs: {', '.join(existing_backup_dirs)}" if existing_backup_dirs else "No backup dirs",
        remediation="Create backup directory: mkdir -p /backup"
    ))
    
    # CP-002: Backup tools installed (CP-9)
    backup_tools = ["rsync", "tar", "borgbackup", "duplicity", "bacula"]
    installed_backup = [tool for tool in backup_tools if command_exists(tool) or check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CP (Contingency Planning)",
        status="Pass" if len(installed_backup) >= 2 else "Fail",
        message=f"{get_nist_id('CP', 2)}: Backup utilities available (CP-9)",
        details=f"Available: {', '.join(installed_backup)}" if installed_backup else "No tools",
        remediation="Install backup tools: apt-get install rsync borgbackup"
    ))
    
    # CP-003: Recent backups exist (CP-9)
    backup_recent = False
    if existing_backup_dirs:
        for backup_dir in existing_backup_dirs[:2]:
            result = run_command(f"find {backup_dir} -type f -mtime -7 2>/dev/null | head -1")
            if result.stdout.strip():
                backup_recent = True
                break
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CP (Contingency Planning)",
        status="Pass" if backup_recent else "Warning",
        message=f"{get_nist_id('CP', 3)}: Recent backups present (CP-9)",
        details="Backups within 7 days" if backup_recent else "No recent backups",
        remediation="Perform regular backups"
    ))
    
    # CP-004: Backup scripts/cron configured (CP-9)
    backup_cron = run_command("crontab -l 2>/dev/null | grep -iE 'backup|rsync|tar' | wc -l").stdout.strip()
    has_backup_cron = safe_int_parse(backup_cron) > 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CP (Contingency Planning)",
        status="Pass" if has_backup_cron else "Warning",
        message=f"{get_nist_id('CP', 4)}: Automated backups scheduled (CP-9)",
        details="Backup jobs in cron" if has_backup_cron else "No scheduled backups",
        remediation="Schedule regular backups in crontab"
    ))
    
    # CP-005: Contingency plan documentation (CP-2)
    contingency_docs = [
        "/etc/security/contingency-plan.txt",
        "/root/disaster-recovery.txt",
        "/usr/share/doc/dr-plan.txt"
    ]
    has_contingency = any(os.path.exists(doc) for doc in contingency_docs)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CP (Contingency Planning)",
        status="Info",
        message=f"{get_nist_id('CP', 5)}: Contingency plan documented (CP-2)",
        details="Plan exists" if has_contingency else "No documented plan",
        remediation="Create contingency/disaster recovery plan"
    ))
    
    # MA-001: System maintenance window (MA-2)
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - MA (Maintenance)",
        status="Info",
        message=f"{get_nist_id('MA', 1)}: Scheduled maintenance window (MA-2)",
        details="Review maintenance procedures",
        remediation="Document maintenance windows and procedures"
    ))
    
    # MA-002: Maintenance tools controlled (MA-3)
    maintenance_tools = ["screen", "tmux"]
    maint_tools_installed = [tool for tool in maintenance_tools if command_exists(tool)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - MA (Maintenance)",
        status="Pass" if maint_tools_installed else "Info",
        message=f"{get_nist_id('MA', 2)}: Maintenance session tools (MA-3)",
        details=f"Available: {', '.join(maint_tools_installed)}" if maint_tools_installed else "None",
        remediation="Install screen or tmux for maintenance sessions"
    ))
    
    # MA-003: System documentation (MA-5)
    doc_locations = ["/usr/share/doc", "/usr/local/share/doc"]
    has_documentation = any(os.path.exists(loc) and os.listdir(loc) for loc in doc_locations)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - MA (Maintenance)",
        status="Pass" if has_documentation else "Info",
        message=f"{get_nist_id('MA', 3)}: System documentation present (MA-5)",
        details="Documentation directories exist" if has_documentation else "Limited docs",
        remediation="Maintain system documentation"
    ))
    
    # MP-001: Removable media detection (MP-2, MP-7)
    removable_media = run_command("lsblk 2>/dev/null | grep -c 'sd[b-z]\\|usb'").stdout.strip()
    try:
        removable_count = int(removable_media) if removable_media and removable_media.isdigit() else 0
        has_removable = removable_count > 0
    except (ValueError, AttributeError):
        removable_count = 0
        has_removable = False
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - MP (Media Protection)",
        status="Info" if has_removable else "Pass",
        message=f"{get_nist_id('MP', 1)}: Removable media present (MP-2)",
        details=f"{removable_count} removable devices" if has_removable else "None detected",
        remediation="Control and monitor removable media usage"
    ))
    
    # MP-002: USB storage module status (MP-7)
    usb_storage_loaded = run_command("lsmod | grep -c usb_storage").stdout.strip()
    usb_loaded = safe_int_parse(usb_storage_loaded) > 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - MP (Media Protection)",
        status="Warning" if usb_loaded else "Pass",
        message=f"{get_nist_id('MP', 2)}: USB storage module status (MP-7)",
        details="USB storage module loaded" if usb_loaded else "Module not loaded",
        remediation="Consider disabling USB storage if not needed"
    ))
    
    # MP-003: Media sanitization tools (MP-6)
    sanitization_tools = ["shred", "wipe", "dd"]
    sanit_tools_available = [tool for tool in sanitization_tools if command_exists(tool)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - MP (Media Protection)",
        status="Pass" if len(sanit_tools_available) >= 2 else "Warning",
        message=f"{get_nist_id('MP', 3)}: Media sanitization tools (MP-6)",
        details=f"Available: {', '.join(sanit_tools_available)}",
        remediation="Ensure shred and dd are available"
    ))
    
    # PE-001: Physical security documentation (PE-1)
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - PE (Physical & Environmental)",
        status="Info",
        message=f"{get_nist_id('PE', 1)}: Physical security policy (PE-1)",
        details="Review physical security controls",
        remediation="Document physical security procedures"
    ))
    
    # PE-002: Power management (PE-11)
    power_management = command_exists("systemctl") and run_command("systemctl status systemd-logind 2>/dev/null").returncode == 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - PE (Physical & Environmental)",
        status="Pass" if power_management else "Info",
        message=f"{get_nist_id('PE', 2)}: Power management configured (PE-11)",
        details="Power management active" if power_management else "Review configuration",
        remediation="Configure power management policies"
    ))
    
    # RA-001: Vulnerability scanning capability (RA-5)
    vuln_scanners = ["lynis", "openvas", "nessus"]
    vuln_tools = [tool for tool in vuln_scanners if check_package_installed(tool, os_info) or command_exists(tool)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - RA (Risk Assessment)",
        status="Pass" if vuln_tools else "Warning",
        message=f"{get_nist_id('RA', 1)}: Vulnerability scanning tools (RA-5)",
        details=f"Installed: {', '.join(vuln_tools)}" if vuln_tools else "No scanners",
        remediation=remediation_for("lynis")
    ))
    
    # RA-002: Risk assessment documentation (RA-3)
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - RA (Risk Assessment)",
        status="Info",
        message=f"{get_nist_id('RA', 2)}: Risk assessment process (RA-3)",
        details="Review risk assessment procedures",
        remediation="Conduct and document risk assessment"
    ))


# ============================================================================
# NIST SA - System and Services Acquisition
# Phase 1 Gap: Software integrity, supply chain security
# ============================================================================

def check_system_services_acquisition(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    NIST SP 800-53 SA family: System and Services Acquisition controls.
    Checks software integrity verification, package provenance, and
    supply chain security measures.
    """
    cache = shared_data.get('cache')

    # --- SA-10: Developer Configuration Management ---
    # Check if package manager verifies signatures
    if os_info.package_manager == "apt":
        # Check APT verification settings
        apt_conf = read_file_safe("/etc/apt/apt.conf.d/99verify-peer") or ""
        apt_main = read_file_safe("/etc/apt/apt.conf") or ""
        # Check that AllowUnauthenticated is not set
        no_auth = "AllowUnauthenticated" in apt_main and "true" in apt_main.lower()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - SA (System & Services Acquisition)",
            status="Fail" if no_auth else "Pass",
            message=f"{get_nist_id('SA', 1)}: SA-10 Package signature verification (APT)",
            details=f"AllowUnauthenticated: {'ENABLED (insecure)' if no_auth else 'not set (secure)'}",
            remediation="Remove 'AllowUnauthenticated' from /etc/apt/apt.conf",
            severity="High"
        ))

        # Check for GPG keys in trusted keyring
        result = run_command("apt-key list 2>/dev/null | grep -c 'pub' || "
                            "gpg --list-keys --keyring /etc/apt/trusted.gpg 2>/dev/null | grep -c 'pub'",
                            check=False)
        key_count = safe_int_parse(result.stdout.strip(), default=0)
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - SA (System & Services Acquisition)",
            status="Pass" if key_count > 0 else "Warning",
            message=f"{get_nist_id('SA', 2)}: SA-10 APT repository GPG keys",
            details=f"Trusted GPG keys: {key_count}",
            remediation="Import repository GPG keys: apt-key adv --keyserver keyserver.ubuntu.com --recv-keys <KEY>",
            severity="Medium"
        ))

    elif os_info.package_manager in ("yum", "dnf"):
        # Check gpgcheck enabled
        yum_conf = read_file_safe("/etc/yum.conf") or read_file_safe("/etc/dnf/dnf.conf") or ""
        gpgcheck = True  # Default is enabled
        for line in yum_conf.splitlines():
            if line.strip().startswith("gpgcheck") and "0" in line:
                gpgcheck = False
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - SA (System & Services Acquisition)",
            status="Pass" if gpgcheck else "Fail",
            message=f"{get_nist_id('SA', 1)}: SA-10 Package GPG verification ({os_info.package_manager})",
            details=f"gpgcheck: {'enabled' if gpgcheck else 'DISABLED'}",
            remediation=f"Set gpgcheck=1 in /etc/{os_info.package_manager}.conf",
            severity="High"
        ))

        # Check repo_gpgcheck
        repo_gpg = "repo_gpgcheck=1" in yum_conf
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - SA (System & Services Acquisition)",
            status="Pass" if repo_gpg else "Warning",
            message=f"{get_nist_id('SA', 2)}: SA-10 Repository metadata GPG verification",
            details=f"repo_gpgcheck: {'enabled' if repo_gpg else 'not explicitly enabled'}",
            remediation=f"Add repo_gpgcheck=1 to /etc/{os_info.package_manager}.conf",
            severity="Medium"
        ))

    # --- SA-11: Developer Security Testing ---
    # Check for presence of security testing/scanning tools
    security_tools = {
        "lynis": "Security auditing tool",
        "chkrootkit": "Rootkit detection",
        "rkhunter": "Rootkit hunter",
        "clamav": "Antivirus scanning",
        "aide": "File integrity monitoring",
        "tripwire": "File integrity monitoring",
        "oscap": "SCAP compliance scanning",
    }
    found_tools = []
    for tool, desc in security_tools.items():
        if command_exists(tool):
            found_tools.append(f"{tool} ({desc})")

    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SA (System & Services Acquisition)",
        status="Pass" if len(found_tools) >= 2 else ("Warning" if found_tools else "Fail"),
        message=f"{get_nist_id('SA', 3)}: SA-11 Security assessment tools availability",
        details=f"Found {len(found_tools)}/{len(security_tools)}: "
                f"{', '.join(found_tools) if found_tools else 'none detected'}",
        remediation="Install security assessment tools: apt install lynis aide rkhunter",
        severity="Medium"
    ))

    # --- SA-12: Supply Chain Protection ---
    # Verify package repositories are using HTTPS
    repo_files = []
    repo_dirs = ["/etc/apt/sources.list.d", "/etc/yum.repos.d"]
    main_sources = ["/etc/apt/sources.list"]

    http_repos = 0
    https_repos = 0
    for src in main_sources:
        content = read_file_safe(src)
        if content:
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    if 'http://' in line:
                        http_repos += 1
                    elif 'https://' in line:
                        https_repos += 1

    for rdir in repo_dirs:
        if os.path.isdir(rdir):
            try:
                for rf in os.listdir(rdir):
                    content = read_file_safe(os.path.join(rdir, rf))
                    if content:
                        for line in content.splitlines():
                            if 'http://' in line and not line.strip().startswith('#'):
                                http_repos += 1
                            elif 'https://' in line and not line.strip().startswith('#'):
                                https_repos += 1
            except (PermissionError, OSError):
                pass

    total_repos = http_repos + https_repos
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SA (System & Services Acquisition)",
        status="Pass" if http_repos == 0 and https_repos > 0 else (
            "Warning" if http_repos > 0 else "Info"),
        message=f"{get_nist_id('SA', 4)}: SA-12 Repository transport security",
        details=f"HTTPS repos: {https_repos}, HTTP (insecure) repos: {http_repos}",
        remediation="Convert all repository URLs from http:// to https://",
        severity="Medium"
    ))

    # --- SA-22: Unsupported System Components ---
    # Check if running an end-of-life OS version
    result = run_command("cat /etc/os-release 2>/dev/null", check=False)
    eol_warning = False
    if result.returncode == 0:
        os_id = ""
        os_version = ""
        for line in result.stdout.splitlines():
            if line.startswith("ID="):
                os_id = line.split('=', 1)[1].strip().strip('"')
            if line.startswith("VERSION_ID="):
                os_version = line.split('=', 1)[1].strip().strip('"')
        # Known EOL versions (simplified check)
        eol_versions = {
            "ubuntu": ["14.04", "16.04", "18.04", "19.04", "19.10", "21.04", "21.10",
                        "22.10", "23.04", "23.10"],
            "debian": ["8", "9", "10"],
            "centos": ["6", "7", "8"],
            "rhel": ["6", "7"],
        }
        if os_id in eol_versions and os_version in eol_versions.get(os_id, []):
            eol_warning = True

    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - SA (System & Services Acquisition)",
        status="Fail" if eol_warning else "Pass",
        message=f"{get_nist_id('SA', 5)}: SA-22 Unsupported system components",
        details=f"OS: {os_id} {os_version} - "
                f"{'END OF LIFE - upgrade required' if eol_warning else 'supported version'}",
        remediation="Upgrade to a supported OS version to receive security patches",
        severity="Critical" if eol_warning else "Low"
    ))


# ============================================================================
# NIST CA - Assessment, Authorization, and Monitoring
# Phase 1 Gap: Vulnerability scanning, audit readiness
# ============================================================================

def check_assessment_authorization(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    NIST SP 800-53 CA family: Assessment, Authorization, and Monitoring.
    Checks for vulnerability scanning capability, security assessment
    readiness, and continuous monitoring configuration.
    """
    cache = shared_data.get('cache')

    # --- CA-2: Security Assessments ---
    # Check for SCAP/OpenSCAP capability
    oscap_available = command_exists("oscap")
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CA (Assessment & Authorization)",
        status="Pass" if oscap_available else "Warning",
        message=f"{get_nist_id('CA', 1)}: CA-2 SCAP compliance scanning capability",
        details=f"OpenSCAP: {'installed' if oscap_available else 'not installed'}",
        remediation=remediation_for("openscap"),
        severity="Medium"
    ))

    # --- CA-7: Continuous Monitoring ---
    # Check for file integrity monitoring
    fim_tools = {"aide": "/etc/aide/aide.conf", "tripwire": "/etc/tripwire",
                 "osquery": "/etc/osquery", "wazuh-agent": "/var/ossec/etc/ossec.conf",
                 "ossec-agent": "/var/ossec/etc/ossec.conf"}
    fim_active = []
    for tool, config_path in fim_tools.items():
        if command_exists(tool) or os.path.exists(config_path):
            fim_active.append(tool)

    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CA (Assessment & Authorization)",
        status="Pass" if fim_active else "Fail",
        message=f"{get_nist_id('CA', 2)}: CA-7 File integrity monitoring",
        details=f"FIM tools: {', '.join(fim_active) if fim_active else 'none detected'}",
        remediation=remediation_for("aide"),
        severity="High"
    ))

    # --- CA-7: Continuous Monitoring - Log forwarding ---
    log_forwarders = {"rsyslog": "/etc/rsyslog.conf", "syslog-ng": "/etc/syslog-ng/syslog-ng.conf",
                      "fluentd": "/etc/td-agent", "filebeat": "/etc/filebeat",
                      "journald-upload": "/etc/systemd/journal-upload.conf"}
    active_forwarders = []
    for fwd, config in log_forwarders.items():
        if command_exists(fwd) or os.path.exists(config):
            active_forwarders.append(fwd)

    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CA (Assessment & Authorization)",
        status="Pass" if active_forwarders else "Warning",
        message=f"{get_nist_id('CA', 3)}: CA-7 Log forwarding/aggregation",
        details=f"Log forwarders: {', '.join(active_forwarders) if active_forwarders else 'none detected'}",
        remediation="Configure centralized log forwarding via rsyslog, filebeat, or fluentd",
        severity="Medium"
    ))

    # --- CA-8: Penetration Testing readiness ---
    # Check for common pentest/assessment tools
    pentest_tools = ["nmap", "nikto", "lynis", "testssl.sh", "testssl"]
    found_pentest = [t for t in pentest_tools if command_exists(t)]
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CA (Assessment & Authorization)",
        status="Info",
        message=f"{get_nist_id('CA', 4)}: CA-8 Security assessment tool availability",
        details=f"Available: {', '.join(found_pentest) if found_pentest else 'none detected'}",
        remediation="Install assessment tools as needed for periodic security testing",
        severity="Low"
    ))

    # --- CA-9: Internal System Connections ---
    # Check for unexpected listening services
    result = run_command("ss -tuln 2>/dev/null | grep LISTEN | wc -l", check=False)
    listen_count = safe_int_parse(result.stdout.strip(), default=0)
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NIST - CA (Assessment & Authorization)",
        status="Pass" if listen_count <= 15 else ("Warning" if listen_count <= 30 else "Fail"),
        message=f"{get_nist_id('CA', 5)}: CA-9 Internal system connections audit",
        details=f"Listening services: {listen_count} (review for unauthorized services)",
        remediation="Audit listening services with 'ss -tuln' and disable unnecessary ones",
        severity="Medium"
    ))


# ============================================================================
# Main Orchestration Function
# ============================================================================

def run_checks(shared_data: Dict[str, Any]) -> List[AuditResult]:
    """
    Main entry point for NIST module
    Executes all control family checks and returns results
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
    
    print(f"\n[{MODULE_NAME}] " + "="*70)
    print(f"[{MODULE_NAME}] NIST SECURITY CONTROLS AUDIT - Comprehensive Edition")
    print(f"[{MODULE_NAME}] " + "="*70)
    print(f"[{MODULE_NAME}] Version: {MODULE_VERSION}")
    print(f"[{MODULE_NAME}] Standards: NIST 800-53 Rev 5, CSF 2.0, 800-171 Rev 2")
    print(f"[{MODULE_NAME}] Control Families: AC, AU, CM, IA, IR, SC, SI, CP, MA, MP, PE, RA, SA, CA")
    print(f"[{MODULE_NAME}] Target: 160+ Comprehensive Security Audit Checks")
    print(f"[{MODULE_NAME}] " + "="*70 + "\n")
    
    is_root = shared_data.get("is_root", os.geteuid() == 0)
    if not is_root:
        print(f"[{MODULE_NAME}]   Note: Running without root privileges")
        print(f"[{MODULE_NAME}] Some checks require elevated privileges for full coverage\n")
    
    try:
        # Execute all control family checks
        check_access_control(results, shared_data, os_info)
        check_audit_accountability(results, shared_data, os_info)
        check_configuration_management(results, shared_data, os_info)
        check_identification_authentication(results, shared_data, os_info)
        check_incident_response(results, shared_data, os_info)
        check_system_communications_protection(results, shared_data, os_info)
        check_system_information_integrity(results, shared_data, os_info)
        check_additional_controls(results, shared_data, os_info)
        # Phase 1 new control families
        check_system_services_acquisition(results, shared_data, os_info)
        check_assessment_authorization(results, shared_data, os_info)
        
    except Exception as e:
        print(f"[{MODULE_NAME}]  Error during audit execution: {str(e)}")
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Error",
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
    
    print(f"\n[{MODULE_NAME}] " + "="*70)
    print(f"[{MODULE_NAME}] NIST AUDIT COMPLETED")
    print(f"[{MODULE_NAME}] " + "="*70)
    print(f"[{MODULE_NAME}] Total Security Audit Checks Executed: {len(results)}")
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
# v3.3 EXPANSION - NIST Deep Coverage
# ----------------------------------------------------------------------------
# Synopsis:
#   Adds depth across:
#   - NIST SP 800-207 Zero Trust Architecture (ZTA) indicators
#   - NIST SP 800-161 Supply Chain Risk Management (SCRM)
#   - NIST CSF 2.0 Govern function indicators
#   - NIST SP 800-53 R5 additional control families:
#     * PE (Physical and Environmental Protection) - technical indicators
#     * PM (Program Management) - technical indicators
#     * SR (Supply Chain Risk Management)
#   - NIST SP 800-171 Rev 3 advanced practices
#
# Notes:
#   - Uses module_helpers + AuditResult directly
#   - Cross-references include NIST 800-53, CSF 2.0, 800-171, 800-207
#   - Standalone module verification proven; integration via run_checks chaining
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


def _v33_nist_result(category, status, message, severity="Medium",
                     details="", remediation="", cross_references=None):
    """Build AuditResult for NIST v3.3 expansion."""
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


def _check_nist_v33_zero_trust(results, shared_data, os_info):
    """NIST SP 800-207 - Zero Trust Architecture indicators."""

    # ZTA tenet 1 - All data sources and computing services are resources
    # Detect resource enumeration tooling
    enumeration = {
        "auditd": _v33_systemd_active("auditd.service") == "active",
        "osquery": (
            _v33_command_available("osqueryi") or
            _v33_systemd_active("osqueryd.service") == "active"
        ),
        "wazuh": _v33_file_exists("/var/ossec/etc/ossec.conf"),
    }
    detected = [k for k, v in enumeration.items() if v]
    results.append(_v33_nist_result(
        "NIST 800-207 v3.3 - Tenet 1",
        "Pass" if detected else "Warning",
        "ZTA Tenet 1: Resource enumeration capability",
        severity="Medium",
        details=f"Detected: {detected or 'none'}",
        remediation=(
            "Deploy resource enumeration: osquery for endpoint inventory, "
            "auditd for resource access logging"
        ),
        cross_references={
            "NIST-800-207": "Tenet 1", "NIST": "CM-8", "CSF": "ID.AM",
        },
    ))

    # ZTA tenet 2 - All communication is secured regardless of location
    # TLS minimum, OpenSSL system-wide config
    openssl_cnf = (
        _v33_read_file_safe("/etc/ssl/openssl.cnf") or
        _v33_read_file_safe("/etc/pki/tls/openssl.cnf")
    )
    has_tls12 = "TLSv1.2" in openssl_cnf or "MinProtocol" in openssl_cnf
    has_seclevel = "SECLEVEL=" in openssl_cnf
    results.append(_v33_nist_result(
        "NIST 800-207 v3.3 - Tenet 2",
        "Pass" if (has_tls12 and has_seclevel) else "Warning",
        "ZTA Tenet 2: All communication secured (TLS 1.2+, SECLEVEL set)",
        severity="High",
        details=f"TLS 1.2+ minimum: {has_tls12}, SECLEVEL set: {has_seclevel}",
        remediation=(
            "In /etc/ssl/openssl.cnf [system_default_sect]: "
            "MinProtocol = TLSv1.2; CipherString = DEFAULT@SECLEVEL=2"
        ),
        cross_references={
            "NIST-800-207": "Tenet 2", "NIST": "SC-8(1)", "CSF": "PR.DS-2",
        },
    ))

    # ZTA tenet 3 - Access to individual resources granted on per-session basis
    # SSH MaxSessions/UseConnectionMultiplexing/persistent connections
    sshd = _v33_read_file_safe("/etc/ssh/sshd_config")
    cai_match = re.search(r"^\s*ClientAliveInterval\s+(\d+)", sshd, re.MULTILINE)
    cai = int(cai_match.group(1)) if cai_match else 0
    cam_match = re.search(r"^\s*ClientAliveCountMax\s+(\d+)", sshd, re.MULTILINE)
    cam = int(cam_match.group(1)) if cam_match else 3
    session_bounded = 0 < cai <= 600
    results.append(_v33_nist_result(
        "NIST 800-207 v3.3 - Tenet 3",
        "Pass" if session_bounded else "Warning",
        "ZTA Tenet 3: Per-session resource access (SSH idle timeout)",
        severity="Medium",
        details=f"ClientAliveInterval={cai}, ClientAliveCountMax={cam}",
        remediation=(
            "In /etc/ssh/sshd_config: ClientAliveInterval 300; "
            "ClientAliveCountMax 0"
        ),
        cross_references={
            "NIST-800-207": "Tenet 3", "NIST": "AC-12", "CSF": "PR.AC-12",
        },
    ))

    # ZTA tenet 4 - Access determined by dynamic policy
    # PAM faillock with dynamic backoff, fail2ban, advanced PAM
    f2b_active = _v33_systemd_active("fail2ban.service") == "active"
    pam_faillock = False
    for pf in ["/etc/pam.d/system-auth", "/etc/pam.d/common-auth",
               "/etc/pam.d/password-auth"]:
        if "pam_faillock" in _v33_read_file_safe(pf):
            pam_faillock = True
            break
    dynamic_indicators = sum([f2b_active, pam_faillock])
    results.append(_v33_nist_result(
        "NIST 800-207 v3.3 - Tenet 4",
        "Pass" if dynamic_indicators >= 1 else "Warning",
        f"ZTA Tenet 4: Dynamic policy enforcement ({dynamic_indicators})",
        severity="Medium",
        details=f"fail2ban: {f2b_active}, pam_faillock: {pam_faillock}",
        remediation=(
            "Enable dynamic backoff: apt-get install -y fail2ban; "
            "configure pam_faillock.so in PAM stack"
        ),
        cross_references={
            "NIST-800-207": "Tenet 4", "NIST": "AC-7", "CSF": "PR.AC-7",
        },
    ))

    # ZTA tenet 5 - Monitor and measure integrity
    fim = (
        _v33_file_exists("/var/lib/aide/aide.db") or
        _v33_file_exists("/var/lib/aide/aide.db.gz") or
        _v33_file_exists("/etc/tripwire/tw.cfg") or
        _v33_file_exists("/var/ossec/etc/ossec.conf")
    )
    results.append(_v33_nist_result(
        "NIST 800-207 v3.3 - Tenet 5",
        "Pass" if fim else "Fail",
        "ZTA Tenet 5: Integrity monitoring active (FIM database present)",
        severity="High",
        details=f"AIDE/Tripwire/Wazuh database present: {fim}",
        remediation=remediation_for("aide"),
        cross_references={
            "NIST-800-207": "Tenet 5", "NIST": "SI-7", "CSF": "DE.CM-4",
        },
    ))

    # ZTA tenet 6 - All resource authentication and authorization is dynamic
    pam_files_to_check = ["/etc/pam.d/sshd", "/etc/pam.d/system-auth",
                           "/etc/pam.d/common-auth"]
    mfa_modules = ["pam_google_authenticator", "pam_yubico", "pam_oath",
                   "pam_duo", "pam_u2f", "pam_pkcs11", "pam_radius_auth"]
    detected_mfa = set()
    for pf in pam_files_to_check:
        c = _v33_read_file_safe(pf)
        for mod in mfa_modules:
            if mod + ".so" in c:
                detected_mfa.add(mod.replace("pam_", ""))
    results.append(_v33_nist_result(
        "NIST 800-207 v3.3 - Tenet 6",
        "Pass" if detected_mfa else "Warning",
        f"ZTA Tenet 6: Dynamic auth ({len(detected_mfa)} MFA modules)",
        severity="High",
        details=f"Detected: {sorted(detected_mfa) or 'none'}",
        remediation=(
            "apt-get install -y libpam-google-authenticator. "
            "Configure pam_google_authenticator.so in /etc/pam.d/sshd"
        ),
        cross_references={
            "NIST-800-207": "Tenet 6", "NIST": "IA-2(1)", "CSF": "PR.AC-7",
        },
    ))

    # ZTA tenet 7 - Collect data on current state of assets
    audit_log = _v33_file_exists("/var/log/audit/audit.log")
    rsyslog = _v33_systemd_active("rsyslog.service") == "active"
    journald = _v33_systemd_active("systemd-journald.service") == "active"
    layers = sum([audit_log, rsyslog, journald])
    results.append(_v33_nist_result(
        "NIST 800-207 v3.3 - Tenet 7",
        "Pass" if layers >= 2 else "Warning",
        f"ZTA Tenet 7: Continuous monitoring layers ({layers}/3)",
        severity="High",
        details=f"audit.log: {audit_log}, rsyslog: {rsyslog}, journald: {journald}",
        remediation=(
            "Enable all 3 logging layers for resilient continuous monitoring"
        ),
        cross_references={
            "NIST-800-207": "Tenet 7", "NIST": "AU-2", "CSF": "DE.CM",
        },
    ))


def _check_nist_v33_scrm(results, shared_data, os_info):
    """NIST SP 800-161 - Supply Chain Risk Management."""

    # SR-3 - Supply chain controls and processes (package signing)
    apt_keyring = (
        _v33_directory_exists("/etc/apt/trusted.gpg.d") or
        _v33_directory_exists("/etc/apt/keyrings")
    )
    rpm_gpgcheck = False
    yum_conf = (
        _v33_read_file_safe("/etc/yum.conf") or
        _v33_read_file_safe("/etc/dnf/dnf.conf")
    )
    if "gpgcheck=1" in yum_conf:
        rpm_gpgcheck = True
    pacman_keyring = _v33_directory_exists("/etc/pacman.d/gnupg")
    sig_indicators = sum([apt_keyring, rpm_gpgcheck, pacman_keyring])
    results.append(_v33_nist_result(
        "NIST SR-3 v3.3 - Supply Chain Controls",
        "Pass" if sig_indicators >= 1 else "Fail",
        f"SR-3 Package signature verification configured ({sig_indicators})",
        severity="High",
        details=(
            f"apt keyring: {apt_keyring}, rpm gpgcheck: {rpm_gpgcheck}, "
            f"pacman keyring: {pacman_keyring}"
        ),
        remediation=(
            "Verify gpgcheck=1 in /etc/yum.conf or /etc/dnf/dnf.conf; "
            "ensure /etc/apt/trusted.gpg.d is populated; "
            "pacman-key --init"
        ),
        cross_references={
            "NIST-800-161": "SR-3", "NIST": "SR-3", "CSF": "ID.SC-3",
        },
    ))

    # SR-4 - Provenance (software bill of materials capability)
    sbom_tools = {
        "syft": _v33_command_available("syft"),
        "trivy": _v33_command_available("trivy"),
        "grype": _v33_command_available("grype"),
        "cyclonedx-py": _v33_command_available("cyclonedx-py"),
    }
    detected_sbom = [k for k, v in sbom_tools.items() if v]
    results.append(_v33_nist_result(
        "NIST SR-4 v3.3 - Provenance",
        "Pass" if detected_sbom else "Info",
        f"SR-4 SBOM/provenance tools ({len(detected_sbom)})",
        severity="Medium",
        details=f"Detected: {detected_sbom or 'none'}",
        remediation=(
            "Install Syft for SBOM generation: "
            "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin"
        ),
        cross_references={
            "NIST-800-161": "SR-4", "NIST": "SR-4", "CSF": "ID.SC-4",
        },
    ))

    # SR-9 - Tamper resistance and detection (FIM)
    fim_present = (
        _v33_file_exists("/var/lib/aide/aide.db") or
        _v33_file_exists("/var/lib/aide/aide.db.gz") or
        _v33_file_exists("/etc/tripwire/tw.cfg") or
        _v33_file_exists("/var/ossec/etc/ossec.conf")
    )
    results.append(_v33_nist_result(
        "NIST SR-9 v3.3 - Tamper Resistance",
        "Pass" if fim_present else "Warning",
        "SR-9 File integrity monitoring (tamper detection)",
        severity="High",
        details=f"FIM database present: {fim_present}",
        remediation=remediation_for("aide"),
        cross_references={
            "NIST-800-161": "SR-9", "NIST": "SR-9", "CSF": "DE.CM-7",
        },
    ))

    # SR-11 - Component authenticity (package transaction logs)
    pkg_logs = []
    for log in ["/var/log/dpkg.log", "/var/log/yum.log",
                "/var/log/dnf.log", "/var/log/zypp/history"]:
        if _v33_file_exists(log):
            pkg_logs.append(log)
    results.append(_v33_nist_result(
        "NIST SR-11 v3.3 - Component Authenticity",
        "Pass" if pkg_logs else "Warning",
        f"SR-11 Package transaction logs ({len(pkg_logs)})",
        severity="Medium",
        details=f"Logs: {pkg_logs}",
        remediation=(
            "Package install/remove logging is automatic. Forward to SIEM "
            "for tamper-evidence."
        ),
        cross_references={
            "NIST-800-161": "SR-11", "NIST": "SR-11", "CSF": "PR.IP-3",
        },
    ))


def _check_nist_v33_csf2_govern(results, shared_data, os_info):
    """NIST CSF 2.0 - Govern function (technical indicators)."""

    # GV.OC - Organizational Context: documented baseline (auditd)
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
    results.append(_v33_nist_result(
        "NIST CSF 2.0 v3.3 - GV.OC",
        "Pass" if (auditd_active and audit_rules_count >= 25) else "Warning",
        f"GV.OC Documented baseline (auditd active, {audit_rules_count} rules)",
        severity="Medium",
        details=(
            f"auditd active: {auditd_active}, rules: {audit_rules_count}"
        ),
        remediation=(
            "Deploy CIS-recommended ruleset (~75 rules) and document baseline"
        ),
        cross_references={
            "NIST-CSF-2.0": "GV.OC", "NIST": "CA-2",
        },
    ))

    # GV.RM - Risk Management: vulnerability scanners
    scanners = ["lynis", "oscap", "trivy", "nuclei", "openvas-scanner"]
    detected = [s for s in scanners if _v33_command_available(s)]
    results.append(_v33_nist_result(
        "NIST CSF 2.0 v3.3 - GV.RM",
        "Pass" if detected else "Warning",
        f"GV.RM Risk management scanners ({len(detected)})",
        severity="Medium",
        details=f"Detected: {detected}",
        remediation=remediation_for("lynis"),
        cross_references={
            "NIST-CSF-2.0": "GV.RM", "NIST": "RA-3, RA-5",
        },
    ))

    # GV.SC - Supply Chain Risk Management: signature verification (cross-ref)
    apt_keyring = (
        _v33_directory_exists("/etc/apt/trusted.gpg.d") or
        _v33_directory_exists("/etc/apt/keyrings")
    )
    rpm_gpgcheck = False
    yum_conf = (
        _v33_read_file_safe("/etc/yum.conf") or
        _v33_read_file_safe("/etc/dnf/dnf.conf")
    )
    if "gpgcheck=1" in yum_conf:
        rpm_gpgcheck = True
    sig_ok = apt_keyring or rpm_gpgcheck
    results.append(_v33_nist_result(
        "NIST CSF 2.0 v3.3 - GV.SC",
        "Pass" if sig_ok else "Fail",
        f"GV.SC Supply chain signature verification: {sig_ok}",
        severity="High",
        details=f"apt keyring: {apt_keyring}, rpm gpgcheck: {rpm_gpgcheck}",
        cross_references={
            "NIST-CSF-2.0": "GV.SC", "NIST": "SR-3", "CSF": "ID.SC-3",
        },
    ))

    # GV.PO - Policy: PAM stack (organizational policy enforcement)
    pam_dir = "/etc/pam.d"
    pam_files = (
        _v33_list_directory(pam_dir) if _v33_directory_exists(pam_dir) else []
    )
    results.append(_v33_nist_result(
        "NIST CSF 2.0 v3.3 - GV.PO",
        "Pass" if len(pam_files) >= 10 else "Warning",
        f"GV.PO Policy enforcement modules ({len(pam_files)})",
        severity="Medium",
        details=f"PAM files: {len(pam_files)}",
        cross_references={
            "NIST-CSF-2.0": "GV.PO", "NIST": "PL-1",
        },
    ))


def _check_nist_v33_pe_environmental(results, shared_data, os_info):
    """NIST 800-53 R5 - PE (Physical and Environmental) technical indicators."""

    # PE-3 - Physical Access Control: USB device control
    usbguard_active = _v33_systemd_active("usbguard.service") == "active"
    usb_storage_blocked = False
    if _v33_directory_exists("/etc/modprobe.d"):
        for f in _v33_list_directory("/etc/modprobe.d"):
            c = _v33_read_file_safe(os.path.join("/etc/modprobe.d", f))
            if re.search(r"^\s*(blacklist|install)\s+usb-storage", c, re.MULTILINE):
                usb_storage_blocked = True
                break
    pe3_ok = usbguard_active or usb_storage_blocked
    results.append(_v33_nist_result(
        "NIST PE-3 v3.3 - Physical Access",
        "Pass" if pe3_ok else "Info",
        f"PE-3 USB/removable media control",
        severity="Medium",
        details=(
            f"USBGuard: {usbguard_active}, "
            f"usb-storage blocked: {usb_storage_blocked}"
        ),
        remediation=remediation_for("usbguard"),
        cross_references={
            "NIST": "PE-3", "STIG": "V-230501", "CSF": "PR.PT-2",
        },
    ))

    # PE-6 - Monitoring Physical Access: auditd mount tracking
    audit_rules = ""
    if _v33_directory_exists(rules_d := "/etc/audit/rules.d"):
        for f in _v33_list_directory(rules_d):
            if f.endswith(".rules"):
                audit_rules += "\n" + _v33_read_file_safe(
                    os.path.join(rules_d, f)
                )
    has_mount_audit = "mount" in audit_rules
    results.append(_v33_nist_result(
        "NIST PE-6 v3.3 - Physical Monitoring",
        "Pass" if has_mount_audit else "Info",
        f"PE-6 Mount/removable-media audit",
        severity="Low",
        details=f"mount audit rule: {has_mount_audit}",
        remediation=(
            "-a always,exit -F arch=b64 -S mount -F auid>=1000 "
            "-F auid!=4294967295 -k mounts"
        ),
        cross_references={
            "NIST": "PE-6", "CSF": "DE.CM-2",
        },
    ))


def _check_nist_v33_pm_program(results, shared_data, os_info):
    """NIST 800-53 R5 - PM (Program Management) technical indicators."""

    # PM-5 - System Inventory: package manager presence
    pkg_managers = {
        "dpkg": _v33_command_available("dpkg"),
        "rpm": _v33_command_available("rpm"),
        "pacman": _v33_command_available("pacman"),
        "apk": _v33_command_available("apk"),
        "zypper": _v33_command_available("zypper"),
    }
    detected = [k for k, v in pkg_managers.items() if v]
    results.append(_v33_nist_result(
        "NIST PM-5 v3.3 - System Inventory",
        "Pass" if detected else "Fail",
        f"PM-5 Package manager(s) for inventory ({len(detected)})",
        severity="Medium",
        details=f"Detected: {detected}",
        cross_references={
            "NIST": "PM-5", "CSF": "ID.AM-1",
        },
    ))

    # PM-12 - Insider Threat Program: comprehensive auditd
    audit_rules_d = "/etc/audit/rules.d"
    insider_threat_keys = ["privileged", "perm_mod", "execve", "session"]
    keys_present = 0
    if _v33_directory_exists(audit_rules_d):
        all_rules = ""
        for f in _v33_list_directory(audit_rules_d):
            if f.endswith(".rules"):
                all_rules += _v33_read_file_safe(
                    os.path.join(audit_rules_d, f)
                )
        keys_present = sum(1 for k in insider_threat_keys if k in all_rules)
    results.append(_v33_nist_result(
        "NIST PM-12 v3.3 - Insider Threat",
        "Pass" if keys_present >= 3 else "Warning",
        f"PM-12 Insider threat audit keys ({keys_present}/{len(insider_threat_keys)})",
        severity="High",
        details=f"Keys present: {keys_present}",
        remediation=(
            "Add CIS audit ruleset for privileged/perm_mod/execve/session"
        ),
        cross_references={
            "NIST": "PM-12", "CSF": "DE.CM-3",
        },
    ))


def _check_nist_v33_advanced_171(results, shared_data, os_info):
    """NIST SP 800-171 Rev 3 - Advanced practices (CUI protection)."""

    # 3.13.8 - Encrypted communications session keys (TLS PFS)
    sshd = _v33_read_file_safe("/etc/ssh/sshd_config")
    kex_match = re.search(r"^\s*KexAlgorithms\s+(\S+)", sshd, re.MULTILINE)
    kex = kex_match.group(1) if kex_match else ""
    pfs_kex = ["curve25519", "diffie-hellman-group16",
                "diffie-hellman-group18"]
    pfs_ok = any(p in kex for p in pfs_kex) if kex else False
    results.append(_v33_nist_result(
        "NIST 800-171 3.13.8 v3.3 - PFS",
        "Pass" if pfs_ok else "Warning",
        f"3.13.8 SSH Perfect Forward Secrecy KexAlgorithms",
        severity="High",
        details=f"KexAlgorithms: {kex or 'default'}, PFS-capable: {pfs_ok}",
        remediation=(
            "In /etc/ssh/sshd_config: KexAlgorithms curve25519-sha256,"
            "curve25519-sha256@libssh.org,diffie-hellman-group16-sha512"
        ),
        cross_references={
            "NIST-800-171": "3.13.8", "NIST": "SC-12", "CSF": "PR.DS-2",
        },
    ))

    # 3.13.11 - FIPS-validated cryptography
    fips_kernel = False
    if _v33_file_exists("/proc/sys/crypto/fips_enabled"):
        fips_kernel = _v33_read_file_safe("/proc/sys/crypto/fips_enabled").strip() == "1"
    fips_provider = False
    if _v33_command_available("openssl"):
        rc, out, _ = _v33_run_command(
            ["openssl", "list", "-providers"], timeout=5.0
        )
        if rc == 0 and "fips" in out.lower():
            fips_provider = True
    fips_active = fips_kernel or fips_provider
    results.append(_v33_nist_result(
        "NIST 800-171 3.13.11 v3.3 - FIPS",
        "Pass" if fips_active else "Info",
        f"3.13.11 FIPS-validated crypto active",
        severity="High",
        details=(
            f"Kernel FIPS: {fips_kernel}, OpenSSL FIPS provider: {fips_provider}"
        ),
        remediation=(
            "Enable FIPS mode (RHEL/Ubuntu Pro): "
            "fips-mode-setup --enable; reboot"
        ),
        cross_references={
            "NIST-800-171": "3.13.11", "NIST": "SC-13", "FIPS": "140-3",
        },
    ))

    # 3.14.1 - Identify, report, correct system flaws (vulnerability mgmt)
    update_active = (
        _v33_systemd_active("unattended-upgrades.service") == "active" or
        _v33_systemd_active("dnf-automatic-install.timer") == "active" or
        _v33_systemd_active("yum-cron.service") == "active"
    )
    results.append(_v33_nist_result(
        "NIST 800-171 3.14.1 v3.3 - Flaw Remediation",
        "Pass" if update_active else "Warning",
        f"3.14.1 Automated patch management: {update_active}",
        severity="High",
        details=f"Automation active: {update_active}",
        remediation=(
            "apt-get install -y unattended-upgrades; "
            "dpkg-reconfigure unattended-upgrades"
        ),
        cross_references={
            "NIST-800-171": "3.14.1", "NIST": "SI-2", "CSF": "PR.IP-12",
        },
    ))

    # 3.14.6 - Monitor org systems including inbound/outbound communications
    nfw_active = (
        _v33_systemd_active("ufw.service") == "active" or
        _v33_systemd_active("firewalld.service") == "active" or
        _v33_systemd_active("nftables.service") == "active"
    )
    results.append(_v33_nist_result(
        "NIST 800-171 3.14.6 v3.3 - Monitoring",
        "Pass" if nfw_active else "Fail",
        f"3.14.6 Firewall active for ingress/egress",
        severity="Critical",
        details=f"Firewall service active: {nfw_active}",
        cross_references={
            "NIST-800-171": "3.14.6", "NIST": "SC-7", "CSF": "DE.CM-1",
        },
    ))

    # 3.14.7 - Identify unauthorized use (auditd)
    audit_active = _v33_systemd_active("auditd.service") == "active"
    results.append(_v33_nist_result(
        "NIST 800-171 3.14.7 v3.3 - Unauthorized Use",
        "Pass" if audit_active else "Fail",
        f"3.14.7 auditd active for unauthorized-use detection",
        severity="High",
        details=f"auditd active: {audit_active}",
        remediation=remediation_for("auditd"),
        cross_references={
            "NIST-800-171": "3.14.7", "NIST": "AU-2", "CSF": "DE.AE",
        },
    ))


def _check_nist_v33_au_extended(results, shared_data, os_info):
    """NIST 800-53 R5 - AU (Audit and Accountability) extended."""

    # AU-3(1) - Additional audit information
    audit_rules = ""
    if _v33_directory_exists(rules_d := "/etc/audit/rules.d"):
        for f in _v33_list_directory(rules_d):
            if f.endswith(".rules"):
                audit_rules += "\n" + _v33_read_file_safe(
                    os.path.join(rules_d, f)
                )
    has_arch = "arch=b64" in audit_rules or "arch=b32" in audit_rules
    results.append(_v33_nist_result(
        "NIST AU-3(1) v3.3 - Audit Content",
        "Pass" if has_arch else "Info",
        "AU-3(1) Audit rules with architecture context",
        severity="Medium",
        details=f"arch= filters in rules: {has_arch}",
        cross_references={
            "NIST": "AU-3(1)", "CSF": "PR.PT-1",
        },
    ))

    # AU-7 - Audit Reduction and Report Generation (ausearch/aureport)
    aud_tools = {
        "ausearch": _v33_command_available("ausearch"),
        "aureport": _v33_command_available("aureport"),
        "auditctl": _v33_command_available("auditctl"),
    }
    detected = [k for k, v in aud_tools.items() if v]
    results.append(_v33_nist_result(
        "NIST AU-7 v3.3 - Audit Reduction",
        "Pass" if len(detected) >= 2 else "Warning",
        f"AU-7 Audit reduction tools ({len(detected)})",
        severity="Medium",
        details=f"Detected: {detected}",
        remediation=remediation_for("auditd"),
        cross_references={
            "NIST": "AU-7",
        },
    ))

    # AU-9(2) - Store on separate physical system / send remote
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
    audisp_remote = (
        _v33_read_file_safe("/etc/audit/audisp-remote.conf") or
        _v33_read_file_safe("/etc/audisp/audisp-remote.conf")
    )
    # bool() coercion is required: `audisp_remote and "x" in audisp_remote`
    # short-circuits to the empty string when audisp_remote is "", and
    # sum([bool, str]) raises TypeError("unsupported operand type(s) for +").
    audisp_set = bool(audisp_remote) and "remote_server" in audisp_remote
    remote_layers = sum([bool(rsy_remote), bool(audisp_set)])
    results.append(_v33_nist_result(
        "NIST AU-9(2) v3.3 - Remote Audit Storage",
        "Pass" if remote_layers >= 1 else "Fail",
        f"AU-9(2) Remote audit storage ({remote_layers})",
        severity="High",
        details=f"rsyslog remote: {rsy_remote}, audisp-remote: {audisp_set}",
        remediation=(
            "Configure /etc/rsyslog.d/50-remote.conf: "
            "*.* @@logserver.example.com:6514"
        ),
        cross_references={
            "NIST": "AU-9(2)", "PCI-DSS": "10.5.3",
        },
    ))

    # AU-12 - Audit Record Generation: comprehensive coverage
    cis_keys = ["identity", "privileged", "perm_mod", "modules",
                "time-change", "system-locale", "MAC-policy",
                "logins", "session", "delete", "scope", "actions"]
    keys_present = sum(1 for k in cis_keys if k in audit_rules)
    results.append(_v33_nist_result(
        "NIST AU-12 v3.3 - Audit Record Generation",
        "Pass" if keys_present >= 8 else "Warning",
        f"AU-12 Audit record coverage ({keys_present}/{len(cis_keys)})",
        severity="High",
        details=f"Keys present: {keys_present}",
        remediation=(
            "Apply CIS-recommended audit ruleset for comprehensive coverage"
        ),
        cross_references={
            "NIST": "AU-12", "CSF": "PR.PT-1",
        },
    ))


def _check_nist_v33_cm_extended(results, shared_data, os_info):
    """NIST 800-53 R5 - CM (Configuration Management) extended."""

    # CM-2(2) - Automation Support for Accuracy/Currency
    cm_tools = {
        "ansible": _v33_command_available("ansible"),
        "puppet": _v33_command_available("puppet"),
        "salt": _v33_command_available("salt-minion") or _v33_command_available("salt-call"),
        "chef": _v33_command_available("chef-client"),
        "cfengine": _v33_command_available("cf-agent"),
    }
    detected = [k for k, v in cm_tools.items() if v]
    results.append(_v33_nist_result(
        "NIST CM-2(2) v3.3 - CM Automation",
        "Info",
        f"CM-2(2) Configuration management agents ({len(detected)})",
        severity="Informational",
        details=f"Detected: {detected or 'none'}",
        remediation=(
            "Use IaC for reproducible configuration: Ansible/Puppet/Salt"
        ),
        cross_references={
            "NIST": "CM-2(2)", "CSF": "ID.AM",
        },
    ))

    # CM-5 - Access Restrictions for Change
    sudoers_mode = _v33_file_mode("/etc/sudoers")
    sudoers_ok = sudoers_mode is not None and (sudoers_mode & 0o022) == 0
    results.append(_v33_nist_result(
        "NIST CM-5 v3.3 - Change Access Restrictions",
        "Pass" if sudoers_ok else "Warning",
        f"CM-5 sudoers permissions appropriate",
        severity="High",
        details=f"Mode: {oct(sudoers_mode) if sudoers_mode else 'N/A'}",
        remediation="chmod 440 /etc/sudoers; chown root:root /etc/sudoers",
        cross_references={
            "NIST": "CM-5", "CSF": "PR.AC-4",
        },
    ))

    # CM-7(2) - Prevent Program Execution (allowlisting)
    allowlist_tools = {
        "fapolicyd": _v33_systemd_active("fapolicyd.service") == "active",
        "AppArmor": _v33_systemd_active("apparmor.service") == "active",
        "SELinux": False,
    }
    if _v33_file_exists("/sys/fs/selinux/enforce"):
        try:
            with open("/sys/fs/selinux/enforce") as f:
                allowlist_tools["SELinux"] = f.read().strip() == "1"
        except OSError:
            pass
    detected = [k for k, v in allowlist_tools.items() if v]
    results.append(_v33_nist_result(
        "NIST CM-7(2) v3.3 - Execution Prevention",
        "Pass" if detected else "Warning",
        f"CM-7(2) Application allowlisting/MAC ({len(detected)})",
        severity="High",
        details=f"Detected: {detected}",
        remediation=(
            "Enable AppArmor/SELinux enforcing mode, or install fapolicyd"
        ),
        cross_references={
            "NIST": "CM-7(2)", "ACSC": "E8.1", "CSF": "PR.PT-3",
        },
    ))


# Save reference to existing run_checks
_original_run_checks_nist_v33 = run_checks


def run_checks(shared_data):
    """Execute the v3.3 expanded NIST module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_nist_v33(shared_data)

    os_info = shared_data.get("os_info") or shared_data.get("v3_os_info")
    if os_info is None:
        from shared_components import os_detection as _os_det
        os_info = _os_det.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        _check_nist_v33_zero_trust(results, shared_data, os_info)
        _check_nist_v33_scrm(results, shared_data, os_info)
        _check_nist_v33_csf2_govern(results, shared_data, os_info)
        _check_nist_v33_pe_environmental(results, shared_data, os_info)
        _check_nist_v33_pm_program(results, shared_data, os_info)
        _check_nist_v33_advanced_171(results, shared_data, os_info)
        _check_nist_v33_au_extended(results, shared_data, os_info)
        _check_nist_v33_cm_extended(results, shared_data, os_info)
    except Exception as exc:  # noqa: BLE001
        results.append(AuditResult(
            module=MODULE_NAME, category="NIST - Error",
            status="Error",
            message=f"NIST v3.3 expansion exception: {exc!r}",
            details=str(exc), severity="Medium",
        ))

    return results


# ============================================================================
# v3.5 EXPANSION - NIST 800-53 Rev 5 Underrepresented Control Families
# ----------------------------------------------------------------------------
# Synopsis:
#   Adds depth across NIST control families that are underrepresented in
#   the existing module: CA, CP, MA, MP, RA, SA, PT plus CSF 2.0 DETECT/
#   RESPOND/RECOVER subcategories and NIST 800-218 SSDF practices.
#
#   Coverage areas:
#     - CA: Assessment, Authorization, Continuous Monitoring
#     - CP: Contingency Planning, backup, alternate processing
#     - MA: Maintenance (controlled, personnel, tools)
#     - MP: Media Protection (access, sanitization, transport)
#     - RA: Risk Assessment (vuln scanning, threat hunting)
#     - SA: System Acquisition (SDLC, supply chain)
#     - PT: PII Processing and Transparency
#     - CSF 2.0: DETECT (DE.AE, DE.CM), RESPOND (RS.RP, RS.CO), RECOVER (RC.RP, RC.CO)
#     - 800-218 SSDF: PO, PS, PW, RV practices
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


def _v35_nist_result(category, status, message, severity="Medium",
                    details="", remediation="", cross_references=None):
    """Build AuditResult for NIST v3.5 expansion."""
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


def _check_nist_v35_ca_continuous_monitoring(results, shared_data, os_info):
    """CA-7 Continuous monitoring + CA-2 Control assessments + CA-5 POA&M."""
    cat = "NIST v3.5 - CA"

    # CA-7 - Continuous monitoring tools (recurring scans)
    monitoring_tools = {
        "auditd": _v35_systemd_active("auditd.service") == "active",
        "fail2ban": _v35_systemd_active("fail2ban.service") == "active",
        "logwatch": _v35_command_available("logwatch"),
        "OSSEC/Wazuh": _v35_file_exists("/var/ossec/etc/ossec.conf"),
        "lynis": _v35_command_available("lynis"),
        "AIDE": (
            _v35_file_exists("/var/lib/aide/aide.db") or
            _v35_file_exists("/var/lib/aide/aide.db.gz")
        ),
    }
    active_monitors = [k for k, v in monitoring_tools.items() if v]
    results.append(_v35_nist_result(
        f"{cat} - CA-7 Continuous Monitoring",
        "Pass" if len(active_monitors) >= 3 else "Warning",
        f"NIST CA-7 Continuous monitoring tools: {len(active_monitors)}/6",
        severity="High",
        details=f"Active: {active_monitors}",
        remediation=(
            "Deploy at minimum: auditd + AIDE + logwatch + fail2ban\n"
            "  apt-get install -y auditd aide aide-common logwatch fail2ban\n"
            "CA-7 requires ongoing observation of security state, not "
            "point-in-time snapshots."
        ),
        cross_references={
            "NIST": "CA-7, CA-7(1), CA-7(3)",
            "CSF": "DE.CM-1, DE.CM-7",
            "ISO27001": "A.5.36, A.8.16",
        },
    ))

    # CA-2 - Control assessment tooling (vulnerability scanners)
    assessment_tools = {
        "OpenSCAP": _v35_command_available("oscap"),
        "Lynis": _v35_command_available("lynis"),
        "Trivy": _v35_command_available("trivy"),
        "Nuclei": _v35_command_available("nuclei"),
    }
    available_assessment = [k for k, v in assessment_tools.items() if v]
    results.append(_v35_nist_result(
        f"{cat} - CA-2 Control Assessment Tools",
        "Pass" if available_assessment else "Warning",
        f"NIST CA-2 Control assessment tools: {len(available_assessment)}",
        severity="High",
        details=f"Available: {available_assessment}",
        remediation=(
            "Install: apt-get install -y libopenscap8 lynis\n"
            "Use OpenSCAP for SCAP-content-driven assessments:\n"
            "  oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis "
            "/usr/share/xml/scap/ssg/content/ssg-ubuntu2404-ds.xml"
        ),
        cross_references={
            "NIST": "CA-2, CA-2(1), CA-2(2)",
            "CSF": "ID.RA-1",
        },
    ))

    # CA-5 - POA&M (Plan of Action and Milestones) tracking
    # Technical surrogate: issue tracker presence (git, pkg-installed reports)
    poam_indicators = []
    if _v35_command_available("git"):
        poam_indicators.append("git")
    if _v35_directory_exists("/var/cache/apt/archives"):
        poam_indicators.append("apt-cache")
    if _v35_directory_exists("/var/cache/dnf"):
        poam_indicators.append("dnf-cache")
    results.append(_v35_nist_result(
        f"{cat} - CA-5 POA&M Tooling Indicator",
        "Info",
        f"NIST CA-5 Tracking infrastructure: {poam_indicators}",
        severity="Informational",
        details=f"Indicators present: {poam_indicators}",
        remediation=(
            "POA&M is largely organizational. Use git for tracked finding "
            "remediation history; integrate scanner reports (lynis, openscap) "
            "into your issue tracker."
        ),
        cross_references={"NIST": "CA-5"},
    ))

    # CA-9 - Internal system connections (services + their access controls)
    rc, out, _ = _v35_run_command(
        ["ss", "-tlnp"], timeout=5.0,
    )
    listening_services = 0
    if rc == 0 and out:
        listening_services = max(0, len(out.splitlines()) - 1)
    results.append(_v35_nist_result(
        f"{cat} - CA-9 Internal System Connections",
        "Info",
        f"NIST CA-9 Local listening services: {listening_services}",
        severity="Informational",
        details=f"Total LISTEN sockets: {listening_services}",
        cross_references={"NIST": "CA-9"},
    ))


def _check_nist_v35_cp_contingency(results, shared_data, os_info):
    """CP-2 Contingency plan + CP-9 Backup + CP-10 Recovery."""
    cat = "NIST v3.5 - CP"

    # CP-9 - Backup tooling presence
    backup_tools = {
        "rsync": _v35_command_available("rsync"),
        "borgbackup": _v35_command_available("borg"),
        "restic": _v35_command_available("restic"),
        "duplicity": _v35_command_available("duplicity"),
        "rdiff-backup": _v35_command_available("rdiff-backup"),
        "tar": _v35_command_available("tar"),
        "bacula": (
            _v35_systemd_active("bacula-fd.service") == "active" or
            _v35_command_available("bconsole")
        ),
        "amanda": _v35_command_available("amanda"),
    }
    available_backup = [k for k, v in backup_tools.items() if v]
    results.append(_v35_nist_result(
        f"{cat} - CP-9 Backup Tooling",
        "Pass" if len(available_backup) >= 2 else "Warning",
        f"NIST CP-9 Backup tools available: {len(available_backup)}",
        severity="High",
        details=f"Available: {available_backup}",
        remediation=remediation_for("borg") if "borgbackup" not in available_backup else "",
        cross_references={
            "NIST": "CP-9, CP-9(1), CP-9(8)",
            "CSF": "PR.IP-4, RC.RP-1",
            "ISO27001": "A.8.13",
            "PCI-DSS": "12.10.1",
        },
    ))

    # CP-9(8) - Backup encryption capability
    encryption_capable = (
        _v35_command_available("borg") or
        _v35_command_available("restic") or
        _v35_command_available("duplicity") or
        _v35_command_available("age") or
        _v35_command_available("gpg")
    )
    results.append(_v35_nist_result(
        f"{cat} - CP-9(8) Encrypted Backup",
        "Pass" if encryption_capable else "Warning",
        f"NIST CP-9(8) Encrypted backup capability: {encryption_capable}",
        severity="Critical",
        details=f"Encryption-capable backup: {encryption_capable}",
        remediation=(
            f"{remediation_for('borg')}\n"
            "Or for cross-platform: restic init --repo /path/to/repo "
            "(prompts for password)\n"
            "Encryption of backups is mandatory under CP-9(8)."
        ),
        cross_references={
            "NIST": "CP-9(8), SC-28",
            "CSF": "PR.DS-1, PR.DS-2",
            "PCI-DSS": "9.5.1.1",
        },
    ))

    # CP-9 - Backup automation (scheduled backups)
    backup_scheduled = False
    cron_dirs = ["/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.d"]
    for d in cron_dirs:
        if not _v35_directory_exists(d):
            continue
        for f in _v35_list_directory(d):
            f_lower = f.lower()
            if any(k in f_lower for k in [
                "backup", "borg", "restic", "duplicity", "rsync", "snapshot",
            ]):
                backup_scheduled = True
                break
        if backup_scheduled:
            break
    if not backup_scheduled:
        # Check systemd timers
        rc, out, _ = _v35_run_command(
            ["systemctl", "list-timers", "--all", "--no-legend"],
            timeout=5.0,
        )
        if rc == 0 and out:
            for line in out.splitlines():
                line_lower = line.lower()
                if any(k in line_lower for k in [
                    "backup", "borg", "restic", "snapshot",
                ]):
                    backup_scheduled = True
                    break
    results.append(_v35_nist_result(
        f"{cat} - CP-9 Backup Scheduled",
        "Pass" if backup_scheduled else "Info",
        f"NIST CP-9 Backup scheduled (cron/timer): {backup_scheduled}",
        severity="High",
        details=f"Scheduled backup detected: {backup_scheduled}",
        remediation=(
            "Schedule via cron or systemd timer. Example /etc/cron.daily/backup:\n"
            "  #!/bin/sh\n"
            "  borg create --stats /path/to/repo::backup-{now} /etc /home /var/log\n"
            "Or for systemd:\n"
            "  systemctl enable --now borgmatic.timer"
        ),
        cross_references={
            "NIST": "CP-9, CP-9(1)",
            "CSF": "PR.IP-4",
        },
    ))

    # CP-10 - System recovery and reconstitution (kexec-tools, dracut)
    recovery_tools = {
        "kexec-tools": _v35_command_available("kexec"),
        "dracut": _v35_command_available("dracut"),
        "mkinitcpio": _v35_command_available("mkinitcpio"),
        "debootstrap": _v35_command_available("debootstrap"),
    }
    recovery_available = [k for k, v in recovery_tools.items() if v]
    results.append(_v35_nist_result(
        f"{cat} - CP-10 Recovery Tools",
        "Pass" if recovery_available else "Info",
        f"NIST CP-10 Recovery/reconstitution tools: {recovery_available}",
        severity="Medium",
        details=f"Available: {recovery_available}",
        cross_references={
            "NIST": "CP-10, CP-10(2)",
            "CSF": "RC.RP-1",
        },
    ))

    # CP-10(4) - Restoration of system from saved state (snapshots)
    snapshot_capable = (
        _v35_command_available("zfs") or  # ZFS snapshots
        _v35_command_available("btrfs") or  # btrfs snapshots
        _v35_command_available("lvm") or _v35_command_available("lvcreate") or
        _v35_command_available("snapper")
    )
    results.append(_v35_nist_result(
        f"{cat} - CP-10(4) Snapshot Capability",
        "Pass" if snapshot_capable else "Info",
        f"NIST CP-10(4) Filesystem snapshot tooling: {snapshot_capable}",
        severity="Low",
        details=f"Snapshot tools (zfs/btrfs/lvm/snapper): {snapshot_capable}",
        cross_references={
            "NIST": "CP-10(4)",
            "CSF": "RC.RP-1",
        },
    ))


def _check_nist_v35_ma_maintenance(results, shared_data, os_info):
    """MA-2 Controlled maintenance + MA-3 Tools + MA-4 Nonlocal."""
    cat = "NIST v3.5 - MA"

    # MA-2 - Audit trail of system changes (auditctl + dpkg/rpm logs)
    pkg_log_present = (
        _v35_file_exists("/var/log/dpkg.log") or  # Debian
        _v35_file_exists("/var/log/dnf.log") or  # RHEL family
        _v35_file_exists("/var/log/yum.log") or  # Older RHEL
        _v35_file_exists("/var/log/zypper.log") or  # SUSE
        _v35_file_exists("/var/log/pacman.log")  # Arch
    )
    results.append(_v35_nist_result(
        f"{cat} - MA-2 Maintenance Trail",
        "Pass" if pkg_log_present else "Warning",
        f"NIST MA-2 Package management trail: {pkg_log_present}",
        severity="Medium",
        details=f"Package log file present: {pkg_log_present}",
        remediation=(
            "Package management logs (/var/log/dpkg.log, /var/log/dnf.log) "
            "provide MA-2 maintenance audit trail by default. Forward to "
            "SIEM via rsyslog for centralized retention."
        ),
        cross_references={
            "NIST": "MA-2, MA-2(2)",
            "CSF": "PR.MA-1",
            "ISO27001": "A.8.32",
        },
    ))

    # MA-3 - Maintenance tools (controlled and inventoried)
    maintenance_tools = {
        "rsync": _v35_command_available("rsync"),
        "scp": _v35_command_available("scp"),
        "ansible": _v35_command_available("ansible"),
        "ssh": _v35_command_available("ssh"),
        "vim": _v35_command_available("vim") or _v35_command_available("vi"),
    }
    available_tools = [k for k, v in maintenance_tools.items() if v]
    results.append(_v35_nist_result(
        f"{cat} - MA-3 Tools Inventory",
        "Info",
        f"NIST MA-3 Maintenance tools available: {len(available_tools)}",
        severity="Informational",
        details=f"Tools: {available_tools}",
        cross_references={"NIST": "MA-3, MA-3(1), MA-3(2)"},
    ))

    # MA-4 - Nonlocal maintenance (SSH controls)
    sshd = _v35_read_file_safe("/etc/ssh/sshd_config")
    sshd_d = ""
    if _v35_directory_exists("/etc/ssh/sshd_config.d"):
        for f in _v35_list_directory("/etc/ssh/sshd_config.d"):
            if f.endswith(".conf"):
                sshd_d += "\n" + _v35_read_file_safe(
                    os.path.join("/etc/ssh/sshd_config.d", f)
                )
    full_sshd = sshd + "\n" + sshd_d
    nonlocal_secure = (
        "Protocol 2" in full_sshd or "Protocol 1" not in full_sshd
    ) and (
        re.search(r"^\s*PermitRootLogin\s+no", full_sshd, re.MULTILINE) or
        re.search(r"^\s*PermitRootLogin\s+prohibit-password", full_sshd, re.MULTILINE)
    )
    results.append(_v35_nist_result(
        f"{cat} - MA-4 Nonlocal Maintenance",
        "Pass" if nonlocal_secure else "Warning",
        f"NIST MA-4 Nonlocal SSH maintenance hardening: {nonlocal_secure}",
        severity="High",
        details=f"SSH PermitRootLogin restricted: {nonlocal_secure}",
        remediation=(
            "In /etc/ssh/sshd_config.d/50-nonlocal-maint.conf:\n"
            "  PermitRootLogin no\n"
            "  PasswordAuthentication no\n"
            "Then: systemctl reload sshd"
        ),
        cross_references={
            "NIST": "MA-4, MA-4(1), MA-4(3)",
            "CIS": "5.2.10",
        },
    ))


def _check_nist_v35_mp_media(results, shared_data, os_info):
    """MP-2 Media access + MP-6 Sanitization + MP-7 Use."""
    cat = "NIST v3.5 - MP"

    # MP-2 - Media access (USB device control)
    usb_control = (
        _v35_systemd_active("usbguard.service") == "active" or
        _v35_command_available("usbguard")
    )
    results.append(_v35_nist_result(
        f"{cat} - MP-2 Media Access Control",
        "Pass" if usb_control else "Info",
        f"NIST MP-2 USB device authorization: {usb_control}",
        severity="Medium",
        details=f"usbguard active/available: {usb_control}",
        remediation=remediation_for("usbguard"),
        cross_references={
            "NIST": "MP-2, MP-7",
            "CIS": "1.1.10",
            "STIG": "V-230503",
        },
    ))

    # MP-6 - Media sanitization (secure delete tooling)
    sanitization_tools = {
        "shred": _v35_command_available("shred"),
        "scrub": _v35_command_available("scrub"),
        "wipe": _v35_command_available("wipe"),
        "srm (secure-delete)": _v35_command_available("srm"),
        "hdparm (security-erase)": _v35_command_available("hdparm"),
        "cryptsetup": _v35_command_available("cryptsetup"),
    }
    available_sanit = [k for k, v in sanitization_tools.items() if v]
    results.append(_v35_nist_result(
        f"{cat} - MP-6 Media Sanitization",
        "Pass" if len(available_sanit) >= 2 else "Warning",
        f"NIST MP-6 Sanitization tools: {len(available_sanit)}",
        severity="Medium",
        details=f"Available: {available_sanit}",
        remediation=(
            "apt-get install -y secure-delete coreutils scrub hdparm cryptsetup\n"
            "MP-6(2) requires media sanitization upon disposal/release; "
            "use:\n"
            "  hdparm --security-erase (for SSD/HDD)\n"
            "  cryptsetup luksFormat + destroy keys (for LUKS volumes)\n"
            "  shred -uvz (for individual files)"
        ),
        cross_references={
            "NIST": "MP-6, MP-6(2), MP-6(3)",
            "ISO27001": "A.8.10",
            "PCI-DSS": "9.5",
            "GDPR": "Art 17",
        },
    ))

    # MP-7 - Media use restrictions (mount option indicators)
    fstab = _v35_read_file_safe("/etc/fstab")
    nodev_mounts = bool(re.search(r"\bnodev\b", fstab))
    nosuid_mounts = bool(re.search(r"\bnosuid\b", fstab))
    noexec_mounts = bool(re.search(r"\bnoexec\b", fstab))
    mount_count = sum([nodev_mounts, nosuid_mounts, noexec_mounts])
    results.append(_v35_nist_result(
        f"{cat} - MP-7 Mount Restrictions",
        "Pass" if mount_count >= 2 else "Warning",
        f"NIST MP-7 Mount option restrictions: {mount_count}/3",
        severity="Medium",
        details=(
            f"nodev: {nodev_mounts}, nosuid: {nosuid_mounts}, "
            f"noexec: {noexec_mounts}"
        ),
        remediation=(
            "In /etc/fstab, add restrictive mount options for /tmp, /var, "
            "/dev/shm, removable media:\n"
            "  /dev/sdaN  /tmp  ext4  defaults,nodev,nosuid,noexec  0 2"
        ),
        cross_references={
            "NIST": "MP-7, AC-3",
            "CIS": "1.1",
        },
    ))


def _check_nist_v35_ra_risk_assessment(results, shared_data, os_info):
    """RA-3 Risk assessment + RA-5 Vuln scanning + RA-10 Threat hunting."""
    cat = "NIST v3.5 - RA"

    # RA-5 - Vulnerability monitoring tooling
    vuln_tools = {
        "lynis": _v35_command_available("lynis"),
        "openscap (oscap)": _v35_command_available("oscap"),
        "trivy": _v35_command_available("trivy"),
        "grype": _v35_command_available("grype"),
        "nuclei": _v35_command_available("nuclei"),
        "rkhunter": _v35_command_available("rkhunter"),
        "chkrootkit": _v35_command_available("chkrootkit"),
        "debsecan": _v35_command_available("debsecan"),
    }
    available_vuln = [k for k, v in vuln_tools.items() if v]
    results.append(_v35_nist_result(
        f"{cat} - RA-5 Vulnerability Tools",
        "Pass" if len(available_vuln) >= 2 else "Warning",
        f"NIST RA-5 Vulnerability tools: {len(available_vuln)}/8",
        severity="High",
        details=f"Available: {available_vuln}",
        remediation=(
            "Deploy multiple complementary scanners:\n"
            "  apt-get install -y lynis libopenscap8 rkhunter chkrootkit debsecan\n"
            "lynis: host configuration audit\n"
            "openscap: SCAP-content compliance scanning\n"
            "rkhunter/chkrootkit: rootkit detection\n"
            "debsecan: Debian security advisory tracking"
        ),
        cross_references={
            "NIST": "RA-5, RA-5(2), RA-5(11)",
            "CSF": "ID.RA-1, DE.CM-8",
            "PCI-DSS": "11.4.1",
        },
    ))

    # RA-5 scheduled execution (recurring, not just on-demand)
    rasched = False
    cron_dirs = ["/etc/cron.daily", "/etc/cron.weekly"]
    for d in cron_dirs:
        if not _v35_directory_exists(d):
            continue
        for f in _v35_list_directory(d):
            f_lower = f.lower()
            if any(k in f_lower for k in [
                "lynis", "rkhunter", "chkrootkit", "debsecan",
                "aide", "openscap", "trivy",
            ]):
                rasched = True
                break
        if rasched:
            break
    results.append(_v35_nist_result(
        f"{cat} - RA-5 Scheduled Scans",
        "Pass" if rasched else "Warning",
        f"NIST RA-5 Vulnerability scans scheduled: {rasched}",
        severity="High",
        details=f"Scheduled scan job present: {rasched}",
        remediation=(
            "Add to /etc/cron.daily/lynis-audit:\n"
            "  #!/bin/sh\n"
            "  lynis audit system --quick --auditor 'auto'\n"
            "Continuous monitoring requires recurring scans, not "
            "point-in-time."
        ),
        cross_references={
            "NIST": "RA-5(2)",
            "CSF": "DE.CM-8",
            "PCI-DSS": "11.4.1",
        },
    ))

    # RA-10 - Threat hunting indicators
    hunt_tools = {
        "osquery": (
            _v35_command_available("osqueryi") or
            _v35_systemd_active("osqueryd.service") == "active"
        ),
        "Falco": _v35_systemd_active("falco.service") == "active",
        "Sysmon": _v35_directory_exists("/var/log/sysmon"),
        "auditd": _v35_systemd_active("auditd.service") == "active",
        "Wazuh": _v35_file_exists("/var/ossec/etc/ossec.conf"),
    }
    hunt_capable = [k for k, v in hunt_tools.items() if v]
    results.append(_v35_nist_result(
        f"{cat} - RA-10 Threat Hunting",
        "Pass" if len(hunt_capable) >= 2 else "Info",
        f"NIST RA-10 Threat-hunting tools: {len(hunt_capable)}/5",
        severity="Medium",
        details=f"Capable: {hunt_capable}",
        remediation=(
            f"{remediation_for('osquery')}\n"
            "osquery enables SQL-based threat hunting; deploy + connect to "
            "Fleet for centralized hunting."
        ),
        cross_references={
            "NIST": "RA-10",
            "CSF": "DE.CM-1, DE.CM-7",
        },
    ))


def _check_nist_v35_sa_acquisition(results, shared_data, os_info):
    """SA-3 SDLC + SA-11 Developer testing + SA-15 Development process."""
    cat = "NIST v3.5 - SA"

    # SA-3 - SDLC tooling indicators (version control, CI)
    sdlc_tools = {
        "git": _v35_command_available("git"),
        "gh (GitHub CLI)": _v35_command_available("gh"),
        "make": _v35_command_available("make"),
        "docker": _v35_command_available("docker"),
        "podman": _v35_command_available("podman"),
    }
    sdlc_available = [k for k, v in sdlc_tools.items() if v]
    results.append(_v35_nist_result(
        f"{cat} - SA-3 SDLC Tooling",
        "Info",
        f"NIST SA-3 SDLC tools: {len(sdlc_available)}/5",
        severity="Informational",
        details=f"Available: {sdlc_available}",
        cross_references={"NIST": "SA-3, SA-15"},
    ))

    # SA-11 - Developer security testing tooling (SAST/DAST surrogates)
    sast_tools = {
        "shellcheck": _v35_command_available("shellcheck"),
        "bandit (Python SAST)": _v35_command_available("bandit"),
        "semgrep": _v35_command_available("semgrep"),
        "flake8": _v35_command_available("flake8"),
        "pylint": _v35_command_available("pylint"),
        "yamllint": _v35_command_available("yamllint"),
    }
    sast_available = [k for k, v in sast_tools.items() if v]
    results.append(_v35_nist_result(
        f"{cat} - SA-11 Developer Testing",
        "Pass" if len(sast_available) >= 2 else "Info",
        f"NIST SA-11 SAST tooling: {len(sast_available)}/6",
        severity="Medium",
        details=f"Available: {sast_available}",
        remediation=(
            "apt-get install -y shellcheck python3-bandit\n"
            "pip install --user semgrep\n"
            "Integrate into CI pipeline for SA-11 developer security testing."
        ),
        cross_references={
            "NIST": "SA-11, SA-11(1), SA-11(8)",
            "CSF": "PR.IP-2",
            "ISO27001": "A.8.28, A.8.29",
        },
    ))

    # SA-15 - Development process / configuration management
    container_runtime = (
        _v35_command_available("docker") or
        _v35_command_available("podman") or
        _v35_command_available("buildah")
    )
    image_signing_capable = (
        _v35_command_available("cosign") or
        _v35_command_available("notary")
    )
    sbom_capable = (
        _v35_command_available("syft") or
        _v35_command_available("trivy")
    )
    devsecops_layers = sum([
        bool(container_runtime), bool(image_signing_capable), bool(sbom_capable),
    ])
    results.append(_v35_nist_result(
        f"{cat} - SA-15/SA-22 Supply Chain Security",
        "Pass" if devsecops_layers >= 2 else "Info",
        f"NIST SA-15/SA-22 DevSecOps layers ({devsecops_layers}/3)",
        severity="Medium",
        details=(
            f"Container: {container_runtime}, "
            f"image-signing (cosign/notary): {image_signing_capable}, "
            f"SBOM (syft/trivy): {sbom_capable}"
        ),
        remediation=(
            f"{remediation_for('syft')}\n"
            f"{remediation_for('trivy')}\n"
            "For image signing: install cosign:\n"
            "  curl -O -L "
            "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"
        ),
        cross_references={
            "NIST": "SA-15, SA-22",
            "CSF": "ID.SC-1, ID.SC-2, ID.SC-4",
            "CISA-SbD": "1.0",
        },
    ))


def _check_nist_v35_pt_pii(results, shared_data, os_info):
    """PT-1 PII control + PT-2 Authority for processing + PT-5 Privacy notice."""
    cat = "NIST v3.5 - PT"

    # PT-3 - Personally identifiable information (PII) processing
    # Technical surrogate: encryption-at-rest indicators
    pii_indicators = {
        "LUKS-encrypted volumes": False,
        "fscrypt": _v35_command_available("fscrypt"),
        "ecryptfs": _v35_command_available("ecryptfs-mount-private") or
                     _v35_directory_exists("/usr/lib/ecryptfs"),
    }
    rc, out, _ = _v35_run_command(["lsblk", "-o", "TYPE", "-n"], timeout=5.0)
    if rc == 0 and out and "crypt" in out.lower():
        pii_indicators["LUKS-encrypted volumes"] = True
    pii_protect_layers = sum(1 for v in pii_indicators.values() if v)
    results.append(_v35_nist_result(
        f"{cat} - PT-3 PII Encryption",
        "Pass" if pii_protect_layers >= 1 else "Info",
        f"NIST PT-3 PII protection layers: {pii_protect_layers}",
        severity="High",
        details=(
            f"Layers: { {k:v for k,v in pii_indicators.items() if v} }"
        ),
        remediation=(
            f"{remediation_for('cryptsetup')}\n"
            "PT-3 requires PII processing be authorized; technical "
            "implementation: encrypt-at-rest volumes containing PII."
        ),
        cross_references={
            "NIST": "PT-3, PT-3(1), PT-3(2)",
            "GDPR": "Art 32(1)(a)",
            "ISO27001": "A.8.24",
        },
    ))


def _check_nist_v35_csf2_detect_respond_recover(
    results, shared_data, os_info
):
    """CSF 2.0 DETECT, RESPOND, RECOVER subcategories."""
    cat = "NIST v3.5 - CSF 2.0"

    # DE.CM-1 - Networks monitored
    netmon_tools = {
        "tcpdump": _v35_command_available("tcpdump"),
        "Suricata": _v35_systemd_active("suricata.service") == "active",
        "Snort": _v35_command_available("snort"),
        "Zeek": _v35_command_available("zeek"),
    }
    netmon_available = [k for k, v in netmon_tools.items() if v]
    results.append(_v35_nist_result(
        f"{cat} - DE.CM-1 Network Monitoring",
        "Pass" if netmon_available else "Warning",
        f"CSF 2.0 DE.CM-1 Network monitoring: {netmon_available}",
        severity="High",
        details=f"Available: {netmon_available}",
        remediation=(
            f"{remediation_for('suricata')}\n"
            "Provides DE.CM-1 network anomaly + intrusion detection."
        ),
        cross_references={
            "NIST": "SI-4",
            "CSF": "DE.CM-1, DE.CM-7",
        },
    ))

    # DE.CM-3 - Personnel activity monitored
    auditd_active = _v35_systemd_active("auditd.service") == "active"
    user_access_logged = False
    audit_rules = ""
    if _v35_directory_exists("/etc/audit/rules.d"):
        for f in _v35_list_directory("/etc/audit/rules.d"):
            if f.endswith(".rules"):
                audit_rules += "\n" + _v35_read_file_safe(
                    os.path.join("/etc/audit/rules.d", f)
                )
    if "auid>=1000" in audit_rules and auditd_active:
        user_access_logged = True
    results.append(_v35_nist_result(
        f"{cat} - DE.CM-3 Personnel Monitoring",
        "Pass" if user_access_logged else "Warning",
        f"CSF 2.0 DE.CM-3 User activity logging: {user_access_logged}",
        severity="High",
        details=(
            f"auditd active: {auditd_active}, auid filter: {'auid>=1000' in audit_rules}"
        ),
        remediation=(
            "Add to /etc/audit/rules.d/41-csf-personnel.rules:\n"
            "  -a always,exit -F arch=b64 -S execve -F auid>=1000 "
            "-F auid!=4294967295 -k personnel-activity"
        ),
        cross_references={
            "NIST": "AU-2, AU-12",
            "CSF": "DE.CM-3",
        },
    ))

    # RS.RP-1 - Response plan executed during/after incident
    # Surrogate: incident response tooling readiness
    ir_tools = {
        "tcpdump": _v35_command_available("tcpdump"),
        "lsof": _v35_command_available("lsof"),
        "strace": _v35_command_available("strace"),
        "ausearch": _v35_command_available("ausearch"),
        "journalctl": _v35_command_available("journalctl"),
    }
    ir_ready = sum(1 for v in ir_tools.values() if v)
    results.append(_v35_nist_result(
        f"{cat} - RS.RP-1 IR Tooling",
        "Pass" if ir_ready >= 4 else "Warning",
        f"CSF 2.0 RS.RP-1 IR tooling readiness: {ir_ready}/5",
        severity="High",
        details=f"Available: {[k for k,v in ir_tools.items() if v]}",
        remediation=(
            "apt-get install -y tcpdump lsof strace iproute2 audit\n"
            "These tools are essential for incident response triage and "
            "containment per CSF 2.0 RESPOND function."
        ),
        cross_references={
            "NIST": "IR-4, IR-5",
            "CSF": "RS.RP-1, RS.AN-1",
        },
    ))

    # RS.CO - Communications during response (mail capability)
    mail_capable = (
        _v35_command_available("mail") or
        _v35_command_available("mailx") or
        _v35_systemd_active("postfix.service") == "active"
    )
    results.append(_v35_nist_result(
        f"{cat} - RS.CO-2 IR Notification",
        "Pass" if mail_capable else "Warning",
        f"CSF 2.0 RS.CO-2 Notification capability: {mail_capable}",
        severity="Medium",
        details=f"Mail tools: {mail_capable}",
        cross_references={
            "NIST": "IR-6",
            "CSF": "RS.CO-2, RS.CO-3",
        },
    ))

    # RC.RP-1 - Recovery plan executed (backup tools + scheduled)
    backup_layers = 0
    if _v35_command_available("borg") or _v35_command_available("restic"):
        backup_layers += 1
    if _v35_command_available("rsync"):
        backup_layers += 1
    # Snapshot capability
    if (_v35_command_available("zfs") or _v35_command_available("btrfs") or
        _v35_command_available("snapper")):
        backup_layers += 1
    results.append(_v35_nist_result(
        f"{cat} - RC.RP-1 Recovery Layers",
        "Pass" if backup_layers >= 2 else "Warning",
        f"CSF 2.0 RC.RP-1 Recovery capability layers: {backup_layers}/3",
        severity="High",
        details=f"Backup/snapshot tooling layers: {backup_layers}",
        remediation=remediation_for("borg"),
        cross_references={
            "NIST": "CP-9, CP-10",
            "CSF": "RC.RP-1",
        },
    ))


def _check_nist_v35_ssdf_800_218(results, shared_data, os_info):
    """NIST 800-218 Secure Software Development Framework (SSDF)."""
    cat = "NIST v3.5 - SSDF (800-218)"

    # PO.1 - Roles defined; PO.5 - Trusted environment
    # Surrogate: container runtime + SBOM tooling
    po_indicators = {
        "container_runtime": (
            _v35_command_available("docker") or
            _v35_command_available("podman") or
            _v35_command_available("buildah")
        ),
        "SBOM_tooling": (
            _v35_command_available("syft") or
            _v35_command_available("trivy")
        ),
    }
    po_layers = sum(1 for v in po_indicators.values() if v)
    results.append(_v35_nist_result(
        f"{cat} - PO Trusted Build Environment",
        "Pass" if po_layers >= 1 else "Info",
        f"SSDF PO.5 Trusted build environment: {po_layers}/2 indicators",
        severity="Medium",
        details=f"Indicators: {po_indicators}",
        cross_references={
            "NIST": "SA-3, SA-15",
            "SSDF": "PO.5, PO.5.1",
        },
    ))

    # PS.1 - Code provenance (git + signed commits)
    git_present = _v35_command_available("git")
    gpg_present = (
        _v35_command_available("gpg") or _v35_command_available("gpg2")
    )
    provenance_capable = git_present and gpg_present
    results.append(_v35_nist_result(
        f"{cat} - PS.1 Code Provenance",
        "Pass" if provenance_capable else "Info",
        f"SSDF PS.1 Code provenance tooling: {provenance_capable}",
        severity="Medium",
        details=f"git: {git_present}, gpg: {gpg_present}",
        remediation=(
            "apt-get install -y git gnupg2\n"
            "Configure signed commits:\n"
            "  git config --global user.signingkey <key-id>\n"
            "  git config --global commit.gpgsign true"
        ),
        cross_references={
            "NIST": "SA-12",
            "SSDF": "PS.1, PS.2",
        },
    ))

    # PW.7 - Code review (linters + analyzers)
    review_tools = {
        "shellcheck": _v35_command_available("shellcheck"),
        "yamllint": _v35_command_available("yamllint"),
        "flake8 / pylint": (
            _v35_command_available("flake8") or _v35_command_available("pylint")
        ),
        "bandit": _v35_command_available("bandit"),
    }
    review_available = [k for k, v in review_tools.items() if v]
    results.append(_v35_nist_result(
        f"{cat} - PW.7/PW.8 Code Review Tools",
        "Pass" if len(review_available) >= 2 else "Info",
        f"SSDF PW.7/PW.8 Static analysis tools: {len(review_available)}/4",
        severity="Medium",
        details=f"Available: {review_available}",
        remediation=(
            "apt-get install -y shellcheck yamllint python3-bandit pylint flake8"
        ),
        cross_references={
            "SSDF": "PW.7, PW.8",
            "NIST": "SA-11",
        },
    ))

    # RV.1 - Vulnerability identification (vuln scanning + dep scanning)
    rv_tools = {
        "trivy": _v35_command_available("trivy"),
        "grype": _v35_command_available("grype"),
        "lynis": _v35_command_available("lynis"),
        "openscap": _v35_command_available("oscap"),
    }
    rv_available = [k for k, v in rv_tools.items() if v]
    results.append(_v35_nist_result(
        f"{cat} - RV.1 Vulnerability Identification",
        "Pass" if rv_available else "Warning",
        f"SSDF RV.1 Vulnerability tooling: {len(rv_available)}/4",
        severity="High",
        details=f"Available: {rv_available}",
        remediation=remediation_for("trivy"),
        cross_references={
            "SSDF": "RV.1, RV.2",
            "NIST": "RA-5, SR-3",
        },
    ))


# Save reference to existing run_checks
_original_run_checks_nist_v35 = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the v3.5 expanded NIST module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_nist_v35(shared_data)

    os_info = shared_data.get("os_info") or shared_data.get("v3_os_info")
    if os_info is None:
        from shared_components import os_detection as _os_det
        os_info = _os_det.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        _check_nist_v35_ca_continuous_monitoring(results, shared_data, os_info)
        _check_nist_v35_cp_contingency(results, shared_data, os_info)
        _check_nist_v35_ma_maintenance(results, shared_data, os_info)
        _check_nist_v35_mp_media(results, shared_data, os_info)
        _check_nist_v35_ra_risk_assessment(results, shared_data, os_info)
        _check_nist_v35_sa_acquisition(results, shared_data, os_info)
        _check_nist_v35_pt_pii(results, shared_data, os_info)
        _check_nist_v35_csf2_detect_respond_recover(results, shared_data, os_info)
        _check_nist_v35_ssdf_800_218(results, shared_data, os_info)
    except Exception as exc:  # noqa: BLE001
        results.append(AuditResult(
            module=MODULE_NAME, category="NIST - Error",
            status="Error",
            message=f"NIST v3.5 expansion exception: {exc!r}",
            details=str(exc), severity="Medium",
        ))

    return results
if __name__ == "__main__":
    """
    Standalone testing capability for the NIST module
    """
    import socket
    import platform
    
    print("="*80)
    print(f"NIST Module Standalone Test - v{MODULE_VERSION}")
    print("Comprehensive NIST 800-53 Rev 5 Security Controls")
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
        "os_version": f"{platform.system()} {platform.release()}",
        "scan_date": datetime.datetime.now(),
        "is_root": os.geteuid() == 0,
        "script_path": Path(__file__).parent.parent if hasattr(Path(__file__), 'parent') else Path.cwd(),
        "cache": cache,
    }
    
    print(f"\nTest Environment:")
    print(f"  Hostname: {test_data['hostname']}")
    print(f"  OS: {test_data['os_version']}")
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
    print(f"\nControl Family Coverage:")
    category_counts = Counter(r.category for r in test_results)
    for category in sorted(category_counts.keys()):
        count = category_counts[category]
        print(f"  {category:40s}: {count:3d} checks")
    
    # Critical findings
    critical_failures = [r for r in test_results if r.status == "Fail"]
    if critical_failures:
        print(f"\n  Critical Failures ({len(critical_failures)}):")
        for failure in critical_failures[:10]:
            print(f"   {failure.message}")
        if len(critical_failures) > 10:
            print(f"  ... and {len(critical_failures) - 10} more")
    
    print(f"\n{'='*80}")
    print(f"NIST module comprehensive test complete")
    print(f"All {len(test_results)} checks executed successfully")
    print(f"{'='*80}\n")
