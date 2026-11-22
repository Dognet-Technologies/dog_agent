#!/usr/bin/env python3
"""
module_stig.py
STIG (Security Technical Implementation Guide) Module for Linux
Version: 2.1

SYNOPSIS:
    Comprehensive DISA STIG (Security Technical Implementation Guide)
    compliance checks for Linux systems.

DESCRIPTION:
    This module performs exhaustive security checks based on DISA STIG:
    
    DISA STIG Compliance:
    - Access Control (AC)
    - Audit and Accountability (AU)
    - Identification and Authentication (IA)
    - System and Information Integrity (SI)
    - Configuration Management (CM)
    - System and Communications Protection (SC)
    - Additional STIG Requirements
    
    Key STIG Publications Covered:
    - Red Hat Enterprise Linux (RHEL) STIG
    - Ubuntu Linux STIG
    - General Purpose Operating System STIG
    - Application Security and Development STIG
    - DISA Security Requirements Guide (SRG)
    
    Security Focus Areas:
    - Mandatory access controls (SELinux/AppArmor)
    - Comprehensive audit logging
    - Strong authentication mechanisms
    - System integrity protection
    - Network security hardening
    - Defense Information Systems Agency requirements
    
    STIG Severity Levels:
    - CAT I (High): Vulnerabilities that can be exploited
    - CAT II (Medium): Vulnerabilities that could result in compromise
    - CAT III (Low): Vulnerabilities that degrade security

PARAMETERS:
    shared_data : Dictionary containing shared data from main script

USAGE:
    Standalone testing
        python3 module_stig.py

    Integration with main audit script
        python3 linux_security_audit.py --modules STIG
        python3 linux_security_audit.py -m STIG

NOTES:
    Version: 2.1
    Reference: https://public.cyber.mil/stigs/
    Focus: DoD security requirements for Linux systems
	Standards: DISA STIG & DoD 8500 series
    Target: 200+ comprehensive security checks; OS-aware technical control checks
    Module automatically detects OS via module_core integration
    
    STIG Finding Types:
    - Open: Non-compliant with STIG requirement
    - Not a Finding: Compliant with STIG requirement
    - Not Applicable: STIG requirement does not apply
    - Not Reviewed: STIG requirement not checked
    
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

MODULE_NAME = "STIG"

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

# STIG Severity Category Constants
CAT_I = "CAT I"    # Critical/High - Vulnerabilities with direct/immediate impact
CAT_II = "CAT II"  # Medium - Vulnerabilities with potential for significant impact
CAT_III = "CAT III" # Low - Vulnerabilities with limited impact

# ============================================================================
# DISA STIG Reference Mapping
# ============================================================================
# Maps our internal check categories to official DISA STIG IDs from the
# Canonical Ubuntu 24.04 LTS STIG (v1r1+) and General Purpose OS SRG.
# This provides traceability to the authoritative DISA vulnerability IDs.
# Format: {category_prefix: {check_number: "UBTU-24-XXXXXX"}}
# Where no exact Ubuntu 24.04 STIG ID exists, the SRG reference is given.
DISA_STIG_REFS = {
    # AC - Access Control
    'AC': {
        1: 'UBTU-24-100500',   # MAC (AppArmor) enabled
        2: 'UBTU-24-300310',   # SSH root login disabled
        3: 'UBTU-24-300260',   # SSH empty passwords disabled
        4: 'UBTU-24-300240',   # SSH host-based auth disabled
        5: 'UBTU-24-200580',   # Only root has UID 0
        6: 'SRG-OS-000104',    # System accounts nologin
        7: 'SRG-OS-000480',    # Valid home directories
        8: 'UBTU-24-400430',   # Home dir permissions
        9: 'UBTU-24-400440',   # Home dirs owned by users
        10: 'UBTU-24-400450',  # .netrc files secured
        11: 'SRG-OS-000480',   # No .rhosts files
        12: 'SRG-OS-000480',   # No shosts.equiv
        13: 'SRG-OS-000480',   # No hosts.equiv
        14: 'UBTU-24-200610',  # sudo installed
        15: 'UBTU-24-400310',  # sudoers permissions
        16: 'UBTU-24-200000',  # Max concurrent sessions
        17: 'UBTU-24-200260',  # Inactive account disable
        18: 'UBTU-24-200250',  # Emergency account auto-remove
        19: 'UBTU-24-300010',  # SSH protocol version
        20: 'UBTU-24-300050',  # SSH session timeout (ClientAlive)
    },
    # AU - Audit & Accountability
    'AU': {
        1: 'UBTU-24-100400',   # auditd installed
        2: 'UBTU-24-100410',   # auditd enabled and running
        3: 'UBTU-24-102010',   # Audit at system startup
        4: 'UBTU-24-300420',   # Audit log not auto-deleted
        5: 'UBTU-24-300430',   # Audit log max size configured
        6: 'UBTU-24-300400',   # Audit space low action
        7: 'UBTU-24-200280',   # Audit /etc/passwd changes
        8: 'UBTU-24-200290',   # Audit /etc/group changes
        9: 'UBTU-24-200300',   # Audit /etc/shadow changes
        10: 'UBTU-24-200310',  # Audit /etc/gshadow changes
        11: 'UBTU-24-200320',  # Audit /etc/opasswd changes
        12: 'UBTU-24-300460',  # Audit privileged commands
        13: 'UBTU-24-300470',  # Audit file deletions
        14: 'UBTU-24-300480',  # Audit kernel module loading
        15: 'UBTU-24-300500',  # Audit successful/failed logins
    },
    # CM - Configuration Management
    'CM': {
        1: 'UBTU-24-100010',   # No systemd-timesyncd
        2: 'UBTU-24-100020',   # No ntp package
        3: 'UBTU-24-100030',   # No telnet
        4: 'UBTU-24-100040',   # No rsh-server
        5: 'UBTU-24-400010',   # File permissions /etc/passwd
        6: 'UBTU-24-400020',   # File permissions /etc/shadow
        7: 'UBTU-24-400030',   # File permissions /etc/group
        8: 'UBTU-24-400040',   # File permissions /etc/gshadow
        9: 'UBTU-24-100100',   # AIDE file integrity tool
        10: 'UBTU-24-100110',  # AIDE filesystem check
        11: 'UBTU-24-100120',  # AIDE runs every 30 days
        12: 'UBTU-24-100130',  # AIDE change notification
        13: 'UBTU-24-90890',   # Integrity of audit tools
        14: 'UBTU-24-400100',  # SUID/SGID permissions
        15: 'UBTU-24-400110',  # World-writable files
    },
    # IA - Identification & Authentication
    'IA': {
        1: 'UBTU-24-100600',   # libpam-pwquality installed
        2: 'UBTU-24-200610',   # Account lockout (3 attempts)
        3: 'UBTU-24-500010',   # Min password length (15+)
        4: 'UBTU-24-500020',   # Password complexity (uppercase)
        5: 'UBTU-24-500030',   # Password complexity (lowercase)
        6: 'UBTU-24-500040',   # Password complexity (digits)
        7: 'UBTU-24-500050',   # Password complexity (special chars)
        8: 'UBTU-24-500070',   # Password max lifetime
        9: 'UBTU-24-500080',   # Password min lifetime
        10: 'UBTU-24-500090',  # Password history (remember)
        11: 'UBTU-24-500060',  # Min chars changed (difok)
        12: 'UBTU-24-102000',  # Single-user mode auth
        13: 'UBTU-24-100650',  # SSSD installed
        14: 'UBTU-24-100660',  # SSSD for MFA
        15: 'UBTU-24-100900',  # PIV credentials accepted
    },
    # SC - System & Communications Protection
    'SC': {
        1: 'UBTU-24-100300',   # Firewall installed (ufw)
        2: 'UBTU-24-100310',   # Firewall enabled and running
        3: 'UBTU-24-100820',   # SSH FIPS 140-3 ciphers
        4: 'UBTU-24-100830',   # SSH FIPS 140-3 MACs
        5: 'UBTU-24-100840',   # SSH FIPS key exchange
        6: 'UBTU-24-100850',   # SSH client FIPS ciphers
        7: 'UBTU-24-100860',   # SSH client FIPS MACs
        8: 'UBTU-24-100800',   # SSH installed
        9: 'UBTU-24-100810',   # SSH for confidentiality/integrity
        10: 'UBTU-24-300120',  # SSH X11 forwarding disabled
    },
    # SI - System & Information Integrity
    'SI': {
        1: 'UBTU-24-600010',   # Security patches applied
        2: 'UBTU-24-600020',   # Automatic updates configured
        3: 'UBTU-24-100200',   # Preserve log records from failure
        4: 'UBTU-24-100450',   # Audit log offloading
        5: 'SRG-OS-000480',    # Antivirus/malware scanning
        6: 'UBTU-24-200640',   # SSH login banner (DoD notice)
        7: 'UBTU-24-200650',   # GUI login banner
        8: 'UBTU-24-100700',   # chrony for time sync
        9: 'SRG-OS-000480',    # Kernel address space layout
        10: 'SRG-OS-000480',   # Core dump restrictions
    },
    # AR - Additional Requirements
    'AR': {
        1: 'UBTU-24-300150',   # SSH banner path
        2: 'UBTU-24-200090',   # Monitor remote access
        3: 'UBTU-24-300060',   # SSH idle timeout interval
        4: 'SRG-OS-000480',    # USB storage disabled
        5: 'UBTU-24-100510',   # AppArmor configured
    },
    # MP - Media Protection
    'MP': {
        1: 'SRG-OS-000480',    # USB mass storage disabled
        2: 'SRG-OS-000480',    # Removable media mount options
        3: 'SRG-OS-000480',    # Automated media labeling
    },
}


def get_stig_id(category: str, number: int) -> str:
    """
    Generate STIG control ID with optional DISA reference.

    Args:
        category: STIG category prefix (e.g., 'AC', 'AU', 'CM')
        number: Check number within category

    Returns:
        Formatted STIG ID string (e.g., 'STIG-AC-001')
    """
    return f"STIG-{category}-{number:03d}"


def get_disa_ref(category: str, number: int) -> Dict[str, str]:
    """
    Get DISA STIG cross-reference for a given check.

    Args:
        category: STIG category prefix (e.g., 'AC', 'AU')
        number: Check number within category

    Returns:
        Dict with cross-reference IDs for use in AuditResult.cross_references
    """
    refs = {}
    disa_id = DISA_STIG_REFS.get(category, {}).get(number, '')
    if disa_id:
        refs['DISA_STIG'] = disa_id
    return refs


def stig_result(category_code: str, check_num: int, cat_level: str,
                status: str, message_suffix: str, details: str = "",
                remediation: str = "", severity: str = "Medium") -> AuditResult:
    """
    Factory function for creating STIG AuditResult with auto-populated
    DISA cross-references and consistent formatting.

    Args:
        category_code: STIG family code (e.g., 'AC', 'AU', 'CM')
        check_num: Check number within category
        cat_level: STIG severity (CAT_I, CAT_II, CAT_III)
        status: Result status (Pass, Fail, Warning, Info)
        message_suffix: Human-readable check description
        details: Technical details
        remediation: Remediation guidance
        severity: Risk severity override (default Medium)

    Returns:
        AuditResult with cross_references auto-populated from DISA_STIG_REFS
    """
    # Map CAT level to severity if not overridden
    if severity == "Medium":
        cat_severity_map = {CAT_I: "High", CAT_II: "Medium", CAT_III: "Low"}
        severity = cat_severity_map.get(cat_level, "Medium")

    # Build category name from code
    cat_names = {
        'AC': 'Access Control', 'AU': 'Audit & Accountability',
        'CM': 'Configuration Management', 'IA': 'Identification & Authentication',
        'SC': 'System & Communications Protection',
        'SI': 'System & Information Integrity',
        'AR': 'Additional Requirements', 'MP': 'Media Protection',
    }
    cat_name = cat_names.get(category_code, category_code)

    return AuditResult(
        module=MODULE_NAME,
        category=f"STIG - {cat_name} ({cat_level})",
        status=status,
        message=f"{get_stig_id(category_code, check_num)}: {message_suffix}",
        details=details,
        remediation=remediation,
        severity=severity,
        cross_references=get_disa_ref(category_code, check_num),
    )

def get_auditd_status(os_info: OSInfo) -> Dict[str, Any]:
    """Get comprehensive auditd status (STIG-specific)"""
    status = {
        'installed': False,
        'active': False,
        'enabled': False,
        'rules_count': 0
    }
    
    status['installed'] = check_package_installed("auditd", os_info) or check_package_installed("audit", os_info)
    status['active'] = check_service_active("auditd")
    status['enabled'] = check_service_enabled("auditd")
    
    if status['active'] and command_exists("auditctl"):
        result = run_command("auditctl -l 2>/dev/null | wc -l")
        status['rules_count'] = safe_int_parse(result.stdout.strip())
    
    return status

def check_firewall_active() -> bool:
    """Check if a firewall is active (STIG-specific simplified check)"""
    firewalls = ["ufw", "firewalld"]
    for fw in firewalls:
        if check_service_active(fw):
            return True
    
    # Check iptables has rules
    result = run_command("iptables -L -n 2>/dev/null | grep -q 'Chain'")
    return result.returncode == 0

def get_umask_value(filepath: str) -> Optional[str]:
    """Get umask value from configuration file"""
    if not os.path.exists(filepath):
        return None
    
    content = read_file_safe(filepath)
    match = re.search(r'umask\s+(\d+)', content, re.IGNORECASE)
    if match:
        return match.group(1)
    return None

def get_stig_user_accounts() -> List[Dict[str, Any]]:
    """Get list of user accounts from /etc/passwd with detailed info (STIG-specific)"""
    accounts = []
    
    if os.path.exists("/etc/passwd"):
        content = read_file_safe("/etc/passwd")
        for line in content.split('\n'):
            if line and not line.startswith('#'):
                fields = line.split(':')
                if len(fields) >= 7:
                    try:
                        accounts.append({
                            'username': fields[0],
                            'uid': int(fields[2]),
                            'gid': int(fields[3]),
                            'home': fields[5],
                            'shell': fields[6]
                        })
                    except:
                        pass
    
    return accounts

def check_account_locked(username: str) -> bool:
    """Check if an account is locked in shadow file"""
    if not os.path.exists("/etc/shadow"):
        return False
    
    content = read_file_safe("/etc/shadow")
    for line in content.split('\n'):
        if line.startswith(f"{username}:"):
            fields = line.split(':')
            if len(fields) >= 2:
                password = fields[1]
                # Locked indicators
                return password in ['!', '*', '!!', '!*', '*LK*'] or password.startswith('!')
    
    return False

def get_file_age_days(filepath: str) -> Optional[int]:
    """Get age of file in days"""
    try:
        mtime = os.path.getmtime(filepath)
        age = time.time() - mtime
        return int(age / 86400)
    except:
        return None

# ============================================================================
# ACCESS CONTROL (AC)
# STIG requires strict access control enforcement
# Reference: DISA STIG Access Control requirements
# ============================================================================

def check_access_control(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Access Control checks (AC) Security Audit Checks
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Access Control...")
    
    selinux_status = get_selinux_status(cache=cache)
    apparmor_status = get_apparmor_status(cache=cache)
    user_accounts = get_stig_user_accounts()
    
    # AC-001: Mandatory Access Control enabled (CAT II)
    mac_enabled = selinux_status['enforcing'] or (apparmor_status['enabled'] and apparmor_status['profiles_enforcing'] > 0)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_II})",
        status="Pass" if mac_enabled else "Fail",
        message=f"{get_stig_id('AC', 1)}: Mandatory Access Control enabled",
        details=f"SELinux: {selinux_status['mode']}, AppArmor: {apparmor_status['profiles_enforcing']} enforcing",
        remediation="Enable SELinux: setenforce 1 || Enable AppArmor profiles"
    ))
    
    # AC-002: Root login disabled for SSH (CAT I)
    root_login = get_ssh_config_value("PermitRootLogin")
    root_disabled = root_login and root_login.lower() == "no"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_I})",
        status="Pass" if root_disabled else "Fail",
        message=f"{get_stig_id('AC', 2)}: SSH root login disabled",
        details=f"PermitRootLogin: {root_login or 'yes (default)'}",
        remediation="Set PermitRootLogin no in /etc/ssh/sshd_config"
    ))
    
    # AC-003: Empty passwords disabled for SSH (CAT I)
    empty_passwords = get_ssh_config_value("PermitEmptyPasswords")
    empty_disabled = not empty_passwords or empty_passwords.lower() == "no"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_I})",
        status="Pass" if empty_disabled else "Fail",
        message=f"{get_stig_id('AC', 3)}: SSH empty passwords disabled",
        details=f"PermitEmptyPasswords: {empty_passwords or 'no (default)'}",
        remediation="Set PermitEmptyPasswords no in /etc/ssh/sshd_config"
    ))
    
    # AC-004: Host-based authentication disabled (CAT II)
    host_based = get_ssh_config_value("HostbasedAuthentication")
    host_based_disabled = not host_based or host_based.lower() == "no"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_II})",
        status="Pass" if host_based_disabled else "Fail",
        message=f"{get_stig_id('AC', 4)}: SSH host-based authentication disabled",
        details=f"HostbasedAuthentication: {host_based or 'no (default)'}",
        remediation="Set HostbasedAuthentication no in /etc/ssh/sshd_config"
    ))
    
    # AC-005: No users with UID 0 except root (CAT I)
    uid0_accounts = [acc['username'] for acc in user_accounts if acc['uid'] == 0 and acc['username'] != 'root']
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_I})",
        status="Pass" if not uid0_accounts else "Fail",
        message=f"{get_stig_id('AC', 5)}: Only root has UID 0",
        details=f"Other UID 0: {', '.join(uid0_accounts)}" if uid0_accounts else "Only root",
        remediation="Remove UID 0 from non-root accounts"
    ))
    
    # AC-006: System accounts are non-login (CAT II)
    system_with_shell = [acc['username'] for acc in user_accounts 
                         if acc['uid'] < 1000 and acc['uid'] != 0 
                         and acc['shell'] not in ['/sbin/nologin', '/usr/sbin/nologin', '/bin/false', '/usr/bin/false']]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_II})",
        status="Pass" if not system_with_shell else "Fail",
        message=f"{get_stig_id('AC', 6)}: System accounts have nologin shell",
        details=f"System accounts with shell: {', '.join(system_with_shell[:5])}" if system_with_shell else "All non-login",
        remediation="Set shell to /sbin/nologin: usermod -s /sbin/nologin <user>"
    ))
    
    # AC-007: All interactive users have home directories (CAT II)
    users_no_home = []
    for acc in user_accounts:
        if acc['uid'] >= 1000 and acc['username'] != 'nobody':
            if not os.path.exists(acc['home']):
                users_no_home.append(acc['username'])
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_II})",
        status="Pass" if not users_no_home else "Fail",
        message=f"{get_stig_id('AC', 7)}: All users have valid home directories",
        details=f"Missing home: {', '.join(users_no_home[:5])}" if users_no_home else "All present",
        remediation="Create home directories: mkhomedir_helper <user>"
    ))
    
    # AC-008: Home directory permissions (CAT II)
    insecure_homes = []
    for acc in user_accounts:
        if acc['uid'] >= 1000 and os.path.exists(acc['home']):
            perms = get_file_permissions(acc['home'])
            if perms and int(perms, 8) > int('750', 8):
                insecure_homes.append(f"{acc['username']}:{perms}")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_II})",
        status="Pass" if not insecure_homes else "Fail",
        message=f"{get_stig_id('AC', 8)}: Home directory permissions secure (0750 or less)",
        details=f"Insecure: {', '.join(insecure_homes[:5])}" if insecure_homes else "All secure",
        remediation="Fix permissions: chmod 0750 /home/<user>"
    ))
    
    # AC-009: Home directory ownership correct (CAT II)
    wrong_ownership = []
    for acc in user_accounts:
        if acc['uid'] >= 1000 and os.path.exists(acc['home']):
            owner, _ = get_file_owner_group(acc['home'])
            if owner != acc['username']:
                wrong_ownership.append(f"{acc['home']}:{owner}")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_II})",
        status="Pass" if not wrong_ownership else "Fail",
        message=f"{get_stig_id('AC', 9)}: Home directories owned by users",
        details=f"Wrong owner: {', '.join(wrong_ownership[:5])}" if wrong_ownership else "All correct",
        remediation="Fix ownership: chown <user>:<user> /home/<user>"
    ))
    
    # AC-010: .netrc files permissions (CAT II)
    netrc_issues = []
    for acc in user_accounts:
        if acc['uid'] >= 1000:
            netrc_path = os.path.join(acc['home'], '.netrc')
            if os.path.exists(netrc_path):
                perms = get_file_permissions(netrc_path)
                if perms and int(perms, 8) > int('600', 8):
                    netrc_issues.append(f"{acc['username']}:{perms}")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_II})",
        status="Pass" if not netrc_issues else "Fail",
        message=f"{get_stig_id('AC', 10)}: .netrc files properly secured",
        details=f"Insecure: {', '.join(netrc_issues[:5])}" if netrc_issues else "All secure",
        remediation="Fix permissions: chmod 0600 ~/.netrc"
    ))
    
    # AC-011: No .rhosts files exist (CAT I)
    rhosts_found = []
    for acc in user_accounts:
        if acc['uid'] >= 1000:
            rhosts_path = os.path.join(acc['home'], '.rhosts')
            if os.path.exists(rhosts_path):
                rhosts_found.append(acc['username'])
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_I})",
        status="Pass" if not rhosts_found else "Fail",
        message=f"{get_stig_id('AC', 11)}: No .rhosts files present",
        details=f"Found: {', '.join(rhosts_found[:5])}" if rhosts_found else "None found",
        remediation="Remove .rhosts files: rm -f ~/.rhosts"
    ))
    
    # AC-012: No shosts.equiv file (CAT I)
    shosts_equiv = os.path.exists("/etc/ssh/shosts.equiv")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_I})",
        status="Pass" if not shosts_equiv else "Fail",
        message=f"{get_stig_id('AC', 12)}: No shosts.equiv file",
        details="shosts.equiv exists" if shosts_equiv else "Not present",
        remediation="Remove: rm -f /etc/ssh/shosts.equiv"
    ))
    
    # AC-013: No hosts.equiv file (CAT I)
    hosts_equiv = os.path.exists("/etc/hosts.equiv")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_I})",
        status="Pass" if not hosts_equiv else "Fail",
        message=f"{get_stig_id('AC', 13)}: No hosts.equiv file",
        details="hosts.equiv exists" if hosts_equiv else "Not present",
        remediation="Remove: rm -f /etc/hosts.equiv"
    ))
    
    # AC-014: sudo installed and configured (CAT II)
    sudo_installed = check_package_installed("sudo", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_II})",
        status="Pass" if sudo_installed else "Fail",
        message=f"{get_stig_id('AC', 14)}: sudo installed",
        details="sudo available" if sudo_installed else "Not installed",
        remediation=remediation_for("sudo")
    ))
    
    # AC-015: sudoers file permissions (CAT II)
    if os.path.exists("/etc/sudoers"):
        perms = get_file_permissions("/etc/sudoers")
        owner, group = get_file_owner_group("/etc/sudoers")
        sudoers_ok = (perms and int(perms, 8) <= int('440', 8) and 
                      owner == 'root' and group == 'root')
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Access Control ({CAT_II})",
            status="Pass" if sudoers_ok else "Fail",
            message=f"{get_stig_id('AC', 15)}: sudoers file properly secured",
            details=f"Perms: {perms}, Owner: {owner}:{group}",
            remediation="Fix: chown root:root /etc/sudoers && chmod 0440 /etc/sudoers"
        ))
    
    # AC-016: sudoers uses !authenticate (CAT II)
    if os.path.exists("/etc/sudoers"):
        sudoers = read_file_safe("/etc/sudoers")
        no_auth = "!authenticate" in sudoers.lower()
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Access Control ({CAT_II})",
            status="Pass" if not no_auth else "Fail",
            message=f"{get_stig_id('AC', 16)}: sudoers requires authentication",
            details="!authenticate found" if no_auth else "Authentication required",
            remediation="Remove !authenticate from /etc/sudoers"
        ))
    
    # AC-017: sudoers NOPASSWD restrictions (CAT II)
    if os.path.exists("/etc/sudoers"):
        sudoers = read_file_safe("/etc/sudoers")
        nopasswd_count = len(re.findall(r'NOPASSWD:', sudoers))
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Access Control ({CAT_II})",
            status="Warning" if nopasswd_count > 0 else "Pass",
            message=f"{get_stig_id('AC', 17)}: sudoers NOPASSWD usage minimal",
            details=f"{nopasswd_count} NOPASSWD entries",
            remediation="Minimize NOPASSWD entries in /etc/sudoers"
        ))
    
    # AC-018: /etc/passwd permissions (CAT II)
    passwd_perms = get_file_permissions("/etc/passwd")
    passwd_ok = passwd_perms and int(passwd_perms, 8) <= int('644', 8)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_II})",
        status="Pass" if passwd_ok else "Fail",
        message=f"{get_stig_id('AC', 18)}: /etc/passwd permissions secure",
        details=f"Permissions: {passwd_perms}",
        remediation="chmod 0644 /etc/passwd"
    ))
    
    # AC-019: /etc/shadow permissions (CAT II)
    if os.path.exists("/etc/shadow"):
        shadow_perms = get_file_permissions("/etc/shadow")
        shadow_ok = shadow_perms and int(shadow_perms, 8) <= int('000', 8)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Access Control ({CAT_II})",
            status="Pass" if shadow_ok else "Fail",
            message=f"{get_stig_id('AC', 19)}: /etc/shadow permissions secure",
            details=f"Permissions: {shadow_perms}",
            remediation="chmod 0000 /etc/shadow"
        ))
    
    # AC-020: /etc/group permissions (CAT II)
    group_perms = get_file_permissions("/etc/group")
    group_ok = group_perms and int(group_perms, 8) <= int('644', 8)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_II})",
        status="Pass" if group_ok else "Fail",
        message=f"{get_stig_id('AC', 20)}: /etc/group permissions secure",
        details=f"Permissions: {group_perms}",
        remediation="chmod 0644 /etc/group"
    ))
    
    # AC-021: /etc/gshadow permissions (CAT II)
    if os.path.exists("/etc/gshadow"):
        gshadow_perms = get_file_permissions("/etc/gshadow")
        gshadow_ok = gshadow_perms and int(gshadow_perms, 8) <= int('000', 8)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Access Control ({CAT_II})",
            status="Pass" if gshadow_ok else "Fail",
            message=f"{get_stig_id('AC', 21)}: /etc/gshadow permissions secure",
            details=f"Permissions: {gshadow_perms}",
            remediation="chmod 0000 /etc/gshadow"
        ))
    
    # AC-022: World-writable files (CAT II) (canonical assessment)
    from shared_components.shared_assessments import get_world_writable_assessment as _ww_assess
    _ww = _ww_assess("fail")
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_II})",
        status=_ww.status,
        message=f"{get_stig_id('AC', 22)}: No world-writable files",
        details=_ww.details,
        remediation=_ww.remediation
    ))
    
    # AC-023: World-writable directories (CAT II)
    result = run_command("find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | head -20 | wc -l")
    ww_dirs = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_II})",
        status="Pass" if ww_dirs == 0 else "Fail",
        message=f"{get_stig_id('AC', 23)}: World-writable dirs have sticky bit",
        details=f"{ww_dirs} dirs without sticky bit",
        remediation="Add sticky bit: chmod +t <directory>"
    ))
    
    # AC-024: Unowned files and directories (CAT II)
    result = run_command("find / -xdev \\( -nouser -o -nogroup \\) 2>/dev/null | head -10 | wc -l")
    unowned = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_II})",
        status="Pass" if unowned == 0 else "Fail",
        message=f"{get_stig_id('AC', 24)}: No unowned files/directories",
        details=f"{unowned} unowned items",
        remediation="Assign ownership: chown <user>:<group> <file>"
    ))
    
    # AC-025: SUID files inventory (CAT II)
    result = run_command("find / -xdev -perm -4000 -type f 2>/dev/null | wc -l")
    suid_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_II})",
        status="Info",
        message=f"{get_stig_id('AC', 25)}: SUID files inventory",
        details=f"{suid_count} SUID files",
        remediation="Review and minimize SUID files"
    ))
    
    # AC-026: SGID files inventory (CAT II)
    result = run_command("find / -xdev -perm -2000 -type f 2>/dev/null | wc -l")
    sgid_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_II})",
        status="Info",
        message=f"{get_stig_id('AC', 26)}: SGID files inventory",
        details=f"{sgid_count} SGID files",
        remediation="Review and minimize SGID files"
    ))
    
    # AC-027: User initialization files permissions (CAT II)
    init_file_issues = []
    for acc in user_accounts:
        if acc['uid'] >= 1000:
            for init_file in ['.bashrc', '.bash_profile', '.profile', '.bash_login']:
                init_path = os.path.join(acc['home'], init_file)
                if os.path.exists(init_path):
                    perms = get_file_permissions(init_path)
                    if perms and int(perms, 8) > int('740', 8):
                        init_file_issues.append(f"{acc['username']}:{init_file}")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_II})",
        status="Pass" if not init_file_issues else "Warning",
        message=f"{get_stig_id('AC', 27)}: User initialization files secured",
        details=f"Issues: {len(init_file_issues)}" if init_file_issues else "All secure",
        remediation="Fix permissions: chmod 0740 ~/.<file>"
    ))
    
    # AC-028: No .forward files (CAT II)
    forward_files = []
    for acc in user_accounts:
        if acc['uid'] >= 1000:
            forward_path = os.path.join(acc['home'], '.forward')
            if os.path.exists(forward_path):
                forward_files.append(acc['username'])
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_II})",
        status="Pass" if not forward_files else "Warning",
        message=f"{get_stig_id('AC', 28)}: No .forward files present",
        details=f"Found: {', '.join(forward_files[:5])}" if forward_files else "None",
        remediation="Remove .forward files: rm -f ~/.forward"
    ))
    
    # AC-029: Default umask secure (CAT II)
    login_defs = read_file_safe("/etc/login.defs")
    umask_match = re.search(r'^UMASK\s+(\d+)', login_defs, re.MULTILINE)
    
    if umask_match:
        umask_value = umask_match.group(1)
        umask_ok = umask_value in ["027", "077"]
    else:
        umask_value = "not set"
        umask_ok = False
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_II})",
        status="Pass" if umask_ok else "Fail",
        message=f"{get_stig_id('AC', 29)}: Default umask secure (027 or 077)",
        details=f"UMASK = {umask_value}",
        remediation="Set UMASK 027 in /etc/login.defs"
    ))
    
    # AC-030: Session timeout configured (CAT II)
    timeout_files = ["/etc/profile", "/etc/bash.bashrc"]
    timeout_configured = False
    
    for tf in timeout_files:
        if os.path.exists(tf):
            content = read_file_safe(tf)
            if re.search(r'TMOUT\s*=\s*\d+', content):
                timeout_configured = True
                break
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_II})",
        status="Pass" if timeout_configured else "Fail",
        message=f"{get_stig_id('AC', 30)}: Session timeout configured",
        details="TMOUT set" if timeout_configured else "Not configured",
        remediation="Set TMOUT=900 in /etc/profile"
    ))
    
    # AC-031: cron restricted to authorized users (CAT II)
    cron_allow = os.path.exists("/etc/cron.allow")
    cron_deny = os.path.exists("/etc/cron.deny")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_II})",
        status="Pass" if cron_allow else "Warning",
        message=f"{get_stig_id('AC', 31)}: cron access restricted",
        details="cron.allow exists" if cron_allow else "Using cron.deny" if cron_deny else "Not restricted",
        remediation="Create /etc/cron.allow with authorized users"
    ))
    
    # AC-032: at restricted to authorized users (CAT II)
    at_allow = os.path.exists("/etc/at.allow")
    at_deny = os.path.exists("/etc/at.deny")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_II})",
        status="Pass" if at_allow else "Warning",
        message=f"{get_stig_id('AC', 32)}: at daemon access restricted",
        details="at.allow exists" if at_allow else "Using at.deny" if at_deny else "Not restricted",
        remediation="Create /etc/at.allow with authorized users"
    ))
    
    # AC-033: cron directories permissions (CAT II)
    cron_dirs = {
        "/etc/cron.hourly": "700",
        "/etc/cron.daily": "700",
        "/etc/cron.weekly": "700",
        "/etc/cron.monthly": "700",
        "/etc/cron.d": "700"
    }
    
    cron_issues = []
    for cron_dir, max_perms in cron_dirs.items():
        if os.path.exists(cron_dir):
            perms = get_file_permissions(cron_dir)
            if perms and int(perms, 8) > int(max_perms, 8):
                cron_issues.append(f"{cron_dir}:{perms}")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_II})",
        status="Pass" if not cron_issues else "Fail",
        message=f"{get_stig_id('AC', 33)}: cron directories properly secured",
        details=f"Issues: {', '.join(cron_issues)}" if cron_issues else "All secure",
        remediation="chmod 0700 /etc/cron.*"
    ))
    
    # AC-034: crontab permissions (CAT II)
    crontab_perms = get_file_permissions("/etc/crontab") if os.path.exists("/etc/crontab") else None
    crontab_ok = crontab_perms and int(crontab_perms, 8) <= int('600', 8)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_II})",
        status="Pass" if crontab_ok else "Warning",
        message=f"{get_stig_id('AC', 34)}: /etc/crontab permissions secure",
        details=f"Permissions: {crontab_perms}" if crontab_perms else "File not found",
        remediation="chmod 0600 /etc/crontab"
    ))
    
    # AC-035: SSH grace time configured (CAT II)
    login_grace = get_ssh_config_value("LoginGraceTime")
    grace_ok = login_grace and safe_int_parse(login_grace.rstrip('s')) <= 60
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_II})",
        status="Pass" if grace_ok else "Warning",
        message=f"{get_stig_id('AC', 35)}: SSH login grace time limited",
        details=f"LoginGraceTime: {login_grace or '120s (default)'}",
        remediation="Set LoginGraceTime 60 in /etc/ssh/sshd_config"
    ))
    
    # AC-036: SSH max sessions limited (CAT II)
    max_sessions = get_ssh_config_value("MaxSessions")
    sessions_ok = max_sessions and safe_int_parse(max_sessions) <= 10
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_II})",
        status="Pass" if sessions_ok else "Warning",
        message=f"{get_stig_id('AC', 36)}: SSH max sessions limited",
        details=f"MaxSessions: {max_sessions or '10 (default)'}",
        remediation="Set MaxSessions 10 in /etc/ssh/sshd_config"
    ))
    
    # AC-037: SSH alive interval configured (CAT II)
    alive_interval = get_ssh_config_value("ClientAliveInterval")
    alive_count = get_ssh_config_value("ClientAliveCountMax")
    alive_ok = alive_interval and safe_int_parse(alive_interval) > 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_II})",
        status="Pass" if alive_ok else "Fail",
        message=f"{get_stig_id('AC', 37)}: SSH session timeout configured",
        details=f"Interval: {alive_interval or '0'}, Count: {alive_count or '3'}",
        remediation="Set ClientAliveInterval 300 and ClientAliveCountMax 0 in /etc/ssh/sshd_config"
    ))
    
    # AC-038: SSH max auth tries limited (CAT II)
    max_auth_tries = get_ssh_config_value("MaxAuthTries")
    auth_ok = max_auth_tries and safe_int_parse(max_auth_tries) <= 4
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_II})",
        status="Pass" if auth_ok else "Fail",
        message=f"{get_stig_id('AC', 38)}: SSH max auth tries limited",
        details=f"MaxAuthTries: {max_auth_tries or '6 (default)'}",
        remediation="Set MaxAuthTries 4 in /etc/ssh/sshd_config"
    ))
    
    # AC-039: SSH ignores .rhosts (CAT I)
    ignore_rhosts = get_ssh_config_value("IgnoreRhosts")
    rhosts_ignored = not ignore_rhosts or ignore_rhosts.lower() == "yes"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_I})",
        status="Pass" if rhosts_ignored else "Fail",
        message=f"{get_stig_id('AC', 39)}: SSH ignores .rhosts files",
        details=f"IgnoreRhosts: {ignore_rhosts or 'yes (default)'}",
        remediation="Set IgnoreRhosts yes in /etc/ssh/sshd_config"
    ))
    
    # AC-040: SSH user environment disabled (CAT II)
    permit_user_env = get_ssh_config_value("PermitUserEnvironment")
    user_env_disabled = not permit_user_env or permit_user_env.lower() == "no"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Access Control ({CAT_II})",
        status="Pass" if user_env_disabled else "Fail",
        message=f"{get_stig_id('AC', 40)}: SSH user environment disabled",
        details=f"PermitUserEnvironment: {permit_user_env or 'no (default)'}",
        remediation="Set PermitUserEnvironment no in /etc/ssh/sshd_config"
    ))


# ============================================================================
# AUDIT AND ACCOUNTABILITY (AU)
# STIG requires comprehensive audit logging and accountability
# Reference: DISA STIG Audit and Accountability requirements
# ============================================================================

def check_audit_accountability(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Audit and Accountability (AU) Security Audit Checks
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Audit and Accountability...")
    
    auditd_status = get_auditd_status(os_info)
    
    # AU-001: auditd installed (CAT II)
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Audit & Accountability ({CAT_II})",
        status="Pass" if auditd_status['installed'] else "Fail",
        message=f"{get_stig_id('AU', 1)}: auditd package installed",
        details="auditd installed" if auditd_status['installed'] else "Not installed",
        remediation=remediation_for("auditd")
    ))
    
    # AU-002: auditd service enabled (CAT II)
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Audit & Accountability ({CAT_II})",
        status="Pass" if auditd_status['enabled'] else "Fail",
        message=f"{get_stig_id('AU', 2)}: auditd service enabled",
        details="Enabled" if auditd_status['enabled'] else "Not enabled",
        remediation=remediation_for("auditd")
    ))
    
    # AU-003: auditd service active (CAT II)
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Audit & Accountability ({CAT_II})",
        status="Pass" if auditd_status['active'] else "Fail",
        message=f"{get_stig_id('AU', 3)}: auditd service running",
        details="Active" if auditd_status['active'] else "Not running",
        remediation="systemctl start auditd"
    ))
    
    # AU-004: audit rules loaded (CAT II)
    rules_count = auditd_status['rules_count']
    rules_ok = rules_count >= 10
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Audit & Accountability ({CAT_II})",
        status="Pass" if rules_ok else "Fail",
        message=f"{get_stig_id('AU', 4)}: Audit rules configured",
        details=f"{rules_count} rules loaded",
        remediation="Configure audit rules in /etc/audit/rules.d/"
    ))
    
    # AU-005: Audit date and time modifications (CAT II)
    time_audit_rules = [
        "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change",
        "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -k time-change",
        "-a always,exit -F arch=b64 -S clock_settime -k time-change"
    ]
    
    if command_exists("auditctl"):
        result = run_command("auditctl -l 2>/dev/null | grep -c 'time-change'")
        time_rules = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Audit & Accountability ({CAT_II})",
            status="Pass" if time_rules >= 2 else "Fail",
            message=f"{get_stig_id('AU', 5)}: Time/date modifications audited",
            details=f"{time_rules} time-change rules",
            remediation=f"Add to /etc/audit/rules.d/audit.rules: {time_audit_rules[0]}"
        ))
    
    # AU-006: Audit user/group modifications (CAT II)
    if command_exists("auditctl"):
        result = run_command("auditctl -l 2>/dev/null | grep -E '(passwd|group|shadow|gshadow)' | wc -l")
        identity_rules = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Audit & Accountability ({CAT_II})",
            status="Pass" if identity_rules >= 4 else "Fail",
            message=f"{get_stig_id('AU', 6)}: User/group modifications audited",
            details=f"{identity_rules} identity file watches",
            remediation="Add watches: -w /etc/passwd -p wa -k identity"
        ))
    
    # AU-007: Audit network environment (CAT II)
    if command_exists("auditctl"):
        result = run_command("auditctl -l 2>/dev/null | grep -E '(sethostname|setdomainname)' | wc -l")
        network_rules = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Audit & Accountability ({CAT_II})",
            status="Pass" if network_rules >= 2 else "Fail",
            message=f"{get_stig_id('AU', 7)}: Network environment changes audited",
            details=f"{network_rules} network audit rules",
            remediation="Add: -a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale"
        ))
    
    # AU-008: Audit MAC modifications (CAT II)
    if command_exists("auditctl"):
        result = run_command("auditctl -l 2>/dev/null | grep -E '(/etc/selinux|/etc/apparmor)' | wc -l")
        mac_rules = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Audit & Accountability ({CAT_II})",
            status="Pass" if mac_rules >= 1 else "Fail",
            message=f"{get_stig_id('AU', 8)}: MAC policy modifications audited",
            details=f"{mac_rules} MAC audit rules",
            remediation="Add: -w /etc/selinux/ -p wa -k MAC-policy"
        ))
    
    # AU-009: Audit failed login attempts (CAT II)
    if command_exists("auditctl"):
        result = run_command("auditctl -l 2>/dev/null | grep -c 'logins'")
        login_rules = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Audit & Accountability ({CAT_II})",
            status="Pass" if login_rules >= 1 else "Fail",
            message=f"{get_stig_id('AU', 9)}: Login attempts audited",
            details=f"{login_rules} login audit rules",
            remediation="Add: -w /var/log/faillog -p wa -k logins"
        ))
    
    # AU-010: Audit session initiation (CAT II)
    if command_exists("auditctl"):
        result = run_command("auditctl -l 2>/dev/null | grep -E '(wtmp|btmp|utmp)' | wc -l")
        session_rules = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Audit & Accountability ({CAT_II})",
            status="Pass" if session_rules >= 2 else "Fail",
            message=f"{get_stig_id('AU', 10)}: Session initiation audited",
            details=f"{session_rules} session audit rules",
            remediation="Add: -w /var/log/wtmp -p wa -k session"
        ))
    
    # AU-011: Audit permission modifications (CAT II)
    if command_exists("auditctl"):
        result = run_command("auditctl -l 2>/dev/null | grep -E '(chmod|chown|setxattr)' | wc -l")
        perm_rules = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Audit & Accountability ({CAT_II})",
            status="Pass" if perm_rules >= 3 else "Fail",
            message=f"{get_stig_id('AU', 11)}: Permission modifications audited",
            details=f"{perm_rules} permission audit rules",
            remediation="Add: -a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod"
        ))
    
    # AU-012: Audit file deletion (CAT II)
    if command_exists("auditctl"):
        result = run_command("auditctl -l 2>/dev/null | grep -E '(unlink|rename|rmdir)' | wc -l")
        delete_rules = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Audit & Accountability ({CAT_II})",
            status="Pass" if delete_rules >= 2 else "Fail",
            message=f"{get_stig_id('AU', 12)}: File deletion audited",
            details=f"{delete_rules} deletion audit rules",
            remediation="Add: -a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete"
        ))
    
    # AU-013: Audit sudoers modifications (CAT II)
    if command_exists("auditctl"):
        result = run_command("auditctl -l 2>/dev/null | grep -c 'sudoers'")
        sudo_rules = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Audit & Accountability ({CAT_II})",
            status="Pass" if sudo_rules >= 1 else "Fail",
            message=f"{get_stig_id('AU', 13)}: sudoers modifications audited",
            details=f"{sudo_rules} sudoers audit rules",
            remediation="Add: -w /etc/sudoers -p wa -k scope"
        ))
    
    # AU-014: Audit kernel module operations (CAT II)
    if command_exists("auditctl"):
        result = run_command("auditctl -l 2>/dev/null | grep -E '(init_module|delete_module)' | wc -l")
        module_rules = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Audit & Accountability ({CAT_II})",
            status="Pass" if module_rules >= 2 else "Fail",
            message=f"{get_stig_id('AU', 14)}: Kernel module operations audited",
            details=f"{module_rules} module audit rules",
            remediation="Add: -a always,exit -F arch=b64 -S init_module -S delete_module -k modules"
        ))
    
    # AU-015: Audit configuration immutable (CAT II)
    if os.path.exists("/etc/audit/audit.rules"):
        audit_rules = read_file_safe("/etc/audit/audit.rules")
        immutable = "-e 2" in audit_rules
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Audit & Accountability ({CAT_II})",
            status="Pass" if immutable else "Warning",
            message=f"{get_stig_id('AU', 15)}: Audit configuration immutable",
            details="Immutable" if immutable else "Can be modified",
            remediation="Add '-e 2' to end of /etc/audit/audit.rules"
        ))
    
    # AU-016: auditd.conf space_left action (CAT II)
    if os.path.exists("/etc/audit/auditd.conf"):
        auditd_conf = read_file_safe("/etc/audit/auditd.conf")
        space_left = re.search(r'space_left_action\s*=\s*(\w+)', auditd_conf)
        action_ok = space_left and space_left.group(1).lower() in ['email', 'syslog', 'exec', 'single', 'halt']
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Audit & Accountability ({CAT_II})",
            status="Pass" if action_ok else "Fail",
            message=f"{get_stig_id('AU', 16)}: Low disk space action configured",
            details=f"space_left_action = {space_left.group(1) if space_left else 'not set'}",
            remediation="Set space_left_action = email in /etc/audit/auditd.conf"
        ))
    
    # AU-017: auditd.conf admin_space_left action (CAT II)
    if os.path.exists("/etc/audit/auditd.conf"):
        auditd_conf = read_file_safe("/etc/audit/auditd.conf")
        admin_space = re.search(r'admin_space_left_action\s*=\s*(\w+)', auditd_conf)
        admin_ok = admin_space and admin_space.group(1).lower() in ['single', 'halt']
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Audit & Accountability ({CAT_II})",
            status="Pass" if admin_ok else "Fail",
            message=f"{get_stig_id('AU', 17)}: Critical disk space action configured",
            details=f"admin_space_left_action = {admin_space.group(1) if admin_space else 'not set'}",
            remediation="Set admin_space_left_action = halt in /etc/audit/auditd.conf"
        ))
    
    # AU-018: auditd.conf disk_full action (CAT II)
    if os.path.exists("/etc/audit/auditd.conf"):
        auditd_conf = read_file_safe("/etc/audit/auditd.conf")
        disk_full = re.search(r'disk_full_action\s*=\s*(\w+)', auditd_conf)
        full_ok = disk_full and disk_full.group(1).lower() in ['single', 'halt']
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Audit & Accountability ({CAT_II})",
            status="Pass" if full_ok else "Fail",
            message=f"{get_stig_id('AU', 18)}: Disk full action configured",
            details=f"disk_full_action = {disk_full.group(1) if disk_full else 'not set'}",
            remediation="Set disk_full_action = halt in /etc/audit/auditd.conf"
        ))
    
    # AU-019: auditd.conf disk_error action (CAT II)
    if os.path.exists("/etc/audit/auditd.conf"):
        auditd_conf = read_file_safe("/etc/audit/auditd.conf")
        disk_error = re.search(r'disk_error_action\s*=\s*(\w+)', auditd_conf)
        error_ok = disk_error and disk_error.group(1).lower() in ['single', 'halt', 'syslog']
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Audit & Accountability ({CAT_II})",
            status="Pass" if error_ok else "Warning",
            message=f"{get_stig_id('AU', 19)}: Disk error action configured",
            details=f"disk_error_action = {disk_error.group(1) if disk_error else 'not set'}",
            remediation="Set disk_error_action = halt in /etc/audit/auditd.conf"
        ))
    
    # AU-020: auditd.conf max_log_file size (CAT II)
    if os.path.exists("/etc/audit/auditd.conf"):
        auditd_conf = read_file_safe("/etc/audit/auditd.conf")
        max_log = re.search(r'max_log_file\s*=\s*(\d+)', auditd_conf)
        size_ok = max_log and int(max_log.group(1)) >= 6
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Audit & Accountability ({CAT_II})",
            status="Pass" if size_ok else "Warning",
            message=f"{get_stig_id('AU', 20)}: Audit log file size configured",
            details=f"max_log_file = {max_log.group(1) if max_log else 'not set'} MB",
            remediation="Set max_log_file = 6 (or higher) in /etc/audit/auditd.conf"
        ))
    
    # AU-021: auditd.conf max_log_file_action (CAT II)
    if os.path.exists("/etc/audit/auditd.conf"):
        auditd_conf = read_file_safe("/etc/audit/auditd.conf")
        log_action = re.search(r'max_log_file_action\s*=\s*(\w+)', auditd_conf)
        action_ok = log_action and log_action.group(1).lower() in ['rotate', 'keep_logs']
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Audit & Accountability ({CAT_II})",
            status="Pass" if action_ok else "Warning",
            message=f"{get_stig_id('AU', 21)}: Audit log rotation configured",
            details=f"max_log_file_action = {log_action.group(1) if log_action else 'not set'}",
            remediation="Set max_log_file_action = rotate in /etc/audit/auditd.conf"
        ))
    
    # AU-022: Audit logs permissions (CAT II)
    audit_log_dir = "/var/log/audit"
    if os.path.exists(audit_log_dir):
        dir_perms = get_file_permissions(audit_log_dir)
        perms_ok = dir_perms and int(dir_perms, 8) <= int('700', 8)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Audit & Accountability ({CAT_II})",
            status="Pass" if perms_ok else "Fail",
            message=f"{get_stig_id('AU', 22)}: Audit log directory permissions secure",
            details=f"Permissions: {dir_perms}",
            remediation="chmod 0700 /var/log/audit"
        ))
    
    # AU-023: Audit log files permissions (CAT II)
    if os.path.exists(audit_log_dir):
        log_files = glob.glob(f"{audit_log_dir}/audit.log*")
        insecure_logs = []
        
        for log_file in log_files[:10]:
            perms = get_file_permissions(log_file)
            if perms and int(perms, 8) > int('600', 8):
                insecure_logs.append(os.path.basename(log_file))
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Audit & Accountability ({CAT_II})",
            status="Pass" if not insecure_logs else "Fail",
            message=f"{get_stig_id('AU', 23)}: Audit log files permissions secure",
            details=f"Insecure: {', '.join(insecure_logs)}" if insecure_logs else "All secure",
            remediation="chmod 0600 /var/log/audit/audit.log*"
        ))
    
    # AU-024: rsyslog installed (CAT II)
    rsyslog_installed = check_package_installed("rsyslog", os_info) or check_package_installed("syslog-ng", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Audit & Accountability ({CAT_II})",
        status="Pass" if rsyslog_installed else "Fail",
        message=f"{get_stig_id('AU', 24)}: System logging installed",
        details="rsyslog/syslog-ng installed" if rsyslog_installed else "Not installed",
        remediation=remediation_for("rsyslog")
    ))
    
    # AU-025: rsyslog service active (CAT II)
    rsyslog_active = check_service_active("rsyslog") or check_service_active("syslog-ng")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Audit & Accountability ({CAT_II})",
        status="Pass" if rsyslog_active else "Fail",
        message=f"{get_stig_id('AU', 25)}: System logging service active",
        details="Service running" if rsyslog_active else "Not running",
        remediation="systemctl start rsyslog"
    ))
    
    # AU-026: System log files exist (CAT II)
    log_files = ["/var/log/syslog", "/var/log/messages", "/var/log/secure", "/var/log/auth.log"]
    existing_logs = [f for f in log_files if os.path.exists(f)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Audit & Accountability ({CAT_II})",
        status="Pass" if len(existing_logs) >= 2 else "Warning",
        message=f"{get_stig_id('AU', 26)}: System log files present",
        details=f"{len(existing_logs)}/4 log files exist",
        remediation="Configure rsyslog to generate log files"
    ))
    
    # AU-027: Log rotation configured (CAT II)
    logrotate_installed = check_package_installed("logrotate", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Audit & Accountability ({CAT_II})",
        status="Pass" if logrotate_installed else "Fail",
        message=f"{get_stig_id('AU', 27)}: Log rotation configured",
        details="logrotate installed" if logrotate_installed else "Not installed",
        remediation=remediation_for("logrotate")
    ))
    
    # AU-028: Logrotate configuration exists (CAT II)
    logrotate_conf = os.path.exists("/etc/logrotate.conf")
    logrotate_d = os.path.exists("/etc/logrotate.d")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Audit & Accountability ({CAT_II})",
        status="Pass" if logrotate_conf and logrotate_d else "Warning",
        message=f"{get_stig_id('AU', 28)}: Logrotate properly configured",
        details="Configuration present" if logrotate_conf else "Missing config",
        remediation="Configure /etc/logrotate.conf"
    ))
    
    # AU-029: lastlog command available (CAT III)
    lastlog_exists = command_exists("lastlog")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Audit & Accountability ({CAT_III})",
        status="Pass" if lastlog_exists else "Info",
        message=f"{get_stig_id('AU', 29)}: Last login tracking available",
        details="lastlog available" if lastlog_exists else "Not available",
        remediation="Ensure util-linux package is installed"
    ))
    
    # AU-030: faillog tracks failed logins (CAT III)
    faillog_exists = os.path.exists("/var/log/faillog")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Audit & Accountability ({CAT_III})",
        status="Pass" if faillog_exists else "Info",
        message=f"{get_stig_id('AU', 30)}: Failed login tracking enabled",
        details="faillog present" if faillog_exists else "Not configured",
        remediation="Configure PAM to log failed attempts"
    ))


# ============================================================================
# IDENTIFICATION AND AUTHENTICATION (IA)
# STIG requires strong authentication mechanisms
# Reference: DISA STIG Identification and Authentication requirements
# ============================================================================

def check_identification_authentication(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Identification and Authentication (IA) Security Audit Checks
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Identification & Authentication...")
    
    password_policy = get_password_policy()
    
    # IA-001: Password maximum age (CAT II)
    max_days = password_policy['pass_max_days']
    max_ok = max_days and max_days <= 60
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Identification & Authentication ({CAT_II})",
        status="Pass" if max_ok else "Fail",
        message=f"{get_stig_id('IA', 1)}: Password maximum age 60 days or less",
        details=f"PASS_MAX_DAYS = {max_days}",
        remediation="Set PASS_MAX_DAYS 60 in /etc/login.defs"
    ))
    
    # IA-002: Password minimum age (CAT II)
    min_days = password_policy['pass_min_days']
    min_ok = min_days and min_days >= 1
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Identification & Authentication ({CAT_II})",
        status="Pass" if min_ok else "Fail",
        message=f"{get_stig_id('IA', 2)}: Password minimum age 1 day or more",
        details=f"PASS_MIN_DAYS = {min_days}",
        remediation="Set PASS_MIN_DAYS 1 in /etc/login.defs"
    ))
    
    # IA-003: Password minimum length (CAT II)
    min_len = password_policy['pass_min_len']
    len_ok = min_len and min_len >= 15
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Identification & Authentication ({CAT_II})",
        status="Pass" if len_ok else "Fail",
        message=f"{get_stig_id('IA', 3)}: Password minimum length 15 characters",
        details=f"PASS_MIN_LEN = {min_len}",
        remediation="Set PASS_MIN_LEN 15 in /etc/login.defs"
    ))
    
    # IA-004: Password warning age (CAT III)
    warn_age = password_policy['pass_warn_age']
    warn_ok = warn_age and warn_age >= 7
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Identification & Authentication ({CAT_III})",
        status="Pass" if warn_ok else "Warning",
        message=f"{get_stig_id('IA', 4)}: Password expiration warning 7 days",
        details=f"PASS_WARN_AGE = {warn_age}",
        remediation="Set PASS_WARN_AGE 7 in /etc/login.defs"
    ))
    
    # IA-005: PAM password complexity (CAT II)
    pwquality_configured = check_pam_module("pam_pwquality") or check_pam_module("pam_cracklib")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Identification & Authentication ({CAT_II})",
        status="Pass" if pwquality_configured else "Fail",
        message=f"{get_stig_id('IA', 5)}: Password complexity enforced",
        details="pam_pwquality configured" if pwquality_configured else "Not configured",
        remediation="Configure pam_pwquality in /etc/pam.d/common-password"
    ))
    
    # IA-006: pwquality minimum different characters (CAT II)
    if os.path.exists("/etc/security/pwquality.conf"):
        pwquality = read_file_safe("/etc/security/pwquality.conf")
        difok = re.search(r'difok\s*=\s*(\d+)', pwquality)
        difok_ok = difok and int(difok.group(1)) >= 8
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Identification & Authentication ({CAT_II})",
            status="Pass" if difok_ok else "Fail",
            message=f"{get_stig_id('IA', 6)}: Password requires 8 different characters",
            details=f"difok = {difok.group(1) if difok else 'not set'}",
            remediation="Set difok = 8 in /etc/security/pwquality.conf"
        ))
    
    # IA-007: pwquality minimum uppercase (CAT II)
    if os.path.exists("/etc/security/pwquality.conf"):
        pwquality = read_file_safe("/etc/security/pwquality.conf")
        ucredit = re.search(r'ucredit\s*=\s*(-?\d+)', pwquality)
        ucredit_ok = ucredit and int(ucredit.group(1)) <= -1
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Identification & Authentication ({CAT_II})",
            status="Pass" if ucredit_ok else "Fail",
            message=f"{get_stig_id('IA', 7)}: Password requires uppercase character",
            details=f"ucredit = {ucredit.group(1) if ucredit else 'not set'}",
            remediation="Set ucredit = -1 in /etc/security/pwquality.conf"
        ))
    
    # IA-008: pwquality minimum lowercase (CAT II)
    if os.path.exists("/etc/security/pwquality.conf"):
        pwquality = read_file_safe("/etc/security/pwquality.conf")
        lcredit = re.search(r'lcredit\s*=\s*(-?\d+)', pwquality)
        lcredit_ok = lcredit and int(lcredit.group(1)) <= -1
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Identification & Authentication ({CAT_II})",
            status="Pass" if lcredit_ok else "Fail",
            message=f"{get_stig_id('IA', 8)}: Password requires lowercase character",
            details=f"lcredit = {lcredit.group(1) if lcredit else 'not set'}",
            remediation="Set lcredit = -1 in /etc/security/pwquality.conf"
        ))
    
    # IA-009: pwquality minimum digit (CAT II)
    if os.path.exists("/etc/security/pwquality.conf"):
        pwquality = read_file_safe("/etc/security/pwquality.conf")
        dcredit = re.search(r'dcredit\s*=\s*(-?\d+)', pwquality)
        dcredit_ok = dcredit and int(dcredit.group(1)) <= -1
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Identification & Authentication ({CAT_II})",
            status="Pass" if dcredit_ok else "Fail",
            message=f"{get_stig_id('IA', 9)}: Password requires numeric character",
            details=f"dcredit = {dcredit.group(1) if dcredit else 'not set'}",
            remediation="Set dcredit = -1 in /etc/security/pwquality.conf"
        ))
    
    # IA-010: pwquality minimum special character (CAT II)
    if os.path.exists("/etc/security/pwquality.conf"):
        pwquality = read_file_safe("/etc/security/pwquality.conf")
        ocredit = re.search(r'ocredit\s*=\s*(-?\d+)', pwquality)
        ocredit_ok = ocredit and int(ocredit.group(1)) <= -1
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Identification & Authentication ({CAT_II})",
            status="Pass" if ocredit_ok else "Fail",
            message=f"{get_stig_id('IA', 10)}: Password requires special character",
            details=f"ocredit = {ocredit.group(1) if ocredit else 'not set'}",
            remediation="Set ocredit = -1 in /etc/security/pwquality.conf"
        ))
    
    # IA-011: pwquality maximum consecutive characters (CAT II)
    if os.path.exists("/etc/security/pwquality.conf"):
        pwquality = read_file_safe("/etc/security/pwquality.conf")
        maxrepeat = re.search(r'maxrepeat\s*=\s*(\d+)', pwquality)
        repeat_ok = maxrepeat and int(maxrepeat.group(1)) <= 3
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Identification & Authentication ({CAT_II})",
            status="Pass" if repeat_ok else "Warning",
            message=f"{get_stig_id('IA', 11)}: Password consecutive character limit",
            details=f"maxrepeat = {maxrepeat.group(1) if maxrepeat else 'not set'}",
            remediation="Set maxrepeat = 3 in /etc/security/pwquality.conf"
        ))
    
    # IA-012: pwquality maximum sequential characters (CAT II)
    if os.path.exists("/etc/security/pwquality.conf"):
        pwquality = read_file_safe("/etc/security/pwquality.conf")
        maxsequence = re.search(r'maxsequence\s*=\s*(\d+)', pwquality)
        seq_ok = maxsequence and int(maxsequence.group(1)) <= 3
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Identification & Authentication ({CAT_II})",
            status="Pass" if seq_ok else "Warning",
            message=f"{get_stig_id('IA', 12)}: Password sequential character limit",
            details=f"maxsequence = {maxsequence.group(1) if maxsequence else 'not set'}",
            remediation="Set maxsequence = 3 in /etc/security/pwquality.conf"
        ))
    
    # IA-013: Password history remember (CAT II)
    pam_remember = check_pam_module("pam_pwhistory") or check_pam_module("remember=")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Identification & Authentication ({CAT_II})",
        status="Pass" if pam_remember else "Fail",
        message=f"{get_stig_id('IA', 13)}: Password history enforcement",
        details="Configured" if pam_remember else "Not configured",
        remediation="Add pam_pwhistory.so remember=5 to PAM"
    ))
    
    # IA-014: Account lockout policy (CAT II)
    faillock_configured = check_pam_module("pam_faillock") or check_pam_module("pam_tally2")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Identification & Authentication ({CAT_II})",
        status="Pass" if faillock_configured else "Fail",
        message=f"{get_stig_id('IA', 14)}: Account lockout configured",
        details="faillock configured" if faillock_configured else "Not configured",
        remediation="Configure pam_faillock in PAM"
    ))
    
    # IA-015: Faillock deny attempts (CAT II)
    if faillock_configured:
        pam_files = glob.glob("/etc/pam.d/*")
        deny_value = None
        
        for pf in pam_files:
            content = read_file_safe(pf)
            deny = re.search(r'pam_faillock.*deny=(\d+)', content)
            if deny:
                deny_value = int(deny.group(1))
                break
        
        deny_ok = deny_value and deny_value <= 3
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Identification & Authentication ({CAT_II})",
            status="Pass" if deny_ok else "Warning",
            message=f"{get_stig_id('IA', 15)}: Account lockout after 3 attempts",
            details=f"deny = {deny_value}" if deny_value else "Not configured",
            remediation="Set deny=3 in pam_faillock configuration"
        ))
    
    # IA-016: Faillock unlock time (CAT II)
    if faillock_configured:
        pam_files = glob.glob("/etc/pam.d/*")
        unlock_value = None
        
        for pf in pam_files:
            content = read_file_safe(pf)
            unlock = re.search(r'pam_faillock.*unlock_time=(\d+)', content)
            if unlock:
                unlock_value = int(unlock.group(1))
                break
        
        unlock_ok = unlock_value and unlock_value >= 900
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Identification & Authentication ({CAT_II})",
            status="Pass" if unlock_ok else "Warning",
            message=f"{get_stig_id('IA', 16)}: Account lockout duration 15 minutes",
            details=f"unlock_time = {unlock_value}s" if unlock_value else "Not configured",
            remediation="Set unlock_time=900 in pam_faillock configuration"
        ))
    
    # IA-017: SSH public key authentication (CAT II)
    pubkey_auth = get_ssh_config_value("PubkeyAuthentication")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Identification & Authentication ({CAT_II})",
        status="Info",
        message=f"{get_stig_id('IA', 17)}: SSH public key authentication status",
        details=f"PubkeyAuthentication: {pubkey_auth or 'yes (default)'}",
        remediation="Configure as needed for environment"
    ))
    
    # IA-018: SSH X11 forwarding disabled (CAT II)
    x11_forward = get_ssh_config_value("X11Forwarding")
    x11_disabled = x11_forward and x11_forward.lower() == "no"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Identification & Authentication ({CAT_II})",
        status="Pass" if x11_disabled else "Fail",
        message=f"{get_stig_id('IA', 18)}: SSH X11 forwarding disabled",
        details=f"X11Forwarding: {x11_forward or 'no (default)'}",
        remediation="Set X11Forwarding no in /etc/ssh/sshd_config"
    ))
    
    # IA-019: SSH permit tunnel disabled (CAT II)
    permit_tunnel = get_ssh_config_value("PermitTunnel")
    tunnel_disabled = permit_tunnel and permit_tunnel.lower() == "no"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Identification & Authentication ({CAT_II})",
        status="Pass" if tunnel_disabled else "Warning",
        message=f"{get_stig_id('IA', 19)}: SSH tunneling disabled",
        details=f"PermitTunnel: {permit_tunnel or 'no (default)'}",
        remediation="Set PermitTunnel no in /etc/ssh/sshd_config"
    ))
    
    # IA-020: SSH gateway ports disabled (CAT II)
    gateway_ports = get_ssh_config_value("GatewayPorts")
    gateway_disabled = not gateway_ports or gateway_ports.lower() == "no"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Identification & Authentication ({CAT_II})",
        status="Pass" if gateway_disabled else "Warning",
        message=f"{get_stig_id('IA', 20)}: SSH gateway ports disabled",
        details=f"GatewayPorts: {gateway_ports or 'no (default)'}",
        remediation="Set GatewayPorts no in /etc/ssh/sshd_config"
    ))
    
    # IA-021: SSH compression delayed (CAT II)
    compression = get_ssh_config_value("Compression")
    compression_ok = compression and compression.lower() in ["no", "delayed"]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Identification & Authentication ({CAT_II})",
        status="Pass" if compression_ok else "Info",
        message=f"{get_stig_id('IA', 21)}: SSH compression configuration",
        details=f"Compression: {compression or 'delayed (default)'}",
        remediation="Set Compression delayed in /etc/ssh/sshd_config"
    ))
    
    # IA-022: SSH strict mode enabled (CAT II)
    strict_modes = get_ssh_config_value("StrictModes")
    strict_enabled = not strict_modes or strict_modes.lower() == "yes"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Identification & Authentication ({CAT_II})",
        status="Pass" if strict_enabled else "Fail",
        message=f"{get_stig_id('IA', 22)}: SSH strict modes enabled",
        details=f"StrictModes: {strict_modes or 'yes (default)'}",
        remediation="Set StrictModes yes in /etc/ssh/sshd_config"
    ))
    
    # IA-023: No user .shosts files (CAT I)
    user_accounts = get_stig_user_accounts()
    shosts_found = []
    
    for acc in user_accounts:
        if acc['uid'] >= 1000:
            shosts_path = os.path.join(acc['home'], '.shosts')
            if os.path.exists(shosts_path):
                shosts_found.append(acc['username'])
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Identification & Authentication ({CAT_I})",
        status="Pass" if not shosts_found else "Fail",
        message=f"{get_stig_id('IA', 23)}: No .shosts files present",
        details=f"Found: {', '.join(shosts_found[:5])}" if shosts_found else "None",
        remediation="Remove .shosts files: rm -f ~/.shosts"
    ))
    
    # IA-024: Root account password set (CAT II)
    shadow_content = read_file_safe("/etc/shadow")
    root_password_set = False
    
    for line in shadow_content.split('\n'):
        if line.startswith("root:"):
            fields = line.split(':')
            if len(fields) >= 2:
                password = fields[1]
                root_password_set = password and password not in ['!', '*', '!!']
                break
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Identification & Authentication ({CAT_II})",
        status="Pass" if root_password_set else "Warning",
        message=f"{get_stig_id('IA', 24)}: Root password configured",
        details="Password set" if root_password_set else "Account locked",
        remediation="Set root password if direct access needed"
    ))
    
    # IA-025: System accounts locked (CAT II)
    system_unlocked = []
    
    for line in shadow_content.split('\n'):
        if line and not line.startswith('#'):
            fields = line.split(':')
            if len(fields) >= 3:
                username = fields[0]
                password = fields[1]
                
                # Find UID
                for acc in user_accounts:
                    if acc['username'] == username and acc['uid'] < 1000 and acc['uid'] != 0:
                        if password and password not in ['!', '*', '!!', '!*', '*LK*'] and not password.startswith('!'):
                            system_unlocked.append(username)
                        break
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Identification & Authentication ({CAT_II})",
        status="Pass" if not system_unlocked else "Fail",
        message=f"{get_stig_id('IA', 25)}: System accounts locked",
        details=f"Unlocked: {', '.join(system_unlocked[:5])}" if system_unlocked else "All locked",
        remediation="Lock system accounts: passwd -l <account>"
    ))
    
    # IA-026: Accounts with empty passwords (CAT I)
    empty_passwords = []
    
    for line in shadow_content.split('\n'):
        if line and not line.startswith('#'):
            fields = line.split(':')
            if len(fields) >= 2:
                username = fields[0]
                password = fields[1]
                
                if not password or password == '':
                    empty_passwords.append(username)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Identification & Authentication ({CAT_I})",
        status="Pass" if not empty_passwords else "Fail",
        message=f"{get_stig_id('IA', 26)}: No accounts with empty passwords",
        details=f"Empty: {', '.join(empty_passwords[:5])}" if empty_passwords else "None",
        remediation="Set password or lock account"
    ))
    
    # IA-027: Password hashing algorithm (CAT II)
    login_defs = read_file_safe("/etc/login.defs")
    encrypt_method = re.search(r'ENCRYPT_METHOD\s+(\w+)', login_defs)
    hash_ok = encrypt_method and encrypt_method.group(1).upper() in ['SHA512', 'YESCRYPT']
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Identification & Authentication ({CAT_II})",
        status="Pass" if hash_ok else "Fail",
        message=f"{get_stig_id('IA', 27)}: Strong password hashing (SHA512/YESCRYPT)",
        details=f"ENCRYPT_METHOD = {encrypt_method.group(1) if encrypt_method else 'not set'}",
        remediation="Set ENCRYPT_METHOD SHA512 in /etc/login.defs"
    ))
    
    # IA-028: SHA rounds configured (CAT III)
    sha_rounds = re.search(r'SHA_CRYPT_.*_ROUNDS\s+(\d+)', login_defs)
    rounds_ok = sha_rounds and int(sha_rounds.group(1)) >= 5000
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Identification & Authentication ({CAT_III})",
        status="Pass" if rounds_ok else "Info",
        message=f"{get_stig_id('IA', 28)}: Password hashing rounds configured",
        details=f"Rounds = {sha_rounds.group(1) if sha_rounds else 'default'}",
        remediation="Set SHA_CRYPT_MIN_ROUNDS 5000 in /etc/login.defs"
    ))
    
    # IA-029: User password expiration dates (CAT II)
    expired_accounts = []
    
    for acc in user_accounts:
        if acc['uid'] >= 1000 and acc['username'] != 'nobody':
            result = run_command(f"chage -l {acc['username']} 2>/dev/null | grep 'Password expires'")
            if result.returncode == 0 and "never" in result.stdout.lower():
                expired_accounts.append(acc['username'])
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Identification & Authentication ({CAT_II})",
        status="Pass" if not expired_accounts else "Warning",
        message=f"{get_stig_id('IA', 29)}: User passwords have expiration dates",
        details=f"Never expire: {len(expired_accounts)}" if expired_accounts else "All configured",
        remediation="Set expiration: chage -M 60 <username>"
    ))
    
    # IA-030: Inactive account lock (CAT II)
    inactive_days = re.search(r'INACTIVE\s*=\s*(\d+)', login_defs)
    inactive_ok = inactive_days and int(inactive_days.group(1)) <= 35
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Identification & Authentication ({CAT_II})",
        status="Pass" if inactive_ok else "Warning",
        message=f"{get_stig_id('IA', 30)}: Inactive accounts locked after 35 days",
        details=f"INACTIVE = {inactive_days.group(1) if inactive_days else 'not set'}",
        remediation="Set INACTIVE=35 in /etc/default/useradd"
    ))


# ============================================================================
# SYSTEM AND INFORMATION INTEGRITY (SI)
# STIG requires system integrity protection and monitoring
# Reference: DISA STIG System and Information Integrity requirements
# ============================================================================

def check_system_information_integrity(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    System and Information (SI) Integrity Security Audit Checks
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking System & Information Integrity...")
    
    # SI-001: AIDE installed (CAT II)
    aide_installed = check_package_installed("aide", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Information Integrity ({CAT_II})",
        status="Pass" if aide_installed else "Fail",
        message=f"{get_stig_id('SI', 1)}: File integrity tool (AIDE) installed",
        details="AIDE installed" if aide_installed else "Not installed",
        remediation=remediation_for("aide")
    ))
    
    # SI-002: AIDE database initialized (CAT II)
    aide_db = os.path.exists("/var/lib/aide/aide.db") or os.path.exists("/var/lib/aide/aide.db.gz")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Information Integrity ({CAT_II})",
        status="Pass" if aide_db else "Fail",
        message=f"{get_stig_id('SI', 2)}: AIDE database initialized",
        details="Database exists" if aide_db else "Not initialized",
        remediation=remediation_for("aide")
    ))
    
    # SI-003: AIDE scheduled to run (CAT II)
    result = run_command("grep -r aide /etc/cron.* /etc/crontab 2>/dev/null | grep -v '#' | wc -l")
    aide_scheduled = safe_int_parse(result.stdout.strip()) > 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Information Integrity ({CAT_II})",
        status="Pass" if aide_scheduled else "Fail",
        message=f"{get_stig_id('SI', 3)}: AIDE checks scheduled",
        details="Scheduled" if aide_scheduled else "Not scheduled",
        remediation="Add to crontab: 0 5 * * * /usr/bin/aide --check"
    ))
    
    # SI-004: Anti-virus software installed (CAT II)
    av_installed = check_package_installed("clamav", os_info) or check_package_installed("clamav-daemon", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Information Integrity ({CAT_II})",
        status="Pass" if av_installed else "Warning",
        message=f"{get_stig_id('SI', 4)}: Anti-malware software installed",
        details="ClamAV installed" if av_installed else "Not installed",
        remediation=remediation_for("clamav")
    ))
    
    # SI-005: Anti-virus definitions updated (CAT II)
    if av_installed and os.path.exists("/var/lib/clamav"):
        db_files = glob.glob("/var/lib/clamav/*.cvd") + glob.glob("/var/lib/clamav/*.cld")
        if db_files:
            newest_db = max(db_files, key=os.path.getmtime)
            db_age = get_file_age_days(newest_db)
            defs_current = db_age is not None and db_age <= 7
        else:
            defs_current = False
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - System & Information Integrity ({CAT_II})",
            status="Pass" if defs_current else "Warning",
            message=f"{get_stig_id('SI', 5)}: Anti-malware definitions current",
            details=f"Last update: {db_age} days ago" if db_age else "No definitions",
            remediation=remediation_for("clamav")
        ))
    
    # SI-006: Automatic virus definition updates (CAT II)
    freshclam_enabled = check_service_enabled("clamav-freshclam")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Information Integrity ({CAT_II})",
        status="Pass" if freshclam_enabled else "Warning",
        message=f"{get_stig_id('SI', 6)}: Automatic malware definition updates",
        details="Enabled" if freshclam_enabled else "Not enabled",
        remediation=remediation_for("clamav")
    ))
    
    # SI-007: System baseline documented (CAT III)
    baseline_files = [
        "/etc/security/baseline.txt",
        "/root/system_baseline.txt",
        "/var/log/baseline.txt"
    ]
    baseline_exists = any(os.path.exists(f) for f in baseline_files)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Information Integrity ({CAT_III})",
        status="Info",
        message=f"{get_stig_id('SI', 7)}: System baseline documented",
        details="Baseline found" if baseline_exists else "No baseline documented",
        remediation="Document system baseline configuration"
    ))
    
    # SI-008: Security patches current (CAT II)
    if command_exists("apt"):
        result = run_command("apt list --upgradable 2>/dev/null | grep -c security || echo 0")
        security_updates = safe_int_parse(result.stdout.strip())
    elif command_exists("yum"):
        result = run_command("yum updateinfo list security 2>/dev/null | wc -l")
        security_updates = safe_int_parse(result.stdout.strip())
    else:
        security_updates = 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Information Integrity ({CAT_II})",
        status="Pass" if security_updates == 0 else "Fail",
        message=f"{get_stig_id('SI', 8)}: Security updates applied",
        details=f"{security_updates} security updates available",
        remediation=patch_for()
    ))
    
    # SI-009: Automatic security updates (CAT II)
    auto_updates = check_package_installed("unattended-upgrades", os_info) or check_package_installed("yum-cron", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Information Integrity ({CAT_II})",
        status="Pass" if auto_updates else "Warning",
        message=f"{get_stig_id('SI', 9)}: Automatic security updates configured",
        details="Configured" if auto_updates else "Not configured",
        remediation=remediation_for("unattended-upgrades")
    ))
    
    # SI-010: Package repository security (CAT II)
    if os.path.exists("/etc/apt/sources.list"):
        sources = read_file_safe("/etc/apt/sources.list")
        https_repos = sources.count("https://")
        http_repos = sources.count("http://") - https_repos
        repos_secure = https_repos > 0 and http_repos == 0
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - System & Information Integrity ({CAT_II})",
            status="Pass" if repos_secure else "Warning",
            message=f"{get_stig_id('SI', 10)}: Package repositories use HTTPS",
            details=f"HTTPS: {https_repos}, HTTP: {http_repos}",
            remediation="Use HTTPS repositories in /etc/apt/sources.list"
        ))
    
    # SI-011: GPG key verification (CAT II)
    if command_exists("apt-key"):
        result = run_command("apt-key list 2>/dev/null | grep -c 'pub'")
        gpg_keys = safe_int_parse(result.stdout.strip())
        keys_ok = gpg_keys > 0
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - System & Information Integrity ({CAT_II})",
            status="Pass" if keys_ok else "Warning",
            message=f"{get_stig_id('SI', 11)}: Package GPG keys configured",
            details=f"{gpg_keys} GPG keys",
            remediation="Import repository GPG keys"
        ))
    
    # SI-012: System integrity tools permissions (CAT II)
    integrity_tools = ["/usr/bin/aide", "/usr/sbin/aide", "/usr/bin/tripwire"]
    tool_issues = []
    
    for tool in integrity_tools:
        if os.path.exists(tool):
            perms = get_file_permissions(tool)
            if perms and int(perms, 8) > int('755', 8):
                tool_issues.append(f"{tool}:{perms}")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Information Integrity ({CAT_II})",
        status="Pass" if not tool_issues else "Warning",
        message=f"{get_stig_id('SI', 12)}: Integrity tool permissions secure",
        details=f"Issues: {', '.join(tool_issues)}" if tool_issues else "All secure",
        remediation="chmod 755 /usr/bin/aide"
    ))
    
    # SI-013: Core dumps disabled (CAT II)
    exists, core_pattern = check_kernel_parameter("kernel.core_pattern")
    limits_conf = read_file_safe("/etc/security/limits.conf")
    core_disabled = ("* hard core 0" in limits_conf or 
                    "* soft core 0" in limits_conf)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Information Integrity ({CAT_II})",
        status="Pass" if core_disabled else "Warning",
        message=f"{get_stig_id('SI', 13)}: Core dumps disabled",
        details="Disabled" if core_disabled else "Not disabled",
        remediation="Add '* hard core 0' to /etc/security/limits.conf"
    ))
    
    # SI-014: ASLR enabled (CAT II)
    exists, aslr = check_kernel_parameter("kernel.randomize_va_space")
    aslr_enabled = aslr == "2"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Information Integrity ({CAT_II})",
        status="Pass" if aslr_enabled else "Fail",
        message=f"{get_stig_id('SI', 14)}: Address Space Layout Randomization enabled",
        details=f"randomize_va_space = {aslr}",
        remediation="sysctl -w kernel.randomize_va_space=2"
    ))
    
    # SI-015: Kernel exploit mitigation (CAT II)
    exists, exec_shield = check_kernel_parameter("kernel.exec-shield")
    if exists:
        shield_ok = exec_shield == "1"
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - System & Information Integrity ({CAT_II})",
            status="Pass" if shield_ok else "Warning",
            message=f"{get_stig_id('SI', 15)}: Kernel ExecShield enabled",
            details=f"exec-shield = {exec_shield}",
            remediation="sysctl -w kernel.exec-shield=1"
        ))
    
    # SI-016: USB storage disabled (CAT II)
    result = run_command("lsmod | grep -c usb_storage || echo 0")
    usb_storage_loaded = safe_int_parse(result.stdout.strip()) > 0
    
    result = run_command("grep -r 'install usb-storage' /etc/modprobe.d/ 2>/dev/null | grep -v '#' | wc -l")
    usb_disabled = safe_int_parse(result.stdout.strip()) > 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Information Integrity ({CAT_II})",
        status="Pass" if usb_disabled or not usb_storage_loaded else "Warning",
        message=f"{get_stig_id('SI', 16)}: USB storage disabled",
        details="Disabled" if usb_disabled else "Loaded" if usb_storage_loaded else "Not loaded",
        remediation="Add 'install usb-storage /bin/true' to /etc/modprobe.d/disable-usb.conf"
    ))
    
    # SI-017: Firmware updates (CAT II)
    fwupd_installed = check_package_installed("fwupd", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Information Integrity ({CAT_II})",
        status="Info",
        message=f"{get_stig_id('SI', 17)}: Firmware update capability",
        details="fwupd installed" if fwupd_installed else "Not installed",
        remediation="Install: apt-get install fwupd"
    ))
    
    # SI-018: Prelink disabled (CAT II)
    prelink_installed = check_package_installed("prelink", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Information Integrity ({CAT_II})",
        status="Pass" if not prelink_installed else "Warning",
        message=f"{get_stig_id('SI', 18)}: Prelink not installed",
        details="Prelink installed" if prelink_installed else "Not installed",
        remediation=removal_for("prelink")
    ))
    
    # SI-019: Kernel modules verified (CAT II)
    if os.path.exists("/proc/sys/kernel/modules_disabled"):
        modules_disabled = read_file_safe("/proc/sys/kernel/modules_disabled").strip()
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - System & Information Integrity ({CAT_II})",
            status="Info",
            message=f"{get_stig_id('SI', 19)}: Kernel module loading status",
            details=f"modules_disabled = {modules_disabled}",
            remediation="Consider disabling after boot: sysctl -w kernel.modules_disabled=1"
        ))
    
    # SI-020: Unnecessary services disabled (CAT II)
    unnecessary_services = [
        "telnet", "rsh", "rlogin", "rexec", "tftp", "talk",
        "ypbind", "ypserv", "finger"
    ]
    
    active_unnecessary = [svc for svc in unnecessary_services if check_service_active(svc)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Information Integrity ({CAT_II})",
        status="Pass" if not active_unnecessary else "Fail",
        message=f"{get_stig_id('SI', 20)}: Unnecessary services disabled",
        details=f"Active: {', '.join(active_unnecessary)}" if active_unnecessary else "All disabled",
        remediation="Disable unnecessary services: systemctl disable <service>"
    ))
    
    # SI-021: X Window System not installed on server (CAT II)
    x_packages = ["xorg", "xserver-xorg", "xorg-x11-server"]
    x_installed = any(check_package_installed(pkg, os_info) for pkg in x_packages)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Information Integrity ({CAT_II})",
        status="Pass" if not x_installed else "Warning",
        message=f"{get_stig_id('SI', 21)}: X Window System not on server",
        details="X11 installed" if x_installed else "Not installed",
        remediation=removal_for("xserver")
    ))
    
    # SI-022: System error logging configured (CAT II)
    result = run_command("journalctl --disk-usage 2>/dev/null | grep -oE '[0-9]+\\.[0-9]+[MGK]'")
    journal_ok = result.returncode == 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Information Integrity ({CAT_II})",
        status="Pass" if journal_ok else "Warning",
        message=f"{get_stig_id('SI', 22)}: System error logging active",
        details="journald active" if journal_ok else "Check journald",
        remediation="Ensure systemd-journald is running"
    ))
    
    # SI-023: Time synchronization active (CAT II)
    time_services = ["chronyd", "ntpd", "systemd-timesyncd"]
    time_active = any(check_service_active(svc) for svc in time_services)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Information Integrity ({CAT_II})",
        status="Pass" if time_active else "Fail",
        message=f"{get_stig_id('SI', 23)}: Time synchronization service active",
        details="Active" if time_active else "Not active",
        remediation=remediation_for("chrony")
    ))
    
    # SI-024: Removable media automount disabled (CAT II)
    result = run_command("systemctl is-enabled autofs 2>/dev/null")
    autofs_disabled = result.returncode != 0 or result.stdout.strip() != "enabled"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Information Integrity ({CAT_II})",
        status="Pass" if autofs_disabled else "Warning",
        message=f"{get_stig_id('SI', 24)}: Automount disabled",
        details="Disabled" if autofs_disabled else "Enabled",
        remediation="systemctl disable autofs"
    ))
    
    # SI-025: World-writable files (CAT II) (canonical assessment)
    from shared_components.shared_assessments import get_world_writable_assessment as _ww_assess
    _ww = _ww_assess("fail")
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Information Integrity ({CAT_II})",
        status=_ww.status,
        message=f"{get_stig_id('SI', 25)}: No world-writable files",
        details=_ww.details,
        remediation=_ww.remediation
    ))
    
    # SI-026: Unowned files (CAT II)
    result = run_command("find / -xdev \\( -nouser -o -nogroup \\) 2>/dev/null | head -10 | wc -l")
    unowned = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Information Integrity ({CAT_II})",
        status="Pass" if unowned == 0 else "Fail",
        message=f"{get_stig_id('SI', 26)}: No unowned files",
        details=f"{unowned} unowned files",
        remediation="Assign ownership: chown <user>:<group> <file>"
    ))
    
    # SI-027: Software inventory (CAT III)
    if command_exists("dpkg"):
        result = run_command("dpkg -l | grep '^ii' | wc -l")
    elif command_exists("rpm"):
        result = run_command("rpm -qa | wc -l")
    else:
        result = None
    
    pkg_count = safe_int_parse(result.stdout.strip()) if result else 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Information Integrity ({CAT_III})",
        status="Info",
        message=f"{get_stig_id('SI', 27)}: Software inventory",
        details=f"{pkg_count} packages installed",
        remediation="Maintain software inventory"
    ))
    
    # SI-028: System commands integrity (CAT II)
    critical_commands = ["/bin/bash", "/usr/bin/sudo", "/bin/su", "/usr/bin/passwd"]
    modified_commands = []
    
    for cmd in critical_commands:
        if os.path.exists(cmd):
            age = get_file_age_days(cmd)
            if age is not None and age < 30:
                modified_commands.append(cmd)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Information Integrity ({CAT_II})",
        status="Info",
        message=f"{get_stig_id('SI', 28)}: System commands integrity",
        details=f"{len(modified_commands)} recently modified" if modified_commands else "Stable",
        remediation="Verify system command integrity with AIDE"
    ))
    
    # SI-029: Banner warnings configured (CAT II)
    banner_files = ["/etc/issue", "/etc/issue.net"]
    banners_configured = sum(1 for f in banner_files if os.path.exists(f) and os.path.getsize(f) > 10)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Information Integrity ({CAT_II})",
        status="Pass" if banners_configured >= 2 else "Warning",
        message=f"{get_stig_id('SI', 29)}: Security banners configured",
        details=f"{banners_configured}/2 banner files",
        remediation="Configure /etc/issue and /etc/issue.net"
    ))
    
    # SI-030: No OS information in banners (CAT II)
    os_info_found = False
    os_keywords = ["ubuntu", "debian", "centos", "red hat", "linux", "kernel", "\\r", "\\m", "\\v"]
    
    for banner_file in banner_files:
        if os.path.exists(banner_file):
            content = read_file_safe(banner_file).lower()
            if any(kw in content for kw in os_keywords):
                os_info_found = True
                break
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Information Integrity ({CAT_II})",
        status="Pass" if not os_info_found else "Fail",
        message=f"{get_stig_id('SI', 30)}: Banners do not disclose OS information",
        details="OS info present" if os_info_found else "Clean",
        remediation="Remove OS/version information from banners"
    ))


# ============================================================================
# CONFIGURATION MANAGEMENT (CM)
# STIG requires strict configuration management and control
# Reference: DISA STIG Configuration Management requirements
# ============================================================================

def check_configuration_management(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Configuration Management (CM) Security Audit Checks
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Configuration Management...")
    
    # CM-001: System has unique hostname (CAT III)
    hostname = socket.gethostname()
    hostname_ok = hostname and hostname != "localhost" and len(hostname) > 3
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Configuration Management ({CAT_III})",
        status="Pass" if hostname_ok else "Warning",
        message=f"{get_stig_id('CM', 1)}: System has unique hostname",
        details=f"Hostname: {hostname}",
        remediation="Set hostname: hostnamectl set-hostname <name>"
    ))
    
    # CM-002: /etc/hosts configured (CAT III)
    hosts_file = read_file_safe("/etc/hosts")
    localhost_entry = "127.0.0.1" in hosts_file and "localhost" in hosts_file
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Configuration Management ({CAT_III})",
        status="Pass" if localhost_entry else "Warning",
        message=f"{get_stig_id('CM', 2)}: /etc/hosts properly configured",
        details="Localhost entry present" if localhost_entry else "Missing entries",
        remediation="Configure /etc/hosts with proper entries"
    ))
    
    # CM-003: Kernel version documented (CAT III)
    kernel_version = run_command("uname -r").stdout.strip()
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Configuration Management ({CAT_III})",
        status="Info",
        message=f"{get_stig_id('CM', 3)}: Kernel version",
        details=f"Running: {kernel_version}",
        remediation="Keep kernel updated with security patches"
    ))
    
    # CM-004: Boot loader password set (CAT I)
    grub_cfg_files = [
        "/boot/grub/grub.cfg",
        "/boot/grub2/grub.cfg",
        "/boot/efi/EFI/*/grub.cfg"
    ]
    
    grub_password_set = False
    for pattern in grub_cfg_files:
        for grub_file in glob.glob(pattern):
            if os.path.exists(grub_file):
                content = read_file_safe(grub_file)
                if "password_pbkdf2" in content or "password" in content:
                    grub_password_set = True
                    break
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Configuration Management ({CAT_I})",
        status="Pass" if grub_password_set else "Fail",
        message=f"{get_stig_id('CM', 4)}: Boot loader password configured",
        details="Password set" if grub_password_set else "No password",
        remediation="Set GRUB password: grub-mkpasswd-pbkdf2"
    ))
    
    # CM-005: Single user mode requires authentication (CAT I)
    if os.path.exists("/usr/lib/systemd/system/rescue.service"):
        rescue_service = read_file_safe("/usr/lib/systemd/system/rescue.service")
        sulogin_required = "sulogin" in rescue_service or "ExecStart=-/bin/sh" not in rescue_service
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Configuration Management ({CAT_I})",
            status="Pass" if sulogin_required else "Fail",
            message=f"{get_stig_id('CM', 5)}: Single user mode requires authentication",
            details="sulogin configured" if sulogin_required else "No authentication",
            remediation="Configure sulogin in rescue.service"
        ))
    
    # CM-006: Emergency mode requires authentication (CAT I)
    if os.path.exists("/usr/lib/systemd/system/emergency.service"):
        emergency_service = read_file_safe("/usr/lib/systemd/system/emergency.service")
        sulogin_required = "sulogin" in emergency_service
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Configuration Management ({CAT_I})",
            status="Pass" if sulogin_required else "Fail",
            message=f"{get_stig_id('CM', 6)}: Emergency mode requires authentication",
            details="sulogin configured" if sulogin_required else "No authentication",
            remediation="Configure sulogin in emergency.service"
        ))
    
    # CM-007: Ctrl-Alt-Del disabled (CAT I)
    ctrl_alt_del_disabled = False
    
    if os.path.exists("/etc/systemd/system/ctrl-alt-del.target"):
        link_target = os.readlink("/etc/systemd/system/ctrl-alt-del.target")
        ctrl_alt_del_disabled = "/dev/null" in link_target
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Configuration Management ({CAT_I})",
        status="Pass" if ctrl_alt_del_disabled else "Fail",
        message=f"{get_stig_id('CM', 7)}: Ctrl-Alt-Del disabled",
        details="Disabled" if ctrl_alt_del_disabled else "Enabled",
        remediation="systemctl mask ctrl-alt-del.target"
    ))
    
    # CM-008: GUI auto-login disabled (CAT II)
    gdm_conf_files = glob.glob("/etc/gdm*/custom.conf") + glob.glob("/etc/gdm*/daemon.conf")
    auto_login_disabled = True
    
    for conf_file in gdm_conf_files:
        if os.path.exists(conf_file):
            content = read_file_safe(conf_file)
            if re.search(r'AutomaticLoginEnable\s*=\s*[Tt]rue', content):
                auto_login_disabled = False
                break
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Configuration Management ({CAT_II})",
        status="Pass" if auto_login_disabled else "Fail",
        message=f"{get_stig_id('CM', 8)}: GUI automatic login disabled",
        details="Disabled" if auto_login_disabled else "Enabled",
        remediation="Set AutomaticLoginEnable=false in GDM config"
    ))
    
    # CM-009: System activity accounting enabled (CAT III)
    sysstat_installed = check_package_installed("sysstat", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Configuration Management ({CAT_III})",
        status="Pass" if sysstat_installed else "Info",
        message=f"{get_stig_id('CM', 9)}: System activity accounting available",
        details="sysstat installed" if sysstat_installed else "Not installed",
        remediation=remediation_for("sysstat")
    ))
    
    # CM-010: Process accounting enabled (CAT III)
    psacct_active = check_service_active("psacct") or check_service_active("acct")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Configuration Management ({CAT_III})",
        status="Pass" if psacct_active else "Info",
        message=f"{get_stig_id('CM', 10)}: Process accounting active",
        details="Active" if psacct_active else "Not active",
        remediation="Enable: systemctl enable psacct"
    ))
    
    # CM-011: Network parameters persistent (CAT II)
    sysctl_conf = read_file_safe("/etc/sysctl.conf")
    net_params = sysctl_conf.count("net.") + sysctl_conf.count("kernel.")
    params_ok = net_params >= 5
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Configuration Management ({CAT_II})",
        status="Pass" if params_ok else "Warning",
        message=f"{get_stig_id('CM', 11)}: Network parameters in sysctl.conf",
        details=f"{net_params} parameters configured",
        remediation="Add network hardening parameters to /etc/sysctl.conf"
    ))
    
    # CM-012: Modprobe configuration exists (CAT III)
    modprobe_d = os.path.exists("/etc/modprobe.d")
    modprobe_files = len(glob.glob("/etc/modprobe.d/*.conf")) if modprobe_d else 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Configuration Management ({CAT_III})",
        status="Pass" if modprobe_files > 0 else "Info",
        message=f"{get_stig_id('CM', 12)}: Kernel module configuration exists",
        details=f"{modprobe_files} configuration files",
        remediation="Configure kernel module restrictions in /etc/modprobe.d/"
    ))
    
    # CM-013: Filesystem types restricted (CAT II)
    restricted_fs = ["cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "squashfs", "udf"]
    
    result = run_command("grep -E '^install.*(/bin/true|/bin/false)' /etc/modprobe.d/*.conf 2>/dev/null | wc -l")
    restricted_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Configuration Management ({CAT_II})",
        status="Pass" if restricted_count >= 3 else "Warning",
        message=f"{get_stig_id('CM', 13)}: Unnecessary filesystems disabled",
        details=f"{restricted_count} filesystems restricted",
        remediation="Disable filesystems in /etc/modprobe.d/disabled-filesystems.conf"
    ))
    
    # CM-014: Separate /tmp partition (CAT II)
    result = run_command("mount | grep -E '^\\S+ on /tmp '")
    tmp_separate = result.returncode == 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Configuration Management ({CAT_II})",
        status="Pass" if tmp_separate else "Warning",
        message=f"{get_stig_id('CM', 14)}: /tmp on separate partition",
        details="Separate partition" if tmp_separate else "Not separate",
        remediation="Create separate /tmp partition"
    ))
    
    # CM-015: /tmp noexec option (CAT II)
    if tmp_separate:
        result = run_command("mount | grep ' on /tmp ' | grep -c noexec")
        tmp_noexec = safe_int_parse(result.stdout.strip()) > 0
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Configuration Management ({CAT_II})",
            status="Pass" if tmp_noexec else "Fail",
            message=f"{get_stig_id('CM', 15)}: /tmp mounted with noexec",
            details="noexec set" if tmp_noexec else "Not set",
            remediation="Add noexec to /tmp in /etc/fstab"
        ))
    
    # CM-016: /tmp nodev option (CAT II)
    if tmp_separate:
        result = run_command("mount | grep ' on /tmp ' | grep -c nodev")
        tmp_nodev = safe_int_parse(result.stdout.strip()) > 0
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Configuration Management ({CAT_II})",
            status="Pass" if tmp_nodev else "Fail",
            message=f"{get_stig_id('CM', 16)}: /tmp mounted with nodev",
            details="nodev set" if tmp_nodev else "Not set",
            remediation="Add nodev to /tmp in /etc/fstab"
        ))
    
    # CM-017: /tmp nosuid option (CAT II)
    if tmp_separate:
        result = run_command("mount | grep ' on /tmp ' | grep -c nosuid")
        tmp_nosuid = safe_int_parse(result.stdout.strip()) > 0
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Configuration Management ({CAT_II})",
            status="Pass" if tmp_nosuid else "Fail",
            message=f"{get_stig_id('CM', 17)}: /tmp mounted with nosuid",
            details="nosuid set" if tmp_nosuid else "Not set",
            remediation="Add nosuid to /tmp in /etc/fstab"
        ))
    
    # CM-018: Separate /var partition (CAT II)
    result = run_command("mount | grep -E '^\\S+ on /var '")
    var_separate = result.returncode == 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Configuration Management ({CAT_II})",
        status="Pass" if var_separate else "Warning",
        message=f"{get_stig_id('CM', 18)}: /var on separate partition",
        details="Separate partition" if var_separate else "Not separate",
        remediation="Create separate /var partition"
    ))
    
    # CM-019: Separate /var/log partition (CAT II)
    result = run_command("mount | grep -E '^\\S+ on /var/log '")
    var_log_separate = result.returncode == 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Configuration Management ({CAT_II})",
        status="Pass" if var_log_separate else "Warning",
        message=f"{get_stig_id('CM', 19)}: /var/log on separate partition",
        details="Separate partition" if var_log_separate else "Not separate",
        remediation="Create separate /var/log partition"
    ))
    
    # CM-020: Separate /var/log/audit partition (CAT II)
    result = run_command("mount | grep -E '^\\S+ on /var/log/audit '")
    audit_separate = result.returncode == 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Configuration Management ({CAT_II})",
        status="Pass" if audit_separate else "Info",
        message=f"{get_stig_id('CM', 20)}: /var/log/audit on separate partition",
        details="Separate partition" if audit_separate else "Not separate",
        remediation="Create separate /var/log/audit partition"
    ))
    
    # CM-021: Separate /home partition (CAT II)
    result = run_command("mount | grep -E '^\\S+ on /home '")
    home_separate = result.returncode == 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Configuration Management ({CAT_II})",
        status="Pass" if home_separate else "Warning",
        message=f"{get_stig_id('CM', 21)}: /home on separate partition",
        details="Separate partition" if home_separate else "Not separate",
        remediation="Create separate /home partition"
    ))
    
    # CM-022: /home nodev option (CAT II)
    if home_separate:
        result = run_command("mount | grep ' on /home ' | grep -c nodev")
        home_nodev = safe_int_parse(result.stdout.strip()) > 0
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Configuration Management ({CAT_II})",
            status="Pass" if home_nodev else "Warning",
            message=f"{get_stig_id('CM', 22)}: /home mounted with nodev",
            details="nodev set" if home_nodev else "Not set",
            remediation="Add nodev to /home in /etc/fstab"
        ))
    
    # CM-023: /dev/shm noexec option (CAT II)
    result = run_command("mount | grep ' on /dev/shm ' | grep -c noexec")
    shm_noexec = safe_int_parse(result.stdout.strip()) > 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Configuration Management ({CAT_II})",
        status="Pass" if shm_noexec else "Fail",
        message=f"{get_stig_id('CM', 23)}: /dev/shm mounted with noexec",
        details="noexec set" if shm_noexec else "Not set",
        remediation="Add noexec to /dev/shm in /etc/fstab"
    ))
    
    # CM-024: /dev/shm nodev option (CAT II)
    result = run_command("mount | grep ' on /dev/shm ' | grep -c nodev")
    shm_nodev = safe_int_parse(result.stdout.strip()) > 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Configuration Management ({CAT_II})",
        status="Pass" if shm_nodev else "Fail",
        message=f"{get_stig_id('CM', 24)}: /dev/shm mounted with nodev",
        details="nodev set" if shm_nodev else "Not set",
        remediation="Add nodev to /dev/shm in /etc/fstab"
    ))
    
    # CM-025: /dev/shm nosuid option (CAT II)
    result = run_command("mount | grep ' on /dev/shm ' | grep -c nosuid")
    shm_nosuid = safe_int_parse(result.stdout.strip()) > 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Configuration Management ({CAT_II})",
        status="Pass" if shm_nosuid else "Fail",
        message=f"{get_stig_id('CM', 25)}: /dev/shm mounted with nosuid",
        details="nosuid set" if shm_nosuid else "Not set",
        remediation="Add nosuid to /dev/shm in /etc/fstab"
    ))
    
    # CM-026: Sticky bit on world-writable directories (CAT II)
    result = run_command("find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | head -20 | wc -l")
    no_sticky = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Configuration Management ({CAT_II})",
        status="Pass" if no_sticky == 0 else "Fail",
        message=f"{get_stig_id('CM', 26)}: Sticky bit on world-writable directories",
        details=f"{no_sticky} directories without sticky bit",
        remediation="Add sticky bit: chmod +t <directory>"
    ))
    
    # CM-027: System timezone configured (CAT III)
    result = run_command("timedatectl status 2>/dev/null | grep 'Time zone'")
    timezone_set = result.returncode == 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Configuration Management ({CAT_III})",
        status="Pass" if timezone_set else "Info",
        message=f"{get_stig_id('CM', 27)}: System timezone configured",
        details="Configured" if timezone_set else "Check timezone",
        remediation="Set timezone: timedatectl set-timezone <zone>"
    ))
    
    # CM-028: DNS servers configured (CAT III)
    resolv_conf = read_file_safe("/etc/resolv.conf")
    dns_count = resolv_conf.count("nameserver")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Configuration Management ({CAT_III})",
        status="Pass" if dns_count >= 2 else "Warning",
        message=f"{get_stig_id('CM', 28)}: Multiple DNS servers configured",
        details=f"{dns_count} nameservers",
        remediation="Configure multiple DNS servers in /etc/resolv.conf"
    ))
    
    # CM-029: Default gateway configured (CAT III)
    result = run_command("ip route | grep -c default")
    gateway_ok = safe_int_parse(result.stdout.strip()) > 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Configuration Management ({CAT_III})",
        status="Pass" if gateway_ok else "Warning",
        message=f"{get_stig_id('CM', 29)}: Default gateway configured",
        details="Configured" if gateway_ok else "Not configured",
        remediation="Configure default gateway"
    ))
    
    # CM-030: System configuration backup (CAT III)
    backup_indicators = [
        "/etc/backup",
        "/var/backups/config",
        "/root/backups"
    ]
    
    backup_exists = any(os.path.exists(d) for d in backup_indicators)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Configuration Management ({CAT_III})",
        status="Info",
        message=f"{get_stig_id('CM', 30)}: System configuration backup",
        details="Backup directory found" if backup_exists else "No backup directory",
        remediation="Implement configuration backup procedures"
    ))


# ============================================================================
# SYSTEM AND COMMUNICATIONS PROTECTION (SC)
# STIG requires protection of system communications
# Reference: DISA STIG System and Communications Protection requirements
# ============================================================================

def check_system_communications_protection(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    System and Communications (SC) Protection checks
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking System & Communications Protection...")
    
    # SC-001: Firewall enabled (CAT II)
    firewall_active = check_firewall_active()
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Communications Protection ({CAT_II})",
        status="Pass" if firewall_active else "Fail",
        message=f"{get_stig_id('SC', 1)}: Firewall enabled",
        details="Active" if firewall_active else "Not active",
        remediation="Enable firewall: ufw enable || firewall-cmd --set-default-zone=drop"
    ))
    
    # SC-002: Default firewall policy drop (CAT II)
    if firewall_active:
        result = run_command("iptables -L | grep 'Chain INPUT' | grep -E '(DROP|REJECT)'")
        default_deny = result.returncode == 0
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - System & Communications Protection ({CAT_II})",
            status="Pass" if default_deny else "Warning",
            message=f"{get_stig_id('SC', 2)}: Firewall default deny policy",
            details="Default deny" if default_deny else "Check policy",
            remediation="Set default policy: iptables -P INPUT DROP"
        ))
    
    # SC-003: ICMP redirects disabled (CAT II)
    exists, accept_redirects = check_kernel_parameter("net.ipv4.conf.all.accept_redirects")
    redirects_disabled = accept_redirects == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Communications Protection ({CAT_II})",
        status="Pass" if redirects_disabled else "Fail",
        message=f"{get_stig_id('SC', 3)}: ICMP redirects disabled",
        details=f"accept_redirects = {accept_redirects}",
        remediation="sysctl -w net.ipv4.conf.all.accept_redirects=0"
    ))
    
    # SC-004: Send redirects disabled (CAT II)
    exists, send_redirects = check_kernel_parameter("net.ipv4.conf.all.send_redirects")
    send_disabled = send_redirects == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Communications Protection ({CAT_II})",
        status="Pass" if send_disabled else "Fail",
        message=f"{get_stig_id('SC', 4)}: ICMP redirect sending disabled",
        details=f"send_redirects = {send_redirects}",
        remediation="sysctl -w net.ipv4.conf.all.send_redirects=0"
    ))
    
    # SC-005: IP forwarding disabled (CAT II)
    exists, ip_forward = check_kernel_parameter("net.ipv4.ip_forward")
    forward_disabled = ip_forward == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Communications Protection ({CAT_II})",
        status="Pass" if forward_disabled else "Warning",
        message=f"{get_stig_id('SC', 5)}: IP forwarding disabled",
        details=f"ip_forward = {ip_forward}",
        remediation="sysctl -w net.ipv4.ip_forward=0"
    ))
    
    # SC-006: Source routing disabled (CAT II)
    exists, source_route = check_kernel_parameter("net.ipv4.conf.all.accept_source_route")
    source_disabled = source_route == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Communications Protection ({CAT_II})",
        status="Pass" if source_disabled else "Fail",
        message=f"{get_stig_id('SC', 6)}: Source routing disabled",
        details=f"accept_source_route = {source_route}",
        remediation="sysctl -w net.ipv4.conf.all.accept_source_route=0"
    ))
    
    # SC-007: SYN cookies enabled (CAT II)
    exists, syn_cookies = check_kernel_parameter("net.ipv4.tcp_syncookies")
    syn_enabled = syn_cookies == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Communications Protection ({CAT_II})",
        status="Pass" if syn_enabled else "Fail",
        message=f"{get_stig_id('SC', 7)}: TCP SYN cookies enabled",
        details=f"tcp_syncookies = {syn_cookies}",
        remediation="sysctl -w net.ipv4.tcp_syncookies=1"
    ))
    
    # SC-008: Reverse path filtering (CAT II)
    exists, rp_filter = check_kernel_parameter("net.ipv4.conf.all.rp_filter")
    rp_enabled = rp_filter == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Communications Protection ({CAT_II})",
        status="Pass" if rp_enabled else "Fail",
        message=f"{get_stig_id('SC', 8)}: Reverse path filtering enabled",
        details=f"rp_filter = {rp_filter}",
        remediation="sysctl -w net.ipv4.conf.all.rp_filter=1"
    ))
    
    # SC-009: Log martian packets (CAT II)
    exists, log_martians = check_kernel_parameter("net.ipv4.conf.all.log_martians")
    martians_logged = log_martians == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Communications Protection ({CAT_II})",
        status="Pass" if martians_logged else "Warning",
        message=f"{get_stig_id('SC', 9)}: Martian packets logged",
        details=f"log_martians = {log_martians}",
        remediation="sysctl -w net.ipv4.conf.all.log_martians=1"
    ))
    
    # SC-010: Ignore ICMP broadcast (CAT II)
    exists, icmp_broadcast = check_kernel_parameter("net.ipv4.icmp_echo_ignore_broadcasts")
    broadcast_ignored = icmp_broadcast == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Communications Protection ({CAT_II})",
        status="Pass" if broadcast_ignored else "Fail",
        message=f"{get_stig_id('SC', 10)}: ICMP broadcast ignored",
        details=f"icmp_echo_ignore_broadcasts = {icmp_broadcast}",
        remediation="sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1"
    ))
    
    # SC-011: SSH ciphers strong (CAT II)
    ssh_ciphers = get_ssh_config_value("Ciphers")
    weak_ciphers = ["3des", "arcfour", "blowfish", "cast", "aes128-cbc", "aes192-cbc", "aes256-cbc"]
    
    if ssh_ciphers:
        has_weak = any(weak in ssh_ciphers.lower() for weak in weak_ciphers)
    else:
        has_weak = False
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Communications Protection ({CAT_II})",
        status="Pass" if not has_weak else "Fail",
        message=f"{get_stig_id('SC', 11)}: SSH strong ciphers configured",
        details=f"Ciphers: {ssh_ciphers or 'default'}"[:60],
        remediation="Configure: Ciphers aes256-ctr,aes192-ctr,aes128-ctr"
    ))
    
    # SC-012: SSH MACs strong (CAT II)
    ssh_macs = get_ssh_config_value("MACs")
    weak_macs = ["md5", "96", "hmac-sha1"]
    
    if ssh_macs:
        has_weak_mac = any(weak in ssh_macs.lower() for weak in weak_macs)
    else:
        has_weak_mac = False
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Communications Protection ({CAT_II})",
        status="Pass" if not has_weak_mac else "Fail",
        message=f"{get_stig_id('SC', 12)}: SSH strong MACs configured",
        details=f"MACs: {ssh_macs or 'default'}"[:60],
        remediation="Configure: MACs hmac-sha2-512,hmac-sha2-256"
    ))
    
    # SC-013: FIPS mode enabled (CAT I)
    fips_enabled = check_fips_mode()
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Communications Protection ({CAT_I})",
        status="Pass" if fips_enabled else "Warning",
        message=f"{get_stig_id('SC', 13)}: FIPS 140-2/3 mode enabled",
        details="FIPS mode active" if fips_enabled else "Not enabled",
        remediation="Enable: fips-mode-setup --enable && reboot"
    ))
    
    # SC-014: Wireless interfaces disabled (CAT II)
    result = run_command("iwconfig 2>&1 | grep -c 'IEEE'")
    wireless_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Communications Protection ({CAT_II})",
        status="Pass" if wireless_count == 0 else "Warning",
        message=f"{get_stig_id('SC', 14)}: Wireless interfaces disabled",
        details=f"{wireless_count} wireless interfaces",
        remediation="Disable wireless interfaces if not needed"
    ))
    
    # SC-015: Bluetooth disabled (CAT II)
    bluetooth_active = check_service_active("bluetooth")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Communications Protection ({CAT_II})",
        status="Pass" if not bluetooth_active else "Warning",
        message=f"{get_stig_id('SC', 15)}: Bluetooth disabled",
        details="Active" if bluetooth_active else "Disabled",
        remediation="Disable: systemctl disable bluetooth"
    ))
    
    # SC-016: Network services minimized (CAT II)
    listening_ports = get_listening_ports()
    port_count = len(listening_ports)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Communications Protection ({CAT_II})",
        status="Pass" if port_count < 20 else "Warning",
        message=f"{get_stig_id('SC', 16)}: Network services minimized",
        details=f"{port_count} listening ports",
        remediation="Disable unnecessary network services"
    ))
    
    # SC-017: Insecure services disabled (CAT I)
    insecure_services = ["telnet", "rsh", "rlogin", "rexec", "ftp", "tftp"]
    active_insecure = [svc for svc in insecure_services if check_service_active(svc)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Communications Protection ({CAT_I})",
        status="Pass" if not active_insecure else "Fail",
        message=f"{get_stig_id('SC', 17)}: Insecure services disabled",
        details=f"Active: {', '.join(active_insecure)}" if active_insecure else "All disabled",
        remediation="Disable insecure services"
    ))
    
    # SC-018: IPv6 disabled or secured (CAT II)
    ipv6_disabled_file = "/proc/sys/net/ipv6/conf/all/disable_ipv6"
    if os.path.exists(ipv6_disabled_file):
        ipv6_status = read_file_safe(ipv6_disabled_file).strip()
        ipv6_disabled = ipv6_status == "1"
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - System & Communications Protection ({CAT_II})",
            status="Info",
            message=f"{get_stig_id('SC', 18)}: IPv6 configuration",
            details="Disabled" if ipv6_disabled else "Enabled",
            remediation="Disable if not needed: sysctl -w net.ipv6.conf.all.disable_ipv6=1"
        ))
    
    # SC-019: Time synchronization secure (CAT II)
    ntp_conf_files = ["/etc/chrony.conf", "/etc/ntp.conf"]
    ntp_servers = []
    
    for conf_file in ntp_conf_files:
        if os.path.exists(conf_file):
            content = read_file_safe(conf_file)
            ntp_servers.extend(re.findall(r'(?:server|pool)\s+(\S+)', content))
    
    ntp_ok = len(ntp_servers) >= 2
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Communications Protection ({CAT_II})",
        status="Pass" if ntp_ok else "Warning",
        message=f"{get_stig_id('SC', 19)}: Time synchronization configured",
        details=f"{len(ntp_servers)} time servers configured",
        remediation="Configure multiple NTP servers"
    ))
    
    # SC-020: Encrypted communications for remote access (CAT I)
    ssh_active = check_service_active("sshd") or check_service_active("ssh")
    telnet_active = check_service_active("telnet")
    
    encrypted_remote = ssh_active and not telnet_active
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Communications Protection ({CAT_I})",
        status="Pass" if encrypted_remote else "Fail",
        message=f"{get_stig_id('SC', 20)}: Encrypted remote access only",
        details="SSH active, Telnet disabled" if encrypted_remote else "Check configuration",
        remediation="Enable SSH, disable Telnet"
    ))


# ============================================================================
# ADDITIONAL STIG REQUIREMENTS
# ============================================================================

def check_additional_requirements(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Additional STIG Requirements Security Audit Checks
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Additional STIG Requirements...")
    
    # ADD-001: System is registered/subscribed (CAT III)
    subscription_files = [
        "/etc/yum.repos.d/redhat.repo",
        "/etc/apt/sources.list.d/*.list",
        "/etc/zypp/repos.d/*.repo"
    ]
    
    has_subscription = any(
        glob.glob(pattern) for pattern in subscription_files if '*' in pattern
    ) or any(os.path.exists(f) for f in subscription_files if '*' not in f)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Additional Requirements ({CAT_III})",
        status="Info",
        message=f"{get_stig_id('ADD', 1)}: System registered/subscribed",
        details="Repository configuration found" if has_subscription else "Check registration",
        remediation="Register system with vendor"
    ))
    
    # ADD-002: Legal notice displayed at boot (CAT II)
    issue_net = os.path.exists("/etc/issue.net") and os.path.getsize("/etc/issue.net") > 10
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Additional Requirements ({CAT_II})",
        status="Pass" if issue_net else "Warning",
        message=f"{get_stig_id('ADD', 2)}: Legal notice at network login",
        details="Configured" if issue_net else "Not configured",
        remediation="Configure /etc/issue.net with legal notice"
    ))
    
    # ADD-003: Message of the day appropriate (CAT III)
    motd = os.path.exists("/etc/motd") and os.path.getsize("/etc/motd") > 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Additional Requirements ({CAT_III})",
        status="Info",
        message=f"{get_stig_id('ADD', 3)}: Message of the day configured",
        details="Configured" if motd else "Not configured",
        remediation="Configure /etc/motd"
    ))
    
    # ADD-004: Emergency accounts identified (CAT II)
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Additional Requirements ({CAT_II})",
        status="Info",
        message=f"{get_stig_id('ADD', 4)}: Emergency accounts identified",
        details="Review emergency access procedures",
        remediation="Document emergency account procedures"
    ))
    
    # ADD-005: Vendor support not expired (CAT III)
    os_release = read_file_safe("/etc/os-release")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Additional Requirements ({CAT_III})",
        status="Info",
        message=f"{get_stig_id('ADD', 5)}: Operating system support status",
        details="Review vendor support status",
        remediation="Ensure OS version is supported"
    ))
    
    # ADD-006: System documentation current (CAT III)
    doc_dirs = ["/usr/share/doc", "/root/documentation"]
    doc_exists = any(os.path.exists(d) for d in doc_dirs)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Additional Requirements ({CAT_III})",
        status="Info",
        message=f"{get_stig_id('ADD', 6)}: System documentation available",
        details="Documentation directory found" if doc_exists else "No documentation",
        remediation="Maintain system documentation"
    ))
    
    # ADD-007: Removable media policy (CAT II)
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Additional Requirements ({CAT_II})",
        status="Info",
        message=f"{get_stig_id('ADD', 7)}: Removable media policy",
        details="Review removable media handling procedures",
        remediation="Document and enforce removable media policy"
    ))
    
    # ADD-008: Mobile device security (CAT II)
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Additional Requirements ({CAT_II})",
        status="Info",
        message=f"{get_stig_id('ADD', 8)}: Mobile device security",
        details="Review mobile device connection policies",
        remediation="Implement mobile device security controls"
    ))
    
    # ADD-009: Information spillage response (CAT II)
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Additional Requirements ({CAT_II})",
        status="Info",
        message=f"{get_stig_id('ADD', 9)}: Information spillage procedures",
        details="Review data spillage response procedures",
        remediation="Document information spillage procedures"
    ))
    
    # ADD-010: Vulnerability scanning (CAT II)
    vuln_scanners = ["openvas", "nessus", "qualys"]
    scanner_installed = any(check_package_installed(s, os_info) for s in vuln_scanners)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Additional Requirements ({CAT_II})",
        status="Info",
        message=f"{get_stig_id('ADD', 10)}: Vulnerability scanning capability",
        details="Scanner installed" if scanner_installed else "No scanner",
        remediation="Implement vulnerability scanning"
    ))
    
    # ADD-011: Patch management process (CAT II)
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Additional Requirements ({CAT_II})",
        status="Info",
        message=f"{get_stig_id('ADD', 11)}: Patch management process",
        details="Review patch management procedures",
        remediation="Document patch management process"
    ))
    
    # ADD-012: Incident response plan (CAT II)
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Additional Requirements ({CAT_II})",
        status="Info",
        message=f"{get_stig_id('ADD', 12)}: Incident response plan",
        details="Review incident response procedures",
        remediation="Document incident response plan"
    ))
    
    # ADD-013: Contingency plan (CAT II)
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Additional Requirements ({CAT_II})",
        status="Info",
        message=f"{get_stig_id('ADD', 13)}: Contingency/disaster recovery plan",
        details="Review contingency planning",
        remediation="Document contingency procedures"
    ))
    
    # ADD-014: Backup procedures (CAT II)
    backup_dirs = ["/backup", "/var/backups", "/mnt/backup"]
    backup_exists = any(os.path.exists(d) for d in backup_dirs)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Additional Requirements ({CAT_II})",
        status="Info",
        message=f"{get_stig_id('ADD', 14)}: Backup procedures implemented",
        details="Backup directory found" if backup_exists else "No backup directory",
        remediation="Implement backup procedures"
    ))
    
    # ADD-015: System monitoring (CAT II)
    monitoring_tools = ["nagios", "zabbix", "prometheus", "collectd"]
    monitoring_active = any(check_service_active(t) for t in monitoring_tools)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Additional Requirements ({CAT_II})",
        status="Info",
        message=f"{get_stig_id('ADD', 15)}: System monitoring implemented",
        details="Monitoring active" if monitoring_active else "No monitoring detected",
        remediation="Implement system monitoring"
    ))
    
    # ADD-016: Security assessment authorization (CAT II)
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Additional Requirements ({CAT_II})",
        status="Info",
        message=f"{get_stig_id('ADD', 16)}: Security assessment & authorization",
        details="Review SA&A documentation",
        remediation="Maintain current SA&A"
    ))
    
    # ADD-017: Personnel security (CAT II)
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Additional Requirements ({CAT_II})",
        status="Info",
        message=f"{get_stig_id('ADD', 17)}: Personnel security requirements",
        details="Review personnel screening procedures",
        remediation="Ensure personnel security requirements met"
    ))
    
    # ADD-018: Security training (CAT II)
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Additional Requirements ({CAT_II})",
        status="Info",
        message=f"{get_stig_id('ADD', 18)}: Security awareness training",
        details="Review training records",
        remediation="Ensure personnel receive required training"
    ))
    
    # ADD-019: Physical security (CAT II)
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Additional Requirements ({CAT_II})",
        status="Info",
        message=f"{get_stig_id('ADD', 19)}: Physical security controls",
        details="Review physical security measures",
        remediation="Implement appropriate physical security"
    ))
    
    # ADD-020: Media protection (CAT II)
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Additional Requirements ({CAT_II})",
        status="Info",
        message=f"{get_stig_id('ADD', 20)}: Media protection procedures",
        details="Review media handling procedures",
        remediation="Document media protection procedures"
    ))


# ============================================================================
# STIG Media Protection & FIPS Validation
# Phase 1 Gap: USB/removable media, FIPS 140-2/140-3
# ============================================================================

def check_media_protection_fips(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    DISA STIG media protection controls and FIPS 140 cryptographic validation.
    Checks USB storage restriction, removable media policies, and FIPS mode.
    """
    cache = shared_data.get('cache')

    # --- USB Storage Module Restriction ---
    # Check if usb-storage kernel module is disabled
    result = run_command("lsmod 2>/dev/null | grep usb_storage", check=False)
    usb_loaded = result.returncode == 0 and "usb_storage" in result.stdout

    # Check modprobe blacklist
    blacklist_files = ["/etc/modprobe.d/blacklist.conf", "/etc/modprobe.d/disable-usb-storage.conf",
                       "/etc/modprobe.d/usb-storage.conf"]
    usb_blacklisted = False
    for bf in blacklist_files:
        content = read_file_safe(bf)
        if content and ("blacklist usb-storage" in content or "install usb-storage /bin/false" in content
                        or "install usb-storage /bin/true" in content):
            usb_blacklisted = True
            break

    if usb_blacklisted and not usb_loaded:
        status = "Pass"
        detail = "USB storage module blacklisted and not loaded"
    elif usb_blacklisted:
        status = "Warning"
        detail = "USB storage module blacklisted but currently loaded"
    elif usb_loaded:
        status = "Fail"
        detail = "USB storage module loaded and not blacklisted"
    else:
        status = "Warning"
        detail = "USB storage module not loaded but not explicitly blacklisted"

    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Media Protection ({CAT_II})",
        status=status,
        message=f"{get_stig_id('MP', 1)}: USB storage device restriction",
        details=detail,
        remediation="echo 'install usb-storage /bin/false' > /etc/modprobe.d/disable-usb-storage.conf "
                    "&& rmmod usb_storage 2>/dev/null",
        severity="Medium"
    ))

    # --- Firewire/Thunderbolt module restriction ---
    dangerous_modules = {
        "firewire-core": "FireWire (DMA attack vector)",
        "firewire_core": "FireWire (DMA attack vector)",
        "thunderbolt": "Thunderbolt (DMA attack vector)",
    }
    for mod, desc in dangerous_modules.items():
        result = run_command(f"lsmod 2>/dev/null | grep {mod.replace('-', '_')}", check=False)
        mod_loaded = result.returncode == 0 and mod.replace('-', '_') in result.stdout

        mod_blacklisted = False
        for bf in ["/etc/modprobe.d/blacklist.conf", f"/etc/modprobe.d/disable-{mod}.conf"]:
            content = read_file_safe(bf)
            if content and (f"blacklist {mod}" in content or f"install {mod} /bin/false" in content):
                mod_blacklisted = True
                break

        results.append(AuditResult(
            module=MODULE_NAME,
            category=f"STIG - Media Protection ({CAT_II})",
            status="Pass" if mod_blacklisted and not mod_loaded else (
                "Warning" if not mod_loaded else "Fail"),
            message=f"{get_stig_id('MP', 2)}: {desc} module restriction",
            details=f"{mod}: loaded={mod_loaded}, blacklisted={mod_blacklisted}",
            remediation=f"echo 'install {mod} /bin/false' >> /etc/modprobe.d/blacklist.conf",
            severity="Medium"
        ))

    # --- Automount disabled ---
    autofs_active = False
    result = run_command("systemctl is-active autofs 2>/dev/null", check=False)
    if result.returncode == 0 and "active" in result.stdout.strip():
        autofs_active = True
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - Media Protection ({CAT_II})",
        status="Fail" if autofs_active else "Pass",
        message=f"{get_stig_id('MP', 3)}: Automount service (autofs) disabled",
        details=f"autofs: {'active (security risk)' if autofs_active else 'not active'}",
        remediation="systemctl stop autofs && systemctl disable autofs && systemctl mask autofs",
        severity="Medium"
    ))

    # --- FIPS 140 Mode ---
    fips_file = "/proc/sys/crypto/fips_enabled"
    fips_enabled = False
    if os.path.exists(fips_file):
        try:
            with open(fips_file, 'r') as f:
                fips_enabled = f.read().strip() == "1"
        except (PermissionError, IOError):
            pass

    # Also check kernel command line
    cmdline = read_file_safe("/proc/cmdline") or ""
    fips_cmdline = "fips=1" in cmdline

    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Communications Protection ({CAT_I})",
        status="Pass" if fips_enabled else "Warning",
        message=f"{get_stig_id('SC', 20)}: FIPS 140-2/140-3 mode",
        details=f"FIPS kernel mode: {'enabled' if fips_enabled else 'disabled'}, "
                f"FIPS cmdline: {'present' if fips_cmdline else 'absent'}",
        remediation="fips-mode-setup --enable  (RHEL) or add fips=1 to kernel cmdline",
        severity="High"
    ))

    # --- Crypto module validation ---
    result = run_command("cat /proc/crypto 2>/dev/null | grep -c 'module.*kernel'", check=False)
    crypto_modules = safe_int_parse(result.stdout.strip(), default=0)
    results.append(AuditResult(
        module=MODULE_NAME,
        category=f"STIG - System & Communications Protection ({CAT_II})",
        status="Info",
        message=f"{get_stig_id('SC', 21)}: Kernel cryptographic modules",
        details=f"Registered kernel crypto modules: {crypto_modules}",
        remediation="Verify all crypto modules are FIPS-validated when in FIPS mode",
        severity="Low"
    ))


# ============================================================================
# Main Orchestration Function
# ============================================================================

def _enrich_disa_references(results: List[AuditResult]) -> None:
    """
    Post-process all STIG results to auto-populate DISA cross-references.

    Parses the STIG ID from each result's message field (format: STIG-XX-NNN:)
    and looks up the corresponding DISA STIG reference ID from DISA_STIG_REFS.
    Only adds references where a mapping exists and cross_references is empty.
    """
    import re
    stig_id_pattern = re.compile(r'STIG-(\w+)-(\d+)')

    for result in results:
        # Skip results that already have cross-references
        if result.cross_references:
            continue

        match = stig_id_pattern.search(result.message)
        if match:
            category = match.group(1)
            number = int(match.group(2))
            refs = get_disa_ref(category, number)
            if refs:
                result.cross_references = refs


def run_checks(shared_data: Dict[str, Any]) -> List[AuditResult]:
    """
    Main entry point for STIG module
    Executes all security control checks and returns results
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
    print(f"[{MODULE_NAME}] DISA STIG COMPLIANCE AUDIT")
    print(f"[{MODULE_NAME}] " + "="*70)
    print(f"[{MODULE_NAME}] Version: {MODULE_VERSION}")
    print(f"[{MODULE_NAME}] Focus: DoD Security Requirements")
    print(f"[{MODULE_NAME}] Control Areas: AC, AU, IA, SI, CM, SC + Additional")
    print(f"[{MODULE_NAME}] Target: 200+ Comprehensive Security Audit Checks")
    print(f"[{MODULE_NAME}] " + "="*70 + "\n")
    
    is_root = shared_data.get("is_root", os.geteuid() == 0)
    if not is_root:
        print(f"[{MODULE_NAME}]   Note: Running without root privileges")
        print(f"[{MODULE_NAME}] Some checks require elevated privileges for full coverage\n")
    
    try:
        # Execute all control area checks
        check_access_control(results, shared_data, os_info)
        check_audit_accountability(results, shared_data, os_info)
        check_identification_authentication(results, shared_data, os_info)
        check_system_information_integrity(results, shared_data, os_info)
        check_configuration_management(results, shared_data, os_info)
        check_system_communications_protection(results, shared_data, os_info)
        check_additional_requirements(results, shared_data, os_info)
        # Phase 1 new checks
        check_media_protection_fips(results, shared_data, os_info)
        
        # Enrich results with DISA STIG cross-references
        _enrich_disa_references(results)
        
    except Exception as e:
        print(f"[{MODULE_NAME}]  Error during audit execution: {str(e)}")
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Error",
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
    cat_i = sum(1 for r in results if CAT_I in r.category)
    cat_ii = sum(1 for r in results if CAT_II in r.category)
    cat_iii = sum(1 for r in results if CAT_III in r.category)
    
    print(f"\n[{MODULE_NAME}] " + "="*70)
    print(f"[{MODULE_NAME}] DISA STIG SECURITY AUDIT COMPLETED")
    print(f"[{MODULE_NAME}] " + "="*70)
    print(f"[{MODULE_NAME}] Total Security Audit Checks Executed: {len(results)}")
    print(f"[{MODULE_NAME}] ")
    print(f"[{MODULE_NAME}] Results Summary:")
    print(f"[{MODULE_NAME}]   Passed:  {pass_count:3d} ({pass_count/len(results)*100:.1f}%)")
    print(f"[{MODULE_NAME}]   Failed:  {fail_count:3d} ({fail_count/len(results)*100:.1f}%)")
    print(f"[{MODULE_NAME}]   Warnings: {warn_count:3d} ({warn_count/len(results)*100:.1f}%)")
    print(f"[{MODULE_NAME}]   Info:    {info_count:3d} ({info_count/len(results)*100:.1f}%)")
    print(f"[{MODULE_NAME}]   Errors:  {error_count:3d} ({error_count/len(results)*100:.1f}%)")
    print(f"[{MODULE_NAME}] ")
    print(f"[{MODULE_NAME}] STIG Severity Categories:")
    print(f"[{MODULE_NAME}]    CAT I   (High):   {cat_i:3d} findings")
    print(f"[{MODULE_NAME}]    CAT II  (Medium): {cat_ii:3d} findings")
    print(f"[{MODULE_NAME}]   CAT III (Low):    {cat_iii:3d} findings")
    print(f"[{MODULE_NAME}] " + "="*70 + "\n")
    
    return results


# ============================================================================
# Module Testing
# ============================================================================



# ============================================================================
# v3.3 EXPANSION - DISA STIG Deep V-Number Coverage
# ----------------------------------------------------------------------------
# Synopsis:
#   Adds explicit V-number cross-references for additional STIG controls:
#   - RHEL 9 STIG additional V-numbers
#   - Ubuntu 22.04 STIG additional V-numbers
#   - General Purpose Operating System SRG (GPOS-00001 to GPOS-00510)
#   - Container Platform SRG indicators
#   - Kubernetes STIG indicators (where containers detected)
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


def _v33_stig_result(category, status, message, severity="Medium",
                     details="", remediation="", cross_references=None):
    """Build AuditResult for STIG v3.3 expansion."""
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


def _check_stig_v33_rhel9_additional(results, shared_data, os_info):
    """RHEL 9 STIG additional V-numbers."""

    sshd = _v33_read_file_safe("/etc/ssh/sshd_config")

    # V-258003 - PrintLastLog
    pll_match = re.search(r"^\s*PrintLastLog\s+(\S+)", sshd, re.MULTILINE)
    pll = pll_match.group(1).lower() if pll_match else "yes"  # default
    results.append(_v33_stig_result(
        "STIG V-258003 v3.3",
        "Pass" if pll == "yes" else "Fail",
        "V-258003 SSH PrintLastLog enabled",
        severity="Medium",
        details=f"PrintLastLog = {pll}",
        remediation="In /etc/ssh/sshd_config: PrintLastLog yes",
        cross_references={
            "STIG": "V-258003 (RHEL 9)", "NIST": "AC-9",
        },
    ))

    # V-258006 - GSSAPIAuthentication
    gssapi_match = re.search(r"^\s*GSSAPIAuthentication\s+(\S+)", sshd, re.MULTILINE)
    gssapi = gssapi_match.group(1).lower() if gssapi_match else "yes"
    results.append(_v33_stig_result(
        "STIG V-258006 v3.3",
        "Pass" if gssapi == "no" else "Fail",
        "V-258006 SSH GSSAPIAuthentication disabled",
        severity="Medium",
        details=f"GSSAPIAuthentication = {gssapi}",
        remediation="In /etc/ssh/sshd_config: GSSAPIAuthentication no",
        cross_references={
            "STIG": "V-258006 (RHEL 9)", "NIST": "CM-7",
        },
    ))

    # V-258007 - KerberosAuthentication
    kerb_match = re.search(r"^\s*KerberosAuthentication\s+(\S+)", sshd, re.MULTILINE)
    kerb = kerb_match.group(1).lower() if kerb_match else "yes"
    results.append(_v33_stig_result(
        "STIG V-258007 v3.3",
        "Pass" if kerb == "no" else "Fail",
        "V-258007 SSH KerberosAuthentication disabled",
        severity="Medium",
        details=f"KerberosAuthentication = {kerb}",
        remediation="In /etc/ssh/sshd_config: KerberosAuthentication no",
        cross_references={
            "STIG": "V-258007 (RHEL 9)", "NIST": "CM-7",
        },
    ))

    # V-258028 - GPG signing of repositories
    rpm_gpgcheck = "gpgcheck=1" in (
        _v33_read_file_safe("/etc/yum.conf") or
        _v33_read_file_safe("/etc/dnf/dnf.conf")
    )
    results.append(_v33_stig_result(
        "STIG V-258028 v3.3",
        "Pass" if rpm_gpgcheck else "Fail",
        "V-258028 RPM gpgcheck enabled",
        severity="High",
        details=f"gpgcheck=1: {rpm_gpgcheck}",
        remediation="In /etc/dnf/dnf.conf: gpgcheck=1",
        cross_references={
            "STIG": "V-258028 (RHEL 9)", "NIST": "CM-5(3)",
        },
    ))

    # V-258029 - localpkg_gpgcheck
    localpkg_check = "localpkg_gpgcheck=1" in (
        _v33_read_file_safe("/etc/yum.conf") or
        _v33_read_file_safe("/etc/dnf/dnf.conf")
    )
    results.append(_v33_stig_result(
        "STIG V-258029 v3.3",
        "Pass" if localpkg_check else "Fail",
        "V-258029 RPM localpkg_gpgcheck enabled",
        severity="High",
        details=f"localpkg_gpgcheck=1: {localpkg_check}",
        remediation="In /etc/dnf/dnf.conf: localpkg_gpgcheck=1",
        cross_references={
            "STIG": "V-258029 (RHEL 9)", "NIST": "CM-5(3)",
        },
    ))

    # V-258034 - kernel.dmesg_restrict
    dmesg = _v33_read_sysctl("kernel.dmesg_restrict")
    results.append(_v33_stig_result(
        "STIG V-258034 v3.3",
        "Pass" if dmesg == "1" else "Fail",
        "V-258034 kernel.dmesg_restrict = 1",
        severity="Medium",
        details=f"kernel.dmesg_restrict = {dmesg}",
        remediation=(
            "echo 'kernel.dmesg_restrict = 1' >> /etc/sysctl.d/99-stig.conf"
        ),
        cross_references={
            "STIG": "V-258034 (RHEL 9)", "NIST": "AC-3",
        },
    ))

    # V-258035 - kernel.kptr_restrict
    kptr = _v33_read_sysctl("kernel.kptr_restrict")
    results.append(_v33_stig_result(
        "STIG V-258035 v3.3",
        "Pass" if kptr in ("1", "2") else "Fail",
        "V-258035 kernel.kptr_restrict",
        severity="Medium",
        details=f"kernel.kptr_restrict = {kptr}",
        remediation=(
            "echo 'kernel.kptr_restrict = 2' >> /etc/sysctl.d/99-stig.conf"
        ),
        cross_references={
            "STIG": "V-258035 (RHEL 9)", "NIST": "AC-3",
        },
    ))

    # V-258049 - fs.protected_hardlinks
    pl = _v33_read_sysctl("fs.protected_hardlinks")
    results.append(_v33_stig_result(
        "STIG V-258049 v3.3",
        "Pass" if pl == "1" else "Fail",
        "V-258049 fs.protected_hardlinks = 1",
        severity="Medium",
        details=f"fs.protected_hardlinks = {pl}",
        remediation=(
            "echo 'fs.protected_hardlinks = 1' >> /etc/sysctl.d/99-stig.conf"
        ),
        cross_references={
            "STIG": "V-258049 (RHEL 9)", "NIST": "AC-3",
        },
    ))

    # V-258050 - fs.protected_symlinks
    ps = _v33_read_sysctl("fs.protected_symlinks")
    results.append(_v33_stig_result(
        "STIG V-258050 v3.3",
        "Pass" if ps == "1" else "Fail",
        "V-258050 fs.protected_symlinks = 1",
        severity="Medium",
        details=f"fs.protected_symlinks = {ps}",
        remediation=(
            "echo 'fs.protected_symlinks = 1' >> /etc/sysctl.d/99-stig.conf"
        ),
        cross_references={
            "STIG": "V-258050 (RHEL 9)", "NIST": "AC-3",
        },
    ))

    # V-258054 - net.ipv4.icmp_echo_ignore_broadcasts
    icmp_b = _v33_read_sysctl("net.ipv4.icmp_echo_ignore_broadcasts")
    results.append(_v33_stig_result(
        "STIG V-258054 v3.3",
        "Pass" if icmp_b == "1" else "Fail",
        "V-258054 ICMP echo broadcasts ignored",
        severity="Medium",
        details=f"icmp_echo_ignore_broadcasts = {icmp_b}",
        remediation=(
            "echo 'net.ipv4.icmp_echo_ignore_broadcasts = 1' "
            ">> /etc/sysctl.d/99-stig.conf"
        ),
        cross_references={
            "STIG": "V-258054 (RHEL 9)", "NIST": "SC-7",
        },
    ))


def _check_stig_v33_ubuntu_additional(results, shared_data, os_info):
    """Ubuntu 22.04 STIG additional V-numbers."""

    # V-260469 - Disable wireless network adapters if not needed
    rc, out, _ = _v33_run_command(["nmcli", "radio", "wifi"], timeout=3.0)
    wifi_off = rc == 0 and "disabled" in out.lower()
    rc2, out2, _ = _v33_run_command(["rfkill", "list", "wifi"], timeout=3.0)
    rfkill_off = rc2 == 0 and "Soft blocked: yes" in out2
    wifi_state = wifi_off or rfkill_off
    has_wifi = (rc == 0 and "wifi" in out.lower()) or (rc2 == 0 and "wlan" in out2.lower())
    if has_wifi:
        results.append(_v33_stig_result(
            "STIG V-260469 v3.3",
            "Pass" if wifi_state else "Info",
            "V-260469 Wireless adapters disabled (Ubuntu)",
            severity="Medium",
            details=f"Wifi disabled: {wifi_state}",
            remediation=(
                "If wireless not needed: nmcli radio wifi off  (or rfkill block all)"
            ),
            cross_references={
                "STIG": "V-260469 (Ubuntu 22.04)", "NIST": "CM-7",
            },
        ))

    # V-260473 - APT GPG verification
    apt_keyring = (
        _v33_directory_exists("/etc/apt/trusted.gpg.d") or
        _v33_directory_exists("/etc/apt/keyrings")
    )
    results.append(_v33_stig_result(
        "STIG V-260473 v3.3",
        "Pass" if apt_keyring else "Fail",
        "V-260473 APT GPG keyring populated",
        severity="High",
        details=f"apt keyring: {apt_keyring}",
        cross_references={
            "STIG": "V-260473 (Ubuntu 22.04)", "NIST": "CM-5(3)",
        },
    ))

    # V-260491 - apt-get unattended upgrades
    unattended = _v33_systemd_active("unattended-upgrades.service") == "active"
    results.append(_v33_stig_result(
        "STIG V-260491 v3.3",
        "Pass" if unattended else "Warning",
        "V-260491 unattended-upgrades active",
        severity="High",
        details=f"unattended-upgrades: {unattended}",
        remediation=(
            "apt-get install -y unattended-upgrades; "
            "dpkg-reconfigure unattended-upgrades"
        ),
        cross_references={
            "STIG": "V-260491 (Ubuntu 22.04)", "NIST": "SI-2",
        },
    ))

    # V-260507 - AppArmor enabled and enforcing
    aa_active = _v33_systemd_active("apparmor.service") == "active"
    rc, _, _ = _v33_run_command(["aa-status", "--enabled"], timeout=3.0)
    aa_enabled = rc == 0
    aa_ok = aa_active or aa_enabled
    results.append(_v33_stig_result(
        "STIG V-260507 v3.3",
        "Pass" if aa_ok else "Fail",
        "V-260507 AppArmor active",
        severity="High",
        details=f"apparmor service: {aa_active}, aa-status: {aa_enabled}",
        remediation=remediation_for("apparmor"),
        cross_references={
            "STIG": "V-260507 (Ubuntu 22.04)", "NIST": "AC-3",
        },
    ))

    # V-260511 - core dump backtraces
    coredumps_off = (
        _v33_read_sysctl("fs.suid_dumpable") == "0"
    )
    results.append(_v33_stig_result(
        "STIG V-260511 v3.3",
        "Pass" if coredumps_off else "Fail",
        "V-260511 fs.suid_dumpable = 0",
        severity="Medium",
        details=f"suid_dumpable = {_v33_read_sysctl('fs.suid_dumpable')}",
        remediation=(
            "echo 'fs.suid_dumpable = 0' >> /etc/sysctl.d/99-stig.conf"
        ),
        cross_references={
            "STIG": "V-260511 (Ubuntu 22.04)", "NIST": "SI-11",
        },
    ))


def _check_stig_v33_gpos_srg(results, shared_data, os_info):
    """General Purpose OS SRG (GPOS) controls."""

    # SRG-OS-000023-GPOS-00006 - Logon banner
    issue = _v33_read_file_safe("/etc/issue")
    banner_match = re.search(
        r"^\s*Banner\s+(\S+)", _v33_read_file_safe("/etc/ssh/sshd_config"),
        re.MULTILINE
    )
    banner_set = banner_match and banner_match.group(1) != "none"
    aup_keywords = ["authorized", "monitor", "consent", "warning"]
    issue_has_aup = any(k in issue.lower() for k in aup_keywords)
    banner_ok = banner_set or issue_has_aup
    results.append(_v33_stig_result(
        "STIG SRG-OS-000023 v3.3",
        "Pass" if banner_ok else "Fail",
        "SRG-OS-000023 System login banner set",
        severity="High",
        details=f"SSH Banner set: {bool(banner_set)}, /etc/issue has AUP: {issue_has_aup}",
        remediation=(
            "Edit /etc/issue with authorized-use legal banner; "
            "in /etc/ssh/sshd_config: Banner /etc/issue.net"
        ),
        cross_references={
            "STIG": "SRG-OS-000023-GPOS-00006", "NIST": "AC-8",
        },
    ))

    # SRG-OS-000033-GPOS-00014 - FIPS-validated cryptography
    fips_active = False
    if _v33_file_exists("/proc/sys/crypto/fips_enabled"):
        fips_active = _v33_read_file_safe(
            "/proc/sys/crypto/fips_enabled"
        ).strip() == "1"
    results.append(_v33_stig_result(
        "STIG SRG-OS-000033 v3.3",
        "Pass" if fips_active else "Info",
        f"SRG-OS-000033 FIPS-validated cryptography: {fips_active}",
        severity="High",
        details=f"Kernel FIPS mode: {fips_active}",
        remediation="fips-mode-setup --enable; reboot  (RHEL family)",
        cross_references={
            "STIG": "SRG-OS-000033-GPOS-00014", "NIST": "SC-13", "FIPS": "140-3",
        },
    ))

    # SRG-OS-000037-GPOS-00015 - Audit records contain identity info
    auditd_active = _v33_systemd_active("auditd.service") == "active"
    audit_rules = ""
    if _v33_directory_exists(rules_d := "/etc/audit/rules.d"):
        for f in _v33_list_directory(rules_d):
            if f.endswith(".rules"):
                audit_rules += "\n" + _v33_read_file_safe(
                    os.path.join(rules_d, f)
                )
    has_uid_filter = "auid" in audit_rules
    results.append(_v33_stig_result(
        "STIG SRG-OS-000037 v3.3",
        "Pass" if (auditd_active and has_uid_filter) else "Warning",
        "SRG-OS-000037 Audit records with identity (auid)",
        severity="High",
        details=f"auditd: {auditd_active}, auid filtering: {has_uid_filter}",
        remediation=(
            "Add audit rules with -F auid>=1000 -F auid!=4294967295"
        ),
        cross_references={
            "STIG": "SRG-OS-000037-GPOS-00015", "NIST": "AU-3",
        },
    ))

    # SRG-OS-000062-GPOS-00031 - Audit privileged functions
    has_priv = "privileged" in audit_rules or "execve" in audit_rules
    results.append(_v33_stig_result(
        "STIG SRG-OS-000062 v3.3",
        "Pass" if has_priv else "Fail",
        "SRG-OS-000062 Audit privileged function execution",
        severity="High",
        details=f"privileged/execve audit: {has_priv}",
        remediation=(
            "-a always,exit -F arch=b64 -S execve -F euid=0 -k privileged"
        ),
        cross_references={
            "STIG": "SRG-OS-000062-GPOS-00031", "NIST": "AU-2",
        },
    ))

    # SRG-OS-000080-GPOS-00048 - Boot loader password protection
    grub_pwd_set = False
    for f in ["/etc/grub.d/01_users", "/etc/grub.d/40_custom",
               "/boot/grub2/user.cfg", "/boot/grub/grub.cfg",
               "/boot/grub2/grub.cfg"]:
        c = _v33_read_file_safe(f)
        if "password_pbkdf2" in c or "GRUB2_PASSWORD" in c:
            grub_pwd_set = True
            break
    results.append(_v33_stig_result(
        "STIG SRG-OS-000080 v3.3",
        "Pass" if grub_pwd_set else "Fail",
        "SRG-OS-000080 GRUB password protection",
        severity="High",
        details=f"GRUB password set: {grub_pwd_set}",
        remediation=(
            "RHEL: grub2-setpassword. "
            "Debian: grub-mkpasswd-pbkdf2 then add to /etc/grub.d/40_custom"
        ),
        cross_references={
            "STIG": "SRG-OS-000080-GPOS-00048", "NIST": "AC-3",
        },
    ))

    # SRG-OS-000363-GPOS-00150 - File integrity verification
    fim_present = (
        _v33_file_exists("/var/lib/aide/aide.db") or
        _v33_file_exists("/var/lib/aide/aide.db.gz") or
        _v33_file_exists("/etc/tripwire/tw.cfg")
    )
    results.append(_v33_stig_result(
        "STIG SRG-OS-000363 v3.3",
        "Pass" if fim_present else "Fail",
        "SRG-OS-000363 File integrity verification capability",
        severity="High",
        details=f"AIDE/Tripwire DB present: {fim_present}",
        remediation=remediation_for("aide"),
        cross_references={
            "STIG": "SRG-OS-000363-GPOS-00150", "NIST": "SI-7",
        },
    ))

    # SRG-OS-000437-GPOS-00194 - System startup processes via systemd
    init_is_systemd = _v33_command_available("systemctl")
    results.append(_v33_stig_result(
        "STIG SRG-OS-000437 v3.3",
        "Pass" if init_is_systemd else "Info",
        "SRG-OS-000437 systemd-managed startup",
        severity="Low",
        details=f"systemctl present: {init_is_systemd}",
        cross_references={
            "STIG": "SRG-OS-000437-GPOS-00194", "NIST": "CM-2",
        },
    ))

    # SRG-OS-000470-GPOS-00214 - Audit unsuccessful logon
    has_failed_login = (
        "/var/run/faillock" in audit_rules or "logins" in audit_rules
    )
    results.append(_v33_stig_result(
        "STIG SRG-OS-000470 v3.3",
        "Pass" if has_failed_login else "Warning",
        "SRG-OS-000470 Audit unsuccessful logons",
        severity="High",
        details=f"login failure audit: {has_failed_login}",
        remediation="-w /var/run/faillock -p wa -k logins",
        cross_references={
            "STIG": "SRG-OS-000470-GPOS-00214", "NIST": "AU-2",
        },
    ))


def _check_stig_v33_container_srg(results, shared_data, os_info):
    """Container Platform SRG indicators (when containers detected)."""

    docker_present = (
        _v33_command_available("docker") or
        _v33_systemd_active("docker.service") == "active"
    )
    podman_present = _v33_command_available("podman")
    k8s_present = _v33_command_available("kubelet")
    cri_present = _v33_command_available("crictl")

    if not (docker_present or podman_present or k8s_present or cri_present):
        return

    # SRG-APP-000033-CTR-00080 - Container with non-root UID
    if docker_present:
        rc, out, _ = _v33_run_command(
            ["docker", "ps", "--format", "{{.Names}}"], timeout=5.0
        )
        any_running = rc == 0 and out.strip()
        results.append(_v33_stig_result(
            "STIG SRG-APP-000033-CTR v3.3",
            "Info",
            f"Container Platform SRG: Docker containers running ({any_running})",
            severity="Informational",
            details=f"Containers running: {bool(any_running)}",
            cross_references={
                "STIG": "SRG-APP-000033-CTR-00080", "NIST": "AC-6",
            },
        ))

    # Docker daemon hardening
    if docker_present:
        daemon_json = _v33_read_file_safe("/etc/docker/daemon.json")
        hardening = {
            "userns-remap": "userns-remap" in daemon_json,
            "no-new-privileges": "no-new-privileges" in daemon_json,
            "icc-disabled": '"icc": false' in daemon_json,
            "live-restore": "live-restore" in daemon_json,
        }
        enabled = sum(hardening.values())
        results.append(_v33_stig_result(
            "STIG SRG-APP-000516-CTR v3.3",
            "Pass" if enabled >= 2 else "Warning",
            f"Container daemon hardening ({enabled}/4)",
            severity="High",
            details=f"Enabled: {[k for k, v in hardening.items() if v]}",
            remediation=(
                'In /etc/docker/daemon.json: '
                '{"userns-remap":"default","no-new-privileges":true,'
                '"icc":false,"live-restore":true}'
            ),
            cross_references={
                "STIG": "SRG-APP-000516-CTR", "NIST": "CM-7",
            },
        ))

    # Kubernetes presence
    if k8s_present:
        results.append(_v33_stig_result(
            "STIG K8s v3.3",
            "Info",
            "Kubernetes kubelet detected - Kubernetes STIG applies",
            severity="Informational",
            details="kubelet binary available",
            remediation=(
                "Apply Kubernetes STIG (V-242376 to V-242477). "
                "Configure kubelet --read-only-port=0, --anonymous-auth=false"
            ),
            cross_references={
                "STIG": "Kubernetes STIG", "NIST": "AC-3",
            },
        ))


def _check_stig_v33_pam_additional(results, shared_data, os_info):
    """STIG additional PAM controls."""

    # V-230373 - Lock account after 35 days inactivity
    login_defs = _v33_read_file_safe("/etc/login.defs")
    inact_match = re.search(r"^\s*INACTIVE\s+(\d+)", login_defs, re.MULTILINE)
    # Also check useradd defaults
    useradd_default = _v33_read_file_safe("/etc/default/useradd")
    inact_useradd = re.search(r"^\s*INACTIVE\s*=\s*(\d+)", useradd_default, re.MULTILINE)
    inact = None
    if inact_match:
        inact = int(inact_match.group(1))
    elif inact_useradd:
        inact = int(inact_useradd.group(1))
    inact_ok = inact is not None and 0 < inact <= 35
    results.append(_v33_stig_result(
        "STIG V-230373 v3.3",
        "Pass" if inact_ok else "Warning",
        f"V-230373 Inactive account lock <= 35 days ({inact})",
        severity="Medium",
        details=f"INACTIVE = {inact}",
        remediation="useradd -D -f 35; or in /etc/default/useradd: INACTIVE=35",
        cross_references={
            "STIG": "V-230373", "NIST": "AC-2(3)",
        },
    ))

    # V-230376 - Empty password lock
    shadow = _v33_read_file_safe("/etc/shadow")
    empty_pw = []
    if shadow:
        for line in shadow.splitlines():
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] == "":
                empty_pw.append(parts[0])
    results.append(_v33_stig_result(
        "STIG V-230376 v3.3",
        "Pass" if not empty_pw else "Fail",
        f"V-230376 No accounts with empty passwords ({len(empty_pw)})",
        severity="Critical",
        details=f"Empty password users: {empty_pw[:5]}",
        remediation="passwd -l <user> for each",
        cross_references={
            "STIG": "V-230376", "NIST": "IA-5",
        },
    ))

    # V-230380 - Encrypt user data at rest (LUKS detection)
    rc, out, _ = _v33_run_command(["lsblk", "-o", "TYPE", "-n"], timeout=3.0)
    luks = rc == 0 and "crypt" in out.lower()
    results.append(_v33_stig_result(
        "STIG V-230380 v3.3",
        "Pass" if luks else "Warning",
        f"V-230380 Disk encryption (LUKS): {luks}",
        severity="High",
        details=f"LUKS volumes detected: {luks}",
        remediation="cryptsetup luksFormat <device> for sensitive volumes",
        cross_references={
            "STIG": "V-230380", "NIST": "SC-28",
        },
    ))

    # V-230388 - Only root has UID 0
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
    results.append(_v33_stig_result(
        "STIG V-230388 v3.3",
        "Pass" if not uid0 else "Fail",
        f"V-230388 Only root has UID 0 ({len(uid0)} extras)",
        severity="Critical",
        details=f"Non-root UID 0: {uid0}",
        remediation="usermod -u <new_uid> <user>",
        cross_references={
            "STIG": "V-230388", "NIST": "AC-6",
        },
    ))


# Save reference to existing run_checks
_original_run_checks_stig_v33 = run_checks


def run_checks(shared_data):
    """Execute the v3.3 expanded STIG module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_stig_v33(shared_data)

    os_info = shared_data.get("os_info") or shared_data.get("v3_os_info")
    if os_info is None:
        from shared_components import os_detection as _os_det
        os_info = _os_det.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        _check_stig_v33_rhel9_additional(results, shared_data, os_info)
        _check_stig_v33_ubuntu_additional(results, shared_data, os_info)
        _check_stig_v33_gpos_srg(results, shared_data, os_info)
        _check_stig_v33_container_srg(results, shared_data, os_info)
        _check_stig_v33_pam_additional(results, shared_data, os_info)
    except Exception as exc:  # noqa: BLE001
        results.append(AuditResult(
            module=MODULE_NAME, category="STIG - Error",
            status="Error",
            message=f"STIG v3.3 expansion exception: {exc!r}",
            details=str(exc), severity="Medium",
        ))

    return results


# ============================================================================
# v3.5 EXPANSION - DISA STIG Application/Network/Web/Database SRG Coverage
# ----------------------------------------------------------------------------
# Synopsis:
#   Adds depth across DISA STIG areas underrepresented in the existing
#   module:
#     - Application Security and Development STIG (server-side software)
#     - Web Server STIG (nginx/Apache hardening)
#     - Database STIG (PostgreSQL/MySQL/SQLite hardening surrogates)
#     - Container Platform STIG depth (Docker/Podman/K8s)
#     - Network Device STIG (relevant Linux network controls)
#     - Additional RHEL 9 / Ubuntu 22.04 / Ubuntu 24.04 V-numbers
#     - SRG-OS additional categories
#     - SRG-APP-SRC additional categories
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


def _v35_stig_result(category, status, message, severity="Medium",
                    details="", remediation="", cross_references=None):
    """Build AuditResult for STIG v3.5 expansion."""
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


def _check_stig_v35_appsrg_application_security(results, shared_data, os_info):
    """DISA Application Security and Development STIG."""
    cat = "STIG v3.5 - SRG-APP-SRC"

    # APP-3300 (SRG-APP-000033-DB-000084) - Application security testing tools
    sast_tools = {
        "shellcheck": _v35_command_available("shellcheck"),
        "bandit": _v35_command_available("bandit"),
        "semgrep": _v35_command_available("semgrep"),
        "pylint": _v35_command_available("pylint"),
    }
    sast_count = sum(1 for v in sast_tools.values() if v)
    results.append(_v35_stig_result(
        f"{cat} - SRG-APP-000033 SAST Tooling",
        "Pass" if sast_count >= 2 else "Warning",
        f"STIG SRG-APP-000033 SAST tools: {sast_count}/4",
        severity="Medium",
        details=f"Available: {[k for k, v in sast_tools.items() if v]}",
        remediation=(
            "Install for build pipelines:\n"
            "  apt-get install -y shellcheck python3-bandit pylint\n"
            "  pip install --user semgrep"
        ),
        cross_references={
            "STIG": "SRG-APP-000033, V-218790",
            "NIST": "SA-11", "ISO27001": "A.8.28",
        },
    ))

    # APP-3500 - Cryptographic key management surrogate
    key_mgmt_tools = {
        "openssl": _v35_command_available("openssl"),
        "gnutls": _v35_command_available("gnutls-cli"),
        "TPM (tpm2-tools)": (
            _v35_command_available("tpm2_pcrread") or
            _v35_directory_exists("/sys/class/tpm/tpm0")
        ),
        "PKCS#11 (pkcs11-tool)": _v35_command_available("pkcs11-tool"),
    }
    km_count = sum(1 for v in key_mgmt_tools.values() if v)
    results.append(_v35_stig_result(
        f"{cat} - SRG-APP-000503 Key Management",
        "Pass" if km_count >= 2 else "Warning",
        f"STIG SRG-APP-000503 Cryptographic key tools: {km_count}/4",
        severity="High",
        details=f"Available: {[k for k, v in key_mgmt_tools.items() if v]}",
        cross_references={
            "STIG": "SRG-APP-000503",
            "NIST": "SC-12, SC-13",
            "FIPS": "140-3",
        },
    ))

    # APP-2105 - Audit logging for application events (auditd watching app dirs)
    rules_text = ""
    if _v35_directory_exists("/etc/audit/rules.d"):
        for f in _v35_list_directory("/etc/audit/rules.d"):
            if f.endswith(".rules"):
                rules_text += "\n" + _v35_read_file_safe(
                    os.path.join("/etc/audit/rules.d", f)
                )
    app_audit_dirs = [
        "/opt", "/usr/local", "/srv", "/var/www",
    ]
    audited_app_dirs = [
        d for d in app_audit_dirs if d in rules_text
    ]
    results.append(_v35_stig_result(
        f"{cat} - SRG-APP-000089 Application Audit",
        "Pass" if audited_app_dirs else "Info",
        f"STIG SRG-APP-000089 Application directory audit: "
        f"{audited_app_dirs or 'none'}",
        severity="Medium",
        details=f"Audited paths: {audited_app_dirs}",
        remediation=(
            "Add to /etc/audit/rules.d/41-stig-app.rules:\n"
            "  -w /opt/ -p wa -k application-changes\n"
            "  -w /usr/local/ -p wa -k application-changes\n"
            "  -w /srv/ -p wa -k application-changes"
        ),
        cross_references={
            "STIG": "SRG-APP-000089",
            "NIST": "AU-2",
        },
    ))


def _check_stig_v35_websrv_hardening(results, shared_data, os_info):
    """DISA Web Server STIG (nginx/Apache hardening)."""
    cat = "STIG v3.5 - SRG-APP-WEB"

    # Detect web server presence
    nginx_installed = _v35_command_available("nginx") or _v35_systemd_active(
        "nginx.service"
    ) == "active"
    apache_installed = _v35_command_available("apachectl") or any(
        _v35_systemd_active(s) == "active"
        for s in ("apache2.service", "httpd.service")
    )

    if not (nginx_installed or apache_installed):
        results.append(_v35_stig_result(
            f"{cat} - Web Server Status",
            "Info",
            "No web server detected (Web Server STIG inapplicable)",
            severity="Informational",
            details="Neither nginx nor Apache installed/active",
            cross_references={"STIG": "SRG-APP-WEB"},
        ))
        return

    # nginx hardening checks
    if nginx_installed:
        nginx_conf_paths = [
            "/etc/nginx/nginx.conf",
        ]
        if _v35_directory_exists("/etc/nginx/conf.d"):
            for f in _v35_list_directory("/etc/nginx/conf.d"):
                nginx_conf_paths.append(f"/etc/nginx/conf.d/{f}")
        nginx_full_conf = ""
        for p in nginx_conf_paths:
            if _v35_file_exists(p):
                nginx_full_conf += "\n" + _v35_read_file_safe(p)

        # SRG-APP-000033-WSR Server tokens off (don't expose version)
        server_tokens_off = "server_tokens off" in nginx_full_conf
        results.append(_v35_stig_result(
            f"{cat} - nginx server_tokens",
            "Pass" if server_tokens_off else "Warning",
            f"STIG SRG-APP-000266 nginx server_tokens off: {server_tokens_off}",
            severity="Medium",
            details=f"server_tokens off in config: {server_tokens_off}",
            remediation=(
                "In /etc/nginx/conf.d/security.conf:\n"
                "  server_tokens off;\n"
                "Then: nginx -t && systemctl reload nginx"
            ),
            cross_references={
                "STIG": "SRG-APP-000266-WSR",
                "NIST": "AC-3",
            },
        ))

        # SRG-APP-000516 - Strong TLS only
        tls_strong = (
            "TLSv1.2" in nginx_full_conf or "TLSv1.3" in nginx_full_conf
        ) and "TLSv1 " not in nginx_full_conf and "TLSv1.1" not in nginx_full_conf
        results.append(_v35_stig_result(
            f"{cat} - nginx TLS Version",
            "Pass" if tls_strong else "Warning",
            f"STIG SRG-APP-000516 nginx TLS strict: {tls_strong}",
            severity="High",
            details=f"TLSv1.2/1.3 only in config: {tls_strong}",
            remediation=(
                "In /etc/nginx/conf.d/ssl.conf:\n"
                "  ssl_protocols TLSv1.2 TLSv1.3;\n"
                "  ssl_ciphers HIGH:!aNULL:!MD5:!RC4:!3DES;"
            ),
            cross_references={
                "STIG": "SRG-APP-000516-WSR",
                "NIST": "SC-13", "FIPS": "140-3",
            },
        ))

        # SRG-APP-000358 - HSTS (Strict-Transport-Security)
        hsts_present = "Strict-Transport-Security" in nginx_full_conf
        results.append(_v35_stig_result(
            f"{cat} - nginx HSTS",
            "Pass" if hsts_present else "Warning",
            f"STIG SRG-APP-000358 nginx HSTS header: {hsts_present}",
            severity="Medium",
            details=f"HSTS present: {hsts_present}",
            remediation=(
                "In nginx server block:\n"
                "  add_header Strict-Transport-Security "
                "\"max-age=31536000; includeSubDomains; preload\" always;"
            ),
            cross_references={"STIG": "SRG-APP-000358"},
        ))

    # Apache hardening checks
    if apache_installed:
        apache_paths = [
            "/etc/apache2/apache2.conf",
            "/etc/apache2/conf-enabled/security.conf",
            "/etc/httpd/conf/httpd.conf",
            "/etc/httpd/conf.d/ssl.conf",
        ]
        apache_full_conf = ""
        for p in apache_paths:
            if _v35_file_exists(p):
                apache_full_conf += "\n" + _v35_read_file_safe(p)

        # ServerTokens Prod (minimal version disclosure)
        m = re.search(
            r"^\s*ServerTokens\s+(\w+)", apache_full_conf, re.MULTILINE,
        )
        server_tokens_secure = m and m.group(1).lower() in (
            "prod", "productonly",
        )
        results.append(_v35_stig_result(
            f"{cat} - Apache ServerTokens",
            "Pass" if server_tokens_secure else "Warning",
            f"STIG SRG-APP-000266 Apache ServerTokens: "
            f"{m.group(1) if m else 'default'}",
            severity="Medium",
            details=f"ServerTokens = {m.group(1) if m else 'unset (default Full)'}",
            remediation=(
                "In /etc/apache2/conf-available/security.conf or "
                "/etc/httpd/conf.d/security.conf:\n"
                "  ServerTokens Prod\n"
                "  ServerSignature Off"
            ),
            cross_references={
                "STIG": "SRG-APP-000266-WSR",
            },
        ))

        # SSLProtocol restrictive
        m = re.search(
            r"^\s*SSLProtocol\s+(.+)$", apache_full_conf, re.MULTILINE,
        )
        ssl_proto_strong = (
            m and "TLSv1.2" in m.group(1) and
            ("-TLSv1" in m.group(1) or "-all" in m.group(1).lower())
        )
        results.append(_v35_stig_result(
            f"{cat} - Apache SSLProtocol",
            "Pass" if ssl_proto_strong else "Warning",
            f"STIG SRG-APP-000516 Apache TLS strict: {ssl_proto_strong}",
            severity="High",
            details=f"SSLProtocol = {m.group(1) if m else 'unset'}",
            remediation=(
                "In /etc/apache2/mods-enabled/ssl.conf or "
                "/etc/httpd/conf.d/ssl.conf:\n"
                "  SSLProtocol -all +TLSv1.2 +TLSv1.3"
            ),
            cross_references={
                "STIG": "SRG-APP-000516-WSR",
                "NIST": "SC-13",
            },
        ))


def _check_stig_v35_database_srg(results, shared_data, os_info):
    """DISA Database STIG (PostgreSQL/MySQL hardening surrogates)."""
    cat = "STIG v3.5 - SRG-APP-DB"

    # Detect databases
    pg_active = _v35_systemd_active("postgresql.service") == "active" or any(
        _v35_systemd_active(f"postgresql@{ver}-main.service") == "active"
        for ver in ("12", "13", "14", "15", "16")
    )
    mysql_active = (
        _v35_systemd_active("mysql.service") == "active" or
        _v35_systemd_active("mariadb.service") == "active" or
        _v35_systemd_active("mysqld.service") == "active"
    )

    if not (pg_active or mysql_active):
        results.append(_v35_stig_result(
            f"{cat} - Database Status",
            "Info",
            "No database server detected (Database STIG inapplicable)",
            severity="Informational",
            details="Neither PostgreSQL nor MySQL/MariaDB active",
            cross_references={"STIG": "SRG-APP-DB"},
        ))
        return

    # PostgreSQL specific
    if pg_active:
        # SRG-APP-000148 - Database authentication
        pg_hba_paths = [
            "/etc/postgresql/12/main/pg_hba.conf",
            "/etc/postgresql/13/main/pg_hba.conf",
            "/etc/postgresql/14/main/pg_hba.conf",
            "/etc/postgresql/15/main/pg_hba.conf",
            "/etc/postgresql/16/main/pg_hba.conf",
            "/var/lib/pgsql/data/pg_hba.conf",
        ]
        pg_hba_content = ""
        for p in pg_hba_paths:
            if _v35_file_exists(p):
                pg_hba_content = _v35_read_file_safe(p)
                break

        if pg_hba_content:
            trust_lines = [
                line for line in pg_hba_content.splitlines()
                if line.strip() and not line.strip().startswith("#")
                and "trust" in line
            ]
            no_trust = not trust_lines
            results.append(_v35_stig_result(
                f"{cat} - PostgreSQL Auth Method",
                "Pass" if no_trust else "Fail",
                f"STIG SRG-APP-000148 PostgreSQL no 'trust' auth: {no_trust}",
                severity="Critical",
                details=f"trust auth lines: {len(trust_lines)}",
                remediation=(
                    "In pg_hba.conf, replace 'trust' with 'scram-sha-256' or "
                    "'md5':\n"
                    "  host all all 0.0.0.0/0 scram-sha-256\n"
                    "Then: systemctl reload postgresql\n"
                    "'trust' allows password-less authentication."
                ),
                cross_references={
                    "STIG": "SRG-APP-000148-DB-000103",
                    "NIST": "IA-2",
                },
            ))

    # MySQL/MariaDB specific
    if mysql_active:
        # SRG-APP-000142 - bind-address (not 0.0.0.0 unless intentional)
        mysql_conf_paths = [
            "/etc/mysql/my.cnf",
            "/etc/mysql/mysql.conf.d/mysqld.cnf",
            "/etc/mysql/mariadb.conf.d/50-server.cnf",
            "/etc/my.cnf",
        ]
        mysql_full_conf = ""
        for p in mysql_conf_paths:
            if _v35_file_exists(p):
                mysql_full_conf += "\n" + _v35_read_file_safe(p)
        # Also check mysql.conf.d if dir exists
        if _v35_directory_exists("/etc/mysql/conf.d"):
            for f in _v35_list_directory("/etc/mysql/conf.d"):
                mysql_full_conf += "\n" + _v35_read_file_safe(
                    f"/etc/mysql/conf.d/{f}"
                )

        bind_match = re.search(
            r"^\s*bind-address\s*=\s*(\S+)", mysql_full_conf, re.MULTILINE,
        )
        bind_addr = bind_match.group(1) if bind_match else "0.0.0.0"
        bind_secure = bind_addr in ("127.0.0.1", "::1", "localhost")
        results.append(_v35_stig_result(
            f"{cat} - MySQL bind-address",
            "Pass" if bind_secure else "Warning",
            f"STIG SRG-APP-000142 MySQL bind-address: {bind_addr}",
            severity="High",
            details=f"bind-address = {bind_addr}",
            remediation=(
                "Unless remote DB connections are required:\n"
                "In my.cnf or 50-server.cnf:\n"
                "  bind-address = 127.0.0.1\n"
                "Then: systemctl restart mysql"
            ),
            cross_references={
                "STIG": "SRG-APP-000142-DB-000094",
                "NIST": "SC-7",
            },
        ))

        # SRG-APP-000516 - TLS for replication / connections
        require_secure_transport = bool(
            re.search(
                r"^\s*require_secure_transport\s*=\s*(?:ON|on|1)",
                mysql_full_conf, re.MULTILINE,
            )
        )
        ssl_enabled = bool(
            re.search(r"^\s*ssl[-_]?ca\s*=", mysql_full_conf, re.MULTILINE)
        )
        results.append(_v35_stig_result(
            f"{cat} - MySQL TLS",
            "Pass" if require_secure_transport or ssl_enabled else "Info",
            f"STIG SRG-APP-000516 MySQL TLS: "
            f"require_secure_transport={require_secure_transport}, "
            f"ssl_ca={ssl_enabled}",
            severity="High",
            details=(
                f"require_secure_transport: {require_secure_transport}, "
                f"ssl_ca configured: {ssl_enabled}"
            ),
            remediation=(
                "In my.cnf:\n"
                "  require_secure_transport = ON\n"
                "  ssl_ca = /etc/mysql/ca.pem\n"
                "  ssl_cert = /etc/mysql/server-cert.pem\n"
                "  ssl_key = /etc/mysql/server-key.pem"
            ),
            cross_references={
                "STIG": "SRG-APP-000516-DB-000363",
                "NIST": "SC-13", "PCI-DSS": "4.2.1",
            },
        ))


def _check_stig_v35_container_srg_depth(results, shared_data, os_info):
    """DISA Container Platform SRG depth checks."""
    cat = "STIG v3.5 - SRG-APP-CTR"

    docker_present = _v35_command_available("docker") or _v35_systemd_active(
        "docker.service"
    ) == "active"
    podman_present = _v35_command_available("podman")

    if not (docker_present or podman_present):
        results.append(_v35_stig_result(
            f"{cat} - Container Status",
            "Info",
            "No container runtime (Container STIG inapplicable)",
            severity="Informational",
            details="Neither docker nor podman present",
            cross_references={"STIG": "SRG-APP-CTR"},
        ))
        return

    # SRG-APP-000118-CTR - Audit container daemon access
    if docker_present:
        rules_text = ""
        if _v35_directory_exists("/etc/audit/rules.d"):
            for f in _v35_list_directory("/etc/audit/rules.d"):
                if f.endswith(".rules"):
                    rules_text += "\n" + _v35_read_file_safe(
                        os.path.join("/etc/audit/rules.d", f)
                    )
        docker_audited = (
            "/var/lib/docker" in rules_text or
            "/usr/bin/docker" in rules_text or
            "docker.sock" in rules_text
        )
        results.append(_v35_stig_result(
            f"{cat} - Docker Audit",
            "Pass" if docker_audited else "Warning",
            f"STIG SRG-APP-000118-CTR Docker audit: {docker_audited}",
            severity="Medium",
            details=f"Docker paths in audit rules: {docker_audited}",
            remediation=(
                "Add to /etc/audit/rules.d/41-stig-docker.rules:\n"
                "  -w /var/lib/docker -p wa -k docker\n"
                "  -w /etc/docker -p wa -k docker\n"
                "  -w /usr/bin/docker -p x -k docker\n"
                "  -w /usr/lib/systemd/system/docker.service -p wa -k docker\n"
                "  -w /var/run/docker.sock -p rwxa -k docker"
            ),
            cross_references={
                "STIG": "SRG-APP-000118-CTR",
                "CIS": "1.1 (Docker Benchmark)",
            },
        ))

    # SRG-APP-000516-CTR - Container security posture
    rootless_capable = (
        podman_present or  # Podman is rootless by default
        _v35_directory_exists("/etc/subuid")
    )
    results.append(_v35_stig_result(
        f"{cat} - Rootless Container Capability",
        "Pass" if rootless_capable else "Info",
        f"STIG Container rootless capability: {rootless_capable}",
        severity="Medium",
        details=(
            f"podman: {podman_present}, "
            f"/etc/subuid present: {_v35_directory_exists('/etc/subuid')}"
        ),
        remediation=(
            "Prefer podman (rootless by default) over docker. For docker:\n"
            "  apt-get install -y uidmap\n"
            "  dockerd-rootless-setuptool.sh install"
        ),
        cross_references={
            "STIG": "SRG-APP-000516-CTR",
            "NIST": "AC-6",
        },
    ))

    # Image scanning capability
    image_scan_tools = {
        "trivy": _v35_command_available("trivy"),
        "grype": _v35_command_available("grype"),
        "syft (SBOM)": _v35_command_available("syft"),
        "docker scan": docker_present,
    }
    available = [k for k, v in image_scan_tools.items() if v]
    results.append(_v35_stig_result(
        f"{cat} - Image Scanning",
        "Pass" if available else "Warning",
        f"STIG Container image scanning tools: {len(available)}/4",
        severity="High",
        details=f"Available: {available}",
        remediation=(
            f"{remediation_for('trivy')}\n"
            "Run on each image build: trivy image <repo>:<tag>"
        ),
        cross_references={
            "STIG": "SRG-APP-000456-CTR, SRG-APP-000228-CTR",
            "NIST": "SI-2, RA-5",
        },
    ))


def _check_stig_v35_network_device_srg(results, shared_data, os_info):
    """DISA Network Device STIG (Linux network controls relevant)."""
    cat = "STIG v3.5 - SRG-NET"

    # SRG-NET-000131 - Default network deny
    rc, out, _ = _v35_run_command(["ufw", "status", "verbose"], timeout=5.0)
    ufw_default_deny = rc == 0 and (
        "Default: deny (incoming)" in out or
        "deny (incoming)" in out.lower()
    )
    rc, out, _ = _v35_run_command(["firewall-cmd", "--get-default-zone"], timeout=5.0)
    firewalld_strict = rc == 0 and out.strip() in ("drop", "block")
    rc, out, _ = _v35_run_command(["nft", "list", "ruleset"], timeout=5.0)
    nft_default_drop = rc == 0 and bool(re.search(
        r"hook\s+input\s+priority\s+\S+;\s*policy\s+drop;",
        out, re.MULTILINE,
    ))
    default_deny = ufw_default_deny or firewalld_strict or nft_default_drop
    results.append(_v35_stig_result(
        f"{cat} - SRG-NET-000131 Default Deny",
        "Pass" if default_deny else "Warning",
        f"STIG SRG-NET-000131 Default-deny network: {default_deny}",
        severity="High",
        details=(
            f"ufw deny: {ufw_default_deny}, firewalld drop: {firewalld_strict}, "
            f"nftables drop: {nft_default_drop}"
        ),
        cross_references={
            "STIG": "SRG-NET-000131", "NIST": "SC-7",
        },
    ))

    # SRG-NET-000074 - Anti-spoofing (rp_filter)
    rp_filter_default = _v35_read_sysctl("net.ipv4.conf.default.rp_filter")
    rp_filter_all = _v35_read_sysctl("net.ipv4.conf.all.rp_filter")
    rp_strict = (
        rp_filter_default in ("1", "2") and rp_filter_all in ("1", "2")
    )
    results.append(_v35_stig_result(
        f"{cat} - SRG-NET-000074 Anti-Spoofing",
        "Pass" if rp_strict else "Warning",
        f"STIG SRG-NET-000074 Reverse-path filtering enabled: {rp_strict}",
        severity="High",
        details=f"rp_filter default={rp_filter_default}, all={rp_filter_all}",
        remediation=(
            "In /etc/sysctl.d/99-stig-network.conf:\n"
            "  net.ipv4.conf.default.rp_filter = 1\n"
            "  net.ipv4.conf.all.rp_filter = 1\n"
            "Then: sysctl --system"
        ),
        cross_references={
            "STIG": "SRG-NET-000074, V-230539",
            "NIST": "SC-7",
        },
    ))

    # SRG-NET-000235 - Source-routed packet rejection
    accept_source_default = _v35_read_sysctl(
        "net.ipv4.conf.default.accept_source_route"
    )
    accept_source_all = _v35_read_sysctl(
        "net.ipv4.conf.all.accept_source_route"
    )
    src_route_blocked = (
        accept_source_default == "0" and accept_source_all == "0"
    )
    results.append(_v35_stig_result(
        f"{cat} - SRG-NET-000235 Source Route Blocked",
        "Pass" if src_route_blocked else "Warning",
        f"STIG SRG-NET-000235 Source-routed packet rejection: "
        f"{src_route_blocked}",
        severity="High",
        details=(
            f"accept_source_route default={accept_source_default}, "
            f"all={accept_source_all}"
        ),
        remediation=(
            "In /etc/sysctl.d/99-stig-network.conf:\n"
            "  net.ipv4.conf.default.accept_source_route = 0\n"
            "  net.ipv4.conf.all.accept_source_route = 0\n"
            "  net.ipv6.conf.default.accept_source_route = 0\n"
            "  net.ipv6.conf.all.accept_source_route = 0"
        ),
        cross_references={
            "STIG": "SRG-NET-000235, V-230541",
            "NIST": "SC-7",
        },
    ))


def _check_stig_v35_additional_v_numbers(results, shared_data, os_info):
    """Additional RHEL/Ubuntu V-numbers not yet covered."""
    cat = "STIG v3.5 - Additional V-numbers"

    # V-258134 (RHEL 9) - KexAlgorithms strict
    sshd = _v35_read_file_safe("/etc/ssh/sshd_config")
    sshd_d = ""
    if _v35_directory_exists("/etc/ssh/sshd_config.d"):
        for f in _v35_list_directory("/etc/ssh/sshd_config.d"):
            if f.endswith(".conf"):
                sshd_d += "\n" + _v35_read_file_safe(
                    os.path.join("/etc/ssh/sshd_config.d", f)
                )
    full_sshd = sshd + "\n" + sshd_d

    kex_match = re.search(
        r"^\s*KexAlgorithms\s+(\S+)", full_sshd, re.MULTILINE,
    )
    kex_strict = False
    if kex_match:
        kex = kex_match.group(1)
        forbidden = ["sha1", "diffie-hellman-group1", "group14-sha1"]
        kex_strict = not any(f in kex.lower() for f in forbidden)
    results.append(_v35_stig_result(
        f"{cat} - V-258134 SSH KEX",
        "Pass" if kex_strict else "Warning",
        f"STIG V-258134 (RHEL9) SSH KexAlgorithms FIPS-aligned: {kex_strict}",
        severity="High",
        details=f"KexAlgorithms = {kex_match.group(1) if kex_match else 'default'}",
        remediation=(
            "In /etc/ssh/sshd_config.d/50-stig.conf:\n"
            "  KexAlgorithms curve25519-sha256@libssh.org,curve25519-sha256,"
            "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
            "diffie-hellman-group16-sha512,diffie-hellman-group18-sha512"
        ),
        cross_references={
            "STIG": "V-258134, V-260533",
            "NIST": "SC-13", "FIPS": "186-5",
        },
    ))

    # V-258153 (RHEL 9) - Audit log files mode 0600 / 0640
    audit_log_path = "/var/log/audit/audit.log"
    audit_perms_ok = False
    audit_perms = "<missing>"
    if _v35_file_exists(audit_log_path):
        try:
            mode = os.stat(audit_log_path).st_mode & 0o7777
            audit_perms = oct(mode)
            audit_perms_ok = mode <= 0o0600
        except OSError:
            pass
    results.append(_v35_stig_result(
        f"{cat} - V-258153 Audit Log Mode",
        "Pass" if audit_perms_ok else "Warning",
        f"STIG V-258153 audit.log mode <= 0600: {audit_perms_ok}",
        severity="Critical",
        details=f"audit.log mode = {audit_perms}",
        remediation=(
            "chmod 0600 /var/log/audit/audit.log\n"
            "In /etc/audit/auditd.conf: log_file_mode = 0600\n"
            "systemctl restart auditd"
        ),
        cross_references={
            "STIG": "V-258153, V-230400",
            "NIST": "AU-9", "PCI-DSS": "10.3.1",
        },
    ))

    # V-258109 (RHEL 9) - System banner files exist
    issue_present = _v35_file_exists("/etc/issue")
    issue_net_present = _v35_file_exists("/etc/issue.net")
    motd_present = _v35_file_exists("/etc/motd")
    banner_layers = sum([issue_present, issue_net_present, motd_present])
    results.append(_v35_stig_result(
        f"{cat} - V-258109 System Banners",
        "Pass" if banner_layers >= 2 else "Warning",
        f"STIG V-258109 System banners: /etc/issue={issue_present}, "
        f"/etc/issue.net={issue_net_present}, /etc/motd={motd_present}",
        severity="Medium",
        details=f"Banner files present: {banner_layers}/3",
        remediation=(
            "Create DoD warning banners. Example /etc/issue:\n"
            "  You are accessing a U.S. Government (USG) Information System "
            "(IS) that is provided for USG-authorized use only..."
        ),
        cross_references={
            "STIG": "V-258109, V-230225",
            "NIST": "AC-8",
        },
    ))

    # V-258215 (Ubuntu 22.04) - apt repositories use HTTPS
    apt_sources = ""
    if _v35_file_exists("/etc/apt/sources.list"):
        apt_sources += _v35_read_file_safe("/etc/apt/sources.list")
    if _v35_directory_exists("/etc/apt/sources.list.d"):
        for f in _v35_list_directory("/etc/apt/sources.list.d"):
            if f.endswith(".list") or f.endswith(".sources"):
                apt_sources += "\n" + _v35_read_file_safe(
                    f"/etc/apt/sources.list.d/{f}"
                )
    if apt_sources:
        active_lines = [
            l for l in apt_sources.splitlines()
            if l.strip() and not l.strip().startswith("#")
            and ("deb " in l or "URIs:" in l)
        ]
        http_lines = [
            l for l in active_lines
            if " http://" in l or "URIs: http://" in l
        ]
        all_https = not http_lines
        if active_lines:
            results.append(_v35_stig_result(
                f"{cat} - apt HTTPS Repositories",
                "Pass" if all_https else "Info",
                f"STIG apt repositories all HTTPS: {all_https}",
                severity="Medium",
                details=f"HTTP repository lines: {len(http_lines)}",
                remediation=(
                    "Update sources.list to use https:// URIs:\n"
                    "  apt-get install -y apt-transport-https ca-certificates\n"
                    "  sed -i 's|http://|https://|g' /etc/apt/sources.list"
                ),
                cross_references={
                    "STIG": "V-260567 (Ubuntu)",
                    "NIST": "SC-8, SI-7", "PCI-DSS": "6.3",
                },
            ))


# Save reference to existing run_checks
_original_run_checks_stig_v35 = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the v3.5 expanded STIG module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_stig_v35(shared_data)

    os_info = shared_data.get("os_info") or shared_data.get("v3_os_info")
    if os_info is None:
        from shared_components import os_detection as _os_det
        os_info = _os_det.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        _check_stig_v35_appsrg_application_security(results, shared_data, os_info)
        _check_stig_v35_websrv_hardening(results, shared_data, os_info)
        _check_stig_v35_database_srg(results, shared_data, os_info)
        _check_stig_v35_container_srg_depth(results, shared_data, os_info)
        _check_stig_v35_network_device_srg(results, shared_data, os_info)
        _check_stig_v35_additional_v_numbers(results, shared_data, os_info)
    except Exception as exc:  # noqa: BLE001
        results.append(AuditResult(
            module=MODULE_NAME, category="STIG - Error",
            status="Error",
            message=f"STIG v3.5 expansion exception: {exc!r}",
            details=str(exc), severity="Medium",
        ))

    return results
if __name__ == "__main__":
    """
    Standalone testing capability for the STIG module
    """
    import datetime
    import platform
    
    print("="*80)
    print(f"STIG Module Standalone Test - v{MODULE_VERSION}")
    print("Comprehensive DISA STIG Compliance for Linux")
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
    print(f"\nControl Area Coverage:")
    category_counts = Counter(r.category for r in test_results)
    for category in sorted(category_counts.keys()):
        count = category_counts[category]
        print(f"  {category:50s}: {count:3d} checks")
    
    # Critical findings
    critical_failures = [r for r in test_results if "CAT I" in r.category and r.status == "Fail"]
    if critical_failures:
        print(f"\n  Category I (High) Failures ({len(critical_failures)}):")
        for failure in critical_failures[:10]:
            print(f"   {failure.message}")
        if len(critical_failures) > 10:
            print(f"  ... and {len(critical_failures) - 10} more")
    
    print(f"\n{'='*80}")
    print(f"STIG module comprehensive test complete")
    print(f"All {len(test_results)} checks executed successfully")
    print(f"{'='*80}\n")
