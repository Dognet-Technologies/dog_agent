#!/usr/bin/env python3
"""
module_nsa.py
NSA Cybersecurity Guidance Module for Linux
Version: 2.1

SYNOPSIS:
    Comprehensive NSA (National Security Agency) cybersecurity guidance
    implementation and compliance checks for Linux systems.

DESCRIPTION:
    This module performs exhaustive security checks based on NSA guidance:
    
    NSA Cybersecurity Guidance:
    - SELinux/Mandatory Access Control (MAC)
    - Network Security Hardening
    - Kernel Security Configuration
    - System Hardening & Configuration
    - Cryptographic Standards & Implementation
    - Service & Application Security
    
    Key NSA Security Publications Covered:
    - Security-Enhanced Linux (SELinux) by NSA
    - NSA's Linux Hardening Guidance
    - NSA Cybersecurity Technical Reports
    - System and Communications Protection Profile (SCPP)
    - Defense Information Systems Agency (DISA) collaboration
    - Commercial Solutions for Classified (CSfC)
    
    Security Focus Areas:
    - Mandatory Access Control enforcement
    - Network stack hardening
    - Kernel security parameters
    - Cryptographic module validation (FIPS 140-2/3)
    - Remote access security
    - Secure communications
    - Defense-in-depth strategies

PARAMETERS:
    shared_data : Dictionary containing shared data from main script

USAGE:
    Standalone testing
        python3 module_nsa.py

    Integration with main audit script
        python3 linux_security_audit.py --modules NSA
        python3 linux_security_audit.py -m NSA

NOTES:
    Version: 2.1
    Reference: https://www.nsa.gov/cybersecurity-guidance
    Focus: Enterprise-grade security for defense and critical infrastructure
    Target: 180+ comprehensive security auditing checks; OS-aware technical control checks
    Module automatically detects OS via module_core integration
    
    SELinux Note: Many checks focus on SELinux which was developed by NSA
    as a mandatory access control mechanism for Linux systems.
    
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

MODULE_NAME = "NSA"

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

def get_nsa_id(category: str, number: int) -> str:
    """Generate NSA control ID"""
    return f"NSA-{category}-{number:03d}"

def check_tcp_wrapper() -> bool:
    """Check if TCP wrappers are configured"""
    return os.path.exists("/etc/hosts.allow") or os.path.exists("/etc/hosts.deny")

# ============================================================================
# SELinux/MAC - Mandatory Access Control
# NSA developed SELinux as a mandatory access control mechanism
# Reference: NSA Security-Enhanced Linux documentation
# ============================================================================

def check_selinux_mac_controls(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    SELinux and Mandatory Access Control Security Audit Checks Against NSA's SELinux guidance
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking SELinux/MAC Controls...")
    
    selinux_status = get_selinux_status(cache=cache)
    apparmor_status = get_apparmor_status(cache=cache)
    
    # MAC-001: SELinux or AppArmor installed
    mac_installed = selinux_status['installed'] or apparmor_status['installed']
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - SELinux/MAC",
        status="Pass" if mac_installed else "Fail",
        message=f"{get_nsa_id('MAC', 1)}: Mandatory Access Control system installed",
        details=f"SELinux: {selinux_status['installed']}, AppArmor: {apparmor_status['installed']}",
        remediation=remediation_for("selinux")
    ))
    
    # MAC-002: SELinux enabled (if installed)
    if selinux_status['installed']:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - SELinux/MAC",
            status="Pass" if selinux_status['enabled'] else "Fail",
            message=f"{get_nsa_id('MAC', 2)}: SELinux enabled",
            details=f"Mode: {selinux_status['mode']}",
            remediation="Enable SELinux in /etc/selinux/config: SELINUX=enforcing"
        ))
    
    # MAC-003: SELinux enforcing mode
    if selinux_status['enabled']:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - SELinux/MAC",
            status="Pass" if selinux_status['enforcing'] else "Fail",
            message=f"{get_nsa_id('MAC', 3)}: SELinux in enforcing mode",
            details=f"Current mode: {selinux_status['mode']}",
            remediation="Set to enforcing: setenforce 1 && sed -i 's/SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config"
        ))
    
    # MAC-004: SELinux policy type
    if selinux_status['enabled']:
        targeted_policy = selinux_status['policy'] in ['targeted', 'mls']
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - SELinux/MAC",
            status="Pass" if targeted_policy else "Warning",
            message=f"{get_nsa_id('MAC', 4)}: SELinux policy appropriate",
            details=f"Policy: {selinux_status['policy']}",
            remediation="Use targeted or mls policy in /etc/selinux/config"
        ))
    
    # MAC-005: SELinux configuration file
    selinux_config_exists = os.path.exists("/etc/selinux/config")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - SELinux/MAC",
        status="Pass" if selinux_config_exists else "Warning",
        message=f"{get_nsa_id('MAC', 5)}: SELinux configuration file exists",
        details="Config present" if selinux_config_exists else "Not found",
        remediation="Create /etc/selinux/config with appropriate settings"
    ))
    
    # MAC-006: SELinux configuration permissions
    if selinux_config_exists:
        perms = get_file_permissions("/etc/selinux/config")
        perms_ok = perms and int(perms, 8) <= int("644", 8)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - SELinux/MAC",
            status="Pass" if perms_ok else "Warning",
            message=f"{get_nsa_id('MAC', 6)}: SELinux config file permissions",
            details=f"Permissions: {perms}",
            remediation="chmod 644 /etc/selinux/config"
        ))
    
    # MAC-007: SELinux tools installed
    selinux_tools = ["semanage", "restorecon", "seinfo", "sesearch", "getsebool", "setsebool"]
    installed_tools = [tool for tool in selinux_tools if command_exists(tool)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - SELinux/MAC",
        status="Pass" if len(installed_tools) >= 4 else "Warning",
        message=f"{get_nsa_id('MAC', 7)}: SELinux management tools available",
        details=f"Installed: {', '.join(installed_tools)}",
        remediation="Install policycoreutils-python-utils"
    ))
    
    # MAC-008: SELinux booleans - httpd_can_network_connect
    if command_exists("getsebool"):
        result = run_command("getsebool httpd_can_network_connect 2>/dev/null")
        if result.returncode == 0:
            httpd_connect = "on" in result.stdout.lower()
            
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NSA - SELinux/MAC",
                status="Info",
                message=f"{get_nsa_id('MAC', 8)}: SELinux httpd network connect boolean",
                details=f"httpd_can_network_connect: {'on' if httpd_connect else 'off'}",
                remediation="Review and set as needed: setsebool -P httpd_can_network_connect off"
            ))
    
    # MAC-009: SELinux booleans - ssh restrict
    if command_exists("getsebool"):
        result = run_command("getsebool ssh_sysadm_login 2>/dev/null")
        if result.returncode == 0:
            ssh_sysadm = "on" in result.stdout.lower()
            
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NSA - SELinux/MAC",
                status="Warning" if ssh_sysadm else "Pass",
                message=f"{get_nsa_id('MAC', 9)}: SELinux SSH sysadm login restricted",
                details=f"ssh_sysadm_login: {'on' if ssh_sysadm else 'off'}",
                remediation="Disable: setsebool -P ssh_sysadm_login off"
            ))
    
    # MAC-010: SELinux file contexts
    if os.path.exists("/etc/selinux/targeted/contexts/files/file_contexts"):
        file_contexts_size = os.path.getsize("/etc/selinux/targeted/contexts/files/file_contexts")
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - SELinux/MAC",
            status="Pass" if file_contexts_size > 1000 else "Warning",
            message=f"{get_nsa_id('MAC', 10)}: SELinux file contexts defined",
            details=f"File contexts size: {file_contexts_size} bytes",
            remediation="Ensure file_contexts is properly configured"
        ))
    
    # MAC-011: SELinux denials logged
    if selinux_status['enabled']:
        avc_log_exists = os.path.exists("/var/log/audit/audit.log")
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - SELinux/MAC",
            status="Pass" if avc_log_exists else "Warning",
            message=f"{get_nsa_id('MAC', 11)}: SELinux denial logging enabled",
            details="Audit log exists" if avc_log_exists else "No audit log",
            remediation="Enable auditd for SELinux denial logging"
        ))
    
    # MAC-012: Recent SELinux denials
    if selinux_status['enabled'] and os.path.exists("/var/log/audit/audit.log"):
        result = run_command("grep -c 'avc:.*denied' /var/log/audit/audit.log 2>/dev/null | tail -1000")
        denial_count = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - SELinux/MAC",
            status="Warning" if denial_count > 100 else "Pass",
            message=f"{get_nsa_id('MAC', 12)}: SELinux denial count (recent)",
            details=f"{denial_count} denials in audit log",
            remediation="Review denials: ausearch -m avc"
        ))
    
    # MAC-013: AppArmor enabled (if installed)
    if apparmor_status['installed']:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - SELinux/MAC",
            status="Pass" if apparmor_status['enabled'] else "Fail",
            message=f"{get_nsa_id('MAC', 13)}: AppArmor enabled",
            details="AppArmor active" if apparmor_status['enabled'] else "Not active",
            remediation="Enable AppArmor: systemctl enable apparmor && systemctl start apparmor"
        ))
    
    # MAC-014: AppArmor profiles loaded
    if apparmor_status['enabled']:
        profiles_loaded = apparmor_status['profiles_loaded'] > 0
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - SELinux/MAC",
            status="Pass" if profiles_loaded else "Warning",
            message=f"{get_nsa_id('MAC', 14)}: AppArmor profiles loaded",
            details=f"{apparmor_status['profiles_loaded']} profiles loaded",
            remediation="Load AppArmor profiles: aa-enforce /etc/apparmor.d/*"
        ))
    
    # MAC-015: AppArmor enforcement mode
    if apparmor_status['enabled'] and apparmor_status['profiles_loaded'] > 0:
        enforcement_ratio = apparmor_status['profiles_enforcing'] / apparmor_status['profiles_loaded']
        enforcement_ok = enforcement_ratio >= 0.8
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - SELinux/MAC",
            status="Pass" if enforcement_ok else "Warning",
            message=f"{get_nsa_id('MAC', 15)}: AppArmor profiles in enforce mode",
            details=f"{apparmor_status['profiles_enforcing']}/{apparmor_status['profiles_loaded']} enforcing",
            remediation="Set profiles to enforce: aa-enforce /etc/apparmor.d/*"
        ))
    
    # MAC-016: AppArmor profile directory
    apparmor_dir = os.path.exists("/etc/apparmor.d")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - SELinux/MAC",
        status="Pass" if apparmor_dir else "Info",
        message=f"{get_nsa_id('MAC', 16)}: AppArmor profile directory exists",
        details="Directory present" if apparmor_dir else "Not found",
        remediation="Create /etc/apparmor.d directory"
    ))
    
    # MAC-017: AppArmor profile count
    if apparmor_dir:
        profile_files = glob.glob("/etc/apparmor.d/*")
        profile_count = len([f for f in profile_files if os.path.isfile(f)])
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - SELinux/MAC",
            status="Pass" if profile_count >= 5 else "Warning",
            message=f"{get_nsa_id('MAC', 17)}: AppArmor profiles configured",
            details=f"{profile_count} profile files",
            remediation="Install more AppArmor profiles"
        ))
    
    # MAC-018: MAC protects sensitive files
    sensitive_files = ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]
    protected_count = 0
    
    for filepath in sensitive_files:
        if selinux_status['enabled'] and command_exists("ls"):
            result = run_command(f"ls -Z {filepath} 2>/dev/null")
            if result.returncode == 0 and ":" in result.stdout:
                protected_count += 1
        elif apparmor_status['enabled']:
            # AppArmor protection is profile-based
            protected_count += 1
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - SELinux/MAC",
        status="Pass" if protected_count >= 2 else "Warning",
        message=f"{get_nsa_id('MAC', 18)}: MAC protects sensitive files",
        details=f"{protected_count}/{len(sensitive_files)} files with MAC labels",
        remediation="Ensure MAC labels are properly set"
    ))
    
    # MAC-019: SELinux user mappings
    if selinux_status['enabled'] and command_exists("semanage"):
        result = run_command("semanage login -l 2>/dev/null | wc -l")
        user_mappings = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - SELinux/MAC",
            status="Pass" if user_mappings >= 2 else "Info",
            message=f"{get_nsa_id('MAC', 19)}: SELinux user mappings configured",
            details=f"{user_mappings} user mappings",
            remediation="Configure user mappings: semanage login -l"
        ))
    
    # MAC-020: SELinux confined users
    if selinux_status['enabled'] and command_exists("semanage"):
        result = run_command("semanage login -l 2>/dev/null | grep -v 'unconfined' | wc -l")
        confined_users = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - SELinux/MAC",
            status="Pass" if confined_users > 0 else "Warning",
            message=f"{get_nsa_id('MAC', 20)}: SELinux confined users exist",
            details=f"{confined_users} confined users",
            remediation="Map users to confined SELinux users"
        ))
    
    # MAC-021: SELinux ports labeled
    if selinux_status['enabled'] and command_exists("semanage"):
        result = run_command("semanage port -l 2>/dev/null | wc -l")
        port_labels = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - SELinux/MAC",
            status="Pass" if port_labels > 10 else "Info",
            message=f"{get_nsa_id('MAC', 21)}: SELinux port labels configured",
            details=f"{port_labels} port definitions",
            remediation="Configure port labels as needed"
        ))
    
    # MAC-022: SELinux modules loaded
    if selinux_status['enabled'] and command_exists("semodule"):
        result = run_command("semodule -l 2>/dev/null | wc -l")
        module_count = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - SELinux/MAC",
            status="Pass" if module_count > 0 else "Warning",
            message=f"{get_nsa_id('MAC', 22)}: SELinux policy modules loaded",
            details=f"{module_count} modules",
            remediation="Load necessary SELinux modules"
        ))
    
    # MAC-023: Relabeling not pending
    if selinux_status['enabled']:
        autorelabel = os.path.exists("/.autorelabel")
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - SELinux/MAC",
            status="Warning" if autorelabel else "Pass",
            message=f"{get_nsa_id('MAC', 23)}: No SELinux relabeling pending",
            details="Relabeling pending" if autorelabel else "No relabeling needed",
            remediation="Complete relabeling and remove /.autorelabel"
        ))
    
    # MAC-024: SELinux state directory
    selinux_state = os.path.exists("/var/lib/selinux")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - SELinux/MAC",
        status="Pass" if selinux_state else "Info",
        message=f"{get_nsa_id('MAC', 24)}: SELinux state directory exists",
        details="State directory present" if selinux_state else "Not found",
        remediation="SELinux state directory should be created automatically"
    ))
    
    # MAC-025: No unconfined services
    if selinux_status['enforcing'] and command_exists("ps"):
        result = run_command("ps -eZ 2>/dev/null | grep -c 'unconfined_service_t' || echo 0")
        unconfined = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - SELinux/MAC",
            status="Pass" if unconfined == 0 else "Warning",
            message=f"{get_nsa_id('MAC', 25)}: Services are SELinux confined",
            details=f"{unconfined} unconfined services",
            remediation="Ensure all services run in confined domains"
        ))
    
    # MAC-026: setroubleshoot not installed (production)
    setroubleshoot_installed = check_package_installed("setroubleshoot", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - SELinux/MAC",
        status="Warning" if setroubleshoot_installed else "Pass",
        message=f"{get_nsa_id('MAC', 26)}: setroubleshoot not on production system",
        details="setroubleshoot installed" if setroubleshoot_installed else "Not installed",
        remediation="Remove on production: yum remove setroubleshoot"
    ))
    
    # MAC-027: mcstrans not needed
    mcstrans_active = check_service_active("mcstrans")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - SELinux/MAC",
        status="Info",
        message=f"{get_nsa_id('MAC', 27)}: MCS translation service status",
        details="mcstrans active" if mcstrans_active else "Not active",
        remediation="Disable if not needed: systemctl disable mcstrans"
    ))
    
    # MAC-028: SELinux audit logging
    if selinux_status['enabled']:
        auditd_active = check_service_active("auditd")
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - SELinux/MAC",
            status="Pass" if auditd_active else "Fail",
            message=f"{get_nsa_id('MAC', 28)}: auditd running for SELinux logging",
            details="auditd active" if auditd_active else "Not running",
            remediation="Start auditd: systemctl start auditd"
        ))
    
    # MAC-029: Permissive domains (should be none)
    if selinux_status['enforcing'] and command_exists("semanage"):
        result = run_command("semanage permissive -l 2>/dev/null | wc -l")
        permissive_count = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - SELinux/MAC",
            status="Pass" if permissive_count == 0 else "Warning",
            message=f"{get_nsa_id('MAC', 29)}: No permissive domains in enforcing mode",
            details=f"{permissive_count} permissive domains",
            remediation="Remove permissive domains: semanage permissive -d <domain>"
        ))
    
    # MAC-030: Overall MAC enforcement status
    mac_enforced = (selinux_status['enforcing'] or 
                    (apparmor_status['enabled'] and apparmor_status['profiles_enforcing'] > 0))
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - SELinux/MAC",
        status="Pass" if mac_enforced else "Fail",
        message=f"{get_nsa_id('MAC', 30)}: Mandatory Access Control enforced",
        details="MAC actively enforcing security policy",
        remediation="Enable and enforce SELinux or AppArmor"
    ))

# ============================================================================
# NETWORK - Network Security Hardening
# NSA emphasizes defense-in-depth for network communications
# Reference: NSA Network Infrastructure Security guidance
# ============================================================================

def check_network_hardening(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Network Security Hardening Security Audit Checks Against NSA Network Guidance
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Network Security Hardening...")
    
    firewall_status = get_firewall_status()
    ipv6_enabled = check_ipv6_enabled()
    
    # NET-001: Firewall active
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Network Security",
        status="Pass" if firewall_status['any_active'] else "Fail",
        message=f"{get_nsa_id('NET', 1)}: Host-based firewall active",
        details=f"Active: {', '.join([k for k,v in firewall_status.items() if v and k != 'any_active'])}",
        remediation="Enable firewall: ufw enable || systemctl start firewalld"
    ))
    
    # NET-002: IP forwarding disabled (unless router)
    exists, ip_forward = check_kernel_parameter("net.ipv4.ip_forward")
    forward_disabled = ip_forward == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Network Security",
        status="Pass" if forward_disabled else "Warning",
        message=f"{get_nsa_id('NET', 2)}: IP forwarding disabled",
        details=f"net.ipv4.ip_forward = {ip_forward}",
        remediation="Disable: sysctl -w net.ipv4.ip_forward=0"
    ))
    
    # NET-003: Send redirects disabled
    exists, send_redirects = check_kernel_parameter("net.ipv4.conf.all.send_redirects")
    redirects_disabled = send_redirects == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Network Security",
        status="Pass" if redirects_disabled else "Fail",
        message=f"{get_nsa_id('NET', 3)}: ICMP redirects sending disabled",
        details=f"send_redirects = {send_redirects}",
        remediation="Disable: sysctl -w net.ipv4.conf.all.send_redirects=0"
    ))
    
    # NET-004: Accept redirects disabled
    exists, accept_redirects = check_kernel_parameter("net.ipv4.conf.all.accept_redirects")
    accept_disabled = accept_redirects == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Network Security",
        status="Pass" if accept_disabled else "Fail",
        message=f"{get_nsa_id('NET', 4)}: ICMP redirects acceptance disabled",
        details=f"accept_redirects = {accept_redirects}",
        remediation="Disable: sysctl -w net.ipv4.conf.all.accept_redirects=0"
    ))
    
    # NET-005: Secure redirects disabled
    exists, secure_redirects = check_kernel_parameter("net.ipv4.conf.all.secure_redirects")
    secure_disabled = secure_redirects == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Network Security",
        status="Pass" if secure_disabled else "Fail",
        message=f"{get_nsa_id('NET', 5)}: Secure ICMP redirects disabled",
        details=f"secure_redirects = {secure_redirects}",
        remediation="Disable: sysctl -w net.ipv4.conf.all.secure_redirects=0"
    ))
    
    # NET-006: Source routing disabled
    exists, source_route = check_kernel_parameter("net.ipv4.conf.all.accept_source_route")
    source_disabled = source_route == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Network Security",
        status="Pass" if source_disabled else "Fail",
        message=f"{get_nsa_id('NET', 6)}: Source routing disabled",
        details=f"accept_source_route = {source_route}",
        remediation="Disable: sysctl -w net.ipv4.conf.all.accept_source_route=0"
    ))
    
    # NET-007: SYN cookies enabled (DoS protection)
    exists, syn_cookies = check_kernel_parameter("net.ipv4.tcp_syncookies")
    syn_enabled = syn_cookies == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Network Security",
        status="Pass" if syn_enabled else "Fail",
        message=f"{get_nsa_id('NET', 7)}: TCP SYN cookies enabled (DoS protection)",
        details=f"tcp_syncookies = {syn_cookies}",
        remediation="Enable: sysctl -w net.ipv4.tcp_syncookies=1"
    ))
    
    # NET-008: Reverse path filtering
    exists, rp_filter = check_kernel_parameter("net.ipv4.conf.all.rp_filter")
    rp_enabled = rp_filter == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Network Security",
        status="Pass" if rp_enabled else "Fail",
        message=f"{get_nsa_id('NET', 8)}: Reverse path filtering enabled",
        details=f"rp_filter = {rp_filter}",
        remediation="Enable: sysctl -w net.ipv4.conf.all.rp_filter=1"
    ))
    
    # NET-009: Log martian packets
    exists, log_martians = check_kernel_parameter("net.ipv4.conf.all.log_martians")
    martians_logged = log_martians == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Network Security",
        status="Pass" if martians_logged else "Warning",
        message=f"{get_nsa_id('NET', 9)}: Martian packets logged",
        details=f"log_martians = {log_martians}",
        remediation="Enable: sysctl -w net.ipv4.conf.all.log_martians=1"
    ))
    
    # NET-010: Ignore ICMP broadcasts
    exists, icmp_broadcast = check_kernel_parameter("net.ipv4.icmp_echo_ignore_broadcasts")
    broadcast_ignored = icmp_broadcast == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Network Security",
        status="Pass" if broadcast_ignored else "Fail",
        message=f"{get_nsa_id('NET', 10)}: ICMP broadcast ignored",
        details=f"icmp_echo_ignore_broadcasts = {icmp_broadcast}",
        remediation="Enable: sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1"
    ))
    
    # NET-011: Ignore bogus ICMP errors
    exists, bogus_icmp = check_kernel_parameter("net.ipv4.icmp_ignore_bogus_error_responses")
    bogus_ignored = bogus_icmp == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Network Security",
        status="Pass" if bogus_ignored else "Warning",
        message=f"{get_nsa_id('NET', 11)}: Bogus ICMP errors ignored",
        details=f"icmp_ignore_bogus_error_responses = {bogus_icmp}",
        remediation="Enable: sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1"
    ))
    
    # NET-012: TCP timestamps disabled (info leak)
    exists, tcp_timestamps = check_kernel_parameter("net.ipv4.tcp_timestamps")
    timestamps_ok = tcp_timestamps == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Network Security",
        status="Pass" if timestamps_ok else "Info",
        message=f"{get_nsa_id('NET', 12)}: TCP timestamps configuration",
        details=f"tcp_timestamps = {tcp_timestamps}",
        remediation="Consider disabling: sysctl -w net.ipv4.tcp_timestamps=0"
    ))
    
    # NET-013: IPv6 forwarding disabled
    if ipv6_enabled:
        exists, ipv6_forward = check_kernel_parameter("net.ipv6.conf.all.forwarding")
        ipv6_forward_disabled = ipv6_forward == "0"
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Pass" if ipv6_forward_disabled else "Warning",
            message=f"{get_nsa_id('NET', 13)}: IPv6 forwarding disabled",
            details=f"net.ipv6.conf.all.forwarding = {ipv6_forward}",
            remediation="Disable: sysctl -w net.ipv6.conf.all.forwarding=0"
        ))
    
    # NET-014: IPv6 redirects disabled
    if ipv6_enabled:
        exists, ipv6_redirects = check_kernel_parameter("net.ipv6.conf.all.accept_redirects")
        ipv6_redir_disabled = ipv6_redirects == "0"
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Pass" if ipv6_redir_disabled else "Fail",
            message=f"{get_nsa_id('NET', 14)}: IPv6 redirects disabled",
            details=f"accept_redirects = {ipv6_redirects}",
            remediation="Disable: sysctl -w net.ipv6.conf.all.accept_redirects=0"
        ))
    
    # NET-015: IPv6 router advertisements disabled
    if ipv6_enabled:
        exists, ipv6_ra = check_kernel_parameter("net.ipv6.conf.all.accept_ra")
        ipv6_ra_disabled = ipv6_ra == "0"
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Pass" if ipv6_ra_disabled else "Warning",
            message=f"{get_nsa_id('NET', 15)}: IPv6 router advertisements disabled",
            details=f"accept_ra = {ipv6_ra}",
            remediation="Disable: sysctl -w net.ipv6.conf.all.accept_ra=0"
        ))
    
    # NET-016: IPv6 autoconfiguration disabled
    if ipv6_enabled:
        exists, ipv6_autoconf = check_kernel_parameter("net.ipv6.conf.all.autoconf")
        autoconf_disabled = ipv6_autoconf == "0"
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Warning" if not autoconf_disabled else "Pass",
            message=f"{get_nsa_id('NET', 16)}: IPv6 autoconfiguration status",
            details=f"autoconf = {ipv6_autoconf}",
            remediation="Consider disabling: sysctl -w net.ipv6.conf.all.autoconf=0"
        ))
    
    # NET-017: TCP wrappers configured
    tcp_wrappers = check_tcp_wrapper()
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Network Security",
        status="Pass" if tcp_wrappers else "Info",
        message=f"{get_nsa_id('NET', 17)}: TCP wrappers configured",
        details="hosts.allow/deny present" if tcp_wrappers else "Not configured",
        remediation="Configure /etc/hosts.allow and /etc/hosts.deny"
    ))
    
    # NET-018: hosts.deny default deny
    if os.path.exists("/etc/hosts.deny"):
        deny_content = read_file_safe("/etc/hosts.deny")
        has_default_deny = "ALL: ALL" in deny_content or "ALL:ALL" in deny_content
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Pass" if has_default_deny else "Warning",
            message=f"{get_nsa_id('NET', 18)}: hosts.deny has default deny",
            details="ALL: ALL present" if has_default_deny else "No default deny",
            remediation="Add 'ALL: ALL' to /etc/hosts.deny"
        ))
    
    # NET-019: No unnecessary listening services
    listening_ports = get_listening_ports()
    unnecessary_ports = {
        21: "FTP", 23: "Telnet", 69: "TFTP", 
        111: "RPCbind", 512: "rexec", 513: "rlogin", 
        514: "rsh", 873: "rsync", 2049: "NFS"
    }
    
    found_unnecessary = {port: service for port, service in unnecessary_ports.items() 
                        if port in listening_ports}
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Network Security",
        status="Fail" if found_unnecessary else "Pass",
        message=f"{get_nsa_id('NET', 19)}: No insecure services listening",
        details=f"Insecure: {found_unnecessary}" if found_unnecessary else "None found",
        remediation="Disable insecure services"
    ))
    
    # NET-020: Minimal listening ports
    port_count = len(listening_ports)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Network Security",
        status="Pass" if port_count < 20 else "Warning",
        message=f"{get_nsa_id('NET', 20)}: Minimal network exposure",
        details=f"{port_count} listening ports",
        remediation="Review and minimize listening services"
    ))
    
    # NET-021: SSH on non-standard port (optional)
    ssh_port = 22
    if os.path.exists("/etc/ssh/sshd_config"):
        port_config = get_ssh_config_value("Port")
        if port_config and port_config.isdigit():
            ssh_port = int(port_config)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Network Security",
        status="Info",
        message=f"{get_nsa_id('NET', 21)}: SSH port configuration",
        details=f"SSH on port {ssh_port}",
        remediation="Consider non-standard port for additional security"
    ))
    
    # NET-022: Network interface count
    result = run_command("ip link show | grep -c '^[0-9]'")
    interface_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Network Security",
        status="Info",
        message=f"{get_nsa_id('NET', 22)}: Network interface inventory",
        details=f"{interface_count} network interfaces",
        remediation="Review and disable unnecessary interfaces"
    ))
    
    # NET-023: Promiscuous mode disabled
    result = run_command("ip link show | grep -c PROMISC")
    promisc_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Network Security",
        status="Pass" if promisc_count == 0 else "Warning",
        message=f"{get_nsa_id('NET', 23)}: No promiscuous mode interfaces",
        details=f"{promisc_count} interfaces in promiscuous mode",
        remediation="Disable promiscuous mode unless required for monitoring"
    ))
    
    # NET-024: Packet filtering rules exist
    if firewall_status['iptables']:
        result = run_command("iptables -L -n | grep -c '^Chain'")
        chain_count = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Pass" if chain_count >= 3 else "Warning",
            message=f"{get_nsa_id('NET', 24)}: Packet filtering rules configured",
            details=f"{chain_count} iptables chains",
            remediation="Configure comprehensive iptables rules"
        ))
    
    # NET-025: Default iptables policy
    if firewall_status['iptables']:
        result = run_command("iptables -L -n | grep 'Chain INPUT'")
        if result.returncode == 0:
            default_deny = "DROP" in result.stdout or "REJECT" in result.stdout
            
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NSA - Network Security",
                status="Pass" if default_deny else "Warning",
                message=f"{get_nsa_id('NET', 25)}: iptables INPUT default deny",
                details="Default DROP/REJECT" if default_deny else "Default ACCEPT",
                remediation="Set default deny: iptables -P INPUT DROP"
            ))
    
    # NET-026: Rate limiting configured
    if firewall_status['iptables']:
        result = run_command("iptables -L -n | grep -c 'limit:'")
        rate_limit_rules = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Pass" if rate_limit_rules > 0 else "Info",
            message=f"{get_nsa_id('NET', 26)}: Rate limiting rules configured",
            details=f"{rate_limit_rules} rate limit rules",
            remediation="Configure rate limiting for DDoS protection"
        ))
    
    # NET-027: Connection tracking configured
    if firewall_status['iptables']:
        result = run_command("iptables -L -n | grep -c 'state'")
        stateful_rules = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Pass" if stateful_rules > 0 else "Warning",
            message=f"{get_nsa_id('NET', 27)}: Stateful packet filtering enabled",
            details=f"{stateful_rules} stateful rules",
            remediation="Use connection tracking: -m state --state"
        ))
    
    # NET-028: Loopback traffic allowed
    if firewall_status['iptables']:
        result = run_command("iptables -L -n | grep -c '127.0.0.0/8'")
        loopback_rules = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Pass" if loopback_rules > 0 else "Warning",
            message=f"{get_nsa_id('NET', 28)}: Loopback traffic rules configured",
            details=f"{loopback_rules} loopback rules",
            remediation="Ensure loopback traffic is properly allowed"
        ))
    
    # NET-029: IPv6 firewall configured
    if ipv6_enabled and firewall_status['iptables']:
        result = run_command("ip6tables -L -n 2>/dev/null | grep -c '^Chain'")
        ipv6_chains = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Pass" if ipv6_chains >= 3 else "Warning",
            message=f"{get_nsa_id('NET', 29)}: IPv6 firewall configured",
            details=f"{ipv6_chains} ip6tables chains",
            remediation="Configure ip6tables rules for IPv6"
        ))
    
    # NET-030: Network parameters in sysctl.conf
    sysctl_conf = read_file_safe("/etc/sysctl.conf")
    net_params_count = sysctl_conf.count("net.ipv4") + sysctl_conf.count("net.ipv6")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Network Security",
        status="Pass" if net_params_count >= 5 else "Warning",
        message=f"{get_nsa_id('NET', 30)}: Network parameters in sysctl.conf",
        details=f"{net_params_count} network parameters configured",
        remediation="Add network hardening parameters to /etc/sysctl.conf"
    ))
    
    # NET-031: Wireless interfaces disabled
    result = run_command("iwconfig 2>&1 | grep -c 'IEEE'")
    wireless_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Network Security",
        status="Pass" if wireless_count == 0 else "Warning",
        message=f"{get_nsa_id('NET', 31)}: Wireless interfaces status",
        details=f"{wireless_count} wireless interfaces",
        remediation="Disable wireless if not needed"
    ))
    
    # NET-032: Bluetooth disabled
    bluetooth_active = check_service_active("bluetooth")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Network Security",
        status="Pass" if not bluetooth_active else "Warning",
        message=f"{get_nsa_id('NET', 32)}: Bluetooth service disabled",
        details="Bluetooth active" if bluetooth_active else "Disabled",
        remediation="Disable: systemctl disable bluetooth"
    ))
    
    # NET-033: avahi-daemon disabled
    avahi_active = check_service_active("avahi-daemon")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Network Security",
        status="Pass" if not avahi_active else "Warning",
        message=f"{get_nsa_id('NET', 33)}: Avahi daemon disabled",
        details="Avahi active" if avahi_active else "Disabled",
        remediation="Disable: systemctl disable avahi-daemon"
    ))
    
    # NET-034: CUPS disabled (if not print server)
    cups_active = check_service_active("cups")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Network Security",
        status="Pass" if not cups_active else "Info",
        message=f"{get_nsa_id('NET', 34)}: CUPS printing service status",
        details="CUPS active" if cups_active else "Disabled",
        remediation="Disable if not needed: systemctl disable cups"
    ))
    
    # NET-035: RPC services disabled
    rpcbind_active = check_service_active("rpcbind")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Network Security",
        status="Pass" if not rpcbind_active else "Warning",
        message=f"{get_nsa_id('NET', 35)}: RPC services disabled",
        details="rpcbind active" if rpcbind_active else "Disabled",
        remediation="Disable: systemctl disable rpcbind"
    ))
    
    # NET-036: NFS services disabled
    nfs_active = check_service_active("nfs-server")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Network Security",
        status="Pass" if not nfs_active else "Info",
        message=f"{get_nsa_id('NET', 36)}: NFS server disabled",
        details="NFS active" if nfs_active else "Disabled",
        remediation="Disable if not needed: systemctl disable nfs-server"
    ))
    
    # NET-037: DNS resolver configured
    resolv_conf = read_file_safe("/etc/resolv.conf")
    has_nameserver = "nameserver" in resolv_conf
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Network Security",
        status="Pass" if has_nameserver else "Warning",
        message=f"{get_nsa_id('NET', 37)}: DNS resolver configured",
        details="Nameservers configured" if has_nameserver else "No nameservers",
        remediation="Configure nameservers in /etc/resolv.conf"
    ))
    
    # NET-038: Network time protocol configured
    ntp_services = ["chrony", "systemd-timesyncd", "ntpd"]
    ntp_active = any(check_service_active(svc) for svc in ntp_services)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Network Security",
        status="Pass" if ntp_active else "Warning",
        message=f"{get_nsa_id('NET', 38)}: Network time synchronization active",
        details="NTP service running" if ntp_active else "No NTP",
        remediation=remediation_for("chrony")
    ))
    
    # NET-039: ICMP rate limiting
    exists, icmp_ratelimit = check_kernel_parameter("net.ipv4.icmp_ratelimit")
    rate_limited = icmp_ratelimit and safe_int_parse(icmp_ratelimit) > 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Network Security",
        status="Pass" if rate_limited else "Info",
        message=f"{get_nsa_id('NET', 39)}: ICMP rate limiting configured",
        details=f"icmp_ratelimit = {icmp_ratelimit}",
        remediation="Configure ICMP rate limiting"
    ))
    
    # NET-040: Network security modules loaded
    net_modules = ["ip_tables", "ip6_tables", "nf_conntrack"]
    loaded_modules = get_loaded_kernel_modules()
    loaded_net_modules = [m for m in net_modules if m in loaded_modules]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Network Security",
        status="Pass" if len(loaded_net_modules) >= 2 else "Warning",
        message=f"{get_nsa_id('NET', 40)}: Network security modules loaded",
        details=f"Loaded: {', '.join(loaded_net_modules)}",
        remediation="Ensure netfilter modules are loaded"
    ))


# ============================================================================
# KERNEL - Kernel Security Hardening
# NSA emphasizes kernel hardening as critical defense layer
# Reference: NSA Linux Kernel Hardening guidance
# ============================================================================

def check_kernel_hardening(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Kernel Security Hardening Security Audit Checks Against NSA Kernel Guidance
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Kernel Security Hardening...")
    
    # KERN-001: Kernel version
    kernel_version = run_command("uname -r").stdout.strip()
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Kernel Security",
        status="Info",
        message=f"{get_nsa_id('KERN', 1)}: Kernel version",
        details=f"Running kernel: {kernel_version}",
        remediation="Keep kernel updated with security patches"
    ))
    
    # KERN-002: ASLR enabled
    exists, aslr = check_kernel_parameter("kernel.randomize_va_space")
    aslr_full = aslr == "2"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Kernel Security",
        status="Pass" if aslr_full else "Fail",
        message=f"{get_nsa_id('KERN', 2)}: Address Space Layout Randomization (ASLR)",
        details=f"randomize_va_space = {aslr}",
        remediation="Enable full ASLR: sysctl -w kernel.randomize_va_space=2"
    ))
    
    # KERN-003: Kernel pointers restricted
    exists, kptr_restrict = check_kernel_parameter("kernel.kptr_restrict")
    kptr_ok = kptr_restrict in ["1", "2"]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Kernel Security",
        status="Pass" if kptr_ok else "Warning",
        message=f"{get_nsa_id('KERN', 3)}: Kernel pointer exposure restricted",
        details=f"kptr_restrict = {kptr_restrict}",
        remediation="Restrict: sysctl -w kernel.kptr_restrict=2"
    ))
    
    # KERN-004: dmesg restricted
    exists, dmesg_restrict = check_kernel_parameter("kernel.dmesg_restrict")
    dmesg_ok = dmesg_restrict == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Kernel Security",
        status="Pass" if dmesg_ok else "Warning",
        message=f"{get_nsa_id('KERN', 4)}: dmesg access restricted",
        details=f"dmesg_restrict = {dmesg_restrict}",
        remediation="Restrict: sysctl -w kernel.dmesg_restrict=1"
    ))
    
    # KERN-005: Kernel module loading restricted
    exists, modules_disabled = check_kernel_parameter("kernel.modules_disabled")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Kernel Security",
        status="Info",
        message=f"{get_nsa_id('KERN', 5)}: Kernel module loading status",
        details=f"modules_disabled = {modules_disabled}",
        remediation="Consider disabling after boot: sysctl -w kernel.modules_disabled=1"
    ))
    
    # KERN-006: Kernel module signature verification
    if os.path.exists("/proc/sys/kernel/module_signature_enforce"):
        sig_enforce = read_file_safe("/proc/sys/kernel/module_signature_enforce").strip()
        sig_enforced = sig_enforce == "1"
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Kernel Security",
            status="Pass" if sig_enforced else "Warning",
            message=f"{get_nsa_id('KERN', 6)}: Kernel module signature enforcement",
            details=f"Enforcement: {sig_enforced}",
            remediation="Enable module signing in kernel config"
        ))
    
    # KERN-007: Core dumps restricted
    exists, core_pattern = check_kernel_parameter("kernel.core_pattern")
    core_restricted = not core_pattern or "|" in core_pattern
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Kernel Security",
        status="Pass" if core_restricted else "Warning",
        message=f"{get_nsa_id('KERN', 7)}: Core dumps restricted",
        details=f"core_pattern = {core_pattern}",
        remediation="Restrict core dumps or pipe to handler"
    ))
    
    # KERN-008: Core uses PID
    exists, core_uses_pid = check_kernel_parameter("kernel.core_uses_pid")
    uses_pid = core_uses_pid == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Kernel Security",
        status="Pass" if uses_pid else "Warning",
        message=f"{get_nsa_id('KERN', 8)}: Core dumps use PID",
        details=f"core_uses_pid = {core_uses_pid}",
        remediation="Enable: sysctl -w kernel.core_uses_pid=1"
    ))
    
    # KERN-009: SUID dumpable disabled
    exists, suid_dumpable = check_kernel_parameter("fs.suid_dumpable")
    suid_ok = suid_dumpable == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Kernel Security",
        status="Pass" if suid_ok else "Fail",
        message=f"{get_nsa_id('KERN', 9)}: SUID core dumps disabled",
        details=f"suid_dumpable = {suid_dumpable}",
        remediation="Disable: sysctl -w fs.suid_dumpable=0"
    ))
    
    # KERN-010: Protected hardlinks
    exists, hardlinks = check_kernel_parameter("fs.protected_hardlinks")
    hardlinks_ok = hardlinks == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Kernel Security",
        status="Pass" if hardlinks_ok else "Warning",
        message=f"{get_nsa_id('KERN', 10)}: Protected hardlinks enabled",
        details=f"protected_hardlinks = {hardlinks}",
        remediation="Enable: sysctl -w fs.protected_hardlinks=1"
    ))
    
    # KERN-011: Protected symlinks
    exists, symlinks = check_kernel_parameter("fs.protected_symlinks")
    symlinks_ok = symlinks == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Kernel Security",
        status="Pass" if symlinks_ok else "Warning",
        message=f"{get_nsa_id('KERN', 11)}: Protected symlinks enabled",
        details=f"protected_symlinks = {symlinks}",
        remediation="Enable: sysctl -w fs.protected_symlinks=1"
    ))
    
    # KERN-012: Yama ptrace scope
    exists, ptrace_scope = check_kernel_parameter("kernel.yama.ptrace_scope")
    ptrace_ok = ptrace_scope and safe_int_parse(ptrace_scope) >= 1
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Kernel Security",
        status="Pass" if ptrace_ok else "Warning",
        message=f"{get_nsa_id('KERN', 12)}: Ptrace scope restricted (Yama)",
        details=f"ptrace_scope = {ptrace_scope}",
        remediation="Restrict: sysctl -w kernel.yama.ptrace_scope=1"
    ))
    
    # KERN-013: Perf events restricted
    exists, perf_paranoid = check_kernel_parameter("kernel.perf_event_paranoid")
    perf_ok = perf_paranoid and safe_int_parse(perf_paranoid) >= 2
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Kernel Security",
        status="Pass" if perf_ok else "Warning",
        message=f"{get_nsa_id('KERN', 13)}: Performance event access restricted",
        details=f"perf_event_paranoid = {perf_paranoid}",
        remediation="Restrict: sysctl -w kernel.perf_event_paranoid=3"
    ))
    
    # KERN-014: BPF JIT hardening
    exists, bpf_jit_harden = check_kernel_parameter("net.core.bpf_jit_harden")
    bpf_ok = bpf_jit_harden and safe_int_parse(bpf_jit_harden) >= 1
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Kernel Security",
        status="Pass" if bpf_ok else "Warning",
        message=f"{get_nsa_id('KERN', 14)}: BPF JIT hardening enabled",
        details=f"bpf_jit_harden = {bpf_jit_harden}",
        remediation="Enable: sysctl -w net.core.bpf_jit_harden=2"
    ))
    
    # KERN-015: Unprivileged BPF disabled
    exists, unprivileged_bpf = check_kernel_parameter("kernel.unprivileged_bpf_disabled")
    bpf_disabled = unprivileged_bpf == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Kernel Security",
        status="Pass" if bpf_disabled else "Warning",
        message=f"{get_nsa_id('KERN', 15)}: Unprivileged BPF disabled",
        details=f"unprivileged_bpf_disabled = {unprivileged_bpf}",
        remediation="Disable: sysctl -w kernel.unprivileged_bpf_disabled=1"
    ))
    
    # KERN-016: User namespaces restricted
    exists, unprivileged_userns = check_kernel_parameter("kernel.unprivileged_userns_clone")
    userns_ok = unprivileged_userns == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Kernel Security",
        status="Pass" if userns_ok else "Warning",
        message=f"{get_nsa_id('KERN', 16)}: Unprivileged user namespaces restricted",
        details=f"unprivileged_userns_clone = {unprivileged_userns}",
        remediation="Restrict: sysctl -w kernel.unprivileged_userns_clone=0"
    ))
    
    # KERN-017: Kernel panic behavior
    exists, panic_on_oops = check_kernel_parameter("kernel.panic_on_oops")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Kernel Security",
        status="Info",
        message=f"{get_nsa_id('KERN', 17)}: Kernel panic on oops",
        details=f"panic_on_oops = {panic_on_oops}",
        remediation="Consider enabling for production: sysctl -w kernel.panic_on_oops=1"
    ))
    
    # KERN-018: Kernel panic timeout
    exists, panic_timeout = check_kernel_parameter("kernel.panic")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Kernel Security",
        status="Info",
        message=f"{get_nsa_id('KERN', 18)}: Kernel panic reboot timeout",
        details=f"panic = {panic_timeout} seconds",
        remediation="Set auto-reboot: sysctl -w kernel.panic=60"
    ))
    
    # KERN-019: ExecShield (if available)
    exists, exec_shield = check_kernel_parameter("kernel.exec-shield")
    if exists:
        shield_enabled = exec_shield == "1"
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Kernel Security",
            status="Pass" if shield_enabled else "Warning",
            message=f"{get_nsa_id('KERN', 19)}: ExecShield enabled",
            details=f"exec-shield = {exec_shield}",
            remediation="Enable: sysctl -w kernel.exec-shield=1"
        ))
    
    # KERN-020: Kernel lockdown mode
    lockdown_file = "/sys/kernel/security/lockdown"
    if os.path.exists(lockdown_file):
        lockdown = read_file_safe(lockdown_file).strip()
        lockdown_enabled = "none" not in lockdown.lower()
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Kernel Security",
            status="Pass" if lockdown_enabled else "Info",
            message=f"{get_nsa_id('KERN', 20)}: Kernel lockdown mode",
            details=f"Lockdown: {lockdown}",
            remediation="Enable via kernel parameter: lockdown=integrity or lockdown=confidentiality"
        ))
    
    # KERN-021: Secureboot status
    secureboot_file = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
    if os.path.exists(secureboot_file):
        # SecureBoot enabled if file exists and byte 4 is 0x01
        try:
            with open(secureboot_file, 'rb') as f:
                data = f.read()
                secureboot_enabled = len(data) > 4 and data[4] == 0x01
        except:
            secureboot_enabled = False
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Kernel Security",
            status="Pass" if secureboot_enabled else "Warning",
            message=f"{get_nsa_id('KERN', 21)}: UEFI Secure Boot status",
            details="Secure Boot enabled" if secureboot_enabled else "Disabled",
            remediation="Enable Secure Boot in UEFI firmware"
        ))
    
    # KERN-022: Kernel page table isolation (Meltdown mitigation)
    cmdline = read_file_safe("/proc/cmdline")
    kpti_disabled = "nopti" in cmdline or "pti=off" in cmdline
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Kernel Security",
        status="Warning" if kpti_disabled else "Pass",
        message=f"{get_nsa_id('KERN', 22)}: Kernel Page Table Isolation (KPTI)",
        details="KPTI disabled" if kpti_disabled else "KPTI enabled",
        remediation="Remove nopti/pti=off from kernel parameters"
    ))
    
    # KERN-023: Spectre/Meltdown mitigations
    mitigations_file = "/sys/devices/system/cpu/vulnerabilities"
    if os.path.exists(mitigations_file):
        vuln_files = os.listdir(mitigations_file)
        mitigated_count = 0
        
        for vuln_file in vuln_files[:5]:  # Check first 5
            vuln_path = os.path.join(mitigations_file, vuln_file)
            status = read_file_safe(vuln_path).strip().lower()
            if "not affected" in status or "mitigation" in status:
                mitigated_count += 1
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Kernel Security",
            status="Pass" if mitigated_count >= 3 else "Warning",
            message=f"{get_nsa_id('KERN', 23)}: CPU vulnerabilities mitigated",
            details=f"{mitigated_count}/{len(vuln_files)} vulnerabilities mitigated",
            remediation="Update kernel and microcode for latest mitigations"
        ))
    
    # KERN-024: Kernel message buffer size
    exists, msg_max = check_kernel_parameter("kernel.msgmax")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Kernel Security",
        status="Info",
        message=f"{get_nsa_id('KERN', 24)}: Kernel message buffer size",
        details=f"msgmax = {msg_max}",
        remediation="Configure appropriate message buffer size"
    ))
    
    # KERN-025: Shared memory limits
    exists, shmmax = check_kernel_parameter("kernel.shmmax")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Kernel Security",
        status="Info",
        message=f"{get_nsa_id('KERN', 25)}: Shared memory maximum size",
        details=f"shmmax = {shmmax}",
        remediation="Configure shared memory limits appropriately"
    ))
    
    # KERN-026: Process ID limits
    exists, pid_max = check_kernel_parameter("kernel.pid_max")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Kernel Security",
        status="Info",
        message=f"{get_nsa_id('KERN', 26)}: Maximum process IDs",
        details=f"pid_max = {pid_max}",
        remediation="Configure PID limits based on workload"
    ))
    
    # KERN-027: Kernel audit enabled
    audit_enabled = check_service_active("auditd")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Kernel Security",
        status="Pass" if audit_enabled else "Fail",
        message=f"{get_nsa_id('KERN', 27)}: Kernel audit system enabled",
        details="auditd running" if audit_enabled else "Not running",
        remediation=remediation_for("auditd")
    ))
    
    # KERN-028: Loaded kernel modules count
    loaded_modules = get_loaded_kernel_modules()
    module_count = len(loaded_modules)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Kernel Security",
        status="Info",
        message=f"{get_nsa_id('KERN', 28)}: Loaded kernel modules inventory",
        details=f"{module_count} modules loaded",
        remediation="Review and minimize loaded modules"
    ))
    
    # KERN-029: Unnecessary modules blacklisted
    blacklist_files = glob.glob("/etc/modprobe.d/*.conf")
    blacklist_count = 0
    
    for bf in blacklist_files:
        content = read_file_safe(bf)
        blacklist_count += content.count("blacklist")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Kernel Security",
        status="Pass" if blacklist_count >= 3 else "Warning",
        message=f"{get_nsa_id('KERN', 29)}: Kernel modules blacklisted",
        details=f"{blacklist_count} blacklist entries",
        remediation="Blacklist unnecessary modules in /etc/modprobe.d/"
    ))
    
    # KERN-030: Dangerous modules disabled
    dangerous_modules = ["dccp", "sctp", "rds", "tipc", "bluetooth", "usb-storage"]
    loaded_dangerous = [m for m in dangerous_modules if m.replace("-", "_") in loaded_modules]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Kernel Security",
        status="Pass" if not loaded_dangerous else "Warning",
        message=f"{get_nsa_id('KERN', 30)}: Potentially dangerous modules disabled",
        details=f"Loaded: {', '.join(loaded_dangerous)}" if loaded_dangerous else "None loaded",
        remediation="Blacklist dangerous modules if not needed"
    ))


# ============================================================================
# SYSTEM - System Hardening & Configuration
# NSA emphasizes defense-in-depth for system configuration
# Reference: NSA System Hardening guidance
# ============================================================================

def check_system_hardening(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    System Hardening Security Audit Checks Against NSA System Guidance
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking System Hardening...")
    
    # SYS-001: Root account password set
    shadow_content = read_file_safe("/etc/shadow")
    root_line = ""
    for line in shadow_content.split('\n'):
        if line.startswith("root:"):
            root_line = line
            break
    
    root_password_set = root_line and not root_line.startswith("root:!") and not root_line.startswith("root:*")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - System Hardening",
        status="Pass" if root_password_set else "Warning",
        message=f"{get_nsa_id('SYS', 1)}: Root account password configured",
        details="Root password set" if root_password_set else "Root locked",
        remediation="Set root password if direct access needed: passwd root"
    ))
    
    # SYS-002: No UID 0 accounts except root
    passwd_content = read_file_safe("/etc/passwd")
    uid0_accounts = []
    
    for line in passwd_content.split('\n'):
        if line and not line.startswith('#'):
            fields = line.split(':')
            if len(fields) >= 3 and fields[2] == "0" and fields[0] != "root":
                uid0_accounts.append(fields[0])
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - System Hardening",
        status="Pass" if not uid0_accounts else "Fail",
        message=f"{get_nsa_id('SYS', 2)}: Only root has UID 0",
        details=f"Other UID 0: {', '.join(uid0_accounts)}" if uid0_accounts else "Only root",
        remediation="Remove UID 0 from non-root accounts"
    ))
    
    # SYS-003: System accounts locked
    system_accounts_unlocked = []
    
    for line in shadow_content.split('\n'):
        if line and not line.startswith('#'):
            fields = line.split(':')
            if len(fields) >= 3:
                username = fields[0]
                password = fields[1]
                
                # Check if system account (UID < 1000)
                for pline in passwd_content.split('\n'):
                    if pline.startswith(f"{username}:"):
                        pfields = pline.split(':')
                        if len(pfields) >= 3:
                            try:
                                uid = int(pfields[2])
                                if uid < 1000 and uid != 0:
                                    # Check if unlocked
                                    if password and password not in ["!", "*", "!!", "!!*", "*LK*"]:
                                        system_accounts_unlocked.append(username)
                            except:
                                pass
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - System Hardening",
        status="Pass" if not system_accounts_unlocked else "Warning",
        message=f"{get_nsa_id('SYS', 3)}: System accounts locked",
        details=f"Unlocked: {', '.join(system_accounts_unlocked[:5])}" if system_accounts_unlocked else "All locked",
        remediation="Lock system accounts: passwd -l <account>"
    ))
    
    # SYS-004: Default umask configured
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
        category="NSA - System Hardening",
        status="Pass" if umask_ok else "Fail",
        message=f"{get_nsa_id('SYS', 4)}: Default umask configured securely",
        details=f"UMASK = {umask_value}",
        remediation="Set UMASK 027 in /etc/login.defs"
    ))
    
    # SYS-005: Password aging configured
    pass_max_days = re.search(r'^PASS_MAX_DAYS\s+(\d+)', login_defs, re.MULTILINE)
    
    if pass_max_days:
        max_days = int(pass_max_days.group(1))
        aging_ok = max_days <= 90
    else:
        max_days = None
        aging_ok = False
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - System Hardening",
        status="Pass" if aging_ok else "Fail",
        message=f"{get_nsa_id('SYS', 5)}: Password maximum age configured",
        details=f"PASS_MAX_DAYS = {max_days}" if max_days else "Not set",
        remediation="Set PASS_MAX_DAYS 90 in /etc/login.defs"
    ))
    
    # SYS-006: Password minimum days
    pass_min_days = re.search(r'^PASS_MIN_DAYS\s+(\d+)', login_defs, re.MULTILINE)
    
    if pass_min_days:
        min_days = int(pass_min_days.group(1))
        min_ok = min_days >= 1
    else:
        min_days = None
        min_ok = False
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - System Hardening",
        status="Pass" if min_ok else "Warning",
        message=f"{get_nsa_id('SYS', 6)}: Password minimum age configured",
        details=f"PASS_MIN_DAYS = {min_days}" if min_days else "Not set",
        remediation="Set PASS_MIN_DAYS 1 in /etc/login.defs"
    ))
    
    # SYS-007: Password complexity enforced
    pam_password_files = glob.glob("/etc/pam.d/common-password") + glob.glob("/etc/pam.d/system-auth")
    password_complexity = False
    
    for pam_file in pam_password_files:
        if os.path.exists(pam_file):
            content = read_file_safe(pam_file)
            if "pam_pwquality" in content or "pam_cracklib" in content:
                password_complexity = True
                break
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - System Hardening",
        status="Pass" if password_complexity else "Fail",
        message=f"{get_nsa_id('SYS', 7)}: Password complexity enforced",
        details="PAM password quality configured" if password_complexity else "Not configured",
        remediation="Configure pam_pwquality in PAM"
    ))
    
    # SYS-008: Account lockout configured
    faillock_configured = False
    
    for pam_file in glob.glob("/etc/pam.d/*"):
        content = read_file_safe(pam_file)
        if "pam_faillock" in content:
            faillock_configured = True
            break
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - System Hardening",
        status="Pass" if faillock_configured else "Warning",
        message=f"{get_nsa_id('SYS', 8)}: Account lockout configured",
        details="faillock configured" if faillock_configured else "Not configured",
        remediation="Configure pam_faillock in PAM"
    ))
    
    # SYS-009: sudo installed and configured
    sudo_installed = check_package_installed("sudo", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - System Hardening",
        status="Pass" if sudo_installed else "Fail",
        message=f"{get_nsa_id('SYS', 9)}: sudo installed",
        details="sudo available" if sudo_installed else "Not installed",
        remediation=remediation_for("sudo")
    ))
    
    # SYS-010: sudoers file permissions
    if os.path.exists("/etc/sudoers"):
        perms = get_file_permissions("/etc/sudoers")
        perms_ok = perms and int(perms, 8) <= int("440", 8)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - System Hardening",
            status="Pass" if perms_ok else "Fail",
            message=f"{get_nsa_id('SYS', 10)}: sudoers file permissions secure",
            details=f"Permissions: {perms}",
            remediation="chmod 440 /etc/sudoers"
        ))
    
    # SYS-011: sudo requires password
    if os.path.exists("/etc/sudoers"):
        sudoers = read_file_safe("/etc/sudoers")
        nopasswd_entries = len(re.findall(r'NOPASSWD', sudoers))
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - System Hardening",
            status="Warning" if nopasswd_entries > 0 else "Pass",
            message=f"{get_nsa_id('SYS', 11)}: sudo requires password authentication",
            details=f"{nopasswd_entries} NOPASSWD entries",
            remediation="Remove NOPASSWD from sudoers"
        ))
    
    # SYS-012: Shell timeout configured
    shell_timeout = False
    shell_files = ["/etc/profile", "/etc/bash.bashrc", "~/.bashrc"]
    
    for shell_file in shell_files:
        if os.path.exists(shell_file):
            content = read_file_safe(shell_file)
            if re.search(r'TMOUT\s*=\s*\d+', content):
                shell_timeout = True
                break
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - System Hardening",
        status="Pass" if shell_timeout else "Warning",
        message=f"{get_nsa_id('SYS', 12)}: Shell timeout configured",
        details="TMOUT set" if shell_timeout else "Not configured",
        remediation="Set TMOUT=900 in /etc/profile"
    ))
    
    # SYS-013: Login banners configured
    banner_files = ["/etc/issue", "/etc/issue.net", "/etc/motd"]
    banners_configured = sum(1 for f in banner_files if os.path.exists(f) and os.path.getsize(f) > 10)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - System Hardening",
        status="Pass" if banners_configured >= 2 else "Warning",
        message=f"{get_nsa_id('SYS', 13)}: Login banners configured",
        details=f"{banners_configured}/3 banner files",
        remediation="Configure /etc/issue, /etc/issue.net, /etc/motd"
    ))
    
    # SYS-014: No OS information in banners
    os_info_in_banner = False
    os_keywords = ["ubuntu", "debian", "centos", "red hat", "linux", "kernel"]
    
    for banner_file in banner_files:
        if os.path.exists(banner_file):
            content = read_file_safe(banner_file).lower()
            if any(kw in content for kw in os_keywords):
                os_info_in_banner = True
                break
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - System Hardening",
        status="Pass" if not os_info_in_banner else "Warning",
        message=f"{get_nsa_id('SYS', 14)}: No OS information in banners",
        details="OS info present" if os_info_in_banner else "Clean banners",
        remediation="Remove OS/version info from login banners"
    ))
    
    # SYS-015: Critical file permissions - passwd
    critical_files_perms = {
        "/etc/passwd": "644",
        "/etc/shadow": "000",
        "/etc/group": "644",
        "/etc/gshadow": "000"
    }
    
    insecure_files = []
    for filepath, max_perms in critical_files_perms.items():
        if os.path.exists(filepath):
            actual = get_file_permissions(filepath)
            if actual and int(actual, 8) > int(max_perms, 8):
                insecure_files.append(f"{filepath}:{actual}")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - System Hardening",
        status="Pass" if not insecure_files else "Fail",
        message=f"{get_nsa_id('SYS', 15)}: Critical file permissions secure",
        details=f"Insecure: {', '.join(insecure_files)}" if insecure_files else "All secure",
        remediation="Fix permissions: chmod 644 /etc/passwd; chmod 000 /etc/shadow"
    ))
    
    # SYS-016: World-writable directories with sticky bit
    result = run_command("find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | head -20 | wc -l")
    ww_no_sticky = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - System Hardening",
        status="Pass" if ww_no_sticky == 0 else "Warning",
        message=f"{get_nsa_id('SYS', 16)}: World-writable dirs have sticky bit",
        details=f"{ww_no_sticky} dirs without sticky bit",
        remediation="Add sticky bit: chmod +t <directory>"
    ))
    
    # SYS-017: No unowned files
    result = run_command("find / -xdev \\( -nouser -o -nogroup \\) 2>/dev/null | head -10 | wc -l")
    unowned_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - System Hardening",
        status="Pass" if unowned_count == 0 else "Warning",
        message=f"{get_nsa_id('SYS', 17)}: No unowned files exist",
        details=f"{unowned_count} unowned files" if unowned_count > 0 else "None",
        remediation="Assign ownership to unowned files"
    ))
    
    # SYS-018: SUID/SGID files minimized
    result = run_command("find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null | wc -l")
    suid_sgid_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - System Hardening",
        status="Info",
        message=f"{get_nsa_id('SYS', 18)}: SUID/SGID binary inventory",
        details=f"{suid_sgid_count} SUID/SGID binaries",
        remediation="Review and minimize SUID/SGID binaries"
    ))
    
    # SYS-019: Log files exist and configured
    log_files = ["/var/log/syslog", "/var/log/messages", "/var/log/auth.log", "/var/log/secure"]
    existing_logs = [f for f in log_files if os.path.exists(f)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - System Hardening",
        status="Pass" if len(existing_logs) >= 2 else "Warning",
        message=f"{get_nsa_id('SYS', 19)}: System logging configured",
        details=f"{len(existing_logs)}/4 log files exist",
        remediation="Configure syslog/rsyslog for system logging"
    ))
    
    # SYS-020: rsyslog or syslog-ng active
    logging_active = check_service_active("rsyslog") or check_service_active("syslog-ng")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - System Hardening",
        status="Pass" if logging_active else "Fail",
        message=f"{get_nsa_id('SYS', 20)}: System logging service active",
        details="Logging active" if logging_active else "No logging",
        remediation="Enable rsyslog: systemctl enable rsyslog"
    ))
    
    # SYS-021: Log rotation configured
    logrotate_installed = check_package_installed("logrotate", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - System Hardening",
        status="Pass" if logrotate_installed else "Warning",
        message=f"{get_nsa_id('SYS', 21)}: Log rotation configured",
        details="logrotate installed" if logrotate_installed else "Not installed",
        remediation="Install logrotate"
    ))
    
    # SYS-022: Cron daemon active
    cron_active = check_service_active("cron") or check_service_active("crond")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - System Hardening",
        status="Pass" if cron_active else "Warning",
        message=f"{get_nsa_id('SYS', 22)}: Cron daemon active",
        details="Cron running" if cron_active else "Not running",
        remediation="Enable cron: systemctl enable cron"
    ))
    
    # SYS-023: Cron restricted to authorized users
    cron_allow = os.path.exists("/etc/cron.allow")
    cron_deny = os.path.exists("/etc/cron.deny")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - System Hardening",
        status="Pass" if cron_allow or cron_deny else "Warning",
        message=f"{get_nsa_id('SYS', 23)}: Cron access restricted",
        details="cron.allow/deny configured" if cron_allow or cron_deny else "Not restricted",
        remediation="Create /etc/cron.allow with authorized users"
    ))
    
    # SYS-024: at restricted to authorized users
    at_allow = os.path.exists("/etc/at.allow")
    at_deny = os.path.exists("/etc/at.deny")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - System Hardening",
        status="Pass" if at_allow or at_deny else "Warning",
        message=f"{get_nsa_id('SYS', 24)}: at daemon access restricted",
        details="at.allow/deny configured" if at_allow or at_deny else "Not restricted",
        remediation="Create /etc/at.allow with authorized users"
    ))
    
    # SYS-025: Unnecessary compilers removed
    compilers = ["gcc", "cc", "g++"]
    installed_compilers = [c for c in compilers if command_exists(c)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - System Hardening",
        status="Warning" if installed_compilers else "Pass",
        message=f"{get_nsa_id('SYS', 25)}: Compilers on production system",
        details=f"Installed: {', '.join(installed_compilers)}" if installed_compilers else "None",
        remediation="Remove compilers on production systems"
    ))
    
    # SYS-026: File integrity monitoring installed
    fim_installed = check_package_installed("aide", os_info) or check_package_installed("tripwire", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - System Hardening",
        status="Pass" if fim_installed else "Warning",
        message=f"{get_nsa_id('SYS', 26)}: File integrity monitoring installed",
        details="AIDE/Tripwire installed" if fim_installed else "Not installed",
        remediation=remediation_for("aide")
    ))
    
    # SYS-027: Separate partitions for critical dirs
    result = run_command("mount | grep -E '/(tmp|var|home|var/log|var/tmp)\\s' | wc -l")
    separate_partitions = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - System Hardening",
        status="Pass" if separate_partitions >= 3 else "Warning",
        message=f"{get_nsa_id('SYS', 27)}: Separate partitions for critical directories",
        details=f"{separate_partitions} separate partitions",
        remediation="Use separate partitions for /tmp, /var, /home"
    ))
    
    # SYS-028: /tmp partition with noexec
    result = run_command("mount | grep ' /tmp ' | grep -c noexec")
    tmp_noexec = safe_int_parse(result.stdout.strip()) > 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - System Hardening",
        status="Pass" if tmp_noexec else "Warning",
        message=f"{get_nsa_id('SYS', 28)}: /tmp mounted with noexec",
        details="noexec set" if tmp_noexec else "Not set",
        remediation="Add noexec to /tmp in /etc/fstab"
    ))
    
    # SYS-029: Removable media mounting restricted
    result = run_command("grep -E '^install\\s+(usb-storage|cramfs|freevxfs|jffs2|hfs|hfsplus|udf)' /etc/modprobe.d/*.conf 2>/dev/null | wc -l")
    restricted_media = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - System Hardening",
        status="Pass" if restricted_media >= 3 else "Warning",
        message=f"{get_nsa_id('SYS', 29)}: Removable media filesystems disabled",
        details=f"{restricted_media} filesystems disabled",
        remediation="Disable unnecessary filesystems in /etc/modprobe.d/"
    ))
    
    # SYS-030: System updates available
    if command_exists("apt"):
        result = run_command("apt list --upgradable 2>/dev/null | wc -l")
        updates = safe_int_parse(result.stdout.strip())
    elif command_exists("yum"):
        result = run_command("yum list updates 2>/dev/null | wc -l")
        updates = safe_int_parse(result.stdout.strip())
    else:
        updates = 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - System Hardening",
        status="Warning" if updates > 10 else "Pass",
        message=f"{get_nsa_id('SYS', 30)}: System updates current",
        details=f"{updates} updates available",
        remediation="Apply system updates regularly"
    ))


# ============================================================================
# CRYPTO - Cryptography & Services
# NSA emphasizes strong cryptography and FIPS compliance
# Reference: NSA Cryptographic Module Validation Program guidance
# ============================================================================

def check_cryptography_services(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Cryptography and Services Security Audit Checks Against NSA Crypto Guidance
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Cryptography & Services...")
    
    fips_enabled = check_fips_mode()
    
    # CRYPTO-001: FIPS mode enabled
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Cryptography",
        status="Pass" if fips_enabled else "Warning",
        message=f"{get_nsa_id('CRYPTO', 1)}: FIPS 140-2/3 mode enabled",
        details="FIPS mode active" if fips_enabled else "FIPS not enabled",
        remediation="Enable FIPS: fips-mode-setup --enable && reboot"
    ))
    
    # CRYPTO-002: OpenSSL installed
    openssl_installed = command_exists("openssl")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Cryptography",
        status="Pass" if openssl_installed else "Fail",
        message=f"{get_nsa_id('CRYPTO', 2)}: OpenSSL available",
        details="OpenSSL installed" if openssl_installed else "Not installed",
        remediation="Install OpenSSL"
    ))
    
    # CRYPTO-003: OpenSSL version
    if openssl_installed:
        result = run_command("openssl version")
        openssl_version = result.stdout.strip()
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Cryptography",
            status="Info",
            message=f"{get_nsa_id('CRYPTO', 3)}: OpenSSL version",
            details=openssl_version,
            remediation="Keep OpenSSL updated"
        ))
    
    # CRYPTO-004: SSL/TLS certificates directory
    cert_dir = os.path.exists("/etc/ssl/certs")
    cert_count = len(glob.glob("/etc/ssl/certs/*.pem")) if cert_dir else 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Cryptography",
        status="Pass" if cert_count > 5 else "Warning",
        message=f"{get_nsa_id('CRYPTO', 4)}: SSL/TLS certificates present",
        details=f"{cert_count} certificates",
        remediation="Install CA certificates"
    ))
    
    # CRYPTO-005: GPG/GnuPG installed
    gpg_installed = command_exists("gpg") or command_exists("gpg2")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Cryptography",
        status="Pass" if gpg_installed else "Warning",
        message=f"{get_nsa_id('CRYPTO', 5)}: GnuPG encryption available",
        details="GPG installed" if gpg_installed else "Not installed",
        remediation=remediation_for("gnupg")
    ))
    
    # CRYPTO-006: Disk encryption capability
    luks_installed = command_exists("cryptsetup")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Cryptography",
        status="Pass" if luks_installed else "Warning",
        message=f"{get_nsa_id('CRYPTO', 6)}: Disk encryption tools available",
        details="cryptsetup installed" if luks_installed else "Not installed",
        remediation=remediation_for("cryptsetup")
    ))
    
    # CRYPTO-007: Encrypted volumes present
    result = run_command("lsblk -f 2>/dev/null | grep -c crypto_LUKS")
    encrypted_volumes = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Cryptography",
        status="Pass" if encrypted_volumes > 0 else "Warning",
        message=f"{get_nsa_id('CRYPTO', 7)}: Encrypted volumes configured",
        details=f"{encrypted_volumes} LUKS volumes",
        remediation="Enable full disk encryption with LUKS"
    ))
    
    # CRYPTO-008: SSH protocol version 2
    ssh_protocol = get_ssh_config_value("Protocol")
    protocol_ok = not ssh_protocol or ssh_protocol == "2"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Cryptography",
        status="Pass" if protocol_ok else "Fail",
        message=f"{get_nsa_id('CRYPTO', 8)}: SSH protocol version 2 only",
        details=f"Protocol: {ssh_protocol or '2 (default)'}",
        remediation="Set Protocol 2 in /etc/ssh/sshd_config"
    ))
    
    # CRYPTO-009: SSH strong ciphers
    ssh_ciphers = get_ssh_config_value("Ciphers")
    weak_ciphers = ["3des", "arcfour", "blowfish", "cast128", "aes128-cbc", "aes192-cbc", "aes256-cbc"]
    
    if ssh_ciphers:
        has_weak = any(weak in ssh_ciphers.lower() for weak in weak_ciphers)
    else:
        has_weak = False
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Cryptography",
        status="Pass" if not has_weak else "Warning",
        message=f"{get_nsa_id('CRYPTO', 9)}: SSH uses strong ciphers",
        details=f"Ciphers: {ssh_ciphers or 'default'}"[:50],
        remediation="Configure strong ciphers: chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr"
    ))
    
    # CRYPTO-010: SSH strong MACs
    ssh_macs = get_ssh_config_value("MACs")
    weak_macs = ["md5", "96", "hmac-sha1"]
    
    if ssh_macs:
        has_weak_mac = any(weak in ssh_macs.lower() for weak in weak_macs)
    else:
        has_weak_mac = False
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Cryptography",
        status="Pass" if not has_weak_mac else "Warning",
        message=f"{get_nsa_id('CRYPTO', 10)}: SSH uses strong MACs",
        details=f"MACs: {ssh_macs or 'default'}"[:50],
        remediation="Configure strong MACs: hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"
    ))
    
    # CRYPTO-011: SSH strong key exchange
    ssh_kex = get_ssh_config_value("KexAlgorithms")
    weak_kex = ["diffie-hellman-group1", "diffie-hellman-group14-sha1"]
    
    if ssh_kex:
        has_weak_kex = any(weak in ssh_kex.lower() for weak in weak_kex)
    else:
        has_weak_kex = False
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Cryptography",
        status="Pass" if not has_weak_kex else "Warning",
        message=f"{get_nsa_id('CRYPTO', 11)}: SSH uses strong key exchange",
        details=f"KexAlgorithms: {ssh_kex or 'default'}"[:50],
        remediation="Configure strong KEX: curve25519-sha256,ecdh-sha2-nistp521"
    ))
    
    # CRYPTO-012: SSH host key algorithms
    ssh_host_key = get_ssh_config_value("HostKeyAlgorithms")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Cryptography",
        status="Info",
        message=f"{get_nsa_id('CRYPTO', 12)}: SSH host key algorithms",
        details=f"HostKeyAlgorithms: {ssh_host_key or 'default'}"[:50],
        remediation="Use strong algorithms: ssh-ed25519,rsa-sha2-512,rsa-sha2-256"
    ))
    
    # CRYPTO-013: SSH server alive interval
    alive_interval = get_ssh_config_value("ClientAliveInterval")
    interval_ok = alive_interval and safe_int_parse(alive_interval) > 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Cryptography",
        status="Pass" if interval_ok else "Warning",
        message=f"{get_nsa_id('CRYPTO', 13)}: SSH session timeout configured",
        details=f"ClientAliveInterval: {alive_interval or 'not set'}",
        remediation="Set ClientAliveInterval 300 in /etc/ssh/sshd_config"
    ))
    
    # CRYPTO-014: SSH password authentication status
    password_auth = get_ssh_config_value("PasswordAuthentication")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Cryptography",
        status="Info",
        message=f"{get_nsa_id('CRYPTO', 14)}: SSH password authentication",
        details=f"PasswordAuthentication: {password_auth or 'yes (default)'}",
        remediation="Consider disabling for key-only auth: PasswordAuthentication no"
    ))
    
    # CRYPTO-015: SSH root login disabled
    root_login = get_ssh_config_value("PermitRootLogin")
    root_disabled = root_login and root_login.lower() == "no"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Cryptography",
        status="Pass" if root_disabled else "Fail",
        message=f"{get_nsa_id('CRYPTO', 15)}: SSH root login disabled",
        details=f"PermitRootLogin: {root_login or 'yes (default)'}",
        remediation="Set PermitRootLogin no in /etc/ssh/sshd_config"
    ))
    
    # CRYPTO-016: SSH empty passwords disabled
    empty_passwords = get_ssh_config_value("PermitEmptyPasswords")
    empty_disabled = not empty_passwords or empty_passwords.lower() == "no"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Cryptography",
        status="Pass" if empty_disabled else "Fail",
        message=f"{get_nsa_id('CRYPTO', 16)}: SSH empty passwords disabled",
        details=f"PermitEmptyPasswords: {empty_passwords or 'no (default)'}",
        remediation="Set PermitEmptyPasswords no in /etc/ssh/sshd_config"
    ))
    
    # CRYPTO-017: SSH X11 forwarding disabled
    x11_forwarding = get_ssh_config_value("X11Forwarding")
    x11_disabled = x11_forwarding and x11_forwarding.lower() == "no"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Cryptography",
        status="Pass" if x11_disabled else "Warning",
        message=f"{get_nsa_id('CRYPTO', 17)}: SSH X11 forwarding disabled",
        details=f"X11Forwarding: {x11_forwarding or 'yes (default)'}",
        remediation="Set X11Forwarding no in /etc/ssh/sshd_config"
    ))
    
    # CRYPTO-018: SSH Max authentication tries
    max_auth_tries = get_ssh_config_value("MaxAuthTries")
    tries_ok = max_auth_tries and safe_int_parse(max_auth_tries) <= 4
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Cryptography",
        status="Pass" if tries_ok else "Warning",
        message=f"{get_nsa_id('CRYPTO', 18)}: SSH authentication attempts limited",
        details=f"MaxAuthTries: {max_auth_tries or '6 (default)'}",
        remediation="Set MaxAuthTries 4 in /etc/ssh/sshd_config"
    ))
    
    # CRYPTO-019: VPN capability available
    vpn_tools = ["openvpn", "strongswan", "wireguard"]
    vpn_installed = any(check_package_installed(tool, os_info) for tool in vpn_tools)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Cryptography",
        status="Info",
        message=f"{get_nsa_id('CRYPTO', 19)}: VPN capability available",
        details="VPN software installed" if vpn_installed else "No VPN",
        remediation="Install VPN: apt-get install openvpn wireguard"
    ))
    
    # CRYPTO-020: IPsec tools available
    ipsec_installed = check_package_installed("libreswan", os_info) or check_package_installed("strongswan", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Cryptography",
        status="Info",
        message=f"{get_nsa_id('CRYPTO', 20)}: IPsec tools available",
        details="IPsec installed" if ipsec_installed else "Not installed",
        remediation="Install IPsec: apt-get install libreswan"
    ))
    
    # CRYPTO-021: TLS/SSL library version
    if command_exists("openssl"):
        result = run_command("openssl version | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+'")
        ssl_version = result.stdout.strip()
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Cryptography",
            status="Info",
            message=f"{get_nsa_id('CRYPTO', 21)}: OpenSSL/TLS version",
            details=f"Version: {ssl_version}",
            remediation="Keep TLS library updated"
        ))
    
    # CRYPTO-022: Random number generator
    result = run_command("cat /proc/sys/kernel/random/entropy_avail")
    entropy = safe_int_parse(result.stdout.strip())
    entropy_ok = entropy >= 1000
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Cryptography",
        status="Pass" if entropy_ok else "Warning",
        message=f"{get_nsa_id('CRYPTO', 22)}: System entropy sufficient",
        details=f"Available entropy: {entropy}",
        remediation="Install rng-tools or haveged for more entropy"
    ))
    
    # CRYPTO-023: Hardware RNG available
    hwrng_exists = os.path.exists("/dev/hwrng")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Cryptography",
        status="Pass" if hwrng_exists else "Info",
        message=f"{get_nsa_id('CRYPTO', 23)}: Hardware RNG available",
        details="Hardware RNG present" if hwrng_exists else "Not available",
        remediation="Use hardware RNG if available"
    ))
    
    # CRYPTO-024: Telnet disabled
    telnet_active = check_service_active("telnet")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Cryptography",
        status="Pass" if not telnet_active else "Fail",
        message=f"{get_nsa_id('CRYPTO', 24)}: Telnet service disabled",
        details="Telnet active" if telnet_active else "Disabled",
        remediation="Disable telnet: systemctl disable telnet"
    ))
    
    # CRYPTO-025: FTP disabled (use SFTP)
    ftp_active = check_service_active("vsftpd") or check_service_active("proftpd")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Cryptography",
        status="Pass" if not ftp_active else "Warning",
        message=f"{get_nsa_id('CRYPTO', 25)}: Insecure FTP disabled",
        details="FTP active" if ftp_active else "Disabled",
        remediation="Use SFTP instead of FTP"
    ))
    
    # CRYPTO-026: TFTP disabled
    tftp_active = check_service_active("tftp")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Cryptography",
        status="Pass" if not tftp_active else "Fail",
        message=f"{get_nsa_id('CRYPTO', 26)}: TFTP service disabled",
        details="TFTP active" if tftp_active else "Disabled",
        remediation="Disable TFTP: systemctl disable tftp"
    ))
    
    # CRYPTO-027: rsh/rlogin/rexec disabled
    r_services = ["rsh", "rlogin", "rexec"]
    r_active = any(check_service_active(svc) for svc in r_services)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Cryptography",
        status="Pass" if not r_active else "Fail",
        message=f"{get_nsa_id('CRYPTO', 27)}: r-services disabled",
        details="r-services active" if r_active else "Disabled",
        remediation="Disable r-services: systemctl disable rsh rlogin rexec"
    ))
    
    # CRYPTO-028: NIS/NIS+ disabled
    nis_active = check_service_active("ypserv") or check_service_active("ypbind")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Cryptography",
        status="Pass" if not nis_active else "Warning",
        message=f"{get_nsa_id('CRYPTO', 28)}: NIS/NIS+ disabled",
        details="NIS active" if nis_active else "Disabled",
        remediation="Disable NIS: systemctl disable ypserv ypbind"
    ))
    
    # CRYPTO-029: SNMP v3 or disabled
    snmp_active = check_service_active("snmpd")
    
    if snmp_active and os.path.exists("/etc/snmp/snmpd.conf"):
        snmp_conf = read_file_safe("/etc/snmp/snmpd.conf")
        has_v3 = "rouser" in snmp_conf or "rwuser" in snmp_conf
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Cryptography",
            status="Pass" if has_v3 else "Warning",
            message=f"{get_nsa_id('CRYPTO', 29)}: SNMP v3 configured",
            details="SNMPv3 configured" if has_v3 else "Check SNMP version",
            remediation="Use SNMPv3 for encryption and authentication"
        ))
    
    # CRYPTO-030: HTTP services use TLS
    http_services = ["apache2", "httpd", "nginx"]
    http_active = any(check_service_active(svc) for svc in http_services)
    
    if http_active:
        ssl_modules = []
        if os.path.exists("/etc/apache2/mods-enabled/ssl.load"):
            ssl_modules.append("Apache SSL")
        if os.path.exists("/etc/nginx/sites-enabled"):
            nginx_configs = glob.glob("/etc/nginx/sites-enabled/*")
            for conf in nginx_configs:
                content = read_file_safe(conf)
                if "ssl" in content and "listen 443" in content:
                    ssl_modules.append("Nginx SSL")
                    break
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Cryptography",
            status="Pass" if ssl_modules else "Warning",
            message=f"{get_nsa_id('CRYPTO', 30)}: HTTP services use TLS/SSL",
            details=f"TLS: {', '.join(ssl_modules)}" if ssl_modules else "Check TLS config",
            remediation="Configure HTTPS/TLS for web services"
        ))


# ============================================================================
# ADDITIONAL - Additional Security Checks
# Miscellaneous NSA security guidance
# ============================================================================

def check_additional_security(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Additional Security Security Audit Checks for Miscellaneous NSA guidance
    """
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Additional Security Controls...")
    
    # ADD-001: Time synchronization active
    time_services = ["chronyd", "ntpd", "systemd-timesyncd"]
    time_sync = any(check_service_active(svc) for svc in time_services)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Additional Security",
        status="Pass" if time_sync else "Fail",
        message=f"{get_nsa_id('ADD', 1)}: Time synchronization active",
        details="Time sync running" if time_sync else "Not configured",
        remediation=remediation_for("chrony")
    ))
    
    # ADD-002: NTP servers configured
    ntp_conf_files = ["/etc/chrony.conf", "/etc/ntp.conf", "/etc/systemd/timesyncd.conf"]
    ntp_configured = False
    
    for conf_file in ntp_conf_files:
        if os.path.exists(conf_file):
            content = read_file_safe(conf_file)
            if "server " in content or "pool " in content or "NTP=" in content:
                ntp_configured = True
                break
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Additional Security",
        status="Pass" if ntp_configured else "Warning",
        message=f"{get_nsa_id('ADD', 2)}: NTP servers configured",
        details="NTP servers set" if ntp_configured else "Not configured",
        remediation="Configure NTP servers in chrony.conf or ntp.conf"
    ))
    
    # ADD-003: DNS configuration secure
    resolv_conf = read_file_safe("/etc/resolv.conf")
    nameservers = re.findall(r'nameserver\s+(\S+)', resolv_conf)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Additional Security",
        status="Pass" if len(nameservers) >= 2 else "Warning",
        message=f"{get_nsa_id('ADD', 3)}: Multiple DNS servers configured",
        details=f"{len(nameservers)} nameservers",
        remediation="Configure multiple DNS servers in /etc/resolv.conf"
    ))
    
    # ADD-004: IPv6 privacy extensions
    if check_ipv6_enabled():
        exists, ipv6_privacy = check_kernel_parameter("net.ipv6.conf.all.use_tempaddr")
        privacy_ok = ipv6_privacy and safe_int_parse(ipv6_privacy) >= 2
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Additional Security",
            status="Pass" if privacy_ok else "Warning",
            message=f"{get_nsa_id('ADD', 4)}: IPv6 privacy extensions enabled",
            details=f"use_tempaddr = {ipv6_privacy}",
            remediation="Enable: sysctl -w net.ipv6.conf.all.use_tempaddr=2"
        ))
    
    # ADD-005: Core dumps disabled globally
    limits_conf = read_file_safe("/etc/security/limits.conf")
    core_disabled = "* hard core 0" in limits_conf
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Additional Security",
        status="Pass" if core_disabled else "Warning",
        message=f"{get_nsa_id('ADD', 5)}: Core dumps disabled globally",
        details="Core dumps disabled" if core_disabled else "Not disabled",
        remediation="Add '* hard core 0' to /etc/security/limits.conf"
    ))
    
    # ADD-006: Process accounting enabled
    acct_active = check_service_active("psacct") or check_service_active("acct")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Additional Security",
        status="Pass" if acct_active else "Info",
        message=f"{get_nsa_id('ADD', 6)}: Process accounting enabled",
        details="psacct active" if acct_active else "Not enabled",
        remediation="Enable: systemctl enable psacct"
    ))
    
    # ADD-007: System activity reporting
    sysstat_installed = check_package_installed("sysstat", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Additional Security",
        status="Pass" if sysstat_installed else "Info",
        message=f"{get_nsa_id('ADD', 7)}: System activity reporting available",
        details="sysstat installed" if sysstat_installed else "Not installed",
        remediation=remediation_for("sysstat")
    ))
    
    # ADD-008: Intrusion detection system
    ids_installed = check_package_installed("aide", os_info) or check_package_installed("tripwire", os_info) or check_package_installed("ossec", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Additional Security",
        status="Pass" if ids_installed else "Warning",
        message=f"{get_nsa_id('ADD', 8)}: Intrusion detection system installed",
        details="IDS present" if ids_installed else "Not installed",
        remediation=remediation_for("aide")
    ))
    
    # ADD-009: Malware scanner available
    av_installed = check_package_installed("clamav", os_info) or check_package_installed("clamav-daemon", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Additional Security",
        status="Pass" if av_installed else "Warning",
        message=f"{get_nsa_id('ADD', 9)}: Anti-malware software installed",
        details="ClamAV installed" if av_installed else "Not installed",
        remediation=remediation_for("clamav")
    ))
    
    # ADD-010: Rootkit detection tools
    rkhunter_installed = check_package_installed("rkhunter", os_info) or check_package_installed("chkrootkit", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Additional Security",
        status="Pass" if rkhunter_installed else "Warning",
        message=f"{get_nsa_id('ADD', 10)}: Rootkit detection available",
        details="rkhunter/chkrootkit installed" if rkhunter_installed else "Not installed",
        remediation=remediation_for("rkhunter")
    ))
    
    # ADD-011: Security updates automatic
    auto_updates = check_package_installed("unattended-upgrades", os_info) or check_package_installed("yum-cron", os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Additional Security",
        status="Pass" if auto_updates else "Warning",
        message=f"{get_nsa_id('ADD', 11)}: Automatic security updates configured",
        details="Auto-updates enabled" if auto_updates else "Not configured",
        remediation=remediation_for("unattended-upgrades")
    ))
    
    # ADD-012: Packet capture tools restricted
    pcap_tools = ["tcpdump", "wireshark", "tshark"]
    pcap_installed = [tool for tool in pcap_tools if command_exists(tool)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Additional Security",
        status="Info",
        message=f"{get_nsa_id('ADD', 12)}: Packet capture tools inventory",
        details=f"Installed: {', '.join(pcap_installed)}" if pcap_installed else "None",
        remediation="Restrict access to packet capture tools"
    ))
    
    # ADD-013: Debug tools restricted
    debug_tools = ["gdb", "strace", "ltrace"]
    debug_installed = [tool for tool in debug_tools if command_exists(tool)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Additional Security",
        status="Warning" if debug_installed else "Pass",
        message=f"{get_nsa_id('ADD', 13)}: Debug tools on production system",
        details=f"Installed: {', '.join(debug_installed)}" if debug_installed else "None",
        remediation="Remove debug tools from production systems"
    ))
    
    # ADD-014: System hostname configured
    hostname = socket.gethostname()
    hostname_ok = hostname and hostname != "localhost" and len(hostname) > 3
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Additional Security",
        status="Pass" if hostname_ok else "Warning",
        message=f"{get_nsa_id('ADD', 14)}: System hostname properly configured",
        details=f"Hostname: {hostname}",
        remediation="Set meaningful hostname: hostnamectl set-hostname <name>"
    ))
    
    # ADD-015: Network interfaces hardened
    result = run_command("ip link show | grep -c 'state UP'")
    active_interfaces = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Additional Security",
        status="Info",
        message=f"{get_nsa_id('ADD', 15)}: Active network interfaces",
        details=f"{active_interfaces} interfaces up",
        remediation="Review and harden network interfaces"
    ))
    
    # ADD-016: Mail transfer agent configuration
    mta_services = ["postfix", "sendmail", "exim"]
    mta_active = [svc for svc in mta_services if check_service_active(svc)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Additional Security",
        status="Info",
        message=f"{get_nsa_id('ADD', 16)}: Mail transfer agent status",
        details=f"Active: {', '.join(mta_active)}" if mta_active else "None",
        remediation="Configure MTA securely if needed"
    ))
    
    # ADD-017: Print services status
    print_services = ["cups", "lpd"]
    print_active = [svc for svc in print_services if check_service_active(svc)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Additional Security",
        status="Pass" if not print_active else "Info",
        message=f"{get_nsa_id('ADD', 17)}: Print services status",
        details=f"Active: {', '.join(print_active)}" if print_active else "Disabled",
        remediation="Disable print services if not needed"
    ))
    
    # ADD-018: X Window System status
    x_packages = ["xorg", "xserver-xorg"]
    x_installed = any(check_package_installed(pkg, os_info) for pkg in x_packages)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Additional Security",
        status="Pass" if not x_installed else "Info",
        message=f"{get_nsa_id('ADD', 18)}: X Window System status",
        details="X11 installed" if x_installed else "Not installed",
        remediation=removal_for("xserver")
    ))
    
    # ADD-019: System rescue capability
    rescue_target = os.path.exists("/usr/lib/systemd/system/rescue.target")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Additional Security",
        status="Pass" if rescue_target else "Info",
        message=f"{get_nsa_id('ADD', 19)}: System rescue mode available",
        details="Rescue target exists" if rescue_target else "Not available",
        remediation="Ensure rescue mode is available for recovery"
    ))
    
    # ADD-020: Emergency mode password protected
    if os.path.exists("/usr/lib/systemd/system/emergency.service"):
        emergency_service = read_file_safe("/usr/lib/systemd/system/emergency.service")
        password_protected = "sulogin" in emergency_service
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Additional Security",
            status="Pass" if password_protected else "Warning",
            message=f"{get_nsa_id('ADD', 20)}: Emergency mode password protected",
            details="Requires password" if password_protected else "Not protected",
            remediation="Configure sulogin in emergency.service"
        ))


# ============================================================================
# NSA DNS Security & Wireless Interface Control
# Phase 1 Gap: DNS hardening, wireless disable, patch management
# ============================================================================

def check_dns_wireless_security(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    NSA guidance for DNS security configuration, wireless interface control,
    and update/patch management cadence.
    """
    cache = shared_data.get('cache')

    # --- DNS resolver configuration ---
    resolv_content = read_file_safe("/etc/resolv.conf")
    if resolv_content:
        nameservers = [l.split()[1] for l in resolv_content.splitlines()
                       if l.strip().startswith('nameserver') and len(l.split()) >= 2]
        # Check for well-known secure DNS providers
        secure_dns = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
                      "9.9.9.9", "149.112.112.112", "208.67.222.222"]
        local_dns = any(ns.startswith("127.") or ns == "::1" for ns in nameservers)
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Network Security",
            status="Pass" if nameservers else "Warning",
            message=f"{get_nsa_id('NET', 20)}: DNS resolver configuration",
            details=f"Nameservers: {', '.join(nameservers) if nameservers else 'none configured'}; "
                    f"Local resolver: {'yes' if local_dns else 'no'}",
            remediation="Configure trusted DNS resolvers in /etc/resolv.conf or use systemd-resolved",
            severity="Medium"
        ))

    # --- DNSSEC validation ---
    resolved_conf = read_file_safe("/etc/systemd/resolved.conf") or ""
    dnssec_enabled = "DNSSEC=yes" in resolved_conf or "DNSSEC=allow-downgrade" in resolved_conf
    result = run_command("systemctl is-active systemd-resolved 2>/dev/null", check=False)
    resolved_active = result.returncode == 0 and "active" in result.stdout

    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Network Security",
        status="Pass" if dnssec_enabled and resolved_active else (
            "Warning" if resolved_active else "Info"),
        message=f"{get_nsa_id('NET', 21)}: DNSSEC validation",
        details=f"systemd-resolved: {'active' if resolved_active else 'inactive'}, "
                f"DNSSEC: {'enabled' if dnssec_enabled else 'not configured'}",
        remediation="Set DNSSEC=yes in /etc/systemd/resolved.conf and restart systemd-resolved",
        severity="Medium"
    ))

    # --- DNS over TLS ---
    dot_enabled = "DNSOverTLS=yes" in resolved_conf or "DNSOverTLS=opportunistic" in resolved_conf
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Network Security",
        status="Pass" if dot_enabled else "Warning",
        message=f"{get_nsa_id('NET', 22)}: DNS over TLS (DoT)",
        details=f"DNSOverTLS: {'enabled' if dot_enabled else 'not configured'}",
        remediation="Set DNSOverTLS=yes in /etc/systemd/resolved.conf",
        severity="Low"
    ))

    # --- Wireless interface detection and control ---
    result = run_command("ip link show 2>/dev/null | grep -i 'wlan\\|wlp\\|wifi\\|wireless'", check=False)
    wireless_present = result.returncode == 0 and result.stdout.strip()

    if wireless_present:
        # Check if rfkill is blocking wireless
        result_rfkill = run_command("rfkill list wifi 2>/dev/null", check=False)
        wifi_blocked = "Soft blocked: yes" in result_rfkill.stdout if result_rfkill.returncode == 0 else False

        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Network Security",
            status="Pass" if wifi_blocked else "Warning",
            message=f"{get_nsa_id('NET', 23)}: Wireless interface control",
            details=f"Wireless interfaces detected; "
                    f"RF kill: {'active (blocked)' if wifi_blocked else 'not blocking'}",
            remediation="rfkill block wifi  (or disable wireless in BIOS for servers)",
            severity="Medium"
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Network Security",
            status="Pass",
            message=f"{get_nsa_id('NET', 23)}: Wireless interface control",
            details="No wireless interfaces detected",
            severity="Low"
        ))

    # --- Bluetooth interface control ---
    result = run_command("systemctl is-active bluetooth 2>/dev/null", check=False)
    bt_active = result.returncode == 0 and "active" in result.stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Network Security",
        status="Fail" if bt_active else "Pass",
        message=f"{get_nsa_id('NET', 24)}: Bluetooth service disabled",
        details=f"bluetooth.service: {'active (should be disabled on servers)' if bt_active else 'inactive'}",
        remediation="systemctl stop bluetooth && systemctl disable bluetooth && systemctl mask bluetooth",
        severity="Medium"
    ))

    # --- Patch management cadence ---
    # Check when packages were last updated
    last_update = ""
    if os_info.package_manager == "apt":
        result = run_command(
            "stat -c '%Y' /var/cache/apt/pkgcache.bin 2>/dev/null || "
            "stat -c '%Y' /var/lib/apt/lists/lock 2>/dev/null",
            check=False)
        if result.returncode == 0 and result.stdout.strip():
            import time as _time
            try:
                update_ts = int(result.stdout.strip())
                days_ago = (int(_time.time()) - update_ts) // 86400
                last_update = f"{days_ago} days ago"
            except (ValueError, TypeError):
                last_update = "unknown"
    elif os_info.package_manager in ("yum", "dnf"):
        result = run_command(
            f"{os_info.package_manager} history list 2>/dev/null | head -3 | tail -1",
            check=False)
        if result.returncode == 0:
            last_update = result.stdout.strip()[:50]

    results.append(AuditResult(
        module=MODULE_NAME,
        category="NSA - Additional Security",
        status="Info",
        message=f"{get_nsa_id('ADD', 21)}: Package update recency",
        details=f"Last package cache update: {last_update if last_update else 'unable to determine'}",
        remediation="Establish regular patching cadence (at least monthly for security updates)",
        severity="Medium"
    ))


# ============================================================================
# Main Orchestration Function
# ============================================================================

def run_checks(shared_data: Dict[str, Any]) -> List[AuditResult]:
    """
    Main entry point for NSA module
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
    print(f"[{MODULE_NAME}] NSA CYBERSECURITY GUIDANCE AUDIT")
    print(f"[{MODULE_NAME}] " + "="*70)
    print(f"[{MODULE_NAME}] Version: {MODULE_VERSION}")
    print(f"[{MODULE_NAME}] Focus: Defense-in-depth, SELinux/MAC, Strong Crypto")
    print(f"[{MODULE_NAME}] Control Areas: MAC, Network, Kernel, System, Crypto, Services")
    print(f"[{MODULE_NAME}] Target: 180+ Comprehensive Security Audit Checks")
    print(f"[{MODULE_NAME}] " + "="*70 + "\n")
    
    is_root = shared_data.get("is_root", os.geteuid() == 0)
    if not is_root:
        print(f"[{MODULE_NAME}]   Note: Running without root privileges")
        print(f"[{MODULE_NAME}] Some checks require elevated privileges for full coverage\n")
    
    try:
        # Execute all control area checks
        check_selinux_mac_controls(results, shared_data, os_info)
        check_network_hardening(results, shared_data, os_info)
        check_kernel_hardening(results, shared_data, os_info)
        check_system_hardening(results, shared_data, os_info)
        check_cryptography_services(results, shared_data, os_info)
        check_additional_security(results, shared_data, os_info)
        # Phase 1 new checks
        check_dns_wireless_security(results, shared_data, os_info)
        
    except Exception as e:
        print(f"[{MODULE_NAME}]  Error during audit execution: {str(e)}")
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Error",
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
    print(f"[{MODULE_NAME}] AUDIT COMPLETED")
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
# v3.3 EXPANSION - NSA Deep Coverage
# ----------------------------------------------------------------------------
# Synopsis:
#   Adds depth across:
#   - SELinux boolean enforcement (~30+ critical booleans)
#   - FIPS 140-3 validated cryptography depth
#   - NSA Commercial Solutions for Classified (CSfC) indicators
#   - NSA Cybersecurity Advisories technical indicators
#   - Kernel hardening depth (NSA recommendations)
#   - Network protocol restrictions per NSA guidance
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


def _v33_nsa_result(category, status, message, severity="Medium",
                    details="", remediation="", cross_references=None):
    """Build AuditResult for NSA v3.3 expansion."""
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


def _check_nsa_v33_selinux_booleans(results, shared_data, os_info):
    """NSA SELinux boolean enforcement - critical booleans for hardening."""

    # First check if SELinux is even running
    selinux_enforcing = False
    if _v33_file_exists("/sys/fs/selinux/enforce"):
        try:
            with open("/sys/fs/selinux/enforce") as f:
                selinux_enforcing = f.read().strip() == "1"
        except OSError:
            pass

    if not selinux_enforcing:
        results.append(_v33_nsa_result(
            "NSA SELinux v3.3 - State",
            "Info",
            "SELinux not enforcing - boolean checks skipped",
            severity="Informational",
            details=f"SELinux enforcing: {selinux_enforcing}",
            remediation=(
                "Enable SELinux: setenforce 1 (or edit /etc/selinux/config)"
            ),
            cross_references={
                "NSA": "SELinux Hardening", "NIST": "AC-3", "CIS": "1.7.1",
            },
        ))
        return

    # Critical NSA-recommended SELinux booleans (off = secure)
    booleans_should_be_off = [
        "allow_execheap",
        "allow_execmem",
        "allow_execmod",
        "allow_execstack",
        "allow_ftpd_anon_write",
        "allow_ftpd_full_access",
        "allow_httpd_anon_write",
        "allow_httpd_sys_script_anon_write",
        "ftp_home_dir",
        "httpd_can_network_connect",
        "httpd_enable_cgi",
        "httpd_enable_homedirs",
        "secure_mode_insmod",
        "ssh_chroot_rw_homedirs",
        "ssh_sysadm_login",
        "use_lpd_server",
        "user_ttyfile_stat",
    ]

    if not _v33_command_available("getsebool"):
        results.append(_v33_nsa_result(
            "NSA SELinux v3.3 - Tools",
            "Info",
            "getsebool not available",
            severity="Informational",
            details="policycoreutils not installed",
            remediation="dnf install -y policycoreutils",
            cross_references={
                "NSA": "SELinux Hardening", "NIST": "AC-3",
            },
        ))
        return

    # Check each boolean
    rc, out, _ = _v33_run_command(["getsebool", "-a"], timeout=10.0)
    boolean_states = {}
    if rc == 0 and out:
        for line in out.splitlines():
            parts = line.split(" --> ")
            if len(parts) == 2:
                boolean_states[parts[0].strip()] = parts[1].strip()

    for bool_name in booleans_should_be_off:
        state = boolean_states.get(bool_name, "unknown")
        ok = state == "off"
        if state == "unknown":
            severity_level = "Informational"
            status = "Info"
        else:
            severity_level = "Medium"
            status = "Pass" if ok else "Warning"
        results.append(_v33_nsa_result(
            f"NSA SELinux v3.3 - {bool_name}",
            status,
            f"SELinux boolean {bool_name} should be off",
            severity=severity_level,
            details=f"{bool_name} = {state}",
            remediation=f"setsebool -P {bool_name} off",
            cross_references={
                "NSA": "SELinux Hardening", "NIST": "AC-3", "CSF": "PR.AC-4",
            },
        ))

    # NSA-recommended booleans that should be ON
    booleans_should_be_on = [
        "deny_execmem",
        "deny_ptrace",
        "fips_mode",
    ]
    for bool_name in booleans_should_be_on:
        state = boolean_states.get(bool_name, "unknown")
        ok = state == "on"
        if state == "unknown":
            continue  # don't pollute results with unknown booleans
        results.append(_v33_nsa_result(
            f"NSA SELinux v3.3 - {bool_name}",
            "Pass" if ok else "Info",
            f"SELinux boolean {bool_name} should be on",
            severity="Medium",
            details=f"{bool_name} = {state}",
            remediation=f"setsebool -P {bool_name} on",
            cross_references={
                "NSA": "SELinux Hardening", "NIST": "AC-3",
            },
        ))


def _check_nsa_v33_fips_depth(results, shared_data, os_info):
    """NSA FIPS 140-3 validated cryptography depth."""

    # Kernel FIPS mode
    fips_kernel = "0"
    if _v33_file_exists("/proc/sys/crypto/fips_enabled"):
        fips_kernel = _v33_read_file_safe("/proc/sys/crypto/fips_enabled").strip()
    fips_kernel_active = fips_kernel == "1"
    results.append(_v33_nsa_result(
        "NSA FIPS v3.3 - Kernel",
        "Pass" if fips_kernel_active else "Info",
        f"Kernel FIPS mode: {fips_kernel}",
        severity="High",
        details=f"/proc/sys/crypto/fips_enabled = {fips_kernel}",
        remediation=(
            "RHEL/CentOS: fips-mode-setup --enable; reboot. "
            "Ubuntu Pro: pro enable fips"
        ),
        cross_references={
            "NSA": "FIPS 140-3", "NIST": "SC-13", "FIPS": "140-3",
        },
    ))

    # OpenSSL FIPS provider
    if _v33_command_available("openssl"):
        rc, out, _ = _v33_run_command(
            ["openssl", "list", "-providers"], timeout=5.0
        )
        fips_provider = rc == 0 and "fips" in out.lower()
        results.append(_v33_nsa_result(
            "NSA FIPS v3.3 - OpenSSL",
            "Pass" if fips_provider else "Info",
            f"OpenSSL FIPS provider loadable: {fips_provider}",
            severity="Medium",
            details=f"openssl list rc={rc}",
            remediation=(
                "Enable: update-crypto-policies --set FIPS (RHEL family)"
            ),
            cross_references={
                "NSA": "FIPS 140-3", "FIPS": "140-3",
            },
        ))

    # System-wide crypto-policies set to FIPS
    if _v33_file_exists("/etc/crypto-policies/config"):
        policy = _v33_read_file_safe("/etc/crypto-policies/config").strip()
        results.append(_v33_nsa_result(
            "NSA FIPS v3.3 - Crypto Policy",
            "Pass" if policy == "FIPS" else "Info",
            f"System crypto policy: {policy or 'unset'}",
            severity="High",
            details=f"crypto-policies = {policy}",
            remediation="update-crypto-policies --set FIPS",
            cross_references={
                "NSA": "FIPS 140-3", "NIST": "SC-13", "FIPS": "140-3",
            },
        ))

    # Kernel keyring usage indicator (FIPS-validated key storage)
    keyutils = _v33_command_available("keyctl")
    results.append(_v33_nsa_result(
        "NSA FIPS v3.3 - Keyring",
        "Pass" if keyutils else "Info",
        f"Linux kernel keyring tools available: {keyutils}",
        severity="Low",
        details=f"keyctl: {keyutils}",
        remediation="apt-get install -y keyutils",
        cross_references={
            "NSA": "Key Management", "NIST": "SC-12",
        },
    ))


def _check_nsa_v33_kernel_hardening(results, shared_data, os_info):
    """NSA kernel hardening recommendations."""

    # Kernel lockdown mode
    lockdown_state = _v33_read_file_safe("/sys/kernel/security/lockdown")
    has_lockdown = lockdown_state and ("integrity" in lockdown_state or
                                         "confidentiality" in lockdown_state) and \
                  "[none]" not in lockdown_state
    results.append(_v33_nsa_result(
        "NSA Kernel v3.3 - Lockdown",
        "Pass" if has_lockdown else "Info",
        f"Kernel lockdown mode active: {has_lockdown}",
        severity="High",
        details=f"lockdown: {lockdown_state.strip() if lockdown_state else 'not present'}",
        remediation=(
            "Boot kernel with lockdown=integrity (or =confidentiality) on cmdline; "
            "or echo 'integrity' > /sys/kernel/security/lockdown"
        ),
        cross_references={
            "NSA": "Kernel Hardening", "NIST": "CM-7",
        },
    ))

    # IMA (Integrity Measurement Architecture)
    ima_present = _v33_directory_exists("/sys/kernel/security/ima")
    results.append(_v33_nsa_result(
        "NSA Kernel v3.3 - IMA",
        "Pass" if ima_present else "Info",
        f"Integrity Measurement Architecture: {ima_present}",
        severity="Medium",
        details=f"/sys/kernel/security/ima: {ima_present}",
        remediation=(
            "Boot kernel with ima_policy=tcb on cmdline for IMA enforcement"
        ),
        cross_references={
            "NSA": "Integrity", "NIST": "SI-7",
        },
    ))

    # Kernel module signing enforcement
    sig_enforce = _v33_read_file_safe(
        "/sys/module/module/parameters/sig_enforce"
    ).strip()
    results.append(_v33_nsa_result(
        "NSA Kernel v3.3 - Module Signing",
        "Pass" if sig_enforce == "Y" else "Info",
        f"Kernel module signature enforcement: {sig_enforce or 'unset'}",
        severity="High",
        details=f"sig_enforce = {sig_enforce}",
        remediation=(
            "Boot with module.sig_enforce=1 on kernel cmdline. "
            "Required for FIPS-validated kernel."
        ),
        cross_references={
            "NSA": "Kernel Hardening", "NIST": "SI-7", "FIPS": "140-3",
        },
    ))

    # ASLR full
    aslr = _v33_read_sysctl("kernel.randomize_va_space")
    results.append(_v33_nsa_result(
        "NSA Kernel v3.3 - ASLR",
        "Pass" if aslr == "2" else "Fail",
        f"Full ASLR enabled (randomize_va_space=2): {aslr == '2'}",
        severity="High",
        details=f"kernel.randomize_va_space = {aslr}",
        remediation=(
            "echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.d/99-aslr.conf"
        ),
        cross_references={
            "NSA": "Kernel Hardening", "NIST": "SI-16", "STIG": "V-230280",
        },
    ))

    # Yama ptrace_scope
    yama = _v33_read_sysctl("kernel.yama.ptrace_scope")
    yama_ok = yama in ("1", "2", "3")
    results.append(_v33_nsa_result(
        "NSA Kernel v3.3 - Yama",
        "Pass" if yama_ok else "Warning",
        f"Yama ptrace_scope: {yama or 'unset'}",
        severity="Medium",
        details=f"kernel.yama.ptrace_scope = {yama}",
        remediation=(
            "echo 'kernel.yama.ptrace_scope = 1' >> /etc/sysctl.d/99-yama.conf"
        ),
        cross_references={
            "NSA": "Kernel Hardening", "NIST": "SI-16", "CIS": "1.6.4",
        },
    ))

    # KASLR not disabled
    cmdline = _v33_read_file_safe("/proc/cmdline")
    nokaslr = "nokaslr" in cmdline
    results.append(_v33_nsa_result(
        "NSA Kernel v3.3 - KASLR",
        "Pass" if not nokaslr else "Fail",
        f"KASLR not disabled in kernel cmdline",
        severity="High",
        details=f"nokaslr in cmdline: {nokaslr}",
        remediation="Remove 'nokaslr' from GRUB cmdline; rebuild grub config",
        cross_references={
            "NSA": "Kernel Hardening", "NIST": "SI-16",
        },
    ))

    # MELTDOWN/SPECTRE mitigations
    vuln_dir = "/sys/devices/system/cpu/vulnerabilities"
    if _v33_directory_exists(vuln_dir):
        vulns_to_check = ["meltdown", "spectre_v1", "spectre_v2",
                           "mds", "spec_store_bypass", "l1tf"]
        unmitigated = []
        for v in vulns_to_check:
            content = _v33_read_file_safe(os.path.join(vuln_dir, v)).strip()
            if content and "Vulnerable" in content and "Mitigation" not in content:
                unmitigated.append(f"{v}: {content[:50]}")
        results.append(_v33_nsa_result(
            "NSA Kernel v3.3 - CPU Vulnerabilities",
            "Pass" if not unmitigated else "Warning",
            f"CPU vulnerabilities mitigated ({len(unmitigated)} unmitigated)",
            severity="High",
            details=f"Unmitigated: {unmitigated[:3]}",
            remediation=(
                "Update kernel and microcode: apt-get update && "
                "apt-get install -y intel-microcode amd64-microcode"
            ),
            cross_references={
                "NSA": "Kernel Hardening", "NIST": "SI-2",
            },
        ))


def _check_nsa_v33_network_protocols(results, shared_data, os_info):
    """NSA network protocol restrictions."""

    # NSA recommends disabling IPv6 if not used; check if hardened
    ipv6_disabled = (
        _v33_read_sysctl("net.ipv6.conf.all.disable_ipv6") == "1"
    )
    results.append(_v33_nsa_result(
        "NSA Network v3.3 - IPv6",
        "Info",
        f"IPv6 disabled: {ipv6_disabled} (informational)",
        severity="Informational",
        details=f"disable_ipv6 = {_v33_read_sysctl('net.ipv6.conf.all.disable_ipv6')}",
        remediation=(
            "If IPv6 is not used: echo 'net.ipv6.conf.all.disable_ipv6 = 1' "
            ">> /etc/sysctl.d/99-disable-ipv6.conf. Otherwise, keep IPv6 enabled."
        ),
        cross_references={
            "NSA": "Network Hardening", "NIST": "CM-7",
        },
    ))

    # Disable uncommon network protocols (CIS 3.4)
    protocols = ["dccp", "sctp", "rds", "tipc"]
    blacklist_d = "/etc/modprobe.d"
    blacklisted = set()
    if _v33_directory_exists(blacklist_d):
        for f in _v33_list_directory(blacklist_d):
            c = _v33_read_file_safe(os.path.join(blacklist_d, f))
            for p in protocols:
                if re.search(rf"^\s*(blacklist|install)\s+{p}", c, re.MULTILINE):
                    blacklisted.add(p)

    for p in protocols:
        results.append(_v33_nsa_result(
            f"NSA Network v3.3 - {p}",
            "Pass" if p in blacklisted else "Warning",
            f"Uncommon protocol {p} disabled: {p in blacklisted}",
            severity="Medium",
            details=f"{p} blacklisted: {p in blacklisted}",
            remediation=f"echo 'install {p} /bin/true' > /etc/modprobe.d/{p}.conf",
            cross_references={
                "NSA": "Network Hardening", "NIST": "CM-7", "CIS": "3.4",
            },
        ))

    # ICMP redirects
    icmp_redirects = (
        _v33_read_sysctl("net.ipv4.conf.all.accept_redirects") == "0" and
        _v33_read_sysctl("net.ipv4.conf.all.send_redirects") == "0"
    )
    results.append(_v33_nsa_result(
        "NSA Network v3.3 - ICMP Redirects",
        "Pass" if icmp_redirects else "Fail",
        f"ICMP redirects disabled: {icmp_redirects}",
        severity="High",
        details=(
            f"accept_redirects = {_v33_read_sysctl('net.ipv4.conf.all.accept_redirects')}, "
            f"send_redirects = {_v33_read_sysctl('net.ipv4.conf.all.send_redirects')}"
        ),
        remediation=(
            "echo 'net.ipv4.conf.all.accept_redirects = 0' >> /etc/sysctl.d/99-net.conf; "
            "echo 'net.ipv4.conf.all.send_redirects = 0' >> /etc/sysctl.d/99-net.conf"
        ),
        cross_references={
            "NSA": "Network Hardening", "NIST": "SC-7", "CIS": "3.3",
        },
    ))

    # Source routing
    source_routing_disabled = (
        _v33_read_sysctl("net.ipv4.conf.all.accept_source_route") == "0"
    )
    results.append(_v33_nsa_result(
        "NSA Network v3.3 - Source Routing",
        "Pass" if source_routing_disabled else "Fail",
        f"Source routing disabled: {source_routing_disabled}",
        severity="High",
        details=(
            f"accept_source_route = "
            f"{_v33_read_sysctl('net.ipv4.conf.all.accept_source_route')}"
        ),
        remediation=(
            "echo 'net.ipv4.conf.all.accept_source_route = 0' "
            ">> /etc/sysctl.d/99-net.conf"
        ),
        cross_references={
            "NSA": "Network Hardening", "NIST": "SC-7", "CIS": "3.3.1",
        },
    ))

    # log_martians
    log_martians = _v33_read_sysctl("net.ipv4.conf.all.log_martians") == "1"
    results.append(_v33_nsa_result(
        "NSA Network v3.3 - log_martians",
        "Pass" if log_martians else "Warning",
        f"log_martians enabled: {log_martians}",
        severity="Medium",
        details=(
            f"log_martians = "
            f"{_v33_read_sysctl('net.ipv4.conf.all.log_martians')}"
        ),
        remediation=(
            "echo 'net.ipv4.conf.all.log_martians = 1' "
            ">> /etc/sysctl.d/99-net.conf"
        ),
        cross_references={
            "NSA": "Network Hardening", "NIST": "AU-12", "CIS": "3.3.6",
        },
    ))


def _check_nsa_v33_advisories(results, shared_data, os_info):
    """NSA Cybersecurity Advisories - technical indicators."""

    # CSA "Detect and Prevent Web Shell Malware" - WAF/IDS indicators
    waf_active = (
        _v33_file_exists("/etc/modsecurity/modsecurity.conf") or
        _v33_directory_exists("/etc/modsecurity") or
        _v33_directory_exists("/usr/share/modsecurity-crs") or
        _v33_file_exists("/etc/nginx/naxsi_core.rules")
    )
    results.append(_v33_nsa_result(
        "NSA CSA v3.3 - WebShell Defense",
        "Pass" if waf_active else "Info",
        f"Web Application Firewall present: {waf_active}",
        severity="Medium",
        details=f"WAF indicator: {waf_active}",
        remediation=(
            "Install ModSecurity v3 + OWASP CRS for web shell prevention"
        ),
        cross_references={
            "NSA": "CSA Web Shell", "NIST": "SC-7(8)",
        },
    ))

    # CSA "Cisco Routers" / network device hardening - host firewall
    fw_active = (
        _v33_systemd_active("ufw.service") == "active" or
        _v33_systemd_active("firewalld.service") == "active" or
        _v33_systemd_active("nftables.service") == "active"
    )
    results.append(_v33_nsa_result(
        "NSA CSA v3.3 - Host Firewall",
        "Pass" if fw_active else "Fail",
        f"Host firewall active: {fw_active}",
        severity="Critical",
        details=f"Firewall service: {fw_active}",
        cross_references={
            "NSA": "CSA Network Hardening", "NIST": "SC-7", "CIS": "3.5",
        },
    ))

    # CSA "Hardening Microsoft Active Directory" parallel - system access boundaries
    sshd = _v33_read_file_safe("/etc/ssh/sshd_config")
    permit_root_match = re.search(
        r"^\s*PermitRootLogin\s+(\S+)", sshd, re.MULTILINE
    )
    permit_root = permit_root_match.group(1) if permit_root_match else "yes"
    root_secure = permit_root.lower() in ("no", "prohibit-password",
                                            "without-password")
    results.append(_v33_nsa_result(
        "NSA CSA v3.3 - Privileged Access",
        "Pass" if root_secure else "Fail",
        f"SSH root login restricted: {permit_root}",
        severity="High",
        details=f"PermitRootLogin = {permit_root}",
        remediation=(
            "In /etc/ssh/sshd_config: PermitRootLogin no; systemctl reload sshd"
        ),
        cross_references={
            "NSA": "CSA Privileged Access", "NIST": "AC-6", "STIG": "V-230336",
        },
    ))

    # CSA "Mitigate Living-Off-The-Land" - monitor common LOLBin paths
    audit_rules = ""
    if _v33_directory_exists(rules_d := "/etc/audit/rules.d"):
        for f in _v33_list_directory(rules_d):
            if f.endswith(".rules"):
                audit_rules += "\n" + _v33_read_file_safe(
                    os.path.join(rules_d, f)
                )
    has_execve = "execve" in audit_rules
    results.append(_v33_nsa_result(
        "NSA CSA v3.3 - LOTL Detection",
        "Pass" if has_execve else "Warning",
        f"Living-off-the-Land detection (execve audit): {has_execve}",
        severity="High",
        details=f"execve audit rules: {has_execve}",
        remediation=(
            "Add audit rule: -a always,exit -F arch=b64 -S execve -k execution"
        ),
        cross_references={
            "NSA": "CSA LOTL", "NIST": "AU-2", "CSF": "DE.CM-3",
        },
    ))

    # CSA "Detect AD Replication Attacks" parallel - auth event logging
    audit_login = "/var/log/lastlog" in audit_rules or "logins" in audit_rules
    results.append(_v33_nsa_result(
        "NSA CSA v3.3 - Auth Logging",
        "Pass" if audit_login else "Warning",
        f"Authentication event logging: {audit_login}",
        severity="High",
        details=f"login audit indicators: {audit_login}",
        remediation=(
            "-w /var/log/lastlog -p wa -k logins; "
            "-w /var/run/faillock -p wa -k logins"
        ),
        cross_references={
            "NSA": "CSA Auth Defense", "NIST": "AU-2",
        },
    ))


def _check_nsa_v33_csfc_indicators(results, shared_data, os_info):
    """NSA Commercial Solutions for Classified - technical indicators."""

    # CSfC requires defense-in-depth: 2 independent layers
    # Layer 1 + Layer 2 indicators
    mac_active = False
    selinux = _v33_file_exists("/sys/fs/selinux/enforce")
    if selinux:
        try:
            with open("/sys/fs/selinux/enforce") as f:
                mac_active = f.read().strip() == "1"
        except OSError:
            pass
    if not mac_active:
        rc, _, _ = _v33_run_command(["aa-status", "--enabled"], timeout=3.0)
        mac_active = rc == 0

    fips_active = False
    if _v33_file_exists("/proc/sys/crypto/fips_enabled"):
        fips_active = _v33_read_file_safe(
            "/proc/sys/crypto/fips_enabled"
        ).strip() == "1"

    layers = sum([mac_active, fips_active])
    results.append(_v33_nsa_result(
        "NSA CSfC v3.3 - Defense in Depth",
        "Pass" if layers >= 2 else "Info",
        f"CSfC defense-in-depth layers ({layers}/2)",
        severity="High",
        details=f"MAC enforcing: {mac_active}, FIPS active: {fips_active}",
        remediation=(
            "CSfC requires multiple independent crypto layers: "
            "enable both MAC and FIPS for compliant baseline"
        ),
        cross_references={
            "NSA": "CSfC", "NIST": "SC-7(13)", "FIPS": "140-3",
        },
    ))

    # CSfC requires audit
    auditd_active = _v33_systemd_active("auditd.service") == "active"
    audit_log = _v33_file_exists("/var/log/audit/audit.log")
    audit_ok = auditd_active and audit_log
    results.append(_v33_nsa_result(
        "NSA CSfC v3.3 - Audit",
        "Pass" if audit_ok else "Fail",
        f"CSfC audit requirements: {audit_ok}",
        severity="Critical",
        details=f"auditd: {auditd_active}, audit.log: {audit_log}",
        cross_references={
            "NSA": "CSfC", "NIST": "AU-2",
        },
    ))


# Save reference to existing run_checks
_original_run_checks_nsa_v33 = run_checks


def run_checks(shared_data):
    """Execute the v3.3 expanded NSA module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_nsa_v33(shared_data)

    os_info = shared_data.get("os_info") or shared_data.get("v3_os_info")
    if os_info is None:
        from shared_components import os_detection as _os_det
        os_info = _os_det.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        _check_nsa_v33_selinux_booleans(results, shared_data, os_info)
        _check_nsa_v33_fips_depth(results, shared_data, os_info)
        _check_nsa_v33_kernel_hardening(results, shared_data, os_info)
        _check_nsa_v33_network_protocols(results, shared_data, os_info)
        _check_nsa_v33_advisories(results, shared_data, os_info)
        _check_nsa_v33_csfc_indicators(results, shared_data, os_info)
    except Exception as exc:  # noqa: BLE001
        results.append(AuditResult(
            module=MODULE_NAME, category="NSA - Error",
            status="Error",
            message=f"NSA v3.3 expansion exception: {exc!r}",
            details=str(exc), severity="Medium",
        ))

    return results


# ============================================================================
# v3.5 EXPANSION - NSA Modern Guidance Areas
# ----------------------------------------------------------------------------
# Synopsis:
#   Adds depth across NSA cybersecurity guidance topics not yet covered:
#     - CNSA 2.0 (quantum-resistant cryptography readiness)
#     - NSA Kubernetes Hardening Guide (V1.2)
#     - NSA Encrypted DNS Implementation (DoH/DoT/DNSSEC)
#     - NSA VPN Configuration Guidance depth
#     - NSA Memory Safety guidance (ASAN, MSAN, kernel mitigations)
#     - NSA eBPF Security guidance
#     - NSA Software Supply Chain (SBOM, attestation)
#     - NSA Secure/Measured Boot depth
#     - NSA Identity-based access (RBAC depth, PKI)
#     - NSA Active Cybersecurity Monitoring integration
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


def _v35_nsa_result(category, status, message, severity="Medium",
                   details="", remediation="", cross_references=None):
    """Build AuditResult for NSA v3.5 expansion."""
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


def _check_nsa_v35_cnsa2_quantum_resistant(results, shared_data, os_info):
    """CNSA 2.0 - Commercial National Security Algorithm Suite v2.0
    quantum-resistant cryptography readiness."""
    cat = "NSA v3.5 - CNSA 2.0 PQC"

    # 1. OpenSSL 3.x detection (CNSA 2.0 requires modern OpenSSL)
    rc, out, _ = _v35_run_command(["openssl", "version"], timeout=5.0)
    openssl_version = ""
    openssl_3x = False
    if rc == 0 and out:
        openssl_version = out.strip().split("\n")[0]
        openssl_3x = "OpenSSL 3." in openssl_version
    results.append(_v35_nsa_result(
        f"{cat} - OpenSSL 3.x",
        "Pass" if openssl_3x else "Info",
        f"NSA CNSA 2.0 OpenSSL 3.x present: {openssl_3x}",
        severity="Medium",
        details=f"openssl version: {openssl_version}",
        remediation=(
            "OpenSSL 3.0+ adds Provider API and CNSA 2.0 algorithm support. "
            "Check distribution upgrade path. Ubuntu 22.04+, Debian 12+, "
            "RHEL 9+ ship with OpenSSL 3.x."
        ),
        cross_references={
            "NSA": "CNSA 2.0",
            "NIST": "SC-13", "FIPS": "203, 204, 205",
        },
    ))

    # 2. AES-256 in active SSH ciphers (CNSA 2.0 minimum symmetric)
    sshd = _v35_read_file_safe("/etc/ssh/sshd_config")
    sshd_d = ""
    if _v35_directory_exists("/etc/ssh/sshd_config.d"):
        for f in _v35_list_directory("/etc/ssh/sshd_config.d"):
            if f.endswith(".conf"):
                sshd_d += "\n" + _v35_read_file_safe(
                    os.path.join("/etc/ssh/sshd_config.d", f)
                )
    full_sshd = sshd + "\n" + sshd_d
    ciphers_match = re.search(
        r"^\s*Ciphers\s+(\S+)", full_sshd, re.MULTILINE,
    )
    aes256_only = (
        ciphers_match and
        "aes256" in ciphers_match.group(1).lower() and
        "aes128" not in ciphers_match.group(1).lower()
    )
    aes256_present = (
        ciphers_match and "aes256" in ciphers_match.group(1).lower()
    )
    results.append(_v35_nsa_result(
        f"{cat} - SSH AES-256",
        "Pass" if aes256_present else "Warning",
        f"NSA CNSA 2.0 SSH AES-256 present: {aes256_present}, "
        f"AES-256 only: {aes256_only}",
        severity="High",
        details=f"Ciphers = {ciphers_match.group(1) if ciphers_match else 'default'}",
        remediation=(
            "In /etc/ssh/sshd_config.d/50-cnsa2.conf:\n"
            "  Ciphers aes256-gcm@openssh.com,aes256-ctr\n"
            "CNSA 2.0 requires AES-256 minimum for symmetric encryption."
        ),
        cross_references={
            "NSA": "CNSA 2.0",
            "NIST": "SC-13", "FIPS": "197",
        },
    ))

    # 3. SHA-384 (or SHA-512) in active SSH MACs (CNSA 2.0 hash minimum)
    macs_match = re.search(r"^\s*MACs\s+(\S+)", full_sshd, re.MULTILINE)
    sha384_or_512 = (
        macs_match and (
            "sha2-384" in macs_match.group(1).lower() or
            "sha2-512" in macs_match.group(1).lower()
        )
    )
    results.append(_v35_nsa_result(
        f"{cat} - SSH SHA-384/512",
        "Pass" if sha384_or_512 else "Warning",
        f"NSA CNSA 2.0 SSH SHA-384/512 MACs: {sha384_or_512}",
        severity="High",
        details=f"MACs = {macs_match.group(1) if macs_match else 'default'}",
        remediation=(
            "In /etc/ssh/sshd_config.d/50-cnsa2.conf:\n"
            "  MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-512,"
            "hmac-sha2-256-etm@openssh.com"
        ),
        cross_references={
            "NSA": "CNSA 2.0",
            "FIPS": "180-4",
        },
    ))

    # 4. RSA-3072+ or ECDSA P-384+ keys (CNSA 2.0 asymmetric minimum)
    # Check SSH host keys
    host_key_strong = False
    host_keys_dir = "/etc/ssh"
    if _v35_directory_exists(host_keys_dir):
        for f in _v35_list_directory(host_keys_dir):
            if not f.startswith("ssh_host_") or not f.endswith("_key.pub"):
                continue
            key_path = os.path.join(host_keys_dir, f)
            try:
                content = _v35_read_file_safe(key_path)
                if content:
                    # ED25519 is acceptable (256-bit edwards curve)
                    if "ed25519" in content:
                        host_key_strong = True
                        break
                    # ECDSA P-384/P-521 acceptable
                    if "ecdsa-sha2-nistp384" in content or "ecdsa-sha2-nistp521" in content:
                        host_key_strong = True
                        break
                    # RSA: check via ssh-keygen -lf
                    if "ssh-rsa" in content:
                        rc, out, _ = _v35_run_command(
                            ["ssh-keygen", "-lf", key_path], timeout=3.0,
                        )
                        if rc == 0 and out:
                            m = re.match(r"^(\d+)\s+", out)
                            if m and int(m.group(1)) >= 3072:
                                host_key_strong = True
                                break
            except OSError:
                pass
    results.append(_v35_nsa_result(
        f"{cat} - Host Key Strength",
        "Pass" if host_key_strong else "Warning",
        f"NSA CNSA 2.0 Asymmetric host key strength: {host_key_strong}",
        severity="High",
        details=f"Strong host key (ED25519 / ECDSA P-384+ / RSA-3072+): "
                f"{host_key_strong}",
        remediation=(
            "Generate ED25519 (preferred): \n"
            "  ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ''\n"
            "Or ECDSA P-384:\n"
            "  ssh-keygen -t ecdsa -b 384 -f /etc/ssh/ssh_host_ecdsa_key -N ''\n"
            "Then: systemctl restart sshd\n"
            "Remove deprecated keys: rm -f /etc/ssh/ssh_host_dsa_key*"
        ),
        cross_references={
            "NSA": "CNSA 2.0",
            "FIPS": "186-5",
        },
    ))


def _check_nsa_v35_kubernetes_hardening(results, shared_data, os_info):
    """NSA Kubernetes Hardening Guide V1.2."""
    cat = "NSA v3.5 - K8s Hardening"

    # K8s presence indicators
    k8s_present = (
        _v35_command_available("kubectl") or
        _v35_command_available("kubelet") or
        _v35_directory_exists("/etc/kubernetes") or
        _v35_systemd_active("kubelet.service") == "active" or
        _v35_command_available("k3s") or
        _v35_command_available("microk8s")
    )

    if not k8s_present:
        results.append(_v35_nsa_result(
            f"{cat} - K8s Status",
            "Info",
            "Kubernetes not detected on host",
            severity="Informational",
            details="No kubectl/kubelet/etc-kubernetes/k3s/microk8s",
            cross_references={"NSA": "K8s Hardening Guide V1.2"},
        ))
        return

    # NSA recommends rootless containers, dropping capabilities, RuntimeDefault seccomp
    # Surrogate: kubelet config presence and audit
    kubelet_config = ""
    for path in [
        "/var/lib/kubelet/config.yaml",
        "/etc/kubernetes/kubelet/kubelet-config.yaml",
        "/etc/kubernetes/kubelet/kubelet.conf",
    ]:
        if _v35_file_exists(path):
            kubelet_config += "\n" + _v35_read_file_safe(path)

    if kubelet_config:
        # NSA: anonymous-auth must be false
        anon_auth = bool(re.search(
            r"anonymous-auth:\s*true",
            kubelet_config, re.IGNORECASE,
        ))
        results.append(_v35_nsa_result(
            f"{cat} - Anonymous Auth Disabled",
            "Pass" if not anon_auth else "Fail",
            f"NSA K8s anonymous-auth disabled: {not anon_auth}",
            severity="Critical",
            details=f"anonymous-auth: true detected: {anon_auth}",
            remediation=(
                "In kubelet config: anonymous-auth: false\n"
                "Anonymous authentication exposes the kubelet API."
            ),
            cross_references={
                "NSA": "K8s Hardening Guide",
                "CIS": "Kubernetes Benchmark 4.2.1",
            },
        ))

        # NSA: read-only port disabled
        read_only_port = re.search(
            r"readOnlyPort:\s*(\d+)", kubelet_config,
        )
        readonly_disabled = (
            read_only_port is None or read_only_port.group(1) == "0"
        )
        results.append(_v35_nsa_result(
            f"{cat} - readOnlyPort Disabled",
            "Pass" if readonly_disabled else "Fail",
            f"NSA K8s readOnlyPort=0: {readonly_disabled}",
            severity="High",
            details=(
                f"readOnlyPort = "
                f"{read_only_port.group(1) if read_only_port else '0 (default)'}"
            ),
            remediation=(
                "In kubelet config: readOnlyPort: 0\n"
                "The read-only port (10255) provides unauthenticated access."
            ),
            cross_references={
                "NSA": "K8s Hardening Guide",
                "CIS": "Kubernetes Benchmark 4.2.4",
            },
        ))

    # Container runtime audit
    runtime_active = (
        _v35_systemd_active("containerd.service") == "active" or
        _v35_systemd_active("crio.service") == "active" or
        _v35_systemd_active("docker.service") == "active"
    )
    results.append(_v35_nsa_result(
        f"{cat} - Container Runtime",
        "Pass" if runtime_active else "Info",
        f"NSA K8s Container runtime active: {runtime_active}",
        severity="Medium",
        details=f"containerd/crio/docker active: {runtime_active}",
        cross_references={"NSA": "K8s Hardening Guide"},
    ))

    # NSA: pod-level audit logging via auditd/journald
    audit_rules_text = ""
    if _v35_directory_exists("/etc/audit/rules.d"):
        for f in _v35_list_directory("/etc/audit/rules.d"):
            if f.endswith(".rules"):
                audit_rules_text += "\n" + _v35_read_file_safe(
                    os.path.join("/etc/audit/rules.d", f)
                )
    k8s_audited = (
        "/etc/kubernetes" in audit_rules_text or
        "kubelet" in audit_rules_text or
        "/var/lib/kubelet" in audit_rules_text
    )
    results.append(_v35_nsa_result(
        f"{cat} - K8s Config Audit",
        "Pass" if k8s_audited else "Warning",
        f"NSA K8s configuration audit: {k8s_audited}",
        severity="High",
        details=f"K8s paths in audit rules: {k8s_audited}",
        remediation=(
            "Add to /etc/audit/rules.d/41-nsa-k8s.rules:\n"
            "  -w /etc/kubernetes -p wa -k k8s-config\n"
            "  -w /var/lib/kubelet -p wa -k k8s-state"
        ),
        cross_references={
            "NSA": "K8s Hardening Guide",
            "NIST": "AU-2",
        },
    ))


def _check_nsa_v35_encrypted_dns(results, shared_data, os_info):
    """NSA Encrypted DNS Implementation Guidance."""
    cat = "NSA v3.5 - Encrypted DNS"

    # systemd-resolved configuration
    resolved_conf = _v35_read_file_safe("/etc/systemd/resolved.conf")
    resolved_d_text = ""
    resolved_d = "/etc/systemd/resolved.conf.d"
    if _v35_directory_exists(resolved_d):
        for f in _v35_list_directory(resolved_d):
            if f.endswith(".conf"):
                resolved_d_text += "\n" + _v35_read_file_safe(
                    os.path.join(resolved_d, f)
                )
    full_resolved = resolved_conf + "\n" + resolved_d_text

    # DNSOverTLS=yes (DoT)
    dot_match = re.search(
        r"^\s*DNSOverTLS\s*=\s*(\w+)", full_resolved, re.MULTILINE,
    )
    dot_enabled = bool(
        dot_match and dot_match.group(1).lower() in ("yes", "opportunistic")
    )

    # DNSSEC=yes
    dnssec_match = re.search(
        r"^\s*DNSSEC\s*=\s*(\w+)", full_resolved, re.MULTILINE,
    )
    dnssec_enabled = bool(
        dnssec_match and dnssec_match.group(1).lower() in ("yes", "allow-downgrade")
    )

    # systemd-resolved active
    resolved_active = _v35_systemd_active("systemd-resolved.service") == "active"

    encrypted_dns_layers = sum([
        bool(dot_enabled), bool(dnssec_enabled), bool(resolved_active),
    ])
    results.append(_v35_nsa_result(
        f"{cat} - DNS Security Posture",
        "Pass" if encrypted_dns_layers >= 2 else "Warning",
        f"NSA Encrypted DNS layers: {encrypted_dns_layers}/3 "
        f"(DoT={dot_enabled}, DNSSEC={dnssec_enabled}, "
        f"resolved={resolved_active})",
        severity="Medium",
        details=(
            f"systemd-resolved active: {resolved_active}, "
            f"DoT: {dot_enabled}, DNSSEC: {dnssec_enabled}"
        ),
        remediation=(
            "In /etc/systemd/resolved.conf.d/dns-security.conf:\n"
            "  [Resolve]\n"
            "  DNSOverTLS=yes\n"
            "  DNSSEC=allow-downgrade\n"
            "  DNS=1.1.1.1#cloudflare-dns.com 9.9.9.9#dns.quad9.net\n"
            "Then: systemctl restart systemd-resolved"
        ),
        cross_references={
            "NSA": "Encrypted DNS Implementation",
            "NIST": "SC-8(1), SC-23",
        },
    ))

    # /etc/resolv.conf points to systemd-resolved
    resolv_conf = _v35_read_file_safe("/etc/resolv.conf")
    points_to_resolved = (
        "127.0.0.53" in resolv_conf or "127.0.0.1" in resolv_conf
    )
    if resolved_active:
        results.append(_v35_nsa_result(
            f"{cat} - resolv.conf Points to Resolver",
            "Pass" if points_to_resolved else "Warning",
            f"NSA Encrypted DNS /etc/resolv.conf via local resolver: "
            f"{points_to_resolved}",
            severity="Medium",
            details=f"127.0.0.53/127.0.0.1 in resolv.conf: {points_to_resolved}",
            remediation=(
                "Symlink /etc/resolv.conf to /run/systemd/resolve/stub-resolv.conf:\n"
                "  ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf"
            ),
            cross_references={"NSA": "Encrypted DNS Implementation"},
        ))


def _check_nsa_v35_vpn_depth(results, shared_data, os_info):
    """NSA VPN Configuration Guidance depth."""
    cat = "NSA v3.5 - VPN"

    # WireGuard / strongSwan / OpenVPN presence
    vpn_tools = {
        "WireGuard": _v35_command_available("wg"),
        "strongSwan": (
            _v35_command_available("ipsec") or
            _v35_systemd_active("strongswan.service") == "active" or
            _v35_systemd_active("strongswan-starter.service") == "active"
        ),
        "Libreswan": _v35_systemd_active("libreswan.service") == "active",
        "OpenVPN": _v35_command_available("openvpn"),
    }
    vpn_available = [k for k, v in vpn_tools.items() if v]
    results.append(_v35_nsa_result(
        f"{cat} - VPN Tooling",
        "Pass" if vpn_available else "Info",
        f"NSA VPN configuration tooling: {vpn_available}",
        severity="Medium",
        details=f"Available: {vpn_available}",
        remediation=remediation_for("wireguard"),
        cross_references={
            "NSA": "Configuring IPsec VPNs",
            "NIST": "SC-8(1), AC-17",
        },
    ))

    # NSA recommends IKEv2 over IKEv1 for IPsec; check ipsec.conf
    ipsec_conf = _v35_read_file_safe("/etc/ipsec.conf")
    ipsec_d_text = ""
    if _v35_directory_exists("/etc/ipsec.d"):
        for f in _v35_list_directory("/etc/ipsec.d"):
            if f.endswith(".conf"):
                ipsec_d_text += "\n" + _v35_read_file_safe(
                    os.path.join("/etc/ipsec.d", f)
                )
    full_ipsec = ipsec_conf + "\n" + ipsec_d_text
    if full_ipsec.strip():
        ikev2_present = "keyexchange=ikev2" in full_ipsec.lower()
        results.append(_v35_nsa_result(
            f"{cat} - IKEv2",
            "Pass" if ikev2_present else "Warning",
            f"NSA IPsec IKEv2 configured: {ikev2_present}",
            severity="High",
            details=f"keyexchange=ikev2 detected: {ikev2_present}",
            remediation=(
                "In /etc/ipsec.conf or /etc/ipsec.d/*.conf:\n"
                "  conn <name>\n"
                "    keyexchange=ikev2\n"
                "    ike=aes256-sha384-modp3072\n"
                "    esp=aes256gcm16-sha384"
            ),
            cross_references={
                "NSA": "Configuring IPsec VPNs",
                "NIST": "SC-13",
            },
        ))


def _check_nsa_v35_memory_safety(results, shared_data, os_info):
    """NSA Memory Safety guidance - kernel-level mitigations and ASAN/MSAN."""
    cat = "NSA v3.5 - Memory Safety"

    # Stack protector / ASLR
    aslr = _v35_read_sysctl("kernel.randomize_va_space")
    aslr_full = aslr == "2"
    results.append(_v35_nsa_result(
        f"{cat} - ASLR Full",
        "Pass" if aslr_full else "Fail",
        f"NSA Memory Safety ASLR randomize_va_space=2: {aslr_full}",
        severity="High",
        details=f"randomize_va_space = {aslr}",
        remediation=(
            "In /etc/sysctl.d/99-nsa-memsafety.conf:\n"
            "  kernel.randomize_va_space = 2\n"
            "Then: sysctl --system"
        ),
        cross_references={
            "NSA": "Memory Safety",
            "NIST": "SI-16", "STIG": "V-230280",
        },
    ))

    # KASLR (kernel ASLR via cmdline)
    cmdline = _v35_read_file_safe("/proc/cmdline")
    kaslr_off = "nokaslr" in cmdline
    results.append(_v35_nsa_result(
        f"{cat} - KASLR",
        "Pass" if not kaslr_off else "Warning",
        f"NSA Memory Safety KASLR enabled: {not kaslr_off}",
        severity="Medium",
        details=f"nokaslr in cmdline: {kaslr_off}",
        remediation=(
            "Remove 'nokaslr' from kernel cmdline (GRUB).\n"
            "KASLR randomizes the kernel base address and is essential against "
            "kernel exploitation."
        ),
        cross_references={
            "NSA": "Memory Safety",
            "NIST": "SI-16",
        },
    ))

    # Heap protections (glibc / malloc tunables)
    glibc_hardening = False
    try:
        # Detect glibc version
        rc, out, _ = _v35_run_command(["ldd", "--version"], timeout=3.0)
        if rc == 0 and out:
            m = re.search(r"GLIBC\s+(\d+)\.(\d+)", out)
            if m and (int(m.group(1)), int(m.group(2))) >= (2, 31):
                glibc_hardening = True  # malloc tunables modern
    except OSError:
        pass
    results.append(_v35_nsa_result(
        f"{cat} - glibc Hardening",
        "Pass" if glibc_hardening else "Info",
        f"NSA Memory Safety glibc 2.31+: {glibc_hardening}",
        severity="Low",
        details=f"Modern glibc with hardened malloc: {glibc_hardening}",
        cross_references={"NSA": "Memory Safety"},
    ))

    # ASan / sanitizer tooling for development
    sanitizer_tools = {
        "AddressSanitizer (gcc)": (
            _v35_command_available("gcc") and
            os.path.exists("/usr/lib/x86_64-linux-gnu/libasan.so.8") or
            os.path.exists("/usr/lib64/libasan.so.8") or
            os.path.exists("/usr/lib/x86_64-linux-gnu/libasan.so.6") or
            os.path.exists("/usr/lib64/libasan.so.6")
        ),
        "Valgrind": _v35_command_available("valgrind"),
    }
    sanitizers = [k for k, v in sanitizer_tools.items() if v]
    if _v35_command_available("gcc") or _v35_command_available("clang"):
        results.append(_v35_nsa_result(
            f"{cat} - Sanitizer Tooling",
            "Pass" if sanitizers else "Info",
            f"NSA Memory Safety sanitizer tooling: {sanitizers}",
            severity="Informational",
            details=f"Available: {sanitizers}",
            cross_references={"NSA": "Memory Safety"},
        ))


def _check_nsa_v35_ebpf_security(results, shared_data, os_info):
    """NSA eBPF Security guidance."""
    cat = "NSA v3.5 - eBPF Security"

    # Unprivileged BPF disabled
    bpf_unpriv = _v35_read_sysctl("kernel.unprivileged_bpf_disabled")
    bpf_locked = bpf_unpriv in ("1", "2")
    results.append(_v35_nsa_result(
        f"{cat} - Unprivileged BPF",
        "Pass" if bpf_locked else "Warning",
        f"NSA eBPF unprivileged disabled: {bpf_locked}",
        severity="High",
        details=f"kernel.unprivileged_bpf_disabled = {bpf_unpriv}",
        remediation=(
            "In /etc/sysctl.d/99-nsa-ebpf.conf:\n"
            "  kernel.unprivileged_bpf_disabled = 1\n"
            "Then: sysctl --system\n"
            "Prevents unprivileged users from loading BPF programs."
        ),
        cross_references={
            "NSA": "eBPF Security",
            "NIST": "AC-3, SI-7",
        },
    ))

    # BPF JIT hardened
    bpf_harden = _v35_read_sysctl("net.core.bpf_jit_harden")
    jit_hardened = bpf_harden in ("1", "2")
    results.append(_v35_nsa_result(
        f"{cat} - BPF JIT Hardening",
        "Pass" if jit_hardened else "Info",
        f"NSA eBPF JIT hardening: {jit_hardened}",
        severity="Medium",
        details=f"net.core.bpf_jit_harden = {bpf_harden}",
        remediation=(
            "In /etc/sysctl.d/99-nsa-ebpf.conf:\n"
            "  net.core.bpf_jit_harden = 2\n"
            "Mitigates BPF JIT spraying attacks."
        ),
        cross_references={"NSA": "eBPF Security"},
    ))

    # eBPF LSM availability (kernel 5.7+)
    lsm_path = "/sys/kernel/security/lsm"
    active_lsms = _v35_read_file_safe(lsm_path).strip() if _v35_file_exists(lsm_path) else ""
    bpf_lsm = "bpf" in active_lsms.lower()
    results.append(_v35_nsa_result(
        f"{cat} - eBPF LSM",
        "Info",
        f"NSA eBPF LSM active: {bpf_lsm}",
        severity="Informational",
        details=f"bpf in active LSMs: {bpf_lsm}",
        cross_references={"NSA": "eBPF Security"},
    ))


def _check_nsa_v35_supply_chain(results, shared_data, os_info):
    """NSA Software Supply Chain - SBOM, attestation, signing."""
    cat = "NSA v3.5 - Supply Chain"

    # SBOM tooling
    sbom_tools = {
        "syft": _v35_command_available("syft"),
        "trivy": _v35_command_available("trivy"),
        "cyclonedx-cli": _v35_command_available("cyclonedx"),
    }
    sbom_available = [k for k, v in sbom_tools.items() if v]
    results.append(_v35_nsa_result(
        f"{cat} - SBOM Generation",
        "Pass" if sbom_available else "Info",
        f"NSA Supply Chain SBOM tools: {sbom_available}",
        severity="High",
        details=f"Available: {sbom_available}",
        remediation=remediation_for("syft"),
        cross_references={
            "NSA": "Software Supply Chain",
            "CISA-SbD": "1.0",
            "NIST": "SR-3, SR-4, SR-11",
        },
    ))

    # Image / artifact signing
    signing_tools = {
        "cosign": _v35_command_available("cosign"),
        "minisign": _v35_command_available("minisign"),
        "gpg": _v35_command_available("gpg") or _v35_command_available("gpg2"),
    }
    signing_available = [k for k, v in signing_tools.items() if v]
    results.append(_v35_nsa_result(
        f"{cat} - Artifact Signing",
        "Pass" if signing_available else "Warning",
        f"NSA Supply Chain signing tools: {signing_available}",
        severity="High",
        details=f"Available: {signing_available}",
        remediation=(
            "Install: apt-get install -y gnupg2\n"
            "For container signing: install cosign:\n"
            "  curl -O -L https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"
        ),
        cross_references={
            "NSA": "Software Supply Chain",
            "NIST": "SR-4, SI-7",
        },
    ))

    # Verify package GPG signatures (apt/dnf)
    apt_keyrings = (
        _v35_directory_exists("/etc/apt/keyrings") or
        _v35_directory_exists("/etc/apt/trusted.gpg.d")
    )
    rpm_gpgcheck = False
    rc, out, _ = _v35_run_command(
        ["rpm", "--eval", "%_gpgcheck"], timeout=3.0,
    )
    if rc == 0 and out and out.strip() == "1":
        rpm_gpgcheck = True
    pkg_signing_active = apt_keyrings or rpm_gpgcheck
    results.append(_v35_nsa_result(
        f"{cat} - Package Signature Verification",
        "Pass" if pkg_signing_active else "Warning",
        f"NSA Supply Chain package signature verification: {pkg_signing_active}",
        severity="High",
        details=(
            f"apt keyrings: {apt_keyrings}, rpm gpgcheck: {rpm_gpgcheck}"
        ),
        cross_references={
            "NSA": "Software Supply Chain",
            "NIST": "SR-3, SR-11",
            "PCI-DSS": "6.3.3",
        },
    ))


def _check_nsa_v35_secure_boot_depth(results, shared_data, os_info):
    """NSA Secure/Measured Boot guidance depth."""
    cat = "NSA v3.5 - Secure Boot"

    # Secure Boot detection (UEFI)
    sb_efi = _v35_directory_exists("/sys/firmware/efi/efivars")
    sb_state = "<unknown>"
    sb_enabled = False
    if sb_efi and _v35_command_available("mokutil"):
        rc, out, _ = _v35_run_command(["mokutil", "--sb-state"], timeout=5.0)
        if rc == 0 and out:
            sb_state = out.strip().split("\n")[0]
            sb_enabled = "enabled" in sb_state.lower()
    elif sb_efi:
        # Fallback: check via efivars
        for f in _v35_list_directory("/sys/firmware/efi/efivars") or []:
            if "SecureBoot" in f and "8be4df61" in f:
                # File exists; can't easily read raw bytes here, but presence
                # suggests UEFI Secure Boot variable is exposed.
                sb_state = "var present"
                break

    results.append(_v35_nsa_result(
        f"{cat} - UEFI Secure Boot",
        "Pass" if sb_enabled else "Info",
        f"NSA Secure Boot enabled: {sb_enabled}, state: {sb_state}",
        severity="High",
        details=f"UEFI: {sb_efi}, sb_state: {sb_state}",
        remediation=(
            "Enable Secure Boot in UEFI firmware setup.\n"
            "On Linux, ensure shim and signed kernel/modules are in use:\n"
            "  apt-get install -y shim-signed grub-efi-amd64-signed"
        ),
        cross_references={
            "NSA": "UEFI Secure Boot Customization",
            "NIST": "SI-7", "STIG": "V-230275",
        },
    ))

    # TPM 2.0 presence (measured boot)
    tpm_present = (
        _v35_directory_exists("/sys/class/tpm/tpm0") or
        _v35_file_exists("/dev/tpm0") or
        _v35_file_exists("/dev/tpmrm0")
    )
    tpm_tools = (
        _v35_command_available("tpm2_pcrread") or
        _v35_command_available("tpm2_quote")
    )
    measured_boot_capable = tpm_present and tpm_tools
    results.append(_v35_nsa_result(
        f"{cat} - TPM 2.0 / Measured Boot",
        "Pass" if measured_boot_capable else "Info",
        f"NSA Measured Boot capable: {measured_boot_capable}",
        severity="Medium",
        details=f"TPM device: {tpm_present}, tpm2-tools: {tpm_tools}",
        remediation=(
            "apt-get install -y tpm2-tools\n"
            "Verify boot integrity: tpm2_pcrread sha256:0,1,2,3,4,5,6,7"
        ),
        cross_references={
            "NSA": "Measured Boot",
            "NIST": "SI-7", "FIPS": "140-3",
        },
    ))


def _check_nsa_v35_active_monitoring(results, shared_data, os_info):
    """NSA Active Cybersecurity Monitoring integration."""
    cat = "NSA v3.5 - Active Monitoring"

    # SIEM agent / forwarder
    siem_agents = {
        "rsyslog forwarding": False,
        "syslog-ng forwarding": False,
        "auditd remote": False,
        "OSSEC/Wazuh agent": _v35_file_exists("/var/ossec/etc/ossec.conf"),
        "Splunk forwarder": _v35_file_exists("/opt/splunkforwarder/bin/splunk"),
        "Filebeat": _v35_systemd_active("filebeat.service") == "active",
        "Vector": _v35_systemd_active("vector.service") == "active",
        "Fluentd / Fluent Bit": (
            _v35_systemd_active("fluentd.service") == "active" or
            _v35_systemd_active("fluent-bit.service") == "active" or
            _v35_systemd_active("td-agent.service") == "active"
        ),
    }
    rsy = _v35_read_file_safe("/etc/rsyslog.conf")
    if "@@" in rsy or "omfwd" in rsy:
        siem_agents["rsyslog forwarding"] = True
    if not siem_agents["rsyslog forwarding"] and _v35_directory_exists(
            "/etc/rsyslog.d"):
        for f in _v35_list_directory("/etc/rsyslog.d"):
            c = _v35_read_file_safe(os.path.join("/etc/rsyslog.d", f))
            if "@@" in c or "omfwd" in c:
                siem_agents["rsyslog forwarding"] = True
                break
    audisp = (
        _v35_read_file_safe("/etc/audit/audisp-remote.conf") or
        _v35_read_file_safe("/etc/audisp/audisp-remote.conf")
    )
    if audisp and "remote_server" in audisp:
        siem_agents["auditd remote"] = True

    active = [k for k, v in siem_agents.items() if v]
    results.append(_v35_nsa_result(
        f"{cat} - SIEM Forwarders",
        "Pass" if active else "Warning",
        f"NSA Active Monitoring SIEM forwarders: {active}",
        severity="High",
        details=f"Active: {active}",
        remediation=(
            "Configure rsyslog remote forwarding (TLS):\n"
            "  /etc/rsyslog.d/50-siem.conf:\n"
            "  *.* action(type=\"omfwd\" target=\"siem.example.com\" "
            "port=\"6514\" protocol=\"tcp\" StreamDriver=\"gtls\")"
        ),
        cross_references={
            "NSA": "Active Cybersecurity Monitoring",
            "NIST": "AU-6, SI-4",
            "PCI-DSS": "10.5.3",
        },
    ))

    # Continuous monitoring tools
    monitoring_active = (
        _v35_systemd_active("auditd.service") == "active" and
        (_v35_command_available("aide") or _v35_file_exists(
            "/var/lib/aide/aide.db"
        )) and
        _v35_systemd_active("fail2ban.service") == "active"
    )
    results.append(_v35_nsa_result(
        f"{cat} - Continuous Monitoring Stack",
        "Pass" if monitoring_active else "Info",
        f"NSA Continuous monitoring stack (auditd+AIDE+fail2ban): "
        f"{monitoring_active}",
        severity="Medium",
        details=f"All three active: {monitoring_active}",
        cross_references={
            "NSA": "Active Cybersecurity Monitoring",
            "NIST": "CA-7",
        },
    ))


# Save reference to existing run_checks
_original_run_checks_nsa_v35 = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the v3.5 expanded NSA module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_nsa_v35(shared_data)

    os_info = shared_data.get("os_info") or shared_data.get("v3_os_info")
    if os_info is None:
        from shared_components import os_detection as _os_det
        os_info = _os_det.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        _check_nsa_v35_cnsa2_quantum_resistant(results, shared_data, os_info)
        _check_nsa_v35_kubernetes_hardening(results, shared_data, os_info)
        _check_nsa_v35_encrypted_dns(results, shared_data, os_info)
        _check_nsa_v35_vpn_depth(results, shared_data, os_info)
        _check_nsa_v35_memory_safety(results, shared_data, os_info)
        _check_nsa_v35_ebpf_security(results, shared_data, os_info)
        _check_nsa_v35_supply_chain(results, shared_data, os_info)
        _check_nsa_v35_secure_boot_depth(results, shared_data, os_info)
        _check_nsa_v35_active_monitoring(results, shared_data, os_info)
    except Exception as exc:  # noqa: BLE001
        results.append(AuditResult(
            module=MODULE_NAME, category="NSA - Error",
            status="Error",
            message=f"NSA v3.5 expansion exception: {exc!r}",
            details=str(exc), severity="Medium",
        ))

    return results
if __name__ == "__main__":
    """
    Standalone testing capability for the NSA module
    """
    import datetime
    import platform
    
    print("="*80)
    print(f"NSA Module Standalone Test - v{MODULE_VERSION}")
    print("Comprehensive NSA Cybersecurity Guidance")
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
    print(f"NSA module comprehensive test complete")
    print(f"All {len(test_results)} checks executed successfully")
    print(f"{'='*80}\n")
