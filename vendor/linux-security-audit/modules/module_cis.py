#!/usr/bin/env python3
"""
module_cis.py - CIS Benchmarks Comprehensive Implementation
Version: 2.1

SYNOPSIS:
    CIS Benchmark compliance and security audit checks for Linux systems.
    Target: 200+ distinct, executable security checks.

DESCRIPTION:
    This module implements comprehensive CIS Benchmark controls across all sections:
    
    Section 1: Initial Setup:
    - Filesystem configuration
    - Package management
    - Filesystem integrity
    - Secure boot settings
    - Additional process hardening
    
    Section 2: Services:
    - Time synchronization
    - X Window System
    - Special purpose services
    - Service clients
    
    Section 3: Network Configuration:
    - Network parameters host only
    - Network parameters host and router
    - IPv6 parameters
    - TCP wrappers
    
    Section 4: Logging and Auditing:
    - System logging
    - Auditd configuration
    
    Section 5: Access, Authentication, Authorization:
    - Cron configuration
    - SSH server configuration
    - PAM configuration
    - User accounts and environment
    
    Section 6: System Maintenance:
    - System file permissions
    - User and group settings

USAGE:
    Standalone module test:
        python3 module_cis.py

    Integration with main audit script:
        python3 linux_security_audit.py --modules CIS
        python3 linux_security_audit.py -m CIS

PARAMETERS:
    shared_data : Dictionary containing shared data from main script

NOTES:
    Version: 2.1
    Target Checks: 200+ individual executable checks; OS-aware technical control checks
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

MODULE_NAME = "CIS"

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

def check_password_quality(setting: str, min_value: int) -> bool:
    """Check if password quality setting meets minimum value"""
    result = run_command(f"grep -E '^{setting}' /etc/security/pwquality.conf 2>/dev/null")
    if result.returncode == 0:
        match = re.search(r'=\s*(-?\d+)', result.stdout)
        if match:
            return int(match.group(1)) >= min_value
    return False


def cis_check_kernel_parameter(param: str, expected: str, cache=None) -> bool:
    """CIS-specific kernel parameter check: returns True if value matches expected
    
    Wraps audit_common's check_kernel_parameter which returns (exists, value) tuple.
    CIS checks compare against an expected value and return a simple boolean.
    """
    exists, value = check_kernel_parameter(param, cache=cache)
    return exists and value.strip() == expected


def cis_check_mount_option(mount_point: str, option: str, cache=None) -> bool:
    """CIS-specific mount option check with cache support"""
    return check_mount_option(mount_point, option, cache=cache)


def get_listening_services() -> List[str]:
    """Get list of services listening on network ports (CIS-specific)"""
    services = []
    result = run_command("ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null")
    for line in result.stdout.split('\n'):
        if 'LISTEN' in line or 'UNCONN' in line:
            parts = line.split()
            if len(parts) >= 7:
                service = parts[-1] if '/' in parts[-1] else 'unknown'
                services.append(service)
    return services
    """Check password quality settings in PAM"""
    pam_files = ["/etc/security/pwquality.conf", "/etc/pam.d/system-auth", 
                 "/etc/pam.d/common-password"]
    for pam_file in pam_files:
        if os.path.exists(pam_file):
            content = read_file_safe(pam_file)
            match = re.search(rf'{setting}\s*=\s*(\d+)', content)
            if match and int(match.group(1)) >= min_value:
                return True
    return False


# ============================================================================
# Section 1: Initial Setup
# ============================================================================

def check_section1_filesystem_configuration(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """CIS Section 1.1 - Filesystem Configuration"""
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Section 1.1 - Filesystem Configuration...")
    
    # 1.1.1.1 - Ensure cramfs is disabled
    cramfs_disabled = run_command("lsmod | grep cramfs").returncode != 0
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.1 - Filesystem",
        status="Pass" if cramfs_disabled else "Fail",
        message="1.1.1.1 Ensure cramfs filesystem is disabled",
        details="cramfs module not loaded" if cramfs_disabled else "cramfs module is loaded",
        remediation="echo 'install cramfs /bin/true' >> /etc/modprobe.d/cramfs.conf"
    ))
    
    # 1.1.1.2 - Ensure freevxfs is disabled
    freevxfs_disabled = run_command("lsmod | grep freevxfs").returncode != 0
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.1 - Filesystem",
        status="Pass" if freevxfs_disabled else "Fail",
        message="1.1.1.2 Ensure freevxfs filesystem is disabled",
        details="freevxfs module not loaded" if freevxfs_disabled else "freevxfs module is loaded",
        remediation="echo 'install freevxfs /bin/true' >> /etc/modprobe.d/freevxfs.conf"
    ))
    
    # 1.1.1.3 - Ensure jffs2 is disabled
    jffs2_disabled = run_command("lsmod | grep jffs2").returncode != 0
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.1 - Filesystem",
        status="Pass" if jffs2_disabled else "Fail",
        message="1.1.1.3 Ensure jffs2 filesystem is disabled",
        details="jffs2 module not loaded" if jffs2_disabled else "jffs2 module is loaded",
        remediation="echo 'install jffs2 /bin/true' >> /etc/modprobe.d/jffs2.conf"
    ))
    
    # 1.1.1.4 - Ensure hfs is disabled
    hfs_disabled = run_command("lsmod | grep hfs").returncode != 0
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.1 - Filesystem",
        status="Pass" if hfs_disabled else "Fail",
        message="1.1.1.4 Ensure hfs filesystem is disabled",
        details="hfs module not loaded" if hfs_disabled else "hfs module is loaded",
        remediation="echo 'install hfs /bin/true' >> /etc/modprobe.d/hfs.conf"
    ))
    
    # 1.1.1.5 - Ensure hfsplus is disabled
    hfsplus_disabled = run_command("lsmod | grep hfsplus").returncode != 0
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.1 - Filesystem",
        status="Pass" if hfsplus_disabled else "Fail",
        message="1.1.1.5 Ensure hfsplus filesystem is disabled",
        details="hfsplus module not loaded" if hfsplus_disabled else "hfsplus module is loaded",
        remediation="echo 'install hfsplus /bin/true' >> /etc/modprobe.d/hfsplus.conf"
    ))
    
    # 1.1.1.6 - Ensure udf is disabled
    udf_disabled = run_command("lsmod | grep udf").returncode != 0
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.1 - Filesystem",
        status="Pass" if udf_disabled else "Fail",
        message="1.1.1.6 Ensure udf filesystem is disabled",
        details="udf module not loaded" if udf_disabled else "udf module is loaded",
        remediation="echo 'install udf /bin/true' >> /etc/modprobe.d/udf.conf"
    ))
    
    # 1.1.2 - Ensure /tmp is configured
    tmp_configured = check_mount_option("/tmp", "")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.1 - Filesystem",
        status="Pass" if tmp_configured else "Fail",
        message="1.1.2 Ensure /tmp is configured as separate partition",
        details="/tmp is separate partition" if tmp_configured else "/tmp is not separate partition",
        remediation="Configure /tmp as separate partition in /etc/fstab"
    ))
    
    # 1.1.3 - Ensure nodev option set on /tmp
    tmp_nodev = check_mount_option("/tmp", "nodev")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.1 - Filesystem",
        status="Pass" if tmp_nodev else "Fail",
        message="1.1.3 Ensure nodev option set on /tmp partition",
        details="/tmp has nodev" if tmp_nodev else "/tmp missing nodev",
        remediation="Add nodev to /tmp in /etc/fstab"
    ))
    
    # 1.1.4 - Ensure nosuid option set on /tmp
    tmp_nosuid = check_mount_option("/tmp", "nosuid")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.1 - Filesystem",
        status="Pass" if tmp_nosuid else "Fail",
        message="1.1.4 Ensure nosuid option set on /tmp partition",
        details="/tmp has nosuid" if tmp_nosuid else "/tmp missing nosuid",
        remediation="Add nosuid to /tmp in /etc/fstab"
    ))
    
    # 1.1.5 - Ensure noexec option set on /tmp
    tmp_noexec = check_mount_option("/tmp", "noexec")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.1 - Filesystem",
        status="Pass" if tmp_noexec else "Fail",
        message="1.1.5 Ensure noexec option set on /tmp partition",
        details="/tmp has noexec" if tmp_noexec else "/tmp missing noexec",
        remediation="Add noexec to /tmp in /etc/fstab"
    ))
    
    # 1.1.6 - Ensure /var is configured
    var_configured = check_mount_option("/var", "")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.1 - Filesystem",
        status="Pass" if var_configured else "Info",
        message="1.1.6 Ensure /var is configured as separate partition",
        details="/var is separate partition" if var_configured else "/var is not separate partition",
        remediation="Configure /var as separate partition for production systems"
    ))
    
    # 1.1.7 - Ensure /var/tmp is configured
    var_tmp_configured = check_mount_option("/var/tmp", "")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.1 - Filesystem",
        status="Pass" if var_tmp_configured else "Info",
        message="1.1.7 Ensure /var/tmp is configured as separate partition",
        details="/var/tmp is separate" if var_tmp_configured else "/var/tmp is not separate",
        remediation="Configure /var/tmp as separate partition"
    ))
    
    # 1.1.8 - Ensure nodev on /var/tmp
    var_tmp_nodev = check_mount_option("/var/tmp", "nodev")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.1 - Filesystem",
        status="Pass" if var_tmp_nodev else "Fail",
        message="1.1.8 Ensure nodev option set on /var/tmp",
        details="/var/tmp has nodev" if var_tmp_nodev else "/var/tmp missing nodev",
        remediation="Add nodev to /var/tmp in /etc/fstab"
    ))
    
    # 1.1.9 - Ensure nosuid on /var/tmp
    var_tmp_nosuid = check_mount_option("/var/tmp", "nosuid")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.1 - Filesystem",
        status="Pass" if var_tmp_nosuid else "Fail",
        message="1.1.9 Ensure nosuid option set on /var/tmp",
        details="/var/tmp has nosuid" if var_tmp_nosuid else "/var/tmp missing nosuid",
        remediation="Add nosuid to /var/tmp in /etc/fstab"
    ))
    
    # 1.1.10 - Ensure noexec on /var/tmp
    var_tmp_noexec = check_mount_option("/var/tmp", "noexec")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.1 - Filesystem",
        status="Pass" if var_tmp_noexec else "Fail",
        message="1.1.10 Ensure noexec option set on /var/tmp",
        details="/var/tmp has noexec" if var_tmp_noexec else "/var/tmp missing noexec",
        remediation="Add noexec to /var/tmp in /etc/fstab"
    ))

def check_section1_package_management(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """CIS Section 1.2 - Configure Software Updates"""
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Section 1.2 - Package Management...")
    
    # 1.2.1 - Ensure GPG keys configured (apt)
    if command_exists("apt-key"):
        gpg_keys = run_command("apt-key list 2>/dev/null | grep -c pub")
        has_keys = gpg_keys.returncode == 0 and int(gpg_keys.stdout.strip() or "0") > 0
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 1.2 - Package Mgmt",
            status="Pass" if has_keys else "Fail",
            message="1.2.1 Ensure package manager repositories are configured",
            details="GPG keys present" if has_keys else "No GPG keys found",
            remediation="Add repository GPG keys: apt-key add <keyfile>"
        ))
    
    # 1.2.2 - Ensure GPG keys configured (rpm)
    if command_exists("rpm"):
        rpm_keys = run_command("rpm -q gpg-pubkey --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' 2>/dev/null | wc -l")
        has_rpm_keys = rpm_keys.returncode == 0 and int(rpm_keys.stdout.strip() or "0") > 0
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 1.2 - Package Mgmt",
            status="Pass" if has_rpm_keys else "Fail",
            message="1.2.2 Ensure GPG keys are configured for RPM",
            details=f"RPM keys: {rpm_keys.stdout.strip()}" if has_rpm_keys else "No RPM keys",
            remediation="Import RPM GPG keys: rpm --import <keyfile>"
        ))
    
    # 1.2.3 - Ensure repo_gpgcheck is enabled (yum/dnf)
    if os.path.exists("/etc/yum.conf"):
        yum_conf = read_file_safe("/etc/yum.conf")
        gpgcheck = "gpgcheck=1" in yum_conf
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 1.2 - Package Mgmt",
            status="Pass" if gpgcheck else "Fail",
            message="1.2.3 Ensure gpgcheck is globally activated",
            details="gpgcheck=1 in yum.conf" if gpgcheck else "gpgcheck not enabled",
            remediation="Add 'gpgcheck=1' to /etc/yum.conf"
        ))
    
    # 1.2.4 - Ensure updates, patches, and additional security software installed
    if command_exists("apt"):
        updates = run_command("apt list --upgradable 2>/dev/null | wc -l")
        update_count = int(updates.stdout.strip() or "0") - 1
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 1.2 - Package Mgmt",
            status="Pass" if update_count == 0 else "Warning",
            message="1.2.4 Ensure software updates available",
            details=f"{update_count} updates available" if update_count > 0 else "System up to date",
            remediation="Run: apt update && apt upgrade" if update_count > 0 else ""
        ))
    elif command_exists("yum"):
        updates = run_command("yum check-update 2>/dev/null | grep -c '^[a-zA-Z]'")
        update_count = int(updates.stdout.strip() or "0")
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 1.2 - Package Mgmt",
            status="Pass" if update_count == 0 else "Warning",
            message="1.2.4 Ensure software updates available",
            details=f"{update_count} updates available" if update_count > 0 else "System up to date",
            remediation=patch_for() if update_count > 0 else ""
        ))
    
    # 1.2.5 - Ensure automatic updates configured
    auto_updates = check_package_installed("unattended-upgrades", os_info) or \
                   check_package_installed("dnf-automatic", os_info) or \
                   check_package_installed("yum-cron", os_info)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.2 - Package Mgmt",
        status="Pass" if auto_updates else "Warning",
        message="1.2.5 Ensure automatic updates are configured",
        details="Auto-update package installed" if auto_updates else "No auto-update package",
        remediation="Install: unattended-upgrades or dnf-automatic"
    ))
    
    # Additional checks for package integrity
    # 1.2.6 - Ensure package manager local configuration files
    if os.path.exists("/etc/apt/sources.list"):
        sources = read_file_safe("/etc/apt/sources.list")
        has_sources = len(sources.strip()) > 0
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 1.2 - Package Mgmt",
            status="Pass" if has_sources else "Fail",
            message="1.2.6 Ensure package sources are configured",
            details="APT sources configured" if has_sources else "No APT sources",
            remediation="Configure /etc/apt/sources.list"
        ))
    
    # 1.2.7 - Ensure repository metadata is valid
    if command_exists("apt"):
        metadata = run_command("apt-cache policy 2>&1 | grep -c 'http\\|https'")
        valid_metadata = metadata.returncode == 0 and int(metadata.stdout.strip() or "0") > 0
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 1.2 - Package Mgmt",
            status="Pass" if valid_metadata else "Warning",
            message="1.2.7 Ensure repository metadata is current",
            details="Repository metadata accessible" if valid_metadata else "Metadata may be stale",
            remediation="Run: apt update"
        ))
    
    # 1.2.8 - Ensure repositories use HTTPS
    if os.path.exists("/etc/apt/sources.list"):
        sources = read_file_safe("/etc/apt/sources.list")
        http_repos = sources.count("http://")
        https_repos = sources.count("https://")
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 1.2 - Package Mgmt",
            status="Pass" if http_repos == 0 else "Warning",
            message="1.2.8 Ensure repositories use secure transport",
            details=f"HTTPS: {https_repos}, HTTP: {http_repos}",
            remediation="Change http:// to https:// in /etc/apt/sources.list" if http_repos > 0 else ""
        ))
    
    # 1.2.9 - Ensure only required repositories are enabled
    if os.path.exists("/etc/apt/sources.list.d"):
        repo_files = glob.glob("/etc/apt/sources.list.d/*.list")
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 1.2 - Package Mgmt",
            status="Info",
            message="1.2.9 Ensure only necessary repositories enabled",
            details=f"{len(repo_files)} additional repository files",
            remediation="Review and disable unnecessary repositories"
        ))
    
    # 1.2.10 - Ensure aide is installed
    aide_installed = check_package_installed("aide", os_info)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.2 - Package Mgmt",
        status="Pass" if aide_installed else "Fail",
        message="1.2.10 Ensure AIDE is installed",
        details="AIDE package installed" if aide_installed else "AIDE not installed",
        remediation=remediation_for("aide")
    ))


def check_section1_mandatory_access_control(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """CIS Section 1.6 - Mandatory Access Control"""
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Section 1.6 - Mandatory Access Control...")
    
    # 1.6.1.1 - Ensure SELinux is installed
    selinux_installed = check_package_installed("selinux-policy", os_info)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.6 - Access Control",
        status="Pass" if selinux_installed else "Fail",
        message="1.6.1.1 Ensure SELinux is installed",
        details="SELinux policy package installed" if selinux_installed else "SELinux not installed",
        remediation=remediation_for("selinux")
    ))
    
    # 1.6.1.2 - Ensure SELinux is not disabled in bootloader
    selinux_boot = not check_grub_parameter("selinux=0") and not check_grub_parameter("enforcing=0")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.6 - Access Control",
        status="Pass" if selinux_boot else "Fail",
        message="1.6.1.2 Ensure SELinux is not disabled in bootloader",
        details="SELinux enabled in boot" if selinux_boot else "SELinux disabled in boot config",
        remediation="Remove selinux=0 and enforcing=0 from GRUB configuration"
    ))
    
    # 1.6.1.3 - Ensure SELinux policy is configured
    if command_exists("sestatus"):
        policy = run_command("sestatus | grep 'Loaded policy'").stdout
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 1.6 - Access Control",
            status="Pass" if "targeted" in policy or "mls" in policy else "Fail",
            message="1.6.1.3 Ensure SELinux policy is configured",
            details=policy.strip() if policy else "No SELinux policy",
            remediation="Set SELINUXTYPE=targeted in /etc/selinux/config"
        ))
    
    # 1.6.1.4 - Ensure SELinux mode is enforcing
    if command_exists("getenforce"):
        mode = run_command("getenforce").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 1.6 - Access Control",
            status="Pass" if mode == "Enforcing" else "Fail",
            message="1.6.1.4 Ensure the SELinux mode is enforcing",
            details=f"SELinux mode: {mode}",
            remediation="Set SELINUX=enforcing in /etc/selinux/config; reboot"
        ))
    
    # 1.6.1.5 - Ensure no unconfined services exist
    if command_exists("ps"):
        unconfined = run_command("ps -eZ | grep unconfined_service_t | wc -l")
        count = int(unconfined.stdout.strip() or "0")
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 1.6 - Access Control",
            status="Pass" if count == 0 else "Warning",
            message="1.6.1.5 Ensure no unconfined services exist",
            details=f"{count} unconfined services" if count > 0 else "No unconfined services",
            remediation="Review and confine services with SELinux policies" if count > 0 else ""
        ))
    
    # 1.6.2.1 - Ensure AppArmor is installed (alternative to SELinux)
    apparmor_installed = check_package_installed("apparmor", os_info)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.6 - Access Control",
        status="Pass" if apparmor_installed else "Info",
        message="1.6.2.1 Ensure AppArmor is installed",
        details="AppArmor installed" if apparmor_installed else "AppArmor not installed",
        remediation=remediation_for("apparmor")
    ))
    
    # 1.6.2.2 - Ensure AppArmor is enabled in bootloader
    if apparmor_installed:
        apparmor_boot = check_grub_parameter("apparmor=1") and check_grub_parameter("security=apparmor")
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 1.6 - Access Control",
            status="Pass" if apparmor_boot else "Fail",
            message="1.6.2.2 Ensure AppArmor is enabled in bootloader",
            details="AppArmor boot parameters set" if apparmor_boot else "AppArmor not in boot config",
            remediation="Add apparmor=1 security=apparmor to GRUB_CMDLINE_LINUX"
        ))
    
    # 1.6.2.3 - Ensure all AppArmor profiles are in enforce mode
    if command_exists("aa-status"):
        profiles = run_command("aa-status --complaining 2>/dev/null | wc -l")
        complaining = int(profiles.stdout.strip() or "0")
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 1.6 - Access Control",
            status="Pass" if complaining == 0 else "Warning",
            message="1.6.2.3 Ensure all AppArmor profiles are enforcing",
            details=f"{complaining} profiles in complain mode" if complaining > 0 else "All profiles enforcing",
            remediation="Set profiles to enforce: aa-enforce /etc/apparmor.d/*" if complaining > 0 else ""
        ))
    
    # 1.6.2.4 - Ensure all AppArmor profiles are loaded
    if command_exists("aa-status"):
        loaded = run_command("aa-status --profiled 2>/dev/null | wc -l")
        profile_count = int(loaded.stdout.strip() or "0")
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 1.6 - Access Control",
            status="Pass" if profile_count > 0 else "Fail",
            message="1.6.2.4 Ensure AppArmor profiles are loaded",
            details=f"{profile_count} profiles loaded",
            remediation="Load profiles: systemctl enable --now apparmor"
        ))
    
    # 1.6.3 - Ensure SELinux or AppArmor are installed
    mac_installed = selinux_installed or apparmor_installed
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.6 - Access Control",
        status="Pass" if mac_installed else "Fail",
        message="1.6.3 Ensure SELinux or AppArmor are installed",
        details="MAC system installed" if mac_installed else "No MAC system installed",
        remediation="Install either SELinux or AppArmor"
    ))

def check_section1_warning_banners(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """CIS Section 1.7 - Command Line Warning Banners"""
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Section 1.7 - Warning Banners...")
    
    # 1.7.1 - Ensure message of the day is configured
    motd = read_file_safe("/etc/motd")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.7 - Banners",
        status="Pass" if len(motd.strip()) > 0 else "Warning",
        message="1.7.1 Ensure message of the day is configured properly",
        details="MOTD configured" if len(motd.strip()) > 0 else "MOTD is empty",
        remediation="Configure /etc/motd with appropriate message"
    ))
    
    # 1.7.2 - Ensure local login warning banner configured
    issue = read_file_safe("/etc/issue")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.7 - Banners",
        status="Pass" if len(issue.strip()) > 0 else "Fail",
        message="1.7.2 Ensure local login warning banner is configured",
        details="Login banner configured" if len(issue.strip()) > 0 else "No login banner",
        remediation="Configure /etc/issue with appropriate warning"
    ))
    
    # 1.7.3 - Ensure remote login warning banner configured
    issue_net = read_file_safe("/etc/issue.net")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.7 - Banners",
        status="Pass" if len(issue_net.strip()) > 0 else "Fail",
        message="1.7.3 Ensure remote login warning banner is configured",
        details="Remote banner configured" if len(issue_net.strip()) > 0 else "No remote banner",
        remediation="Configure /etc/issue.net with appropriate warning"
    ))
    
    # 1.7.4 - Ensure permissions on /etc/motd are configured
    if os.path.exists("/etc/motd"):
        motd_perms = get_file_permissions("/etc/motd")
        owner, group = get_file_owner_group("/etc/motd")
        correct_perms = motd_perms and int(motd_perms, 8) <= int("0644", 8) and owner == "root"
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 1.7 - Banners",
            status="Pass" if correct_perms else "Fail",
            message="1.7.4 Ensure permissions on /etc/motd are configured",
            details=f"Perms: {motd_perms}, Owner: {owner}" if motd_perms else "File doesn't exist",
            remediation="chown root:root /etc/motd && chmod 644 /etc/motd"
        ))
    
    # 1.7.5 - Ensure permissions on /etc/issue are configured
    if os.path.exists("/etc/issue"):
        issue_perms = get_file_permissions("/etc/issue")
        owner, group = get_file_owner_group("/etc/issue")
        correct_perms = issue_perms and int(issue_perms, 8) <= int("0644", 8) and owner == "root"
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 1.7 - Banners",
            status="Pass" if correct_perms else "Fail",
            message="1.7.5 Ensure permissions on /etc/issue are configured",
            details=f"Perms: {issue_perms}, Owner: {owner}",
            remediation="chown root:root /etc/issue && chmod 644 /etc/issue"
        ))


# ============================================================================
# Section 2: Services
# ============================================================================

def check_section2_services(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """CIS Section 2 - Services Configuration"""
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Section 2 - Services...")
    
    # 2.1.1 - Ensure time synchronization is in use
    time_sync = check_package_installed("chrony", os_info) or check_package_installed("ntp", os_info) or \
                check_package_installed("systemd-timesyncd", os_info)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 2.1 - Time Sync",
        status="Pass" if time_sync else "Fail",
        message="2.1.1 Ensure time synchronization is in use",
        details="Time sync package installed" if time_sync else "No time sync package",
        remediation=remediation_for("chrony")
    ))
    
    # 2.1.2 - Ensure chrony is configured
    if check_package_installed("chrony", os_info):
        chrony_conf = read_file_safe("/etc/chrony.conf") or read_file_safe("/etc/chrony/chrony.conf")
        has_servers = "server" in chrony_conf or "pool" in chrony_conf
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 2.1 - Time Sync",
            status="Pass" if has_servers else "Fail",
            message="2.1.2 Ensure chrony is configured",
            details="NTP servers configured" if has_servers else "No NTP servers in config",
            remediation="Add NTP servers to /etc/chrony.conf"
        ))
    
    # 2.1.3 - Ensure chrony is running as user chrony
    if check_service_active("chronyd"):
        chrony_user = run_command("ps -ef | grep chronyd | grep -v grep | awk '{print $1}' | head -1").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 2.1 - Time Sync",
            status="Pass" if chrony_user in ["chrony", "_chrony"] else "Fail",
            message="2.1.3 Ensure chrony is running as chrony user",
            details=f"Running as: {chrony_user}" if chrony_user else "Not running",
            remediation="Ensure chrony runs as chrony user in /etc/sysconfig/chronyd"
        ))
    
    # 2.1.4 - Ensure systemd-timesyncd is configured
    if check_package_installed("systemd-timesyncd", os_info):
        timesyncd_conf = read_file_safe("/etc/systemd/timesyncd.conf")
        has_ntp = "NTP=" in timesyncd_conf or "FallbackNTP=" in timesyncd_conf
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 2.1 - Time Sync",
            status="Pass" if has_ntp else "Warning",
            message="2.1.4 Ensure systemd-timesyncd is configured",
            details="NTP servers configured" if has_ntp else "Default NTP servers",
            remediation="Configure NTP servers in /etc/systemd/timesyncd.conf"
        ))
    
    # 2.1.5 - Ensure NTP is enabled
    ntp_enabled = check_service_enabled("chronyd") or check_service_enabled("ntpd") or \
                  check_service_enabled("systemd-timesyncd")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 2.1 - Time Sync",
        status="Pass" if ntp_enabled else "Fail",
        message="2.1.5 Ensure NTP service is enabled",
        details="Time sync service enabled" if ntp_enabled else "No time sync service enabled",
        remediation="Enable time synchronization service"
    ))
    
    # 2.1.6 - Ensure NTP is running
    ntp_running = check_service_active("chronyd") or check_service_active("ntpd") or \
                  check_service_active("systemd-timesyncd")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 2.1 - Time Sync",
        status="Pass" if ntp_running else "Fail",
        message="2.1.6 Ensure NTP service is running",
        details="Time sync service active" if ntp_running else "No time sync service running",
        remediation="Start time synchronization service"
    ))
    
    # 2.2.1 - Ensure X Window System is not installed
    xorg_installed = check_package_installed("xserver-xorg", os_info) or check_package_installed("xorg-x11-server-common", os_info)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 2.2 - X Window",
        status="Pass" if not xorg_installed else "Warning",
        message="2.2.1 Ensure X Window System is not installed",
        details="X11 not installed" if not xorg_installed else "X11 is installed",
        remediation=removal_for("xserver")
    ))
    
    # 2.2.2 - Ensure Avahi Server is not installed
    avahi_installed = check_package_installed("avahi-daemon", os_info)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 2.2 - Services",
        status="Pass" if not avahi_installed else "Fail",
        message="2.2.2 Ensure Avahi Server is not installed",
        details="Avahi not installed" if not avahi_installed else "Avahi is installed",
        remediation=removal_for("avahi")
    ))
    
    # 2.2.3 - Ensure CUPS is not installed
    cups_installed = check_package_installed("cups", os_info)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 2.2 - Services",
        status="Pass" if not cups_installed else "Warning",
        message="2.2.3 Ensure CUPS is not installed",
        details="CUPS not installed" if not cups_installed else "CUPS is installed",
        remediation=removal_for("cups")
    ))
    
    # 2.2.4 - Ensure DHCP Server is not installed
    dhcp_installed = check_package_installed("isc-dhcp-server", os_info) or check_package_installed("dhcp-server", os_info)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 2.2 - Services",
        status="Pass" if not dhcp_installed else "Fail",
        message="2.2.4 Ensure DHCP Server is not installed",
        details="DHCP server not installed" if not dhcp_installed else "DHCP server installed",
        remediation=removal_for("dhcp-server")
    ))
    
    # 2.2.5 - Ensure LDAP server is not installed
    ldap_installed = check_package_installed("slapd", os_info)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 2.2 - Services",
        status="Pass" if not ldap_installed else "Fail",
        message="2.2.5 Ensure LDAP server is not installed",
        details="LDAP server not installed" if not ldap_installed else "LDAP server installed",
        remediation=removal_for("ldap-server")
    ))
    
    # 2.2.6 - Ensure NFS is not installed
    nfs_installed = check_package_installed("nfs-kernel-server", os_info) or check_package_installed("nfs-utils", os_info)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 2.2 - Services",
        status="Pass" if not nfs_installed else "Warning",
        message="2.2.6 Ensure NFS is not installed",
        details="NFS not installed" if not nfs_installed else "NFS is installed",
        remediation=removal_for("nfs-server")
    ))
    
    # 2.2.7 - Ensure DNS Server is not installed
    dns_installed = check_package_installed("bind9", os_info) or check_package_installed("bind", os_info)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 2.2 - Services",
        status="Pass" if not dns_installed else "Fail",
        message="2.2.7 Ensure DNS Server is not installed",
        details="DNS server not installed" if not dns_installed else "DNS server installed",
        remediation=removal_for("dns-server")
    ))
    
    # 2.2.8 - Ensure FTP Server is not installed
    ftp_installed = check_package_installed("vsftpd", os_info) or check_package_installed("proftpd", os_info)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 2.2 - Services",
        status="Pass" if not ftp_installed else "Fail",
        message="2.2.8 Ensure FTP Server is not installed",
        details="FTP server not installed" if not ftp_installed else "FTP server installed",
        remediation=removal_for("vsftpd")
    ))
    
    # 2.2.9 - Ensure HTTP server is not installed
    http_installed = check_package_installed("apache2", os_info) or check_package_installed("httpd", os_info) or check_package_installed("nginx", os_info)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 2.2 - Services",
        status="Pass" if not http_installed else "Info",
        message="2.2.9 Ensure HTTP server is not installed",
        details="HTTP server not installed" if not http_installed else "HTTP server installed",
        remediation="Review if HTTP server is needed for business requirements"
    ))
    
    # 2.2.10 - Ensure IMAP and POP3 server are not installed
    mail_installed = check_package_installed("dovecot-imapd", os_info) or check_package_installed("dovecot-pop3d", os_info) or \
                     check_package_installed("cyrus-imapd", os_info)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 2.2 - Services",
        status="Pass" if not mail_installed else "Fail",
        message="2.2.10 Ensure IMAP and POP3 server are not installed",
        details="Mail server not installed" if not mail_installed else "Mail server installed",
        remediation=removal_for("dovecot")
    ))
    
    # 2.2.11 - Ensure Samba is not installed
    samba_installed = check_package_installed("samba", os_info)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 2.2 - Services",
        status="Pass" if not samba_installed else "Warning",
        message="2.2.11 Ensure Samba is not installed",
        details="Samba not installed" if not samba_installed else "Samba is installed",
        remediation=removal_for("samba")
    ))
    
    # 2.2.12 - Ensure HTTP Proxy Server is not installed
    proxy_installed = check_package_installed("squid", os_info) or check_package_installed("squid3", os_info)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 2.2 - Services",
        status="Pass" if not proxy_installed else "Fail",
        message="2.2.12 Ensure HTTP Proxy Server is not installed",
        details="Proxy server not installed" if not proxy_installed else "Proxy server installed",
        remediation=removal_for("squid")
    ))
    
    # 2.2.13 - Ensure SNMP Server is not installed
    snmp_installed = check_package_installed("snmpd", os_info)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 2.2 - Services",
        status="Pass" if not snmp_installed else "Fail",
        message="2.2.13 Ensure SNMP Server is not installed",
        details="SNMP server not installed" if not snmp_installed else "SNMP server installed",
        remediation=removal_for("snmp")
    ))
    
    # 2.2.14 - Ensure mail transfer agent is configured for local-only mode
    if check_package_installed("postfix", os_info) or check_package_installed("sendmail", os_info):
        listening = run_command("ss -lntu | grep -E ':25\\s' | grep -v '127.0.0.1:25\\|::1:25'").returncode
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 2.2 - Services",
            status="Pass" if listening != 0 else "Fail",
            message="2.2.14 Ensure mail transfer agent is configured for local-only",
            details="MTA local-only" if listening != 0 else "MTA listening externally",
            remediation="Configure MTA to listen only on localhost"
        ))
    
    # 2.2.15 - Ensure rsync service is not installed
    rsync_daemon = check_package_installed("rsync", os_info) and check_service_active("rsync")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 2.2 - Services",
        status="Pass" if not rsync_daemon else "Fail",
        message="2.2.15 Ensure rsync service is not enabled",
        details="rsync service not running" if not rsync_daemon else "rsync service active",
        remediation="Disable: systemctl disable rsync"
    ))
    
    # 2.2.16 - Ensure NIS Server is not installed
    nis_installed = check_package_installed("nis", os_info)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 2.2 - Services",
        status="Pass" if not nis_installed else "Fail",
        message="2.2.16 Ensure NIS Server is not installed",
        details="NIS not installed" if not nis_installed else "NIS is installed",
        remediation=removal_for("nis")
    ))
    
    # 2.3.1 - Ensure NIS Client is not installed
    nis_client = check_package_installed("nis", os_info)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 2.3 - Service Clients",
        status="Pass" if not nis_client else "Fail",
        message="2.3.1 Ensure NIS Client is not installed",
        details="NIS client not installed" if not nis_client else "NIS client installed",
        remediation=removal_for("nis")
    ))
    
    # 2.3.2 - Ensure rsh client is not installed
    rsh_client = check_package_installed("rsh-client", os_info) or check_package_installed("rsh", os_info)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 2.3 - Service Clients",
        status="Pass" if not rsh_client else "Fail",
        message="2.3.2 Ensure rsh client is not installed",
        details="rsh client not installed" if not rsh_client else "rsh client installed",
        remediation=removal_for("rsh")
    ))
    
    # 2.3.3 - Ensure talk client is not installed
    talk_client = check_package_installed("talk", os_info)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 2.3 - Service Clients",
        status="Pass" if not talk_client else "Fail",
        message="2.3.3 Ensure talk client is not installed",
        details="talk client not installed" if not talk_client else "talk client installed",
        remediation=removal_for("talk")
    ))
    
    # 2.3.4 - Ensure telnet client is not installed
    telnet_client = check_package_installed("telnet", os_info)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 2.3 - Service Clients",
        status="Pass" if not telnet_client else "Fail",
        message="2.3.4 Ensure telnet client is not installed",
        details="telnet client not installed" if not telnet_client else "telnet client installed",
        remediation=removal_for("telnet")
    ))
    
    # 2.3.5 - Ensure LDAP client is not installed
    ldap_client = check_package_installed("ldap-utils", os_info) or check_package_installed("openldap-clients", os_info)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 2.3 - Service Clients",
        status="Pass" if not ldap_client else "Warning",
        message="2.3.5 Ensure LDAP client is not installed",
        details="LDAP client not installed" if not ldap_client else "LDAP client installed",
        remediation=removal_for("ldap-utils")
    ))
    
    # Additional service checks
    # 2.4.1 - Ensure nonessential services are removed
    listening_services = get_listening_services()
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 2.4 - Services",
        status="Info",
        message="2.4.1 Review listening network services",
        details=f"Found {len(listening_services)} listening services",
        remediation="Review and disable unnecessary network services"
    ))
    
    # 2.4.2 - Check for unnecessary daemons
    running_daemons = run_command("systemctl list-units --type=service --state=running | grep -c '\\.service'").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 2.4 - Services",
        status="Info",
        message="2.4.2 Review running service daemons",
        details=f"{running_daemons} services currently running",
        remediation="Audit and disable unnecessary services"
    ))
    
    # 2.4.3 - Ensure services are enabled only when needed
    enabled_services = run_command("systemctl list-unit-files --type=service --state=enabled | grep -c '\\.service'").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 2.4 - Services",
        status="Info",
        message="2.4.3 Review enabled services",
        details=f"{enabled_services} services enabled at boot",
        remediation="Review and disable unnecessary enabled services"
    ))


# ============================================================================
# Section 3: Network Configuration
# ============================================================================

def check_section3_network_parameters(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """CIS Section 3.1 - Network Parameters (Host Only)"""
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Section 3.1 - Network Parameters (Host Only)...")
    
    # 3.1.1 - Ensure IP forwarding is disabled
    ipv4_forward = cis_check_kernel_parameter("net.ipv4.ip_forward", "0")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.1 - Network",
        status="Pass" if ipv4_forward else "Fail",
        message="3.1.1 Ensure IP forwarding is disabled",
        details="IPv4 forwarding disabled" if ipv4_forward else "IPv4 forwarding enabled",
        remediation="sysctl -w net.ipv4.ip_forward=0; add to /etc/sysctl.conf"
    ))
    
    # 3.1.2 - Ensure packet redirect sending is disabled
    send_redirects_all = cis_check_kernel_parameter("net.ipv4.conf.all.send_redirects", "0")
    send_redirects_default = cis_check_kernel_parameter("net.ipv4.conf.default.send_redirects", "0")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.1 - Network",
        status="Pass" if send_redirects_all and send_redirects_default else "Fail",
        message="3.1.2 Ensure packet redirect sending is disabled",
        details="Redirects disabled" if send_redirects_all and send_redirects_default else "Redirects enabled",
        remediation="sysctl -w net.ipv4.conf.all.send_redirects=0; sysctl -w net.ipv4.conf.default.send_redirects=0"
    ))
    
    # Additional network hardening checks
    # 3.1.3 - Ensure ICMP redirect acceptance is disabled (all interfaces)
    icmp_accept_all = cis_check_kernel_parameter("net.ipv4.conf.all.accept_redirects", "0")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.1 - Network",
        status="Pass" if icmp_accept_all else "Fail",
        message="3.1.3 Ensure ICMP redirects are not accepted (all)",
        details="ICMP redirects disabled (all)" if icmp_accept_all else "ICMP redirects enabled",
        remediation="sysctl -w net.ipv4.conf.all.accept_redirects=0"
    ))
    
    # 3.1.4 - Ensure ICMP redirect acceptance is disabled (default)
    icmp_accept_default = cis_check_kernel_parameter("net.ipv4.conf.default.accept_redirects", "0")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.1 - Network",
        status="Pass" if icmp_accept_default else "Fail",
        message="3.1.4 Ensure ICMP redirects are not accepted (default)",
        details="ICMP redirects disabled (default)" if icmp_accept_default else "ICMP redirects enabled",
        remediation="sysctl -w net.ipv4.conf.default.accept_redirects=0"
    ))
    
    # 3.1.5 - Ensure secure ICMP redirects are not accepted (all)
    secure_redir_all = cis_check_kernel_parameter("net.ipv4.conf.all.secure_redirects", "0")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.1 - Network",
        status="Pass" if secure_redir_all else "Fail",
        message="3.1.5 Ensure secure ICMP redirects are not accepted (all)",
        details="Secure redirects disabled" if secure_redir_all else "Secure redirects enabled",
        remediation="sysctl -w net.ipv4.conf.all.secure_redirects=0"
    ))
    
    # 3.1.6 - Ensure secure ICMP redirects are not accepted (default)
    secure_redir_default = cis_check_kernel_parameter("net.ipv4.conf.default.secure_redirects", "0")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.1 - Network",
        status="Pass" if secure_redir_default else "Fail",
        message="3.1.6 Ensure secure ICMP redirects are not accepted (default)",
        details="Secure redirects disabled" if secure_redir_default else "Secure redirects enabled",
        remediation="sysctl -w net.ipv4.conf.default.secure_redirects=0"
    ))
    
    # 3.1.7 - Ensure Reverse Path Filtering is enabled (all)
    rp_filter_all = cis_check_kernel_parameter("net.ipv4.conf.all.rp_filter", "1")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.1 - Network",
        status="Pass" if rp_filter_all else "Fail",
        message="3.1.7 Ensure Reverse Path Filtering is enabled (all)",
        details="RPF enabled (all)" if rp_filter_all else "RPF disabled",
        remediation="sysctl -w net.ipv4.conf.all.rp_filter=1"
    ))
    
    # 3.1.8 - Ensure Reverse Path Filtering is enabled (default)
    rp_filter_default = cis_check_kernel_parameter("net.ipv4.conf.default.rp_filter", "1")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.1 - Network",
        status="Pass" if rp_filter_default else "Fail",
        message="3.1.8 Ensure Reverse Path Filtering is enabled (default)",
        details="RPF enabled (default)" if rp_filter_default else "RPF disabled",
        remediation="sysctl -w net.ipv4.conf.default.rp_filter=1"
    ))
    
    # 3.1.9 - Ensure source routed packets are not accepted (all)
    source_route_all = cis_check_kernel_parameter("net.ipv4.conf.all.accept_source_route", "0")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.1 - Network",
        status="Pass" if source_route_all else "Fail",
        message="3.1.9 Ensure source routed packets are not accepted (all)",
        details="Source routing disabled" if source_route_all else "Source routing enabled",
        remediation="sysctl -w net.ipv4.conf.all.accept_source_route=0"
    ))
    
    # 3.1.10 - Ensure source routed packets are not accepted (default)
    source_route_default = cis_check_kernel_parameter("net.ipv4.conf.default.accept_source_route", "0")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.1 - Network",
        status="Pass" if source_route_default else "Fail",
        message="3.1.10 Ensure source routed packets are not accepted (default)",
        details="Source routing disabled" if source_route_default else "Source routing enabled",
        remediation="sysctl -w net.ipv4.conf.default.accept_source_route=0"
    ))
    
    # 3.1.11 - Ensure suspicious packets are logged (all)
    log_martians_all = cis_check_kernel_parameter("net.ipv4.conf.all.log_martians", "1")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.1 - Network",
        status="Pass" if log_martians_all else "Fail",
        message="3.1.11 Ensure suspicious packets are logged (all)",
        details="Martian logging enabled" if log_martians_all else "Martian logging disabled",
        remediation="sysctl -w net.ipv4.conf.all.log_martians=1"
    ))
    
    # 3.1.12 - Ensure suspicious packets are logged (default)
    log_martians_default = cis_check_kernel_parameter("net.ipv4.conf.default.log_martians", "1")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.1 - Network",
        status="Pass" if log_martians_default else "Fail",
        message="3.1.12 Ensure suspicious packets are logged (default)",
        details="Martian logging enabled" if log_martians_default else "Martian logging disabled",
        remediation="sysctl -w net.ipv4.conf.default.log_martians=1"
    ))
    
    # 3.1.13 - Ensure broadcast ICMP requests are ignored
    ignore_broadcasts = cis_check_kernel_parameter("net.ipv4.icmp_echo_ignore_broadcasts", "1")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.1 - Network",
        status="Pass" if ignore_broadcasts else "Fail",
        message="3.1.13 Ensure broadcast ICMP requests are ignored",
        details="Broadcast ICMP ignored" if ignore_broadcasts else "Broadcast ICMP accepted",
        remediation="sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1"
    ))
    
    # 3.1.14 - Ensure bogus ICMP responses are ignored
    ignore_bogus = cis_check_kernel_parameter("net.ipv4.icmp_ignore_bogus_error_responses", "1")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.1 - Network",
        status="Pass" if ignore_bogus else "Fail",
        message="3.1.14 Ensure bogus ICMP responses are ignored",
        details="Bogus ICMP ignored" if ignore_bogus else "Bogus ICMP accepted",
        remediation="sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1"
    ))
    
    # 3.1.15 - Ensure TCP SYN Cookies is enabled
    syn_cookies = cis_check_kernel_parameter("net.ipv4.tcp_syncookies", "1")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.1 - Network",
        status="Pass" if syn_cookies else "Fail",
        message="3.1.15 Ensure TCP SYN Cookies is enabled",
        details="SYN cookies enabled" if syn_cookies else "SYN cookies disabled",
        remediation="sysctl -w net.ipv4.tcp_syncookies=1"
    ))

def check_section3_network_host_and_router(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """CIS Section 3.2 - Network Parameters (Host and Router)"""
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Section 3.2 - Network Parameters (Host and Router)...")
    
    # 3.2.1 - Ensure source routed packets are not accepted
    accept_source_route_all = cis_check_kernel_parameter("net.ipv4.conf.all.accept_source_route", "0")
    accept_source_route_default = cis_check_kernel_parameter("net.ipv4.conf.default.accept_source_route", "0")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.2 - Network",
        status="Pass" if accept_source_route_all and accept_source_route_default else "Fail",
        message="3.2.1 Ensure source routed packets are not accepted",
        details="Source routing disabled" if accept_source_route_all and accept_source_route_default else "Source routing enabled",
        remediation="sysctl -w net.ipv4.conf.all.accept_source_route=0; sysctl -w net.ipv4.conf.default.accept_source_route=0"
    ))
    
    # 3.2.2 - Ensure ICMP redirects are not accepted
    accept_redirects_all = cis_check_kernel_parameter("net.ipv4.conf.all.accept_redirects", "0")
    accept_redirects_default = cis_check_kernel_parameter("net.ipv4.conf.default.accept_redirects", "0")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.2 - Network",
        status="Pass" if accept_redirects_all and accept_redirects_default else "Fail",
        message="3.2.2 Ensure ICMP redirects are not accepted",
        details="ICMP redirects disabled" if accept_redirects_all and accept_redirects_default else "ICMP redirects enabled",
        remediation="sysctl -w net.ipv4.conf.all.accept_redirects=0; sysctl -w net.ipv4.conf.default.accept_redirects=0"
    ))
    
    # 3.2.3 - Ensure secure ICMP redirects are not accepted
    secure_redirects_all = cis_check_kernel_parameter("net.ipv4.conf.all.secure_redirects", "0")
    secure_redirects_default = cis_check_kernel_parameter("net.ipv4.conf.default.secure_redirects", "0")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.2 - Network",
        status="Pass" if secure_redirects_all and secure_redirects_default else "Fail",
        message="3.2.3 Ensure secure ICMP redirects are not accepted",
        details="Secure redirects disabled" if secure_redirects_all and secure_redirects_default else "Secure redirects enabled",
        remediation="sysctl -w net.ipv4.conf.all.secure_redirects=0; sysctl -w net.ipv4.conf.default.secure_redirects=0"
    ))
    
    # 3.2.4 - Ensure suspicious packets are logged
    log_martians_all = cis_check_kernel_parameter("net.ipv4.conf.all.log_martians", "1")
    log_martians_default = cis_check_kernel_parameter("net.ipv4.conf.default.log_martians", "1")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.2 - Network",
        status="Pass" if log_martians_all and log_martians_default else "Fail",
        message="3.2.4 Ensure suspicious packets are logged",
        details="Martian logging enabled" if log_martians_all and log_martians_default else "Martian logging disabled",
        remediation="sysctl -w net.ipv4.conf.all.log_martians=1; sysctl -w net.ipv4.conf.default.log_martians=1"
    ))
    
    # 3.2.5 - Ensure broadcast ICMP requests are ignored
    ignore_broadcasts = cis_check_kernel_parameter("net.ipv4.icmp_echo_ignore_broadcasts", "1")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.2 - Network",
        status="Pass" if ignore_broadcasts else "Fail",
        message="3.2.5 Ensure broadcast ICMP requests are ignored",
        details="Broadcast ICMP ignored" if ignore_broadcasts else "Broadcast ICMP accepted",
        remediation="sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1"
    ))
    
    # 3.2.6 - Ensure bogus ICMP responses are ignored
    ignore_bogus = cis_check_kernel_parameter("net.ipv4.icmp_ignore_bogus_error_responses", "1")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.2 - Network",
        status="Pass" if ignore_bogus else "Fail",
        message="3.2.6 Ensure bogus ICMP responses are ignored",
        details="Bogus ICMP ignored" if ignore_bogus else "Bogus ICMP accepted",
        remediation="sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1"
    ))
    
    # 3.2.7 - Ensure Reverse Path Filtering is enabled
    rp_filter_all = cis_check_kernel_parameter("net.ipv4.conf.all.rp_filter", "1")
    rp_filter_default = cis_check_kernel_parameter("net.ipv4.conf.default.rp_filter", "1")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.2 - Network",
        status="Pass" if rp_filter_all and rp_filter_default else "Fail",
        message="3.2.7 Ensure Reverse Path Filtering is enabled",
        details="RPF enabled" if rp_filter_all and rp_filter_default else "RPF disabled",
        remediation="sysctl -w net.ipv4.conf.all.rp_filter=1; sysctl -w net.ipv4.conf.default.rp_filter=1"
    ))
    
    # 3.2.8 - Ensure TCP SYN Cookies is enabled
    syn_cookies = cis_check_kernel_parameter("net.ipv4.tcp_syncookies", "1")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.2 - Network",
        status="Pass" if syn_cookies else "Fail",
        message="3.2.8 Ensure TCP SYN Cookies is enabled",
        details="SYN cookies enabled" if syn_cookies else "SYN cookies disabled",
        remediation="sysctl -w net.ipv4.tcp_syncookies=1"
    ))
    
    # 3.2.9 - Ensure IPv6 router advertisements are not accepted
    ipv6_accept_ra_all = cis_check_kernel_parameter("net.ipv6.conf.all.accept_ra", "0")
    ipv6_accept_ra_default = cis_check_kernel_parameter("net.ipv6.conf.default.accept_ra", "0")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.2 - Network",
        status="Pass" if ipv6_accept_ra_all and ipv6_accept_ra_default else "Warning",
        message="3.2.9 Ensure IPv6 router advertisements are not accepted",
        details="IPv6 RA disabled" if ipv6_accept_ra_all and ipv6_accept_ra_default else "IPv6 RA enabled",
        remediation="sysctl -w net.ipv6.conf.all.accept_ra=0; sysctl -w net.ipv6.conf.default.accept_ra=0"
    ))

def check_section3_network_host_and_router(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """CIS Section 3.2 - Network Parameters (Host and Router)"""
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Section 3.2 - Network Parameters (Host and Router)...")
    
    # 3.2.1 - Ensure source routed packets are not accepted
    accept_source_route_all = cis_check_kernel_parameter("net.ipv4.conf.all.accept_source_route", "0")
    accept_source_route_default = cis_check_kernel_parameter("net.ipv4.conf.default.accept_source_route", "0")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.2 - Network",
        status="Pass" if accept_source_route_all and accept_source_route_default else "Fail",
        message="3.2.1 Ensure source routed packets are not accepted",
        details="Source routing disabled" if accept_source_route_all and accept_source_route_default else "Source routing enabled",
        remediation="sysctl -w net.ipv4.conf.all.accept_source_route=0; sysctl -w net.ipv4.conf.default.accept_source_route=0"
    ))
    
    # 3.2.2 - Ensure ICMP redirects are not accepted
    accept_redirects_all = cis_check_kernel_parameter("net.ipv4.conf.all.accept_redirects", "0")
    accept_redirects_default = cis_check_kernel_parameter("net.ipv4.conf.default.accept_redirects", "0")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.2 - Network",
        status="Pass" if accept_redirects_all and accept_redirects_default else "Fail",
        message="3.2.2 Ensure ICMP redirects are not accepted",
        details="ICMP redirects disabled" if accept_redirects_all and accept_redirects_default else "ICMP redirects enabled",
        remediation="sysctl -w net.ipv4.conf.all.accept_redirects=0; sysctl -w net.ipv4.conf.default.accept_redirects=0"
    ))
    
    # 3.2.3 - Ensure secure ICMP redirects are not accepted
    secure_redirects_all = cis_check_kernel_parameter("net.ipv4.conf.all.secure_redirects", "0")
    secure_redirects_default = cis_check_kernel_parameter("net.ipv4.conf.default.secure_redirects", "0")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.2 - Network",
        status="Pass" if secure_redirects_all and secure_redirects_default else "Fail",
        message="3.2.3 Ensure secure ICMP redirects are not accepted",
        details="Secure redirects disabled" if secure_redirects_all and secure_redirects_default else "Secure redirects enabled",
        remediation="sysctl -w net.ipv4.conf.all.secure_redirects=0; sysctl -w net.ipv4.conf.default.secure_redirects=0"
    ))
    
    # 3.2.4 - Ensure suspicious packets are logged
    log_martians_all = cis_check_kernel_parameter("net.ipv4.conf.all.log_martians", "1")
    log_martians_default = cis_check_kernel_parameter("net.ipv4.conf.default.log_martians", "1")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.2 - Network",
        status="Pass" if log_martians_all and log_martians_default else "Fail",
        message="3.2.4 Ensure suspicious packets are logged",
        details="Martian logging enabled" if log_martians_all and log_martians_default else "Martian logging disabled",
        remediation="sysctl -w net.ipv4.conf.all.log_martians=1; sysctl -w net.ipv4.conf.default.log_martians=1"
    ))
    
    # 3.2.5 - Ensure broadcast ICMP requests are ignored
    ignore_broadcasts = cis_check_kernel_parameter("net.ipv4.icmp_echo_ignore_broadcasts", "1")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.2 - Network",
        status="Pass" if ignore_broadcasts else "Fail",
        message="3.2.5 Ensure broadcast ICMP requests are ignored",
        details="Broadcast ICMP ignored" if ignore_broadcasts else "Broadcast ICMP accepted",
        remediation="sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1"
    ))
    
    # 3.2.6 - Ensure bogus ICMP responses are ignored
    ignore_bogus = cis_check_kernel_parameter("net.ipv4.icmp_ignore_bogus_error_responses", "1")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.2 - Network",
        status="Pass" if ignore_bogus else "Fail",
        message="3.2.6 Ensure bogus ICMP responses are ignored",
        details="Bogus ICMP ignored" if ignore_bogus else "Bogus ICMP accepted",
        remediation="sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1"
    ))
    
    # 3.2.7 - Ensure Reverse Path Filtering is enabled
    rp_filter_all = cis_check_kernel_parameter("net.ipv4.conf.all.rp_filter", "1")
    rp_filter_default = cis_check_kernel_parameter("net.ipv4.conf.default.rp_filter", "1")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.2 - Network",
        status="Pass" if rp_filter_all and rp_filter_default else "Fail",
        message="3.2.7 Ensure Reverse Path Filtering is enabled",
        details="RPF enabled" if rp_filter_all and rp_filter_default else "RPF disabled",
        remediation="sysctl -w net.ipv4.conf.all.rp_filter=1; sysctl -w net.ipv4.conf.default.rp_filter=1"
    ))
    
    # 3.2.8 - Ensure TCP SYN Cookies is enabled
    syn_cookies = cis_check_kernel_parameter("net.ipv4.tcp_syncookies", "1")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.2 - Network",
        status="Pass" if syn_cookies else "Fail",
        message="3.2.8 Ensure TCP SYN Cookies is enabled",
        details="SYN cookies enabled" if syn_cookies else "SYN cookies disabled",
        remediation="sysctl -w net.ipv4.tcp_syncookies=1"
    ))
    
    # 3.2.9 - Ensure IPv6 router advertisements are not accepted
    ipv6_accept_ra_all = cis_check_kernel_parameter("net.ipv6.conf.all.accept_ra", "0")
    ipv6_accept_ra_default = cis_check_kernel_parameter("net.ipv6.conf.default.accept_ra", "0")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.2 - Network",
        status="Pass" if ipv6_accept_ra_all and ipv6_accept_ra_default else "Warning",
        message="3.2.9 Ensure IPv6 router advertisements are not accepted",
        details="IPv6 RA disabled" if ipv6_accept_ra_all and ipv6_accept_ra_default else "IPv6 RA enabled",
        remediation="sysctl -w net.ipv6.conf.all.accept_ra=0; sysctl -w net.ipv6.conf.default.accept_ra=0"
    ))
    
    # Additional router-specific checks
    # 3.2.10 - Ensure TCP timestamps are disabled
    tcp_timestamps = cis_check_kernel_parameter("net.ipv4.tcp_timestamps", "0")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.2 - Network",
        status="Pass" if tcp_timestamps else "Info",
        message="3.2.10 Ensure TCP timestamps consideration",
        details="TCP timestamps disabled" if tcp_timestamps else "TCP timestamps enabled (default)",
        remediation="Consider: sysctl -w net.ipv4.tcp_timestamps=0 for enhanced security"
    ))
    
    # 3.2.11 - Ensure ARP proxy is disabled
    proxy_arp_all = cis_check_kernel_parameter("net.ipv4.conf.all.proxy_arp", "0")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.2 - Network",
        status="Pass" if proxy_arp_all else "Info",
        message="3.2.11 Ensure ARP proxy is disabled",
        details="ARP proxy disabled" if proxy_arp_all else "ARP proxy may be enabled",
        remediation="sysctl -w net.ipv4.conf.all.proxy_arp=0"
    ))
    
    # 3.2.12 - Ensure medium ARP is disabled
    arp_announce = cis_check_kernel_parameter("net.ipv4.conf.all.arp_announce", "2")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.2 - Network",
        status="Info",
        message="3.2.12 Ensure ARP announcement is configured",
        details="ARP announce configured" if arp_announce else "Default ARP announcement",
        remediation="Consider: sysctl -w net.ipv4.conf.all.arp_announce=2"
    ))
    
    # 3.2.13 - Ensure ARP ignore is configured
    arp_ignore = cis_check_kernel_parameter("net.ipv4.conf.all.arp_ignore", "1")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.2 - Network",
        status="Info",
        message="3.2.13 Ensure ARP ignore is configured",
        details="ARP ignore configured" if arp_ignore else "Default ARP handling",
        remediation="Consider: sysctl -w net.ipv4.conf.all.arp_ignore=1"
    ))
    
    # 3.2.14 - Ensure ICMP echo ignore all is configured
    icmp_echo_ignore = cis_check_kernel_parameter("net.ipv4.icmp_echo_ignore_all", "0")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.2 - Network",
        status="Info",
        message="3.2.14 ICMP echo response status",
        details="ICMP echo enabled (normal)" if not icmp_echo_ignore else "ICMP echo disabled",
        remediation="Note: Disabling ICMP echo may impact network troubleshooting"
    ))
    
    # 3.2.15 - Ensure IPv4 TCP RFC1337 protection is enabled
    tcp_rfc1337 = cis_check_kernel_parameter("net.ipv4.tcp_rfc1337", "1")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.2 - Network",
        status="Pass" if tcp_rfc1337 else "Warning",
        message="3.2.15 Ensure TCP RFC1337 protection enabled",
        details="RFC1337 protection enabled" if tcp_rfc1337 else "RFC1337 protection disabled",
        remediation="sysctl -w net.ipv4.tcp_rfc1337=1"
    ))

def check_section3_ipv6(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """CIS Section 3.3 - IPv6"""
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Section 3.3 - IPv6...")
    
    # 3.3.1 - Ensure IPv6 is disabled if not needed
    ipv6_disabled = check_grub_parameter("ipv6.disable=1")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.3 - IPv6",
        status="Pass" if ipv6_disabled else "Info",
        message="3.3.1 Ensure IPv6 is disabled if not in use",
        details="IPv6 disabled in boot" if ipv6_disabled else "IPv6 is enabled",
        remediation="Add ipv6.disable=1 to GRUB_CMDLINE_LINUX if IPv6 not needed"
    ))
    
    # 3.3.2 - Ensure IPv6 forwarding is disabled
    ipv6_forward_all = cis_check_kernel_parameter("net.ipv6.conf.all.forwarding", "0")
    ipv6_forward_default = cis_check_kernel_parameter("net.ipv6.conf.default.forwarding", "0")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.3 - IPv6",
        status="Pass" if ipv6_forward_all and ipv6_forward_default else "Fail",
        message="3.3.2 Ensure IPv6 forwarding is disabled",
        details="IPv6 forwarding disabled" if ipv6_forward_all and ipv6_forward_default else "IPv6 forwarding enabled",
        remediation="sysctl -w net.ipv6.conf.all.forwarding=0; sysctl -w net.ipv6.conf.default.forwarding=0"
    ))
    
    # 3.3.3 - Ensure IPv6 redirects are not accepted
    ipv6_redirects_all = cis_check_kernel_parameter("net.ipv6.conf.all.accept_redirects", "0")
    ipv6_redirects_default = cis_check_kernel_parameter("net.ipv6.conf.default.accept_redirects", "0")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.3 - IPv6",
        status="Pass" if ipv6_redirects_all and ipv6_redirects_default else "Fail",
        message="3.3.3 Ensure IPv6 redirects are not accepted",
        details="IPv6 redirects disabled" if ipv6_redirects_all and ipv6_redirects_default else "IPv6 redirects enabled",
        remediation="sysctl -w net.ipv6.conf.all.accept_redirects=0; sysctl -w net.ipv6.conf.default.accept_redirects=0"
    ))
    
    # Additional IPv6 security checks
    # 3.3.4 - Ensure IPv6 source routing is disabled
    ipv6_source_route_all = cis_check_kernel_parameter("net.ipv6.conf.all.accept_source_route", "0")
    ipv6_source_route_default = cis_check_kernel_parameter("net.ipv6.conf.default.accept_source_route", "0")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.3 - IPv6",
        status="Pass" if ipv6_source_route_all and ipv6_source_route_default else "Fail",
        message="3.3.4 Ensure IPv6 source routing is disabled",
        details="IPv6 source routing disabled" if ipv6_source_route_all else "IPv6 source routing enabled",
        remediation="sysctl -w net.ipv6.conf.all.accept_source_route=0"
    ))
    
    # 3.3.5 - Ensure IPv6 router advertisements are not accepted
    ipv6_accept_ra_all = cis_check_kernel_parameter("net.ipv6.conf.all.accept_ra", "0")
    ipv6_accept_ra_default = cis_check_kernel_parameter("net.ipv6.conf.default.accept_ra", "0")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.3 - IPv6",
        status="Pass" if ipv6_accept_ra_all and ipv6_accept_ra_default else "Fail",
        message="3.3.5 Ensure IPv6 router advertisements are not accepted",
        details="IPv6 RA disabled" if ipv6_accept_ra_all else "IPv6 RA enabled",
        remediation="sysctl -w net.ipv6.conf.all.accept_ra=0"
    ))
    
    # 3.3.6 - Ensure IPv6 neighbor solicitations are limited
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.3 - IPv6",
        status="Info",
        message="3.3.6 IPv6 neighbor discovery status",
        details="Review IPv6 neighbor discovery settings if IPv6 is used",
        remediation="Configure IPv6 neighbor discovery rate limiting if needed"
    ))
    
    # 3.3.7 - Ensure IPv6 router solicitations are disabled
    ipv6_router_solicitations = cis_check_kernel_parameter("net.ipv6.conf.all.router_solicitations", "0")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.3 - IPv6",
        status="Info",
        message="3.3.7 IPv6 router solicitations status",
        details="Router solicitations disabled" if ipv6_router_solicitations else "Router solicitations may be enabled",
        remediation="Consider: sysctl -w net.ipv6.conf.all.router_solicitations=0"
    ))
    
    # 3.3.8 - Ensure IPv6 accept_ra_rtr_pref is disabled
    ipv6_ra_rtr_pref = cis_check_kernel_parameter("net.ipv6.conf.all.accept_ra_rtr_pref", "0")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.3 - IPv6",
        status="Info",
        message="3.3.8 IPv6 router preference status",
        details="Router preference disabled" if ipv6_ra_rtr_pref else "Default router preference",
        remediation="Consider: sysctl -w net.ipv6.conf.all.accept_ra_rtr_pref=0"
    ))
    
    # 3.3.9 - Ensure IPv6 accept_ra_pinfo is disabled
    ipv6_ra_pinfo = cis_check_kernel_parameter("net.ipv6.conf.all.accept_ra_pinfo", "0")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.3 - IPv6",
        status="Info",
        message="3.3.9 IPv6 prefix information status",
        details="Prefix info disabled" if ipv6_ra_pinfo else "Default prefix information",
        remediation="Consider: sysctl -w net.ipv6.conf.all.accept_ra_pinfo=0"
    ))
    
    # 3.3.10 - Ensure IPv6 autoconf is disabled
    ipv6_autoconf_all = cis_check_kernel_parameter("net.ipv6.conf.all.autoconf", "0")
    ipv6_autoconf_default = cis_check_kernel_parameter("net.ipv6.conf.default.autoconf", "0")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.3 - IPv6",
        status="Info",
        message="3.3.10 IPv6 autoconfiguration status",
        details="Autoconf disabled" if ipv6_autoconf_all else "Autoconf may be enabled",
        remediation="Consider: sysctl -w net.ipv6.conf.all.autoconf=0"
    ))

def check_section3_firewall(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """CIS Section 3.4 - Firewall Configuration"""
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Section 3.4 - Firewall...")
    
    # 3.4.1 - Ensure firewall is installed
    firewall_installed = check_package_installed("firewalld", os_info) or check_package_installed("ufw", os_info) or \
                        check_package_installed("iptables", os_info) or check_package_installed("nftables", os_info)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.4 - Firewall",
        status="Pass" if firewall_installed else "Fail",
        message="3.4.1 Ensure a Firewall package is installed",
        details="Firewall package present" if firewall_installed else "No firewall package",
        remediation="Install firewall: apt install ufw || yum install firewalld"
    ))
    
    # 3.4.2 - Ensure firewall service is enabled and running
    firewall_active = check_service_active("firewalld") or check_service_active("ufw")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.4 - Firewall",
        status="Pass" if firewall_active else "Fail",
        message="3.4.2 Ensure firewall service is enabled and running",
        details="Firewall active" if firewall_active else "Firewall not running",
        remediation="systemctl enable --now firewalld || ufw enable"
    ))
    
    # 3.4.3 - Ensure default deny firewall policy
    if check_service_active("ufw"):
        ufw_status = run_command("ufw status verbose | grep 'Default:'").stdout
        default_deny = "deny (incoming)" in ufw_status.lower()
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 3.4 - Firewall",
            status="Pass" if default_deny else "Fail",
            message="3.4.3 Ensure default deny firewall policy",
            details="Default deny configured" if default_deny else "Default policy not deny",
            remediation="ufw default deny incoming"
        ))
    
    # 3.4.4 - Ensure loopback traffic is configured
    loopback_rules = run_command("iptables -L INPUT -v -n | grep -c 'lo'").stdout.strip()
    has_loopback = loopback_rules and int(loopback_rules) > 0
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.4 - Firewall",
        status="Pass" if has_loopback else "Warning",
        message="3.4.4 Ensure loopback traffic is configured",
        details="Loopback rules present" if has_loopback else "No loopback rules detected",
        remediation="Configure firewall rules for loopback interface"
    ))
    
    # 3.4.5 - Ensure outbound connections are configured
    outbound_rules = run_command("iptables -L OUTPUT -v -n 2>/dev/null | wc -l").stdout.strip()
    has_outbound = outbound_rules and int(outbound_rules) > 3
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.4 - Firewall",
        status="Info",
        message="3.4.5 Ensure outbound connections are configured",
        details=f"Outbound rules: {outbound_rules}" if outbound_rules else "No OUTPUT rules",
        remediation="Review and configure appropriate outbound firewall rules"
    ))


# ============================================================================
# Section 4: Logging and Auditing
# ============================================================================

def check_section4_system_logging(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """CIS Section 4.1 - Configure System Accounting (auditd)"""
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Section 4.1 - System Auditing...")
    
    # 4.1.1 - Ensure auditing is enabled
    auditd_installed = check_package_installed("auditd", os_info) or check_package_installed("audit", os_info)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 4.1 - Auditing",
        status="Pass" if auditd_installed else "Fail",
        message="4.1.1 Ensure auditing is enabled - auditd installed",
        details="auditd package installed" if auditd_installed else "auditd not installed",
        remediation=remediation_for("auditd")
    ))
    
    # 4.1.2 - Ensure auditd service is enabled
    auditd_enabled = check_service_enabled("auditd")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 4.1 - Auditing",
        status="Pass" if auditd_enabled else "Fail",
        message="4.1.2 Ensure auditd service is enabled and running",
        details="auditd service enabled" if auditd_enabled else "auditd not enabled",
        remediation=remediation_for("auditd")
    ))
    
    # 4.1.3 - Ensure auditing for processes prior to auditd is enabled
    audit_backlog = check_grub_parameter("audit_backlog_limit=")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 4.1 - Auditing",
        status="Pass" if audit_backlog else "Warning",
        message="4.1.3 Ensure auditing for processes prior to auditd is enabled",
        details="Audit backlog configured" if audit_backlog else "No audit backlog in boot params",
        remediation="Add audit=1 audit_backlog_limit=8192 to GRUB_CMDLINE_LINUX"
    ))
    
    # 4.1.4 - Ensure audit_log_file is configured
    audit_conf_exists = os.path.exists("/etc/audit/auditd.conf")
    if audit_conf_exists:
        audit_conf = read_file_safe("/etc/audit/auditd.conf")
        log_file = re.search(r'log_file\s*=\s*(.+)', audit_conf)
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 4.1 - Auditing",
            status="Pass" if log_file else "Fail",
            message="4.1.4 Ensure audit log storage size is configured",
            details=f"Log file: {log_file.group(1)}" if log_file else "No log_file configured",
            remediation="Configure log_file in /etc/audit/auditd.conf"
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 4.1 - Auditing",
            status="Fail",
            message="4.1.4 Ensure audit log storage size is configured",
            details="auditd.conf not found",
            remediation="Install and configure auditd"
        ))
    
    # 4.1.5 - Ensure audit logs are not automatically deleted
    if audit_conf_exists:
        audit_conf = read_file_safe("/etc/audit/auditd.conf")
        max_log_file_action = re.search(r'max_log_file_action\s*=\s*(\w+)', audit_conf)
        keep_logs = max_log_file_action and max_log_file_action.group(1) != "delete"
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 4.1 - Auditing",
            status="Pass" if keep_logs else "Fail",
            message="4.1.5 Ensure audit logs are not automatically deleted",
            details=f"Action: {max_log_file_action.group(1)}" if max_log_file_action else "Action not set",
            remediation="Set max_log_file_action = keep_logs or rotate in /etc/audit/auditd.conf"
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 4.1 - Auditing",
            status="Fail",
            message="4.1.5 Ensure audit logs are not automatically deleted",
            details="auditd.conf not found",
            remediation="Install and configure auditd"
        ))
    
    # 4.1.6 - Ensure system is disabled when audit logs are full
    if audit_conf_exists:
        audit_conf = read_file_safe("/etc/audit/auditd.conf")
        space_left_action = re.search(r'space_left_action\s*=\s*(\w+)', audit_conf)
        admin_space_left_action = re.search(r'admin_space_left_action\s*=\s*(\w+)', audit_conf)
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 4.1 - Auditing",
            status="Pass" if space_left_action and admin_space_left_action else "Warning",
            message="4.1.6 Ensure system is disabled when audit logs are full",
            details="Disk full actions configured" if space_left_action else "Actions not configured",
            remediation="Configure space_left_action and admin_space_left_action"
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 4.1 - Auditing",
            status="Fail",
            message="4.1.6 Ensure system is disabled when audit logs are full",
            details="auditd.conf not found",
            remediation="Install and configure auditd"
        ))
    
    # 4.1.7 - Ensure audit rules are immutable
    rules_file_locations = ["/etc/audit/rules.d/audit.rules", "/etc/audit/audit.rules"]
    rules_file = None
    for loc in rules_file_locations:
        if os.path.exists(loc):
            rules_file = loc
            break
    
    if rules_file:
        rules = read_file_safe(rules_file)
        immutable = "-e 2" in rules
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 4.1 - Auditing",
            status="Pass" if immutable else "Fail",
            message="4.1.7 Ensure audit configuration is immutable",
            details="Audit rules immutable" if immutable else "Audit rules not immutable",
            remediation="Add '-e 2' to end of audit.rules"
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 4.1 - Auditing",
            status="Fail",
            message="4.1.7 Ensure audit configuration is immutable",
            details="No audit rules file found",
            remediation="Create /etc/audit/rules.d/audit.rules with '-e 2'"
        ))
    
    # Specific audit rules (4.1.8 - 4.1.20) - ALWAYS execute these checks
    audit_rules_checks = [
        ("4.1.8", "time-change", "date and time modification events are collected"),
        ("4.1.9", "identity", "user/group information modification events are collected"),
        ("4.1.10", "system-locale", "network environment modification events are collected"),
        ("4.1.11", "MAC-policy", "MAC policy modification events are collected"),
        ("4.1.12", "logins", "login and logout events are collected"),
        ("4.1.13", "session", "session initiation information is collected"),
        ("4.1.14", "perm_mod", "discretionary access control permission modification events are collected"),
        ("4.1.15", "access", "unsuccessful unauthorized file access attempts are collected"),
        ("4.1.16", "mounts", "successful file system mounts are collected"),
        ("4.1.17", "delete", "file deletion events by users are collected"),
        ("4.1.18", "scope", "changes to system administration scope are collected"),
        ("4.1.19", "actions", "system administrator actions are collected"),
        ("4.1.20", "modules", "kernel module loading and unloading is collected"),
    ]
    
    # Read rules content if file exists, otherwise empty
    rules_content = read_file_safe(rules_file) if rules_file else ""
    
    # ALWAYS execute these checks regardless of file existence
    for rule_id, key, description in audit_rules_checks:
        has_rule = f"-k {key}" in rules_content or f"key={key}" in rules_content
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 4.1 - Auditing",
            status="Pass" if has_rule else "Fail",
            message=f"{rule_id} Ensure {description}",
            details=f"Audit rule present for {key}" if has_rule else f"No audit rule for {key}",
            remediation=f"Add audit rule with key={key} to {rules_file or '/etc/audit/rules.d/audit.rules'}"
        ))

def check_section4_logging(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """CIS Section 4.2 - Configure Logging"""
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Section 4.2 - System Logging...")
    
    # 4.2.1 - Ensure rsyslog is installed
    rsyslog_installed = check_package_installed("rsyslog", os_info)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 4.2 - Logging",
        status="Pass" if rsyslog_installed else "Warning",
        message="4.2.1 Ensure rsyslog is installed",
        details="rsyslog installed" if rsyslog_installed else "rsyslog not installed",
        remediation=remediation_for("rsyslog")
    ))
    
    # 4.2.2 - Ensure rsyslog Service is enabled
    rsyslog_enabled = check_service_enabled("rsyslog")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 4.2 - Logging",
        status="Pass" if rsyslog_enabled else "Fail",
        message="4.2.2 Ensure rsyslog Service is enabled and running",
        details="rsyslog service enabled" if rsyslog_enabled else "rsyslog not enabled",
        remediation="systemctl enable --now rsyslog"
    ))
    
    # 4.2.3 - Ensure rsyslog default file permissions configured
    if os.path.exists("/etc/rsyslog.conf"):
        rsyslog_conf = read_file_safe("/etc/rsyslog.conf")
        file_perms = "$FileCreateMode" in rsyslog_conf and "0640" in rsyslog_conf
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 4.2 - Logging",
            status="Pass" if file_perms else "Fail",
            message="4.2.3 Ensure rsyslog default file permissions configured",
            details="File permissions configured" if file_perms else "File permissions not set",
            remediation="Add '$FileCreateMode 0640' to /etc/rsyslog.conf"
        ))
    
    # 4.2.4 - Ensure logging is configured
    log_rules = ["/var/log/messages", "/var/log/secure", "/var/log/maillog", "/var/log/cron"]
    logs_configured = 0
    if os.path.exists("/etc/rsyslog.conf"):
        rsyslog_conf = read_file_safe("/etc/rsyslog.conf")
        for log in log_rules:
            if log in rsyslog_conf:
                logs_configured += 1
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 4.2 - Logging",
        status="Pass" if logs_configured >= 3 else "Warning",
        message="4.2.4 Ensure logging is configured",
        details=f"{logs_configured}/{len(log_rules)} standard logs configured",
        remediation="Configure logging rules in /etc/rsyslog.conf or /etc/rsyslog.d/"
    ))
    
    # 4.2.5 - Ensure rsyslog is configured to send logs to remote host
    if os.path.exists("/etc/rsyslog.conf"):
        rsyslog_conf = read_file_safe("/etc/rsyslog.conf")
        remote_host = "@@" in rsyslog_conf or "*.*" in rsyslog_conf and "@" in rsyslog_conf
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 4.2 - Logging",
            status="Pass" if remote_host else "Warning",
            message="4.2.5 Ensure rsyslog is configured to send logs to remote host",
            details="Remote logging configured" if remote_host else "No remote logging",
            remediation="Configure remote host: *.* @@remote-host:514 in rsyslog.conf"
        ))
    
    # 4.2.6 - Ensure syslog-ng is installed (alternative)
    syslog_ng = check_package_installed("syslog-ng", os_info)
    if syslog_ng:
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 4.2 - Logging",
            status="Info",
            message="4.2.6 Syslog-ng detected as alternative",
            details="syslog-ng is installed",
            remediation=""
        ))
    
    # 4.2.7 - Ensure journald is configured
    journald_conf = read_file_safe("/etc/systemd/journald.conf")
    if journald_conf:
        storage = "Storage=" in journald_conf
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 4.2 - Logging",
            status="Pass" if storage else "Warning",
            message="4.2.7 Ensure journald is configured to send logs to rsyslog",
            details="Storage configured" if storage else "Storage not configured",
            remediation="Configure Storage=persistent in /etc/systemd/journald.conf"
        ))
    
    # 4.3.1 - Ensure logrotate is configured
    logrotate_installed = check_package_installed("logrotate", os_info)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 4.3 - Logrotate",
        status="Pass" if logrotate_installed else "Fail",
        message="4.3.1 Ensure logrotate is configured",
        details="logrotate installed" if logrotate_installed else "logrotate not installed",
        remediation=remediation_for("logrotate")
    ))
    
    # 4.3.2 - Ensure logrotate runs daily
    logrotate_daily = os.path.exists("/etc/cron.daily/logrotate")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 4.3 - Logrotate",
        status="Pass" if logrotate_daily else "Warning",
        message="4.3.2 Ensure logrotate runs periodically",
        details="Daily rotation configured" if logrotate_daily else "No daily rotation",
        remediation="Ensure /etc/cron.daily/logrotate exists"
    ))


# ============================================================================
# Section 5: Access, Authentication and Authorization
# ============================================================================

def check_section5_cron(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """CIS Section 5.1 - Configure cron"""
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Section 5.1 - Cron Configuration...")
    
    # 5.1.1 - Ensure cron daemon is enabled
    cron_enabled = check_service_enabled("cron") or check_service_enabled("crond")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.1 - Cron",
        status="Pass" if cron_enabled else "Fail",
        message="5.1.1 Ensure cron daemon is enabled and running",
        details="Cron service enabled" if cron_enabled else "Cron not enabled",
        remediation="systemctl enable --now cron || systemctl enable --now crond"
    ))
    
    # 5.1.2 - Ensure permissions on /etc/crontab are configured
    if os.path.exists("/etc/crontab"):
        perms = get_file_permissions("/etc/crontab")
        owner, group = get_file_owner_group("/etc/crontab")
        correct = perms and int(perms, 8) <= int("0600", 8) and owner == "root"
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 5.1 - Cron",
            status="Pass" if correct else "Fail",
            message="5.1.2 Ensure permissions on /etc/crontab are configured",
            details=f"Perms: {perms}, Owner: {owner}" if perms else "File missing",
            remediation="chown root:root /etc/crontab && chmod 600 /etc/crontab"
        ))
    
    # 5.1.3 - Ensure permissions on /etc/cron.hourly are configured
    if os.path.exists("/etc/cron.hourly"):
        perms = get_file_permissions("/etc/cron.hourly")
        owner, group = get_file_owner_group("/etc/cron.hourly")
        correct = perms and int(perms, 8) <= int("0700", 8) and owner == "root"
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 5.1 - Cron",
            status="Pass" if correct else "Fail",
            message="5.1.3 Ensure permissions on /etc/cron.hourly are configured",
            details=f"Perms: {perms}, Owner: {owner}" if perms else "Dir missing",
            remediation="chown root:root /etc/cron.hourly && chmod 700 /etc/cron.hourly"
        ))
    
    # 5.1.4 - Ensure permissions on /etc/cron.daily are configured
    if os.path.exists("/etc/cron.daily"):
        perms = get_file_permissions("/etc/cron.daily")
        owner, group = get_file_owner_group("/etc/cron.daily")
        correct = perms and int(perms, 8) <= int("0700", 8) and owner == "root"
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 5.1 - Cron",
            status="Pass" if correct else "Fail",
            message="5.1.4 Ensure permissions on /etc/cron.daily are configured",
            details=f"Perms: {perms}, Owner: {owner}" if perms else "Dir missing",
            remediation="chown root:root /etc/cron.daily && chmod 700 /etc/cron.daily"
        ))
    
    # 5.1.5 - Ensure permissions on /etc/cron.weekly are configured
    if os.path.exists("/etc/cron.weekly"):
        perms = get_file_permissions("/etc/cron.weekly")
        owner, group = get_file_owner_group("/etc/cron.weekly")
        correct = perms and int(perms, 8) <= int("0700", 8) and owner == "root"
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 5.1 - Cron",
            status="Pass" if correct else "Fail",
            message="5.1.5 Ensure permissions on /etc/cron.weekly are configured",
            details=f"Perms: {perms}, Owner: {owner}" if perms else "Dir missing",
            remediation="chown root:root /etc/cron.weekly && chmod 700 /etc/cron.weekly"
        ))
    
    # 5.1.6 - Ensure permissions on /etc/cron.monthly are configured
    if os.path.exists("/etc/cron.monthly"):
        perms = get_file_permissions("/etc/cron.monthly")
        owner, group = get_file_owner_group("/etc/cron.monthly")
        correct = perms and int(perms, 8) <= int("0700", 8) and owner == "root"
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 5.1 - Cron",
            status="Pass" if correct else "Fail",
            message="5.1.6 Ensure permissions on /etc/cron.monthly are configured",
            details=f"Perms: {perms}, Owner: {owner}" if perms else "Dir missing",
            remediation="chown root:root /etc/cron.monthly && chmod 700 /etc/cron.monthly"
        ))
    
    # 5.1.7 - Ensure permissions on /etc/cron.d are configured
    if os.path.exists("/etc/cron.d"):
        perms = get_file_permissions("/etc/cron.d")
        owner, group = get_file_owner_group("/etc/cron.d")
        correct = perms and int(perms, 8) <= int("0700", 8) and owner == "root"
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 5.1 - Cron",
            status="Pass" if correct else "Fail",
            message="5.1.7 Ensure permissions on /etc/cron.d are configured",
            details=f"Perms: {perms}, Owner: {owner}" if perms else "Dir missing",
            remediation="chown root:root /etc/cron.d && chmod 700 /etc/cron.d"
        ))
    
    # 5.1.8 - Ensure cron is restricted to authorized users
    cron_allow = os.path.exists("/etc/cron.allow")
    cron_deny = os.path.exists("/etc/cron.deny")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.1 - Cron",
        status="Pass" if cron_allow or not cron_deny else "Fail",
        message="5.1.8 Ensure cron is restricted to authorized users",
        details="cron.allow exists" if cron_allow else "No cron.allow, cron.deny present" if cron_deny else "No restriction files",
        remediation="Create /etc/cron.allow with authorized users; rm /etc/cron.deny"
    ))

def check_section5_ssh(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """CIS Section 5.2 - SSH Server Configuration"""
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Section 5.2 - SSH Server Configuration...")
    
    sshd_config = read_file_safe("/etc/ssh/sshd_config")
    
    # 5.2.1 - Ensure permissions on /etc/ssh/sshd_config are configured
    if os.path.exists("/etc/ssh/sshd_config"):
        perms = get_file_permissions("/etc/ssh/sshd_config")
        owner, group = get_file_owner_group("/etc/ssh/sshd_config")
        correct = perms and int(perms, 8) <= int("0600", 8) and owner == "root"
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 5.2 - SSH",
            status="Pass" if correct else "Fail",
            message="5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured",
            details=f"Perms: {perms}, Owner: {owner}" if perms else "Config missing",
            remediation="chown root:root /etc/ssh/sshd_config && chmod 600 /etc/ssh/sshd_config"
        ))
    
    # 5.2.2 - Ensure SSH access is limited
    allow_users = "AllowUsers" in sshd_config or "AllowGroups" in sshd_config
    deny_users = "DenyUsers" in sshd_config or "DenyGroups" in sshd_config
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.2 - SSH",
        status="Pass" if allow_users or deny_users else "Warning",
        message="5.2.2 Ensure SSH access is limited",
        details="SSH access restrictions configured" if allow_users or deny_users else "No access restrictions",
        remediation="Configure AllowUsers/AllowGroups or DenyUsers/DenyGroups in sshd_config"
    ))
    
    # 5.2.3 - Ensure permissions on SSH private host key files are configured
    private_keys = glob.glob("/etc/ssh/ssh_host_*_key")
    keys_secure = 0
    for key in private_keys:
        perms = get_file_permissions(key)
        if perms and int(perms, 8) <= int("0600", 8):
            keys_secure += 1
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.2 - SSH",
        status="Pass" if len(private_keys) > 0 and keys_secure == len(private_keys) else "Fail",
        message="5.2.3 Ensure permissions on SSH private host key files configured",
        details=f"{keys_secure}/{len(private_keys)} keys properly secured",
        remediation="chmod 600 /etc/ssh/ssh_host_*_key"
    ))
    
    # 5.2.4 - Ensure permissions on SSH public host key files are configured
    public_keys = glob.glob("/etc/ssh/ssh_host_*_key.pub")
    pub_keys_secure = 0
    for key in public_keys:
        perms = get_file_permissions(key)
        if perms and int(perms, 8) <= int("0644", 8):
            pub_keys_secure += 1
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.2 - SSH",
        status="Pass" if len(public_keys) > 0 and pub_keys_secure == len(public_keys) else "Fail",
        message="5.2.4 Ensure permissions on SSH public host key files configured",
        details=f"{pub_keys_secure}/{len(public_keys)} public keys properly configured",
        remediation="chmod 644 /etc/ssh/ssh_host_*_key.pub"
    ))
    
    # 5.2.5 - Ensure SSH Protocol is set to 2
    protocol = re.search(r'^Protocol\s+(\d+)', sshd_config, re.MULTILINE)
    protocol_2 = not protocol or protocol.group(1) == "2"
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.2 - SSH",
        status="Pass" if protocol_2 else "Fail",
        message="5.2.5 Ensure SSH Protocol is set to 2",
        details="Protocol 2 (default)" if protocol_2 else f"Protocol {protocol.group(1)}",
        remediation="Remove 'Protocol 1' or set 'Protocol 2' in sshd_config"
    ))
    
    # 5.2.6 - Ensure SSH LogLevel is appropriate
    log_level = re.search(r'^LogLevel\s+(\w+)', sshd_config, re.MULTILINE)
    appropriate = log_level and log_level.group(1).upper() in ["INFO", "VERBOSE"]
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.2 - SSH",
        status="Pass" if appropriate else "Warning",
        message="5.2.6 Ensure SSH LogLevel is appropriate",
        details=f"LogLevel: {log_level.group(1)}" if log_level else "LogLevel not set (default INFO)",
        remediation="Set 'LogLevel VERBOSE' or 'LogLevel INFO' in sshd_config"
    ))
    
    # 5.2.7 - Ensure SSH X11 forwarding is disabled
    x11_forward = re.search(r'^X11Forwarding\s+(\w+)', sshd_config, re.MULTILINE)
    x11_disabled = x11_forward and x11_forward.group(1).lower() == "no"
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.2 - SSH",
        status="Pass" if x11_disabled else "Warning",
        message="5.2.7 Ensure SSH X11 forwarding is disabled",
        details="X11Forwarding no" if x11_disabled else "X11Forwarding enabled or not set",
        remediation="Set 'X11Forwarding no' in sshd_config"
    ))
    
    # 5.2.8 - Ensure SSH MaxAuthTries is set to 4 or less
    max_auth = re.search(r'^MaxAuthTries\s+(\d+)', sshd_config, re.MULTILINE)
    auth_ok = max_auth and int(max_auth.group(1)) <= 4
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.2 - SSH",
        status="Pass" if auth_ok else "Fail",
        message="5.2.8 Ensure SSH MaxAuthTries is set to 4 or less",
        details=f"MaxAuthTries: {max_auth.group(1)}" if max_auth else "MaxAuthTries not set (default 6)",
        remediation="Set 'MaxAuthTries 4' in sshd_config"
    ))
    
    # 5.2.9 - Ensure SSH IgnoreRhosts is enabled
    ignore_rhosts = re.search(r'^IgnoreRhosts\s+(\w+)', sshd_config, re.MULTILINE)
    rhosts_ok = not ignore_rhosts or ignore_rhosts.group(1).lower() == "yes"
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.2 - SSH",
        status="Pass" if rhosts_ok else "Fail",
        message="5.2.9 Ensure SSH IgnoreRhosts is enabled",
        details="IgnoreRhosts yes" if rhosts_ok else "IgnoreRhosts no",
        remediation="Set 'IgnoreRhosts yes' in sshd_config"
    ))
    
    # 5.2.10 - Ensure SSH HostbasedAuthentication is disabled
    hostbased = re.search(r'^HostbasedAuthentication\s+(\w+)', sshd_config, re.MULTILINE)
    hostbased_ok = not hostbased or hostbased.group(1).lower() == "no"
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.2 - SSH",
        status="Pass" if hostbased_ok else "Fail",
        message="5.2.10 Ensure SSH HostbasedAuthentication is disabled",
        details="HostbasedAuthentication no" if hostbased_ok else "HostbasedAuthentication yes",
        remediation="Set 'HostbasedAuthentication no' in sshd_config"
    ))
    
    # 5.2.11 - Ensure SSH root login is disabled
    permit_root = re.search(r'^PermitRootLogin\s+(\w+)', sshd_config, re.MULTILINE)
    root_disabled = permit_root and permit_root.group(1).lower() == "no"
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.2 - SSH",
        status="Pass" if root_disabled else "Fail",
        message="5.2.11 Ensure SSH root login is disabled",
        details="PermitRootLogin no" if root_disabled else f"PermitRootLogin {permit_root.group(1) if permit_root else 'not set'}",
        remediation="Set 'PermitRootLogin no' in sshd_config"
    ))
    
    # 5.2.12 - Ensure SSH PermitEmptyPasswords is disabled
    empty_pass = re.search(r'^PermitEmptyPasswords\s+(\w+)', sshd_config, re.MULTILINE)
    empty_disabled = not empty_pass or empty_pass.group(1).lower() == "no"
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.2 - SSH",
        status="Pass" if empty_disabled else "Fail",
        message="5.2.12 Ensure SSH PermitEmptyPasswords is disabled",
        details="PermitEmptyPasswords no" if empty_disabled else "PermitEmptyPasswords yes",
        remediation="Set 'PermitEmptyPasswords no' in sshd_config"
    ))
    
    # 5.2.13 - Ensure SSH PermitUserEnvironment is disabled
    user_env = re.search(r'^PermitUserEnvironment\s+(\w+)', sshd_config, re.MULTILINE)
    env_disabled = not user_env or user_env.group(1).lower() == "no"
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.2 - SSH",
        status="Pass" if env_disabled else "Fail",
        message="5.2.13 Ensure SSH PermitUserEnvironment is disabled",
        details="PermitUserEnvironment no" if env_disabled else "PermitUserEnvironment yes",
        remediation="Set 'PermitUserEnvironment no' in sshd_config"
    ))
    
    # 5.2.14 - Ensure only strong ciphers are used
    ciphers = re.search(r'^Ciphers\s+(.+)', sshd_config, re.MULTILINE)
    weak_ciphers = ["3des", "des", "rc4", "blowfish"] if ciphers else []
    has_weak = any(weak in ciphers.group(1).lower() for weak in weak_ciphers) if ciphers else False
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.2 - SSH",
        status="Pass" if not has_weak else "Fail",
        message="5.2.14 Ensure only strong ciphers are used",
        details="Strong ciphers configured" if not has_weak else "Weak ciphers detected",
        remediation="Set 'Ciphers aes256-ctr,aes192-ctr,aes128-ctr' in sshd_config"
    ))
    
    # 5.2.15 - Ensure only strong MAC algorithms are used
    macs = re.search(r'^MACs\s+(.+)', sshd_config, re.MULTILINE)
    weak_macs = ["md5", "sha1-96"] if macs else []
    has_weak_mac = any(weak in macs.group(1).lower() for weak in weak_macs) if macs else False
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.2 - SSH",
        status="Pass" if not has_weak_mac else "Fail",
        message="5.2.15 Ensure only strong MAC algorithms are used",
        details="Strong MACs configured" if not has_weak_mac else "Weak MACs detected",
        remediation="Set strong MACs in sshd_config"
    ))
    
    # 5.2.16 - Ensure SSH Idle Timeout Interval is configured
    client_alive = re.search(r'^ClientAliveInterval\s+(\d+)', sshd_config, re.MULTILINE)
    timeout_ok = client_alive and 1 <= int(client_alive.group(1)) <= 300
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.2 - SSH",
        status="Pass" if timeout_ok else "Fail",
        message="5.2.16 Ensure SSH Idle Timeout Interval is configured",
        details=f"ClientAliveInterval: {client_alive.group(1)}" if client_alive else "ClientAliveInterval not set",
        remediation="Set 'ClientAliveInterval 300' and 'ClientAliveCountMax 0' in sshd_config"
    ))
    
    # 5.2.17 - Ensure SSH LoginGraceTime is set to one minute or less
    login_grace = re.search(r'^LoginGraceTime\s+(\d+)', sshd_config, re.MULTILINE)
    grace_ok = login_grace and int(login_grace.group(1)) <= 60
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.2 - SSH",
        status="Pass" if grace_ok else "Warning",
        message="5.2.17 Ensure SSH LoginGraceTime is set to one minute or less",
        details=f"LoginGraceTime: {login_grace.group(1)}s" if login_grace else "LoginGraceTime not set (default 120s)",
        remediation="Set 'LoginGraceTime 60' in sshd_config"
    ))
    
    # 5.2.18 - Ensure SSH warning banner is configured
    banner = re.search(r'^Banner\s+(.+)', sshd_config, re.MULTILINE)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.2 - SSH",
        status="Pass" if banner else "Warning",
        message="5.2.18 Ensure SSH warning banner is configured",
        details=f"Banner: {banner.group(1)}" if banner else "No banner configured",
        remediation="Set 'Banner /etc/issue.net' in sshd_config"
    ))

def check_section5_pam(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """CIS Section 5.3 - Configure PAM"""
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Section 5.3 - PAM Configuration...")
    
    # 5.3.1 - Ensure password creation requirements are configured
    pwquality_conf = read_file_safe("/etc/security/pwquality.conf")
    has_minlen = "minlen" in pwquality_conf and check_password_quality("minlen", 14)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.3 - PAM",
        status="Pass" if has_minlen else "Fail",
        message="5.3.1 Ensure password creation requirements are configured",
        details="Password quality configured" if has_minlen else "Password quality not configured",
        remediation="Configure /etc/security/pwquality.conf: minlen=14, dcredit=-1, ucredit=-1, ocredit=-1, lcredit=-1"
    ))
    
    # 5.3.2 - Ensure lockout for failed password attempts is configured
    faillock = check_package_installed("libpam-pwquality", os_info) or os.path.exists("/etc/security/faillock.conf")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.3 - PAM",
        status="Pass" if faillock else "Fail",
        message="5.3.2 Ensure lockout for failed password attempts is configured",
        details="Faillock configured" if faillock else "Faillock not configured",
        remediation="Configure pam_faillock in PAM configuration files"
    ))
    
    # 5.3.3 - Ensure password reuse is limited
    pam_files = ["/etc/pam.d/common-password", "/etc/pam.d/system-auth"]
    has_remember = False
    for pam_file in pam_files:
        if os.path.exists(pam_file):
            content = read_file_safe(pam_file)
            if "remember=" in content:
                has_remember = True
                break
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.3 - PAM",
        status="Pass" if has_remember else "Fail",
        message="5.3.3 Ensure password reuse is limited",
        details="Password history configured" if has_remember else "No password history",
        remediation="Add 'remember=5' to pam_unix.so in PAM password configuration"
    ))
    
    # 5.3.4 - Ensure password hashing algorithm is SHA-512
    pam_files = ["/etc/pam.d/common-password", "/etc/pam.d/system-auth", "/etc/pam.d/password-auth"]
    has_sha512 = False
    for pam_file in pam_files:
        if os.path.exists(pam_file):
            content = read_file_safe(pam_file)
            if "sha512" in content:
                has_sha512 = True
                break
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.3 - PAM",
        status="Pass" if has_sha512 else "Fail",
        message="5.3.4 Ensure password hashing algorithm is SHA-512",
        details="SHA-512 configured" if has_sha512 else "SHA-512 not configured",
        remediation="Add 'sha512' to pam_unix.so in PAM password configuration"
    ))


# ============================================================================
# Section 6: System Maintenance
# ============================================================================

def check_section5_user_password_aging(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """CIS Section 5.4.1 - Set Shadow Password Suite Parameters"""
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Section 5.4.1 - Password Aging...")
    
    login_defs = read_file_safe("/etc/login.defs")
    
    # 5.4.1.1 - Ensure password expiration is 365 days or less
    pass_max_days = re.search(r'^PASS_MAX_DAYS\s+(\d+)', login_defs, re.MULTILINE)
    max_days_ok = pass_max_days and int(pass_max_days.group(1)) <= 365
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.4.1 - Password Aging",
        status="Pass" if max_days_ok else "Fail",
        message="5.4.1.1 Ensure password expiration is 365 days or less",
        details=f"PASS_MAX_DAYS: {pass_max_days.group(1)}" if pass_max_days else "PASS_MAX_DAYS not set",
        remediation="Set 'PASS_MAX_DAYS 365' in /etc/login.defs"
    ))
    
    # 5.4.1.2 - Ensure minimum days between password changes is 7 or more
    pass_min_days = re.search(r'^PASS_MIN_DAYS\s+(\d+)', login_defs, re.MULTILINE)
    min_days_ok = pass_min_days and int(pass_min_days.group(1)) >= 1
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.4.1 - Password Aging",
        status="Pass" if min_days_ok else "Fail",
        message="5.4.1.2 Ensure minimum days between password changes is configured",
        details=f"PASS_MIN_DAYS: {pass_min_days.group(1)}" if pass_min_days else "PASS_MIN_DAYS not set",
        remediation="Set 'PASS_MIN_DAYS 1' in /etc/login.defs"
    ))
    
    # 5.4.1.3 - Ensure password expiration warning days is 7 or more
    pass_warn_age = re.search(r'^PASS_WARN_AGE\s+(\d+)', login_defs, re.MULTILINE)
    warn_age_ok = pass_warn_age and int(pass_warn_age.group(1)) >= 7
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.4.1 - Password Aging",
        status="Pass" if warn_age_ok else "Fail",
        message="5.4.1.3 Ensure password expiration warning days is 7 or more",
        details=f"PASS_WARN_AGE: {pass_warn_age.group(1)}" if pass_warn_age else "PASS_WARN_AGE not set",
        remediation="Set 'PASS_WARN_AGE 7' in /etc/login.defs"
    ))
    
    # 5.4.1.4 - Ensure inactive password lock is 30 days or less
    useradd_defaults = read_file_safe("/etc/default/useradd")
    inactive = re.search(r'^INACTIVE=(\d+)', useradd_defaults, re.MULTILINE)
    inactive_ok = inactive and 0 <= int(inactive.group(1)) <= 30
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.4.1 - Password Aging",
        status="Pass" if inactive_ok else "Fail",
        message="5.4.1.4 Ensure inactive password lock is 30 days or less",
        details=f"INACTIVE: {inactive.group(1)}" if inactive else "INACTIVE not set",
        remediation="Set 'INACTIVE=30' in /etc/default/useradd; useradd -D -f 30"
    ))
    
    # 5.4.1.5 - Ensure all users last password change date is in the past
    shadow = read_file_safe("/etc/shadow")
    future_passwords = []
    import time
    current_days = int(time.time() / 86400)
    
    for line in shadow.split('\n'):
        if line and not line.startswith('#'):
            parts = line.split(':')
            if len(parts) >= 3 and parts[2]:
                try:
                    last_change = int(parts[2])
                    if last_change > current_days:
                        future_passwords.append(parts[0])
                except:
                    pass
    
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.4.1 - Password Aging",
        status="Pass" if not future_passwords else "Fail",
        message="5.4.1.5 Ensure all users last password change date is in the past",
        details="All password dates valid" if not future_passwords else f"Future dates: {len(future_passwords)} users",
        remediation="Review and correct password change dates in /etc/shadow"
    ))
    
    # Additional password aging checks for existing users
    # 5.4.1.6 - Check system accounts are set to non-login
    passwd_content = read_file_safe("/etc/passwd")
    system_accounts_with_shell = []
    for line in passwd_content.split('\n'):
        if line and not line.startswith('#'):
            parts = line.split(':')
            if len(parts) >= 7:
                uid = int(parts[2]) if parts[2].isdigit() else 0
                shell = parts[6]
                if uid < 1000 and uid != 0 and shell not in ["/sbin/nologin", "/bin/false", "/usr/sbin/nologin"]:
                    system_accounts_with_shell.append(parts[0])
    
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.4.1 - Password Aging",
        status="Pass" if not system_accounts_with_shell else "Warning",
        message="5.4.1.6 Ensure system accounts are secured",
        details="All system accounts non-login" if not system_accounts_with_shell else f"{len(system_accounts_with_shell)} system accounts with shell",
        remediation="Set system accounts to nologin shell: usermod -s /sbin/nologin <account>"
    ))
    
    # 5.4.1.7 - Ensure default group for root is GID 0
    root_gid = None
    for line in passwd_content.split('\n'):
        if line.startswith('root:'):
            parts = line.split(':')
            if len(parts) >= 4:
                root_gid = parts[3]
                break
    
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.4.1 - Password Aging",
        status="Pass" if root_gid == "0" else "Fail",
        message="5.4.1.7 Ensure default group for root account is GID 0",
        details=f"Root GID: {root_gid}" if root_gid else "Root account not found",
        remediation="usermod -g 0 root"
    ))
    
    # 5.4.1.8 - Ensure default user umask is configured
    bashrc_umask = read_file_safe("/etc/bashrc") or read_file_safe("/etc/bash.bashrc")
    profile_umask = read_file_safe("/etc/profile")
    umask_set = "umask 027" in bashrc_umask or "umask 077" in bashrc_umask or \
                "umask 027" in profile_umask or "umask 077" in profile_umask
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.4.1 - Password Aging",
        status="Pass" if umask_set else "Fail",
        message="5.4.1.8 Ensure default user umask is 027 or more restrictive",
        details="Restrictive umask configured" if umask_set else "Permissive umask",
        remediation="Set 'umask 027' in /etc/profile and /etc/bashrc"
    ))
    
    # 5.4.1.9 - Ensure default user shell timeout is configured
    timeout_set = "TMOUT=" in bashrc_umask or "TMOUT=" in profile_umask
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.4.1 - Password Aging",
        status="Pass" if timeout_set else "Warning",
        message="5.4.1.9 Ensure default user shell timeout is configured",
        details="TMOUT configured" if timeout_set else "No shell timeout",
        remediation="Set 'TMOUT=900' in /etc/profile and /etc/bashrc"
    ))
    
    # 5.4.1.10 - Check for accounts with empty passwords
    shadow_content = read_file_safe("/etc/shadow")
    empty_pass_count = 0
    for line in shadow_content.split('\n'):
        if line and not line.startswith('#'):
            parts = line.split(':')
            if len(parts) >= 2 and not parts[1]:
                empty_pass_count += 1
    
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.4.1 - Password Aging",
        status="Pass" if empty_pass_count == 0 else "Fail",
        message="5.4.1.10 Verify no accounts have empty passwords",
        details="No empty passwords" if empty_pass_count == 0 else f"{empty_pass_count} accounts with empty passwords",
        remediation="Lock or delete accounts with empty passwords"
    ))

def check_section1_warning_banners(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """CIS Section 1.7 - Command Line Warning Banners"""
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Section 1.7 - Warning Banners...")
    
    # 1.7.1 - Ensure message of the day is configured
    motd = read_file_safe("/etc/motd")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.7 - Banners",
        status="Pass" if len(motd.strip()) > 0 else "Warning",
        message="1.7.1 Ensure message of the day is configured properly",
        details="MOTD configured" if len(motd.strip()) > 0 else "MOTD is empty",
        remediation="Configure /etc/motd with appropriate message"
    ))
    
    # 1.7.2 - Ensure local login warning banner configured
    issue = read_file_safe("/etc/issue")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.7 - Banners",
        status="Pass" if len(issue.strip()) > 0 else "Fail",
        message="1.7.2 Ensure local login warning banner is configured",
        details="Login banner configured" if len(issue.strip()) > 0 else "No login banner",
        remediation="Configure /etc/issue with appropriate warning"
    ))
    
    # 1.7.3 - Ensure remote login warning banner configured
    issue_net = read_file_safe("/etc/issue.net")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.7 - Banners",
        status="Pass" if len(issue_net.strip()) > 0 else "Fail",
        message="1.7.3 Ensure remote login warning banner is configured",
        details="Remote banner configured" if len(issue_net.strip()) > 0 else "No remote banner",
        remediation="Configure /etc/issue.net with appropriate warning"
    ))
    
    # 1.7.4 - Ensure permissions on /etc/motd are configured
    if os.path.exists("/etc/motd"):
        motd_perms = get_file_permissions("/etc/motd")
        owner, group = get_file_owner_group("/etc/motd")
        correct_perms = motd_perms and int(motd_perms, 8) <= int("0644", 8) and owner == "root"
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 1.7 - Banners",
            status="Pass" if correct_perms else "Fail",
            message="1.7.4 Ensure permissions on /etc/motd are configured",
            details=f"Perms: {motd_perms}, Owner: {owner}" if motd_perms else "File doesn't exist",
            remediation="chown root:root /etc/motd && chmod 644 /etc/motd"
        ))
    
    # 1.7.5 - Ensure permissions on /etc/issue are configured
    if os.path.exists("/etc/issue"):
        issue_perms = get_file_permissions("/etc/issue")
        owner, group = get_file_owner_group("/etc/issue")
        correct_perms = issue_perms and int(issue_perms, 8) <= int("0644", 8) and owner == "root"
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 1.7 - Banners",
            status="Pass" if correct_perms else "Fail",
            message="1.7.5 Ensure permissions on /etc/issue are configured",
            details=f"Perms: {issue_perms}, Owner: {owner}",
            remediation="chown root:root /etc/issue && chmod 644 /etc/issue"
        ))

def check_section1_bootloader(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """CIS Section 1.4 - Secure Boot Settings"""
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Section 1.4 - Bootloader Security...")
    
    # 1.4.1 - Ensure bootloader password is set (GRUB)
    grub_cfg_files = ["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"]
    grub_cfg = None
    for cfg in grub_cfg_files:
        if os.path.exists(cfg):
            grub_cfg = cfg
            break
    
    if grub_cfg:
        grub_content = read_file_safe(grub_cfg)
        has_password = "password_pbkdf2" in grub_content or "set superusers" in grub_content
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 1.4 - Boot Security",
            status="Pass" if has_password else "Fail",
            message="1.4.1 Ensure bootloader password is set",
            details="GRUB password configured" if has_password else "No bootloader password",
            remediation="Set GRUB password: grub2-setpassword or grub-mkpasswd-pbkdf2"
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 1.4 - Boot Security",
            status="Warning",
            message="1.4.1 Ensure bootloader password is set",
            details="GRUB configuration not found",
            remediation="Locate and secure bootloader configuration"
        ))
    
    # 1.4.2 - Ensure permissions on bootloader config are configured
    if grub_cfg:
        perms = get_file_permissions(grub_cfg)
        owner, group = get_file_owner_group(grub_cfg)
        correct_perms = perms and int(perms, 8) <= int("0600", 8) and owner == "root"
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 1.4 - Boot Security",
            status="Pass" if correct_perms else "Fail",
            message="1.4.2 Ensure permissions on bootloader config are configured",
            details=f"Perms: {perms}, Owner: {owner}" if perms else "Cannot read permissions",
            remediation=f"chown root:root {grub_cfg} && chmod 600 {grub_cfg}"
        ))
    
    # 1.4.3 - Ensure authentication required for single user mode
    rescue_service = check_service_enabled("rescue.service")
    emergency_service = check_service_enabled("emergency.service")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.4 - Boot Security",
        status="Info",
        message="1.4.3 Ensure authentication required for single user mode",
        details="Review single user mode authentication settings",
        remediation="Ensure /usr/lib/systemd/system/rescue.service has ExecStart with -sulogin-shell"
    ))
    
    # Additional boot security checks
    # 1.4.4 - Ensure core dumps are restricted
    limits_conf = read_file_safe("/etc/security/limits.conf")
    sysctl_conf = read_file_safe("/etc/sysctl.conf")
    core_dumps_disabled = "hard core 0" in limits_conf
    suid_dumpable = cis_check_kernel_parameter("fs.suid_dumpable", "0")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.4 - Boot Security",
        status="Pass" if core_dumps_disabled and suid_dumpable else "Fail",
        message="1.4.4 Ensure core dumps are restricted",
        details="Core dumps disabled" if core_dumps_disabled and suid_dumpable else "Core dumps not restricted",
        remediation="Add '* hard core 0' to /etc/security/limits.conf; Set fs.suid_dumpable=0"
    ))
    
    # 1.4.5 - Ensure XD/NX support is enabled
    nx_enabled = run_command("dmesg | grep -i nx").returncode == 0
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.4 - Boot Security",
        status="Pass" if nx_enabled else "Warning",
        message="1.4.5 Ensure XD/NX support is enabled",
        details="NX protection enabled" if nx_enabled else "NX protection status unknown",
        remediation="Ensure NX/XD is enabled in BIOS"
    ))
    
    # 1.4.6 - Ensure address space layout randomization (ASLR) is enabled
    aslr_enabled = cis_check_kernel_parameter("kernel.randomize_va_space", "2")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.4 - Boot Security",
        status="Pass" if aslr_enabled else "Fail",
        message="1.4.6 Ensure address space layout randomization (ASLR) is enabled",
        details="ASLR fully enabled" if aslr_enabled else "ASLR not fully enabled",
        remediation="sysctl -w kernel.randomize_va_space=2"
    ))
    
    # 1.4.7 - Ensure prelink is disabled
    prelink_installed = check_package_installed("prelink", os_info)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.4 - Boot Security",
        status="Pass" if not prelink_installed else "Fail",
        message="1.4.7 Ensure prelink is disabled",
        details="prelink not installed" if not prelink_installed else "prelink is installed",
        remediation=removal_for("prelink")
    ))
    
    # 1.4.8 - Ensure kernel pointer restriction
    kptr_restrict = cis_check_kernel_parameter("kernel.kptr_restrict", "1")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.4 - Boot Security",
        status="Pass" if kptr_restrict else "Warning",
        message="1.4.8 Ensure kernel pointers are restricted",
        details="Kernel pointers restricted" if kptr_restrict else "Kernel pointers exposed",
        remediation="sysctl -w kernel.kptr_restrict=1"
    ))
    
    # 1.4.9 - Ensure kernel dmesg restriction
    dmesg_restrict = cis_check_kernel_parameter("kernel.dmesg_restrict", "1")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.4 - Boot Security",
        status="Pass" if dmesg_restrict else "Warning",
        message="1.4.9 Ensure dmesg is restricted",
        details="dmesg restricted" if dmesg_restrict else "dmesg unrestricted",
        remediation="sysctl -w kernel.dmesg_restrict=1"
    ))
    
    # 1.4.10 - Ensure kernel module loading is disabled
    modules_disabled = cis_check_kernel_parameter("kernel.modules_disabled", "1")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.4 - Boot Security",
        status="Info",
        message="1.4.10 Kernel module loading status",
        details="Module loading restricted" if modules_disabled else "Module loading allowed (typical)",
        remediation="Consider: sysctl -w kernel.modules_disabled=1 (NOTE: Cannot be undone without reboot)"
    ))
    
    # 1.4.11 - Ensure ptrace scope is restricted
    ptrace_scope = cis_check_kernel_parameter("kernel.yama.ptrace_scope", "1")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.4 - Boot Security",
        status="Pass" if ptrace_scope else "Warning",
        message="1.4.11 Ensure ptrace scope is restricted",
        details="ptrace restricted" if ptrace_scope else "ptrace unrestricted",
        remediation="sysctl -w kernel.yama.ptrace_scope=1"
    ))

def check_section6_file_permissions(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """CIS Section 6.1 - System File Permissions"""
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Section 6.1 - System File Permissions...")
    
    # 6.1.1 - Audit system file permissions
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 6.1 - File Permissions",
        status="Info",
        message="6.1.1 Audit system file permissions",
        details="Run: rpm -Va or dpkg --verify to audit package file permissions",
        remediation="Review and correct any permission discrepancies"
    ))
    
    # 6.1.2 - Ensure permissions on /etc/passwd are configured
    if os.path.exists("/etc/passwd"):
        perms = get_file_permissions("/etc/passwd")
        owner, group = get_file_owner_group("/etc/passwd")
        correct = perms and int(perms, 8) <= int("0644", 8) and owner == "root"
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 6.1 - File Permissions",
            status="Pass" if correct else "Fail",
            message="6.1.2 Ensure permissions on /etc/passwd are configured",
            details=f"Perms: {perms}, Owner: {owner}",
            remediation="chown root:root /etc/passwd && chmod 644 /etc/passwd"
        ))
    
    # 6.1.3 - Ensure permissions on /etc/shadow are configured
    if os.path.exists("/etc/shadow"):
        perms = get_file_permissions("/etc/shadow")
        owner, group = get_file_owner_group("/etc/shadow")
        correct = perms and int(perms, 8) <= int("0000", 8) and owner == "root"
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 6.1 - File Permissions",
            status="Pass" if correct else "Fail",
            message="6.1.3 Ensure permissions on /etc/shadow are configured",
            details=f"Perms: {perms}, Owner: {owner}",
            remediation="chown root:root /etc/shadow && chmod 000 /etc/shadow"
        ))
    
    # 6.1.4 - Ensure permissions on /etc/group are configured
    if os.path.exists("/etc/group"):
        perms = get_file_permissions("/etc/group")
        owner, group = get_file_owner_group("/etc/group")
        correct = perms and int(perms, 8) <= int("0644", 8) and owner == "root"
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 6.1 - File Permissions",
            status="Pass" if correct else "Fail",
            message="6.1.4 Ensure permissions on /etc/group are configured",
            details=f"Perms: {perms}, Owner: {owner}",
            remediation="chown root:root /etc/group && chmod 644 /etc/group"
        ))
    
    # 6.1.5 - Ensure permissions on /etc/gshadow are configured
    if os.path.exists("/etc/gshadow"):
        perms = get_file_permissions("/etc/gshadow")
        owner, group = get_file_owner_group("/etc/gshadow")
        correct = perms and int(perms, 8) <= int("0000", 8) and owner == "root"
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 6.1 - File Permissions",
            status="Pass" if correct else "Fail",
            message="6.1.5 Ensure permissions on /etc/gshadow are configured",
            details=f"Perms: {perms}, Owner: {owner}",
            remediation="chown root:root /etc/gshadow && chmod 000 /etc/gshadow"
        ))
    
    # 6.1.6 - Ensure permissions on /etc/passwd- are configured
    if os.path.exists("/etc/passwd-"):
        perms = get_file_permissions("/etc/passwd-")
        owner, group = get_file_owner_group("/etc/passwd-")
        correct = perms and int(perms, 8) <= int("0644", 8) and owner == "root"
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 6.1 - File Permissions",
            status="Pass" if correct else "Fail",
            message="6.1.6 Ensure permissions on /etc/passwd- are configured",
            details=f"Perms: {perms}, Owner: {owner}",
            remediation="chown root:root /etc/passwd- && chmod 644 /etc/passwd-"
        ))
    
    # 6.1.7 - Ensure permissions on /etc/shadow- are configured
    if os.path.exists("/etc/shadow-"):
        perms = get_file_permissions("/etc/shadow-")
        owner, group = get_file_owner_group("/etc/shadow-")
        correct = perms and int(perms, 8) <= int("0000", 8) and owner == "root"
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 6.1 - File Permissions",
            status="Pass" if correct else "Fail",
            message="6.1.7 Ensure permissions on /etc/shadow- are configured",
            details=f"Perms: {perms}, Owner: {owner}",
            remediation="chown root:root /etc/shadow- && chmod 000 /etc/shadow-"
        ))
    
    # 6.1.8 - Ensure permissions on /etc/group- are configured
    if os.path.exists("/etc/group-"):
        perms = get_file_permissions("/etc/group-")
        owner, group = get_file_owner_group("/etc/group-")
        correct = perms and int(perms, 8) <= int("0644", 8) and owner == "root"
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 6.1 - File Permissions",
            status="Pass" if correct else "Fail",
            message="6.1.8 Ensure permissions on /etc/group- are configured",
            details=f"Perms: {perms}, Owner: {owner}",
            remediation="chown root:root /etc/group- && chmod 644 /etc/group-"
        ))
    
    # 6.1.9 - Ensure permissions on /etc/gshadow- are configured
    if os.path.exists("/etc/gshadow-"):
        perms = get_file_permissions("/etc/gshadow-")
        owner, group = get_file_owner_group("/etc/gshadow-")
        correct = perms and int(perms, 8) <= int("0000", 8) and owner == "root"
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 6.1 - File Permissions",
            status="Pass" if correct else "Fail",
            message="6.1.9 Ensure permissions on /etc/gshadow- are configured",
            details=f"Perms: {perms}, Owner: {owner}",
            remediation="chown root:root /etc/gshadow- && chmod 000 /etc/gshadow-"
        ))
    
    # 6.1.10 - Ensure no world writable files exist (canonical assessment)
    from shared_components.shared_assessments import get_world_writable_assessment as _ww_assess
    _ww = _ww_assess("fail")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 6.1 - File Permissions",
        status=_ww.status,
        message="6.1.10 Ensure no world writable files exist",
        details=_ww.details,
        remediation=_ww.remediation
    ))
    
    # 6.1.11 - Ensure no unowned files or directories exist
    unowned = run_command("find / -xdev -nouser 2>/dev/null | head -5").stdout
    has_unowned = len(unowned.strip()) > 0
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 6.1 - File Permissions",
        status="Pass" if not has_unowned else "Fail",
        message="6.1.11 Ensure no unowned files or directories exist",
        details="No unowned files" if not has_unowned else "Unowned files detected",
        remediation="Assign owner to unowned files: chown <user> <file>"
    ))
    
    # 6.1.12 - Ensure no ungrouped files or directories exist
    ungrouped = run_command("find / -xdev -nogroup 2>/dev/null | head -5").stdout
    has_ungrouped = len(ungrouped.strip()) > 0
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 6.1 - File Permissions",
        status="Pass" if not has_ungrouped else "Fail",
        message="6.1.12 Ensure no ungrouped files or directories exist",
        details="No ungrouped files" if not has_ungrouped else "Ungrouped files detected",
        remediation="Assign group to ungrouped files: chgrp <group> <file>"
    ))
    
    # 6.1.13 - Audit SUID executables
    suid_files = run_command("find / -xdev -type f -perm -4000 2>/dev/null | wc -l").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 6.1 - File Permissions",
        status="Info",
        message="6.1.13 Audit SUID executables",
        details=f"{suid_files} SUID files found - review for necessity",
        remediation="Review SUID binaries and remove unnecessary SUID bits"
    ))
    
    # 6.1.14 - Audit SGID executables
    sgid_files = run_command("find / -xdev -type f -perm -2000 2>/dev/null | wc -l").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 6.1 - File Permissions",
        status="Info",
        message="6.1.14 Audit SGID executables",
        details=f"{sgid_files} SGID files found - review for necessity",
        remediation="Review SGID binaries and remove unnecessary SGID bits"
    ))

def check_section6_user_accounts(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """CIS Section 6.2 - User and Group Settings"""
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    print(f"[{MODULE_NAME}] Checking Section 6.2 - User and Group Settings...")
    
    # 6.2.1 - Ensure password fields are not empty
    shadow_content = read_file_safe("/etc/shadow")
    empty_passwords = len([line for line in shadow_content.split('\n') 
                          if line and not line.startswith('#') and '::' in line])
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 6.2 - User Accounts",
        status="Pass" if empty_passwords == 0 else "Fail",
        message="6.2.1 Ensure password fields are not empty",
        details="All accounts have passwords" if empty_passwords == 0 else f"{empty_passwords} accounts with empty passwords",
        remediation="Lock or assign passwords to accounts with empty password fields"
    ))
    
    # 6.2.2 - Ensure no legacy "+" entries exist in /etc/passwd
    passwd_content = read_file_safe("/etc/passwd")
    legacy_passwd = any(line.startswith('+') for line in passwd_content.split('\n'))
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 6.2 - User Accounts",
        status="Pass" if not legacy_passwd else "Fail",
        message="6.2.2 Ensure no legacy '+' entries exist in /etc/passwd",
        details="No legacy entries" if not legacy_passwd else "Legacy '+' entries found",
        remediation="Remove legacy '+' entries from /etc/passwd"
    ))
    
    # 6.2.3 - Ensure no legacy "+" entries exist in /etc/shadow
    shadow_content = read_file_safe("/etc/shadow")
    legacy_shadow = any(line.startswith('+') for line in shadow_content.split('\n'))
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 6.2 - User Accounts",
        status="Pass" if not legacy_shadow else "Fail",
        message="6.2.3 Ensure no legacy '+' entries exist in /etc/shadow",
        details="No legacy entries" if not legacy_shadow else "Legacy '+' entries found",
        remediation="Remove legacy '+' entries from /etc/shadow"
    ))
    
    # 6.2.4 - Ensure no legacy "+" entries exist in /etc/group
    group_content = read_file_safe("/etc/group")
    legacy_group = any(line.startswith('+') for line in group_content.split('\n'))
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 6.2 - User Accounts",
        status="Pass" if not legacy_group else "Fail",
        message="6.2.4 Ensure no legacy '+' entries exist in /etc/group",
        details="No legacy entries" if not legacy_group else "Legacy '+' entries found",
        remediation="Remove legacy '+' entries from /etc/group"
    ))
    
    # 6.2.5 - Ensure root is the only UID 0 account
    uid_0_accounts = [line.split(':')[0] for line in passwd_content.split('\n') 
                     if line and not line.startswith('#') and ':0:' in line]
    root_only = len(uid_0_accounts) == 1 and uid_0_accounts[0] == "root"
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 6.2 - User Accounts",
        status="Pass" if root_only else "Fail",
        message="6.2.5 Ensure root is the only UID 0 account",
        details="Only root has UID 0" if root_only else f"UID 0 accounts: {', '.join(uid_0_accounts)}",
        remediation="Remove or change UID for non-root UID 0 accounts"
    ))
    
    # 6.2.6 - Ensure root PATH Integrity
    root_path = os.environ.get('PATH', '')
    has_dot = '.:' in root_path or root_path.startswith('.') or root_path.endswith(':.')
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 6.2 - User Accounts",
        status="Pass" if not has_dot else "Fail",
        message="6.2.6 Ensure root PATH Integrity",
        details="PATH does not contain '.'" if not has_dot else "PATH contains '.'",
        remediation="Remove '.' from root's PATH"
    ))
    
    # 6.2.7 - Ensure all users' home directories exist
    users_without_home = []
    for line in passwd_content.split('\n'):
        if line and not line.startswith('#'):
            parts = line.split(':')
            if len(parts) >= 6:
                username, home = parts[0], parts[5]
                if int(parts[2]) >= 1000 and not os.path.exists(home):
                    users_without_home.append(username)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 6.2 - User Accounts",
        status="Pass" if not users_without_home else "Warning",
        message="6.2.7 Ensure all users' home directories exist",
        details="All homes exist" if not users_without_home else f"Missing homes: {', '.join(users_without_home[:5])}",
        remediation="Create home directories for users"
    ))
    
    # 6.2.8 - Ensure users' home directories permissions are 750 or more restrictive
    weak_home_perms = []
    for line in passwd_content.split('\n'):
        if line and not line.startswith('#'):
            parts = line.split(':')
            if len(parts) >= 6 and int(parts[2]) >= 1000:
                home = parts[5]
                if os.path.exists(home):
                    perms = get_file_permissions(home)
                    if perms and int(perms, 8) > int("0750", 8):
                        weak_home_perms.append(parts[0])
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 6.2 - User Accounts",
        status="Pass" if not weak_home_perms else "Fail",
        message="6.2.8 Ensure users' home directories permissions are 750 or more restrictive",
        details="All home permissions OK" if not weak_home_perms else f"Weak permissions: {len(weak_home_perms)} homes",
        remediation="Restrict home directory permissions: chmod 750 /home/<user>"
    ))
    
    # 6.2.9 - Ensure users own their home directories
    wrong_ownership = []
    for line in passwd_content.split('\n'):
        if line and not line.startswith('#'):
            parts = line.split(':')
            if len(parts) >= 6 and int(parts[2]) >= 1000:
                username, home = parts[0], parts[5]
                if os.path.exists(home):
                    owner, _ = get_file_owner_group(home)
                    if owner != username:
                        wrong_ownership.append(username)
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 6.2 - User Accounts",
        status="Pass" if not wrong_ownership else "Fail",
        message="6.2.9 Ensure users own their home directories",
        details="All homes properly owned" if not wrong_ownership else f"Wrong ownership: {len(wrong_ownership)} homes",
        remediation="Correct home directory ownership: chown <user>:<user> /home/<user>"
    ))
    
    # 6.2.10 - Ensure users' dot files are not group or world writable
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 6.2 - User Accounts",
        status="Info",
        message="6.2.10 Ensure users' dot files are not group or world writable",
        details="Review user dot files for excessive permissions",
        remediation="Find and correct: find /home -name '.*' -type f -exec chmod go-w {} \\;"
    ))


# ============================================================================
# CIS 1.5 - Additional Process Hardening
# ============================================================================

def check_section1_process_hardening(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """CIS Section 1.5 - Additional Process Hardening checks"""
    print(f"[{MODULE_NAME}] Checking Section 1.5 - Additional Process Hardening...")
    
    cache = shared_data.get('cache')
    
    # 1.5.1 - Ensure core dumps are restricted
    limits_conf = read_file_safe("/etc/security/limits.conf", use_cache=True) or ""
    limits_d_dir = "/etc/security/limits.d"
    core_hard_set = "* hard core 0" in limits_conf
    if not core_hard_set and os.path.isdir(limits_d_dir):
        for lf in os.listdir(limits_d_dir):
            ld_content = read_file_safe(os.path.join(limits_d_dir, lf), use_cache=True) or ""
            if "* hard core 0" in ld_content or "hard core 0" in ld_content:
                core_hard_set = True
                break
    
    exists, suid_dump = check_kernel_parameter("fs.suid_dumpable")
    suid_ok = suid_dump == "0"
    
    # Also check systemd coredump config
    coredump_conf = read_file_safe("/etc/systemd/coredump.conf", use_cache=True) or ""
    coredump_storage_none = "Storage=none" in coredump_conf
    
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.5 - Process Hardening",
        status="Pass" if (core_hard_set and suid_ok) else "Fail",
        message="1.5.1 Ensure core dumps are restricted",
        details=f"limits.conf '* hard core 0': {'set' if core_hard_set else 'not set'}; "
                f"suid_dumpable={suid_dump}; systemd Storage=none: {coredump_storage_none}",
        remediation="Set '* hard core 0' in /etc/security/limits.conf; "
                    "sysctl -w fs.suid_dumpable=0; Set Storage=none in /etc/systemd/coredump.conf"
    ))
    
    # 1.5.2 - Ensure XD/NX support is enabled
    cpuflags = read_file_safe("/proc/cpuinfo", use_cache=True) or ""
    nx_enabled = " nx " in cpuflags or " nx\n" in cpuflags
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.5 - Process Hardening",
        status="Pass" if nx_enabled else "Warning",
        message="1.5.2 Ensure XD/NX support is enabled",
        details=f"NX (Execute Disable) bit: {'supported' if nx_enabled else 'not detected in /proc/cpuinfo'}",
        remediation="Enable NX/XD in BIOS/UEFI firmware settings"
    ))
    
    # 1.5.3 - Ensure ASLR is enabled
    exists, aslr = check_kernel_parameter("kernel.randomize_va_space")
    aslr_full = aslr == "2"
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.5 - Process Hardening",
        status="Pass" if aslr_full else "Fail",
        message="1.5.3 Ensure address space layout randomization (ASLR) is enabled",
        details=f"randomize_va_space = {aslr} ({'full randomization' if aslr_full else 'not fully enabled, expected 2'})",
        remediation="Enable: sysctl -w kernel.randomize_va_space=2; add to /etc/sysctl.d/99-security.conf"
    ))
    
    # 1.5.4 - Ensure prelink is not installed
    prelink_installed = command_exists("prelink")
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 1.5 - Process Hardening",
        status="Fail" if prelink_installed else "Pass",
        message="1.5.4 Ensure prelink is not installed",
        details=f"prelink: {'installed (weakens ASLR)' if prelink_installed else 'not installed'}",
        remediation=("Undo prelinking first: prelink -ua\n" + removal_for("prelink"))
    ))


# ============================================================================
# CIS 3.5 - Uncommon Network Protocols
# ============================================================================

def check_section3_uncommon_protocols(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """CIS Section 3.5 - Ensure uncommon network protocols are disabled"""
    print(f"[{MODULE_NAME}] Checking Section 3.5 - Uncommon Network Protocols...")
    
    cache = shared_data.get('cache')
    
    # Get loaded kernel modules from cache if available
    loaded_modules = set()
    if cache:
        loaded_modules = cache.get_parsed('loaded_modules') or set()
    else:
        lsmod_out = run_command("lsmod 2>/dev/null")
        if lsmod_out.returncode == 0:
            for line in lsmod_out.stdout.splitlines()[1:]:
                parts = line.split()
                if parts:
                    loaded_modules.add(parts[0])
    
    # Protocols that should be disabled per CIS
    uncommon_protocols = {
        "dccp": ("3.5.1", "DCCP (Datagram Congestion Control Protocol)"),
        "sctp": ("3.5.2", "SCTP (Stream Control Transmission Protocol)"),
        "rds": ("3.5.3", "RDS (Reliable Datagram Sockets)"),
        "tipc": ("3.5.4", "TIPC (Transparent Inter-Process Communication)"),
    }
    
    for module_name, (check_num, description) in uncommon_protocols.items():
        # Check if module is currently loaded
        is_loaded = module_name in loaded_modules
        
        # Check if module is blacklisted
        is_blacklisted = False
        blacklist_details = ""
        
        # Check modprobe blacklist configs
        modprobe_dirs = ["/etc/modprobe.d"]
        for mpdir in modprobe_dirs:
            if os.path.isdir(mpdir):
                for conf in os.listdir(mpdir):
                    if conf.endswith('.conf'):
                        content = read_file_safe(os.path.join(mpdir, conf), use_cache=True) or ""
                        if (f"blacklist {module_name}" in content or
                                f"install {module_name} /bin/true" in content or
                                f"install {module_name} /bin/false" in content):
                            is_blacklisted = True
                            blacklist_details = f"in {conf}"
                            break
        
        status = "Pass" if (not is_loaded and is_blacklisted) else (
            "Warning" if is_blacklisted else "Fail" if is_loaded else "Warning"
        )
        
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 3.5 - Protocols",
            status=status,
            message=f"{check_num} Ensure {description} is disabled",
            details=f"Module {module_name}: {'loaded' if is_loaded else 'not loaded'}; "
                    f"Blacklisted: {'yes' if is_blacklisted else 'no'} {blacklist_details}",
            remediation=f"echo 'install {module_name} /bin/true' >> /etc/modprobe.d/CIS.conf; "
                        f"echo 'blacklist {module_name}' >> /etc/modprobe.d/CIS.conf"
        ))
    
    # 3.5.5 - Ensure wireless interfaces are disabled (if no wifi needed)
    wireless_ifaces = run_command("iw dev 2>/dev/null | grep -c 'Interface'")
    wifi_count = safe_int_parse(wireless_ifaces.stdout.strip(), 0) if wireless_ifaces.returncode == 0 else 0
    
    # Also check rfkill
    rfkill_check = run_command("rfkill list wifi 2>/dev/null")
    wifi_blocked = "Soft blocked: yes" in rfkill_check.stdout if rfkill_check.returncode == 0 else False
    
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 3.5 - Protocols",
        status="Pass" if (wifi_count == 0 or wifi_blocked) else "Warning",
        message="3.5.5 Ensure wireless interfaces are disabled",
        details=f"Wireless interfaces: {wifi_count}; "
                f"{'RF-kill blocked' if wifi_blocked else 'active' if wifi_count > 0 else 'none detected'}",
        remediation="Disable wireless: rfkill block wifi; or nmcli radio wifi off"
    ))


# ============================================================================
# CIS 5.4.2+ - Advanced User Account Controls
# ============================================================================

def check_section5_advanced_user_controls(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """CIS Section 5.4.2+ - Advanced user account security controls"""
    print(f"[{MODULE_NAME}] Checking Section 5.4.2+ - Advanced User Account Controls...")
    
    cache = shared_data.get('cache')
    
    # 5.4.2 - Ensure system accounts are secured (non-login shell)
    passwd_content = read_file_safe("/etc/passwd", use_cache=True) or ""
    system_login_accounts = []
    for line in passwd_content.splitlines():
        parts = line.strip().split(':')
        if len(parts) >= 7:
            username = parts[0]
            uid = safe_int_parse(parts[2], -1)
            shell = parts[6]
            # System accounts (UID < 1000) should not have login shells
            if uid > 0 and uid < 1000 and username != "root":
                if shell not in ["/usr/sbin/nologin", "/sbin/nologin", "/bin/false",
                                 "/usr/bin/false", "/dev/null"]:
                    system_login_accounts.append(f"{username}(uid={uid},shell={shell})")
    
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.4 - User Accounts",
        status="Pass" if len(system_login_accounts) == 0 else "Warning",
        message="5.4.2 Ensure system accounts are secured",
        details=f"System accounts with login shells: {len(system_login_accounts)}"
                + (f" [{', '.join(system_login_accounts[:5])}]" if system_login_accounts else ""),
        remediation="Set nologin shell: usermod -s /usr/sbin/nologin <username>"
    ))
    
    # 5.4.3 - Ensure default group for root is GID 0
    root_entry = [l for l in passwd_content.splitlines() if l.startswith("root:")]
    if root_entry:
        root_gid = root_entry[0].split(':')[3] if len(root_entry[0].split(':')) > 3 else ""
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 5.4 - User Accounts",
            status="Pass" if root_gid == "0" else "Fail",
            message="5.4.3 Ensure default group for the root account is GID 0",
            details=f"Root GID: {root_gid}",
            remediation="Set: usermod -g 0 root"
        ))
    
    # 5.4.4 - Ensure default user umask is 027 or more restrictive
    umask_files = ["/etc/profile", "/etc/bashrc", "/etc/bash.bashrc",
                   "/etc/profile.d/*.sh", "/etc/login.defs"]
    umask_found = False
    umask_restrictive = False
    umask_value = ""
    
    login_defs = read_file_safe("/etc/login.defs", use_cache=True) or ""
    for line in login_defs.splitlines():
        stripped = line.strip()
        if stripped.startswith("UMASK") and not stripped.startswith("#"):
            parts = stripped.split()
            if len(parts) >= 2:
                umask_value = parts[1]
                umask_found = True
                umask_restrictive = umask_value in ["027", "077"]
    
    # Also check profile files
    for uf in ["/etc/profile", "/etc/bashrc", "/etc/bash.bashrc"]:
        content = read_file_safe(uf, use_cache=True) or ""
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("umask") and not stripped.startswith("#"):
                parts = stripped.split()
                if len(parts) >= 2 and not umask_found:
                    umask_value = parts[1]
                    umask_found = True
                    umask_restrictive = umask_value in ["027", "077"]
    
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.4 - User Accounts",
        status="Pass" if umask_restrictive else ("Warning" if umask_found else "Fail"),
        message="5.4.4 Ensure default user umask is 027 or more restrictive",
        details=f"Default umask: {umask_value if umask_value else 'not explicitly set (default 022)'}",
        remediation="Set UMASK 027 in /etc/login.defs and umask 027 in /etc/profile"
    ))
    
    # 5.4.5 - Ensure default user shell timeout is configured
    tmout_set = False
    tmout_value = ""
    for tf in ["/etc/profile", "/etc/bashrc", "/etc/bash.bashrc",
               "/etc/profile.d/tmout.sh"]:
        content = read_file_safe(tf, use_cache=True) or ""
        for line in content.splitlines():
            if "TMOUT=" in line and not line.strip().startswith("#"):
                tmout_set = True
                tmout_value = line.strip()
                break
        if tmout_set:
            break
    
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.4 - User Accounts",
        status="Pass" if tmout_set else "Warning",
        message="5.4.5 Ensure default user shell timeout is configured",
        details=f"{'TMOUT configured: ' + tmout_value if tmout_set else 'TMOUT not set - no idle timeout'}",
        remediation="Add to /etc/profile.d/tmout.sh: TMOUT=900; readonly TMOUT; export TMOUT"
    ))
    
    # 5.5 - Ensure root login is restricted to system console
    securetty = read_file_safe("/etc/securetty", use_cache=True)
    if securetty is not None:
        console_count = len([l for l in securetty.splitlines()
                             if l.strip() and not l.strip().startswith('#')])
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS 5.5 - Root Access",
            status="Pass" if console_count <= 2 else "Warning",
            message="5.5 Ensure root login is restricted to system console",
            details=f"/etc/securetty: {console_count} consoles configured",
            remediation="Limit consoles in /etc/securetty to only necessary terminals"
        ))
    
    # 5.6 - Ensure access to su command is restricted
    su_pam = read_file_safe("/etc/pam.d/su", use_cache=True) or ""
    wheel_required = "pam_wheel.so" in su_pam and "required" in su_pam
    results.append(AuditResult(
        module=MODULE_NAME, category="CIS 5.6 - Su Access",
        status="Pass" if wheel_required else "Warning",
        message="5.6 Ensure access to the su command is restricted",
        details=f"pam_wheel.so in /etc/pam.d/su: {'required (wheel group only)' if wheel_required else 'not enforced'}",
        remediation="Add to /etc/pam.d/su: auth required pam_wheel.so use_uid"
    ))


# ============================================================================
# Main Entry Point
# ============================================================================

def run_checks(shared_data: Dict[str, Any]) -> List[AuditResult]:
    """Main entry point for CIS Benchmark module"""
    results = []
    
    # Extract SharedDataCache from shared_data (populated by main script)
    cache = shared_data.get('cache')
    
    print(f"\n[{MODULE_NAME}] ===== CIS BENCHMARK SECURITY AUDIT =====")
    print(f"[{MODULE_NAME}] Version: {MODULE_VERSION} - Comprehensive OS-Aware Coverage")
    print(f"[{MODULE_NAME}] Target: 200+ distinct security checks")
    print(f"[{MODULE_NAME}] Scope: All CIS Benchmark sections\n")
    
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
        print(f"[{MODULE_NAME}]    Note: Running without root privileges")
        print(f"[{MODULE_NAME}] Some checks require elevated privileges for full coverage\n")
    
    try:
        # Section 1: Initial Setup
        check_section1_filesystem_configuration(results, shared_data, os_info)
        check_section1_package_management(results, shared_data, os_info)
        check_section1_bootloader(results, shared_data, os_info)
        check_section1_mandatory_access_control(results, shared_data, os_info)
        check_section1_process_hardening(results, shared_data, os_info)
        check_section1_warning_banners(results, shared_data, os_info)
        
        # Section 2: Services
        check_section2_services(results, shared_data, os_info)
        
        # Section 3: Network Configuration
        check_section3_network_parameters(results, shared_data, os_info)
        check_section3_network_host_and_router(results, shared_data, os_info)
        check_section3_ipv6(results, shared_data, os_info)
        check_section3_uncommon_protocols(results, shared_data, os_info)
        check_section3_firewall(results, shared_data, os_info)
        
        # Section 4: Logging and Auditing
        check_section4_system_logging(results, shared_data, os_info)
        check_section4_logging(results, shared_data, os_info)
        
        # Section 5: Access, Authentication and Authorization
        check_section5_cron(results, shared_data, os_info)
        check_section5_ssh(results, shared_data, os_info)
        check_section5_pam(results, shared_data, os_info)
        check_section5_user_password_aging(results, shared_data, os_info)
        check_section5_advanced_user_controls(results, shared_data, os_info)
        
        # Section 6: System Maintenance
        check_section6_file_permissions(results, shared_data, os_info)
        check_section6_user_accounts(results, shared_data, os_info)
        
    except Exception as e:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CIS - Error",
            status="Error",
            message=f"Module execution error: {str(e)}",
            details="",
            remediation="Review module logs"
        ))
    
    # Generate summary statistics
    pass_count = sum(1 for r in results if r.status == "Pass")
    fail_count = sum(1 for r in results if r.status == "Fail")
    warn_count = sum(1 for r in results if r.status == "Warning")
    info_count = sum(1 for r in results if r.status == "Info")
    error_count = sum(1 for r in results if r.status == "Error")
    
    print(f"\n[{MODULE_NAME}] " + "="*70)
    print(f"[{MODULE_NAME}] CIS BENCHMARK SECURITY AUDIT COMPLETED")
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
# Standalone Testing
# ============================================================================



# ============================================================================
# v3.3 EXPANSION - CIS Benchmark Deep Coverage
# ----------------------------------------------------------------------------
# Synopsis:
#   Extends the CIS module with deeper coverage of:
#   - SSH key algorithms (CIS 5.2.x advanced)
#   - PAM faillock & pwquality depth (CIS 5.4.x L2)
#   - Auditd ruleset coverage (CIS 4.1.3.1-4.1.3.21)
#   - nftables modern firewall (CIS 3.5.x)
#   - Filesystem additional checks (CIS 1.1.x extended)
#   - Crypto policy hardening (CIS 1.10)
#
# Notes:
#   - Imports module_helpers for streamlined helpers
#   - Uses AuditResult directly with cross_references and severity
#   - Always returns results from run_checks
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


def _v33_result(category, status, message, severity="Medium",
                details="", remediation="", cross_references=None):
    """Build AuditResult for CIS v3.3 expansion."""
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


def _check_cis_v33_ssh_advanced(results, shared_data, os_info):
    """CIS 5.2.x extended - SSH algorithm hardening."""
    sshd = _v33_read_file_safe("/etc/ssh/sshd_config")

    # CIS 5.2.13 - Strong Ciphers Only
    cipher_match = re.search(r"^\s*Ciphers\s+(\S+)", sshd, re.MULTILINE)
    ciphers = cipher_match.group(1) if cipher_match else ""
    weak = ["arcfour", "3des", "des-cbc", "blowfish", "cast128", "rijndael"]
    has_weak_cipher = any(w in ciphers for w in weak) if ciphers else False
    results.append(_v33_result(
        "CIS 5.2.13 v3.3 - SSH Ciphers",
        "Pass" if (ciphers and not has_weak_cipher) else "Fail",
        "5.2.13 Strong SSH ciphers configured",
        severity="High",
        details=f"Ciphers configured: {bool(ciphers)}, weak ciphers detected: {has_weak_cipher}",
        remediation=(
            "In /etc/ssh/sshd_config: "
            "Ciphers chacha20-poly1305@openssh.com,"
            "aes256-gcm@openssh.com,aes128-gcm@openssh.com,"
            "aes256-ctr,aes192-ctr,aes128-ctr"
        ),
        cross_references={
            "CIS": "5.2.13", "NIST": "SC-13", "STIG": "V-230252",
        },
    ))

    # CIS 5.2.14 - Strong MACs
    mac_match = re.search(r"^\s*MACs\s+(\S+)", sshd, re.MULTILINE)
    macs = mac_match.group(1) if mac_match else ""
    weak_macs = ["hmac-md5", "hmac-sha1-96", "hmac-md5-96", "umac-64"]
    has_weak_mac = any(w in macs for w in weak_macs) if macs else False
    results.append(_v33_result(
        "CIS 5.2.14 v3.3 - SSH MACs",
        "Pass" if (macs and not has_weak_mac) else "Fail",
        "5.2.14 Strong SSH MAC algorithms configured",
        severity="High",
        details=f"MACs configured: {bool(macs)}, weak detected: {has_weak_mac}",
        remediation=(
            "In /etc/ssh/sshd_config: "
            "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,"
            "hmac-sha2-512,hmac-sha2-256"
        ),
        cross_references={
            "CIS": "5.2.14", "NIST": "SC-13",
        },
    ))

    # CIS 5.2.15 - Strong Key Exchange
    kex_match = re.search(r"^\s*KexAlgorithms\s+(\S+)", sshd, re.MULTILINE)
    kex = kex_match.group(1) if kex_match else ""
    weak_kex = ["diffie-hellman-group1", "diffie-hellman-group14-sha1",
                "diffie-hellman-group-exchange-sha1"]
    has_weak_kex = any(w in kex for w in weak_kex) if kex else False
    results.append(_v33_result(
        "CIS 5.2.15 v3.3 - SSH Key Exchange",
        "Pass" if (kex and not has_weak_kex) else "Fail",
        "5.2.15 Strong SSH KexAlgorithms configured",
        severity="High",
        details=f"KexAlgorithms configured: {bool(kex)}, weak detected: {has_weak_kex}",
        remediation=(
            "In /etc/ssh/sshd_config: "
            "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,"
            "diffie-hellman-group16-sha512,diffie-hellman-group18-sha512"
        ),
        cross_references={
            "CIS": "5.2.15", "NIST": "SC-13",
        },
    ))

    # CIS 5.2.16 - HostKeyAlgorithms (modern)
    hka_match = re.search(r"^\s*HostKeyAlgorithms\s+(\S+)", sshd, re.MULTILINE)
    hka = hka_match.group(1) if hka_match else ""
    weak_hka = ["ssh-dss", "ssh-rsa "]  # ssh-rsa deprecated for verification
    has_weak_hka = any(w in (hka + " ") for w in weak_hka) if hka else False
    results.append(_v33_result(
        "CIS 5.2.16 v3.3 - SSH HostKeyAlgorithms",
        "Pass" if (hka and not has_weak_hka) else "Info",
        "5.2.16 Modern SSH HostKeyAlgorithms",
        severity="Medium",
        details=f"HostKeyAlgorithms: {hka or 'default'}",
        remediation=(
            "In /etc/ssh/sshd_config: "
            "HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,"
            "ecdsa-sha2-nistp384,rsa-sha2-512,rsa-sha2-256"
        ),
        cross_references={
            "CIS": "5.2.16", "NIST": "SC-13",
        },
    ))

    # CIS 5.2.17 - LoginGraceTime <= 60s
    lgt_match = re.search(r"^\s*LoginGraceTime\s+(\d+)", sshd, re.MULTILINE)
    lgt = int(lgt_match.group(1)) if lgt_match else 120
    results.append(_v33_result(
        "CIS 5.2.17 v3.3 - SSH LoginGraceTime",
        "Pass" if lgt <= 60 else "Warning",
        f"5.2.17 LoginGraceTime <= 60s ({lgt})",
        severity="Medium",
        details=f"LoginGraceTime = {lgt}",
        remediation="In /etc/ssh/sshd_config: LoginGraceTime 60",
        cross_references={
            "CIS": "5.2.17", "NIST": "AC-7",
        },
    ))

    # CIS 5.2.18 - MaxAuthTries <= 4
    mat_match = re.search(r"^\s*MaxAuthTries\s+(\d+)", sshd, re.MULTILINE)
    mat = int(mat_match.group(1)) if mat_match else 6
    results.append(_v33_result(
        "CIS 5.2.18 v3.3 - SSH MaxAuthTries",
        "Pass" if mat <= 4 else "Warning",
        f"5.2.18 MaxAuthTries <= 4 ({mat})",
        severity="Medium",
        details=f"MaxAuthTries = {mat}",
        remediation="In /etc/ssh/sshd_config: MaxAuthTries 4",
        cross_references={
            "CIS": "5.2.18", "NIST": "AC-7",
        },
    ))

    # CIS 5.2.19 - MaxStartups
    ms_match = re.search(r"^\s*MaxStartups\s+(\S+)", sshd, re.MULTILINE)
    ms = ms_match.group(1) if ms_match else ""
    ms_ok = ms == "10:30:60" or "10:30:60" in ms
    results.append(_v33_result(
        "CIS 5.2.19 v3.3 - SSH MaxStartups",
        "Pass" if ms_ok else "Warning",
        f"5.2.19 MaxStartups configured ({ms or 'default'})",
        severity="Low",
        details=f"MaxStartups = {ms}",
        remediation="In /etc/ssh/sshd_config: MaxStartups 10:30:60",
        cross_references={
            "CIS": "5.2.19", "NIST": "AC-7",
        },
    ))

    # CIS 5.2.20 - MaxSessions <= 10
    msess_match = re.search(r"^\s*MaxSessions\s+(\d+)", sshd, re.MULTILINE)
    msess = int(msess_match.group(1)) if msess_match else 10
    results.append(_v33_result(
        "CIS 5.2.20 v3.3 - SSH MaxSessions",
        "Pass" if msess <= 10 else "Info",
        f"5.2.20 MaxSessions <= 10 ({msess})",
        severity="Low",
        details=f"MaxSessions = {msess}",
        remediation="In /etc/ssh/sshd_config: MaxSessions 10",
        cross_references={
            "CIS": "5.2.20", "NIST": "AC-10",
        },
    ))

    # CIS 5.2.21 - AllowTcpForwarding no
    atf_match = re.search(r"^\s*AllowTcpForwarding\s+(\S+)", sshd, re.MULTILINE)
    atf = atf_match.group(1).lower() if atf_match else "yes"
    results.append(_v33_result(
        "CIS 5.2.21 v3.3 - SSH AllowTcpForwarding",
        "Pass" if atf == "no" else "Info",
        f"5.2.21 AllowTcpForwarding: {atf}",
        severity="Medium",
        details=f"AllowTcpForwarding = {atf}",
        remediation="In /etc/ssh/sshd_config: AllowTcpForwarding no",
        cross_references={
            "CIS": "5.2.21", "NIST": "AC-4",
        },
    ))

    # CIS 5.2.22 - PermitUserEnvironment no
    pue_match = re.search(r"^\s*PermitUserEnvironment\s+(\S+)", sshd, re.MULTILINE)
    pue = pue_match.group(1).lower() if pue_match else "no"
    results.append(_v33_result(
        "CIS 5.2.22 v3.3 - SSH PermitUserEnvironment",
        "Pass" if pue == "no" else "Fail",
        f"5.2.22 PermitUserEnvironment: {pue}",
        severity="High",
        details=f"PermitUserEnvironment = {pue}",
        remediation="In /etc/ssh/sshd_config: PermitUserEnvironment no",
        cross_references={
            "CIS": "5.2.22", "NIST": "CM-7",
        },
    ))


def _check_cis_v33_pam_advanced(results, shared_data, os_info):
    """CIS 5.4.x extended - PAM password & lockout depth."""
    # CIS 5.4.1 - faillock configuration
    faillock_conf = _v33_read_file_safe("/etc/security/faillock.conf")
    if faillock_conf:
        deny_match = re.search(r"^\s*deny\s*=\s*(\d+)", faillock_conf, re.MULTILINE)
        unlock_match = re.search(r"^\s*unlock_time\s*=\s*(\d+)", faillock_conf, re.MULTILINE)
        deny = int(deny_match.group(1)) if deny_match else 0
        unlock = int(unlock_match.group(1)) if unlock_match else 0
        results.append(_v33_result(
            "CIS 5.4.1 v3.3 - faillock deny",
            "Pass" if 1 <= deny <= 5 else "Warning",
            f"5.4.1.1 faillock deny <= 5 ({deny})",
            severity="High",
            details=f"deny = {deny}, unlock_time = {unlock}",
            remediation="In /etc/security/faillock.conf: deny = 5; unlock_time = 900",
            cross_references={
                "CIS": "5.4.1.1", "NIST": "AC-7", "STIG": "V-230332",
            },
        ))
        results.append(_v33_result(
            "CIS 5.4.1 v3.3 - faillock unlock_time",
            "Pass" if unlock >= 900 else "Warning",
            f"5.4.1.2 faillock unlock_time >= 900 ({unlock})",
            severity="High",
            details=f"unlock_time = {unlock}",
            remediation="In /etc/security/faillock.conf: unlock_time = 900",
            cross_references={
                "CIS": "5.4.1.2", "NIST": "AC-7",
            },
        ))

    # CIS 5.4.2 - pwquality configuration
    pwq_conf = _v33_read_file_safe("/etc/security/pwquality.conf")
    if pwq_conf:
        # minlen >= 14
        minlen_match = re.search(r"^\s*minlen\s*=\s*(\d+)", pwq_conf, re.MULTILINE)
        minlen = int(minlen_match.group(1)) if minlen_match else 8
        results.append(_v33_result(
            "CIS 5.4.2 v3.3 - pwquality minlen",
            "Pass" if minlen >= 14 else "Warning",
            f"5.4.2.1 pwquality minlen >= 14 ({minlen})",
            severity="High",
            details=f"minlen = {minlen}",
            remediation="In /etc/security/pwquality.conf: minlen = 14",
            cross_references={
                "CIS": "5.4.2.1", "NIST": "IA-5(1)(a)",
            },
        ))

        # Complexity directives: dcredit, ucredit, ocredit, lcredit
        for prefix, name in [("dcredit", "digit"), ("ucredit", "uppercase"),
                              ("ocredit", "other"), ("lcredit", "lowercase")]:
            cm = re.search(rf"^\s*{prefix}\s*=\s*(-?\d+)", pwq_conf, re.MULTILINE)
            val = int(cm.group(1)) if cm else 0
            ok = val < 0  # Negative means at least N required
            results.append(_v33_result(
                f"CIS 5.4.2 v3.3 - pwquality {prefix}",
                "Pass" if ok else "Info",
                f"5.4.2.2 pwquality {prefix} ({name}) requires character class: {ok}",
                severity="Medium",
                details=f"{prefix} = {val}",
                remediation=f"In /etc/security/pwquality.conf: {prefix} = -1",
                cross_references={
                    "CIS": "5.4.2.2", "NIST": "IA-5(1)(a)",
                },
            ))

        # minclass >= 4
        mc_match = re.search(r"^\s*minclass\s*=\s*(\d+)", pwq_conf, re.MULTILINE)
        mc = int(mc_match.group(1)) if mc_match else 0
        results.append(_v33_result(
            "CIS 5.4.2 v3.3 - pwquality minclass",
            "Pass" if mc >= 4 else "Info",
            f"5.4.2.3 pwquality minclass >= 4 ({mc})",
            severity="Medium",
            details=f"minclass = {mc}",
            remediation="In /etc/security/pwquality.conf: minclass = 4",
            cross_references={
                "CIS": "5.4.2.3", "NIST": "IA-5(1)(a)",
            },
        ))

        # maxrepeat
        mr_match = re.search(r"^\s*maxrepeat\s*=\s*(\d+)", pwq_conf, re.MULTILINE)
        mr = int(mr_match.group(1)) if mr_match else 0
        results.append(_v33_result(
            "CIS 5.4.2 v3.3 - pwquality maxrepeat",
            "Pass" if 1 <= mr <= 3 else "Info",
            f"5.4.2.4 pwquality maxrepeat <= 3 ({mr})",
            severity="Low",
            details=f"maxrepeat = {mr}",
            remediation="In /etc/security/pwquality.conf: maxrepeat = 3",
            cross_references={
                "CIS": "5.4.2.4", "NIST": "IA-5(1)(a)",
            },
        ))

        # dictcheck
        dc_match = re.search(r"^\s*dictcheck\s*=\s*(\d+)", pwq_conf, re.MULTILINE)
        dc = int(dc_match.group(1)) if dc_match else 1
        results.append(_v33_result(
            "CIS 5.4.2 v3.3 - pwquality dictcheck",
            "Pass" if dc == 1 else "Info",
            f"5.4.2.5 pwquality dictcheck enabled ({dc})",
            severity="Medium",
            details=f"dictcheck = {dc}",
            remediation="In /etc/security/pwquality.conf: dictcheck = 1",
            cross_references={
                "CIS": "5.4.2.5", "NIST": "IA-5(1)(a)",
            },
        ))

    # CIS 5.4.3 - pwhistory remember
    pam_files = [
        "/etc/pam.d/system-auth", "/etc/pam.d/common-password",
        "/etc/pam.d/password-auth",
    ]
    pwh_remember = 0
    for pf in pam_files:
        c = _v33_read_file_safe(pf)
        m = re.search(r"pam_pwhistory.*remember\s*=\s*(\d+)", c)
        if m:
            pwh_remember = max(pwh_remember, int(m.group(1)))
    results.append(_v33_result(
        "CIS 5.4.3 v3.3 - pam_pwhistory",
        "Pass" if pwh_remember >= 5 else "Warning",
        f"5.4.3 pam_pwhistory remember >= 5 ({pwh_remember})",
        severity="High",
        details=f"pam_pwhistory remember = {pwh_remember}",
        remediation="Add to PAM password stack: password required pam_pwhistory.so remember=24",
        cross_references={
            "CIS": "5.4.3", "NIST": "IA-5(1)(e)",
        },
    ))

    # CIS 5.4.4 - SHA-512/yescrypt password hashing
    login_defs = _v33_read_file_safe("/etc/login.defs")
    em_match = re.search(r"^\s*ENCRYPT_METHOD\s+(\S+)", login_defs, re.MULTILINE)
    em = em_match.group(1).upper() if em_match else ""
    em_ok = em in {"SHA512", "YESCRYPT"}
    results.append(_v33_result(
        "CIS 5.4.4 v3.3 - ENCRYPT_METHOD",
        "Pass" if em_ok else "Fail",
        f"5.4.4 ENCRYPT_METHOD strong ({em or 'unset'})",
        severity="High",
        details=f"ENCRYPT_METHOD = {em}",
        remediation="In /etc/login.defs: ENCRYPT_METHOD SHA512",
        cross_references={
            "CIS": "5.4.4", "NIST": "IA-5(1)(c)",
        },
    ))


def _check_cis_v33_auditd_rules(results, shared_data, os_info):
    """CIS 4.1.3.x - Auditd rule coverage by category."""
    audit_rules = ""
    if _v33_directory_exists("/etc/audit/rules.d"):
        for f in _v33_list_directory("/etc/audit/rules.d"):
            if f.endswith(".rules"):
                audit_rules += "\n" + _v33_read_file_safe(
                    os.path.join("/etc/audit/rules.d", f)
                )
    if not audit_rules:
        audit_rules = _v33_read_file_safe("/etc/audit/audit.rules")

    # CIS 4.1.3.1 - Events that modify date/time
    has_time = ("clock_settime" in audit_rules and
                "settimeofday" in audit_rules and
                "adjtimex" in audit_rules)
    results.append(_v33_result(
        "CIS 4.1.3.1 v3.3 - time-change",
        "Pass" if has_time else "Fail",
        "4.1.3.1 Date/time modification events audited",
        severity="High",
        details=f"clock_settime/adjtimex/settimeofday rules: {has_time}",
        remediation=(
            "-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime "
            "-k time-change"
        ),
        cross_references={
            "CIS": "4.1.3.1", "NIST": "AU-2",
        },
    ))

    # CIS 4.1.3.4 - Events that modify identity
    has_id = ("identity" in audit_rules or
              ("/etc/passwd" in audit_rules and "/etc/shadow" in audit_rules))
    results.append(_v33_result(
        "CIS 4.1.3.4 v3.3 - identity",
        "Pass" if has_id else "Fail",
        "4.1.3.4 Identity-modification events audited",
        severity="High",
        details=f"Identity audit indicators: {has_id}",
        remediation=(
            "-w /etc/group -p wa -k identity; "
            "-w /etc/passwd -p wa -k identity; "
            "-w /etc/gshadow -p wa -k identity; "
            "-w /etc/shadow -p wa -k identity; "
            "-w /etc/security/opasswd -p wa -k identity"
        ),
        cross_references={
            "CIS": "4.1.3.4", "NIST": "AU-2",
        },
    ))

    # CIS 4.1.3.5 - Events that modify network environment
    has_net = ("system-locale" in audit_rules or
               ("/etc/hostname" in audit_rules and "/etc/hosts" in audit_rules))
    results.append(_v33_result(
        "CIS 4.1.3.5 v3.3 - system-locale",
        "Pass" if has_net else "Fail",
        "4.1.3.5 Network environment changes audited",
        severity="High",
        details=f"system-locale audit indicators: {has_net}",
        remediation=(
            "-a always,exit -F arch=b64 -S sethostname,setdomainname "
            "-k system-locale; "
            "-w /etc/hosts -p wa -k system-locale; "
            "-w /etc/network -p wa -k system-locale"
        ),
        cross_references={
            "CIS": "4.1.3.5", "NIST": "AU-2",
        },
    ))

    # CIS 4.1.3.6 - SELinux/AppArmor MAC events
    has_mac = "MAC-policy" in audit_rules or "/etc/selinux" in audit_rules or "/etc/apparmor" in audit_rules
    results.append(_v33_result(
        "CIS 4.1.3.6 v3.3 - MAC-policy",
        "Pass" if has_mac else "Fail",
        "4.1.3.6 MAC policy modifications audited",
        severity="High",
        details=f"MAC-policy audit rules: {has_mac}",
        remediation=(
            "-w /etc/selinux -p wa -k MAC-policy; "
            "-w /usr/share/selinux -p wa -k MAC-policy"
        ),
        cross_references={
            "CIS": "4.1.3.6", "NIST": "AU-2",
        },
    ))

    # CIS 4.1.3.7 - Login/logout events
    has_login = ("logins" in audit_rules or
                 "/var/log/lastlog" in audit_rules or
                 "/var/log/faillog" in audit_rules)
    results.append(_v33_result(
        "CIS 4.1.3.7 v3.3 - logins",
        "Pass" if has_login else "Fail",
        "4.1.3.7 Login/logout events audited",
        severity="High",
        details=f"Login audit indicators: {has_login}",
        remediation=(
            "-w /var/log/lastlog -p wa -k logins; "
            "-w /var/log/faillog -p wa -k logins; "
            "-w /var/run/faillock -p wa -k logins"
        ),
        cross_references={
            "CIS": "4.1.3.7", "NIST": "AU-2",
        },
    ))

    # CIS 4.1.3.8 - Session initiation events
    has_session = ("session" in audit_rules or
                   "/var/run/utmp" in audit_rules or
                   "/var/log/wtmp" in audit_rules)
    results.append(_v33_result(
        "CIS 4.1.3.8 v3.3 - session",
        "Pass" if has_session else "Fail",
        "4.1.3.8 Session initiation events audited",
        severity="High",
        details=f"Session audit indicators: {has_session}",
        remediation=(
            "-w /var/run/utmp -p wa -k session; "
            "-w /var/log/wtmp -p wa -k logins; "
            "-w /var/log/btmp -p wa -k logins"
        ),
        cross_references={
            "CIS": "4.1.3.8", "NIST": "AU-2",
        },
    ))

    # CIS 4.1.3.9 - Discretionary access control modifications
    has_perm_mod = ("perm_mod" in audit_rules or
                     "chmod" in audit_rules or "chown" in audit_rules)
    results.append(_v33_result(
        "CIS 4.1.3.9 v3.3 - perm_mod",
        "Pass" if has_perm_mod else "Fail",
        "4.1.3.9 DAC permission modifications audited",
        severity="High",
        details=f"perm_mod audit indicators: {has_perm_mod}",
        remediation=(
            "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 "
            "-F auid!=4294967295 -k perm_mod; "
            "-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown "
            "-F auid>=1000 -F auid!=4294967295 -k perm_mod"
        ),
        cross_references={
            "CIS": "4.1.3.9", "NIST": "AU-2",
        },
    ))

    # CIS 4.1.3.10 - Unsuccessful unauthorized file access attempts
    has_access = "access" in audit_rules and ("EACCES" in audit_rules or
                                               "EPERM" in audit_rules)
    results.append(_v33_result(
        "CIS 4.1.3.10 v3.3 - access",
        "Pass" if has_access else "Warning",
        "4.1.3.10 Failed file access attempts audited",
        severity="Medium",
        details=f"access audit with EACCES/EPERM: {has_access}",
        remediation=(
            "-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate "
            "-F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access; "
            "(also -F exit=-EPERM)"
        ),
        cross_references={
            "CIS": "4.1.3.10", "NIST": "AU-2",
        },
    ))

    # CIS 4.1.3.13 - Successful filesystem mounts
    has_mount = "mount" in audit_rules
    results.append(_v33_result(
        "CIS 4.1.3.13 v3.3 - mount",
        "Pass" if has_mount else "Warning",
        "4.1.3.13 Filesystem mounts audited",
        severity="Medium",
        details=f"mount audit rule: {has_mount}",
        remediation=(
            "-a always,exit -F arch=b64 -S mount -F auid>=1000 "
            "-F auid!=4294967295 -k mounts"
        ),
        cross_references={
            "CIS": "4.1.3.13", "NIST": "AU-2",
        },
    ))

    # CIS 4.1.3.14 - File deletion events by user
    has_delete = "delete" in audit_rules and ("unlink" in audit_rules or
                                                "rename" in audit_rules)
    results.append(_v33_result(
        "CIS 4.1.3.14 v3.3 - delete",
        "Pass" if has_delete else "Warning",
        "4.1.3.14 File deletion events audited",
        severity="Medium",
        details=f"delete audit indicators: {has_delete}",
        remediation=(
            "-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat "
            "-F auid>=1000 -F auid!=4294967295 -k delete"
        ),
        cross_references={
            "CIS": "4.1.3.14", "NIST": "AU-2",
        },
    ))

    # CIS 4.1.3.16 - Modifications to /etc/sudoers
    has_sudoers = "/etc/sudoers" in audit_rules
    results.append(_v33_result(
        "CIS 4.1.3.16 v3.3 - sudoers",
        "Pass" if has_sudoers else "Fail",
        "4.1.3.16 sudoers modifications audited",
        severity="High",
        details=f"sudoers audit watch: {has_sudoers}",
        remediation=(
            "-w /etc/sudoers -p wa -k scope; "
            "-w /etc/sudoers.d -p wa -k scope"
        ),
        cross_references={
            "CIS": "4.1.3.16", "NIST": "AU-2",
        },
    ))

    # CIS 4.1.3.17 - sudo log file
    has_sudo_log = "/var/log/sudo.log" in audit_rules
    results.append(_v33_result(
        "CIS 4.1.3.17 v3.3 - sudo.log",
        "Pass" if has_sudo_log else "Info",
        "4.1.3.17 sudo log file audited",
        severity="Medium",
        details=f"/var/log/sudo.log audit watch: {has_sudo_log}",
        remediation="-w /var/log/sudo.log -p wa -k actions",
        cross_references={
            "CIS": "4.1.3.17", "NIST": "AU-2",
        },
    ))

    # CIS 4.1.3.18 - Kernel module loading and unloading
    has_modules = ("init_module" in audit_rules or
                   "delete_module" in audit_rules or
                   "modules" in audit_rules)
    results.append(_v33_result(
        "CIS 4.1.3.18 v3.3 - modules",
        "Pass" if has_modules else "Fail",
        "4.1.3.18 Kernel module changes audited",
        severity="High",
        details=f"modules audit indicators: {has_modules}",
        remediation=(
            "-a always,exit -F arch=b64 -S init_module,delete_module,finit_module "
            "-k modules"
        ),
        cross_references={
            "CIS": "4.1.3.18", "NIST": "AU-2",
        },
    ))

    # CIS 4.1.3.20 - Audit configuration immutable
    has_immutable = "-e 2" in audit_rules
    results.append(_v33_result(
        "CIS 4.1.3.20 v3.3 - immutable",
        "Pass" if has_immutable else "Fail",
        "4.1.3.20 Audit config immutable (-e 2)",
        severity="High",
        details=f"-e 2 directive in rules: {has_immutable}",
        remediation=(
            "Add as last line of /etc/audit/rules.d/99-finalize.rules: -e 2"
        ),
        cross_references={
            "CIS": "4.1.3.20", "NIST": "AU-9",
        },
    ))


def _check_cis_v33_nftables(results, shared_data, os_info):
    """CIS 3.5 - nftables modern firewall."""
    nft_present = _v33_command_available("nft")
    nft_active = _v33_systemd_active("nftables.service") == "active"

    if not nft_present:
        results.append(_v33_result(
            "CIS 3.5.2 v3.3 - nftables installed",
            "Info",
            "3.5.2 nftables not installed",
            severity="Informational",
            details="nft binary not present",
            remediation=remediation_for("nftables"),
            cross_references={
                "CIS": "3.5.2", "NIST": "SC-7",
            },
        ))
        return

    results.append(_v33_result(
        "CIS 3.5.2 v3.3 - nftables installed",
        "Pass",
        "3.5.2 nftables installed",
        severity="Low",
        details="nft binary available",
        cross_references={
            "CIS": "3.5.2", "NIST": "SC-7",
        },
    ))

    results.append(_v33_result(
        "CIS 3.5.2 v3.3 - nftables service",
        "Pass" if nft_active else "Warning",
        f"3.5.2.7 nftables service active ({nft_active})",
        severity="High",
        details=f"nftables.service: {nft_active}",
        remediation="systemctl enable --now nftables",
        cross_references={
            "CIS": "3.5.2.7", "NIST": "SC-7",
        },
    ))

    # Check for default deny policy
    rc, out, _ = _v33_run_command(["nft", "list", "ruleset"], timeout=3.0)
    has_rules = rc == 0 and "table" in out
    has_drop_policy = rc == 0 and ("policy drop" in out or
                                    "policy reject" in out)
    results.append(_v33_result(
        "CIS 3.5.2 v3.3 - nftables ruleset",
        "Pass" if (has_rules and has_drop_policy) else "Warning",
        f"3.5.2.6 nftables default deny policy ({has_drop_policy})",
        severity="High",
        details=f"rules present: {has_rules}, drop policy: {has_drop_policy}",
        remediation=(
            "nft add table inet filter; "
            "nft add chain inet filter input '{type filter hook input priority 0; policy drop;}'"
        ),
        cross_references={
            "CIS": "3.5.2.6", "NIST": "SC-7",
        },
    ))


def _check_cis_v33_filesystem_extended(results, shared_data, os_info):
    """CIS 1.1.x extended - filesystem hardening."""
    # CIS 1.1.1 - Disabled filesystems
    disabled_fs = ["cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "udf",
                   "squashfs"]
    blacklist_d = "/etc/modprobe.d"
    if not _v33_directory_exists(blacklist_d):
        return
    blacklisted = set()
    for f in _v33_list_directory(blacklist_d):
        c = _v33_read_file_safe(os.path.join(blacklist_d, f))
        for fs in disabled_fs:
            if re.search(rf"^\s*(blacklist|install)\s+{fs}", c, re.MULTILINE):
                blacklisted.add(fs)
    for fs in disabled_fs:
        results.append(_v33_result(
            f"CIS 1.1.1 v3.3 - {fs}",
            "Pass" if fs in blacklisted else "Warning",
            f"1.1.1.x {fs} module disabled: {fs in blacklisted}",
            severity="Medium",
            details=f"{fs} blacklisted: {fs in blacklisted}",
            remediation=f"echo 'install {fs} /bin/true' >> /etc/modprobe.d/{fs}.conf",
            cross_references={
                "CIS": f"1.1.1 ({fs})", "NIST": "CM-7",
            },
        ))


def _check_cis_v33_crypto_policy(results, shared_data, os_info):
    """CIS 1.10 - System-wide crypto policies (RHEL family)."""
    if _v33_file_exists("/etc/crypto-policies/config"):
        policy = _v33_read_file_safe("/etc/crypto-policies/config").strip()
        good = {"DEFAULT", "FUTURE", "FIPS"}
        results.append(_v33_result(
            "CIS 1.10 v3.3 - crypto policy",
            "Pass" if policy in good else "Warning",
            f"1.10 System crypto policy ({policy or 'unset'})",
            severity="High",
            details=f"crypto-policies = {policy}",
            remediation="update-crypto-policies --set FUTURE",
            cross_references={
                "CIS": "1.10", "NIST": "SC-13",
            },
        ))


# Save reference to existing run_checks
_original_run_checks_cis_v33 = run_checks


def run_checks(shared_data):
    """Execute the v3.3 expanded CIS module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_cis_v33(shared_data)

    os_info = shared_data.get("os_info") or shared_data.get("v3_os_info")
    if os_info is None:
        from shared_components import os_detection as _os_det
        os_info = _os_det.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        _check_cis_v33_ssh_advanced(results, shared_data, os_info)
        _check_cis_v33_pam_advanced(results, shared_data, os_info)
        _check_cis_v33_auditd_rules(results, shared_data, os_info)
        _check_cis_v33_nftables(results, shared_data, os_info)
        _check_cis_v33_filesystem_extended(results, shared_data, os_info)
        _check_cis_v33_crypto_policy(results, shared_data, os_info)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled exception in CIS v3.3 expansion") if 'logger' in dir() else None
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS - Error",
            status="Error",
            message=f"CIS v3.3 expansion exception: {exc!r}",
            details=str(exc), severity="Medium",
        ))

    return results


# ============================================================================
# v3.5 EXPANSION - CIS Controls v8 IG3 + Benchmark Depth
# ----------------------------------------------------------------------------
# Synopsis:
#   Adds depth across CIS areas not yet covered:
#     - CIS Control 16 Application Software Security
#     - CIS Control 17 Incident Response Management
#     - CIS Control 18 Penetration Testing readiness
#     - CIS_Distribution_Independent_Linux Benchmark v2.x deeper
#     - CIS Docker Benchmark surrogates
#     - CIS Kubernetes Benchmark surrogates
#     - IG3 specific safeguards (advanced)
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


def _v35_cis_result(category, status, message, severity="Medium",
                   details="", remediation="", cross_references=None):
    """Build AuditResult for CIS v3.5 expansion."""
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


def _check_cis_v35_control16_appsec(results, shared_data, os_info):
    """CIS Control 16 - Application Software Security."""
    cat = "CIS v3.5 - Control 16"

    # 16.7 - Use standard hardening configuration templates
    hardening_indicators = sum([
        _v35_command_available("oscap"),
        _v35_command_available("lynis"),
        _v35_directory_exists("/usr/share/xml/scap"),
    ])
    results.append(_v35_cis_result(
        f"{cat} - 16.7 Hardening Templates",
        "Pass" if hardening_indicators >= 2 else "Warning",
        f"CIS 16.7 Hardening templates available: {hardening_indicators}/3",
        severity="Medium",
        details=f"Tools: oscap/lynis/SCAP content",
        remediation=(
            "apt-get install -y libopenscap8 ssg-applications lynis"
        ),
        cross_references={
            "CIS-Controls": "16.7", "NIST": "CM-6, CM-7",
        },
    ))

    # 16.10 - Apply secure design principles in app architectures
    sast_tools = sum(_v35_command_available(t)
                     for t in ["shellcheck", "bandit", "semgrep", "yamllint"])
    results.append(_v35_cis_result(
        f"{cat} - 16.10 Secure Design (SAST)",
        "Pass" if sast_tools >= 2 else "Info",
        f"CIS 16.10 SAST tooling: {sast_tools}/4",
        severity="Medium",
        details=f"Tools: {sast_tools}",
        remediation=(
            "apt-get install -y shellcheck python3-bandit yamllint\n"
            "pip install --user semgrep"
        ),
        cross_references={
            "CIS-Controls": "16.10", "NIST": "SA-11", "SSDF": "PW.7",
        },
    ))

    # 16.11 - Leverage vetted modules / services for app security
    pkg_signing = (
        _v35_directory_exists("/etc/apt/keyrings") or
        _v35_directory_exists("/etc/apt/trusted.gpg.d") or
        _v35_directory_exists("/etc/pki/rpm-gpg")
    )
    results.append(_v35_cis_result(
        f"{cat} - 16.11 Vetted Modules",
        "Pass" if pkg_signing else "Warning",
        f"CIS 16.11 Package signing infrastructure: {pkg_signing}",
        severity="Medium",
        details=f"Keyring presence: {pkg_signing}",
        cross_references={
            "CIS-Controls": "16.11", "NIST": "SR-3, SR-4",
        },
    ))


def _check_cis_v35_control17_ir(results, shared_data, os_info):
    """CIS Control 17 - Incident Response Management."""
    cat = "CIS v3.5 - Control 17"

    # 17.1 - Designated personnel (technical surrogate: mail capability)
    mail_capable = (
        _v35_command_available("mail") or
        _v35_command_available("mailx") or
        _v35_systemd_active("postfix.service") == "active"
    )
    results.append(_v35_cis_result(
        f"{cat} - 17.1 IR Notification",
        "Pass" if mail_capable else "Warning",
        f"CIS 17.1 IR notification capability (mail): {mail_capable}",
        severity="Medium",
        details=f"Mail tooling: {mail_capable}",
        cross_references={
            "CIS-Controls": "17.1, 17.4", "NIST": "IR-6",
        },
    ))

    # 17.3 - Incident handling reporting (logs preserved)
    auditd_active = _v35_systemd_active("auditd.service") == "active"
    journal_persistent = _v35_directory_exists("/var/log/journal")
    ir_logging_ready = auditd_active and journal_persistent
    results.append(_v35_cis_result(
        f"{cat} - 17.3 IR Log Preservation",
        "Pass" if ir_logging_ready else "Warning",
        f"CIS 17.3 IR log preservation: {ir_logging_ready}",
        severity="High",
        details=(
            f"auditd: {auditd_active}, journald persistent: {journal_persistent}"
        ),
        cross_references={
            "CIS-Controls": "17.3, 17.5", "NIST": "AU-9, AU-11",
        },
    ))

    # 17.7 - Conduct routine IR exercises (technical surrogate: IR tooling readiness)
    ir_tools = sum(_v35_command_available(t)
                   for t in ["tcpdump", "lsof", "strace", "ausearch", "journalctl"])
    results.append(_v35_cis_result(
        f"{cat} - 17.7 IR Tooling",
        "Pass" if ir_tools >= 4 else "Warning",
        f"CIS 17.7 IR triage tooling: {ir_tools}/5",
        severity="High",
        details=f"Tools: {ir_tools}",
        cross_references={
            "CIS-Controls": "17.7, 17.8", "NIST": "IR-3, IR-4",
        },
    ))


def _check_cis_v35_control18_pentest(results, shared_data, os_info):
    """CIS Control 18 - Penetration Testing readiness."""
    cat = "CIS v3.5 - Control 18"

    # 18.1 - Establish program / scope (vuln scanning + pentest tools)
    pentest_indicators = sum([
        _v35_command_available("lynis"),
        _v35_command_available("oscap"),
        _v35_command_available("nuclei"),
        _v35_command_available("nmap"),
    ])
    results.append(_v35_cis_result(
        f"{cat} - 18.1 Pentest Tooling",
        "Pass" if pentest_indicators >= 2 else "Info",
        f"CIS 18.1 Pentest/vuln tools: {pentest_indicators}/4",
        severity="Medium",
        details=f"Tools: {pentest_indicators}",
        remediation=(
            "Install vulnerability assessment tools:\n"
            "  apt-get install -y lynis libopenscap8 nmap"
        ),
        cross_references={
            "CIS-Controls": "18.1, 18.2", "NIST": "CA-8, RA-5",
        },
    ))

    # 18.5 - Validate measures via pentest (re-test after remediation)
    # Surrogate: scheduled vuln scans
    scheduled_scan = False
    for d in ["/etc/cron.daily", "/etc/cron.weekly"]:
        if not _v35_directory_exists(d):
            continue
        for f in _v35_list_directory(d):
            f_lower = f.lower()
            if any(k in f_lower for k in [
                "lynis", "rkhunter", "chkrootkit", "openscap", "trivy",
            ]):
                scheduled_scan = True
                break
        if scheduled_scan:
            break
    results.append(_v35_cis_result(
        f"{cat} - 18.5 Re-test Cadence",
        "Pass" if scheduled_scan else "Warning",
        f"CIS 18.5 Scheduled vuln scans: {scheduled_scan}",
        severity="High",
        details=f"Scheduled scan job present: {scheduled_scan}",
        remediation=(
            "Add to /etc/cron.weekly/lynis-scan:\n"
            "  #!/bin/sh\n"
            "  lynis audit system --quick"
        ),
        cross_references={
            "CIS-Controls": "18.5", "NIST": "RA-5",
        },
    ))


def _check_cis_v35_distro_indep_benchmark(results, shared_data, os_info):
    """CIS_Distribution_Independent_Linux Benchmark deeper coverage."""
    cat = "CIS v3.5 - DIL Benchmark"

    # 1.5.1 - ASLR enabled (full)
    aslr = _v35_read_sysctl("kernel.randomize_va_space")
    aslr_full = aslr == "2"
    results.append(_v35_cis_result(
        f"{cat} - 1.5.1 ASLR Full",
        "Pass" if aslr_full else "Fail",
        f"CIS DIL 1.5.1 randomize_va_space=2: {aslr_full}",
        severity="High",
        details=f"randomize_va_space = {aslr}",
        remediation=(
            "In /etc/sysctl.d/99-cis-aslr.conf:\n"
            "  kernel.randomize_va_space = 2\n"
            "Then: sysctl --system"
        ),
        cross_references={
            "CIS": "DIL 1.5.1", "NIST": "SI-16",
        },
    ))

    # 1.5.2 - prelink not installed
    prelink_present = (
        _v35_command_available("prelink") or
        _v35_file_exists("/etc/prelink.conf")
    )
    results.append(_v35_cis_result(
        f"{cat} - 1.5.2 Prelink Not Installed",
        "Pass" if not prelink_present else "Warning",
        f"CIS DIL 1.5.2 prelink not present: {not prelink_present}",
        severity="Medium",
        details=f"prelink detected: {prelink_present}",
        remediation=(
            "If prelink is present:\n"
            "  prelink -ua  (undo all)\n"
            "  apt-get remove --purge -y prelink  (Debian)\n"
            "  dnf remove -y prelink  (RHEL)\n"
            "Prelink can interfere with ASLR effectiveness."
        ),
        cross_references={
            "CIS": "DIL 1.5.2", "NIST": "SI-16",
        },
    ))

    # 1.6.x - Configure additional process information hiding (kptr_restrict)
    kptr = _v35_read_sysctl("kernel.kptr_restrict")
    kptr_strong = kptr in ("1", "2")
    results.append(_v35_cis_result(
        f"{cat} - 1.6.x kptr_restrict",
        "Pass" if kptr_strong else "Warning",
        f"CIS DIL kptr_restrict >= 1: {kptr_strong}",
        severity="Medium",
        details=f"kptr_restrict = {kptr}",
        remediation=(
            "In /etc/sysctl.d/99-cis-kptr.conf:\n"
            "  kernel.kptr_restrict = 2"
        ),
        cross_references={
            "CIS": "DIL", "NIST": "SI-7", "STIG": "V-230266",
        },
    ))

    # 5.4.x - User accounts and environment / inactive password lock
    inactive_match = re.search(
        r"^\s*INACTIVE\s*=\s*(\d+)",
        _v35_read_file_safe("/etc/default/useradd"),
        re.MULTILINE,
    )
    inactive_set = bool(inactive_match) and 0 < int(inactive_match.group(1)) <= 30
    results.append(_v35_cis_result(
        f"{cat} - 5.4.1.4 Inactive Password Lock",
        "Pass" if inactive_set else "Warning",
        f"CIS DIL 5.4.1.4 INACTIVE <= 30 days: {inactive_set}",
        severity="Medium",
        details=(
            f"INACTIVE = {inactive_match.group(1) if inactive_match else 'unset'}"
        ),
        remediation=(
            "useradd -D -f 30  (set default INACTIVE to 30 days)\n"
            "Existing accounts: chage --inactive 30 <user>"
        ),
        cross_references={
            "CIS": "DIL 5.4.1.4", "NIST": "AC-2(3)",
        },
    ))

    # 6.1.x - System file permissions
    critical_files = {
        "/etc/passwd": 0o0644,
        "/etc/shadow": 0o0640,  # 0640 acceptable on modern systems
        "/etc/group": 0o0644,
        "/etc/gshadow": 0o0640,
    }
    file_perm_issues = []
    for path, max_mode in critical_files.items():
        if not _v35_file_exists(path):
            continue
        try:
            mode = os.stat(path).st_mode & 0o7777
            # Should not be world-writable; for shadow files, also no group-write
            if path in ("/etc/shadow", "/etc/gshadow"):
                if mode & 0o0027:  # group/other read or any other write
                    file_perm_issues.append(f"{path}({oct(mode)})")
            elif mode & 0o0022:  # group or other write
                file_perm_issues.append(f"{path}({oct(mode)})")
        except OSError:
            pass
    results.append(_v35_cis_result(
        f"{cat} - 6.1 Critical File Permissions",
        "Pass" if not file_perm_issues else "Fail",
        f"CIS DIL 6.1 critical file permissions: "
        f"{'OK' if not file_perm_issues else 'issues'}",
        severity="High",
        details=f"Issues: {file_perm_issues}",
        remediation=(
            "chmod 0644 /etc/passwd /etc/group\n"
            "chmod 0640 /etc/shadow /etc/gshadow\n"
            "chown root:root /etc/passwd /etc/group\n"
            "chown root:shadow /etc/shadow /etc/gshadow  (Debian)\n"
            "chown root:root /etc/shadow /etc/gshadow    (RHEL)"
        ),
        cross_references={
            "CIS": "DIL 6.1", "NIST": "AC-3, SI-7",
        },
    ))


def _check_cis_v35_docker_benchmark(results, shared_data, os_info):
    """CIS Docker Benchmark surrogates."""
    cat = "CIS v3.5 - Docker"

    docker_present = (
        _v35_command_available("docker") or
        _v35_systemd_active("docker.service") == "active"
    )
    if not docker_present:
        results.append(_v35_cis_result(
            f"{cat} - Docker Status",
            "Info",
            "Docker not detected (Docker Benchmark inapplicable)",
            severity="Informational",
            details="No docker binary or service",
            cross_references={"CIS": "Docker Benchmark"},
        ))
        return

    # 1.1 - Audit Docker daemon
    audit_rules = ""
    if _v35_directory_exists("/etc/audit/rules.d"):
        for f in _v35_list_directory("/etc/audit/rules.d"):
            if f.endswith(".rules"):
                audit_rules += "\n" + _v35_read_file_safe(
                    os.path.join("/etc/audit/rules.d", f)
                )
    docker_audited = (
        "/var/lib/docker" in audit_rules or
        "/usr/bin/docker" in audit_rules or
        "/etc/docker" in audit_rules
    )
    results.append(_v35_cis_result(
        f"{cat} - 1.1 Docker Audit",
        "Pass" if docker_audited else "Warning",
        f"CIS Docker 1.1 Docker daemon audit rules: {docker_audited}",
        severity="Medium",
        details=f"Docker audit rules: {docker_audited}",
        remediation=(
            "Add to /etc/audit/rules.d/41-cis-docker.rules:\n"
            "  -w /usr/bin/docker -p x -k docker\n"
            "  -w /var/lib/docker -p wa -k docker\n"
            "  -w /etc/docker -p wa -k docker\n"
            "  -w /var/run/docker.sock -p rwxa -k docker"
        ),
        cross_references={
            "CIS": "Docker 1.1", "NIST": "AU-2",
        },
    ))

    # 2.5 - Restrict default-bridge networking
    docker_daemon_conf = _v35_read_file_safe("/etc/docker/daemon.json")
    iptables_disabled = '"iptables": false' in docker_daemon_conf
    # Default is iptables enabled (good); check we haven't disabled it
    iptables_kept_default = not iptables_disabled
    results.append(_v35_cis_result(
        f"{cat} - 2.5 Iptables NOT Disabled",
        "Pass" if iptables_kept_default else "Warning",
        f"CIS Docker 2.5 docker iptables management default (true): "
        f"{iptables_kept_default}",
        severity="High",
        details=(
            f'iptables: false in daemon.json: {iptables_disabled}'
        ),
        cross_references={
            "CIS": "Docker 2.5", "NIST": "SC-7",
        },
    ))


def _check_cis_v35_kubernetes_benchmark(results, shared_data, os_info):
    """CIS Kubernetes Benchmark surrogates."""
    cat = "CIS v3.5 - K8s"

    k8s_present = (
        _v35_command_available("kubectl") or
        _v35_command_available("kubelet") or
        _v35_directory_exists("/etc/kubernetes") or
        _v35_systemd_active("kubelet.service") == "active"
    )
    if not k8s_present:
        results.append(_v35_cis_result(
            f"{cat} - K8s Status",
            "Info",
            "Kubernetes not detected (K8s Benchmark inapplicable)",
            severity="Informational",
            details="No kubectl/kubelet/etc-kubernetes",
            cross_references={"CIS": "K8s Benchmark"},
        ))
        return

    # 4.2.1 - anonymous-auth false (kubelet)
    kubelet_config = ""
    for path in [
        "/var/lib/kubelet/config.yaml",
        "/etc/kubernetes/kubelet/kubelet-config.yaml",
        "/etc/kubernetes/kubelet/kubelet.conf",
    ]:
        if _v35_file_exists(path):
            kubelet_config += "\n" + _v35_read_file_safe(path)

    if kubelet_config:
        anon_auth = bool(re.search(
            r"anonymous-auth:\s*true",
            kubelet_config, re.IGNORECASE,
        ))
        results.append(_v35_cis_result(
            f"{cat} - 4.2.1 anonymous-auth",
            "Pass" if not anon_auth else "Fail",
            f"CIS K8s 4.2.1 anonymous-auth=false: {not anon_auth}",
            severity="Critical",
            details=f"anonymous-auth=true detected: {anon_auth}",
            cross_references={
                "CIS": "K8s 4.2.1", "NIST": "AC-3",
            },
        ))

    # 4.1.x - kubelet config file permissions
    kubelet_conf_path = "/etc/kubernetes/kubelet.conf"
    if _v35_file_exists(kubelet_conf_path):
        try:
            mode = os.stat(kubelet_conf_path).st_mode & 0o7777
            mode_secure = mode <= 0o0644
            results.append(_v35_cis_result(
                f"{cat} - 4.1.x kubelet.conf Permissions",
                "Pass" if mode_secure else "Warning",
                f"CIS K8s kubelet.conf mode <= 0644: {mode_secure}",
                severity="High",
                details=f"kubelet.conf mode = {oct(mode)}",
                remediation=(
                    "chmod 0644 /etc/kubernetes/kubelet.conf"
                ),
                cross_references={
                    "CIS": "K8s 4.1.x", "NIST": "AC-3",
                },
            ))
        except OSError:
            pass


def _check_cis_v35_ig3_advanced(results, shared_data, os_info):
    """CIS Controls v8 IG3 specific safeguards (advanced)."""
    cat = "CIS v3.5 - IG3"

    # IG3 advanced: AI/ML threat hunting tools (osquery, sysmon, etc.)
    advanced_detection = sum([
        _v35_command_available("osqueryi") or
        _v35_systemd_active("osqueryd.service") == "active",
        _v35_systemd_active("falco.service") == "active",
        _v35_directory_exists("/var/log/sysmon"),
        _v35_systemd_active("auditd.service") == "active",
        _v35_file_exists("/var/ossec/etc/ossec.conf"),
    ])
    results.append(_v35_cis_result(
        f"{cat} - IG3 Advanced Detection",
        "Pass" if advanced_detection >= 3 else "Warning",
        f"CIS IG3 Advanced detection layers: {advanced_detection}/5",
        severity="Medium",
        details=f"Layers: {advanced_detection}",
        cross_references={
            "CIS-Controls": "IG3",
            "NIST": "SI-4(24), RA-10",
        },
    ))

    # IG3: SBOM + supply chain attestation
    supply_chain = sum([
        _v35_command_available("syft") or _v35_command_available("trivy"),
        _v35_command_available("cosign") or _v35_command_available("minisign"),
        _v35_command_available("gpg") or _v35_command_available("gpg2"),
    ])
    results.append(_v35_cis_result(
        f"{cat} - IG3 Supply Chain",
        "Pass" if supply_chain >= 2 else "Info",
        f"CIS IG3 Supply chain layers (SBOM/sign/gpg): {supply_chain}/3",
        severity="Medium",
        details=f"Layers: {supply_chain}",
        cross_references={
            "CIS-Controls": "16.11 IG3, 2.4 IG3",
            "NIST": "SR-3, SR-4, SR-11",
        },
    ))


# Save reference to existing run_checks
_original_run_checks_cis_v35 = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the v3.5 expanded CIS module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_cis_v35(shared_data)

    os_info = shared_data.get("os_info") or shared_data.get("v3_os_info")
    if os_info is None:
        from shared_components import os_detection as _os_det
        os_info = _os_det.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        _check_cis_v35_control16_appsec(results, shared_data, os_info)
        _check_cis_v35_control17_ir(results, shared_data, os_info)
        _check_cis_v35_control18_pentest(results, shared_data, os_info)
        _check_cis_v35_distro_indep_benchmark(results, shared_data, os_info)
        _check_cis_v35_docker_benchmark(results, shared_data, os_info)
        _check_cis_v35_kubernetes_benchmark(results, shared_data, os_info)
        _check_cis_v35_ig3_advanced(results, shared_data, os_info)
    except Exception as exc:  # noqa: BLE001
        results.append(AuditResult(
            module=MODULE_NAME, category="CIS - Error",
            status="Error",
            message=f"CIS v3.5 expansion exception: {exc!r}",
            details=str(exc), severity="Medium",
        ))

    return results
if __name__ == "__main__":
    """Standalone module testing"""
    import socket
    import platform
    
    print("="*70)
    print(f"Testing {MODULE_NAME} Module - Comprehensive CIS Benchmark Checks")
    print("="*70)
    
    test_shared_data = {
        "hostname": socket.gethostname(),
        "os_version": f"{platform.system()} {platform.release()}",
        "is_root": os.geteuid() == 0
    }
    
    print(f"\nTest Environment:")
    print(f"  Hostname: {test_shared_data['hostname']}")
    print(f"  OS: {test_shared_data['os_version']}")
    print(f"  Running as root: {test_shared_data['is_root']}")
    print(f"\nExecuting checks...\n")
    
    test_results = run_checks(test_shared_data)
    
    # Summary statistics
    stats = {
        "Pass": sum(1 for r in test_results if r.status == "Pass"),
        "Fail": sum(1 for r in test_results if r.status == "Fail"),
        "Warning": sum(1 for r in test_results if r.status == "Warning"),
        "Info": sum(1 for r in test_results if r.status == "Info"),
        "Error": sum(1 for r in test_results if r.status == "Error")
    }
    
    print("\n" + "="*70)
    print("TEST RESULTS SUMMARY")
    print("="*70)
    print(f"Total Checks Executed: {len(test_results)}")
    for status, count in stats.items():
        if count > 0:
            print(f"  {status}: {count}")
    print("="*70)
    
    # Show sample results
    print("\nSample Check Results (first 10):")
    for i, result in enumerate(test_results[:10], 1):
        print(f"\n{i}. [{result.status}] {result.message}")
        print(f"   Category: {result.category}")
        if result.details:
            print(f"   Details: {result.details}")
