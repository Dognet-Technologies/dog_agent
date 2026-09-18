#!/usr/bin/env python3
"""
module_core.py
Core Security Baseline Module for Linux
Version: 2.0

SYNOPSIS:
    Comprehensive baseline security assessment for Linux systems based on
    industry best practices and OS-specific security guidance.

DESCRIPTION:
    This module performs thorough security checks with dynamic OS detection:
    
    Core Security Baseline:
    - OS Detection & Version Management
    - Package Management Security (OS-specific)
    - Service Management & Hardening
    - User & Group Security
    - Filesystem Security & Permissions
    - Network Configuration Baseline
    - Process & Memory Security
    - System Updates & Patch Management
    - Security Tools & Monitoring
    
    OS-Specific Coverage:
    - Debian-based: Ubuntu, Debian, Linux Mint, Kali Linux
      * Based on Debian Security Advisory (DSA)
      * Ubuntu Security Notices (USN)
      * APT security configuration
    
    - RedHat-based: RHEL, Fedora, CentOS, Rocky, AlmaLinux
      * Based on Red Hat Security Advisory (RHSA)
      * Red Hat Customer Portal security guidance
      * YUM/DNF security configuration
    
    Key Standards Referenced:
    - CIS Benchmarks (OS-specific sections)
    - Linux Foundation security best practices
    - Debian Security Manual
    - Red Hat Enterprise Linux Security Guide
    - Ubuntu Server Guide Security section

PARAMETERS:
    shared_data : Dictionary containing shared data from main script
                  shared_data['cache'] provides SharedDataCache for performance

USAGE:
    Standalone testing
        python3 module_core.py

    Integration with main audit script
        python3 linux_security_audit.py --modules CORE
        python3 linux_security_audit.py -m CORE

NOTES:
    Version: 2.0
    Focus: Industry best practices with OS-specific optimizations
    Target: 150+ comprehensive, OS-aware security checks
    
    v2.0 Changes:
    - Uses audit_common.py shared library (eliminates duplicated helpers)
    - SharedDataCache integration for cached file/command lookups
    - Severity levels on all AuditResults
    - Cross-framework references where applicable
    - Structured logging via get_module_logger()
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
# This eliminates ~200 lines of duplicated helper functions
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
        get_file_permissions, get_file_owner_group, check_file_exists,
        # Kernel parameters (cache-aware)
        check_kernel_parameter,
        # Security subsystems (cache-aware)
        get_selinux_status, get_apparmor_status,
        # Parsing helpers
        safe_int_parse,
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

MODULE_NAME = "CORE"

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

# ============================================================================
# Module-Specific Helper Functions
# ============================================================================

def get_core_id(category: str, number: int) -> str:
    """Generate CORE control ID"""
    if HAS_COMMON_LIB:
        return generate_check_id("CORE", category, number)
    return f"CORE-{category}-{number:03d}"

def get_available_updates(os_info: OSInfo) -> int:
    """Get count of available updates (OS-specific)"""
    if os_info.package_manager == 'apt':
        # Update cache first
        run_command("apt-get update 2>/dev/null", check=False)
        result = run_command("apt list --upgradable 2>/dev/null | grep -c upgradable")
        return max(0, safe_int_parse(result.stdout.strip()) - 1)  # Subtract header line
    elif os_info.package_manager == 'dnf':
        result = run_command("dnf check-update --quiet 2>/dev/null | grep -v '^$' | wc -l")
        return safe_int_parse(result.stdout.strip())
    elif os_info.package_manager == 'yum':
        result = run_command("yum check-update --quiet 2>/dev/null | grep -v '^$' | wc -l")
        return safe_int_parse(result.stdout.strip())
    return 0

def get_security_updates(os_info: OSInfo) -> int:
    """Get count of security updates (OS-specific)"""
    if os_info.package_manager == 'apt':
        result = run_command("apt list --upgradable 2>/dev/null | grep -ci security")
        return safe_int_parse(result.stdout.strip())
    elif os_info.package_manager in ['dnf', 'yum']:
        cmd = os_info.package_manager
        result = run_command(f"{cmd} updateinfo list security 2>/dev/null | wc -l")
        return safe_int_parse(result.stdout.strip())
    return 0

def get_last_update_time(os_info: OSInfo) -> Optional[int]:
    """Get days since last update (OS-specific)"""
    import time
    
    if os_info.package_manager == 'apt':
        log_files = [
            "/var/log/apt/history.log",
            "/var/log/dpkg.log"
        ]
    elif os_info.package_manager in ['yum', 'dnf']:
        log_files = [
            "/var/log/yum.log",
            "/var/log/dnf.log"
        ]
    else:
        return None
    
    for log_file in log_files:
        if os.path.exists(log_file):
            try:
                mtime = os.path.getmtime(log_file)
                days = int((time.time() - mtime) / 86400)
                return days
            except:
                continue
    
    return None

def get_repositories(os_info: OSInfo) -> List[str]:
    """Get configured repositories (OS-specific)"""
    repos = []
    
    if os_info.package_manager == 'apt':
        # Check sources.list
        if os.path.exists("/etc/apt/sources.list"):
            content = read_file_safe("/etc/apt/sources.list")
            for line in content.split('\n'):
                if line.strip() and not line.strip().startswith('#'):
                    if line.startswith('deb'):
                        repos.append(line.split()[1])
        
        # Check sources.list.d
        for source_file in glob.glob("/etc/apt/sources.list.d/*.list"):
            content = read_file_safe(source_file)
            for line in content.split('\n'):
                if line.strip() and not line.strip().startswith('#'):
                    if line.startswith('deb'):
                        repos.append(line.split()[1])
    
    elif os_info.package_manager in ['yum', 'dnf']:
        result = run_command(f"{os_info.package_manager} repolist 2>/dev/null | grep -v '^repo id' | awk '{{print $1}}'")
        if result.returncode == 0:
            repos = [r.strip() for r in result.stdout.split('\n') if r.strip()]
    
    return repos

def check_selinux_status_core(cache=None) -> Dict[str, Any]:
    """Get SELinux status - delegates to audit_common if available"""
    if HAS_COMMON_LIB:
        return get_selinux_status(cache=cache)
    # Fallback for backward compatibility
    status = {
        'installed': False,
        'enabled': False,
        'enforcing': False,
        'mode': 'disabled'
    }
    
    if os.path.exists("/etc/selinux/config") or command_exists("getenforce"):
        status['installed'] = True
    
    if command_exists("getenforce"):
        result = run_command("getenforce")
        if result.returncode == 0:
            mode = result.stdout.strip().lower()
            status['mode'] = mode
            status['enabled'] = mode in ['enforcing', 'permissive']
            status['enforcing'] = mode == 'enforcing'
    
    return status

def check_apparmor_status_core(cache=None) -> Dict[str, Any]:
    """Get AppArmor status - delegates to audit_common if available"""
    if HAS_COMMON_LIB:
        return get_apparmor_status(cache=cache)
    # Fallback for backward compatibility
    status = {
        'installed': False,
        'enabled': False,
        'profiles_loaded': 0,
        'profiles_enforcing': 0
    }
    
    if check_service_active("apparmor"):
        status['installed'] = True
        status['enabled'] = True
        
        if command_exists("apparmor_status"):
            result = run_command("apparmor_status 2>/dev/null")
            if result.returncode == 0:
                loaded = re.search(r'(\d+) profiles are loaded', result.stdout)
                enforcing = re.search(r'(\d+) profiles are in enforce mode', result.stdout)
                
                if loaded:
                    status['profiles_loaded'] = int(loaded.group(1))
                if enforcing:
                    status['profiles_enforcing'] = int(enforcing.group(1))
    
    return status

def get_running_services(os_info: OSInfo, cache=None) -> List[str]:
    """Get list of running services (cache-aware)"""
    # Use cached service data if available
    if cache:
        running = cache.get_parsed('running_services')
        if running is not None:
            return sorted(running)
    
    services = []
    if os_info.init_system == 'systemd':
        result = run_command("systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}'")
        if result.returncode == 0:
            services = [s.strip().replace('.service', '') for s in result.stdout.split('\n') if s.strip()]
    
    return services

def get_enabled_services(os_info: OSInfo, cache=None) -> List[str]:
    """Get list of enabled services (cache-aware)"""
    # Use cached service data if available
    if cache:
        enabled = cache.get_parsed('enabled_services')
        if enabled is not None:
            return sorted(enabled)
    
    services = []
    if os_info.init_system == 'systemd':
        result = run_command("systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend | awk '{print $1}'")
        if result.returncode == 0:
            services = [s.strip().replace('.service', '') for s in result.stdout.split('\n') if s.strip()]
    
    return services

# ============================================================================
# OS & PACKAGE MANAGEMENT
# Dynamic Checks Based on OS Family with Specific Guidance
# ============================================================================

def check_os_package_management(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    OS Detection and Package Management Security Audit Checks
    """
    print(f"[{MODULE_NAME}] Checking OS & OS-Specfic Package Management...")
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    
    # OS-001: Operating System Identified
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - OS Detection",
        status="Pass" if os_info.family != "Unknown" else "Warning",
        message=f"{get_core_id('OS', 1)}: Operating system identified",
        details=f"{os_info.distro} {os_info.version} ({os_info.family})",
        remediation="OS detection successful"
    ))
    
    # OS-002: OS Version Current
    version_current = True
    version_details = f"{os_info.distro} {os_info.version}"
    
    # Check for EOL versions
    if os_info.distro == 'ubuntu':
        try:
            major = os_info.version_id.split('.')[0]
            if int(major) < 20:
                version_current = False
                version_details += " (Consider upgrading to LTS version)"
        except:
            pass
    elif os_info.distro == 'debian':
        # Debian 10 (Buster) and older are getting old
        if os_info.version_id and int(os_info.version_id) < 11:
            version_current = False
            version_details += " (Consider upgrading)"
    elif os_info.distro in ['centos', 'rhel']:
        try:
            major = os_info.version_id.split('.')[0]
            if int(major) < 8:
                version_current = False
                version_details += " (Consider upgrading)"
        except:
            pass
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - OS Detection",
        status="Pass" if version_current else "Warning",
        message=f"{get_core_id('OS', 2)}: OS version supported",
        details=version_details,
        remediation="Keep OS version current with vendor support"
    ))
    
    # OS-003: Package manager identified
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Package Management",
        status="Pass" if os_info.package_manager != "Unknown" else "Fail",
        message=f"{get_core_id('PKG', 1)}: Package manager identified",
        details=f"Package manager: {os_info.package_manager}",
        remediation="Ensure package manager is functional"
    ))
    
    # PKG-002: Package database integrity (OS-specific)
    if os_info.package_manager == 'apt':
        result = run_command("dpkg --audit 2>&1 | wc -l")
        issues = safe_int_parse(result.stdout.strip())
        pkg_ok = issues == 0
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Package Management",
            status="Pass" if pkg_ok else "Warning",
            message=f"{get_core_id('PKG', 2)}: Package database integrity (dpkg)",
            details=f"{issues} package issues",
            remediation="Run: dpkg --configure -a && apt-get install -f"
        ))
    
    elif os_info.package_manager in ['yum', 'dnf']:
        result = run_command("rpm -Va 2>&1 | wc -l")
        issues = safe_int_parse(result.stdout.strip())
        pkg_ok = issues < 50  # Some variation is normal
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Package Management",
            status="Pass" if pkg_ok else "Info",
            message=f"{get_core_id('PKG', 2)}: Package database integrity (RPM)",
            details=f"{issues} package verification messages",
            remediation="Review: rpm -Va"
        ))
    
    # PKG-003: Repository configuration (OS-specific)
    repos = get_repositories(os_info)
    repos_configured = len(repos) > 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Package Management",
        status="Pass" if repos_configured else "Warning",
        message=f"{get_core_id('PKG', 3)}: Repositories configured",
        details=f"{len(repos)} repositories configured",
        remediation="Configure official distribution repositories"
    ))
    
    # PKG-004: Official repositories used (OS-specific)
    official_repos = 0
    unofficial_repos = []
    
    if os_info.family == 'debian':
        official_domains = ['debian.org', 'ubuntu.com', 'canonical.com']
        for repo in repos:
            if any(domain in repo for domain in official_domains):
                official_repos += 1
            else:
                unofficial_repos.append(repo)
    elif os_info.family == 'redhat':
        official_domains = ['redhat.com', 'fedoraproject.org', 'centos.org']
        for repo in repos:
            if any(domain in repo for domain in official_domains):
                official_repos += 1
            else:
                unofficial_repos.append(repo)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Package Management",
        status="Pass" if official_repos > 0 else "Warning",
        message=f"{get_core_id('PKG', 4)}: Official repositories in use",
        details=f"{official_repos} official, {len(unofficial_repos)} unofficial",
        remediation="Use official distribution repositories when possible"
    ))
    
    # PKG-005: HTTPS repositories (Debian-specific best practice)
    if os_info.family == 'debian':
        https_repos = sum(1 for r in repos if r.startswith('https://'))
        http_repos = sum(1 for r in repos if r.startswith('http://') and not r.startswith('https://'))
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Package Management",
            status="Pass" if http_repos == 0 else "Warning",
            message=f"{get_core_id('PKG', 5)}: Repositories use HTTPS",
            details=f"HTTPS: {https_repos}, HTTP: {http_repos}",
            remediation="Use HTTPS repositories in /etc/apt/sources.list"
        ))
    
    # PKG-006: GPG key verification (OS-specific)
    if os_info.package_manager == 'apt':
        if command_exists('apt-key'):
            result = run_command("apt-key list 2>/dev/null | grep -c 'pub'")
            keys = safe_int_parse(result.stdout.strip())
        else:
            # Modern Debian/Ubuntu use /etc/apt/trusted.gpg.d/
            keys = len(glob.glob("/etc/apt/trusted.gpg.d/*.gpg"))
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Package Management",
            status="Pass" if keys > 0 else "Warning",
            message=f"{get_core_id('PKG', 6)}: GPG keys configured (APT)",
            details=f"{keys} GPG keys",
            remediation="Import repository GPG keys"
        ))
    
    elif os_info.package_manager in ['yum', 'dnf']:
        result = run_command("rpm -q gpg-pubkey 2>/dev/null | wc -l")
        keys = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Package Management",
            status="Pass" if keys > 0 else "Warning",
            message=f"{get_core_id('PKG', 6)}: GPG keys configured (RPM)",
            details=f"{keys} GPG keys",
            remediation="Import repository GPG keys: rpm --import <key>"
        ))
    
    # PKG-007: Automatic updates configured (OS-specific)
    if os_info.family == 'debian':
        auto_updates = check_package_installed("unattended-upgrades", os_info)
        auto_enabled = False
        
        if auto_updates and os.path.exists("/etc/apt/apt.conf.d/20auto-upgrades"):
            content = read_file_safe("/etc/apt/apt.conf.d/20auto-upgrades")
            auto_enabled = 'APT::Periodic::Unattended-Upgrade "1"' in content
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Package Management",
            status="Pass" if auto_enabled else "Warning",
            message=f"{get_core_id('PKG', 7)}: Automatic security updates (Debian/Ubuntu)",
            details="Enabled" if auto_enabled else "Not configured",
            remediation="Configure: dpkg-reconfigure -plow unattended-upgrades"
        ))
    
    elif os_info.family == 'redhat':
        auto_updates = check_package_installed("yum-cron", os_info) or check_package_installed("dnf-automatic", os_info)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Package Management",
            status="Pass" if auto_updates else "Warning",
            message=f"{get_core_id('PKG', 7)}: Automatic security updates (RedHat)",
            details="Installed" if auto_updates else "Not installed",
            remediation=remediation_for("dnf-automatic")
        ))
    
    # PKG-008: Available updates count
    available_updates = get_available_updates(os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Package Management",
        status="Pass" if available_updates < 10 else "Warning" if available_updates < 50 else "Fail",
        message=f"{get_core_id('PKG', 8)}: System updates current",
        details=f"{available_updates} updates available",
        remediation=f"Update: {os_info.package_manager} upgrade"
    ))
    
    # PKG-009: Security updates available
    security_updates = get_security_updates(os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Package Management",
        status="Pass" if security_updates == 0 else "Fail",
        message=f"{get_core_id('PKG', 9)}: Security updates applied",
        details=f"{security_updates} security updates pending",
        remediation=f"Apply security updates immediately"
    ))
    
    # PKG-010: Last update time
    last_update = get_last_update_time(os_info)
    update_recent = last_update is not None and last_update < 30
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Package Management",
        status="Pass" if update_recent else "Warning",
        message=f"{get_core_id('PKG', 10)}: Recent system updates",
        details=f"Last update: {last_update} days ago" if last_update else "Cannot determine",
        remediation="Update system regularly (at least monthly)"
    ))
    
    # PKG-011: Essential packages installed (OS-specific)
    if os_info.family == 'debian':
        essential_packages = ['apt-transport-https', 'ca-certificates', 'gnupg']
    elif os_info.family == 'redhat':
        essential_packages = ['ca-certificates', 'gnupg2']
    else:
        essential_packages = []
    
    missing_essential = [pkg for pkg in essential_packages if not check_package_installed(pkg, os_info)]
    
    if essential_packages:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Package Management",
            status="Pass" if not missing_essential else "Warning",
            message=f"{get_core_id('PKG', 11)}: Essential security packages installed",
            details=f"Missing: {', '.join(missing_essential)}" if missing_essential else "All present",
            remediation=f"Install missing packages"
        ))
    
    # PKG-012: Package hold/pin status (prevents unexpected updates)
    if os_info.package_manager == 'apt':
        result = run_command("apt-mark showhold 2>/dev/null | wc -l")
        held_packages = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Package Management",
            status="Info",
            message=f"{get_core_id('PKG', 12)}: Package hold status (APT)",
            details=f"{held_packages} packages on hold",
            remediation="Review held packages: apt-mark showhold"
        ))
    
    # PKG-013: Kernel packages installed count
    if os_info.package_manager == 'apt':
        result = run_command("dpkg -l | grep -c '^ii.*linux-image'")
    elif os_info.package_manager in ['yum', 'dnf']:
        result = run_command("rpm -qa | grep -c '^kernel-'")
    else:
        result = None
    
    kernel_count = safe_int_parse(result.stdout.strip()) if result else 0
    
    if kernel_count > 0:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Package Management",
            status="Info",
            message=f"{get_core_id('PKG', 13)}: Kernel packages installed",
            details=f"{kernel_count} kernel packages",
            remediation="Remove old kernels to save space"
        ))
    
    # PKG-014: Running kernel vs available (security critical)
    running_kernel = platform.release()
    
    if os_info.package_manager == 'apt':
        result = run_command("dpkg -l | grep '^ii.*linux-image' | awk '{print $3}' | sort -V | tail -1")
        latest_kernel = result.stdout.strip()
        kernel_current = running_kernel in latest_kernel or latest_kernel in running_kernel
    elif os_info.package_manager in ['yum', 'dnf']:
        result = run_command("rpm -q kernel | sort -V | tail -1")
        latest_kernel = result.stdout.strip()
        kernel_current = running_kernel in latest_kernel
    else:
        kernel_current = True
        latest_kernel = "unknown"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Package Management",
        status="Pass" if kernel_current else "Warning",
        message=f"{get_core_id('PKG', 14)}: Running latest installed kernel",
        details=f"Running: {running_kernel}, Latest: {latest_kernel}"[:80],
        remediation="Reboot to use updated kernel"
    ))
    
    # PKG-015: Package manager locks (indicates ongoing operations)
    lock_files = []
    if os_info.package_manager == 'apt':
        if os.path.exists("/var/lib/dpkg/lock"):
            lock_files.append("dpkg")
        if os.path.exists("/var/lib/apt/lists/lock"):
            lock_files.append("apt")
    elif os_info.package_manager in ['yum', 'dnf']:
        if os.path.exists("/var/run/yum.pid"):
            lock_files.append("yum")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Package Management",
        status="Pass" if not lock_files else "Warning",
        message=f"{get_core_id('PKG', 15)}: Package manager not locked",
        details=f"Locks: {', '.join(lock_files)}" if lock_files else "No locks",
        remediation="Wait for package operations to complete or remove stale locks"
    ))
    
    # PKG-016: Development tools installed (security consideration)
    dev_tools = ['gcc', 'g++', 'make', 'gdb']
    installed_dev = [tool for tool in dev_tools if command_exists(tool)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Package Management",
        status="Warning" if installed_dev else "Pass",
        message=f"{get_core_id('PKG', 16)}: Development tools on production system",
        details=f"Installed: {', '.join(installed_dev)}" if installed_dev else "None",
        remediation="Remove development tools from production systems"
    ))
    
    # PKG-017: System architecture
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - OS Detection",
        status="Info",
        message=f"{get_core_id('OS', 3)}: System architecture",
        details=f"Architecture: {os_info.architecture}",
        remediation="Informational"
    ))
    
    # PKG-018: Kernel version
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - OS Detection",
        status="Info",
        message=f"{get_core_id('OS', 4)}: Kernel version",
        details=f"Kernel: {os_info.kernel_version}",
        remediation="Keep kernel updated"
    ))
    
    # PKG-019: Init system
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - OS Detection",
        status="Info",
        message=f"{get_core_id('OS', 5)}: Init system",
        details=f"Init: {os_info.init_system}",
        remediation="Informational"
    ))
    
    # PKG-020: Distribution codename
    if os_info.codename != "Unknown":
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - OS Detection",
            status="Info",
            message=f"{get_core_id('OS', 6)}: Distribution release name",
            details=f"Codename: {os_info.codename}",
            remediation="Informational"
        ))
    
    # PKG-021: Third-party repositories (security risk assessment)
    if os_info.family == 'debian':
        ppa_count = len(glob.glob("/etc/apt/sources.list.d/*ppa*.list"))
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Package Management",
            status="Pass" if ppa_count == 0 else "Info",
            message=f"{get_core_id('PKG', 17)}: Third-party repositories (PPAs)",
            details=f"{ppa_count} PPAs configured",
            remediation="Minimize use of third-party repositories"
        ))
    
    # PKG-022: Package verification (Debian-specific)
    if os_info.package_manager == 'apt' and command_exists('debsums'):
        result = run_command("debsums -c 2>&1 | wc -l")
        checksum_errors = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Package Management",
            status="Pass" if checksum_errors < 10 else "Warning",
            message=f"{get_core_id('PKG', 18)}: Package file integrity (debsums)",
            details=f"{checksum_errors} checksum mismatches",
            remediation="Reinstall packages with errors: apt-get install --reinstall <pkg>"
        ))
    
    # PKG-023: Orphaned packages (Debian-specific)
    if os_info.package_manager == 'apt':
        result = run_command("apt-get autoremove --dry-run 2>/dev/null | grep -c '^Remv'")
        orphaned = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Package Management",
            status="Pass" if orphaned < 5 else "Info",
            message=f"{get_core_id('PKG', 19)}: Orphaned packages",
            details=f"{orphaned} packages can be auto-removed",
            remediation="Remove: apt-get autoremove"
        ))
    
    # PKG-024: SELinux status (RedHat-specific)
    if os_info.family == 'redhat':
        selinux_status = check_selinux_status_core(cache=cache)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - OS Security (RedHat)",
            status="Pass" if selinux_status['enforcing'] else "Warning",
            message=f"{get_core_id('OS', 7)}: SELinux enforcing mode",
            details=f"Mode: {selinux_status['mode']}",
            remediation="Enable SELinux: setenforce 1"
        ))
    
    # PKG-025: AppArmor status (Debian-specific)
    if os_info.family == 'debian':
        apparmor_status = check_apparmor_status_core(cache=cache)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - OS Security (Debian)",
            status="Pass" if apparmor_status['enabled'] else "Warning",
            message=f"{get_core_id('OS', 8)}: AppArmor enabled",
            details=f"{apparmor_status['profiles_enforcing']} profiles enforcing",
            remediation="Enable AppArmor profiles"
        ))
    
    # PKG-026: System timezone configured
    result = run_command("timedatectl status 2>/dev/null | grep 'Time zone'")
    tz_set = result.returncode == 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - OS Detection",
        status="Pass" if tz_set else "Info",
        message=f"{get_core_id('OS', 9)}: System timezone configured",
        details="Configured" if tz_set else "Check timezone",
        remediation="Set timezone: timedatectl set-timezone <zone>"
    ))
    
    # PKG-027: System hostname configured
    hostname = socket.gethostname()
    hostname_ok = hostname and hostname != "localhost" and len(hostname) > 3
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - OS Detection",
        status="Pass" if hostname_ok else "Warning",
        message=f"{get_core_id('OS', 10)}: System hostname configured",
        details=f"Hostname: {hostname}",
        remediation="Set hostname: hostnamectl set-hostname <name>"
    ))
    
    # PKG-028: Package cache size (maintenance consideration)
    if os_info.package_manager == 'apt':
        cache_dir = "/var/cache/apt/archives"
        if os.path.exists(cache_dir):
            result = run_command(f"du -sh {cache_dir} 2>/dev/null | awk '{{print $1}}'")
            cache_size = result.stdout.strip()
            
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CORE - Package Management",
                status="Info",
                message=f"{get_core_id('PKG', 20)}: Package cache size",
                details=f"Cache: {cache_size}",
                remediation="Clean cache: apt-get clean"
            ))
    
    # PKG-029: Installed package count
    if os_info.package_manager == 'apt':
        result = run_command("dpkg -l | grep -c '^ii'")
    elif os_info.package_manager in ['yum', 'dnf']:
        result = run_command("rpm -qa | wc -l")
    else:
        result = None
    
    pkg_count = safe_int_parse(result.stdout.strip()) if result else 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Package Management",
        status="Info",
        message=f"{get_core_id('PKG', 21)}: Installed packages",
        details=f"{pkg_count} packages installed",
        remediation="Maintain package inventory"
    ))
    
    # PKG-030: System uptime
    result = run_command("uptime -p 2>/dev/null || uptime")
    uptime = result.stdout.strip()
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - OS Detection",
        status="Info",
        message=f"{get_core_id('OS', 11)}: System uptime",
        details=uptime,
        remediation="Reboot after kernel updates"
    ))


# ============================================================================
# SERVICE & USER MANAGEMENT
# OS-Aware Service and User Security Validation
# ============================================================================

def check_service_user_management(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Service and User Management OS-Aware Security Audit Checks
    """
    print(f"[{MODULE_NAME}] Checking Service & User Management...")
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    
    # Get service information (cache-aware)
    running_services = get_running_services(os_info)
    enabled_services = get_enabled_services(os_info)
    
    # SVC-001: Service count
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Service Management",
        status="Info",
        message=f"{get_core_id('SVC', 1)}: Running services inventory",
        details=f"{len(running_services)} services running",
        remediation="Review and minimize running services"
    ))
    
    # SVC-002: Unnecessary services check
    unnecessary = ['telnet', 'ftp', 'rsh', 'rlogin', 'rexec', 'tftp', 'talk', 'finger']
    found_unnecessary = [svc for svc in unnecessary if svc in running_services]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Service Management",
        status="Pass" if not found_unnecessary else "Fail",
        message=f"{get_core_id('SVC', 2)}: Insecure services disabled",
        details=f"Found: {', '.join(found_unnecessary)}" if found_unnecessary else "None",
        remediation="Disable insecure services: systemctl disable <service>"
    ))
    
    # SVC-003: SSH service
    ssh_running = any('ssh' in svc for svc in running_services)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Service Management",
        status="Pass" if ssh_running else "Info",
        message=f"{get_core_id('SVC', 3)}: SSH service status",
        details="Running" if ssh_running else "Not running",
        remediation="Configure SSH for remote access"
    ))
    
    # SVC-004: Firewall service
    firewall_services = ['ufw', 'firewalld', 'iptables']
    firewall_active = any(svc in running_services for svc in firewall_services)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Service Management",
        status="Pass" if firewall_active else "Fail",
        message=f"{get_core_id('SVC', 4)}: Firewall service active",
        details="Active" if firewall_active else "Not active",
        remediation="Enable firewall: ufw enable || firewall-cmd --reload"
    ))
    
    # SVC-005: Logging service
    logging_services = ['rsyslog', 'syslog-ng', 'systemd-journald']
    logging_active = any(svc in running_services for svc in logging_services)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Service Management",
        status="Pass" if logging_active else "Fail",
        message=f"{get_core_id('SVC', 5)}: System logging active",
        details="Active" if logging_active else "Not active",
        remediation="Enable logging: systemctl enable rsyslog"
    ))
    
    # SVC-006: Time sync service
    time_services = ['chronyd', 'ntpd', 'systemd-timesyncd']
    time_active = any(svc in running_services for svc in time_services)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Service Management",
        status="Pass" if time_active else "Warning",
        message=f"{get_core_id('SVC', 6)}: Time synchronization active",
        details="Active" if time_active else "Not active",
        remediation=remediation_for("chrony")
    ))
    
    # SVC-007: Cron service
    cron_active = any('cron' in svc for svc in running_services)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Service Management",
        status="Pass" if cron_active else "Info",
        message=f"{get_core_id('SVC', 7)}: Cron daemon active",
        details="Active" if cron_active else "Not active",
        remediation="Enable cron: systemctl enable cron"
    ))
    
    # SVC-008: Audit daemon (auditd)
    audit_active = 'auditd' in running_services
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Service Management",
        status="Pass" if audit_active else "Warning",
        message=f"{get_core_id('SVC', 8)}: Audit daemon (auditd) active",
        details="Active" if audit_active else "Not active",
        remediation=remediation_for("auditd")
    ))
    
    # User Management Checks
    
    # USR-001: User account inventory
    result = run_command("getent passwd | wc -l")
    user_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - User Management",
        status="Info",
        message=f"{get_core_id('USR', 1)}: User account inventory",
        details=f"{user_count} user accounts",
        remediation="Review user accounts regularly"
    ))
    
    # USR-002: Root account check
    result = run_command("getent passwd root")
    root_exists = result.returncode == 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - User Management",
        status="Pass" if root_exists else "Fail",
        message=f"{get_core_id('USR', 2)}: Root account exists",
        details="Exists" if root_exists else "Missing",
        remediation="Root account must exist"
    ))
    
    # USR-003: Only root has UID 0
    result = run_command("awk -F: '$3 == 0 {print $1}' /etc/passwd")
    uid0_accounts = [u.strip() for u in result.stdout.strip().split('\n') if u.strip()]
    only_root = len(uid0_accounts) == 1 and uid0_accounts[0] == 'root'
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - User Management",
        status="Pass" if only_root else "Fail",
        message=f"{get_core_id('USR', 3)}: Only root has UID 0",
        details=f"UID 0: {', '.join(uid0_accounts)}",
        remediation="Remove UID 0 from non-root accounts"
    ))
    
    # USR-004: System accounts have nologin shell
    result = run_command("awk -F: '$3 < 1000 && $3 != 0 && $7 !~ /nologin|false/ {print $1}' /etc/passwd | wc -l")
    system_with_shell = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - User Management",
        status="Pass" if system_with_shell == 0 else "Warning",
        message=f"{get_core_id('USR', 4)}: System accounts have nologin shell",
        details=f"{system_with_shell} system accounts with login shell",
        remediation="Set nologin shell: usermod -s /sbin/nologin <user>"
    ))
    
    # USR-005: No accounts with empty passwords
    if os.path.exists("/etc/shadow"):
        result = run_command("awk -F: '$2 == \"\" {print $1}' /etc/shadow | wc -l")
        empty_passwords = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - User Management",
            status="Pass" if empty_passwords == 0 else "Fail",
            message=f"{get_core_id('USR', 5)}: No accounts with empty passwords",
            details=f"{empty_passwords} accounts",
            remediation="Set passwords or lock accounts"
        ))
    
    # USR-006: Users with home directories
    result = run_command("awk -F: '$3 >= 1000 && $6 !~ /\\/home/ {print $1}' /etc/passwd | wc -l")
    no_home = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - User Management",
        status="Pass" if no_home <= 1 else "Info",  # nobody is ok
        message=f"{get_core_id('USR', 6)}: Users have proper home directories",
        details=f"{no_home} users without /home",
        remediation="Ensure users have home directories"
    ))
    
    # USR-007: Group inventory
    result = run_command("getent group | wc -l")
    group_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - User Management",
        status="Info",
        message=f"{get_core_id('USR', 7)}: Group inventory",
        details=f"{group_count} groups",
        remediation="Review groups regularly"
    ))
    
    # USR-008: Root group members
    result = run_command("getent group root | cut -d: -f4")
    root_group_members = result.stdout.strip()
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - User Management",
        status="Info",
        message=f"{get_core_id('USR', 8)}: Root group membership",
        details=f"Members: {root_group_members if root_group_members else 'none'}",
        remediation="Minimize root group membership"
    ))
    
    # USR-009: sudo group/wheel group
    if os_info.family == 'debian':
        sudo_group = 'sudo'
    else:
        sudo_group = 'wheel'
    
    result = run_command(f"getent group {sudo_group}")
    sudo_exists = result.returncode == 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - User Management",
        status="Pass" if sudo_exists else "Warning",
        message=f"{get_core_id('USR', 9)}: Sudo group exists",
        details=f"{sudo_group} group {'exists' if sudo_exists else 'missing'}",
        remediation=f"Create sudo group: groupadd {sudo_group}"
    ))
    
    # USR-010: sudo package installed
    sudo_installed = check_package_installed('sudo', os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - User Management",
        status="Pass" if sudo_installed else "Fail",
        message=f"{get_core_id('USR', 10)}: sudo package installed",
        details="Installed" if sudo_installed else "Not installed",
        remediation="Install sudo"
    ))
    
    # USR-011: /etc/passwd permissions
    if os.path.exists("/etc/passwd"):
        perms = get_file_permissions("/etc/passwd")
        perms_ok = perms and int(perms, 8) <= int('644', 8)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - User Management",
            status="Pass" if perms_ok else "Fail",
            message=f"{get_core_id('USR', 11)}: /etc/passwd permissions secure",
            details=f"Permissions: {perms}",
            remediation="chmod 644 /etc/passwd"
        ))
    
    # USR-012: /etc/shadow permissions
    if os.path.exists("/etc/shadow"):
        perms = get_file_permissions("/etc/shadow")
        perms_ok = perms and int(perms, 8) <= int('000', 8)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - User Management",
            status="Pass" if perms_ok else "Fail",
            message=f"{get_core_id('USR', 12)}: /etc/shadow permissions secure",
            details=f"Permissions: {perms}",
            remediation="chmod 000 /etc/shadow"
        ))
    
    # USR-013: /etc/group permissions
    if os.path.exists("/etc/group"):
        perms = get_file_permissions("/etc/group")
        perms_ok = perms and int(perms, 8) <= int('644', 8)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - User Management",
            status="Pass" if perms_ok else "Fail",
            message=f"{get_core_id('USR', 13)}: /etc/group permissions secure",
            details=f"Permissions: {perms}",
            remediation="chmod 644 /etc/group"
        ))
    
    # USR-014: Password aging configured
    if os.path.exists("/etc/login.defs"):
        content = read_file_safe("/etc/login.defs")
        pass_max = re.search(r'^PASS_MAX_DAYS\s+(\d+)', content, re.MULTILINE)
        aging_ok = pass_max and int(pass_max.group(1)) <= 90
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - User Management",
            status="Pass" if aging_ok else "Warning",
            message=f"{get_core_id('USR', 14)}: Password aging configured",
            details=f"PASS_MAX_DAYS: {pass_max.group(1) if pass_max else 'not set'}",
            remediation="Set PASS_MAX_DAYS 90 in /etc/login.defs"
        ))
    
    # USR-015: Default umask
    if os.path.exists("/etc/login.defs"):
        content = read_file_safe("/etc/login.defs")
        umask = re.search(r'^UMASK\s+(\d+)', content, re.MULTILINE)
        umask_ok = umask and umask.group(1) in ['027', '077']
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - User Management",
            status="Pass" if umask_ok else "Warning",
            message=f"{get_core_id('USR', 15)}: Default umask secure",
            details=f"UMASK: {umask.group(1) if umask else 'not set'}",
            remediation="Set UMASK 027 in /etc/login.defs"
        ))
    
    # Additional service checks
    
    # SVC-009: Unnecessary network services
    network_unnecessary = ['avahi-daemon', 'cups', 'bluetooth']
    found_net_unnecessary = [svc for svc in network_unnecessary if svc in running_services]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Service Management",
        status="Pass" if not found_net_unnecessary else "Info",
        message=f"{get_core_id('SVC', 9)}: Optional network services",
        details=f"Running: {', '.join(found_net_unnecessary)}" if found_net_unnecessary else "None",
        remediation="Disable if not needed: systemctl disable <service>"
    ))
    
    # SVC-010: X11/GUI services on server
    x11_services = ['gdm', 'lightdm', 'xdm', 'kdm']
    x11_running = [svc for svc in x11_services if svc in running_services]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Service Management",
        status="Pass" if not x11_running else "Info",
        message=f"{get_core_id('SVC', 10)}: GUI services on server",
        details=f"Running: {', '.join(x11_running)}" if x11_running else "None",
        remediation="Disable GUI on servers: systemctl set-default multi-user.target"
    ))


# ============================================================================
# FILESYSTEM & NETWORK SECURITY
# Critical Security Configurations
# ============================================================================

def check_filesystem_network(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Filesystem and Network Security Security Audit Checks
    """
    print(f"[{MODULE_NAME}] Checking Filesystem & Network Security...")
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    
    # FS-001: Root filesystem mounted
    result = run_command("mount | grep ' / '")
    root_mounted = result.returncode == 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Filesystem",
        status="Pass" if root_mounted else "Fail",
        message=f"{get_core_id('FS', 1)}: Root filesystem mounted",
        details="Mounted" if root_mounted else "Not mounted",
        remediation="Root filesystem must be mounted"
    ))
    
    # FS-002: /tmp exists
    tmp_exists = os.path.exists("/tmp")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Filesystem",
        status="Pass" if tmp_exists else "Fail",
        message=f"{get_core_id('FS', 2)}: /tmp directory exists",
        details="Exists" if tmp_exists else "Missing",
        remediation="Create /tmp directory"
    ))
    
    # FS-003: /tmp permissions
    if tmp_exists:
        perms = get_file_permissions("/tmp")
        # /tmp should be 1777 (sticky bit set)
        perms_ok = perms and int(perms, 8) == int('1777', 8)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Filesystem",
            status="Pass" if perms_ok else "Warning",
            message=f"{get_core_id('FS', 3)}: /tmp permissions secure",
            details=f"Permissions: {perms}",
            remediation="chmod 1777 /tmp"
        ))
    
    # FS-004: Separate partitions
    critical_mounts = ['/tmp', '/var', '/var/log', '/home']
    result = run_command("mount | awk '{print $3}'")
    current_mounts = result.stdout.strip().split('\n')
    
    separate_count = sum(1 for m in critical_mounts if m in current_mounts)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Filesystem",
        status="Pass" if separate_count >= 2 else "Info",
        message=f"{get_core_id('FS', 4)}: Separate partitions for critical directories",
        details=f"{separate_count}/4 on separate partitions",
        remediation="Use separate partitions for /tmp, /var, /home"
    ))
    
    # FS-005: nodev on /tmp
    result = run_command("mount | grep ' /tmp ' | grep -c nodev")
    tmp_nodev = safe_int_parse(result.stdout.strip()) > 0
    
    if '/tmp' in current_mounts:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Filesystem",
            status="Pass" if tmp_nodev else "Warning",
            message=f"{get_core_id('FS', 5)}: /tmp mounted with nodev",
            details="nodev set" if tmp_nodev else "Not set",
            remediation="Add nodev to /tmp in /etc/fstab"
        ))
    
    # FS-006: World-writable files (canonical shared assessment)
    from shared_components.shared_assessments import get_world_writable_assessment as _ww_assess
    _ww = _ww_assess("fail")
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Filesystem",
        status=_ww.status,
        message=f"{get_core_id('FS', 6)}: World-writable files",
        details=_ww.details,
        remediation=_ww.remediation
    ))
    
    # FS-007: SUID files inventory
    result = run_command("find / -xdev -perm -4000 -type f 2>/dev/null | wc -l")
    suid_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Filesystem",
        status="Info",
        message=f"{get_core_id('FS', 7)}: SUID files inventory",
        details=f"{suid_count} SUID files",
        remediation="Review and minimize SUID files"
    ))
    
    # FS-008: SGID files inventory  
    result = run_command("find / -xdev -perm -2000 -type f 2>/dev/null | wc -l")
    sgid_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Filesystem",
        status="Info",
        message=f"{get_core_id('FS', 8)}: SGID files inventory",
        details=f"{sgid_count} SGID files",
        remediation="Review and minimize SGID files"
    ))
    
    # FS-009: Unowned files
    result = run_command("find / -xdev \\( -nouser -o -nogroup \\) 2>/dev/null | head -10 | wc -l")
    unowned = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Filesystem",
        status="Pass" if unowned == 0 else "Warning",
        message=f"{get_core_id('FS', 9)}: No unowned files",
        details=f"{unowned} unowned files",
        remediation="Assign ownership: chown <user>:<group> <file>"
    ))
    
    # FS-010: Sticky bit on world-writable directories
    result = run_command("find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | head -10 | wc -l")
    no_sticky = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Filesystem",
        status="Pass" if no_sticky == 0 else "Warning",
        message=f"{get_core_id('FS', 10)}: Sticky bit on world-writable dirs",
        details=f"{no_sticky} dirs without sticky bit",
        remediation="Add sticky bit: chmod +t <directory>"
    ))
    
    # Network Security Checks
    
    # NET-001: Network interfaces
    result = run_command("ip -o link show | grep -v 'lo:' | wc -l")
    interface_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Network",
        status="Info",
        message=f"{get_core_id('NET', 1)}: Network interfaces",
        details=f"{interface_count} interfaces (excluding loopback)",
        remediation="Review network interfaces"
    ))
    
    # NET-002: IP forwarding disabled
    exists, ip_forward = check_kernel_parameter("net.ipv4.ip_forward")
    forward_disabled = ip_forward == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Network",
        status="Pass" if forward_disabled else "Warning",
        message=f"{get_core_id('NET', 2)}: IP forwarding disabled",
        details=f"ip_forward = {ip_forward}",
        remediation="Disable: sysctl -w net.ipv4.ip_forward=0"
    ))
    
    # NET-003: ICMP redirects disabled
    exists, redirects = check_kernel_parameter("net.ipv4.conf.all.accept_redirects")
    redirects_disabled = redirects == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Network",
        status="Pass" if redirects_disabled else "Warning",
        message=f"{get_core_id('NET', 3)}: ICMP redirects disabled",
        details=f"accept_redirects = {redirects}",
        remediation="Disable: sysctl -w net.ipv4.conf.all.accept_redirects=0"
    ))
    
    # NET-004: Source routing disabled
    exists, source_route = check_kernel_parameter("net.ipv4.conf.all.accept_source_route")
    source_disabled = source_route == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Network",
        status="Pass" if source_disabled else "Fail",
        message=f"{get_core_id('NET', 4)}: Source routing disabled",
        details=f"accept_source_route = {source_route}",
        remediation="Disable: sysctl -w net.ipv4.conf.all.accept_source_route=0"
    ))
    
    # NET-005: SYN cookies enabled
    exists, syn_cookies = check_kernel_parameter("net.ipv4.tcp_syncookies")
    syn_enabled = syn_cookies == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Network",
        status="Pass" if syn_enabled else "Warning",
        message=f"{get_core_id('NET', 5)}: TCP SYN cookies enabled",
        details=f"tcp_syncookies = {syn_cookies}",
        remediation="Enable: sysctl -w net.ipv4.tcp_syncookies=1"
    ))
    
    # NET-006: Reverse path filtering
    exists, rp_filter = check_kernel_parameter("net.ipv4.conf.all.rp_filter")
    rp_enabled = rp_filter == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Network",
        status="Pass" if rp_enabled else "Warning",
        message=f"{get_core_id('NET', 6)}: Reverse path filtering enabled",
        details=f"rp_filter = {rp_filter}",
        remediation="Enable: sysctl -w net.ipv4.conf.all.rp_filter=1"
    ))
    
    # NET-007: Log martian packets
    exists, log_martians = check_kernel_parameter("net.ipv4.conf.all.log_martians")
    martians_logged = log_martians == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Network",
        status="Pass" if martians_logged else "Info",
        message=f"{get_core_id('NET', 7)}: Martian packets logged",
        details=f"log_martians = {log_martians}",
        remediation="Enable: sysctl -w net.ipv4.conf.all.log_martians=1"
    ))
    
    # NET-008: ICMP broadcast ignored
    exists, icmp_broadcast = check_kernel_parameter("net.ipv4.icmp_echo_ignore_broadcasts")
    broadcast_ignored = icmp_broadcast == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Network",
        status="Pass" if broadcast_ignored else "Warning",
        message=f"{get_core_id('NET', 8)}: ICMP broadcast ignored",
        details=f"icmp_echo_ignore_broadcasts = {icmp_broadcast}",
        remediation="Enable: sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1"
    ))
    
    # NET-009: Listening ports inventory
    result = run_command("ss -tuln 2>/dev/null | grep LISTEN | wc -l")
    if result.returncode != 0:
        result = run_command("netstat -tuln 2>/dev/null | grep LISTEN | wc -l")
    
    listening_ports = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Network",
        status="Info",
        message=f"{get_core_id('NET', 9)}: Listening network ports",
        details=f"{listening_ports} ports listening",
        remediation="Minimize listening ports"
    ))
    
    # NET-010: DNS configuration
    if os.path.exists("/etc/resolv.conf"):
        content = read_file_safe("/etc/resolv.conf")
        nameservers = content.count("nameserver")
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Network",
            status="Pass" if nameservers >= 1 else "Warning",
            message=f"{get_core_id('NET', 10)}: DNS servers configured",
            details=f"{nameservers} nameservers",
            remediation="Configure DNS in /etc/resolv.conf"
        ))
    
    # NET-011: Default gateway
    result = run_command("ip route | grep -c default")
    has_gateway = safe_int_parse(result.stdout.strip()) > 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Network",
        status="Pass" if has_gateway else "Warning",
        message=f"{get_core_id('NET', 11)}: Default gateway configured",
        details="Configured" if has_gateway else "Not configured",
        remediation="Configure default gateway"
    ))
    
    # NET-012: IPv6 status
    ipv6_disabled = not os.path.exists("/proc/sys/net/ipv6/conf/all/disable_ipv6") or \
                    read_file_safe("/proc/sys/net/ipv6/conf/all/disable_ipv6").strip() == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Network",
        status="Info",
        message=f"{get_core_id('NET', 12)}: IPv6 status",
        details="Disabled" if ipv6_disabled else "Enabled",
        remediation="Disable if not needed: sysctl -w net.ipv6.conf.all.disable_ipv6=1"
    ))
    
    # NET-013: Firewall rules count (iptables)
    result = run_command("iptables -L 2>/dev/null | grep -c Chain")
    iptables_chains = safe_int_parse(result.stdout.strip())
    
    if iptables_chains > 0:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Network",
            status="Info",
            message=f"{get_core_id('NET', 13)}: Firewall rules configured",
            details=f"{iptables_chains} iptables chains",
            remediation="Review firewall rules"
        ))
    
    # NET-014: Network parameters in sysctl.conf
    if os.path.exists("/etc/sysctl.conf"):
        content = read_file_safe("/etc/sysctl.conf")
        net_params = content.count("net.")
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Network",
            status="Pass" if net_params >= 5 else "Info",
            message=f"{get_core_id('NET', 14)}: Network parameters persistent",
            details=f"{net_params} network parameters in sysctl.conf",
            remediation="Add network hardening parameters to /etc/sysctl.conf"
        ))
    
    # NET-015: Hosts file configured
    if os.path.exists("/etc/hosts"):
        content = read_file_safe("/etc/hosts")
        localhost_entry = "127.0.0.1" in content and "localhost" in content
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Network",
            status="Pass" if localhost_entry else "Warning",
            message=f"{get_core_id('NET', 15)}: /etc/hosts configured",
            details="Localhost entry present" if localhost_entry else "Missing entries",
            remediation="Configure /etc/hosts"
        ))


# ============================================================================
# SYSTEM HARDENING & SECURITY TOOLS
# Core System Security and Monitoring
# ============================================================================

def check_system_hardening_tools(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    System Hardening and Security Tools Checks
    """
    print(f"[{MODULE_NAME}] Checking System Hardening & Security Tools...")
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    
    # HARD-001: ASLR enabled
    exists, aslr = check_kernel_parameter("kernel.randomize_va_space")
    aslr_enabled = aslr == "2"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Pass" if aslr_enabled else "Fail",
        message=f"{get_core_id('HARD', 1)}: Address Space Layout Randomization",
        details=f"randomize_va_space = {aslr}",
        remediation="Enable: sysctl -w kernel.randomize_va_space=2"
    ))
    
    # HARD-002: Kernel pointers restricted
    exists, kptr_restrict = check_kernel_parameter("kernel.kptr_restrict")
    kptr_ok = kptr_restrict in ["1", "2"]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Pass" if kptr_ok else "Warning",
        message=f"{get_core_id('HARD', 2)}: Kernel pointers restricted",
        details=f"kptr_restrict = {kptr_restrict}",
        remediation="Enable: sysctl -w kernel.kptr_restrict=1"
    ))
    
    # HARD-003: dmesg restricted
    exists, dmesg_restrict = check_kernel_parameter("kernel.dmesg_restrict")
    dmesg_ok = dmesg_restrict == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Pass" if dmesg_ok else "Warning",
        message=f"{get_core_id('HARD', 3)}: dmesg access restricted",
        details=f"dmesg_restrict = {dmesg_restrict}",
        remediation="Enable: sysctl -w kernel.dmesg_restrict=1"
    ))
    
    # HARD-004: Core dumps restricted
    exists, core_pattern = check_kernel_parameter("kernel.core_pattern")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Info",
        message=f"{get_core_id('HARD', 4)}: Core dump configuration",
        details=f"core_pattern = {core_pattern}"[:60],
        remediation="Restrict core dumps in /etc/security/limits.conf"
    ))
    
    # HARD-005: SUID dumpable
    exists, suid_dumpable = check_kernel_parameter("fs.suid_dumpable")
    suid_ok = suid_dumpable == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Pass" if suid_ok else "Warning",
        message=f"{get_core_id('HARD', 5)}: SUID core dumps disabled",
        details=f"suid_dumpable = {suid_dumpable}",
        remediation="Disable: sysctl -w fs.suid_dumpable=0"
    ))
    
    # HARD-006: Protected hardlinks
    exists, hardlinks = check_kernel_parameter("fs.protected_hardlinks")
    hardlinks_ok = hardlinks == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Pass" if hardlinks_ok else "Warning",
        message=f"{get_core_id('HARD', 6)}: Protected hardlinks enabled",
        details=f"protected_hardlinks = {hardlinks}",
        remediation="Enable: sysctl -w fs.protected_hardlinks=1"
    ))
    
    # HARD-007: Protected symlinks
    exists, symlinks = check_kernel_parameter("fs.protected_symlinks")
    symlinks_ok = symlinks == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Pass" if symlinks_ok else "Warning",
        message=f"{get_core_id('HARD', 7)}: Protected symlinks enabled",
        details=f"protected_symlinks = {symlinks}",
        remediation="Enable: sysctl -w fs.protected_symlinks=1"
    ))
    
    # HARD-008: Ptrace scope
    exists, ptrace_scope = check_kernel_parameter("kernel.yama.ptrace_scope")
    ptrace_ok = ptrace_scope in ["1", "2", "3"]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Pass" if ptrace_ok else "Warning",
        message=f"{get_core_id('HARD', 8)}: Ptrace scope restricted",
        details=f"ptrace_scope = {ptrace_scope}",
        remediation="Enable: sysctl -w kernel.yama.ptrace_scope=1"
    ))
    
    # Security Tools Checks
    
    # TOOL-001: File integrity monitoring
    fim_tools = ['aide', 'tripwire', 'samhain']
    fim_installed = [tool for tool in fim_tools if check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Security Tools",
        status="Pass" if fim_installed else "Warning",
        message=f"{get_core_id('TOOL', 1)}: File integrity monitoring installed",
        details=f"Installed: {', '.join(fim_installed)}" if fim_installed else "Not installed",
        remediation=remediation_for("aide")
    ))
    
    # TOOL-002: Intrusion detection
    ids_tools = ['ossec', 'snort', 'suricata']
    ids_installed = [tool for tool in ids_tools if check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Security Tools",
        status="Info",
        message=f"{get_core_id('TOOL', 2)}: Intrusion detection system",
        details=f"Installed: {', '.join(ids_installed)}" if ids_installed else "Not installed",
        remediation="Consider installing IDS/IPS"
    ))
    
    # TOOL-003: Anti-malware
    av_installed = check_package_installed('clamav', os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Security Tools",
        status="Pass" if av_installed else "Warning",
        message=f"{get_core_id('TOOL', 3)}: Anti-malware software installed",
        details="ClamAV installed" if av_installed else "Not installed",
        remediation=remediation_for("clamav")
    ))
    
    # TOOL-004: Rootkit detection
    rk_tools = ['rkhunter', 'chkrootkit']
    rk_installed = [tool for tool in rk_tools if check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Security Tools",
        status="Pass" if rk_installed else "Warning",
        message=f"{get_core_id('TOOL', 4)}: Rootkit detection tools",
        details=f"Installed: {', '.join(rk_installed)}" if rk_installed else "Not installed",
        remediation=remediation_for("rkhunter")
    ))
    
    # TOOL-005: System monitoring
    mon_tools = ['monit', 'nagios', 'zabbix']
    mon_installed = [tool for tool in mon_tools if check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Security Tools",
        status="Info",
        message=f"{get_core_id('TOOL', 5)}: System monitoring tools",
        details=f"Installed: {', '.join(mon_installed)}" if mon_installed else "Not installed",
        remediation="Consider installing monitoring tools"
    ))
    
    # TOOL-006: Log analysis
    log_tools = ['logwatch', 'fail2ban']
    log_installed = [tool for tool in log_tools if check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Security Tools",
        status="Info",
        message=f"{get_core_id('TOOL', 6)}: Log analysis tools",
        details=f"Installed: {', '.join(log_installed)}" if log_installed else "Not installed",
        remediation=remediation_for("fail2ban")
    ))
    
    # TOOL-007: Firewall management tools
    fw_tools = ['ufw', 'firewalld']
    fw_installed = [tool for tool in fw_tools if check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Security Tools",
        status="Pass" if fw_installed else "Warning",
        message=f"{get_core_id('TOOL', 7)}: Firewall management tools",
        details=f"Installed: {', '.join(fw_installed)}" if fw_installed else "Not installed",
        remediation="Install firewall management: ufw or firewalld"
    ))
    
    # Additional Hardening Checks
    
    # HARD-009: Kernel modules restricted
    modprobe_d = os.path.exists("/etc/modprobe.d")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Pass" if modprobe_d else "Info",
        message=f"{get_core_id('HARD', 9)}: Kernel module configuration directory",
        details="Exists" if modprobe_d else "Not found",
        remediation="Create /etc/modprobe.d/ for module restrictions"
    ))
    
    # HARD-010: Ctrl-Alt-Del disabled
    ctrl_alt_del_disabled = False
    if os.path.exists("/etc/systemd/system/ctrl-alt-del.target"):
        link = os.path.realpath("/etc/systemd/system/ctrl-alt-del.target")
        ctrl_alt_del_disabled = "/dev/null" in link
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Pass" if ctrl_alt_del_disabled else "Warning",
        message=f"{get_core_id('HARD', 10)}: Ctrl-Alt-Del disabled",
        details="Disabled" if ctrl_alt_del_disabled else "Enabled",
        remediation="Disable: systemctl mask ctrl-alt-del.target"
    ))
    
    # HARD-011: Bootloader installed
    grub_exists = os.path.exists("/boot/grub") or os.path.exists("/boot/grub2")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Pass" if grub_exists else "Warning",
        message=f"{get_core_id('HARD', 11)}: Bootloader present",
        details="GRUB found" if grub_exists else "Not found",
        remediation="Install GRUB bootloader"
    ))
    
    # HARD-012: System accounting
    process_acct = check_package_installed('psacct', os_info) or check_package_installed('acct', os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Info",
        message=f"{get_core_id('HARD', 12)}: Process accounting installed",
        details="Installed" if process_acct else "Not installed",
        remediation="Install: apt-get install psacct"
    ))
    
    # HARD-013: System activity reporting
    sysstat = check_package_installed('sysstat', os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Info",
        message=f"{get_core_id('HARD', 13)}: System activity reporting",
        details="sysstat installed" if sysstat else "Not installed",
        remediation=remediation_for("sysstat")
    ))
    
    # HARD-014: Memory overcommit
    exists, overcommit = check_kernel_parameter("vm.overcommit_memory")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Info",
        message=f"{get_core_id('HARD', 14)}: Memory overcommit setting",
        details=f"overcommit_memory = {overcommit}",
        remediation="Configure based on workload requirements"
    ))
    
    # HARD-015: Swap usage
    result = run_command("swapon --show | wc -l")
    swap_configured = safe_int_parse(result.stdout.strip()) > 1  # Header line present
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Info",
        message=f"{get_core_id('HARD', 15)}: Swap space configured",
        details="Configured" if swap_configured else "No swap",
        remediation="Configure swap based on system requirements"
    ))
    
    # HARD-016: Kernel panic behavior
    exists, panic_timeout = check_kernel_parameter("kernel.panic")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Info",
        message=f"{get_core_id('HARD', 16)}: Kernel panic timeout",
        details=f"panic = {panic_timeout}",
        remediation="Configure panic behavior"
    ))
    
    # HARD-017: File descriptor limits
    result = run_command("ulimit -n")
    fd_limit = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Info",
        message=f"{get_core_id('HARD', 17)}: File descriptor limit",
        details=f"Limit: {fd_limit}",
        remediation="Adjust in /etc/security/limits.conf if needed"
    ))
    
    # HARD-018: Process limit
    result = run_command("ulimit -u")
    proc_limit = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Info",
        message=f"{get_core_id('HARD', 18)}: Process limit",
        details=f"Limit: {proc_limit}",
        remediation="Adjust in /etc/security/limits.conf if needed"
    ))
    
    # HARD-019: Loaded kernel modules
    result = run_command("lsmod | wc -l")
    module_count = safe_int_parse(result.stdout.strip()) - 1  # Subtract header
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Info",
        message=f"{get_core_id('HARD', 19)}: Loaded kernel modules",
        details=f"{module_count} modules loaded",
        remediation="Review and minimize kernel modules"
    ))
    
    # HARD-020: Kernel log level
    if os.path.exists("/proc/sys/kernel/printk"):
        printk = read_file_safe("/proc/sys/kernel/printk").strip().split()[0]
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - System Hardening",
            status="Info",
            message=f"{get_core_id('HARD', 20)}: Kernel log level",
            details=f"Console log level: {printk}",
            remediation="Configure kernel logging"
        ))


# ============================================================================
# Advanced Security Checks
# Covers: Kernel Security Modules, systemd Hardening, Crypto Policy,
#         SELinux/AppArmor Deep, Container Security, UEFI, Supply Chain
# ============================================================================

def check_advanced_security(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Advanced Security Checks - Cross-cutting controls applicable to multiple frameworks.
    
    Covers:
        - Kernel security modules (YAMA, Lockdown, IMA/EVM)
        - systemd unit hardening (ProtectSystem, PrivateTmp, etc.)
        - Cryptographic policy assessment (crypto-policies, TLS, FIPS)
        - SELinux/AppArmor deep inspection (profiles, enforcement)
        - Container/Docker security detection
        - UEFI Secure Boot validation
        - Supply chain security (package signing, repository integrity)
    """
    print(f"[{MODULE_NAME}] Checking Advanced Security Controls...")
    
    # Extract cache from shared_data for performance
    cache = shared_data.get('cache')
    
    # ----------------------------------------------------------------
    # Kernel Security Modules
    # ----------------------------------------------------------------
    
    # ADVK-001: YAMA ptrace scope
    exists, yama_val = check_kernel_parameter("kernel.yama.ptrace_scope")
    if exists:
        yama_ok = yama_val in ["1", "2", "3"]
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Kernel Security",
            status="Pass" if yama_ok else "Warning",
            message=f"{get_core_id('ADVK', 1)}: YAMA ptrace scope restriction",
            details=f"ptrace_scope = {yama_val} ({'restricted' if yama_ok else 'unrestricted - any process can ptrace'})",
            remediation="Enable: sysctl -w kernel.yama.ptrace_scope=1"
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Kernel Security",
            status="Warning",
            message=f"{get_core_id('ADVK', 1)}: YAMA ptrace scope restriction",
            details="YAMA LSM not loaded or not available",
            remediation="Enable YAMA: ensure CONFIG_SECURITY_YAMA=y in kernel config"
        ))
    
    # ADVK-002: Kernel lockdown mode
    lockdown_path = "/sys/kernel/security/lockdown"
    lockdown_val = ""
    try:
        if os.path.exists(lockdown_path):
            with open(lockdown_path, 'r') as f:
                lockdown_val = f.read().strip()
        # Parse: format is "[none] integrity confidentiality" with brackets on active
        lockdown_active = "none" not in lockdown_val.split('[')[1].split(']')[0] if '[' in lockdown_val else False
    except (IOError, IndexError, PermissionError):
        lockdown_active = False
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Kernel Security",
        status="Pass" if lockdown_active else "Info",
        message=f"{get_core_id('ADVK', 2)}: Kernel lockdown mode",
        details=f"Lockdown: {lockdown_val if lockdown_val else 'not available'}",
        remediation="Enable via kernel boot parameter: lockdown=integrity"
    ))
    
    # ADVK-003: Integrity Measurement Architecture (IMA)
    ima_active = os.path.exists("/sys/kernel/security/ima")
    ima_policy = ""
    if ima_active:
        try:
            with open("/sys/kernel/security/ima/runtime_measurements_count", 'r') as f:
                ima_count = f.read().strip()
            ima_policy = f"{ima_count} measurements recorded"
        except (IOError, PermissionError):
            ima_policy = "Active but measurements not readable"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Kernel Security",
        status="Pass" if ima_active else "Info",
        message=f"{get_core_id('ADVK', 3)}: Integrity Measurement Architecture (IMA)",
        details=f"IMA: {'enabled - ' + ima_policy if ima_active else 'not enabled'}",
        remediation="Enable IMA via kernel boot parameter: ima_policy=tcb"
    ))
    
    # ADVK-004: Extended Verification Module (EVM)
    evm_active = os.path.exists("/sys/kernel/security/evm")
    evm_status = ""
    if evm_active:
        try:
            with open("/sys/kernel/security/evm", 'r') as f:
                evm_status = f.read().strip()
        except (IOError, PermissionError):
            evm_status = "active but not readable"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Kernel Security",
        status="Pass" if evm_active else "Info",
        message=f"{get_core_id('ADVK', 4)}: Extended Verification Module (EVM)",
        details=f"EVM: {'enabled (status=' + evm_status + ')' if evm_active else 'not enabled'}",
        remediation="Enable EVM via kernel configuration: CONFIG_EVM=y"
    ))
    
    # ADVK-005: Unprivileged BPF disabled
    exists, bpf_val = check_kernel_parameter("kernel.unprivileged_bpf_disabled")
    bpf_restricted = bpf_val == "1" or bpf_val == "2"
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Kernel Security",
        status="Pass" if bpf_restricted else "Warning",
        message=f"{get_core_id('ADVK', 5)}: Unprivileged BPF programs restricted",
        details=f"unprivileged_bpf_disabled = {bpf_val if exists else 'not set'}",
        remediation="Restrict: sysctl -w kernel.unprivileged_bpf_disabled=1"
    ))
    
    # ADVK-006: Unprivileged user namespaces
    exists, userns_val = check_kernel_parameter("kernel.unprivileged_userns_clone")
    if exists:
        userns_restricted = userns_val == "0"
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Kernel Security",
            status="Pass" if userns_restricted else "Warning",
            message=f"{get_core_id('ADVK', 6)}: Unprivileged user namespaces restricted",
            details=f"unprivileged_userns_clone = {userns_val}",
            remediation="Restrict: sysctl -w kernel.unprivileged_userns_clone=0"
        ))
    else:
        # Check max_user_namespaces as alternative
        exists2, maxns = check_kernel_parameter("user.max_user_namespaces")
        ns_restricted = exists2 and maxns == "0"
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Kernel Security",
            status="Pass" if ns_restricted else "Info",
            message=f"{get_core_id('ADVK', 6)}: Unprivileged user namespaces",
            details=f"max_user_namespaces = {maxns if exists2 else 'kernel default'}",
            remediation="Restrict: sysctl -w user.max_user_namespaces=0"
        ))
    
    # ADVK-007: kexec_load restricted
    exists, kexec_val = check_kernel_parameter("kernel.kexec_load_disabled")
    kexec_disabled = exists and kexec_val == "1"
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Kernel Security",
        status="Pass" if kexec_disabled else "Warning",
        message=f"{get_core_id('ADVK', 7)}: kexec_load disabled",
        details=f"kexec_load_disabled = {kexec_val if exists else 'not set (kexec allowed)'}",
        remediation="Disable: sysctl -w kernel.kexec_load_disabled=1"
    ))
    
    # ----------------------------------------------------------------
    # systemd Unit Hardening
    # ----------------------------------------------------------------
    
    # Check critical services for hardening directives
    critical_services = ["sshd", "ssh", "systemd-resolved", "systemd-journald",
                         "systemd-logind", "systemd-networkd", "dbus"]
    
    hardening_directives = [
        "ProtectSystem", "ProtectHome", "PrivateTmp",
        "NoNewPrivileges", "ProtectKernelTunables",
        "ProtectKernelModules", "ProtectControlGroups"
    ]
    
    services_checked = 0
    services_hardened = 0
    hardening_details = []
    
    for svc in critical_services:
        svc_result = run_command(f"systemctl show {svc}.service 2>/dev/null "
                                f"--property=ProtectSystem,ProtectHome,PrivateTmp,"
                                f"NoNewPrivileges,ProtectKernelTunables,"
                                f"ProtectKernelModules,ProtectControlGroups")
        if svc_result.returncode == 0 and svc_result.stdout.strip():
            props = {}
            for line in svc_result.stdout.strip().splitlines():
                if '=' in line:
                    k, v = line.split('=', 1)
                    props[k] = v
            
            # Only count if the service actually exists/is loaded
            if any(v not in ['', 'no'] for v in props.values()):
                services_checked += 1
                active_directives = [k for k, v in props.items()
                                     if v.lower() not in ['no', 'false', '', '0']]
                if len(active_directives) >= 3:
                    services_hardened += 1
                hardening_details.append(f"{svc}: {len(active_directives)}/{len(hardening_directives)} directives")
    
    # ADVS-001: systemd service hardening overview
    if services_checked > 0:
        hardening_ratio = services_hardened / services_checked
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - systemd Hardening",
            status="Pass" if hardening_ratio >= 0.5 else ("Warning" if hardening_ratio > 0 else "Fail"),
            message=f"{get_core_id('ADVS', 1)}: systemd service security hardening",
            details=f"{services_hardened}/{services_checked} critical services have 3+ hardening directives; "
                    f"{'; '.join(hardening_details[:5])}",
            remediation="Add hardening directives to unit files: ProtectSystem=strict, PrivateTmp=true, "
                        "NoNewPrivileges=true, ProtectKernelTunables=true"
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - systemd Hardening",
            status="Info",
            message=f"{get_core_id('ADVS', 1)}: systemd service security hardening",
            details="No critical systemd services found to assess",
            remediation="Verify systemd is the init system"
        ))
    
    # ADVS-002: SSH service specific hardening
    ssh_svc = "sshd" if command_exists("sshd") else "ssh"
    ssh_show = run_command(f"systemctl show {ssh_svc}.service 2>/dev/null "
                           f"--property=ProtectSystem,PrivateTmp,NoNewPrivileges")
    if ssh_show.returncode == 0 and ssh_show.stdout.strip():
        ssh_props = {}
        for line in ssh_show.stdout.strip().splitlines():
            if '=' in line:
                k, v = line.split('=', 1)
                ssh_props[k] = v
        ssh_hardened = sum(1 for v in ssh_props.values()
                          if v.lower() not in ['no', 'false', '', '0'])
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - systemd Hardening",
            status="Pass" if ssh_hardened >= 2 else "Warning",
            message=f"{get_core_id('ADVS', 2)}: SSH service unit hardening",
            details=f"{ssh_svc}.service: {ssh_hardened}/3 key hardening directives active "
                    f"({', '.join(k + '=' + v for k, v in ssh_props.items())})",
            remediation=f"Add to {ssh_svc}.service override: ProtectSystem=strict, "
                        f"PrivateTmp=true, NoNewPrivileges=true"
        ))
    
    # ADVS-003: Default umask for systemd services
    default_umask = run_command("systemctl show --property=DefaultLimitNOFILE,DefaultLimitCORE 2>/dev/null")
    # Check /etc/login.defs UMASK
    umask_val = ""
    login_defs = read_file_safe("/etc/login.defs", use_cache=True)
    if login_defs:
        for line in login_defs.splitlines():
            if line.strip().startswith("UMASK") and not line.strip().startswith("#"):
                parts = line.strip().split()
                if len(parts) >= 2:
                    umask_val = parts[1]
    
    umask_secure = umask_val in ["027", "077"]
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - systemd Hardening",
        status="Pass" if umask_secure else "Warning",
        message=f"{get_core_id('ADVS', 3)}: Default system umask",
        details=f"UMASK = {umask_val if umask_val else 'not set (default 022)'}",
        remediation="Set UMASK 027 in /etc/login.defs for restrictive default permissions"
    ))
    
    # ----------------------------------------------------------------
    # Cryptographic Policy
    # ----------------------------------------------------------------
    
    # ADVC-001: System-wide crypto policy (RHEL/Fedora)
    crypto_policy_file = "/etc/crypto-policies/config"
    if os.path.exists(crypto_policy_file):
        crypto_policy = read_file_safe(crypto_policy_file, use_cache=True).strip()
        # LEGACY < DEFAULT < FUTURE < FIPS
        policy_ok = crypto_policy.upper() in ["DEFAULT", "FUTURE", "FIPS", "FIPS:OSPP"]
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Cryptographic Policy",
            status="Pass" if policy_ok else "Fail",
            message=f"{get_core_id('ADVC', 1)}: System-wide cryptographic policy",
            details=f"Crypto policy: {crypto_policy}",
            remediation="Set policy: update-crypto-policies --set FUTURE (or FIPS)"
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Cryptographic Policy",
            status="Info",
            message=f"{get_core_id('ADVC', 1)}: System-wide cryptographic policy",
            details="crypto-policies not available (non-RHEL/Fedora system)",
            remediation="On Debian/Ubuntu, manage crypto settings per-application"
        ))
    
    # ADVC-002: OpenSSL version and configuration
    openssl_ver = run_command("openssl version 2>/dev/null")
    if openssl_ver.returncode == 0:
        ver_str = openssl_ver.stdout.strip()
        # Check for known vulnerable versions (OpenSSL < 3.0 is end of life)
        is_v3 = "OpenSSL 3." in ver_str
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Cryptographic Policy",
            status="Pass" if is_v3 else "Warning",
            message=f"{get_core_id('ADVC', 2)}: OpenSSL version",
            details=f"{ver_str}",
            remediation="Upgrade to OpenSSL 3.x for current security features and support"
        ))
    
    # ADVC-003: SSH protocol and cipher strength
    ssh_config = {}
    if cache:
        ssh_config = cache.get_parsed('ssh_config') or {}
    
    # Check for weak ciphers
    ciphers = ssh_config.get('ciphers', '')
    weak_ciphers = ['3des-cbc', 'arcfour', 'blowfish-cbc', 'cast128-cbc']
    has_weak = any(wc in ciphers.lower() for wc in weak_ciphers) if ciphers else False
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Cryptographic Policy",
        status="Fail" if has_weak else ("Pass" if ciphers else "Info"),
        message=f"{get_core_id('ADVC', 3)}: SSH cipher configuration",
        details=f"Ciphers: {ciphers if ciphers else 'system default'}; "
                f"{'Weak ciphers detected!' if has_weak else 'No weak ciphers'}",
        remediation="Set strong ciphers in /etc/ssh/sshd_config: "
                    "Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr"
    ))
    
    # ADVC-004: SSH key exchange algorithms
    kex = ssh_config.get('kexalgorithms', '')
    weak_kex = ['diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1',
                'diffie-hellman-group-exchange-sha1']
    has_weak_kex = any(wk in kex.lower() for wk in weak_kex) if kex else False
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Cryptographic Policy",
        status="Fail" if has_weak_kex else ("Pass" if kex else "Info"),
        message=f"{get_core_id('ADVC', 4)}: SSH key exchange algorithms",
        details=f"KexAlgorithms: {kex if kex else 'system default'}; "
                f"{'Weak KEX detected!' if has_weak_kex else 'No weak KEX algorithms'}",
        remediation="Set strong KEX in /etc/ssh/sshd_config: "
                    "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,"
                    "diffie-hellman-group16-sha512"
    ))
    
    # ADVC-005: SSH MAC algorithms
    macs = ssh_config.get('macs', '')
    weak_macs = ['hmac-md5', 'hmac-sha1', 'umac-64', 'hmac-sha1-96', 'hmac-md5-96']
    has_weak_macs = any(wm in macs.lower() for wm in weak_macs) if macs else False
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Cryptographic Policy",
        status="Fail" if has_weak_macs else ("Pass" if macs else "Info"),
        message=f"{get_core_id('ADVC', 5)}: SSH MAC algorithms",
        details=f"MACs: {macs if macs else 'system default'}; "
                f"{'Weak MACs detected!' if has_weak_macs else 'No weak MAC algorithms'}",
        remediation="Set strong MACs in /etc/ssh/sshd_config: "
                    "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"
    ))
    
    # ADVC-006: TLS minimum version check (system OpenSSL)
    tls_min = run_command("openssl s_client -help 2>&1 | grep -o 'tls1_[0-9]'")
    # Check openssl.cnf for MinProtocol
    openssl_cnf = read_file_safe("/etc/ssl/openssl.cnf", use_cache=True)
    min_protocol = ""
    if openssl_cnf:
        for line in openssl_cnf.splitlines():
            if 'MinProtocol' in line and not line.strip().startswith('#'):
                min_protocol = line.strip()
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Cryptographic Policy",
        status="Pass" if "TLSv1.2" in min_protocol or "TLSv1.3" in min_protocol else "Info",
        message=f"{get_core_id('ADVC', 6)}: System TLS minimum protocol version",
        details=f"{min_protocol if min_protocol else 'No MinProtocol set in openssl.cnf (default applies)'}",
        remediation="Set MinProtocol = TLSv1.2 in /etc/ssl/openssl.cnf [system_default_sect]"
    ))
    
    # ----------------------------------------------------------------
    # SELinux / AppArmor Deep Inspection
    # ----------------------------------------------------------------
    
    # ADVM-001: SELinux detailed mode (beyond boolean)
    selinux_status = run_command("sestatus 2>/dev/null")
    if selinux_status.returncode == 0 and selinux_status.stdout.strip():
        se_lines = selinux_status.stdout.strip().splitlines()
        se_dict = {}
        for line in se_lines:
            if ':' in line:
                k, v = line.split(':', 1)
                se_dict[k.strip()] = v.strip()
        
        current_mode = se_dict.get('Current mode', 'unknown')
        policy_name = se_dict.get('Loaded policy name', 'unknown')
        mode_from_config = se_dict.get('Mode from config file', 'unknown')
        
        enforcing = current_mode.lower() == 'enforcing'
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Mandatory Access Control",
            status="Pass" if enforcing else "Fail",
            message=f"{get_core_id('ADVM', 1)}: SELinux enforcement mode",
            details=f"Current mode: {current_mode}, Config mode: {mode_from_config}, "
                    f"Policy: {policy_name}",
            remediation="Set SELINUX=enforcing in /etc/selinux/config and reboot"
        ))
        
        # ADVM-002: SELinux denials / permissive domains
        denials = run_command("ausearch -m avc --start today 2>/dev/null | head -5")
        denial_count = len([l for l in denials.stdout.splitlines() if 'avc:' in l]) if denials.returncode == 0 else -1
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Mandatory Access Control",
            status="Pass" if denial_count == 0 else ("Warning" if denial_count > 0 else "Info"),
            message=f"{get_core_id('ADVM', 2)}: SELinux recent denials",
            details=f"{'No AVC denials today' if denial_count == 0 else (str(denial_count) + ' recent AVC denials' if denial_count > 0 else 'Unable to query audit log')}",
            remediation="Review denials: ausearch -m avc --start today; resolve with sealert or audit2allow"
        ))
        
        # ADVM-003: SELinux boolean hardening
        booleans_check = run_command("getsebool -a 2>/dev/null | grep -c 'on$'")
        booleans_total = run_command("getsebool -a 2>/dev/null | wc -l")
        if booleans_check.returncode == 0:
            on_count = safe_int_parse(booleans_check.stdout.strip(), 0)
            total_count = safe_int_parse(booleans_total.stdout.strip(), 0)
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CORE - Mandatory Access Control",
                status="Info",
                message=f"{get_core_id('ADVM', 3)}: SELinux boolean policy",
                details=f"{on_count}/{total_count} SELinux booleans enabled",
                remediation="Review enabled booleans: getsebool -a | grep on; "
                            "disable unnecessary with setsebool -P <bool> off"
            ))
    
    # AppArmor deep inspection
    aa_status = run_command("aa-status 2>/dev/null")
    if aa_status.returncode == 0 and aa_status.stdout.strip():
        aa_lines = aa_status.stdout.strip().splitlines()
        enforce_count = 0
        complain_count = 0
        for line in aa_lines:
            if 'enforce' in line.lower() and 'profiles' in line.lower():
                enforce_count = safe_int_parse(line.split()[0], 0)
            elif 'complain' in line.lower() and 'profiles' in line.lower():
                complain_count = safe_int_parse(line.split()[0], 0)
        
        # ADVM-004: AppArmor profile enforcement
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Mandatory Access Control",
            status="Pass" if enforce_count > 0 else "Warning",
            message=f"{get_core_id('ADVM', 4)}: AppArmor profile enforcement",
            details=f"{enforce_count} profiles in enforce mode, {complain_count} in complain mode",
            remediation="Set profiles to enforce: aa-enforce /etc/apparmor.d/*"
        ))
        
        # ADVM-005: Unconfined processes
        unconfined = run_command("aa-unconfined 2>/dev/null | wc -l")
        if unconfined.returncode == 0:
            unconfined_count = safe_int_parse(unconfined.stdout.strip(), 0)
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CORE - Mandatory Access Control",
                status="Warning" if unconfined_count > 10 else "Pass",
                message=f"{get_core_id('ADVM', 5)}: AppArmor unconfined processes",
                details=f"{unconfined_count} unconfined processes detected",
                remediation="Create AppArmor profiles for unconfined network-facing services"
            ))
    
    # ADVM-006: MAC system present check (either SELinux or AppArmor)
    has_selinux = selinux_status.returncode == 0 if 'selinux_status' in dir() else False
    has_apparmor = aa_status.returncode == 0 if 'aa_status' in dir() else False
    
    if not has_selinux and not has_apparmor:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Mandatory Access Control",
            status="Fail",
            message=f"{get_core_id('ADVM', 6)}: Mandatory Access Control system active",
            details="Neither SELinux nor AppArmor is active on this system",
            remediation="Enable SELinux or AppArmor for mandatory access control"
        ))
    
    # ----------------------------------------------------------------
    # Container / Docker Security Detection
    # ----------------------------------------------------------------
    
    # ADVD-001: Running inside a container?
    in_container = False
    container_type = "none"
    
    if os.path.exists("/.dockerenv"):
        in_container = True
        container_type = "Docker"
    elif os.path.exists("/run/.containerenv"):
        in_container = True
        container_type = "Podman"
    else:
        cgroup_content = read_file_safe("/proc/1/cgroup", use_cache=True)
        if cgroup_content and ('docker' in cgroup_content or 'lxc' in cgroup_content
                               or 'kubepods' in cgroup_content):
            in_container = True
            container_type = "container (cgroup detected)"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Container Security",
        status="Info",
        message=f"{get_core_id('ADVD', 1)}: Container environment detection",
        details=f"Running in: {container_type if in_container else 'bare metal / VM'}",
        remediation="If containerized, ensure host-level security is also audited"
    ))
    
    # ADVD-002: Docker daemon present and configuration
    if command_exists("docker"):
        docker_info = run_command("docker info --format '{{.SecurityOptions}}' 2>/dev/null")
        docker_running = docker_info.returncode == 0
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Container Security",
            status="Info" if docker_running else "Info",
            message=f"{get_core_id('ADVD', 2)}: Docker daemon status",
            details=f"Docker: {'running, security options: ' + docker_info.stdout.strip() if docker_running else 'installed but not accessible'}",
            remediation="Review Docker security: enable content trust, use rootless mode, "
                        "restrict container capabilities"
        ))
        
        # ADVD-003: Docker content trust
        docker_trust = os.environ.get("DOCKER_CONTENT_TRUST", "0")
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Container Security",
            status="Pass" if docker_trust == "1" else "Warning",
            message=f"{get_core_id('ADVD', 3)}: Docker Content Trust enabled",
            details=f"DOCKER_CONTENT_TRUST={docker_trust}",
            remediation="Enable: export DOCKER_CONTENT_TRUST=1"
        ))
        
        # ADVD-004: Docker daemon configuration
        docker_config = read_file_safe("/etc/docker/daemon.json", use_cache=True)
        has_config = bool(docker_config and docker_config.strip() != '{}')
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Container Security",
            status="Pass" if has_config else "Warning",
            message=f"{get_core_id('ADVD', 4)}: Docker daemon configuration file",
            details=f"/etc/docker/daemon.json: {'configured' if has_config else 'empty or missing'}",
            remediation="Configure /etc/docker/daemon.json with: userns-remap, no-new-privileges, "
                        "log-driver, storage-driver, icc=false"
        ))
    
    # ----------------------------------------------------------------
    # UEFI Secure Boot
    # ----------------------------------------------------------------
    
    # ADVB-001: UEFI Secure Boot status
    secureboot_enabled = False
    sb_details = "Unable to determine"
    
    if os.path.isdir("/sys/firmware/efi"):
        # System is UEFI
        sb_check = run_command("mokutil --sb-state 2>/dev/null")
        if sb_check.returncode == 0:
            sb_details = sb_check.stdout.strip()
            secureboot_enabled = "SecureBoot enabled" in sb_details
        else:
            # Try reading EFI variable directly
            sb_var = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
            if os.path.exists(sb_var):
                try:
                    with open(sb_var, 'rb') as f:
                        data = f.read()
                    secureboot_enabled = data[-1] == 1 if data else False
                    sb_details = f"SecureBoot {'enabled' if secureboot_enabled else 'disabled'} (EFI variable)"
                except (IOError, PermissionError):
                    sb_details = "EFI variable not readable"
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Boot Security",
            status="Pass" if secureboot_enabled else "Warning",
            message=f"{get_core_id('ADVB', 1)}: UEFI Secure Boot",
            details=f"{sb_details}",
            remediation="Enable Secure Boot in UEFI/BIOS firmware settings"
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Boot Security",
            status="Info",
            message=f"{get_core_id('ADVB', 1)}: UEFI Secure Boot",
            details="System uses legacy BIOS (not UEFI) - Secure Boot not applicable",
            remediation="Consider migrating to UEFI for Secure Boot support"
        ))
    
    # ADVB-002: Boot loader password protection
    grub_cfg_paths = ["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg", "/boot/efi/EFI/*/grub.cfg"]
    grub_password = False
    for grub_path in grub_cfg_paths:
        import glob as _glob
        for gpath in _glob.glob(grub_path):
            grub_content = read_file_safe(gpath, use_cache=True)
            if grub_content and ('password_pbkdf2' in grub_content or 'set superusers' in grub_content):
                grub_password = True
                break
    
    grub_user_cfg = read_file_safe("/etc/grub.d/40_custom", use_cache=True)
    if grub_user_cfg and 'password_pbkdf2' in grub_user_cfg:
        grub_password = True
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Boot Security",
        status="Pass" if grub_password else "Warning",
        message=f"{get_core_id('ADVB', 2)}: Boot loader password protection",
        details=f"GRUB password: {'configured' if grub_password else 'not configured'}",
        remediation="Set GRUB password: grub-mkpasswd-pbkdf2, then add to /etc/grub.d/40_custom"
    ))
    
    # ----------------------------------------------------------------
    # Supply Chain / Package Signing
    # ----------------------------------------------------------------
    
    # ADVP-001: Package repository GPG verification
    if os_info.package_manager == "apt":
        apt_config = run_command("apt-config dump 2>/dev/null | grep -i 'AllowUnauthenticated\\|AllowInsecure'")
        unauthenticated = "true" in apt_config.stdout.lower() if apt_config.returncode == 0 else False
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Supply Chain",
            status="Fail" if unauthenticated else "Pass",
            message=f"{get_core_id('ADVP', 1)}: APT package signature verification",
            details=f"{'AllowUnauthenticated/AllowInsecure is enabled - packages not verified!' if unauthenticated else 'Package signature verification enforced'}",
            remediation="Remove any AllowUnauthenticated or AllowInsecure settings from apt configuration"
        ))
    elif os_info.package_manager in ["yum", "dnf"]:
        yum_conf = read_file_safe("/etc/yum.conf", use_cache=True) or ""
        dnf_conf = read_file_safe("/etc/dnf/dnf.conf", use_cache=True) or ""
        conf = yum_conf + dnf_conf
        gpgcheck_disabled = "gpgcheck=0" in conf
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Supply Chain",
            status="Fail" if gpgcheck_disabled else "Pass",
            message=f"{get_core_id('ADVP', 1)}: RPM package GPG verification",
            details=f"{'gpgcheck=0 found - GPG verification disabled!' if gpgcheck_disabled else 'GPG verification enabled in package manager config'}",
            remediation="Set gpgcheck=1 in /etc/yum.conf or /etc/dnf/dnf.conf"
        ))
    
    # ADVP-002: Repository HTTPS usage
    repo_files = []
    if os_info.package_manager == "apt":
        sources_list = read_file_safe("/etc/apt/sources.list", use_cache=True) or ""
        http_repos = [l for l in sources_list.splitlines()
                      if l.strip() and not l.strip().startswith('#') and 'http://' in l]
        https_repos = [l for l in sources_list.splitlines()
                       if l.strip() and not l.strip().startswith('#') and 'https://' in l]
        total_repos = len(http_repos) + len(https_repos)
    elif os_info.package_manager in ["yum", "dnf"]:
        repo_dir = "/etc/yum.repos.d"
        http_repos = []
        https_repos = []
        if os.path.isdir(repo_dir):
            for rf in os.listdir(repo_dir):
                if rf.endswith('.repo'):
                    content = read_file_safe(os.path.join(repo_dir, rf), use_cache=True) or ""
                    for line in content.splitlines():
                        if line.strip().startswith('baseurl') or line.strip().startswith('metalink'):
                            if 'http://' in line:
                                http_repos.append(line.strip())
                            elif 'https://' in line:
                                https_repos.append(line.strip())
        total_repos = len(http_repos) + len(https_repos)
    else:
        http_repos = []
        https_repos = []
        total_repos = 0
    
    if total_repos > 0:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Supply Chain",
            status="Pass" if len(http_repos) == 0 else "Warning",
            message=f"{get_core_id('ADVP', 2)}: Package repository transport security",
            details=f"{len(https_repos)} HTTPS repos, {len(http_repos)} HTTP repos "
                    f"({len(http_repos)}/{total_repos} unencrypted)",
            remediation="Switch all repository URLs from http:// to https://"
        ))
    
    # ADVP-003: Automatic security updates configuration
    if os_info.package_manager == "apt":
        unattended = os.path.exists("/etc/apt/apt.conf.d/50unattended-upgrades")
        auto_update = os.path.exists("/etc/apt/apt.conf.d/20auto-upgrades")
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Supply Chain",
            status="Pass" if (unattended and auto_update) else "Warning",
            message=f"{get_core_id('ADVP', 3)}: Automatic security updates",
            details=f"unattended-upgrades: {'configured' if unattended else 'not configured'}, "
                    f"auto-upgrades: {'configured' if auto_update else 'not configured'}",
            remediation="Install and configure: apt install unattended-upgrades && "
                        "dpkg-reconfigure unattended-upgrades"
        ))
    elif os_info.package_manager in ["yum", "dnf"]:
        dnf_auto = command_exists("dnf-automatic") or os.path.exists("/etc/dnf/automatic.conf")
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Supply Chain",
            status="Pass" if dnf_auto else "Warning",
            message=f"{get_core_id('ADVP', 3)}: Automatic security updates",
            details=f"dnf-automatic: {'configured' if dnf_auto else 'not configured'}",
            remediation="Install and enable: dnf install dnf-automatic && "
                        "systemctl enable --now dnf-automatic-install.timer"
        ))


# ============================================================================
# Kernel Security Modules (YAMA, Lockdown, IMA/EVM)
# Phase 1 Gap: Core baseline, NSA, NIST cross-cutting
# ============================================================================

def check_kernel_security_modules(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Check kernel security module status including YAMA LSM, Kernel Lockdown,
    and IMA/EVM integrity measurement subsystems.

    These checks address gaps identified in CIS 1.5, NIST SI, NSA Kernel Security,
    and STIG System & Information Integrity categories.
    """
    cache = shared_data.get('cache')

    # --- YAMA ptrace scope ---
    # Controls process tracing; 1+ restricts ptrace to parent-child only
    yama_exists, yama_value = check_kernel_parameter("kernel.yama.ptrace_scope", cache=cache)
    if yama_exists:
        yama_int = safe_int_parse(yama_value, default=0)
        # 0 = classic (permissive), 1 = restricted, 2 = admin-only, 3 = no attach
        if yama_int >= 1:
            status = "Pass"
            detail = f"YAMA ptrace_scope = {yama_int} (restricted)"
        else:
            status = "Fail"
            detail = f"YAMA ptrace_scope = {yama_int} (permissive - any process can ptrace)"
    else:
        status = "Warning"
        detail = "YAMA LSM not available or not loaded"
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Kernel Security",
        status=status,
        message=f"{get_core_id('KSEC', 1)}: YAMA ptrace restriction",
        details=detail,
        remediation="echo 'kernel.yama.ptrace_scope = 1' >> /etc/sysctl.d/90-security.conf && sysctl -p",
        severity="Medium"
    ))

    # --- Kernel Lockdown mode ---
    # Prevents modification of running kernel; 'integrity' or 'confidentiality' modes
    lockdown_path = "/sys/kernel/security/lockdown"
    lockdown_status = "none"
    try:
        if os.path.exists(lockdown_path):
            with open(lockdown_path, 'r') as f:
                lockdown_content = f.read().strip()
            # Format: [none] integrity confidentiality  (brackets = active)
            if '[integrity]' in lockdown_content:
                lockdown_status = "integrity"
            elif '[confidentiality]' in lockdown_content:
                lockdown_status = "confidentiality"
            elif '[none]' in lockdown_content:
                lockdown_status = "none"
    except (PermissionError, IOError, OSError):
        lockdown_status = "unreadable"

    if lockdown_status in ("integrity", "confidentiality"):
        status = "Pass"
    elif lockdown_status == "none":
        status = "Warning"
    else:
        status = "Info"
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Kernel Security",
        status=status,
        message=f"{get_core_id('KSEC', 2)}: Kernel Lockdown mode",
        details=f"Lockdown mode: {lockdown_status}",
        remediation="Add 'lockdown=integrity' to GRUB_CMDLINE_LINUX in /etc/default/grub && update-grub",
        severity="Medium"
    ))

    # --- IMA (Integrity Measurement Architecture) ---
    # Measures file integrity at kernel level
    ima_active = os.path.exists("/sys/kernel/security/ima")
    ima_policy = os.path.exists("/sys/kernel/security/ima/policy")
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Kernel Security",
        status="Pass" if ima_active else "Info",
        message=f"{get_core_id('KSEC', 3)}: IMA (Integrity Measurement Architecture)",
        details=f"IMA subsystem: {'active' if ima_active else 'not active'}, "
                f"IMA policy: {'loaded' if ima_policy else 'not loaded'}",
        remediation="Enable IMA: add 'ima_policy=tcb ima_appraise=fix' to kernel command line",
        severity="Low"
    ))

    # --- EVM (Extended Verification Module) ---
    # Protects file extended attributes used by IMA
    evm_active = os.path.exists("/sys/kernel/security/evm")
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Kernel Security",
        status="Pass" if evm_active else "Info",
        message=f"{get_core_id('KSEC', 4)}: EVM (Extended Verification Module)",
        details=f"EVM subsystem: {'active' if evm_active else 'not active'}",
        remediation="Enable EVM alongside IMA for extended attribute protection",
        severity="Low"
    ))

    # --- Loaded LSMs ---
    lsm_path = "/sys/kernel/security/lsm"
    lsm_list = ""
    try:
        if os.path.exists(lsm_path):
            with open(lsm_path, 'r') as f:
                lsm_list = f.read().strip()
    except (PermissionError, IOError, OSError):
        pass
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Kernel Security",
        status="Pass" if lsm_list else "Warning",
        message=f"{get_core_id('KSEC', 5)}: Active Linux Security Modules",
        details=f"LSM stack: {lsm_list if lsm_list else 'unable to determine'}",
        remediation="Ensure at least one MAC LSM is active (AppArmor or SELinux)",
        severity="Medium"
    ))

    # --- Address Space Layout Randomization (ASLR) ---
    aslr_exists, aslr_value = check_kernel_parameter("kernel.randomize_va_space", cache=cache)
    if aslr_exists:
        aslr_int = safe_int_parse(aslr_value, default=0)
        # 0 = disabled, 1 = conservative, 2 = full
        if aslr_int >= 2:
            status, detail = "Pass", f"ASLR = {aslr_int} (full randomization)"
        elif aslr_int == 1:
            status, detail = "Warning", f"ASLR = {aslr_int} (partial - stack only)"
        else:
            status, detail = "Fail", f"ASLR = {aslr_int} (disabled)"
    else:
        status, detail = "Warning", "Unable to read ASLR setting"
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Kernel Security",
        status=status,
        message=f"{get_core_id('KSEC', 6)}: Address Space Layout Randomization (ASLR)",
        details=detail,
        remediation="sysctl -w kernel.randomize_va_space=2",
        severity="High"
    ))

    # --- Core dumps restriction ---
    core_exists, core_value = check_kernel_parameter("fs.suid_dumpable", cache=cache)
    if core_exists:
        core_int = safe_int_parse(core_value, default=2)
        if core_int == 0:
            status, detail = "Pass", "SUID core dumps disabled (fs.suid_dumpable = 0)"
        else:
            status, detail = "Fail", f"SUID core dumps enabled (fs.suid_dumpable = {core_int})"
    else:
        status, detail = "Warning", "Unable to read fs.suid_dumpable"
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Kernel Security",
        status=status,
        message=f"{get_core_id('KSEC', 7)}: SUID core dump restriction",
        details=detail,
        remediation="echo 'fs.suid_dumpable = 0' >> /etc/sysctl.d/90-security.conf && sysctl -p",
        severity="Medium"
    ))

    # --- Kernel pointer hiding ---
    kptr_exists, kptr_value = check_kernel_parameter("kernel.kptr_restrict", cache=cache)
    if kptr_exists:
        kptr_int = safe_int_parse(kptr_value, default=0)
        if kptr_int >= 1:
            status = "Pass"
            detail = f"Kernel pointer restriction = {kptr_int}"
        else:
            status = "Fail"
            detail = "Kernel pointers exposed to unprivileged users (kptr_restrict = 0)"
    else:
        status, detail = "Warning", "Unable to read kernel.kptr_restrict"
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Kernel Security",
        status=status,
        message=f"{get_core_id('KSEC', 8)}: Kernel pointer restriction",
        details=detail,
        remediation="echo 'kernel.kptr_restrict = 2' >> /etc/sysctl.d/90-security.conf && sysctl -p",
        severity="Medium"
    ))

    # --- dmesg restriction ---
    dmesg_exists, dmesg_value = check_kernel_parameter("kernel.dmesg_restrict", cache=cache)
    if dmesg_exists:
        dmesg_int = safe_int_parse(dmesg_value, default=0)
        status = "Pass" if dmesg_int >= 1 else "Fail"
        detail = f"dmesg_restrict = {dmesg_int}"
    else:
        status, detail = "Warning", "Unable to read kernel.dmesg_restrict"
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Kernel Security",
        status=status,
        message=f"{get_core_id('KSEC', 9)}: Restrict dmesg access",
        details=detail,
        remediation="echo 'kernel.dmesg_restrict = 1' >> /etc/sysctl.d/90-security.conf && sysctl -p",
        severity="Low"
    ))

    # --- Unprivileged BPF disabled ---
    bpf_exists, bpf_value = check_kernel_parameter("kernel.unprivileged_bpf_disabled", cache=cache)
    if bpf_exists:
        bpf_int = safe_int_parse(bpf_value, default=0)
        status = "Pass" if bpf_int >= 1 else "Warning"
        detail = f"unprivileged_bpf_disabled = {bpf_int}"
    else:
        status, detail = "Info", "kernel.unprivileged_bpf_disabled not available"
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Kernel Security",
        status=status,
        message=f"{get_core_id('KSEC', 10)}: Restrict unprivileged BPF",
        details=detail,
        remediation="echo 'kernel.unprivileged_bpf_disabled = 1' >> /etc/sysctl.d/90-security.conf && sysctl -p",
        severity="Medium"
    ))

    # --- Unprivileged user namespaces ---
    userns_exists, userns_value = check_kernel_parameter(
        "kernel.unprivileged_userns_clone", cache=cache)
    if userns_exists:
        userns_int = safe_int_parse(userns_value, default=1)
        status = "Pass" if userns_int == 0 else "Info"
        detail = f"unprivileged_userns_clone = {userns_int}"
    else:
        # Not all kernels expose this; check via /proc/sys alternate
        status, detail = "Info", "kernel.unprivileged_userns_clone not available (kernel may not support)"
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Kernel Security",
        status=status,
        message=f"{get_core_id('KSEC', 11)}: Unprivileged user namespaces",
        details=detail,
        remediation="echo 'kernel.unprivileged_userns_clone = 0' >> /etc/sysctl.d/90-security.conf && sysctl -p",
        severity="Low"
    ))


# ============================================================================
# systemd Unit Hardening Assessment
# Phase 1 Gap: Core, CIS, STIG cross-cutting
# ============================================================================

def check_systemd_hardening(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Assess systemd service hardening features including ProtectSystem,
    PrivateTmp, NoNewPrivileges, and other sandboxing directives.

    Evaluates critical system services for security sandboxing posture.
    """
    cache = shared_data.get('cache')

    # Critical services to assess for hardening properties
    critical_services = [
        "sshd", "ssh",
        "httpd", "apache2", "nginx",
        "mariadb", "mysql", "postgresql",
        "named", "bind9",
        "docker", "containerd",
        "systemd-resolved", "systemd-journald", "systemd-logind",
        "cron", "crond", "atd",
        "rsyslog", "syslog-ng",
        "NetworkManager", "systemd-networkd",
    ]

    # Security properties to check (directive: description)
    hardening_directives = {
        "ProtectSystem": "Restrict writes to /usr and /boot",
        "ProtectHome": "Restrict access to /home, /root, /run/user",
        "PrivateTmp": "Private /tmp and /var/tmp namespaces",
        "NoNewPrivileges": "Prevent privilege escalation via execve",
        "ProtectKernelTunables": "Read-only access to /proc and /sys",
        "ProtectKernelModules": "Deny loading kernel modules",
        "ProtectControlGroups": "Read-only access to cgroup filesystem",
        "RestrictSUIDSGID": "Restrict creation of SUID/SGID files",
    }

    # Determine which critical services are actually running
    running_services = set()
    for svc in critical_services:
        result = run_command(f"systemctl is-active {svc}.service 2>/dev/null", check=False)
        if result.returncode == 0 and result.stdout.strip() == "active":
            running_services.add(svc)

    if not running_services:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - systemd Hardening",
            status="Info",
            message=f"{get_core_id('SYSD', 1)}: systemd service hardening assessment",
            details="No critical services detected as running for hardening assessment",
            severity="Low"
        ))
        return

    # Assess each running service
    total_hardened = 0
    total_checked = 0
    weak_services = []

    for svc in sorted(running_services):
        # Use systemctl show to get security properties
        result = run_command(
            f"systemctl show {svc}.service "
            f"--property=ProtectSystem,ProtectHome,PrivateTmp,NoNewPrivileges,"
            f"ProtectKernelTunables,ProtectKernelModules,ProtectControlGroups,"
            f"RestrictSUIDSGID 2>/dev/null",
            check=False
        )
        if result.returncode != 0:
            continue

        total_checked += 1
        props = {}
        for line in result.stdout.strip().splitlines():
            if '=' in line:
                key, val = line.split('=', 1)
                props[key.strip()] = val.strip()

        # Count enabled hardening directives
        enabled_count = 0
        for directive in hardening_directives:
            val = props.get(directive, "no")
            # ProtectSystem can be "strict" or "full" or "true"
            if val.lower() in ("yes", "true", "strict", "full", "read-only"):
                enabled_count += 1

        svc_score = enabled_count / len(hardening_directives) * 100
        if svc_score >= 50:
            total_hardened += 1
        else:
            weak_services.append(f"{svc} ({enabled_count}/{len(hardening_directives)})")

    # Overall systemd hardening score
    if total_checked > 0:
        hardening_pct = total_hardened / total_checked * 100
        if hardening_pct >= 75:
            status = "Pass"
        elif hardening_pct >= 50:
            status = "Warning"
        else:
            status = "Fail"
    else:
        status = "Info"
        hardening_pct = 0

    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - systemd Hardening",
        status=status,
        message=f"{get_core_id('SYSD', 1)}: systemd service hardening posture",
        details=f"{total_hardened}/{total_checked} running services adequately hardened "
                f"({hardening_pct:.0f}%)"
                f"{'; Weak: ' + ', '.join(weak_services[:5]) if weak_services else ''}",
        remediation="Use 'systemd-analyze security <service>' to review and add hardening "
                    "directives to unit files in /etc/systemd/system/<service>.d/override.conf",
        severity="Medium"
    ))

    # Individual directive assessments across all services
    for directive, description in hardening_directives.items():
        enabled_svc_count = 0
        for svc in running_services:
            result = run_command(
                f"systemctl show {svc}.service --property={directive} 2>/dev/null",
                check=False
            )
            if result.returncode == 0:
                val = result.stdout.strip().split('=', 1)[-1] if '=' in result.stdout else ""
                if val.lower() in ("yes", "true", "strict", "full", "read-only"):
                    enabled_svc_count += 1

        if len(running_services) > 0:
            pct = enabled_svc_count / len(running_services) * 100
        else:
            pct = 0

        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - systemd Hardening",
            status="Pass" if pct >= 50 else ("Warning" if pct >= 25 else "Info"),
            message=f"{get_core_id('SYSD', 2)}: {directive} adoption",
            details=f"{description}: {enabled_svc_count}/{len(running_services)} "
                    f"services ({pct:.0f}%)",
            remediation=f"Add '{directive}=yes' to service unit override files",
            severity="Low"
        ))

    # --- systemd-analyze security score ---
    # Run on a representative service to demonstrate capability
    test_svc = next(iter(running_services), None)
    if test_svc:
        result = run_command(
            f"systemd-analyze security {test_svc}.service 2>/dev/null | tail -1",
            check=False
        )
        if result.returncode == 0 and result.stdout.strip():
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CORE - systemd Hardening",
                status="Info",
                message=f"{get_core_id('SYSD', 3)}: systemd-analyze security capability",
                details=f"Security analysis available. Sample ({test_svc}): "
                        f"{result.stdout.strip()[:100]}",
                remediation="Run 'systemd-analyze security' to review all service exposure scores",
                severity="Low"
            ))


# ============================================================================
# Cryptographic Policy Assessment
# Phase 1 Gap: NIST SC, NSA Crypto, STIG cross-cutting
# ============================================================================

def check_crypto_policy(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Check system-wide cryptographic policy settings including crypto-policies
    (RHEL/Fedora), OpenSSL configuration, and TLS version enforcement.
    """
    cache = shared_data.get('cache')

    # --- System-wide crypto-policies (RHEL/Fedora) ---
    crypto_policy_file = "/etc/crypto-policies/config"
    if os.path.exists(crypto_policy_file):
        try:
            with open(crypto_policy_file, 'r') as f:
                policy = f.read().strip()
            # Policies: LEGACY, DEFAULT, FUTURE, FIPS
            if policy in ("FUTURE", "FIPS"):
                status = "Pass"
            elif policy == "DEFAULT":
                status = "Warning"
            else:
                status = "Fail"
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CORE - Cryptographic Policy",
                status=status,
                message=f"{get_core_id('CRYPTO', 1)}: System-wide crypto-policy (RHEL/Fedora)",
                details=f"Active crypto-policy: {policy}",
                remediation="update-crypto-policies --set FUTURE  (or FIPS for FIPS compliance)",
                severity="High"
            ))
        except (PermissionError, IOError):
            pass
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Cryptographic Policy",
            status="Info",
            message=f"{get_core_id('CRYPTO', 1)}: System-wide crypto-policy",
            details="crypto-policies framework not available (non-RHEL/Fedora system)",
            remediation="On RHEL/Fedora: update-crypto-policies --set FUTURE",
            severity="Low"
        ))

    # --- OpenSSL version and FIPS status ---
    result = run_command("openssl version 2>/dev/null", check=False)
    if result.returncode == 0:
        openssl_ver = result.stdout.strip()
        # Check if version is reasonably current (3.x preferred)
        is_v3 = "OpenSSL 3." in openssl_ver or "OpenSSL 4." in openssl_ver
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Cryptographic Policy",
            status="Pass" if is_v3 else "Warning",
            message=f"{get_core_id('CRYPTO', 2)}: OpenSSL version",
            details=openssl_ver,
            remediation="Update to OpenSSL 3.x+ for current security features and algorithm support",
            severity="Medium"
        ))

    # --- TLS minimum version in OpenSSL config ---
    openssl_conf_paths = [
        "/etc/ssl/openssl.cnf",
        "/etc/pki/tls/openssl.cnf",
        "/etc/crypto-policies/back-ends/opensslcnf.config",
    ]
    min_tls_found = False
    for conf_path in openssl_conf_paths:
        content = read_file_safe(conf_path)
        if content:
            if "MinProtocol" in content:
                for line in content.splitlines():
                    if "MinProtocol" in line and not line.strip().startswith('#'):
                        min_proto = line.split('=')[-1].strip() if '=' in line else "unknown"
                        is_safe = min_proto in ("TLSv1.2", "TLSv1.3")
                        results.append(AuditResult(
                            module=MODULE_NAME,
                            category="CORE - Cryptographic Policy",
                            status="Pass" if is_safe else "Fail",
                            message=f"{get_core_id('CRYPTO', 3)}: Minimum TLS protocol version",
                            details=f"MinProtocol = {min_proto} (in {conf_path})",
                            remediation="Set MinProtocol = TLSv1.2 in OpenSSL configuration",
                            severity="High"
                        ))
                        min_tls_found = True
                        break
            if min_tls_found:
                break

    if not min_tls_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Cryptographic Policy",
            status="Warning",
            message=f"{get_core_id('CRYPTO', 3)}: Minimum TLS protocol version",
            details="No explicit MinProtocol found in OpenSSL configuration",
            remediation="Add 'MinProtocol = TLSv1.2' to [system_default_sect] in openssl.cnf",
            severity="High"
        ))

    # --- SSH cryptographic settings ---
    ssh_config = {}
    if cache:
        ssh_config = cache.get_parsed('ssh_config') or {}

    # Check SSH Ciphers
    ssh_ciphers = ssh_config.get('ciphers', '')
    weak_ciphers = ['3des-cbc', 'arcfour', 'blowfish-cbc', 'cast128-cbc']
    has_weak = any(wc in ssh_ciphers.lower() for wc in weak_ciphers) if ssh_ciphers else False
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Cryptographic Policy",
        status="Fail" if has_weak else ("Pass" if ssh_ciphers else "Warning"),
        message=f"{get_core_id('CRYPTO', 4)}: SSH cipher strength",
        details=f"Ciphers: {ssh_ciphers if ssh_ciphers else 'using system defaults (verify manually)'}",
        remediation="Set strong ciphers in /etc/ssh/sshd_config: "
                    "Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr",
        severity="High"
    ))

    # Check SSH MACs
    ssh_macs = ssh_config.get('macs', '')
    weak_macs = ['hmac-md5', 'hmac-sha1', 'hmac-ripemd160']
    has_weak_mac = any(wm in ssh_macs.lower() for wm in weak_macs) if ssh_macs else False
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Cryptographic Policy",
        status="Fail" if has_weak_mac else ("Pass" if ssh_macs else "Warning"),
        message=f"{get_core_id('CRYPTO', 5)}: SSH MAC algorithm strength",
        details=f"MACs: {ssh_macs if ssh_macs else 'using system defaults (verify manually)'}",
        remediation="Set strong MACs in /etc/ssh/sshd_config: "
                    "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com",
        severity="Medium"
    ))

    # Check SSH Key Exchange algorithms
    ssh_kex = ssh_config.get('kexalgorithms', '')
    weak_kex = ['diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1',
                'diffie-hellman-group-exchange-sha1']
    has_weak_kex = any(wk in ssh_kex.lower() for wk in weak_kex) if ssh_kex else False
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Cryptographic Policy",
        status="Fail" if has_weak_kex else ("Pass" if ssh_kex else "Warning"),
        message=f"{get_core_id('CRYPTO', 6)}: SSH key exchange algorithm strength",
        details=f"KexAlgorithms: {ssh_kex if ssh_kex else 'using system defaults (verify manually)'}",
        remediation="Set strong KexAlgorithms in /etc/ssh/sshd_config: "
                    "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,"
                    "diffie-hellman-group16-sha512",
        severity="Medium"
    ))


# ============================================================================
# Container / Docker Security
# Phase 1 Gap: Core, CIS, NIST, STIG cross-cutting
# ============================================================================

def check_container_security(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Detect container runtime presence (Docker, Podman, containerd) and assess
    basic security configuration including daemon settings, user namespaces,
    and rootless mode.
    """
    cache = shared_data.get('cache')

    # --- Detect container runtimes ---
    runtimes_detected = []
    for runtime in ["docker", "podman", "containerd", "crio"]:
        if command_exists(runtime):
            runtimes_detected.append(runtime)

    if not runtimes_detected:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Container Security",
            status="Info",
            message=f"{get_core_id('CONT', 1)}: Container runtime detection",
            details="No container runtimes detected (Docker, Podman, containerd, CRI-O)",
            severity="Low"
        ))
        return

    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Container Security",
        status="Info",
        message=f"{get_core_id('CONT', 1)}: Container runtime detection",
        details=f"Detected runtimes: {', '.join(runtimes_detected)}",
        severity="Low"
    ))

    # --- Docker-specific checks ---
    if "docker" in runtimes_detected:
        # Check Docker daemon configuration
        docker_config_paths = ["/etc/docker/daemon.json"]
        docker_config = ""
        for dpath in docker_config_paths:
            content = read_file_safe(dpath)
            if content:
                docker_config = content
                break

        # Docker daemon.json existence
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Container Security",
            status="Pass" if docker_config else "Warning",
            message=f"{get_core_id('CONT', 2)}: Docker daemon configuration",
            details=f"daemon.json: {'configured' if docker_config else 'not found (using defaults)'}",
            remediation="Create /etc/docker/daemon.json with security hardening options",
            severity="Medium"
        ))

        if docker_config:
            # Check for user namespace remapping
            userns_remap = '"userns-remap"' in docker_config
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CORE - Container Security",
                status="Pass" if userns_remap else "Warning",
                message=f"{get_core_id('CONT', 3)}: Docker user namespace remapping",
                details=f"userns-remap: {'enabled' if userns_remap else 'not configured'}",
                remediation='Add "userns-remap": "default" to /etc/docker/daemon.json',
                severity="Medium"
            ))

            # Check for live-restore
            live_restore = '"live-restore"' in docker_config and "true" in docker_config.lower()
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CORE - Container Security",
                status="Pass" if live_restore else "Info",
                message=f"{get_core_id('CONT', 4)}: Docker live restore",
                details=f"live-restore: {'enabled' if live_restore else 'not configured'}",
                remediation='Add "live-restore": true to /etc/docker/daemon.json',
                severity="Low"
            ))

            # Check for no-new-privileges default
            no_new_priv = '"no-new-privileges"' in docker_config
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CORE - Container Security",
                status="Pass" if no_new_priv else "Warning",
                message=f"{get_core_id('CONT', 5)}: Docker no-new-privileges default",
                details=f"no-new-privileges: {'enabled' if no_new_priv else 'not configured'}",
                remediation='Add "no-new-privileges": true to /etc/docker/daemon.json',
                severity="Medium"
            ))

        # Check Docker socket permissions
        docker_sock = "/var/run/docker.sock"
        if os.path.exists(docker_sock):
            sock_perms = get_file_permissions(docker_sock)
            sock_owner, sock_group = get_file_owner_group(docker_sock)
            is_safe = sock_perms and int(sock_perms, 8) <= 0o660
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CORE - Container Security",
                status="Pass" if is_safe else "Warning",
                message=f"{get_core_id('CONT', 6)}: Docker socket permissions",
                details=f"docker.sock: mode={sock_perms}, owner={sock_owner}:{sock_group}",
                remediation="chmod 660 /var/run/docker.sock && chown root:docker /var/run/docker.sock",
                severity="High"
            ))

    # --- Podman-specific: check for rootless configuration ---
    if "podman" in runtimes_detected:
        # Podman rootless check
        result = run_command("podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null",
                            check=False)
        is_rootless = result.returncode == 0 and "true" in result.stdout.strip().lower()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Container Security",
            status="Pass" if is_rootless else "Info",
            message=f"{get_core_id('CONT', 7)}: Podman rootless mode",
            details=f"Rootless mode: {'active' if is_rootless else 'not active or not determinable'}",
            remediation="Run Podman as non-root user for rootless container execution",
            severity="Medium"
        ))


# ============================================================================
# UEFI Secure Boot Validation
# Phase 1 Gap: Core, STIG cross-cutting
# ============================================================================

def check_uefi_secureboot(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Validate UEFI Secure Boot status and related boot integrity settings
    including GRUB password protection and kernel module signing.
    """
    cache = shared_data.get('cache')

    # --- UEFI vs Legacy BIOS detection ---
    is_uefi = os.path.isdir("/sys/firmware/efi")
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Boot Security",
        status="Info",
        message=f"{get_core_id('BOOT', 1)}: Boot firmware type",
        details=f"Firmware: {'UEFI' if is_uefi else 'Legacy BIOS'}",
        severity="Low"
    ))

    # --- Secure Boot status ---
    if is_uefi:
        # Check via mokutil (most reliable)
        result = run_command("mokutil --sb-state 2>/dev/null", check=False)
        if result.returncode == 0:
            sb_output = result.stdout.strip()
            sb_enabled = "enabled" in sb_output.lower() and "not" not in sb_output.lower()
        else:
            # Fallback: check EFI variable directly
            sb_var = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
            sb_enabled = False
            if os.path.exists(sb_var):
                try:
                    with open(sb_var, 'rb') as f:
                        data = f.read()
                    # Last byte indicates state: 1 = enabled
                    if len(data) >= 5 and data[-1] == 1:
                        sb_enabled = True
                except (PermissionError, IOError, OSError):
                    pass
            sb_output = f"SecureBoot: {'enabled' if sb_enabled else 'disabled/unknown'}"

        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Boot Security",
            status="Pass" if sb_enabled else "Warning",
            message=f"{get_core_id('BOOT', 2)}: UEFI Secure Boot status",
            details=sb_output,
            remediation="Enable Secure Boot in UEFI firmware settings. "
                        "Ensure all bootloaders and kernel modules are signed.",
            severity="High"
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Boot Security",
            status="Info",
            message=f"{get_core_id('BOOT', 2)}: UEFI Secure Boot status",
            details="Not applicable (Legacy BIOS system)",
            severity="Low"
        ))

    # --- GRUB password protection ---
    grub_configs = [
        "/boot/grub2/user.cfg",
        "/boot/grub/grub.cfg",
        "/boot/grub2/grub.cfg",
        "/etc/grub.d/40_custom",
        "/etc/grub.d/01_users",
    ]
    grub_password_set = False
    for gpath in grub_configs:
        content = read_file_safe(gpath)
        if content and ("password_pbkdf2" in content or "set superusers" in content):
            grub_password_set = True
            break

    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Boot Security",
        status="Pass" if grub_password_set else "Warning",
        message=f"{get_core_id('BOOT', 3)}: GRUB bootloader password protection",
        details=f"GRUB password: {'configured' if grub_password_set else 'not configured'}",
        remediation="grub2-setpassword  (or grub-mkpasswd-pbkdf2 and add to /etc/grub.d/40_custom)",
        severity="High"
    ))

    # --- Kernel module signature enforcement ---
    sig_enforce_path = "/proc/sys/kernel/modules_disabled"
    mod_sig_exists, mod_sig_value = check_kernel_parameter("kernel.modules_disabled", cache=cache)
    # Also check kernel config for CONFIG_MODULE_SIG_FORCE
    result = run_command("cat /boot/config-$(uname -r) 2>/dev/null | grep CONFIG_MODULE_SIG_FORCE",
                        check=False)
    sig_force = "CONFIG_MODULE_SIG_FORCE=y" in result.stdout if result.returncode == 0 else False

    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Boot Security",
        status="Pass" if sig_force else ("Info" if mod_sig_exists else "Info"),
        message=f"{get_core_id('BOOT', 4)}: Kernel module signature enforcement",
        details=f"CONFIG_MODULE_SIG_FORCE: {'enabled' if sig_force else 'not enforced'}, "
                f"modules_disabled: {mod_sig_value if mod_sig_exists else 'not set'}",
        remediation="Rebuild kernel with CONFIG_MODULE_SIG_FORCE=y for mandatory module signing",
        severity="Medium"
    ))

    # --- Kernel command line security parameters ---
    cmdline = read_file_safe("/proc/cmdline") or ""
    security_params = {
        "quiet": "Suppress verbose boot messages",
        "init_on_alloc=1": "Zero-fill memory on allocation",
        "init_on_free=1": "Zero-fill memory on deallocation",
        "slab_nomerge": "Prevent slab cache merging (hardening)",
        "page_alloc.shuffle=1": "Randomize page allocator freelists",
        "randomize_kstack_offset=on": "Randomize kernel stack offset",
        "vsyscall=none": "Disable vsyscall (legacy interface)",
    }
    found_params = []
    missing_params = []
    for param, desc in security_params.items():
        if param in cmdline:
            found_params.append(param)
        else:
            missing_params.append(param)

    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Boot Security",
        status="Pass" if len(found_params) >= 3 else (
            "Warning" if len(found_params) >= 1 else "Info"),
        message=f"{get_core_id('BOOT', 5)}: Kernel command line hardening parameters",
        details=f"Present: {', '.join(found_params) if found_params else 'none'}; "
                f"Missing: {', '.join(missing_params[:4]) if missing_params else 'none'}",
        remediation="Add hardening parameters to GRUB_CMDLINE_LINUX in /etc/default/grub "
                    "and run update-grub",
        severity="Medium"
    ))


def check_cloud_security(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Cloud instance security checks.

    Detects whether the system is running in a cloud environment (AWS, Azure, GCP)
    and validates metadata endpoint protection, instance identity, and cloud-specific
    hardening. These checks are skipped gracefully on non-cloud systems.

    Relevant frameworks: NIST AC-4, CISA Zero Trust, CIS cloud benchmarks
    """
    cache = shared_data.get('cache')
    is_root = shared_data.get("is_root", os.geteuid() == 0)

    # ---- Detect cloud environment ----
    cloud_provider = "none"
    cloud_indicators = []

    # Check DMI/BIOS for cloud signatures
    dmi_paths = [
        "/sys/class/dmi/id/board_vendor",
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/bios_vendor",
        "/sys/class/dmi/id/chassis_asset_tag",
        "/sys/class/dmi/id/product_name",
    ]
    for dmi_path in dmi_paths:
        try:
            if os.path.exists(dmi_path):
                with open(dmi_path, 'r') as f:
                    value = f.read().strip().lower()
                if 'amazon' in value or 'ec2' in value:
                    cloud_provider = "AWS"
                    cloud_indicators.append(f"{dmi_path}: {value}")
                elif 'microsoft' in value or 'azure' in value:
                    cloud_provider = "Azure"
                    cloud_indicators.append(f"{dmi_path}: {value}")
                elif 'google' in value or 'gce' in value:
                    cloud_provider = "GCP"
                    cloud_indicators.append(f"{dmi_path}: {value}")
        except (PermissionError, IOError):
            pass

    # CLOUD-001: Cloud environment detection
    if cloud_provider != "none":
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Cloud Security",
            status="Info",
            message=f"{get_core_id('CLOUD', 1)}: Cloud environment detected: {cloud_provider}",
            details=f"Indicators: {'; '.join(cloud_indicators[:3])}",
            severity="Informational",
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Cloud Security",
            status="Info",
            message=f"{get_core_id('CLOUD', 1)}: No cloud environment detected (bare metal or VM)",
            details="No AWS/Azure/GCP DMI signatures found",
            severity="Informational",
        ))
        # Skip remaining cloud checks if not in cloud
        return

    # CLOUD-002: IMDS (Instance Metadata Service) protection
    # AWS IMDSv2, Azure IMDS, GCP metadata - check if iptables blocks 169.254.169.254
    imds_blocked = False
    iptables_result = run_command("iptables -L OUTPUT -n 2>/dev/null")
    if iptables_result.returncode == 0:
        if '169.254.169.254' in iptables_result.stdout:
            imds_blocked = True

    # Also check if IMDSv2 is enforced (AWS-specific: check for hop limit)
    imds_details = "Metadata endpoint 169.254.169.254 "
    if cloud_provider == "AWS":
        # Token-based IMDSv2 detection: check if curl to metadata works without token
        token_check = run_command(
            "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 2 "
            "http://169.254.169.254/latest/meta-data/ 2>/dev/null", cache=cache
        )
        if token_check.returncode == 0 and token_check.stdout.strip() == '401':
            imds_details += "IMDSv2 enforced (token required)"
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CORE - Cloud Security",
                status="Pass",
                message=f"{get_core_id('CLOUD', 2)}: AWS IMDSv2 enforced (High)",
                details=imds_details,
                severity="High",
            ))
        elif imds_blocked:
            imds_details += "blocked via iptables"
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CORE - Cloud Security",
                status="Pass",
                message=f"{get_core_id('CLOUD', 2)}: Metadata endpoint blocked by firewall (High)",
                details=imds_details,
                severity="High",
            ))
        else:
            imds_details += "may be accessible without IMDSv2 token"
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CORE - Cloud Security",
                status="Fail",
                message=f"{get_core_id('CLOUD', 2)}: AWS IMDSv1 may be enabled - enforce IMDSv2 (High)",
                details=imds_details,
                remediation="aws ec2 modify-instance-metadata-options --instance-id <ID> "
                            "--http-tokens required --http-endpoint enabled",
                severity="High",
            ))
    else:
        # Generic IMDS firewall check for Azure/GCP
        if imds_blocked:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CORE - Cloud Security",
                status="Pass",
                message=f"{get_core_id('CLOUD', 2)}: Metadata endpoint restricted by firewall (High)",
                details="iptables rule blocks 169.254.169.254",
                severity="High",
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CORE - Cloud Security",
                status="Warning",
                message=f"{get_core_id('CLOUD', 2)}: No firewall rule restricting metadata endpoint (High)",
                details="Consider restricting 169.254.169.254 to authorized processes only",
                remediation="iptables -A OUTPUT -d 169.254.169.254 -j REJECT "
                            "(or use cloud-native IMDS restrictions)",
                severity="High",
            ))

    # CLOUD-003: Cloud-init configuration security
    cloud_init_paths = ["/etc/cloud/cloud.cfg", "/etc/cloud/cloud.cfg.d/"]
    cloud_init_found = False
    for ci_path in cloud_init_paths:
        if os.path.exists(ci_path):
            cloud_init_found = True
            break

    if cloud_init_found:
        # Check if user-data scripts are restricted
        ci_content = read_file_safe("/etc/cloud/cloud.cfg")
        if ci_content:
            user_data_disabled = 'allow_userdata: false' in ci_content.lower()
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CORE - Cloud Security",
                status="Pass" if user_data_disabled else "Warning",
                message=f"{get_core_id('CLOUD', 3)}: Cloud-init user-data script execution (Medium)",
                details="User-data disabled" if user_data_disabled else
                        "User-data scripts are enabled (potential code execution vector)",
                severity="Medium",
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CORE - Cloud Security",
                status="Info",
                message=f"{get_core_id('CLOUD', 3)}: Cloud-init present but config unreadable (Medium)",
                details="Unable to read /etc/cloud/cloud.cfg",
                severity="Medium",
            ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Cloud Security",
            status="Info",
            message=f"{get_core_id('CLOUD', 3)}: Cloud-init not installed",
            details="Not applicable for this instance configuration",
            severity="Informational",
        ))

    # CLOUD-004: Instance identity document / credentials on disk
    credential_paths = [
        "/root/.aws/credentials",
        "/home/*/.aws/credentials",
        "/root/.azure/accessTokens.json",
        "/root/.config/gcloud/credentials.db",
        "/root/.config/gcloud/application_default_credentials.json",
    ]
    creds_found = []
    for cred_pattern in credential_paths:
        import glob as _glob
        matches = _glob.glob(cred_pattern)
        creds_found.extend(matches)

    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Cloud Security",
        status="Fail" if creds_found else "Pass",
        message=f"{get_core_id('CLOUD', 4)}: Cloud credentials stored on disk (Critical)" if creds_found else
                f"{get_core_id('CLOUD', 4)}: No cloud credentials on disk (Critical)",
        details=f"Found: {', '.join(creds_found[:5])}" if creds_found else
                "No AWS/Azure/GCP credential files found in common locations",
        remediation="Use IAM instance roles/managed identities instead of stored credentials. "
                    "Remove credential files and rotate exposed keys." if creds_found else "",
        severity="Critical" if creds_found else "Critical",
    ))

    # CLOUD-005: Instance tags / role assignment check
    # Check if instance has an IAM role (AWS), managed identity (Azure), or service account (GCP)
    if cloud_provider == "AWS":
        role_check = run_command(
            "curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/iam/info 2>/dev/null"
        )
        has_role = role_check.returncode == 0 and 'InstanceProfileArn' in role_check.stdout
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Cloud Security",
            status="Pass" if has_role else "Warning",
            message=f"{get_core_id('CLOUD', 5)}: IAM instance role assignment (High)",
            details="Instance has IAM role attached" if has_role else
                    "No IAM instance role detected - use roles for API access instead of keys",
            severity="High",
        ))
    elif cloud_provider == "Azure":
        identity_check = run_command(
            "curl -s --connect-timeout 2 -H 'Metadata:true' "
            "'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01"
            "&resource=https://management.azure.com/' 2>/dev/null"
        )
        has_identity = identity_check.returncode == 0 and 'access_token' in identity_check.stdout
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Cloud Security",
            status="Info",
            message=f"{get_core_id('CLOUD', 5)}: Azure managed identity {'enabled' if has_identity else 'not detected'}",
            details="Managed identity available" if has_identity else
                    "No managed identity - consider enabling for Azure resource access",
            severity="High",
        ))
    elif cloud_provider == "GCP":
        sa_check = run_command(
            "curl -s --connect-timeout 2 -H 'Metadata-Flavor: Google' "
            "'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email' 2>/dev/null"
        )
        has_sa = sa_check.returncode == 0 and '@' in sa_check.stdout
        sa_email = sa_check.stdout.strip() if has_sa else "none"
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Cloud Security",
            status="Pass" if has_sa else "Warning",
            message=f"{get_core_id('CLOUD', 5)}: GCP service account {'attached' if has_sa else 'not detected'} (High)",
            details=f"Service account: {sa_email}" if has_sa else
                    "No service account attached - consider assigning one with least-privilege scope",
            severity="High",
        ))


# ============================================================================
# Main Orchestration Function
# ============================================================================

def run_checks(shared_data: Dict[str, Any]) -> List[AuditResult]:
    """
    Main entry point for CORE module
    Executes all security baseline checks and returns results
    """
    results = []
    
    # Extract SharedDataCache from shared_data (populated by main script)
    cache = shared_data.get('cache')
    
    print(f"\n[{MODULE_NAME}] " + "="*70)
    print(f"[{MODULE_NAME}] CORE SECURITY BASELINE AUDIT")
    print(f"[{MODULE_NAME}] " + "="*70)
    print(f"[{MODULE_NAME}] Version: {MODULE_VERSION}")
    print(f"[{MODULE_NAME}] Focus: Industry Best Practices with OS-Specific Guidance")
    print(f"[{MODULE_NAME}] Areas: OS, Packages, Services, Users, Filesystem, Network, Hardening, Advanced,")
    print(f"[{MODULE_NAME}]        Kernel Security, systemd, Cryptography, Containers, Boot, Cloud Security")
    print(f"[{MODULE_NAME}] Target: 200+ comprehensive OS-aware checks")
    if cache:
        print(f"[{MODULE_NAME}] Cache: Enabled ({cache.get_summary()['files_cached']} files, "
              f"{cache.get_summary()['commands_cached']} commands cached)")
    print(f"[{MODULE_NAME}] " + "="*70 + "\n")
    
    # Get OS info from cache if available (avoids redundant detection)
    if cache and cache.os_info:
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
    
    try:
        # Execute all check categories
        check_os_package_management(results, shared_data, os_info)
        check_service_user_management(results, shared_data, os_info)
        check_filesystem_network(results, shared_data, os_info)
        check_system_hardening_tools(results, shared_data, os_info)
        check_advanced_security(results, shared_data, os_info)
        # Phase 1 cross-cutting checks
        check_kernel_security_modules(results, shared_data, os_info)
        check_systemd_hardening(results, shared_data, os_info)
        check_crypto_policy(results, shared_data, os_info)
        check_container_security(results, shared_data, os_info)
        check_uefi_secureboot(results, shared_data, os_info)
        check_cloud_security(results, shared_data, os_info)
        
    except Exception as e:
        print(f"[{MODULE_NAME}]  Error during audit execution: {str(e)}")
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Error",
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
    os_checks = sum(1 for r in results if "OS Detection" in r.category or "Package Management" in r.category)
    service_checks = sum(1 for r in results if "Service" in r.category or "User" in r.category)
    fs_net_checks = sum(1 for r in results if "Filesystem" in r.category or "Network" in r.category)
    hard_tool_checks = sum(1 for r in results if "Hardening" in r.category or "Tools" in r.category)
    
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
    print(f"[{MODULE_NAME}] ")
    print(f"[{MODULE_NAME}] Check Categories:")
    print(f"[{MODULE_NAME}]   OS & Packages:         {os_checks:3d} checks")
    print(f"[{MODULE_NAME}]   Services & Users:      {service_checks:3d} checks")
    print(f"[{MODULE_NAME}]   Filesystem & Network:  {fs_net_checks:3d} checks")
    print(f"[{MODULE_NAME}]   Hardening & Tools:     {hard_tool_checks:3d} checks")
    print(f"[{MODULE_NAME}] " + "="*70 + "\n")
    
    return results

# ============================================================================
# Module Testing
# ============================================================================



# ============================================================================
# v3.3 EXPANSION - Core Linux Security Baseline Deep Coverage
# ----------------------------------------------------------------------------
# Synopsis:
#   Adds depth across:
#   - Per-service systemd hardening directives (sshd, journald, etc.)
#   - SUSE family-specific hardening
#   - Arch family-specific hardening
#   - Advanced kernel security features
#   - Container/namespace hardening at host level
#   - Time synchronization NTS
#   - Secure boot chain indicators
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


def _v33_core_result(category, status, message, severity="Medium",
                     details="", remediation="", cross_references=None):
    """Build AuditResult for Core v3.3 expansion."""
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


def _check_core_v33_systemd_hardening(results, shared_data, os_info):
    """Per-service systemd hardening directive coverage."""

    if not _v33_command_available("systemctl"):
        return

    # Critical services with hardening expectation
    critical_services = [
        "sshd.service", "ssh.service",
        "systemd-journald.service",
        "auditd.service",
        "rsyslog.service",
        "chronyd.service", "chrony.service",
        "cron.service", "crond.service",
    ]

    hardening_directives = {
        "ProtectSystem": ["full", "strict"],
        "ProtectHome": ["yes", "read-only", "tmpfs"],
        "PrivateTmp": ["yes"],
        "NoNewPrivileges": ["yes"],
        "RestrictRealtime": ["yes"],
        "MemoryDenyWriteExecute": ["yes"],
        "RestrictSUIDSGID": ["yes"],
        "LockPersonality": ["yes"],
    }

    inspected = 0
    avg_score = 0
    services_with_data = []

    for svc in critical_services:
        rc, out, _ = _v33_run_command(
            ["systemctl", "show", svc, "--no-page"], timeout=3.0
        )
        if rc != 0 or not out:
            continue
        if "LoadState=not-found" in out or "LoadState=masked" in out:
            continue
        inspected += 1

        score = 0
        for directive, good_values in hardening_directives.items():
            for line in out.splitlines():
                if line.startswith(directive + "="):
                    val = line.split("=", 1)[1].strip().lower()
                    if val in good_values:
                        score += 1
                    break

        if score >= 1:
            avg_score += score
            services_with_data.append(f"{svc}={score}")

    if inspected > 0:
        # Most services should have at least 2 hardening directives
        ratio = avg_score / max(1, inspected)
        results.append(_v33_core_result(
            "Core systemd v3.3 - Hardening",
            "Pass" if ratio >= 2.0 else "Warning",
            f"Critical services systemd hardening "
            f"(avg {ratio:.1f}/{len(hardening_directives)} directives)",
            severity="Medium",
            details=(
                f"Inspected: {inspected}, services with hardening: "
                f"{services_with_data[:5]}"
            ),
            remediation=(
                "Use systemd-analyze security <unit> to score each service. "
                "Add directives via systemctl edit <unit>: "
                "ProtectSystem=full, ProtectHome=yes, PrivateTmp=yes, "
                "NoNewPrivileges=yes"
            ),
            cross_references={
                "NIST": "SI-7", "CIS": "5.1",
            },
        ))


def _check_core_v33_advanced_kernel(results, shared_data, os_info):
    """Advanced kernel security features."""

    # Kernel lockdown
    lockdown = _v33_read_file_safe("/sys/kernel/security/lockdown")
    has_lockdown = lockdown and "[none]" not in lockdown
    results.append(_v33_core_result(
        "Core Kernel v3.3 - Lockdown",
        "Pass" if has_lockdown else "Info",
        f"Kernel lockdown active: {has_lockdown}",
        severity="High",
        details=f"lockdown: {lockdown.strip() if lockdown else 'unset'}",
        remediation="Boot with lockdown=integrity on kernel cmdline",
        cross_references={
            "NIST": "CM-7",
        },
    ))

    # IMA Integrity Measurement Architecture
    ima_present = _v33_directory_exists("/sys/kernel/security/ima")
    results.append(_v33_core_result(
        "Core Kernel v3.3 - IMA",
        "Pass" if ima_present else "Info",
        f"Integrity Measurement Architecture: {ima_present}",
        severity="Medium",
        details=f"/sys/kernel/security/ima: {ima_present}",
        remediation="Boot with ima_policy=tcb on kernel cmdline",
        cross_references={
            "NIST": "SI-7",
        },
    ))

    # Module signing enforcement
    sig_enforce = _v33_read_file_safe(
        "/sys/module/module/parameters/sig_enforce"
    ).strip()
    results.append(_v33_core_result(
        "Core Kernel v3.3 - Module Signing",
        "Pass" if sig_enforce == "Y" else "Info",
        f"Module sig_enforce: {sig_enforce or 'unset'}",
        severity="High",
        details=f"sig_enforce = {sig_enforce}",
        remediation="Boot with module.sig_enforce=1 on kernel cmdline",
        cross_references={
            "NIST": "SI-7",
        },
    ))

    # CPU Vulnerability Mitigations
    vuln_dir = "/sys/devices/system/cpu/vulnerabilities"
    if _v33_directory_exists(vuln_dir):
        vulns = ["meltdown", "spectre_v1", "spectre_v2", "mds",
                  "spec_store_bypass", "l1tf", "srbds", "tsx_async_abort"]
        unmitigated = []
        for v in vulns:
            content = _v33_read_file_safe(os.path.join(vuln_dir, v)).strip()
            if content and "Vulnerable" in content and "Mitigation" not in content:
                unmitigated.append(v)
        results.append(_v33_core_result(
            "Core Kernel v3.3 - CPU Vulnerabilities",
            "Pass" if not unmitigated else "Warning",
            f"CPU vulnerabilities mitigated ({len(unmitigated)} unmitigated)",
            severity="High",
            details=f"Unmitigated: {unmitigated}",
            remediation=(
                "Update kernel and microcode: apt-get install -y "
                "intel-microcode amd64-microcode; reboot"
            ),
            cross_references={
                "NIST": "SI-2",
            },
        ))

    # User namespaces (kernel.unprivileged_userns_clone)
    userns = _v33_read_sysctl("kernel.unprivileged_userns_clone")
    results.append(_v33_core_result(
        "Core Kernel v3.3 - User Namespaces",
        "Info",
        f"Unprivileged user namespaces: "
        f"{'disabled' if userns == '0' else 'enabled or unset'}",
        severity="Informational",
        details=f"kernel.unprivileged_userns_clone = {userns}",
        remediation=(
            "If not used by containers: echo 'kernel.unprivileged_userns_clone = 0' "
            ">> /etc/sysctl.d/99-userns.conf"
        ),
        cross_references={
            "NIST": "CM-7",
        },
    ))


def _check_core_v33_secure_boot(results, shared_data, os_info):
    """Secure boot chain indicators."""

    # UEFI / EFI variables
    efi_present = _v33_directory_exists("/sys/firmware/efi")
    efi_vars_present = _v33_directory_exists("/sys/firmware/efi/efivars")
    results.append(_v33_core_result(
        "Core Boot v3.3 - UEFI/EFI",
        "Pass" if efi_present else "Info",
        f"UEFI firmware: {efi_present} (efivars: {efi_vars_present})",
        severity="Medium",
        details=f"/sys/firmware/efi: {efi_present}",
        remediation=(
            "If on UEFI: ensure Secure Boot enabled in firmware. "
            "Run mokutil --sb-state to verify."
        ),
        cross_references={
            "NIST": "SI-7", "CIS": "1.5.4",
        },
    ))

    # mokutil for Secure Boot state
    if _v33_command_available("mokutil"):
        rc, out, _ = _v33_run_command(["mokutil", "--sb-state"], timeout=3.0)
        sb_enabled = rc == 0 and "SecureBoot enabled" in out
        results.append(_v33_core_result(
            "Core Boot v3.3 - Secure Boot",
            "Pass" if sb_enabled else "Info",
            f"Secure Boot enabled: {sb_enabled}",
            severity="High",
            details=f"mokutil --sb-state output: {out.strip()[:80]}",
            remediation="Enable Secure Boot in firmware/BIOS settings",
            cross_references={
                "NIST": "SI-7",
            },
        ))

    # GRUB password protection (cross-ref via DistBaseline pattern)
    grub_password = False
    for f in ["/etc/grub.d/01_users", "/etc/grub.d/40_custom",
               "/boot/grub2/user.cfg", "/boot/grub/grub.cfg"]:
        c = _v33_read_file_safe(f)
        if "password_pbkdf2" in c or "GRUB2_PASSWORD" in c:
            grub_password = True
            break
    results.append(_v33_core_result(
        "Core Boot v3.3 - GRUB Password",
        "Pass" if grub_password else "Warning",
        f"GRUB password protection: {grub_password}",
        severity="High",
        details=f"password_pbkdf2 in GRUB config: {grub_password}",
        remediation=(
            "RHEL: grub2-setpassword. "
            "Debian: grub-mkpasswd-pbkdf2 then add to /etc/grub.d/40_custom"
        ),
        cross_references={
            "NIST": "AC-3", "CIS": "1.5.2", "STIG": "V-230234",
        },
    ))


def _check_core_v33_suse_specific(results, shared_data, os_info):
    """SUSE family specific hardening."""
    if not getattr(os_info, "is_suse_family", lambda: False)():
        return

    # Snapper for btrfs snapshots
    snapper = _v33_command_available("snapper")
    results.append(_v33_core_result(
        "Core SUSE v3.3 - Snapper",
        "Pass" if snapper else "Info",
        f"snapper btrfs snapshots: {snapper}",
        severity="Low",
        details=f"snapper binary: {snapper}",
        remediation="zypper install -y snapper",
        cross_references={
            "NIST": "CP-9",
        },
    ))

    # AppArmor (SUSE default MAC)
    aa_active = _v33_systemd_active("apparmor.service") == "active"
    results.append(_v33_core_result(
        "Core SUSE v3.3 - AppArmor",
        "Pass" if aa_active else "Warning",
        f"AppArmor active: {aa_active}",
        severity="High",
        details=f"apparmor.service: {aa_active}",
        remediation=remediation_for("apparmor"),
        cross_references={
            "NIST": "AC-3",
        },
    ))

    # zypper repository signing (SUSE)
    zypper_repos = _v33_directory_exists("/etc/zypp/repos.d")
    results.append(_v33_core_result(
        "Core SUSE v3.3 - Zypper Repos",
        "Pass" if zypper_repos else "Info",
        f"zypper repos directory: {zypper_repos}",
        severity="Medium",
        details=f"/etc/zypp/repos.d: {zypper_repos}",
        cross_references={
            "NIST": "CM-5(3)",
        },
    ))


def _check_core_v33_arch_specific(results, shared_data, os_info):
    """Arch family specific hardening."""
    if not getattr(os_info, "is_arch_family", lambda: False)():
        return

    # pacman keyring
    pacman_keyring = _v33_directory_exists("/etc/pacman.d/gnupg")
    results.append(_v33_core_result(
        "Core Arch v3.3 - pacman keyring",
        "Pass" if pacman_keyring else "Warning",
        f"pacman keyring: {pacman_keyring}",
        severity="High",
        details=f"/etc/pacman.d/gnupg: {pacman_keyring}",
        remediation="pacman-key --init && pacman-key --populate archlinux",
        cross_references={
            "NIST": "CM-5(3)",
        },
    ))

    # pacman SigLevel strict
    pacman_conf = _v33_read_file_safe("/etc/pacman.conf")
    siglevel_match = re.search(
        r"^\s*SigLevel\s*=\s*(\S.*)", pacman_conf, re.MULTILINE
    )
    siglevel = siglevel_match.group(1).strip() if siglevel_match else ""
    siglevel_strict = "Required" in siglevel and "DatabaseRequired" in siglevel
    results.append(_v33_core_result(
        "Core Arch v3.3 - SigLevel",
        "Pass" if siglevel_strict else "Warning",
        f"pacman SigLevel strict: {siglevel_strict}",
        severity="High",
        details=f"SigLevel = {siglevel}",
        remediation=(
            "In /etc/pacman.conf: SigLevel = Required DatabaseRequired"
        ),
        cross_references={
            "NIST": "CM-5(3)",
        },
    ))

    # Reflector / mirrorlist freshness indicator
    reflector_present = _v33_command_available("reflector")
    results.append(_v33_core_result(
        "Core Arch v3.3 - Reflector",
        "Info",
        f"reflector mirrorlist tool: {reflector_present}",
        severity="Informational",
        details=f"reflector: {reflector_present}",
        cross_references={
            "NIST": "CM-7",
        },
    ))


def _check_core_v33_container_host(results, shared_data, os_info):
    """Container hardening at host level."""

    # Container runtimes detected
    runtimes = {
        "docker": (
            _v33_command_available("docker") or
            _v33_systemd_active("docker.service") == "active"
        ),
        "podman": _v33_command_available("podman"),
        "containerd": (
            _v33_command_available("containerd") or
            _v33_systemd_active("containerd.service") == "active"
        ),
    }
    detected_rt = [k for k, v in runtimes.items() if v]
    if not detected_rt:
        return

    results.append(_v33_core_result(
        "Core Container v3.3 - Runtimes",
        "Info",
        f"Container runtimes detected: {detected_rt}",
        severity="Informational",
        details=f"Runtimes: {detected_rt}",
        cross_references={
            "NIST": "SI-4",
        },
    ))

    # cgroup v2 for better isolation
    cgroup_v2 = _v33_file_exists("/sys/fs/cgroup/cgroup.controllers")
    results.append(_v33_core_result(
        "Core Container v3.3 - cgroup v2",
        "Pass" if cgroup_v2 else "Info",
        f"cgroup v2 unified hierarchy: {cgroup_v2}",
        severity="Low",
        details=f"/sys/fs/cgroup/cgroup.controllers: {cgroup_v2}",
        remediation=(
            "Boot with systemd.unified_cgroup_hierarchy=1 on kernel cmdline"
        ),
        cross_references={
            "NIST": "SC-7(13)",
        },
    ))

    # Docker daemon hardening
    if runtimes["docker"]:
        daemon_json = _v33_read_file_safe("/etc/docker/daemon.json")
        hardening = sum([
            "userns-remap" in daemon_json,
            "no-new-privileges" in daemon_json,
            '"icc": false' in daemon_json,
            "live-restore" in daemon_json,
        ])
        results.append(_v33_core_result(
            "Core Container v3.3 - Docker Hardening",
            "Pass" if hardening >= 2 else "Warning",
            f"Docker daemon hardening directives ({hardening}/4)",
            severity="High",
            details=f"Hardening directives present: {hardening}",
            remediation=(
                'In /etc/docker/daemon.json: '
                '{"userns-remap":"default","no-new-privileges":true,'
                '"icc":false,"live-restore":true}'
            ),
            cross_references={
                "NIST": "CM-7", "CIS-Docker": "2.x",
            },
        ))


def _check_core_v33_time_security(results, shared_data, os_info):
    """Time synchronization with authentication (NTS)."""

    chrony_active = (
        _v33_systemd_active("chronyd.service") == "active" or
        _v33_systemd_active("chrony.service") == "active"
    )

    if chrony_active:
        chrony_conf = (
            _v33_read_file_safe("/etc/chrony.conf") or
            _v33_read_file_safe("/etc/chrony/chrony.conf")
        )
        nts_present = bool(re.search(
            r"^\s*server\s+\S+.*nts", chrony_conf, re.MULTILINE
        ))
        results.append(_v33_core_result(
            "Core Time v3.3 - NTS",
            "Pass" if nts_present else "Info",
            f"chrony NTS-authenticated time: {nts_present}",
            severity="Medium",
            details=f"NTS server directive: {nts_present}",
            remediation=(
                "Add to /etc/chrony.conf: server time.cloudflare.com nts iburst"
            ),
            cross_references={
                "NIST": "AU-8(2)",
            },
        ))


def _check_core_v33_filesystem_advanced(results, shared_data, os_info):
    """Advanced filesystem security features."""

    # Filesystem read-only / immutable indicators
    rc, out, _ = _v33_run_command(["lsblk", "-f", "-J"], timeout=3.0)
    has_btrfs_or_zfs = False
    if rc == 0 and out:
        if "btrfs" in out.lower() or "zfs" in out.lower():
            has_btrfs_or_zfs = True
    results.append(_v33_core_result(
        "Core Filesystem v3.3 - Modern FS",
        "Info",
        f"Modern filesystem (btrfs/zfs) detected: {has_btrfs_or_zfs}",
        severity="Informational",
        details=f"btrfs/zfs in lsblk: {has_btrfs_or_zfs}",
        cross_references={
            "NIST": "SI-7",
        },
    ))

    # /tmp on tmpfs (RAM-backed)
    proc_mounts = _v33_read_file_safe("/proc/mounts")
    tmp_on_tmpfs = bool(re.search(
        r"^tmpfs\s+/tmp\s+tmpfs", proc_mounts, re.MULTILINE
    ))
    results.append(_v33_core_result(
        "Core Filesystem v3.3 - /tmp tmpfs",
        "Pass" if tmp_on_tmpfs else "Info",
        f"/tmp on tmpfs (RAM-backed): {tmp_on_tmpfs}",
        severity="Low",
        details=f"/tmp tmpfs mount: {tmp_on_tmpfs}",
        remediation=(
            "systemctl enable tmp.mount  (uses tmpfs by default)"
        ),
        cross_references={
            "NIST": "SI-12",
        },
    ))


# Save reference to existing run_checks
_original_run_checks_core_v33 = run_checks


def run_checks(shared_data):
    """Execute the v3.3 expanded Core module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_core_v33(shared_data)

    os_info = shared_data.get("os_info") or shared_data.get("v3_os_info")
    if os_info is None:
        from shared_components import os_detection as _os_det
        os_info = _os_det.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        _check_core_v33_systemd_hardening(results, shared_data, os_info)
        _check_core_v33_advanced_kernel(results, shared_data, os_info)
        _check_core_v33_secure_boot(results, shared_data, os_info)
        _check_core_v33_suse_specific(results, shared_data, os_info)
        _check_core_v33_arch_specific(results, shared_data, os_info)
        _check_core_v33_container_host(results, shared_data, os_info)
        _check_core_v33_time_security(results, shared_data, os_info)
        _check_core_v33_filesystem_advanced(results, shared_data, os_info)
    except Exception as exc:  # noqa: BLE001
        results.append(AuditResult(
            module=MODULE_NAME, category="Core - Error",
            status="Error",
            message=f"Core v3.3 expansion exception: {exc!r}",
            details=str(exc), severity="Medium",
        ))

    return results


# ============================================================================
# v3.5 EXPANSION - Core Linux Baseline Additional Depth
# ----------------------------------------------------------------------------
# Synopsis:
#   Adds depth across Core baseline areas not yet covered:
#     - Sudo hygiene depth (additional defaults, secure logging)
#     - User/group hygiene (locked accounts, expired passwords)
#     - Service inventory hygiene (no-shell system accounts)
#     - Mount hygiene (additional restrictive options)
#     - Cron file permissions
#     - Boot loader hygiene depth (grub.cfg permissions, password)
#     - Service banner hygiene
#     - PAM faillock hygiene depth
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


def _v35_core_result(category, status, message, severity="Medium",
                    details="", remediation="", cross_references=None):
    """Build AuditResult for Core v3.5 expansion."""
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


def _check_core_v35_sudo_hygiene(results, shared_data, os_info):
    """Sudo hygiene depth - defaults and secure logging."""
    cat = "Core v3.5 - Sudo"

    sudoers_main = _v35_read_file_safe("/etc/sudoers")
    sudoers_d = ""
    if _v35_directory_exists("/etc/sudoers.d"):
        for f in _v35_list_directory("/etc/sudoers.d"):
            if f != "README":
                sudoers_d += "\n" + _v35_read_file_safe(
                    os.path.join("/etc/sudoers.d", f)
                )
    full_sudoers = sudoers_main + "\n" + sudoers_d

    # Defaults use_pty (prevents privilege escalation via pty hijacking)
    use_pty = bool(re.search(
        r"^\s*Defaults\s+use_pty",
        full_sudoers, re.MULTILINE,
    ))
    results.append(_v35_core_result(
        f"{cat} - use_pty",
        "Pass" if use_pty else "Warning",
        f"Sudo Defaults use_pty: {use_pty}",
        severity="Medium",
        details=f"use_pty in sudoers: {use_pty}",
        remediation=(
            "In /etc/sudoers.d/00-defaults:\n"
            "  Defaults use_pty\n"
            "Mitigates io_uring-based PTY hijacking attacks against sudo."
        ),
        cross_references={
            "NIST": "AC-6", "CIS": "5.2.5",
        },
    ))

    # Defaults logfile (separate sudo log)
    logfile_set = bool(re.search(
        r"^\s*Defaults\s+logfile=",
        full_sudoers, re.MULTILINE,
    ))
    results.append(_v35_core_result(
        f"{cat} - Sudo Logfile",
        "Pass" if logfile_set else "Info",
        f"Sudo Defaults logfile set: {logfile_set}",
        severity="Low",
        details=f"logfile defined: {logfile_set}",
        remediation=(
            "In /etc/sudoers.d/00-defaults:\n"
            "  Defaults logfile=\"/var/log/sudo.log\"\n"
            "Aids incident response by aggregating sudo events."
        ),
        cross_references={
            "NIST": "AU-2", "CIS": "5.2.3",
        },
    ))

    # Wheel/sudo group has no NOPASSWD (review NOPASSWD count)
    nopasswd_count = len([
        line for line in full_sudoers.splitlines()
        if "NOPASSWD" in line and not line.strip().startswith("#")
    ])
    nopasswd_minimal = nopasswd_count <= 2
    results.append(_v35_core_result(
        f"{cat} - NOPASSWD Minimal",
        "Pass" if nopasswd_minimal else "Warning",
        f"Sudo NOPASSWD entries: {nopasswd_count} (minimal threshold: 2)",
        severity="High",
        details=f"NOPASSWD count: {nopasswd_count}",
        remediation=(
            "Audit NOPASSWD entries:\n"
            "  grep NOPASSWD /etc/sudoers /etc/sudoers.d/*\n"
            "Each represents a privilege grant without re-authentication."
        ),
        cross_references={
            "NIST": "AC-6(5)",
            "PCI-DSS": "8.2.7",
        },
    ))


def _check_core_v35_user_hygiene(results, shared_data, os_info):
    """User/group hygiene - locked accounts, expired passwords."""
    cat = "Core v3.5 - User Hygiene"

    # System accounts (UID < 1000) should not have login shells
    passwd = _v35_read_file_safe("/etc/passwd")
    system_login_accounts = []
    if passwd:
        for line in passwd.splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            try:
                uid = int(parts[2])
            except ValueError:
                continue
            shell = parts[6]
            interactive = shell not in (
                "/sbin/nologin", "/usr/sbin/nologin", "/bin/false",
                "/usr/bin/false",
            )
            if 0 < uid < 1000 and interactive:
                system_login_accounts.append(parts[0])
    results.append(_v35_core_result(
        f"{cat} - System Account Shells",
        "Pass" if not system_login_accounts else "Warning",
        f"System accounts (UID 1-999) with login shells: "
        f"{len(system_login_accounts)}",
        severity="High",
        details=f"Accounts: {system_login_accounts[:5]}",
        remediation=(
            "For each system account:\n"
            "  usermod -s /usr/sbin/nologin <user>\n"
            "System accounts should not have interactive shells."
        ),
        cross_references={
            "NIST": "AC-2", "STIG": "V-230373",
            "CIS": "5.4.2.1",
        },
    ))

    # Empty passwords in /etc/shadow
    shadow = _v35_read_file_safe("/etc/shadow")
    empty_pw_accounts = []
    if shadow:
        for line in shadow.splitlines():
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] == "":
                empty_pw_accounts.append(parts[0])
    results.append(_v35_core_result(
        f"{cat} - Empty Password Hashes",
        "Pass" if not empty_pw_accounts else "Fail",
        f"Accounts with empty password hash: {len(empty_pw_accounts)}",
        severity="Critical",
        details=f"Accounts: {empty_pw_accounts}",
        remediation=(
            "For each: passwd -l <user>  (lock the account)\n"
            "Or set a strong password / SSH-key only login."
        ),
        cross_references={
            "NIST": "IA-5",
            "PCI-DSS": "8.3.1",
        },
    ))

    # Default UMASK in /etc/login.defs
    umask_match = re.search(
        r"^\s*UMASK\s+(\d+)",
        _v35_read_file_safe("/etc/login.defs"),
        re.MULTILINE,
    )
    umask_value = umask_match.group(1) if umask_match else "022"
    umask_secure = umask_value in ("027", "077")
    results.append(_v35_core_result(
        f"{cat} - UMASK Default",
        "Pass" if umask_secure else "Info",
        f"Default UMASK: {umask_value}",
        severity="Low",
        details=f"UMASK = {umask_value}",
        remediation=(
            "In /etc/login.defs:\n"
            "  UMASK 027  (or 077 for stricter)"
        ),
        cross_references={
            "CIS": "5.5.5", "NIST": "AC-3",
        },
    ))


def _check_core_v35_mount_hygiene(results, shared_data, os_info):
    """Mount hygiene - additional restrictive mount options."""
    cat = "Core v3.5 - Mount Hygiene"

    fstab = _v35_read_file_safe("/etc/fstab")

    # /tmp with nodev/nosuid/noexec
    tmp_secure = False
    for line in fstab.splitlines():
        if line.strip().startswith("#") or not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 4 and parts[1] == "/tmp":
            opts = parts[3]
            tmp_secure = (
                "nodev" in opts and "nosuid" in opts and "noexec" in opts
            )
            break
    # Or systemd tmp.mount
    if not tmp_secure:
        tmp_mount_unit = _v35_read_file_safe(
            "/usr/lib/systemd/system/tmp.mount"
        )
        if tmp_mount_unit and "nodev" in tmp_mount_unit and "nosuid" in tmp_mount_unit:
            tmp_secure = True
    results.append(_v35_core_result(
        f"{cat} - /tmp Restrictive Mount",
        "Pass" if tmp_secure else "Warning",
        f"/tmp mounted with nodev/nosuid/noexec: {tmp_secure}",
        severity="Medium",
        details=f"/tmp restrictive: {tmp_secure}",
        remediation=(
            "In /etc/fstab:\n"
            "  tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec 0 0\n"
            "Then: systemctl daemon-reload && mount -o remount /tmp"
        ),
        cross_references={
            "CIS": "1.1.2", "NIST": "AC-3",
        },
    ))

    # /dev/shm with nodev/nosuid/noexec
    shm_secure = False
    for line in fstab.splitlines():
        if line.strip().startswith("#") or not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 4 and parts[1] == "/dev/shm":
            opts = parts[3]
            shm_secure = (
                "nodev" in opts and "nosuid" in opts and "noexec" in opts
            )
            break
    results.append(_v35_core_result(
        f"{cat} - /dev/shm Restrictive Mount",
        "Pass" if shm_secure else "Info",
        f"/dev/shm restrictive mount: {shm_secure}",
        severity="Medium",
        details=f"/dev/shm restrictive: {shm_secure}",
        remediation=(
            "In /etc/fstab:\n"
            "  tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0"
        ),
        cross_references={
            "CIS": "1.1.7", "NIST": "AC-3",
        },
    ))


def _check_core_v35_cron_hygiene(results, shared_data, os_info):
    """Cron file permissions - root-owned and not world-readable."""
    cat = "Core v3.5 - Cron"

    cron_paths = [
        "/etc/crontab",
        "/etc/cron.hourly", "/etc/cron.daily",
        "/etc/cron.weekly", "/etc/cron.monthly", "/etc/cron.d",
    ]
    issues = []
    for path in cron_paths:
        if not (_v35_file_exists(path) or _v35_directory_exists(path)):
            continue
        try:
            st = os.stat(path)
            mode = st.st_mode & 0o7777
            # World-writable is the cardinal sin
            if mode & 0o0002:
                issues.append(f"{path}({oct(mode)})")
        except OSError:
            pass
    results.append(_v35_core_result(
        f"{cat} - Cron File Permissions",
        "Pass" if not issues else "Fail",
        f"Cron files not world-writable: {'OK' if not issues else 'issues'}",
        severity="High",
        details=f"Issues: {issues}",
        remediation=(
            "chmod o-w /etc/crontab /etc/cron.* (for any flagged paths)\n"
            "chown root:root /etc/crontab /etc/cron.*"
        ),
        cross_references={
            "CIS": "5.1.2", "NIST": "AC-3",
            "STIG": "V-230380",
        },
    ))

    # /etc/cron.allow exists (allowlist preferred over denylist)
    cron_allow = _v35_file_exists("/etc/cron.allow")
    cron_deny = _v35_file_exists("/etc/cron.deny")
    cron_allowlist_active = cron_allow and not cron_deny
    results.append(_v35_core_result(
        f"{cat} - Allowlist Policy",
        "Pass" if cron_allowlist_active else "Info",
        f"cron.allow allowlist (no cron.deny): {cron_allowlist_active}",
        severity="Medium",
        details=(
            f"/etc/cron.allow: {cron_allow}, /etc/cron.deny: {cron_deny}"
        ),
        remediation=(
            "echo 'root' > /etc/cron.allow; chmod 0640 /etc/cron.allow\n"
            "rm -f /etc/cron.deny"
        ),
        cross_references={
            "CIS": "5.1.8", "NIST": "AC-3",
        },
    ))


def _check_core_v35_grub_hygiene(results, shared_data, os_info):
    """Boot loader hygiene depth - grub.cfg permissions."""
    cat = "Core v3.5 - GRUB"

    grub_paths = [
        "/boot/grub/grub.cfg",
        "/boot/grub2/grub.cfg",
        "/boot/efi/EFI/redhat/grub.cfg",
        "/boot/efi/EFI/ubuntu/grub.cfg",
        "/boot/efi/EFI/debian/grub.cfg",
    ]
    grub_path_found = None
    grub_mode = -1
    for p in grub_paths:
        if _v35_file_exists(p):
            grub_path_found = p
            try:
                grub_mode = os.stat(p).st_mode & 0o7777
            except OSError:
                pass
            break
    grub_secure = grub_path_found and 0 <= grub_mode <= 0o0600
    results.append(_v35_core_result(
        f"{cat} - grub.cfg Mode <= 0600",
        "Pass" if grub_secure else "Warning",
        f"GRUB config mode <= 0600: {grub_secure}",
        severity="High",
        details=(
            f"path: {grub_path_found}, mode: "
            f"{oct(grub_mode) if grub_mode >= 0 else 'unknown'}"
        ),
        remediation=(
            f"chmod 0600 {grub_path_found or '/boot/grub/grub.cfg'}\n"
            "Prevents disclosure of boot parameters to non-root users."
        ),
        cross_references={
            "CIS": "1.4.1", "NIST": "AC-3",
            "STIG": "V-230275",
        },
    ))

    # GRUB superuser/password (interactive boot menu protection)
    grub_password = False
    for grub_d in ["/etc/grub.d", "/etc/default/grub.d"]:
        if not _v35_directory_exists(grub_d):
            continue
        for f in _v35_list_directory(grub_d):
            content = _v35_read_file_safe(os.path.join(grub_d, f))
            if "password_pbkdf2" in content or "set superusers" in content:
                grub_password = True
                break
        if grub_password:
            break
    results.append(_v35_core_result(
        f"{cat} - GRUB Password",
        "Pass" if grub_password else "Info",
        f"GRUB superuser password set: {grub_password}",
        severity="Medium",
        details=f"password_pbkdf2 in grub config: {grub_password}",
        remediation=(
            "Generate hash: grub-mkpasswd-pbkdf2\n"
            "In /etc/grub.d/40_custom:\n"
            "  set superusers=\"root\"\n"
            "  password_pbkdf2 root grub.pbkdf2.sha512.10000.<HASH>\n"
            "Then: update-grub  (Debian) or grub2-mkconfig  (RHEL)"
        ),
        cross_references={
            "CIS": "1.4.2", "STIG": "V-230275",
        },
    ))


def _check_core_v35_service_inventory(results, shared_data, os_info):
    """Service inventory hygiene - no-shell system accounts, listening services."""
    cat = "Core v3.5 - Service Inventory"

    # Listening service inventory
    rc, out, _ = _v35_run_command(["ss", "-tlnp"], timeout=5.0)
    tcp_count = 0
    if rc == 0 and out:
        tcp_count = max(0, len(out.splitlines()) - 1)
    rc, out, _ = _v35_run_command(["ss", "-ulnp"], timeout=5.0)
    udp_count = 0
    if rc == 0 and out:
        udp_count = max(0, len(out.splitlines()) - 1)

    results.append(_v35_core_result(
        f"{cat} - Listening Sockets Count",
        "Pass" if tcp_count + udp_count <= 20 else "Info",
        f"TCP listeners: {tcp_count}, UDP listeners: {udp_count}",
        severity="Informational",
        details=f"Total listening sockets: {tcp_count + udp_count}",
        remediation=(
            "Audit with: ss -tlnp; ss -ulnp\n"
            "For each non-essential listener, disable: "
            "systemctl disable --now <unit>"
        ),
        cross_references={
            "NIST": "CM-7", "CIS": "Multi",
        },
    ))

    # Network services that should typically not be on a hardened host
    legacy_services = []
    for unit, label in [
        ("rpcbind.service", "rpcbind"),
        ("nfs-server.service", "nfs-server"),
        ("avahi-daemon.service", "avahi-daemon"),
        ("cups.service", "cups"),
        ("isc-dhcp-server.service", "dhcp-server"),
        ("dhcpd.service", "dhcpd"),
        ("vsftpd.service", "vsftpd"),
        ("xinetd.service", "xinetd"),
        ("inetd.service", "inetd"),
        ("ypserv.service", "ypserv"),
        ("rsh.service", "rsh"),
        ("telnet.service", "telnet"),
    ]:
        if _v35_systemd_active(unit) == "active":
            legacy_services.append(label)
    results.append(_v35_core_result(
        f"{cat} - Legacy Services",
        "Pass" if not legacy_services else "Warning",
        f"Legacy/risky services active: {len(legacy_services)}",
        severity="High",
        details=f"Active: {legacy_services}",
        remediation=(
            "Disable each: systemctl disable --now <service>\n"
            "Common targets: rpcbind, nfs-server (if not used), avahi-daemon, "
            "cups (if not a print server), telnet, rsh, xinetd"
        ),
        cross_references={
            "NIST": "CM-7", "CIS": "Multi",
        },
    ))


def _check_core_v35_pam_hygiene(results, shared_data, os_info):
    """PAM faillock hygiene depth."""
    cat = "Core v3.5 - PAM"

    # Look for pam_faillock or pam_tally2 configuration
    pam_files = [
        "/etc/pam.d/sshd",
        "/etc/pam.d/system-auth",
        "/etc/pam.d/password-auth",
        "/etc/pam.d/common-auth",
    ]
    pam_content = ""
    for pf in pam_files:
        pam_content += "\n" + _v35_read_file_safe(pf)

    # Check for deny<= 5
    deny_match = re.search(
        r"pam_faillock\.so.+?deny\s*=\s*(\d+)",
        pam_content,
    )
    deny_strict = deny_match and int(deny_match.group(1)) <= 5
    pam_lockout_present = (
        "pam_faillock" in pam_content or "pam_tally2" in pam_content
    )
    results.append(_v35_core_result(
        f"{cat} - faillock Configuration",
        "Pass" if pam_lockout_present and deny_strict else "Warning",
        f"PAM faillock active with deny<=5: {deny_strict}, "
        f"present: {pam_lockout_present}",
        severity="High",
        details=(
            f"deny = {deny_match.group(1) if deny_match else 'unset'}, "
            f"module present: {pam_lockout_present}"
        ),
        remediation=(
            "On RHEL: authselect select sssd with-faillock\n"
            "On Debian: edit /etc/pam.d/common-auth - add:\n"
            "  auth required pam_faillock.so preauth deny=5 unlock_time=900\n"
            "  auth [default=die] pam_faillock.so authfail deny=5 unlock_time=900"
        ),
        cross_references={
            "NIST": "AC-7", "CIS": "5.3.2",
            "PCI-DSS": "8.3.4",
        },
    ))

    # pwquality minlen >= 14 (modern alignment with NIST 800-63B)
    pwquality = _v35_read_file_safe("/etc/security/pwquality.conf")
    if _v35_directory_exists("/etc/security/pwquality.conf.d"):
        for f in _v35_list_directory("/etc/security/pwquality.conf.d"):
            if f.endswith(".conf"):
                pwquality += "\n" + _v35_read_file_safe(
                    os.path.join("/etc/security/pwquality.conf.d", f)
                )
    minlen_match = re.search(
        r"^\s*minlen\s*=\s*(\d+)", pwquality, re.MULTILINE,
    )
    minlen = int(minlen_match.group(1)) if minlen_match else 0
    minlen_strong = minlen >= 14
    results.append(_v35_core_result(
        f"{cat} - pwquality minlen",
        "Pass" if minlen_strong else "Warning",
        f"pwquality minlen >= 14: {minlen_strong} (current: {minlen})",
        severity="High",
        details=f"minlen = {minlen}",
        remediation=(
            "In /etc/security/pwquality.conf:\n"
            "  minlen = 14"
        ),
        cross_references={
            "NIST": "IA-5(1)", "CIS": "5.3.1",
        },
    ))


# Save reference to existing run_checks
_original_run_checks_core_v35 = run_checks


def _check_core_v38_attack_surface(results, shared_data, os_info):
    """v3.8: Attack-surface enumeration checks (CORE - Attack Surface).

    These checks explicitly enumerate exposure-relevant facts that feed the
    attack-surface assessment report. They are tagged with the dedicated
    'CORE - Attack Surface' category so the synthesis engine can pick them
    up reliably. CORE is the only non-framework-tied module, so it is the
    correct home for cross-cutting exposure enumeration.
    """
    import subprocess as _sp

    def _run(cmd, timeout=6):
        try:
            p = _sp.run(cmd, shell=True, capture_output=True, text=True,
                        timeout=timeout)
            return p.returncode, p.stdout, p.stderr
        except Exception:
            return 1, "", ""

    CAT = "CORE - Attack Surface"

    # AS-001: External-facing listening TCP sockets
    rc, out, _ = _run("ss -tlnH 2>/dev/null || ss -tln 2>/dev/null")
    external = []
    loopback = 0
    if rc == 0 and out:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            # ss columns: State Recv-Q Send-Q Local:Port Peer:Port
            local = parts[3] if parts[0] in ("LISTEN", "UNCONN") else (
                parts[3] if len(parts) >= 5 else "")
            if not local:
                # Some ss outputs omit State in -H; find host:port token
                local = next((p for p in parts if ':' in p), "")
            if local.startswith("127.") or local.startswith("[::1]") or \
               local.startswith("[::ffff:127"):
                loopback += 1
            elif local:
                external.append(local)
    ext_count = len(external)
    results.append(AuditResult(
        module=MODULE_NAME, category=CAT,
        status="Pass" if ext_count == 0 else ("Warning" if ext_count <= 3 else "Fail"),
        message=f"{get_core_id('AS', 1)}: External-facing TCP listeners",
        details=(f"{ext_count} external-facing listener(s): "
                 f"{', '.join(sorted(set(external))[:12])}"
                 if ext_count else "No external-facing TCP listeners detected")
                + f" ({loopback} loopback-only)",
        remediation=("Bind services to loopback where possible, or restrict "
                     "with firewall rules. Review each external listener for "
                     "necessity."),
        severity="High" if ext_count > 3 else "Medium",
    ))

    # AS-002: External-facing UDP sockets
    rc, out, _ = _run("ss -ulnH 2>/dev/null || ss -uln 2>/dev/null")
    udp_external = 0
    if rc == 0 and out:
        for line in out.splitlines():
            parts = line.split()
            local = next((p for p in parts if ':' in p), "")
            if local and not (local.startswith("127.") or
                              local.startswith("[::1]")):
                udp_external += 1
    results.append(AuditResult(
        module=MODULE_NAME, category=CAT,
        status="Pass" if udp_external == 0 else "Warning",
        message=f"{get_core_id('AS', 2)}: External-facing UDP listeners",
        details=f"{udp_external} external-facing UDP socket(s)",
        remediation=("Review UDP services (often amplification vectors). "
                     "Disable or firewall unneeded UDP listeners."),
        severity="Medium",
    ))

    # AS-003: Legacy / cleartext network services present
    legacy_services = {
        "telnet": "telnetd", "rsh": "rsh-server", "rlogin": "rlogin",
        "ftp": "vsftpd", "tftp": "tftpd", "finger": "fingerd",
        "talk": "talkd", "xinetd": "xinetd",
    }
    present_legacy = []
    for svc, _pkg in legacy_services.items():
        rc, out, _ = _run(f"command -v {svc} 2>/dev/null")
        if rc == 0 and out.strip():
            present_legacy.append(svc)
    results.append(AuditResult(
        module=MODULE_NAME, category=CAT,
        status="Pass" if not present_legacy else "Fail",
        message=f"{get_core_id('AS', 3)}: Legacy/cleartext service binaries",
        details=(f"Legacy service binaries present: {', '.join(present_legacy)}"
                 if present_legacy else "No legacy cleartext service binaries found"),
        remediation=removal_for("telnet") if present_legacy else "",
        severity="High" if present_legacy else "Low",
    ))

    # AS-004: SUID/SGID binary exposure summary (canonical assessment)
    from shared_components.shared_assessments import get_suid_sgid_assessment as _suid_assess
    _suid = _suid_assess()
    results.append(AuditResult(
        module=MODULE_NAME, category=CAT,
        status=_suid.status,
        message=f"{get_core_id('AS', 4)}: SUID/SGID binary exposure",
        details=_suid.details,
        remediation=_suid.remediation,
        severity="Medium",
    ))

    # AS-005: World-writable file exposure summary (canonical assessment)
    from shared_components.shared_assessments import get_world_writable_assessment as _ww_assess5
    _ww5 = _ww_assess5("fail")
    results.append(AuditResult(
        module=MODULE_NAME, category=CAT,
        status=_ww5.status,
        message=f"{get_core_id('AS', 5)}: World-writable file exposure",
        details=_ww5.details,
        remediation=_ww5.remediation,
        severity="High" if _ww5.count and _ww5.count > 0 else "Low",
    ))

    # AS-006: Container runtime socket exposure
    docker_sock = os.path.exists("/var/run/docker.sock")
    sock_mode = ""
    if docker_sock:
        try:
            st = os.stat("/var/run/docker.sock")
            sock_mode = oct(st.st_mode & 0o777)
        except OSError:
            pass
    results.append(AuditResult(
        module=MODULE_NAME, category=CAT,
        status="Warning" if docker_sock else "Pass",
        message=f"{get_core_id('AS', 6)}: Container runtime socket exposure",
        details=(f"Docker socket present (/var/run/docker.sock, mode {sock_mode}) "
                 " -  equivalent to root access if exposed"
                 if docker_sock else "No Docker socket exposure detected"),
        remediation=("Restrict access to the Docker socket; never mount it "
                     "into untrusted containers. Consider rootless Docker or "
                     "Podman."),
        severity="High" if docker_sock else "Low",
    ))

    # AS-007: Kernel module loading exposure
    rc, out, _ = _run("sysctl -n kernel.modules_disabled 2>/dev/null")
    modules_locked = out.strip() == "1"
    results.append(AuditResult(
        module=MODULE_NAME, category=CAT,
        status="Pass" if modules_locked else "Info",
        message=f"{get_core_id('AS', 7)}: Kernel module loading lockdown",
        details=("Kernel module loading is disabled (kernel.modules_disabled=1)"
                 if modules_locked else
                 "Kernel module loading is enabled (expands kernel attack "
                 "surface; lock down on appliance/static systems)"),
        remediation=("On systems with a fixed module set, set "
                     "kernel.modules_disabled=1 after boot via sysctl."),
        severity="Low",
    ))

    # AS-008: Firewall posture (installed vs active vs configured) across
    # all variants (ufw / firewalld / nftables / iptables / ipset).
    from shared_components.shared_assessments import get_firewall_posture
    _fw = get_firewall_posture()
    results.append(AuditResult(
        module=MODULE_NAME, category=CAT,
        status=_fw.status,
        message=f"{get_core_id('AS', 8)}: Firewall posture",
        details=_fw.details,
        remediation=_fw.remediation,
        severity="High" if _fw.status == "Fail" else (
            "Medium" if _fw.status == "Warning" else "Low"),
    ))

    # AS-009: Writable directories on the executable PATH (a writable PATH
    # entry lets an attacker plant a binary that runs with the caller's
    # privileges - a classic privilege-escalation / persistence pathway).
    path_env = os.environ.get("PATH", "/usr/local/sbin:/usr/local/bin:"
                              "/usr/sbin:/usr/bin:/sbin:/bin")
    writable_path_dirs = []
    world_writable_path_dirs = []
    for d in path_env.split(":"):
        if not d or not os.path.isdir(d):
            continue
        try:
            st = os.stat(d)
            mode = st.st_mode
            # world-writable without sticky bit is the dangerous case
            if (mode & 0o002) and not (mode & 0o1000):
                world_writable_path_dirs.append(d)
            elif os.access(d, os.W_OK) and os.getuid() != 0:
                writable_path_dirs.append(d)
        except OSError:
            continue
    if world_writable_path_dirs:
        as9_status, as9_sev = "Fail", "High"
        as9_detail = ("World-writable directories on the executable PATH: "
                      + ", ".join(world_writable_path_dirs))
    elif writable_path_dirs:
        as9_status, as9_sev = "Warning", "Medium"
        as9_detail = ("User-writable directories on the executable PATH: "
                      + ", ".join(writable_path_dirs))
    else:
        as9_status, as9_sev = "Pass", "Low"
        as9_detail = "No writable directories on the executable PATH"
    results.append(AuditResult(
        module=MODULE_NAME, category=CAT,
        status=as9_status,
        message=f"{get_core_id('AS', 9)}: Executable PATH writability",
        details=as9_detail,
        remediation=("Remove world-write from PATH directories and never "
                     "place user-writable directories on root's PATH:\n"
                     "  chmod o-w <dir>\n"
                     "Audit $PATH for entries under /home, /tmp, or current "
                     "directory ('.')."),
        severity=as9_sev,
    ))

    # AS-010: Insecure shared-object / linker controls. World-writable .so
    # files or writable ld.so config let an attacker hijack code loaded into
    # other processes (LD_PRELOAD-style persistence/escalation).
    rc, out, _ = _run(
        "find /lib /lib64 /usr/lib /usr/lib64 /usr/local/lib -xdev "
        "-name '*.so*' -perm -0002 2>/dev/null | head -25")
    ww_so = [l for l in out.splitlines() if l.strip()] if rc == 0 else []
    ld_conf_writable = []
    for p in ["/etc/ld.so.conf", "/etc/ld.so.preload"]:
        try:
            if os.path.exists(p):
                st = os.stat(p)
                if st.st_mode & 0o002:
                    ld_conf_writable.append(p)
        except OSError:
            pass
    # ld.so.preload existing at all is itself worth flagging
    preload_present = os.path.exists("/etc/ld.so.preload")
    if ww_so or ld_conf_writable:
        as10_status, as10_sev = "Fail", "High"
        parts = []
        if ww_so:
            parts.append(f"{len(ww_so)} world-writable shared object(s): "
                         + "; ".join(ww_so[:10]))
        if ld_conf_writable:
            parts.append("world-writable linker config: "
                         + ", ".join(ld_conf_writable))
        as10_detail = " | ".join(parts)
    elif preload_present:
        as10_status, as10_sev = "Warning", "Medium"
        as10_detail = ("/etc/ld.so.preload exists - verify its contents are "
                       "expected (a common LD_PRELOAD persistence vector)")
    else:
        as10_status, as10_sev = "Pass", "Low"
        as10_detail = ("No world-writable shared objects or writable linker "
                       "configuration detected")
    results.append(AuditResult(
        module=MODULE_NAME, category=CAT,
        status=as10_status,
        message=f"{get_core_id('AS', 10)}: Shared object / linker controls",
        details=as10_detail,
        remediation=("Remove world-write from shared objects and linker "
                     "configuration; review /etc/ld.so.preload:\n"
                     "  chmod o-w <file>\n"
                     "  cat /etc/ld.so.preload   # should normally be empty/absent"),
        severity=as10_sev,
    ))


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the v3.5 expanded Core module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_core_v35(shared_data)

    os_info = shared_data.get("os_info") or shared_data.get("v3_os_info")
    if os_info is None:
        from shared_components import os_detection as _os_det
        os_info = _os_det.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        _check_core_v35_sudo_hygiene(results, shared_data, os_info)
        _check_core_v35_user_hygiene(results, shared_data, os_info)
        _check_core_v35_mount_hygiene(results, shared_data, os_info)
        _check_core_v35_cron_hygiene(results, shared_data, os_info)
        _check_core_v35_grub_hygiene(results, shared_data, os_info)
        _check_core_v35_service_inventory(results, shared_data, os_info)
        _check_core_v35_pam_hygiene(results, shared_data, os_info)
        _check_core_v38_attack_surface(results, shared_data, os_info)
    except Exception as exc:  # noqa: BLE001
        results.append(AuditResult(
            module=MODULE_NAME, category="Core - Error",
            status="Error",
            message=f"Core v3.5 expansion exception: {exc!r}",
            details=str(exc), severity="Medium",
        ))

    return results
if __name__ == "__main__":
    """
    Standalone testing capability for the CORE module
    """
    import datetime
    
    print("="*80)
    print(f"CORE Module Standalone Test - v{MODULE_VERSION}")
    print("Comprehensive Linux Security Baseline")
    print("="*80)
    
    # Initialize cache if shared library is available
    cache = None
    if HAS_COMMON_LIB:
        os_info = detect_os()
        cache = SharedDataCache(os_info)
        cache.warm_up()
        print(f"  Cache: Enabled ({cache.get_summary()['files_cached']} files cached)")
    
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
    print(f"\nCheck Area Coverage:")
    category_counts = Counter(r.category for r in test_results)
    for category in sorted(category_counts.keys()):
        count = category_counts[category]
        print(f"  {category:45s}: {count:3d} checks")
    
    print(f"\n{'='*80}")
    print(f"CORE module comprehensive test complete")
    print(f"All {len(test_results)} checks executed successfully")
    print(f"{'='*80}\n")
