#!/usr/bin/env python3
"""
module_acsc.py
ACSC Essential Eight + Information Security Manual (ISM) Module for Linux
Version: 3.9

SYNOPSIS
    Linux technical compliance assessment against the Australian Cyber
    Security Centre's (ACSC) Essential Eight Maturity Model and the
    Information Security Manual (ISM) controls applicable to Linux.

DESCRIPTION
    The Essential Eight is the ACSC's prioritised list of mitigation
    strategies. While originally framed for Windows environments, the
    underlying objectives map directly to Linux technical controls:

        E8.1 - Application control (executable allow-listing)
        E8.2 - Patch applications
        E8.3 - Configure Microsoft Office macro settings (n/a on Linux;
               adapted to scripting language hardening indicators)
        E8.4 - User application hardening (browser, PDF readers)
        E8.5 - Restrict administrative privileges
        E8.6 - Patch operating systems
        E8.7 - Multi-factor authentication
        E8.8 - Regular backups

    The ISM is the broader Australian government cybersecurity standard.
    This module covers the ISM technical controls relevant to Linux
    servers and workstations, drawn from the September 2024 release.

    Each check populates AuditResult.cross_references with the ACSC
    identifier plus equivalents in NIST 800-53, ISO 27001, CIS, and
    other frameworks where applicable.

PARAMETERS
    shared_data : Dictionary containing shared data from the orchestrator.

USAGE
    Standalone:
        python3 modules/module_acsc.py

    Via orchestrator:
        python3 linux_security_audit.py -m ACSC

NOTES
    Version: 3.9
    Reference: https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight
    Standards: ACSC Essential Eight Maturity Model (November 2023),
               Australian Government Information Security Manual (Sept 2024)
    Target: 80+ technical control checks
    Multi-distribution support via shared_components.os_detection.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional

from shared_components.audit_common import AuditResult
from shared_components import os_detection
from shared_components.module_helpers import (
    collect_listening_ports,
    read_file_safe, file_exists, directory_exists, command_available,
    run_command, read_sysctl, systemd_active, systemd_enabled,
    file_mode, parse_kv_file, list_directory, make_result,
    first_existing, package_installed,
)

logger = logging.getLogger("audit.module_acsc")
MODULE_NAME = "ACSC"
MODULE_VERSION = "3.9"

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



def _r(category: str, status: str, message: str,
       severity: str = "Medium", details: str = "",
       remediation: str = "",
       cross_references: Optional[Dict[str, str]] = None) -> AuditResult:
    return make_result(
        module=MODULE_NAME, category=category, status=status,
        message=message, severity=severity, details=details,
        remediation=remediation, cross_references=cross_references,
    )


# ===========================================================================
# E8.1 - Application Control (Executable Allow-Listing)
# ===========================================================================

def _check_e8_1_application_control(os_info) -> List[AuditResult]:
    cat = "ACSC E8.1 - Application Control"
    results: List[AuditResult] = []

    # Linux equivalents: SELinux/AppArmor enforcing mode, fapolicyd (RHEL),
    # or third-party tools like Sentinel/Crowdstrike/Falco
    fapolicyd_state = systemd_active("fapolicyd.service")
    fapolicyd_enabled = fapolicyd_state == "active"

    # AppArmor: profiles in enforce mode
    apparmor_enforcing = False
    if os_info.mac_framework == "apparmor" and command_available("aa-status"):
        rc, out, _ = run_command(["aa-status"])
        if rc == 0:
            m = re.search(r"(\d+)\s+profiles are in enforce mode", out)
            if m and int(m.group(1)) > 0:
                apparmor_enforcing = True

    # SELinux: enforcing mode is a substantial app control posture
    selinux_enforcing = False
    if os_info.mac_framework == "selinux":
        try:
            with open("/sys/fs/selinux/enforce", "r", encoding="ascii") as f:
                selinux_enforcing = f.read().strip() == "1"
        except OSError:
            pass

    has_app_control = fapolicyd_enabled or apparmor_enforcing or selinux_enforcing

    results.append(_r(
        cat,
        "Pass" if has_app_control else "Fail",
        "ACSC-E8.1: Application control mechanism active",
        severity="High",
        details=(
            f"fapolicyd: {fapolicyd_state}, "
            f"apparmor enforcing: {apparmor_enforcing}, "
            f"selinux enforcing: {selinux_enforcing}"
        ),
        remediation=(
            "On RHEL family install fapolicyd: dnf install -y fapolicyd && "
            "systemctl enable --now fapolicyd. On Debian/Ubuntu enforce "
            "AppArmor profiles: aa-enforce /etc/apparmor.d/*. On any system "
            "with SELinux, set enforcing mode: setenforce 1."
        ),
        cross_references={
            "ACSC": "E8.1", "NIST": "CM-7(5)", "ISO27001": "A.8.7",
            "CIS": "1.6.1.3", "STIG": "V-230230",
        },
    ))

    # Check for unrestricted execution paths (world-writable in PATH)
    path_dirs = os.environ.get("PATH", "").split(":") + [
        "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin",
    ]
    writable_path_dirs = []
    for d in path_dirs:
        if not d or not os.path.isdir(d):
            continue
        try:
            st = os.stat(d)
        except OSError:
            continue
        if st.st_mode & 0o002:  # world-writable
            writable_path_dirs.append(d)

    results.append(_r(
        cat,
        "Pass" if not writable_path_dirs else "Fail",
        "ACSC-E8.1: No world-writable directories in PATH",
        severity="High",
        details=f"World-writable PATH dirs: {', '.join(writable_path_dirs) or 'none'}",
        remediation=(
            "Remove world-write permission from any directory in PATH: "
            "chmod o-w <directory>"
        ),
        cross_references={
            "ACSC": "E8.1", "NIST": "AC-3", "CIS": "6.2.10",
            "ISO27001": "A.8.3",
        },
    ))

    return results


# ===========================================================================
# E8.2 - Patch Applications
# ===========================================================================

def _check_e8_2_patch_applications(os_info) -> List[AuditResult]:
    cat = "ACSC E8.2 - Patch Applications"
    results: List[AuditResult] = []

    # Check for unattended-upgrades (Debian) or dnf-automatic (RHEL)
    if os_info.is_debian_family():
        unattended_installed = file_exists("/etc/apt/apt.conf.d/50unattended-upgrades")
        unattended_active = systemd_active("unattended-upgrades.service") in (
            "active", "exited",
        )

        results.append(_r(
            cat,
            "Pass" if unattended_active else "Warning",
            "ACSC-E8.2: Automatic security updates configured",
            severity="High",
            details=(
                f"unattended-upgrades config: {unattended_installed}, "
                f"service: {unattended_active}"
            ),
            remediation=(
                "apt-get install -y unattended-upgrades && "
                "dpkg-reconfigure unattended-upgrades"
            ),
            cross_references={
                "ACSC": "E8.2", "NIST": "SI-2", "CIS": "1.9",
                "ISO27001": "A.8.8",
            },
        ))

    elif os_info.is_redhat_family():
        dnf_automatic = systemd_active("dnf-automatic.timer") == "active"
        dnf_install = systemd_active("dnf-automatic-install.timer") == "active"
        any_active = dnf_automatic or dnf_install

        results.append(_r(
            cat,
            "Pass" if any_active else "Warning",
            "ACSC-E8.2: Automatic security updates configured",
            severity="High",
            details=(
                f"dnf-automatic.timer: {dnf_automatic}, "
                f"dnf-automatic-install.timer: {dnf_install}"
            ),
            remediation=(
                "dnf install -y dnf-automatic && "
                "systemctl enable --now dnf-automatic-install.timer"
            ),
            cross_references={
                "ACSC": "E8.2", "NIST": "SI-2", "CIS": "1.9",
                "ISO27001": "A.8.8",
            },
        ))

    # Check pending security updates
    pending_updates = -1  # unknown
    if os_info.is_debian_family() and command_available("apt-get"):
        rc, out, _ = run_command(["apt-get", "-s", "upgrade"], timeout=30.0)
        if rc == 0:
            pending_updates = sum(
                1 for line in out.splitlines()
                if line.startswith("Inst ") and "-security" in line.lower()
            )
    elif os_info.is_redhat_family() and command_available("dnf"):
        rc, out, _ = run_command(
            ["dnf", "-q", "updateinfo", "list", "security"], timeout=30.0
        )
        if rc == 0:
            pending_updates = sum(
                1 for line in out.splitlines()
                if line.strip() and not line.startswith("Last metadata")
            )

    if pending_updates >= 0:
        results.append(_r(
            cat,
            "Pass" if pending_updates == 0 else "Fail",
            "ACSC-E8.2: No pending security patches",
            severity="Critical",
            details=(
                f"Pending security updates: {pending_updates}. "
                "ACSC ML2 requires patching within 2 weeks; ML3 within 48 hours."
            ),
            remediation=(
                "apt-get update && apt-get -y upgrade  (Debian/Ubuntu) or "
                "dnf -y update --security  (RHEL family)"
            ),
            cross_references={
                "ACSC": "E8.2", "NIST": "SI-2(2)", "ISO27001": "A.8.8",
                "CISA": "BOD-22-01", "PCI-DSS": "6.3.3",
            },
        ))

    return results


# ===========================================================================
# E8.4 - User Application Hardening
# ===========================================================================

def _check_e8_4_user_app_hardening(os_info) -> List[AuditResult]:
    cat = "ACSC E8.4 - User Application Hardening"
    results: List[AuditResult] = []

    # Browser presence in server environments is a configuration smell
    browser_indicators = [
        "/usr/bin/firefox", "/usr/bin/google-chrome",
        "/usr/bin/chromium", "/usr/bin/chromium-browser",
    ]
    found_browsers = [b for b in browser_indicators if file_exists(b)]

    # Note: this is informational - server systems should not have browsers
    # but desktop systems will and that's expected
    results.append(_r(
        cat,
        "Info",
        f"ACSC-E8.4: Browser inventory: {len(found_browsers)} detected",
        severity="Informational",
        details=f"Browsers found: {', '.join(found_browsers) or 'none'}",
        remediation=(
            "On server systems, remove browsers: apt-get remove -y firefox "
            "(or equivalent for installed browsers). On desktop systems, "
            "ensure browsers are kept current and configured per ACSC guidance."
        ),
        cross_references={"ACSC": "E8.4", "NIST": "CM-7"},
    ))

    # Disable unnecessary scripting interpreters in critical paths
    # PowerShell on Linux is unusual - flag if installed
    pwsh_installed = file_exists("/usr/bin/pwsh") or file_exists("/opt/microsoft/powershell/7/pwsh")
    results.append(_r(
        cat,
        "Info",
        "ACSC-E8.4: PowerShell on Linux inventory",
        severity="Informational",
        details=(
            f"PowerShell installed: {pwsh_installed}. "
            "Justify PowerShell presence; remove if not required."
        ),
        cross_references={"ACSC": "E8.4", "NIST": "CM-7"},
    ))

    return results


# ===========================================================================
# E8.5 - Restrict Administrative Privileges
# ===========================================================================

def _check_e8_5_restrict_admin(os_info) -> List[AuditResult]:
    cat = "ACSC E8.5 - Restrict Admin Privileges"
    results: List[AuditResult] = []

    # Check sudoers for unrestricted access patterns
    sudoers_files = ["/etc/sudoers"] + list_directory("/etc/sudoers.d", "")
    nopasswd_count = 0
    all_command_grants = []

    for sf in sudoers_files:
        content = read_file_safe(sf)
        if not content:
            continue
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("Defaults") or not stripped:
                continue
            if "NOPASSWD" in stripped.upper():
                nopasswd_count += 1
            # Look for ALL=(ALL:ALL) ALL or similar unrestricted grants
            if re.search(r"ALL\s*=\s*\(\s*ALL[\s:]*ALL?\s*\)\s*ALL", stripped):
                all_command_grants.append(stripped[:100])

    results.append(_r(
        cat,
        "Pass" if nopasswd_count == 0 else "Fail",
        "ACSC-E8.5: No NOPASSWD sudo entries",
        severity="High",
        details=f"NOPASSWD sudoers entries: {nopasswd_count}",
        remediation=(
            "Review every NOPASSWD entry in /etc/sudoers and /etc/sudoers.d/. "
            "Replace with PASSWD-required rules unless there is a documented "
            "operational requirement (e.g. service automation accounts)."
        ),
        cross_references={
            "ACSC": "E8.5", "NIST": "AC-6(2)", "CIS": "5.5.4",
            "ISO27001": "A.8.2", "STIG": "V-230363",
        },
    ))

    # Audit number of users with sudo group membership
    group_content = read_file_safe("/etc/group")
    sudo_members = []
    wheel_members = []
    for line in group_content.splitlines():
        fields = line.split(":")
        if len(fields) < 4:
            continue
        if fields[0] == "sudo":
            sudo_members = [m for m in fields[3].split(",") if m]
        elif fields[0] == "wheel":
            wheel_members = [m for m in fields[3].split(",") if m]

    privileged_users = set(sudo_members + wheel_members)

    results.append(_r(
        cat,
        "Info",
        f"ACSC-E8.5: Privileged group membership: {len(privileged_users)} users",
        severity="Informational",
        details=(
            f"sudo group: {', '.join(sudo_members) or 'empty'}; "
            f"wheel group: {', '.join(wheel_members) or 'empty'}"
        ),
        remediation=(
            "Review the privileged group membership list. ACSC ML2/ML3 require "
            "privileged accounts to be reviewed at least every 12 months and "
            "tied to documented business requirements."
        ),
        cross_references={
            "ACSC": "E8.5", "NIST": "AC-6", "CIS": "5.6",
            "ISO27001": "A.8.2",
        },
    ))

    return results


# ===========================================================================
# E8.6 - Patch Operating Systems
# ===========================================================================

def _check_e8_6_patch_os(os_info) -> List[AuditResult]:
    cat = "ACSC E8.6 - Patch Operating Systems"
    results: List[AuditResult] = []

    # Check OS support status (EOL detection)
    if os_info.eol:
        results.append(_r(
            cat,
            "Fail",
            "ACSC-E8.6: Operating system version is past end-of-life",
            severity="Critical",
            details=(
                f"Distribution {os_info.distro_id} {os_info.version_id} "
                "is no longer receiving security updates."
            ),
            remediation=(
                "Upgrade to a supported version of the distribution. "
                "Running an EOL OS is incompatible with ACSC E8 ML1+."
            ),
            cross_references={
                "ACSC": "E8.6", "NIST": "SA-22", "ISO27001": "A.8.8",
                "CISA": "BOD-22-01", "PCI-DSS": "6.3.3",
            },
        ))
    else:
        results.append(_r(
            cat,
            "Pass",
            "ACSC-E8.6: Operating system version is currently supported",
            severity="High",
            details=f"Distribution: {os_info.distro_id} {os_info.version_id}",
            cross_references={
                "ACSC": "E8.6", "NIST": "SA-22", "ISO27001": "A.8.8",
            },
        ))

    # Check kernel age via uname/proc/version
    kernel_age_days = None
    try:
        version_path = "/proc/version"
        if file_exists(version_path):
            stat = os.stat(version_path)
            # /proc/version mtime is the kernel build time
            import time
            kernel_age_days = int((time.time() - stat.st_mtime) / 86400)
    except OSError:
        pass

    if kernel_age_days is not None:
        ml1_threshold = 30  # days
        ml2_threshold = 14
        ml3_threshold = 2

        if kernel_age_days > ml1_threshold:
            severity = "High"
            status = "Warning"
            ml = f"older than ML1 threshold ({ml1_threshold}d)"
        elif kernel_age_days > ml2_threshold:
            severity = "Medium"
            status = "Info"
            ml = f"meets ML1 (within {ml1_threshold}d)"
        else:
            severity = "Low"
            status = "Pass"
            ml = f"meets ML2 (within {ml2_threshold}d)"

        results.append(_r(
            cat,
            status,
            f"ACSC-E8.6: Running kernel age {kernel_age_days} days",
            severity=severity,
            details=(
                f"Kernel: {os_info.kernel.raw}; build age: {kernel_age_days}d. "
                f"{ml}. ML3 requires patches within 48 hours of release."
            ),
            remediation=(
                "Apply pending kernel updates and reboot. On Debian/Ubuntu "
                "with livepatch: enable Canonical Livepatch. On RHEL with "
                "kpatch: kpatch install <patch>."
            ),
            cross_references={
                "ACSC": "E8.6", "NIST": "SI-2", "ISO27001": "A.8.8",
            },
        ))

    return results


# ===========================================================================
# E8.7 - Multi-Factor Authentication
# ===========================================================================

def _check_e8_7_mfa(os_info) -> List[AuditResult]:
    cat = "ACSC E8.7 - Multi-Factor Authentication"
    results: List[AuditResult] = []

    # Check for PAM modules that provide MFA
    pam_files = list_directory("/etc/pam.d", "")
    mfa_modules_seen = set()

    mfa_indicators = {
        "pam_google_authenticator.so": "Google Authenticator (TOTP)",
        "pam_oath.so": "OATH (HOTP/TOTP)",
        "pam_yubico.so": "YubiKey",
        "pam_duo.so": "Duo Security",
        "pam_radius.so": "RADIUS (often used for MFA)",
        "pam_u2f.so": "Universal 2nd Factor",
        "pam_pkcs11.so": "Smart Card / PKCS#11",
    }

    for pf in pam_files:
        content = read_file_safe(pf)
        for module_name, label in mfa_indicators.items():
            if module_name in content:
                mfa_modules_seen.add(label)

    sshd_uses_mfa = False
    sshd_config = read_file_safe("/etc/ssh/sshd_config")
    if sshd_config:
        # AuthenticationMethods with multiple factors indicates MFA
        for line in sshd_config.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("authenticationmethods"):
                # Multiple methods separated by comma or space (and with multiple factor types)
                if "," in stripped or " keyboard-interactive" in stripped.lower():
                    sshd_uses_mfa = True
                    break

    has_any_mfa = bool(mfa_modules_seen) or sshd_uses_mfa

    results.append(_r(
        cat,
        "Pass" if has_any_mfa else "Fail",
        "ACSC-E8.7: Multi-factor authentication mechanism present",
        severity="Critical",
        details=(
            f"PAM MFA modules: {', '.join(sorted(mfa_modules_seen)) or 'none'}; "
            f"sshd MFA configured: {sshd_uses_mfa}"
        ),
        remediation=(
            "Configure MFA for privileged access. For SSH: install "
            "libpam-google-authenticator (Debian) or google-authenticator "
            "(RHEL). Configure /etc/pam.d/sshd to use pam_google_authenticator.so. "
            "Set AuthenticationMethods publickey,keyboard-interactive in sshd_config."
        ),
        cross_references={
            "ACSC": "E8.7", "NIST": "IA-2(1)", "ISO27001": "A.8.5",
            "PCI-DSS": "8.4.2", "HIPAA": "164.312(d)",
            "CISA": "CPG-2.H",
        },
    ))

    return results


# ===========================================================================
# E8.8 - Regular Backups
# ===========================================================================

def _check_e8_8_backups(os_info) -> List[AuditResult]:
    cat = "ACSC E8.8 - Regular Backups"
    results: List[AuditResult] = []

    # Look for backup tooling indicators
    backup_indicators = {
        "rsync": command_available("rsync"),
        "rsnapshot": command_available("rsnapshot") or file_exists("/etc/rsnapshot.conf"),
        "BackupPC": file_exists("/etc/backuppc/config.pl"),
        "Bacula": file_exists("/etc/bacula/bacula-fd.conf"),
        "Borg": command_available("borg"),
        "Restic": command_available("restic"),
        "Duplicity": command_available("duplicity"),
        "AWS CLI (S3 backup)": command_available("aws"),
        "rclone": command_available("rclone"),
    }
    detected_backup_tools = [name for name, present in backup_indicators.items() if present]

    results.append(_r(
        cat,
        "Info" if detected_backup_tools else "Warning",
        "ACSC-E8.8: Backup tooling inventory",
        severity="Medium",
        details=(
            f"Detected: {', '.join(detected_backup_tools) or 'none'}. "
            "Tool presence alone does not confirm working backups; "
            "verify scheduled execution and successful test restoration."
        ),
        remediation=(
            "Install a backup tool appropriate for the environment. "
            "Configure scheduled backups, off-host storage, encryption, "
            "retention policy, and test restoration at least every six months "
            "(ACSC ML2)."
        ),
        cross_references={
            "ACSC": "E8.8", "NIST": "CP-9", "ISO27001": "A.8.13",
            "PCI-DSS": "12.10.1", "HIPAA": "164.308(a)(7)(ii)(A)",
        },
    ))

    return results


# ===========================================================================
# ISM Controls (Selected Linux-Applicable Subset)
# ===========================================================================

def _check_ism_secure_boot(os_info) -> List[AuditResult]:
    cat = "ACSC ISM - Secure Boot"
    results: List[AuditResult] = []

    # ISM-1610 - Secure Boot enabled
    secure_boot = "unknown"
    if directory_exists("/sys/firmware/efi"):
        # UEFI system
        sb_files = list_directory("/sys/firmware/efi/efivars", "")
        for sb_file in sb_files:
            if "SecureBoot" in os.path.basename(sb_file):
                # Read the variable - first 4 bytes are attributes, then 1 byte value
                try:
                    with open(sb_file, "rb") as f:
                        data = f.read()
                    if len(data) >= 5:
                        secure_boot = "enabled" if data[4] == 1 else "disabled"
                        break
                except OSError:
                    continue

        results.append(_r(
            cat,
            "Pass" if secure_boot == "enabled" else "Fail",
            "ACSC-ISM-1610: UEFI Secure Boot enabled",
            severity="High",
            details=f"Secure Boot state: {secure_boot}",
            remediation=(
                "Enable Secure Boot in firmware (BIOS/UEFI setup). "
                "Ensure shim/grub are signed by a key in the platform DB."
            ),
            cross_references={
                "ACSC": "ISM-1610", "NIST": "SI-7", "ISO27001": "A.8.7",
                "NSA": "BOOT-1.1",
            },
        ))
    else:
        results.append(_r(
            cat,
            "Info",
            "ACSC-ISM-1610: Legacy BIOS system - Secure Boot not applicable",
            severity="Informational",
            details="No /sys/firmware/efi directory; system booted via legacy BIOS",
            cross_references={"ACSC": "ISM-1610", "NIST": "SI-7"},
        ))

    return results


def _check_ism_event_logging(os_info) -> List[AuditResult]:
    cat = "ACSC ISM - Event Logging"
    results: List[AuditResult] = []

    # ISM-0580 - Centralised event logging
    rsyslog_files = ["/etc/rsyslog.conf"] + list_directory("/etc/rsyslog.d", ".conf")
    remote_forwarding = False
    forwarding_target = ""

    for rf in rsyslog_files:
        content = read_file_safe(rf)
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            m = re.search(r"@@?([a-zA-Z0-9.\-]+)(:\d+)?", stripped)
            if m and "*" in stripped[:5]:
                remote_forwarding = True
                forwarding_target = m.group(0)
                break
        if remote_forwarding:
            break

    results.append(_r(
        cat,
        "Pass" if remote_forwarding else "Warning",
        "ACSC-ISM-0580: Event logs forwarded to centralised log server",
        severity="High",
        details=f"Forwarding configured: {remote_forwarding} ({forwarding_target or 'none'})",
        remediation=(
            "Configure rsyslog or systemd-journald to forward to a central "
            "syslog/SIEM. Example /etc/rsyslog.d/50-remote.conf: "
            "*.* @@logserver.gov.au:514"
        ),
        cross_references={
            "ACSC": "ISM-0580", "NIST": "AU-6(3)", "CIS": "4.2.1.5",
            "ISO27001": "A.8.15", "PCI-DSS": "10.5.4",
        },
    ))

    # ISM-1815 - Cryptographic protection of logs in transit
    tls_logging = False
    for rf in rsyslog_files:
        content = read_file_safe(rf)
        if "DefaultNetstreamDriver" in content and "gtls" in content.lower():
            tls_logging = True
            break
        if "RELP" in content and ("relp.tls" in content.lower() or "tls=on" in content.lower()):
            tls_logging = True
            break

    results.append(_r(
        cat,
        "Pass" if tls_logging else "Warning" if remote_forwarding else "Info",
        "ACSC-ISM-1815: Log forwarding uses TLS",
        severity="High",
        details=f"TLS-secured log forwarding: {tls_logging}",
        remediation=(
            "Enable TLS for remote rsyslog: configure DefaultNetstreamDriver gtls "
            "or use omrelp with TLS=on. Provision certificates from your CA."
        ),
        cross_references={
            "ACSC": "ISM-1815", "NIST": "AU-9(3)", "ISO27001": "A.8.15",
            "PCI-DSS": "4.2.1",
        },
    ))

    return results


def _check_ism_session_lock(os_info) -> List[AuditResult]:
    cat = "ACSC ISM - Session Locking"
    results: List[AuditResult] = []

    # ISM-0428 - Idle terminal sessions locked
    tmout_set = False
    tmout_value = ""
    profile_paths = ["/etc/profile"] + list_directory("/etc/profile.d", ".sh")
    for path in profile_paths:
        content = read_file_safe(path)
        m = re.search(
            r"^\s*(?:readonly\s+|export\s+)?TMOUT=(\d+)",
            content, re.MULTILINE,
        )
        if m:
            tmout_set = True
            tmout_value = m.group(1)
            break

    try:
        tmout_int = int(tmout_value) if tmout_value else 0
    except ValueError:
        tmout_int = 0

    # ACSC ISM-0428 specifies max 15 minutes for idle lock
    tmout_ok = tmout_set and 0 < tmout_int <= 900

    results.append(_r(
        cat,
        "Pass" if tmout_ok else "Fail",
        "ACSC-ISM-0428: Terminal sessions lock after 15 minutes idle",
        severity="Medium",
        details=f"TMOUT = {tmout_value or 'unset'} seconds (must be 1-900)",
        remediation=(
            "Create /etc/profile.d/tmout.sh: "
            'echo "readonly TMOUT=900; export TMOUT" > /etc/profile.d/tmout.sh && '
            "chmod 644 /etc/profile.d/tmout.sh"
        ),
        cross_references={
            "ACSC": "ISM-0428", "NIST": "AC-12", "CIS": "5.4.4",
            "STIG": "V-230363", "PCI-DSS": "8.2.8",
        },
    ))

    return results


def _check_ism_authentication(os_info) -> List[AuditResult]:
    cat = "ACSC ISM - Authentication"
    results: List[AuditResult] = []

    # ISM-0421 - Account lockout after failed authentication
    pam_paths = (
        "/etc/security/faillock.conf",
        "/etc/pam.d/system-auth",
        "/etc/pam.d/common-auth",
        "/etc/pam.d/password-auth",
    )
    deny_value: Optional[int] = None
    for path in pam_paths:
        content = read_file_safe(path)
        if not content:
            continue
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            m = re.search(r"deny\s*=\s*(\d+)", stripped)
            if m:
                deny_value = int(m.group(1))
                break
        if deny_value is not None:
            break

    lockout_ok = deny_value is not None and 1 <= deny_value <= 5

    results.append(_r(
        cat,
        "Pass" if lockout_ok else "Fail",
        "ACSC-ISM-0421: Account lockout configured for <= 5 failed attempts",
        severity="High",
        details=f"deny value: {deny_value or 'not configured'}",
        remediation=(
            "Configure pam_faillock with deny=5 in /etc/security/faillock.conf "
            "(RHEL family) or /etc/pam.d/common-auth (Debian/Ubuntu)."
        ),
        cross_references={
            "ACSC": "ISM-0421", "NIST": "AC-7", "CIS": "5.3.1",
            "STIG": "V-230333", "PCI-DSS": "8.3.4",
        },
    ))

    # ISM-0417 - Password complexity
    pwquality_conf = read_file_safe("/etc/security/pwquality.conf")
    pw_settings = parse_kv_file(pwquality_conf)

    minlen_str = pw_settings.get("minlen", "")
    try:
        minlen_int = int(minlen_str) if minlen_str.split("=")[-1].strip().isdigit() else 0
    except (ValueError, AttributeError):
        minlen_int = 0
    # Also check if it's in =N format
    minlen_match = re.search(r"=\s*(\d+)", minlen_str)
    if minlen_match:
        minlen_int = int(minlen_match.group(1))

    # ISM requires minimum 14 chars for general user passwords
    minlen_ok = minlen_int >= 14

    results.append(_r(
        cat,
        "Pass" if minlen_ok else "Fail",
        "ACSC-ISM-0417: Password minimum length 14 characters",
        severity="High",
        details=f"pwquality.conf minlen = {minlen_str or 'unset'}",
        remediation=(
            "Edit /etc/security/pwquality.conf: minlen = 14"
        ),
        cross_references={
            "ACSC": "ISM-0417", "NIST": "IA-5(1)", "CIS": "5.4.1.1",
            "PCI-DSS": "8.3.6", "STIG": "V-230369",
        },
    ))

    return results


def _check_ism_data_at_rest(os_info) -> List[AuditResult]:
    cat = "ACSC ISM - Data at Rest"
    results: List[AuditResult] = []

    # ISM-0457 - Full disk encryption
    luks_active = False
    if command_available("dmsetup"):
        rc, out, _ = run_command(["dmsetup", "ls", "--target=crypt"])
        if rc == 0 and out and "No devices found" not in out:
            luks_active = True

    results.append(_r(
        cat,
        "Pass" if luks_active else "Warning",
        "ACSC-ISM-0457: Disk encryption (LUKS) active",
        severity="High",
        details=f"LUKS-encrypted devices detected: {luks_active}",
        remediation=(
            "Encrypt sensitive volumes with LUKS at provisioning time. "
            "Existing systems require offline encryption; consult vendor "
            "documentation for the safest path."
        ),
        cross_references={
            "ACSC": "ISM-0457", "NIST": "SC-28", "ISO27001": "A.8.10",
            "GDPR": "Art-32", "HIPAA": "164.312(a)(2)(iv)",
            "PCI-DSS": "3.5.1",
        },
    ))

    return results


# ===========================================================================
# Module entry point
# ===========================================================================

def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the ACSC module against the current host.

    Returns a list of AuditResult instances. Cross-references are
    populated by each check; the orchestrator's pipeline applies further
    enrichment via the correlation registry.
    """
    if shared_data is None:
        shared_data = {}

    os_info = shared_data.get("v3_os_info")
    if os_info is None:
        os_info = os_detection.detect_os()
        shared_data["v3_os_info"] = os_info

    results: List[AuditResult] = []

    try:
        results.extend(_check_e8_1_application_control(os_info))
        results.extend(_check_e8_2_patch_applications(os_info))
        results.extend(_check_e8_4_user_app_hardening(os_info))
        results.extend(_check_e8_5_restrict_admin(os_info))
        results.extend(_check_e8_6_patch_os(os_info))
        results.extend(_check_e8_7_mfa(os_info))
        results.extend(_check_e8_8_backups(os_info))
        results.extend(_check_ism_secure_boot(os_info))
        results.extend(_check_ism_event_logging(os_info))
        results.extend(_check_ism_session_lock(os_info))
        results.extend(_check_ism_authentication(os_info))
        results.extend(_check_ism_data_at_rest(os_info))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled exception in ACSC module")
        results.append(_r(
            "ACSC - Error", "Error",
            f"ACSC module encountered an unhandled exception: {exc!r}",
            severity="Medium", details=str(exc),
        ))

    return results



# ===========================================================================
# v3.1 EXPANSION - ACSC Comprehensive ISM + Essential Eight ML2/ML3
# ---------------------------------------------------------------------------
# Adds ISM controls (technical subset) and deeper Essential Eight depth:
#   - ISM cryptography (0457, 0467, 1162, 1232, 1233)
#   - ISM network hardening (0428, 0540, 1182, 1416)
#   - ISM access control (0405, 1505, 1506)
#   - ISM logging/monitoring (0586, 0859, 1228)
#   - ISM malware protection (1417, 1418)
#   - ISM patch management (0297, 1493, 1494)
#   - ISM gateway/web (0263, 1239)
# ===========================================================================


def _check_ism_cryptography(os_info) -> List[AuditResult]:
    """ISM cryptography controls."""
    results: List[AuditResult] = []
    cat = "ACSC - ISM Cryptography"

    # ISM-0467 Approved cryptographic algorithms (SSH)
    sshd_config = read_file_safe("/etc/ssh/sshd_config")
    if sshd_config:
        cipher_lines = [l.strip() for l in sshd_config.splitlines()
                       if l.strip().lower().startswith("ciphers ")]
        weak_ciphers = []
        if cipher_lines:
            cipher_value = cipher_lines[-1].lower()
            for w in ("3des", "arcfour", "blowfish", "cast128", "rc4", "des-cbc"):
                if w in cipher_value:
                    weak_ciphers.append(w)
        results.append(_r(
            cat, "Pass" if not weak_ciphers else "Fail",
            "ISM-0467: SSH ciphers exclude weak algorithms",
            severity="High",
            details=f"Configured ciphers excluded weak: {not weak_ciphers}; weak found: {weak_ciphers}",
            remediation=(
                "/etc/ssh/sshd_config: Ciphers chacha20-poly1305@openssh.com,"
                "aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr"
            ),
            cross_references={
                "ACSC": "ISM-0467", "NIST": "SC-13", "STIG": "V-230252",
            },
        ))

    # ISM-1162 Mandatory key length
    sshd_keys = list_directory("/etc/ssh", suffix=".pub")
    weak_key_found = False
    for k in sshd_keys:
        if "rsa" in k.lower() and "host_key" in k.lower():
            # Check key length using ssh-keygen
            if command_available("ssh-keygen"):
                rc, out, _ = run_command(
                    ["ssh-keygen", "-l", "-f", os.path.join("/etc/ssh", k)],
                    timeout=5.0
                )
                if rc == 0:
                    bits_match = re.match(r"(\d+)\s", out)
                    if bits_match:
                        bits = int(bits_match.group(1))
                        if bits < 2048:
                            weak_key_found = True
    results.append(_r(
        cat, "Pass" if not weak_key_found else "Fail",
        "ISM-1162: SSH host key length >= 2048 bits",
        severity="High",
        details=f"Weak key detected: {weak_key_found}",
        remediation=(
            "Regenerate weak keys: ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key. "
            "Prefer ed25519: ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key."
        ),
        cross_references={
            "ACSC": "ISM-1162", "NIST": "SC-13", "STIG": "V-230255",
        },
    ))

    # ISM-1232 Disk encryption
    luks_active = False
    if command_available("dmsetup"):
        rc, out, _ = run_command(["dmsetup", "ls", "--target=crypt"], timeout=5.0)
        if rc == 0 and out and "No devices" not in out:
            luks_active = True
    results.append(_r(
        cat, "Pass" if luks_active else "Fail",
        "ISM-1232: Disk encryption (LUKS) active",
        severity="High",
        details=f"LUKS-encrypted devices: {luks_active}",
        remediation="Install with LUKS encryption enabled.",
        cross_references={
            "ACSC": "ISM-1232", "NIST": "SC-28", "PCI-DSS": "3.5",
        },
    ))

    # ISM-1233 Use of approved cryptographic protocols (TLS 1.2+)
    if file_exists("/etc/crypto-policies/config"):
        policy = read_file_safe("/etc/crypto-policies/config").strip()
        results.append(_r(
            cat, "Pass" if policy in ("DEFAULT", "FUTURE", "FIPS") else "Warning",
            f"ISM-1233: System crypto policy: {policy}",
            severity="Medium",
            details=f"Policy: {policy}",
            remediation="update-crypto-policies --set FUTURE",
            cross_references={
                "ACSC": "ISM-1233", "NIST": "SC-13",
            },
        ))

    return results


def _check_ism_network_hardening(os_info) -> List[AuditResult]:
    """ISM network hardening controls."""
    results: List[AuditResult] = []
    cat = "ACSC - ISM Network Hardening"

    # ISM-0428 Workstation firewall
    fw_active = (
        systemd_active("firewalld.service") == "active" or
        systemd_active("ufw.service") == "active" or
        systemd_active("nftables.service") == "active" or
        systemd_active("iptables.service") == "active"
    )
    results.append(_r(
        cat, "Pass" if fw_active else "Fail",
        "ISM-0428: Host-based firewall enabled",
        severity="High",
        details=f"Firewall active: {fw_active}",
        remediation="systemctl enable --now firewalld (or ufw enable)",
        cross_references={
            "ACSC": "ISM-0428", "NIST": "SC-7", "CIS": "3.4",
        },
    ))

    # ISM-1182 IPv6 hardening (if not used, disable)
    ipv6_disabled = read_sysctl("net.ipv6.conf.all.disable_ipv6") == "1"
    if ipv6_disabled:
        results.append(_r(
            cat, "Info",
            "ISM-1182: IPv6 disabled (acceptable if not in use)",
            severity="Informational",
            details="net.ipv6.conf.all.disable_ipv6 = 1",
            cross_references={
                "ACSC": "ISM-1182", "NIST": "SC-7",
            },
        ))
    else:
        # If enabled, check accept_ra and accept_redirects
        ra_disabled = read_sysctl("net.ipv6.conf.all.accept_ra") == "0"
        redirects_disabled = read_sysctl("net.ipv6.conf.all.accept_redirects") == "0"
        results.append(_r(
            cat, "Pass" if ra_disabled and redirects_disabled else "Warning",
            "ISM-1182: IPv6 hardening (accept_ra=0, accept_redirects=0)",
            severity="Medium",
            details=(
                f"accept_ra: {read_sysctl('net.ipv6.conf.all.accept_ra')}, "
                f"accept_redirects: {read_sysctl('net.ipv6.conf.all.accept_redirects')}"
            ),
            remediation=(
                "/etc/sysctl.d/99-acsc.conf: "
                "net.ipv6.conf.all.accept_ra = 0; "
                "net.ipv6.conf.all.accept_redirects = 0"
            ),
            cross_references={
                "ACSC": "ISM-1182", "NIST": "SC-7", "CIS": "3.3.5",
            },
        ))

    # ISM-1416 Disable unnecessary services
    listening = collect_listening_ports()
    common_unneeded = [
        13,    # daytime
        17,    # qotd
        19,    # chargen
        23,    # telnet
        37,    # time
        69,    # tftp
        79,    # finger
        111,   # rpcbind
        137,   # netbios-ns
        138,   # netbios-dgm
        139,   # netbios-ssn
        515,   # printer
        540,   # uucp
    ]
    risky_listening = [p for p in common_unneeded if p in listening]
    results.append(_r(
        cat, "Pass" if not risky_listening else "Fail",
        f"ISM-1416: Common unnecessary services not listening ({len(risky_listening)} risky)",
        severity="High",
        details=f"Risky listening ports: {risky_listening}",
        remediation=(
            "Identify service: ss -tulpn | grep <port>. "
            "Disable: systemctl disable --now <service>."
        ),
        cross_references={
            "ACSC": "ISM-1416", "NIST": "CM-7", "CIS": "2.2",
        },
    ))

    return results


def _check_ism_access_control(os_info) -> List[AuditResult]:
    """ISM access control."""
    results: List[AuditResult] = []
    cat = "ACSC - ISM Access Control"

    # ISM-0405 Account suspension after failed logins
    pam_files = ["/etc/pam.d/system-auth", "/etc/pam.d/common-auth"]
    faillock = False
    for f in pam_files:
        c = read_file_safe(f)
        if c and ("pam_faillock" in c or "pam_tally2" in c):
            faillock = True
            break

    results.append(_r(
        cat, "Pass" if faillock else "Fail",
        "ISM-0405: Account lockout after multiple failed logins (PAM)",
        severity="High",
        details=f"PAM faillock/tally2 module loaded: {faillock}",
        remediation=(
            "Add to /etc/pam.d/system-auth: "
            "auth required pam_faillock.so preauth deny=5 unlock_time=900"
        ),
        cross_references={
            "ACSC": "ISM-0405", "NIST": "AC-7", "CIS": "5.4.2",
        },
    ))

    # ISM-1505/1506 Default account passwords
    shadow = read_file_safe("/etc/shadow")
    no_password_accounts = []
    if shadow:
        for line in shadow.splitlines():
            fields = line.split(":")
            if len(fields) < 2:
                continue
            user = fields[0]
            pwd = fields[1]
            if not pwd or pwd == "":
                no_password_accounts.append(user)

    results.append(_r(
        cat, "Pass" if not no_password_accounts else "Fail",
        f"ISM-1505: No accounts have empty passwords ({len(no_password_accounts)} found)",
        severity="Critical",
        details=f"Empty-password accounts: {no_password_accounts}",
        remediation=(
            "passwd -l <user> for each affected user, or set strong password"
        ),
        cross_references={
            "ACSC": "ISM-1505", "NIST": "IA-5", "CIS": "5.4.2.4",
        },
    ))

    return results


def _check_ism_event_logging_extended(os_info) -> List[AuditResult]:
    """ISM event logging deeper checks."""
    results: List[AuditResult] = []
    cat = "ACSC - ISM Logging Extended"

    # ISM-0859 Centralized logging
    rsyslog_d = list_directory("/etc/rsyslog.d", suffix=".conf")
    forwarding = False
    for f in rsyslog_d + ["/etc/rsyslog.conf"]:
        if f == "/etc/rsyslog.conf":
            c = read_file_safe(f)
        else:
            c = read_file_safe(os.path.join("/etc/rsyslog.d", f))
        if c and ("@@" in c or "omfwd" in c):
            forwarding = True
            break

    results.append(_r(
        cat, "Pass" if forwarding else "Fail",
        "ISM-0859: Centralized log forwarding configured",
        severity="High",
        details=f"Remote log forwarding: {forwarding}",
        remediation=(
            "/etc/rsyslog.d/50-remote.conf: *.* @@logserver:514"
        ),
        cross_references={
            "ACSC": "ISM-0859", "NIST": "AU-6(3)", "PCI-DSS": "10.5.4",
        },
    ))

    # ISM-1228 Time synchronization
    ts_active = (
        systemd_active("chronyd.service") == "active" or
        systemd_active("chrony.service") == "active" or
        systemd_active("ntp.service") == "active" or
        systemd_active("systemd-timesyncd.service") == "active"
    )
    results.append(_r(
        cat, "Pass" if ts_active else "Fail",
        "ISM-1228: Network time synchronization active",
        severity="High",
        details=f"Time sync service active: {ts_active}",
        remediation=remediation_for("chrony"),
        cross_references={
            "ACSC": "ISM-1228", "NIST": "AU-8(1)", "PCI-DSS": "10.6",
        },
    ))

    # Audit rules for privileged escalation
    audit_rules_text = ""
    rules_d = list_directory("/etc/audit/rules.d", suffix=".rules")
    for rf in rules_d:
        audit_rules_text += "\n" + read_file_safe(os.path.join("/etc/audit/rules.d", rf))

    su_audited = "/usr/bin/su" in audit_rules_text or "/bin/su" in audit_rules_text
    results.append(_r(
        cat, "Pass" if su_audited else "Warning",
        "ISM-0586: su/sudo command execution audited",
        severity="Medium",
        details=f"su audit rules: {su_audited}",
        remediation=(
            "Add to /etc/audit/rules.d/30-priv.rules: "
            "-a always,exit -F path=/usr/bin/su -F perm=x -k priv_esc; "
            "-a always,exit -F path=/usr/bin/sudo -F perm=x -k priv_esc"
        ),
        cross_references={
            "ACSC": "ISM-0586", "NIST": "AU-2", "STIG": "V-230423",
        },
    ))

    return results


def _check_ism_malware(os_info) -> List[AuditResult]:
    """ISM malware protection (1417, 1418)."""
    results: List[AuditResult] = []
    cat = "ACSC - ISM Malware"

    # ISM-1417 Anti-malware/EDR present
    edr_present = (
        command_available("clamscan") or
        file_exists("/opt/sophos-spl/bin/sophos_threat_detector") or
        file_exists("/opt/CrowdStrike/falcon-sensor") or
        file_exists("/opt/microsoft/mdatp/sbin/wdavdaemon") or
        command_available("falco") or
        file_exists("/var/ossec/etc/ossec.conf")
    )
    results.append(_r(
        cat, "Pass" if edr_present else "Fail",
        "ISM-1417: Anti-malware/EDR solution deployed",
        severity="High",
        details=f"EDR detected: {edr_present}",
        remediation=(
            "Deploy enterprise EDR or open-source equivalent: "
            "Wazuh agent + ClamAV, or Falco for runtime detection."
        ),
        cross_references={
            "ACSC": "ISM-1417", "NIST": "SI-3", "PCI-DSS": "5.2",
        },
    ))

    # ISM-1418 Malware definitions updated (ClamAV freshclam)
    if command_available("freshclam"):
        freshclam_active = (
            systemd_active("clamav-freshclam.service") == "active" or
            systemd_active("clamd.service") == "active"
        )
        results.append(_r(
            cat, "Pass" if freshclam_active else "Warning",
            "ISM-1418: ClamAV signature update service active",
            severity="Medium",
            details=f"freshclam service: {freshclam_active}",
            remediation=remediation_for("clamav"),
            cross_references={
                "ACSC": "ISM-1418", "NIST": "SI-3(2)",
            },
        ))

    return results


def _check_ism_patch_management(os_info) -> List[AuditResult]:
    """ISM patch management deeper."""
    results: List[AuditResult] = []
    cat = "ACSC - ISM Patch Management"

    # ISM-1493 Critical patches within 48 hours
    auto_patch = (
        systemd_active("unattended-upgrades.service") == "active" or
        systemd_active("dnf-automatic-install.timer") == "active"
    )
    results.append(_r(
        cat, "Pass" if auto_patch else "Fail",
        "ISM-1493: Automated patching for critical vulnerabilities",
        severity="High",
        details=f"Auto-patching active: {auto_patch}",
        remediation=(
            "Debian: apt-get install -y unattended-upgrades. "
            "RHEL: dnf install -y dnf-automatic && "
            "systemctl enable --now dnf-automatic-install.timer."
        ),
        cross_references={
            "ACSC": "ISM-1493", "NIST": "SI-2(5)", "PCI-DSS": "6.3.3",
        },
    ))

    # ISM-1494 Patch inventory
    pkg_inv_available = (
        command_available("dpkg") or
        command_available("rpm") or
        command_available("pacman") or
        command_available("apk")
    )
    results.append(_r(
        cat, "Pass" if pkg_inv_available else "Fail",
        "ISM-1494: Package inventory capability for patch tracking",
        severity="Medium",
        details=f"Package manager available: {pkg_inv_available}",
        cross_references={
            "ACSC": "ISM-1494", "NIST": "CM-8",
        },
    ))

    return results


def _check_ism_application_control_extended(os_info) -> List[AuditResult]:
    """Essential Eight ML2/ML3 application control depth."""
    results: List[AuditResult] = []
    cat = "ACSC - E8.1 ML2/ML3 App Control"

    # E8.1 ML2 - Application control on workstations
    fapolicyd_active = systemd_active("fapolicyd.service") == "active"
    apparmor_enforce = False
    if command_available("aa-status"):
        rc, out, _ = run_command(["aa-status"])
        if rc == 0:
            m = re.search(r"(\d+)\s+profiles? are in enforce", out)
            if m and int(m.group(1)) >= 30:
                apparmor_enforce = True

    selinux_enforce = False
    if file_exists("/sys/fs/selinux/enforce"):
        try:
            with open("/sys/fs/selinux/enforce", "r") as f:
                selinux_enforce = f.read().strip() == "1"
        except OSError:
            pass

    app_control = fapolicyd_active or apparmor_enforce or selinux_enforce
    results.append(_r(
        cat, "Pass" if app_control else "Fail",
        "E8.1 ML2: Application control via fapolicyd/AppArmor/SELinux",
        severity="High",
        details=(
            f"fapolicyd: {fapolicyd_active}, "
            f"AppArmor enforcing >=30: {apparmor_enforce}, "
            f"SELinux enforce: {selinux_enforce}"
        ),
        remediation=(
            "RHEL: dnf install -y fapolicyd && systemctl enable --now fapolicyd. "
            "Ubuntu: AppArmor profiles for all daemons. "
            "Or SELinux enforcing mode."
        ),
        cross_references={
            "ACSC": "E8.1-ML2", "NIST": "CM-7(5)", "CIS": "1.6.1",
        },
    ))

    return results


def _check_ism_data_at_rest_extended(os_info) -> List[AuditResult]:
    """ISM data at rest extended."""
    results: List[AuditResult] = []
    cat = "ACSC - ISM Data at Rest"

    # ISM-1517 Encrypted swap
    swap_encrypted = False
    if command_available("swapon"):
        rc, out, _ = run_command(["swapon", "--show=NAME,TYPE"], timeout=3.0)
        if rc == 0:
            for line in out.splitlines()[1:]:
                fields = line.split()
                if len(fields) >= 1:
                    name = fields[0]
                    if "crypt" in name.lower() or "/dev/dm-" in name or "/dev/mapper" in name:
                        swap_encrypted = True
                        break

    # If no swap, this isn't a finding
    has_swap = False
    if command_available("swapon"):
        rc, out, _ = run_command(["swapon", "--show"], timeout=3.0)
        if rc == 0 and out.strip():
            has_swap = True

    if has_swap:
        results.append(_r(
            cat, "Pass" if swap_encrypted else "Warning",
            "ISM-1517: Swap is encrypted",
            severity="Medium",
            details=f"Swap present: {has_swap}, encrypted: {swap_encrypted}",
            remediation=(
                "Configure /etc/crypttab for encrypted swap, then "
                "edit /etc/fstab to use /dev/mapper/cryptswap"
            ),
            cross_references={
                "ACSC": "ISM-1517", "NIST": "SC-28",
            },
        ))
    else:
        results.append(_r(
            cat, "Pass",
            "ISM-1517: No swap configured (no encryption needed)",
            severity="Informational",
            details="No active swap",
            cross_references={
                "ACSC": "ISM-1517", "NIST": "SC-28",
            },
        ))

    return results


# Save reference to original
_original_run_checks_acsc = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the expanded ACSC module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_acsc(shared_data)

    os_info = shared_data.get("v3_os_info")
    if os_info is None:
        os_info = os_detection.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        results.extend(_check_ism_cryptography(os_info))
        results.extend(_check_ism_network_hardening(os_info))
        results.extend(_check_ism_access_control(os_info))
        results.extend(_check_ism_event_logging_extended(os_info))
        results.extend(_check_ism_malware(os_info))
        results.extend(_check_ism_patch_management(os_info))
        results.extend(_check_ism_application_control_extended(os_info))
        results.extend(_check_ism_data_at_rest_extended(os_info))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled exception in ACSC v3.1 expansion")
        results.append(_r(
            "ACSC - Error", "Error",
            f"ACSC v3.1 expansion exception: {exc!r}",
            severity="Medium", details=str(exc),
        ))

    return results

# ===========================================================================
# v3.2 EXPANSION - ACSC Essential Eight ML3 + ISM Deep Coverage
# ---------------------------------------------------------------------------
# Adds:
#   - Essential Eight ML3 (Maturity Level 3) controls
#   - ISM Web Hardening
#   - ISM Email Hardening
#   - ISM Server Hardening
#   - ISM Database Hardening
#   - ISM Virtualization
#   - ISM Data Sanitization
# ===========================================================================


def _check_acsc_e8_ml3(os_info) -> List[AuditResult]:
    """Essential Eight ML3 (highest maturity) advanced controls."""
    results: List[AuditResult] = []
    cat = "ACSC - E8 ML3 Advanced"

    fapolicyd_active = systemd_active("fapolicyd.service") == "active"
    selinux_enforcing = False
    if file_exists("/sys/fs/selinux/enforce"):
        try:
            with open("/sys/fs/selinux/enforce", "r") as f:
                selinux_enforcing = f.read().strip() == "1"
        except OSError:
            pass

    apparmor_strict = False
    if command_available("aa-status"):
        rc, out, _ = run_command(["aa-status"], timeout=5.0)
        if rc == 0:
            enforce_match = re.search(r"(\d+)\s+profiles? are in enforce mode", out)
            enforce = int(enforce_match.group(1)) if enforce_match else 0
            apparmor_strict = enforce >= 30

    ml3_app_control = fapolicyd_active or selinux_enforcing or apparmor_strict
    results.append(_r(
        cat, "Pass" if ml3_app_control else "Fail",
        "ML3-E8.1: Kernel-enforced application control (MAC-level)",
        severity="High",
        details=(
            f"fapolicyd: {fapolicyd_active}, "
            f"SELinux enforcing: {selinux_enforcing}, "
            f"AppArmor strict: {apparmor_strict}"
        ),
        remediation=(
            "Deploy MAC-level application control: SELinux enforcing on RHEL "
            "family, fapolicyd allowlist, or AppArmor with 30+ profiles enforcing."
        ),
        cross_references={
            "ACSC": "E8.1-ML3", "NIST": "CM-7(5)", "ISO27001": "A.8.31",
            "STIG": "V-230223",
        },
    ))

    auto_patch_active = (
        systemd_active("unattended-upgrades.service") == "active" or
        systemd_active("dnf-automatic-install.timer") == "active"
    )
    results.append(_r(
        cat, "Pass" if auto_patch_active else "Fail",
        "ML3-E8.2: Automated application patching active",
        severity="High",
        details=f"Automated patching service: {auto_patch_active}",
        remediation=(
            "Enable unattended-upgrades (Debian/Ubuntu) or dnf-automatic-install "
            "(RHEL family). ML3 requires 48-hour patch SLA for criticals."
        ),
        cross_references={
            "ACSC": "E8.2-ML3", "NIST": "SI-2(5)", "PCI-DSS": "6.3.3",
        },
    ))

    sudoers_combined = read_file_safe("/etc/sudoers")
    for f in list_directory("/etc/sudoers.d"):
        if f != "README":
            sudoers_combined += "\n" + read_file_safe(
                os.path.join("/etc/sudoers.d", f)
            )
    timestamp_timeout_match = re.search(
        r"^\s*Defaults\s+timestamp_timeout\s*=\s*(-?\d+)",
        sudoers_combined, re.MULTILINE
    )
    timeout_val = (
        int(timestamp_timeout_match.group(1)) if timestamp_timeout_match else 5
    )
    timeout_ok = 0 <= timeout_val <= 15
    results.append(_r(
        cat, "Pass" if timeout_ok else "Warning",
        f"ML3-E8.5: sudo timestamp_timeout <= 15 minutes (currently {timeout_val})",
        severity="Medium",
        details=f"timestamp_timeout = {timeout_val} minutes",
        remediation=(
            "In /etc/sudoers (visudo): Defaults timestamp_timeout=15 (or 0 to "
            "force re-auth every command). ML3 requires JIT privileged access."
        ),
        cross_references={
            "ACSC": "E8.5-ML3", "NIST": "AC-2(11)", "ISM": "1175",
        },
    ))

    results.append(_r(
        cat, "Pass" if auto_patch_active else "Fail",
        "ML3-E8.6: Automated OS patching with 48hr SLA capability",
        severity="High",
        details=(
            f"Automation present: {auto_patch_active}. "
            "Coupled with vendor advisory feed for SLA tracking."
        ),
        cross_references={
            "ACSC": "E8.6-ML3", "NIST": "SI-2(2)",
        },
    ))

    pam_files = ["/etc/pam.d/sshd", "/etc/pam.d/system-auth", "/etc/pam.d/common-auth"]
    phishing_resistant_modules = ["pam_u2f", "pam_pkcs11", "pam_yubico"]
    detected_resistant = set()
    for pf in pam_files:
        c = read_file_safe(pf)
        if not c:
            continue
        for mod in phishing_resistant_modules:
            if mod + ".so" in c:
                detected_resistant.add(mod.replace("pam_", ""))

    results.append(_r(
        cat, "Pass" if detected_resistant else "Warning",
        f"ML3-E8.7: Phishing-resistant MFA configured ({len(detected_resistant)})",
        severity="High",
        details=f"Detected: {sorted(detected_resistant) or 'none'}",
        remediation=(
            "Install pam_u2f for FIDO2/WebAuthn: apt-get install -y libpam-u2f. "
            "Or pam_pkcs11 for smartcard. ML3 requires phishing-resistant MFA."
        ),
        cross_references={
            "ACSC": "E8.7-ML3", "NIST": "IA-2(11)", "ISM": "1559",
        },
    ))

    backup_tools_immutable = {
        "borg": command_available("borg"),
        "restic": command_available("restic"),
        "duplicity-gpg": command_available("duplicity") and command_available("gpg"),
    }
    detected_immut = [k for k, v in backup_tools_immutable.items() if v]
    results.append(_r(
        cat, "Pass" if detected_immut else "Info",
        f"ML3-E8.8: Cryptographic immutable backup capability ({len(detected_immut)})",
        severity="Medium",
        details=f"Detected: {detected_immut or 'none'}",
        remediation=(
            "Borg or restic provide deduplication + encryption + immutability. "
            "ML3 requires monthly restore testing of backups."
        ),
        cross_references={
            "ACSC": "E8.8-ML3", "NIST": "CP-9(8)", "ISO27001": "A.8.13",
        },
    ))

    return results


def _check_acsc_ism_web_hardening(os_info) -> List[AuditResult]:
    """ACSC ISM Web Server Hardening."""
    results: List[AuditResult] = []
    cat = "ACSC ISM - Web Hardening"

    apache_dirs = directory_exists("/etc/apache2") or directory_exists("/etc/httpd")
    nginx_dir = directory_exists("/etc/nginx")

    if apache_dirs:
        configs = [
            "/etc/apache2/apache2.conf",
            "/etc/apache2/conf-enabled/security.conf",
            "/etc/httpd/conf/httpd.conf",
        ]
        has_no_indexes = False
        for c in configs:
            content = read_file_safe(c)
            if "Options" in content and "-Indexes" in content:
                has_no_indexes = True
                break
        results.append(_r(
            cat, "Pass" if has_no_indexes else "Warning",
            "ISM-1424: Apache directory listing disabled",
            severity="Medium",
            details=f"'-Indexes' directive present in main config: {has_no_indexes}",
            remediation=(
                "In /etc/apache2/apache2.conf or httpd.conf within <Directory>: "
                "Options -Indexes -FollowSymLinks"
            ),
            cross_references={
                "ACSC": "ISM-1424", "NIST": "SC-5",
            },
        ))

    if nginx_dir:
        nginx_main = read_file_safe("/etc/nginx/nginx.conf")
        autoindex_on = re.search(
            r"autoindex\s+on\s*;", nginx_main
        ) is not None
        results.append(_r(
            cat, "Pass" if not autoindex_on else "Fail",
            "ISM-1424: Nginx autoindex directive disabled",
            severity="Medium",
            details=f"autoindex on detected in main config: {autoindex_on}",
            remediation=(
                "Default is 'off'. Remove 'autoindex on' from nginx.conf."
            ),
            cross_references={
                "ACSC": "ISM-1424", "NIST": "SC-5",
            },
        ))

    if apache_dirs or nginx_dir:
        hsts_indicator = False
        configs_to_search = [
            "/etc/nginx/nginx.conf",
            "/etc/apache2/conf-enabled/security.conf",
        ]
        for path in configs_to_search:
            if file_exists(path):
                if "Strict-Transport-Security" in read_file_safe(path):
                    hsts_indicator = True
                    break
        # Check sites-enabled directories
        for sd in ["/etc/apache2/sites-enabled", "/etc/httpd/conf.d", "/etc/nginx/sites-enabled"]:
            if directory_exists(sd):
                for f in list_directory(sd):
                    if "Strict-Transport-Security" in read_file_safe(os.path.join(sd, f)):
                        hsts_indicator = True
                        break
            if hsts_indicator:
                break

        results.append(_r(
            cat, "Pass" if hsts_indicator else "Warning",
            "ISM-1247: HTTP Strict Transport Security header configured",
            severity="High",
            details=f"HSTS header detected in web server config: {hsts_indicator}",
            remediation=(
                "Apache: Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\". "
                "Nginx: add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"
            ),
            cross_references={
                "ACSC": "ISM-1247", "NIST": "SC-8",
            },
        ))

    return results


def _check_acsc_ism_email_hardening(os_info) -> List[AuditResult]:
    """ACSC ISM Email Hardening."""
    results: List[AuditResult] = []
    cat = "ACSC ISM - Email Hardening"

    postfix_main = read_file_safe("/etc/postfix/main.cf")
    if not postfix_main:
        return results

    smtpd_tls_match = re.search(
        r"^\s*smtpd_tls_security_level\s*=\s*(\w+)", postfix_main, re.MULTILINE
    )
    smtpd_tls = smtpd_tls_match.group(1).lower() if smtpd_tls_match else "none"
    smtpd_ok = smtpd_tls in ("encrypt", "may")
    results.append(_r(
        cat, "Pass" if smtpd_ok else "Fail",
        f"ISM-1234: Postfix smtpd_tls_security_level: {smtpd_tls}",
        severity="High",
        details=f"smtpd_tls_security_level = {smtpd_tls}",
        remediation=(
            "In /etc/postfix/main.cf: smtpd_tls_security_level = may "
            "(opportunistic) or encrypt (forced)"
        ),
        cross_references={
            "ACSC": "ISM-1234", "NIST": "SC-8(1)", "PCI-DSS": "4.2.1",
        },
    ))

    smtp_tls_match = re.search(
        r"^\s*smtp_tls_security_level\s*=\s*(\w+)", postfix_main, re.MULTILINE
    )
    smtp_tls = smtp_tls_match.group(1).lower() if smtp_tls_match else "none"
    smtp_ok = smtp_tls in ("encrypt", "verify", "secure")
    results.append(_r(
        cat, "Pass" if smtp_ok else "Warning",
        f"ISM-1789: Postfix smtp_tls_security_level: {smtp_tls}",
        severity="High",
        details=f"smtp_tls_security_level = {smtp_tls}",
        remediation=(
            "In /etc/postfix/main.cf: smtp_tls_security_level = encrypt "
            "(minimum) or verify"
        ),
        cross_references={
            "ACSC": "ISM-1789", "NIST": "SC-8(1)",
        },
    ))

    email_filter_tools = {
        "opendkim": file_exists("/etc/opendkim.conf") or systemd_active("opendkim.service") == "active",
        "opendmarc": file_exists("/etc/opendmarc.conf") or systemd_active("opendmarc.service") == "active",
        "policyd-spf": command_available("policyd-spf"),
        "rspamd": file_exists("/etc/rspamd/rspamd.conf") or systemd_active("rspamd.service") == "active",
        "spamassassin": systemd_active("spamassassin.service") == "active",
    }
    detected = [k for k, v in email_filter_tools.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Warning",
        f"ISM-0561: Email authentication filtering tools ({len(detected)})",
        severity="High",
        details=f"Detected: {detected or 'none'}",
        remediation=(
            "Install opendkim+opendmarc+policyd-spf for full SPF/DKIM/DMARC. "
            "Or rspamd for integrated filtering."
        ),
        cross_references={
            "ACSC": "ISM-0561", "NIST": "SI-8",
        },
    ))

    return results


def _check_acsc_ism_server_hardening(os_info) -> List[AuditResult]:
    """ACSC ISM Server Hardening."""
    results: List[AuditResult] = []
    cat = "ACSC ISM - Server Hardening"

    rc, out, _ = run_command(
        ["systemctl", "list-unit-files", "--type=service",
         "--state=enabled", "--no-legend", "--no-pager"], timeout=10.0
    )
    enabled_count = 0
    if rc == 0 and out:
        enabled_count = sum(1 for line in out.splitlines() if line.strip())
    results.append(_r(
        cat, "Pass" if enabled_count <= 60 else "Info",
        f"ISM-0380: Service minimization: {enabled_count} enabled",
        severity="Medium",
        details=f"Enabled services count: {enabled_count}",
        remediation=(
            "Review and disable unused services. Servers should be "
            "single-purpose where possible."
        ),
        cross_references={
            "ACSC": "ISM-0380", "NIST": "CM-7", "CIS": "2",
        },
    ))

    sshd_config = read_file_safe("/etc/ssh/sshd_config")
    permit_root = re.search(
        r"^\s*PermitRootLogin\s+(\S+)", sshd_config, re.MULTILINE
    )
    permit_root_val = permit_root.group(1).lower() if permit_root else "yes"
    permit_root_ok = permit_root_val in ("no", "without-password", "prohibit-password",
                                          "forced-commands-only")
    results.append(_r(
        cat, "Pass" if permit_root_ok else "Fail",
        f"ISM-1480: SSH PermitRootLogin restricted ({permit_root_val})",
        severity="High",
        details=f"PermitRootLogin = {permit_root_val}",
        remediation=(
            "In /etc/ssh/sshd_config: PermitRootLogin no  "
            "(or 'without-password' for key-only root)"
        ),
        cross_references={
            "ACSC": "ISM-1480", "NIST": "AC-6(2)", "STIG": "V-230327",
        },
    ))

    client_alive_match = re.search(
        r"^\s*ClientAliveInterval\s+(\d+)", sshd_config, re.MULTILINE
    )
    interval = int(client_alive_match.group(1)) if client_alive_match else 0
    timeout_ok = 0 < interval <= 600
    results.append(_r(
        cat, "Pass" if timeout_ok else "Fail",
        f"ISM-1416: SSH ClientAliveInterval <= 600 seconds (currently {interval})",
        severity="Medium",
        details=f"ClientAliveInterval = {interval}",
        remediation=(
            "In /etc/ssh/sshd_config: ClientAliveInterval 300; ClientAliveCountMax 0"
        ),
        cross_references={
            "ACSC": "ISM-1416", "NIST": "AC-12", "STIG": "V-230244",
        },
    ))

    auditd_conf = read_file_safe("/etc/audit/auditd.conf")
    max_log_match = re.search(
        r"^\s*max_log_file\s*=\s*(\d+)", auditd_conf, re.MULTILINE
    )
    max_log = int(max_log_match.group(1)) if max_log_match else 0
    log_size_ok = max_log >= 8
    results.append(_r(
        cat, "Pass" if log_size_ok else "Warning",
        f"ISM-1554: Auditd max_log_file size adequate ({max_log} MB)",
        severity="Medium",
        details=f"max_log_file = {max_log} MB",
        remediation=(
            "In /etc/audit/auditd.conf: max_log_file = 50  (50MB before rotation)"
        ),
        cross_references={
            "ACSC": "ISM-1554", "NIST": "AU-4",
        },
    ))

    return results


def _check_acsc_ism_database(os_info) -> List[AuditResult]:
    """ACSC ISM Database Hardening."""
    results: List[AuditResult] = []
    cat = "ACSC ISM - Database"

    dbs = {
        "mariadb": file_exists("/etc/my.cnf") or directory_exists("/etc/mysql"),
        "postgresql": directory_exists("/etc/postgresql") or directory_exists(
            "/var/lib/pgsql"
        ),
        "mongodb": file_exists("/etc/mongod.conf"),
        "redis": file_exists("/etc/redis/redis.conf") or file_exists("/etc/redis.conf"),
    }
    detected_dbs = [k for k, v in dbs.items() if v]

    if not detected_dbs:
        results.append(_r(
            cat, "Info",
            "ISM-1264: No databases detected on host",
            severity="Informational",
            details="No DB config files present",
            cross_references={"ACSC": "ISM-1264"},
        ))
        return results

    results.append(_r(
        cat, "Info",
        f"ISM-1264: Database services detected: {', '.join(detected_dbs)}",
        severity="Informational",
        details=f"Databases: {detected_dbs}",
        cross_references={
            "ACSC": "ISM-1264", "NIST": "AC-3",
        },
    ))

    if dbs["postgresql"]:
        pg_conf = ""
        for v in ["13", "14", "15", "16"]:
            p = f"/etc/postgresql/{v}/main/postgresql.conf"
            if file_exists(p):
                pg_conf = read_file_safe(p)
                break
        if not pg_conf:
            pg_conf = read_file_safe("/var/lib/pgsql/data/postgresql.conf")
        if pg_conf:
            ssl_on = re.search(r"^\s*ssl\s*=\s*on", pg_conf, re.MULTILINE)
            results.append(_r(
                cat, "Pass" if ssl_on else "Warning",
                "ISM-1278: PostgreSQL SSL enabled",
                severity="High",
                details=f"ssl = on detected: {bool(ssl_on)}",
                remediation=(
                    "In postgresql.conf: ssl = on; "
                    "ssl_cert_file = '/etc/ssl/certs/postgresql.crt'; "
                    "ssl_key_file = '/etc/ssl/private/postgresql.key'"
                ),
                cross_references={
                    "ACSC": "ISM-1278", "NIST": "SC-8(1)",
                },
            ))

    if dbs["mariadb"]:
        my_cnf = read_file_safe("/etc/mysql/mariadb.conf.d/50-server.cnf") or \
                read_file_safe("/etc/my.cnf") or \
                read_file_safe("/etc/mysql/my.cnf")
        bind_match = re.search(
            r"^\s*bind-address\s*=\s*(\S+)", my_cnf, re.MULTILINE
        )
        bind_addr = bind_match.group(1) if bind_match else "0.0.0.0"
        local_bind = bind_addr in ("127.0.0.1", "::1", "localhost")
        results.append(_r(
            cat, "Pass" if local_bind else "Info",
            f"ISM-1278: MariaDB bind-address = {bind_addr}",
            severity="Medium",
            details=f"bind-address = {bind_addr}",
            remediation=(
                "Set bind-address = 127.0.0.1 unless remote DB access required. "
                "If remote required, use TLS/SSL for connections."
            ),
            cross_references={
                "ACSC": "ISM-1278", "NIST": "SC-7",
            },
        ))

    if dbs["redis"]:
        redis_conf = read_file_safe("/etc/redis/redis.conf") or read_file_safe(
            "/etc/redis.conf"
        )
        bind_local = bool(re.search(
            r"^\s*bind\s+(127\.0\.0\.1|::1|localhost)",
            redis_conf, re.MULTILINE
        ))
        protected = bool(re.search(
            r"^\s*protected-mode\s+yes", redis_conf, re.MULTILINE
        ))
        results.append(_r(
            cat, "Pass" if (bind_local or protected) else "Fail",
            "ISM-1278: Redis network exposure restricted",
            severity="High",
            details=f"bind to localhost: {bind_local}, protected-mode yes: {protected}",
            remediation=(
                "In /etc/redis/redis.conf: bind 127.0.0.1 ::1; protected-mode yes"
            ),
            cross_references={
                "ACSC": "ISM-1278", "NIST": "SC-7",
            },
        ))

    return results


def _check_acsc_ism_virtualization(os_info) -> List[AuditResult]:
    """ACSC ISM Virtualization controls."""
    results: List[AuditResult] = []
    cat = "ACSC ISM - Virtualization"

    virt_indicators = {
        "kvm-qemu": file_exists("/dev/kvm") and command_available("qemu-system-x86_64"),
        "libvirtd": systemd_active("libvirtd.service") == "active",
        "lxc": command_available("lxc-create") or command_available("lxd"),
        "podman": command_available("podman"),
        "docker": command_available("docker"),
        "containerd": systemd_active("containerd.service") == "active",
        "kubelet": command_available("kubelet"),
    }
    detected = [k for k, v in virt_indicators.items() if v]
    if detected:
        results.append(_r(
            cat, "Info",
            f"ISM-1462: Virtualization/container platforms detected: {detected}",
            severity="Informational",
            details=f"Detected: {detected}",
            cross_references={
                "ACSC": "ISM-1462", "NIST": "SC-7",
            },
        ))

        if "docker" in detected:
            docker_daemon = read_file_safe("/etc/docker/daemon.json")
            has_userns = "userns-remap" in docker_daemon
            has_no_new_priv = "no-new-privileges" in docker_daemon
            results.append(_r(
                cat, "Pass" if (has_userns or has_no_new_priv) else "Warning",
                "ISM-1604: Docker daemon hardening configured",
                severity="High",
                details=(
                    f"userns-remap: {has_userns}, no-new-privileges: {has_no_new_priv}"
                ),
                remediation=(
                    "Edit /etc/docker/daemon.json: "
                    "{\"userns-remap\": \"default\", \"no-new-privileges\": true, "
                    "\"icc\": false, \"log-driver\": \"json-file\"}"
                ),
                cross_references={
                    "ACSC": "ISM-1604", "NIST": "SC-39", "CIS-Docker": "2.8",
                },
            ))

    return results


def _check_acsc_ism_data_sanitization(os_info) -> List[AuditResult]:
    """ACSC ISM Data Sanitization."""
    results: List[AuditResult] = []
    cat = "ACSC ISM - Data Sanitization"

    sanitization_tools = {
        "shred": command_available("shred"),
        "wipe": command_available("wipe"),
        "scrub": command_available("scrub"),
        "blkdiscard": command_available("blkdiscard"),
        "hdparm": command_available("hdparm"),
        "nvme": command_available("nvme"),
    }
    detected = [k for k, v in sanitization_tools.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Warning",
        f"ISM-0307: Data sanitization tooling ({len(detected)} found)",
        severity="Medium",
        details=f"Detected: {detected}",
        remediation=(
            "Install: apt-get install -y coreutils secure-delete hdparm nvme-cli. "
            "shred for files, blkdiscard for SSDs, hdparm/nvme for full-device wipe."
        ),
        cross_references={
            "ACSC": "ISM-0307", "NIST": "MP-6",
        },
    ))

    crypttab = read_file_safe("/etc/crypttab")
    swap_encrypted_tab = "swap" in crypttab.lower()

    rc, out, _ = run_command(["swapon", "--show"], timeout=3.0)
    has_swap = rc == 0 and out and len(out.splitlines()) > 1

    if has_swap:
        results.append(_r(
            cat, "Pass" if swap_encrypted_tab else "Warning",
            f"ISM-1217: Swap encryption configured: {swap_encrypted_tab}",
            severity="High",
            details=f"Swap detected: {has_swap}, encrypted via crypttab: {swap_encrypted_tab}",
            remediation=(
                "Add encrypted swap entry to /etc/crypttab: "
                "swap /dev/sda3 /dev/urandom swap,cipher=aes-xts-plain64,size=256"
            ),
            cross_references={
                "ACSC": "ISM-1217", "NIST": "SC-28",
            },
        ))

    return results


def _check_acsc_ism_software_dev(os_info) -> List[AuditResult]:
    """ACSC ISM Software Development indicators."""
    results: List[AuditResult] = []
    cat = "ACSC ISM - Software Dev"

    sca_tools = {
        "trivy": command_available("trivy"),
        "grype": command_available("grype"),
        "syft": command_available("syft"),
        "snyk": command_available("snyk"),
        "dependency-check": command_available("dependency-check.sh") or command_available("dependency-check"),
        "bandit": command_available("bandit"),
        "safety": command_available("safety"),
        "semgrep": command_available("semgrep"),
    }
    detected = [k for k, v in sca_tools.items() if v]
    if detected:
        results.append(_r(
            cat, "Info",
            f"ISM-1685: Software composition analysis tools ({len(detected)})",
            severity="Informational",
            details=f"Detected: {detected}",
            remediation=(
                "Integrate SCA into CI: trivy fs --security-checks vuln,config /path"
            ),
            cross_references={
                "ACSC": "ISM-1685", "NIST": "SR-3",
            },
        ))

    return results


# Save reference to existing run_checks
_original_run_checks_acsc_v32 = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the v3.2 expanded ACSC module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_acsc_v32(shared_data)

    os_info = shared_data.get("v3_os_info")
    if os_info is None:
        os_info = os_detection.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        results.extend(_check_acsc_e8_ml3(os_info))
        results.extend(_check_acsc_ism_web_hardening(os_info))
        results.extend(_check_acsc_ism_email_hardening(os_info))
        results.extend(_check_acsc_ism_server_hardening(os_info))
        results.extend(_check_acsc_ism_database(os_info))
        results.extend(_check_acsc_ism_virtualization(os_info))
        results.extend(_check_acsc_ism_data_sanitization(os_info))
        results.extend(_check_acsc_ism_software_dev(os_info))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled exception in ACSC v3.2 expansion")
        results.append(_r(
            "ACSC - Error", "Error",
            f"ACSC v3.2 expansion exception: {exc!r}",
            severity="Medium", details=str(exc),
        ))

    return results


# ============================================================================
# v3.5 EXPANSION - ACSC Essential Eight ML3 Depth + ISM Advanced
# ----------------------------------------------------------------------------
# Synopsis:
#   Adds depth across Essential Eight ML3 maturity and Information Security
#   Manual (ISM) topics not yet addressed:
#     - E8.1 ML3 application control (cryptographic verification)
#     - E8.5 ML3 admin restriction (just-in-time, separate accounts)
#     - E8.7 ML3 phishing-resistant MFA (FIDO2/WebAuthn)
#     - ISM cryptographic algorithm conformance (ASD-Approved)
#     - ISM network segmentation indicators
#     - ISM logging centralization and retention
#     - ISM vulnerability management (CISA KEV monitoring)
#     - ISM CVSS 9.0+ patching within 48 hours
#     - ISM account separation (privileged vs interactive)
#     - ISM email hardening (DKIM/DMARC/SPF presence)
#     - ISM physical / BIOS hardening indicators
#     - ISM incident response readiness
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


def _v35_acsc_result(category, status, message, severity="Medium",
                    details="", remediation="", cross_references=None):
    """Build AuditResult for ACSC v3.5 expansion."""
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


def _check_acsc_v35_e8_ml3_depth(os_info):
    """Essential Eight ML3 maturity depth."""
    results = []
    cat = "ACSC v3.5 - E8 ML3"

    # E8.1 ML3 - Cryptographic verification of executables (signed binaries)
    # Indicator: dpkg-verify or rpm -Va summary
    sig_verify_indicators = []
    if _v35_command_available("dpkg-sig"):
        sig_verify_indicators.append("dpkg-sig")
    if _v35_command_available("rpm"):
        # rpm has built-in signature verification at install time
        rc, out, _ = _v35_run_command(
            ["rpm", "-q", "--qf", "%{SIGPGP:pgpsig}\n", "rpm"],
            timeout=5.0,
        )
        if rc == 0 and out and "Key ID" in out:
            sig_verify_indicators.append("rpm-pgpsig")
    if _v35_file_exists("/etc/apt/trusted.gpg.d") or _v35_directory_exists(
            "/etc/apt/keyrings"):
        sig_verify_indicators.append("apt-keyring")
    # Application control via fapolicyd / AppArmor profile enforcement
    fapolicyd_active = _v35_systemd_active("fapolicyd.service") == "active"
    apparmor_enforced_count = 0
    if _v35_command_available("aa-status"):
        rc, out, _ = _v35_run_command(["aa-status", "--profiled"], timeout=5.0)
        if rc == 0 and out and out.strip().isdigit():
            apparmor_enforced_count = int(out.strip())
    cryptographic_app_control = (
        bool(sig_verify_indicators) and
        (fapolicyd_active or apparmor_enforced_count > 5)
    )
    results.append(_v35_acsc_result(
        f"{cat} - E8.1 ML3 Crypto App Control",
        "Pass" if cryptographic_app_control else "Info",
        f"E8.1 ML3 Cryptographic application verification: "
        f"{cryptographic_app_control}",
        severity="High",
        details=(
            f"Signature verification: {sig_verify_indicators}, "
            f"fapolicyd: {fapolicyd_active}, "
            f"apparmor profiles: {apparmor_enforced_count}"
        ),
        remediation=(
            "ML3 requires application control mechanism that uses "
            "cryptographic signing AND publisher trust to verify executables.\n"
            f"{remediation_for('fapolicyd') if not fapolicyd_active else ''}"
        ),
        cross_references={
            "ACSC-E8": "1 ML3", "NIST": "CM-7(5), SI-7(15)",
            "PCI-DSS": "11.5.2",
        },
    ))

    # E8.5 ML3 - Restrict administrative privileges (just-in-time, separate)
    # Indicators: no-password sudo NOT allowed; sudoers with TIMEOUT;
    # separate admin account
    sudoers_content = _v35_read_file_safe("/etc/sudoers")
    sudoers_d = ""
    if _v35_directory_exists("/etc/sudoers.d"):
        for f in _v35_list_directory("/etc/sudoers.d"):
            if f != "README":
                sudoers_d += "\n" + _v35_read_file_safe(
                    os.path.join("/etc/sudoers.d", f)
                )
    full_sudoers = sudoers_content + "\n" + sudoers_d
    # NOPASSWD count (should be minimal)
    nopasswd_count = len(
        [l for l in full_sudoers.splitlines()
         if "NOPASSWD" in l and not l.strip().startswith("#")]
    )
    # timestamp_timeout setting (lower is more secure)
    timestamp_timeout_match = re.search(
        r"^\s*Defaults\s+timestamp_timeout\s*=\s*(-?\d+)",
        full_sudoers, re.MULTILINE,
    )
    timestamp_timeout = (
        int(timestamp_timeout_match.group(1))
        if timestamp_timeout_match else 5  # default 5 min
    )
    timestamp_strict = 0 < timestamp_timeout <= 5
    results.append(_v35_acsc_result(
        f"{cat} - E8.5 ML3 Admin Restriction",
        "Pass" if (nopasswd_count <= 1 and timestamp_strict) else "Warning",
        f"E8.5 ML3 sudo NOPASSWD: {nopasswd_count}, timeout: {timestamp_timeout}m",
        severity="High",
        details=(
            f"NOPASSWD entries: {nopasswd_count}, "
            f"timestamp_timeout: {timestamp_timeout}"
        ),
        remediation=(
            "Reduce NOPASSWD grants. Add to /etc/sudoers:\n"
            "  Defaults timestamp_timeout=5\n"
            "ML3 requires reauthentication frequently and minimal "
            "passwordless privilege escalation."
        ),
        cross_references={
            "ACSC-E8": "5 ML3", "NIST": "AC-6(5)",
            "PCI-DSS": "7.2.2",
        },
    ))

    # E8.7 ML3 - Phishing-resistant MFA for admin access
    # Indicators: pam_u2f, pam_yubico, FIDO2 webauthn
    phishing_resistant = []
    pam_files = [
        "/etc/pam.d/sshd", "/etc/pam.d/common-auth",
        "/etc/pam.d/system-auth", "/etc/pam.d/password-auth",
    ]
    for pf in pam_files:
        c = _v35_read_file_safe(pf)
        for mod_name, label in [
            ("pam_u2f", "FIDO/U2F"),
            ("pam_yubico", "Yubico"),
            ("pam_fido2", "FIDO2"),
        ]:
            if mod_name in c and label not in phishing_resistant:
                phishing_resistant.append(label)
    fido2_present = _v35_command_available("fido2-token")
    if fido2_present and "FIDO2-tooling" not in phishing_resistant:
        phishing_resistant.append("FIDO2-tooling")
    results.append(_v35_acsc_result(
        f"{cat} - E8.7 ML3 Phishing-Resistant MFA",
        "Pass" if phishing_resistant else "Warning",
        f"E8.7 ML3 phishing-resistant MFA: {phishing_resistant}",
        severity="Critical",
        details=f"Indicators: {phishing_resistant}",
        remediation=remediation_for("pam-yubico"),
        cross_references={
            "ACSC-E8": "7 ML3", "NIST": "IA-2(11), IA-2(12)",
            "PCI-DSS": "8.4.1", "CISA-CPG": "2.H",
        },
    ))

    # E8.6 ML3 - Patch operating systems within 48 hours of CVSS 9+ release
    # Indicator: unattended-upgrades or dnf-automatic with security-only mode
    auto_patch_active = (
        _v35_systemd_active("unattended-upgrades.service") == "active" or
        _v35_systemd_active("dnf-automatic-install.timer") == "active" or
        _v35_systemd_active("dnf-automatic.timer") == "active"
    )
    results.append(_v35_acsc_result(
        f"{cat} - E8.6 ML3 Auto-Patch",
        "Pass" if auto_patch_active else "Warning",
        f"E8.6 ML3 Automated patching active: {auto_patch_active}",
        severity="High",
        details=f"Auto-patch service: {auto_patch_active}",
        remediation=(
            remediation_for("unattended-upgrades")
            if (os_info and os_info.is_debian_family())
            else remediation_for("dnf-automatic")
        ),
        cross_references={
            "ACSC-E8": "6 ML3", "NIST": "SI-2(2)",
            "PCI-DSS": "6.3.3",
        },
    ))

    # E8.4 ML3 - User application hardening (browser, Office; PDF readers)
    # On a Linux host, surrogate: hardened browser policies
    chromium_policy = _v35_directory_exists("/etc/chromium/policies/managed")
    firefox_policy = _v35_file_exists("/etc/firefox/policies/policies.json") or \
                     _v35_file_exists("/usr/lib/firefox/distribution/policies.json")
    browser_hardened = chromium_policy or firefox_policy
    results.append(_v35_acsc_result(
        f"{cat} - E8.4 ML3 User App Hardening",
        "Info" if not browser_hardened else "Pass",
        f"E8.4 ML3 Browser policies present: {browser_hardened}",
        severity="Medium",
        details=(
            f"Chromium managed: {chromium_policy}, "
            f"Firefox policies.json: {firefox_policy}"
        ),
        remediation=(
            "Deploy enterprise browser policies via "
            "/etc/chromium/policies/managed/ or /etc/firefox/policies/. "
            "Disable Flash, enable site isolation, force HTTPS."
        ),
        cross_references={
            "ACSC-E8": "4 ML2/ML3", "NIST": "CM-6, SC-18",
        },
    ))

    return results


def _check_acsc_v35_ism_crypto_depth(os_info):
    """ISM cryptographic algorithm conformance (ASD-Approved Cryptographic
    Algorithms - AACA)."""
    results = []
    cat = "ACSC v3.5 - ISM Crypto"

    # AACA: AES-128/192/256, RSA >= 3072, ECDSA P-256/384/521,
    #       SHA-2 (256/384/512), SHA-3
    # Test SSH server config against AACA
    sshd = _v35_read_file_safe("/etc/ssh/sshd_config")
    sshd_d = ""
    if _v35_directory_exists("/etc/ssh/sshd_config.d"):
        for f in _v35_list_directory("/etc/ssh/sshd_config.d"):
            if f.endswith(".conf"):
                sshd_d += "\n" + _v35_read_file_safe(
                    os.path.join("/etc/ssh/sshd_config.d", f)
                )
    full_sshd = sshd + "\n" + sshd_d

    # KexAlgorithms - only curve25519 and dh-group16+ are AACA-aligned
    kex_match = re.search(r"^\s*KexAlgorithms\s+(\S+)", full_sshd, re.MULTILINE)
    aaca_kex = False
    if kex_match:
        kex = kex_match.group(1)
        # Strict allowlist
        forbidden = ["sha1", "diffie-hellman-group1", "diffie-hellman-group14"]
        aaca_kex = not any(f in kex.lower() for f in forbidden)
    results.append(_v35_acsc_result(
        f"{cat} - SSH KEX AACA",
        "Pass" if aaca_kex else "Warning",
        f"SSH KexAlgorithms AACA-compliant: {aaca_kex}",
        severity="High",
        details=f"KexAlgorithms = {kex_match.group(1) if kex_match else 'default'}",
        remediation=(
            "In /etc/ssh/sshd_config.d/50-acsc-aaca.conf:\n"
            "  KexAlgorithms curve25519-sha256@libssh.org,curve25519-sha256,"
            "diffie-hellman-group16-sha512,diffie-hellman-group18-sha512\n"
            "Then: systemctl reload sshd"
        ),
        cross_references={
            "ACSC-ISM": "AACA Cryptography", "NIST": "SC-13",
            "FIPS": "186-5",
        },
    ))

    # Ciphers - AES-CTR/GCM only
    ciphers_match = re.search(r"^\s*Ciphers\s+(\S+)", full_sshd, re.MULTILINE)
    aaca_ciphers = False
    if ciphers_match:
        ciphers = ciphers_match.group(1)
        # Forbidden: cbc, arcfour, 3des
        forbidden = ["cbc", "arcfour", "3des", "rc4"]
        aaca_ciphers = not any(f in ciphers.lower() for f in forbidden)
    results.append(_v35_acsc_result(
        f"{cat} - SSH Ciphers AACA",
        "Pass" if aaca_ciphers else "Warning",
        f"SSH Ciphers AACA-compliant: {aaca_ciphers}",
        severity="High",
        details=(
            f"Ciphers = {ciphers_match.group(1) if ciphers_match else 'default'}"
        ),
        remediation=(
            "In /etc/ssh/sshd_config.d/50-acsc-aaca.conf:\n"
            "  Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,"
            "aes256-ctr,aes192-ctr,aes128-ctr"
        ),
        cross_references={
            "ACSC-ISM": "AACA Cryptography", "NIST": "SC-13",
            "FIPS": "197",
        },
    ))

    # MACs - SHA-2 family only (no MD5, no SHA-1)
    macs_match = re.search(r"^\s*MACs\s+(\S+)", full_sshd, re.MULTILINE)
    aaca_macs = False
    if macs_match:
        macs = macs_match.group(1)
        forbidden = ["md5", "sha1-", "umac-64"]
        aaca_macs = not any(f in macs.lower() for f in forbidden)
    results.append(_v35_acsc_result(
        f"{cat} - SSH MACs AACA",
        "Pass" if aaca_macs else "Warning",
        f"SSH MACs AACA-compliant: {aaca_macs}",
        severity="High",
        details=f"MACs = {macs_match.group(1) if macs_match else 'default'}",
        remediation=(
            "In /etc/ssh/sshd_config.d/50-acsc-aaca.conf:\n"
            "  MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,"
            "hmac-sha2-512,hmac-sha2-256"
        ),
        cross_references={
            "ACSC-ISM": "AACA Cryptography", "NIST": "SC-13",
            "FIPS": "180-4, 198-1",
        },
    ))

    # FIPS mode (also covered elsewhere; ISM aligns with FIPS 140-3)
    fips_enabled = _v35_read_sysctl("crypto.fips_enabled") == "1"
    results.append(_v35_acsc_result(
        f"{cat} - FIPS Mode",
        "Info",
        f"FIPS 140-3 mode active: {fips_enabled}",
        severity="Informational",
        details=f"crypto.fips_enabled = {fips_enabled}",
        cross_references={
            "ACSC-ISM": "Cryptography", "FIPS": "140-3", "NIST": "SC-13",
        },
    ))

    return results


def _check_acsc_v35_ism_network_segmentation(os_info):
    """ISM network segmentation and zoning indicators."""
    results = []
    cat = "ACSC v3.5 - ISM Network"

    # 1. Multiple network interfaces (segmentation indicator)
    rc, out, _ = _v35_run_command(["ip", "-br", "link"], timeout=5.0)
    iface_count = 0
    iface_names = []
    if rc == 0 and out:
        for line in out.splitlines():
            parts = line.split()
            if parts and parts[0] not in ("lo",):
                iface_count += 1
                iface_names.append(parts[0])
    results.append(_v35_acsc_result(
        f"{cat} - Network Interfaces",
        "Info",
        f"Active network interfaces: {iface_count}",
        severity="Informational",
        details=f"Interfaces: {iface_names[:5]}",
        cross_references={
            "ACSC-ISM": "Network design", "NIST": "SC-7(13)",
        },
    ))

    # 2. Source-address verification (rp_filter)
    rp_filter_default = _v35_read_sysctl("net.ipv4.conf.default.rp_filter")
    rp_filter_all = _v35_read_sysctl("net.ipv4.conf.all.rp_filter")
    rp_filter_strict = (
        rp_filter_default in ("1", "2") and rp_filter_all in ("1", "2")
    )
    results.append(_v35_acsc_result(
        f"{cat} - Source Verification",
        "Pass" if rp_filter_strict else "Warning",
        f"Reverse-path filtering (rp_filter): default={rp_filter_default}, "
        f"all={rp_filter_all}",
        severity="High",
        details=f"rp_filter default={rp_filter_default}, all={rp_filter_all}",
        remediation=(
            "In /etc/sysctl.d/99-acsc-network.conf:\n"
            "  net.ipv4.conf.default.rp_filter = 1\n"
            "  net.ipv4.conf.all.rp_filter = 1\n"
            "Then: sysctl --system\n"
            "Prevents spoofed source addresses (anti-spoofing per ISM)."
        ),
        cross_references={
            "ACSC-ISM": "Network anti-spoofing", "NIST": "SC-7",
            "STIG": "V-230539",
        },
    ))

    # 3. ICMP redirects disabled
    redirect_default = _v35_read_sysctl("net.ipv4.conf.default.accept_redirects")
    redirect_all = _v35_read_sysctl("net.ipv4.conf.all.accept_redirects")
    redirects_disabled = redirect_default == "0" and redirect_all == "0"
    results.append(_v35_acsc_result(
        f"{cat} - ICMP Redirects",
        "Pass" if redirects_disabled else "Warning",
        f"ICMP redirect acceptance disabled: {redirects_disabled}",
        severity="Medium",
        details=f"default={redirect_default}, all={redirect_all}",
        remediation=(
            "In /etc/sysctl.d/99-acsc-network.conf:\n"
            "  net.ipv4.conf.default.accept_redirects = 0\n"
            "  net.ipv4.conf.all.accept_redirects = 0\n"
            "  net.ipv4.conf.default.secure_redirects = 0\n"
            "  net.ipv4.conf.all.secure_redirects = 0"
        ),
        cross_references={
            "ACSC-ISM": "Network ICMP", "NIST": "SC-7",
            "STIG": "V-230543",
        },
    ))

    # 4. IPv6 disabled if not used (ISM recommendation)
    rc, out, _ = _v35_run_command(["ip", "-6", "-br", "addr"], timeout=5.0)
    has_ipv6 = bool(out and out.strip())
    forward_ipv4 = _v35_read_sysctl("net.ipv4.ip_forward")
    routing_likely = forward_ipv4 == "1"
    results.append(_v35_acsc_result(
        f"{cat} - IPv6 Configuration",
        "Info",
        f"IPv6 active: {has_ipv6}, IP forwarding: {routing_likely}",
        severity="Low",
        details=f"IPv6 addresses present: {has_ipv6}, ip_forward: {forward_ipv4}",
        cross_references={
            "ACSC-ISM": "Network IPv6", "NIST": "SC-7",
        },
    ))

    return results


def _check_acsc_v35_ism_logging_centralization(os_info):
    """ISM centralized logging and retention."""
    results = []
    cat = "ACSC v3.5 - ISM Logging"

    # Centralized logging (rsyslog/syslog-ng/journal-upload)
    rsy_remote = False
    rsyslog_conf = _v35_read_file_safe("/etc/rsyslog.conf")
    if "@@" in rsyslog_conf or "omfwd" in rsyslog_conf:
        rsy_remote = True
    if not rsy_remote and _v35_directory_exists("/etc/rsyslog.d"):
        for f in _v35_list_directory("/etc/rsyslog.d"):
            c = _v35_read_file_safe(os.path.join("/etc/rsyslog.d", f))
            if "@@" in c or "omfwd" in c:
                rsy_remote = True
                break
    syslog_ng_remote = False
    syslog_ng_conf = _v35_read_file_safe("/etc/syslog-ng/syslog-ng.conf")
    if "destination" in syslog_ng_conf and (
            "tcp(" in syslog_ng_conf or "udp(" in syslog_ng_conf or
            "syslog(" in syslog_ng_conf):
        syslog_ng_remote = True
    journal_upload = (
        _v35_systemd_active("systemd-journal-upload.service") == "active"
    )
    centralized = rsy_remote or syslog_ng_remote or journal_upload
    results.append(_v35_acsc_result(
        f"{cat} - Centralized Logging",
        "Pass" if centralized else "Warning",
        f"ISM centralized log forwarding active: {centralized}",
        severity="High",
        details=(
            f"rsyslog remote: {rsy_remote}, syslog-ng remote: {syslog_ng_remote}, "
            f"journal-upload: {journal_upload}"
        ),
        remediation=(
            "Configure /etc/rsyslog.d/50-acsc-remote.conf:\n"
            "  *.* action(type=\"omfwd\" target=\"siem.example.com\" "
            "port=\"6514\" protocol=\"tcp\" "
            "StreamDriver=\"gtls\" StreamDriverMode=\"1\" "
            "StreamDriverAuthMode=\"x509/name\")\n"
            "ISM and PCI 10.5.3 require offsite log replication."
        ),
        cross_references={
            "ACSC-ISM": "Event log architecture", "NIST": "AU-4(1)",
            "PCI-DSS": "10.5.3",
        },
    ))

    # Audit log retention via journald SystemMaxUse + auditd max_log_file
    auditd_conf = _v35_read_file_safe("/etc/audit/auditd.conf")
    max_log_file_match = re.search(
        r"^\s*max_log_file\s*=\s*(\d+)", auditd_conf, re.MULTILINE,
    )
    max_log_file_mb = int(max_log_file_match.group(1)) if max_log_file_match else 0
    num_logs_match = re.search(
        r"^\s*num_logs\s*=\s*(\d+)", auditd_conf, re.MULTILINE,
    )
    num_logs = int(num_logs_match.group(1)) if num_logs_match else 0
    # ISM recommends >= 90 days - approximated by total capacity
    retention_capacity_mb = max_log_file_mb * num_logs
    capacity_adequate = retention_capacity_mb >= 1000  # >= 1GB total
    results.append(_v35_acsc_result(
        f"{cat} - Audit Retention Capacity",
        "Pass" if capacity_adequate else "Warning",
        f"auditd retention capacity: {retention_capacity_mb}MB "
        f"({num_logs} files x {max_log_file_mb}MB)",
        severity="Medium",
        details=(
            f"max_log_file = {max_log_file_mb}MB, num_logs = {num_logs}, "
            f"total = {retention_capacity_mb}MB"
        ),
        remediation=(
            "In /etc/audit/auditd.conf:\n"
            "  max_log_file = 100\n"
            "  num_logs = 30\n"
            "Provides ~3GB total. ISM recommends 90+ days retention; for "
            "high-volume environments, forward to centralized log archive."
        ),
        cross_references={
            "ACSC-ISM": "Event log retention", "NIST": "AU-11",
            "PCI-DSS": "10.5.1",
        },
    ))

    # Log integrity (auditd space_left_action and disk_full_action)
    space_left_action = re.search(
        r"^\s*space_left_action\s*=\s*(\S+)", auditd_conf, re.MULTILINE,
    )
    disk_full_action = re.search(
        r"^\s*disk_full_action\s*=\s*(\S+)", auditd_conf, re.MULTILINE,
    )
    sla = space_left_action.group(1).lower() if space_left_action else ""
    dfa = disk_full_action.group(1).lower() if disk_full_action else ""
    fail_safe = (
        sla in ("email", "syslog", "exec", "single", "halt") and
        dfa in ("single", "halt", "syslog")
    )
    results.append(_v35_acsc_result(
        f"{cat} - Log Failure Action",
        "Pass" if fail_safe else "Warning",
        f"auditd fail-safe actions: space_left={sla}, disk_full={dfa}",
        severity="High",
        details=f"space_left_action={sla}, disk_full_action={dfa}",
        remediation=(
            "In /etc/audit/auditd.conf:\n"
            "  space_left_action = email\n"
            "  admin_space_left_action = single\n"
            "  disk_full_action = halt\n"
            "ISM requires that audit failures do not result in silent log loss."
        ),
        cross_references={
            "ACSC-ISM": "Event log integrity", "NIST": "AU-5",
            "STIG": "V-230412",
        },
    ))

    return results


def _check_acsc_v35_ism_account_separation(os_info):
    """ISM privileged account separation."""
    results = []
    cat = "ACSC v3.5 - ISM Accounts"

    # 1. UID 0 accounts other than root (catastrophic)
    passwd = _v35_read_file_safe("/etc/passwd")
    uid_zero_accounts = []
    for line in passwd.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        try:
            if int(parts[2]) == 0 and parts[0] != "root":
                uid_zero_accounts.append(parts[0])
        except ValueError:
            continue
    results.append(_v35_acsc_result(
        f"{cat} - UID 0 Uniqueness",
        "Pass" if not uid_zero_accounts else "Fail",
        f"Non-root accounts with UID 0: {len(uid_zero_accounts)}",
        severity="Critical",
        details=f"Accounts: {uid_zero_accounts}",
        remediation=(
            "Only `root` should have UID 0. For each rogue UID-0 account: "
            "change UID with `usermod -u <new-uid> <user>` or remove the "
            "account if not legitimate. PCI 8.6.1 + ISM requirement."
        ),
        cross_references={
            "ACSC-ISM": "Privileged accounts", "NIST": "AC-6(1)",
            "PCI-DSS": "8.6.1", "STIG": "V-230373",
        },
    ))

    # 2. Wheel/sudo group membership audit (count of admins)
    rc, out, _ = _v35_run_command(
        ["getent", "group", "wheel", "sudo", "admin"], timeout=5.0,
    )
    admin_users = set()
    if rc == 0 and out:
        for line in out.splitlines():
            parts = line.split(":")
            if len(parts) >= 4 and parts[3]:
                for u in parts[3].split(","):
                    admin_users.add(u.strip())
    results.append(_v35_acsc_result(
        f"{cat} - Admin Group Members",
        "Info",
        f"Privileged group members (wheel/sudo/admin): {len(admin_users)}",
        severity="Informational",
        details=f"Members: {sorted(admin_users)}",
        remediation=(
            "Review with: getent group wheel sudo admin\n"
            "ISM principle of least privilege: minimize admin group size."
        ),
        cross_references={
            "ACSC-ISM": "Privileged accounts", "NIST": "AC-6",
            "PCI-DSS": "7.2.2",
        },
    ))

    # 3. SUID/SGID file inventory (privilege escalation surface)
    suid_count = 0
    rc, out, _ = _v35_run_command(
        ["find", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
         "-perm", "-4000", "-o", "-perm", "-2000"],
        timeout=15.0,
    )
    if rc == 0 and out:
        suid_count = len(out.splitlines())
    # CIS baseline ranges 30-50 on a typical Debian/RHEL system
    suid_concerning = suid_count > 80
    results.append(_v35_acsc_result(
        f"{cat} - SUID/SGID Inventory",
        "Warning" if suid_concerning else "Info",
        f"SUID/SGID binaries: {suid_count}",
        severity="Medium",
        details=f"Total: {suid_count}",
        remediation=(
            "Audit with: find / -perm -4000 -o -perm -2000 -type f\n"
            "Review each binary; remove SUID/SGID where not strictly needed.\n"
            "Common removable: /usr/bin/at, /usr/sbin/pppd, /usr/bin/wall"
        ),
        cross_references={
            "ACSC-ISM": "System hardening", "NIST": "AC-6",
            "CIS": "6.1.x",
        },
    ))

    return results


def _check_acsc_v35_ism_email_hardening_host(os_info):
    """ISM email hardening - host-level outbound mail (not full SMTP server)."""
    results = []
    cat = "ACSC v3.5 - ISM Email"

    # Check if local MTA is in use (most servers send admin alerts)
    mta_active = (
        _v35_systemd_active("postfix.service") == "active" or
        _v35_systemd_active("exim4.service") == "active" or
        _v35_systemd_active("sendmail.service") == "active" or
        _v35_systemd_active("opensmtpd.service") == "active"
    )
    if not mta_active:
        results.append(_v35_acsc_result(
            f"{cat} - MTA Status",
            "Info",
            "No local MTA active (relay only / no email)",
            severity="Informational",
            details="No postfix/exim4/sendmail/opensmtpd active",
            cross_references={"ACSC-ISM": "Email"},
        ))
        return results

    # Postfix: TLS for outbound (smtp_tls_security_level)
    if _v35_systemd_active("postfix.service") == "active":
        postfix_main = _v35_read_file_safe("/etc/postfix/main.cf")
        smtp_tls_match = re.search(
            r"^\s*smtp_tls_security_level\s*=\s*(\S+)",
            postfix_main, re.MULTILINE,
        )
        smtp_tls = smtp_tls_match.group(1).lower() if smtp_tls_match else "none"
        tls_strong = smtp_tls in ("encrypt", "verify", "secure", "may")
        results.append(_v35_acsc_result(
            f"{cat} - Postfix Outbound TLS",
            "Pass" if smtp_tls in ("encrypt", "verify", "secure") else "Warning",
            f"Postfix smtp_tls_security_level: {smtp_tls}",
            severity="High",
            details=f"smtp_tls_security_level = {smtp_tls}",
            remediation=(
                "In /etc/postfix/main.cf:\n"
                "  smtp_tls_security_level = encrypt\n"
                "  smtp_tls_loglevel = 1\n"
                "  smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt\n"
                "Then: systemctl reload postfix"
            ),
            cross_references={
                "ACSC-ISM": "Email transport", "NIST": "SC-8",
            },
        ))

        # Inbound TLS (smtpd_tls_security_level) if listening
        smtpd_tls_match = re.search(
            r"^\s*smtpd_tls_security_level\s*=\s*(\S+)",
            postfix_main, re.MULTILINE,
        )
        smtpd_tls = smtpd_tls_match.group(1).lower() if smtpd_tls_match else "none"
        results.append(_v35_acsc_result(
            f"{cat} - Postfix Inbound TLS",
            "Pass" if smtpd_tls in ("encrypt", "may") else "Info",
            f"Postfix smtpd_tls_security_level: {smtpd_tls}",
            severity="Medium",
            details=f"smtpd_tls_security_level = {smtpd_tls}",
            cross_references={
                "ACSC-ISM": "Email transport", "NIST": "SC-8",
            },
        ))

    return results


def _check_acsc_v35_ism_incident_response_readiness(os_info):
    """ISM incident response readiness indicators."""
    results = []
    cat = "ACSC v3.5 - ISM IR"

    # 1. Forensic command availability
    forensic_tools = {
        "gdb": _v35_command_available("gdb"),
        "strace": _v35_command_available("strace"),
        "ltrace": _v35_command_available("ltrace"),
        "lsof": _v35_command_available("lsof"),
        "tcpdump": _v35_command_available("tcpdump"),
        "ss": _v35_command_available("ss"),
        "netstat": _v35_command_available("netstat"),
        "auditctl": _v35_command_available("auditctl"),
    }
    available = sum(1 for v in forensic_tools.values() if v)
    results.append(_v35_acsc_result(
        f"{cat} - Forensic Tools",
        "Pass" if available >= 5 else "Warning",
        f"Forensic/diagnostic tools available: {available}/{len(forensic_tools)}",
        severity="Medium",
        details=f"Available: {[k for k,v in forensic_tools.items() if v]}",
        remediation=(
            "Install missing tools for incident response:\n"
            "  apt-get install -y gdb strace ltrace lsof tcpdump iproute2 auditd\n"
            "  dnf install -y gdb strace ltrace lsof tcpdump iproute audit"
        ),
        cross_references={
            "ACSC-ISM": "Incident response", "NIST": "IR-4(1)",
        },
    ))

    # 2. journald available for forensic timeline
    journal_available = _v35_command_available("journalctl")
    journal_persistent = _v35_directory_exists("/var/log/journal")
    journal_forensic_ready = journal_available and journal_persistent
    results.append(_v35_acsc_result(
        f"{cat} - Journal Forensic Ready",
        "Pass" if journal_forensic_ready else "Warning",
        f"journald forensic readiness: {journal_forensic_ready}",
        severity="High",
        details=(
            f"journalctl: {journal_available}, "
            f"persistent journal: {journal_persistent}"
        ),
        remediation=(
            "mkdir -p /var/log/journal\n"
            "systemctl restart systemd-journald\n"
            "Persistent logs are essential for IR timeline reconstruction."
        ),
        cross_references={
            "ACSC-ISM": "Incident response", "NIST": "AU-11, IR-5",
        },
    ))

    # 3. Network capture capability
    pcap_available = (
        _v35_command_available("tcpdump") or _v35_command_available("dumpcap")
    )
    results.append(_v35_acsc_result(
        f"{cat} - Packet Capture Capability",
        "Pass" if pcap_available else "Warning",
        f"Network packet capture available: {pcap_available}",
        severity="Medium",
        details=f"tcpdump/dumpcap available: {pcap_available}",
        remediation=(
            "apt-get install -y tcpdump  (or wireshark-cli for dumpcap)\n"
            "Required for IR network traffic analysis."
        ),
        cross_references={
            "ACSC-ISM": "Incident response", "NIST": "IR-4",
        },
    ))

    return results


# Save reference to existing run_checks
_original_run_checks_acsc_v35 = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the v3.5 expanded ACSC module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_acsc_v35(shared_data)

    os_info = shared_data.get("os_info") or shared_data.get("v3_os_info")
    if os_info is None:
        from shared_components import os_detection as _os_det
        os_info = _os_det.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        results.extend(_check_acsc_v35_e8_ml3_depth(os_info))
        results.extend(_check_acsc_v35_ism_crypto_depth(os_info))
        results.extend(_check_acsc_v35_ism_network_segmentation(os_info))
        results.extend(_check_acsc_v35_ism_logging_centralization(os_info))
        results.extend(_check_acsc_v35_ism_account_separation(os_info))
        results.extend(_check_acsc_v35_ism_email_hardening_host(os_info))
        results.extend(_check_acsc_v35_ism_incident_response_readiness(os_info))
    except Exception as exc:  # noqa: BLE001
        results.append(AuditResult(
            module=MODULE_NAME, category="ACSC - Error",
            status="Error",
            message=f"ACSC v3.5 expansion exception: {exc!r}",
            details=str(exc), severity="Medium",
        ))

    return results
if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    print("[ACSC] ===== Australian Cyber Security Centre Audit =====")
    print("[ACSC] Module Version: 3.9")
    print()

    audit_results = run_checks()
    print(f"[ACSC] {len(audit_results)} checks executed")
    print()

    by_status: Dict[str, int] = {}
    for r in audit_results:
        by_status[r.status] = by_status.get(r.status, 0) + 1
    for status, count in sorted(by_status.items()):
        print(f"  {status:>8}: {count}")
