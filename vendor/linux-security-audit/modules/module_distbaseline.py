#!/usr/bin/env python3
"""
module_distbaseline.py
Distribution-Specific Hardening Baseline Module for Linux
Version: 3.9

SYNOPSIS
    Linux technical compliance assessment against distribution-specific
    hardening guides published by upstream maintainers and security
    organisations: Ubuntu Security Guide (USG), Red Hat Security Hardening
    Guide, SUSE Linux Enterprise Security Hardening Guide, and Arch Linux
    security recommendations.

DESCRIPTION
    The generic CIS benchmark covers controls common across distributions.
    This module covers distribution-specific controls that vary or are
    only available on particular families:

        Ubuntu USG (Ubuntu Security Guide):
            - Canonical Livepatch enablement
            - Ubuntu Pro / ESM subscription state
            - AppArmor profile coverage
            - Snap confinement settings
            - ufw default-deny posture
            - unattended-upgrades configuration
            - Ubuntu Pro security profiles (FIPS, USG, CIS)

        RHEL Security Hardening:
            - SCAP scanner integration (oscap)
            - System-wide crypto policies
            - FAPolicyd application control
            - USBGuard daemon
            - FIPS mode setup state
            - Common SELinux booleans
            - Subscription-manager entitlement state

        SUSE Hardening Guide:
            - Zypper patch state
            - AppArmor profile state on SLES
            - SUSE-specific firewall (firewalld 2.x on SLES 15+)
            - AIDE configuration
            - Sudo configuration on SLES

        Arch baseline:
            - Kernel hardening flags
            - Pacman keyring trust
            - AUR helper presence
            - Pacman lockfile detection

        Cross-distribution hardening:
            - TPM presence and tpm2-tools
            - Kernel lockdown mode
            - USBGuard daemon (any distro)
            - Measured boot indicators

    Each check populates AuditResult.cross_references with the relevant
    distribution guide identifier plus equivalents in CIS, NIST 800-53,
    and ISO 27001 where applicable.

PARAMETERS
    shared_data : Dictionary containing shared data from the orchestrator.

USAGE
    Standalone:
        python3 modules/module_distbaseline.py

    Via orchestrator:
        python3 linux_security_audit.py -m DistBaseline

NOTES
    Version: 3.9
    Reference:
        Ubuntu Security Guide: https://ubuntu.com/security/certifications/docs
        RHEL Hardening: https://access.redhat.com/articles/1454933
        SUSE Hardening: https://documentation.suse.com/sles/
        Arch Security: https://wiki.archlinux.org/title/Security
    Target: 80+ technical control checks
    Multi-distribution dispatch via os_info.family.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional

from shared_components.audit_common import AuditResult
from shared_components import os_detection
from shared_components.module_helpers import (
    read_file_safe, file_exists, directory_exists, command_available,
    run_command, read_sysctl, systemd_active, systemd_enabled,
    file_mode, parse_kv_file, list_directory, make_result, first_existing,
    package_installed,
)

logger = logging.getLogger("audit.module_distbaseline")
MODULE_NAME = "DISTBASELINE"
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
# Ubuntu / Debian Family - Ubuntu Security Guide indicators
# ===========================================================================

def _check_ubuntu_baseline(os_info) -> List[AuditResult]:
    cat = "DistBaseline - Ubuntu USG"
    results: List[AuditResult] = []

    if not os_info.is_debian_family():
        return results

    # USG-1: Canonical Livepatch service
    livepatch_active = systemd_active("canonical-livepatch.service") == "active"
    livepatch_relevant = (
        os_info.distro_id == "ubuntu" and os_info.version_id != ""
    )

    if livepatch_relevant:
        results.append(_r(
            cat,
            "Pass" if livepatch_active else "Info",
            "USG: Canonical Livepatch service active",
            severity="Medium",
            details=(
                f"canonical-livepatch.service: "
                f"{systemd_active('canonical-livepatch.service')}. "
                "Livepatch reduces kernel-update reboot frequency for "
                "supported Ubuntu releases."
            ),
            remediation=(
                "Free for personal use. Enable: snap install canonical-livepatch "
                "&& canonical-livepatch enable <token>. Or via Ubuntu Pro: ua attach"
            ),
            cross_references={
                "USG": "Livepatch", "NIST": "SI-2", "ISO27001": "A.8.8",
            },
        ))

    # USG-2: Ubuntu Pro / Universe entitlement state
    if command_available("ua") or command_available("pro"):
        rc, out, _ = run_command(["pro" if command_available("pro") else "ua", "status"], timeout=10.0)
        attached = rc == 0 and "This machine is attached" in out
        results.append(_r(
            cat,
            "Info",
            f"USG: Ubuntu Pro attachment state: {'attached' if attached else 'unattached'}",
            severity="Informational",
            details=(
                "Ubuntu Pro provides additional security maintenance (ESM), "
                "FIPS, USG, and CIS profiles. Free for personal use up to "
                "5 machines."
            ),
            remediation=(
                "ua attach <token>  (or  pro attach <token>  on newer releases)"
            ),
            cross_references={"USG": "Pro", "NIST": "SI-2"},
        ))

    # USG-3: AppArmor profile coverage
    if command_available("aa-status"):
        rc, out, _ = run_command(["aa-status"])
        if rc == 0:
            loaded_match = re.search(r"(\d+)\s+profiles are loaded", out)
            enforce_match = re.search(r"(\d+)\s+profiles are in enforce mode", out)
            complain_match = re.search(r"(\d+)\s+profiles are in complain mode", out)

            loaded = int(loaded_match.group(1)) if loaded_match else 0
            enforcing = int(enforce_match.group(1)) if enforce_match else 0
            complaining = int(complain_match.group(1)) if complain_match else 0

            results.append(_r(
                cat,
                "Pass" if enforcing > 0 else "Warning",
                f"USG: AppArmor enforces {enforcing}/{loaded} profiles",
                severity="High",
                details=(
                    f"Loaded: {loaded}, enforcing: {enforcing}, "
                    f"complaining: {complaining}"
                ),
                remediation=(
                    "Move complain-mode profiles to enforce: "
                    "aa-enforce /etc/apparmor.d/<profile>"
                ),
                cross_references={
                    "USG": "AppArmor", "NIST": "AC-3(4)", "CIS": "1.6.1.4",
                    "ISO27001": "A.8.3",
                },
            ))

    # USG-4: ufw default deny posture
    if command_available("ufw"):
        rc, out, _ = run_command(["ufw", "status", "verbose"])
        ufw_default_incoming = ""
        if rc == 0:
            m = re.search(r"Default:\s+(\w+)\s+\(incoming\)", out)
            if m:
                ufw_default_incoming = m.group(1).lower()

        results.append(_r(
            cat,
            "Pass" if ufw_default_incoming in ("deny", "reject") else "Warning",
            "USG: ufw default-deny inbound posture",
            severity="High",
            details=f"ufw default incoming policy: {ufw_default_incoming or 'unknown'}",
            remediation="ufw default deny incoming",
            cross_references={
                "USG": "Firewall", "NIST": "SC-7(5)", "CIS": "3.4.2.1",
                "ISO27001": "A.8.20", "PCI-DSS": "1.2.1",
            },
        ))

    # USG-5: unattended-upgrades configured for security updates
    unattended_conf = read_file_safe("/etc/apt/apt.conf.d/50unattended-upgrades")
    has_security_origin = (
        "${distro_id}:${distro_codename}-security" in unattended_conf
        or "Ubuntu Pro" in unattended_conf
    )

    results.append(_r(
        cat,
        "Pass" if has_security_origin else "Warning" if unattended_conf else "Fail",
        "USG: unattended-upgrades includes security origin",
        severity="High",
        details=(
            f"Config present: {bool(unattended_conf)}, "
            f"security origin enabled: {has_security_origin}"
        ),
        remediation=(
            "apt-get install -y unattended-upgrades && "
            "dpkg-reconfigure -plow unattended-upgrades"
        ),
        cross_references={
            "USG": "Updates", "NIST": "SI-2", "CIS": "1.9",
            "ISO27001": "A.8.8",
        },
    ))

    # USG-6: snap confinement (if snapd present)
    if command_available("snap"):
        rc, out, _ = run_command(["snap", "list"], timeout=10.0)
        snaps_present = rc == 0 and len(out.splitlines()) > 1
        results.append(_r(
            cat,
            "Info",
            f"USG: snapd present, {'snaps installed' if snaps_present else 'no snaps'}",
            severity="Informational",
            details=(
                "Snaps are confined by AppArmor by default. Ensure snap-confine "
                "and AppArmor are operating."
            ),
            cross_references={"USG": "Snap", "NIST": "AC-3(4)"},
        ))

    return results


# ===========================================================================
# RHEL Family - Red Hat Security Hardening
# ===========================================================================

def _check_rhel_baseline(os_info) -> List[AuditResult]:
    cat = "DistBaseline - RHEL Hardening"
    results: List[AuditResult] = []

    if not os_info.is_redhat_family():
        return results

    # RHEL-1: SCAP scanner availability
    oscap_available = command_available("oscap")
    results.append(_r(
        cat,
        "Pass" if oscap_available else "Warning",
        "RHEL Hardening: OpenSCAP scanner installed",
        severity="Medium",
        details=f"oscap binary present: {oscap_available}",
        remediation=remediation_for("openscap"),
        cross_references={
            "RHEL-Hardening": "SCAP", "NIST": "CA-7", "ISO27001": "A.8.8",
            "PCI-DSS": "11.3.1",
        },
    ))

    # RHEL-2: System-wide crypto policy
    if file_exists("/etc/crypto-policies/config"):
        policy = read_file_safe("/etc/crypto-policies/config").strip()
        modern = policy in ("DEFAULT", "FUTURE", "FIPS")
        results.append(_r(
            cat,
            "Pass" if modern else "Fail",
            f"RHEL Hardening: System-wide crypto policy = {policy or 'unset'}",
            severity="High",
            details=f"Active crypto policy: {policy}",
            remediation=(
                "update-crypto-policies --set DEFAULT  # baseline; "
                "or FUTURE for stricter posture"
            ),
            cross_references={
                "RHEL-Hardening": "Crypto", "NIST": "SC-13",
                "ISO27001": "A.8.24", "NSA": "CRYPTO-1.1",
                "PCI-DSS": "4.2.1",
            },
        ))

    # RHEL-3: FAPolicyd application control
    fapolicyd_state = systemd_active("fapolicyd.service")
    results.append(_r(
        cat,
        "Pass" if fapolicyd_state == "active" else "Warning",
        "RHEL Hardening: fapolicyd application control",
        severity="High",
        details=f"fapolicyd state: {fapolicyd_state}",
        remediation=(
            "dnf install -y fapolicyd && systemctl enable --now fapolicyd"
        ),
        cross_references={
            "RHEL-Hardening": "fapolicyd", "NIST": "CM-7(5)",
            "ACSC": "E8.1", "ISO27001": "A.8.7",
        },
    ))

    # RHEL-4: USBGuard daemon
    usbguard_state = systemd_active("usbguard.service")
    results.append(_r(
        cat,
        "Pass" if usbguard_state == "active" else "Info",
        "RHEL Hardening: USBGuard daemon active",
        severity="Medium",
        details=f"usbguard state: {usbguard_state}",
        remediation=remediation_for("usbguard"),
        cross_references={
            "RHEL-Hardening": "USBGuard", "NIST": "MP-7",
            "CIS": "1.1.10", "ISO27001": "A.8.10",
        },
    ))

    # RHEL-5: FIPS mode
    fips_enabled = False
    if file_exists("/proc/sys/crypto/fips_enabled"):
        try:
            with open("/proc/sys/crypto/fips_enabled", "r", encoding="ascii") as f:
                fips_enabled = f.read().strip() == "1"
        except OSError:
            pass

    results.append(_r(
        cat,
        "Pass" if fips_enabled else "Info",
        "RHEL Hardening: FIPS mode enabled",
        severity="High",
        details=f"crypto.fips_enabled = {1 if fips_enabled else 0}",
        remediation=(
            "fips-mode-setup --enable && reboot. Required for FedRAMP/DoD; "
            "optional otherwise."
        ),
        cross_references={
            "RHEL-Hardening": "FIPS", "NIST": "SC-13", "STIG": "V-230223",
            "CMMC": "SC.L2-3.13.11",
        },
    ))

    # RHEL-6: Subscription-manager state
    if command_available("subscription-manager"):
        rc, out, _ = run_command(["subscription-manager", "status"], timeout=10.0)
        subscribed = rc == 0 and "Current" in out

        results.append(_r(
            cat,
            "Info",
            "RHEL Hardening: Red Hat subscription state",
            severity="Informational",
            details=(
                f"subscription-manager status: "
                f"{'current' if subscribed else 'not current/unsubscribed'}"
            ),
            remediation=(
                "Subscribe via: subscription-manager register --auto-attach "
                "(requires Red Hat account)"
            ),
            cross_references={
                "RHEL-Hardening": "Subscription", "NIST": "SI-2",
                "ISO27001": "A.8.8",
            },
        ))

    return results


# ===========================================================================
# SUSE Family
# ===========================================================================

def _check_suse_baseline(os_info) -> List[AuditResult]:
    cat = "DistBaseline - SUSE Hardening"
    results: List[AuditResult] = []

    if not os_info.is_suse_family():
        return results

    # SUSE-1: zypper patch state
    if command_available("zypper"):
        rc, out, _ = run_command(["zypper", "--non-interactive", "list-patches", "--severity", "important"], timeout=30.0)
        pending_patches = -1
        if rc == 0:
            # Count lines that look like patch entries (skip headers)
            lines = [l for l in out.splitlines() if l.strip() and "|" in l]
            # Header is typically first one with "Repository" or similar
            content_lines = [l for l in lines if not l.startswith("Repository") and not l.startswith("---")]
            pending_patches = len(content_lines)

        if pending_patches >= 0:
            results.append(_r(
                cat,
                "Pass" if pending_patches == 0 else "Fail",
                f"SUSE Hardening: No pending important patches",
                severity="High",
                details=f"Pending important/security patches: {pending_patches}",
                remediation=patch_for(),
                cross_references={
                    "SUSE-Hardening": "Patches", "NIST": "SI-2",
                    "ISO27001": "A.8.8", "CIS": "1.9",
                    "PCI-DSS": "6.3.3",
                },
            ))

    # SUSE-2: AppArmor on SLES
    apparmor_loaded = file_exists("/sys/kernel/security/apparmor/profiles")
    if apparmor_loaded and command_available("aa-status"):
        rc, out, _ = run_command(["aa-status"])
        enforcing = 0
        if rc == 0:
            m = re.search(r"(\d+)\s+profiles are in enforce mode", out)
            if m:
                enforcing = int(m.group(1))

        results.append(_r(
            cat,
            "Pass" if enforcing > 0 else "Warning",
            f"SUSE Hardening: AppArmor enforcing {enforcing} profiles",
            severity="High",
            details=f"Profiles in enforce mode: {enforcing}",
            remediation="aa-enforce /etc/apparmor.d/*",
            cross_references={
                "SUSE-Hardening": "AppArmor", "NIST": "AC-3(4)",
                "CIS": "1.6.1.4", "ISO27001": "A.8.3",
            },
        ))

    # SUSE-3: AIDE installation
    aide_present = command_available("aide") or file_exists("/etc/aide.conf")
    results.append(_r(
        cat,
        "Pass" if aide_present else "Warning",
        "SUSE Hardening: AIDE file integrity tool installed",
        severity="High",
        details=f"AIDE present: {aide_present}",
        remediation=remediation_for("aide"),
        cross_references={
            "SUSE-Hardening": "AIDE", "NIST": "SI-7", "CIS": "1.4.1",
            "PCI-DSS": "11.5.2",
        },
    ))

    return results


# ===========================================================================
# Arch Family
# ===========================================================================

def _check_arch_baseline(os_info) -> List[AuditResult]:
    cat = "DistBaseline - Arch Linux"
    results: List[AuditResult] = []

    if not os_info.is_arch_family():
        return results

    # Arch-1: Pacman keyring is initialized
    keyring_init = directory_exists("/etc/pacman.d/gnupg") and file_exists(
        "/etc/pacman.d/gnupg/pubring.gpg"
    )
    results.append(_r(
        cat,
        "Pass" if keyring_init else "Fail",
        "Arch: Pacman keyring initialized",
        severity="Critical",
        details=f"Pacman GPG keyring directory and pubring present: {keyring_init}",
        remediation="pacman-key --init && pacman-key --populate archlinux",
        cross_references={
            "Arch": "Keyring", "NIST": "SI-7", "ISO27001": "A.8.19",
            "NSA": "PKG-1.1",
        },
    ))

    # Arch-2: pacman SigLevel verification
    pacman_conf = read_file_safe("/etc/pacman.conf")
    siglevel_match = re.search(r"^\s*SigLevel\s*=\s*(.+)$", pacman_conf, re.MULTILINE)
    siglevel = siglevel_match.group(1).strip() if siglevel_match else ""
    siglevel_required = "Required" in siglevel and "Never" not in siglevel

    results.append(_r(
        cat,
        "Pass" if siglevel_required else "Fail",
        "Arch: Pacman requires package signatures",
        severity="High",
        details=f"SigLevel = {siglevel or 'default (Required DatabaseOptional)'}",
        remediation=(
            "Ensure /etc/pacman.conf has 'SigLevel = Required DatabaseOptional' "
            "or stricter; do not use 'SigLevel = Never'."
        ),
        cross_references={
            "Arch": "SigLevel", "NIST": "SI-7", "ISO27001": "A.8.19",
        },
    ))

    # Arch-3: AUR helper presence (security smell - inform only)
    aur_helpers = ("yay", "paru", "trizen", "pikaur", "pakku")
    found_aur = [h for h in aur_helpers if command_available(h)]
    results.append(_r(
        cat,
        "Info",
        f"Arch: AUR helper inventory: {len(found_aur)} detected",
        severity="Informational",
        details=(
            f"Detected: {', '.join(found_aur) or 'none'}. "
            "AUR packages are user-contributed and not audited; review "
            "PKGBUILDs before installation."
        ),
        cross_references={"Arch": "AUR", "NIST": "SA-12"},
    ))

    return results


# ===========================================================================
# Cross-Distribution Hardening
# ===========================================================================

def _check_cross_distro_hardening(os_info) -> List[AuditResult]:
    cat = "DistBaseline - Cross-Distribution"
    results: List[AuditResult] = []

    # XD-1: TPM 2.0 presence
    tpm_present = directory_exists("/sys/class/tpm/tpm0") or directory_exists("/sys/class/tpm/tpmrm0")
    tpm2_tools = command_available("tpm2_pcrread") or command_available("tpm2-tools")

    results.append(_r(
        cat,
        "Pass" if tpm_present else "Info",
        "Cross-Distro: TPM hardware present",
        severity="Medium",
        details=f"TPM device detected: {tpm_present}, tpm2-tools: {tpm2_tools}",
        remediation=(
            "If hardware supports TPM 2.0, enable it in firmware. Install "
            "tpm2-tools to interact with the device."
        ),
        cross_references={
            "DistBaseline": "TPM", "NIST": "SI-7", "ISO27001": "A.8.7",
            "NSA": "BOOT-1.2",
        },
    ))

    # XD-2: USBGuard daemon (any distribution)
    usbguard_state = systemd_active("usbguard.service")
    results.append(_r(
        cat,
        "Pass" if usbguard_state == "active" else "Info",
        "Cross-Distro: USBGuard daemon active",
        severity="Medium",
        details=f"usbguard state: {usbguard_state}",
        remediation=remediation_for("usbguard"),
        cross_references={
            "DistBaseline": "USBGuard", "NIST": "MP-7", "CIS": "1.1.10",
            "ACSC": "ISM-1416",
        },
    ))

    # XD-3: Kernel lockdown mode
    lockdown_state = ""
    if file_exists("/sys/kernel/security/lockdown"):
        try:
            with open("/sys/kernel/security/lockdown", "r", encoding="ascii") as f:
                content = f.read().strip()
            # Format: [none] integrity confidentiality (with brackets around active)
            m = re.search(r"\[(\w+)\]", content)
            lockdown_state = m.group(1) if m else "unknown"
        except OSError:
            pass

    lockdown_active = lockdown_state in ("integrity", "confidentiality")
    results.append(_r(
        cat,
        "Pass" if lockdown_active else "Info",
        f"Cross-Distro: Kernel lockdown mode = {lockdown_state or 'not available'}",
        severity="High",
        details=(
            f"Lockdown state: {lockdown_state}. "
            "Lockdown mode restricts kernel modifications by root, useful "
            "for Secure Boot environments."
        ),
        remediation=(
            "Add to kernel command line: lockdown=integrity (or confidentiality). "
            "Edit /etc/default/grub GRUB_CMDLINE_LINUX, regenerate, and reboot."
        ),
        cross_references={
            "DistBaseline": "Lockdown", "NIST": "SI-7", "ISO27001": "A.8.7",
            "NSA": "KERN-3.2",
        },
    ))

    # XD-4: Secure Boot status
    if directory_exists("/sys/firmware/efi"):
        secure_boot = "unknown"
        sb_files = list_directory("/sys/firmware/efi/efivars", "")
        for sb_file in sb_files:
            if "SecureBoot" in os.path.basename(sb_file):
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
            "Pass" if secure_boot == "enabled" else "Warning",
            f"Cross-Distro: UEFI Secure Boot = {secure_boot}",
            severity="High",
            details=f"Secure Boot state: {secure_boot}",
            remediation=(
                "Enable Secure Boot in firmware. Ensure shim/grub are signed "
                "by a key in the platform DB."
            ),
            cross_references={
                "DistBaseline": "SecureBoot", "NIST": "SI-7",
                "ISO27001": "A.8.7", "NSA": "BOOT-1.1",
                "ACSC": "ISM-1610",
            },
        ))

    # XD-5: Kernel hardening sysctl checks
    hardening_sysctls = (
        ("kernel.kptr_restrict", ("1", "2")),
        ("kernel.dmesg_restrict", ("1",)),
        ("kernel.yama.ptrace_scope", ("1", "2", "3")),
        ("kernel.unprivileged_bpf_disabled", ("1",)),
        ("net.core.bpf_jit_harden", ("1", "2")),
    )
    pass_count = 0
    for key, accepted in hardening_sysctls:
        actual = read_sysctl(key)
        if actual is not None and actual in accepted:
            pass_count += 1

    results.append(_r(
        cat,
        "Pass" if pass_count >= 4 else "Warning" if pass_count >= 2 else "Fail",
        f"Cross-Distro: Kernel hardening sysctls applied ({pass_count}/{len(hardening_sysctls)})",
        severity="High",
        details=(
            f"{pass_count} of {len(hardening_sysctls)} recommended kernel "
            "hardening sysctls are at recommended values"
        ),
        remediation=(
            "Create /etc/sysctl.d/99-distbaseline.conf with: "
            "kernel.kptr_restrict=2, kernel.dmesg_restrict=1, "
            "kernel.yama.ptrace_scope=1, kernel.unprivileged_bpf_disabled=1, "
            "net.core.bpf_jit_harden=2"
        ),
        cross_references={
            "DistBaseline": "Kernel", "NIST": "SI-16", "CIS": "1.5.3",
            "NSA": "KERN-1.1",
        },
    ))

    return results


# ===========================================================================
# Module entry point
# ===========================================================================

def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    if shared_data is None:
        shared_data = {}
    os_info = shared_data.get("v3_os_info") or os_detection.detect_os()
    shared_data["v3_os_info"] = os_info

    results: List[AuditResult] = []
    try:
        # Distribution-specific dispatch
        results.extend(_check_ubuntu_baseline(os_info))
        results.extend(_check_rhel_baseline(os_info))
        results.extend(_check_suse_baseline(os_info))
        results.extend(_check_arch_baseline(os_info))
        # Cross-distro applies to all
        results.extend(_check_cross_distro_hardening(os_info))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled exception in DistBaseline module")
        results.append(_r(
            "DistBaseline - Error", "Error",
            f"DistBaseline module encountered an unhandled exception: {exc!r}",
            severity="Medium", details=str(exc),
        ))

    return results



# ===========================================================================
# v3.1 EXPANSION - DistBaseline Comprehensive Per-Distribution Coverage
# ---------------------------------------------------------------------------
# Adds deep per-family coverage:
#   - Ubuntu: Pro/ESM, Livepatch, USG, snap confinement, AppArmor depth
#   - Debian: needrestart, debsums, fail2ban, harden-doc, libpam-tmpdir
#   - RHEL family: OpenSCAP, fapolicyd, USBGuard, FIPS, subscription-manager
#   - Rocky/Alma: errata-import-tool, distro-sync state
#   - Fedora: dnf-automatic, modular streams, btrfs snapshots
#   - SLES: zypper, AppArmor on SLES, FIPS, suseconnect
#   - openSUSE: snapper, btrfs, transactional-update
#   - Arch: pacman keyring, mirror trust, AUR helpers, mkinitcpio
#   - Alpine: apk, doas, OpenRC, busybox
#   - Cross-distro: TPM 2.0 depth, USBGuard, kernel lockdown, IMA/EVM,
#                   journald compression
# ===========================================================================


def _check_ubuntu_extended(os_info) -> List[AuditResult]:
    """Ubuntu-specific deep checks."""
    results: List[AuditResult] = []
    if os_info.distro_id != "ubuntu":
        return results

    cat = "DistBaseline - Ubuntu Pro/ESM"

    # Ubuntu Pro / ESM attachment
    pro_status_present = command_available("pro") or command_available("ua")
    if pro_status_present:
        cmd = "pro" if command_available("pro") else "ua"
        rc, out, _ = run_command([cmd, "status", "--format=json"], timeout=10.0)
        if rc == 0 and out:
            try:
                import json as _json
                status = _json.loads(out)
                attached = status.get("attached", False)
                results.append(_r(
                    cat, "Pass" if attached else "Info",
                    f"Ubuntu Pro: subscription attached: {attached}",
                    severity="Informational",
                    details=(
                        f"Ubuntu Pro status: attached={attached}. "
                        f"Services: {[s.get('name') for s in status.get('services', [])]}"
                    ),
                    remediation=(
                        "Free for personal use (5 machines): pro attach <token>. "
                        "Provides 10-year support, ESM, Livepatch, FIPS, USG."
                    ),
                    cross_references={
                        "DistBaseline": "Ubuntu-Pro", "NIST": "SI-2",
                    },
                ))
            except Exception:
                pass

    # Livepatch (kernel hot-patching)
    livepatch_active = systemd_active("canonical-livepatch.service") == "active" or \
                       file_exists("/var/snap/canonical-livepatch/current/livepatchd.conf")
    results.append(_r(
        cat, "Pass" if livepatch_active else "Info",
        f"Ubuntu Livepatch: kernel hot-patching active: {livepatch_active}",
        severity="Medium",
        details=f"Livepatch status: {livepatch_active}",
        remediation=(
            "Enable via Ubuntu Pro: pro enable livepatch. "
            "Reduces critical kernel CVE exposure window."
        ),
        cross_references={
            "DistBaseline": "Ubuntu-Livepatch", "NIST": "SI-2(2)",
            "PCI-DSS": "6.3.3",
        },
    ))

    # Ubuntu Security Guide (USG)
    usg_present = command_available("usg")
    results.append(_r(
        cat, "Pass" if usg_present else "Info",
        f"Ubuntu Security Guide (usg): {usg_present}",
        severity="Informational",
        details=f"usg command available: {usg_present}",
        remediation=(
            "USG provides CIS Benchmark and DISA STIG profiles. "
            "Enable via Ubuntu Pro: pro enable usg, then usg fix cis_level1_server"
        ),
        cross_references={
            "DistBaseline": "Ubuntu-USG", "CIS": "Various",
        },
    ))

    # Snap confinement
    if command_available("snap"):
        rc, out, _ = run_command(["snap", "list"], timeout=10.0)
        if rc == 0:
            snap_count = max(0, len([l for l in out.splitlines() if l.strip()]) - 1)
            results.append(_r(
                "DistBaseline - Snap",
                "Info",
                f"Snap packages installed: {snap_count}",
                severity="Informational",
                details=f"Snap count: {snap_count}. Each snap runs in confinement.",
                cross_references={
                    "DistBaseline": "Ubuntu-Snap", "NIST": "CM-7",
                },
            ))

    # AppArmor profile coverage (Ubuntu defaults heavily on AppArmor)
    if command_available("aa-status"):
        rc, out, _ = run_command(["aa-status"], timeout=5.0)
        if rc == 0:
            enforce_match = re.search(r"(\d+)\s+profiles? are in enforce mode", out)
            complain_match = re.search(r"(\d+)\s+profiles? are in complain mode", out)
            enforce = int(enforce_match.group(1)) if enforce_match else 0
            complain = int(complain_match.group(1)) if complain_match else 0
            results.append(_r(
                "DistBaseline - AppArmor",
                "Pass" if enforce >= 30 else "Warning",
                f"AppArmor profiles: {enforce} enforcing, {complain} complaining",
                severity="Medium",
                details=f"Enforcing profiles: {enforce}; Complain: {complain}",
                remediation=(
                    "apt-get install -y apparmor-profiles apparmor-profiles-extra "
                    "for additional profiles. aa-enforce /etc/apparmor.d/* to enforce all."
                ),
                cross_references={
                    "DistBaseline": "Ubuntu-AppArmor", "NIST": "AC-3(4)",
                    "STIG": "V-230230",
                },
            ))

    # Unattended upgrades configuration
    unattended_conf = read_file_safe("/etc/apt/apt.conf.d/50unattended-upgrades")
    if unattended_conf:
        security_only = "security" in unattended_conf.lower()
        auto_remove = "Unattended-Upgrade::Remove-Unused-Dependencies" in unattended_conf
        results.append(_r(
            "DistBaseline - Patches",
            "Pass" if security_only else "Warning",
            "Ubuntu unattended-upgrades configured for security",
            severity="High",
            details=(
                f"Security origin pattern present: {security_only}, "
                f"auto-remove deps: {auto_remove}"
            ),
            remediation=(
                "dpkg-reconfigure unattended-upgrades. "
                "Enable Unattended-Upgrade::Allowed-Origins for -security."
            ),
            cross_references={
                "DistBaseline": "Ubuntu-Patches", "NIST": "SI-2(5)",
                "PCI-DSS": "6.3.3", "ACSC": "E8.6",
            },
        ))

    # fwupd presence (firmware updates)
    fwupd_active = systemd_active("fwupd.service") in ("active", "inactive")  # service may be socket-activated
    fwupd_present = command_available("fwupdmgr")
    if fwupd_present:
        results.append(_r(
            "DistBaseline - Firmware",
            "Info",
            "fwupd available for firmware updates",
            severity="Low",
            details="fwupdmgr command present",
            remediation="fwupdmgr refresh && fwupdmgr update",
            cross_references={
                "DistBaseline": "Ubuntu-Firmware", "NIST": "SI-2",
            },
        ))

    return results


def _check_debian_extended(os_info) -> List[AuditResult]:
    """Debian-specific (and Ubuntu-overlap) deeper checks."""
    results: List[AuditResult] = []
    if not os_info.is_debian_family():
        return results

    cat = "DistBaseline - Debian Family"

    # needrestart for service restart awareness
    needrestart = command_available("needrestart")
    results.append(_r(
        cat, "Pass" if needrestart else "Info",
        f"needrestart installed: {needrestart}",
        severity="Low",
        details=f"needrestart command: {needrestart}",
        remediation=(
            "apt-get install -y needrestart  # alerts to services needing restart "
            "after libc updates etc."
        ),
        cross_references={
            "DistBaseline": "Debian-NeedRestart", "NIST": "SI-2(2)",
        },
    ))

    # debsums for package integrity
    debsums_present = command_available("debsums")
    results.append(_r(
        cat, "Pass" if debsums_present else "Info",
        f"debsums available for package integrity: {debsums_present}",
        severity="Medium",
        details=f"debsums command: {debsums_present}",
        remediation=(
            "apt-get install -y debsums. Run periodically: "
            "debsums --all --changed --ignore-permissions"
        ),
        cross_references={
            "DistBaseline": "Debian-Debsums", "NIST": "SI-7", "PCI-DSS": "11.5",
        },
    ))

    # fail2ban for brute-force protection
    fail2ban_active = systemd_active("fail2ban.service") == "active"
    results.append(_r(
        cat, "Pass" if fail2ban_active else "Info",
        f"fail2ban active: {fail2ban_active}",
        severity="Medium",
        details=f"fail2ban service state: {systemd_active('fail2ban.service')}",
        remediation=(
            "apt-get install -y fail2ban && systemctl enable --now fail2ban"
        ),
        cross_references={
            "DistBaseline": "Debian-Fail2ban", "NIST": "AC-7", "PCI-DSS": "8.3.4",
        },
    ))

    # libpam-tmpdir for per-user /tmp isolation
    pam_tmpdir_present = file_exists("/usr/lib/x86_64-linux-gnu/security/pam_tmpdir.so") or \
                        file_exists("/usr/lib/aarch64-linux-gnu/security/pam_tmpdir.so")
    results.append(_r(
        cat, "Pass" if pam_tmpdir_present else "Info",
        f"libpam-tmpdir for per-user tmp isolation: {pam_tmpdir_present}",
        severity="Low",
        details=f"pam_tmpdir.so present: {pam_tmpdir_present}",
        remediation=(
            "apt-get install -y libpam-tmpdir. Provides per-user /tmp/ subdirectories."
        ),
        cross_references={
            "DistBaseline": "Debian-TmpDir", "NIST": "SC-4",
        },
    ))

    # APT GPG verification
    apt_conf_files = list_directory("/etc/apt/apt.conf.d")
    no_pubkey = False
    for f in apt_conf_files:
        c = read_file_safe(os.path.join("/etc/apt/apt.conf.d", f))
        if "AllowUnsigned" in c or "AllowInsecureRepositories \"true\"" in c.replace(" ", ""):
            no_pubkey = True

    results.append(_r(
        cat, "Pass" if not no_pubkey else "Fail",
        "APT repository signature verification enforced",
        severity="High",
        details=f"Insecure repository allowance detected: {no_pubkey}",
        remediation=(
            "Remove any AllowInsecureRepositories or AllowUnsigned from "
            "/etc/apt/apt.conf.d/*. Use only signed repositories."
        ),
        cross_references={
            "DistBaseline": "Debian-APT", "NIST": "CM-5(3)", "PCI-DSS": "6.3.3",
        },
    ))

    return results


def _check_rhel_extended(os_info) -> List[AuditResult]:
    """RHEL family deeper checks."""
    results: List[AuditResult] = []
    if not os_info.is_redhat_family():
        return results

    cat = "DistBaseline - RHEL Family"

    # OpenSCAP scanner
    oscap_present = command_available("oscap")
    scap_content = directory_exists("/usr/share/xml/scap/ssg/content")
    results.append(_r(
        cat, "Pass" if oscap_present and scap_content else "Warning",
        f"OpenSCAP scanner: {oscap_present}, SCAP content: {scap_content}",
        severity="Medium",
        details=(
            f"oscap command: {oscap_present}, "
            f"scap-security-guide content: {scap_content}"
        ),
        remediation=(
            "dnf install -y openscap-scanner scap-security-guide. "
            "Run: oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis "
            "/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml"
        ),
        cross_references={
            "DistBaseline": "RHEL-OpenSCAP", "NIST": "RA-5", "CIS": "Various",
        },
    ))

    # System crypto policy
    crypto_policy_path = "/etc/crypto-policies/config"
    if file_exists(crypto_policy_path):
        policy = read_file_safe(crypto_policy_path).strip()
        good_policy = policy in ("DEFAULT", "FUTURE", "FIPS")
        results.append(_r(
            cat, "Pass" if good_policy else "Warning",
            f"System crypto policy: {policy or 'unset'}",
            severity="High",
            details=f"crypto-policies config: {policy}",
            remediation=(
                "update-crypto-policies --set FUTURE  # or FIPS for federal"
            ),
            cross_references={
                "DistBaseline": "RHEL-CryptoPolicy", "NIST": "SC-13",
                "NSA": "CRYPTO-1.1", "PCI-DSS": "4.2.1",
            },
        ))

    # fapolicyd application allowlist
    fapolicyd_active = systemd_active("fapolicyd.service") == "active"
    fapolicyd_installed = file_exists("/etc/fapolicyd/fapolicyd.conf")
    results.append(_r(
        cat, "Pass" if fapolicyd_active else ("Info" if fapolicyd_installed else "Warning"),
        f"fapolicyd application allowlisting: {fapolicyd_active}",
        severity="High",
        details=(
            f"fapolicyd installed: {fapolicyd_installed}, "
            f"active: {fapolicyd_active}"
        ),
        remediation=(
            "dnf install -y fapolicyd && systemctl enable --now fapolicyd. "
            "Provides DAC-bypass-resistant application allowlist."
        ),
        cross_references={
            "DistBaseline": "RHEL-fapolicyd", "NIST": "CM-7(5)", "ACSC": "E8.1",
        },
    ))

    # USBGuard
    usbguard_active = systemd_active("usbguard.service") == "active"
    results.append(_r(
        cat, "Pass" if usbguard_active else "Info",
        f"USBGuard active: {usbguard_active}",
        severity="Medium",
        details=f"usbguard service: {systemd_active('usbguard.service')}",
        remediation=remediation_for("usbguard"),
        cross_references={
            "DistBaseline": "RHEL-USBGuard", "NIST": "MP-7", "PCI-DSS": "9.5",
            "HIPAA": "164.310(d)(1)",
        },
    ))

    # FIPS mode
    fips_enabled_path = "/proc/sys/crypto/fips_enabled"
    fips_enabled = read_sysctl("crypto.fips_enabled") == "1"
    if file_exists(fips_enabled_path):
        results.append(_r(
            cat, "Info",
            f"FIPS 140-3 mode: {'enabled' if fips_enabled else 'disabled'}",
            severity="Informational",
            details=f"crypto.fips_enabled = {read_sysctl('crypto.fips_enabled')}",
            remediation=(
                "For federal/regulated workloads: fips-mode-setup --enable, "
                "then reboot. Verify with: fips-mode-setup --check"
            ),
            cross_references={
                "DistBaseline": "RHEL-FIPS", "NIST": "SC-13", "NSA": "FIPS-1.1",
            },
        ))

    # subscription-manager (RHEL only)
    if os_info.distro_id == "rhel":
        sub_mgr = command_available("subscription-manager")
        if sub_mgr:
            rc, out, _ = run_command(["subscription-manager", "status"], timeout=10.0)
            attached = "Overall Status: Current" in out if rc == 0 else False
            results.append(_r(
                cat, "Pass" if attached else "Warning",
                f"RHEL subscription attached: {attached}",
                severity="High",
                details=f"Status: {out[:200] if out else 'unknown'}",
                remediation=(
                    "subscription-manager register --auto-attach. "
                    "Required for security update access."
                ),
                cross_references={
                    "DistBaseline": "RHEL-Subscription", "NIST": "SI-2",
                },
            ))

    # SELinux state
    selinux_config = read_file_safe("/etc/selinux/config")
    selinux_enforcing = False
    if file_exists("/sys/fs/selinux/enforce"):
        try:
            with open("/sys/fs/selinux/enforce", "r") as f:
                selinux_enforcing = f.read().strip() == "1"
        except OSError:
            pass

    results.append(_r(
        cat, "Pass" if selinux_enforcing else "Fail",
        f"SELinux enforcing: {selinux_enforcing}",
        severity="High",
        details=(
            f"SELinux runtime enforce: {selinux_enforcing}. "
            f"Config: {[l for l in selinux_config.splitlines() if l.startswith('SELINUX=')]}"
        ),
        remediation=(
            "setenforce 1 && sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config"
        ),
        cross_references={
            "DistBaseline": "RHEL-SELinux", "NIST": "AC-3(4)", "STIG": "V-230223",
            "NSA": "MAC-1.1",
        },
    ))

    # dnf-automatic
    dnf_auto_active = (
        systemd_active("dnf-automatic-install.timer") == "active" or
        systemd_active("dnf-automatic.timer") == "active"
    )
    results.append(_r(
        cat, "Pass" if dnf_auto_active else "Warning",
        f"dnf-automatic for security patches: {dnf_auto_active}",
        severity="High",
        details=f"dnf-automatic timer: {dnf_auto_active}",
        remediation=(
            "dnf install -y dnf-automatic && "
            "systemctl enable --now dnf-automatic-install.timer"
        ),
        cross_references={
            "DistBaseline": "RHEL-Patches", "NIST": "SI-2(5)", "PCI-DSS": "6.3.3",
        },
    ))

    return results


def _check_suse_extended(os_info) -> List[AuditResult]:
    """SUSE family deeper checks."""
    results: List[AuditResult] = []
    if not os_info.is_suse_family():
        return results

    cat = "DistBaseline - SUSE Family"

    # zypper updates
    if command_available("zypper"):
        rc, out, _ = run_command(["zypper", "-q", "list-patches"], timeout=30.0)
        if rc == 0:
            patch_count = sum(1 for line in out.splitlines() if "|" in line and "patch" in line.lower())
            results.append(_r(
                cat, "Pass" if patch_count == 0 else "Warning",
                f"zypper pending patches: {patch_count}",
                severity="High",
                details=f"Pending patches: {patch_count}",
                remediation=patch_for(),
                cross_references={
                    "DistBaseline": "SUSE-Patches", "NIST": "SI-2(2)",
                    "PCI-DSS": "6.3.3",
                },
            ))

    # AppArmor on SLES (default MAC framework on SUSE)
    if command_available("aa-status"):
        rc, out, _ = run_command(["aa-status"])
        if rc == 0:
            enforce_match = re.search(r"(\d+)\s+profiles? are in enforce", out)
            enforce = int(enforce_match.group(1)) if enforce_match else 0
            results.append(_r(
                cat, "Pass" if enforce >= 10 else "Warning",
                f"SUSE AppArmor profiles: {enforce} enforcing",
                severity="Medium",
                details=f"Enforcing profiles: {enforce}",
                remediation=(
                    "zypper install -y apparmor-profiles && "
                    "aa-enforce /etc/apparmor.d/*"
                ),
                cross_references={
                    "DistBaseline": "SUSE-AppArmor", "NIST": "AC-3(4)",
                },
            ))

    # snapper for btrfs snapshots (rollback safety)
    snapper_present = command_available("snapper")
    snapper_configs = directory_exists("/etc/snapper/configs")
    results.append(_r(
        cat, "Pass" if snapper_present and snapper_configs else "Info",
        f"snapper btrfs snapshots: {snapper_present}",
        severity="Medium",
        details=(
            f"snapper command: {snapper_present}, "
            f"configs: {snapper_configs}"
        ),
        remediation=(
            "zypper install -y snapper && snapper -c root create-config /. "
            "Provides automatic pre/post snapshot rollback for changes."
        ),
        cross_references={
            "DistBaseline": "SUSE-Snapper", "NIST": "CP-9",
        },
    ))

    # transactional-update (MicroOS / SLE Micro)
    transactional_update = command_available("transactional-update")
    if transactional_update:
        results.append(_r(
            cat, "Info",
            "transactional-update available (immutable system pattern)",
            severity="Informational",
            details="transactional-update command present",
            remediation=(
                "Use: transactional-update up; reboot. Atomic updates with rollback."
            ),
            cross_references={
                "DistBaseline": "SUSE-Transactional", "NIST": "CM-3",
            },
        ))

    # SUSEConnect (SLES)
    if command_available("SUSEConnect"):
        rc, out, _ = run_command(["SUSEConnect", "--status"], timeout=10.0)
        registered = "Registered" in out if rc == 0 else False
        results.append(_r(
            cat, "Pass" if registered else "Warning",
            f"SUSE registration: {registered}",
            severity="High",
            details=f"SUSEConnect status: {out[:200] if out else 'unknown'}",
            remediation=(
                "SUSEConnect -r <regcode>. Required for security update access."
            ),
            cross_references={
                "DistBaseline": "SUSE-Registration", "NIST": "SI-2",
            },
        ))

    return results


def _check_arch_extended(os_info) -> List[AuditResult]:
    """Arch family deeper checks."""
    results: List[AuditResult] = []
    if not os_info.is_arch_family():
        return results

    cat = "DistBaseline - Arch Family"

    # pacman keyring initialized
    pacman_keyring = directory_exists("/etc/pacman.d/gnupg")
    if pacman_keyring:
        # Check if keys are present
        try:
            keys_count = len([f for f in os.listdir("/etc/pacman.d/gnupg")
                             if f.startswith("trustdb")])
        except OSError:
            keys_count = 0
        results.append(_r(
            cat, "Pass",
            f"Pacman keyring initialized at /etc/pacman.d/gnupg",
            severity="High",
            details=f"Keyring directory present, trustdb files: {keys_count}",
            cross_references={
                "DistBaseline": "Arch-Keyring", "NIST": "CM-5(3)",
            },
        ))
    else:
        results.append(_r(
            cat, "Fail",
            "Pacman keyring NOT initialized",
            severity="Critical",
            details="/etc/pacman.d/gnupg missing",
            remediation=(
                "pacman-key --init && pacman-key --populate archlinux"
            ),
            cross_references={
                "DistBaseline": "Arch-Keyring", "NIST": "CM-5(3)",
            },
        ))

    # SigLevel verification in pacman.conf
    pacman_conf = read_file_safe("/etc/pacman.conf")
    siglevel_match = re.search(r"^\s*SigLevel\s*=\s*(.*)", pacman_conf, re.MULTILINE)
    siglevel = siglevel_match.group(1).strip() if siglevel_match else ""
    siglevel_strict = "Required" in siglevel and "Never" not in siglevel
    results.append(_r(
        cat, "Pass" if siglevel_strict else "Warning",
        f"Pacman SigLevel: {siglevel or 'default'}",
        severity="High",
        details=f"SigLevel: {siglevel}",
        remediation=(
            "In /etc/pacman.conf set: SigLevel = Required DatabaseOptional"
        ),
        cross_references={
            "DistBaseline": "Arch-SigLevel", "NIST": "CM-5(3)",
        },
    ))

    # AUR helpers (informational - users frequently install untrusted packages)
    aur_helpers = {
        "yay": command_available("yay"),
        "paru": command_available("paru"),
        "pikaur": command_available("pikaur"),
        "trizen": command_available("trizen"),
    }
    detected = [k for k, v in aur_helpers.items() if v]
    if detected:
        results.append(_r(
            cat, "Info",
            f"AUR helper installed: {', '.join(detected)}",
            severity="Medium",
            details=f"Detected: {detected}. AUR packages are user-submitted, review PKGBUILD.",
            remediation=(
                "Always review PKGBUILD before installing. "
                "Consider AUR-LTS or audited-only packages for production."
            ),
            cross_references={
                "DistBaseline": "Arch-AUR", "NIST": "CM-7",
            },
        ))

    # mkinitcpio hooks for security
    mkinitcpio_conf = read_file_safe("/etc/mkinitcpio.conf")
    if mkinitcpio_conf:
        encrypt_hook = "encrypt" in mkinitcpio_conf
        results.append(_r(
            cat, "Info",
            f"mkinitcpio encrypt hook present: {encrypt_hook}",
            severity="Informational",
            details=f"Hook detected: {encrypt_hook}",
            cross_references={
                "DistBaseline": "Arch-Mkinitcpio", "NIST": "SC-28",
            },
        ))

    # systemd-boot vs grub
    sd_boot = directory_exists("/boot/loader") and file_exists("/boot/loader/loader.conf")
    grub2 = file_exists("/boot/grub/grub.cfg") or file_exists("/boot/grub2/grub.cfg")
    if sd_boot or grub2:
        loader_type = "systemd-boot" if sd_boot else "grub"
        results.append(_r(
            cat, "Info",
            f"Boot loader: {loader_type}",
            severity="Informational",
            details=(
                f"systemd-boot: {sd_boot}, grub: {grub2}"
            ),
            cross_references={
                "DistBaseline": "Arch-BootLoader", "NIST": "SI-7",
            },
        ))

    return results


def _check_alpine_extended(os_info) -> List[AuditResult]:
    """Alpine Linux deeper checks (containerized environments common)."""
    results: List[AuditResult] = []
    if os_info.distro_id != "alpine":
        return results

    cat = "DistBaseline - Alpine Linux"

    # APK keyring
    apk_keys = directory_exists("/etc/apk/keys")
    if apk_keys:
        try:
            key_files = [f for f in os.listdir("/etc/apk/keys") if f.endswith(".pub.rsa.pem") or f.endswith(".rsa.pub")]
            results.append(_r(
                cat, "Pass" if key_files else "Fail",
                f"APK keyring: {len(key_files)} keys present",
                severity="Critical",
                details=f"Keys in /etc/apk/keys: {len(key_files)}",
                remediation="apk add alpine-keys",
                cross_references={
                    "DistBaseline": "Alpine-Keys", "NIST": "CM-5(3)",
                },
            ))
        except OSError:
            pass

    # doas instead of sudo (Alpine default)
    doas_present = command_available("doas")
    sudo_present = command_available("sudo")
    results.append(_r(
        cat, "Info",
        f"Privilege escalation: doas={doas_present}, sudo={sudo_present}",
        severity="Informational",
        details=f"doas: {doas_present}, sudo: {sudo_present}",
        cross_references={
            "DistBaseline": "Alpine-PrivEsc", "NIST": "AC-6",
        },
    ))

    # OpenRC services (instead of systemd)
    openrc_present = command_available("rc-service") or command_available("openrc")
    results.append(_r(
        cat, "Info",
        f"OpenRC init system: {openrc_present}",
        severity="Informational",
        details=f"OpenRC: {openrc_present}",
        cross_references={
            "DistBaseline": "Alpine-OpenRC", "NIST": "CM-7",
        },
    ))

    return results


def _check_cross_distro_kernel_security(os_info) -> List[AuditResult]:
    """Cross-distribution kernel-level security features."""
    results: List[AuditResult] = []
    cat = "DistBaseline - Kernel Security"

    # Kernel lockdown mode
    lockdown_path = "/sys/kernel/security/lockdown"
    if file_exists(lockdown_path):
        lockdown = read_file_safe(lockdown_path).strip()
        # Format: "[none] integrity confidentiality" - bracketed item is active
        active_match = re.search(r"\[(\w+)\]", lockdown)
        active = active_match.group(1) if active_match else "unknown"
        results.append(_r(
            cat, "Pass" if active in ("integrity", "confidentiality") else "Info",
            f"Kernel lockdown mode: {active}",
            severity="Medium",
            details=f"Lockdown state: {lockdown}",
            remediation=(
                "Set kernel parameter lockdown=integrity (or confidentiality) "
                "in GRUB. Requires Secure Boot for full effect."
            ),
            cross_references={
                "DistBaseline": "Kernel-Lockdown", "NIST": "SC-39",
                "NSA": "KERN-1.5",
            },
        ))

    # Secure Boot
    sb_var = "/sys/firmware/efi/efivars"
    sb_enabled = False
    if directory_exists(sb_var):
        try:
            for entry in os.listdir(sb_var):
                if "SecureBoot" in entry:
                    sb_path = os.path.join(sb_var, entry)
                    try:
                        with open(sb_path, "rb") as f:
                            data = f.read()
                            if len(data) >= 5 and data[4] == 1:
                                sb_enabled = True
                                break
                    except OSError:
                        continue
        except OSError:
            pass

    results.append(_r(
        cat, "Pass" if sb_enabled else "Info",
        f"UEFI Secure Boot: {'enabled' if sb_enabled else 'disabled or not UEFI'}",
        severity="Medium",
        details=f"Secure Boot active: {sb_enabled}",
        remediation=(
            "Enable in UEFI firmware settings. Required for STIG compliance "
            "on physical hardware. VMs may not support."
        ),
        cross_references={
            "DistBaseline": "SecureBoot", "NIST": "SI-7", "STIG": "V-230469",
            "ACSC": "ISM-1411",
        },
    ))

    # IMA / EVM
    ima_runtime = file_exists("/sys/kernel/security/ima/runtime_measurements_count")
    evm_present = file_exists("/sys/kernel/security/evm")
    results.append(_r(
        cat, "Info",
        f"Kernel integrity: IMA={ima_runtime}, EVM={evm_present}",
        severity="Informational",
        details=(
            f"IMA runtime measurements: {ima_runtime}, "
            f"EVM (Extended Verification Module): {evm_present}"
        ),
        cross_references={
            "DistBaseline": "Kernel-IMA", "NIST": "SI-7", "NSA": "INTEGRITY-1.1",
        },
    ))

    # eBPF capabilities
    bpf_jit = read_sysctl("kernel.unprivileged_bpf_disabled")
    bpf_hardening = bpf_jit == "1" or bpf_jit == "2"
    results.append(_r(
        cat, "Pass" if bpf_hardening else "Warning",
        f"eBPF unprivileged users disabled: {bpf_hardening}",
        severity="Medium",
        details=f"kernel.unprivileged_bpf_disabled = {bpf_jit or 'unset'}",
        remediation=(
            "echo 'kernel.unprivileged_bpf_disabled = 2' >> /etc/sysctl.d/99-bpf.conf "
            "&& sysctl --system"
        ),
        cross_references={
            "DistBaseline": "Kernel-BPF", "NIST": "SC-39", "NSA": "KERN-1.6",
        },
    ))

    # Yama ptrace_scope
    ptrace_scope = read_sysctl("kernel.yama.ptrace_scope")
    ptrace_ok = ptrace_scope in ("1", "2", "3")
    results.append(_r(
        cat, "Pass" if ptrace_ok else "Fail",
        "Yama ptrace_scope >= 1 (restricts ptrace to direct children)",
        severity="High",
        details=f"kernel.yama.ptrace_scope = {ptrace_scope or 'unset'}",
        remediation=(
            "echo 'kernel.yama.ptrace_scope = 1' >> /etc/sysctl.d/99-yama.conf "
            "&& sysctl --system"
        ),
        cross_references={
            "DistBaseline": "Kernel-Yama", "NIST": "AC-6(10)", "CIS": "1.5.4",
            "STIG": "V-230266",
        },
    ))

    # Module loading restriction
    modules_disabled = read_sysctl("kernel.modules_disabled")
    if modules_disabled == "1":
        results.append(_r(
            cat, "Pass",
            "Kernel module loading disabled",
            severity="Medium",
            details="kernel.modules_disabled = 1 (cannot be reverted without reboot)",
            cross_references={
                "DistBaseline": "Kernel-Modules", "NIST": "CM-7(5)",
            },
        ))

    return results


def _check_cross_distro_systemd_hardening(os_info) -> List[AuditResult]:
    """Cross-distribution systemd service hardening."""
    results: List[AuditResult] = []
    if os_info.init_system != "systemd":
        return results

    cat = "DistBaseline - systemd Hardening"

    # systemd-analyze security
    if command_available("systemd-analyze"):
        rc, out, _ = run_command(
            ["systemd-analyze", "security", "--no-pager"], timeout=10.0
        )
        if rc == 0 and out:
            # Count UNSAFE (red) services
            unsafe_count = sum(
                1 for line in out.splitlines()
                if "UNSAFE" in line or "EXPOSED" in line
            )
            results.append(_r(
                cat, "Info",
                f"systemd service security analysis: {unsafe_count} services flagged",
                severity="Medium",
                details=(
                    f"systemd-analyze security report: "
                    f"{unsafe_count} services with UNSAFE/EXPOSED rating"
                ),
                remediation=(
                    "Review each service: systemd-analyze security <unit>. "
                    "Add hardening directives in /etc/systemd/system/<unit>.d/override.conf"
                ),
                cross_references={
                    "DistBaseline": "Systemd-Hardening", "NIST": "CM-6",
                    "NSA": "PROC-1.1",
                },
            ))

    # journald compression and persistence
    journald_conf = read_file_safe("/etc/systemd/journald.conf")
    journald_d = list_directory("/etc/systemd/journald.conf.d", suffix=".conf")
    combined_journal_conf = journald_conf
    for f in journald_d:
        combined_journal_conf += "\n" + read_file_safe(
            os.path.join("/etc/systemd/journald.conf.d", f)
        )

    compress = "Compress=yes" in combined_journal_conf or "Compress=true" in combined_journal_conf
    seal = "Seal=yes" in combined_journal_conf
    forward_to_syslog = "ForwardToSyslog=yes" in combined_journal_conf

    results.append(_r(
        cat, "Pass" if seal else "Info",
        f"journald FSS sealing: {seal}",
        severity="Medium",
        details=(
            f"Compress: {compress}, Seal: {seal}, ForwardToSyslog: {forward_to_syslog}"
        ),
        remediation=(
            "Set Seal=yes in journald.conf and run journalctl --setup-keys. "
            "Provides forward-secure cryptographic sealing of log entries."
        ),
        cross_references={
            "DistBaseline": "Systemd-JournalSeal", "NIST": "AU-9", "PCI-DSS": "10.5",
        },
    ))

    return results


def _check_cross_distro_tpm(os_info) -> List[AuditResult]:
    """Cross-distribution TPM 2.0 capabilities."""
    results: List[AuditResult] = []
    cat = "DistBaseline - TPM"

    # TPM 2.0 device
    tpm_device = file_exists("/dev/tpm0") or file_exists("/dev/tpmrm0")
    tpm_userspace = command_available("tpm2_pcrread")
    results.append(_r(
        cat, "Info" if tpm_device else "Info",
        f"TPM 2.0: device={tpm_device}, tools={tpm_userspace}",
        severity="Informational",
        details=(
            f"/dev/tpm0 or /dev/tpmrm0: {tpm_device}, "
            f"tpm2-tools: {tpm_userspace}"
        ),
        remediation=(
            "Install: apt-get install -y tpm2-tools (Debian) or "
            "dnf install -y tpm2-tools (RHEL family). "
            "TPM enables measured boot, key sealing, and remote attestation."
        ),
        cross_references={
            "DistBaseline": "TPM", "NIST": "SC-12", "NSA": "INTEGRITY-2.1",
        },
    ))

    # TPM event log
    tpm_event_log = file_exists("/sys/kernel/security/tpm0/binary_bios_measurements")
    if tpm_event_log:
        results.append(_r(
            cat, "Info",
            "TPM measured boot event log present",
            severity="Informational",
            details="/sys/kernel/security/tpm0/binary_bios_measurements available",
            cross_references={
                "DistBaseline": "TPM-EventLog", "NIST": "SI-7",
            },
        ))

    return results


def _check_cross_distro_audit_dispatcher(os_info) -> List[AuditResult]:
    """Audit dispatcher and remote audit logging."""
    results: List[AuditResult] = []
    cat = "DistBaseline - Audit Dispatcher"

    # audisp-remote configuration (audit log centralization)
    audisp_remote_conf = read_file_safe("/etc/audit/audisp-remote.conf") or \
                         read_file_safe("/etc/audisp/audisp-remote.conf")
    audisp_active = "remote_server" in audisp_remote_conf
    results.append(_r(
        cat, "Pass" if audisp_active else "Info",
        f"audisp-remote remote audit forwarding: {audisp_active}",
        severity="Medium",
        details=f"audisp-remote configured: {audisp_active}",
        remediation=(
            "Edit /etc/audit/audisp-remote.conf, set remote_server. "
            "Enable: systemctl enable --now audit-rules. Forwards to "
            "auditd remote receiver on SIEM."
        ),
        cross_references={
            "DistBaseline": "Audit-Dispatcher", "NIST": "AU-6(3)",
            "STIG": "V-230484", "PCI-DSS": "10.5.4",
        },
    ))

    return results


# Save reference to original run_checks
_original_run_checks_distbaseline = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the expanded DistBaseline module.

    Combines baseline per-family checks with the v3.1 expansion adding deep
    distro-specific coverage and cross-distribution kernel/systemd/TPM/audit
    hardening.
    """
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_distbaseline(shared_data)

    os_info = shared_data.get("v3_os_info")
    if os_info is None:
        os_info = os_detection.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        results.extend(_check_ubuntu_extended(os_info))
        results.extend(_check_debian_extended(os_info))
        results.extend(_check_rhel_extended(os_info))
        results.extend(_check_suse_extended(os_info))
        results.extend(_check_arch_extended(os_info))
        results.extend(_check_alpine_extended(os_info))
        results.extend(_check_cross_distro_kernel_security(os_info))
        results.extend(_check_cross_distro_systemd_hardening(os_info))
        results.extend(_check_cross_distro_tpm(os_info))
        results.extend(_check_cross_distro_audit_dispatcher(os_info))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled exception in DistBaseline v3.1 expansion")
        results.append(_r(
            "DistBaseline - Error", "Error",
            f"DistBaseline v3.1 expansion exception: {exc!r}",
            severity="Medium", details=str(exc),
        ))

    return results

# ===========================================================================
# v3.2 EXPANSION - DistBaseline Cross-Distribution Deep Coverage
# ---------------------------------------------------------------------------
# Cross-distribution checks firing on most/all Linux systems
# ===========================================================================


def _check_dist_kernel_module_signing(os_info) -> List[AuditResult]:
    """Kernel module signing enforcement."""
    results: List[AuditResult] = []
    cat = "DistBaseline - Module Signing"

    config = read_file_safe("/proc/config.gz")
    if not config:
        rc, kver, _ = run_command(["uname", "-r"], timeout=2.0)
        if rc == 0:
            config = read_file_safe(f"/boot/config-{kver.strip()}")

    sig_force = "CONFIG_MODULE_SIG_FORCE=y" in config
    sig_all = "CONFIG_MODULE_SIG_ALL=y" in config
    sig_present = "CONFIG_MODULE_SIG=y" in config

    results.append(_r(
        cat, "Pass" if sig_force else ("Info" if sig_present else "Warning"),
        f"Kernel module signature enforcement: {sig_force}",
        severity="High",
        details=(
            f"CONFIG_MODULE_SIG: {sig_present}, "
            f"CONFIG_MODULE_SIG_FORCE: {sig_force}, "
            f"CONFIG_MODULE_SIG_ALL: {sig_all}"
        ),
        remediation=(
            "Enable at kernel build: CONFIG_MODULE_SIG_FORCE=y. "
            "Distribution kernels often have SIG=y but not FORCE=y."
        ),
        cross_references={
            "DistBaseline": "Kernel-Module-Signing", "NIST": "SI-7",
            "STIG": "V-230484",
        },
    ))

    tainted = read_file_safe("/proc/sys/kernel/tainted").strip()
    try:
        tainted_int = int(tainted) if tainted else 0
    except ValueError:
        tainted_int = 0
    tainted_unsigned = bool(tainted_int & (1 << 13))
    tainted_oot = bool(tainted_int & (1 << 12))

    results.append(_r(
        cat, "Pass" if tainted_int == 0 else "Warning",
        f"Kernel taint state: {tainted_int}",
        severity="Medium",
        details=(
            f"Tainted bitmask: {tainted_int}. "
            f"Unsigned module loaded: {tainted_unsigned}, "
            f"Out-of-tree module: {tainted_oot}"
        ),
        remediation=(
            "Investigate /proc/sys/kernel/tainted bits. Reboot may clear if "
            "unsigned modules are not auto-loaded."
        ),
        cross_references={
            "DistBaseline": "Kernel-Tainted", "NIST": "SI-7",
        },
    ))

    return results


def _check_dist_ima_evm(os_info) -> List[AuditResult]:
    """IMA / EVM."""
    results: List[AuditResult] = []
    cat = "DistBaseline - IMA/EVM"

    ima_dir = directory_exists("/sys/kernel/security/ima")
    evm_present = file_exists("/sys/kernel/security/evm")

    results.append(_r(
        cat, "Pass" if ima_dir else "Info",
        f"IMA (Integrity Measurement Architecture) available: {ima_dir}",
        severity="Medium",
        details=f"/sys/kernel/security/ima present: {ima_dir}",
        remediation=(
            "Enable IMA at boot: add 'ima_policy=tcb ima_appraise=enforce' "
            "to GRUB_CMDLINE_LINUX. Provides file integrity measurement."
        ),
        cross_references={
            "DistBaseline": "IMA", "NIST": "SI-7", "STIG": "V-230523",
        },
    ))

    if ima_dir:
        ima_policy = read_file_safe("/sys/kernel/security/ima/policy")
        results.append(_r(
            cat, "Pass" if ima_policy and "appraise" in ima_policy else "Info",
            f"IMA appraisal policy active: {bool(ima_policy and 'appraise' in ima_policy)}",
            severity="Medium",
            details=f"IMA policy bytes: {len(ima_policy)}",
            remediation=(
                "Configure IMA policy to enforce appraisal."
            ),
            cross_references={
                "DistBaseline": "IMA-Policy",
            },
        ))

    results.append(_r(
        cat, "Pass" if evm_present else "Info",
        f"EVM (Extended Verification Module) available: {evm_present}",
        severity="Low",
        details=f"/sys/kernel/security/evm present: {evm_present}",
        remediation=(
            "EVM extends IMA with HMAC over file metadata. Requires TPM-backed "
            "or kernel master key. See evmctl tool."
        ),
        cross_references={
            "DistBaseline": "EVM", "NIST": "SI-7(8)",
        },
    ))

    return results


def _check_dist_kernel_lockdown(os_info) -> List[AuditResult]:
    """Kernel Lockdown mode."""
    results: List[AuditResult] = []
    cat = "DistBaseline - Kernel Lockdown"

    lockdown_path = "/sys/kernel/security/lockdown"
    lockdown_present = file_exists(lockdown_path)

    if lockdown_present:
        content = read_file_safe(lockdown_path)
        active = "none"
        for token in ["[none]", "[integrity]", "[confidentiality]"]:
            if token in content:
                active = token.strip("[]")
                break
        lockdown_active = active in ("integrity", "confidentiality")
        results.append(_r(
            cat, "Pass" if lockdown_active else "Warning",
            f"Kernel Lockdown mode: {active}",
            severity="Medium",
            details=f"Lockdown content: {content.strip()}",
            remediation=(
                "Enable Lockdown via boot: lockdown=integrity in GRUB_CMDLINE_LINUX "
                "(or 'confidentiality' for stricter mode). Requires Secure Boot."
            ),
            cross_references={
                "DistBaseline": "Lockdown", "NIST": "SI-7", "ISO27001": "A.8.31",
            },
        ))
    else:
        results.append(_r(
            cat, "Info",
            "Kernel Lockdown not available on this kernel",
            severity="Informational",
            details="/sys/kernel/security/lockdown not present (kernel < 5.4 or feature disabled)",
            cross_references={
                "DistBaseline": "Lockdown",
            },
        ))

    return results


def _check_dist_firmware_updates(os_info) -> List[AuditResult]:
    """Firmware update tooling (fwupd)."""
    results: List[AuditResult] = []
    cat = "DistBaseline - Firmware Updates"

    fwupd_present = (
        command_available("fwupdmgr") or
        systemd_active("fwupd.service") in ("active", "inactive")
    )
    results.append(_r(
        cat, "Pass" if fwupd_present else "Info",
        f"fwupd firmware update daemon installed: {fwupd_present}",
        severity="Medium",
        details=f"fwupdmgr available: {command_available('fwupdmgr')}",
        remediation=(
            "Install: apt-get install -y fwupd (Debian/Ubuntu) or "
            "dnf install -y fwupd (RHEL family). Run: fwupdmgr refresh && "
            "fwupdmgr get-updates && fwupdmgr update"
        ),
        cross_references={
            "DistBaseline": "Firmware", "NIST": "SI-2", "ISO27001": "A.8.7",
        },
    ))

    return results


def _check_dist_systemd_analyze_security(os_info) -> List[AuditResult]:
    """systemd-analyze security score for critical services."""
    results: List[AuditResult] = []
    cat = "DistBaseline - systemd Security Score"

    if not command_available("systemd-analyze"):
        return results

    critical_units = ["sshd.service", "auditd.service", "rsyslog.service",
                     "cron.service", "crond.service", "systemd-journald.service"]
    scores = {}
    for unit in critical_units:
        rc, out, _ = run_command(
            ["systemd-analyze", "security", unit, "--no-pager"],
            timeout=10.0
        )
        if rc == 0 and out:
            m = re.search(r"Overall exposure level for .+:\s+([\d.]+)", out)
            if m:
                scores[unit] = float(m.group(1))

    if scores:
        avg = sum(scores.values()) / len(scores)
        results.append(_r(
            cat, "Pass" if avg < 6.0 else "Warning",
            f"systemd-analyze security average: {avg:.1f} (lower=better)",
            severity="Medium",
            details=f"Per-unit scores: {scores}",
            remediation=(
                "Apply systemd hardening directives: PrivateTmp=true, "
                "ProtectSystem=strict, NoNewPrivileges=true, ProtectHome=true, "
                "etc. via /etc/systemd/system/<unit>.d/override.conf"
            ),
            cross_references={
                "DistBaseline": "systemd-Security", "NIST": "SC-39",
                "STIG": "V-230345",
            },
        ))

    return results


def _check_dist_pam_stack_depth(os_info) -> List[AuditResult]:
    """PAM stack hardening across modules."""
    results: List[AuditResult] = []
    cat = "DistBaseline - PAM Stack"

    pam_files = ["/etc/pam.d/system-auth", "/etc/pam.d/common-auth",
                 "/etc/pam.d/password-auth"]
    has_faillock = False
    has_tally = False
    has_pwquality = False

    for pf in pam_files:
        c = read_file_safe(pf)
        if not c:
            continue
        if "pam_faillock" in c:
            has_faillock = True
        if "pam_tally2" in c:
            has_tally = True
        if "pam_pwquality" in c or "pam_cracklib" in c:
            has_pwquality = True

    results.append(_r(
        cat, "Pass" if (has_faillock or has_tally) else "Fail",
        f"PAM account lockout (faillock/tally2): {has_faillock or has_tally}",
        severity="High",
        details=f"faillock: {has_faillock}, tally2: {has_tally}",
        remediation=(
            "RHEL: authselect select sssd with-faillock. "
            "Debian: edit /etc/pam.d/common-auth to include "
            "'auth required pam_faillock.so preauth deny=5 unlock_time=900'"
        ),
        cross_references={
            "DistBaseline": "PAM-Lockout", "NIST": "AC-7",
            "STIG": "V-230332", "CIS": "5.4.2",
        },
    ))

    results.append(_r(
        cat, "Pass" if has_pwquality else "Fail",
        f"PAM password quality enforcement (pwquality/cracklib): {has_pwquality}",
        severity="High",
        details=f"pam_pwquality or pam_cracklib loaded: {has_pwquality}",
        remediation=(
            "Add: password requisite pam_pwquality.so retry=3 minlen=14 "
            "dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1"
        ),
        cross_references={
            "DistBaseline": "PAM-Pwquality", "NIST": "IA-5",
            "STIG": "V-230367", "CIS": "5.4.1",
        },
    ))

    return results


def _check_dist_grub_integrity(os_info) -> List[AuditResult]:
    """GRUB bootloader integrity."""
    results: List[AuditResult] = []
    cat = "DistBaseline - Bootloader"

    grub_files = [
        "/etc/grub.d/40_custom",
        "/etc/grub.d/01_users",
        "/boot/grub2/user.cfg",
        "/boot/grub/grub.cfg",
    ]
    has_grub_pw = False
    for gf in grub_files:
        c = read_file_safe(gf)
        if "password_pbkdf2" in c or "set superusers" in c:
            has_grub_pw = True
            break

    results.append(_r(
        cat, "Pass" if has_grub_pw else "Warning",
        f"GRUB bootloader password protection: {has_grub_pw}",
        severity="High",
        details=f"GRUB password configured: {has_grub_pw}",
        remediation=(
            "Set GRUB password: grub-mkpasswd-pbkdf2; add to /etc/grub.d/01_users; "
            "update-grub. Prevents single-user mode bypass at console."
        ),
        cross_references={
            "DistBaseline": "GRUB-Password", "NIST": "AC-3", "STIG": "V-230234",
            "CIS": "1.4.1",
        },
    ))

    grub_cfg = "/boot/grub/grub.cfg"
    if not file_exists(grub_cfg):
        grub_cfg = "/boot/grub2/grub.cfg"
    if file_exists(grub_cfg):
        mode = file_mode(grub_cfg)
        if mode is not None:
            try:
                # file_mode() returns an int already (st_mode & 0o7777),
                # so use it directly. Earlier code incorrectly called
                # int(mode, 8) which raises TypeError because the second
                # argument is only valid when the first argument is a string.
                mode_int = mode if isinstance(mode, int) else int(str(mode), 8)
                mode_ok = (mode_int & 0o077) == 0
                results.append(_r(
                    cat, "Pass" if mode_ok else "Fail",
                    f"GRUB config file permissions ({oct(mode_int)})",
                    severity="Medium",
                    details=f"{grub_cfg} mode = {oct(mode_int)}",
                    remediation=(
                        f"chown root:root {grub_cfg}; chmod og-rwx {grub_cfg}"
                    ),
                    cross_references={
                        "DistBaseline": "GRUB-Perms", "NIST": "AC-3",
                        "STIG": "V-230236", "CIS": "1.4.2",
                    },
                ))
            except (ValueError, TypeError):
                pass

    sb_path = "/sys/firmware/efi/efivars"
    sb_efi = directory_exists(sb_path)
    sb_status = "unknown"
    if sb_efi and command_available("mokutil"):
        rc, out, _ = run_command(["mokutil", "--sb-state"], timeout=5.0)
        if rc == 0:
            sb_status = out.strip().split("\n")[0] if out else "unknown"
    results.append(_r(
        cat, "Pass" if "enabled" in sb_status.lower() else "Info",
        f"Secure Boot status: {sb_status}",
        severity="Medium",
        details=f"EFI: {sb_efi}, mokutil --sb-state: {sb_status}",
        remediation=(
            "Enable Secure Boot in firmware (UEFI). Provides chain-of-trust "
            "validation for bootloader and kernel."
        ),
        cross_references={
            "DistBaseline": "Secure-Boot", "NIST": "SI-7", "STIG": "V-230278",
        },
    ))

    return results


def _check_dist_filesystem_protections(os_info) -> List[AuditResult]:
    """Filesystem protection sysctls."""
    results: List[AuditResult] = []
    cat = "DistBaseline - FS Protections"

    fs_sysctls = {
        "fs.protected_hardlinks": "1",
        "fs.protected_symlinks": "1",
        "fs.protected_fifos": "1",
        "fs.protected_regular": "1",
        "fs.suid_dumpable": "0",
    }
    misc = []
    for key, expected in fs_sysctls.items():
        actual = read_sysctl(key)
        if actual != expected:
            misc.append(f"{key}={actual or 'unset'}")

    results.append(_r(
        cat, "Pass" if not misc else "Fail",
        f"Filesystem protection sysctls ({len(fs_sysctls) - len(misc)}/{len(fs_sysctls)})",
        severity="High",
        details=f"Misconfigured: {misc}",
        remediation=(
            "echo -e 'fs.protected_hardlinks = 1\\n"
            "fs.protected_symlinks = 1\\n"
            "fs.protected_fifos = 1\\n"
            "fs.protected_regular = 1\\n"
            "fs.suid_dumpable = 0' >> /etc/sysctl.d/99-fs-protect.conf; sysctl --system"
        ),
        cross_references={
            "DistBaseline": "FS-Sysctls", "NIST": "SC-7", "STIG": "V-230267",
            "CIS": "1.6", "ISO27001": "A.8.4",
        },
    ))

    return results


def _check_dist_network_sysctls_extended(os_info) -> List[AuditResult]:
    """Extended network sysctl hardening."""
    results: List[AuditResult] = []
    cat = "DistBaseline - Network Sysctls"

    net_sysctls = {
        "net.ipv4.conf.all.accept_source_route": "0",
        "net.ipv4.conf.default.accept_source_route": "0",
        "net.ipv4.conf.all.accept_redirects": "0",
        "net.ipv4.conf.default.accept_redirects": "0",
        "net.ipv4.conf.all.secure_redirects": "0",
        "net.ipv4.conf.default.secure_redirects": "0",
        "net.ipv4.conf.all.send_redirects": "0",
        "net.ipv4.conf.default.send_redirects": "0",
        "net.ipv4.conf.all.log_martians": "1",
        "net.ipv4.conf.default.log_martians": "1",
        "net.ipv4.icmp_echo_ignore_broadcasts": "1",
        "net.ipv4.icmp_ignore_bogus_error_responses": "1",
        "net.ipv4.tcp_syncookies": "1",
        "net.ipv6.conf.all.accept_redirects": "0",
        "net.ipv6.conf.default.accept_redirects": "0",
        "net.ipv6.conf.all.accept_source_route": "0",
        "net.ipv6.conf.default.accept_source_route": "0",
        "net.ipv6.conf.all.accept_ra": "0",
        "net.ipv6.conf.default.accept_ra": "0",
    }
    misc = []
    for key, expected in net_sysctls.items():
        actual = read_sysctl(key)
        if actual != expected:
            misc.append(f"{key}={actual or 'unset'}")

    results.append(_r(
        cat, "Pass" if len(misc) <= 3 else "Fail",
        f"Network hardening sysctls ({len(net_sysctls) - len(misc)}/{len(net_sysctls)} ok)",
        severity="High",
        details=f"Misconfigured ({len(misc)}): first 5: {misc[:5]}",
        remediation=(
            "Apply CIS Benchmark network sysctls in /etc/sysctl.d/99-network-hardening.conf "
            "with all redirect/source-route disabled and martian logging enabled."
        ),
        cross_references={
            "DistBaseline": "Network-Sysctls", "NIST": "SC-7",
            "CIS": "3.3", "STIG": "V-230540",
        },
    ))

    return results


def _check_dist_audit_rules_coverage(os_info) -> List[AuditResult]:
    """Auditd rule coverage breadth."""
    results: List[AuditResult] = []
    cat = "DistBaseline - Audit Rule Coverage"

    audit_rules = read_file_safe("/etc/audit/audit.rules")
    rules_d = list_directory("/etc/audit/rules.d", suffix=".rules")
    combined = audit_rules
    for f in rules_d:
        combined += "\n" + read_file_safe(os.path.join("/etc/audit/rules.d", f))

    active_rules = [
        l for l in combined.splitlines()
        if l.strip() and not l.strip().startswith("#")
    ]

    required_watches = {
        "/etc/passwd": False,
        "/etc/group": False,
        "/etc/shadow": False,
        "/etc/gshadow": False,
        "/etc/sudoers": False,
        "/etc/ssh/sshd_config": False,
        "/var/log/wtmp": False,
        "/var/log/btmp": False,
        "/etc/audit/audit.rules": False,
    }
    for path in required_watches:
        if path in combined:
            required_watches[path] = True

    covered = sum(1 for v in required_watches.values() if v)
    results.append(_r(
        cat, "Pass" if covered >= 7 else "Fail",
        f"Audit rule coverage: {covered}/{len(required_watches)} key paths watched",
        severity="High",
        details=(
            f"Active rules: {len(active_rules)}, "
            f"Watched: {[k for k, v in required_watches.items() if v]}"
        ),
        remediation=(
            "Use Neo23x0/auditd ruleset (github.com/Neo23x0/auditd) as a "
            "comprehensive baseline covering all CIS recommendations."
        ),
        cross_references={
            "DistBaseline": "Audit-Coverage", "NIST": "AU-2",
            "CIS": "4.1", "STIG": "V-230400",
        },
    ))

    return results


def _check_dist_repo_hygiene(os_info) -> List[AuditResult]:
    """Package repository hygiene."""
    results: List[AuditResult] = []
    cat = "DistBaseline - Repo Hygiene"

    if os_info.is_debian_family():
        sources_list = read_file_safe("/etc/apt/sources.list")
        sources_d = list_directory("/etc/apt/sources.list.d")
        all_sources = sources_list
        for f in sources_d:
            all_sources += "\n" + read_file_safe(
                os.path.join("/etc/apt/sources.list.d", f)
            )

        active_sources = [
            l for l in all_sources.splitlines()
            if l.strip() and not l.strip().startswith("#") and (
                l.strip().startswith("deb") or l.strip().startswith("URIs")
            )
        ]

        http_only = [
            l for l in active_sources
            if "http://" in l and "https://" not in l and "[trusted=yes]" not in l
        ]
        results.append(_r(
            cat, "Pass" if not http_only else "Warning",
            f"APT sources HTTPS coverage: {len(active_sources) - len(http_only)}/{len(active_sources)}",
            severity="Medium",
            details=f"HTTP-only sources: {len(http_only)}",
            remediation=(
                "Update /etc/apt/sources.list to use https:// URLs where available."
            ),
            cross_references={
                "DistBaseline": "APT-Repo-HTTPS", "NIST": "SC-8",
            },
        ))

    elif os_info.is_redhat_family():
        repo_files = list_directory("/etc/yum.repos.d", suffix=".repo")
        all_repos = ""
        for f in repo_files:
            all_repos += read_file_safe(os.path.join("/etc/yum.repos.d", f))

        repos_no_gpg = re.findall(r"^\s*gpgcheck\s*=\s*0", all_repos, re.MULTILINE)
        results.append(_r(
            cat, "Pass" if not repos_no_gpg else "Fail",
            f"YUM/DNF repos with gpgcheck=0: {len(repos_no_gpg)}",
            severity="High",
            details=f"Disabled gpgcheck count: {len(repos_no_gpg)}",
            remediation=(
                "Set gpgcheck=1 in all .repo files. Verify gpgkey is valid and from vendor."
            ),
            cross_references={
                "DistBaseline": "YUM-GPG", "NIST": "CM-5(3)",
                "STIG": "V-230223",
            },
        ))

    return results


def _check_dist_skel_hardening(os_info) -> List[AuditResult]:
    """/etc/skel hardening."""
    results: List[AuditResult] = []
    cat = "DistBaseline - User Skeleton"

    if not directory_exists("/etc/skel"):
        return results

    bashrc = read_file_safe("/etc/skel/.bashrc")
    profile = read_file_safe("/etc/skel/.profile")
    has_umask = ("umask" in bashrc) or ("umask" in profile)
    umask_strict = False
    for c in [bashrc, profile]:
        for m in re.finditer(r"umask\s+(\d+)", c):
            try:
                if int(m.group(1), 8) >= 0o077:
                    umask_strict = True
            except ValueError:
                pass

    results.append(_r(
        cat, "Pass" if umask_strict else "Info",
        f"/etc/skel umask 077 or stricter: {umask_strict}",
        severity="Low",
        details=f"umask line found: {has_umask}, strict: {umask_strict}",
        remediation=(
            "Add 'umask 077' to /etc/skel/.bashrc or /etc/skel/.profile."
        ),
        cross_references={
            "DistBaseline": "Skel-Umask", "NIST": "AC-3", "CIS": "5.5.5",
        },
    ))

    login_defs = read_file_safe("/etc/login.defs")
    umask_match = re.search(r"^\s*UMASK\s+(\d+)", login_defs, re.MULTILINE)
    login_umask = umask_match.group(1) if umask_match else "022"
    try:
        login_umask_strict = int(login_umask, 8) >= 0o077
    except ValueError:
        login_umask_strict = False

    results.append(_r(
        cat, "Pass" if login_umask_strict else "Warning",
        f"/etc/login.defs UMASK 077 or stricter: {login_umask_strict} (={login_umask})",
        severity="Medium",
        details=f"UMASK = {login_umask}",
        remediation=(
            "In /etc/login.defs: UMASK 077  (default for new users)"
        ),
        cross_references={
            "DistBaseline": "Login-UMASK", "NIST": "AC-3", "CIS": "5.5.5",
        },
    ))

    return results


def _check_dist_critical_world_writable(os_info) -> List[AuditResult]:
    """Critical world-writable file/dir check."""
    results: List[AuditResult] = []
    cat = "DistBaseline - World-Writable"

    rc, out, _ = run_command(
        ["find", "/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin",
         "-xdev", "-type", "f", "-perm", "-002", "-not", "-path", "*/proc/*"],
        timeout=15.0
    )
    ww_files = []
    if rc == 0 and out:
        ww_files = [l.strip() for l in out.splitlines() if l.strip()][:20]

    results.append(_r(
        cat, "Pass" if not ww_files else "Fail",
        f"Critical paths world-writable file count: {len(ww_files)}",
        severity="High",
        details=f"Files (first 5): {ww_files[:5]}",
        remediation=(
            "Remove world-write permission: chmod o-w <file>. "
            "Investigate why each became world-writable."
        ),
        cross_references={
            "DistBaseline": "World-Writable", "NIST": "AC-3",
            "CIS": "6.1.10", "STIG": "V-230258",
        },
    ))

    return results


def _check_dist_unowned_files(os_info) -> List[AuditResult]:
    """Unowned (orphan) file detection."""
    results: List[AuditResult] = []
    cat = "DistBaseline - Unowned Files"

    rc, out, _ = run_command(
        ["find", "/etc", "/var", "/home", "/root", "/opt",
         "-xdev", "-nouser",
         "-not", "-path", "/proc/*", "-not", "-path", "/sys/*", "-not", "-path", "/run/*"],
        timeout=15.0
    )
    nouser = []
    if rc == 0 and out:
        nouser = [l.strip() for l in out.splitlines() if l.strip()][:20]

    rc2, out2, _ = run_command(
        ["find", "/etc", "/var", "/home", "/root", "/opt",
         "-xdev", "-nogroup",
         "-not", "-path", "/proc/*", "-not", "-path", "/sys/*", "-not", "-path", "/run/*"],
        timeout=15.0
    )
    nogroup = []
    if rc2 == 0 and out2:
        nogroup = [l.strip() for l in out2.splitlines() if l.strip()][:20]

    total = len(nouser) + len(nogroup)
    results.append(_r(
        cat, "Pass" if total == 0 else "Warning",
        f"Unowned files (nouser={len(nouser)}, nogroup={len(nogroup)})",
        severity="Medium",
        details=(
            f"Sample nouser: {nouser[:3]}, nogroup: {nogroup[:3]}"
            if total else "No unowned files found"
        ),
        remediation=(
            "Reassign ownership: chown root:root <file>. Or remove if orphaned."
        ),
        cross_references={
            "DistBaseline": "Unowned-Files", "NIST": "AC-3",
            "CIS": "6.1.11", "STIG": "V-230322",
        },
    ))

    return results


def _check_dist_unused_filesystems(os_info) -> List[AuditResult]:
    """Unused filesystem types disabled."""
    results: List[AuditResult] = []
    cat = "DistBaseline - Unused Filesystems"

    modprobe_d = list_directory("/etc/modprobe.d", suffix=".conf")
    combined_modprobe = ""
    for f in modprobe_d:
        combined_modprobe += "\n" + read_file_safe(os.path.join("/etc/modprobe.d", f))

    unused_fs = ["cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "udf"]
    blocked = []
    for fs in unused_fs:
        if re.search(rf"^\s*install\s+{fs}\s+/bin/(?:false|true)", combined_modprobe, re.MULTILINE):
            blocked.append(fs)
        elif re.search(rf"^\s*blacklist\s+{fs}", combined_modprobe, re.MULTILINE):
            blocked.append(fs)

    results.append(_r(
        cat, "Pass" if len(blocked) >= 4 else "Warning",
        f"Unused filesystems blocked: {len(blocked)}/{len(unused_fs)}",
        severity="Medium",
        details=f"Blocked: {blocked}",
        remediation=(
            "Create /etc/modprobe.d/CIS.conf with: "
            "install cramfs /bin/false (and same for freevxfs, jffs2, hfs, hfsplus, udf)"
        ),
        cross_references={
            "DistBaseline": "Unused-FS", "NIST": "CM-7",
            "CIS": "1.1.1", "STIG": "V-230255",
        },
    ))

    return results


# Save reference
_original_run_checks_distbaseline_v32 = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the v3.2 expanded DistBaseline module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_distbaseline_v32(shared_data)

    os_info = shared_data.get("v3_os_info")
    if os_info is None:
        os_info = os_detection.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        results.extend(_check_dist_kernel_module_signing(os_info))
        results.extend(_check_dist_ima_evm(os_info))
        results.extend(_check_dist_kernel_lockdown(os_info))
        results.extend(_check_dist_firmware_updates(os_info))
        results.extend(_check_dist_systemd_analyze_security(os_info))
        results.extend(_check_dist_pam_stack_depth(os_info))
        results.extend(_check_dist_grub_integrity(os_info))
        results.extend(_check_dist_filesystem_protections(os_info))
        results.extend(_check_dist_network_sysctls_extended(os_info))
        results.extend(_check_dist_audit_rules_coverage(os_info))
        results.extend(_check_dist_repo_hygiene(os_info))
        results.extend(_check_dist_skel_hardening(os_info))
        results.extend(_check_dist_critical_world_writable(os_info))
        results.extend(_check_dist_unowned_files(os_info))
        results.extend(_check_dist_unused_filesystems(os_info))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled exception in DistBaseline v3.2 expansion")
        results.append(_r(
            "DistBaseline - Error", "Error",
            f"DistBaseline v3.2 expansion exception: {exc!r}",
            severity="Medium", details=str(exc),
        ))

    return results


# ===========================================================================
# v3.3 EXPANSION - DistBaseline Deep Coverage
# ---------------------------------------------------------------------------
# Adds:
#   - Filesystem mount option hardening (nosuid/nodev/noexec)
#   - systemd unit hardening per-critical-service
#   - Boot security: GRUB password, initramfs, kdump, SecureBoot
#   - TLS / system-wide crypto policies
#   - BPF / namespace restrictions
#   - Journal/syslog forwarding & rotation
#   - NTP/chrony hardening
#   - PAM stack additional depth
#   - Critical user/group ownership
#   - Per-distro additional checks
# ===========================================================================


def _check_dist_mount_options(os_info) -> List[AuditResult]:
    """Filesystem mount option hardening (CIS-aligned)."""
    results: List[AuditResult] = []
    cat = "DistBaseline - Mount Options"

    # Read mounted filesystems
    mounts = read_file_safe("/proc/mounts")
    mount_map: Dict[str, Dict[str, Any]] = {}
    for line in mounts.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            mount_map[parts[1]] = {
                "fstype": parts[2],
                "options": set(parts[3].split(",")),
            }

    # Check tmpfs / shared memory
    if "/dev/shm" in mount_map:
        opts = mount_map["/dev/shm"]["options"]
        required = {"nosuid", "nodev", "noexec"}
        missing = required - opts
        results.append(_r(
            cat, "Pass" if not missing else "Warning",
            f"DIST-MNT-1: /dev/shm hardened (missing: {sorted(missing) or 'none'})",
            severity="Medium",
            details=f"/dev/shm options: {sorted(opts)}",
            remediation=(
                "Add to /etc/fstab: tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0; "
                "then mount -o remount /dev/shm"
            ),
            cross_references={
                "CIS": "1.1.2.2", "STIG": "V-230511", "NIST": "CM-7",
            },
        ))

    # Check /tmp
    if "/tmp" in mount_map:
        opts = mount_map["/tmp"]["options"]
        required = {"nosuid", "nodev", "noexec"}
        missing = required - opts
        results.append(_r(
            cat, "Pass" if not missing else "Warning",
            f"DIST-MNT-2: /tmp hardened (missing: {sorted(missing) or 'none'})",
            severity="Medium",
            details=f"/tmp options: {sorted(opts)}",
            remediation=(
                "Mount /tmp as separate filesystem with nodev,nosuid,noexec. "
                "Modern systems: systemctl enable tmp.mount  (uses tmpfs with hardened opts)"
            ),
            cross_references={
                "CIS": "1.1.2.1", "STIG": "V-230292", "NIST": "CM-7",
            },
        ))
    else:
        results.append(_r(
            cat, "Info",
            "DIST-MNT-2: /tmp is not on a separate mount",
            severity="Informational",
            details="/tmp shares the root filesystem; mount-option hardening unavailable",
            remediation=(
                "For separation: create /tmp partition or enable tmp.mount unit"
            ),
            cross_references={
                "CIS": "1.1.2.1", "NIST": "CM-7",
            },
        ))

    # Check /var
    if "/var" in mount_map:
        results.append(_r(
            cat, "Pass",
            "DIST-MNT-3: /var on separate mount",
            severity="Low",
            details=f"/var options: {sorted(mount_map['/var']['options'])}",
            cross_references={
                "CIS": "1.1.3.1", "NIST": "CM-7",
            },
        ))

    # Check /var/log
    if "/var/log" in mount_map:
        results.append(_r(
            cat, "Pass",
            "DIST-MNT-4: /var/log on separate mount",
            severity="Low",
            details=f"/var/log options: {sorted(mount_map['/var/log']['options'])}",
            cross_references={
                "CIS": "1.1.4.1", "NIST": "AU-4",
            },
        ))

    # Check /home
    if "/home" in mount_map:
        opts = mount_map["/home"]["options"]
        nodev_set = "nodev" in opts
        results.append(_r(
            cat, "Pass" if nodev_set else "Info",
            f"DIST-MNT-5: /home nodev option ({'set' if nodev_set else 'not set'})",
            severity="Low",
            details=f"/home options: {sorted(opts)}",
            remediation=(
                "Add 'nodev' to /home mount options in /etc/fstab"
            ),
            cross_references={
                "CIS": "1.1.6.2", "NIST": "CM-7",
            },
        ))

    return results


def _check_dist_systemd_unit_hardening(os_info) -> List[AuditResult]:
    """systemd unit hardening for critical services."""
    results: List[AuditResult] = []
    cat = "DistBaseline - systemd Unit Hardening"

    if not command_available("systemctl"):
        return results

    # Critical services to inspect
    critical_units = ["sshd.service", "ssh.service", "systemd-journald.service",
                      "auditd.service", "rsyslog.service", "chronyd.service",
                      "cron.service", "crond.service"]

    hardened_count = 0
    inspected_count = 0
    hardening_directives = ["ProtectSystem=", "ProtectHome=", "PrivateTmp=",
                            "NoNewPrivileges=", "CapabilityBoundingSet=",
                            "RestrictNamespaces=", "MemoryDenyWriteExecute=",
                            "RestrictRealtime=", "SystemCallFilter="]

    for unit in critical_units:
        rc, out, _ = run_command(["systemctl", "show", unit,
                                  "--no-page"], timeout=3.0)
        if rc != 0 or not out:
            continue
        # Skip if unit doesn't exist
        if "LoadState=not-found" in out or "LoadState=masked" in out:
            continue
        inspected_count += 1
        # Count how many hardening directives are non-default
        hardened_directives = 0
        for directive in hardening_directives:
            for line in out.splitlines():
                if line.startswith(directive):
                    val = line.split("=", 1)[1].strip()
                    if val and val.lower() not in ("no", "false", "[unset]",
                                                    "infinity", ""):
                        hardened_directives += 1
                    break
        if hardened_directives >= 2:
            hardened_count += 1

    if inspected_count > 0:
        ratio = hardened_count / inspected_count
        results.append(_r(
            cat, "Pass" if ratio >= 0.5 else "Warning",
            f"DIST-SYSD-1: Critical services with systemd hardening "
            f"({hardened_count}/{inspected_count})",
            severity="Medium",
            details=(
                f"Hardened: {hardened_count}, Inspected: {inspected_count}, "
                f"Ratio: {ratio:.0%}"
            ),
            remediation=(
                "Use systemd-analyze security <unit> to score each service. "
                "Add directives in unit override (systemctl edit <unit>): "
                "ProtectSystem=full, ProtectHome=yes, PrivateTmp=yes, "
                "NoNewPrivileges=yes"
            ),
            cross_references={
                "NIST": "SI-7", "CIS": "5.1",
            },
        ))

    # Check systemd-tmpfiles for proper /tmp cleanup
    tmpfiles_active = (
        systemd_active("systemd-tmpfiles-clean.timer") == "active" or
        systemd_active("systemd-tmpfiles-setup.service") in ("active", "exited")
    )
    results.append(_r(
        cat, "Pass" if tmpfiles_active else "Info",
        f"DIST-SYSD-2: systemd-tmpfiles cleanup active",
        severity="Low",
        details=f"systemd-tmpfiles services active: {tmpfiles_active}",
        cross_references={
            "NIST": "SI-12",
        },
    ))

    # Check journald persistent storage
    journald_conf = read_file_safe("/etc/systemd/journald.conf")
    storage_match = re.search(r"^\s*Storage\s*=\s*(\w+)", journald_conf, re.MULTILINE)
    storage = storage_match.group(1).lower() if storage_match else "auto"
    persistent = storage in ("persistent", "auto")
    has_var_log_journal = directory_exists("/var/log/journal")
    results.append(_r(
        cat, "Pass" if persistent and has_var_log_journal else "Warning",
        f"DIST-SYSD-3: journald persistent storage configured",
        severity="Medium",
        details=(
            f"Storage = {storage}, /var/log/journal exists: {has_var_log_journal}"
        ),
        remediation=(
            "mkdir -p /var/log/journal; systemd-tmpfiles --create --prefix /var/log/journal; "
            "set Storage=persistent in /etc/systemd/journald.conf"
        ),
        cross_references={
            "NIST": "AU-9", "CIS": "4.2.2",
        },
    ))

    # Check journald compression
    compress_match = re.search(
        r"^\s*Compress\s*=\s*(\w+)", journald_conf, re.MULTILINE
    )
    compress = compress_match.group(1).lower() if compress_match else "yes"  # default
    results.append(_r(
        cat, "Pass" if compress == "yes" else "Info",
        f"DIST-SYSD-4: journald compression enabled ({compress})",
        severity="Low",
        details=f"Compress = {compress}",
        cross_references={
            "NIST": "AU-4",
        },
    ))

    # Check journald log size
    sysmaxuse_match = re.search(
        r"^\s*SystemMaxUse\s*=\s*(\S+)", journald_conf, re.MULTILINE
    )
    has_sysmaxuse = sysmaxuse_match is not None
    results.append(_r(
        cat, "Pass" if has_sysmaxuse else "Info",
        f"DIST-SYSD-5: journald SystemMaxUse limit set",
        severity="Low",
        details=(
            f"SystemMaxUse = {sysmaxuse_match.group(1) if sysmaxuse_match else 'auto'}"
        ),
        remediation=(
            "Set explicit limit: SystemMaxUse=4G in /etc/systemd/journald.conf"
        ),
        cross_references={
            "NIST": "AU-4",
        },
    ))

    # ForwardToSyslog setting
    fwd_match = re.search(
        r"^\s*ForwardToSyslog\s*=\s*(\w+)", journald_conf, re.MULTILINE
    )
    forward = fwd_match.group(1).lower() if fwd_match else "yes"  # default in many distros
    results.append(_r(
        cat, "Info",
        f"DIST-SYSD-6: journald->syslog forwarding: {forward}",
        severity="Informational",
        details=f"ForwardToSyslog = {forward}",
        cross_references={
            "NIST": "AU-6(3)",
        },
    ))

    return results


def _check_dist_boot_security(os_info) -> List[AuditResult]:
    """Boot security: GRUB password, kdump, initramfs."""
    results: List[AuditResult] = []
    cat = "DistBaseline - Boot Security"

    # GRUB password file presence
    grub_user_files = [
        "/etc/grub.d/01_users",
        "/etc/grub.d/40_custom",
        "/boot/grub2/user.cfg",
        "/boot/grub/grub.cfg",
        "/boot/grub2/grub.cfg",
    ]
    grub_password_set = False
    grub_user_set = False
    for f in grub_user_files:
        c = read_file_safe(f)
        if not c:
            continue
        if "password_pbkdf2" in c or "GRUB2_PASSWORD" in c:
            grub_password_set = True
        if "set superusers" in c:
            grub_user_set = True

    results.append(_r(
        cat, "Pass" if grub_password_set else "Warning",
        "DIST-BOOT-1: GRUB password protection",
        severity="High",
        details=(
            f"password_pbkdf2 in GRUB config: {grub_password_set}, "
            f"superusers set: {grub_user_set}"
        ),
        remediation=(
            "RHEL/CentOS: grub2-setpassword. "
            "Debian/Ubuntu: grub-mkpasswd-pbkdf2 then add to /etc/grub.d/40_custom; "
            "update-grub. STIG V-230234."
        ),
        cross_references={
            "CIS": "1.5.2", "STIG": "V-230234", "NIST": "AC-3",
        },
    ))

    # GRUB config permission
    for cfg in ["/boot/grub2/grub.cfg", "/boot/grub/grub.cfg"]:
        if file_exists(cfg):
            mode = file_mode(cfg)
            mode_ok = mode is not None and (mode & 0o077) == 0
            results.append(_r(
                cat, "Pass" if mode_ok else "Warning",
                f"DIST-BOOT-2: {cfg} permissions",
                severity="High",
                details=f"Mode: {oct(mode) if mode is not None else 'unknown'}",
                remediation=f"chown root:root {cfg}; chmod 0600 {cfg}",
                cross_references={
                    "CIS": "1.5.1", "STIG": "V-230241",
                },
            ))
            break

    # initramfs/initrd permissions
    initrd_files = []
    for f in list_directory("/boot"):
        if f.startswith("initr") and (f.endswith(".img") or f.endswith(".gz")):
            initrd_files.append(os.path.join("/boot", f))
    initrd_secure = True
    for f in initrd_files[:3]:  # limit to 3 to avoid excessive
        mode = file_mode(f)
        if mode is None or (mode & 0o077) != 0:
            initrd_secure = False
            break
    if initrd_files:
        results.append(_r(
            cat, "Pass" if initrd_secure else "Warning",
            f"DIST-BOOT-3: initramfs permissions ({len(initrd_files)} files)",
            severity="Medium",
            details=f"All inspected initramfs files secure: {initrd_secure}",
            remediation="chmod 0600 /boot/initrd*",
            cross_references={
                "NIST": "AC-3",
            },
        ))

    # kdump configuration
    kdump_active = (
        systemd_active("kdump.service") == "active" or
        systemd_active("kdump-tools.service") == "active"
    )
    kdump_present = (
        file_exists("/etc/kdump.conf") or
        file_exists("/etc/default/kdump-tools")
    )
    if kdump_present:
        results.append(_r(
            cat, "Pass" if kdump_active else "Info",
            f"DIST-BOOT-4: kdump crash dump active: {kdump_active}",
            severity="Low",
            details=f"kdump configured: {kdump_present}, active: {kdump_active}",
            remediation=(
                "systemctl enable --now kdump (RHEL) or kdump-tools (Debian)"
            ),
            cross_references={
                "NIST": "SI-11",
            },
        ))

    # Secure Boot status (already checked in baseline; provide v3.3 indicator)
    sb_status_files = ["/sys/firmware/efi/efivars/SecureBoot-*"]
    sb_present = directory_exists("/sys/firmware/efi/efivars")
    results.append(_r(
        cat, "Info" if sb_present else "Info",
        f"DIST-BOOT-5: UEFI/EFI variables accessible: {sb_present}",
        severity="Informational",
        details=f"/sys/firmware/efi/efivars exists: {sb_present}",
        remediation=(
            "Run 'mokutil --sb-state' to check Secure Boot. "
            "Enable Secure Boot in firmware for measured boot chain."
        ),
        cross_references={
            "NIST": "SI-7", "CIS": "1.5.4",
        },
    ))

    return results


def _check_dist_crypto_policies(os_info) -> List[AuditResult]:
    """System-wide crypto policy checks."""
    results: List[AuditResult] = []
    cat = "DistBaseline - Crypto Policies"

    # update-crypto-policies (RHEL family)
    if file_exists("/etc/crypto-policies/config"):
        policy = read_file_safe("/etc/crypto-policies/config").strip()
        good_policies = {"DEFAULT", "FUTURE", "FIPS"}
        results.append(_r(
            cat, "Pass" if policy in good_policies else "Warning",
            f"DIST-CRYPTO-1: System crypto policy: {policy or 'unset'}",
            severity="High",
            details=f"crypto-policies config: {policy}",
            remediation=(
                "update-crypto-policies --set FUTURE  (or DEFAULT/FIPS)"
            ),
            cross_references={
                "NIST": "SC-13", "STIG": "V-230223",
            },
        ))

        # Backend policies present
        backend_dir = "/etc/crypto-policies/back-ends"
        if directory_exists(backend_dir):
            backends = list_directory(backend_dir)
            results.append(_r(
                cat, "Pass" if backends else "Warning",
                f"DIST-CRYPTO-2: Crypto backends configured ({len(backends)})",
                severity="Medium",
                details=f"Backend policy files: {len(backends)}",
                cross_references={
                    "NIST": "SC-13",
                },
            ))

    # OpenSSL FIPS provider availability
    rc, out, _ = run_command(
        ["openssl", "list", "-provider", "fips", "-providers"], timeout=5.0
    )
    fips_provider_loaded = rc == 0 and out and "fips" in out.lower()
    if command_available("openssl"):
        results.append(_r(
            cat, "Info",
            f"DIST-CRYPTO-3: OpenSSL FIPS provider loadable: {fips_provider_loaded}",
            severity="Informational",
            details=f"OpenSSL FIPS provider check rc={rc}",
            remediation=(
                "Activate: update-crypto-policies --set FIPS (RHEL family). "
                "FIPS 140-3 validation required for federal CUI."
            ),
            cross_references={
                "NIST": "SC-13", "FIPS": "140-3",
            },
        ))

    # OpenSSL config (system level)
    openssl_cnf = read_file_safe("/etc/ssl/openssl.cnf") or read_file_safe(
        "/etc/pki/tls/openssl.cnf"
    )
    if openssl_cnf:
        # Look for MinProtocol / CipherString
        has_min_proto = "MinProtocol" in openssl_cnf
        has_cipher_string = "CipherString" in openssl_cnf
        results.append(_r(
            cat, "Pass" if (has_min_proto or has_cipher_string) else "Info",
            f"DIST-CRYPTO-4: OpenSSL system-wide TLS minimums set",
            severity="Medium",
            details=(
                f"MinProtocol set: {has_min_proto}, "
                f"CipherString set: {has_cipher_string}"
            ),
            remediation=(
                "In /etc/ssl/openssl.cnf [system_default_sect]: "
                "MinProtocol = TLSv1.2; CipherString = DEFAULT@SECLEVEL=2"
            ),
            cross_references={
                "NIST": "SC-13", "CIS": "5.2",
            },
        ))

    # GnuTLS config
    if file_exists("/etc/gnutls/config"):
        results.append(_r(
            cat, "Info",
            "DIST-CRYPTO-5: GnuTLS system config present",
            severity="Informational",
            details="GnuTLS uses crypto-policies on RHEL family",
            cross_references={
                "NIST": "SC-13",
            },
        ))

    return results


def _check_dist_kernel_features(os_info) -> List[AuditResult]:
    """Kernel security features and BPF/namespace restrictions."""
    results: List[AuditResult] = []
    cat = "DistBaseline - Kernel Features"

    # Kernel module loading restriction
    modules_disabled = read_sysctl("kernel.modules_disabled") == "1"
    results.append(_r(
        cat, "Info",
        f"DIST-KERN-1: Kernel modules_disabled: {modules_disabled}",
        severity="Informational",
        details=(
            f"kernel.modules_disabled = {read_sysctl('kernel.modules_disabled')}. "
            "Once set to 1 (post-boot), no further modules can be loaded."
        ),
        remediation=(
            "After boot completes, set: sysctl -w kernel.modules_disabled=1 "
            "(only for static kernels - permanent until reboot)"
        ),
        cross_references={
            "NIST": "CM-7",
        },
    ))

    # User namespace restrictions
    userns_unpriv = read_sysctl("kernel.unprivileged_userns_clone")
    if userns_unpriv is not None:
        userns_disabled = userns_unpriv == "0"
        results.append(_r(
            cat, "Info",
            f"DIST-KERN-2: Unprivileged user namespaces: "
            f"{'disabled' if userns_disabled else 'enabled'}",
            severity="Informational",
            details=f"kernel.unprivileged_userns_clone = {userns_unpriv}",
            remediation=(
                "If not used: echo 'kernel.unprivileged_userns_clone = 0' "
                ">> /etc/sysctl.d/99-namespaces.conf  "
                "(disables unprivileged user namespaces - mitigates kernel "
                "exploit surface)"
            ),
            cross_references={
                "NIST": "CM-7", "ACSC": "ISM-1632",
            },
        ))

    # BPF JIT hardening
    bpf_harden = read_sysctl("net.core.bpf_jit_harden")
    bpf_ok = bpf_harden in ("1", "2")
    results.append(_r(
        cat, "Pass" if bpf_ok else "Info",
        f"DIST-KERN-3: BPF JIT hardening: {bpf_harden or 'unset'}",
        severity="Medium",
        details=f"net.core.bpf_jit_harden = {bpf_harden}",
        remediation=(
            "echo 'net.core.bpf_jit_harden = 2' >> /etc/sysctl.d/99-bpf.conf"
        ),
        cross_references={
            "NIST": "SI-16",
        },
    ))

    # BPF unprivileged disabled
    bpf_unpriv = read_sysctl("kernel.unprivileged_bpf_disabled")
    bpf_unpriv_ok = bpf_unpriv in ("1", "2")
    results.append(_r(
        cat, "Pass" if bpf_unpriv_ok else "Info",
        f"DIST-KERN-4: Unprivileged BPF disabled: {bpf_unpriv}",
        severity="Medium",
        details=f"kernel.unprivileged_bpf_disabled = {bpf_unpriv}",
        remediation=(
            "echo 'kernel.unprivileged_bpf_disabled = 1' >> /etc/sysctl.d/99-bpf.conf"
        ),
        cross_references={
            "NIST": "SI-16",
        },
    ))

    # Yama ptrace scope
    yama = read_sysctl("kernel.yama.ptrace_scope")
    yama_ok = yama in ("1", "2", "3")
    results.append(_r(
        cat, "Pass" if yama_ok else "Warning",
        f"DIST-KERN-5: Yama ptrace_scope: {yama or 'unset (0)'}",
        severity="Medium",
        details=(
            f"kernel.yama.ptrace_scope = {yama}. "
            "1 = restricted, 2 = admin only, 3 = no attach"
        ),
        remediation=(
            "echo 'kernel.yama.ptrace_scope = 1' >> /etc/sysctl.d/99-yama.conf"
        ),
        cross_references={
            "NIST": "SI-16", "CIS": "1.6.4",
        },
    ))

    # Address space layout randomization
    aslr = read_sysctl("kernel.randomize_va_space")
    aslr_ok = aslr == "2"
    results.append(_r(
        cat, "Pass" if aslr_ok else "Fail",
        f"DIST-KERN-6: Full ASLR enabled (randomize_va_space=2)",
        severity="High",
        details=f"kernel.randomize_va_space = {aslr}",
        remediation=(
            "echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.d/99-aslr.conf"
        ),
        cross_references={
            "NIST": "SI-16", "CIS": "1.5.3", "STIG": "V-230280",
        },
    ))

    # Restrict kernel logs / dmesg
    dmesg_restrict = read_sysctl("kernel.dmesg_restrict")
    dmesg_ok = dmesg_restrict == "1"
    results.append(_r(
        cat, "Pass" if dmesg_ok else "Warning",
        f"DIST-KERN-7: dmesg_restrict enabled: {dmesg_ok}",
        severity="Medium",
        details=f"kernel.dmesg_restrict = {dmesg_restrict}",
        remediation=(
            "echo 'kernel.dmesg_restrict = 1' >> /etc/sysctl.d/99-kern.conf"
        ),
        cross_references={
            "NIST": "AC-3", "CIS": "1.6.1",
        },
    ))

    # kptr restrict
    kptr = read_sysctl("kernel.kptr_restrict")
    kptr_ok = kptr in ("1", "2")
    results.append(_r(
        cat, "Pass" if kptr_ok else "Warning",
        f"DIST-KERN-8: kptr_restrict: {kptr or 'unset'}",
        severity="Medium",
        details=f"kernel.kptr_restrict = {kptr}",
        remediation=(
            "echo 'kernel.kptr_restrict = 2' >> /etc/sysctl.d/99-kern.conf"
        ),
        cross_references={
            "NIST": "AC-3",
        },
    ))

    # Core dumps for SUID
    suid_dumpable = read_sysctl("fs.suid_dumpable")
    suid_ok = suid_dumpable == "0"
    results.append(_r(
        cat, "Pass" if suid_ok else "Fail",
        f"DIST-KERN-9: fs.suid_dumpable disabled: {suid_dumpable}",
        severity="High",
        details=f"fs.suid_dumpable = {suid_dumpable}",
        remediation=(
            "echo 'fs.suid_dumpable = 0' >> /etc/sysctl.d/99-coredump.conf"
        ),
        cross_references={
            "NIST": "SI-11", "CIS": "1.5.1", "STIG": "V-230472",
        },
    ))

    # Hardlink/symlink protection
    fs_protected_hardlinks = read_sysctl("fs.protected_hardlinks") == "1"
    fs_protected_symlinks = read_sysctl("fs.protected_symlinks") == "1"
    fs_protect_ok = fs_protected_hardlinks and fs_protected_symlinks
    results.append(_r(
        cat, "Pass" if fs_protect_ok else "Fail",
        f"DIST-KERN-10: Filesystem hardlink/symlink protection enabled",
        severity="Medium",
        details=(
            f"protected_hardlinks={fs_protected_hardlinks}, "
            f"protected_symlinks={fs_protected_symlinks}"
        ),
        remediation=(
            "echo 'fs.protected_hardlinks = 1' >> /etc/sysctl.d/99-fs.conf; "
            "echo 'fs.protected_symlinks = 1' >> /etc/sysctl.d/99-fs.conf"
        ),
        cross_references={
            "NIST": "AC-3", "CIS": "1.6.3",
        },
    ))

    return results


def _check_dist_time_sync(os_info) -> List[AuditResult]:
    """Time synchronization (chrony / ntp / systemd-timesyncd)."""
    results: List[AuditResult] = []
    cat = "DistBaseline - Time Sync"

    chrony_active = (
        systemd_active("chronyd.service") == "active" or
        systemd_active("chrony.service") == "active"
    )
    ntpd_active = systemd_active("ntp.service") == "active" or \
                  systemd_active("ntpd.service") == "active"
    timesyncd_active = systemd_active("systemd-timesyncd.service") == "active"

    has_time_sync = chrony_active or ntpd_active or timesyncd_active

    results.append(_r(
        cat, "Pass" if has_time_sync else "Fail",
        f"DIST-TIME-1: Time synchronization service active",
        severity="High",
        details=(
            f"chronyd: {chrony_active}, ntpd: {ntpd_active}, "
            f"systemd-timesyncd: {timesyncd_active}"
        ),
        remediation=(
            "Enable chrony (preferred): systemctl enable --now chronyd "
            "(RHEL) or chrony (Debian/Ubuntu)"
        ),
        cross_references={
            "CIS": "2.2.1.1", "NIST": "AU-8",
            "STIG": "V-230475", "PCI-DSS": "10.6",
        },
    ))

    # chrony configuration check
    if chrony_active:
        chrony_conf = read_file_safe("/etc/chrony.conf") or \
                      read_file_safe("/etc/chrony/chrony.conf")
        if chrony_conf:
            has_servers = bool(re.search(
                r"^\s*(server|pool)\s+\S+", chrony_conf, re.MULTILINE
            ))
            results.append(_r(
                cat, "Pass" if has_servers else "Warning",
                "DIST-TIME-2: chrony has time sources configured",
                severity="Medium",
                details=f"server/pool directives present: {has_servers}",
                remediation=(
                    "Add to /etc/chrony.conf: server time.nist.gov iburst"
                ),
                cross_references={
                    "CIS": "2.2.1.2", "NIST": "AU-8",
                },
            ))

            # chrony "server" using authenticated NTP (NTS or symmetric key)
            has_authenticated = bool(re.search(
                r"^\s*server\s+\S+.*(nts|key\s+\d+)",
                chrony_conf, re.MULTILINE
            ))
            results.append(_r(
                cat, "Pass" if has_authenticated else "Info",
                f"DIST-TIME-3: chrony authenticated NTP (NTS/key): {has_authenticated}",
                severity="Medium",
                details=f"NTS or symmetric key auth detected: {has_authenticated}",
                remediation=(
                    "Use NTS-capable servers: server time.cloudflare.com nts iburst"
                ),
                cross_references={
                    "NIST": "AU-8(2)",
                },
            ))

    # systemd-timesyncd configuration
    if timesyncd_active:
        ts_conf = read_file_safe("/etc/systemd/timesyncd.conf")
        ntp_match = re.search(r"^\s*NTP\s*=\s*(.+)", ts_conf, re.MULTILINE)
        has_ntp = ntp_match and ntp_match.group(1).strip()
        results.append(_r(
            cat, "Pass" if has_ntp else "Warning",
            "DIST-TIME-2b: systemd-timesyncd NTP servers configured",
            severity="Medium",
            details=f"NTP= line set: {bool(has_ntp)}",
            remediation=(
                "Edit /etc/systemd/timesyncd.conf and set: "
                "NTP=time.nist.gov pool.ntp.org"
            ),
            cross_references={
                "CIS": "2.2.1.2", "NIST": "AU-8",
            },
        ))

    return results


def _check_dist_user_account_security(os_info) -> List[AuditResult]:
    """User and group account security."""
    results: List[AuditResult] = []
    cat = "DistBaseline - Account Security"

    # Empty passwords
    shadow = read_file_safe("/etc/shadow")
    empty_pw_users = []
    if shadow:
        for line in shadow.splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] == "":
                empty_pw_users.append(parts[0])
    results.append(_r(
        cat, "Pass" if not empty_pw_users else "Fail",
        f"DIST-ACCT-1: No accounts with empty passwords ({len(empty_pw_users)})",
        severity="Critical",
        details=f"Empty password users: {empty_pw_users[:5]}",
        remediation=(
            "Lock accounts with empty passwords: passwd -l <username>"
        ),
        cross_references={
            "CIS": "6.2.2", "STIG": "V-230376", "NIST": "IA-5",
        },
    ))

    # UID 0 accounts (only root should have UID 0)
    passwd = read_file_safe("/etc/passwd")
    uid0_users = []
    if passwd:
        for line in passwd.splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 3:
                try:
                    if int(parts[2]) == 0 and parts[0] != "root":
                        uid0_users.append(parts[0])
                except ValueError:
                    pass
    results.append(_r(
        cat, "Pass" if not uid0_users else "Fail",
        f"DIST-ACCT-2: Only root has UID 0 ({len(uid0_users)} extras)",
        severity="Critical",
        details=f"Non-root UID 0 accounts: {uid0_users}",
        remediation=(
            "Change UID of any non-root account with UID 0: "
            "usermod -u <new_uid> <username>"
        ),
        cross_references={
            "CIS": "6.2.5", "STIG": "V-230388", "NIST": "AC-6",
        },
    ))

    # Duplicate UIDs
    uid_map: Dict[str, List[str]] = {}
    if passwd:
        for line in passwd.splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 3:
                uid_map.setdefault(parts[2], []).append(parts[0])
    duplicate_uids = {k: v for k, v in uid_map.items() if len(v) > 1}
    results.append(_r(
        cat, "Pass" if not duplicate_uids else "Warning",
        f"DIST-ACCT-3: No duplicate UIDs ({len(duplicate_uids)} duplicates)",
        severity="Medium",
        details=f"Duplicate UIDs: {duplicate_uids}",
        remediation=(
            "Reassign duplicate UIDs: usermod -u <new_uid> <username>"
        ),
        cross_references={
            "CIS": "6.2.16", "NIST": "IA-2",
        },
    ))

    # Duplicate GIDs
    group = read_file_safe("/etc/group")
    gid_map: Dict[str, List[str]] = {}
    if group:
        for line in group.splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 3:
                gid_map.setdefault(parts[2], []).append(parts[0])
    duplicate_gids = {k: v for k, v in gid_map.items() if len(v) > 1}
    results.append(_r(
        cat, "Pass" if not duplicate_gids else "Info",
        f"DIST-ACCT-4: No duplicate GIDs ({len(duplicate_gids)} duplicates)",
        severity="Medium",
        details=f"Duplicate GIDs: {duplicate_gids}",
        cross_references={
            "CIS": "6.2.17", "NIST": "IA-2",
        },
    ))

    # /etc/passwd, /etc/shadow ownership/perms
    for path, expected_mode_max, expected_owner in [
        ("/etc/passwd", 0o644, "root"),
        ("/etc/shadow", 0o000, "root"),  # 0 = read-only by root
        ("/etc/group", 0o644, "root"),
        ("/etc/gshadow", 0o000, "root"),
    ]:
        if not file_exists(path):
            continue
        mode = file_mode(path)
        if mode is None:
            continue
        # For shadow files, 0o000 means only root can read (mode <= 0o400)
        if expected_mode_max == 0o000:
            mode_ok = (mode & 0o077) == 0  # group/others have no perms
        else:
            mode_ok = (mode & 0o022) == 0  # no group/other write
        results.append(_r(
            cat, "Pass" if mode_ok else "Fail",
            f"DIST-ACCT-5: {path} permissions appropriate",
            severity="High",
            details=f"Mode: {oct(mode)}",
            remediation=f"chmod {('640' if expected_mode_max == 0o000 else '644')} {path}; "
                       f"chown root:root {path}",
            cross_references={
                "CIS": "6.1.2", "STIG": "V-230229", "NIST": "AC-3",
            },
        ))

    return results


def _check_dist_audit_dispatcher_extended(os_info) -> List[AuditResult]:
    """Audit dispatcher and remote audit log."""
    results: List[AuditResult] = []
    cat = "DistBaseline - Audit Extended"

    auditd_active = systemd_active("auditd.service") == "active"
    if not auditd_active:
        return results

    # auditd configuration values
    auditd_conf = read_file_safe("/etc/audit/auditd.conf")
    if auditd_conf:
        # space_left_action and disk_full_action
        space_left_action_match = re.search(
            r"^\s*space_left_action\s*=\s*(\w+)", auditd_conf, re.MULTILINE
        )
        space_left_action = (
            space_left_action_match.group(1).lower() if space_left_action_match
            else "syslog"
        )
        good_actions = {"email", "exec", "single", "halt"}
        results.append(_r(
            cat, "Pass" if space_left_action in good_actions else "Warning",
            f"DIST-AUDIT-1: auditd space_left_action = {space_left_action}",
            severity="Medium",
            details=f"space_left_action = {space_left_action}",
            remediation=(
                "In /etc/audit/auditd.conf: space_left_action = email"
            ),
            cross_references={
                "CIS": "4.1.1.3", "STIG": "V-230389", "NIST": "AU-5",
            },
        ))

        disk_full_action_match = re.search(
            r"^\s*disk_full_action\s*=\s*(\w+)", auditd_conf, re.MULTILINE
        )
        disk_full_action = (
            disk_full_action_match.group(1).lower() if disk_full_action_match
            else "ignore"
        )
        good_full = {"single", "halt"}
        results.append(_r(
            cat, "Pass" if disk_full_action in good_full else "Warning",
            f"DIST-AUDIT-2: auditd disk_full_action = {disk_full_action}",
            severity="Medium",
            details=f"disk_full_action = {disk_full_action}",
            remediation=(
                "In /etc/audit/auditd.conf: disk_full_action = halt  "
                "(or single for single-user mode)"
            ),
            cross_references={
                "CIS": "4.1.1.4", "NIST": "AU-5",
            },
        ))

        # max_log_file_action
        max_action_match = re.search(
            r"^\s*max_log_file_action\s*=\s*(\w+)", auditd_conf, re.MULTILINE
        )
        max_action = (
            max_action_match.group(1).lower() if max_action_match else "rotate"
        )
        results.append(_r(
            cat, "Pass" if max_action == "keep_logs" else "Info",
            f"DIST-AUDIT-3: auditd max_log_file_action = {max_action}",
            severity="Low",
            details=f"max_log_file_action = {max_action}",
            remediation=(
                "For long-term retention: max_log_file_action = keep_logs"
            ),
            cross_references={
                "CIS": "4.1.1.2", "NIST": "AU-4",
            },
        ))

    # auditd remote forwarding (audisp-remote)
    audisp_remote = (
        read_file_safe("/etc/audit/audisp-remote.conf") or
        read_file_safe("/etc/audisp/audisp-remote.conf")
    )
    has_remote = audisp_remote and "remote_server" in audisp_remote
    results.append(_r(
        cat, "Pass" if has_remote else "Info",
        f"DIST-AUDIT-4: audisp-remote forwarding configured: {has_remote}",
        severity="Medium",
        details=f"remote_server directive present: {has_remote}",
        remediation=(
            "Configure /etc/audit/audisp-remote.conf with remote audit "
            "log server. Required for compliance frameworks."
        ),
        cross_references={
            "NIST": "AU-9(2)", "PCI-DSS": "10.5.3",
        },
    ))

    return results


def _check_dist_per_distro_extended(os_info) -> List[AuditResult]:
    """Per-distribution extended checks."""
    results: List[AuditResult] = []
    cat = "DistBaseline - Per-Distro Extended"

    # Ubuntu Pro / ESM (if Ubuntu)
    if os_info.is_debian_family():
        # Check for AppArmor (Debian/Ubuntu native MAC)
        aa_status = command_available("aa-status")
        aa_active = systemd_active("apparmor.service") == "active"
        results.append(_r(
            cat, "Pass" if aa_active else "Warning",
            f"DIST-DEB-1: AppArmor service active: {aa_active}",
            severity="High",
            details=f"apparmor.service active: {aa_active}, aa-status available: {aa_status}",
            remediation=(
                "systemctl enable --now apparmor; aa-enforce /etc/apparmor.d/*"
            ),
            cross_references={
                "CIS": "1.7.1", "NIST": "AC-3",
            },
        ))

        # Ubuntu Pro client
        pro_present = command_available("pro") or command_available("ua")
        if pro_present:
            rc, out, _ = run_command(["pro", "status", "--format=json"], timeout=5.0)
            if rc != 0:
                rc, out, _ = run_command(["ua", "status", "--format=json"], timeout=5.0)
            attached = rc == 0 and out and '"attached":true' in out.replace(" ", "")
            results.append(_r(
                cat, "Info",
                f"DIST-DEB-2: Ubuntu Pro attached: {attached}",
                severity="Informational",
                details=f"pro/ua status check rc={rc}, attached={attached}",
                remediation=(
                    "For ESM/Livepatch coverage: pro attach <token>"
                ),
                cross_references={
                    "NIST": "SI-2",
                },
            ))

        # debsums
        debsums_present = command_available("debsums")
        results.append(_r(
            cat, "Pass" if debsums_present else "Info",
            f"DIST-DEB-3: debsums installed: {debsums_present}",
            severity="Medium",
            details=f"debsums binary available: {debsums_present}",
            remediation=(
                "apt-get install -y debsums; debsums -c  (verify package files)"
            ),
            cross_references={
                "NIST": "SI-7",
            },
        ))

        # needrestart
        needrestart_present = command_available("needrestart")
        results.append(_r(
            cat, "Pass" if needrestart_present else "Info",
            f"DIST-DEB-4: needrestart installed: {needrestart_present}",
            severity="Low",
            details=f"needrestart available: {needrestart_present}",
            remediation=(
                "apt-get install -y needrestart  (warns when restarts needed)"
            ),
            cross_references={
                "NIST": "SI-2",
            },
        ))

        # fail2ban
        f2b_active = systemd_active("fail2ban.service") == "active"
        results.append(_r(
            cat, "Pass" if f2b_active else "Info",
            f"DIST-DEB-5: fail2ban service active: {f2b_active}",
            severity="Medium",
            details=f"fail2ban active: {f2b_active}",
            remediation=(
                "apt-get install -y fail2ban; systemctl enable --now fail2ban"
            ),
            cross_references={
                "NIST": "AC-7",
            },
        ))

    # RHEL family
    if os_info.is_redhat_family():
        # SELinux
        selinux_enforcing = False
        if file_exists("/sys/fs/selinux/enforce"):
            try:
                with open("/sys/fs/selinux/enforce", "r") as f:
                    selinux_enforcing = f.read().strip() == "1"
            except OSError:
                pass
        results.append(_r(
            cat, "Pass" if selinux_enforcing else "Fail",
            f"DIST-RHEL-1: SELinux enforcing mode active: {selinux_enforcing}",
            severity="High",
            details=f"SELinux enforce flag: {selinux_enforcing}",
            remediation=(
                "Edit /etc/selinux/config: SELINUX=enforcing; reboot. "
                "Or runtime: setenforce 1"
            ),
            cross_references={
                "CIS": "1.7.1.4", "STIG": "V-230223", "NIST": "AC-3",
            },
        ))

        # fapolicyd
        fapolicyd_active = systemd_active("fapolicyd.service") == "active"
        results.append(_r(
            cat, "Pass" if fapolicyd_active else "Info",
            f"DIST-RHEL-2: fapolicyd application allowlist: {fapolicyd_active}",
            severity="Medium",
            details=f"fapolicyd active: {fapolicyd_active}",
            remediation=(
                "dnf install -y fapolicyd; systemctl enable --now fapolicyd"
            ),
            cross_references={
                "NIST": "CM-7(5)", "ACSC": "E8.1-ML3",
            },
        ))

        # USBGuard
        usbguard_active = systemd_active("usbguard.service") == "active"
        results.append(_r(
            cat, "Pass" if usbguard_active else "Info",
            f"DIST-RHEL-3: USBGuard active: {usbguard_active}",
            severity="Low",
            details=f"usbguard service: {usbguard_active}",
            remediation=remediation_for("usbguard"),
            cross_references={
                "NIST": "MP-7", "STIG": "V-230501",
            },
        ))

        # OpenSCAP
        oscap_present = command_available("oscap")
        results.append(_r(
            cat, "Info",
            f"DIST-RHEL-4: OpenSCAP scanner installed: {oscap_present}",
            severity="Informational",
            details=f"oscap binary: {oscap_present}",
            remediation=(
                "dnf install -y openscap-scanner scap-security-guide"
            ),
            cross_references={
                "NIST": "RA-5",
            },
        ))

        # rhel-system-roles / Insights
        insights_present = command_available("insights-client")
        if insights_present:
            results.append(_r(
                cat, "Info",
                "DIST-RHEL-5: Red Hat Insights client installed",
                severity="Informational",
                details="insights-client binary available",
                cross_references={
                    "NIST": "RA-5",
                },
            ))

    # SUSE family
    if os_info.is_suse_family():
        # AppArmor on SUSE
        aa_active = systemd_active("apparmor.service") == "active"
        results.append(_r(
            cat, "Pass" if aa_active else "Warning",
            f"DIST-SUSE-1: AppArmor service active: {aa_active}",
            severity="High",
            details=f"apparmor.service: {aa_active}",
            remediation=remediation_for("apparmor"),
            cross_references={
                "NIST": "AC-3",
            },
        ))

        # snapper
        snapper_present = command_available("snapper")
        results.append(_r(
            cat, "Pass" if snapper_present else "Info",
            f"DIST-SUSE-2: snapper btrfs snapshots available: {snapper_present}",
            severity="Low",
            details=f"snapper: {snapper_present}",
            remediation="zypper install -y snapper",
            cross_references={
                "NIST": "CP-9",
            },
        ))

        # zypper
        zypper_present = command_available("zypper")
        results.append(_r(
            cat, "Pass" if zypper_present else "Info",
            f"DIST-SUSE-3: zypper package manager: {zypper_present}",
            severity="Informational",
            details=f"zypper available: {zypper_present}",
            cross_references={
                "NIST": "CM-8",
            },
        ))

    # Arch family
    if os_info.is_arch_family():
        # pacman keyring
        pacman_keyring = directory_exists("/etc/pacman.d/gnupg")
        results.append(_r(
            cat, "Pass" if pacman_keyring else "Warning",
            f"DIST-ARCH-1: pacman keyring directory: {pacman_keyring}",
            severity="High",
            details=f"/etc/pacman.d/gnupg exists: {pacman_keyring}",
            remediation="pacman-key --init && pacman-key --populate archlinux",
            cross_references={
                "NIST": "CM-5(3)",
            },
        ))

        # pacman.conf SigLevel
        pacman_conf = read_file_safe("/etc/pacman.conf")
        siglevel_match = re.search(
            r"^\s*SigLevel\s*=\s*(\S.*)", pacman_conf, re.MULTILINE
        )
        siglevel = siglevel_match.group(1).strip() if siglevel_match else ""
        siglevel_strict = "Required" in siglevel and "DatabaseRequired" in siglevel
        results.append(_r(
            cat, "Pass" if siglevel_strict else "Warning",
            f"DIST-ARCH-2: pacman SigLevel strict: {siglevel_strict}",
            severity="High",
            details=f"SigLevel = {siglevel}",
            remediation=(
                "In /etc/pacman.conf: SigLevel = Required DatabaseRequired"
            ),
            cross_references={
                "NIST": "CM-5(3)",
            },
        ))

    return results


def _check_dist_critical_log_paths(os_info) -> List[AuditResult]:
    """Critical log path permissions and integrity."""
    results: List[AuditResult] = []
    cat = "DistBaseline - Log Paths"

    log_paths = [
        ("/var/log", 0o755, ["root"]),
        ("/var/log/audit", 0o750, ["root"]),
        ("/var/log/journal", 0o2755, ["root", "systemd-journal"]),
        ("/var/log/btmp", 0o600, ["root"]),
        ("/var/log/wtmp", 0o644, ["root"]),
        ("/var/log/lastlog", 0o644, ["root"]),
    ]

    issues: List[str] = []
    for path, max_mode, _ in log_paths:
        if not os.path.exists(path):
            continue
        try:
            st = os.stat(path)
            actual_mode = st.st_mode & 0o7777
            # Allow more restrictive modes
            if actual_mode & ~max_mode & 0o077:
                issues.append(f"{path}={oct(actual_mode)}")
        except OSError:
            continue

    results.append(_r(
        cat, "Pass" if not issues else "Warning",
        f"DIST-LOG-1: Log file permissions appropriate ({len(issues)} issues)",
        severity="Medium",
        details=f"Issues: {issues[:5]}" if issues else "All log paths properly secured",
        remediation=(
            "Secure log files: chmod 640 /var/log/messages; "
            "chmod 600 /var/log/btmp; chmod 750 /var/log/audit"
        ),
        cross_references={
            "CIS": "4.2.4", "STIG": "V-230245", "NIST": "AU-9",
        },
    ))

    # logrotate configured for major logs
    logrotate_d = list_directory("/etc/logrotate.d")
    expected_rotations = ["rsyslog", "syslog", "audit", "messages", "secure"]
    detected_rotations = []
    for f in logrotate_d:
        if any(exp in f.lower() for exp in expected_rotations):
            detected_rotations.append(f)

    results.append(_r(
        cat, "Pass" if detected_rotations else "Info",
        f"DIST-LOG-2: logrotate configurations for system logs ({len(detected_rotations)})",
        severity="Low",
        details=f"Detected: {detected_rotations}",
        remediation=(
            "Ensure /etc/logrotate.d contains rotation rules for syslog, "
            "auditd, and other security-critical logs"
        ),
        cross_references={
            "NIST": "AU-4",
        },
    ))

    return results


# Save reference to existing run_checks
_original_run_checks_distbaseline_v33 = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the v3.3 expanded DistBaseline module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_distbaseline_v33(shared_data)

    os_info = shared_data.get("v3_os_info")
    if os_info is None:
        os_info = os_detection.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        results.extend(_check_dist_mount_options(os_info))
        results.extend(_check_dist_systemd_unit_hardening(os_info))
        results.extend(_check_dist_boot_security(os_info))
        results.extend(_check_dist_crypto_policies(os_info))
        results.extend(_check_dist_kernel_features(os_info))
        results.extend(_check_dist_time_sync(os_info))
        results.extend(_check_dist_user_account_security(os_info))
        results.extend(_check_dist_audit_dispatcher_extended(os_info))
        results.extend(_check_dist_per_distro_extended(os_info))
        results.extend(_check_dist_critical_log_paths(os_info))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled exception in DistBaseline v3.3 expansion")
        results.append(_r(
            "DistBaseline - Error", "Error",
            f"DistBaseline v3.3 expansion exception: {exc!r}",
            severity="Medium", details=str(exc),
        ))

    return results


# ============================================================================
# v3.5 EXPANSION - DistBaseline Advanced Distribution Features
# ----------------------------------------------------------------------------
# Synopsis:
#   Adds advanced distribution-specific and cross-distribution coverage:
#     - Ubuntu Pro features (Livepatch, ESM, FIPS, USG)
#     - RHEL Insights / subscription-manager
#     - SUSE SCC / SUSE Manager registration
#     - Snap confinement state and connections
#     - Flatpak sandboxing and permissions
#     - journald discipline (persistence, compression, retention limits)
#     - Disk integrity (fstrim.timer, btrfs scrub timers)
#     - System integrity markers (machine-id, cron.allow/deny, at.allow/deny)
#     - Advanced firewall depth (nftables sets, firewalld zone audit)
#     - kdump configuration
#     - eBPF LSM, IMA appraisal mode
#     - Network namespace and user namespace audit
# ============================================================================

# v3.5 helpers (aliased per L9 convention)
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


def _v35_distbase_result(category, status, message, severity="Medium",
                         details="", remediation="", cross_references=None):
    """Build AuditResult for DistBaseline v3.5 expansion."""
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


def _check_distbase_v35_ubuntu_pro(os_info):
    """Ubuntu Pro features: Livepatch, ESM, FIPS, USG."""
    results = []
    cat = "DistBaseline v3.5 - Ubuntu Pro"

    if not (os_info and os_info.is_debian_family() and
            os_info.distro_id == "ubuntu"):
        return results

    # 1. pro CLI presence
    pro_present = _v35_command_available("pro") or _v35_command_available("ua")
    results.append(_v35_distbase_result(
        f"{cat} - pro CLI",
        "Pass" if pro_present else "Info",
        f"Ubuntu Pro client (pro/ua) installed: {pro_present}",
        severity="Low",
        details=f"pro/ua command available: {pro_present}",
        remediation=(
            "apt-get install -y ubuntu-advantage-tools\n"
            "Required to manage Ubuntu Pro subscription features "
            "(Livepatch, ESM, FIPS, USG)."
        ),
        cross_references={
            "Ubuntu-Pro": "Client", "NIST": "SI-2",
        },
    ))

    if not pro_present:
        return results

    # 2. Subscription attached
    rc, out, _ = _v35_run_command(
        ["pro", "status", "--format=json"], timeout=8.0,
    )
    pro_attached = False
    enabled_services = []
    if rc == 0 and out:
        try:
            import json as _json
            data = _json.loads(out)
            pro_attached = bool(data.get("attached"))
            for svc in data.get("services", []):
                if svc.get("entitled") == "yes" and svc.get("status") == "enabled":
                    enabled_services.append(svc.get("name"))
        except (_json.JSONDecodeError, ValueError, TypeError):
            pass

    results.append(_v35_distbase_result(
        f"{cat} - Subscription Attached",
        "Pass" if pro_attached else "Info",
        f"Ubuntu Pro subscription attached: {pro_attached}",
        severity="Medium",
        details=(
            f"Attached: {pro_attached}, "
            f"enabled services: {enabled_services or 'none'}"
        ),
        remediation=(
            "Free for personal use (up to 5 machines): pro attach <token>. "
            "Provides 10-year ESM security updates, Livepatch kernel patches, "
            "FIPS-validated cryptography, and Ubuntu Security Guide (USG)."
        ),
        cross_references={
            "Ubuntu-Pro": "Subscription", "NIST": "SI-2", "PCI-DSS": "6.3.3",
        },
    ))

    # 3. Livepatch enabled (kernel hot-patching)
    livepatch_enabled = "livepatch" in enabled_services
    livepatch_status = "<unknown>"
    if _v35_command_available("canonical-livepatch"):
        rc, out, _ = _v35_run_command(
            ["canonical-livepatch", "status"], timeout=5.0,
        )
        if rc == 0 and out:
            livepatch_status = out.split("\n")[0][:60]
    results.append(_v35_distbase_result(
        f"{cat} - Livepatch",
        "Pass" if livepatch_enabled else "Info",
        f"Ubuntu Livepatch active: {livepatch_enabled}",
        severity="High",
        details=(
            f"livepatch in enabled services: {livepatch_enabled}, "
            f"status: {livepatch_status}"
        ),
        remediation=(
            "pro enable livepatch\n"
            "Eliminates reboots for critical kernel security patches by "
            "applying them to the running kernel (PCI 6.3.3 patching)."
        ),
        cross_references={
            "Ubuntu-Pro": "Livepatch", "NIST": "SI-2", "PCI-DSS": "6.3.3",
            "STIG": "V-260491",
        },
    ))

    # 4. ESM Infrastructure / Apps
    esm_enabled = any(s for s in enabled_services if "esm" in s.lower())
    results.append(_v35_distbase_result(
        f"{cat} - ESM",
        "Pass" if esm_enabled else "Info",
        f"Extended Security Maintenance (ESM): {esm_enabled}",
        severity="High",
        details=f"ESM in enabled services: {esm_enabled}",
        remediation=(
            "pro enable esm-infra; pro enable esm-apps\n"
            "Extends security patch coverage to 10 years (essential for "
            "Ubuntu LTS systems past 5-year standard support)."
        ),
        cross_references={
            "Ubuntu-Pro": "ESM", "NIST": "SI-2",
        },
    ))

    # 5. USG (Ubuntu Security Guide / hardening profiles)
    usg_present = (
        _v35_command_available("usg") or
        _v35_file_exists("/usr/share/doc/usg")
    )
    usg_enabled = "usg" in enabled_services or usg_present
    results.append(_v35_distbase_result(
        f"{cat} - USG",
        "Pass" if usg_enabled else "Info",
        f"Ubuntu Security Guide (USG) tooling: {usg_enabled}",
        severity="Medium",
        details=f"usg present: {usg_present}",
        remediation=(
            "pro enable usg; apt-get install -y usg\n"
            "Provides automated hardening (CIS, DISA-STIG profiles) and "
            "compliance scanning."
        ),
        cross_references={
            "Ubuntu-Pro": "USG", "CIS": "1.0", "STIG": "Ubuntu",
        },
    ))

    # 6. Realtime kernel (Ubuntu Pro feature for low-latency workloads)
    rt_kernel = "realtime" in enabled_services
    if rt_kernel:
        results.append(_v35_distbase_result(
            f"{cat} - Realtime Kernel",
            "Info",
            f"Ubuntu Pro Realtime kernel enabled",
            severity="Informational",
            details="realtime service active",
            cross_references={"Ubuntu-Pro": "Realtime"},
        ))

    return results


def _check_distbase_v35_rhel_insights(os_info):
    """RHEL Insights / subscription-manager."""
    results = []
    cat = "DistBaseline v3.5 - RHEL Insights"

    if not (os_info and os_info.is_redhat_family()):
        return results

    # subscription-manager status (RHEL only)
    if os_info.distro_id == "rhel":
        sm_present = _v35_command_available("subscription-manager")
        results.append(_v35_distbase_result(
            f"{cat} - Subscription Manager",
            "Pass" if sm_present else "Warning",
            f"subscription-manager installed: {sm_present}",
            severity="High",
            details=f"subscription-manager: {sm_present}",
            remediation=(
                "Required on RHEL for entitlement and updates. "
                "subscription-manager register; subscription-manager attach"
            ),
            cross_references={
                "RHEL": "Subscription", "NIST": "SI-2",
            },
        ))

        if sm_present:
            # Check attachment status
            rc, out, _ = _v35_run_command(
                ["subscription-manager", "status"], timeout=10.0,
            )
            attached = rc == 0 and "Current" in (out or "")
            results.append(_v35_distbase_result(
                f"{cat} - Attached",
                "Pass" if attached else "Warning",
                f"RHEL subscription attached: {attached}",
                severity="High",
                details=(
                    out.split('\n')[0] if rc == 0 and out
                    else "subscription-manager status failed"
                )[:100],
                remediation=(
                    "Without an active subscription RHEL cannot receive "
                    "security updates. subscription-manager register --auto-attach"
                ),
                cross_references={
                    "RHEL": "Subscription", "NIST": "SI-2", "PCI-DSS": "6.3.3",
                },
            ))

    # Insights client (Red Hat Insights remote system advisor)
    insights_client = (
        _v35_command_available("insights-client") or
        _v35_file_exists("/etc/insights-client/insights-client.conf")
    )
    insights_active = (
        _v35_systemd_active("insights-client.timer") == "active"
    )
    results.append(_v35_distbase_result(
        f"{cat} - Insights Client",
        "Info",
        f"Red Hat Insights client: present={insights_client}, "
        f"timer active={insights_active}",
        severity="Informational",
        details=(
            f"insights-client: {insights_client}, "
            f"timer active: {insights_active}"
        ),
        remediation=(
            "Optional but recommended on RHEL for proactive vulnerability "
            "detection and CVE advisories. dnf install -y insights-client; "
            "insights-client --register"
        ),
        cross_references={
            "RHEL": "Insights", "NIST": "RA-5",
        },
    ))

    # Red Hat Update Infrastructure / RHUI (cloud-only)
    rhui_present = _v35_directory_exists("/etc/yum.repos.d/redhat-rhui.repo") or any(
        f.startswith("rhui") for f in _v35_list_directory("/etc/yum.repos.d")
        if _v35_directory_exists("/etc/yum.repos.d")
    )
    if rhui_present:
        results.append(_v35_distbase_result(
            f"{cat} - RHUI",
            "Info",
            f"Red Hat Update Infrastructure (RHUI) detected",
            severity="Informational",
            details=f"RHUI repo files: {rhui_present}",
            cross_references={"RHEL": "RHUI"},
        ))

    return results


def _check_distbase_v35_snap_flatpak(os_info):
    """Snap/Flatpak host-level confinement and permissions."""
    results = []
    cat = "DistBaseline v3.5 - Snap/Flatpak"

    # Snap (Ubuntu primarily)
    snap_present = (
        _v35_command_available("snap") or
        _v35_systemd_active("snapd.service") == "active"
    )
    if snap_present:
        # Snap confinement model
        rc, out, _ = _v35_run_command(["snap", "version"], timeout=5.0)
        snap_version = (out.split("\n")[0] if rc == 0 and out else "unknown")[:60]

        # Count installed snaps
        rc, out, _ = _v35_run_command(["snap", "list"], timeout=8.0)
        snap_count = max(0, len((out or "").splitlines()) - 1) if rc == 0 else 0

        # Connections (interfaces granted)
        rc, out, _ = _v35_run_command(["snap", "connections"], timeout=8.0)
        sensitive_connections = []
        if rc == 0 and out:
            for line in out.splitlines():
                # Lines indicating sensitive interface grants
                for risky in ["home", "system-files", "raw-usb", "removable-media",
                              "block-devices", "kernel-module-load",
                              "raw-volume", "personal-files"]:
                    if (f":{risky} " in line or line.endswith(f":{risky}") or
                        f"  {risky}  " in line):
                        sensitive_connections.append(risky)
                        break

        results.append(_v35_distbase_result(
            f"{cat} - Snap Inventory",
            "Info",
            f"Snap packages installed: {snap_count}, version: {snap_version}",
            severity="Informational",
            details=f"snap version: {snap_version}, snap count: {snap_count}",
            cross_references={"NIST": "CM-8"},
        ))

        results.append(_v35_distbase_result(
            f"{cat} - Snap Sensitive Interfaces",
            "Pass" if not sensitive_connections else "Warning",
            f"Snap sensitive interface grants: "
            f"{len(set(sensitive_connections))}",
            severity="Medium",
            details=(
                f"Sensitive interfaces granted: {sorted(set(sensitive_connections)) or 'none'}"
            ),
            remediation=(
                "Review with: snap connections\n"
                "Disconnect unnecessary grants: snap disconnect <snap>:<plug>\n"
                "Snap interfaces like home, system-files, raw-usb broaden the "
                "attack surface beyond the default strict confinement."
            ),
            cross_references={
                "NIST": "AC-3, CM-7", "ISO27001": "A.8.7",
            },
        ))

    # Flatpak
    flatpak_present = _v35_command_available("flatpak")
    if flatpak_present:
        rc, out, _ = _v35_run_command(
            ["flatpak", "list", "--app", "--columns=application"],
            timeout=5.0,
        )
        flatpak_count = max(0, len((out or "").splitlines()) - 1) if rc == 0 else 0

        # Check for risky overrides
        risky_override = False
        override_dir = "/var/lib/flatpak/overrides"
        if _v35_directory_exists(override_dir):
            for f in _v35_list_directory(override_dir):
                content = _v35_read_file_safe(
                    os.path.join(override_dir, f)
                )
                if ("filesystems=host" in content or
                    "filesystems=/" in content or
                    "filesystems=home" in content):
                    risky_override = True
                    break

        results.append(_v35_distbase_result(
            f"{cat} - Flatpak Inventory",
            "Info",
            f"Flatpak applications installed: {flatpak_count}",
            severity="Informational",
            details=f"flatpak count: {flatpak_count}",
            cross_references={"NIST": "CM-8"},
        ))

        results.append(_v35_distbase_result(
            f"{cat} - Flatpak Sandbox",
            "Pass" if not risky_override else "Warning",
            f"Flatpak host-filesystem overrides: {risky_override}",
            severity="Medium",
            details=f"Risky override (filesystems=host) detected: {risky_override}",
            remediation=(
                "Review per-app overrides: flatpak override --show <app>\n"
                "Reset risky grants: flatpak override --reset <app>"
            ),
            cross_references={"NIST": "CM-7"},
        ))

    return results


def _check_distbase_v35_journald(os_info):
    """journald discipline: persistence, compression, retention."""
    results = []
    cat = "DistBaseline v3.5 - journald"

    if not _v35_command_available("journalctl"):
        return results

    journald_conf = _v35_read_file_safe("/etc/systemd/journald.conf")
    journald_d_content = ""
    journald_d_dir = "/etc/systemd/journald.conf.d"
    if _v35_directory_exists(journald_d_dir):
        for f in _v35_list_directory(journald_d_dir):
            if f.endswith(".conf"):
                journald_d_content += "\n" + _v35_read_file_safe(
                    os.path.join(journald_d_dir, f)
                )
    full_conf = journald_conf + "\n" + journald_d_content

    # 1. Storage=persistent (logs survive reboot)
    storage_match = re.search(
        r"^\s*Storage\s*=\s*(\w+)", full_conf, re.MULTILINE,
    )
    storage = storage_match.group(1) if storage_match else "auto"
    persistent = (
        storage == "persistent" or
        (storage == "auto" and _v35_directory_exists("/var/log/journal"))
    )
    results.append(_v35_distbase_result(
        f"{cat} - Persistent Storage",
        "Pass" if persistent else "Warning",
        f"journald persistent storage: {persistent}",
        severity="High",
        details=f"Storage = {storage}, /var/log/journal exists: "
                 f"{_v35_directory_exists('/var/log/journal')}",
        remediation=(
            "In /etc/systemd/journald.conf: Storage=persistent\n"
            "mkdir -p /var/log/journal && systemctl restart systemd-journald\n"
            "Persistence required for forensics and PCI 10.5 retention."
        ),
        cross_references={
            "NIST": "AU-11", "PCI-DSS": "10.5.1", "ISO27001": "A.8.15",
        },
    ))

    # 2. Compress=yes (default but verify)
    compress_match = re.search(
        r"^\s*Compress\s*=\s*(\S+)", full_conf, re.MULTILINE,
    )
    compress = (
        compress_match.group(1) if compress_match else "yes"  # default
    )
    compress_ok = compress.lower() in ("yes", "true", "1")
    results.append(_v35_distbase_result(
        f"{cat} - Compression",
        "Pass" if compress_ok else "Warning",
        f"journald compression: {compress}",
        severity="Low",
        details=f"Compress = {compress}",
        remediation="In /etc/systemd/journald.conf: Compress=yes",
        cross_references={"NIST": "AU-4"},
    ))

    # 3. SystemMaxUse set (retention limit)
    sysmax_match = re.search(
        r"^\s*SystemMaxUse\s*=\s*(\S+)", full_conf, re.MULTILINE,
    )
    sysmax_set = sysmax_match is not None
    results.append(_v35_distbase_result(
        f"{cat} - SystemMaxUse",
        "Pass" if sysmax_set else "Info",
        f"journald SystemMaxUse limit configured: {sysmax_set}",
        severity="Medium",
        details=(
            f"SystemMaxUse = {sysmax_match.group(1) if sysmax_match else 'unset (default 10% of disk)'}"
        ),
        remediation=(
            "In /etc/systemd/journald.conf: SystemMaxUse=2G\n"
            "Without an explicit limit, journald may consume up to 10% of "
            "the filesystem, which can fill /var unexpectedly."
        ),
        cross_references={"NIST": "AU-4"},
    ))

    # 4. ForwardToSyslog (for SIEM forwarding via rsyslog)
    forward_match = re.search(
        r"^\s*ForwardToSyslog\s*=\s*(\S+)", full_conf, re.MULTILINE,
    )
    forward = (
        forward_match.group(1).lower() if forward_match else "no"  # default
    )
    rsy_present = _v35_systemd_active("rsyslog.service") == "active"
    if rsy_present:
        forward_ok = forward in ("yes", "true", "1")
        results.append(_v35_distbase_result(
            f"{cat} - ForwardToSyslog",
            "Pass" if forward_ok else "Warning",
            f"journald -> rsyslog forwarding: {forward}",
            severity="Medium",
            details=f"ForwardToSyslog = {forward}, rsyslog active: {rsy_present}",
            remediation=(
                "In /etc/systemd/journald.conf: ForwardToSyslog=yes\n"
                "Enables centralized log forwarding via rsyslog (PCI 10.5.3)."
            ),
            cross_references={
                "NIST": "AU-6", "PCI-DSS": "10.5.3",
            },
        ))

    # 5. Seal=yes (Forward Secure Sealing for tamper detection)
    seal_match = re.search(
        r"^\s*Seal\s*=\s*(\S+)", full_conf, re.MULTILINE,
    )
    seal = seal_match.group(1).lower() if seal_match else "yes"  # default
    seal_ok = seal in ("yes", "true", "1")
    results.append(_v35_distbase_result(
        f"{cat} - FSS Seal",
        "Pass" if seal_ok else "Warning",
        f"journald Forward Secure Sealing: {seal}",
        severity="Medium",
        details=f"Seal = {seal}",
        remediation=(
            "In /etc/systemd/journald.conf: Seal=yes\n"
            "Enable per-machine sealing key: journalctl --setup-keys\n"
            "FSS provides tamper-detection for journal logs."
        ),
        cross_references={
            "NIST": "AU-9", "ISO27001": "A.8.34",
        },
    ))

    # 6. RuntimeMaxFileSize (per-file rotation)
    runtime_max = re.search(
        r"^\s*SystemMaxFileSize\s*=\s*\S+", full_conf, re.MULTILINE,
    )
    if runtime_max is None:
        results.append(_v35_distbase_result(
            f"{cat} - SystemMaxFileSize",
            "Info",
            f"journald per-file rotation size unset (uses default)",
            severity="Low",
            details="SystemMaxFileSize uses default (1/8 of SystemMaxUse)",
            cross_references={"NIST": "AU-4"},
        ))

    return results


def _check_distbase_v35_disk_integrity(os_info):
    """Disk integrity timers and maintenance."""
    results = []
    cat = "DistBaseline v3.5 - Disk Integrity"

    # 1. fstrim.timer for SSD discard (also wipes deleted-file blocks)
    fstrim_active = (
        _v35_systemd_active("fstrim.timer") == "active"
    )
    rc, out, _ = _v35_run_command(["lsblk", "-d", "-o", "ROTA", "-n"], timeout=5.0)
    has_ssd = rc == 0 and out and "0" in out
    results.append(_v35_distbase_result(
        f"{cat} - fstrim.timer",
        "Pass" if fstrim_active or not has_ssd else "Info",
        f"fstrim.timer (SSD trim): "
        f"{'active' if fstrim_active else 'inactive'}, SSD detected: {has_ssd}",
        severity="Low",
        details=f"fstrim.timer: {fstrim_active}, SSD detected: {has_ssd}",
        remediation=(
            "systemctl enable --now fstrim.timer\n"
            "Weekly fstrim aids SSD wear leveling and ensures deleted-file "
            "blocks are unmapped (data hygiene)."
        ),
        cross_references={"NIST": "MP-6"},
    ))

    # 2. Btrfs scrub timers (data integrity check)
    btrfs_present = False
    if _v35_command_available("btrfs"):
        rc, out, _ = _v35_run_command(["btrfs", "filesystem", "show"], timeout=5.0)
        btrfs_present = rc == 0 and out and "Label:" in out
    btrfs_scrub_timer = False
    if btrfs_present:
        rc, out, _ = _v35_run_command(
            ["systemctl", "list-timers", "--all", "--no-legend"],
            timeout=5.0,
        )
        if rc == 0 and out and "btrfs-scrub" in out:
            btrfs_scrub_timer = True
        results.append(_v35_distbase_result(
            f"{cat} - btrfs Scrub",
            "Pass" if btrfs_scrub_timer else "Info",
            f"btrfs scrub timer present: {btrfs_scrub_timer}",
            severity="Medium",
            details=f"btrfs filesystem detected with scrub timer: {btrfs_scrub_timer}",
            remediation=(
                "Schedule monthly scrub: create a systemd timer btrfs-scrub@.timer "
                "or use snapper-timeline.timer (SUSE) which schedules scrubs."
            ),
            cross_references={"NIST": "SI-7"},
        ))

    # 3. ZFS scrub
    zfs_present = _v35_command_available("zpool")
    if zfs_present:
        rc, out, _ = _v35_run_command(["zpool", "list", "-H"], timeout=5.0)
        has_pools = rc == 0 and out and out.strip()
        if has_pools:
            zfs_scrub_timer = (
                _v35_systemd_active("zfs-scrub-monthly@.timer") == "active" or
                _v35_systemd_active("zfs-scrub@.timer") == "active" or
                _v35_directory_exists("/etc/cron.d")
            )
            # Best-effort: check for cron or timer
            results.append(_v35_distbase_result(
                f"{cat} - ZFS Scrub",
                "Info",
                f"ZFS pools detected; scrub schedule should be configured",
                severity="Medium",
                details=f"zpool present, schedule check: best-effort",
                remediation=(
                    "Schedule weekly: zpool scrub <pool>\n"
                    "Or systemd: systemctl enable --now zfs-scrub-monthly@<pool>.timer"
                ),
                cross_references={"NIST": "SI-7"},
            ))

    # 4. Swap encryption (LUKS for swap or zswap)
    swap_encrypted = False
    proc_swaps = _v35_read_file_safe("/proc/swaps")
    crypttab = _v35_read_file_safe("/etc/crypttab")
    if proc_swaps:
        for line in proc_swaps.splitlines()[1:]:
            parts = line.split()
            if not parts:
                continue
            swap_dev = parts[0]
            # Either crypttab covers it or it's a /dev/dm-* (mapper device)
            if "/dev/mapper/" in swap_dev or "/dev/dm-" in swap_dev:
                swap_encrypted = True
                break
            # Or crypttab has an entry for it
            if crypttab and any(
                line.split()[0] in swap_dev
                for line in crypttab.splitlines() if line.strip()
                and not line.startswith("#")
            ):
                swap_encrypted = True
                break
    no_swap_in_use = not (proc_swaps and len(proc_swaps.splitlines()) > 1)
    results.append(_v35_distbase_result(
        f"{cat} - Swap Encryption",
        "Pass" if swap_encrypted or no_swap_in_use else "Warning",
        f"Swap encrypted: {swap_encrypted}, swap in use: {not no_swap_in_use}",
        severity="High" if not no_swap_in_use else "Low",
        details=(
            f"swap encrypted: {swap_encrypted}, swap entries: "
            f"{max(0, len(proc_swaps.splitlines()) - 1) if proc_swaps else 0}"
        ),
        remediation=(
            "If swap is enabled and contains sensitive data, encrypt it.\n"
            "Add to /etc/crypttab:\n"
            "  swap UUID=<uuid> /dev/urandom swap,cipher=aes-xts-plain64,size=512\n"
            "Or use zram with encryption."
        ),
        cross_references={
            "NIST": "SC-28", "PCI-DSS": "3.5.1", "STIG": "V-230380",
        },
    ))

    return results


def _check_distbase_v35_system_integrity_markers(os_info):
    """System integrity: machine-id, cron policies, at policies."""
    results = []
    cat = "DistBaseline v3.5 - System Integrity"

    # 1. machine-id consistency (/etc/machine-id == /var/lib/dbus/machine-id)
    etc_mid = _v35_read_file_safe("/etc/machine-id").strip()
    dbus_mid = _v35_read_file_safe("/var/lib/dbus/machine-id").strip()
    mid_consistent = bool(etc_mid) and bool(dbus_mid) and etc_mid == dbus_mid
    results.append(_v35_distbase_result(
        f"{cat} - machine-id",
        "Pass" if mid_consistent else "Warning",
        f"/etc/machine-id == /var/lib/dbus/machine-id: {mid_consistent}",
        severity="Medium",
        details=(
            f"/etc/machine-id present: {bool(etc_mid)}, "
            f"/var/lib/dbus/machine-id present: {bool(dbus_mid)}, "
            f"match: {mid_consistent}"
        ),
        remediation=(
            "Stale or mismatched machine-id can cause D-Bus issues and may "
            "indicate cloned-image hygiene problems.\n"
            "Reset: rm /etc/machine-id /var/lib/dbus/machine-id\n"
            "       systemd-machine-id-setup\n"
            "       ln -s /etc/machine-id /var/lib/dbus/machine-id"
        ),
        cross_references={"NIST": "CM-8"},
    ))

    # 2. /etc/cron.allow exists (allowlist for cron access)
    cron_allow = _v35_file_exists("/etc/cron.allow")
    cron_deny = _v35_file_exists("/etc/cron.deny")
    cron_policy_strict = cron_allow and not cron_deny
    results.append(_v35_distbase_result(
        f"{cat} - cron Access Policy",
        "Pass" if cron_policy_strict else "Warning",
        f"cron.allow allowlist (preferred): {cron_allow}, "
        f"cron.deny present: {cron_deny}",
        severity="Medium",
        details=(
            f"/etc/cron.allow: {cron_allow}, /etc/cron.deny: {cron_deny}"
        ),
        remediation=(
            "PCI/STIG prefer allowlist over denylist:\n"
            "  echo 'root' > /etc/cron.allow; chmod 600 /etc/cron.allow\n"
            "  rm -f /etc/cron.deny\n"
            "Without /etc/cron.allow, all users can submit cron jobs."
        ),
        cross_references={
            "NIST": "AC-3", "STIG": "V-230380", "CIS": "5.1.8",
        },
    ))

    # 3. /etc/at.allow allowlist for at(1) batch jobs
    at_present = _v35_command_available("at")
    if at_present:
        at_allow = _v35_file_exists("/etc/at.allow")
        at_deny = _v35_file_exists("/etc/at.deny")
        at_policy_strict = at_allow and not at_deny
        results.append(_v35_distbase_result(
            f"{cat} - at Access Policy",
            "Pass" if at_policy_strict else "Warning",
            f"at.allow allowlist: {at_allow}, at.deny present: {at_deny}",
            severity="Medium",
            details=f"/etc/at.allow: {at_allow}, /etc/at.deny: {at_deny}",
            remediation=(
                "echo 'root' > /etc/at.allow; chmod 600 /etc/at.allow\n"
                "rm -f /etc/at.deny"
            ),
            cross_references={
                "NIST": "AC-3", "STIG": "V-230380", "CIS": "5.1.9",
            },
        ))

    # 4. Cron file permissions (/etc/crontab, /etc/cron.d, etc.)
    cron_paths = [
        "/etc/crontab",
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/etc/cron.d",
    ]
    cron_secure_count = 0
    cron_insecure = []
    for path in cron_paths:
        if not _v35_file_exists(path) and not _v35_directory_exists(path):
            continue
        try:
            mode = os.stat(path).st_mode & 0o7777
            # Should be 0700 or 0600 (or 0755 for /etc/crontab is acceptable)
            # World-writable is the cardinal sin
            if (mode & 0o002) == 0:
                cron_secure_count += 1
            else:
                cron_insecure.append(f"{path}({oct(mode)})")
        except OSError:
            pass
    results.append(_v35_distbase_result(
        f"{cat} - cron File Permissions",
        "Pass" if not cron_insecure else "Fail",
        f"cron files not world-writable ({cron_secure_count} secure)",
        severity="High",
        details=f"World-writable cron paths: {cron_insecure}",
        remediation=(
            "chmod o-w /etc/crontab /etc/cron.* (for any flagged paths)"
        ),
        cross_references={
            "NIST": "AC-3", "STIG": "V-230380", "CIS": "5.1.2",
        },
    ))

    return results


def _check_distbase_v35_advanced_firewall(os_info):
    """Advanced firewall: nftables sets/maps, firewalld zones."""
    results = []
    cat = "DistBaseline v3.5 - Advanced Firewall"

    # nftables: count tables and chains in active ruleset
    if _v35_command_available("nft"):
        rc, out, _ = _v35_run_command(["nft", "list", "ruleset"], timeout=5.0)
        if rc == 0:
            content = out or ""
            # Count tables
            tables = re.findall(r"^\s*table\s+(\S+\s+\S+)\s*{", content,
                                  re.MULTILINE)
            # Count chains and rules
            chain_count = len(re.findall(r"^\s*chain\s+\S+", content, re.MULTILINE))
            rule_count = sum(
                1 for line in content.splitlines()
                if line.strip() and not line.strip().startswith(("#", "table",
                                                                  "chain", "}", "{"))
            )
            results.append(_v35_distbase_result(
                f"{cat} - nftables Ruleset",
                "Pass" if tables else "Info",
                f"nftables tables: {len(tables)}, chains: {chain_count}, "
                f"rule lines: {rule_count}",
                severity="Low",
                details=(
                    f"Tables: {[t.strip() for t in tables[:5]]}, "
                    f"chains: {chain_count}"
                ),
                cross_references={"NIST": "SC-7"},
            ))

            # Look for default-drop policies
            default_drop = bool(re.search(
                r"^\s*type\s+filter\s+hook\s+input\s+priority\s+\S+;\s*policy\s+drop;",
                content, re.MULTILINE,
            ))
            results.append(_v35_distbase_result(
                f"{cat} - nftables Default Drop",
                "Pass" if default_drop else "Info",
                f"nftables INPUT chain default-drop policy: {default_drop}",
                severity="High",
                details=f"INPUT default-drop: {default_drop}",
                remediation=(
                    "In /etc/nftables.conf, set chain input policy:\n"
                    "  type filter hook input priority 0; policy drop;"
                ),
                cross_references={
                    "NIST": "SC-7", "PCI-DSS": "1.4.4",
                },
            ))

    # firewalld zone audit
    if _v35_command_available("firewall-cmd"):
        rc, out, _ = _v35_run_command(
            ["firewall-cmd", "--get-default-zone"], timeout=5.0,
        )
        default_zone = out.strip() if rc == 0 else "unknown"
        secure_default = default_zone in ("drop", "block")
        results.append(_v35_distbase_result(
            f"{cat} - firewalld Default Zone",
            "Pass" if secure_default else "Warning",
            f"firewalld default zone: {default_zone}",
            severity="High",
            details=f"default zone = {default_zone}",
            remediation=(
                "firewall-cmd --set-default-zone=drop\n"
                "Default 'public' zone allows incoming on common services; "
                "use 'drop' or 'block' for deny-by-default."
            ),
            cross_references={
                "NIST": "SC-7", "PCI-DSS": "1.4.4",
            },
        ))

        # ICMP block inversion (more secure)
        rc, out, _ = _v35_run_command(
            ["firewall-cmd", "--zone", default_zone, "--query-icmp-block-inversion"],
            timeout=5.0,
        )
        # Don't fail if zone doesn't support, just log
        # Check active zones count
        rc, out, _ = _v35_run_command(
            ["firewall-cmd", "--get-active-zones"], timeout=5.0,
        )
        active_zone_count = 0
        if rc == 0 and out:
            active_zone_count = sum(
                1 for line in out.splitlines()
                if line.strip() and not line.startswith((" ", "\t"))
            )
        results.append(_v35_distbase_result(
            f"{cat} - firewalld Active Zones",
            "Info",
            f"firewalld active zones: {active_zone_count}",
            severity="Informational",
            details=f"Active zones: {active_zone_count}",
            cross_references={"NIST": "SC-7"},
        ))

    return results


def _check_distbase_v35_kdump_panic(os_info):
    """kdump configuration and panic-on-oops."""
    results = []
    cat = "DistBaseline v3.5 - kdump"

    # kdump.service (RHEL family) or makedumpfile (cross-distro)
    kdump_service_active = (
        _v35_systemd_active("kdump.service") == "active"
    )
    kexec_tools = (
        _v35_command_available("kexec") or
        _v35_command_available("makedumpfile")
    )

    # kdump is most common on RHEL family; on Debian, recommend if not installed
    if os_info and os_info.is_redhat_family():
        results.append(_v35_distbase_result(
            f"{cat} - kdump",
            "Pass" if kdump_service_active else "Info",
            f"kdump service active: {kdump_service_active}",
            severity="Low",
            details=(
                f"kdump service: {kdump_service_active}, "
                f"kexec/makedumpfile: {kexec_tools}"
            ),
            remediation=(
                "dnf install -y kexec-tools\n"
                "systemctl enable --now kdump.service\n"
                "Captures kernel crash dumps for forensic analysis."
            ),
            cross_references={"NIST": "AU-9, SI-7"},
        ))

    # panic_on_oops (kernel hardening)
    panic_on_oops = _v35_read_sysctl("kernel.panic_on_oops") == "1"
    panic_value = _v35_read_sysctl("kernel.panic")
    panic_set = panic_value and panic_value != "0"
    results.append(_v35_distbase_result(
        f"{cat} - panic_on_oops",
        "Pass" if panic_on_oops else "Info",
        f"kernel.panic_on_oops = 1: {panic_on_oops}, kernel.panic = {panic_value}",
        severity="Medium",
        details=(
            f"panic_on_oops = {_v35_read_sysctl('kernel.panic_on_oops')}, "
            f"panic = {panic_value}"
        ),
        remediation=(
            "In /etc/sysctl.d/99-panic.conf:\n"
            "  kernel.panic_on_oops = 1\n"
            "  kernel.panic = 60\n"
            "Halts the kernel on oops conditions to prevent silent compromise; "
            "panic=60 reboots after 60 seconds."
        ),
        cross_references={"NIST": "SI-17"},
    ))

    return results


def _check_distbase_v35_lsm_advanced(os_info):
    """Advanced LSM detection: eBPF LSM, IMA appraisal mode, capabilities."""
    results = []
    cat = "DistBaseline v3.5 - LSM Advanced"

    # 1. List of active LSMs
    lsm_path = "/sys/kernel/security/lsm"
    active_lsms = ""
    if _v35_file_exists(lsm_path):
        active_lsms = _v35_read_file_safe(lsm_path).strip()
    results.append(_v35_distbase_result(
        f"{cat} - Active LSMs",
        "Pass" if active_lsms else "Warning",
        f"Active Linux Security Modules: {active_lsms or '<none>'}",
        severity="High" if not active_lsms else "Low",
        details=f"/sys/kernel/security/lsm = {active_lsms}",
        cross_references={"NIST": "AC-3, SI-7"},
    ))

    # 2. eBPF LSM availability (kernel 5.7+, optional opt-in)
    bpf_lsm_active = "bpf" in active_lsms.lower()
    results.append(_v35_distbase_result(
        f"{cat} - eBPF LSM",
        "Info",
        f"eBPF LSM active: {bpf_lsm_active}",
        severity="Informational",
        details=f"bpf in active_lsms: {bpf_lsm_active}",
        remediation=(
            "Enable in kernel cmdline: lsm=lockdown,yama,integrity,apparmor,bpf\n"
            "(kernel 5.7+); allows runtime-loadable security policies."
        ),
        cross_references={"NIST": "AC-3"},
    ))

    # 3. IMA appraisal mode (vs measurement-only)
    ima_policy_path = "/sys/kernel/security/ima/policy"
    ima_active = _v35_directory_exists("/sys/kernel/security/ima")
    ima_appraise = False
    if ima_active and _v35_file_exists(ima_policy_path):
        # /sys/kernel/security/ima/policy is write-only. Check the build-time
        # default policy via /proc/cmdline
        cmdline = _v35_read_file_safe("/proc/cmdline")
        ima_appraise = (
            "ima_appraise=enforce" in cmdline or
            "ima_appraise=fix" in cmdline
        )
    results.append(_v35_distbase_result(
        f"{cat} - IMA Appraisal",
        "Pass" if ima_appraise else "Info",
        f"IMA appraisal mode (enforce): {ima_appraise}",
        severity="Medium",
        details=f"IMA active: {ima_active}, ima_appraise in cmdline: {ima_appraise}",
        remediation=(
            "Boot with kernel cmdline: ima_policy=tcb ima_appraise=enforce\n"
            "Provides cryptographic verification of file integrity at exec/mmap time."
        ),
        cross_references={
            "NIST": "SI-7", "ISO27001": "A.8.32",
        },
    ))

    # 4. Linux capabilities for non-root processes (CAP_SYS_ADMIN audit)
    # Indicator: setcap binaries in $PATH
    setcap_binaries = []
    setcap_dirs = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
    if _v35_command_available("getcap"):
        for d in setcap_dirs:
            if not _v35_directory_exists(d):
                continue
            rc, out, _ = _v35_run_command(["getcap", "-r", d], timeout=10.0)
            if rc == 0 and out:
                for line in out.splitlines():
                    if line.strip():
                        setcap_binaries.append(line.split(" =")[0])
            if len(setcap_binaries) > 30:
                break  # bounded
    results.append(_v35_distbase_result(
        f"{cat} - File Capabilities",
        "Info",
        f"File capabilities set on {len(setcap_binaries)} binaries",
        severity="Informational",
        details=(
            f"setcap binaries: {setcap_binaries[:5]}"
            f"{'...' if len(setcap_binaries) > 5 else ''}"
        ),
        remediation=(
            "Audit setcap binaries with: getcap -r /usr/bin /usr/sbin /bin /sbin\n"
            "Each represents a capability-grant that bypasses normal permission "
            "checks. Document and review periodically (PCI 7.2.2)."
        ),
        cross_references={
            "NIST": "AC-6", "PCI-DSS": "7.2.2",
        },
    ))

    return results


# Save reference to existing run_checks
_original_run_checks_distbase_v35 = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the v3.5 expanded DistBaseline module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_distbase_v35(shared_data)

    os_info = shared_data.get("os_info") or shared_data.get("v3_os_info")
    if os_info is None:
        from shared_components import os_detection as _os_det
        os_info = _os_det.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        results.extend(_check_distbase_v35_ubuntu_pro(os_info))
        results.extend(_check_distbase_v35_rhel_insights(os_info))
        results.extend(_check_distbase_v35_snap_flatpak(os_info))
        results.extend(_check_distbase_v35_journald(os_info))
        results.extend(_check_distbase_v35_disk_integrity(os_info))
        results.extend(_check_distbase_v35_system_integrity_markers(os_info))
        results.extend(_check_distbase_v35_advanced_firewall(os_info))
        results.extend(_check_distbase_v35_kdump_panic(os_info))
        results.extend(_check_distbase_v35_lsm_advanced(os_info))
    except Exception as exc:  # noqa: BLE001
        results.append(AuditResult(
            module=MODULE_NAME, category="DistBaseline - Error",
            status="Error",
            message=f"DistBaseline v3.5 expansion exception: {exc!r}",
            details=str(exc), severity="Medium",
        ))

    return results
if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    print("[DISTBASELINE] ===== Distribution Hardening Baseline =====")
    print("[DISTBASELINE] Module Version: 3.9\n")
    rs = run_checks()
    print(f"[DISTBASELINE] {len(rs)} checks executed\n")
    counts: Dict[str, int] = {}
    for r in rs:
        counts[r.status] = counts.get(r.status, 0) + 1
    for s, c in sorted(counts.items()):
        print(f"  {s:>8}: {c}")
