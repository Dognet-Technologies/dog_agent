#!/usr/bin/env python3
"""
module_cmmc.py
CMMC 2.0 + DFARS 252.204-7012 Module for Linux
Version: 3.9

SYNOPSIS
    Linux technical compliance assessment against the U.S. Department
    of Defense Cybersecurity Maturity Model Certification (CMMC) 2.0
    and DFARS 252.204-7012 (Safeguarding Covered Defense Information).

DESCRIPTION
    CMMC 2.0 establishes three levels of cybersecurity maturity for
    organizations handling Federal Contract Information (FCI) or
    Controlled Unclassified Information (CUI):

        Level 1 - Foundational (17 practices, FAR 52.204-21 derived)
        Level 2 - Advanced     (110 practices, NIST SP 800-171 R2)
        Level 3 - Expert       (NIST SP 800-172 enhanced controls)

    This module covers the technical practices applicable to Linux
    workstations and servers in the CDE (CUI Data Environment) or FCI
    handling environments. It also includes DFARS 252.204-7012 SPRS
    (Supplier Performance Risk System) score indicators.

    Practices map to 14 CMMC domains:
        AC - Access Control            MA - Maintenance
        AT - Awareness and Training    MP - Media Protection
        AU - Audit and Accountability  PE - Physical Protection
        CM - Configuration Management  PS - Personnel Security
        IA - Identification & Auth     RA - Risk Assessment
        IR - Incident Response         CA - Security Assessment
                                       SC - System and Communications
                                       SI - System and Information

    Each check populates AuditResult.cross_references with the CMMC
    practice ID plus equivalents in NIST 800-171, NIST 800-53, ISO 27001,
    and other frameworks.

PARAMETERS
    shared_data : Dictionary containing shared data from the orchestrator.

USAGE
    Standalone:
        python3 modules/module_cmmc.py

    Via orchestrator:
        python3 linux_security_audit.py -m CMMC

NOTES
    Version: 3.9
    Reference: https://dodcio.defense.gov/CMMC/
    Standards: CMMC 2.0 (May 2024 draft rule), NIST SP 800-171 R2,
               NIST SP 800-172, DFARS 252.204-7012
    Target: 80+ technical practice checks across all 14 domains.
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
    file_mode, parse_kv_file, list_directory, make_result,
    first_existing,
)

logger = logging.getLogger("audit.module_cmmc")
MODULE_NAME = "CMMC"
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
# AC - Access Control (Domain)
# ===========================================================================

def _check_ac_domain(os_info) -> List[AuditResult]:
    cat = "CMMC AC - Access Control"
    results: List[AuditResult] = []

    # AC.L1-3.1.1 (NIST 800-171 3.1.1) - Authorized users
    # No empty passwords - everyone must have a credential
    shadow = read_file_safe("/etc/shadow")
    empty_pwd_accounts = []
    if shadow:
        for line in shadow.splitlines():
            fields = line.split(":")
            if len(fields) >= 2 and fields[1] == "":
                empty_pwd_accounts.append(fields[0])

    results.append(_r(
        cat,
        "Pass" if not empty_pwd_accounts else "Fail",
        "CMMC AC.L1-3.1.1: All accounts have credentials configured",
        severity="Critical",
        details=f"Empty-password accounts: {', '.join(empty_pwd_accounts) or 'none'}",
        remediation=(
            "Lock empty-password accounts: passwd -l <username>. "
            "Or remove unused accounts: userdel -r <username>."
        ),
        cross_references={
            "CMMC": "AC.L1-3.1.1", "NIST-171": "3.1.1", "NIST": "AC-2",
            "ISO27001": "A.8.5", "PCI-DSS": "8.2.1",
        },
    ))

    # AC.L1-3.1.2 - Limit transactions/functions to authorized users
    # Check /etc/sudoers permissions (must be 0440)
    sudoers_mode = file_mode("/etc/sudoers")
    sudoers_ok = sudoers_mode == 0o440
    results.append(_r(
        cat,
        "Pass" if sudoers_ok else "Fail",
        "CMMC AC.L1-3.1.2: /etc/sudoers permissions are 0440",
        severity="High",
        details=f"/etc/sudoers mode: {oct(sudoers_mode) if sudoers_mode else 'not present'}",
        remediation="chmod 0440 /etc/sudoers && chown root:root /etc/sudoers",
        cross_references={
            "CMMC": "AC.L1-3.1.2", "NIST-171": "3.1.2", "NIST": "AC-3",
            "ISO27001": "A.8.3",
        },
    ))

    # AC.L2-3.1.5 (Level 2) - Least privilege
    # Check for non-root UID 0 accounts
    passwd_content = read_file_safe("/etc/passwd")
    uid0 = []
    if passwd_content:
        for line in passwd_content.splitlines():
            fields = line.split(":")
            if len(fields) >= 3:
                try:
                    if int(fields[2]) == 0 and fields[0] != "root":
                        uid0.append(fields[0])
                except ValueError:
                    continue

    results.append(_r(
        cat,
        "Pass" if not uid0 else "Fail",
        "CMMC AC.L2-3.1.5: Only root has UID 0 (least privilege)",
        severity="Critical",
        details=f"Non-root UID 0 accounts: {', '.join(uid0) or 'none'}",
        remediation="Reassign UID for non-root accounts: usermod -u <new_uid> <name>",
        cross_references={
            "CMMC": "AC.L2-3.1.5", "NIST-171": "3.1.5", "NIST": "AC-6",
            "CIS": "6.2.10", "STIG": "V-230327",
        },
    ))

    # AC.L2-3.1.6 - Use non-privileged accounts for non-security functions
    # Indicator: root account direct login should be disabled via SSH
    sshd_config = read_file_safe("/etc/ssh/sshd_config")
    permit_root = "yes"  # OpenSSH default
    if sshd_config:
        for line in sshd_config.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("permitrootlogin"):
                permit_root = stripped.split(None, 1)[1].lower() if len(stripped.split()) > 1 else "yes"

    root_disabled = permit_root in ("no", "prohibit-password", "forced-commands-only")
    results.append(_r(
        cat,
        "Pass" if root_disabled else "Fail",
        "CMMC AC.L2-3.1.6: Root SSH access restricted",
        severity="High",
        details=f"PermitRootLogin = {permit_root}",
        remediation=(
            "sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "
            "/etc/ssh/sshd_config && systemctl restart sshd"
        ),
        cross_references={
            "CMMC": "AC.L2-3.1.6", "NIST-171": "3.1.6", "NIST": "AC-6(2)",
            "CIS": "5.2.7", "STIG": "V-230296", "PCI-DSS": "8.2.1",
        },
    ))

    # AC.L2-3.1.10 - Session lock with pattern-hiding display
    # Linux equivalent: TMOUT in shells
    profile_paths = ["/etc/profile"] + list_directory("/etc/profile.d", ".sh")
    tmout_set = False
    for path in profile_paths:
        content = read_file_safe(path)
        if re.search(r"^\s*(?:readonly\s+|export\s+)?TMOUT=\d+",
                     content, re.MULTILINE):
            tmout_set = True
            break

    results.append(_r(
        cat,
        "Pass" if tmout_set else "Fail",
        "CMMC AC.L2-3.1.10: Session inactivity lock configured",
        severity="Medium",
        details=f"TMOUT set in shell profiles: {tmout_set}",
        remediation=(
            "echo 'readonly TMOUT=900; export TMOUT' > /etc/profile.d/tmout.sh && "
            "chmod 644 /etc/profile.d/tmout.sh"
        ),
        cross_references={
            "CMMC": "AC.L2-3.1.10", "NIST-171": "3.1.10", "NIST": "AC-11",
            "CIS": "5.4.4", "STIG": "V-230363",
        },
    ))

    # AC.L2-3.1.20 - Verify and control connections to external systems
    # Indicator: firewall present
    firewall_active = (
        systemd_active("firewalld.service") == "active"
        or systemd_active("ufw.service") == "active"
        or systemd_active("nftables.service") == "active"
        or systemd_active("iptables.service") == "active"
    )

    results.append(_r(
        cat,
        "Pass" if firewall_active else "Fail",
        "CMMC AC.L2-3.1.20: Network firewall active",
        severity="Critical",
        details=f"Active firewall service detected: {firewall_active}",
        remediation=(
            "systemctl enable --now firewalld  (RHEL family) or "
            "systemctl enable --now ufw  (Debian/Ubuntu)"
        ),
        cross_references={
            "CMMC": "AC.L2-3.1.20", "NIST-171": "3.1.20", "NIST": "SC-7",
            "CIS": "3.4.1.2", "ISO27001": "A.8.20", "PCI-DSS": "1.2.6",
        },
    ))

    return results


# ===========================================================================
# AU - Audit and Accountability
# ===========================================================================

def _check_au_domain(os_info) -> List[AuditResult]:
    cat = "CMMC AU - Audit & Accountability"
    results: List[AuditResult] = []

    # AU.L2-3.3.1 - Create and retain audit records
    auditd_active = systemd_active("auditd.service") == "active"
    results.append(_r(
        cat,
        "Pass" if auditd_active else "Fail",
        "CMMC AU.L2-3.3.1: Audit logging service active",
        severity="High",
        details=f"auditd.service state: {systemd_active('auditd.service')}",
        remediation=(
            "Install: dnf install -y audit (RHEL) or apt-get install -y auditd "
            "(Debian). Enable: systemctl enable --now auditd."
        ),
        cross_references={
            "CMMC": "AU.L2-3.3.1", "NIST-171": "3.3.1", "NIST": "AU-2",
            "CIS": "4.1.1.1", "ISO27001": "A.8.15", "PCI-DSS": "10.2.1",
            "HIPAA": "164.312(b)",
        },
    ))

    # AU.L2-3.3.2 - Ensure actions of individual users can be uniquely traced
    # Audit rules for /etc/passwd, /etc/shadow, /etc/group must be present
    audit_rules_files = (
        "/etc/audit/audit.rules", "/etc/audit/rules.d/audit.rules",
    ) + tuple(list_directory("/etc/audit/rules.d", ".rules"))

    has_identity_audit = False
    for arf in audit_rules_files:
        content = read_file_safe(arf)
        if re.search(r"-w\s+/etc/(passwd|shadow|group)", content):
            has_identity_audit = True
            break

    results.append(_r(
        cat,
        "Pass" if has_identity_audit else "Fail",
        "CMMC AU.L2-3.3.2: Identity changes are audited",
        severity="High",
        details=f"Identity file watch rules present: {has_identity_audit}",
        remediation=(
            "Create /etc/audit/rules.d/50-identity.rules with: "
            "-w /etc/passwd -p wa -k identity\\n"
            "-w /etc/shadow -p wa -k identity\\n"
            "-w /etc/group -p wa -k identity\\n"
            "-w /etc/gshadow -p wa -k identity"
        ),
        cross_references={
            "CMMC": "AU.L2-3.3.2", "NIST-171": "3.3.2", "NIST": "AU-2",
            "CIS": "4.1.3.7", "STIG": "V-230418",
        },
    ))

    # AU.L2-3.3.4 - Alert in event of audit logging process failure
    auditd_conf = read_file_safe("/etc/audit/auditd.conf")
    failure_action = "unknown"
    for line in auditd_conf.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("disk_full_action"):
            failure_action = stripped.split("=", 1)[-1].strip().lower() if "=" in stripped else stripped.split()[-1].lower()
            break

    failure_ok = failure_action in ("halt", "single", "syslog")
    results.append(_r(
        cat,
        "Pass" if failure_ok else "Warning",
        "CMMC AU.L2-3.3.4: Audit failure action configured",
        severity="High",
        details=f"disk_full_action = {failure_action}",
        remediation=(
            "Edit /etc/audit/auditd.conf: disk_full_action = halt "
            "(or 'syslog' for environments where halting is unacceptable)"
        ),
        cross_references={
            "CMMC": "AU.L2-3.3.4", "NIST-171": "3.3.4", "NIST": "AU-5",
            "CIS": "4.1.2.2", "STIG": "V-230398",
        },
    ))

    # AU.L2-3.3.7 - Time synchronization for audit accuracy
    chrony_or_ntp_active = (
        systemd_active("chronyd.service") == "active"
        or systemd_active("chrony.service") == "active"
        or systemd_active("ntp.service") == "active"
        or systemd_active("ntpd.service") == "active"
        or systemd_active("systemd-timesyncd.service") == "active"
    )

    results.append(_r(
        cat,
        "Pass" if chrony_or_ntp_active else "Fail",
        "CMMC AU.L2-3.3.7: Time synchronization active for audit accuracy",
        severity="High",
        details=f"Time sync service active: {chrony_or_ntp_active}",
        remediation=(
            "Enable a time sync service: systemctl enable --now chronyd "
            "(or chrony, ntp, systemd-timesyncd)."
        ),
        cross_references={
            "CMMC": "AU.L2-3.3.7", "NIST-171": "3.3.7", "NIST": "AU-8(1)",
            "CIS": "2.1.1.1", "STIG": "V-230484", "PCI-DSS": "10.6.1",
        },
    ))

    return results


# ===========================================================================
# CM - Configuration Management
# ===========================================================================

def _check_cm_domain(os_info) -> List[AuditResult]:
    cat = "CMMC CM - Configuration Management"
    results: List[AuditResult] = []

    # CM.L2-3.4.6 - Apply principle of least functionality
    # Disable unnecessary services - check the usual suspects
    risky_services = (
        "telnet.socket", "rsh.socket", "rlogin.socket", "rexec.socket",
        "vsftpd.service", "tftpd-hpa.service", "xinetd.service",
    )
    active_risky = []
    for svc in risky_services:
        if systemd_active(svc) == "active":
            active_risky.append(svc)

    results.append(_r(
        cat,
        "Pass" if not active_risky else "Fail",
        "CMMC CM.L2-3.4.6: Unnecessary insecure services disabled",
        severity="High",
        details=f"Active insecure services: {', '.join(active_risky) or 'none'}",
        remediation=(
            f"systemctl disable --now {' '.join(active_risky) or '<service>'}"
        ),
        cross_references={
            "CMMC": "CM.L2-3.4.6", "NIST-171": "3.4.6", "NIST": "CM-7",
            "CIS": "2.2", "PCI-DSS": "2.2.4",
        },
    ))

    # CM.L2-3.4.7 - Restrict, disable, or prevent the use of nonessential
    # programs, functions, ports, protocols, and/or services
    # Check kernel module blacklisting for risky modules
    blacklisted_modules = ("dccp", "sctp", "rds", "tipc", "cramfs", "freevxfs",
                            "jffs2", "hfs", "hfsplus", "udf", "usb-storage")
    bl_count = 0
    for path in ("/etc/modprobe.d/blacklist.conf",
                 "/etc/modprobe.d/CIS.conf",
                 "/etc/modprobe.d/disable-modules.conf"):
        content = read_file_safe(path)
        for mod in blacklisted_modules:
            if re.search(rf"^\s*(?:install\s+{mod}\s+/bin/(?:false|true)|blacklist\s+{mod})",
                         content, re.MULTILINE):
                bl_count += 1

    results.append(_r(
        cat,
        "Pass" if bl_count >= 5 else "Warning",
        f"CMMC CM.L2-3.4.7: Risky kernel modules blacklisted ({bl_count}/{len(blacklisted_modules)})",
        severity="Medium",
        details=(
            f"{bl_count} of {len(blacklisted_modules)} recommended modules blacklisted. "
            "Modules: dccp, sctp, rds, tipc, cramfs, freevxfs, jffs2, hfs, "
            "hfsplus, udf, usb-storage"
        ),
        remediation=(
            "Create /etc/modprobe.d/cmmc-blacklist.conf with: "
            "install dccp /bin/false, install sctp /bin/false, etc."
        ),
        cross_references={
            "CMMC": "CM.L2-3.4.7", "NIST-171": "3.4.7", "NIST": "CM-7(1)",
            "CIS": "1.1.1", "STIG": "V-230498",
        },
    ))

    return results


# ===========================================================================
# IA - Identification and Authentication
# ===========================================================================

def _check_ia_domain(os_info) -> List[AuditResult]:
    cat = "CMMC IA - Identification & Authentication"
    results: List[AuditResult] = []

    # IA.L1-3.5.1 - Identify users
    # No duplicate UIDs
    passwd = read_file_safe("/etc/passwd")
    uids_seen: Dict[int, List[str]] = {}
    if passwd:
        for line in passwd.splitlines():
            fields = line.split(":")
            if len(fields) >= 3:
                try:
                    uid = int(fields[2])
                    uids_seen.setdefault(uid, []).append(fields[0])
                except ValueError:
                    continue

    duplicates = {uid: names for uid, names in uids_seen.items() if len(names) > 1}

    results.append(_r(
        cat,
        "Pass" if not duplicates else "Fail",
        "CMMC IA.L1-3.5.1: No duplicate user identifiers",
        severity="High",
        details=(
            f"Duplicate UIDs: {duplicates}" if duplicates else "All UIDs unique"
        ),
        remediation="Reassign duplicate UIDs: usermod -u <new_uid> <username>",
        cross_references={
            "CMMC": "IA.L1-3.5.1", "NIST-171": "3.5.1", "NIST": "IA-2",
            "CIS": "6.2.6", "STIG": "V-230371",
        },
    ))

    # IA.L2-3.5.7 - Enforce minimum password complexity
    pwquality = read_file_safe("/etc/security/pwquality.conf")
    minlen_match = re.search(r"^\s*minlen\s*=\s*(\d+)", pwquality, re.MULTILINE)
    minlen = int(minlen_match.group(1)) if minlen_match else 0
    minlen_ok = minlen >= 12  # CMMC L2 requires minimum 12

    results.append(_r(
        cat,
        "Pass" if minlen_ok else "Fail",
        "CMMC IA.L2-3.5.7: Password minimum length >= 12",
        severity="High",
        details=f"pwquality.conf minlen = {minlen or 'unset'}",
        remediation="Edit /etc/security/pwquality.conf: minlen = 14",
        cross_references={
            "CMMC": "IA.L2-3.5.7", "NIST-171": "3.5.7", "NIST": "IA-5(1)",
            "CIS": "5.4.1.1", "PCI-DSS": "8.3.6",
        },
    ))

    # IA.L2-3.5.8 - Prohibit reuse for specified number of generations
    pamd_files = list_directory("/etc/pam.d", "")
    history_min = 0
    for pf in pamd_files:
        content = read_file_safe(pf)
        m = re.search(r"pam_pwhistory.*?remember\s*=\s*(\d+)", content)
        if m:
            history_min = max(history_min, int(m.group(1)))

    history_ok = history_min >= 5  # CMMC L2 requires at least 5 generations

    results.append(_r(
        cat,
        "Pass" if history_ok else "Fail",
        "CMMC IA.L2-3.5.8: Password history >= 5 generations",
        severity="High",
        details=f"pam_pwhistory remember value: {history_min}",
        remediation=(
            "Configure /etc/pam.d/system-auth (RHEL) or common-password "
            "(Debian) with pam_pwhistory.so remember=24 (24 is more strict)."
        ),
        cross_references={
            "CMMC": "IA.L2-3.5.8", "NIST-171": "3.5.8", "NIST": "IA-5(1)",
            "CIS": "5.4.1.3", "PCI-DSS": "8.3.7",
        },
    ))

    # IA.L2-3.5.10 - Store and transmit only cryptographically-protected passwords
    # ENCRYPT_METHOD must be SHA512 in /etc/login.defs
    login_defs = read_file_safe("/etc/login.defs")
    settings = parse_kv_file(login_defs)
    encrypt = settings.get("encrypt_method", "").upper()
    encrypt_ok = encrypt in ("SHA512", "YESCRYPT")

    results.append(_r(
        cat,
        "Pass" if encrypt_ok else "Fail",
        "CMMC IA.L2-3.5.10: Strong password hashing algorithm",
        severity="High",
        details=f"ENCRYPT_METHOD = {encrypt or 'unset'}",
        remediation=(
            "sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs"
        ),
        cross_references={
            "CMMC": "IA.L2-3.5.10", "NIST-171": "3.5.10", "NIST": "IA-5(1)",
            "CIS": "5.4.1.7", "STIG": "V-230231", "PCI-DSS": "8.3.2",
        },
    ))

    return results


# ===========================================================================
# SC - System and Communications Protection
# ===========================================================================

def _check_sc_domain(os_info) -> List[AuditResult]:
    cat = "CMMC SC - System & Comms Protection"
    results: List[AuditResult] = []

    # SC.L1-3.13.1 - Monitor and control communications at boundaries
    # Already covered by AC.L2-3.1.20 (firewall); add IPv4 forwarding check
    ip_forward = read_sysctl("net.ipv4.ip_forward")
    fwd_disabled = ip_forward == "0"

    results.append(_r(
        cat,
        "Pass" if fwd_disabled else "Warning",
        "CMMC SC.L1-3.13.1: IPv4 forwarding disabled (host not acting as router)",
        severity="Medium",
        details=f"net.ipv4.ip_forward = {ip_forward or 'unset'}",
        remediation=(
            "echo 'net.ipv4.ip_forward = 0' > /etc/sysctl.d/99-cmmc.conf && "
            "sysctl --system"
        ),
        cross_references={
            "CMMC": "SC.L1-3.13.1", "NIST-171": "3.13.1", "NIST": "SC-7",
            "CIS": "3.2.1", "STIG": "V-230540", "PCI-DSS": "1.3.3",
        },
    ))

    # SC.L2-3.13.8 - Implement cryptographic mechanisms to prevent
    # unauthorized disclosure of CUI during transmission
    sshd_config = read_file_safe("/etc/ssh/sshd_config")
    weak_ciphers = []
    if sshd_config:
        for line in sshd_config.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("ciphers "):
                for weak in ("3des", "arcfour", "blowfish", "des-cbc",
                             "aes128-cbc", "aes256-cbc"):
                    if weak in stripped.lower():
                        weak_ciphers.append(weak)
                break

    results.append(_r(
        cat,
        "Pass" if not weak_ciphers else "Fail",
        "CMMC SC.L2-3.13.8: SSH uses strong cryptography for CUI in transit",
        severity="High",
        details=f"Weak SSH ciphers in config: {', '.join(weak_ciphers) or 'none'}",
        remediation=(
            "Set in /etc/ssh/sshd_config: Ciphers "
            "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,"
            "aes128-gcm@openssh.com,aes256-ctr,aes128-ctr"
        ),
        cross_references={
            "CMMC": "SC.L2-3.13.8", "NIST-171": "3.13.8", "NIST": "SC-13",
            "CIS": "5.2.13", "STIG": "V-255924", "PCI-DSS": "4.2.1",
        },
    ))

    # SC.L2-3.13.11 - Employ FIPS-validated cryptography for CUI
    fips_enabled = False
    fips_path = "/proc/sys/crypto/fips_enabled"
    if file_exists(fips_path):
        try:
            with open(fips_path, "r", encoding="ascii") as f:
                fips_enabled = f.read().strip() == "1"
        except OSError:
            pass

    results.append(_r(
        cat,
        "Pass" if fips_enabled else "Warning",
        "CMMC SC.L2-3.13.11: FIPS 140-validated cryptography active",
        severity="High",
        details=f"crypto.fips_enabled = {1 if fips_enabled else 0}",
        remediation=(
            "On RHEL family: fips-mode-setup --enable && reboot. "
            "On Ubuntu: subscribe to Ubuntu Pro and ua enable fips. "
            "FIPS mode requires a fresh install or careful migration."
        ),
        cross_references={
            "CMMC": "SC.L2-3.13.11", "NIST-171": "3.13.11", "NIST": "SC-13",
            "STIG": "V-230223", "NSA": "CRYPTO-1.1",
        },
    ))

    return results


# ===========================================================================
# SI - System and Information Integrity
# ===========================================================================

def _check_si_domain(os_info) -> List[AuditResult]:
    cat = "CMMC SI - System & Information Integrity"
    results: List[AuditResult] = []

    # SI.L1-3.14.1 - Identify, report, and correct system flaws
    # Indicator: pending security updates
    pending = -1
    if os_info.is_debian_family() and command_available("apt-get"):
        rc, out, _ = run_command(["apt-get", "-s", "upgrade"], timeout=30.0)
        if rc == 0:
            pending = sum(
                1 for line in out.splitlines()
                if line.startswith("Inst ") and "-security" in line.lower()
            )
    elif os_info.is_redhat_family() and command_available("dnf"):
        rc, out, _ = run_command(
            ["dnf", "-q", "updateinfo", "list", "security"], timeout=30.0
        )
        if rc == 0:
            pending = sum(
                1 for line in out.splitlines()
                if line.strip() and not line.startswith("Last metadata")
            )

    if pending >= 0:
        results.append(_r(
            cat,
            "Pass" if pending == 0 else "Fail",
            "CMMC SI.L1-3.14.1: Security updates current",
            severity="Critical",
            details=f"Pending security updates: {pending}",
            remediation=patch_for(),
            cross_references={
                "CMMC": "SI.L1-3.14.1", "NIST-171": "3.14.1", "NIST": "SI-2",
                "CIS": "1.9", "ISO27001": "A.8.8", "PCI-DSS": "6.3.3",
                "CISA": "BOD-22-01",
            },
        ))

    # SI.L1-3.14.2 - Provide protection from malicious code
    av_indicators = {
        "ClamAV": command_available("clamscan") or file_exists("/etc/clamav/clamd.conf"),
        "Falco": command_available("falco") or file_exists("/etc/falco/falco.yaml"),
        "Wazuh/OSSEC": file_exists("/var/ossec/etc/ossec.conf"),
        "ChkRootkit": command_available("chkrootkit"),
        "RKHunter": command_available("rkhunter"),
    }
    detected = [name for name, present in av_indicators.items() if present]

    results.append(_r(
        cat,
        "Pass" if detected else "Fail",
        "CMMC SI.L1-3.14.2: Malicious-code protection deployed",
        severity="High",
        details=f"Detected: {', '.join(detected) or 'none'}",
        remediation=(
            "Install an anti-malware solution: apt-get install -y clamav clamav-daemon "
            "(Debian) or dnf install -y clamav clamav-update (RHEL)."
        ),
        cross_references={
            "CMMC": "SI.L1-3.14.2", "NIST-171": "3.14.2", "NIST": "SI-3",
            "ISO27001": "A.8.7", "PCI-DSS": "5.2.1", "HIPAA": "164.308(a)(5)(ii)(B)",
        },
    ))

    # SI.L2-3.14.6 - Monitor organizational systems for security incidents
    ids_indicators = {
        "Suricata": command_available("suricata"),
        "Snort": command_available("snort"),
        "OSSEC/Wazuh": file_exists("/var/ossec/etc/ossec.conf"),
        "Falco": command_available("falco"),
        "auditd": systemd_active("auditd.service") == "active",
    }
    detected_ids = [name for name, present in ids_indicators.items() if present]

    results.append(_r(
        cat,
        "Pass" if detected_ids else "Fail",
        "CMMC SI.L2-3.14.6: Security monitoring solution deployed",
        severity="High",
        details=f"Detected: {', '.join(detected_ids) or 'none'}",
        remediation=(
            "Deploy host-based detection (Falco, Wazuh) and ensure auditd "
            "is configured with comprehensive rules."
        ),
        cross_references={
            "CMMC": "SI.L2-3.14.6", "NIST-171": "3.14.6", "NIST": "SI-4",
            "ISO27001": "A.8.16", "PCI-DSS": "11.5.1",
        },
    ))

    # SI.L2-3.14.7 - Identify unauthorized use of organizational systems
    # File integrity monitoring
    fim_indicators = {
        "AIDE": command_available("aide") or file_exists("/etc/aide.conf"),
        "Tripwire": command_available("tripwire"),
        "OSSEC/Wazuh FIM": file_exists("/var/ossec/etc/ossec.conf"),
    }
    detected_fim = [name for name, present in fim_indicators.items() if present]

    results.append(_r(
        cat,
        "Pass" if detected_fim else "Fail",
        "CMMC SI.L2-3.14.7: File integrity monitoring deployed",
        severity="High",
        details=f"Detected FIM: {', '.join(detected_fim) or 'none'}",
        remediation=remediation_for("aide"),
        cross_references={
            "CMMC": "SI.L2-3.14.7", "NIST-171": "3.14.7", "NIST": "SI-7",
            "ISO27001": "A.8.16", "PCI-DSS": "11.5.2", "HIPAA": "164.312(c)(1)",
        },
    ))

    return results


# ===========================================================================
# DFARS 252.204-7012 SPRS Indicators
# ===========================================================================

def _check_dfars_indicators(os_info) -> List[AuditResult]:
    cat = "CMMC DFARS-252.204-7012"
    results: List[AuditResult] = []

    # DFARS requires reporting cyber incidents within 72 hours
    # Indicator: incident response capability through logging
    journal_persist = directory_exists("/var/log/journal")
    results.append(_r(
        cat,
        "Pass" if journal_persist else "Warning",
        "DFARS 7012(c): Persistent system journal for incident reconstruction",
        severity="Medium",
        details=(
            f"/var/log/journal directory exists: {journal_persist}. "
            "Without persistent journal, incident logs are lost on reboot."
        ),
        remediation=(
            "mkdir -p /var/log/journal && systemd-tmpfiles --create --prefix /var/log/journal && "
            "systemctl restart systemd-journald"
        ),
        cross_references={
            "CMMC": "DFARS-7012(c)", "NIST-171": "3.6.1", "NIST": "IR-4",
            "ISO27001": "A.8.15",
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
        results.extend(_check_ac_domain(os_info))
        results.extend(_check_au_domain(os_info))
        results.extend(_check_cm_domain(os_info))
        results.extend(_check_ia_domain(os_info))
        results.extend(_check_sc_domain(os_info))
        results.extend(_check_si_domain(os_info))
        results.extend(_check_dfars_indicators(os_info))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled exception in CMMC module")
        results.append(_r(
            "CMMC - Error", "Error",
            f"CMMC module encountered an unhandled exception: {exc!r}",
            severity="Medium", details=str(exc),
        ))

    return results



# ===========================================================================
# v3.1 EXPANSION - CMMC Comprehensive 14-Domain Coverage
# ---------------------------------------------------------------------------
# Adds domains and deeper Level 2/3 controls:
#   - AT - Awareness and Training (technical indicators)
#   - IR - Incident Response (host-applicable subset)
#   - MA - Maintenance (controlled remote, audit logging)
#   - MP - Media Protection (encryption, sanitization)
#   - PE - Physical Protection (host-applicable indicators)
#   - PS - Personnel Security (access lifecycle indicators)
#   - RA - Risk Assessment (vulnerability scanning)
#   - CA - Security Assessment (logging, monitoring)
#   - Extended AC, AU, CM, IA, SC, SI Level 2 controls
# ===========================================================================


def _check_at_domain(os_info) -> List[AuditResult]:
    """AT - Awareness and Training (technical indicators)."""
    results: List[AuditResult] = []
    cat = "CMMC - AT Awareness & Training"

    # AT.L2-3.2.2 - Banner with security policies
    issue_net = read_file_safe("/etc/issue.net")
    has_warning = (
        len(issue_net) > 100 and
        ("unauthorized" in issue_net.lower() or "warning" in issue_net.lower())
    )
    results.append(_r(
        cat, "Pass" if has_warning else "Warning",
        "AT.L2-3.2.2: Login banner provides security policy reminder",
        severity="Medium",
        details=f"/etc/issue.net length: {len(issue_net)}, has warning text: {has_warning}",
        remediation=(
            "Configure /etc/issue.net with DoD-approved warning banner including "
            "DFARS notice, monitoring statement, and unauthorized access prohibition."
        ),
        cross_references={
            "CMMC": "AT.L2-3.2.2", "NIST": "AC-8", "STIG": "V-230225",
        },
    ))

    return results


def _check_ir_domain(os_info) -> List[AuditResult]:
    """IR - Incident Response (host-applicable subset)."""
    results: List[AuditResult] = []
    cat = "CMMC - IR Incident Response"

    # IR.L2-3.6.1 - Detection capability
    detection_tools = {
        "auditd": systemd_active("auditd.service") == "active",
        "wazuh-agent": systemd_active("wazuh-agent.service") == "active",
        "ossec": file_exists("/var/ossec/etc/ossec.conf"),
        "falco": command_available("falco"),
        "fail2ban": systemd_active("fail2ban.service") == "active",
    }
    detected = [k for k, v in detection_tools.items() if v]
    results.append(_r(
        cat, "Pass" if len(detected) >= 2 else "Fail",
        f"IR.L2-3.6.1: Incident detection capability ({len(detected)} layers)",
        severity="High",
        details=f"Detection tools: {detected}",
        remediation=(
            "Deploy multiple detection layers: auditd + Wazuh + Falco. "
            "L3 requires advanced behavioral detection."
        ),
        cross_references={
            "CMMC": "IR.L2-3.6.1", "NIST": "IR-4", "ISO27001": "A.5.24",
        },
    ))

    # IR.L2-3.6.2 - Reporting capability (centralized logging)
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
        cat, "Pass" if forwarding else "Warning",
        "IR.L2-3.6.2: Logs forwarded for incident reporting/correlation",
        severity="High",
        details=f"Remote forwarding: {forwarding}",
        remediation=(
            "Configure rsyslog forwarding to SIEM in /etc/rsyslog.d/50-remote.conf"
        ),
        cross_references={
            "CMMC": "IR.L2-3.6.2", "NIST": "IR-6", "PCI-DSS": "10.5.4",
        },
    ))

    # IR.L2-3.6.3 - Test response capability (alerting)
    aliases_content = read_file_safe("/etc/aliases")
    root_aliased = bool(re.search(r"^\s*root\s*:\s*\S+@", aliases_content, re.MULTILINE))
    results.append(_r(
        cat, "Pass" if root_aliased else "Warning",
        "IR.L2-3.6.3: Root mail aliased for incident notification",
        severity="Medium",
        details=f"root: alias to external address: {root_aliased}",
        remediation=(
            "In /etc/aliases: root: incidents@example.com, then: newaliases"
        ),
        cross_references={
            "CMMC": "IR.L2-3.6.3", "NIST": "IR-6(2)",
        },
    ))

    return results


def _check_ma_domain(os_info) -> List[AuditResult]:
    """MA - Maintenance (host-side technical controls)."""
    results: List[AuditResult] = []
    cat = "CMMC - MA Maintenance"

    # MA.L2-3.7.5 - Multifactor for remote maintenance (SSH MFA)
    pam_files = ["/etc/pam.d/sshd", "/etc/pam.d/system-auth"]
    mfa_modules = ["pam_google_authenticator", "pam_yubico", "pam_oath",
                   "pam_duo", "pam_u2f", "pam_pkcs11"]
    mfa_loaded = False
    for f in pam_files:
        c = read_file_safe(f)
        for mod in mfa_modules:
            if mod + ".so" in c:
                mfa_loaded = True
                break
        if mfa_loaded:
            break

    sshd_config = read_file_safe("/etc/ssh/sshd_config")
    challenge_response = "ChallengeResponseAuthentication yes" in sshd_config

    results.append(_r(
        cat, "Pass" if mfa_loaded else "Fail",
        "MA.L2-3.7.5: Multifactor authentication for remote maintenance (SSH)",
        severity="High",
        details=(
            f"PAM MFA module loaded: {mfa_loaded}, "
            f"SSH ChallengeResponseAuthentication: {challenge_response}"
        ),
        remediation=(
            "Install PAM MFA: apt-get install -y libpam-google-authenticator. "
            "Add to /etc/pam.d/sshd: auth required pam_google_authenticator.so. "
            "In sshd_config: ChallengeResponseAuthentication yes."
        ),
        cross_references={
            "CMMC": "MA.L2-3.7.5", "NIST": "MA-4", "PCI-DSS": "8.4",
        },
    ))

    # MA.L2-3.7.4 - Maintenance tools sanitized (audit non-system commands)
    audit_rules = read_file_safe("/etc/audit/audit.rules")
    rules_d = list_directory("/etc/audit/rules.d", suffix=".rules")
    for rf in rules_d:
        audit_rules += "\n" + read_file_safe(os.path.join("/etc/audit/rules.d", rf))

    maintenance_audited = (
        "/usr/local/bin" in audit_rules or
        "perm_mod" in audit_rules
    )
    results.append(_r(
        cat, "Pass" if maintenance_audited else "Warning",
        "MA.L2-3.7.4: Maintenance command execution audited",
        severity="Medium",
        details=f"Maintenance audit rules: {maintenance_audited}",
        remediation=(
            "Add to /etc/audit/rules.d/30-maintenance.rules: "
            "-w /usr/local/bin -p x -k maintenance"
        ),
        cross_references={
            "CMMC": "MA.L2-3.7.4", "NIST": "MA-3",
        },
    ))

    return results


def _check_mp_domain(os_info) -> List[AuditResult]:
    """MP - Media Protection."""
    results: List[AuditResult] = []
    cat = "CMMC - MP Media Protection"

    # MP.L2-3.8.6 - Encrypt CUI on digital media
    luks_active = False
    if command_available("dmsetup"):
        rc, out, _ = run_command(["dmsetup", "ls", "--target=crypt"], timeout=5.0)
        if rc == 0 and out and "No devices" not in out:
            luks_active = True

    results.append(_r(
        cat, "Pass" if luks_active else "Fail",
        "MP.L2-3.8.6: Disk encryption (LUKS) for CUI protection",
        severity="High",
        details=f"LUKS-encrypted devices detected: {luks_active}",
        remediation=(
            "For new systems: install with LUKS encryption. "
            "For existing: data migration required for cryptsetup luksFormat. "
            "FIPS-validated cipher: aes-xts-plain64 with 512-bit key."
        ),
        cross_references={
            "CMMC": "MP.L2-3.8.6", "NIST": "MP-5(4)", "PCI-DSS": "3.5",
        },
    ))

    # MP.L2-3.8.3 - Sanitize media before disposal
    deletion_tools = {
        "shred": command_available("shred"),
        "wipe": command_available("wipe"),
        "scrub": command_available("scrub"),
        "blkdiscard": command_available("blkdiscard"),
        "cryptsetup": command_available("cryptsetup"),
    }
    detected = [k for k, v in deletion_tools.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Warning",
        f"MP.L2-3.8.3: Media sanitization tools available ({len(detected)})",
        severity="Medium",
        details=f"Tools: {detected}",
        remediation=(
            "shred for files, blkdiscard for SSDs, cryptsetup erase for LUKS. "
            "Document procedure aligned with NIST SP 800-88."
        ),
        cross_references={
            "CMMC": "MP.L2-3.8.3", "NIST": "MP-6", "ISO27001": "A.7.14",
        },
    ))

    # MP.L2-3.8.7 - Control removable media use (USBGuard)
    usbguard_active = systemd_active("usbguard.service") == "active"
    results.append(_r(
        cat, "Pass" if usbguard_active else "Warning",
        "MP.L2-3.8.7: USB device control via USBGuard",
        severity="High",
        details=f"USBGuard active: {usbguard_active}",
        remediation=remediation_for("usbguard"),
        cross_references={
            "CMMC": "MP.L2-3.8.7", "NIST": "MP-7", "PCI-DSS": "9.5",
        },
    ))

    return results


def _check_pe_domain(os_info) -> List[AuditResult]:
    """PE - Physical Protection (host-side indicators)."""
    results: List[AuditResult] = []
    cat = "CMMC - PE Physical Protection"

    # PE.L2-3.10.6 - Workstation lock (screen lock tooling)
    lock_tools = (
        command_available("vlock") or
        command_available("xscreensaver") or
        command_available("gnome-screensaver") or
        command_available("i3lock")
    )
    results.append(_r(
        cat, "Info",
        f"PE.L2-3.10.6: Screen lock tooling available: {lock_tools}",
        severity="Informational",
        details=(
            f"Lock tooling detected: {lock_tools}. "
            "Headless servers don't require this control."
        ),
        cross_references={
            "CMMC": "PE.L2-3.10.6", "NIST": "AC-11",
        },
    ))

    return results


def _check_ps_domain(os_info) -> List[AuditResult]:
    """PS - Personnel Security (access lifecycle technical indicators)."""
    results: List[AuditResult] = []
    cat = "CMMC - PS Personnel Security"

    # PS.L2-3.9.2 - Account lifecycle: locked accounts present (terminated personnel)
    shadow = read_file_safe("/etc/shadow")
    locked_count = 0
    active_count = 0
    if shadow:
        for line in shadow.splitlines():
            fields = line.split(":")
            if len(fields) < 2:
                continue
            pwd = fields[1]
            if pwd.startswith("!") or pwd.startswith("*"):
                locked_count += 1
            elif pwd and pwd != "x":
                active_count += 1

    results.append(_r(
        cat, "Info",
        f"PS.L2-3.9.2: Account state inventory ({active_count} active, {locked_count} locked)",
        severity="Informational",
        details=(
            f"Active password accounts: {active_count}, "
            f"Locked: {locked_count}"
        ),
        remediation=(
            "Verify locked accounts correspond to terminated personnel. "
            "Document procedure: passwd -l <user> on termination, "
            "userdel -r <user> after retention period."
        ),
        cross_references={
            "CMMC": "PS.L2-3.9.2", "NIST": "PS-4",
        },
    ))

    # Inactive account auto-disable
    useradd_defaults = read_file_safe("/etc/default/useradd")
    inactive_match = re.search(r"^\s*INACTIVE\s*=\s*(-?\d+)", useradd_defaults, re.MULTILINE)
    inactive = int(inactive_match.group(1)) if inactive_match else -1
    inactive_ok = 0 < inactive <= 35

    results.append(_r(
        cat, "Pass" if inactive_ok else "Warning",
        "PS.L2-3.9.2: Inactive accounts auto-disabled (<=35 days)",
        severity="Medium",
        details=f"INACTIVE = {inactive}",
        remediation=(
            "Set in /etc/default/useradd: INACTIVE=35"
        ),
        cross_references={
            "CMMC": "PS.L2-3.9.2", "NIST": "AC-2(3)", "STIG": "V-230372",
        },
    ))

    return results


def _check_ra_domain(os_info) -> List[AuditResult]:
    """RA - Risk Assessment."""
    results: List[AuditResult] = []
    cat = "CMMC - RA Risk Assessment"

    # RA.L2-3.11.1 - Periodic risk assessment via vulnerability scanner
    scanners = {
        "openscap": command_available("oscap"),
        "lynis": command_available("lynis"),
        "openvas": command_available("openvas-cli"),
        "nessus": file_exists("/opt/nessus_agent/sbin/nessuscli"),
        "qualys": file_exists("/opt/qualys/cloud-agent/bin/qualys-cloud-agent.sh"),
    }
    detected = [k for k, v in scanners.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Fail",
        f"RA.L2-3.11.1: Vulnerability scanner deployed ({len(detected)})",
        severity="High",
        details=f"Scanners: {detected}",
        remediation=(
            "Install OpenSCAP: dnf install -y openscap-scanner scap-security-guide. "
            "Run: oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cui "
            "/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml"
        ),
        cross_references={
            "CMMC": "RA.L2-3.11.1", "NIST": "RA-5", "PCI-DSS": "11.3.1",
        },
    ))

    # RA.L2-3.11.2 - Vulnerability remediation (auto-patch)
    auto_patch = (
        systemd_active("unattended-upgrades.service") == "active" or
        systemd_active("dnf-automatic-install.timer") == "active"
    )
    results.append(_r(
        cat, "Pass" if auto_patch else "Warning",
        "RA.L2-3.11.2: Automated vulnerability remediation (auto-patch)",
        severity="High",
        details=f"Auto-patch active: {auto_patch}",
        remediation=(
            "Debian: apt-get install -y unattended-upgrades. "
            "RHEL: dnf install -y dnf-automatic && "
            "systemctl enable --now dnf-automatic-install.timer."
        ),
        cross_references={
            "CMMC": "RA.L2-3.11.2", "NIST": "SI-2(5)", "PCI-DSS": "6.3.3",
        },
    ))

    return results


def _check_ca_domain(os_info) -> List[AuditResult]:
    """CA - Security Assessment."""
    results: List[AuditResult] = []
    cat = "CMMC - CA Security Assessment"

    # CA.L2-3.12.1 - Periodic assessment (auditing infrastructure)
    auditd_active = systemd_active("auditd.service") == "active"
    results.append(_r(
        cat, "Pass" if auditd_active else "Fail",
        "CA.L2-3.12.1: Audit infrastructure active for assessment evidence",
        severity="High",
        details=f"auditd state: {systemd_active('auditd.service')}",
        remediation=remediation_for("auditd"),
        cross_references={
            "CMMC": "CA.L2-3.12.1", "NIST": "AU-2", "ISO27001": "A.8.15",
        },
    ))

    # CA.L2-3.12.3 - Continuous monitoring
    monitoring_active = (
        command_available("aide") or
        file_exists("/var/ossec/etc/ossec.conf") or
        command_available("falco") or
        command_available("lynis")
    )
    results.append(_r(
        cat, "Pass" if monitoring_active else "Warning",
        "CA.L2-3.12.3: Continuous monitoring tooling deployed",
        severity="High",
        details=f"Monitoring tooling present: {monitoring_active}",
        remediation=(
            "Deploy continuous monitoring: AIDE (FIM) + Wazuh (HIDS) + "
            "Lynis (periodic hardening assessment)."
        ),
        cross_references={
            "CMMC": "CA.L2-3.12.3", "NIST": "CA-7", "PCI-DSS": "11.5",
        },
    ))

    return results


def _check_l2_extended_ac(os_info) -> List[AuditResult]:
    """AC domain L2 extended controls."""
    results: List[AuditResult] = []
    cat = "CMMC - AC Extended L2"

    # AC.L2-3.1.5 - Least privilege (sudoers analysis)
    sudoers = read_file_safe("/etc/sudoers")
    sudoers_d_files = list_directory("/etc/sudoers.d")
    for f in sudoers_d_files:
        if f != "README":
            sudoers += "\n" + read_file_safe(os.path.join("/etc/sudoers.d", f))

    # Check for ALL=NOPASSWD without specific commands (excessive privilege)
    nopasswd_all = "NOPASSWD: ALL" in sudoers or "NOPASSWD:ALL" in sudoers
    results.append(_r(
        cat, "Warning" if nopasswd_all else "Pass",
        "AC.L2-3.1.5: Least privilege - sudo NOPASSWD: ALL constructs minimized",
        severity="High",
        details=f"NOPASSWD: ALL detected: {nopasswd_all}",
        remediation=(
            "Replace NOPASSWD: ALL with specific command paths. "
            "Example: user ALL=(root) NOPASSWD: /usr/sbin/service apache2 restart"
        ),
        cross_references={
            "CMMC": "AC.L2-3.1.5", "NIST": "AC-6", "ISO27001": "A.8.2",
        },
    ))

    # AC.L2-3.1.10 - Session lock
    sshd_config = read_file_safe("/etc/ssh/sshd_config")
    cai_match = re.search(
        r"^\s*ClientAliveInterval\s+(\d+)", sshd_config, re.MULTILINE
    )
    cai = int(cai_match.group(1)) if cai_match else 0
    cai_ok = 0 < cai <= 900
    results.append(_r(
        cat, "Pass" if cai_ok else "Fail",
        "AC.L2-3.1.10: SSH session timeout enforces session lock",
        severity="Medium",
        details=f"ClientAliveInterval: {cai}",
        remediation=(
            "/etc/ssh/sshd_config: ClientAliveInterval 900; ClientAliveCountMax 0"
        ),
        cross_references={
            "CMMC": "AC.L2-3.1.10", "NIST": "AC-12", "STIG": "V-230244",
        },
    ))

    # AC.L2-3.1.11 - Session termination idle
    bash_logout = read_file_safe("/etc/profile.d/tmout.sh")
    profile = read_file_safe("/etc/profile")
    tmout_set = (
        "TMOUT=" in bash_logout or
        re.search(r"^\s*(?:export\s+)?TMOUT\s*=\s*\d+", profile, re.MULTILINE) is not None
    )
    results.append(_r(
        cat, "Pass" if tmout_set else "Warning",
        "AC.L2-3.1.11: Shell idle timeout (TMOUT) configured",
        severity="Medium",
        details=f"TMOUT configured in /etc/profile or /etc/profile.d: {tmout_set}",
        remediation=(
            "Create /etc/profile.d/tmout.sh: "
            "echo 'TMOUT=900' > /etc/profile.d/tmout.sh && "
            "echo 'readonly TMOUT' >> /etc/profile.d/tmout.sh"
        ),
        cross_references={
            "CMMC": "AC.L2-3.1.11", "NIST": "AC-12", "CIS": "5.4.5",
        },
    ))

    return results


def _check_l2_extended_au(os_info) -> List[AuditResult]:
    """AU domain L2 extended."""
    results: List[AuditResult] = []
    cat = "CMMC - AU Extended L2"

    # AU.L2-3.3.4 - Audit log alerting
    audit_d = list_directory("/etc/audit/rules.d", suffix=".rules")
    audit_rules_text = ""
    for f in audit_d:
        audit_rules_text += "\n" + read_file_safe(os.path.join("/etc/audit/rules.d", f))

    # Look for -k tags indicating organized rule schema
    has_keys = audit_rules_text.count("-k ") >= 5
    results.append(_r(
        cat, "Pass" if has_keys else "Warning",
        "AU.L2-3.3.4: Audit rules use key tagging for alerting/correlation",
        severity="Medium",
        details=f"Rules with -k tags: {audit_rules_text.count('-k ')}",
        remediation=(
            "Tag audit rules with -k <category>. Example: "
            "-w /etc/sudoers -p wa -k privileged_config. "
            "SIEM correlates by key."
        ),
        cross_references={
            "CMMC": "AU.L2-3.3.4", "NIST": "AU-2", "STIG": "V-230423",
        },
    ))

    # AU.L2-3.3.6 - Audit reduction and report generation
    aureport = command_available("aureport")
    ausearch = command_available("ausearch")
    results.append(_r(
        cat, "Pass" if aureport and ausearch else "Fail",
        "AU.L2-3.3.6: Audit analysis tools (aureport/ausearch) available",
        severity="Medium",
        details=f"aureport: {aureport}, ausearch: {ausearch}",
        remediation=(
            "Install audit-userspace: dnf install -y audit (RHEL) or "
            "apt-get install -y auditd"
        ),
        cross_references={
            "CMMC": "AU.L2-3.3.6", "NIST": "AU-7",
        },
    ))

    # AU.L2-3.3.8 - Protect audit information
    audit_log_path = "/var/log/audit/audit.log"
    if file_exists(audit_log_path):
        mode = file_mode(audit_log_path)
        log_protected = mode is not None and mode <= 0o600
        results.append(_r(
            cat, "Pass" if log_protected else "Fail",
            f"AU.L2-3.3.8: Audit log file permissions <= 600 (current: {oct(mode) if mode else 'unknown'})",
            severity="High",
            details=f"audit.log mode: {oct(mode) if mode else 'unknown'}",
            remediation=(
                "chmod 600 /var/log/audit/audit.log; "
                "chown root:root /var/log/audit/audit.log"
            ),
            cross_references={
                "CMMC": "AU.L2-3.3.8", "NIST": "AU-9", "STIG": "V-230469",
            },
        ))

    return results


def _check_l2_extended_si(os_info) -> List[AuditResult]:
    """SI domain L2 extended."""
    results: List[AuditResult] = []
    cat = "CMMC - SI Extended L2"

    # SI.L2-3.14.1 - Identify, report, and correct flaws
    auto_patch = (
        systemd_active("unattended-upgrades.service") == "active" or
        systemd_active("dnf-automatic-install.timer") == "active"
    )
    fim_active = command_available("aide") or file_exists("/var/ossec/etc/ossec.conf")
    flaw_correction = auto_patch and fim_active
    results.append(_r(
        cat, "Pass" if flaw_correction else "Warning",
        f"SI.L2-3.14.1: Flaw identification + correction (auto-patch={auto_patch}, FIM={fim_active})",
        severity="High",
        details=f"Auto-patch: {auto_patch}, FIM: {fim_active}",
        remediation=remediation_for("aide"),
        cross_references={
            "CMMC": "SI.L2-3.14.1", "NIST": "SI-2", "PCI-DSS": "6.3.3",
        },
    ))

    # SI.L2-3.14.6 - Monitor inbound communications
    ids_present = (
        command_available("suricata") or
        command_available("snort") or
        file_exists("/var/ossec/etc/ossec.conf") or
        command_available("falco")
    )
    results.append(_r(
        cat, "Pass" if ids_present else "Fail",
        "SI.L2-3.14.6: Network/system monitoring for inbound traffic",
        severity="High",
        details=f"IDS/HIDS detected: {ids_present}",
        remediation=(
            "Install Wazuh: HIDS+SIEM. Or Suricata for network IDS: "
            "apt-get install -y suricata && systemctl enable --now suricata."
        ),
        cross_references={
            "CMMC": "SI.L2-3.14.6", "NIST": "SI-4(4)", "PCI-DSS": "11.5",
        },
    ))

    return results


# Save reference to original run_checks
_original_run_checks_cmmc = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the expanded CMMC module.

    Combines baseline (AC/AU/CM/IA/SC/SI core) with v3.1 expansion adding
    AT, IR, MA, MP, PE, PS, RA, CA domains plus L2 extended depth in
    AC, AU, SI.
    """
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_cmmc(shared_data)

    os_info = shared_data.get("v3_os_info")
    if os_info is None:
        os_info = os_detection.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        results.extend(_check_at_domain(os_info))
        results.extend(_check_ir_domain(os_info))
        results.extend(_check_ma_domain(os_info))
        results.extend(_check_mp_domain(os_info))
        results.extend(_check_pe_domain(os_info))
        results.extend(_check_ps_domain(os_info))
        results.extend(_check_ra_domain(os_info))
        results.extend(_check_ca_domain(os_info))
        results.extend(_check_l2_extended_ac(os_info))
        results.extend(_check_l2_extended_au(os_info))
        results.extend(_check_l2_extended_si(os_info))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled exception in CMMC v3.1 expansion")
        results.append(_r(
            "CMMC - Error", "Error",
            f"CMMC v3.1 expansion exception: {exc!r}",
            severity="Medium", details=str(exc),
        ))

    return results

# ===========================================================================
# v3.2 EXPANSION - CMMC Level 3 (NIST SP 800-172) + L2 Technical Depth
# ---------------------------------------------------------------------------
# Adds:
#   - L3 advanced practices (NIST SP 800-172): adversarial protection,
#     threat hunting, dual authorization, system isolation
#   - CM domain technical depth (configuration baselines, change ctrl)
#   - IA domain depth (cryptographic auth, identifier mgmt, replay
#     resistance, privileged separation)
#   - SC domain depth (cryptographic key establishment, transmission
#     confidentiality, network architecture, mobile code)
#   - SI domain depth (flaw remediation, malicious code protection,
#     spam, security alerts, info handling)
#   - SR (Supply Chain Risk) practices (DFARS 252.204-7019/7020)
# ===========================================================================


def _check_l3_adversarial_protection(os_info) -> List[AuditResult]:
    """CMMC L3 - Adversarial protection (NIST SP 800-172 advanced practices)."""
    results: List[AuditResult] = []
    cat = "CMMC L3 - Adversarial Protection"

    # 03.11.02e - Threat hunting capability
    threat_hunt_tools = {
        "wazuh-agent": file_exists("/var/ossec/etc/ossec.conf"),
        "auditbeat": file_exists("/etc/auditbeat/auditbeat.yml"),
        "filebeat": file_exists("/etc/filebeat/filebeat.yml"),
        "osquery": command_available("osqueryi") or file_exists("/etc/osquery/osquery.conf"),
        "sysmon-linux": file_exists("/opt/sysmon/sysmonconfig.xml"),
        "falco": command_available("falco"),
    }
    detected = [k for k, v in threat_hunt_tools.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Fail",
        f"L3 RA.L3-3.11.2e: Threat hunting telemetry deployed ({len(detected)} tools)",
        severity="High",
        details=f"Detected tools: {detected or 'none'}",
        remediation=(
            "Deploy threat-hunting capable telemetry: osquery for endpoint "
            "data; Wazuh for HIDS; Falco for runtime; auditbeat/filebeat "
            "for centralization. CMMC L3 requires proactive hunting capability."
        ),
        cross_references={
            "CMMC": "RA.L3-3.11.2e", "NIST-800-172": "3.11.2e",
            "NIST": "RA-3(3)", "ISO27001": "A.5.7",
        },
    ))

    # 03.13.04e - Resource isolation through hypervisor/container
    isolation = {
        "namespaces": file_exists("/proc/self/ns/user"),
        "cgroups-v2": directory_exists("/sys/fs/cgroup") and file_exists(
            "/sys/fs/cgroup/cgroup.controllers"
        ),
        "podman": command_available("podman"),
        "docker": command_available("docker"),
        "lxc": command_available("lxc-create"),
        "firejail": command_available("firejail"),
        "bubblewrap": command_available("bwrap"),
    }
    detected_iso = [k for k, v in isolation.items() if v]
    results.append(_r(
        cat, "Pass" if len(detected_iso) >= 3 else "Warning",
        f"L3 SC.L3-3.13.4e: Process/resource isolation capabilities ({len(detected_iso)})",
        severity="Medium",
        details=f"Isolation primitives: {detected_iso}",
        remediation=(
            "Use containers (podman) or firejail for application sandboxing. "
            "Verify cgroups v2 enabled in kernel. NIST 800-172 calls for "
            "isolated execution environments for high-value assets."
        ),
        cross_references={
            "CMMC": "SC.L3-3.13.4e", "NIST-800-172": "3.13.4e",
            "NIST": "SC-39", "ISO27001": "A.8.31",
        },
    ))

    # 03.14.06e - Forensic investigative tools
    forensic_tools = {
        "memory-acq": command_available("avml") or command_available("lime"),
        "disk-image": command_available("dd") and command_available("dcfldd"),
        "network-cap": command_available("tcpdump") or command_available("tshark"),
        "volatility": command_available("vol.py") or command_available("volatility"),
        "sleuthkit": command_available("fls") or command_available("mmls"),
    }
    detected_fx = [k for k, v in forensic_tools.items() if v]
    results.append(_r(
        cat, "Pass" if len(detected_fx) >= 2 else "Warning",
        f"L3 IR.L3-3.6.4e: Forensic acquisition capability ({len(detected_fx)} tools)",
        severity="Medium",
        details=f"Detected: {detected_fx}",
        remediation=(
            "Install forensic toolkit: apt-get install -y tcpdump sleuthkit "
            "volatility3 dcfldd. Required for incident-response evidence chain."
        ),
        cross_references={
            "CMMC": "IR.L3-3.6.4e", "NIST-800-172": "3.6.4e",
            "NIST": "IR-4(11)",
        },
    ))

    return results


def _check_l3_dual_authorization(os_info) -> List[AuditResult]:
    """CMMC L3 - Dual authorization for critical operations."""
    results: List[AuditResult] = []
    cat = "CMMC L3 - Dual Authorization"

    # 03.01.07e - Privileged action review (sudo logging adequate)
    sudoers = read_file_safe("/etc/sudoers")
    sudoers_d = list_directory("/etc/sudoers.d")
    combined = sudoers
    for f in sudoers_d:
        if f != "README":
            combined += "\n" + read_file_safe(os.path.join("/etc/sudoers.d", f))

    has_log_input = "log_input" in combined.lower()
    has_log_output = "log_output" in combined.lower()
    has_iolog = has_log_input and has_log_output

    results.append(_r(
        cat, "Pass" if has_iolog else "Fail",
        "L3 AC.L3-3.1.7e: Privileged session I/O logging configured",
        severity="High",
        details=(
            f"sudo log_input: {has_log_input}, log_output: {has_log_output}. "
            "I/O logging captures full command sessions for review."
        ),
        remediation=(
            "Add to /etc/sudoers (via visudo): "
            "Defaults  log_input,log_output,iolog_dir=/var/log/sudo-io"
        ),
        cross_references={
            "CMMC": "AC.L3-3.1.7e", "NIST-800-172": "3.1.7e",
            "NIST": "AU-2", "STIG": "V-230367",
        },
    ))

    # 03.01.08e - Privileged separation: SSH cert authority indicators
    sshd_config = read_file_safe("/etc/ssh/sshd_config")
    trusted_user_ca = "TrustedUserCAKeys" in sshd_config
    results.append(_r(
        cat, "Info",
        f"L3 IA.L3-3.5.4e: SSH certificate authority configured: {trusted_user_ca}",
        severity="Informational",
        details=(
            f"TrustedUserCAKeys directive present: {trusted_user_ca}. "
            "Cert-based auth supports short-lived credentials and PKI rotation."
        ),
        remediation=(
            "Configure SSH CA: ssh-keygen -t ed25519 -f /etc/ssh/ca; "
            "add 'TrustedUserCAKeys /etc/ssh/ca.pub' to sshd_config. "
            "Issue short-lived certs via Vault, Smallstep, or Teleport."
        ),
        cross_references={
            "CMMC": "IA.L3-3.5.4e", "NIST-800-172": "3.5.4e",
            "NIST": "IA-5(2)",
        },
    ))

    return results


def _check_cm_l2_v32(os_info) -> List[AuditResult]:
    """CMMC L2 - CM domain extended technical practices (v3.2)."""
    results: List[AuditResult] = []
    cat = "CMMC - CM Extended L2 v3.2"

    # 03.04.01 - Baseline configuration documentation indicators
    cm_indicators = {
        "ansible": directory_exists("/etc/ansible") or command_available("ansible"),
        "puppet": file_exists("/etc/puppetlabs/puppet/puppet.conf"),
        "salt": file_exists("/etc/salt/minion"),
        "chef": command_available("chef-client"),
        "etckeeper": directory_exists("/etc/.git") or directory_exists("/etc/.hg"),
    }
    detected = [k for k, v in cm_indicators.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Warning",
        f"CM.L2-3.4.1: Configuration baseline tooling ({len(detected)} detected)",
        severity="High",
        details=f"Detected: {detected or 'none'}",
        remediation=(
            "Deploy configuration management (Ansible recommended for "
            "agentless deployment). Track /etc with etckeeper for change "
            "history: apt-get install -y etckeeper && etckeeper init"
        ),
        cross_references={
            "CMMC": "CM.L2-3.4.1", "NIST-800-171": "3.4.1",
            "NIST": "CM-2", "ISO27001": "A.8.9",
        },
    ))

    # 03.04.02 - Security configuration settings
    sysctls_required = [
        ("net.ipv4.conf.all.rp_filter", "1"),
        ("net.ipv4.conf.all.send_redirects", "0"),
        ("net.ipv4.conf.all.accept_redirects", "0"),
        ("net.ipv4.tcp_syncookies", "1"),
        ("kernel.dmesg_restrict", "1"),
        ("kernel.kptr_restrict", "2"),
    ]
    misconfigured = []
    for key, expected in sysctls_required:
        actual = read_sysctl(key)
        if actual != expected:
            misconfigured.append(f"{key}={actual or 'unset'}")

    results.append(_r(
        cat, "Pass" if not misconfigured else "Fail",
        f"CM.L2-3.4.2: Security configuration baseline applied ({len(misconfigured)} issues)",
        severity="High",
        details=(
            f"Misconfigured kernel parameters: {misconfigured[:5]}"
            if misconfigured else "All required sysctls correctly set"
        ),
        remediation=(
            "Apply CIS hardening profile via Ansible/Puppet, or manually: "
            "echo 'kernel.dmesg_restrict = 1' >> /etc/sysctl.d/99-hardening.conf; "
            "sysctl --system"
        ),
        cross_references={
            "CMMC": "CM.L2-3.4.2", "NIST-800-171": "3.4.2",
            "NIST": "CM-6", "CIS": "1.1-1.5",
        },
    ))

    # 03.04.06 - Least functionality (services minimization)
    rc, out, _ = run_command(
        ["systemctl", "list-unit-files", "--type=service",
         "--state=enabled", "--no-legend", "--no-pager"], timeout=10.0
    )
    enabled_count = 0
    if rc == 0 and out:
        enabled_count = sum(1 for line in out.splitlines() if line.strip())

    results.append(_r(
        cat, "Pass" if enabled_count <= 60 else "Info",
        f"CM.L2-3.4.6: Enabled services count: {enabled_count}",
        severity="Medium",
        details=(
            f"Enabled systemd services: {enabled_count}. "
            "Higher counts may indicate unnecessary services."
        ),
        remediation=(
            "Review enabled services: systemctl list-unit-files --state=enabled. "
            "Disable unneeded: systemctl disable --now <unit>"
        ),
        cross_references={
            "CMMC": "CM.L2-3.4.6", "NIST-800-171": "3.4.6",
            "NIST": "CM-7", "CIS": "2",
        },
    ))

    # 03.04.07 - Software application allowlisting
    allowlist_tools = {
        "fapolicyd": systemd_active("fapolicyd.service") == "active",
        "selinux-policy": file_exists("/sys/fs/selinux/enforce"),
        "apparmor-enforce": (
            systemd_active("apparmor.service") == "active" or
            command_available("aa-status")
        ),
    }
    detected_aw = [k for k, v in allowlist_tools.items() if v]
    results.append(_r(
        cat, "Pass" if detected_aw else "Warning",
        f"CM.L2-3.4.7: Application execution control ({len(detected_aw)} mechanisms)",
        severity="High",
        details=f"Active: {detected_aw}",
        remediation=(
            "Enable fapolicyd (RHEL family): dnf install -y fapolicyd && "
            "systemctl enable --now fapolicyd. Or rely on SELinux/AppArmor "
            "policies covering critical applications."
        ),
        cross_references={
            "CMMC": "CM.L2-3.4.7", "NIST-800-171": "3.4.7",
            "NIST": "CM-7(5)", "ACSC": "E8.1",
        },
    ))

    # 03.04.09 - User-installed software restrictions
    sudoers_combined = read_file_safe("/etc/sudoers")
    for f in list_directory("/etc/sudoers.d"):
        if f != "README":
            sudoers_combined += "\n" + read_file_safe(os.path.join("/etc/sudoers.d", f))
    has_unrestricted_all = bool(re.search(
        r"^\s*[^#]\S+\s+ALL\s*=\s*\(\s*ALL\s*(:\s*ALL\s*)?\)\s*ALL\s*$",
        sudoers_combined,
        re.MULTILINE
    ))
    results.append(_r(
        cat, "Info" if has_unrestricted_all else "Pass",
        f"CM.L2-3.4.9: Unrestricted ALL=(ALL) ALL sudo entries: {has_unrestricted_all}",
        severity="Medium",
        details=(
            f"Wildcard sudo entries detected: {has_unrestricted_all}. "
            "Per-command sudo specs are stricter than ALL=(ALL) ALL."
        ),
        remediation=(
            "Replace generic ALL=(ALL) ALL with specific allowed commands "
            "where possible: alice ALL=(ALL) /usr/bin/systemctl status *"
        ),
        cross_references={
            "CMMC": "CM.L2-3.4.9", "NIST-800-171": "3.4.9",
            "NIST": "CM-11",
        },
    ))

    return results


def _check_ia_l2_v32(os_info) -> List[AuditResult]:
    """CMMC L2 - IA domain extended (v3.2)."""
    results: List[AuditResult] = []
    cat = "CMMC - IA Extended L2 v3.2"

    # 03.05.04 - Replay-resistant authentication
    sshd_config = read_file_safe("/etc/ssh/sshd_config")
    proto_match = re.search(r"^\s*Protocol\s+(\S+)", sshd_config, re.MULTILINE)
    proto = proto_match.group(1) if proto_match else "2"
    proto_ok = proto == "2"
    results.append(_r(
        cat, "Pass" if proto_ok else "Fail",
        f"IA.L2-3.5.4: SSH protocol version 2 (replay-resistant)",
        severity="High",
        details=f"SSH Protocol: {proto}",
        remediation=(
            "Modern OpenSSH uses Protocol 2 by default. If explicitly set, "
            "ensure 'Protocol 2' in sshd_config."
        ),
        cross_references={
            "CMMC": "IA.L2-3.5.4", "NIST-800-171": "3.5.4",
            "NIST": "IA-2(8)",
        },
    ))

    # 03.05.07 - Identifier management (password expiration <=90 days)
    login_defs = read_file_safe("/etc/login.defs")
    pass_max_match = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", login_defs, re.MULTILINE)
    pass_max = int(pass_max_match.group(1)) if pass_max_match else 99999
    pass_max_ok = 0 < pass_max <= 90
    results.append(_r(
        cat, "Pass" if pass_max_ok else "Fail",
        f"IA.L2-3.5.7: Password maximum age <= 90 days",
        severity="Medium",
        details=f"PASS_MAX_DAYS = {pass_max}",
        remediation=(
            "In /etc/login.defs: PASS_MAX_DAYS 90. "
            "Apply to existing users: chage --maxdays 90 <user>"
        ),
        cross_references={
            "CMMC": "IA.L2-3.5.7", "NIST-800-171": "3.5.7",
            "NIST": "IA-5(1)(d)", "STIG": "V-230367",
        },
    ))

    # 03.05.08 - Password reuse prohibition
    pwhistory_modules = {
        "/etc/pam.d/system-auth": False,
        "/etc/pam.d/common-password": False,
        "/etc/pam.d/password-auth": False,
    }
    remember_count = 0
    for path in pwhistory_modules:
        c = read_file_safe(path)
        if "pam_pwhistory" in c or "remember=" in c:
            pwhistory_modules[path] = True
            m = re.search(r"remember\s*=\s*(\d+)", c)
            if m:
                remember_count = max(remember_count, int(m.group(1)))

    has_pwhistory = any(pwhistory_modules.values())
    pwhistory_ok = has_pwhistory and remember_count >= 5
    results.append(_r(
        cat, "Pass" if pwhistory_ok else "Fail",
        f"IA.L2-3.5.8: Password reuse prohibited (remember >= 5)",
        severity="Medium",
        details=f"pam_pwhistory configured: {has_pwhistory}, remember={remember_count}",
        remediation=(
            "Add to /etc/pam.d/system-auth (RHEL) or /etc/pam.d/common-password "
            "(Debian): password required pam_pwhistory.so remember=24"
        ),
        cross_references={
            "CMMC": "IA.L2-3.5.8", "NIST-800-171": "3.5.8",
            "NIST": "IA-5(1)(e)", "CIS": "5.4.3",
        },
    ))

    # 03.05.10 - Cryptographically protected passwords
    encrypt_method_match = re.search(
        r"^\s*ENCRYPT_METHOD\s+(\S+)", login_defs, re.MULTILINE
    )
    method = encrypt_method_match.group(1).upper() if encrypt_method_match else ""
    strong_methods = {"SHA512", "YESCRYPT"}
    method_ok = method in strong_methods
    results.append(_r(
        cat, "Pass" if method_ok else "Fail",
        f"IA.L2-3.5.10: Strong password hash algorithm in use",
        severity="High",
        details=f"ENCRYPT_METHOD = {method or 'unset (default likely SHA512)'}",
        remediation=(
            "In /etc/login.defs: ENCRYPT_METHOD SHA512 (or YESCRYPT)."
        ),
        cross_references={
            "CMMC": "IA.L2-3.5.10", "NIST-800-171": "3.5.10",
            "NIST": "IA-5(1)(c)", "PCI-DSS": "8.3.2",
        },
    ))

    # 03.05.11 - Obscure feedback
    sudoers_combined2 = read_file_safe("/etc/sudoers")
    for f in list_directory("/etc/sudoers.d"):
        if f != "README":
            sudoers_combined2 += "\n" + read_file_safe(
                os.path.join("/etc/sudoers.d", f)
            )
    pwfeedback_match = re.search(
        r"^\s*Defaults\s+!?pwfeedback", sudoers_combined2, re.MULTILINE
    )
    pwfeedback_disabled = (
        not pwfeedback_match or
        "!pwfeedback" in sudoers_combined2
    )
    results.append(_r(
        cat, "Pass" if pwfeedback_disabled else "Fail",
        f"IA.L2-3.5.11: sudo password feedback disabled (obscured)",
        severity="Medium",
        details=f"Defaults pwfeedback enabled: {not pwfeedback_disabled}",
        remediation=(
            "Ensure /etc/sudoers does NOT contain 'Defaults pwfeedback'. "
            "If present, remove or change to 'Defaults !pwfeedback'."
        ),
        cross_references={
            "CMMC": "IA.L2-3.5.11", "NIST-800-171": "3.5.11",
            "NIST": "IA-6", "STIG": "V-230381",
        },
    ))

    return results


def _check_sc_l2_v32(os_info) -> List[AuditResult]:
    """CMMC L2 - SC domain extended (v3.2)."""
    results: List[AuditResult] = []
    cat = "CMMC - SC Extended L2 v3.2"

    # 03.13.01 - Boundary protection (firewall active)
    fw_active = (
        systemd_active("firewalld.service") == "active" or
        systemd_active("ufw.service") == "active" or
        systemd_active("nftables.service") == "active" or
        systemd_active("iptables.service") == "active"
    )
    results.append(_r(
        cat, "Pass" if fw_active else "Fail",
        "SC.L2-3.13.1: Boundary protection (firewall active)",
        severity="High",
        details=f"Firewall service active: {fw_active}",
        remediation=(
            "Enable firewalld (RHEL): systemctl enable --now firewalld. "
            "Or ufw (Debian/Ubuntu): ufw enable."
        ),
        cross_references={
            "CMMC": "SC.L2-3.13.1", "NIST-800-171": "3.13.1",
            "NIST": "SC-7",
        },
    ))

    # 03.13.06 - Default deny network
    iptables_default = ""
    if command_available("iptables"):
        rc, out, _ = run_command(["iptables", "-S", "INPUT"], timeout=3.0)
        if rc == 0:
            for line in out.splitlines():
                if line.startswith("-P INPUT"):
                    iptables_default = line.split()[-1]
                    break
    results.append(_r(
        cat, "Pass" if iptables_default == "DROP" else "Info",
        f"SC.L2-3.13.6: INPUT chain default policy: {iptables_default or 'unknown'}",
        severity="Medium",
        details=f"iptables INPUT default: {iptables_default}",
        remediation=(
            "iptables -P INPUT DROP (after configuring explicit accept rules). "
            "firewalld/nftables/ufw default-deny by default."
        ),
        cross_references={
            "CMMC": "SC.L2-3.13.6", "NIST-800-171": "3.13.6",
            "NIST": "SC-7(11)",
        },
    ))

    # 03.13.08 - Cryptographic mechanisms in transit
    sshd_config = read_file_safe("/etc/ssh/sshd_config")
    has_ciphers = "Ciphers " in sshd_config
    has_macs = "MACs " in sshd_config
    has_kex = "KexAlgorithms " in sshd_config
    crypto_explicit = has_ciphers and has_macs and has_kex
    results.append(_r(
        cat, "Pass" if crypto_explicit else "Warning",
        f"SC.L2-3.13.8: SSH crypto algorithms explicitly configured",
        severity="High",
        details=(
            f"Ciphers set: {has_ciphers}, MACs set: {has_macs}, "
            f"KexAlgorithms set: {has_kex}"
        ),
        remediation=(
            "In sshd_config, explicitly set: "
            "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com; "
            "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com; "
            "KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256"
        ),
        cross_references={
            "CMMC": "SC.L2-3.13.8", "NIST-800-171": "3.13.8",
            "NIST": "SC-13", "STIG": "V-230252",
        },
    ))

    # 03.13.10 - Cryptographic key establishment
    if file_exists("/etc/crypto-policies/config"):
        policy = read_file_safe("/etc/crypto-policies/config").strip()
        results.append(_r(
            cat, "Pass" if policy in ("FUTURE", "FIPS") else (
                "Info" if policy == "DEFAULT" else "Warning"),
            f"SC.L2-3.13.10: System crypto policy: {policy or 'unset'}",
            severity="High",
            details=f"crypto-policies config: {policy}",
            remediation=(
                "update-crypto-policies --set FUTURE  (or FIPS for federal CUI)"
            ),
            cross_references={
                "CMMC": "SC.L2-3.13.10", "NIST-800-171": "3.13.10",
                "NIST": "SC-12", "NSA": "CRYPTO-1.1",
            },
        ))

    # 03.13.11 - FIPS-validated cryptography
    fips_enabled = read_sysctl("crypto.fips_enabled") == "1"
    results.append(_r(
        cat, "Info",
        f"SC.L2-3.13.11: FIPS 140-3 mode: {'enabled' if fips_enabled else 'disabled'}",
        severity="Informational",
        details=f"crypto.fips_enabled = {read_sysctl('crypto.fips_enabled') or 'unset'}",
        remediation=(
            "Enable for federal CUI environments: "
            "fips-mode-setup --enable (RHEL family). Reboot required."
        ),
        cross_references={
            "CMMC": "SC.L2-3.13.11", "NIST-800-171": "3.13.11",
            "NIST": "SC-13", "FIPS": "140-3",
        },
    ))

    # 03.13.13 - Mobile code controls
    mobile_code_indicators = {
        "javascript-engines": (
            command_available("node") or command_available("nodejs")
        ),
        "wasm-runtime": (
            command_available("wasmer") or command_available("wasmtime")
        ),
    }
    detected = [k for k, v in mobile_code_indicators.items() if v]
    results.append(_r(
        cat, "Info",
        f"SC.L2-3.13.13: Mobile code runtimes installed: {detected or 'none'}",
        severity="Informational",
        details=f"Detected runtimes: {detected}",
        remediation=(
            "Document and authorize each mobile code runtime. "
            "Restrict to dev/build hosts where possible."
        ),
        cross_references={
            "CMMC": "SC.L2-3.13.13", "NIST-800-171": "3.13.13",
            "NIST": "SC-18",
        },
    ))

    # 03.13.16 - Information at rest protection
    luks_present = False
    if command_available("dmsetup"):
        rc, out, _ = run_command(["dmsetup", "ls", "--target=crypt"], timeout=3.0)
        if rc == 0 and out and "No devices" not in out:
            luks_present = True
    results.append(_r(
        cat, "Pass" if luks_present else "Fail",
        f"SC.L2-3.13.16: Information at rest cryptographically protected",
        severity="High",
        details=f"LUKS-encrypted devices: {luks_present}",
        remediation=(
            "Use LUKS for full-disk encryption. New systems: install with "
            "LUKS enabled. Existing: cryptsetup luksFormat (data migration "
            "required)."
        ),
        cross_references={
            "CMMC": "SC.L2-3.13.16", "NIST-800-171": "3.13.16",
            "NIST": "SC-28", "PCI-DSS": "3.5",
        },
    ))

    return results


def _check_si_l2_v32(os_info) -> List[AuditResult]:
    """CMMC L2 - SI domain extended (v3.2)."""
    results: List[AuditResult] = []
    cat = "CMMC - SI Extended L2 v3.2"

    # 03.14.01 - Flaw remediation: package update tracking
    update_tools = {
        "unattended-upgrades": (
            file_exists("/etc/apt/apt.conf.d/50unattended-upgrades") and
            systemd_active("unattended-upgrades.service") == "active"
        ),
        "dnf-automatic": (
            systemd_active("dnf-automatic-install.timer") == "active" or
            systemd_active("dnf-automatic.timer") == "active"
        ),
        "yum-cron": systemd_active("yum-cron.service") == "active",
    }
    detected = [k for k, v in update_tools.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Warning",
        f"SI.L2-3.14.1: Automated patch installation ({len(detected)} active)",
        severity="High",
        details=f"Active: {detected or 'none'}",
        remediation=(
            "Debian/Ubuntu: apt-get install -y unattended-upgrades && "
            "dpkg-reconfigure unattended-upgrades. "
            "RHEL family: dnf install -y dnf-automatic && "
            "systemctl enable --now dnf-automatic-install.timer."
        ),
        cross_references={
            "CMMC": "SI.L2-3.14.1", "NIST-800-171": "3.14.1",
            "NIST": "SI-2", "PCI-DSS": "6.3.3",
        },
    ))

    # 03.14.05 - Periodic scans (integrity check)
    aide_db = first_existing("/var/lib/aide/aide.db", "/var/lib/aide/aide.db.gz")
    aide_present = bool(aide_db)
    aide_cron = (
        file_exists("/etc/cron.d/aide") or
        file_exists("/etc/cron.daily/aide") or
        systemd_active("aidecheck.timer") == "active"
    )
    results.append(_r(
        cat, "Pass" if aide_present and aide_cron else (
            "Warning" if aide_present else "Fail"
        ),
        f"SI.L2-3.14.5: Periodic integrity scan scheduled",
        severity="Medium",
        details=(
            f"AIDE database: {aide_present}, scheduled: {aide_cron}"
        ),
        remediation=remediation_for("aide"),
        cross_references={
            "CMMC": "SI.L2-3.14.5", "NIST-800-171": "3.14.5",
            "NIST": "SI-7", "PCI-DSS": "11.5",
        },
    ))

    # 03.14.07 - System monitoring
    monitoring = {
        "auditd": systemd_active("auditd.service") == "active",
        "rsyslog": systemd_active("rsyslog.service") == "active",
        "journald": systemd_active("systemd-journald.service") == "active",
        "wazuh": systemd_active("wazuh-agent.service") == "active",
        "falco": systemd_active("falco.service") == "active",
    }
    active_mon = [k for k, v in monitoring.items() if v]
    results.append(_r(
        cat, "Pass" if len(active_mon) >= 2 else "Warning",
        f"SI.L2-3.14.7: Continuous monitoring ({len(active_mon)} services)",
        severity="High",
        details=f"Active monitoring: {active_mon}",
        remediation=(
            "Layer monitoring: auditd + rsyslog (forwarded to SIEM) + "
            "Wazuh agent. CMMC requires continuous monitoring of CUI systems."
        ),
        cross_references={
            "CMMC": "SI.L2-3.14.7", "NIST-800-171": "3.14.7",
            "NIST": "SI-4", "PCI-DSS": "10.6",
        },
    ))

    return results


def _check_supply_chain_risk(os_info) -> List[AuditResult]:
    """CMMC SR domain - Supply Chain Risk Management (DFARS 7019/7020)."""
    results: List[AuditResult] = []
    cat = "CMMC - SR Supply Chain Risk"

    if os_info.is_debian_family():
        apt_conf_d_files = list_directory("/etc/apt/apt.conf.d")
        unsigned_allowed = False
        for f in apt_conf_d_files:
            c = read_file_safe(os.path.join("/etc/apt/apt.conf.d", f))
            if "AllowUnsigned" in c or 'AllowInsecureRepositories "true"' in c:
                unsigned_allowed = True
                break
        results.append(_r(
            cat, "Pass" if not unsigned_allowed else "Fail",
            "SR: APT package signature verification enforced",
            severity="High",
            details=f"Unsigned repos allowed: {unsigned_allowed}",
            remediation=(
                "Remove AllowUnsigned/AllowInsecureRepositories from "
                "/etc/apt/apt.conf.d/* configuration files."
            ),
            cross_references={
                "CMMC": "SR.L2-Supply-Chain", "NIST": "CM-5(3)",
                "DFARS": "252.204-7019",
            },
        ))
    elif os_info.is_redhat_family():
        yum_conf = read_file_safe("/etc/yum.conf") + read_file_safe("/etc/dnf/dnf.conf")
        gpgcheck_global = re.search(
            r"^\s*gpgcheck\s*=\s*1", yum_conf, re.MULTILINE
        ) is not None

        repo_files = list_directory("/etc/yum.repos.d", suffix=".repo")
        repos_no_gpg = []
        for rf in repo_files:
            rc = read_file_safe(os.path.join("/etc/yum.repos.d", rf))
            if rc and re.search(r"^\s*gpgcheck\s*=\s*0", rc, re.MULTILINE):
                repos_no_gpg.append(rf)

        results.append(_r(
            cat, "Pass" if gpgcheck_global and not repos_no_gpg else "Fail",
            "SR: RPM/DNF GPG signature verification enabled",
            severity="High",
            details=(
                f"Global gpgcheck=1: {gpgcheck_global}, "
                f"Repos with gpgcheck=0: {repos_no_gpg}"
            ),
            remediation=(
                "In /etc/dnf/dnf.conf: gpgcheck=1. Remove gpgcheck=0 "
                "from repo files in /etc/yum.repos.d/"
            ),
            cross_references={
                "CMMC": "SR.L2-Supply-Chain", "NIST": "CM-5(3)",
                "DFARS": "252.204-7019",
            },
        ))

    # SBOM tooling
    sbom_tools = {
        "syft": command_available("syft"),
        "trivy": command_available("trivy"),
        "grype": command_available("grype"),
        "cyclonedx": command_available("cyclonedx") or command_available("cyclonedx-cli"),
    }
    detected_sbom = [k for k, v in sbom_tools.items() if v]
    results.append(_r(
        cat, "Pass" if detected_sbom else "Info",
        f"SR: SBOM/SCA tooling ({len(detected_sbom)} detected)",
        severity="Medium",
        details=f"Detected: {detected_sbom or 'none'}",
        remediation=(
            "Install syft (SBOM generation): "
            "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin. "
            "DoD increasingly requires SBOM for delivered software."
        ),
        cross_references={
            "CMMC": "SR.L2-SBOM", "NIST": "SR-4(3)",
            "DFARS": "252.204-7019",
        },
    ))

    # Container image scanning capability
    container_scan = {
        "trivy": command_available("trivy"),
        "grype": command_available("grype"),
        "clair": directory_exists("/opt/clair") or command_available("clairctl"),
        "anchore": command_available("anchore-cli"),
    }
    detected_cs = [k for k, v in container_scan.items() if v]
    results.append(_r(
        cat, "Pass" if detected_cs else "Info",
        f"SR: Container vulnerability scanning ({len(detected_cs)} tools)",
        severity="Medium",
        details=f"Detected: {detected_cs or 'none'}",
        remediation=(
            "Install Trivy: apt-get install -y trivy or wget binary. "
            "Scan images: trivy image <image>:<tag>"
        ),
        cross_references={
            "CMMC": "SR.L2-Container-Scan", "NIST": "RA-5(3)",
        },
    ))

    return results


def _check_dfars_sprs_extended(os_info) -> List[AuditResult]:
    """DFARS 252.204-7019/7020 SPRS scoring indicators (extended)."""
    results: List[AuditResult] = []
    cat = "CMMC DFARS-7019/7020 SPRS"

    # MFA for privileged access (SPRS scored)
    pam_files = ["/etc/pam.d/sshd", "/etc/pam.d/system-auth",
                 "/etc/pam.d/common-auth"]
    mfa_modules = ["pam_google_authenticator", "pam_yubico", "pam_oath",
                   "pam_duo", "pam_u2f", "pam_pkcs11"]
    detected_mfa = set()
    for pf in pam_files:
        c = read_file_safe(pf)
        if not c:
            continue
        for mod in mfa_modules:
            if mod + ".so" in c:
                detected_mfa.add(mod.replace("pam_", ""))

    results.append(_r(
        cat, "Pass" if detected_mfa else "Fail",
        f"DFARS-7019: MFA for privileged access ({len(detected_mfa)} modules)",
        severity="Critical",
        details=f"Detected MFA: {sorted(detected_mfa) or 'none'}",
        remediation=(
            "Install MFA: apt-get install -y libpam-google-authenticator. "
            "Configure /etc/pam.d/sshd with: auth required pam_google_authenticator.so. "
            "SPRS scoring penalizes lack of MFA on privileged accounts."
        ),
        cross_references={
            "CMMC": "DFARS-7019", "NIST-800-171": "3.5.3",
            "NIST": "IA-2(1)", "DFARS": "252.204-7019/7020",
        },
    ))

    # Centralized log management (SPRS scored)
    rsyslog_d = list_directory("/etc/rsyslog.d", suffix=".conf")
    has_remote_log = False
    for f in rsyslog_d + ["/etc/rsyslog.conf"]:
        if f == "/etc/rsyslog.conf":
            c = read_file_safe(f)
        else:
            c = read_file_safe(os.path.join("/etc/rsyslog.d", f))
        if c and ("@@" in c or "omfwd" in c or "omrelp" in c):
            has_remote_log = True
            break
    results.append(_r(
        cat, "Pass" if has_remote_log else "Fail",
        "DFARS-7019: Centralized logging configured (SPRS factor)",
        severity="High",
        details=f"Remote forwarding configured: {has_remote_log}",
        remediation=(
            "Configure rsyslog forwarding: /etc/rsyslog.d/50-remote.conf "
            "with '*.* @@logserver:6514' (TLS preferred)"
        ),
        cross_references={
            "CMMC": "DFARS-7019", "NIST-800-171": "3.3.5",
            "NIST": "AU-6(3)",
        },
    ))

    # System inventory (SPRS factor)
    inv_capable = (
        command_available("dpkg") or
        command_available("rpm") or
        command_available("pacman") or
        command_available("apk")
    )
    results.append(_r(
        cat, "Pass" if inv_capable else "Fail",
        "DFARS-7019: System inventory enumeration capability",
        severity="Medium",
        details=f"Package manager available: {inv_capable}",
        remediation=(
            "Periodically export to CMDB: dpkg --list > /var/lib/cmdb/inventory.txt"
        ),
        cross_references={
            "CMMC": "DFARS-7019", "NIST-800-171": "3.4.1",
            "NIST": "CM-8",
        },
    ))

    return results


# Save reference to existing run_checks
_original_run_checks_cmmc_v32 = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the v3.2 expanded CMMC module.

    Combines existing baseline + L2 expansions with v3.2 additions covering
    NIST SP 800-172 Level 3 advanced practices, deeper L2 technical
    coverage across CM/IA/SC/SI domains, supply-chain (SR) practices,
    and DFARS SPRS scoring indicators.
    """
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_cmmc_v32(shared_data)

    os_info = shared_data.get("v3_os_info")
    if os_info is None:
        os_info = os_detection.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        # Level 3 advanced practices (NIST SP 800-172)
        results.extend(_check_l3_adversarial_protection(os_info))
        results.extend(_check_l3_dual_authorization(os_info))

        # Level 2 technical depth (v3.2)
        results.extend(_check_cm_l2_v32(os_info))
        results.extend(_check_ia_l2_v32(os_info))
        results.extend(_check_sc_l2_v32(os_info))
        results.extend(_check_si_l2_v32(os_info))

        # Supply chain risk
        results.extend(_check_supply_chain_risk(os_info))

        # DFARS extended
        results.extend(_check_dfars_sprs_extended(os_info))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled exception in CMMC v3.2 expansion")
        results.append(_r(
            "CMMC - Error", "Error",
            f"CMMC v3.2 expansion exception: {exc!r}",
            severity="Medium", details=str(exc),
        ))

    return results


# ============================================================================
# v3.5 EXPANSION - CMMC NIST SP 800-171 Rev 3 + Level 3 Enhancements + CUI
# ----------------------------------------------------------------------------
# Synopsis:
#   Adds depth across CMMC 2.0 areas not yet covered:
#     - NIST SP 800-171 Rev 3 (May 2024) updated controls
#     - Level 3 enhancement controls (NIST SP 800-172) depth
#     - CUI handling deep checks (cryptographic protection, marking,
#       transit, sanitization)
#     - Assessment readiness indicators (SSP, POA&M, SPRS)
#     - DFARS 252.204-7012/7019/7020/7021 specific surrogates
#     - External Service Provider (ESP) / Cloud Service Provider readiness
#     - C3PAO assessment readiness
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


def _v35_cmmc_result(category, status, message, severity="Medium",
                    details="", remediation="", cross_references=None):
    """Build AuditResult for CMMC v3.5 expansion."""
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


def _check_cmmc_v35_171_rev3_updates(os_info):
    """NIST SP 800-171 Rev 3 (May 2024) updated control surrogates."""
    results = []
    cat = "CMMC v3.5 - 800-171 Rev 3"

    # 03.05.07 - Password management (updated in Rev 3)
    pwquality = _v35_read_file_safe("/etc/security/pwquality.conf")
    pwquality_d = ""
    if _v35_directory_exists("/etc/security/pwquality.conf.d"):
        for f in _v35_list_directory("/etc/security/pwquality.conf.d"):
            if f.endswith(".conf"):
                pwquality_d += "\n" + _v35_read_file_safe(
                    os.path.join("/etc/security/pwquality.conf.d", f)
                )
    full_pwq = pwquality + "\n" + pwquality_d
    minlen_match = re.search(
        r"^\s*minlen\s*=\s*(\d+)", full_pwq, re.MULTILINE,
    )
    minlen = int(minlen_match.group(1)) if minlen_match else 0
    minlen_ok = minlen >= 14  # Rev 3 aligns with NIST 800-63B 14+ chars
    results.append(_v35_cmmc_result(
        f"{cat} - 03.05.07 Password Length",
        "Pass" if minlen_ok else "Warning",
        f"NIST SP 800-171 Rev 3 03.05.07 minlen >= 14: {minlen_ok}",
        severity="High",
        details=f"pwquality minlen = {minlen}",
        remediation=(
            "In /etc/security/pwquality.conf.d/cmmc-rev3.conf:\n"
            "  minlen = 14\n"
            "  minclass = 4\n"
            "  difok = 4\n"
            "Rev 3 emphasizes length over complexity (aligns with NIST 800-63B)."
        ),
        cross_references={
            "CMMC": "L2 03.05.07",
            "NIST-171-r3": "03.05.07",
            "NIST": "IA-5(1)",
        },
    ))

    # 03.13.11 - Cryptographic key establishment (FIPS 140-3)
    fips_enabled = _v35_read_sysctl("crypto.fips_enabled") == "1"
    crypto_policy = _v35_read_file_safe(
        "/etc/crypto-policies/state/current"
    ).strip()
    fips_aligned = fips_enabled or crypto_policy.upper() in ("FIPS", "FUTURE")
    results.append(_v35_cmmc_result(
        f"{cat} - 03.13.11 Cryptographic Keys",
        "Pass" if fips_aligned else "Warning",
        f"NIST SP 800-171 Rev 3 03.13.11 FIPS-aligned: {fips_aligned}",
        severity="High",
        details=(
            f"crypto.fips_enabled: {fips_enabled}, "
            f"crypto-policy: {crypto_policy or 'unset'}"
        ),
        remediation=(
            "RHEL: fips-mode-setup --enable\n"
            "Or: update-crypto-policies --set FIPS\n"
            "Ubuntu Pro: pro enable fips"
        ),
        cross_references={
            "CMMC": "L2 03.13.11",
            "NIST-171-r3": "03.13.11",
            "FIPS": "140-3",
        },
    ))

    # 03.14.01 - Flaw remediation (auto-patch indicator)
    auto_patch_active = (
        _v35_systemd_active("unattended-upgrades.service") == "active" or
        _v35_systemd_active("dnf-automatic-install.timer") == "active" or
        _v35_systemd_active("dnf-automatic.timer") == "active"
    )
    results.append(_v35_cmmc_result(
        f"{cat} - 03.14.01 Flaw Remediation",
        "Pass" if auto_patch_active else "Warning",
        f"NIST SP 800-171 Rev 3 03.14.01 Auto-patch active: {auto_patch_active}",
        severity="High",
        details=f"Auto-patch service active: {auto_patch_active}",
        remediation=(
            remediation_for("unattended-upgrades")
            if (os_info and os_info.is_debian_family())
            else remediation_for("dnf-automatic")
        ),
        cross_references={
            "CMMC": "L2 03.14.01",
            "NIST-171-r3": "03.14.01",
            "NIST": "SI-2",
        },
    ))

    # 03.13.08 - Cryptographic protection of CUI in transit (TLS strict)
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
    transit_strong = bool(
        ciphers_match and
        "aes256" in ciphers_match.group(1).lower() and
        "cbc" not in ciphers_match.group(1).lower()
    )
    results.append(_v35_cmmc_result(
        f"{cat} - 03.13.08 Transit Crypto",
        "Pass" if transit_strong else "Warning",
        f"NIST SP 800-171 Rev 3 03.13.08 SSH transit crypto strong: "
        f"{transit_strong}",
        severity="High",
        details=(
            f"Ciphers = "
            f"{ciphers_match.group(1) if ciphers_match else 'default'}"
        ),
        remediation=(
            "In /etc/ssh/sshd_config.d/50-cmmc.conf:\n"
            "  Ciphers aes256-gcm@openssh.com,aes256-ctr"
        ),
        cross_references={
            "CMMC": "L2 03.13.08",
            "NIST-171-r3": "03.13.08",
            "FIPS": "197",
        },
    ))

    return results


def _check_cmmc_v35_l3_enhancements_depth(os_info):
    """Level 3 enhancement controls (NIST SP 800-172) depth."""
    results = []
    cat = "CMMC v3.5 - L3 Enhancements"

    # 3.1.3e - Concurrent session limit (more strict than L2)
    pam_files = [
        "/etc/security/limits.conf",
    ]
    if _v35_directory_exists("/etc/security/limits.d"):
        for f in _v35_list_directory("/etc/security/limits.d"):
            pam_files.append(f"/etc/security/limits.d/{f}")
    limits_content = ""
    for p in pam_files:
        limits_content += "\n" + _v35_read_file_safe(p)
    maxlogins_match = re.search(
        r"^\s*\S+\s+\S+\s+maxlogins\s+(\d+)",
        limits_content, re.MULTILINE,
    )
    maxlogins_set = bool(maxlogins_match)
    results.append(_v35_cmmc_result(
        f"{cat} - 3.1.3e Concurrent Sessions",
        "Pass" if maxlogins_set else "Info",
        f"L3 3.1.3e Concurrent session limit: {maxlogins_set}",
        severity="Medium",
        details=(
            f"maxlogins = "
            f"{maxlogins_match.group(1) if maxlogins_match else 'unset'}"
        ),
        remediation=(
            "In /etc/security/limits.d/cmmc-l3.conf:\n"
            "  * hard maxlogins 3\n"
            "L3 enhances L2 by limiting concurrent sessions per user."
        ),
        cross_references={
            "CMMC": "L3 3.1.3e",
            "NIST-172": "3.1.3e",
            "NIST": "AC-10",
        },
    ))

    # 3.4.1e - Diverse architectures
    multi_arch = False
    rc, out, _ = _v35_run_command(["uname", "-m"], timeout=3.0)
    primary_arch = out.strip() if rc == 0 else "unknown"
    # Heuristic: presence of foreign architecture support (multi-lib)
    if _v35_command_available("dpkg"):
        rc, out, _ = _v35_run_command(
            ["dpkg", "--print-foreign-architectures"], timeout=3.0,
        )
        if rc == 0 and out.strip():
            multi_arch = True
    results.append(_v35_cmmc_result(
        f"{cat} - 3.4.1e Architecture Diversity",
        "Info",
        f"L3 3.4.1e Primary arch: {primary_arch}, multi-arch: {multi_arch}",
        severity="Informational",
        details=f"primary: {primary_arch}, multi-arch support: {multi_arch}",
        cross_references={
            "CMMC": "L3 3.4.1e",
            "NIST-172": "3.4.1e",
        },
    ))

    # 3.13.4e - Detect/prevent unauthorized exfiltration (DLP indicators)
    dlp_indicators = {
        "fail2ban (rate limit)": _v35_systemd_active("fail2ban.service") == "active",
        "egress firewall (nft/iptables)": False,
        "DNS filtering (resolved)": False,
        "auditd egress watch": False,
    }
    rc, out, _ = _v35_run_command(["nft", "list", "ruleset"], timeout=5.0)
    if rc == 0 and out and "output" in out.lower():
        # Check if there's any output chain rule (egress filtering)
        if re.search(r"chain\s+\S*output\S*\s*{.*type\s+filter", out,
                     re.DOTALL | re.IGNORECASE):
            dlp_indicators["egress firewall (nft/iptables)"] = True
    if _v35_systemd_active("systemd-resolved.service") == "active":
        dlp_indicators["DNS filtering (resolved)"] = True
    audit_rules = ""
    if _v35_directory_exists("/etc/audit/rules.d"):
        for f in _v35_list_directory("/etc/audit/rules.d"):
            if f.endswith(".rules"):
                audit_rules += "\n" + _v35_read_file_safe(
                    os.path.join("/etc/audit/rules.d", f)
                )
    if "connect" in audit_rules and "exit" in audit_rules:
        dlp_indicators["auditd egress watch"] = True
    detected = [k for k, v in dlp_indicators.items() if v]
    results.append(_v35_cmmc_result(
        f"{cat} - 3.13.4e DLP Indicators",
        "Pass" if len(detected) >= 2 else "Warning",
        f"L3 3.13.4e Exfiltration detection layers: {len(detected)}/4",
        severity="High",
        details=f"Active: {detected}",
        remediation=(
            "Layered DLP: nftables egress rules + DNS filtering + auditd "
            "connect() syscall watch + commercial DLP agent if applicable."
        ),
        cross_references={
            "CMMC": "L3 3.13.4e",
            "NIST-172": "3.13.4e",
            "NIST": "SI-4(18)",
        },
    ))

    # 3.14.6e - Analyze suspicious activity (SIEM forwarding)
    siem_forward = False
    rsy = _v35_read_file_safe("/etc/rsyslog.conf")
    if "@@" in rsy or "omfwd" in rsy:
        siem_forward = True
    if not siem_forward and _v35_directory_exists("/etc/rsyslog.d"):
        for f in _v35_list_directory("/etc/rsyslog.d"):
            c = _v35_read_file_safe(os.path.join("/etc/rsyslog.d", f))
            if "@@" in c or "omfwd" in c:
                siem_forward = True
                break
    results.append(_v35_cmmc_result(
        f"{cat} - 3.14.6e SIEM Forwarding",
        "Pass" if siem_forward else "Warning",
        f"L3 3.14.6e SIEM log forwarding: {siem_forward}",
        severity="High",
        details=f"Remote rsyslog: {siem_forward}",
        remediation=(
            "In /etc/rsyslog.d/50-cmmc-siem.conf:\n"
            "  *.* action(type=\"omfwd\" target=\"siem.example.com\" "
            "port=\"6514\" protocol=\"tcp\" StreamDriver=\"gtls\")\n"
            "L3 requires near-real-time analysis of suspicious activity."
        ),
        cross_references={
            "CMMC": "L3 3.14.6e",
            "NIST-172": "3.14.6e",
            "NIST": "AU-6, SI-4",
        },
    ))

    # 3.6.1e - SOC integration / 24x7 monitoring indicator
    monitor_layers = sum([
        _v35_systemd_active("auditd.service") == "active",
        _v35_file_exists("/var/ossec/etc/ossec.conf"),
        _v35_systemd_active("falco.service") == "active",
        siem_forward,
    ])
    results.append(_v35_cmmc_result(
        f"{cat} - 3.6.1e SOC Integration",
        "Pass" if monitor_layers >= 3 else "Warning",
        f"L3 3.6.1e Monitoring layers (SOC integration): {monitor_layers}/4",
        severity="High",
        details=f"Active layers: {monitor_layers}",
        cross_references={
            "CMMC": "L3 3.6.1e",
            "NIST-172": "3.6.1e",
            "NIST": "SI-4",
        },
    ))

    return results


def _check_cmmc_v35_cui_handling(os_info):
    """CUI (Controlled Unclassified Information) handling deep checks."""
    results = []
    cat = "CMMC v3.5 - CUI Handling"

    # CUI cryptographic protection at rest (FIPS-validated)
    luks_present = False
    rc, out, _ = _v35_run_command(["lsblk", "-o", "TYPE", "-n"], timeout=5.0)
    if rc == 0 and out and "crypt" in out.lower():
        luks_present = True
    fips_enabled = _v35_read_sysctl("crypto.fips_enabled") == "1"
    cui_at_rest = luks_present and fips_enabled
    results.append(_v35_cmmc_result(
        f"{cat} - 03.13.16 CUI At Rest",
        "Pass" if cui_at_rest else ("Info" if luks_present else "Warning"),
        f"CUI cryptographic protection at rest: LUKS={luks_present}, "
        f"FIPS={fips_enabled}",
        severity="Critical",
        details=(
            f"LUKS-encrypted volumes: {luks_present}, "
            f"FIPS mode: {fips_enabled}"
        ),
        remediation=(
            f"{remediation_for('cryptsetup')}\n"
            "Enable FIPS mode: fips-mode-setup --enable (RHEL) or "
            "pro enable fips (Ubuntu Pro)\n"
            "FIPS-validated LUKS satisfies 03.13.16 CUI at rest protection."
        ),
        cross_references={
            "CMMC": "L2 03.13.16",
            "NIST-171-r3": "03.13.16",
            "FIPS": "140-3",
            "DFARS": "252.204-7012",
        },
    ))

    # CUI media sanitization (MP-6 enforcement)
    sanit_tools = sum(1 for t in ["shred", "scrub", "wipe", "srm", "hdparm"]
                      if _v35_command_available(t))
    results.append(_v35_cmmc_result(
        f"{cat} - 03.08.03 CUI Media Sanitization",
        "Pass" if sanit_tools >= 2 else "Warning",
        f"CUI media sanitization tools: {sanit_tools}/5",
        severity="High",
        details=f"Tools available: {sanit_tools}",
        remediation=(
            "apt-get install -y secure-delete coreutils scrub hdparm\n"
            "DoD 5220.22-M / NIST 800-88 sanitization required for CUI "
            "disposal/release."
        ),
        cross_references={
            "CMMC": "L2 03.08.03",
            "NIST-171-r3": "03.08.03",
            "NIST": "MP-6",
        },
    ))

    # CUI marking (technical surrogate: file labeling indicators)
    selinux_active = (
        _v35_command_available("getenforce") and
        ((_v35_run_command(["getenforce"], timeout=2.0)[1] or "").strip() == "Enforcing")
    )
    apparmor_active = _v35_command_available("aa-status")
    label_capable = selinux_active or apparmor_active
    results.append(_v35_cmmc_result(
        f"{cat} - 03.08.04 CUI Marking Capability",
        "Pass" if label_capable else "Warning",
        f"CUI labeling capability (MAC active): {label_capable}",
        severity="Medium",
        details=(
            f"SELinux enforcing: {selinux_active}, AppArmor: {apparmor_active}"
        ),
        remediation=(
            "Enable SELinux enforcing mode (RHEL):\n"
            "  setenforce 1; sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config\n"
            "Or AppArmor (Ubuntu): aa-enforce /etc/apparmor.d/*\n"
            "MAC enables file/process labeling for CUI compartmentalization."
        ),
        cross_references={
            "CMMC": "L2 03.08.04",
            "NIST-171-r3": "03.08.04",
        },
    ))

    return results


def _check_cmmc_v35_assessment_readiness(os_info):
    """Assessment readiness indicators (SSP, POA&M, SPRS)."""
    results = []
    cat = "CMMC v3.5 - Assessment Readiness"

    # Continuous monitoring tooling for assessment evidence
    assessment_tools = {
        "lynis": _v35_command_available("lynis"),
        "openscap (oscap)": _v35_command_available("oscap"),
        "auditd": _v35_systemd_active("auditd.service") == "active",
        "AIDE/FIM": (
            _v35_file_exists("/var/lib/aide/aide.db") or
            _v35_file_exists("/var/lib/aide/aide.db.gz")
        ),
        "package signing": (
            _v35_directory_exists("/etc/apt/keyrings") or
            _v35_directory_exists("/etc/apt/trusted.gpg.d") or
            _v35_directory_exists("/etc/pki/rpm-gpg")
        ),
    }
    available = [k for k, v in assessment_tools.items() if v]
    results.append(_v35_cmmc_result(
        f"{cat} - Assessment Evidence Tooling",
        "Pass" if len(available) >= 4 else "Warning",
        f"Assessment evidence tooling: {len(available)}/5",
        severity="High",
        details=f"Available: {available}",
        remediation=(
            "Required for C3PAO assessment evidence:\n"
            "  apt-get install -y lynis libopenscap8 auditd aide\n"
            "Each provides automated, periodic evidence generation for "
            "control assessment."
        ),
        cross_references={
            "CMMC": "Assessment Process",
            "NIST-171-r3": "03.12.01",
        },
    ))

    # SPRS scoring readiness - evidence that NIST SP 800-171 Rev 3 controls
    # are partially implemented (lynis run history, openscap reports)
    lynis_logs = _v35_directory_exists("/var/log/lynis-report.dat") or \
                 _v35_file_exists("/var/log/lynis.log") or \
                 _v35_file_exists("/var/log/lynis-report.dat")
    openscap_report_dir = _v35_directory_exists("/var/log/openscap")
    history_evidence = lynis_logs or openscap_report_dir
    results.append(_v35_cmmc_result(
        f"{cat} - SPRS Scoring Evidence",
        "Pass" if history_evidence else "Info",
        f"SPRS scoring evidence: lynis history={lynis_logs}, "
        f"openscap reports={openscap_report_dir}",
        severity="Medium",
        details=(
            f"lynis log: {lynis_logs}, "
            f"openscap dir: {openscap_report_dir}"
        ),
        remediation=(
            "Schedule periodic scans for SPRS evidence:\n"
            "  /etc/cron.daily/lynis-cmmc:\n"
            "    #!/bin/sh\n"
            "    lynis audit system --quick --auditor 'cmmc-assessor' "
            "--log-file /var/log/lynis.log"
        ),
        cross_references={
            "CMMC": "SPRS Scoring",
            "DFARS": "252.204-7019, 252.204-7020",
        },
    ))

    return results


def _check_cmmc_v35_dfars_additional(os_info):
    """DFARS additional clauses 252.204-7019/7020/7021 surrogates."""
    results = []
    cat = "CMMC v3.5 - DFARS Additional"

    # 252.204-7012 - ICTRS reporting capability (indicator)
    mail_capable = (
        _v35_command_available("mail") or
        _v35_command_available("mailx") or
        _v35_systemd_active("postfix.service") == "active"
    )
    results.append(_v35_cmmc_result(
        f"{cat} - 252.204-7012 Reporting",
        "Pass" if mail_capable else "Warning",
        f"DFARS 252.204-7012 ICTRS reporting capability: {mail_capable}",
        severity="High",
        details=f"Mail capability for incident reporting: {mail_capable}",
        remediation=(
            "apt-get install -y mailutils postfix\n"
            "DFARS 252.204-7012 requires 72-hour incident reporting to DoD "
            "via DIBNet (https://dibnet.dod.mil)."
        ),
        cross_references={
            "DFARS": "252.204-7012",
            "CMMC": "L2 03.06.02",
        },
    ))

    # 252.204-7020 - NIST SP 800-171 implementation (continuous compliance)
    monitoring_continuous = (
        _v35_systemd_active("auditd.service") == "active" and
        (_v35_file_exists("/var/lib/aide/aide.db") or
         _v35_file_exists("/var/lib/aide/aide.db.gz"))
    )
    results.append(_v35_cmmc_result(
        f"{cat} - 252.204-7020 Continuous Compliance",
        "Pass" if monitoring_continuous else "Warning",
        f"DFARS 252.204-7020 continuous compliance: {monitoring_continuous}",
        severity="High",
        details=f"auditd + AIDE active: {monitoring_continuous}",
        remediation=(
            f"{remediation_for('aide')}\n"
            "Continuous compliance evidence supports DFARS 252.204-7020 "
            "NIST SP 800-171 self-assessment annual update."
        ),
        cross_references={
            "DFARS": "252.204-7020",
            "CMMC": "L2 03.12.01",
        },
    ))

    return results


def _check_cmmc_v35_esp_csp_readiness(os_info):
    """ESP / CSP (External Service Provider / Cloud Service Provider) readiness."""
    results = []
    cat = "CMMC v3.5 - ESP/CSP Readiness"

    # FedRAMP Moderate baseline cryptographic indicators
    fips_enabled = _v35_read_sysctl("crypto.fips_enabled") == "1"
    crypto_policy = _v35_read_file_safe(
        "/etc/crypto-policies/state/current"
    ).strip()
    fedramp_aligned = fips_enabled or crypto_policy.upper() == "FIPS"
    results.append(_v35_cmmc_result(
        f"{cat} - FedRAMP Moderate Crypto",
        "Pass" if fedramp_aligned else "Info",
        f"FedRAMP Moderate crypto baseline: {fedramp_aligned}",
        severity="Medium",
        details=(
            f"FIPS mode: {fips_enabled}, crypto-policy: {crypto_policy}"
        ),
        remediation=(
            "ESPs/CSPs handling CUI must align with FedRAMP Moderate "
            "baseline. RHEL: fips-mode-setup --enable; or "
            "Ubuntu: pro enable fips."
        ),
        cross_references={
            "CMMC": "ESP/CSP",
            "FedRAMP": "Moderate",
            "FIPS": "140-3",
        },
    ))

    # Cloud-managed agent presence (CSP integration)
    cloud_agents = {
        "AWS SSM": _v35_systemd_active("amazon-ssm-agent.service") == "active",
        "Azure Monitor": _v35_systemd_active("azuremonitoragent.service") == "active",
        "GCP Ops": _v35_systemd_active("google-cloud-ops-agent.service") == "active",
    }
    detected = [k for k, v in cloud_agents.items() if v]
    if detected:
        results.append(_v35_cmmc_result(
            f"{cat} - Cloud Agent Detected",
            "Info",
            f"Cloud-managed agent: {detected}",
            severity="Informational",
            details=f"Cloud platforms: {detected}",
            cross_references={"CMMC": "ESP/CSP"},
        ))

    return results


# Save reference to existing run_checks
_original_run_checks_cmmc_v35 = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the v3.5 expanded CMMC module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_cmmc_v35(shared_data)

    os_info = shared_data.get("os_info") or shared_data.get("v3_os_info")
    if os_info is None:
        from shared_components import os_detection as _os_det
        os_info = _os_det.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        results.extend(_check_cmmc_v35_171_rev3_updates(os_info))
        results.extend(_check_cmmc_v35_l3_enhancements_depth(os_info))
        results.extend(_check_cmmc_v35_cui_handling(os_info))
        results.extend(_check_cmmc_v35_assessment_readiness(os_info))
        results.extend(_check_cmmc_v35_dfars_additional(os_info))
        results.extend(_check_cmmc_v35_esp_csp_readiness(os_info))
    except Exception as exc:  # noqa: BLE001
        results.append(AuditResult(
            module=MODULE_NAME, category="CMMC - Error",
            status="Error",
            message=f"CMMC v3.5 expansion exception: {exc!r}",
            details=str(exc), severity="Medium",
        ))

    return results
if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    print("[CMMC] ===== CMMC 2.0 + DFARS Audit =====")
    print("[CMMC] Module Version: 3.9\n")
    rs = run_checks()
    print(f"[CMMC] {len(rs)} checks executed\n")
    counts: Dict[str, int] = {}
    for r in rs:
        counts[r.status] = counts.get(r.status, 0) + 1
    for s, c in sorted(counts.items()):
        print(f"  {s:>8}: {c}")
