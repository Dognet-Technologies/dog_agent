#!/usr/bin/env python3
"""
module_soc2.py
SOC 2 Type II Trust Service Criteria Module for Linux
Version: 3.9

SYNOPSIS
    Linux technical compliance assessment against the AICPA Trust
    Services Criteria (TSC) used in SOC 2 Type II audits.

DESCRIPTION
    SOC 2 reports describe a service organisation's controls relevant
    to security, availability, processing integrity, confidentiality,
    and privacy. Type II reports cover the operating effectiveness of
    those controls over a period (typically 6-12 months).

    This module provides automated technical evidence for the controls
    that have direct Linux indicators. SOC 2 includes substantial
    process, governance, and policy elements that no automated tool can
    verify; those require auditor interview and documentation review.

    Trust Service Criteria covered (focus on technical controls):

        Common Criteria (Security - applies to every SOC 2 engagement):
          CC1 - Control Environment             [process - limited tech]
          CC2 - Communication and Information   [process - limited tech]
          CC3 - Risk Assessment                 [process - limited tech]
          CC4 - Monitoring Activities           [tech indicators]
          CC5 - Control Activities              [tech indicators]
          CC6 - Logical and Physical Access     [extensive tech coverage]
          CC7 - System Operations                [extensive tech coverage]
          CC8 - Change Management                [tech indicators]
          CC9 - Risk Mitigation                  [tech indicators]

        Availability:
          A1.1 - Performance and capacity        [tech indicators]
          A1.2 - Environmental protections        [physical - limited]
          A1.3 - Backup and recovery              [tech indicators]

        Confidentiality:
          C1.1 - Identification of confidential information [process]
          C1.2 - Disposal of confidential information       [tech]

    Each check populates AuditResult.cross_references with the SOC 2
    TSC reference plus equivalents in NIST 800-53, ISO 27001, COBIT,
    and PCI DSS where applicable.

PARAMETERS
    shared_data : Dictionary containing shared data from the orchestrator.

USAGE
    Standalone:
        python3 modules/module_soc2.py

    Via orchestrator:
        python3 linux_security_audit.py -m SOC2

NOTES
    Version: 3.9
    Reference: AICPA Trust Services Criteria 2017 (with 2022 revisions)
               https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services
    Standards: AICPA TSP Section 100 (TSC), NIST SP 800-53 mapping,
               ISO/IEC 27001 alignment
    Target: 70+ technical control checks
    Note: SOC 2 evidence usually includes period-of-time observations;
    point-in-time host audits provide a snapshot only.
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
    file_mode, parse_kv_file, list_directory, make_result, first_existing,
)

logger = logging.getLogger("audit.module_soc2")
MODULE_NAME = "SOC2"
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
# CC4 - Monitoring Activities (Technical Indicators)
# ===========================================================================

def _check_cc4_monitoring(os_info) -> List[AuditResult]:
    cat = "SOC 2 CC4 - Monitoring"
    results: List[AuditResult] = []

    # CC4.1 - Selects, develops, and operates ongoing monitoring activities
    auditd_active = systemd_active("auditd.service") == "active"
    results.append(_r(
        cat,
        "Pass" if auditd_active else "Fail",
        "SOC 2 CC4.1: System monitoring (auditd) active",
        severity="High",
        details=f"auditd state: {systemd_active('auditd.service')}",
        remediation=remediation_for("auditd"),
        cross_references={
            "SOC2": "CC4.1", "NIST": "AU-2", "ISO27001": "A.8.15",
            "CIS": "4.1.1.1", "PCI-DSS": "10.2.1",
        },
    ))

    # CC4.2 - Communicates internal control deficiencies to those parties
    # responsible for taking corrective action - centralised log forwarding
    rsyslog_files = ["/etc/rsyslog.conf"] + list_directory("/etc/rsyslog.d", ".conf")
    has_remote_logging = False
    for rf in rsyslog_files:
        content = read_file_safe(rf)
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            if re.search(r"@@?[a-zA-Z0-9.\-]+", stripped) and stripped[:5].count("*") >= 1:
                has_remote_logging = True
                break
        if has_remote_logging:
            break

    results.append(_r(
        cat,
        "Pass" if has_remote_logging else "Warning",
        "SOC 2 CC4.2: Centralised logging configured for monitoring",
        severity="High",
        details=f"Remote rsyslog forwarding: {has_remote_logging}",
        remediation=(
            "Configure rsyslog to forward to central log server: "
            "echo '*.* @@logserver.example.com:514' > /etc/rsyslog.d/50-remote.conf"
        ),
        cross_references={
            "SOC2": "CC4.2", "NIST": "AU-6(3)", "ISO27001": "A.8.15",
            "CIS": "4.2.1.5", "PCI-DSS": "10.5.4",
        },
    ))

    return results


# ===========================================================================
# CC5 - Control Activities
# ===========================================================================

def _check_cc5_control_activities(os_info) -> List[AuditResult]:
    cat = "SOC 2 CC5 - Control Activities"
    results: List[AuditResult] = []

    # CC5.1 - Selects and develops control activities to mitigate risks
    # MAC framework enforcing
    mac_enforcing = False
    if os_info.mac_framework == "selinux":
        try:
            with open("/sys/fs/selinux/enforce", "r", encoding="ascii") as f:
                mac_enforcing = f.read().strip() == "1"
        except OSError:
            pass
    elif os_info.mac_framework == "apparmor":
        if command_available("aa-status"):
            rc, out, _ = run_command(["aa-status"])
            mac_enforcing = rc == 0 and "profiles are in enforce mode" in out

    results.append(_r(
        cat,
        "Pass" if mac_enforcing else "Warning",
        "SOC 2 CC5.1: Mandatory access control enforcing",
        severity="High",
        details=(
            f"MAC framework: {os_info.mac_framework or 'none'}, "
            f"enforcing: {mac_enforcing}"
        ),
        remediation=(
            "Enable SELinux enforcing: setenforce 1 && update /etc/selinux/config. "
            "Or AppArmor: aa-enforce /etc/apparmor.d/*."
        ),
        cross_references={
            "SOC2": "CC5.1", "NIST": "AC-3(4)", "ISO27001": "A.8.3",
            "CIS": "1.6.1.3", "STIG": "V-230230",
        },
    ))

    return results


# ===========================================================================
# CC6 - Logical and Physical Access (Most Linux-Applicable Section)
# ===========================================================================

def _check_cc6_logical_access(os_info) -> List[AuditResult]:
    cat = "SOC 2 CC6 - Logical Access"
    results: List[AuditResult] = []

    # CC6.1 - Identifies and manages logical access security
    # No empty passwords
    shadow = read_file_safe("/etc/shadow")
    empty_pwd = []
    if shadow:
        for line in shadow.splitlines():
            fields = line.split(":")
            if len(fields) >= 2 and fields[1] == "":
                empty_pwd.append(fields[0])

    if shadow:
        results.append(_r(
            cat,
            "Pass" if not empty_pwd else "Fail",
            "SOC 2 CC6.1: No empty-password accounts",
            severity="Critical",
            details=f"Empty-password accounts: {', '.join(empty_pwd) or 'none'}",
            remediation="Lock empty-password accounts: passwd -l <username>",
            cross_references={
                "SOC2": "CC6.1", "NIST": "IA-5", "ISO27001": "A.8.5",
                "CIS": "6.2.5", "PCI-DSS": "8.3.5",
            },
        ))

    # CC6.1 - Unique user IDs (no duplicate UIDs)
    passwd_content = read_file_safe("/etc/passwd")
    uids: Dict[int, List[str]] = {}
    if passwd_content:
        for line in passwd_content.splitlines():
            fields = line.split(":")
            if len(fields) >= 3:
                try:
                    uid = int(fields[2])
                    uids.setdefault(uid, []).append(fields[0])
                except ValueError:
                    continue
    duplicates = {uid: names for uid, names in uids.items() if len(names) > 1}

    results.append(_r(
        cat,
        "Pass" if not duplicates else "Fail",
        "SOC 2 CC6.1: Unique user identifiers",
        severity="High",
        details=f"Duplicate UIDs: {duplicates or 'none'}",
        remediation="Reassign duplicate UIDs: usermod -u <new_uid> <username>",
        cross_references={
            "SOC2": "CC6.1", "NIST": "IA-2", "ISO27001": "A.8.5",
            "CIS": "6.2.6", "PCI-DSS": "8.2.1", "HIPAA": "164.312(a)(2)(i)",
        },
    ))

    # CC6.2 - Registers, authorises, and tracks new internal user identifiers
    # Indicator: only root has UID 0
    uid0_others = [
        names for uid, names in uids.items() if uid == 0 and "root" not in names
    ]
    extra_root_users = []
    for uid, names in uids.items():
        if uid == 0:
            extra_root_users = [n for n in names if n != "root"]

    results.append(_r(
        cat,
        "Pass" if not extra_root_users else "Fail",
        "SOC 2 CC6.2: Only root has UID 0",
        severity="Critical",
        details=f"Non-root UID 0 accounts: {', '.join(extra_root_users) or 'none'}",
        remediation="Reassign UID for non-root accounts: usermod -u <new_uid> <user>",
        cross_references={
            "SOC2": "CC6.2", "NIST": "AC-6", "CIS": "6.2.10",
            "STIG": "V-230327", "PCI-DSS": "7.2.1",
        },
    ))

    # CC6.3 - Authorises, modifies, or removes access based on role/job
    # Indicator: sudoers does not have unrestricted NOPASSWD
    sudoers_files = ["/etc/sudoers"] + list_directory("/etc/sudoers.d", "")
    nopasswd_count = 0
    for sf in sudoers_files:
        content = read_file_safe(sf)
        if not content:
            continue
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("Defaults"):
                continue
            if "NOPASSWD" in stripped.upper():
                nopasswd_count += 1

    results.append(_r(
        cat,
        "Pass" if nopasswd_count == 0 else "Warning",
        "SOC 2 CC6.3: NOPASSWD sudo entries are reviewed",
        severity="High",
        details=f"NOPASSWD entries: {nopasswd_count}",
        remediation="Review and justify each NOPASSWD entry; remove unjustified ones",
        cross_references={
            "SOC2": "CC6.3", "NIST": "AC-6(2)", "CIS": "5.5.4",
            "ISO27001": "A.8.2", "PCI-DSS": "7.2.5",
        },
    ))

    # CC6.6 - Implements logical access security measures over external infrastructure
    # SSH hardening: root login restricted, strong ciphers
    sshd_config = read_file_safe("/etc/ssh/sshd_config")
    if sshd_config:
        permit_root = "yes"
        for line in sshd_config.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("permitrootlogin"):
                parts = stripped.split(None, 1)
                if len(parts) > 1:
                    permit_root = parts[1].lower()
                break

        root_disabled = permit_root in ("no", "prohibit-password", "forced-commands-only")
        results.append(_r(
            cat,
            "Pass" if root_disabled else "Fail",
            "SOC 2 CC6.6: SSH root login restricted",
            severity="High",
            details=f"PermitRootLogin = {permit_root}",
            remediation=(
                "sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "
                "/etc/ssh/sshd_config && systemctl restart sshd"
            ),
            cross_references={
                "SOC2": "CC6.6", "NIST": "AC-6(2)", "CIS": "5.2.7",
                "STIG": "V-230296", "PCI-DSS": "8.2.1",
            },
        ))

    # CC6.7 - Restricts the transmission, movement, and removal of information
    # Indicator: encrypted transit (no insecure remote services)
    insecure_remote = []
    for unit in ("telnet.socket", "rsh.socket", "rlogin.socket", "rexec.socket"):
        if systemd_active(unit) == "active":
            insecure_remote.append(unit)

    results.append(_r(
        cat,
        "Pass" if not insecure_remote else "Fail",
        "SOC 2 CC6.7: No cleartext remote-access services",
        severity="Critical",
        details=f"Active insecure: {', '.join(insecure_remote) or 'none'}",
        remediation="systemctl disable --now <each-unit>",
        cross_references={
            "SOC2": "CC6.7", "NIST": "SC-8", "CIS": "2.2",
            "PCI-DSS": "4.2.1", "HIPAA": "164.312(e)(1)",
        },
    ))

    # CC6.8 - Implements controls to prevent or detect unauthorised software
    # Application allow-listing indicator
    fapolicyd_active = systemd_active("fapolicyd.service") == "active"
    selinux_enforcing = False
    apparmor_enforce_count = 0

    if os_info.mac_framework == "selinux":
        try:
            with open("/sys/fs/selinux/enforce", "r", encoding="ascii") as f:
                selinux_enforcing = f.read().strip() == "1"
        except OSError:
            pass

    if os_info.mac_framework == "apparmor" and command_available("aa-status"):
        rc, out, _ = run_command(["aa-status"])
        if rc == 0:
            m = re.search(r"(\d+)\s+profiles are in enforce mode", out)
            if m:
                apparmor_enforce_count = int(m.group(1))

    has_app_control = (
        fapolicyd_active or selinux_enforcing or apparmor_enforce_count > 0
    )

    results.append(_r(
        cat,
        "Pass" if has_app_control else "Warning",
        "SOC 2 CC6.8: Software execution controls active",
        severity="High",
        details=(
            f"fapolicyd: {fapolicyd_active}, "
            f"SELinux enforcing: {selinux_enforcing}, "
            f"AppArmor profiles in enforce: {apparmor_enforce_count}"
        ),
        remediation=(
            "Deploy application control via fapolicyd (RHEL family), "
            "AppArmor (Debian/Ubuntu), or strict SELinux policy."
        ),
        cross_references={
            "SOC2": "CC6.8", "NIST": "CM-7(5)", "CIS": "1.6.1.3",
            "ISO27001": "A.8.7", "ACSC": "E8.1",
        },
    ))

    return results


# ===========================================================================
# CC7 - System Operations (Heavy Linux Coverage)
# ===========================================================================

def _check_cc7_system_operations(os_info) -> List[AuditResult]:
    cat = "SOC 2 CC7 - System Operations"
    results: List[AuditResult] = []

    # CC7.1 - Detection of vulnerabilities and security incidents
    ids_indicators = {
        "Suricata": command_available("suricata"),
        "Snort": command_available("snort"),
        "OSSEC/Wazuh": file_exists("/var/ossec/etc/ossec.conf"),
        "Falco": command_available("falco"),
        "auditd": systemd_active("auditd.service") == "active",
    }
    detected = [n for n, p in ids_indicators.items() if p]

    results.append(_r(
        cat,
        "Pass" if detected else "Fail",
        "SOC 2 CC7.1: Security event detection capability",
        severity="High",
        details=f"Detected: {', '.join(detected) or 'none'}",
        remediation=(
            "Deploy host- or network-based detection (Falco, Wazuh, Suricata) "
            "with comprehensive auditd rule coverage."
        ),
        cross_references={
            "SOC2": "CC7.1", "NIST": "SI-4", "ISO27001": "A.8.16",
            "PCI-DSS": "11.5.1", "HIPAA": "164.308(a)(5)(ii)(B)",
        },
    ))

    # CC7.2 - Monitors system components and performs integrity checks
    fim_tools = {
        "AIDE": command_available("aide") or file_exists("/etc/aide.conf"),
        "Tripwire": command_available("tripwire"),
        "OSSEC/Wazuh": file_exists("/var/ossec/etc/ossec.conf"),
    }
    detected_fim = [n for n, p in fim_tools.items() if p]

    results.append(_r(
        cat,
        "Pass" if detected_fim else "Fail",
        "SOC 2 CC7.2: File integrity monitoring deployed",
        severity="High",
        details=f"Detected: {', '.join(detected_fim) or 'none'}",
        remediation=remediation_for("aide"),
        cross_references={
            "SOC2": "CC7.2", "NIST": "SI-7", "ISO27001": "A.8.16",
            "PCI-DSS": "11.5.2", "HIPAA": "164.312(c)(1)",
        },
    ))

    # CC7.3 - Evaluates security events to determine response
    # Indicator: log retention configuration
    auditd_conf = read_file_safe("/etc/audit/auditd.conf")
    failure_action = ""
    for line in auditd_conf.splitlines():
        stripped = line.strip().lower()
        if stripped.startswith("disk_full_action"):
            failure_action = stripped.split("=", 1)[-1].strip() if "=" in stripped else stripped.split()[-1]
            break

    has_failure_action = failure_action in ("halt", "single", "syslog")
    results.append(_r(
        cat,
        "Pass" if has_failure_action else "Warning",
        "SOC 2 CC7.3: Audit failure action configured",
        severity="Medium",
        details=f"disk_full_action = {failure_action or 'unset'}",
        remediation=(
            "Edit /etc/audit/auditd.conf: disk_full_action = halt "
            "(or syslog if halting is not operationally acceptable)"
        ),
        cross_references={
            "SOC2": "CC7.3", "NIST": "AU-5", "CIS": "4.1.2.2",
            "STIG": "V-230398", "PCI-DSS": "10.2.1",
        },
    ))

    # CC7.4 - Identifies, tests, and approves system changes (technical: time sync)
    time_sync_active = (
        systemd_active("chronyd.service") == "active"
        or systemd_active("chrony.service") == "active"
        or systemd_active("ntpd.service") == "active"
        or systemd_active("systemd-timesyncd.service") == "active"
    )
    results.append(_r(
        cat,
        "Pass" if time_sync_active else "Fail",
        "SOC 2 CC7.4: Time synchronization for change traceability",
        severity="High",
        details=f"Time sync service active: {time_sync_active}",
        remediation=remediation_for("chrony"),
        cross_references={
            "SOC2": "CC7.4", "NIST": "AU-8(1)", "CIS": "2.1.1.1",
            "PCI-DSS": "10.6.1", "ISO27001": "A.8.17",
        },
    ))

    return results


# ===========================================================================
# CC8 - Change Management
# ===========================================================================

def _check_cc8_change_management(os_info) -> List[AuditResult]:
    cat = "SOC 2 CC8 - Change Management"
    results: List[AuditResult] = []

    # CC8.1 - Authorises, designs, develops, and tests changes
    # Indicator: audit watches on critical config paths
    audit_files = (
        "/etc/audit/audit.rules", "/etc/audit/rules.d/audit.rules",
    ) + tuple(list_directory("/etc/audit/rules.d", ".rules"))

    audit_content = ""
    for af in audit_files:
        audit_content += read_file_safe(af) + "\n"

    critical_paths = [
        "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers",
        "/etc/ssh/sshd_config",
    ]
    watched_count = sum(1 for p in critical_paths if f"-w {p}" in audit_content
                        or f"-w  {p}" in audit_content)

    results.append(_r(
        cat,
        "Pass" if watched_count >= 4 else "Warning" if watched_count > 0 else "Fail",
        f"SOC 2 CC8.1: Critical config files audited ({watched_count}/{len(critical_paths)})",
        severity="High",
        details=(
            f"{watched_count} of {len(critical_paths)} critical paths under "
            "audit watch"
        ),
        remediation=(
            "Create /etc/audit/rules.d/50-changemgmt.rules with watches on "
            "/etc/passwd, /etc/shadow, /etc/group, /etc/sudoers, "
            "/etc/ssh/sshd_config (-w <path> -p wa)."
        ),
        cross_references={
            "SOC2": "CC8.1", "NIST": "CM-3", "ISO27001": "A.8.32",
            "CIS": "4.1.3", "PCI-DSS": "6.5.2",
        },
    ))

    return results


# ===========================================================================
# CC9 - Risk Mitigation
# ===========================================================================

def _check_cc9_risk_mitigation(os_info) -> List[AuditResult]:
    cat = "SOC 2 CC9 - Risk Mitigation"
    results: List[AuditResult] = []

    # CC9.1 - Identifies, selects, and develops risk mitigation activities
    # Firewall posture
    firewall_active = (
        systemd_active("firewalld.service") == "active"
        or systemd_active("ufw.service") == "active"
        or systemd_active("nftables.service") == "active"
        or systemd_active("iptables.service") == "active"
    )
    results.append(_r(
        cat,
        "Pass" if firewall_active else "Fail",
        "SOC 2 CC9.1: Network firewall deployed and active",
        severity="Critical",
        details=f"Firewall service active: {firewall_active}",
        remediation=(
            "systemctl enable --now firewalld (RHEL) or "
            "systemctl enable --now ufw (Debian)"
        ),
        cross_references={
            "SOC2": "CC9.1", "NIST": "SC-7", "ISO27001": "A.8.20",
            "CIS": "3.4.1.2", "PCI-DSS": "1.2.6",
        },
    ))

    # CC9.2 - Assesses and manages risks associated with vendors and partners
    # Indicator: package signature verification configured
    if os_info.is_debian_family():
        gpg_check_files = list_directory("/etc/apt/sources.list.d", ".list")
        gpg_check_files.append("/etc/apt/sources.list")
        unsigned_repos = 0
        for f in gpg_check_files:
            content = read_file_safe(f)
            if "[trusted=yes" in content:
                unsigned_repos += 1
        results.append(_r(
            cat,
            "Pass" if unsigned_repos == 0 else "Warning",
            "SOC 2 CC9.2: Package repositories require GPG signatures",
            severity="High",
            details=f"Repositories with [trusted=yes]: {unsigned_repos}",
            remediation=(
                "Remove [trusted=yes] from /etc/apt/sources.list and *.list "
                "files; add proper GPG keys via apt-key or signed-by= directives."
            ),
            cross_references={
                "SOC2": "CC9.2", "NIST": "SI-7", "CIS": "1.2.1",
                "ISO27001": "A.8.19", "NSA": "PKG-1.1",
            },
        ))
    elif os_info.is_redhat_family():
        repos = list_directory("/etc/yum.repos.d", ".repo")
        nogpg_repos = 0
        for f in repos:
            content = read_file_safe(f)
            if re.search(r"^\s*gpgcheck\s*=\s*0", content, re.MULTILINE):
                nogpg_repos += 1
        results.append(_r(
            cat,
            "Pass" if nogpg_repos == 0 else "Warning",
            "SOC 2 CC9.2: Yum/dnf repositories enforce GPG checking",
            severity="High",
            details=f"Repos with gpgcheck=0: {nogpg_repos}",
            remediation=(
                "Edit each repo file in /etc/yum.repos.d/ to set gpgcheck=1"
            ),
            cross_references={
                "SOC2": "CC9.2", "NIST": "SI-7", "CIS": "1.2.2",
                "ISO27001": "A.8.19",
            },
        ))

    return results


# ===========================================================================
# A1 - Availability
# ===========================================================================

def _check_a1_availability(os_info) -> List[AuditResult]:
    cat = "SOC 2 A1 - Availability"
    results: List[AuditResult] = []

    # A1.1 - Performance and capacity (disk space monitoring)
    try:
        import shutil as _sh
        st = _sh.disk_usage("/var")
        free_pct = (st.free / st.total) * 100 if st.total else 100
        space_ok = free_pct > 10
    except OSError:
        free_pct = -1
        space_ok = True

    if free_pct >= 0:
        results.append(_r(
            cat,
            "Pass" if space_ok else "Fail",
            f"SOC 2 A1.1: /var disk usage healthy (free: {free_pct:.1f}%)",
            severity="High",
            details=f"/var free space: {free_pct:.1f}% (alert threshold: 10%)",
            remediation=(
                "Identify and clean up large old logs/data; expand /var if "
                "persistent shortage"
            ),
            cross_references={
                "SOC2": "A1.1", "NIST": "AU-4", "ISO27001": "A.8.6",
            },
        ))

    # A1.3 - Backup and recovery
    backup_tools = {
        "rsync": command_available("rsync"),
        "Borg": command_available("borg"),
        "Restic": command_available("restic"),
        "Duplicity": command_available("duplicity"),
        "Bacula": file_exists("/etc/bacula/bacula-fd.conf"),
    }
    detected = [n for n, p in backup_tools.items() if p]

    results.append(_r(
        cat,
        "Info" if detected else "Warning",
        "SOC 2 A1.3: Backup tooling present",
        severity="High",
        details=f"Detected: {', '.join(detected) or 'none'}",
        remediation=(
            "Install backup tooling and configure scheduled, off-site, "
            "encrypted backups with documented RTO/RPO. SOC 2 A1.3 requires "
            "evidence of regular successful backups and tested restoration."
        ),
        cross_references={
            "SOC2": "A1.3", "NIST": "CP-9", "ISO27001": "A.8.13",
            "PCI-DSS": "12.10.1", "HIPAA": "164.308(a)(7)(ii)(A)",
        },
    ))

    # systemd Restart= directives on critical services
    sshd_unit = first_existing(
        "/lib/systemd/system/sshd.service",
        "/usr/lib/systemd/system/sshd.service",
        "/lib/systemd/system/ssh.service",
        "/usr/lib/systemd/system/ssh.service",
    )
    if sshd_unit:
        content = read_file_safe(sshd_unit)
        has_restart = "Restart=" in content and "Restart=no" not in content
        results.append(_r(
            cat,
            "Info",
            f"SOC 2 A1.1: sshd has Restart= configured ({has_restart})",
            severity="Low",
            details=f"sshd unit file: {sshd_unit}, has Restart: {has_restart}",
            remediation=(
                "Override unit if needed: systemctl edit sshd  and add "
                "[Service]\\nRestart=on-failure"
            ),
            cross_references={
                "SOC2": "A1.1", "NIST": "CP-2", "ISO27001": "A.8.14",
            },
        ))

    return results


# ===========================================================================
# C1 - Confidentiality
# ===========================================================================

def _check_c1_confidentiality(os_info) -> List[AuditResult]:
    cat = "SOC 2 C1 - Confidentiality"
    results: List[AuditResult] = []

    # C1.1 - Identifies confidential information
    # Indicator: disk encryption available for confidential data
    luks_active = False
    if command_available("dmsetup"):
        rc, out, _ = run_command(["dmsetup", "ls", "--target=crypt"])
        if rc == 0 and out and "No devices found" not in out:
            luks_active = True

    results.append(_r(
        cat,
        "Pass" if luks_active else "Warning",
        "SOC 2 C1.1: Disk encryption (LUKS) active for confidential data",
        severity="High",
        details=f"LUKS encryption detected: {luks_active}",
        remediation=(
            "Encrypt volumes that hold confidential data with LUKS at "
            "provisioning time."
        ),
        cross_references={
            "SOC2": "C1.1", "NIST": "SC-28", "ISO27001": "A.8.10",
            "PCI-DSS": "3.5.1", "GDPR": "Art-32(1)(a)",
            "HIPAA": "164.312(a)(2)(iv)",
        },
    ))

    # C1.2 - Disposes of confidential information securely
    # Indicator: shred command available for secure deletion
    shred_available = command_available("shred")
    results.append(_r(
        cat,
        "Pass" if shred_available else "Warning",
        "SOC 2 C1.2: Secure file deletion utility available",
        severity="Medium",
        details=f"shred(1) available: {shred_available}",
        remediation=(
            "Install coreutils (always present on most distros). For SSDs, "
            "additionally use blkdiscard or vendor secure-erase utilities."
        ),
        cross_references={
            "SOC2": "C1.2", "NIST": "MP-6", "ISO27001": "A.8.10",
        },
    ))

    # File permissions on critical files
    critical_files = (
        ("/etc/shadow", (0o0, 0o400, 0o600, 0o640)),
        ("/etc/gshadow", (0o0, 0o400, 0o600, 0o640)),
    )
    perm_issues = []
    for path, accepted in critical_files:
        actual = file_mode(path)
        if actual is not None and actual not in accepted:
            perm_issues.append(f"{path}={oct(actual)}")

    results.append(_r(
        cat,
        "Pass" if not perm_issues else "Fail",
        "SOC 2 C1.1: Sensitive files have restrictive permissions",
        severity="High",
        details=f"Issues: {'; '.join(perm_issues) or 'none'}",
        remediation="chmod 0640 /etc/shadow /etc/gshadow",
        cross_references={
            "SOC2": "C1.1", "NIST": "AC-3", "ISO27001": "A.8.3",
            "CIS": "6.1.3", "STIG": "V-230323",
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
        results.extend(_check_cc4_monitoring(os_info))
        results.extend(_check_cc5_control_activities(os_info))
        results.extend(_check_cc6_logical_access(os_info))
        results.extend(_check_cc7_system_operations(os_info))
        results.extend(_check_cc8_change_management(os_info))
        results.extend(_check_cc9_risk_mitigation(os_info))
        results.extend(_check_a1_availability(os_info))
        results.extend(_check_c1_confidentiality(os_info))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled exception in SOC2 module")
        results.append(_r(
            "SOC2 - Error", "Error",
            f"SOC2 module encountered an unhandled exception: {exc!r}",
            severity="Medium", details=str(exc),
        ))

    return results



# ===========================================================================
# v3.1 EXPANSION - SOC 2 Comprehensive Trust Service Criteria
# ---------------------------------------------------------------------------
# Adds:
#   - CC1 Control Environment (governance indicators)
#   - CC2 Communication and Information
#   - CC3 Risk Assessment (vulnerability scanner, asset inventory)
#   - CC6 Logical Access (extended depth)
#   - CC7 System Operations (extended depth)
#   - CC8 Change Management (FIM, audit)
#   - PI Processing Integrity (data validation indicators)
#   - P Privacy (data handling indicators)
# ===========================================================================


def _check_cc1_control_environment(os_info) -> List[AuditResult]:
    """CC1 - Control environment (governance technical indicators)."""
    results: List[AuditResult] = []
    cat = "SOC2 - CC1 Control Environment"

    # Documentation indicators - login banner with policies
    issue_net = read_file_safe("/etc/issue.net")
    motd = read_file_safe("/etc/motd")
    has_governance_text = (
        len(issue_net) > 100 or len(motd) > 100
    )
    results.append(_r(
        cat, "Pass" if has_governance_text else "Warning",
        "CC1.4: System usage policies communicated via login banner",
        severity="Medium",
        details=(
            f"/etc/issue.net length: {len(issue_net)}, "
            f"/etc/motd length: {len(motd)}"
        ),
        remediation=(
            "Configure /etc/issue.net with usage policy excerpt, contact info, "
            "and unauthorized access warning."
        ),
        cross_references={
            "SOC2": "CC1.4", "NIST": "AC-8", "ISO27001": "A.5.1",
        },
    ))

    # Configuration management agent (governance through automation)
    cm_agents = [
        command_available("ansible"),
        command_available("puppet"),
        file_exists("/etc/salt/minion"),
        command_available("chef-client"),
    ]
    cm_present = any(cm_agents)
    results.append(_r(
        cat, "Info",
        "CC1.5: Configuration management agent for governance enforcement",
        severity="Informational",
        details=f"CM agent detected: {cm_present}",
        remediation=(
            "Deploy Ansible (agentless) or Puppet/Salt/Chef for "
            "documented, version-controlled configuration governance."
        ),
        cross_references={
            "SOC2": "CC1.5", "NIST": "CM-2",
        },
    ))

    return results


def _check_cc2_communication(os_info) -> List[AuditResult]:
    """CC2 - Communication and information."""
    results: List[AuditResult] = []
    cat = "SOC2 - CC2 Communication"

    # Mail relay configured for system notifications
    mail_present = (
        file_exists("/etc/postfix/main.cf") or
        file_exists("/etc/aliases") or
        command_available("sendmail")
    )
    results.append(_r(
        cat, "Pass" if mail_present else "Warning",
        "CC2.2: Mail relay capability for system notifications",
        severity="Medium",
        details=f"Mail infrastructure detected: {mail_present}",
        remediation=(
            "Install Postfix as null-client: apt-get install -y postfix. "
            "Configure relay to corporate SMTP for cron/audit notifications."
        ),
        cross_references={
            "SOC2": "CC2.2", "NIST": "AU-5(2)",
        },
    ))

    # Root mail aliased to operations team
    aliases_content = read_file_safe("/etc/aliases")
    root_aliased = bool(re.search(r"^\s*root\s*:", aliases_content, re.MULTILINE))
    results.append(_r(
        cat, "Pass" if root_aliased else "Warning",
        "CC2.2: root mail aliased to operations team",
        severity="Low",
        details=f"root: alias in /etc/aliases: {root_aliased}",
        remediation=(
            "In /etc/aliases add: root: ops@example.com, then run newaliases"
        ),
        cross_references={
            "SOC2": "CC2.2", "NIST": "AU-5(2)",
        },
    ))

    return results


def _check_cc3_risk_assessment(os_info) -> List[AuditResult]:
    """CC3 - Risk assessment (technical indicators)."""
    results: List[AuditResult] = []
    cat = "SOC2 - CC3 Risk Assessment"

    # Vulnerability scanner deployed
    scanners = {
        "openscap": command_available("oscap"),
        "lynis": command_available("lynis"),
        "openvas": command_available("openvas-cli"),
        "nessus": file_exists("/opt/nessus_agent/sbin/nessuscli"),
        "qualys": file_exists("/opt/qualys/cloud-agent/bin/qualys-cloud-agent.sh"),
        "trivy": command_available("trivy"),
        "grype": command_available("grype"),
    }
    detected = [k for k, v in scanners.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Fail",
        f"CC3.2: Vulnerability identification tool deployed ({len(detected)} found)",
        severity="High",
        details=f"Scanners: {detected or 'none'}",
        remediation=(
            "Install vulnerability scanner: dnf install -y openscap-scanner "
            "scap-security-guide (RHEL) or apt-get install -y lynis (Debian)."
        ),
        cross_references={
            "SOC2": "CC3.2", "NIST": "RA-5", "ISO27001": "A.5.34",
        },
    ))

    # Asset inventory capability
    pkg_inv = (
        command_available("dpkg") or
        command_available("rpm") or
        command_available("pacman") or
        command_available("apk")
    )
    results.append(_r(
        cat, "Pass" if pkg_inv else "Fail",
        "CC3.2: Software asset inventory capability",
        severity="Medium",
        details=f"Package manager available: {pkg_inv}",
        remediation=(
            "Use package manager to enumerate inventory: "
            "dpkg --list (Debian) or rpm -qa (RHEL family). "
            "Schedule periodic export to CMDB."
        ),
        cross_references={
            "SOC2": "CC3.2", "NIST": "CM-8",
        },
    ))

    # Network exposure assessment (listening services)
    listening = collect_listening_ports()
    results.append(_r(
        cat, "Info",
        f"CC3.2: Listening port inventory ({len(listening)} ports)",
        severity="Informational",
        details=f"Listening TCP ports: {sorted(listening)[:20]}",
        remediation=(
            "Periodically review listening services: ss -tuln. "
            "Disable unnecessary services."
        ),
        cross_references={
            "SOC2": "CC3.2", "NIST": "CM-7", "CIS": "2.2.1",
        },
    ))

    return results


def _check_cc6_logical_access_extended(os_info) -> List[AuditResult]:
    """CC6 - Logical access controls (extended depth)."""
    results: List[AuditResult] = []
    cat = "SOC2 - CC6 Logical Access (Extended)"

    # CC6.1 SSH protocol version (must be 2)
    sshd_config = read_file_safe("/etc/ssh/sshd_config")
    if sshd_config:
        proto2 = True
        for line in sshd_config.splitlines():
            s = line.strip()
            if s.lower().startswith("protocol "):
                proto2 = "2" in s
                break
        results.append(_r(
            cat, "Pass" if proto2 else "Fail",
            "CC6.1: SSH protocol version 2 enforced (no protocol 1)",
            severity="Critical" if not proto2 else "High",
            details=f"SSH protocol 2 enforced: {proto2}",
            remediation=(
                "Modern OpenSSH (>=7) defaults to protocol 2. "
                "Verify no Protocol 1 in /etc/ssh/sshd_config."
            ),
            cross_references={
                "SOC2": "CC6.1", "NIST": "SC-13", "STIG": "V-230245",
            },
        ))

        # SSH MaxAuthTries
        max_auth_match = re.search(
            r"^\s*MaxAuthTries\s+(\d+)", sshd_config, re.MULTILINE
        )
        max_auth = int(max_auth_match.group(1)) if max_auth_match else 6
        results.append(_r(
            cat, "Pass" if max_auth <= 4 else "Warning",
            f"CC6.1: SSH MaxAuthTries <= 4 (current: {max_auth})",
            severity="Medium",
            details=f"MaxAuthTries: {max_auth}",
            remediation="In /etc/ssh/sshd_config: MaxAuthTries 4",
            cross_references={
                "SOC2": "CC6.1", "NIST": "AC-7", "CIS": "5.2.5",
                "STIG": "V-230244",
            },
        ))

        # ClientAliveInterval (idle timeout)
        cai_match = re.search(
            r"^\s*ClientAliveInterval\s+(\d+)", sshd_config, re.MULTILINE
        )
        cai = int(cai_match.group(1)) if cai_match else 0
        cai_ok = 0 < cai <= 900
        results.append(_r(
            cat, "Pass" if cai_ok else "Fail",
            f"CC6.1: SSH session idle timeout configured (<=900s)",
            severity="Medium",
            details=f"ClientAliveInterval: {cai} seconds",
            remediation=(
                "In /etc/ssh/sshd_config: "
                "ClientAliveInterval 900 and ClientAliveCountMax 0"
            ),
            cross_references={
                "SOC2": "CC6.1", "NIST": "AC-12", "CIS": "5.2.16",
                "STIG": "V-230244",
            },
        ))

    # CC6.2 Account password aging
    login_defs = read_file_safe("/etc/login.defs")
    pass_max_match = re.search(
        r"^\s*PASS_MAX_DAYS\s+(\d+)", login_defs, re.MULTILINE
    )
    pass_max = int(pass_max_match.group(1)) if pass_max_match else 99999
    pass_max_ok = 0 < pass_max <= 90
    results.append(_r(
        cat, "Pass" if pass_max_ok else "Fail",
        f"CC6.2: Password maximum age <=90 days (current: {pass_max})",
        severity="Medium",
        details=f"PASS_MAX_DAYS: {pass_max}",
        remediation=(
            "In /etc/login.defs: PASS_MAX_DAYS 90. "
            "Apply to existing users: chage --maxdays 90 <user>."
        ),
        cross_references={
            "SOC2": "CC6.2", "NIST": "IA-5(1)", "CIS": "5.4.1.1",
            "STIG": "V-230367",
        },
    ))

    # CC6.3 PAM password complexity
    pwquality_conf = read_file_safe("/etc/security/pwquality.conf")
    if pwquality_conf:
        minlen_match = re.search(
            r"^\s*minlen\s*=\s*(\d+)", pwquality_conf, re.MULTILINE
        )
        minlen = int(minlen_match.group(1)) if minlen_match else 0
        complexity_ok = minlen >= 14
        results.append(_r(
            cat, "Pass" if complexity_ok else "Warning",
            f"CC6.3: Password minimum length >=14 (current: {minlen})",
            severity="Medium",
            details=f"pwquality minlen: {minlen}",
            remediation=(
                "In /etc/security/pwquality.conf: "
                "minlen = 14, dcredit = -1, ucredit = -1, "
                "ocredit = -1, lcredit = -1"
            ),
            cross_references={
                "SOC2": "CC6.3", "NIST": "IA-5(1)(a)", "CIS": "5.4.1.2",
                "PCI-DSS": "8.3.6",
            },
        ))

    # CC6.6 Network segmentation indicators
    fw_active = (
        systemd_active("firewalld.service") == "active" or
        systemd_active("ufw.service") == "active" or
        systemd_active("nftables.service") == "active" or
        systemd_active("iptables.service") == "active"
    )
    results.append(_r(
        cat, "Pass" if fw_active else "Fail",
        "CC6.6: Network access controls enforced via host firewall",
        severity="High",
        details=f"Firewall service active: {fw_active}",
        remediation=(
            "systemctl enable --now firewalld (RHEL) or "
            "ufw enable (Debian/Ubuntu) or "
            "systemctl enable --now nftables"
        ),
        cross_references={
            "SOC2": "CC6.6", "NIST": "SC-7", "CIS": "3.4",
            "PCI-DSS": "1.2",
        },
    ))

    # CC6.7 PAM faillock for account lockout
    pam_files = ["/etc/pam.d/system-auth", "/etc/pam.d/common-auth",
                 "/etc/pam.d/password-auth"]
    faillock_present = False
    for f in pam_files:
        c = read_file_safe(f)
        if c and ("pam_faillock.so" in c or "pam_tally2.so" in c):
            faillock_present = True
            break

    results.append(_r(
        cat, "Pass" if faillock_present else "Fail",
        "CC6.7: Account lockout after failed login attempts (PAM faillock)",
        severity="High",
        details=f"PAM faillock/tally2 module loaded: {faillock_present}",
        remediation=(
            "Configure pam_faillock in /etc/pam.d/system-auth: "
            "auth required pam_faillock.so preauth deny=5 unlock_time=900"
        ),
        cross_references={
            "SOC2": "CC6.7", "NIST": "AC-7", "CIS": "5.4.2",
            "PCI-DSS": "8.3.4",
        },
    ))

    return results


def _check_cc7_system_operations_extended(os_info) -> List[AuditResult]:
    """CC7 - System operations (extended depth)."""
    results: List[AuditResult] = []
    cat = "SOC2 - CC7 System Operations (Extended)"

    # CC7.1 Vulnerability monitoring (continuous)
    auto_patch = (
        systemd_active("unattended-upgrades.service") == "active" or
        systemd_active("dnf-automatic-install.timer") == "active" or
        systemd_active("dnf-automatic.timer") == "active"
    )
    results.append(_r(
        cat, "Pass" if auto_patch else "Warning",
        "CC7.1: Automatic patch installation configured",
        severity="High",
        details=f"Auto-patch active: {auto_patch}",
        remediation=(
            "Debian: apt-get install -y unattended-upgrades && "
            "dpkg-reconfigure unattended-upgrades. "
            "RHEL: dnf install -y dnf-automatic && "
            "systemctl enable --now dnf-automatic-install.timer."
        ),
        cross_references={
            "SOC2": "CC7.1", "NIST": "SI-2(5)", "PCI-DSS": "6.3.3",
        },
    ))

    # CC7.2 System monitoring infrastructure
    monitoring_tools = {
        "node_exporter": (
            command_available("node_exporter") or
            file_exists("/etc/systemd/system/node_exporter.service")
        ),
        "prometheus": file_exists("/etc/prometheus/prometheus.yml"),
        "telegraf": file_exists("/etc/telegraf/telegraf.conf"),
        "datadog": file_exists("/etc/datadog-agent/datadog.yaml"),
        "newrelic": file_exists("/etc/newrelic-infra.yml"),
        "zabbix-agent": (
            file_exists("/etc/zabbix/zabbix_agentd.conf") or
            file_exists("/etc/zabbix/zabbix_agent2.conf")
        ),
        "nagios": directory_exists("/usr/local/nagios"),
        "collectd": file_exists("/etc/collectd/collectd.conf"),
    }
    detected_mon = [k for k, v in monitoring_tools.items() if v]
    results.append(_r(
        cat, "Pass" if detected_mon else "Warning",
        f"CC7.2: System monitoring agent ({len(detected_mon)} found)",
        severity="High",
        details=f"Detected: {detected_mon}",
        remediation=(
            "Deploy monitoring agent: Prometheus node_exporter (open source), "
            "or Datadog/NewRelic/Zabbix (enterprise)."
        ),
        cross_references={
            "SOC2": "CC7.2", "NIST": "SI-4", "ISO27001": "A.8.16",
        },
    ))

    # CC7.3 Anomaly detection (HIDS)
    hids_tools = {
        "wazuh-agent": file_exists("/var/ossec/etc/ossec.conf"),
        "falco": command_available("falco"),
        "aide": command_available("aide"),
        "samhain": command_available("samhain"),
    }
    detected_hids = [k for k, v in hids_tools.items() if v]
    results.append(_r(
        cat, "Pass" if detected_hids else "Fail",
        f"CC7.3: Anomaly/intrusion detection ({len(detected_hids)} found)",
        severity="High",
        details=f"HIDS: {detected_hids}",
        remediation=(
            "Deploy Wazuh agent: curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/... "
            "or Falco for runtime threat detection."
        ),
        cross_references={
            "SOC2": "CC7.3", "NIST": "SI-4(2)", "PCI-DSS": "11.5.1",
        },
    ))

    # CC7.4 Incident response capability
    log_forwarding = False
    rsyslog_d = list_directory("/etc/rsyslog.d", suffix=".conf")
    for f in rsyslog_d + ["/etc/rsyslog.conf"]:
        if f == "/etc/rsyslog.conf":
            c = read_file_safe(f)
        else:
            c = read_file_safe(os.path.join("/etc/rsyslog.d", f))
        if c and ("@@" in c or "omfwd" in c):
            log_forwarding = True
            break

    results.append(_r(
        cat, "Pass" if log_forwarding else "Warning",
        "CC7.4: Logs forwarded to centralized SIEM for incident analysis",
        severity="High",
        details=f"Remote forwarding configured: {log_forwarding}",
        remediation=(
            "/etc/rsyslog.d/50-remote.conf: *.* @@siem.internal:6514"
        ),
        cross_references={
            "SOC2": "CC7.4", "NIST": "IR-4", "PCI-DSS": "10.5",
        },
    ))

    return results


def _check_cc8_change_management(os_info) -> List[AuditResult]:
    """CC8 - Change management (file integrity)."""
    results: List[AuditResult] = []
    cat = "SOC2 - CC8 Change Management"

    # File integrity monitoring
    fim_tools = {
        "aide": command_available("aide"),
        "tripwire": command_available("tripwire"),
        "wazuh-fim": file_exists("/var/ossec/etc/ossec.conf"),
        "samhain": command_available("samhain"),
    }
    detected = [k for k, v in fim_tools.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Fail",
        f"CC8.1: File integrity monitoring ({len(detected)} found)",
        severity="High",
        details=f"FIM tools: {detected}",
        remediation=remediation_for("aide"),
        cross_references={
            "SOC2": "CC8.1", "NIST": "SI-7", "PCI-DSS": "11.5.2",
        },
    ))

    # auditd capturing /etc changes
    audit_rules = read_file_safe("/etc/audit/audit.rules")
    rules_d = list_directory("/etc/audit/rules.d", suffix=".rules")
    for rf in rules_d:
        audit_rules += "\n" + read_file_safe(os.path.join("/etc/audit/rules.d", rf))

    etc_audited = "/etc" in audit_rules and ("-w /etc" in audit_rules or "watch=/etc" in audit_rules)
    results.append(_r(
        cat, "Pass" if etc_audited else "Warning",
        "CC8.1: /etc directory changes audited via auditd",
        severity="Medium",
        details=f"/etc watch rules in auditd: {etc_audited}",
        remediation=(
            "Add to /etc/audit/rules.d/30-config.rules: "
            "-w /etc/passwd -p wa -k identity (per-file watches recommended)"
        ),
        cross_references={
            "SOC2": "CC8.1", "NIST": "AU-2", "CIS": "4.1.3",
        },
    ))

    return results


def _check_pi_processing_integrity(os_info) -> List[AuditResult]:
    """PI - Processing Integrity Trust Service Criterion."""
    results: List[AuditResult] = []
    cat = "SOC2 - PI Processing Integrity"

    # PI1.1 Data quality - clock sync (essential for ordering)
    clock_sync = (
        systemd_active("chronyd.service") == "active" or
        systemd_active("chrony.service") == "active" or
        systemd_active("ntp.service") == "active" or
        systemd_active("systemd-timesyncd.service") == "active"
    )
    results.append(_r(
        cat, "Pass" if clock_sync else "Fail",
        "PI1.1: Time synchronization for processing event ordering",
        severity="High",
        details=f"Clock sync active: {clock_sync}",
        remediation=remediation_for("chrony"),
        cross_references={
            "SOC2": "PI1.1", "NIST": "AU-8(1)", "PCI-DSS": "10.6",
        },
    ))

    # PI1.4 Output processing - audit log capacity
    rc, out, _ = run_command(["df", "-BM", "/var/log"], timeout=3.0)
    log_space_ok = True
    if rc == 0:
        for line in out.splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 5:
                use_pct = fields[4].rstrip("%")
                try:
                    if int(use_pct) > 85:
                        log_space_ok = False
                except ValueError:
                    pass

    results.append(_r(
        cat, "Pass" if log_space_ok else "Warning",
        "PI1.4: Audit log filesystem has sufficient capacity (<=85% used)",
        severity="High",
        details="/var/log filesystem usage check",
        remediation="Monitor /var/log via Prometheus/Nagios. Alert at 80%.",
        cross_references={
            "SOC2": "PI1.4", "NIST": "AU-4", "PCI-DSS": "10.5.1",
        },
    ))

    return results


def _check_p_privacy(os_info) -> List[AuditResult]:
    """P - Privacy Trust Service Criterion."""
    results: List[AuditResult] = []
    cat = "SOC2 - P Privacy"

    # P3.1 Notice and consent - banner presence
    issue = read_file_safe("/etc/issue.net")
    privacy_banner = "privacy" in issue.lower() or "monitoring" in issue.lower()
    results.append(_r(
        cat, "Pass" if privacy_banner else "Warning",
        "P3.1: Privacy notice in login banner",
        severity="Medium",
        details=f"Privacy/monitoring language in /etc/issue.net: {privacy_banner}",
        remediation=(
            "Update /etc/issue.net with privacy notice: 'This system may "
            "process personal data. Activity is monitored and logged for "
            "security purposes.'"
        ),
        cross_references={
            "SOC2": "P3.1", "GDPR": "Art-13", "NIST": "AC-8",
        },
    ))

    # P4.1 Collection limitation - log redaction tooling
    rsyslog_d = list_directory("/etc/rsyslog.d", suffix=".conf")
    has_anonymization = False
    for f in rsyslog_d:
        c = read_file_safe(os.path.join("/etc/rsyslog.d", f))
        if "mmanon" in c:
            has_anonymization = True
            break

    results.append(_r(
        cat, "Info",
        f"P4.1: Log anonymization tooling configured: {has_anonymization}",
        severity="Informational",
        details=f"rsyslog mmanon module: {has_anonymization}",
        remediation=(
            "rsyslog mmanon module redacts IPs from forwarded logs. "
            "Useful for log forwarding to non-EU destinations."
        ),
        cross_references={
            "SOC2": "P4.1", "GDPR": "Art-25", "ISO27001": "A.8.11",
        },
    ))

    # P5.1 Use, retention, and disposal - log retention config
    auditd_conf = read_file_safe("/etc/audit/auditd.conf")
    num_logs_match = re.search(r"^\s*num_logs\s*=\s*(\d+)", auditd_conf, re.MULTILINE)
    num_logs = int(num_logs_match.group(1)) if num_logs_match else 0
    retention_bounded = num_logs > 0
    results.append(_r(
        cat, "Pass" if retention_bounded else "Warning",
        "P5.1: Audit log retention bounded by configuration",
        severity="Medium",
        details=f"auditd num_logs: {num_logs}",
        remediation=(
            "In /etc/audit/auditd.conf: num_logs = 10, "
            "max_log_file = 50 (MB)"
        ),
        cross_references={
            "SOC2": "P5.1", "GDPR": "Art-5(1)(e)", "NIST": "AU-11",
        },
    ))

    return results


# Save reference to original run_checks
_original_run_checks_soc2 = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the expanded SOC 2 module.

    Combines baseline (CC4-CC9, A1, C1) with v3.1 expansion adding
    CC1, CC2, CC3 trust service criteria, deeper CC6/CC7/CC8, plus
    PI Processing Integrity and P Privacy categories.
    """
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_soc2(shared_data)

    os_info = shared_data.get("v3_os_info")
    if os_info is None:
        os_info = os_detection.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        results.extend(_check_cc1_control_environment(os_info))
        results.extend(_check_cc2_communication(os_info))
        results.extend(_check_cc3_risk_assessment(os_info))
        results.extend(_check_cc6_logical_access_extended(os_info))
        results.extend(_check_cc7_system_operations_extended(os_info))
        results.extend(_check_cc8_change_management(os_info))
        results.extend(_check_pi_processing_integrity(os_info))
        results.extend(_check_p_privacy(os_info))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled exception in SOC2 v3.1 expansion")
        results.append(_r(
            "SOC2 - Error", "Error",
            f"SOC2 v3.1 expansion exception: {exc!r}",
            severity="Medium", details=str(exc),
        ))

    return results




# ===========================================================================
# v3.3 EXPANSION - SOC 2 Trust Services Criteria Deep Coverage
# ---------------------------------------------------------------------------
# Adds depth across CC1-CC9, A1, C1, PI, P trust criteria.
# ===========================================================================


def _check_soc2_cc1_control_environment_v33(os_info) -> List[AuditResult]:
    """CC1 - Commitment to integrity, governance, and accountability."""
    results: List[AuditResult] = []
    cat = "SOC2 CC1 v3.3"

    # CC1.1 - Code of conduct indicators (login banners, MOTD, /etc/issue)
    issue = read_file_safe("/etc/issue")
    issue_net = read_file_safe("/etc/issue.net")
    motd = read_file_safe("/etc/motd")

    aup_indicators = ["authorized", "monitor", "notice", "policy",
                       "unauthorized", "consent"]
    issue_has_aup = any(k in issue.lower() for k in aup_indicators)
    issue_net_has_aup = any(k in issue_net.lower() for k in aup_indicators)
    motd_has_aup = any(k in motd.lower() for k in aup_indicators)

    aup_count = sum([issue_has_aup, issue_net_has_aup, motd_has_aup])
    results.append(_r(
        cat, "Pass" if aup_count >= 2 else "Warning",
        f"SOC2-CC1.1: Acceptable use banner indicators ({aup_count}/3)",
        severity="Medium",
        details=(
            f"/etc/issue: {issue_has_aup}, /etc/issue.net: {issue_net_has_aup}, "
            f"/etc/motd: {motd_has_aup}"
        ),
        remediation=(
            "Set authorized-use-only legal banner in /etc/issue, /etc/issue.net, "
            "and /etc/motd. Required for many compliance frameworks."
        ),
        cross_references={
            "SOC2": "CC1.1", "NIST": "AC-8", "STIG": "V-230225",
        },
    ))

    # CC1.4 - Personnel competence: sudo group / wheel group documented
    sudo_group = read_file_safe("/etc/group")
    sudo_users = []
    wheel_users = []
    for line in sudo_group.splitlines():
        if line.startswith("sudo:") or line.startswith("wheel:"):
            parts = line.split(":")
            if len(parts) >= 4 and parts[3]:
                if line.startswith("sudo:"):
                    sudo_users = parts[3].split(",")
                else:
                    wheel_users = parts[3].split(",")
    privileged_users = list(set(sudo_users + wheel_users))
    privileged_users = [u for u in privileged_users if u]

    results.append(_r(
        cat, "Info",
        f"SOC2-CC1.4: Privileged group members ({len(privileged_users)})",
        severity="Informational",
        details=f"sudo+wheel members: {privileged_users[:10]}",
        remediation=(
            "Document privileged user assignments. Review quarterly. "
            "Maintain access matrix as evidence."
        ),
        cross_references={
            "SOC2": "CC1.4", "NIST": "AC-6, AC-2",
        },
    ))

    return results


def _check_soc2_cc2_communication_v33(os_info) -> List[AuditResult]:
    """CC2 - Communication and information."""
    results: List[AuditResult] = []
    cat = "SOC2 CC2 v3.3"

    # CC2.1 - Information for internal control: log forwarding to SIEM
    siem_indicators = []
    if directory_exists("/etc/rsyslog.d"):
        for f in list_directory("/etc/rsyslog.d"):
            if not f.endswith(".conf"):
                continue
            c = read_file_safe(os.path.join("/etc/rsyslog.d", f))
            if "@@" in c or "omfwd" in c or "omrelp" in c:
                siem_indicators.append(f)
    rsy_main = read_file_safe("/etc/rsyslog.conf")
    has_main_forward = "@@" in rsy_main or "omfwd" in rsy_main

    results.append(_r(
        cat, "Pass" if (siem_indicators or has_main_forward) else "Warning",
        f"SOC2-CC2.1: Log forwarding to SIEM/aggregator",
        severity="High",
        details=(
            f"rsyslog.d forward configs: {len(siem_indicators)}, "
            f"main config has forwarding: {has_main_forward}"
        ),
        remediation=(
            "Configure /etc/rsyslog.d/50-remote.conf to forward to SIEM: "
            "*.* @@logserver.example.com:6514"
        ),
        cross_references={
            "SOC2": "CC2.1", "NIST": "AU-6(3)",
        },
    ))

    # CC2.3 - External communication: outbound TLS for transmission
    tls_packages = []
    for cmd in ["openssl", "gnutls-cli", "curl", "wget"]:
        if command_available(cmd):
            tls_packages.append(cmd)
    results.append(_r(
        cat, "Pass" if tls_packages else "Warning",
        f"SOC2-CC2.3: TLS-capable utilities present ({len(tls_packages)})",
        severity="Medium",
        details=f"Available: {tls_packages}",
        cross_references={
            "SOC2": "CC2.3", "NIST": "SC-13",
        },
    ))

    return results


def _check_soc2_cc4_monitoring_v33(os_info) -> List[AuditResult]:
    """CC4 - Monitoring activities deep coverage."""
    results: List[AuditResult] = []
    cat = "SOC2 CC4 v3.3"

    # CC4.1 - Ongoing/separate evaluations: automated audit framework
    audit_active = systemd_active("auditd.service") == "active"
    results.append(_r(
        cat, "Pass" if audit_active else "Fail",
        f"SOC2-CC4.1: Continuous monitoring (auditd) active: {audit_active}",
        severity="High",
        details=f"auditd active: {audit_active}",
        remediation=remediation_for("auditd"),
        cross_references={
            "SOC2": "CC4.1", "NIST": "CA-7",
        },
    ))

    # CC4.2 - Evaluation findings: vulnerability scanner
    scanners = ["lynis", "oscap", "trivy", "nuclei"]
    detected = [s for s in scanners if command_available(s)]
    results.append(_r(
        cat, "Pass" if detected else "Warning",
        f"SOC2-CC4.2: Vulnerability evaluation tools ({len(detected)})",
        severity="High",
        details=f"Detected: {detected}",
        remediation=(
            "Install Lynis: apt-get install -y lynis. Schedule quarterly scans."
        ),
        cross_references={
            "SOC2": "CC4.2", "NIST": "RA-5, CA-7",
        },
    ))

    # CC4.1 - File integrity monitoring (separate from auditd)
    fim_indicators = {
        "AIDE": file_exists("/var/lib/aide/aide.db") or
                file_exists("/var/lib/aide/aide.db.gz") or
                command_available("aide"),
        "Tripwire": command_available("tripwire") or
                    file_exists("/etc/tripwire/tw.cfg"),
        "Wazuh": file_exists("/var/ossec/etc/ossec.conf"),
        "Samhain": command_available("samhain"),
    }
    detected_fim = [k for k, v in fim_indicators.items() if v]
    results.append(_r(
        cat, "Pass" if detected_fim else "Warning",
        f"SOC2-CC4.1b: File integrity monitoring ({len(detected_fim)})",
        severity="High",
        details=f"Detected: {detected_fim}",
        remediation=remediation_for("aide"),
        cross_references={
            "SOC2": "CC4.1", "NIST": "SI-7",
        },
    ))

    return results


def _check_soc2_cc5_control_activities_v33(os_info) -> List[AuditResult]:
    """CC5 - Control activities (technology-related)."""
    results: List[AuditResult] = []
    cat = "SOC2 CC5 v3.3"

    # CC5.2 - General controls over technology: configuration management
    cm_tools = {
        "ansible": command_available("ansible"),
        "puppet": command_available("puppet"),
        "chef": command_available("chef-client"),
        "salt": command_available("salt-minion") or command_available("salt-call"),
        "cfengine": command_available("cf-agent"),
    }
    detected_cm = [k for k, v in cm_tools.items() if v]
    results.append(_r(
        cat, "Info",
        f"SOC2-CC5.2: Configuration management agents ({len(detected_cm)})",
        severity="Informational",
        details=f"Detected: {detected_cm or 'none'}",
        remediation=(
            "Use IaC for config management: Ansible/Puppet/Salt for "
            "consistent, auditable configurations"
        ),
        cross_references={
            "SOC2": "CC5.2", "NIST": "CM-2, CM-6",
        },
    ))

    # CC5.3 - Policies/procedures: PAM stack present
    pam_dir = "/etc/pam.d"
    pam_files = list_directory(pam_dir) if directory_exists(pam_dir) else []
    results.append(_r(
        cat, "Pass" if len(pam_files) >= 10 else "Warning",
        f"SOC2-CC5.3: PAM policy modules ({len(pam_files)})",
        severity="Medium",
        details=f"/etc/pam.d files: {len(pam_files)}",
        cross_references={
            "SOC2": "CC5.3", "NIST": "AC-3",
        },
    ))

    return results


def _check_soc2_cc6_logical_access_v33(os_info) -> List[AuditResult]:
    """CC6 - Logical and physical access deep coverage."""
    results: List[AuditResult] = []
    cat = "SOC2 CC6 v3.3"

    # CC6.1 - Logical access security software (PAM modules)
    pam_files_to_check = ["/etc/pam.d/system-auth", "/etc/pam.d/common-auth",
                           "/etc/pam.d/password-auth"]
    pam_security_modules = ["pam_faillock", "pam_pwquality", "pam_pwhistory",
                             "pam_unix", "pam_tally2"]
    detected = set()
    for pf in pam_files_to_check:
        c = read_file_safe(pf)
        for m in pam_security_modules:
            if m in c:
                detected.add(m)
    results.append(_r(
        cat, "Pass" if len(detected) >= 3 else "Warning",
        f"SOC2-CC6.1: PAM security modules configured ({len(detected)})",
        severity="High",
        details=f"Detected: {sorted(detected)}",
        remediation=(
            "Install: apt-get install -y libpam-pwquality; "
            "configure pam_pwquality.so + pam_faillock.so + pam_pwhistory.so"
        ),
        cross_references={
            "SOC2": "CC6.1", "NIST": "IA-5(1)",
        },
    ))

    # CC6.2 - Authorized user access management
    # /etc/login.defs PASS_MAX_DAYS
    login_defs = read_file_safe("/etc/login.defs")
    max_days_match = re.search(
        r"^\s*PASS_MAX_DAYS\s+(\d+)", login_defs, re.MULTILINE
    )
    max_days = int(max_days_match.group(1)) if max_days_match else 99999
    days_ok = max_days <= 90
    results.append(_r(
        cat, "Pass" if days_ok else "Warning",
        f"SOC2-CC6.2: PASS_MAX_DAYS <= 90 ({max_days})",
        severity="Medium",
        details=f"PASS_MAX_DAYS = {max_days}",
        remediation=(
            "In /etc/login.defs: PASS_MAX_DAYS 90"
        ),
        cross_references={
            "SOC2": "CC6.2", "NIST": "IA-5(1)(d)",
        },
    ))

    # CC6.3 - Network access boundary protection: firewall enforced
    nft_present = command_available("nft")
    iptables_present = command_available("iptables")
    ufw_active = systemd_active("ufw.service") == "active"
    firewalld_active = systemd_active("firewalld.service") == "active"
    fw_active = ufw_active or firewalld_active
    if not fw_active and (nft_present or iptables_present):
        # Check for any rules
        rc, out, _ = run_command(["nft", "list", "ruleset"], timeout=3.0)
        if rc == 0 and out and "chain" in out:
            fw_active = True
    results.append(_r(
        cat, "Pass" if fw_active else "Fail",
        f"SOC2-CC6.3: Network firewall active: {fw_active}",
        severity="Critical",
        details=(
            f"ufw: {ufw_active}, firewalld: {firewalld_active}, "
            f"nft: {nft_present}, iptables: {iptables_present}"
        ),
        remediation=(
            "Enable firewall: systemctl enable --now ufw  (or firewalld)"
        ),
        cross_references={
            "SOC2": "CC6.3", "NIST": "SC-7",
        },
    ))

    # CC6.6 - Logical access boundaries: SSH PermitRootLogin
    sshd = read_file_safe("/etc/ssh/sshd_config")
    permit_root_match = re.search(
        r"^\s*PermitRootLogin\s+(\S+)", sshd, re.MULTILINE
    )
    permit_root = permit_root_match.group(1) if permit_root_match else "yes"
    root_login_ok = permit_root.lower() in ("no", "prohibit-password", "without-password")
    results.append(_r(
        cat, "Pass" if root_login_ok else "Fail",
        f"SOC2-CC6.6: SSH PermitRootLogin secured: {permit_root}",
        severity="High",
        details=f"PermitRootLogin = {permit_root}",
        remediation=(
            "In /etc/ssh/sshd_config: PermitRootLogin no  (or "
            "prohibit-password). systemctl reload sshd"
        ),
        cross_references={
            "SOC2": "CC6.6", "NIST": "AC-6(2)", "STIG": "V-230336",
        },
    ))

    # CC6.7 - Restriction of access to information assets: file permissions audit
    sensitive_paths = [
        ("/etc/shadow", 0o400),
        ("/etc/gshadow", 0o400),
        ("/etc/ssh/sshd_config", 0o600),
        ("/etc/sudoers", 0o440),
    ]
    issues = []
    for path, max_mode in sensitive_paths:
        if not file_exists(path):
            continue
        mode = file_mode(path)
        if mode is None:
            continue
        if mode & ~max_mode & 0o077:
            issues.append(f"{path}={oct(mode)}")
    results.append(_r(
        cat, "Pass" if not issues else "Warning",
        f"SOC2-CC6.7: Sensitive file permissions ({len(issues)} issues)",
        severity="High",
        details=f"Issues: {issues}",
        remediation=(
            "chmod 400 /etc/shadow /etc/gshadow; chmod 600 /etc/ssh/sshd_config; "
            "chmod 440 /etc/sudoers"
        ),
        cross_references={
            "SOC2": "CC6.7", "NIST": "AC-3",
        },
    ))

    # CC6.8 - Software/hardware vulnerability mitigation: package updates
    update_indicators = {
        "unattended-upgrades": (
            systemd_active("unattended-upgrades.service") == "active"
        ),
        "dnf-automatic": (
            systemd_active("dnf-automatic-install.timer") == "active"
        ),
        "yum-cron": systemd_active("yum-cron.service") == "active",
    }
    detected = [k for k, v in update_indicators.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Warning",
        f"SOC2-CC6.8: Automated security updates configured ({len(detected)})",
        severity="High",
        details=f"Detected: {detected}",
        remediation=(
            "Enable unattended-upgrades (Debian/Ubuntu) or dnf-automatic (RHEL)"
        ),
        cross_references={
            "SOC2": "CC6.8", "NIST": "SI-2(2)",
        },
    ))

    return results


def _check_soc2_cc7_operations_v33(os_info) -> List[AuditResult]:
    """CC7 - System operations deep coverage."""
    results: List[AuditResult] = []
    cat = "SOC2 CC7 v3.3"

    # CC7.1 - Configuration baseline detection: kernel security parameters
    sysctl_baseline = {
        "kernel.randomize_va_space": "2",
        "kernel.dmesg_restrict": "1",
        "kernel.kptr_restrict": "2",
        "fs.protected_hardlinks": "1",
        "fs.protected_symlinks": "1",
        "fs.suid_dumpable": "0",
    }
    misconfig = []
    for k, v in sysctl_baseline.items():
        actual = read_sysctl(k)
        if actual != v:
            misconfig.append(f"{k}={actual or 'unset'}")
    results.append(_r(
        cat, "Pass" if not misconfig else "Warning",
        f"SOC2-CC7.1: Kernel security baseline ({len(misconfig)} drift)",
        severity="Medium",
        details=f"Drift: {misconfig}",
        remediation=(
            "Apply security baseline via /etc/sysctl.d/99-security.conf"
        ),
        cross_references={
            "SOC2": "CC7.1", "NIST": "CM-2, CM-6",
        },
    ))

    # CC7.2 - Anomaly identification: process accounting
    acct_active = (
        systemd_active("acct.service") == "active" or
        systemd_active("psacct.service") == "active"
    )
    results.append(_r(
        cat, "Info",
        f"SOC2-CC7.2: Process accounting active: {acct_active}",
        severity="Informational",
        details=f"acct/psacct: {acct_active}",
        remediation=(
            "apt-get install -y acct; systemctl enable --now acct"
        ),
        cross_references={
            "SOC2": "CC7.2", "NIST": "AU-2",
        },
    ))

    # CC7.3 - Security incident response: dmesg/journal forwarded
    journal_forward_config = read_file_safe("/etc/systemd/journald.conf")
    forward_match = re.search(
        r"^\s*ForwardToSyslog\s*=\s*(\w+)", journal_forward_config, re.MULTILINE
    )
    forward = forward_match.group(1).lower() if forward_match else "yes"
    results.append(_r(
        cat, "Info",
        f"SOC2-CC7.3: journald->syslog forwarding: {forward}",
        severity="Informational",
        details=f"ForwardToSyslog = {forward}",
        cross_references={
            "SOC2": "CC7.3", "NIST": "AU-6",
        },
    ))

    # CC7.4 - Incident response capability: log retention
    auditd_conf = read_file_safe("/etc/audit/auditd.conf")
    num_logs_match = re.search(
        r"^\s*num_logs\s*=\s*(\d+)", auditd_conf, re.MULTILINE
    )
    num_logs = int(num_logs_match.group(1)) if num_logs_match else 0
    results.append(_r(
        cat, "Pass" if num_logs >= 5 else "Warning",
        f"SOC2-CC7.4: auditd num_logs ({num_logs})",
        severity="Medium",
        details=f"num_logs = {num_logs}",
        remediation=(
            "In /etc/audit/auditd.conf: num_logs = 10"
        ),
        cross_references={
            "SOC2": "CC7.4", "NIST": "AU-11",
        },
    ))

    # CC7.5 - Recovery: backup tools
    backup_tools = {
        "rsync": command_available("rsync"),
        "borg": command_available("borg"),
        "restic": command_available("restic"),
        "duplicity": command_available("duplicity"),
        "snapper": command_available("snapper"),
    }
    detected = [k for k, v in backup_tools.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Info",
        f"SOC2-CC7.5: Backup tools available ({len(detected)})",
        severity="Medium",
        details=f"Detected: {detected}",
        cross_references={
            "SOC2": "CC7.5", "NIST": "CP-9",
        },
    ))

    return results


def _check_soc2_cc8_change_management_v33(os_info) -> List[AuditResult]:
    """CC8 - Change management."""
    results: List[AuditResult] = []
    cat = "SOC2 CC8 v3.3"

    # CC8.1 - Change tracking via auditd
    audit_rules_d = "/etc/audit/rules.d"
    config_watches = 0
    if directory_exists(audit_rules_d):
        for f in list_directory(audit_rules_d):
            if not f.endswith(".rules"):
                continue
            c = read_file_safe(os.path.join(audit_rules_d, f))
            for path in ["/etc/passwd", "/etc/shadow", "/etc/sudoers",
                          "/etc/ssh/sshd_config", "/etc/sysctl"]:
                if path in c:
                    config_watches += 1
    results.append(_r(
        cat, "Pass" if config_watches >= 3 else "Warning",
        f"SOC2-CC8.1: Configuration change auditing ({config_watches} watches)",
        severity="High",
        details=f"Critical config watches: {config_watches}",
        remediation=(
            "Add audit watches in /etc/audit/rules.d/cc8.rules: "
            "-w /etc/passwd -p wa -k cc8_identity; "
            "-w /etc/sudoers -p wa -k cc8_privileged"
        ),
        cross_references={
            "SOC2": "CC8.1", "NIST": "CM-3, AU-2",
        },
    ))

    # CC8.1 - Package management transaction logs
    pkg_logs = {
        "/var/log/dpkg.log": file_exists("/var/log/dpkg.log"),
        "/var/log/yum.log": file_exists("/var/log/yum.log"),
        "/var/log/dnf.log": file_exists("/var/log/dnf.log"),
        "/var/log/zypp/history": file_exists("/var/log/zypp/history"),
    }
    detected = [k for k, v in pkg_logs.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Warning",
        f"SOC2-CC8.1b: Package transaction logs ({len(detected)})",
        severity="Medium",
        details=f"Logs present: {detected}",
        cross_references={
            "SOC2": "CC8.1", "NIST": "CM-3(2)",
        },
    ))

    return results


def _check_soc2_cc9_risk_mitigation_v33(os_info) -> List[AuditResult]:
    """CC9 - Risk mitigation including vendor management."""
    results: List[AuditResult] = []
    cat = "SOC2 CC9 v3.3"

    # CC9.2 - Vendor & business partner management: package signing
    apt_keyring = directory_exists("/etc/apt/trusted.gpg.d") or \
                  directory_exists("/etc/apt/keyrings")
    rpm_gpgcheck = False
    yum_conf = read_file_safe("/etc/yum.conf") or read_file_safe("/etc/dnf/dnf.conf")
    if "gpgcheck=1" in yum_conf:
        rpm_gpgcheck = True
    pacman_keyring = directory_exists("/etc/pacman.d/gnupg")

    signing_indicators = sum([apt_keyring, rpm_gpgcheck, pacman_keyring])
    results.append(_r(
        cat, "Pass" if signing_indicators >= 1 else "Fail",
        f"SOC2-CC9.2: Package signature verification ({signing_indicators})",
        severity="High",
        details=(
            f"apt keyring: {apt_keyring}, rpm gpgcheck: {rpm_gpgcheck}, "
            f"pacman keyring: {pacman_keyring}"
        ),
        remediation=(
            "Verify package source authenticity: ensure gpgcheck=1 in dnf.conf, "
            "trusted.gpg.d populated for apt, pacman keyring initialized"
        ),
        cross_references={
            "SOC2": "CC9.2", "NIST": "CM-5(3), SR-11",
        },
    ))

    return results


def _check_soc2_a1_availability_v33(os_info) -> List[AuditResult]:
    """A1 - Availability deep coverage."""
    results: List[AuditResult] = []
    cat = "SOC2 A1 v3.3"

    # A1.1 - Capacity monitoring: disk usage tools
    monitoring_tools = {
        "node_exporter": (
            file_exists("/usr/local/bin/node_exporter") or
            command_available("node_exporter")
        ),
        "prometheus": command_available("prometheus"),
        "telegraf": command_available("telegraf"),
        "collectd": command_available("collectd"),
        "zabbix-agent": (
            command_available("zabbix_agentd") or
            command_available("zabbix_agent2")
        ),
        "datadog-agent": command_available("datadog-agent"),
    }
    detected = [k for k, v in monitoring_tools.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Warning",
        f"SOC2-A1.1: Capacity monitoring agents ({len(detected)})",
        severity="High",
        details=f"Detected: {detected or 'none'}",
        remediation=(
            "Deploy node_exporter for Prometheus, or telegraf for "
            "InfluxDB/observability platform"
        ),
        cross_references={
            "SOC2": "A1.1", "NIST": "CP-2",
        },
    ))

    # A1.2 - Environmental protections (logical): swap configured
    swap_info = read_file_safe("/proc/swaps")
    has_swap = len(swap_info.strip().splitlines()) > 1
    results.append(_r(
        cat, "Pass" if has_swap else "Info",
        f"SOC2-A1.2: Swap space configured: {has_swap}",
        severity="Low",
        details=f"swap entries: {len(swap_info.splitlines()) - 1}",
        cross_references={
            "SOC2": "A1.2", "NIST": "SC-5",
        },
    ))

    # A1.3 - Recovery: backup automation
    backup_cron_indicators = []
    for cron_dir in ["/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.d"]:
        if directory_exists(cron_dir):
            for f in list_directory(cron_dir):
                lf = f.lower()
                if any(k in lf for k in ["backup", "rsync", "borg", "restic",
                                           "duplicity", "snapshot"]):
                    backup_cron_indicators.append(f"{cron_dir}/{f}")
    results.append(_r(
        cat, "Pass" if backup_cron_indicators else "Warning",
        f"SOC2-A1.3: Scheduled backup cron jobs ({len(backup_cron_indicators)})",
        severity="High",
        details=f"Found: {backup_cron_indicators[:5]}",
        remediation=(
            "Schedule daily backups via cron or systemd timer. "
            "Test restore procedures quarterly."
        ),
        cross_references={
            "SOC2": "A1.3", "NIST": "CP-9",
        },
    ))

    return results


def _check_soc2_c1_confidentiality_v33(os_info) -> List[AuditResult]:
    """C1 - Confidentiality deep coverage."""
    results: List[AuditResult] = []
    cat = "SOC2 C1 v3.3"

    # C1.1 - Confidential information protection: disk encryption indicators
    luks_present = False
    rc, out, _ = run_command(["lsblk", "-o", "NAME,TYPE,FSTYPE", "-n"], timeout=3.0)
    if rc == 0 and out:
        for line in out.splitlines():
            if "crypt" in line.lower():
                luks_present = True
                break
    results.append(_r(
        cat, "Pass" if luks_present else "Warning",
        f"SOC2-C1.1: Disk encryption (LUKS) detected: {luks_present}",
        severity="High",
        details=f"crypt device indicator: {luks_present}",
        remediation=(
            "Encrypt sensitive volumes with LUKS: cryptsetup luksFormat /dev/<dev>"
        ),
        cross_references={
            "SOC2": "C1.1", "NIST": "SC-28",
        },
    ))

    # C1.2 - Disposal of confidential information
    secure_delete_tools = {
        "shred": command_available("shred"),
        "wipe": command_available("wipe"),
        "blkdiscard": command_available("blkdiscard"),
    }
    detected = [k for k, v in secure_delete_tools.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Warning",
        f"SOC2-C1.2: Secure deletion tools ({len(detected)})",
        severity="Medium",
        details=f"Detected: {detected}",
        cross_references={
            "SOC2": "C1.2", "NIST": "MP-6",
        },
    ))

    return results


def _check_soc2_pi_processing_integrity_v33(os_info) -> List[AuditResult]:
    """PI - Processing integrity deep coverage."""
    results: List[AuditResult] = []
    cat = "SOC2 PI v3.3"

    # PI1.1 - Processing integrity: file integrity monitoring
    fim_active = (
        file_exists("/var/lib/aide/aide.db") or
        file_exists("/var/lib/aide/aide.db.gz") or
        file_exists("/etc/tripwire/tw.cfg")
    )
    results.append(_r(
        cat, "Pass" if fim_active else "Warning",
        f"SOC2-PI1.1: File integrity database initialized: {fim_active}",
        severity="High",
        details=f"AIDE/Tripwire DB present: {fim_active}",
        remediation=remediation_for("aide"),
        cross_references={
            "SOC2": "PI1.1", "NIST": "SI-7",
        },
    ))

    # PI1.4 - Output review: audit log indicators
    audit_log_present = file_exists("/var/log/audit/audit.log") or \
                        directory_exists("/var/log/audit")
    results.append(_r(
        cat, "Pass" if audit_log_present else "Warning",
        f"SOC2-PI1.4: Audit log directory present: {audit_log_present}",
        severity="High",
        details=f"/var/log/audit: {audit_log_present}",
        cross_references={
            "SOC2": "PI1.4", "NIST": "AU-2",
        },
    ))

    return results


def _check_soc2_p_privacy_v33(os_info) -> List[AuditResult]:
    """P - Privacy criteria deep coverage."""
    results: List[AuditResult] = []
    cat = "SOC2 P v3.3"

    # P3.2 - Privacy notice: privacy-related logging restrictions
    # Check that PII fields aren't logged in cleartext
    rsy_conf = read_file_safe("/etc/rsyslog.conf")
    has_filter = "stop" in rsy_conf.lower() or ":msg" in rsy_conf
    results.append(_r(
        cat, "Info",
        f"SOC2-P3.2: rsyslog content filtering rules: {has_filter}",
        severity="Informational",
        details=f"Filter directives present: {has_filter}",
        remediation=(
            "Configure rsyslog filters to redact PII before forwarding. "
            "Example: :msg, contains, 'SSN' /dev/null  & stop"
        ),
        cross_references={
            "SOC2": "P3.2", "NIST": "SI-12",
        },
    ))

    # P4.2 - Use, retention, disposal: log rotation
    logrotate_d = list_directory("/etc/logrotate.d") if directory_exists("/etc/logrotate.d") else []
    results.append(_r(
        cat, "Pass" if logrotate_d else "Warning",
        f"SOC2-P4.2: logrotate configurations ({len(logrotate_d)})",
        severity="Medium",
        details=f"Configs in /etc/logrotate.d: {len(logrotate_d)}",
        cross_references={
            "SOC2": "P4.2", "NIST": "AU-11",
        },
    ))

    # P6.5 - Data subject rights: encryption indicators
    enc_libs = {
        "openssl": command_available("openssl"),
        "gnupg": command_available("gpg"),
        "age": command_available("age"),
    }
    detected_enc = [k for k, v in enc_libs.items() if v]
    results.append(_r(
        cat, "Pass" if detected_enc else "Fail",
        f"SOC2-P6.5: Encryption libraries available ({len(detected_enc)})",
        severity="High",
        details=f"Detected: {detected_enc}",
        cross_references={
            "SOC2": "P6.5", "NIST": "SC-13",
        },
    ))

    return results


# Save reference to existing run_checks
_original_run_checks_soc2_v33 = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the v3.3 expanded SOC2 module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_soc2_v33(shared_data)

    os_info = shared_data.get("v3_os_info")
    if os_info is None:
        os_info = os_detection.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        results.extend(_check_soc2_cc1_control_environment_v33(os_info))
        results.extend(_check_soc2_cc2_communication_v33(os_info))
        results.extend(_check_soc2_cc4_monitoring_v33(os_info))
        results.extend(_check_soc2_cc5_control_activities_v33(os_info))
        results.extend(_check_soc2_cc6_logical_access_v33(os_info))
        results.extend(_check_soc2_cc7_operations_v33(os_info))
        results.extend(_check_soc2_cc8_change_management_v33(os_info))
        results.extend(_check_soc2_cc9_risk_mitigation_v33(os_info))
        results.extend(_check_soc2_a1_availability_v33(os_info))
        results.extend(_check_soc2_c1_confidentiality_v33(os_info))
        results.extend(_check_soc2_pi_processing_integrity_v33(os_info))
        results.extend(_check_soc2_p_privacy_v33(os_info))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled exception in SOC2 v3.3 expansion")
        results.append(_r(
            "SOC2 - Error", "Error",
            f"SOC2 v3.3 expansion exception: {exc!r}",
            severity="Medium", details=str(exc),
        ))

    return results


# ============================================================================
# v3.5 EXPANSION - SOC 2 Trust Service Criteria Depth
# ----------------------------------------------------------------------------
# Synopsis:
#   Adds depth across SOC 2 Trust Service Criteria (TSC) areas:
#     - Common Criteria (CC) 1-9 depth
#     - Additional Criteria (Availability, Confidentiality, Processing
#       Integrity, Privacy)
#     - SOC 2 Type II evidence collection readiness
#     - AICPA TSP 100 - Trust Services Criteria for SOC 2
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


def _v35_soc2_result(category, status, message, severity="Medium",
                   details="", remediation="", cross_references=None):
    """Build AuditResult for SOC 2 v3.5 expansion."""
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


def _check_soc2_v35_cc1_control_environment(results, shared_data, os_info):
    """CC1 - Control Environment."""
    cat = "SOC 2 v3.5 - CC1"

    # CC1.4 - Workforce competence (technical surrogate: training tools)
    # Document presence indicators
    docs_paths = ["/usr/share/doc", "/etc/issue", "/etc/issue.net", "/etc/motd"]
    docs_present = sum(1 for p in docs_paths if _v35_file_exists(p) or _v35_directory_exists(p))
    results.append(_v35_soc2_result(
        f"{cat} - CC1.4 Documentation",
        "Pass" if docs_present >= 3 else "Info",
        f"SOC 2 CC1.4 Documentation indicators: {docs_present}/4",
        severity="Informational",
        details=f"Document paths: {docs_present}",
        cross_references={"SOC2": "CC1.4"},
    ))


def _check_soc2_v35_cc2_communication(results, shared_data, os_info):
    """CC2 - Communication and Information."""
    cat = "SOC 2 v3.5 - CC2"

    # CC2.2 - Internal communication (mail capability)
    mail_capable = (
        _v35_command_available("mail") or
        _v35_command_available("mailx") or
        _v35_systemd_active("postfix.service") == "active"
    )
    results.append(_v35_soc2_result(
        f"{cat} - CC2.2 Internal Communication",
        "Pass" if mail_capable else "Warning",
        f"SOC 2 CC2.2 Email capability: {mail_capable}",
        severity="Medium",
        details=f"Mail tooling: {mail_capable}",
        cross_references={"SOC2": "CC2.2", "NIST": "IR-6"},
    ))


def _check_soc2_v35_cc3_risk_assessment(results, shared_data, os_info):
    """CC3 - Risk Assessment."""
    cat = "SOC 2 v3.5 - CC3"

    # CC3.2 - Identifies and analyzes risks (vuln scanning)
    risk_tools = sum(1 for t in [
        "lynis", "oscap", "trivy", "nuclei", "rkhunter",
    ] if _v35_command_available(t))
    results.append(_v35_soc2_result(
        f"{cat} - CC3.2 Risk Identification",
        "Pass" if risk_tools >= 2 else "Warning",
        f"SOC 2 CC3.2 Risk assessment tools: {risk_tools}/5",
        severity="High",
        details=f"Vuln/risk tools: {risk_tools}",
        remediation=remediation_for("lynis"),
        cross_references={"SOC2": "CC3.2", "NIST": "RA-3, RA-5"},
    ))

    # CC3.4 - Assesses changes (auditd /etc watch)
    audit_rules = ""
    if _v35_directory_exists("/etc/audit/rules.d"):
        for f in _v35_list_directory("/etc/audit/rules.d"):
            if f.endswith(".rules"):
                audit_rules += "\n" + _v35_read_file_safe(
                    os.path.join("/etc/audit/rules.d", f)
                )
    etc_audited = "/etc" in audit_rules and "wa" in audit_rules
    results.append(_v35_soc2_result(
        f"{cat} - CC3.4 Change Assessment",
        "Pass" if etc_audited else "Warning",
        f"SOC 2 CC3.4 /etc auditing: {etc_audited}",
        severity="High",
        details=f"audit watch on /etc: {etc_audited}",
        remediation=(
            "Add to /etc/audit/rules.d/41-soc2-changes.rules:\n"
            "  -w /etc -p wa -k config-changes"
        ),
        cross_references={"SOC2": "CC3.4", "NIST": "CM-3"},
    ))


def _check_soc2_v35_cc6_logical_physical(results, shared_data, os_info):
    """CC6 - Logical and Physical Access Controls."""
    cat = "SOC 2 v3.5 - CC6"

    # CC6.1 - Logical access (MFA/auth)
    pam_files_content = ""
    for pf in ["/etc/pam.d/sshd", "/etc/pam.d/system-auth",
                "/etc/pam.d/password-auth", "/etc/pam.d/common-auth"]:
        pam_files_content += "\n" + _v35_read_file_safe(pf)
    pam_mfa = any(mod in pam_files_content for mod in [
        "pam_google_authenticator", "pam_yubico", "pam_oath",
        "pam_u2f", "pam_duo",
    ])
    sshd = _v35_read_file_safe("/etc/ssh/sshd_config")
    sshd_d = ""
    if _v35_directory_exists("/etc/ssh/sshd_config.d"):
        for f in _v35_list_directory("/etc/ssh/sshd_config.d"):
            if f.endswith(".conf"):
                sshd_d += "\n" + _v35_read_file_safe(
                    os.path.join("/etc/ssh/sshd_config.d", f)
                )
    full_sshd = sshd + "\n" + sshd_d
    pubkey_only = bool(re.search(
        r"^\s*PasswordAuthentication\s+no", full_sshd, re.MULTILINE,
    ))
    auth_strong = pam_mfa or pubkey_only
    results.append(_v35_soc2_result(
        f"{cat} - CC6.1 Logical Access",
        "Pass" if auth_strong else "Warning",
        f"SOC 2 CC6.1 Strong auth (MFA or pubkey-only): {auth_strong}",
        severity="High",
        details=(
            f"PAM MFA: {pam_mfa}, SSH pubkey-only: {pubkey_only}"
        ),
        cross_references={"SOC2": "CC6.1", "NIST": "IA-2(1), IA-2(2)"},
    ))

    # CC6.6 - Logical access removed for departed personnel (account lockout)
    pam_lockout = (
        "pam_faillock" in pam_files_content or "pam_tally2" in pam_files_content
    )
    results.append(_v35_soc2_result(
        f"{cat} - CC6.6 Account Lockout",
        "Pass" if pam_lockout else "Warning",
        f"SOC 2 CC6.6 PAM account lockout: {pam_lockout}",
        severity="High",
        details=f"PAM lockout module: {pam_lockout}",
        cross_references={"SOC2": "CC6.6", "NIST": "AC-7"},
    ))

    # CC6.7 - Restricted physical/logical access (least privilege via MAC)
    selinux_enforcing = (
        _v35_command_available("getenforce") and
        ((_v35_run_command(["getenforce"], timeout=2.0)[1] or "").strip()
         == "Enforcing")
    )
    apparmor_active = _v35_command_available("aa-status")
    mac_active = selinux_enforcing or apparmor_active
    results.append(_v35_soc2_result(
        f"{cat} - CC6.7 Least Privilege",
        "Pass" if mac_active else "Warning",
        f"SOC 2 CC6.7 MAC enforcement (SELinux/AppArmor): {mac_active}",
        severity="High",
        details=(
            f"SELinux enforcing: {selinux_enforcing}, AppArmor: {apparmor_active}"
        ),
        cross_references={"SOC2": "CC6.7", "NIST": "AC-3, AC-6"},
    ))

    # CC6.8 - Prevents/detects unauthorized changes (FIM)
    fim_present = (
        _v35_file_exists("/var/lib/aide/aide.db") or
        _v35_file_exists("/var/lib/aide/aide.db.gz") or
        _v35_file_exists("/var/lib/tripwire/tw.db") or
        _v35_file_exists("/var/ossec/queue/syscheck/syscheck.db")
    )
    results.append(_v35_soc2_result(
        f"{cat} - CC6.8 Change Detection (FIM)",
        "Pass" if fim_present else "Warning",
        f"SOC 2 CC6.8 FIM database: {fim_present}",
        severity="High",
        details=f"FIM DB present: {fim_present}",
        remediation=remediation_for("aide"),
        cross_references={"SOC2": "CC6.8", "NIST": "SI-7", "PCI-DSS": "11.5.2"},
    ))


def _check_soc2_v35_cc7_system_operations(results, shared_data, os_info):
    """CC7 - System Operations."""
    cat = "SOC 2 v3.5 - CC7"

    # CC7.1 - Detection of system anomalies
    detection_layers = sum([
        _v35_systemd_active("auditd.service") == "active",
        _v35_systemd_active("fail2ban.service") == "active",
        _v35_file_exists("/var/ossec/etc/ossec.conf"),
        _v35_systemd_active("falco.service") == "active",
    ])
    results.append(_v35_soc2_result(
        f"{cat} - CC7.1 Anomaly Detection",
        "Pass" if detection_layers >= 2 else "Warning",
        f"SOC 2 CC7.1 Anomaly detection layers: {detection_layers}/4",
        severity="High",
        details=f"Active: {detection_layers}",
        cross_references={"SOC2": "CC7.1", "NIST": "SI-4"},
    ))

    # CC7.2 - Monitors system components for anomalies
    monitoring_active = (
        _v35_systemd_active("auditd.service") == "active" and
        _v35_directory_exists("/var/log/journal")
    )
    results.append(_v35_soc2_result(
        f"{cat} - CC7.2 Continuous Monitoring",
        "Pass" if monitoring_active else "Warning",
        f"SOC 2 CC7.2 Continuous monitoring (auditd + persistent journal): "
        f"{monitoring_active}",
        severity="High",
        details=f"auditd + journald persistent: {monitoring_active}",
        cross_references={"SOC2": "CC7.2", "NIST": "SI-4, AU-11"},
    ))

    # CC7.3 - Evaluates security events (SIEM forwarding)
    siem_forward = False
    rsy = _v35_read_file_safe("/etc/rsyslog.conf")
    if "@@" in rsy or "omfwd" in rsy:
        siem_forward = True
    elif _v35_directory_exists("/etc/rsyslog.d"):
        for f in _v35_list_directory("/etc/rsyslog.d"):
            c = _v35_read_file_safe(os.path.join("/etc/rsyslog.d", f))
            if "@@" in c or "omfwd" in c:
                siem_forward = True
                break
    results.append(_v35_soc2_result(
        f"{cat} - CC7.3 Event Evaluation",
        "Pass" if siem_forward else "Warning",
        f"SOC 2 CC7.3 SIEM forwarding: {siem_forward}",
        severity="High",
        details=f"Remote rsyslog: {siem_forward}",
        cross_references={"SOC2": "CC7.3", "NIST": "AU-6"},
    ))

    # CC7.4 - Responds to security incidents (IR tooling)
    ir_layers = sum([
        _v35_command_available(t)
        for t in ["tcpdump", "lsof", "strace", "ausearch", "journalctl"]
    ])
    results.append(_v35_soc2_result(
        f"{cat} - CC7.4 Incident Response",
        "Pass" if ir_layers >= 4 else "Warning",
        f"SOC 2 CC7.4 IR tooling: {ir_layers}/5",
        severity="High",
        details=f"IR tools: {ir_layers}",
        cross_references={"SOC2": "CC7.4", "NIST": "IR-4, IR-5"},
    ))

    # CC7.5 - Recovery from incidents (backup tools)
    backup_tools = sum(
        _v35_command_available(t)
        for t in ["borg", "restic", "duplicity", "rsync"]
    )
    results.append(_v35_soc2_result(
        f"{cat} - CC7.5 Recovery",
        "Pass" if backup_tools >= 2 else "Warning",
        f"SOC 2 CC7.5 Backup/recovery tools: {backup_tools}/4",
        severity="High",
        details=f"Backup tools: {backup_tools}",
        remediation=remediation_for("borg"),
        cross_references={"SOC2": "CC7.5", "NIST": "CP-9, CP-10"},
    ))


def _check_soc2_v35_cc8_change_mgmt(results, shared_data, os_info):
    """CC8 - Change Management."""
    cat = "SOC 2 v3.5 - CC8"

    # CC8.1 - Authorizes, designs, develops, configures, documents, tests, approves
    change_layers = sum([
        _v35_command_available("git"),
        _v35_command_available("ansible") or _v35_command_available("puppet"),
        _v35_command_available("etckeeper"),
        bool(_v35_file_exists("/var/log/dpkg.log") or
             _v35_file_exists("/var/log/dnf.log")),
    ])
    results.append(_v35_soc2_result(
        f"{cat} - CC8.1 Change Management",
        "Pass" if change_layers >= 2 else "Warning",
        f"SOC 2 CC8.1 Change management layers: {change_layers}/4",
        severity="High",
        details=f"Layers: {change_layers}",
        remediation=(
            "apt-get install -y git ansible etckeeper\n"
            "etckeeper init"
        ),
        cross_references={"SOC2": "CC8.1", "NIST": "CM-3, CM-5"},
    ))


def _check_soc2_v35_cc9_risk_mitigation(results, shared_data, os_info):
    """CC9 - Risk Mitigation."""
    cat = "SOC 2 v3.5 - CC9"

    # CC9.1 - Identifies, selects, develops risk mitigation activities
    mitigation_layers = sum([
        # Auto-patching
        bool(
            _v35_systemd_active("unattended-upgrades.service") == "active" or
            _v35_systemd_active("dnf-automatic.timer") == "active" or
            _v35_systemd_active("dnf-automatic-install.timer") == "active"
        ),
        # Anti-malware
        bool(
            _v35_systemd_active("clamav-daemon.service") == "active" or
            _v35_systemd_active("clamd.service") == "active" or
            _v35_command_available("rkhunter")
        ),
        # FIM
        bool(_v35_file_exists("/var/lib/aide/aide.db") or
             _v35_file_exists("/var/lib/aide/aide.db.gz")),
        # MAC
        bool(
            _v35_command_available("getenforce") and
            (_v35_run_command(["getenforce"], timeout=2.0)[1] or "").strip()
            == "Enforcing"
        ) or _v35_command_available("aa-status"),
    ])
    results.append(_v35_soc2_result(
        f"{cat} - CC9.1 Risk Mitigation",
        "Pass" if mitigation_layers >= 3 else "Warning",
        f"SOC 2 CC9.1 Risk mitigation layers: {mitigation_layers}/4",
        severity="High",
        details=f"Layers: {mitigation_layers}",
        cross_references={"SOC2": "CC9.1", "NIST": "RA-3, SI-2, SI-3"},
    ))


def _check_soc2_v35_availability(results, shared_data, os_info):
    """A - Availability (Additional Criteria)."""
    cat = "SOC 2 v3.5 - Availability"

    # A1.2 - Backup, recovery, capacity
    availability_layers = sum([
        # Backup
        bool(any(_v35_command_available(t) for t in ["borg", "restic", "duplicity"])),
        # Snapshot capability
        bool(any(_v35_command_available(t) for t in ["zfs", "btrfs", "snapper"])),
        # Time sync (essential for distributed systems)
        bool(
            _v35_systemd_active("chronyd.service") == "active" or
            _v35_systemd_active("chrony.service") == "active" or
            _v35_systemd_active("systemd-timesyncd.service") == "active"
        ),
        # Log rotation (capacity mgmt)
        _v35_command_available("logrotate"),
    ])
    results.append(_v35_soc2_result(
        f"{cat} - A1.2 Availability Layers",
        "Pass" if availability_layers >= 3 else "Warning",
        f"SOC 2 A1.2 Availability layers: {availability_layers}/4",
        severity="High",
        details=f"Layers: {availability_layers}",
        cross_references={"SOC2": "A1.2", "NIST": "CP-9, CP-10"},
    ))

    # A1.3 - Tests recovery (snapshot/backup automation)
    backup_scheduled = False
    cron_dirs = ["/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.d"]
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
    results.append(_v35_soc2_result(
        f"{cat} - A1.3 Recovery Testing",
        "Pass" if backup_scheduled else "Info",
        f"SOC 2 A1.3 Backup automation present: {backup_scheduled}",
        severity="Medium",
        details=f"Scheduled backup: {backup_scheduled}",
        cross_references={"SOC2": "A1.3", "NIST": "CP-9(1)"},
    ))


def _check_soc2_v35_confidentiality(results, shared_data, os_info):
    """C - Confidentiality (Additional Criteria)."""
    cat = "SOC 2 v3.5 - Confidentiality"

    # C1.1 - Identifies and maintains confidential information
    luks_present = False
    rc, out, _ = _v35_run_command(["lsblk", "-o", "TYPE", "-n"], timeout=5.0)
    if rc == 0 and out and "crypt" in out.lower():
        luks_present = True
    fips_enabled = _v35_read_sysctl("crypto.fips_enabled") == "1"
    confidentiality_strong = luks_present and fips_enabled
    results.append(_v35_soc2_result(
        f"{cat} - C1.1 Confidential Data Protection",
        "Pass" if confidentiality_strong else (
            "Info" if luks_present else "Warning"
        ),
        f"SOC 2 C1.1 LUKS={luks_present}, FIPS={fips_enabled}",
        severity="High",
        details=(
            f"LUKS volumes: {luks_present}, FIPS: {fips_enabled}"
        ),
        cross_references={"SOC2": "C1.1", "NIST": "SC-13, SC-28"},
    ))

    # C1.2 - Disposes of confidential information (sanitization)
    sanit_count = sum(
        _v35_command_available(t)
        for t in ["shred", "scrub", "wipe", "srm", "hdparm"]
    )
    results.append(_v35_soc2_result(
        f"{cat} - C1.2 Disposal Tools",
        "Pass" if sanit_count >= 2 else "Warning",
        f"SOC 2 C1.2 Sanitization tools: {sanit_count}/5",
        severity="Medium",
        details=f"Tools available: {sanit_count}",
        cross_references={"SOC2": "C1.2", "NIST": "MP-6"},
    ))


def _check_soc2_v35_processing_integrity(results, shared_data, os_info):
    """PI - Processing Integrity (Additional Criteria)."""
    cat = "SOC 2 v3.5 - Processing Integrity"

    # PI1.1 - Inputs are complete, accurate, valid
    # Surrogate: package signature verification + FIM
    processing_layers = sum([
        # Package verification
        bool(
            _v35_directory_exists("/etc/apt/keyrings") or
            _v35_directory_exists("/etc/apt/trusted.gpg.d") or
            _v35_directory_exists("/etc/pki/rpm-gpg")
        ),
        # FIM
        bool(_v35_file_exists("/var/lib/aide/aide.db") or
             _v35_file_exists("/var/lib/aide/aide.db.gz")),
        # Integrity tools
        bool(
            _v35_command_available("debsums") or
            (_v35_command_available("rpm") and (os_info and
             os_info.is_redhat_family()))
        ),
    ])
    results.append(_v35_soc2_result(
        f"{cat} - PI1.1 Input Integrity",
        "Pass" if processing_layers >= 2 else "Warning",
        f"SOC 2 PI1.1 Integrity verification layers: {processing_layers}/3",
        severity="Medium",
        details=f"Layers: {processing_layers}",
        cross_references={"SOC2": "PI1.1", "NIST": "SI-7"},
    ))


def _check_soc2_v35_privacy(results, shared_data, os_info):
    """P - Privacy (Additional Criteria)."""
    cat = "SOC 2 v3.5 - Privacy"

    # P3.1 - Personal information collection (encrypt-at-rest indicators)
    luks_present = False
    rc, out, _ = _v35_run_command(["lsblk", "-o", "TYPE", "-n"], timeout=5.0)
    if rc == 0 and out and "crypt" in out.lower():
        luks_present = True
    results.append(_v35_soc2_result(
        f"{cat} - P3.1 Personal Info Encryption",
        "Pass" if luks_present else "Warning",
        f"SOC 2 P3.1 At-rest encryption (LUKS): {luks_present}",
        severity="High",
        details=f"LUKS volumes: {luks_present}",
        remediation=remediation_for("cryptsetup"),
        cross_references={"SOC2": "P3.1", "NIST": "SC-28", "GDPR": "Art 32"},
    ))

    # P5.1 - Disposal of personal information (sanitization + erasure)
    erasure_tools = sum(
        _v35_command_available(t)
        for t in ["shred", "scrub", "wipe", "srm"]
    )
    fstrim_active = _v35_systemd_active("fstrim.timer") == "active"
    erasure_capable = erasure_tools >= 1 and (erasure_tools >= 2 or fstrim_active)
    results.append(_v35_soc2_result(
        f"{cat} - P5.1 Personal Info Disposal",
        "Pass" if erasure_capable else "Warning",
        f"SOC 2 P5.1 Erasure capability: {erasure_capable}",
        severity="High",
        details=(
            f"Sanitization tools: {erasure_tools}, fstrim.timer: {fstrim_active}"
        ),
        cross_references={"SOC2": "P5.1", "NIST": "MP-6", "GDPR": "Art 17"},
    ))


# Save reference to existing run_checks
_original_run_checks_soc2_v35 = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the v3.5 expanded SOC 2 module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_soc2_v35(shared_data)

    os_info = shared_data.get("os_info") or shared_data.get("v3_os_info")
    if os_info is None:
        from shared_components import os_detection as _os_det
        os_info = _os_det.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        _check_soc2_v35_cc1_control_environment(results, shared_data, os_info)
        _check_soc2_v35_cc2_communication(results, shared_data, os_info)
        _check_soc2_v35_cc3_risk_assessment(results, shared_data, os_info)
        _check_soc2_v35_cc6_logical_physical(results, shared_data, os_info)
        _check_soc2_v35_cc7_system_operations(results, shared_data, os_info)
        _check_soc2_v35_cc8_change_mgmt(results, shared_data, os_info)
        _check_soc2_v35_cc9_risk_mitigation(results, shared_data, os_info)
        _check_soc2_v35_availability(results, shared_data, os_info)
        _check_soc2_v35_confidentiality(results, shared_data, os_info)
        _check_soc2_v35_processing_integrity(results, shared_data, os_info)
        _check_soc2_v35_privacy(results, shared_data, os_info)
    except Exception as exc:  # noqa: BLE001
        results.append(AuditResult(
            module=MODULE_NAME, category="SOC2 - Error",
            status="Error",
            message=f"SOC2 v3.5 expansion exception: {exc!r}",
            details=str(exc), severity="Medium",
        ))

    return results
if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    print("[SOC2] ===== SOC 2 Type II Trust Services Audit =====")
    print("[SOC2] Module Version: 3.9\n")
    rs = run_checks()
    print(f"[SOC2] {len(rs)} checks executed\n")
    counts: Dict[str, int] = {}
    for r in rs:
        counts[r.status] = counts.get(r.status, 0) + 1
    for s, c in sorted(counts.items()):
        print(f"  {s:>8}: {c}")
