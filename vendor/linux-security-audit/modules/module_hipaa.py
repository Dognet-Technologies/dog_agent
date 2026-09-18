#!/usr/bin/env python3
"""
module_hipaa.py
HIPAA Security Rule + 405(d) HICP Module for Linux
Version: 3.9

SYNOPSIS
    Linux technical compliance assessment against the U.S. Health
    Insurance Portability and Accountability Act (HIPAA) Security Rule
    (45 CFR Parts 160, 162, and 164) and the 405(d) Health Industry
    Cybersecurity Practices (HICP).

DESCRIPTION
    The HIPAA Security Rule defines technical, administrative, and
    physical safeguards that covered entities and business associates
    must implement to protect electronic Protected Health Information
    (ePHI). This module covers the technical controls from Sec. 164.312
    plus the administrative safeguards from Sec. 164.308 that have direct
    Linux technical indicators.

    HIPAA Security Rule sections covered:
        Sec. 164.312(a)(1) - Access Control
        Sec. 164.312(a)(2) - Unique User Identification, Emergency Access,
                          Automatic Logoff, Encryption and Decryption
        Sec. 164.312(b)   - Audit Controls
        Sec. 164.312(c)(1) - Integrity
        Sec. 164.312(d)   - Person or Entity Authentication
        Sec. 164.312(e)(1) - Transmission Security

    Selected Sec. 164.308 administrative safeguards with technical
    indicators:
        Sec. 164.308(a)(1)(ii)(D) - Information system activity review
        Sec. 164.308(a)(3)(ii)    - Workforce clearance / termination
        Sec. 164.308(a)(4)(ii)(B) - Access authorization
        Sec. 164.308(a)(5)(ii)(B) - Protection from malicious software
        Sec. 164.308(a)(5)(ii)(C) - Log-in monitoring
        Sec. 164.308(a)(5)(ii)(D) - Password management
        Sec. 164.308(a)(7)        - Contingency plan (technical indicators)

    Plus 405(d) HICP small/medium/large practice indicators where
    Linux-applicable (email protection, endpoint protection, access
    management, data protection, vulnerability management, IR).

    Each check populates AuditResult.cross_references with the HIPAA
    citation plus equivalents in NIST 800-53, NIST 800-66 (HIPAA
    Implementation Guide), HITRUST CSF, and PCI DSS.

PARAMETERS
    shared_data : Dictionary containing shared data from the orchestrator.

USAGE
    Standalone:
        python3 modules/module_hipaa.py

    Via orchestrator:
        python3 linux_security_audit.py -m HIPAA

NOTES
    Version: 3.9
    Reference: 45 CFR Part 164, NIST SP 800-66 R2 (Feb 2024),
               HHS 405(d) HICP (2023 update)
    Target: 90+ technical control checks
    Applies regardless of whether ePHI is actually present on the
    system - HIPAA technical safeguards are a baseline regardless.
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
    file_mode, file_owner, parse_kv_file, list_directory, make_result,
    first_existing,
)

logger = logging.getLogger("audit.module_hipaa")
MODULE_NAME = "HIPAA"
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
# Sec. 164.312(a)(2)(i) - Unique User Identification
# ===========================================================================

def _check_unique_user_id(os_info) -> List[AuditResult]:
    cat = "HIPAA 164.312(a)(2)(i) - Unique User ID"
    results: List[AuditResult] = []

    # No duplicate UIDs
    passwd = read_file_safe("/etc/passwd")
    uids: Dict[int, List[str]] = {}
    if passwd:
        for line in passwd.splitlines():
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
        "HIPAA 164.312(a)(2)(i): No duplicate user IDs",
        severity="High",
        details=f"Duplicate UIDs: {duplicates or 'none'}",
        remediation="Reassign UIDs: usermod -u <new_uid> <username>",
        cross_references={
            "HIPAA": "164.312(a)(2)(i)", "NIST": "IA-2",
            "ISO27001": "A.8.5", "CIS": "6.2.6", "STIG": "V-230371",
            "PCI-DSS": "8.2.1",
        },
    ))

    # No duplicate user names (rare but possible via direct /etc/passwd edit)
    names_seen: Dict[str, int] = {}
    if passwd:
        for line in passwd.splitlines():
            fields = line.split(":")
            if fields[0]:
                names_seen[fields[0]] = names_seen.get(fields[0], 0) + 1
    dup_names = [n for n, c in names_seen.items() if c > 1]

    results.append(_r(
        cat,
        "Pass" if not dup_names else "Fail",
        "HIPAA 164.312(a)(2)(i): No duplicate user names",
        severity="High",
        details=f"Duplicate names: {', '.join(dup_names) or 'none'}",
        remediation=(
            "Edit /etc/passwd and /etc/shadow to remove duplicate entries; "
            "use vipw and vipw -s for safe editing."
        ),
        cross_references={
            "HIPAA": "164.312(a)(2)(i)", "NIST": "IA-2", "ISO27001": "A.8.5",
        },
    ))

    return results


# ===========================================================================
# Sec. 164.312(a)(2)(iii) - Automatic Logoff
# ===========================================================================

def _check_automatic_logoff(os_info) -> List[AuditResult]:
    cat = "HIPAA 164.312(a)(2)(iii) - Automatic Logoff"
    results: List[AuditResult] = []

    # TMOUT in shell profiles
    profile_paths = ["/etc/profile"] + list_directory("/etc/profile.d", ".sh")
    tmout_set = False
    tmout_value = ""
    for path in profile_paths:
        content = read_file_safe(path)
        m = re.search(r"^\s*(?:readonly\s+|export\s+)?TMOUT=(\d+)",
                      content, re.MULTILINE)
        if m:
            tmout_set = True
            tmout_value = m.group(1)
            break

    try:
        tmout_int = int(tmout_value) if tmout_value else 0
    except ValueError:
        tmout_int = 0

    # HIPAA does not specify a duration but commonly accepted: 10-15 min
    tmout_ok = tmout_set and 0 < tmout_int <= 900

    results.append(_r(
        cat,
        "Pass" if tmout_ok else "Fail",
        "HIPAA 164.312(a)(2)(iii): Automatic shell logoff configured",
        severity="High",
        details=(
            f"TMOUT = {tmout_value or 'unset'} seconds "
            "(recommended: <= 900s / 15 min)"
        ),
        remediation=(
            "echo 'readonly TMOUT=900; export TMOUT' > /etc/profile.d/tmout.sh && "
            "chmod 644 /etc/profile.d/tmout.sh"
        ),
        cross_references={
            "HIPAA": "164.312(a)(2)(iii)", "NIST": "AC-12",
            "CIS": "5.4.4", "STIG": "V-230363", "PCI-DSS": "8.2.8",
        },
    ))

    # SSH ClientAliveInterval (server-side equivalent)
    sshd_config = read_file_safe("/etc/ssh/sshd_config")
    cai = -1
    cacm = -1
    if sshd_config:
        for line in sshd_config.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("clientaliveinterval"):
                parts = stripped.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    cai = int(parts[1])
            elif stripped.lower().startswith("clientalivecountmax"):
                parts = stripped.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    cacm = int(parts[1])

    ssh_idle_ok = cai > 0 and cacm >= 0 and (cai * max(cacm, 1)) <= 900
    results.append(_r(
        cat,
        "Pass" if ssh_idle_ok else "Warning",
        "HIPAA 164.312(a)(2)(iii): SSH idle session timeout configured",
        severity="Medium",
        details=(
            f"ClientAliveInterval = {cai if cai >= 0 else 'unset'}, "
            f"ClientAliveCountMax = {cacm if cacm >= 0 else 'unset'}; "
            f"effective timeout = {cai * cacm if cai > 0 and cacm > 0 else 'unbounded'}s"
        ),
        remediation=(
            "Add to /etc/ssh/sshd_config: ClientAliveInterval 300, "
            "ClientAliveCountMax 0  (or appropriate values yielding <= 900s)"
        ),
        cross_references={
            "HIPAA": "164.312(a)(2)(iii)", "NIST": "AC-12",
            "CIS": "5.2.16", "STIG": "V-230244",
        },
    ))

    return results


# ===========================================================================
# Sec. 164.312(a)(2)(iv) - Encryption and Decryption
# ===========================================================================

def _check_encryption(os_info) -> List[AuditResult]:
    cat = "HIPAA 164.312(a)(2)(iv) - Encryption"
    results: List[AuditResult] = []

    # Disk encryption (LUKS)
    luks_active = False
    if command_available("dmsetup"):
        rc, out, _ = run_command(["dmsetup", "ls", "--target=crypt"])
        if rc == 0 and out and "No devices found" not in out:
            luks_active = True

    results.append(_r(
        cat,
        "Pass" if luks_active else "Warning",
        "HIPAA 164.312(a)(2)(iv): Disk encryption (LUKS) for ePHI at rest",
        severity="High",
        details=(
            f"LUKS-encrypted devices: {luks_active}. "
            "HIPAA encryption is addressable; HHS guidance recommends "
            "encryption at rest for systems holding ePHI."
        ),
        remediation=(
            "Encrypt volumes containing ePHI with LUKS. New deployments "
            "should be provisioned encrypted; existing systems require "
            "careful migration."
        ),
        cross_references={
            "HIPAA": "164.312(a)(2)(iv)", "NIST": "SC-28",
            "ISO27001": "A.8.10", "PCI-DSS": "3.5.1",
            "GDPR": "Art-32(1)(a)",
        },
    ))

    return results


# ===========================================================================
# Sec. 164.312(b) - Audit Controls
# ===========================================================================

def _check_audit_controls(os_info) -> List[AuditResult]:
    cat = "HIPAA 164.312(b) - Audit Controls"
    results: List[AuditResult] = []

    # auditd active
    auditd_active = systemd_active("auditd.service") == "active"
    results.append(_r(
        cat,
        "Pass" if auditd_active else "Fail",
        "HIPAA 164.312(b): System audit logging active",
        severity="Critical",
        details=f"auditd state: {systemd_active('auditd.service')}",
        remediation=(
            "Install: dnf install -y audit (RHEL) or apt-get install -y auditd "
            "(Debian). Enable: systemctl enable --now auditd."
        ),
        cross_references={
            "HIPAA": "164.312(b)", "NIST": "AU-2", "CIS": "4.1.1.1",
            "ISO27001": "A.8.15", "PCI-DSS": "10.2.1", "STIG": "V-230395",
        },
    ))

    # Audit rules for ePHI-relevant operations
    audit_files = (
        "/etc/audit/audit.rules", "/etc/audit/rules.d/audit.rules",
    ) + tuple(list_directory("/etc/audit/rules.d", ".rules"))
    audit_content = ""
    for af in audit_files:
        audit_content += read_file_safe(af) + "\n"

    has_identity = bool(re.search(r"-w\s+/etc/(passwd|shadow|group)", audit_content))
    has_logins = bool(re.search(r"/var/log/(faillog|lastlog|tallylog)", audit_content))
    has_session = bool(re.search(r"/var/run/(utmp|wtmp|btmp)", audit_content))
    has_priv_cmds = bool(re.search(r"-a\s+(?:always|never),exit.*\bperm=x.*\bauid", audit_content))
    has_dac_changes = bool(re.search(r"-a\s+(?:always|never),exit.*-S.*chmod|chown|fchmod", audit_content))

    rules_satisfied = sum([has_identity, has_logins, has_session, has_priv_cmds, has_dac_changes])

    results.append(_r(
        cat,
        "Pass" if rules_satisfied >= 4 else "Fail" if rules_satisfied < 2 else "Warning",
        f"HIPAA 164.312(b): Audit rules cover ePHI-relevant events ({rules_satisfied}/5)",
        severity="High",
        details=(
            f"identity: {has_identity}, logins: {has_logins}, "
            f"sessions: {has_session}, privileged cmds: {has_priv_cmds}, "
            f"DAC changes: {has_dac_changes}"
        ),
        remediation=(
            "Create /etc/audit/rules.d/50-hipaa.rules with comprehensive "
            "rules for identity changes, login events, session changes, "
            "privileged commands, and DAC modifications. Restart auditd."
        ),
        cross_references={
            "HIPAA": "164.312(b)", "NIST": "AU-2", "CIS": "4.1.3",
            "ISO27001": "A.8.15", "STIG": "V-230418",
        },
    ))

    # Time synchronization (audit timestamp accuracy)
    time_sync_active = (
        systemd_active("chronyd.service") == "active"
        or systemd_active("chrony.service") == "active"
        or systemd_active("ntpd.service") == "active"
        or systemd_active("systemd-timesyncd.service") == "active"
    )

    results.append(_r(
        cat,
        "Pass" if time_sync_active else "Fail",
        "HIPAA 164.312(b): Time synchronization for audit accuracy",
        severity="High",
        details=f"Time sync service active: {time_sync_active}",
        remediation=remediation_for("chrony"),
        cross_references={
            "HIPAA": "164.312(b)", "NIST": "AU-8(1)", "CIS": "2.1.1.1",
            "ISO27001": "A.8.17", "PCI-DSS": "10.6.1",
        },
    ))

    return results


# ===========================================================================
# Sec. 164.312(c)(1) - Integrity
# ===========================================================================

def _check_integrity(os_info) -> List[AuditResult]:
    cat = "HIPAA 164.312(c)(1) - Integrity"
    results: List[AuditResult] = []

    # File integrity monitoring
    fim = {
        "AIDE": command_available("aide") or file_exists("/etc/aide.conf"),
        "Tripwire": command_available("tripwire"),
        "Wazuh/OSSEC": file_exists("/var/ossec/etc/ossec.conf"),
    }
    detected = [n for n, p in fim.items() if p]

    results.append(_r(
        cat,
        "Pass" if detected else "Fail",
        "HIPAA 164.312(c)(1): File integrity monitoring deployed",
        severity="High",
        details=f"Detected: {', '.join(detected) or 'none'}",
        remediation=remediation_for("aide"),
        cross_references={
            "HIPAA": "164.312(c)(1)", "NIST": "SI-7", "ISO27001": "A.8.16",
            "PCI-DSS": "11.5.2", "GDPR": "Art-32(1)(b)",
        },
    ))

    # Critical file permissions
    critical_files = (
        ("/etc/passwd", 0o644),
        ("/etc/shadow", 0o0),  # 0/400/600/640 acceptable
        ("/etc/group", 0o644),
        ("/etc/gshadow", 0o0),
    )
    perm_issues = []
    for path, expected in critical_files:
        actual = file_mode(path)
        if actual is None:
            continue
        if expected == 0:
            ok = actual in (0o0, 0o400, 0o600, 0o640)
        else:
            ok = actual == expected
        if not ok:
            perm_issues.append(f"{path}={oct(actual)}")

    results.append(_r(
        cat,
        "Pass" if not perm_issues else "Fail",
        "HIPAA 164.312(c)(1): Critical file permissions appropriate",
        severity="High",
        details=f"Permission issues: {'; '.join(perm_issues) or 'none'}",
        remediation=(
            "chmod 0644 /etc/passwd /etc/group; chmod 0640 /etc/shadow /etc/gshadow"
        ),
        cross_references={
            "HIPAA": "164.312(c)(1)", "NIST": "AC-3", "CIS": "6.1.2",
            "STIG": "V-230322", "ISO27001": "A.8.3",
        },
    ))

    return results


# ===========================================================================
# Sec. 164.312(d) - Person or Entity Authentication
# ===========================================================================

def _check_authentication(os_info) -> List[AuditResult]:
    cat = "HIPAA 164.312(d) - Authentication"
    results: List[AuditResult] = []

    # No empty passwords
    shadow = read_file_safe("/etc/shadow")
    empty_pwd = []
    if shadow:
        for line in shadow.splitlines():
            fields = line.split(":")
            if len(fields) >= 2 and fields[1] == "":
                empty_pwd.append(fields[0])

    if shadow:  # only report if we could read shadow
        results.append(_r(
            cat,
            "Pass" if not empty_pwd else "Fail",
            "HIPAA 164.312(d): No empty-password accounts",
            severity="Critical",
            details=f"Empty-password accounts: {', '.join(empty_pwd) or 'none'}",
            remediation="passwd -l <username>  for each affected account",
            cross_references={
                "HIPAA": "164.312(d)", "NIST": "IA-5", "CIS": "6.2.5",
                "STIG": "V-230345", "PCI-DSS": "8.3.5",
            },
        ))

    # Password complexity (pwquality)
    pwquality = read_file_safe("/etc/security/pwquality.conf")
    minlen_match = re.search(r"^\s*minlen\s*=\s*(\d+)", pwquality, re.MULTILINE)
    minlen = int(minlen_match.group(1)) if minlen_match else 0

    results.append(_r(
        cat,
        "Pass" if minlen >= 8 else "Fail",
        "HIPAA 164.312(d): Password minimum length >= 8",
        severity="High",
        details=f"pwquality.conf minlen = {minlen or 'unset'} (HIPAA recommends >= 8)",
        remediation="Edit /etc/security/pwquality.conf: minlen = 14",
        cross_references={
            "HIPAA": "164.312(d)", "NIST": "IA-5(1)", "CIS": "5.4.1.1",
            "PCI-DSS": "8.3.6",
        },
    ))

    # Account lockout (HIPAA 164.308(a)(5)(ii)(C) login monitoring)
    pam_paths = (
        "/etc/security/faillock.conf",
        "/etc/pam.d/system-auth",
        "/etc/pam.d/common-auth",
        "/etc/pam.d/password-auth",
    )
    deny: Optional[int] = None
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
                deny = int(m.group(1))
                break
        if deny is not None:
            break

    lockout_ok = deny is not None and 1 <= deny <= 6

    results.append(_r(
        cat,
        "Pass" if lockout_ok else "Fail",
        "HIPAA 164.308(a)(5)(ii)(C): Account lockout configured (<=6 attempts)",
        severity="High",
        details=f"deny value: {deny or 'not configured'}",
        remediation="Configure pam_faillock with deny=5 in /etc/security/faillock.conf",
        cross_references={
            "HIPAA": "164.308(a)(5)(ii)(C)", "NIST": "AC-7",
            "CIS": "5.3.1", "STIG": "V-230333", "PCI-DSS": "8.3.4",
        },
    ))

    return results


# ===========================================================================
# Sec. 164.312(e)(1) - Transmission Security
# ===========================================================================

def _check_transmission_security(os_info) -> List[AuditResult]:
    cat = "HIPAA 164.312(e)(1) - Transmission Security"
    results: List[AuditResult] = []

    # SSH protocol and ciphers
    sshd_config = read_file_safe("/etc/ssh/sshd_config")
    if sshd_config:
        # Modern OpenSSH only supports protocol 2; check for legacy "Protocol 1"
        legacy_proto = bool(re.search(r"^\s*Protocol\s+1\b",
                                       sshd_config, re.MULTILINE))
        results.append(_r(
            cat,
            "Pass" if not legacy_proto else "Fail",
            "HIPAA 164.312(e)(1): SSH legacy protocol disabled",
            severity="Critical",
            details=f"Protocol 1 explicitly enabled: {legacy_proto}",
            remediation="Remove or comment out 'Protocol 1' in /etc/ssh/sshd_config",
            cross_references={
                "HIPAA": "164.312(e)(1)", "NIST": "SC-8", "CIS": "5.2.1",
                "ISO27001": "A.8.21", "PCI-DSS": "4.2.1",
            },
        ))

        # Strong ciphers
        weak = []
        for line in sshd_config.splitlines():
            stripped = line.strip().lower()
            if stripped.startswith("ciphers "):
                for w in ("3des", "arcfour", "blowfish", "des-cbc"):
                    if w in stripped:
                        weak.append(w)
                break

        if "ciphers " in sshd_config.lower():
            results.append(_r(
                cat,
                "Pass" if not weak else "Fail",
                "HIPAA 164.312(e)(1): SSH cipher suite excludes weak algorithms",
                severity="High",
                details=f"Weak ciphers: {', '.join(weak) or 'none'}",
                remediation=(
                    "Set in /etc/ssh/sshd_config: Ciphers "
                    "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,"
                    "aes128-gcm@openssh.com,aes256-ctr,aes128-ctr"
                ),
                cross_references={
                    "HIPAA": "164.312(e)(1)", "NIST": "SC-13",
                    "CIS": "5.2.13", "PCI-DSS": "4.2.1", "ISO27001": "A.8.24",
                },
            ))

    # No insecure remote-access services
    insecure = []
    for unit in ("telnet.socket", "rsh.socket", "rlogin.socket"):
        if systemd_active(unit) == "active":
            insecure.append(unit)

    results.append(_r(
        cat,
        "Pass" if not insecure else "Fail",
        "HIPAA 164.312(e)(1): No cleartext remote-access services",
        severity="Critical",
        details=f"Active insecure: {', '.join(insecure) or 'none'}",
        remediation="systemctl disable --now <each-unit>",
        cross_references={
            "HIPAA": "164.312(e)(1)", "NIST": "SC-8", "CIS": "2.2",
            "PCI-DSS": "2.2.4",
        },
    ))

    return results


# ===========================================================================
# Sec. 164.308(a)(5)(ii)(B) - Protection from Malicious Software
# ===========================================================================

def _check_malware_protection(os_info) -> List[AuditResult]:
    cat = "HIPAA 164.308(a)(5)(ii)(B) - Malware Protection"
    results: List[AuditResult] = []

    av_indicators = {
        "ClamAV": command_available("clamscan") or file_exists("/etc/clamav/clamd.conf"),
        "Sophos": file_exists("/opt/sophos-spl/bin/sophos_threat_detector"),
        "Falco": command_available("falco"),
        "Wazuh/OSSEC": file_exists("/var/ossec/etc/ossec.conf"),
        "ChkRootkit": command_available("chkrootkit"),
        "RKHunter": command_available("rkhunter"),
    }
    detected = [n for n, p in av_indicators.items() if p]

    results.append(_r(
        cat,
        "Pass" if detected else "Fail",
        "HIPAA 164.308(a)(5)(ii)(B): Anti-malware solution deployed",
        severity="High",
        details=f"Detected: {', '.join(detected) or 'none'}",
        remediation=(
            "Install ClamAV (free): apt-get install -y clamav clamav-daemon "
            "(Debian) or dnf install -y clamav clamav-update (RHEL)."
        ),
        cross_references={
            "HIPAA": "164.308(a)(5)(ii)(B)", "NIST": "SI-3",
            "ISO27001": "A.8.7", "PCI-DSS": "5.2.1",
        },
    ))

    return results


# ===========================================================================
# Sec. 164.308(a)(7) - Contingency Plan (Technical Indicators)
# ===========================================================================

def _check_contingency(os_info) -> List[AuditResult]:
    cat = "HIPAA 164.308(a)(7) - Contingency Plan"
    results: List[AuditResult] = []

    # Backup tooling indicator
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
        "HIPAA 164.308(a)(7)(ii)(A): Backup tooling present",
        severity="High",
        details=f"Detected: {', '.join(detected) or 'none'}",
        remediation=(
            "Install backup tooling and configure scheduled, encrypted, "
            "off-site backups. Test restoration regularly. HIPAA requires "
            "a data backup plan AND a disaster recovery plan."
        ),
        cross_references={
            "HIPAA": "164.308(a)(7)(ii)(A)", "NIST": "CP-9",
            "ISO27001": "A.8.13", "PCI-DSS": "12.10.1",
        },
    ))

    # Persistent system logs (for incident reconstruction)
    journal_persist = directory_exists("/var/log/journal")
    results.append(_r(
        cat,
        "Pass" if journal_persist else "Warning",
        "HIPAA 164.308(a)(7)(ii)(D): Persistent system logs",
        severity="Medium",
        details=f"/var/log/journal directory exists: {journal_persist}",
        remediation=(
            "mkdir -p /var/log/journal && "
            "systemd-tmpfiles --create --prefix /var/log/journal && "
            "systemctl restart systemd-journald"
        ),
        cross_references={
            "HIPAA": "164.308(a)(7)(ii)(D)", "NIST": "CP-9",
            "ISO27001": "A.8.15",
        },
    ))

    return results


# ===========================================================================
# 405(d) HICP - Selected Indicators
# ===========================================================================

def _check_hicp_indicators(os_info) -> List[AuditResult]:
    cat = "HIPAA 405(d) HICP"
    results: List[AuditResult] = []

    # HICP-1 Email Protection - SMTP server hardening if present
    postfix_main = read_file_safe("/etc/postfix/main.cf")
    if postfix_main:
        smtpd_tls = "smtpd_tls_security_level" in postfix_main
        results.append(_r(
            cat,
            "Pass" if smtpd_tls else "Warning",
            "HIPAA HICP-1: Postfix TLS security configured",
            severity="High",
            details=(
                f"smtpd_tls_security_level present in main.cf: {smtpd_tls}"
            ),
            remediation=(
                "Add to /etc/postfix/main.cf: "
                "smtpd_tls_security_level = encrypt (or may where appropriate)"
            ),
            cross_references={
                "HIPAA": "164.312(e)(1)", "NIST": "SC-8(1)",
                "ISO27001": "A.8.24", "PCI-DSS": "4.2.1",
            },
        ))

    # HICP-3 Access Management - sudo log file
    sudoers_files = ["/etc/sudoers"] + list_directory("/etc/sudoers.d", "")
    has_sudo_log = False
    for sf in sudoers_files:
        content = read_file_safe(sf)
        if re.search(r"Defaults\s+log_input|Defaults\s+log_output|Defaults\s+logfile=",
                      content):
            has_sudo_log = True
            break

    results.append(_r(
        cat,
        "Pass" if has_sudo_log else "Warning",
        "HIPAA HICP-3: Sudo command logging enabled",
        severity="Medium",
        details=f"sudo log directives found: {has_sudo_log}",
        remediation=(
            "Add to /etc/sudoers.d/00-logging: "
            "Defaults logfile=/var/log/sudo.log\nDefaults log_input,log_output"
        ),
        cross_references={
            "HIPAA": "164.308(a)(1)(ii)(D)", "NIST": "AU-12",
            "CIS": "5.5.3", "STIG": "V-230332", "ISO27001": "A.8.18",
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
        results.extend(_check_unique_user_id(os_info))
        results.extend(_check_automatic_logoff(os_info))
        results.extend(_check_encryption(os_info))
        results.extend(_check_audit_controls(os_info))
        results.extend(_check_integrity(os_info))
        results.extend(_check_authentication(os_info))
        results.extend(_check_transmission_security(os_info))
        results.extend(_check_malware_protection(os_info))
        results.extend(_check_contingency(os_info))
        results.extend(_check_hicp_indicators(os_info))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled exception in HIPAA module")
        results.append(_r(
            "HIPAA - Error", "Error",
            f"HIPAA module encountered an unhandled exception: {exc!r}",
            severity="Medium", details=str(exc),
        ))

    return results



# ===========================================================================
# v3.1 EXPANSION - HIPAA Comprehensive Coverage
# ---------------------------------------------------------------------------
# This expansion adds:
#   - Sec. 164.308 Administrative Safeguards (technical indicators)
#   - Sec. 164.310 Physical Safeguards (host-applicable subset)
#   - Sec. 164.312 Technical Safeguards (extended depth)
#   - 405(d) HICP-1 through HICP-10 (full ten threat practices)
# ===========================================================================


def _check_admin_workforce_security(os_info) -> List[AuditResult]:
    """Sec. 164.308(a)(3) - Workforce security & access management."""
    results: List[AuditResult] = []
    cat = "HIPAA - Sec. 164.308(a)(3) Workforce Access"

    # Sec. 164.308(a)(3)(ii)(A) Authorization/supervision: track sudoers privileges
    sudoers = read_file_safe("/etc/sudoers")
    sudoers_d_files = list_directory("/etc/sudoers.d")
    sudoers_combined = sudoers
    for f in sudoers_d_files:
        if f != "README":
            sudoers_combined += "\n" + read_file_safe(os.path.join("/etc/sudoers.d", f))

    # Count distinct privileged principals
    sudo_principals = set()
    for line in sudoers_combined.splitlines():
        s = line.strip()
        if s.startswith("#") or not s or s.startswith("Defaults"):
            continue
        parts = s.split()
        if len(parts) >= 2 and ("ALL" in s.upper() or "/" in s):
            sudo_principals.add(parts[0])

    results.append(_r(
        cat, "Info",
        f"Sec. 164.308(a)(3)(ii)(A): {len(sudo_principals)} principals with sudoers entries",
        severity="Informational",
        details=f"Principals with sudo privileges: {sorted(sudo_principals)}",
        remediation=(
            "Document business justification for each principal with sudo. "
            "Review and remove any unauthorized entries. "
            "Implement least-privilege access controls."
        ),
        cross_references={
            "HIPAA": "164.308(a)(3)(ii)(A)", "NIST": "AC-6", "ISO27001": "A.8.2",
            "SOC2": "CC6.3", "PCI-DSS": "7.1.2",
        },
    ))

    # Sec. 164.308(a)(3)(ii)(C) Termination procedures: detect locked vs active accounts
    shadow = read_file_safe("/etc/shadow")
    locked_count = 0
    active_count = 0
    if shadow:
        for line in shadow.splitlines():
            fields = line.split(":")
            if len(fields) < 2:
                continue
            pwd_field = fields[1]
            if pwd_field.startswith("!") or pwd_field.startswith("*"):
                locked_count += 1
            elif pwd_field and pwd_field != "x":
                active_count += 1

    results.append(_r(
        cat, "Info" if shadow else "Error",
        f"Sec. 164.308(a)(3)(ii)(C): Account state inventory ({active_count} active, {locked_count} locked)",
        severity="Informational",
        details=(
            f"Active password accounts: {active_count}, "
            f"Locked accounts: {locked_count}. "
            "Verify locked accounts correspond to terminated workforce members."
        ),
        remediation=(
            "On workforce termination, immediately lock the account: "
            "passwd -l <user>. After applicable retention period, "
            "remove with userdel -r <user>."
        ),
        cross_references={
            "HIPAA": "164.308(a)(3)(ii)(C)", "NIST": "PS-4", "ISO27001": "A.6.5",
        },
    ))

    return results


def _check_admin_information_access_management(os_info) -> List[AuditResult]:
    """Sec. 164.308(a)(4) - Information access management."""
    results: List[AuditResult] = []
    cat = "HIPAA - Sec. 164.308(a)(4) Access Management"

    # Sec. 164.308(a)(4)(ii)(B) Access authorization: PAM access control
    pam_access_conf = read_file_safe("/etc/security/access.conf")
    pam_access_active = False
    if pam_access_conf:
        for line in pam_access_conf.splitlines():
            s = line.strip()
            if s and not s.startswith("#"):
                pam_access_active = True
                break

    # Look for pam_access in PAM configs
    pam_files = ["/etc/pam.d/system-auth", "/etc/pam.d/common-auth",
                 "/etc/pam.d/login", "/etc/pam.d/sshd"]
    pam_access_loaded = False
    for f in pam_files:
        c = read_file_safe(f)
        if c and "pam_access.so" in c:
            pam_access_loaded = True
            break

    results.append(_r(
        cat, "Info" if pam_access_active and pam_access_loaded else "Warning",
        "Sec. 164.308(a)(4)(ii)(B): PAM-based access authorization configured",
        severity="Medium",
        details=(
            f"pam_access.so loaded: {pam_access_loaded}; "
            f"access.conf has rules: {pam_access_active}. "
            "PAM access control provides per-user/per-service authorization."
        ),
        remediation=(
            "Configure /etc/security/access.conf with explicit allow/deny "
            "rules. Add 'account required pam_access.so' to relevant "
            "PAM service files (login, sshd, system-auth)."
        ),
        cross_references={
            "HIPAA": "164.308(a)(4)(ii)(B)", "NIST": "AC-3", "ISO27001": "A.8.3",
        },
    ))

    # Sec. 164.308(a)(4)(ii)(C) Access establishment/modification: useradd defaults
    useradd_defaults = read_file_safe("/etc/default/useradd")
    inactive_value = ""
    expire_value = ""
    if useradd_defaults:
        for line in useradd_defaults.splitlines():
            s = line.strip()
            if s.startswith("INACTIVE="):
                inactive_value = s.split("=", 1)[1].strip()
            elif s.startswith("EXPIRE="):
                expire_value = s.split("=", 1)[1].strip()

    try:
        inactive_int = int(inactive_value) if inactive_value else -1
    except ValueError:
        inactive_int = -1

    inactive_ok = 0 < inactive_int <= 35
    results.append(_r(
        cat, "Pass" if inactive_ok else "Warning",
        "Sec. 164.308(a)(4)(ii)(C): Inactive accounts auto-disabled (<= 35 days)",
        severity="Medium",
        details=f"INACTIVE = {inactive_value or 'unset'} (recommend <= 35)",
        remediation=(
            "Set in /etc/default/useradd: INACTIVE=35. "
            "Apply to existing users: chage --inactive 35 <user>."
        ),
        cross_references={
            "HIPAA": "164.308(a)(4)(ii)(C)", "NIST": "AC-2(3)", "CIS": "5.4.1.5",
            "STIG": "V-230372",
        },
    ))

    return results


def _check_admin_security_awareness(os_info) -> List[AuditResult]:
    """Sec. 164.308(a)(5) - Security awareness/training (technical indicators)."""
    results: List[AuditResult] = []
    cat = "HIPAA - Sec. 164.308(a)(5) Security Awareness"

    # Sec. 164.308(a)(5)(ii)(A) Periodic security reminders: login banners
    issue_net = read_file_safe("/etc/issue.net")
    issue_local = read_file_safe("/etc/issue")
    motd = read_file_safe("/etc/motd")

    has_banner = bool(
        (issue_net and len(issue_net.strip()) > 50) or
        (issue_local and len(issue_local.strip()) > 50)
    )

    results.append(_r(
        cat, "Pass" if has_banner else "Fail",
        "Sec. 164.308(a)(5)(ii)(A): Login banner with security/privacy notice",
        severity="Medium",
        details=(
            f"/etc/issue.net length: {len(issue_net.strip())}, "
            f"/etc/issue length: {len(issue_local.strip())}. "
            "Banner should include unauthorized access warning and HIPAA notice."
        ),
        remediation=(
            "Configure /etc/issue.net with HIPAA-appropriate notice including: "
            "system contains protected health information, unauthorized access "
            "is prohibited, monitoring may occur, and contact information."
        ),
        cross_references={
            "HIPAA": "164.308(a)(5)(ii)(A)", "NIST": "AC-8", "CIS": "1.7.1",
            "STIG": "V-230225",
        },
    ))

    # Sec. 164.308(a)(5)(ii)(B) Protection from malicious software (existing check enhanced)
    av_indicators = {
        "ClamAV": command_available("clamscan"),
        "Sophos": file_exists("/opt/sophos-spl/bin/sophos_threat_detector"),
        "ESET": file_exists("/opt/eset/efs/sbin/efs"),
        "MDE": file_exists("/opt/microsoft/mdatp/sbin/wdavdaemon"),
        "CrowdStrike": file_exists("/opt/CrowdStrike/falcon-sensor"),
        "Falco": command_available("falco"),
        "Wazuh": file_exists("/var/ossec/etc/ossec.conf"),
    }
    detected = [k for k, v in av_indicators.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Fail",
        f"Sec. 164.308(a)(5)(ii)(B): Anti-malware/EDR deployed ({len(detected)} found)",
        severity="High",
        details=f"Detected: {', '.join(detected) or 'none'}",
        remediation=(
            "Deploy enterprise EDR (CrowdStrike, MDE, SentinelOne) or "
            "open-source equivalent (Wazuh, Falco, ClamAV)."
        ),
        cross_references={
            "HIPAA": "164.308(a)(5)(ii)(B)", "NIST": "SI-3", "PCI-DSS": "5.2",
            "ISO27001": "A.8.7",
        },
    ))

    # Sec. 164.308(a)(5)(ii)(C) Login monitoring: faillock/wtmp/btmp
    btmp_exists = file_exists("/var/log/btmp")
    wtmp_exists = file_exists("/var/log/wtmp")
    lastlog_exists = file_exists("/var/log/lastlog")

    login_log_ok = btmp_exists and wtmp_exists and lastlog_exists
    results.append(_r(
        cat, "Pass" if login_log_ok else "Fail",
        "Sec. 164.308(a)(5)(ii)(C): Login monitoring infrastructure present",
        severity="Medium",
        details=(
            f"/var/log/btmp (failed): {btmp_exists}, "
            f"/var/log/wtmp (success): {wtmp_exists}, "
            f"/var/log/lastlog: {lastlog_exists}"
        ),
        remediation=(
            "Ensure btmp/wtmp logging enabled. PAM should log via "
            "pam_lastlog and pam_faillock. Centralize logs to SIEM."
        ),
        cross_references={
            "HIPAA": "164.308(a)(5)(ii)(C)", "NIST": "AU-2", "PCI-DSS": "10.2",
        },
    ))

    return results


def _check_admin_security_incident(os_info) -> List[AuditResult]:
    """Sec. 164.308(a)(6) - Security incident procedures."""
    results: List[AuditResult] = []
    cat = "HIPAA - Sec. 164.308(a)(6) Incident Response"

    # Sec. 164.308(a)(6)(ii) Response and reporting: detection capability
    ids_present = (
        command_available("falco") or
        file_exists("/var/ossec/etc/ossec.conf") or
        command_available("suricata") or
        file_exists("/etc/snort/snort.conf")
    )

    results.append(_r(
        cat, "Pass" if ids_present else "Fail",
        "Sec. 164.308(a)(6)(ii): Intrusion detection capability for incident identification",
        severity="High",
        details=f"IDS/HIDS detected: {ids_present}",
        remediation=(
            "Deploy Wazuh (HIDS+SIEM), Falco (runtime), or commercial EDR. "
            "Required for HIPAA breach detection within reasonable timeframe."
        ),
        cross_references={
            "HIPAA": "164.308(a)(6)(ii)", "NIST": "IR-4", "ISO27001": "A.5.24",
            "PCI-DSS": "12.10",
        },
    ))

    # Audit log forwarding for incident analysis
    rsyslog_d = list_directory("/etc/rsyslog.d", suffix=".conf")
    forwarding_configured = False
    for f in rsyslog_d:
        c = read_file_safe(os.path.join("/etc/rsyslog.d", f))
        if any(p in c for p in ["@@", "@!", "omfwd", "omrelp"]):
            forwarding_configured = True
            break
    if not forwarding_configured:
        c = read_file_safe("/etc/rsyslog.conf")
        forwarding_configured = any(p in c for p in ["@@", "omfwd"])

    # Also check journald forwarding
    journald_conf = read_file_safe("/etc/systemd/journald.conf")
    journald_forward = "ForwardToSyslog=yes" in journald_conf

    log_forwarding_ok = forwarding_configured or journald_forward
    results.append(_r(
        cat, "Pass" if log_forwarding_ok else "Warning",
        "Sec. 164.308(a)(6)(ii): Audit logs forwarded for incident reconstruction",
        severity="High",
        details=(
            f"rsyslog forwarding: {forwarding_configured}, "
            f"journald->syslog: {journald_forward}"
        ),
        remediation=(
            "Configure /etc/rsyslog.d/50-remote.conf to forward to SIEM: "
            "*.* @@siem.example.com:6514 (TLS recommended)"
        ),
        cross_references={
            "HIPAA": "164.308(a)(6)(ii)", "NIST": "AU-6(3)", "PCI-DSS": "10.5.4",
        },
    ))

    return results


def _check_admin_contingency(os_info) -> List[AuditResult]:
    """Sec. 164.308(a)(7) - Contingency plan."""
    results: List[AuditResult] = []
    cat = "HIPAA - Sec. 164.308(a)(7) Contingency Plan"

    # Sec. 164.308(a)(7)(ii)(A) Data backup plan
    backup_tools = {
        "rsync": command_available("rsync"),
        "borg": command_available("borg"),
        "restic": command_available("restic"),
        "duplicity": command_available("duplicity"),
        "bacula": file_exists("/etc/bacula/bacula-fd.conf"),
        "amanda": command_available("amrecover"),
        "duply": command_available("duply"),
    }
    detected = [k for k, v in backup_tools.items() if v]
    results.append(_r(
        cat, "Info",
        f"Sec. 164.308(a)(7)(ii)(A): Backup tools available ({len(detected)} found)",
        severity="Medium",
        details=f"Detected: {', '.join(detected) or 'none'}",
        remediation=(
            "Establish regular backup schedule with offsite copy. "
            "Tools: borg/restic for encrypted backups, rsync for file sync. "
            "Enterprise: Veeam, Veritas NetBackup, Commvault."
        ),
        cross_references={
            "HIPAA": "164.308(a)(7)(ii)(A)", "NIST": "CP-9", "ISO27001": "A.8.13",
        },
    ))

    # Sec. 164.308(a)(7)(ii)(C) Emergency mode operation: minimum kernel + dracut presence
    rescue_target = systemd_active("rescue.target")
    emergency_target_exists = file_exists("/usr/lib/systemd/system/emergency.target") or \
                              file_exists("/lib/systemd/system/emergency.target")

    results.append(_r(
        cat, "Pass" if emergency_target_exists else "Info",
        "Sec. 164.308(a)(7)(ii)(C): Emergency boot capability present",
        severity="Low",
        details=f"emergency.target available: {emergency_target_exists}",
        remediation=(
            "Maintain rescue/emergency boot capability. "
            "Verify GRUB recovery menu works."
        ),
        cross_references={
            "HIPAA": "164.308(a)(7)(ii)(C)", "NIST": "CP-10",
        },
    ))

    return results


def _check_physical_safeguards(os_info) -> List[AuditResult]:
    """Sec. 164.310 - Physical Safeguards (host-applicable subset)."""
    results: List[AuditResult] = []
    cat = "HIPAA - Sec. 164.310 Physical Safeguards"

    # Sec. 164.310(c) Workstation security: screen lock detection
    # Check for lock-screen utilities
    lock_tools = {
        "vlock": command_available("vlock"),
        "physlock": command_available("physlock"),
        "i3lock": command_available("i3lock"),
        "xscreensaver": command_available("xscreensaver"),
        "gnome-screensaver": command_available("gnome-screensaver"),
    }
    detected_lockers = [k for k, v in lock_tools.items() if v]

    results.append(_r(
        cat, "Info",
        f"Sec. 164.310(c): Screen lock tooling ({len(detected_lockers)} found)",
        severity="Medium",
        details=f"Detected: {', '.join(detected_lockers) or 'none (acceptable on headless servers)'}",
        remediation=(
            "On workstations, configure auto-lock after idle period. "
            "Headless servers don't require this control."
        ),
        cross_references={
            "HIPAA": "164.310(c)", "NIST": "AC-11", "ISO27001": "A.7.9",
        },
    ))

    # Sec. 164.310(d)(2)(i) Disposal: secure deletion tooling
    deletion_tools = {
        "shred": command_available("shred"),
        "wipe": command_available("wipe"),
        "srm": command_available("srm"),
        "scrub": command_available("scrub"),
        "blkdiscard": command_available("blkdiscard"),
    }
    detected_del = [k for k, v in deletion_tools.items() if v]

    results.append(_r(
        cat, "Pass" if detected_del else "Warning",
        f"Sec. 164.310(d)(2)(i): Secure deletion tooling available ({len(detected_del)} found)",
        severity="Medium",
        details=f"Detected: {', '.join(detected_del) or 'none'}",
        remediation=(
            "Install coreutils (provides shred). For SSDs use blkdiscard. "
            "For full-disk: cryptsetup erase (LUKS) or hdparm secure-erase."
        ),
        cross_references={
            "HIPAA": "164.310(d)(2)(i)", "NIST": "MP-6", "ISO27001": "A.7.14",
            "PCI-DSS": "9.4.7",
        },
    ))

    # Sec. 164.310(d)(2)(iii) Accountability: media tracking via audit
    auditd_active = systemd_active("auditd.service") == "active"
    audit_rules_d = list_directory("/etc/audit/rules.d")
    has_mount_rules = False
    for rf in audit_rules_d:
        c = read_file_safe(os.path.join("/etc/audit/rules.d", rf))
        if "mount" in c.lower() or "umount" in c.lower():
            has_mount_rules = True
            break

    results.append(_r(
        cat, "Pass" if auditd_active and has_mount_rules else "Warning",
        "Sec. 164.310(d)(2)(iii): Removable media access auditing configured",
        severity="Medium",
        details=(
            f"auditd active: {auditd_active}, "
            f"mount/umount audit rules: {has_mount_rules}"
        ),
        remediation=(
            "Add to /etc/audit/rules.d/40-removable.rules: "
            "-a always,exit -F arch=b64 -S mount -S umount2 -k removable_media"
        ),
        cross_references={
            "HIPAA": "164.310(d)(2)(iii)", "NIST": "MP-4", "ISO27001": "A.7.10",
        },
    ))

    # Sec. 164.310(d)(1) Device controls: USBGuard
    usbguard_active = systemd_active("usbguard.service") == "active"
    results.append(_r(
        cat, "Pass" if usbguard_active else "Info",
        "Sec. 164.310(d)(1): USB device control (USBGuard)",
        severity="Medium",
        details=f"usbguard service: {systemd_active('usbguard.service')}",
        remediation=remediation_for("usbguard"),
        cross_references={
            "HIPAA": "164.310(d)(1)", "NIST": "MP-7", "PCI-DSS": "9.5",
        },
    ))

    return results


def _check_tech_audit_extended(os_info) -> List[AuditResult]:
    """Sec. 164.312(b) - Audit Controls (extended depth)."""
    results: List[AuditResult] = []
    cat = "HIPAA - Sec. 164.312(b) Audit Controls"

    # Verify auditd buffer size adequate
    auditd_conf = read_file_safe("/etc/audit/auditd.conf")
    audit_rules = read_file_safe("/etc/audit/audit.rules")
    rules_d = list_directory("/etc/audit/rules.d", suffix=".rules")
    for rf in rules_d:
        audit_rules += "\n" + read_file_safe(os.path.join("/etc/audit/rules.d", rf))

    # Buffer size from -b flag in rules
    buffer_match = re.search(r"-b\s+(\d+)", audit_rules)
    buffer_size = int(buffer_match.group(1)) if buffer_match else 0

    results.append(_r(
        cat, "Pass" if buffer_size >= 8192 else "Warning",
        "Sec. 164.312(b): Audit buffer adequately sized (>= 8192)",
        severity="Medium",
        details=f"Configured buffer: {buffer_size or 'default'}",
        remediation=(
            "Add to /etc/audit/rules.d/00-buffer.rules: -b 8192 "
            "(or larger for high-volume systems)"
        ),
        cross_references={
            "HIPAA": "164.312(b)", "NIST": "AU-4", "STIG": "V-230401",
        },
    ))

    # disk_full_action - HIPAA log integrity requires noisy fail mode
    disk_full = ""
    for line in auditd_conf.splitlines():
        s = line.strip()
        if s.startswith("disk_full_action") and "=" in s:
            disk_full = s.split("=", 1)[1].strip().lower()

    df_ok = disk_full in ("halt", "single", "syslog")
    results.append(_r(
        cat, "Pass" if df_ok else "Fail",
        "Sec. 164.312(b): Audit disk-full action prevents silent log loss",
        severity="High",
        details=f"disk_full_action = {disk_full or 'default (suspend)'}",
        remediation=(
            "Set in /etc/audit/auditd.conf: disk_full_action = SYSLOG  "
            "(or HALT for stricter posture)"
        ),
        cross_references={
            "HIPAA": "164.312(b)", "NIST": "AU-5", "STIG": "V-230399",
            "PCI-DSS": "10.7",
        },
    ))

    # max_log_file_action - rotation with notification
    max_action = ""
    for line in auditd_conf.splitlines():
        s = line.strip()
        if s.startswith("max_log_file_action") and "=" in s:
            max_action = s.split("=", 1)[1].strip().lower()

    max_ok = max_action in ("rotate", "keep_logs")
    results.append(_r(
        cat, "Pass" if max_ok else "Warning",
        "Sec. 164.312(b): Audit log rotation policy prevents data loss",
        severity="Medium",
        details=f"max_log_file_action = {max_action or 'default (rotate)'}",
        remediation=(
            "Set in /etc/audit/auditd.conf: max_log_file_action = keep_logs"
        ),
        cross_references={
            "HIPAA": "164.312(b)", "NIST": "AU-4", "STIG": "V-230400",
        },
    ))

    # Verify auditd has identity-modification rules
    identity_files = ["/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow",
                      "/etc/security/opasswd"]
    identity_audited = sum(1 for f in identity_files if f in audit_rules)
    results.append(_r(
        cat, "Pass" if identity_audited >= 4 else "Fail",
        f"Sec. 164.312(b): Identity files audited ({identity_audited}/5 covered)",
        severity="High",
        details=f"Audited identity files in rules: {identity_audited}/5",
        remediation=(
            "Add to /etc/audit/rules.d/30-identity.rules: "
            "-w /etc/passwd -p wa -k identity, similarly for "
            "/etc/group /etc/shadow /etc/gshadow /etc/security/opasswd"
        ),
        cross_references={
            "HIPAA": "164.312(b)", "NIST": "AU-2", "CIS": "4.1.3.10",
            "STIG": "V-230415",
        },
    ))

    # Privileged-command auditing
    priv_cmds_audited = (
        "perm_mod" in audit_rules or
        "/usr/bin/sudo" in audit_rules or
        "-S setuid" in audit_rules
    )
    results.append(_r(
        cat, "Pass" if priv_cmds_audited else "Fail",
        "Sec. 164.312(b): Privileged command execution audited",
        severity="High",
        details=f"Privileged-command auditing rules present: {priv_cmds_audited}",
        remediation=(
            "Add to /etc/audit/rules.d/30-priv.rules: "
            "-a always,exit -F path=/usr/bin/sudo -F perm=x -k priv_cmd; "
            "and per-syscall rules for setuid/setgid"
        ),
        cross_references={
            "HIPAA": "164.312(b)", "NIST": "AU-2", "CIS": "4.1.3.7",
            "STIG": "V-230423",
        },
    ))

    return results


def _check_tech_integrity_extended(os_info) -> List[AuditResult]:
    """Sec. 164.312(c) - Integrity controls (extended depth)."""
    results: List[AuditResult] = []
    cat = "HIPAA - Sec. 164.312(c) Integrity"

    # FIM database age check
    aide_db_paths = ["/var/lib/aide/aide.db", "/var/lib/aide/aide.db.gz"]
    aide_db_path = first_existing(*aide_db_paths)

    if aide_db_path:
        try:
            import time
            mtime = os.stat(aide_db_path).st_mtime
            age_days = (time.time() - mtime) / 86400
            age_ok = age_days < 30
            results.append(_r(
                cat, "Pass" if age_ok else "Warning",
                f"Sec. 164.312(c)(1): AIDE database recent (age: {age_days:.0f} days)",
                severity="Medium",
                details=f"AIDE database: {aide_db_path}, age: {age_days:.1f} days",
                remediation=(
                    "Re-baseline AIDE: aide --update && "
                    "cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db. "
                    "Schedule via cron: 0 4 * * 0 aide --check"
                ),
                cross_references={
                    "HIPAA": "164.312(c)(1)", "NIST": "SI-7", "PCI-DSS": "11.5",
                },
            ))
        except OSError:
            pass

    # IMA/EVM kernel integrity (if available)
    ima_active = file_exists("/sys/kernel/security/ima/policy")
    if ima_active:
        ima_runtime = file_exists("/sys/kernel/security/ima/runtime_measurements_count")
        results.append(_r(
            cat, "Info",
            "Sec. 164.312(c)(1): Kernel IMA (Integrity Measurement Architecture) active",
            severity="Informational",
            details=f"IMA policy interface present: {ima_active}, runtime: {ima_runtime}",
            cross_references={
                "HIPAA": "164.312(c)(1)", "NIST": "SI-7", "NSA": "INTEGRITY-1.1",
            },
        ))

    # Critical /etc file permissions
    critical_files = {
        "/etc/passwd": (0o644, 0, 0),
        "/etc/shadow": (0o000, 0, None),  # 000-640 acceptable
        "/etc/group": (0o644, 0, 0),
        "/etc/gshadow": (0o000, 0, None),
        "/etc/ssh/sshd_config": (0o600, 0, 0),
        "/etc/sudoers": (0o440, 0, 0),
        "/boot/grub2/grub.cfg": (0o600, 0, 0),
        "/boot/grub/grub.cfg": (0o644, 0, 0),
    }

    perm_failures = []
    for path, (max_mode, owner, group) in critical_files.items():
        if not file_exists(path):
            continue
        actual_mode = file_mode(path)
        if actual_mode is None:
            continue
        if actual_mode > max_mode and max_mode != 0o000:
            perm_failures.append(f"{path}: mode {oct(actual_mode)} (max {oct(max_mode)})")
        # Owner check
        owner_info = file_owner(path)
        if owner_info:
            uid, gid = owner_info
            if owner is not None and uid != owner:
                perm_failures.append(f"{path}: uid {uid} (expected {owner})")

    results.append(_r(
        cat, "Pass" if not perm_failures else "Fail",
        f"Sec. 164.312(c)(1): Critical file permissions correct ({len(perm_failures)} issues)",
        severity="High",
        details=f"Permission issues: {'; '.join(perm_failures[:5])}" if perm_failures else "All checked files have correct permissions",
        remediation=(
            "Restore permissions: chmod 644 /etc/passwd; chmod 0 /etc/shadow; "
            "chmod 600 /etc/ssh/sshd_config; chmod 440 /etc/sudoers; "
            "chown root:root <each>"
        ),
        cross_references={
            "HIPAA": "164.312(c)(1)", "NIST": "AC-3", "CIS": "6.1.1",
            "STIG": "V-230311", "PCI-DSS": "7.2",
        },
    ))

    return results


def _check_tech_transmission_extended(os_info) -> List[AuditResult]:
    """Sec. 164.312(e) - Transmission security (extended depth)."""
    results: List[AuditResult] = []
    cat = "HIPAA - Sec. 164.312(e) Transmission Security"

    # Insecure remote services should be absent
    insecure = {
        "telnetd": file_exists("/usr/sbin/in.telnetd") or command_available("telnetd"),
        "rsh": file_exists("/usr/sbin/in.rshd") or command_available("rshd"),
        "rlogin": file_exists("/usr/sbin/in.rlogind"),
        "tftpd-no-tls": file_exists("/usr/sbin/in.tftpd"),
        "vsftpd-plain": (
            file_exists("/etc/vsftpd.conf") and
            "ssl_enable=YES" not in read_file_safe("/etc/vsftpd.conf")
        ),
    }
    present = [k for k, v in insecure.items() if v]
    results.append(_r(
        cat, "Pass" if not present else "Fail",
        f"Sec. 164.312(e)(1): No cleartext remote services ({len(present)} found)",
        severity="Critical" if present else "High",
        details=f"Cleartext services detected: {', '.join(present) or 'none'}",
        remediation=(
            "Remove insecure servers: apt-get purge -y telnetd rsh-server "
            "tftpd-hpa. Use SSH/SFTP for remote access."
        ),
        cross_references={
            "HIPAA": "164.312(e)(1)", "NIST": "SC-8", "CIS": "2.2",
            "PCI-DSS": "4.2", "STIG": "V-230557",
        },
    ))

    # SMTP TLS for outbound mail (if Postfix present)
    postfix_main = read_file_safe("/etc/postfix/main.cf")
    if postfix_main:
        smtp_tls = "smtp_tls_security_level" in postfix_main
        smtp_tls_strong = re.search(
            r"smtp_tls_security_level\s*=\s*(encrypt|verify|secure)", postfix_main
        )
        results.append(_r(
            cat, "Pass" if smtp_tls_strong else ("Warning" if smtp_tls else "Fail"),
            "Sec. 164.312(e)(1): Postfix SMTP outbound TLS enforced",
            severity="High",
            details=(
                f"smtp_tls_security_level configured: {smtp_tls}, "
                f"strong: {bool(smtp_tls_strong)}"
            ),
            remediation=(
                "In /etc/postfix/main.cf: smtp_tls_security_level = encrypt "
                "(minimum) or verify (preferred)"
            ),
            cross_references={
                "HIPAA": "164.312(e)(1)", "NIST": "SC-8(1)", "PCI-DSS": "4.2",
            },
        ))

    # NFS encryption (Kerberos)
    nfs_exports = read_file_safe("/etc/exports")
    if nfs_exports:
        krb_present = any(
            "sec=krb5" in line for line in nfs_exports.splitlines()
        )
        results.append(_r(
            cat, "Pass" if krb_present else "Warning",
            "Sec. 164.312(e)(1): NFS exports use Kerberos security",
            severity="High",
            details=(
                f"NFS exports configured with sec=krb5 or krb5i/krb5p: {krb_present}. "
                "Without Kerberos, NFS traffic is in cleartext."
            ),
            remediation=(
                "Modify /etc/exports to use sec=krb5p (preferred) or sec=krb5i "
                "for ePHI-bearing exports"
            ),
            cross_references={
                "HIPAA": "164.312(e)(1)", "NIST": "SC-8", "PCI-DSS": "4.2.1",
            },
        ))

    # Apache/Nginx TLS configuration audit
    apache_conf_exists = (
        directory_exists("/etc/apache2") or
        directory_exists("/etc/httpd")
    )
    nginx_conf_exists = directory_exists("/etc/nginx")

    if apache_conf_exists or nginx_conf_exists:
        # Look for SSL protocol config in main configs
        web_configs_to_check = []
        if apache_conf_exists:
            web_configs_to_check.extend([
                "/etc/apache2/mods-enabled/ssl.conf",
                "/etc/apache2/conf-enabled/ssl-params.conf",
                "/etc/httpd/conf.d/ssl.conf",
            ])
        if nginx_conf_exists:
            web_configs_to_check.append("/etc/nginx/nginx.conf")

        weak_proto_found = False
        for cf in web_configs_to_check:
            content = read_file_safe(cf)
            if not content:
                continue
            for line in content.splitlines():
                s = line.strip().lower()
                if s.startswith("#"):
                    continue
                if "sslprotocol" in s or "ssl_protocols" in s:
                    if "sslv2" in s or "sslv3" in s or "tlsv1.0" in s.replace(" ", "") or "tlsv1.1" in s.replace(" ", ""):
                        # Allowed unless explicitly negated
                        if "-sslv2" not in s and "-sslv3" not in s and "-tlsv1" not in s.replace(" ", ""):
                            weak_proto_found = True

        results.append(_r(
            cat, "Warning" if weak_proto_found else "Pass",
            "Sec. 164.312(e)(1): Web server TLS configuration excludes SSLv2/SSLv3/TLSv1.0",
            severity="High",
            details=(
                f"Weak protocol indicators found: {weak_proto_found}. "
                "Manual review recommended for site-specific configs."
            ),
            remediation=(
                "Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3. "
                "Nginx: ssl_protocols TLSv1.2 TLSv1.3;"
            ),
            cross_references={
                "HIPAA": "164.312(e)(1)", "NIST": "SC-13", "PCI-DSS": "4.2.1",
                "NSA": "CRYPTO-2.1",
            },
        ))

    return results


def _check_hicp_endpoint_protection(os_info) -> List[AuditResult]:
    """405(d) HICP-2 - Endpoint Protection."""
    results: List[AuditResult] = []
    cat = "HIPAA - HICP-2 Endpoint Protection"

    # Host firewall verification
    fw_active = (
        systemd_active("firewalld.service") == "active" or
        systemd_active("ufw.service") == "active" or
        systemd_active("nftables.service") == "active" or
        systemd_active("iptables.service") == "active"
    )
    results.append(_r(
        cat, "Pass" if fw_active else "Fail",
        "HICP-2: Host firewall service active",
        severity="High",
        details=f"Firewall active: {fw_active}",
        remediation=(
            "Enable firewall: systemctl enable --now firewalld (RHEL family) "
            "or ufw enable (Debian/Ubuntu) or systemctl enable --now nftables"
        ),
        cross_references={
            "HIPAA": "164.308(a)(5)(ii)(B)-HICP2", "NIST": "SC-7", "PCI-DSS": "1.2",
        },
    ))

    # Host-based intrusion detection
    hids = file_exists("/var/ossec/etc/ossec.conf") or command_available("falco")
    results.append(_r(
        cat, "Pass" if hids else "Fail",
        "HICP-2: Host-based intrusion detection deployed",
        severity="High",
        details=f"HIDS detected: {hids}",
        remediation=(
            "Deploy Wazuh agent (HIDS+SIEM) or Falco (runtime)."
        ),
        cross_references={
            "HIPAA": "164.308(a)(5)(ii)(B)-HICP2", "NIST": "SI-4",
        },
    ))

    return results


def _check_hicp_access_management(os_info) -> List[AuditResult]:
    """405(d) HICP-3 - Access Management."""
    results: List[AuditResult] = []
    cat = "HIPAA - HICP-3 Access Management"

    # MFA via PAM modules
    pam_files = ["/etc/pam.d/sshd", "/etc/pam.d/system-auth", "/etc/pam.d/common-auth"]
    mfa_modules = ["pam_google_authenticator", "pam_yubico", "pam_oath",
                   "pam_duo", "pam_u2f", "pam_pkcs11"]
    detected_mfa = set()
    for f in pam_files:
        c = read_file_safe(f)
        if not c:
            continue
        for mod in mfa_modules:
            if mod + ".so" in c:
                detected_mfa.add(mod.replace("pam_", ""))

    results.append(_r(
        cat, "Pass" if detected_mfa else "Fail",
        f"HICP-3: Multi-factor authentication PAM module loaded ({len(detected_mfa)} found)",
        severity="High",
        details=f"MFA modules detected: {sorted(detected_mfa) or 'none'}",
        remediation=(
            "Install MFA: apt-get install -y libpam-google-authenticator. "
            "Configure /etc/pam.d/sshd with: auth required pam_google_authenticator.so. "
            "Set ChallengeResponseAuthentication yes in sshd_config."
        ),
        cross_references={
            "HIPAA": "164.312(d)-HICP3", "NIST": "IA-2(1)", "PCI-DSS": "8.4",
            "CISA": "CPG-1.D",
        },
    ))

    # Privileged account separation
    wheel_members_file = read_file_safe("/etc/group")
    wheel_users = []
    sudo_users = []
    for line in wheel_members_file.splitlines():
        fields = line.split(":")
        if len(fields) >= 4:
            grp_name = fields[0]
            members = fields[3]
            if grp_name == "wheel" and members:
                wheel_users = [u for u in members.split(",") if u]
            elif grp_name == "sudo" and members:
                sudo_users = [u for u in members.split(",") if u]

    privileged_total = len(set(wheel_users + sudo_users))
    results.append(_r(
        cat, "Info",
        f"HICP-3: Privileged user inventory ({privileged_total} principals)",
        severity="Medium",
        details=(
            f"Members of 'wheel': {wheel_users}, "
            f"Members of 'sudo': {sudo_users}"
        ),
        remediation=(
            "Maintain inventory of privileged users. Review quarterly. "
            "Remove users on termination or role change."
        ),
        cross_references={
            "HIPAA": "164.308(a)(4)-HICP3", "NIST": "AC-2(7)", "ISO27001": "A.8.2",
        },
    ))

    return results


def _check_hicp_data_protection(os_info) -> List[AuditResult]:
    """405(d) HICP-4 - Data Protection and Loss Prevention."""
    results: List[AuditResult] = []
    cat = "HIPAA - HICP-4 Data Protection"

    # Full-disk encryption (LUKS)
    luks_present = False
    if command_available("dmsetup"):
        rc, out, _ = run_command(["dmsetup", "ls", "--target=crypt"])
        if rc == 0 and out and "No devices" not in out:
            luks_present = True

    results.append(_r(
        cat, "Pass" if luks_present else "Fail",
        "HICP-4: Disk-level encryption active (LUKS)",
        severity="High",
        details=f"LUKS-encrypted devices: {luks_present}",
        remediation=(
            "For new systems: install with LUKS encryption enabled. "
            "For existing: cryptsetup luksFormat <device> (requires data migration). "
            "Note: cloud instances often use provider-managed encryption (acceptable)."
        ),
        cross_references={
            "HIPAA": "164.312(a)(2)(iv)-HICP4", "NIST": "SC-28", "PCI-DSS": "3.5",
            "GDPR": "Art-32",
        },
    ))

    # File-level encryption capability (fscrypt/eCryptfs)
    fs_crypto = (
        command_available("fscrypt") or
        command_available("ecryptfs-setup-private") or
        file_exists("/sys/fs/ext4/features/encryption")
    )
    results.append(_r(
        cat, "Info",
        f"HICP-4: Filesystem-level encryption available: {fs_crypto}",
        severity="Informational",
        details=(
            f"fscrypt: {command_available('fscrypt')}, "
            f"ecryptfs: {command_available('ecryptfs-setup-private')}"
        ),
        remediation=(
            "For per-user encryption: apt-get install -y fscrypt && "
            "fscrypt setup. Useful for shared systems."
        ),
        cross_references={
            "HIPAA": "164.312(a)(2)(iv)-HICP4", "NIST": "SC-28", "GDPR": "Art-32",
        },
    ))

    # Network DLP indicators
    dlp_tools = {
        "fail2ban": systemd_active("fail2ban.service") == "active",
        "audit-rsyslog-forward": False,  # populated below
    }
    rsyslog_d = list_directory("/etc/rsyslog.d", suffix=".conf")
    for f in rsyslog_d:
        c = read_file_safe(os.path.join("/etc/rsyslog.d", f))
        if "@@" in c or "omfwd" in c:
            dlp_tools["audit-rsyslog-forward"] = True
            break

    detected_dlp = [k for k, v in dlp_tools.items() if v]
    results.append(_r(
        cat, "Info",
        f"HICP-4: Data loss prevention indicators ({len(detected_dlp)} found)",
        severity="Medium",
        details=f"Indicators present: {detected_dlp}",
        remediation=(
            "Centralize logs to SIEM, enable fail2ban for brute-force prevention, "
            "deploy network DLP at perimeter."
        ),
        cross_references={
            "HIPAA": "164.308(a)(1)(ii)(D)-HICP4", "NIST": "SC-7(10)",
        },
    ))

    return results


def _check_hicp_asset_management(os_info) -> List[AuditResult]:
    """405(d) HICP-5 - IT Asset Management."""
    results: List[AuditResult] = []
    cat = "HIPAA - HICP-5 Asset Management"

    # Software inventory tools
    inv_tools = {
        "dpkg": command_available("dpkg"),
        "rpm": command_available("rpm"),
        "pacman": command_available("pacman"),
        "apk": command_available("apk"),
        "snap": command_available("snap"),
        "flatpak": command_available("flatpak"),
    }
    detected = [k for k, v in inv_tools.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Fail",
        f"HICP-5: Package inventory tooling available ({len(detected)} found)",
        severity="Low",
        details=f"Available: {detected}",
        remediation=(
            "Verify package manager works: dpkg --list (Debian) or "
            "rpm -qa (RHEL). Periodically export inventory to CMDB."
        ),
        cross_references={
            "HIPAA": "164.310(d)(1)-HICP5", "NIST": "CM-8",
        },
    ))

    # Configuration management agent
    cm_agents = {
        "ansible": command_available("ansible") or directory_exists("/etc/ansible"),
        "puppet": command_available("puppet") or file_exists("/etc/puppetlabs/puppet/puppet.conf"),
        "salt-minion": file_exists("/etc/salt/minion"),
        "chef-client": command_available("chef-client"),
    }
    detected_cm = [k for k, v in cm_agents.items() if v]
    results.append(_r(
        cat, "Info",
        f"HICP-5: Configuration management agent ({len(detected_cm)} found)",
        severity="Informational",
        details=f"Agents: {detected_cm or 'none'}",
        remediation=(
            "Configuration management ensures consistent, audited deployments. "
            "Recommended: Ansible (agentless) or Puppet/Chef/Salt."
        ),
        cross_references={
            "HIPAA": "164.308(a)(8)-HICP5", "NIST": "CM-2",
        },
    ))

    return results


def _check_hicp_network_management(os_info) -> List[AuditResult]:
    """405(d) HICP-6 - Network Management."""
    results: List[AuditResult] = []
    cat = "HIPAA - HICP-6 Network Management"

    # Network sysctls for HIPAA-grade hardening
    sysctls_to_check = [
        ("net.ipv4.conf.all.accept_redirects", "0", "ICMP redirects ignored"),
        ("net.ipv4.conf.all.send_redirects", "0", "ICMP redirects not sent"),
        ("net.ipv4.conf.all.accept_source_route", "0", "Source routing rejected"),
        ("net.ipv4.conf.all.log_martians", "1", "Martian packets logged"),
        ("net.ipv4.icmp_echo_ignore_broadcasts", "1", "Broadcast pings ignored"),
        ("net.ipv4.icmp_ignore_bogus_error_responses", "1", "Bogus ICMP errors ignored"),
        ("net.ipv4.tcp_syncookies", "1", "SYN cookies enabled"),
        ("net.ipv4.conf.all.rp_filter", "1", "Reverse path filtering enabled"),
    ]

    for key, expected, desc in sysctls_to_check:
        actual = read_sysctl(key)
        ok = actual == expected
        results.append(_r(
            cat, "Pass" if ok else "Fail",
            f"HICP-6: {desc} ({key} = {expected})",
            severity="Medium",
            details=f"{key} = {actual or 'unset'} (expected {expected})",
            remediation=(
                f"echo '{key} = {expected}' >> /etc/sysctl.d/99-hipaa.conf "
                "&& sysctl --system"
            ),
            cross_references={
                "HIPAA": "164.308(a)(1)(ii)(D)-HICP6", "NIST": "SC-7", "CIS": "3.3",
            },
        ))

    return results


def _check_hicp_vulnerability_management(os_info) -> List[AuditResult]:
    """405(d) HICP-7 - Vulnerability Management."""
    results: List[AuditResult] = []
    cat = "HIPAA - HICP-7 Vulnerability Management"

    # Scanner tooling
    scanners = {
        "openscap": command_available("oscap"),
        "lynis": command_available("lynis"),
        "openvas": command_available("openvas-cli") or command_available("gvm-cli"),
        "nessus-agent": file_exists("/opt/nessus_agent/sbin/nessuscli"),
        "qualys-cloud-agent": file_exists("/opt/qualys/cloud-agent/bin/qualys-cloud-agent.sh"),
        "trivy": command_available("trivy"),
        "grype": command_available("grype"),
    }
    detected = [k for k, v in scanners.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Warning",
        f"HICP-7: Vulnerability scanner deployed ({len(detected)} found)",
        severity="High",
        details=f"Detected: {detected or 'none'}",
        remediation=(
            "Install OpenSCAP (RHEL family): dnf install -y openscap-scanner scap-security-guide. "
            "Or Lynis: apt-get install -y lynis. "
            "Schedule weekly scans, integrate findings with ticketing."
        ),
        cross_references={
            "HIPAA": "164.308(a)(1)(ii)(A)-HICP7", "NIST": "RA-5", "PCI-DSS": "11.3.1",
        },
    ))

    # Auto-update / patch tooling
    auto_patch = {
        "unattended-upgrades": (
            file_exists("/etc/apt/apt.conf.d/50unattended-upgrades") and
            systemd_active("unattended-upgrades.service") == "active"
        ),
        "dnf-automatic": (
            systemd_active("dnf-automatic.timer") == "active" or
            systemd_active("dnf-automatic-install.timer") == "active"
        ),
        "yum-cron": systemd_active("yum-cron.service") == "active",
    }
    auto_active = [k for k, v in auto_patch.items() if v]
    results.append(_r(
        cat, "Pass" if auto_active else "Warning",
        f"HICP-7: Automatic patch installation configured ({len(auto_active)} found)",
        severity="High",
        details=f"Active: {auto_active or 'none'}",
        remediation=(
            "Debian/Ubuntu: apt-get install -y unattended-upgrades && "
            "dpkg-reconfigure unattended-upgrades. "
            "RHEL family: dnf install -y dnf-automatic && "
            "systemctl enable --now dnf-automatic-install.timer."
        ),
        cross_references={
            "HIPAA": "164.308(a)(5)(ii)(B)-HICP7", "NIST": "SI-2(5)", "PCI-DSS": "6.3.3",
        },
    ))

    return results


def _check_hicp_incident_response(os_info) -> List[AuditResult]:
    """405(d) HICP-8 - Incident Response."""
    results: List[AuditResult] = []
    cat = "HIPAA - HICP-8 Incident Response"

    # SIEM integration via remote logging (TLS preferred)
    rsyslog_d = list_directory("/etc/rsyslog.d", suffix=".conf")
    rsyslog_main = read_file_safe("/etc/rsyslog.conf")
    has_tls_forwarding = False
    has_plain_forwarding = False
    for f in rsyslog_d + ["/etc/rsyslog.conf"]:
        if f == "/etc/rsyslog.conf":
            c = rsyslog_main
        else:
            c = read_file_safe(os.path.join("/etc/rsyslog.d", f))
        if not c:
            continue
        if "$DefaultNetstreamDriver gtls" in c or "StreamDriver=\"gtls\"" in c or "omrelp" in c:
            has_tls_forwarding = True
        elif "@@" in c or "omfwd" in c or "@" in c:
            has_plain_forwarding = True

    if has_tls_forwarding:
        results.append(_r(
            cat, "Pass",
            "HICP-8: SIEM forwarding configured with TLS encryption",
            severity="High",
            details="rsyslog gtls/RELP encrypted forwarding detected",
            cross_references={
                "HIPAA": "164.308(a)(6)-HICP8", "NIST": "AU-9(3)", "PCI-DSS": "10.5",
            },
        ))
    elif has_plain_forwarding:
        results.append(_r(
            cat, "Warning",
            "HICP-8: SIEM forwarding configured but cleartext (TLS recommended)",
            severity="High",
            details="Plain @@ or @ forwarding without TLS detected",
            remediation=(
                "Configure rsyslog gtls: $DefaultNetstreamDriver gtls; "
                "$ActionSendStreamDriverMode 1; *.* @@(o)siem.example.com:6514"
            ),
            cross_references={
                "HIPAA": "164.308(a)(6)-HICP8", "NIST": "AU-9(3)", "PCI-DSS": "10.5",
            },
        ))
    else:
        results.append(_r(
            cat, "Fail",
            "HICP-8: No SIEM/centralized log forwarding detected",
            severity="High",
            details="No forwarding configuration found in rsyslog.conf or rsyslog.d/",
            remediation=(
                "Centralize logs to SIEM via rsyslog with TLS. "
                "Required for breach detection and forensic analysis."
            ),
            cross_references={
                "HIPAA": "164.308(a)(6)-HICP8", "NIST": "AU-6(3)", "PCI-DSS": "10.5.4",
            },
        ))

    # Persistent journald (incident analysis requires logs to survive reboots)
    journald_conf = read_file_safe("/etc/systemd/journald.conf")
    storage_match = re.search(r"^\s*Storage\s*=\s*(\w+)", journald_conf, re.MULTILINE)
    storage = storage_match.group(1).lower() if storage_match else "auto"
    persistent = storage in ("persistent", "auto")  # auto becomes persistent if /var/log/journal exists
    journal_dir_exists = directory_exists("/var/log/journal")

    persistent_ok = persistent and (storage == "persistent" or journal_dir_exists)
    results.append(_r(
        cat, "Pass" if persistent_ok else "Fail",
        "HICP-8: systemd journal persistent across reboots",
        severity="High",
        details=(
            f"Storage = {storage}, /var/log/journal exists: {journal_dir_exists}"
        ),
        remediation=(
            "Set Storage=persistent in /etc/systemd/journald.conf, "
            "create /var/log/journal directory, then restart "
            "systemd-journald.service"
        ),
        cross_references={
            "HIPAA": "164.312(b)-HICP8", "NIST": "AU-11", "PCI-DSS": "10.5.1",
        },
    ))

    return results


def _check_hicp_medical_device(os_info) -> List[AuditResult]:
    """405(d) HICP-9 - Medical Device Security (host-applicable indicators)."""
    results: List[AuditResult] = []
    cat = "HIPAA - HICP-9 Medical Device Security"

    # Network namespace isolation indicators
    netns = directory_exists("/var/run/netns")
    has_netns_capability = command_available("ip")  # ip netns is part of iproute2
    results.append(_r(
        cat, "Info",
        "HICP-9: Network namespace capability available",
        severity="Informational",
        details=(
            f"ip command: {has_netns_capability}, "
            f"/var/run/netns exists: {netns}. "
            "Network namespaces enable network isolation for medical-device comms."
        ),
        remediation=(
            "Use network namespaces or VLANs to isolate medical device traffic "
            "from general workstation networks. ip netns add medical-vlan"
        ),
        cross_references={
            "HIPAA": "164.308(a)(1)(ii)(B)-HICP9", "NIST": "SC-7(13)",
        },
    ))

    return results


def _check_hicp_policies(os_info) -> List[AuditResult]:
    """405(d) HICP-10 - Cybersecurity Policies (technical indicators)."""
    results: List[AuditResult] = []
    cat = "HIPAA - HICP-10 Cybersecurity Policies"

    # Documentation indicators (banner, MOTD, /etc/issue)
    issue_net = read_file_safe("/etc/issue.net")
    has_unauthorized_warning = (
        "unauthorized" in issue_net.lower() or
        "authorized only" in issue_net.lower() or
        "monitoring" in issue_net.lower()
    )

    results.append(_r(
        cat, "Pass" if has_unauthorized_warning else "Warning",
        "HICP-10: Login banner contains unauthorized-access warning",
        severity="Medium",
        details=(
            f"/etc/issue.net contains warning language: {has_unauthorized_warning}. "
            f"Length: {len(issue_net)}"
        ),
        remediation=(
            "Set /etc/issue.net with HIPAA-required banner: "
            "'WARNING: Unauthorized access prohibited. This system contains "
            "ePHI. All activity is monitored and logged.'"
        ),
        cross_references={
            "HIPAA": "164.310(b)-HICP10", "NIST": "AC-8", "STIG": "V-230225",
        },
    ))

    return results


# ===========================================================================
# Updated entry point - extends original run_checks
# ===========================================================================

# Save reference to original run_checks before redefining
_original_run_checks_hipaa = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the expanded HIPAA module.

    Combines the baseline checks (Sec. 164.312 core technical safeguards)
    with the v3.1 expansion covering Sec. 164.308 Administrative Safeguards,
    Sec. 164.310 Physical Safeguards (host-applicable subset), extended
    Sec. 164.312, and the full 405(d) HICP threat practices.
    """
    if shared_data is None:
        shared_data = {}

    # Run original baseline checks
    results = _original_run_checks_hipaa(shared_data)

    # Detect OS for the new checks
    os_info = shared_data.get("v3_os_info")
    if os_info is None:
        os_info = os_detection.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        # Sec. 164.308 Administrative Safeguards
        results.extend(_check_admin_workforce_security(os_info))
        results.extend(_check_admin_information_access_management(os_info))
        results.extend(_check_admin_security_awareness(os_info))
        results.extend(_check_admin_security_incident(os_info))
        results.extend(_check_admin_contingency(os_info))

        # Sec. 164.310 Physical Safeguards (host-applicable)
        results.extend(_check_physical_safeguards(os_info))

        # Sec. 164.312 Technical Safeguards (extended)
        results.extend(_check_tech_audit_extended(os_info))
        results.extend(_check_tech_integrity_extended(os_info))
        results.extend(_check_tech_transmission_extended(os_info))

        # 405(d) HICP threat practices
        results.extend(_check_hicp_endpoint_protection(os_info))
        results.extend(_check_hicp_access_management(os_info))
        results.extend(_check_hicp_data_protection(os_info))
        results.extend(_check_hicp_asset_management(os_info))
        results.extend(_check_hicp_network_management(os_info))
        results.extend(_check_hicp_vulnerability_management(os_info))
        results.extend(_check_hicp_incident_response(os_info))
        results.extend(_check_hicp_medical_device(os_info))
        results.extend(_check_hicp_policies(os_info))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled exception in HIPAA v3.1 expansion")
        results.append(_r(
            "HIPAA - Error", "Error",
            f"HIPAA v3.1 expansion exception: {exc!r}",
            severity="Medium", details=str(exc),
        ))

    return results


# ===========================================================================
# v3.3 EXPANSION - HIPAA Security Rule Deep Coverage
# ---------------------------------------------------------------------------
# Adds depth across:
#   - Sec. 164.308 Administrative Safeguards
#   - Sec. 164.312 Technical Safeguards
#   - Sec. 164.314 Organizational Requirements
#   - Sec. 164.316 Policies, Procedures and Documentation
#   - Sec. 164.402-414 Breach Notification (technical indicators)
# ===========================================================================


def _check_hipaa_308_admin_v33(os_info) -> List[AuditResult]:
    """Sec. 164.308 - Administrative safeguards extended."""
    results: List[AuditResult] = []
    cat = "HIPAA Sec. 164.308 v3.3"

    # 308(a)(1)(ii)(D) - Information system activity review (auditd)
    auditd_active = systemd_active("auditd.service") == "active"
    audit_rules_d = "/etc/audit/rules.d"
    rule_count = 0
    if directory_exists(audit_rules_d):
        for f in list_directory(audit_rules_d):
            if f.endswith(".rules"):
                c = read_file_safe(os.path.join(audit_rules_d, f))
                rule_count += sum(
                    1 for ln in c.splitlines()
                    if ln.strip() and not ln.strip().startswith("#")
                )
    results.append(_r(
        cat, "Pass" if (auditd_active and rule_count >= 25) else "Warning",
        f"HIPAA-308(a)(1)(ii)(D): Activity review (auditd active, {rule_count} rules)",
        severity="High",
        details=(
            f"auditd active: {auditd_active}, rule count: {rule_count}"
        ),
        remediation=(
            "Deploy CIS-recommended ruleset (~75 rules) for HIPAA "
            "audit trail completeness"
        ),
        cross_references={
            "HIPAA": "164.308(a)(1)(ii)(D)", "NIST": "AU-2, AU-6",
        },
    ))

    # 308(a)(3)(ii)(B) - Workforce clearance: privileged group review
    group_file = read_file_safe("/etc/group")
    sudo_count = 0
    wheel_count = 0
    for line in group_file.splitlines():
        if line.startswith("sudo:"):
            parts = line.split(":")
            if len(parts) >= 4 and parts[3]:
                sudo_count = len([m for m in parts[3].split(",") if m])
        elif line.startswith("wheel:"):
            parts = line.split(":")
            if len(parts) >= 4 and parts[3]:
                wheel_count = len([m for m in parts[3].split(",") if m])
    privileged_total = sudo_count + wheel_count
    results.append(_r(
        cat, "Info",
        f"HIPAA-308(a)(3)(ii)(B): Privileged group members "
        f"({privileged_total} total)",
        severity="Informational",
        details=f"sudo: {sudo_count}, wheel: {wheel_count}",
        remediation=(
            "Review privileged user access quarterly. "
            "Document workforce clearance procedures."
        ),
        cross_references={
            "HIPAA": "164.308(a)(3)(ii)(B)", "NIST": "AC-6, PS-3",
        },
    ))

    # 308(a)(4)(ii)(A) - Authorization/supervision: sudoers config protected
    sudoers_mode = file_mode("/etc/sudoers")
    sudoers_d_present = directory_exists("/etc/sudoers.d")
    sudoers_ok = sudoers_mode is not None and (sudoers_mode & 0o022) == 0
    results.append(_r(
        cat, "Pass" if sudoers_ok else "Warning",
        f"HIPAA-308(a)(4)(ii)(A): /etc/sudoers permissions adequate",
        severity="High",
        details=(
            f"Mode: {oct(sudoers_mode) if sudoers_mode else 'N/A'}, "
            f"sudoers.d present: {sudoers_d_present}"
        ),
        remediation=(
            "chmod 440 /etc/sudoers; chown root:root /etc/sudoers"
        ),
        cross_references={
            "HIPAA": "164.308(a)(4)(ii)(A)", "NIST": "AC-3",
        },
    ))

    # 308(a)(5)(ii)(B) - Protection from malicious software
    malware_indicators = {
        "ClamAV": command_available("clamscan"),
        "rkhunter": command_available("rkhunter"),
        "chkrootkit": command_available("chkrootkit"),
        "MDE": file_exists("/opt/microsoft/mdatp/sbin/wdavdaemon"),
        "CrowdStrike": file_exists("/opt/CrowdStrike/falconctl"),
    }
    detected = [k for k, v in malware_indicators.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Fail",
        f"HIPAA-308(a)(5)(ii)(B): Anti-malware tools ({len(detected)})",
        severity="High",
        details=f"Detected: {detected}",
        remediation=(
            "Deploy enterprise EDR or open-source: "
            "apt-get install -y clamav rkhunter chkrootkit"
        ),
        cross_references={
            "HIPAA": "164.308(a)(5)(ii)(B)", "NIST": "SI-3",
        },
    ))

    # 308(a)(5)(ii)(C) - Login monitoring: PAM faillock
    faillock_configured = False
    for pf in ["/etc/pam.d/system-auth", "/etc/pam.d/common-auth",
               "/etc/pam.d/password-auth"]:
        if "pam_faillock" in read_file_safe(pf) or \
           "pam_tally2" in read_file_safe(pf):
            faillock_configured = True
            break
    results.append(_r(
        cat, "Pass" if faillock_configured else "Fail",
        f"HIPAA-308(a)(5)(ii)(C): Login attempt monitoring (faillock): "
        f"{faillock_configured}",
        severity="High",
        details=f"PAM faillock/tally2 detected: {faillock_configured}",
        remediation=(
            "Configure /etc/security/faillock.conf with deny=5 unlock_time=900"
        ),
        cross_references={
            "HIPAA": "164.308(a)(5)(ii)(C)", "NIST": "AC-7",
        },
    ))

    # 308(a)(6)(ii) - Response and reporting: SIEM forwarding
    rsy_conf = read_file_safe("/etc/rsyslog.conf")
    has_remote = "@@" in rsy_conf or "omfwd" in rsy_conf
    if not has_remote and directory_exists("/etc/rsyslog.d"):
        for f in list_directory("/etc/rsyslog.d"):
            if not f.endswith(".conf"):
                continue
            c = read_file_safe(os.path.join("/etc/rsyslog.d", f))
            if "@@" in c or "omfwd" in c:
                has_remote = True
                break
    results.append(_r(
        cat, "Pass" if has_remote else "Fail",
        f"HIPAA-308(a)(6)(ii): Incident response log forwarding: {has_remote}",
        severity="Critical",
        details=f"rsyslog remote forwarding: {has_remote}",
        remediation=(
            "Configure /etc/rsyslog.d/50-remote.conf: "
            "*.* @@siem.example.com:6514"
        ),
        cross_references={
            "HIPAA": "164.308(a)(6)(ii)", "NIST": "IR-6",
        },
    ))

    # 308(a)(7)(ii)(A) - Data backup plan
    backup_tools = {
        "rsync": command_available("rsync"),
        "borg": command_available("borg"),
        "restic": command_available("restic"),
        "duplicity": command_available("duplicity"),
        "snapper": command_available("snapper"),
    }
    detected = [k for k, v in backup_tools.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Fail",
        f"HIPAA-308(a)(7)(ii)(A): Backup tooling ({len(detected)})",
        severity="High",
        details=f"Detected: {detected}",
        cross_references={
            "HIPAA": "164.308(a)(7)(ii)(A)", "NIST": "CP-9",
        },
    ))

    # 308(a)(7)(ii)(C) - Emergency mode: rescue/recovery indicators
    rescue_indicators = {
        "systemd-rescue.target": True,  # always present in systemd
        "kdump": (
            systemd_active("kdump.service") == "active" or
            file_exists("/etc/kdump.conf")
        ),
        "systemd-emergency": True,
    }
    rescue_count = sum(1 for v in rescue_indicators.values() if v)
    results.append(_r(
        cat, "Pass",
        f"HIPAA-308(a)(7)(ii)(C): Emergency recovery capabilities ({rescue_count})",
        severity="Low",
        details=f"systemd rescue/emergency targets present, kdump: "
                f"{rescue_indicators['kdump']}",
        cross_references={
            "HIPAA": "164.308(a)(7)(ii)(C)", "NIST": "CP-10",
        },
    ))

    # 308(a)(8) - Evaluation: vulnerability scanning capability
    scanners = ["lynis", "oscap", "trivy", "nuclei"]
    detected_scanners = [s for s in scanners if command_available(s)]
    results.append(_r(
        cat, "Pass" if detected_scanners else "Warning",
        f"HIPAA-308(a)(8): Security evaluation tools ({len(detected_scanners)})",
        severity="High",
        details=f"Detected: {detected_scanners}",
        remediation=(
            "apt-get install -y lynis. Schedule monthly evaluations."
        ),
        cross_references={
            "HIPAA": "164.308(a)(8)", "NIST": "CA-2, RA-5",
        },
    ))

    return results


def _check_hipaa_310_physical_v33(os_info) -> List[AuditResult]:
    """Sec. 164.310 - Physical safeguards (technical indicators)."""
    results: List[AuditResult] = []
    cat = "HIPAA Sec. 164.310 v3.3"

    # 310(a)(2)(iv) - Maintenance records: package transaction logs
    pkg_logs = []
    for log in ["/var/log/dpkg.log", "/var/log/yum.log",
                "/var/log/dnf.log", "/var/log/zypp/history"]:
        if file_exists(log):
            pkg_logs.append(log)
    results.append(_r(
        cat, "Pass" if pkg_logs else "Warning",
        f"HIPAA-310(a)(2)(iv): Package maintenance logs ({len(pkg_logs)})",
        severity="Medium",
        details=f"Logs: {pkg_logs}",
        cross_references={
            "HIPAA": "164.310(a)(2)(iv)", "NIST": "MA-2",
        },
    ))

    # 310(d)(2)(i) - Disposal: secure deletion tools
    erasure = {
        "shred": command_available("shred"),
        "wipe": command_available("wipe"),
        "blkdiscard": command_available("blkdiscard"),
        "scrub": command_available("scrub"),
        "nvme": command_available("nvme"),  # nvme format
    }
    detected = [k for k, v in erasure.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Fail",
        f"HIPAA-310(d)(2)(i): Disposal/destruction tools ({len(detected)})",
        severity="High",
        details=f"Detected: {detected}",
        remediation=(
            "Install: apt-get install -y secure-delete coreutils nvme-cli"
        ),
        cross_references={
            "HIPAA": "164.310(d)(2)(i)", "NIST": "MP-6",
        },
    ))

    # 310(d)(2)(iii) - Accountability: media tracking via auditd
    audit_rules = read_file_safe("/etc/audit/audit.rules")
    if directory_exists("/etc/audit/rules.d"):
        for f in list_directory("/etc/audit/rules.d"):
            if f.endswith(".rules"):
                audit_rules += "\n" + read_file_safe(
                    os.path.join("/etc/audit/rules.d", f)
                )
    media_tracking = "mount" in audit_rules or "/dev" in audit_rules
    results.append(_r(
        cat, "Info",
        f"HIPAA-310(d)(2)(iii): Media accountability auditing: {media_tracking}",
        severity="Low",
        details=f"Mount/device audit indicator: {media_tracking}",
        remediation=(
            "Add audit rule: -a always,exit -F arch=b64 -S mount -k mounts"
        ),
        cross_references={
            "HIPAA": "164.310(d)(2)(iii)", "NIST": "AU-2, MP-3",
        },
    ))

    return results


def _check_hipaa_312_technical_v33(os_info) -> List[AuditResult]:
    """Sec. 164.312 - Technical safeguards extended."""
    results: List[AuditResult] = []
    cat = "HIPAA Sec. 164.312 v3.3"

    # 312(a)(2)(iii) - Automatic logoff: ClientAliveInterval
    sshd = read_file_safe("/etc/ssh/sshd_config")
    cai_match = re.search(
        r"^\s*ClientAliveInterval\s+(\d+)", sshd, re.MULTILINE
    )
    cam_match = re.search(
        r"^\s*ClientAliveCountMax\s+(\d+)", sshd, re.MULTILINE
    )
    cai = int(cai_match.group(1)) if cai_match else 0
    cam = int(cam_match.group(1)) if cam_match else 3
    cai_ok = 0 < cai <= 900  # within 15 minutes
    results.append(_r(
        cat, "Pass" if cai_ok else "Fail",
        f"HIPAA-312(a)(2)(iii): SSH automatic logoff "
        f"(ClientAliveInterval={cai}, max={cam})",
        severity="High",
        details=f"ClientAliveInterval = {cai}, ClientAliveCountMax = {cam}",
        remediation=(
            "In /etc/ssh/sshd_config: ClientAliveInterval 300; "
            "ClientAliveCountMax 0; systemctl reload sshd"
        ),
        cross_references={
            "HIPAA": "164.312(a)(2)(iii)", "NIST": "AC-12", "STIG": "V-230244",
        },
    ))

    # 312(a)(2)(iv) - Encryption and decryption: openssl/gpg
    crypto_libs = {
        "openssl": command_available("openssl"),
        "gpg": command_available("gpg"),
        "cryptsetup": command_available("cryptsetup"),
    }
    detected = [k for k, v in crypto_libs.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Fail",
        f"HIPAA-312(a)(2)(iv): Encryption tools available ({len(detected)})",
        severity="High",
        details=f"Detected: {detected}",
        cross_references={
            "HIPAA": "164.312(a)(2)(iv)", "NIST": "SC-13",
        },
    ))

    # 312(b) - Audit controls: comprehensive auditd ruleset
    audit_rules = read_file_safe("/etc/audit/audit.rules")
    if directory_exists("/etc/audit/rules.d"):
        for f in list_directory("/etc/audit/rules.d"):
            if f.endswith(".rules"):
                audit_rules += "\n" + read_file_safe(
                    os.path.join("/etc/audit/rules.d", f)
                )
    standard_keys = ["identity", "privileged", "perm_mod", "modules",
                     "time-change", "system-locale", "MAC-policy",
                     "logins", "session"]
    keys_present = sum(1 for k in standard_keys if k in audit_rules)
    results.append(_r(
        cat, "Pass" if keys_present >= 7 else "Warning",
        f"HIPAA-312(b): Standard audit rule keys ({keys_present}/{len(standard_keys)})",
        severity="High",
        details=f"Keys present: {keys_present}",
        remediation=(
            "Apply CIS-recommended auditd ruleset (CIS Benchmark Sec. 4.1.3)"
        ),
        cross_references={
            "HIPAA": "164.312(b)", "NIST": "AU-2",
        },
    ))

    # 312(c)(1) - Integrity: file integrity monitoring
    fim_tools = {
        "AIDE": file_exists("/var/lib/aide/aide.db") or
                file_exists("/var/lib/aide/aide.db.gz") or
                command_available("aide"),
        "Tripwire": file_exists("/etc/tripwire/tw.cfg"),
        "Wazuh-FIM": file_exists("/var/ossec/etc/ossec.conf"),
    }
    detected = [k for k, v in fim_tools.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Fail",
        f"HIPAA-312(c)(1): File integrity monitoring ({len(detected)})",
        severity="High",
        details=f"Detected: {detected}",
        remediation=remediation_for("aide"),
        cross_references={
            "HIPAA": "164.312(c)(1)", "NIST": "SI-7",
        },
    ))

    # 312(d) - Person/entity authentication: MFA capability
    mfa_modules = ["pam_google_authenticator", "pam_yubico", "pam_oath",
                   "pam_duo", "pam_u2f", "pam_pkcs11"]
    detected_mfa = []
    for pf in ["/etc/pam.d/sshd", "/etc/pam.d/system-auth",
               "/etc/pam.d/common-auth"]:
        c = read_file_safe(pf)
        for mod in mfa_modules:
            if mod + ".so" in c:
                detected_mfa.append(mod.replace("pam_", ""))
    detected_mfa = list(set(detected_mfa))
    results.append(_r(
        cat, "Pass" if detected_mfa else "Warning",
        f"HIPAA-312(d): MFA modules configured ({len(detected_mfa)})",
        severity="High",
        details=f"Detected: {detected_mfa}",
        remediation=(
            "apt-get install -y libpam-google-authenticator. "
            "Configure pam_google_authenticator.so in /etc/pam.d/sshd"
        ),
        cross_references={
            "HIPAA": "164.312(d)", "NIST": "IA-2(1)",
        },
    ))

    # 312(e)(1) - Transmission security: TLS protocol minimum
    openssl_cnf = read_file_safe("/etc/ssl/openssl.cnf") or \
                  read_file_safe("/etc/pki/tls/openssl.cnf")
    has_tls12 = "TLSv1.2" in openssl_cnf or "MinProtocol" in openssl_cnf
    results.append(_r(
        cat, "Pass" if has_tls12 else "Warning",
        f"HIPAA-312(e)(1): TLS minimum 1.2 in OpenSSL config: {has_tls12}",
        severity="High",
        details=f"OpenSSL TLSv1.2/MinProtocol indicator: {has_tls12}",
        remediation=(
            "In /etc/ssl/openssl.cnf [system_default_sect]: "
            "MinProtocol = TLSv1.2"
        ),
        cross_references={
            "HIPAA": "164.312(e)(1)", "NIST": "SC-8(1)",
        },
    ))

    # 312(e)(2)(ii) - Encryption in transmission: SSH ciphers strong
    sshd_ciphers_match = re.search(
        r"^\s*Ciphers\s+(\S+)", sshd, re.MULTILINE
    )
    sshd_ciphers = sshd_ciphers_match.group(1) if sshd_ciphers_match else ""
    weak_ciphers = ["arcfour", "3des", "des-cbc", "blowfish"]
    has_weak = any(w in sshd_ciphers for w in weak_ciphers) if sshd_ciphers else False
    results.append(_r(
        cat, "Pass" if (sshd_ciphers and not has_weak) else "Warning",
        f"HIPAA-312(e)(2)(ii): SSH cipher suite hardened",
        severity="High",
        details=(
            f"Ciphers configured: {bool(sshd_ciphers)}, "
            f"weak ciphers detected: {has_weak}"
        ),
        remediation=(
            "In /etc/ssh/sshd_config: "
            "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,"
            "aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
        ),
        cross_references={
            "HIPAA": "164.312(e)(2)(ii)", "NIST": "SC-13",
        },
    ))

    return results


def _check_hipaa_314_organizational_v33(os_info) -> List[AuditResult]:
    """Sec. 164.314 - Organizational requirements (technical indicators)."""
    results: List[AuditResult] = []
    cat = "HIPAA Sec. 164.314 v3.3"

    # 314(a)(2)(i) - Business associate compliance: package signing
    apt_keyring = (
        directory_exists("/etc/apt/trusted.gpg.d") or
        directory_exists("/etc/apt/keyrings")
    )
    rpm_gpgcheck = False
    yum_conf = read_file_safe("/etc/yum.conf") or \
               read_file_safe("/etc/dnf/dnf.conf")
    if "gpgcheck=1" in yum_conf:
        rpm_gpgcheck = True
    pacman_keyring = directory_exists("/etc/pacman.d/gnupg")
    sig_indicators = sum([apt_keyring, rpm_gpgcheck, pacman_keyring])
    results.append(_r(
        cat, "Pass" if sig_indicators >= 1 else "Fail",
        f"HIPAA-314(a)(2)(i): Software supply chain integrity ({sig_indicators})",
        severity="High",
        details=(
            f"apt: {apt_keyring}, rpm gpgcheck: {rpm_gpgcheck}, "
            f"pacman: {pacman_keyring}"
        ),
        cross_references={
            "HIPAA": "164.314(a)(2)(i)", "NIST": "CM-5(3), SR-11",
        },
    ))

    return results


def _check_hipaa_316_documentation_v33(os_info) -> List[AuditResult]:
    """Sec. 164.316 - Policies, procedures and documentation."""
    results: List[AuditResult] = []
    cat = "HIPAA Sec. 164.316 v3.3"

    # 316(b)(2)(i) - Time limit on retention: log retention
    auditd_conf = read_file_safe("/etc/audit/auditd.conf")
    num_logs_match = re.search(
        r"^\s*num_logs\s*=\s*(\d+)", auditd_conf, re.MULTILINE
    )
    num_logs = int(num_logs_match.group(1)) if num_logs_match else 0
    results.append(_r(
        cat, "Pass" if num_logs >= 5 else "Warning",
        f"HIPAA-316(b)(2)(i): auditd retention (num_logs={num_logs})",
        severity="High",
        details=f"num_logs = {num_logs} (HIPAA requires 6 years)",
        remediation=(
            "In /etc/audit/auditd.conf: num_logs = 10; "
            "max_log_file_action = keep_logs. Forward to long-term storage."
        ),
        cross_references={
            "HIPAA": "164.316(b)(2)(i)", "NIST": "AU-11",
        },
    ))

    # 316(b)(2)(ii) - Availability: documentation accessibility
    # Check for /usr/share/doc directories indicating package documentation
    doc_present = directory_exists("/usr/share/doc")
    man_present = directory_exists("/usr/share/man")
    results.append(_r(
        cat, "Pass" if (doc_present and man_present) else "Info",
        f"HIPAA-316(b)(2)(ii): System documentation present",
        severity="Informational",
        details=f"/usr/share/doc: {doc_present}, /usr/share/man: {man_present}",
        cross_references={
            "HIPAA": "164.316(b)(2)(ii)", "NIST": "SA-5",
        },
    ))

    # 316(b)(2)(iii) - Updates: change management via package logs
    pkg_logs = []
    for log in ["/var/log/dpkg.log", "/var/log/yum.log",
                "/var/log/dnf.log", "/var/log/zypp/history"]:
        if file_exists(log):
            pkg_logs.append(log)
    results.append(_r(
        cat, "Pass" if pkg_logs else "Warning",
        f"HIPAA-316(b)(2)(iii): Change management via package logs ({len(pkg_logs)})",
        severity="Medium",
        details=f"Logs present: {pkg_logs}",
        cross_references={
            "HIPAA": "164.316(b)(2)(iii)", "NIST": "CM-3",
        },
    ))

    return results


def _check_hipaa_breach_notification_v33(os_info) -> List[AuditResult]:
    """Sec. 164.402-414 - Breach notification technical readiness."""
    results: List[AuditResult] = []
    cat = "HIPAA Breach Notification v3.3"

    # 404 - Notification to individuals: log forwarding for detection
    rsy_remote = False
    rsy_conf = read_file_safe("/etc/rsyslog.conf")
    if "@@" in rsy_conf or "omfwd" in rsy_conf:
        rsy_remote = True
    if not rsy_remote and directory_exists("/etc/rsyslog.d"):
        for f in list_directory("/etc/rsyslog.d"):
            if not f.endswith(".conf"):
                continue
            c = read_file_safe(os.path.join("/etc/rsyslog.d", f))
            if "@@" in c or "omfwd" in c:
                rsy_remote = True
                break
    results.append(_r(
        cat, "Pass" if rsy_remote else "Fail",
        f"HIPAA-404: Remote log forwarding for breach detection: {rsy_remote}",
        severity="Critical",
        details=f"rsyslog forwarding: {rsy_remote}",
        remediation=(
            "Configure /etc/rsyslog.d/50-remote.conf for SIEM forwarding"
        ),
        cross_references={
            "HIPAA": "164.404", "NIST": "IR-6",
        },
    ))

    # 408 - Notification: SIEM/aggregator presence
    siem_indicators = {
        "wazuh": file_exists("/var/ossec/etc/ossec.conf"),
        "filebeat": (
            file_exists("/etc/filebeat/filebeat.yml") or
            systemd_active("filebeat.service") == "active"
        ),
        "fluentd": (
            command_available("fluentd") or
            command_available("td-agent")
        ),
        "vector": command_available("vector"),
        "logstash": file_exists("/etc/logstash/logstash.yml"),
    }
    detected = [k for k, v in siem_indicators.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Warning",
        f"HIPAA-408: SIEM/log aggregation tooling ({len(detected)})",
        severity="High",
        details=f"Detected: {detected}",
        remediation=(
            "Deploy Wazuh agent for SIEM/SOC integration"
        ),
        cross_references={
            "HIPAA": "164.408", "NIST": "AU-6(3)",
        },
    ))

    # 410 - Notification by business associate: monitoring readiness (auditd)
    auditd_active = systemd_active("auditd.service") == "active"
    audit_log_present = file_exists("/var/log/audit/audit.log")
    results.append(_r(
        cat, "Pass" if (auditd_active and audit_log_present) else "Fail",
        f"HIPAA-410: Audit trail for breach investigation",
        severity="High",
        details=(
            f"auditd active: {auditd_active}, audit.log present: {audit_log_present}"
        ),
        cross_references={
            "HIPAA": "164.410", "NIST": "AU-2, IR-4",
        },
    ))

    return results


# Save reference to existing run_checks
_original_run_checks_hipaa_v33 = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the v3.3 expanded HIPAA module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_hipaa_v33(shared_data)

    os_info = shared_data.get("v3_os_info")
    if os_info is None:
        os_info = os_detection.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        results.extend(_check_hipaa_308_admin_v33(os_info))
        results.extend(_check_hipaa_310_physical_v33(os_info))
        results.extend(_check_hipaa_312_technical_v33(os_info))
        results.extend(_check_hipaa_314_organizational_v33(os_info))
        results.extend(_check_hipaa_316_documentation_v33(os_info))
        results.extend(_check_hipaa_breach_notification_v33(os_info))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled exception in HIPAA v3.3 expansion")
        results.append(_r(
            "HIPAA - Error", "Error",
            f"HIPAA v3.3 expansion exception: {exc!r}",
            severity="Medium", details=str(exc),
        ))

    return results


# ============================================================================
# v3.5 EXPANSION - HIPAA Security Rule Technical Depth
# ----------------------------------------------------------------------------
# Synopsis:
#   Adds depth across HIPAA 45 CFR 164 Security Rule technical safeguards
#   sub-implementations and breach notification readiness:
#     - 164.312(a)(2)(i) Unique user identification depth (shared account
#       detection, generic-account audit, per-user logging)
#     - 164.312(a)(2)(iii) Automatic logoff depth (TMOUT, screen lock,
#       SSH ClientAlive)
#     - 164.312(a)(2)(iv) Encryption depth (FIPS providers, TLS strict mode,
#       certificate trust chain validation)
#     - 164.312(b) Audit controls depth (per-user logging, log access
#       audit, retention proof)
#     - 164.312(c)(2) Integrity authentication (file hashing, digital
#       signatures, package signing verification)
#     - 164.312(d) Person/entity authentication depth (MFA enforcement,
#       mutual TLS, certificate-based)
#     - 164.312(e)(2)(i) Transmission integrity (MAC, HMAC; AH/ESP for
#       IPsec)
#     - 164.402 Breach notification readiness (timeline tracking, log
#       availability, identification capability)
#     - 164.306(b) Risk analysis (vuln scanning periodicity)
#     - 164.308(a)(1)(ii)(D) Information system activity review
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


def _v35_hipaa_result(category, status, message, severity="Medium",
                     details="", remediation="", cross_references=None):
    """Build AuditResult for HIPAA v3.5 expansion."""
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


def _check_hipaa_v35_unique_id_depth(os_info):
    """164.312(a)(2)(i) Unique user identification - depth checks."""
    results = []
    cat = "HIPAA v3.5 - 164.312(a)(2)(i)"

    # 1. Detect generic/shared account names
    passwd = _v35_read_file_safe("/etc/passwd")
    shadow = _v35_read_file_safe("/etc/shadow")
    generic_names = {
        "admin", "administrator", "user", "guest", "test", "demo",
        "ephi", "hipaa", "shared", "common", "operator",
    }
    found_generic = []
    if passwd:
        for line in passwd.splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            try:
                uid = int(parts[2])
            except ValueError:
                continue
            username = parts[0].lower()
            shell = parts[6]
            # Risky: UID >= 1000, generic name, has login shell
            interactive = shell not in (
                "/sbin/nologin", "/usr/sbin/nologin", "/bin/false",
            )
            if uid >= 1000 and username in generic_names and interactive:
                found_generic.append(parts[0])

    results.append(_v35_hipaa_result(
        f"{cat} - Generic Account Detection",
        "Pass" if not found_generic else "Warning",
        f"HIPAA 164.312(a)(2)(i) Generic accounts: {len(found_generic)}",
        severity="High",
        details=f"Generic-named interactive accounts: {found_generic}",
        remediation=(
            "Each ePHI-accessing user must have a unique identifier. "
            "Replace shared/generic accounts with per-individual accounts. "
            "If a generic account is needed for a service, set its shell "
            "to /usr/sbin/nologin and ensure no humans login to it directly."
        ),
        cross_references={
            "HIPAA": "164.312(a)(2)(i)", "NIST": "IA-2",
            "PCI-DSS": "8.6.1",
        },
    ))

    # 2. Duplicate UIDs (multiple usernames, same UID)
    uid_counts = {}
    if passwd:
        for line in passwd.splitlines():
            parts = line.split(":")
            if len(parts) < 3:
                continue
            try:
                uid = int(parts[2])
                uid_counts[uid] = uid_counts.get(uid, 0) + 1
            except ValueError:
                continue
    duplicates = [uid for uid, c in uid_counts.items() if c > 1]
    results.append(_v35_hipaa_result(
        f"{cat} - Unique UIDs",
        "Pass" if not duplicates else "Fail",
        f"HIPAA 164.312(a)(2)(i) UID uniqueness: "
        f"{'unique' if not duplicates else f'{len(duplicates)} duplicates'}",
        severity="Critical",
        details=f"Duplicate UIDs: {duplicates}",
        remediation=(
            "Each user must have a unique UID. Duplicates allow one user "
            "to assume another's identity. Use `usermod -u <new>` to "
            "assign unique UIDs."
        ),
        cross_references={
            "HIPAA": "164.312(a)(2)(i)", "NIST": "IA-4",
            "STIG": "V-230373",
        },
    ))

    # 3. /etc/login.defs UID_MIN - auto-assigned UIDs respect threshold
    login_defs = _v35_read_file_safe("/etc/login.defs")
    uid_min_match = re.search(
        r"^\s*UID_MIN\s+(\d+)", login_defs, re.MULTILINE,
    )
    uid_min = int(uid_min_match.group(1)) if uid_min_match else 1000
    results.append(_v35_hipaa_result(
        f"{cat} - UID_MIN",
        "Pass" if uid_min >= 1000 else "Warning",
        f"HIPAA 164.312(a)(2)(i) UID_MIN = {uid_min}",
        severity="Low",
        details=f"UID_MIN in /etc/login.defs = {uid_min}",
        cross_references={
            "HIPAA": "164.312(a)(2)(i)", "NIST": "IA-4",
        },
    ))

    return results


def _check_hipaa_v35_logoff_depth(os_info):
    """164.312(a)(2)(iii) Automatic logoff - multi-layer depth."""
    results = []
    cat = "HIPAA v3.5 - 164.312(a)(2)(iii)"

    # 1. TMOUT shell idle timeout
    profile_files = [
        "/etc/profile",
        "/etc/bash.bashrc",
    ]
    if _v35_directory_exists("/etc/profile.d"):
        for f in _v35_list_directory("/etc/profile.d"):
            if f.endswith(".sh"):
                profile_files.append(f"/etc/profile.d/{f}")
    tmout_seconds = 0
    tmout_readonly = False
    for pf in profile_files:
        c = _v35_read_file_safe(pf)
        m = re.search(r"^\s*(?:export\s+)?TMOUT\s*=\s*(\d+)", c, re.MULTILINE)
        if m:
            tmout_seconds = max(tmout_seconds, int(m.group(1)))
        if "readonly TMOUT" in c:
            tmout_readonly = True
    tmout_ok = 0 < tmout_seconds <= 900  # 15 min or less
    results.append(_v35_hipaa_result(
        f"{cat} - Shell TMOUT",
        "Pass" if tmout_ok else "Warning",
        f"HIPAA 164.312(a)(2)(iii) TMOUT = {tmout_seconds}s, "
        f"readonly: {tmout_readonly}",
        severity="Medium",
        details=(
            f"TMOUT seconds: {tmout_seconds}, readonly: {tmout_readonly}"
        ),
        remediation=(
            "Add to /etc/profile.d/99-hipaa-tmout.sh:\n"
            "  TMOUT=900\n"
            "  export TMOUT\n"
            "  readonly TMOUT\n"
            "Idle shell sessions auto-logoff after 15 minutes."
        ),
        cross_references={
            "HIPAA": "164.312(a)(2)(iii)", "NIST": "AC-11, AC-12",
            "STIG": "V-230380",
        },
    ))

    # 2. SSH ClientAlive timeout
    sshd = _v35_read_file_safe("/etc/ssh/sshd_config")
    sshd_d = ""
    if _v35_directory_exists("/etc/ssh/sshd_config.d"):
        for f in _v35_list_directory("/etc/ssh/sshd_config.d"):
            if f.endswith(".conf"):
                sshd_d += "\n" + _v35_read_file_safe(
                    os.path.join("/etc/ssh/sshd_config.d", f)
                )
    full_sshd = sshd + "\n" + sshd_d
    cai_match = re.search(
        r"^\s*ClientAliveInterval\s+(\d+)", full_sshd, re.MULTILINE,
    )
    cam_match = re.search(
        r"^\s*ClientAliveCountMax\s+(\d+)", full_sshd, re.MULTILINE,
    )
    cai = int(cai_match.group(1)) if cai_match else 0
    cam = int(cam_match.group(1)) if cam_match else 3
    total_idle_sec = cai * cam if cai > 0 else 0
    ssh_logoff_ok = 0 < total_idle_sec <= 900
    results.append(_v35_hipaa_result(
        f"{cat} - SSH ClientAlive",
        "Pass" if ssh_logoff_ok else "Warning",
        f"HIPAA 164.312(a)(2)(iii) SSH idle disconnect: {total_idle_sec}s "
        f"({cai} x {cam})",
        severity="Medium",
        details=(
            f"ClientAliveInterval={cai}, ClientAliveCountMax={cam}"
        ),
        remediation=(
            "In /etc/ssh/sshd_config.d/50-hipaa-idle.conf:\n"
            "  ClientAliveInterval 300\n"
            "  ClientAliveCountMax 3\n"
            "Then: systemctl reload sshd\n"
            "Disconnects idle SSH sessions after 15 minutes."
        ),
        cross_references={
            "HIPAA": "164.312(a)(2)(iii)", "NIST": "AC-12",
            "CIS": "5.2.16, 5.2.17",
        },
    ))

    # 3. Screen lock for desktop sessions (gnome-screensaver, xscreensaver)
    gnome_lock = _v35_command_available("gsettings")
    xscreen_present = _v35_command_available("xscreensaver-command")
    desktop_screensaver = gnome_lock or xscreen_present
    has_gui = (
        _v35_systemd_active("graphical.target") == "active" or
        _v35_systemd_active("gdm.service") == "active" or
        _v35_systemd_active("display-manager.service") == "active"
    )
    if has_gui:
        results.append(_v35_hipaa_result(
            f"{cat} - Desktop Screen Lock",
            "Pass" if desktop_screensaver else "Warning",
            f"HIPAA 164.312(a)(2)(iii) Desktop screensaver tooling: "
            f"{desktop_screensaver}",
            severity="Medium",
            details=(
                f"GUI session: {has_gui}, gsettings/xscreensaver: "
                f"{desktop_screensaver}"
            ),
            remediation=(
                "GNOME: gsettings set org.gnome.desktop.session "
                "idle-delay 900\n"
                "       gsettings set org.gnome.desktop.screensaver "
                "lock-enabled true\n"
                "X11/xscreensaver: configure ~/.xscreensaver with "
                "timeout 0:15:00 + lock-mode True"
            ),
            cross_references={
                "HIPAA": "164.312(a)(2)(iii)", "NIST": "AC-11",
            },
        ))

    return results


def _check_hipaa_v35_encryption_depth(os_info):
    """164.312(a)(2)(iv) Encryption - provider depth, TLS strict, cert chain."""
    results = []
    cat = "HIPAA v3.5 - 164.312(a)(2)(iv)"

    # 1. FIPS-validated cryptographic provider
    fips_enabled = _v35_read_sysctl("crypto.fips_enabled") == "1"
    fips_indicator_files = [
        _v35_file_exists("/proc/sys/crypto/fips_enabled"),
        _v35_file_exists("/etc/system-fips"),
        _v35_file_exists("/etc/crypto-policies/state/current"),
    ]
    results.append(_v35_hipaa_result(
        f"{cat} - FIPS Provider",
        "Pass" if fips_enabled else "Info",
        f"HIPAA 164.312(a)(2)(iv) FIPS 140-3 mode: {fips_enabled}",
        severity="High",
        details=(
            f"crypto.fips_enabled: {fips_enabled}, "
            f"FIPS indicator files: {sum(fips_indicator_files)}/3"
        ),
        remediation=(
            "On RHEL: fips-mode-setup --enable; reboot\n"
            "On Ubuntu (with Pro): pro enable fips\n"
            "HIPAA addressable safeguard; FIPS-validated cryptography "
            "satisfies the encryption requirement strongly."
        ),
        cross_references={
            "HIPAA": "164.312(a)(2)(iv), 164.312(e)(2)(ii)",
            "NIST": "SC-13", "FIPS": "140-3",
        },
    ))

    # 2. OpenSSL crypto-policies (RHEL/Fedora) - DEFAULT vs FUTURE/FIPS
    crypto_policy = _v35_read_file_safe(
        "/etc/crypto-policies/state/current"
    ).strip()
    if crypto_policy:
        strict_policy = crypto_policy.upper() in ("FIPS", "FUTURE")
        results.append(_v35_hipaa_result(
            f"{cat} - Crypto Policy",
            "Pass" if strict_policy else "Info",
            f"HIPAA 164.312 Crypto policy: {crypto_policy}",
            severity="Medium",
            details=f"Active crypto policy: {crypto_policy}",
            remediation=(
                "update-crypto-policies --set FUTURE\n"
                "Or for FIPS: fips-mode-setup --enable\n"
                "FUTURE/FIPS policies enforce stronger algorithms across "
                "all OpenSSL/GnuTLS/NSS/OpenSSH consumers."
            ),
            cross_references={
                "HIPAA": "164.312(a)(2)(iv)", "NIST": "SC-13",
            },
        ))

    # 3. CA bundle freshness (TLS chain validation depends on this)
    ca_bundle_paths = [
        "/etc/ssl/certs/ca-certificates.crt",  # Debian/Ubuntu
        "/etc/pki/tls/certs/ca-bundle.crt",  # RHEL
        "/etc/ssl/cert.pem",  # Alpine
    ]
    ca_bundle_path = None
    ca_bundle_age = -1
    for p in ca_bundle_paths:
        if _v35_file_exists(p):
            ca_bundle_path = p
            try:
                import time
                mtime = os.path.getmtime(p)
                ca_bundle_age = int((time.time() - mtime) / 86400)
            except OSError:
                pass
            break
    ca_fresh = 0 <= ca_bundle_age <= 180  # 6 months
    results.append(_v35_hipaa_result(
        f"{cat} - CA Bundle Freshness",
        "Pass" if ca_fresh else "Warning",
        f"HIPAA 164.312(e)(2)(ii) CA bundle age: {ca_bundle_age}d",
        severity="Medium",
        details=f"path: {ca_bundle_path}, age: {ca_bundle_age} days",
        remediation=(
            "Update CA bundle:\n"
            "  Debian/Ubuntu: apt-get install -y ca-certificates && "
            "update-ca-certificates\n"
            "  RHEL: dnf install -y ca-certificates && update-ca-trust\n"
            "Stale CA bundles fail to validate certificates from newer CAs."
        ),
        cross_references={
            "HIPAA": "164.312(e)(2)(ii)", "NIST": "SC-17",
        },
    ))

    # 4. SSH server keys: types and lengths
    ssh_keys = []
    ssh_dir = "/etc/ssh"
    if _v35_directory_exists(ssh_dir):
        for f in _v35_list_directory(ssh_dir):
            if f.startswith("ssh_host_") and f.endswith("_key.pub"):
                ssh_keys.append(f)
    has_ed25519 = any("ed25519" in k for k in ssh_keys)
    has_ecdsa = any("ecdsa" in k for k in ssh_keys)
    has_rsa = any("rsa" in k for k in ssh_keys)
    has_dsa = any("dsa_key.pub" in k or "dsa.pub" in k for k in ssh_keys)
    # ED25519 is preferred; DSA must be removed
    strong_keys = has_ed25519 and not has_dsa
    results.append(_v35_hipaa_result(
        f"{cat} - SSH Host Keys",
        "Pass" if strong_keys else "Warning",
        f"HIPAA 164.312(e) SSH host key types: ed25519={has_ed25519}, "
        f"ecdsa={has_ecdsa}, rsa={has_rsa}, dsa={has_dsa}",
        severity="High",
        details=(
            f"Keys present: {ssh_keys}, ED25519: {has_ed25519}, "
            f"DSA (forbidden): {has_dsa}"
        ),
        remediation=(
            "Generate strong host keys (run as root):\n"
            "  ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ''\n"
            "Remove DSA: rm -f /etc/ssh/ssh_host_dsa_key*\n"
            "DSA is cryptographically broken (1024-bit fixed)."
        ),
        cross_references={
            "HIPAA": "164.312(e)(2)(ii)", "NIST": "SC-13",
            "STIG": "V-230275",
        },
    ))

    return results


def _check_hipaa_v35_audit_controls_depth(os_info):
    """164.312(b) Audit controls - per-user logging, log access, retention."""
    results = []
    cat = "HIPAA v3.5 - 164.312(b)"

    # 1. auditd active and logging per-user (auid)
    auditd_active = _v35_systemd_active("auditd.service") == "active"
    audit_rules = ""
    if _v35_directory_exists("/etc/audit/rules.d"):
        for f in _v35_list_directory("/etc/audit/rules.d"):
            if f.endswith(".rules"):
                audit_rules += "\n" + _v35_read_file_safe(
                    os.path.join("/etc/audit/rules.d", f)
                )
    auid_enforced = "auid>=1000" in audit_rules and "auid!=4294967295" in audit_rules
    results.append(_v35_hipaa_result(
        f"{cat} - Per-User Audit (auid)",
        "Pass" if auditd_active and auid_enforced else "Warning",
        f"HIPAA 164.312(b) Per-user audit (auid filtering): "
        f"{auditd_active and auid_enforced}",
        severity="High",
        details=(
            f"auditd active: {auditd_active}, "
            f"auid filter rules: {auid_enforced}"
        ),
        remediation=(
            "Add to /etc/audit/rules.d/41-hipaa-perusers.rules:\n"
            "  -a always,exit -F arch=b64 -S execve "
            "-F auid>=1000 -F auid!=4294967295 -k user-actions\n"
            "augenrules --load\n"
            "Tracks all process executions by individual users (not system)."
        ),
        cross_references={
            "HIPAA": "164.312(b)", "NIST": "AU-2, AU-3, AU-12",
        },
    ))

    # 2. Audit log access auditing (logs of log access)
    audit_log_accessed = (
        "/var/log/audit" in audit_rules or
        "audit.log" in audit_rules
    )
    results.append(_v35_hipaa_result(
        f"{cat} - Audit Log Access Tracking",
        "Pass" if audit_log_accessed else "Warning",
        f"HIPAA 164.312(b) Audit log access tracked: {audit_log_accessed}",
        severity="High",
        details=f"Watch on /var/log/audit: {audit_log_accessed}",
        remediation=(
            "Add to /etc/audit/rules.d/41-hipaa-logaccess.rules:\n"
            "  -w /var/log/audit/ -p wra -k audit-log-access\n"
            "Captures any read/write/attribute change to audit logs."
        ),
        cross_references={
            "HIPAA": "164.312(b)", "NIST": "AU-9",
        },
    ))

    # 3. Audit log immutability (-e 2 finalization)
    immutable_set = bool(re.search(r"^\s*-e\s+2", audit_rules, re.MULTILINE))
    results.append(_v35_hipaa_result(
        f"{cat} - Audit Rules Immutable",
        "Pass" if immutable_set else "Info",
        f"HIPAA 164.312(b)/(c) Audit ruleset locked (-e 2): {immutable_set}",
        severity="Medium",
        details=f"Immutable directive present: {immutable_set}",
        remediation=(
            "Append to /etc/audit/rules.d/99-finalize.rules:\n"
            "  -e 2\n"
            "Locks the audit ruleset until next reboot - prevents runtime "
            "tampering of audit policy."
        ),
        cross_references={
            "HIPAA": "164.312(b), 164.312(c)(1)",
            "NIST": "AU-9, AU-12(3)",
        },
    ))

    # 4. journald: persistent + sealed
    journald_conf = _v35_read_file_safe("/etc/systemd/journald.conf")
    journald_d = ""
    if _v35_directory_exists("/etc/systemd/journald.conf.d"):
        for f in _v35_list_directory("/etc/systemd/journald.conf.d"):
            if f.endswith(".conf"):
                journald_d += "\n" + _v35_read_file_safe(
                    os.path.join("/etc/systemd/journald.conf.d", f)
                )
    full_journald = journald_conf + "\n" + journald_d
    storage = re.search(r"^\s*Storage\s*=\s*(\w+)", full_journald, re.MULTILINE)
    persistent = (
        (storage and storage.group(1) == "persistent") or
        (not storage and _v35_directory_exists("/var/log/journal"))
    )
    seal = re.search(r"^\s*Seal\s*=\s*(\w+)", full_journald, re.MULTILINE)
    seal_ok = (seal is None) or seal.group(1).lower() in ("yes", "true", "1")
    results.append(_v35_hipaa_result(
        f"{cat} - journald Discipline",
        "Pass" if persistent and seal_ok else "Warning",
        f"HIPAA 164.312(b) journald persistent={persistent}, seal={seal_ok}",
        severity="High",
        details=(
            f"Storage = {storage.group(1) if storage else 'auto'}, "
            f"Seal = {seal.group(1) if seal else 'default(yes)'}"
        ),
        remediation=(
            "In /etc/systemd/journald.conf:\n"
            "  Storage=persistent\n"
            "  Seal=yes\n"
            "  SystemMaxUse=2G\n"
            "Set up Forward Secure Sealing keys: journalctl --setup-keys\n"
            "Then: systemctl restart systemd-journald"
        ),
        cross_references={
            "HIPAA": "164.312(b), 164.308(a)(1)(ii)(D)",
            "NIST": "AU-4, AU-9, AU-11",
        },
    ))

    return results


def _check_hipaa_v35_integrity_authentication(os_info):
    """164.312(c)(2) Mechanism to authenticate ePHI integrity."""
    results = []
    cat = "HIPAA v3.5 - 164.312(c)(2)"

    # 1. AIDE / Tripwire / Samhain - file integrity baseline
    fim_databases = {
        "AIDE": (
            _v35_file_exists("/var/lib/aide/aide.db") or
            _v35_file_exists("/var/lib/aide/aide.db.gz")
        ),
        "Tripwire": _v35_file_exists("/var/lib/tripwire/tw.db"),
        "Samhain": _v35_file_exists("/var/lib/samhain/samhain_file"),
        "OSSEC FIM": _v35_file_exists("/var/ossec/queue/syscheck/syscheck.db"),
        "Wazuh FIM": _v35_file_exists("/var/ossec/queue/fim/db/fim.db"),
    }
    fim_present = [k for k, v in fim_databases.items() if v]
    results.append(_v35_hipaa_result(
        f"{cat} - FIM Database",
        "Pass" if fim_present else "Fail",
        f"HIPAA 164.312(c)(2) FIM baseline: {fim_present or 'none'}",
        severity="High",
        details=f"FIM databases detected: {fim_present}",
        remediation=remediation_for("aide") if not fim_present else (
            f"{fim_present[0]} active. Verify daily cron job and SIEM forwarding."
        ),
        cross_references={
            "HIPAA": "164.312(c)(1), 164.312(c)(2)",
            "NIST": "SI-7", "PCI-DSS": "11.5.2",
            "ISO27001": "A.8.32",
        },
    ))

    # 2. Package signature verification (rpm -Va or debsums)
    pkg_verify_tool = None
    if _v35_command_available("debsums"):
        pkg_verify_tool = "debsums"
    elif _v35_command_available("rpm"):
        pkg_verify_tool = "rpm -Va"
    results.append(_v35_hipaa_result(
        f"{cat} - Package Verification Tool",
        "Pass" if pkg_verify_tool else "Warning",
        f"HIPAA 164.312(c)(2) Package verification tool: {pkg_verify_tool}",
        severity="Medium",
        details=f"Tool available: {pkg_verify_tool}",
        remediation=(
            "Debian/Ubuntu: apt-get install -y debsums; debsums -c\n"
            "RHEL: rpm -Va  (built-in)\n"
            "Detects modifications to package-managed binaries (a key "
            "ePHI integrity authentication signal)."
        ),
        cross_references={
            "HIPAA": "164.312(c)(2)", "NIST": "SI-7",
        },
    ))

    # 3. dm-verity / IMA presence (kernel-level integrity)
    dm_verity = (
        _v35_directory_exists("/sys/module/dm_verity") or
        _v35_command_available("veritysetup")
    )
    ima_present = _v35_directory_exists("/sys/kernel/security/ima")
    kernel_integrity = dm_verity or ima_present
    results.append(_v35_hipaa_result(
        f"{cat} - Kernel-level Integrity",
        "Pass" if kernel_integrity else "Info",
        f"HIPAA 164.312(c)(2) Kernel-level integrity: dm-verity={dm_verity}, "
        f"IMA={ima_present}",
        severity="Medium",
        details=f"dm-verity: {dm_verity}, IMA: {ima_present}",
        remediation=(
            "Enable IMA: kernel cmdline `ima_policy=tcb`\n"
            "dm-verity is typically used for read-only root partitions on "
            "embedded/cloud systems."
        ),
        cross_references={
            "HIPAA": "164.312(c)(2)", "NIST": "SI-7(1)",
        },
    ))

    return results


def _check_hipaa_v35_authentication_depth(os_info):
    """164.312(d) Person/entity authentication - MFA, mutual TLS, certs."""
    results = []
    cat = "HIPAA v3.5 - 164.312(d)"

    # 1. MFA enforcement on SSH
    sshd = _v35_read_file_safe("/etc/ssh/sshd_config")
    sshd_d_text = ""
    if _v35_directory_exists("/etc/ssh/sshd_config.d"):
        for f in _v35_list_directory("/etc/ssh/sshd_config.d"):
            if f.endswith(".conf"):
                sshd_d_text += "\n" + _v35_read_file_safe(
                    os.path.join("/etc/ssh/sshd_config.d", f)
                )
    full_sshd = sshd + "\n" + sshd_d_text
    auth_methods_match = re.search(
        r"^\s*AuthenticationMethods\s+(\S+)", full_sshd, re.MULTILINE,
    )
    mfa_enforced = bool(
        auth_methods_match and
        ("publickey,keyboard-interactive" in auth_methods_match.group(1) or
         "publickey,password" in auth_methods_match.group(1))
    )
    # Also check for PAM MFA modules
    pam_files = [
        "/etc/pam.d/sshd", "/etc/pam.d/common-auth",
        "/etc/pam.d/system-auth", "/etc/pam.d/password-auth",
    ]
    pam_mfa = False
    for pf in pam_files:
        c = _v35_read_file_safe(pf)
        if any(mod in c for mod in [
            "pam_google_authenticator", "pam_yubico",
            "pam_oath", "pam_u2f", "pam_duo",
        ]):
            pam_mfa = True
            break
    mfa_present = mfa_enforced or pam_mfa
    results.append(_v35_hipaa_result(
        f"{cat} - MFA",
        "Pass" if mfa_present else "Fail",
        f"HIPAA 164.312(d) Multi-factor authentication: "
        f"{'enforced' if mfa_present else 'not detected'}",
        severity="Critical",
        details=(
            f"AuthenticationMethods MFA: {mfa_enforced}, "
            f"PAM MFA module: {pam_mfa}"
        ),
        remediation=remediation_for("pam-google-authenticator"),
        cross_references={
            "HIPAA": "164.312(d), 164.308(a)(5)(ii)(D)",
            "NIST": "IA-2(1), IA-2(2), IA-2(11), IA-2(12)",
            "PCI-DSS": "8.4.1", "CISA-CPG": "2.H",
        },
    ))

    # 2. Public-key only (preferred over passwords)
    password_auth_match = re.search(
        r"^\s*PasswordAuthentication\s+(yes|no)", full_sshd, re.MULTILINE,
    )
    pwd_auth_disabled = (
        password_auth_match and password_auth_match.group(1).lower() == "no"
    )
    pubkey_match = re.search(
        r"^\s*PubkeyAuthentication\s+(yes|no)", full_sshd, re.MULTILINE,
    )
    pubkey_enabled = (
        pubkey_match is None or pubkey_match.group(1).lower() == "yes"
    )
    results.append(_v35_hipaa_result(
        f"{cat} - SSH Pubkey Auth",
        "Pass" if pwd_auth_disabled and pubkey_enabled else "Warning",
        f"HIPAA 164.312(d) SSH pubkey-only: pwd_off={pwd_auth_disabled}, "
        f"pubkey_on={pubkey_enabled}",
        severity="High",
        details=(
            f"PasswordAuthentication = "
            f"{password_auth_match.group(1) if password_auth_match else 'default(yes)'}, "
            f"PubkeyAuthentication = "
            f"{pubkey_match.group(1) if pubkey_match else 'default(yes)'}"
        ),
        remediation=(
            "In /etc/ssh/sshd_config.d/50-hipaa-pubkey.conf:\n"
            "  PasswordAuthentication no\n"
            "  PubkeyAuthentication yes\n"
            "  PermitRootLogin prohibit-password\n"
            "(Migrate users to SSH keys before flipping PasswordAuthentication "
            "to no.)"
        ),
        cross_references={
            "HIPAA": "164.312(d)", "NIST": "IA-2(1)",
            "CIS": "5.2.10",
        },
    ))

    # 3. PAM faillock for account lockout
    pam_files_content = ""
    for pf in pam_files:
        pam_files_content += "\n" + _v35_read_file_safe(pf)
    faillock_present = (
        "pam_faillock" in pam_files_content or
        "pam_tally2" in pam_files_content
    )
    results.append(_v35_hipaa_result(
        f"{cat} - Account Lockout",
        "Pass" if faillock_present else "Warning",
        f"HIPAA 164.308(a)(5)(ii)(C) Account lockout (PAM faillock/tally2): "
        f"{faillock_present}",
        severity="High",
        details=f"PAM lockout module present: {faillock_present}",
        remediation=(
            "On RHEL: authselect select sssd with-faillock\n"
            "On Debian: edit /etc/pam.d/common-auth - add:\n"
            "  auth required pam_faillock.so preauth deny=5 unlock_time=900\n"
            "  auth [default=die] pam_faillock.so authfail deny=5 unlock_time=900"
        ),
        cross_references={
            "HIPAA": "164.308(a)(5)(ii)(C)", "NIST": "AC-7",
            "PCI-DSS": "8.3.4",
        },
    ))

    return results


def _check_hipaa_v35_transmission_security(os_info):
    """164.312(e)(1) and (e)(2) Transmission integrity + encryption."""
    results = []
    cat = "HIPAA v3.5 - 164.312(e)"

    # 1. IPsec strongSwan / Libreswan presence
    ipsec_present = (
        _v35_systemd_active("strongswan.service") == "active" or
        _v35_systemd_active("strongswan-starter.service") == "active" or
        _v35_systemd_active("libreswan.service") == "active" or
        _v35_systemd_active("ipsec.service") == "active"
    )

    # WireGuard as a modern alternative
    wireguard_present = (
        _v35_command_available("wg") and
        any(("wg" in iface) for iface in (
            (_v35_run_command(["ip", "-br", "link"], timeout=5.0)[1] or "").split()
        ))
    )

    transit_vpn_present = ipsec_present or wireguard_present
    results.append(_v35_hipaa_result(
        f"{cat} - Network Encryption Layer",
        "Pass" if transit_vpn_present else "Info",
        f"HIPAA 164.312(e)(2)(ii) Network encryption: "
        f"IPsec={ipsec_present}, WireGuard={wireguard_present}",
        severity="High",
        details=(
            f"IPsec: {ipsec_present}, WireGuard active: {wireguard_present}"
        ),
        remediation=(
            "WireGuard (recommended): \n"
            f"{remediation_for('wireguard')}\n"
            "Or IPsec with strongSwan / Libreswan for tunnel-based ePHI "
            "transmission encryption."
        ),
        cross_references={
            "HIPAA": "164.312(e)(2)(ii)", "NIST": "SC-8(1)",
            "PCI-DSS": "4.2.1",
        },
    ))

    # 2. TLS minimum version on local services
    # nginx
    nginx_tls_strong = False
    nginx_conf_paths = [
        "/etc/nginx/nginx.conf",
        "/etc/nginx/conf.d",
        "/etc/nginx/sites-enabled",
    ]
    nginx_ssl_protocols = ""
    for path in nginx_conf_paths:
        if _v35_file_exists(path):
            content = _v35_read_file_safe(path)
            m = re.search(r"ssl_protocols\s+([^;]+);", content)
            if m:
                nginx_ssl_protocols = m.group(1)
                break
        elif _v35_directory_exists(path):
            for f in _v35_list_directory(path):
                content = _v35_read_file_safe(os.path.join(path, f))
                m = re.search(r"ssl_protocols\s+([^;]+);", content)
                if m:
                    nginx_ssl_protocols = m.group(1)
                    break
    if nginx_ssl_protocols:
        nginx_tls_strong = (
            "TLSv1" not in nginx_ssl_protocols.replace("TLSv1.2", "").replace("TLSv1.3", "") and
            ("TLSv1.2" in nginx_ssl_protocols or "TLSv1.3" in nginx_ssl_protocols)
        )
        results.append(_v35_hipaa_result(
            f"{cat} - nginx TLS Version",
            "Pass" if nginx_tls_strong else "Warning",
            f"HIPAA 164.312(e)(2)(ii) nginx ssl_protocols: "
            f"{nginx_ssl_protocols.strip()}",
            severity="Critical",
            details=f"ssl_protocols = {nginx_ssl_protocols.strip()}",
            remediation=(
                "In /etc/nginx/conf.d/security.conf:\n"
                "  ssl_protocols TLSv1.2 TLSv1.3;\n"
                "  ssl_ciphers HIGH:!aNULL:!MD5:!RC4:!3DES;\n"
                "  ssl_prefer_server_ciphers on;\n"
                "Then: nginx -s reload"
            ),
            cross_references={
                "HIPAA": "164.312(e)(2)(ii)", "NIST": "SC-13",
                "PCI-DSS": "4.2.1",
            },
        ))

    # Apache
    apache_paths = [
        "/etc/apache2/mods-enabled/ssl.conf",
        "/etc/httpd/conf.d/ssl.conf",
    ]
    apache_protocol_line = ""
    for path in apache_paths:
        if _v35_file_exists(path):
            c = _v35_read_file_safe(path)
            m = re.search(r"^\s*SSLProtocol\s+(.+)$", c, re.MULTILINE)
            if m:
                apache_protocol_line = m.group(1)
                break
    if apache_protocol_line:
        apache_tls_strong = (
            "TLSv1.2" in apache_protocol_line or "TLSv1.3" in apache_protocol_line
        ) and "-TLSv1 " in apache_protocol_line + " " + apache_protocol_line.replace("TLSv1.2", "")
        results.append(_v35_hipaa_result(
            f"{cat} - Apache TLS Version",
            "Pass" if apache_tls_strong else "Warning",
            f"HIPAA 164.312(e)(2)(ii) Apache SSLProtocol: {apache_protocol_line[:60]}",
            severity="Critical",
            details=f"SSLProtocol = {apache_protocol_line}",
            remediation=(
                "In /etc/apache2/mods-enabled/ssl.conf or "
                "/etc/httpd/conf.d/ssl.conf:\n"
                "  SSLProtocol -all +TLSv1.2 +TLSv1.3\n"
                "  SSLCipherSuite HIGH:!aNULL:!MD5:!RC4:!3DES\n"
                "Then: apachectl restart"
            ),
            cross_references={
                "HIPAA": "164.312(e)(2)(ii)", "NIST": "SC-13",
            },
        ))

    return results


def _check_hipaa_v35_breach_notification_readiness(os_info):
    """45 CFR 164.402-410 Breach notification - technical readiness indicators."""
    results = []
    cat = "HIPAA v3.5 - 164.402-410"

    # 1. Logs available for breach assessment (90+ days; HIPAA requires 6 years
    #    for documentation but operational logs typically need 90+ days for IR)
    auditd_conf = _v35_read_file_safe("/etc/audit/auditd.conf")
    max_log_match = re.search(
        r"^\s*max_log_file\s*=\s*(\d+)", auditd_conf, re.MULTILINE,
    )
    num_logs_match = re.search(
        r"^\s*num_logs\s*=\s*(\d+)", auditd_conf, re.MULTILINE,
    )
    max_log = int(max_log_match.group(1)) if max_log_match else 0
    num_logs = int(num_logs_match.group(1)) if num_logs_match else 0
    capacity_mb = max_log * num_logs
    breach_window_adequate = capacity_mb >= 1000  # >=1GB rolling window
    results.append(_v35_hipaa_result(
        f"{cat} - Breach Assessment Capacity",
        "Pass" if breach_window_adequate else "Warning",
        f"HIPAA 164.402 Audit retention capacity: {capacity_mb}MB",
        severity="High",
        details=(
            f"max_log_file = {max_log}MB, num_logs = {num_logs}, "
            f"total = {capacity_mb}MB"
        ),
        remediation=(
            "In /etc/audit/auditd.conf:\n"
            "  max_log_file = 100\n"
            "  num_logs = 30\n"
            "Provides ~3GB rolling retention. For long-term HIPAA "
            "documentation (6 years for breach docs), forward to "
            "centralized archive."
        ),
        cross_references={
            "HIPAA": "164.402, 164.408, 164.530(j)",
            "NIST": "AU-11, IR-6",
        },
    ))

    # 2. Alerting capability (mailx / postfix / sendmail for breach notification)
    mail_capable = (
        _v35_command_available("mail") or
        _v35_command_available("mailx") or
        _v35_command_available("sendmail") or
        _v35_systemd_active("postfix.service") == "active"
    )
    results.append(_v35_hipaa_result(
        f"{cat} - Email Alerting",
        "Pass" if mail_capable else "Warning",
        f"HIPAA 164.404 Email alerting capability: {mail_capable}",
        severity="High",
        details=f"mail/mailx/sendmail/postfix available: {mail_capable}",
        remediation=(
            "Install: apt-get install -y mailutils postfix\n"
            "Configure relay to MTA in /etc/postfix/main.cf for breach "
            "notification automation per 45 CFR 164.404 60-day rule."
        ),
        cross_references={
            "HIPAA": "164.404, 164.406, 164.408",
            "NIST": "IR-6, AU-5",
        },
    ))

    # 3. Identifiable user activity (auditd auid filter; ties actions to users)
    rules_text = ""
    if _v35_directory_exists("/etc/audit/rules.d"):
        for f in _v35_list_directory("/etc/audit/rules.d"):
            if f.endswith(".rules"):
                rules_text += "\n" + _v35_read_file_safe(
                    os.path.join("/etc/audit/rules.d", f)
                )
    auid_tracking = "auid" in rules_text
    results.append(_v35_hipaa_result(
        f"{cat} - User Identification Capability",
        "Pass" if auid_tracking else "Fail",
        f"HIPAA 164.402 User-action attribution capability: {auid_tracking}",
        severity="Critical",
        details=(
            f"auid-tracking audit rules: {auid_tracking}"
        ),
        remediation=(
            "Add to /etc/audit/rules.d/41-hipaa-attribution.rules:\n"
            "  -a always,exit -F arch=b64 -S execve -F auid>=1000 "
            "-F auid!=4294967295 -k user-action\n"
            "Required for breach analysis: which user accessed what data "
            "and when. Without auid tracking, post-breach attribution is "
            "impossible."
        ),
        cross_references={
            "HIPAA": "164.402, 164.312(b)",
            "NIST": "AU-2, AU-3, IR-4",
        },
    ))

    # 4. Time accuracy for breach timeline reconstruction
    time_sync_active = (
        _v35_systemd_active("chronyd.service") == "active" or
        _v35_systemd_active("chrony.service") == "active" or
        _v35_systemd_active("systemd-timesyncd.service") == "active"
    )
    results.append(_v35_hipaa_result(
        f"{cat} - Time Sync (Timeline Accuracy)",
        "Pass" if time_sync_active else "Fail",
        f"HIPAA 164.402 Time synchronization for breach timeline: "
        f"{time_sync_active}",
        severity="Critical",
        details=f"NTP/chrony/timesyncd active: {time_sync_active}",
        remediation=remediation_for("chrony"),
        cross_references={
            "HIPAA": "164.402, 164.312(b)",
            "NIST": "AU-8", "PCI-DSS": "10.6.1",
        },
    ))

    return results


def _check_hipaa_v35_risk_analysis(os_info):
    """164.308(a)(1)(ii)(A) Risk Analysis - vuln scanning & monitoring."""
    results = []
    cat = "HIPAA v3.5 - 164.308(a)(1)"

    # Vulnerability scanning tools
    scan_tools = {
        "lynis": _v35_command_available("lynis"),
        "openscap": _v35_command_available("oscap"),
        "trivy": _v35_command_available("trivy"),
        "nuclei": _v35_command_available("nuclei"),
        "nikto": _v35_command_available("nikto"),
        "rkhunter": _v35_command_available("rkhunter"),
    }
    scanners = [k for k, v in scan_tools.items() if v]
    results.append(_v35_hipaa_result(
        f"{cat} - Vulnerability Scanners",
        "Pass" if scanners else "Warning",
        f"HIPAA 164.308(a)(1) Vuln scanning tools: {len(scanners)}",
        severity="High",
        details=f"Available: {scanners}",
        remediation=remediation_for("lynis"),
        cross_references={
            "HIPAA": "164.308(a)(1)(ii)(A), 164.308(a)(8)",
            "NIST": "RA-5", "PCI-DSS": "11.4.1",
        },
    ))

    # Information system activity review (164.308(a)(1)(ii)(D))
    log_review_indicators = {
        "logwatch": _v35_command_available("logwatch"),
        "logcheck": _v35_command_available("logcheck"),
        "OSSEC/Wazuh": _v35_file_exists("/var/ossec/etc/ossec.conf"),
        "auditd": _v35_systemd_active("auditd.service") == "active",
    }
    review_tools = [k for k, v in log_review_indicators.items() if v]
    results.append(_v35_hipaa_result(
        f"{cat} - Activity Review",
        "Pass" if len(review_tools) >= 2 else "Warning",
        f"HIPAA 164.308(a)(1)(ii)(D) Activity-review tooling: {len(review_tools)}",
        severity="High",
        details=f"Detected: {review_tools}",
        remediation=(
            "Install logwatch for daily log summary email:\n"
            "  apt-get install -y logwatch\n"
            "  /etc/cron.daily/00logwatch is created automatically.\n"
            "Pair with auditd for kernel-level activity audit."
        ),
        cross_references={
            "HIPAA": "164.308(a)(1)(ii)(D)", "NIST": "AU-6, AU-12",
        },
    ))

    return results


# Save reference to existing run_checks
_original_run_checks_hipaa_v35 = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the v3.5 expanded HIPAA module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_hipaa_v35(shared_data)

    os_info = shared_data.get("os_info") or shared_data.get("v3_os_info")
    if os_info is None:
        from shared_components import os_detection as _os_det
        os_info = _os_det.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        results.extend(_check_hipaa_v35_unique_id_depth(os_info))
        results.extend(_check_hipaa_v35_logoff_depth(os_info))
        results.extend(_check_hipaa_v35_encryption_depth(os_info))
        results.extend(_check_hipaa_v35_audit_controls_depth(os_info))
        results.extend(_check_hipaa_v35_integrity_authentication(os_info))
        results.extend(_check_hipaa_v35_authentication_depth(os_info))
        results.extend(_check_hipaa_v35_transmission_security(os_info))
        results.extend(_check_hipaa_v35_breach_notification_readiness(os_info))
        results.extend(_check_hipaa_v35_risk_analysis(os_info))
    except Exception as exc:  # noqa: BLE001
        results.append(AuditResult(
            module=MODULE_NAME, category="HIPAA - Error",
            status="Error",
            message=f"HIPAA v3.5 expansion exception: {exc!r}",
            details=str(exc), severity="Medium",
        ))

    return results
if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    print("[HIPAA] ===== HIPAA Security Rule + 405(d) HICP Audit =====")
    print("[HIPAA] Module Version: 3.9\n")
    rs = run_checks()
    print(f"[HIPAA] {len(rs)} checks executed\n")
    counts: Dict[str, int] = {}
    for r in rs:
        counts[r.status] = counts.get(r.status, 0) + 1
    for s, c in sorted(counts.items()):
        print(f"  {s:>8}: {c}")
