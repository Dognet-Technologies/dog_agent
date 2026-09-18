#!/usr/bin/env python3
"""
module_gdpr.py
GDPR Article 32 + ePrivacy Module for Linux
Version: 3.9

SYNOPSIS
    Linux technical compliance assessment against the European Union
    General Data Protection Regulation (GDPR) Article 32 (Security of
    processing) and the ePrivacy Directive 2002/58/EC technical
    requirements applicable to information systems.

DESCRIPTION
    GDPR Article 32 requires controllers and processors to implement
    appropriate technical and organisational measures to ensure a level
    of security appropriate to the risk. This module covers the technical
    measures listed in Article 32(1)(a)-(d) plus related obligations
    from Articles 25 (Data Protection by Design and by Default) and
    33 (Notification of personal data breach).

    Article 32 technical requirements covered:
        Art-32(1)(a) - Pseudonymisation and encryption of personal data
        Art-32(1)(b) - Ongoing confidentiality, integrity, availability,
                       and resilience of processing systems and services
        Art-32(1)(c) - Ability to restore the availability and access to
                       personal data in a timely manner in the event of
                       a physical or technical incident
        Art-32(1)(d) - Process for regularly testing, assessing and
                       evaluating the effectiveness of technical and
                       organisational measures

    Additional articles addressed:
        Art-25 - Data Protection by Design and by Default (technical)
        Art-33 - Breach notification (technical indicators)
        ePrivacy Art-4 - Security of services
        ePrivacy Art-5 - Confidentiality of communications

    Each check populates AuditResult.cross_references with the GDPR
    article reference plus equivalents in NIST 800-53, ISO 27001, ENISA
    Baseline Security Recommendations, and NIS2 Article 21.

PARAMETERS
    shared_data : Dictionary containing shared data from the orchestrator.

USAGE
    Standalone:
        python3 modules/module_gdpr.py

    Via orchestrator:
        python3 linux_security_audit.py -m GDPR

NOTES
    Version: 3.9
    Reference: https://gdpr-info.eu/, EUR-Lex 32016R0679
    Standards: GDPR Regulation (EU) 2016/679, ePrivacy Directive 2002/58/EC,
               NIS2 Directive (EU) 2022/2555, ENISA Threat Landscape 2024
    Target: 75+ technical control checks
    Note: GDPR compliance involves substantial process and documentation
    requirements beyond what host-based audit can verify; this module
    covers the technical-control subset.
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

logger = logging.getLogger("audit.module_gdpr")
MODULE_NAME = "GDPR"
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
# Article 32(1)(a) - Pseudonymisation and Encryption of Personal Data
# ===========================================================================

def _check_art32_encryption_at_rest(os_info) -> List[AuditResult]:
    cat = "GDPR Art-32(1)(a) - Encryption at Rest"
    results: List[AuditResult] = []

    # LUKS disk encryption
    luks_active = False
    luks_devices = 0
    if command_available("dmsetup"):
        rc, out, _ = run_command(["dmsetup", "ls", "--target=crypt"])
        if rc == 0 and out and "No devices found" not in out:
            luks_active = True
            luks_devices = sum(
                1 for line in out.splitlines() if line.strip()
            )

    results.append(_r(
        cat,
        "Pass" if luks_active else "Warning",
        "GDPR Art-32(1)(a): Disk encryption (LUKS) active for personal data",
        severity="High",
        details=(
            f"LUKS-encrypted devices: {luks_devices}. "
            "GDPR encryption requirement is risk-based; disk encryption is "
            "appropriate for systems holding personal data on portable media "
            "or in environments with physical access risks."
        ),
        remediation=(
            "Encrypt volumes containing personal data with LUKS at provisioning. "
            "Migration of existing volumes requires careful planning - consult "
            "distribution documentation for safe procedures."
        ),
        cross_references={
            "GDPR": "Art-32(1)(a)", "NIST": "SC-28", "ISO27001": "A.8.10",
            "ENISA": "BSR-DP-1", "PCI-DSS": "3.5.1",
            "HIPAA": "164.312(a)(2)(iv)",
        },
    ))

    # Filesystem-level encryption alternatives (eCryptfs, fscrypt)
    fscrypt_supported = file_exists("/sys/fs/ext4/features/encryption")
    ecryptfs_loaded = False
    try:
        with open("/proc/modules", "r", encoding="utf-8") as f:
            ecryptfs_loaded = "ecryptfs" in f.read()
    except OSError:
        pass

    # Inform about availability without flagging absence as a failure
    results.append(_r(
        cat,
        "Info",
        "GDPR Art-32(1)(a): File-level encryption capabilities",
        severity="Informational",
        details=(
            f"fscrypt support: {fscrypt_supported}, "
            f"eCryptfs module loaded: {ecryptfs_loaded}"
        ),
        remediation=(
            "Where disk encryption is impractical, fscrypt or eCryptfs can "
            "encrypt specific directories holding personal data."
        ),
        cross_references={
            "GDPR": "Art-32(1)(a)", "NIST": "SC-28", "ISO27001": "A.8.10",
        },
    ))

    return results


def _check_art32_encryption_in_transit(os_info) -> List[AuditResult]:
    cat = "GDPR Art-32(1)(a) - Encryption in Transit"
    results: List[AuditResult] = []

    # SSH cipher hardening
    sshd_config = read_file_safe("/etc/ssh/sshd_config")
    if sshd_config:
        weak_ciphers_present = []
        ciphers_line = ""
        for line in sshd_config.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("ciphers "):
                ciphers_line = stripped
                for weak in ("3des", "arcfour", "blowfish", "des-cbc",
                             "rc4", "aes128-cbc", "aes256-cbc"):
                    if weak in stripped.lower():
                        weak_ciphers_present.append(weak)
                break

        if ciphers_line:
            results.append(_r(
                cat,
                "Pass" if not weak_ciphers_present else "Fail",
                "GDPR Art-32(1)(a): SSH cipher suite excludes weak algorithms",
                severity="High",
                details=(
                    f"Configured: {ciphers_line[:200]}; "
                    f"weak: {', '.join(weak_ciphers_present) or 'none'}"
                ),
                remediation=(
                    "Set in /etc/ssh/sshd_config: Ciphers "
                    "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,"
                    "aes128-gcm@openssh.com,aes256-ctr,aes128-ctr"
                ),
                cross_references={
                    "GDPR": "Art-32(1)(a)", "NIST": "SC-13",
                    "ISO27001": "A.8.24", "ENISA": "BSR-COM-1",
                    "CIS": "5.2.13", "PCI-DSS": "4.2.1",
                },
            ))

    # System-wide crypto policy (RHEL family)
    if file_exists("/etc/crypto-policies/config"):
        policy = read_file_safe("/etc/crypto-policies/config").strip()
        modern = policy in ("DEFAULT", "FUTURE", "FIPS")
        results.append(_r(
            cat,
            "Pass" if modern else "Fail",
            "GDPR Art-32(1)(a): System-wide crypto policy active",
            severity="High",
            details=f"Active policy: {policy or 'unset'}",
            remediation=(
                "update-crypto-policies --set DEFAULT (or FUTURE for stricter)"
            ),
            cross_references={
                "GDPR": "Art-32(1)(a)", "NIST": "SC-13",
                "ISO27001": "A.8.24", "NSA": "CRYPTO-1.1",
            },
        ))

    # TLS minimum version indicator: Apache/Nginx config check
    web_server_configs = (
        "/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf",
        "/etc/nginx/nginx.conf",
    )
    for cfg in web_server_configs:
        if not file_exists(cfg):
            continue
        content = read_file_safe(cfg)
        # Basic check for SSLProtocol/ssl_protocols directives
        if re.search(r"SSLProtocol\s+all\s+-SSLv[23]\s+-TLSv1\s+-TLSv1\.1",
                      content) or re.search(r"ssl_protocols\s+TLSv1\.[23]",
                                              content):
            tls_modern = True
        else:
            tls_modern = False

        results.append(_r(
            cat,
            "Pass" if tls_modern else "Warning",
            f"GDPR Art-32(1)(a): TLS configuration in {os.path.basename(cfg)}",
            severity="High",
            details=(
                f"Web server config detected: {cfg}; "
                f"explicit TLS 1.2+ enforcement found: {tls_modern}"
            ),
            remediation=(
                "For Apache: SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1. "
                "For nginx: ssl_protocols TLSv1.2 TLSv1.3."
            ),
            cross_references={
                "GDPR": "Art-32(1)(a)", "NIST": "SC-8(1)",
                "ISO27001": "A.8.24", "PCI-DSS": "4.2.1",
            },
        ))
        break  # Only check the first detected web server config

    return results


def _check_art32_pseudonymisation(os_info) -> List[AuditResult]:
    cat = "GDPR Art-32(1)(a) - Pseudonymisation"
    results: List[AuditResult] = []

    # Pseudonymisation is largely application-level; we check log
    # sanitisation indicators (rsyslog templates that strip/hash PII
    # are uncommon but possible)
    rsyslog_files = ["/etc/rsyslog.conf"] + list_directory("/etc/rsyslog.d", ".conf")
    has_log_sanitisation = False
    for rf in rsyslog_files:
        content = read_file_safe(rf)
        # Look for property replacers (PII redaction patterns)
        if re.search(r'\$\(replace\s', content) or "subtree-mask" in content:
            has_log_sanitisation = True
            break

    results.append(_r(
        cat,
        "Info",
        "GDPR Art-32(1)(a): Log sanitisation/pseudonymisation indicators",
        severity="Informational",
        details=(
            f"rsyslog content-replacement directives found: {has_log_sanitisation}. "
            "Pseudonymisation is usually applied in the application layer; "
            "this host-based check is informational only."
        ),
        remediation=(
            "Ensure applications writing personal data to logs apply "
            "pseudonymisation (e.g. hashing, tokenisation) before log emission."
        ),
        cross_references={
            "GDPR": "Art-32(1)(a)", "NIST": "SC-28(2)",
            "ISO27001": "A.8.11", "ENISA": "BSR-DP-2",
        },
    ))

    return results


# ===========================================================================
# Article 32(1)(b) - Confidentiality, Integrity, Availability, Resilience
# ===========================================================================

def _check_art32_confidentiality(os_info) -> List[AuditResult]:
    cat = "GDPR Art-32(1)(b) - Confidentiality"
    results: List[AuditResult] = []

    # File permissions on critical files
    critical_perms = (
        ("/etc/passwd", 0o644, "Critical"),
        ("/etc/shadow", 0o0,    "Critical"),  # mode 0 or 400
        ("/etc/group",  0o644, "High"),
        ("/etc/gshadow", 0o0,   "Critical"),
    )
    for path, expected, sev in critical_perms:
        actual = file_mode(path)
        if actual is None:
            continue
        if path == "/etc/shadow" or path == "/etc/gshadow":
            ok = actual in (0o0, 0o400, 0o600, 0o640)
        else:
            ok = actual == expected
        results.append(_r(
            cat,
            "Pass" if ok else "Fail",
            f"GDPR Art-32(1)(b): {path} permissions are appropriate",
            severity=sev,
            details=f"Mode: {oct(actual)} (expected: {oct(expected) if expected else '0/400/600/640'})",
            remediation=(
                f"chmod {oct(expected)[2:] or '0640'} {path} && "
                f"chown root:root {path}"
            ),
            cross_references={
                "GDPR": "Art-32(1)(b)", "NIST": "AC-3", "ISO27001": "A.8.3",
                "CIS": "6.1.2", "STIG": "V-230322",
            },
        ))

    # Access control via MAC (SELinux/AppArmor)
    mac_active = False
    if os_info.mac_framework == "selinux":
        try:
            with open("/sys/fs/selinux/enforce", "r", encoding="ascii") as f:
                mac_active = f.read().strip() == "1"
        except OSError:
            pass
    elif os_info.mac_framework == "apparmor":
        if command_available("aa-status"):
            rc, out, _ = run_command(["aa-status"])
            mac_active = rc == 0 and "profiles are in enforce mode" in out

    results.append(_r(
        cat,
        "Pass" if mac_active else "Warning",
        "GDPR Art-32(1)(b): Mandatory access control active",
        severity="High",
        details=(
            f"Framework: {os_info.mac_framework or 'none'}, "
            f"enforcing: {mac_active}"
        ),
        remediation=(
            "On RHEL/Fedora: setenforce 1 && update /etc/selinux/config. "
            "On Debian/Ubuntu: aa-enforce /etc/apparmor.d/*."
        ),
        cross_references={
            "GDPR": "Art-32(1)(b)", "NIST": "AC-3(4)", "ISO27001": "A.8.3",
            "CIS": "1.6.1.3", "ENISA": "BSR-AC-1",
        },
    ))

    return results


def _check_art32_integrity(os_info) -> List[AuditResult]:
    cat = "GDPR Art-32(1)(b) - Integrity"
    results: List[AuditResult] = []

    # File integrity monitoring
    fim_indicators = {
        "AIDE": command_available("aide") or file_exists("/etc/aide.conf"),
        "Tripwire": command_available("tripwire"),
        "Wazuh/OSSEC": file_exists("/var/ossec/etc/ossec.conf"),
        "Samhain": command_available("samhain"),
    }
    detected = [n for n, p in fim_indicators.items() if p]

    results.append(_r(
        cat,
        "Pass" if detected else "Warning",
        "GDPR Art-32(1)(b): File integrity monitoring deployed",
        severity="High",
        details=f"Detected: {', '.join(detected) or 'none'}",
        remediation=remediation_for("aide"),
        cross_references={
            "GDPR": "Art-32(1)(b)", "NIST": "SI-7", "ISO27001": "A.8.16",
            "PCI-DSS": "11.5.2", "ENISA": "BSR-INT-1",
        },
    ))

    # auditd for system integrity logging
    auditd_active = systemd_active("auditd.service") == "active"
    results.append(_r(
        cat,
        "Pass" if auditd_active else "Fail",
        "GDPR Art-32(1)(b): System auditing active for integrity",
        severity="High",
        details=f"auditd state: {systemd_active('auditd.service')}",
        remediation=remediation_for("auditd"),
        cross_references={
            "GDPR": "Art-32(1)(b)", "NIST": "AU-2", "ISO27001": "A.8.15",
            "CIS": "4.1.1.1", "ENISA": "BSR-LOG-1",
        },
    ))

    return results


def _check_art32_availability(os_info) -> List[AuditResult]:
    cat = "GDPR Art-32(1)(b) - Availability"
    results: List[AuditResult] = []

    # Backup tooling indicators
    backup_tools = {
        "rsync": command_available("rsync"),
        "Borg": command_available("borg"),
        "Restic": command_available("restic"),
        "Duplicity": command_available("duplicity"),
        "Bacula": file_exists("/etc/bacula/bacula-fd.conf"),
        "BackupPC": file_exists("/etc/backuppc/config.pl"),
    }
    detected_backup = [n for n, p in backup_tools.items() if p]

    results.append(_r(
        cat,
        "Info" if detected_backup else "Warning",
        "GDPR Art-32(1)(b): Backup tooling for data availability",
        severity="High",
        details=(
            f"Detected: {', '.join(detected_backup) or 'none'}. "
            "Tool presence alone does not confirm scheduled or tested backups."
        ),
        remediation=(
            "Implement scheduled backups with off-site storage and test "
            "restoration at least quarterly. Document recovery time and "
            "recovery point objectives (RTO/RPO) appropriate to the data."
        ),
        cross_references={
            "GDPR": "Art-32(1)(b)", "NIST": "CP-9", "ISO27001": "A.8.13",
            "ENISA": "BSR-AVAIL-1",
        },
    ))

    # Disk space monitoring (availability concern)
    disk_low = False
    try:
        import shutil as _shutil
        st = _shutil.disk_usage("/var")
        free_pct = (st.free / st.total) * 100 if st.total else 100
        disk_low = free_pct < 10
    except OSError:
        free_pct = -1

    if free_pct >= 0:
        results.append(_r(
            cat,
            "Fail" if disk_low else "Pass",
            "GDPR Art-32(1)(b): Sufficient free disk space on /var",
            severity="Medium",
            details=f"Free: {free_pct:.1f}% (threshold: 10%)",
            remediation="Identify and remove old data; expand storage if persistent",
            cross_references={
                "GDPR": "Art-32(1)(b)", "NIST": "AU-4", "ISO27001": "A.8.6",
            },
        ))

    return results


def _check_art32_resilience(os_info) -> List[AuditResult]:
    cat = "GDPR Art-32(1)(b) - Resilience"
    results: List[AuditResult] = []

    # systemd service auto-restart - sample of common services
    common_services = ("sshd.service", "auditd.service")
    for svc in common_services:
        unit_file = f"/lib/systemd/system/{svc}"
        if not file_exists(unit_file):
            unit_file = f"/usr/lib/systemd/system/{svc}"
            if not file_exists(unit_file):
                continue

        content = read_file_safe(unit_file)
        has_restart = "Restart=" in content and "Restart=no" not in content

        results.append(_r(
            cat,
            "Info",
            f"GDPR Art-32(1)(b): {svc} restart policy",
            severity="Low",
            details=f"Unit has Restart= directive (non-no): {has_restart}",
            remediation=(
                "Override unit to add Restart=on-failure if appropriate: "
                f"systemctl edit {svc}"
            ),
            cross_references={
                "GDPR": "Art-32(1)(b)", "NIST": "CP-2", "ISO27001": "A.8.14",
            },
        ))

    return results


# ===========================================================================
# Article 32(1)(c) - Restoration of Availability
# ===========================================================================

def _check_art32_restoration(os_info) -> List[AuditResult]:
    cat = "GDPR Art-32(1)(c) - Data Restoration"
    results: List[AuditResult] = []

    # journald persistent logging supports incident reconstruction
    journal_persist = directory_exists("/var/log/journal")
    results.append(_r(
        cat,
        "Pass" if journal_persist else "Warning",
        "GDPR Art-32(1)(c): Persistent journald logs for restoration evidence",
        severity="Medium",
        details=f"/var/log/journal directory exists: {journal_persist}",
        remediation=(
            "mkdir -p /var/log/journal && "
            "systemd-tmpfiles --create --prefix /var/log/journal && "
            "systemctl restart systemd-journald"
        ),
        cross_references={
            "GDPR": "Art-32(1)(c)", "NIST": "AU-9", "ISO27001": "A.8.15",
        },
    ))

    return results


# ===========================================================================
# Article 32(1)(d) - Regular Testing of Effectiveness
# ===========================================================================

def _check_art32_testing(os_info) -> List[AuditResult]:
    cat = "GDPR Art-32(1)(d) - Effectiveness Testing"
    results: List[AuditResult] = []

    # Vulnerability scanning tool presence
    vuln_tools = {
        "OpenSCAP": command_available("oscap"),
        "Lynis": command_available("lynis"),
        "OpenVAS/GVM": command_available("gvm-cli") or command_available("openvas"),
        "Nessus": file_exists("/opt/nessus/sbin/nessusd"),
    }
    detected_vuln = [n for n, p in vuln_tools.items() if p]

    results.append(_r(
        cat,
        "Info" if detected_vuln else "Warning",
        "GDPR Art-32(1)(d): Security testing tools available",
        severity="Medium",
        details=f"Detected: {', '.join(detected_vuln) or 'none'}",
        remediation=(
            "Install security testing tools and schedule regular scans. "
            "Lynis provides good Linux baseline; OpenSCAP supports STIG/CIS "
            "scanning; OpenVAS for network vulnerability assessment."
        ),
        cross_references={
            "GDPR": "Art-32(1)(d)", "NIST": "RA-5", "ISO27001": "A.8.8",
            "PCI-DSS": "11.3", "ENISA": "BSR-VULN-1",
        },
    ))

    return results


# ===========================================================================
# Article 25 - Data Protection by Design and by Default
# ===========================================================================

def _check_art25_by_design(os_info) -> List[AuditResult]:
    cat = "GDPR Art-25 - Data Protection by Design"
    results: List[AuditResult] = []

    # Default-deny network posture
    fw_default_deny = False
    if command_available("iptables"):
        rc, out, _ = run_command(["iptables", "-S", "INPUT"])
        if rc == 0:
            for line in out.splitlines():
                if line.startswith("-P INPUT"):
                    if line.split()[-1] in ("DROP", "REJECT"):
                        fw_default_deny = True
                    break

    results.append(_r(
        cat,
        "Pass" if fw_default_deny else "Warning",
        "GDPR Art-25: Default-deny INPUT firewall policy",
        severity="High",
        details=f"INPUT default policy: {'DROP/REJECT' if fw_default_deny else 'ACCEPT (permissive)'}",
        remediation=(
            "Set default-deny: iptables -P INPUT DROP. Add explicit allow "
            "rules for required services (loopback, established/related, ssh)."
        ),
        cross_references={
            "GDPR": "Art-25", "NIST": "SC-7(5)", "ISO27001": "A.8.20",
            "CIS": "3.4.2.1", "ENISA": "BSR-NET-1",
        },
    ))

    # Default umask (027 or stricter ensures private-by-default for new files)
    login_defs = read_file_safe("/etc/login.defs")
    settings = parse_kv_file(login_defs)
    umask_str = settings.get("umask", "")
    umask_ok = umask_str in ("027", "077", "0027", "0077")

    results.append(_r(
        cat,
        "Pass" if umask_ok else "Warning",
        "GDPR Art-25: Restrictive default umask (027 or 077)",
        severity="Medium",
        details=f"UMASK in login.defs: {umask_str or 'unset'}",
        remediation="sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs",
        cross_references={
            "GDPR": "Art-25", "NIST": "AC-3", "ISO27001": "A.8.3",
            "CIS": "5.4.5", "STIG": "V-230337",
        },
    ))

    return results


# ===========================================================================
# ePrivacy Directive 2002/58/EC
# ===========================================================================

def _check_eprivacy_communications(os_info) -> List[AuditResult]:
    cat = "ePrivacy Art-5 - Communications Confidentiality"
    results: List[AuditResult] = []

    # Insecure remote-access services prohibited
    insecure_services = (
        ("telnet.socket", "telnet"),
        ("rsh.socket", "rsh"),
        ("rlogin.socket", "rlogin"),
        ("rexec.socket", "rexec"),
    )
    active_insecure = []
    for unit, name in insecure_services:
        if systemd_active(unit) == "active":
            active_insecure.append(name)

    results.append(_r(
        cat,
        "Pass" if not active_insecure else "Fail",
        "ePrivacy Art-5: No cleartext remote-access services active",
        severity="Critical",
        details=f"Active insecure services: {', '.join(active_insecure) or 'none'}",
        remediation=(
            f"Disable: " +
            (' && '.join(f"systemctl disable --now {svc}.socket" for svc in active_insecure) if active_insecure else "(none)")
        ),
        cross_references={
            "GDPR": "Art-32(1)(a)", "NIST": "SC-8", "ISO27001": "A.8.21",
            "CIS": "2.2.16", "PCI-DSS": "4.2.1",
        },
    ))

    return results


# ===========================================================================
# Article 33 - Breach Notification (Technical Indicators)
# ===========================================================================

def _check_art33_breach_detection(os_info) -> List[AuditResult]:
    cat = "GDPR Art-33 - Breach Detection"
    results: List[AuditResult] = []

    # Intrusion detection capability
    ids_indicators = {
        "Suricata": command_available("suricata") or file_exists("/etc/suricata/suricata.yaml"),
        "Snort": command_available("snort"),
        "Wazuh/OSSEC": file_exists("/var/ossec/etc/ossec.conf"),
        "Falco": command_available("falco"),
        "auditd": systemd_active("auditd.service") == "active",
    }
    detected = [n for n, p in ids_indicators.items() if p]

    results.append(_r(
        cat,
        "Pass" if detected else "Fail",
        "GDPR Art-33: Breach detection capability",
        severity="High",
        details=(
            f"Detected: {', '.join(detected) or 'none'}. "
            "Article 33 requires breach notification to supervisory authority "
            "within 72 hours - this is impossible without detection capability."
        ),
        remediation=(
            "Deploy host or network IDS (Falco, Wazuh, Suricata). "
            "Ensure auditd is active with comprehensive rules covering "
            "identity changes, privileged commands, and unusual file access."
        ),
        cross_references={
            "GDPR": "Art-33", "NIST": "SI-4", "ISO27001": "A.8.16",
            "PCI-DSS": "11.5.1", "ENISA": "BSR-DETECT-1",
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
        results.extend(_check_art32_encryption_at_rest(os_info))
        results.extend(_check_art32_encryption_in_transit(os_info))
        results.extend(_check_art32_pseudonymisation(os_info))
        results.extend(_check_art32_confidentiality(os_info))
        results.extend(_check_art32_integrity(os_info))
        results.extend(_check_art32_availability(os_info))
        results.extend(_check_art32_resilience(os_info))
        results.extend(_check_art32_restoration(os_info))
        results.extend(_check_art32_testing(os_info))
        results.extend(_check_art25_by_design(os_info))
        results.extend(_check_eprivacy_communications(os_info))
        results.extend(_check_art33_breach_detection(os_info))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled exception in GDPR module")
        results.append(_r(
            "GDPR - Error", "Error",
            f"GDPR module encountered an unhandled exception: {exc!r}",
            severity="Medium", details=str(exc),
        ))

    return results



# ===========================================================================
# v3.1 EXPANSION - GDPR Comprehensive Coverage
# ---------------------------------------------------------------------------
# Adds:
#   - Article 5 Data Minimization & Storage Limitation
#   - Article 24 Controller Responsibility (technical indicators)
#   - Article 25 Data Protection by Design (extended)
#   - Article 30 Records of Processing (log retention discipline)
#   - Article 32 deeper technical coverage
#   - Article 33 Breach Notification (detection capability depth)
#   - Article 35 DPIA risk indicators
#   - Article 44 International Transfers (TLS-only)
#   - ePrivacy Article 4 Confidentiality of Communications
# ===========================================================================


def _check_art5_data_minimization(os_info) -> List[AuditResult]:
    """Article 5(1)(c) - Data minimization through log handling discipline."""
    results: List[AuditResult] = []
    cat = "GDPR - Art-5 Data Minimization"

    # Log rotation discipline: prevents indefinite accumulation of personal data
    logrotate_conf = read_file_safe("/etc/logrotate.conf")
    logrotate_d = list_directory("/etc/logrotate.d")
    has_logrotate = bool(logrotate_conf and len(logrotate_d) > 5)
    results.append(_r(
        cat, "Pass" if has_logrotate else "Warning",
        "Art-5(1)(e): Log rotation policy controls personal data retention",
        severity="Medium",
        details=(
            f"/etc/logrotate.conf size: {len(logrotate_conf)} bytes, "
            f"/etc/logrotate.d entries: {len(logrotate_d)}"
        ),
        remediation=(
            "Install logrotate: apt-get install -y logrotate. "
            "Configure rotation, compression, and removal aligned with GDPR "
            "retention policy (typically 30-90 days for routine logs)."
        ),
        cross_references={
            "GDPR": "Art-5(1)(e)", "NIST": "AU-11", "ISO27001": "A.8.10",
            "PCI-DSS": "10.5.1",
        },
    ))

    # Auditd log retention configured
    auditd_conf = read_file_safe("/etc/audit/auditd.conf")
    num_logs_match = re.search(r"^\s*num_logs\s*=\s*(\d+)", auditd_conf, re.MULTILINE)
    max_size_match = re.search(r"^\s*max_log_file\s*=\s*(\d+)", auditd_conf, re.MULTILINE)
    retention_configured = bool(num_logs_match and max_size_match)
    results.append(_r(
        cat, "Pass" if retention_configured else "Warning",
        "Art-5(1)(e): Auditd retention bounded by configuration",
        severity="Medium",
        details=(
            f"num_logs: {num_logs_match.group(1) if num_logs_match else 'unset'}, "
            f"max_log_file: {max_size_match.group(1) if max_size_match else 'unset'} MB"
        ),
        remediation=(
            "Set num_logs=10 and max_log_file=50 in /etc/audit/auditd.conf "
            "to bound audit log retention. Forward to SIEM for archival."
        ),
        cross_references={
            "GDPR": "Art-5(1)(e)", "NIST": "AU-11", "ISO27001": "A.8.15",
        },
    ))

    return results


def _check_art24_controller_responsibility(os_info) -> List[AuditResult]:
    """Article 24 - Controller's responsibility (technical indicators)."""
    results: List[AuditResult] = []
    cat = "GDPR - Art-24 Controller Responsibility"

    # Configuration management agent presence indicates documented configs
    cm_present = (
        command_available("ansible") or
        command_available("puppet") or
        file_exists("/etc/salt/minion") or
        command_available("chef-client")
    )
    results.append(_r(
        cat, "Info",
        "Art-24: Configuration management capability present",
        severity="Informational",
        details=(
            f"CM agent detected: {cm_present}. "
            "CM enables documented, repeatable, audited configurations."
        ),
        remediation=(
            "Deploy Ansible/Puppet/Salt/Chef for configuration management. "
            "Required for demonstrating Art-24 'appropriate technical measures'."
        ),
        cross_references={
            "GDPR": "Art-24", "NIST": "CM-2", "ISO27001": "A.5.36",
        },
    ))

    # System integrity monitoring (FIM) for change detection
    fim_present = (
        command_available("aide") or
        command_available("tripwire") or
        file_exists("/var/ossec/etc/ossec.conf") or
        command_available("samhain")
    )
    results.append(_r(
        cat, "Pass" if fim_present else "Fail",
        "Art-24: File integrity monitoring tracks configuration changes",
        severity="High",
        details=f"FIM tool detected: {fim_present}",
        remediation=remediation_for("aide"),
        cross_references={
            "GDPR": "Art-24", "NIST": "SI-7", "ISO27001": "A.8.16",
            "PCI-DSS": "11.5.2",
        },
    ))

    return results


def _check_art25_data_protection_by_design(os_info) -> List[AuditResult]:
    """Article 25 - Data Protection by Design and by Default (extended)."""
    results: List[AuditResult] = []
    cat = "GDPR - Art-25 By Design & Default"

    # Default umask should restrict permissions on new files
    profile_files = ["/etc/profile", "/etc/bashrc", "/etc/bash.bashrc",
                     "/etc/login.defs"]
    umask_values = []
    for f in profile_files:
        c = read_file_safe(f)
        for line in c.splitlines():
            s = line.strip()
            if s.startswith("#") or not s:
                continue
            m = re.match(r"^\s*(?:umask|UMASK)\s+(\d+)", s)
            if m:
                umask_values.append((f, m.group(1)))

    # 027 or 077 acceptable; 022 too permissive for personal data
    strict_umask = any(int(v, 8) >= 0o027 for _, v in umask_values)

    results.append(_r(
        cat, "Pass" if strict_umask else "Warning",
        "Art-25(2): Default umask restricts new-file permissions (>= 027)",
        severity="Medium",
        details=(
            f"Configured umask values: {umask_values}. "
            "umask 027 prevents world-read on new files."
        ),
        remediation=(
            "Set UMASK 027 in /etc/login.defs and umask 027 in /etc/profile.d/umask.sh. "
            "PCI/HIPAA/GDPR all benefit from strict default file permissions."
        ),
        cross_references={
            "GDPR": "Art-25(2)", "NIST": "AC-3", "CIS": "5.4.5",
            "STIG": "V-230380",
        },
    ))

    # Default deny iptables policy
    iptables_default_drop = False
    if command_available("iptables"):
        rc, out, _ = run_command(["iptables", "-S", "INPUT"])
        if rc == 0:
            for line in out.splitlines():
                if line.startswith("-P INPUT"):
                    iptables_default_drop = "DROP" in line.upper()
                    break

    results.append(_r(
        cat, "Pass" if iptables_default_drop else "Info",
        "Art-25(2): Network default-deny policy on INPUT chain",
        severity="Medium",
        details=f"INPUT default DROP: {iptables_default_drop}",
        remediation=(
            "iptables -P INPUT DROP (after configuring explicit accept rules). "
            "Or use firewalld/ufw which default-deny by default."
        ),
        cross_references={
            "GDPR": "Art-25(2)", "NIST": "SC-7(11)", "PCI-DSS": "1.2.1",
        },
    ))

    return results


def _check_art30_records_of_processing(os_info) -> List[AuditResult]:
    """Article 30 - Records of processing (log centralization)."""
    results: List[AuditResult] = []
    cat = "GDPR - Art-30 Records of Processing"

    # auditd active for processing operation logs
    auditd_state = systemd_active("auditd.service") == "active"
    results.append(_r(
        cat, "Pass" if auditd_state else "Fail",
        "Art-30: System auditing active for processing record evidence",
        severity="High",
        details=f"auditd state: {systemd_active('auditd.service')}",
        remediation=(
            remediation_for("auditd")
            + " Configure rules to capture data access events."
        ),
        cross_references={
            "GDPR": "Art-30", "NIST": "AU-2", "ISO27001": "A.8.15",
            "HIPAA": "164.312(b)",
        },
    ))

    # Centralized logging for cross-system processing records
    rsyslog_d = list_directory("/etc/rsyslog.d", suffix=".conf")
    forwarding_present = False
    for f in rsyslog_d + ["/etc/rsyslog.conf"]:
        if f == "/etc/rsyslog.conf":
            c = read_file_safe(f)
        else:
            c = read_file_safe(os.path.join("/etc/rsyslog.d", f))
        if c and ("@@" in c or "omfwd" in c or "omrelp" in c):
            forwarding_present = True
            break

    results.append(_r(
        cat, "Pass" if forwarding_present else "Warning",
        "Art-30: Logs forwarded to central system for processing records",
        severity="High",
        details=f"Remote log forwarding configured: {forwarding_present}",
        remediation=(
            "Configure log forwarding in /etc/rsyslog.d/50-remote.conf: "
            "*.* @@logserver.internal:6514"
        ),
        cross_references={
            "GDPR": "Art-30", "NIST": "AU-6(3)", "PCI-DSS": "10.5.4",
        },
    ))

    return results


def _check_art32_extended(os_info) -> List[AuditResult]:
    """Article 32 - Extended technical measure depth."""
    results: List[AuditResult] = []
    cat = "GDPR - Art-32 Extended"

    # Strong cipher support (verify SSH key algorithms)
    sshd_config = read_file_safe("/etc/ssh/sshd_config")
    if sshd_config:
        # Look for KexAlgorithms
        kex_lines = [l.strip() for l in sshd_config.splitlines()
                     if l.strip().lower().startswith("kexalgorithms ")]
        weak_kex = []
        if kex_lines:
            kex_value = kex_lines[-1].lower()
            for w in ("diffie-hellman-group1", "diffie-hellman-group14-sha1"):
                if w in kex_value:
                    weak_kex.append(w)

        results.append(_r(
            cat, "Pass" if not weak_kex else "Fail",
            "Art-32(1)(a): SSH key exchange algorithms exclude weak DH",
            severity="High",
            details=(
                f"Configured KexAlgorithms (last): "
                f"{kex_lines[-1] if kex_lines else 'default'}. "
                f"Weak detected: {', '.join(weak_kex) or 'none'}"
            ),
            remediation=(
                "In /etc/ssh/sshd_config: KexAlgorithms "
                "curve25519-sha256@libssh.org,ecdh-sha2-nistp521,"
                "diffie-hellman-group-exchange-sha256"
            ),
            cross_references={
                "GDPR": "Art-32(1)(a)", "NIST": "SC-13", "STIG": "V-230252",
                "NSA": "SSH-2.3", "PCI-DSS": "4.2.1",
            },
        ))

        # HostKeyAlgorithms (no weak)
        hostkey_lines = [l.strip() for l in sshd_config.splitlines()
                         if l.strip().lower().startswith("hostkeyalgorithms ")]
        weak_hostkey = []
        if hostkey_lines:
            hk_value = hostkey_lines[-1].lower()
            for w in ("ssh-dss", "ssh-rsa "):  # space to exclude rsa-sha2-*
                if w in hk_value or hk_value.endswith("ssh-rsa"):
                    weak_hostkey.append(w.strip())

        results.append(_r(
            cat, "Pass" if not weak_hostkey and hostkey_lines else "Info",
            "Art-32(1)(a): SSH host key algorithms exclude DSS/legacy RSA-SHA1",
            severity="Medium",
            details=(
                f"HostKeyAlgorithms configured: {bool(hostkey_lines)}, "
                f"Weak: {weak_hostkey}"
            ),
            remediation=(
                "In sshd_config: HostKeyAlgorithms "
                "ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp521"
            ),
            cross_references={
                "GDPR": "Art-32(1)(a)", "NIST": "SC-13",
            },
        ))

    # OpenSSL system FIPS or strong default
    if file_exists("/etc/crypto-policies/config"):
        policy = read_file_safe("/etc/crypto-policies/config").strip()
        results.append(_r(
            cat, "Pass" if policy in ("FUTURE", "FIPS") else (
                "Pass" if policy == "DEFAULT" else "Warning"),
            f"Art-32(1)(a): System crypto policy: {policy or 'unset'}",
            severity="Medium",
            details=f"Active policy: {policy}. FUTURE/FIPS exceed Art-32(1)(a)",
            remediation=(
                "update-crypto-policies --set FUTURE  # for stricter posture"
            ),
            cross_references={
                "GDPR": "Art-32(1)(a)", "NIST": "SC-13", "NSA": "CRYPTO-1.1",
                "ISO27001": "A.8.24",
            },
        ))

    # Disk space monitoring (Art-32(1)(b) ongoing availability)
    rc, out, _ = run_command(["df", "/var", "/var/log"], timeout=3.0)
    if rc == 0:
        critical_fs = []
        for line in out.splitlines()[1:]:  # skip header
            fields = line.split()
            if len(fields) >= 5:
                use_pct = fields[4].rstrip("%")
                try:
                    if int(use_pct) > 85:
                        critical_fs.append(f"{fields[5]}: {use_pct}%")
                except ValueError:
                    continue
        results.append(_r(
            cat, "Pass" if not critical_fs else "Warning",
            "Art-32(1)(b): Critical filesystems have available capacity",
            severity="Medium",
            details=f"Filesystems > 85% full: {critical_fs or 'none'}",
            remediation=(
                "Monitor disk space: df -h. Set up Prometheus/Nagios/Zabbix "
                "alerts at 80% threshold."
            ),
            cross_references={
                "GDPR": "Art-32(1)(b)", "NIST": "AU-5", "ISO27001": "A.8.6",
            },
        ))

    return results


def _check_art33_breach_detection(os_info) -> List[AuditResult]:
    """Article 33 - Breach notification (detection capability)."""
    results: List[AuditResult] = []
    cat = "GDPR - Art-33 Breach Detection"

    # Detection mechanisms (HIDS, IDS, log monitoring)
    detection_tools = {
        "auditd": systemd_active("auditd.service") == "active",
        "fail2ban": systemd_active("fail2ban.service") == "active",
        "wazuh-agent": systemd_active("wazuh-agent.service") == "active",
        "ossec": file_exists("/var/ossec/etc/ossec.conf"),
        "falco": command_available("falco"),
        "suricata": command_available("suricata"),
        "snort": command_available("snort"),
        "aide": command_available("aide"),
    }
    detected = [k for k, v in detection_tools.items() if v]
    has_detection = len(detected) >= 2

    results.append(_r(
        cat, "Pass" if has_detection else ("Warning" if detected else "Fail"),
        f"Art-33: Multiple detection layers present ({len(detected)} of {len(detection_tools)})",
        severity="Critical",
        details=(
            f"Tools detected: {detected}. "
            "Art-33 requires breach detection within reasonable timeframe (72h)."
        ),
        remediation=(
            "Deploy a defense-in-depth detection stack: "
            "auditd + fail2ban + Wazuh + AIDE for comprehensive coverage."
        ),
        cross_references={
            "GDPR": "Art-33", "NIST": "IR-4", "ISO27001": "A.5.24",
            "HIPAA": "164.308(a)(1)(ii)(D)", "PCI-DSS": "12.10",
        },
    ))

    # Time sync (essential for event correlation across breach investigation)
    time_sync_active = (
        systemd_active("chronyd.service") == "active" or
        systemd_active("chrony.service") == "active" or
        systemd_active("ntp.service") == "active" or
        systemd_active("systemd-timesyncd.service") == "active"
    )
    results.append(_r(
        cat, "Pass" if time_sync_active else "Fail",
        "Art-33: Time synchronization for accurate breach timeline",
        severity="High",
        details=f"Time sync active: {time_sync_active}",
        remediation=remediation_for("chrony"),
        cross_references={
            "GDPR": "Art-33", "NIST": "AU-8(1)", "PCI-DSS": "10.6",
            "ISO27001": "A.8.17",
        },
    ))

    return results


def _check_art35_dpia_indicators(os_info) -> List[AuditResult]:
    """Article 35 - DPIA technical risk indicators."""
    results: List[AuditResult] = []
    cat = "GDPR - Art-35 DPIA Indicators"

    # Vulnerability scanner presence (essential for DPIA risk assessment)
    scanners = {
        "openscap": command_available("oscap"),
        "lynis": command_available("lynis"),
        "trivy": command_available("trivy"),
        "grype": command_available("grype"),
    }
    detected = [k for k, v in scanners.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Warning",
        f"Art-35: Vulnerability scanner available for risk assessment ({len(detected)})",
        severity="Medium",
        details=f"Scanners detected: {detected or 'none'}",
        remediation=(
            "Install OpenSCAP for compliance scanning: "
            "dnf install -y openscap-scanner scap-security-guide. "
            "Lynis for hardening assessment: apt-get install -y lynis."
        ),
        cross_references={
            "GDPR": "Art-35", "NIST": "RA-5", "ISO27001": "A.5.34",
        },
    ))

    # Asset inventory tooling
    inventory_capable = (
        command_available("dpkg") or
        command_available("rpm") or
        command_available("pacman") or
        command_available("apk")
    )
    results.append(_r(
        cat, "Pass" if inventory_capable else "Fail",
        "Art-35: Software asset enumeration available",
        severity="Low",
        details=f"Package inventory commands available: {inventory_capable}",
        remediation=(
            "Periodically export inventory to CMDB. "
            "dpkg --list > inventory.txt or rpm -qa > inventory.txt"
        ),
        cross_references={
            "GDPR": "Art-35", "NIST": "CM-8",
        },
    ))

    return results


def _check_art44_international_transfers(os_info) -> List[AuditResult]:
    """Article 44 - International transfers (TLS-only enforcement)."""
    results: List[AuditResult] = []
    cat = "GDPR - Art-44 International Transfers"

    # Postfix outbound TLS for cross-border email
    postfix_main = read_file_safe("/etc/postfix/main.cf")
    if postfix_main:
        smtp_tls_match = re.search(
            r"^\s*smtp_tls_security_level\s*=\s*(\w+)", postfix_main, re.MULTILINE
        )
        smtp_tls = smtp_tls_match.group(1).lower() if smtp_tls_match else "none"
        smtp_tls_strong = smtp_tls in ("encrypt", "verify", "secure")

        results.append(_r(
            cat, "Pass" if smtp_tls_strong else "Fail",
            "Art-44: SMTP outbound enforces TLS (encrypted international email)",
            severity="High",
            details=f"smtp_tls_security_level = {smtp_tls}",
            remediation=(
                "In /etc/postfix/main.cf: smtp_tls_security_level = encrypt "
                "(minimum for international transfers). Add DANE for verification."
            ),
            cross_references={
                "GDPR": "Art-44", "NIST": "SC-8(1)", "PCI-DSS": "4.2",
            },
        ))

    # Outbound DNS over TLS / HTTPS (modern privacy-preserving DNS)
    systemd_resolved_conf = read_file_safe("/etc/systemd/resolved.conf")
    dns_tls = "DNSOverTLS=yes" in systemd_resolved_conf or "DNSOverTLS=opportunistic" in systemd_resolved_conf
    results.append(_r(
        cat, "Info",
        f"Art-44: Encrypted DNS (DoT) configured: {dns_tls}",
        severity="Low",
        details=(
            f"DNSOverTLS in resolved.conf: {dns_tls}. "
            "Encrypted DNS prevents passive surveillance of cross-border lookups."
        ),
        remediation=(
            "In /etc/systemd/resolved.conf: DNSOverTLS=yes; "
            "DNS=1.1.1.1 9.9.9.9 (privacy-respecting)"
        ),
        cross_references={
            "GDPR": "Art-44", "NIST": "SC-8", "ENISA": "BSR-8.1",
        },
    ))

    return results


def _check_eprivacy_art4_confidentiality(os_info) -> List[AuditResult]:
    """ePrivacy Article 4 - Confidentiality of communications."""
    results: List[AuditResult] = []
    cat = "GDPR - ePrivacy Art-4"

    # Mail server TLS (Postfix smtpd)
    postfix_main = read_file_safe("/etc/postfix/main.cf")
    if postfix_main:
        smtpd_tls_match = re.search(
            r"^\s*smtpd_tls_security_level\s*=\s*(\w+)", postfix_main, re.MULTILINE
        )
        smtpd_tls = smtpd_tls_match.group(1).lower() if smtpd_tls_match else "none"
        smtpd_ok = smtpd_tls in ("encrypt", "may")

        results.append(_r(
            cat, "Pass" if smtpd_ok else "Warning",
            "ePrivacy Art-4: Postfix inbound SMTP advertises TLS",
            severity="High",
            details=f"smtpd_tls_security_level = {smtpd_tls}",
            remediation=(
                "In /etc/postfix/main.cf: smtpd_tls_security_level = may "
                "(opportunistic) or encrypt (forced - for internal MTAs)"
            ),
            cross_references={
                "GDPR": "ePrivacy-Art-4", "NIST": "SC-8(1)", "PCI-DSS": "4.2.1",
            },
        ))

    # Dovecot IMAP/POP3 TLS (if Dovecot installed)
    dovecot_conf = read_file_safe("/etc/dovecot/conf.d/10-ssl.conf")
    if dovecot_conf:
        ssl_required = "ssl = required" in dovecot_conf or "ssl=required" in dovecot_conf
        results.append(_r(
            cat, "Pass" if ssl_required else "Fail",
            "ePrivacy Art-4: Dovecot enforces SSL/TLS for IMAP/POP3",
            severity="High",
            details=f"Dovecot ssl=required configured: {ssl_required}",
            remediation=(
                "In /etc/dovecot/conf.d/10-ssl.conf: ssl = required"
            ),
            cross_references={
                "GDPR": "ePrivacy-Art-4", "NIST": "SC-8(1)",
            },
        ))

    # XMPP/Jabber: ejabberd or Prosody TLS
    if file_exists("/etc/ejabberd/ejabberd.yml") or file_exists("/etc/prosody/prosody.cfg.lua"):
        results.append(_r(
            cat, "Info",
            "ePrivacy Art-4: XMPP server detected - manual TLS verification needed",
            severity="Medium",
            details="ejabberd or Prosody configuration detected",
            remediation=(
                "Verify c2s_require_encryption: true and "
                "s2s_require_encryption: true in server config"
            ),
            cross_references={
                "GDPR": "ePrivacy-Art-4", "NIST": "SC-8(1)",
            },
        ))

    return results


def _check_pseudonymization_capabilities(os_info) -> List[AuditResult]:
    """Article 32(1)(a) - Pseudonymization (extended)."""
    results: List[AuditResult] = []
    cat = "GDPR - Pseudonymization"

    # Tools that support pseudonymization
    crypto_tools = {
        "gpg": command_available("gpg") or command_available("gpg2"),
        "openssl": command_available("openssl"),
        "age": command_available("age"),
        "minisign": command_available("minisign"),
        "veracrypt": command_available("veracrypt"),
        "tomb": command_available("tomb"),
    }
    detected = [k for k, v in crypto_tools.items() if v]
    results.append(_r(
        cat, "Pass" if "openssl" in detected else "Warning",
        f"Art-32(1)(a): Cryptographic tools for pseudonymization ({len(detected)} found)",
        severity="Medium",
        details=f"Detected: {detected}",
        remediation=(
            "Install OpenSSL (typically present): apt-get install -y openssl. "
            "Application-level pseudonymization typically uses HMAC with kept secret."
        ),
        cross_references={
            "GDPR": "Art-32(1)(a)", "NIST": "SC-13", "ISO27001": "A.8.11",
        },
    ))

    # Log redaction tools (rsyslog supports anonymization)
    rsyslog_d_files = list_directory("/etc/rsyslog.d", suffix=".conf")
    has_anonymization = False
    for f in rsyslog_d_files + ["/etc/rsyslog.conf"]:
        if f == "/etc/rsyslog.conf":
            c = read_file_safe(f)
        else:
            c = read_file_safe(os.path.join("/etc/rsyslog.d", f))
        if c and ("mmanon" in c or "anonymize" in c.lower()):
            has_anonymization = True
            break

    results.append(_r(
        cat, "Info",
        f"Art-32(1)(a): rsyslog log anonymization configured: {has_anonymization}",
        severity="Informational",
        details=(
            f"mmanon module detected in rsyslog: {has_anonymization}. "
            "Useful for redacting personal data from forwarded logs."
        ),
        remediation=(
            "Configure rsyslog mmanon: load module 'imuxsock'; load 'mmanon'; "
            "set $!fromip = $msg in templates"
        ),
        cross_references={
            "GDPR": "Art-32(1)(a)", "NIST": "SI-19", "ISO27001": "A.8.11",
        },
    ))

    return results


# Save reference to original run_checks before redefining
_original_run_checks_gdpr = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the expanded GDPR module.

    Combines baseline (Article 32 core) with v3.1 expansion covering
    Articles 5, 24, 25 (extended), 30, 32 (extended), 33, 35, 44 plus
    ePrivacy Article 4 and pseudonymization capability assessment.
    """
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_gdpr(shared_data)

    os_info = shared_data.get("v3_os_info")
    if os_info is None:
        os_info = os_detection.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        results.extend(_check_art5_data_minimization(os_info))
        results.extend(_check_art24_controller_responsibility(os_info))
        results.extend(_check_art25_data_protection_by_design(os_info))
        results.extend(_check_art30_records_of_processing(os_info))
        results.extend(_check_art32_extended(os_info))
        results.extend(_check_art33_breach_detection(os_info))
        results.extend(_check_art35_dpia_indicators(os_info))
        results.extend(_check_art44_international_transfers(os_info))
        results.extend(_check_eprivacy_art4_confidentiality(os_info))
        results.extend(_check_pseudonymization_capabilities(os_info))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled exception in GDPR v3.1 expansion")
        results.append(_r(
            "GDPR - Error", "Error",
            f"GDPR v3.1 expansion exception: {exc!r}",
            severity="Medium", details=str(exc),
        ))

    return results



# ===========================================================================
# v3.3 EXPANSION - GDPR Article-Level Deep Coverage
# ---------------------------------------------------------------------------
# Adds:
#   - Article 32 deeper technical and organizational measures
#   - Article 17 - Right to erasure (technical indicators)
#   - Article 30 - Records of processing depth
#   - Article 5 - Data minimization technical indicators
#   - Article 25 - Privacy by design depth
#   - Cross-border transfer (Article 44-49) depth
#   - Article 33 - Breach detection technical indicators
# ===========================================================================


def _check_gdpr_art17_erasure_v33(os_info) -> List[AuditResult]:
    """Article 17 - Right to erasure (right to be forgotten) indicators."""
    results: List[AuditResult] = []
    cat = "GDPR Art.17 v3.3"

    # 17.1 - Erasure capability: secure deletion tools
    erasure_tools = {
        "shred": command_available("shred"),
        "wipe": command_available("wipe"),
        "secure-delete": command_available("srm"),
        "blkdiscard": command_available("blkdiscard"),
        "scrub": command_available("scrub"),
    }
    detected = [k for k, v in erasure_tools.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Fail",
        f"GDPR-17.1: Secure deletion tools available ({len(detected)})",
        severity="High",
        details=f"Detected: {detected}",
        remediation=(
            "Install secure deletion: apt-get install -y secure-delete coreutils. "
            "Document erasure procedures in privacy policy."
        ),
        cross_references={
            "GDPR": "Art.17", "NIST": "MP-6",
        },
    ))

    # 17.2 - Public/transmitted data erasure: backup retention controls
    backup_retention_indicators = []
    for path in ["/etc/borgmatic/config.yaml", "/etc/restic.conf",
                  "/etc/duplicity"]:
        if file_exists(path) or directory_exists(path):
            backup_retention_indicators.append(path)
    results.append(_r(
        cat, "Info",
        f"GDPR-17.2: Backup retention configurations detected ({len(backup_retention_indicators)})",
        severity="Informational",
        details=f"Backup retention configs: {backup_retention_indicators}",
        remediation=(
            "Document backup retention to satisfy erasure obligations. "
            "Implement backup-purge workflow within 30 days of erasure request."
        ),
        cross_references={
            "GDPR": "Art.17(2)", "NIST": "MP-6, CP-9",
        },
    ))

    return results


def _check_gdpr_art30_ropa_v33(os_info) -> List[AuditResult]:
    """Article 30 - Records of processing activities (ROPA) depth."""
    results: List[AuditResult] = []
    cat = "GDPR Art.30 v3.3"

    # 30.1 - Auditd records all data access
    auditd_active = systemd_active("auditd.service") == "active"
    audit_rules = read_file_safe("/etc/audit/audit.rules")
    if directory_exists("/etc/audit/rules.d"):
        for f in list_directory("/etc/audit/rules.d"):
            if f.endswith(".rules"):
                audit_rules += "\n" + read_file_safe(
                    os.path.join("/etc/audit/rules.d", f)
                )

    data_access_audit = (
        "open" in audit_rules or "openat" in audit_rules or
        any(w in audit_rules for w in ["-w /var/lib", "-w /home", "-w /opt"])
    )
    results.append(_r(
        cat, "Pass" if (auditd_active and data_access_audit) else "Warning",
        f"GDPR-30.1: Data access auditing capability",
        severity="High",
        details=(
            f"auditd active: {auditd_active}, "
            f"data access rules: {data_access_audit}"
        ),
        remediation=(
            "Configure auditd to record access to PII/data directories: "
            "-a always,exit -F arch=b64 -S openat -F dir=/var/lib/<service> "
            "-F success=1 -k personal_data_access"
        ),
        cross_references={
            "GDPR": "Art.30(1)", "NIST": "AU-2",
        },
    ))

    # 30.4 - Records made available on request: log retention
    auditd_conf = read_file_safe("/etc/audit/auditd.conf")
    num_logs_match = re.search(
        r"^\s*num_logs\s*=\s*(\d+)", auditd_conf, re.MULTILINE
    )
    max_log_match = re.search(
        r"^\s*max_log_file\s*=\s*(\d+)", auditd_conf, re.MULTILINE
    )
    num_logs = int(num_logs_match.group(1)) if num_logs_match else 0
    max_log = int(max_log_match.group(1)) if max_log_match else 0
    results.append(_r(
        cat, "Pass" if num_logs >= 5 else "Warning",
        f"GDPR-30.4: Audit log retention (num_logs={num_logs}, max_log_file={max_log}MB)",
        severity="Medium",
        details=f"num_logs = {num_logs}, max_log_file = {max_log}MB",
        remediation=(
            "In /etc/audit/auditd.conf: num_logs = 10; max_log_file = 100"
        ),
        cross_references={
            "GDPR": "Art.30(4)", "NIST": "AU-11",
        },
    ))

    return results


def _check_gdpr_art5_minimization_v33(os_info) -> List[AuditResult]:
    """Article 5 - Data minimization technical indicators."""
    results: List[AuditResult] = []
    cat = "GDPR Art.5 v3.3"

    # 5.1.b - Purpose limitation: structured logging policies
    rsy_conf = read_file_safe("/etc/rsyslog.conf")
    rsy_d_configs = []
    if directory_exists("/etc/rsyslog.d"):
        for f in list_directory("/etc/rsyslog.d"):
            if f.endswith(".conf"):
                rsy_d_configs.append(read_file_safe(
                    os.path.join("/etc/rsyslog.d", f)
                ))

    has_filter = (
        ":msg," in rsy_conf or
        any(":msg," in c for c in rsy_d_configs) or
        any("stop" in c for c in rsy_d_configs)
    )
    results.append(_r(
        cat, "Info",
        f"GDPR-5.1.b: rsyslog content filtering: {has_filter}",
        severity="Informational",
        details=f"rsyslog filter rules detected: {has_filter}",
        remediation=(
            "Configure rsyslog filters to drop or redact PII before forwarding."
        ),
        cross_references={
            "GDPR": "Art.5(1)(b)", "NIST": "SI-12",
        },
    ))

    # 5.1.c - Data minimization: log forwarding selectivity
    fwd_count = 0
    if "@@" in rsy_conf or "omfwd" in rsy_conf:
        fwd_count += 1
    for c in rsy_d_configs:
        if "@@" in c or "omfwd" in c:
            fwd_count += 1
    results.append(_r(
        cat, "Info",
        f"GDPR-5.1.c: Log forwarding configurations ({fwd_count})",
        severity="Informational",
        details=f"Forwarding directives: {fwd_count}",
        cross_references={
            "GDPR": "Art.5(1)(c)", "NIST": "AU-9",
        },
    ))

    # 5.1.e - Storage limitation: logrotate
    logrotate_d = (
        list_directory("/etc/logrotate.d")
        if directory_exists("/etc/logrotate.d") else []
    )
    results.append(_r(
        cat, "Pass" if logrotate_d else "Warning",
        f"GDPR-5.1.e: Log rotation configurations ({len(logrotate_d)})",
        severity="Medium",
        details=f"/etc/logrotate.d entries: {len(logrotate_d)}",
        remediation=(
            "Configure logrotate per-service for time-limited retention. "
            "Example: rotate 30 daily compress in /etc/logrotate.d/<svc>"
        ),
        cross_references={
            "GDPR": "Art.5(1)(e)", "NIST": "AU-11, AU-4",
        },
    ))

    return results


def _check_gdpr_art25_by_design_v33(os_info) -> List[AuditResult]:
    """Article 25 - Data protection by design and by default deep."""
    results: List[AuditResult] = []
    cat = "GDPR Art.25 v3.3"

    # 25.1 - State of the art: TLS minimum version
    openssl_cnf = read_file_safe("/etc/ssl/openssl.cnf") or \
                  read_file_safe("/etc/pki/tls/openssl.cnf")
    has_tls12 = "TLSv1.2" in openssl_cnf or "MinProtocol" in openssl_cnf
    results.append(_r(
        cat, "Pass" if has_tls12 else "Warning",
        f"GDPR-25.1: TLS 1.2+ minimum protocol set: {has_tls12}",
        severity="High",
        details=f"OpenSSL MinProtocol/TLSv1.2 indicator: {has_tls12}",
        remediation=(
            "In /etc/ssl/openssl.cnf [system_default_sect]: "
            "MinProtocol = TLSv1.2; CipherString = DEFAULT@SECLEVEL=2"
        ),
        cross_references={
            "GDPR": "Art.25(1)", "NIST": "SC-13",
        },
    ))

    # 25.2 - Data protection by default: file permissions on sensitive dirs
    sensitive_dirs = [
        ("/var/lib/mysql", 0o700),
        ("/var/lib/postgresql", 0o700),
        ("/var/lib/mongodb", 0o700),
        ("/var/lib/redis", 0o700),
        ("/etc/ssl/private", 0o710),
    ]
    issues = []
    for d, max_mode in sensitive_dirs:
        if not directory_exists(d):
            continue
        try:
            st = os.stat(d)
            actual = st.st_mode & 0o7777
            if actual & 0o077:  # any group/other access
                issues.append(f"{d}={oct(actual)}")
        except OSError:
            pass
    results.append(_r(
        cat, "Pass" if not issues else "Warning",
        f"GDPR-25.2: Sensitive data directory permissions ({len(issues)} issues)",
        severity="High",
        details=f"Issues: {issues}",
        remediation=(
            "Restrict access: chmod 700 /var/lib/mysql /var/lib/postgresql"
        ),
        cross_references={
            "GDPR": "Art.25(2)", "NIST": "AC-3",
        },
    ))

    return results


def _check_gdpr_art32_extended_v33(os_info) -> List[AuditResult]:
    """Article 32 - Security of processing extended depth."""
    results: List[AuditResult] = []
    cat = "GDPR Art.32 v3.3"

    # 32.1.a - Pseudonymisation indicators
    crypto_libs = {
        "openssl": command_available("openssl"),
        "libsodium": file_exists("/usr/lib/x86_64-linux-gnu/libsodium.so") or
                     file_exists("/usr/lib64/libsodium.so"),
        "gpg": command_available("gpg"),
        "age": command_available("age"),
    }
    detected = [k for k, v in crypto_libs.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Fail",
        f"GDPR-32.1.a: Pseudonymisation/encryption libraries ({len(detected)})",
        severity="High",
        details=f"Detected: {detected}",
        cross_references={
            "GDPR": "Art.32(1)(a)", "NIST": "SC-13, SC-28(1)",
        },
    ))

    # 32.1.b - Confidentiality: SSH/TLS encrypted services
    sshd_active = systemd_active("sshd.service") == "active" or \
                  systemd_active("ssh.service") == "active"
    results.append(_r(
        cat, "Pass" if sshd_active else "Info",
        f"GDPR-32.1.b: SSH service for encrypted admin access: {sshd_active}",
        severity="Medium",
        details=f"sshd active: {sshd_active}",
        cross_references={
            "GDPR": "Art.32(1)(b)", "NIST": "SC-8",
        },
    ))

    # 32.1.c - Restoring availability: snapshot tools
    snapshot_tools = {
        "snapper": command_available("snapper"),
        "lvm-snapshot": command_available("lvcreate"),
        "btrfs-snapshot": command_available("btrfs"),
        "zfs-snapshot": command_available("zfs"),
    }
    detected = [k for k, v in snapshot_tools.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Info",
        f"GDPR-32.1.c: Snapshot/restore capability ({len(detected)})",
        severity="Medium",
        details=f"Detected: {detected}",
        cross_references={
            "GDPR": "Art.32(1)(c)", "NIST": "CP-9",
        },
    ))

    # 32.1.d - Regular testing: vulnerability scanners
    scanners = ["lynis", "oscap", "trivy", "nuclei", "openvas-scanner"]
    detected_scanners = [s for s in scanners if command_available(s)]
    results.append(_r(
        cat, "Pass" if detected_scanners else "Warning",
        f"GDPR-32.1.d: Security scanners installed ({len(detected_scanners)})",
        severity="High",
        details=f"Detected: {detected_scanners}",
        remediation=(
            "Install lynis: apt-get install -y lynis. Run quarterly."
        ),
        cross_references={
            "GDPR": "Art.32(1)(d)", "NIST": "RA-5",
        },
    ))

    # 32.2 - Risks of processing: log integrity
    auditd_immutable = "-e 2" in read_file_safe("/etc/audit/audit.rules")
    if not auditd_immutable and directory_exists("/etc/audit/rules.d"):
        for f in list_directory("/etc/audit/rules.d"):
            if f.endswith(".rules"):
                if "-e 2" in read_file_safe(
                    os.path.join("/etc/audit/rules.d", f)
                ):
                    auditd_immutable = True
                    break
    results.append(_r(
        cat, "Pass" if auditd_immutable else "Warning",
        f"GDPR-32.2: Audit log immutability (-e 2) configured: {auditd_immutable}",
        severity="High",
        details=f"-e 2 in audit rules: {auditd_immutable}",
        remediation=(
            "Add to /etc/audit/rules.d/99-immutable.rules: -e 2 (last line)"
        ),
        cross_references={
            "GDPR": "Art.32(2)", "NIST": "AU-9",
        },
    ))

    # 32.4 - Adherence to approved code of conduct: SELinux/AppArmor enforcement
    selinux_enforcing = False
    apparmor_enforcing = False
    if file_exists("/sys/fs/selinux/enforce"):
        try:
            with open("/sys/fs/selinux/enforce", "r") as f:
                selinux_enforcing = f.read().strip() == "1"
        except OSError:
            pass
    if command_available("aa-status"):
        rc, out, _ = run_command(["aa-status", "--enabled"], timeout=3.0)
        apparmor_enforcing = rc == 0

    mac_active = selinux_enforcing or apparmor_enforcing
    results.append(_r(
        cat, "Pass" if mac_active else "Warning",
        f"GDPR-32.4: Mandatory access control enforcing: {mac_active}",
        severity="High",
        details=(
            f"SELinux enforcing: {selinux_enforcing}, "
            f"AppArmor enabled: {apparmor_enforcing}"
        ),
        remediation=(
            "Enable SELinux (RHEL): setenforce 1; edit /etc/selinux/config. "
            "Enable AppArmor (Debian/Ubuntu): systemctl enable --now apparmor"
        ),
        cross_references={
            "GDPR": "Art.32(4)", "NIST": "AC-3",
        },
    ))

    return results


def _check_gdpr_art33_breach_v33(os_info) -> List[AuditResult]:
    """Article 33 - Breach notification technical readiness."""
    results: List[AuditResult] = []
    cat = "GDPR Art.33 v3.3"

    # 33.1 - 72-hour notification capability: log forwarding
    rsy_conf = read_file_safe("/etc/rsyslog.conf")
    has_remote_rsy = "@@" in rsy_conf or "omfwd" in rsy_conf
    if not has_remote_rsy and directory_exists("/etc/rsyslog.d"):
        for f in list_directory("/etc/rsyslog.d"):
            if f.endswith(".conf"):
                c = read_file_safe(os.path.join("/etc/rsyslog.d", f))
                if "@@" in c or "omfwd" in c:
                    has_remote_rsy = True
                    break

    journal_fwd = "ForwardToSyslog=yes" in read_file_safe(
        "/etc/systemd/journald.conf"
    ) or "ForwardToSyslog" not in read_file_safe(
        "/etc/systemd/journald.conf"
    )  # Default is yes

    results.append(_r(
        cat, "Pass" if has_remote_rsy else "Fail",
        f"GDPR-33.1: Remote log forwarding for breach detection: {has_remote_rsy}",
        severity="Critical",
        details=(
            f"rsyslog forward: {has_remote_rsy}, "
            f"journald->syslog: {journal_fwd}"
        ),
        remediation=(
            "Configure /etc/rsyslog.d/50-remote.conf: "
            "*.* @@siem.example.com:6514"
        ),
        cross_references={
            "GDPR": "Art.33(1)", "NIST": "IR-6, AU-6(3)",
        },
    ))

    # 33.5 - Documentation: audit trail integrity
    audit_log_dir = directory_exists("/var/log/audit")
    audit_log_present = file_exists("/var/log/audit/audit.log")
    results.append(_r(
        cat, "Pass" if (audit_log_dir and audit_log_present) else "Fail",
        f"GDPR-33.5: Audit trail directory and file present",
        severity="High",
        details=(
            f"/var/log/audit dir: {audit_log_dir}, "
            f"audit.log file: {audit_log_present}"
        ),
        remediation=(
            "systemctl enable --now auditd"
        ),
        cross_references={
            "GDPR": "Art.33(5)", "NIST": "AU-2",
        },
    ))

    return results


def _check_gdpr_art44_transfers_v33(os_info) -> List[AuditResult]:
    """Article 44-49 - International transfers technical safeguards."""
    results: List[AuditResult] = []
    cat = "GDPR Art.44 v3.3"

    # 46.2.c - Standard contractual clauses: VPN/IPSec capability
    vpn_indicators = {
        "wireguard": (
            command_available("wg") or
            file_exists("/etc/wireguard")
        ),
        "openvpn": (
            command_available("openvpn") or
            directory_exists("/etc/openvpn")
        ),
        "strongswan/ipsec": (
            command_available("ipsec") or
            file_exists("/etc/ipsec.conf") or
            directory_exists("/etc/strongswan.d")
        ),
        "tinc": command_available("tinc"),
    }
    detected = [k for k, v in vpn_indicators.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Info",
        f"GDPR-46.2.c: VPN technologies for cross-border transfers ({len(detected)})",
        severity="Medium",
        details=f"Detected: {detected}",
        remediation=(
            "Use WireGuard for modern VPN: apt-get install -y wireguard"
        ),
        cross_references={
            "GDPR": "Art.46(2)(c)", "NIST": "SC-8(1)",
        },
    ))

    # 46.3 - Encryption at rest for transferred data
    luks_present = False
    rc, out, _ = run_command(["lsblk", "-o", "TYPE", "-n"], timeout=3.0)
    if rc == 0 and out:
        if "crypt" in out.lower():
            luks_present = True
    results.append(_r(
        cat, "Pass" if luks_present else "Warning",
        f"GDPR-46.3: Disk encryption (LUKS) detected: {luks_present}",
        severity="High",
        details=f"LUKS encrypted volumes present: {luks_present}",
        remediation=(
            "Encrypt sensitive volumes: cryptsetup luksFormat <device>"
        ),
        cross_references={
            "GDPR": "Art.46(3)", "NIST": "SC-28",
        },
    ))

    return results


# Save reference to existing run_checks
_original_run_checks_gdpr_v33 = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the v3.3 expanded GDPR module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_gdpr_v33(shared_data)

    os_info = shared_data.get("v3_os_info")
    if os_info is None:
        os_info = os_detection.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        results.extend(_check_gdpr_art17_erasure_v33(os_info))
        results.extend(_check_gdpr_art30_ropa_v33(os_info))
        results.extend(_check_gdpr_art5_minimization_v33(os_info))
        results.extend(_check_gdpr_art25_by_design_v33(os_info))
        results.extend(_check_gdpr_art32_extended_v33(os_info))
        results.extend(_check_gdpr_art33_breach_v33(os_info))
        results.extend(_check_gdpr_art44_transfers_v33(os_info))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled exception in GDPR v3.3 expansion")
        results.append(_r(
            "GDPR - Error", "Error",
            f"GDPR v3.3 expansion exception: {exc!r}",
            severity="Medium", details=str(exc),
        ))

    return results


# ============================================================================
# v3.5 EXPANSION - GDPR Article Technical Depth
# ----------------------------------------------------------------------------
# Synopsis:
#   Adds depth across GDPR articles' technical surrogates:
#     - Art 5(1)(e) Storage limitation - retention auto-purge mechanisms
#     - Art 5(1)(f) Integrity confidentiality (multi-layer)
#     - Art 17 Right to erasure depth (secure delete, swap clearing)
#     - Art 20 Right to data portability (export tooling)
#     - Art 25 Privacy by default (firewall default-deny, minimal services)
#     - Art 32 Crypto depth (CSPRNG, key strength, password hashing)
#     - Art 32 Access control depth (RBAC, ABAC, capability-based)
#     - Art 32 Testing/evaluation (continuous scanning evidence)
#     - Art 33 Breach detection depth (SIEM forwarding, alerting MTTR)
#     - Art 34 Individual notification capability (email/SMTP)
#     - Art 35 DPIA indicators (high-risk processing markers)
#     - Art 30 ROPA depth (audit log architecture)
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


def _v35_gdpr_result(category, status, message, severity="Medium",
                    details="", remediation="", cross_references=None):
    """Build AuditResult for GDPR v3.5 expansion."""
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


def _check_gdpr_v35_storage_limitation(os_info):
    """Article 5(1)(e) Storage limitation - retention auto-purge."""
    results = []
    cat = "GDPR v3.5 - Art 5(1)(e)"

    # 1. Log rotation configured
    logrotate_present = (
        _v35_command_available("logrotate") and
        (_v35_file_exists("/etc/logrotate.conf") or
         _v35_directory_exists("/etc/logrotate.d"))
    )
    logrotate_timer_active = (
        _v35_systemd_active("logrotate.timer") == "active" or
        _v35_file_exists("/etc/cron.daily/logrotate")
    )
    results.append(_v35_gdpr_result(
        f"{cat} - Log Rotation",
        "Pass" if logrotate_present and logrotate_timer_active else "Warning",
        f"GDPR Art 5(1)(e) Log rotation: present={logrotate_present}, "
        f"scheduled={logrotate_timer_active}",
        severity="Medium",
        details=(
            f"logrotate present: {logrotate_present}, "
            f"scheduled: {logrotate_timer_active}"
        ),
        remediation=(
            "apt-get install -y logrotate\n"
            "systemctl enable --now logrotate.timer (or cron.daily)\n"
            "Storage limitation requires logs/data not retained beyond "
            "purpose. logrotate is the technical foundation."
        ),
        cross_references={
            "GDPR": "Art 5(1)(e), Art 25",
            "NIST": "AU-11", "ISO27001": "A.8.15",
        },
    ))

    # 2. tmpwatch / tmpfiles for /tmp purging
    tmpfiles_d = _v35_directory_exists("/etc/tmpfiles.d") or \
                 _v35_directory_exists("/usr/lib/tmpfiles.d")
    systemd_tmpfiles_active = (
        _v35_systemd_active("systemd-tmpfiles-clean.timer") == "active"
    )
    results.append(_v35_gdpr_result(
        f"{cat} - Temp File Cleanup",
        "Pass" if tmpfiles_d and systemd_tmpfiles_active else "Warning",
        f"GDPR Art 5(1)(e) Temp file cleanup: "
        f"tmpfiles.d={tmpfiles_d}, timer={systemd_tmpfiles_active}",
        severity="Medium",
        details=(
            f"tmpfiles.d: {tmpfiles_d}, "
            f"systemd-tmpfiles-clean.timer: {systemd_tmpfiles_active}"
        ),
        remediation=(
            "systemctl enable --now systemd-tmpfiles-clean.timer\n"
            "Default policy purges /tmp files older than 10 days; review "
            "/etc/tmpfiles.d/*.conf for entries covering personal data."
        ),
        cross_references={
            "GDPR": "Art 5(1)(e)", "NIST": "MP-6",
        },
    ))

    # 3. Auditd retention configuration (limits on how long we keep)
    auditd_conf = _v35_read_file_safe("/etc/audit/auditd.conf")
    max_log_match = re.search(
        r"^\s*max_log_file\s*=\s*(\d+)", auditd_conf, re.MULTILINE,
    )
    num_logs_match = re.search(
        r"^\s*num_logs\s*=\s*(\d+)", auditd_conf, re.MULTILINE,
    )
    has_explicit_retention = bool(max_log_match and num_logs_match)
    results.append(_v35_gdpr_result(
        f"{cat} - Audit Log Retention Configured",
        "Pass" if has_explicit_retention else "Info",
        f"GDPR Art 5(1)(e) Explicit audit retention: "
        f"{has_explicit_retention}",
        severity="Low",
        details=(
            f"max_log_file: {max_log_match.group(1) if max_log_match else 'unset'}, "
            f"num_logs: {num_logs_match.group(1) if num_logs_match else 'unset'}"
        ),
        remediation=(
            "GDPR Art 5(1)(e) requires retention proportional to purpose.\n"
            "In /etc/audit/auditd.conf set explicit max_log_file and num_logs "
            "to bound the rolling retention window."
        ),
        cross_references={
            "GDPR": "Art 5(1)(e)", "NIST": "AU-11",
        },
    ))

    return results


def _check_gdpr_v35_erasure_depth(os_info):
    """Article 17 Right to erasure - secure deletion + swap/swap-cache clearing."""
    results = []
    cat = "GDPR v3.5 - Art 17"

    # 1. Secure-delete tooling (shred, srm, scrub)
    secure_delete_tools = {
        "shred": _v35_command_available("shred"),
        "srm": _v35_command_available("srm"),
        "scrub": _v35_command_available("scrub"),
        "wipe": _v35_command_available("wipe"),
    }
    available_secure_delete = [k for k, v in secure_delete_tools.items() if v]
    results.append(_v35_gdpr_result(
        f"{cat} - Secure Delete Tooling",
        "Pass" if available_secure_delete else "Warning",
        f"GDPR Art 17 Secure-delete tools: {available_secure_delete}",
        severity="Medium",
        details=f"Available: {available_secure_delete}",
        remediation=(
            "apt-get install -y secure-delete coreutils  (shred ships in coreutils)\n"
            "Or scrub: apt-get install -y scrub\n"
            "Note: secure-delete tools are reliable on traditional spinning disks; "
            "on SSDs use device-level secure-erase (hdparm --security-erase) "
            "or LUKS volume re-encrypt."
        ),
        cross_references={
            "GDPR": "Art 17, Art 5(1)(e)",
            "NIST": "MP-6", "ISO27001": "A.8.10",
        },
    ))

    # 2. Swap encrypted (so deleted data in swap is unrecoverable)
    proc_swaps = _v35_read_file_safe("/proc/swaps")
    swap_in_use = bool(
        proc_swaps and len(proc_swaps.splitlines()) > 1
    )
    swap_encrypted = False
    if swap_in_use:
        for line in proc_swaps.splitlines()[1:]:
            parts = line.split()
            if not parts:
                continue
            if "/dev/mapper/" in parts[0] or "/dev/dm-" in parts[0]:
                swap_encrypted = True
                break
    results.append(_v35_gdpr_result(
        f"{cat} - Swap Encryption",
        "Pass" if swap_encrypted or not swap_in_use else "Fail",
        f"GDPR Art 17 Swap encrypted: {swap_encrypted}, "
        f"swap-in-use: {swap_in_use}",
        severity="High" if swap_in_use and not swap_encrypted else "Low",
        details=(
            f"swap encrypted: {swap_encrypted}, in use: {swap_in_use}"
        ),
        remediation=(
            "If swap contains personal data and isn't encrypted, GDPR-protected "
            "data may persist beyond erasure. Add to /etc/crypttab:\n"
            "  swap UUID=<uuid> /dev/urandom swap,cipher=aes-xts-plain64,size=512"
        ),
        cross_references={
            "GDPR": "Art 17, Art 32",
            "NIST": "SC-28", "PCI-DSS": "3.5.1",
        },
    ))

    # 3. fstrim.timer (SSD trim - unmaps deleted blocks)
    fstrim_active = _v35_systemd_active("fstrim.timer") == "active"
    rc, out, _ = _v35_run_command(["lsblk", "-d", "-o", "ROTA", "-n"], timeout=5.0)
    has_ssd = rc == 0 and out and "0" in out
    results.append(_v35_gdpr_result(
        f"{cat} - SSD Trim (Block Unmapping)",
        "Pass" if fstrim_active or not has_ssd else "Warning",
        f"GDPR Art 17 SSD fstrim.timer: {fstrim_active}, has SSD: {has_ssd}",
        severity="Medium" if has_ssd else "Low",
        details=f"fstrim.timer: {fstrim_active}, SSD detected: {has_ssd}",
        remediation=(
            "systemctl enable --now fstrim.timer\n"
            "Weekly fstrim ensures deleted blocks are unmapped from the SSD "
            "controller - important for true erasure on SSDs where direct "
            "overwrite is unreliable."
        ),
        cross_references={
            "GDPR": "Art 17", "NIST": "MP-6",
        },
    ))

    return results


def _check_gdpr_v35_portability(os_info):
    """Article 20 Right to data portability - export tooling."""
    results = []
    cat = "GDPR v3.5 - Art 20"

    # Standard export tooling (jq, csvkit, xmlstarlet)
    export_tools = {
        "jq (JSON)": _v35_command_available("jq"),
        "csvkit": _v35_command_available("csvcut") or _v35_command_available("csvjson"),
        "xmlstarlet (XML)": _v35_command_available("xmlstarlet") or
                             _v35_command_available("xml"),
        "yq (YAML)": _v35_command_available("yq"),
        "pandoc (multi)": _v35_command_available("pandoc"),
    }
    available = [k for k, v in export_tools.items() if v]
    results.append(_v35_gdpr_result(
        f"{cat} - Export Tooling",
        "Pass" if len(available) >= 2 else "Info",
        f"GDPR Art 20 Data export tooling: {len(available)}/5",
        severity="Low",
        details=f"Available: {available}",
        remediation=(
            "apt-get install -y jq xmlstarlet csvkit yq pandoc\n"
            "Provides reliable data conversion to portable formats "
            "(JSON, CSV, XML, YAML) per data subject portability requests."
        ),
        cross_references={
            "GDPR": "Art 20", "ISO27001": "A.8.10",
        },
    ))

    # Database client tools (for data extraction from common DBs)
    db_clients = {
        "PostgreSQL": _v35_command_available("psql"),
        "MySQL/MariaDB": (
            _v35_command_available("mysql") or
            _v35_command_available("mariadb")
        ),
        "SQLite": _v35_command_available("sqlite3"),
        "MongoDB": _v35_command_available("mongo") or _v35_command_available("mongosh"),
    }
    available_db = [k for k, v in db_clients.items() if v]
    results.append(_v35_gdpr_result(
        f"{cat} - DB Client Tools",
        "Info",
        f"GDPR Art 20 DB clients available: {len(available_db)}",
        severity="Low",
        details=f"DB clients present: {available_db}",
        cross_references={
            "GDPR": "Art 20", "ISO27001": "A.8.10",
        },
    ))

    return results


def _check_gdpr_v35_privacy_by_default(os_info):
    """Article 25(2) Privacy by default - minimal-by-default configuration."""
    results = []
    cat = "GDPR v3.5 - Art 25(2)"

    # 1. Firewall default-deny
    rc, out, _ = _v35_run_command(["ufw", "status", "verbose"], timeout=5.0)
    ufw_default_deny = rc == 0 and (
        "Default: deny (incoming)" in out or
        "deny (incoming)" in out.lower()
    )
    rc, out, _ = _v35_run_command(["firewall-cmd", "--get-default-zone"], timeout=5.0)
    firewalld_strict = rc == 0 and out.strip() in ("drop", "block")
    privacy_firewall = ufw_default_deny or firewalld_strict
    results.append(_v35_gdpr_result(
        f"{cat} - Default-Deny Network",
        "Pass" if privacy_firewall else "Warning",
        f"GDPR Art 25(2) Network default-deny: {privacy_firewall}",
        severity="High",
        details=(
            f"ufw default deny: {ufw_default_deny}, "
            f"firewalld drop/block: {firewalld_strict}"
        ),
        remediation=(
            "ufw default deny incoming  (Debian/Ubuntu)\n"
            "firewall-cmd --set-default-zone=drop --permanent  (RHEL family)\n"
            "Privacy-by-default principle: no service exposed unless "
            "explicitly justified."
        ),
        cross_references={
            "GDPR": "Art 25(2), Art 32(1)(b)",
            "NIST": "SC-7", "PCI-DSS": "1.4.4",
        },
    ))

    # 2. Minimal listening services (privacy-by-default)
    rc, out, _ = _v35_run_command(["ss", "-tlnp"], timeout=5.0)
    listening_count = 0
    listening_external = 0
    if rc == 0 and out:
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4 and parts[0] in ("LISTEN",):
                listening_count += 1
                local_addr = parts[3]
                # External listeners (not 127.0.0.1, not ::1)
                if not (
                    local_addr.startswith("127.") or
                    local_addr.startswith("[::1]") or
                    local_addr.startswith("[::ffff:127")
                ):
                    listening_external += 1
    minimal_exposure = listening_external <= 5
    results.append(_v35_gdpr_result(
        f"{cat} - Minimal Network Exposure",
        "Pass" if minimal_exposure else "Warning",
        f"GDPR Art 25(2) Externally-bound TCP listeners: {listening_external}",
        severity="Medium",
        details=(
            f"Total LISTEN: {listening_count}, "
            f"non-loopback: {listening_external}"
        ),
        remediation=(
            "Audit with: ss -tlnp\n"
            "For each non-essential service, disable: systemctl disable --now <unit>\n"
            "Privacy-by-default favors minimal external attack surface."
        ),
        cross_references={
            "GDPR": "Art 25(2)", "NIST": "CM-7, SC-7",
        },
    ))

    # 3. Default UMASK (027 or 077 for privacy-by-default)
    login_defs = _v35_read_file_safe("/etc/login.defs")
    umask_match = re.search(
        r"^\s*UMASK\s+(\d+)", login_defs, re.MULTILINE,
    )
    umask_value = umask_match.group(1) if umask_match else "022"
    privacy_umask = umask_value in ("027", "077")
    results.append(_v35_gdpr_result(
        f"{cat} - Default UMASK Privacy-Friendly",
        "Pass" if privacy_umask else "Warning",
        f"GDPR Art 25(2) Default UMASK: {umask_value}",
        severity="Medium",
        details=f"UMASK in /etc/login.defs = {umask_value}",
        remediation=(
            "In /etc/login.defs: UMASK 027  (or 077 for stricter)\n"
            "Default 022 makes new files world-readable; 027/077 means "
            "privacy-by-default for newly-created files containing personal data."
        ),
        cross_references={
            "GDPR": "Art 25(2), Art 32",
            "NIST": "AC-3", "CIS": "5.5.5",
        },
    ))

    return results


def _check_gdpr_v35_crypto_depth(os_info):
    """Article 32 Crypto depth - CSPRNG, key strength, hashing."""
    results = []
    cat = "GDPR v3.5 - Art 32 Crypto"

    # 1. CSPRNG availability (/dev/urandom + getrandom syscall)
    urandom_present = _v35_file_exists("/dev/urandom")
    # getrandom is a syscall, not a file; verify via existing in /proc/sys
    poolsize_str = _v35_read_file_safe("/proc/sys/kernel/random/poolsize").strip()
    try:
        poolsize = int(poolsize_str) if poolsize_str else 0
    except ValueError:
        poolsize = 0
    csprng_ok = urandom_present and poolsize >= 256
    # rngd for hardware entropy supplement
    rngd_active = (
        _v35_systemd_active("rngd.service") == "active" or
        _v35_systemd_active("rng-tools.service") == "active" or
        _v35_systemd_active("haveged.service") == "active"
    )
    results.append(_v35_gdpr_result(
        f"{cat} - CSPRNG",
        "Pass" if csprng_ok else "Warning",
        f"GDPR Art 32 Cryptographic random source: "
        f"urandom={urandom_present}, poolsize={poolsize}",
        severity="High",
        details=(
            f"/dev/urandom: {urandom_present}, poolsize: {poolsize}, "
            f"rngd/haveged: {rngd_active}"
        ),
        remediation=(
            "On VMs/cloud (low entropy): apt-get install -y rng-tools haveged\n"
            "systemctl enable --now haveged\n"
            "Strong CSPRNG is foundational for all cryptography under GDPR Art 32."
        ),
        cross_references={
            "GDPR": "Art 32(1)(a)",
            "NIST": "SC-12, SC-13", "FIPS": "140-3",
        },
    ))

    # 2. Password hash strength (yescrypt > sha512 > sha256 > md5/des)
    login_defs = _v35_read_file_safe("/etc/login.defs")
    em_match = re.search(
        r"^\s*ENCRYPT_METHOD\s+(\S+)", login_defs, re.MULTILINE,
    )
    method = em_match.group(1).upper() if em_match else ""
    method_strong = method in ("YESCRYPT", "SHA512")
    method_excellent = method == "YESCRYPT"  # GDPR-aligned modern hash
    results.append(_v35_gdpr_result(
        f"{cat} - Password Hash Algorithm",
        "Pass" if method_strong else "Warning",
        f"GDPR Art 32(1)(a) ENCRYPT_METHOD: {method or 'unset'} "
        f"({'modern' if method_excellent else 'acceptable' if method_strong else 'weak'})",
        severity="High",
        details=f"ENCRYPT_METHOD = {method or 'default(SHA512)'}",
        remediation=(
            "On modern Debian/Ubuntu (libpam-modules >= 1.5): yescrypt is recommended:\n"
            "  In /etc/login.defs: ENCRYPT_METHOD YESCRYPT\n"
            "On RHEL family use SHA512: ENCRYPT_METHOD SHA512\n"
            "(MD5/DES are GDPR Art 32 violations - they're computationally trivial.)"
        ),
        cross_references={
            "GDPR": "Art 32(1)(a), Art 5(1)(f)",
            "NIST": "IA-5(1)", "FIPS": "180-4",
        },
    ))

    # 3. Pseudonymization tool availability (Article 32(1)(a) explicitly names it)
    pseudo_tools = {
        "openssl (HMAC capable)": _v35_command_available("openssl"),
        "gpg (encryption)": _v35_command_available("gpg") or _v35_command_available("gpg2"),
        "age (file encryption)": _v35_command_available("age"),
        "minisign": _v35_command_available("minisign"),
    }
    pseudo_available = [k for k, v in pseudo_tools.items() if v]
    results.append(_v35_gdpr_result(
        f"{cat} - Pseudonymization Tooling",
        "Pass" if len(pseudo_available) >= 2 else "Info",
        f"GDPR Art 32(1)(a) Pseudonymization tools: {len(pseudo_available)}",
        severity="Medium",
        details=f"Available: {pseudo_available}",
        remediation=(
            "apt-get install -y openssl gnupg age\n"
            "Examples:\n"
            "  Pseudonymize email: openssl dgst -hmac \"key\" -sha256 < email.txt\n"
            "  Encrypt file: age -r <recipient> input.txt -o input.txt.age"
        ),
        cross_references={
            "GDPR": "Art 32(1)(a)",
            "NIST": "SC-13",
        },
    ))

    return results


def _check_gdpr_v35_breach_detection_depth(os_info):
    """Article 33 Breach detection depth - SIEM forwarding, alerting MTTR."""
    results = []
    cat = "GDPR v3.5 - Art 33"

    # 1. Centralized log forwarding (rsyslog @@/omfwd or syslog-ng remote)
    rsy_remote = False
    rsyslog_main = _v35_read_file_safe("/etc/rsyslog.conf")
    if "@@" in rsyslog_main or "omfwd" in rsyslog_main:
        rsy_remote = True
    if not rsy_remote and _v35_directory_exists("/etc/rsyslog.d"):
        for f in _v35_list_directory("/etc/rsyslog.d"):
            c = _v35_read_file_safe(os.path.join("/etc/rsyslog.d", f))
            if "@@" in c or "omfwd" in c:
                rsy_remote = True
                break
    journal_upload = (
        _v35_systemd_active("systemd-journal-upload.service") == "active"
    )
    centralized = rsy_remote or journal_upload
    results.append(_v35_gdpr_result(
        f"{cat} - SIEM Forwarding",
        "Pass" if centralized else "Fail",
        f"GDPR Art 33(1) Centralized log forwarding (72h notification clock): "
        f"{centralized}",
        severity="Critical",
        details=(
            f"rsyslog remote: {rsy_remote}, "
            f"journal-upload: {journal_upload}"
        ),
        remediation=(
            "Configure /etc/rsyslog.d/50-gdpr-siem.conf:\n"
            "  *.* action(type=\"omfwd\" target=\"siem.example.com\" "
            "port=\"6514\" protocol=\"tcp\" StreamDriver=\"gtls\")\n"
            "GDPR Art 33 requires breach notification within 72 hours of "
            "AWARENESS - without centralized monitoring, awareness is delayed."
        ),
        cross_references={
            "GDPR": "Art 33(1), Art 33(2)",
            "NIST": "AU-6, IR-6", "PCI-DSS": "10.5.3",
        },
    ))

    # 2. Real-time alerting (host-level: postfix/sendmail/auditd alerts)
    alert_tools = {
        "auditd email alert": False,  # Need to check space_left_action
        "fail2ban active": _v35_systemd_active("fail2ban.service") == "active",
        "logwatch": _v35_command_available("logwatch"),
        "OSSEC/Wazuh": _v35_file_exists("/var/ossec/etc/ossec.conf"),
    }
    auditd_conf = _v35_read_file_safe("/etc/audit/auditd.conf")
    space_left_action_match = re.search(
        r"^\s*space_left_action\s*=\s*(\w+)", auditd_conf, re.MULTILINE,
    )
    if space_left_action_match and space_left_action_match.group(1).lower() in (
            "email", "exec", "syslog"):
        alert_tools["auditd email alert"] = True
    available = [k for k, v in alert_tools.items() if v]
    results.append(_v35_gdpr_result(
        f"{cat} - Real-Time Alerting",
        "Pass" if len(available) >= 2 else "Warning",
        f"GDPR Art 33 Real-time alerting: {len(available)} mechanisms",
        severity="High",
        details=f"Active: {available}",
        remediation=(
            "Combine multiple alert sources:\n"
            "  - auditd: space_left_action = email\n"
            "  - apt-get install -y fail2ban logwatch\n"
            "  - For deep monitoring: Wazuh / OSSEC agent\n"
            "Multiple layers shorten time-to-awareness for the 72-hour clock."
        ),
        cross_references={
            "GDPR": "Art 33(1), Art 32(1)(d)",
            "NIST": "AU-6, IR-4, IR-5",
        },
    ))

    # 3. Time accuracy (essential for breach timeline reconstruction)
    time_sync = (
        _v35_systemd_active("chronyd.service") == "active" or
        _v35_systemd_active("chrony.service") == "active" or
        _v35_systemd_active("systemd-timesyncd.service") == "active"
    )
    results.append(_v35_gdpr_result(
        f"{cat} - Timeline Accuracy",
        "Pass" if time_sync else "Fail",
        f"GDPR Art 33 Time synchronization (timeline accuracy): {time_sync}",
        severity="Critical",
        details=f"NTP/chrony/timesyncd active: {time_sync}",
        remediation=remediation_for("chrony"),
        cross_references={
            "GDPR": "Art 33(2), Art 33(5)",
            "NIST": "AU-8", "PCI-DSS": "10.6.1",
        },
    ))

    # 4. Breach evidence preservation (immutable audit logs)
    rules_text = ""
    if _v35_directory_exists("/etc/audit/rules.d"):
        for f in _v35_list_directory("/etc/audit/rules.d"):
            if f.endswith(".rules"):
                rules_text += "\n" + _v35_read_file_safe(
                    os.path.join("/etc/audit/rules.d", f)
                )
    immutable_rules = bool(re.search(r"^\s*-e\s+2", rules_text, re.MULTILINE))
    results.append(_v35_gdpr_result(
        f"{cat} - Evidence Preservation",
        "Pass" if immutable_rules else "Info",
        f"GDPR Art 33(5) Audit ruleset immutable (-e 2): {immutable_rules}",
        severity="Medium",
        details=f"Rules locked at runtime: {immutable_rules}",
        remediation=(
            "Append to /etc/audit/rules.d/99-finalize.rules:\n"
            "  -e 2\n"
            "Locks audit ruleset until next reboot - prevents post-breach "
            "tampering of the audit trail."
        ),
        cross_references={
            "GDPR": "Art 33(5)",
            "NIST": "AU-9, AU-12(3)",
        },
    ))

    return results


def _check_gdpr_v35_data_subject_rights(os_info):
    """Articles 15-22 Data subject rights - technical readiness."""
    results = []
    cat = "GDPR v3.5 - Art 15-22"

    # Mail capability for data subject communication (Art 15, 19, 21)
    mail_capable = (
        _v35_command_available("mail") or
        _v35_command_available("mailx") or
        _v35_systemd_active("postfix.service") == "active"
    )
    results.append(_v35_gdpr_result(
        f"{cat} - Subject Communication Capability",
        "Pass" if mail_capable else "Warning",
        f"GDPR Art 15/19/21 Email capability for subject communications: "
        f"{mail_capable}",
        severity="Medium",
        details=f"mail/mailx/postfix available: {mail_capable}",
        remediation=(
            "apt-get install -y mailutils\n"
            "Configure /etc/postfix/main.cf for delivery - required to "
            "respond within Art 12 one-month deadline to data subject requests."
        ),
        cross_references={
            "GDPR": "Art 12, Art 15, Art 19, Art 21",
        },
    ))

    # Activity log read-access (data subjects may request copy of personal data)
    journal_readable = _v35_command_available("journalctl")
    audit_readable = (
        _v35_command_available("ausearch") or
        _v35_command_available("aureport")
    )
    log_readable = journal_readable and audit_readable
    results.append(_v35_gdpr_result(
        f"{cat} - Activity Query Tools",
        "Pass" if log_readable else "Warning",
        f"GDPR Art 15 Activity-log query tools: journalctl={journal_readable}, "
        f"ausearch/aureport={audit_readable}",
        severity="Medium",
        details=(
            f"journalctl: {journal_readable}, "
            f"ausearch/aureport: {audit_readable}"
        ),
        remediation=(
            "apt-get install -y systemd auditd\n"
            "Enables data subject Article 15 requests: 'what activity has "
            "been logged about my account?' Use:\n"
            "  ausearch -ua <username>\n"
            "  journalctl _UID=<uid>"
        ),
        cross_references={
            "GDPR": "Art 15", "NIST": "AU-6",
        },
    ))

    return results


def _check_gdpr_v35_dpia_indicators(os_info):
    """Article 35 DPIA indicators - high-risk processing markers."""
    results = []
    cat = "GDPR v3.5 - Art 35"

    # Indicators that high-risk processing is occurring (DPIA likely required)
    high_risk_indicators = []

    # Public-facing web/database services (large-scale processing risk)
    rc, out, _ = _v35_run_command(["ss", "-tlnp"], timeout=5.0)
    if rc == 0 and out:
        if ":443 " in out or ":80 " in out:
            high_risk_indicators.append("public_web")
        if ":3306 " in out or ":5432 " in out or ":27017 " in out:
            high_risk_indicators.append("public_database")

    # Camera/biometric devices (special-category data processing risk)
    if _v35_directory_exists("/sys/class/video4linux") and \
        _v35_list_directory("/sys/class/video4linux"):
        high_risk_indicators.append("video_capture_device")

    # Audio recording capability
    if _v35_directory_exists("/proc/asound") and \
        not all("Modules" in f for f in
                _v35_list_directory("/proc/asound") if f.startswith("card")):
        # crude check - most real systems have sound cards
        pass

    # Geolocation (gpsd)
    if _v35_systemd_active("gpsd.service") == "active":
        high_risk_indicators.append("geolocation")

    # Container/orchestration (large-scale processing)
    if _v35_command_available("docker") or _v35_command_available("kubelet"):
        high_risk_indicators.append("orchestration")

    risk_level = (
        "high" if len(high_risk_indicators) >= 3
        else "medium" if len(high_risk_indicators) >= 1
        else "low"
    )

    results.append(_v35_gdpr_result(
        f"{cat} - DPIA Indicators",
        "Info",
        f"GDPR Art 35 DPIA-relevant indicators ({risk_level}): "
        f"{high_risk_indicators}",
        severity="Informational",
        details=(
            f"Indicators: {high_risk_indicators}, risk level: {risk_level}"
        ),
        remediation=(
            "If 2+ indicators present, a DPIA per Art 35 is likely required.\n"
            "Document in DPIA: nature/scope/context/purposes of processing, "
            "necessity assessment, risks to data subject rights, and "
            "safeguards (encryption, pseudonymization, access control)."
        ),
        cross_references={
            "GDPR": "Art 35", "NIST": "RA-3, PT-3",
        },
    ))

    return results


# Save reference to existing run_checks
_original_run_checks_gdpr_v35 = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the v3.5 expanded GDPR module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_gdpr_v35(shared_data)

    os_info = shared_data.get("os_info") or shared_data.get("v3_os_info")
    if os_info is None:
        from shared_components import os_detection as _os_det
        os_info = _os_det.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        results.extend(_check_gdpr_v35_storage_limitation(os_info))
        results.extend(_check_gdpr_v35_erasure_depth(os_info))
        results.extend(_check_gdpr_v35_portability(os_info))
        results.extend(_check_gdpr_v35_privacy_by_default(os_info))
        results.extend(_check_gdpr_v35_crypto_depth(os_info))
        results.extend(_check_gdpr_v35_breach_detection_depth(os_info))
        results.extend(_check_gdpr_v35_data_subject_rights(os_info))
        results.extend(_check_gdpr_v35_dpia_indicators(os_info))
    except Exception as exc:  # noqa: BLE001
        results.append(AuditResult(
            module=MODULE_NAME, category="GDPR - Error",
            status="Error",
            message=f"GDPR v3.5 expansion exception: {exc!r}",
            details=str(exc), severity="Medium",
        ))

    return results
if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    print("[GDPR] ===== GDPR Article 32 + ePrivacy Audit =====")
    print("[GDPR] Module Version: 3.9\n")
    rs = run_checks()
    print(f"[GDPR] {len(rs)} checks executed\n")
    counts: Dict[str, int] = {}
    for r in rs:
        counts[r.status] = counts.get(r.status, 0) + 1
    for s, c in sorted(counts.items()):
        print(f"  {s:>8}: {c}")
