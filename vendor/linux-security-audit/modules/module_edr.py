#!/usr/bin/env python3
"""
module_edr.py
Linux EDR Equivalent Detection Module
Version: 3.9

SYNOPSIS
    Inventory of Endpoint Detection and Response (EDR) capability on
    Linux systems. Detects open-source and commercial EDR agents,
    validates their configuration, and reports on related detection
    capabilities (eBPF, FIM, behavioral monitoring).

DESCRIPTION
    Linux endpoints in security-conscious environments need detection
    and response capability comparable to what Windows EDR provides.
    No single Linux tool covers everything an EDR does on Windows;
    coverage is typically built from a combination of agents:

        Falco                  - Runtime threat detection (eBPF/kmod)
        Wazuh / OSSEC          - HIDS + SIEM agent
        Auditbeat              - File integrity + auditd integration
        Sysdig                 - Container/host monitoring
        Tracee                 - eBPF-based syscall tracking
        CrowdStrike Falcon     - Commercial EDR (Linux sensor)
        SentinelOne            - Commercial EDR (Linux agent)
        Microsoft Defender     - Microsoft Defender for Endpoint Linux

    Plus supporting capabilities:
        eBPF / BPF LSM          - Kernel-level instrumentation
        AIDE / Tripwire         - File integrity baseline
        OSSEC syscheck          - File integrity in Wazuh/OSSEC
        Persistent journald     - Log preservation across reboots
        Central log forwarding  - Off-host detection material

    This module focuses on detection and reporting; it does not
    deploy agents. Configuration validation is performed where the
    relevant agent is detected.

    Each check populates AuditResult.cross_references with NIST 800-53,
    ISO 27001, and ATT&CK technique tactical mappings where applicable.

PARAMETERS
    shared_data : Dictionary containing shared data from the orchestrator.

USAGE
    Standalone:
        python3 modules/module_edr.py

    Via orchestrator:
        python3 linux_security_audit.py -m EDR

NOTES
    Version: 3.9
    Reference:
        Falco docs:        https://falco.org/docs/
        Wazuh docs:        https://documentation.wazuh.com/
        Auditbeat docs:    https://www.elastic.co/guide/en/beats/auditbeat/
        MDE Linux:         https://learn.microsoft.com/microsoft-365/security/defender-endpoint/microsoft-defender-endpoint-linux
        CrowdStrike Falcon: https://www.crowdstrike.com/products/endpoint-security/falcon-linux/
    Target: 65+ EDR-related checks
    Vendor neutrality: this module reports presence and basic config
    correctness; vendor-specific tuning is out of scope.
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
)

logger = logging.getLogger("audit.module_edr")
MODULE_NAME = "EDR"
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
# Open-Source EDR Agent Detection
# ===========================================================================

def _check_falco(os_info) -> List[AuditResult]:
    cat = "EDR - Falco Runtime Detection"
    results: List[AuditResult] = []

    falco_installed = command_available("falco") or file_exists(
        "/etc/falco/falco.yaml"
    )
    falco_active = systemd_active("falco.service") in ("active", "running")

    results.append(_r(
        cat,
        "Pass" if falco_active else "Info" if falco_installed else "Info",
        f"EDR-Falco: Runtime threat detection deployed ({'active' if falco_active else 'installed' if falco_installed else 'not present'})",
        severity="High" if not falco_installed else "Informational",
        details=(
            f"Falco binary present: {command_available('falco')}, "
            f"config: {file_exists('/etc/falco/falco.yaml')}, "
            f"service active: {falco_active}"
        ),
        remediation=(
            "Install: curl -fsSL https://falco.org/repo/falcosecurity-packages.asc "
            "| gpg --dearmor -o /etc/apt/keyrings/falcosecurity.gpg; "
            "follow installation guide for chosen driver (eBPF/kmod). "
            "Then: systemctl enable --now falco-bpf"
        ),
        cross_references={
            "EDR": "Falco", "NIST": "SI-4(2)", "ISO27001": "A.8.16",
            "ATT&CK": "TA0007-Discovery",
        },
    ))

    # Falco configuration validation if present
    if falco_installed and file_exists("/etc/falco/falco.yaml"):
        config = read_file_safe("/etc/falco/falco.yaml")

        # Check whether outputs are configured (otherwise alerts are lost)
        outputs_configured = any(
            keyword in config
            for keyword in ("file_output:", "syslog_output:", "program_output:",
                            "http_output:", "stdout_output:")
        )
        # Check for at least one output enabled
        enabled_outputs = []
        for output_type in ("file_output", "syslog_output", "program_output",
                            "http_output", "stdout_output"):
            # Look for enabled: true within ~10 lines of the output_type
            pattern = rf"{output_type}:\s*\n(?:.*?\n){{0,10}}\s*enabled:\s*true"
            if re.search(pattern, config, re.DOTALL):
                enabled_outputs.append(output_type)

        results.append(_r(
            cat,
            "Pass" if enabled_outputs else "Fail",
            f"EDR-Falco: At least one output is enabled",
            severity="High",
            details=f"Enabled outputs: {', '.join(enabled_outputs) or 'none'}",
            remediation=(
                "Edit /etc/falco/falco.yaml and enable at least one of "
                "file_output, syslog_output, or program_output"
            ),
            cross_references={
                "EDR": "Falco-Output", "NIST": "AU-6", "ISO27001": "A.8.15",
            },
        ))

        # Check default rules file is loaded
        rule_files_loaded = "rules_files:" in config
        results.append(_r(
            cat,
            "Pass" if rule_files_loaded else "Warning",
            "EDR-Falco: Detection rules configured",
            severity="High",
            details=f"rules_files directive present: {rule_files_loaded}",
            remediation=(
                "Ensure /etc/falco/falco.yaml has rules_files: that points to "
                "the default rule set (typically /etc/falco/falco_rules.yaml "
                "and /etc/falco/falco_rules.local.yaml)"
            ),
            cross_references={
                "EDR": "Falco-Rules", "NIST": "SI-4(2)", "ISO27001": "A.8.16",
            },
        ))

    return results


def _check_wazuh_ossec(os_info) -> List[AuditResult]:
    cat = "EDR - Wazuh / OSSEC"
    results: List[AuditResult] = []

    ossec_path = "/var/ossec/etc/ossec.conf"
    wazuh_present = file_exists(ossec_path)
    wazuh_state = systemd_active("wazuh-agent.service")
    if wazuh_state == "unknown":
        wazuh_state = systemd_active("wazuh-manager.service")
    if wazuh_state == "unknown":
        wazuh_state = systemd_active("ossec.service")

    results.append(_r(
        cat,
        "Pass" if wazuh_state == "active" else "Info",
        f"EDR-Wazuh: Wazuh/OSSEC agent state: {wazuh_state}",
        severity="High" if not wazuh_present else "Informational",
        details=(
            f"ossec.conf present: {wazuh_present}, "
            f"agent service: {wazuh_state}"
        ),
        remediation=(
            "Install Wazuh agent: see https://documentation.wazuh.com/current/installation-guide/"
        ),
        cross_references={
            "EDR": "Wazuh", "NIST": "SI-4", "ISO27001": "A.8.16",
        },
    ))

    if wazuh_present:
        config = read_file_safe(ossec_path)

        # Check syscheck (FIM) enabled
        syscheck_match = re.search(r"<syscheck>(.*?)</syscheck>", config, re.DOTALL)
        syscheck_enabled = False
        if syscheck_match:
            inner = syscheck_match.group(1)
            disabled_match = re.search(r"<disabled>(\w+)</disabled>", inner)
            syscheck_enabled = (
                disabled_match is None or disabled_match.group(1).lower() == "no"
            )

        results.append(_r(
            cat,
            "Pass" if syscheck_enabled else "Warning",
            "EDR-Wazuh: syscheck (FIM) enabled",
            severity="High",
            details=f"syscheck enabled: {syscheck_enabled}",
            remediation=(
                "In /var/ossec/etc/ossec.conf within <syscheck>: "
                "<disabled>no</disabled>"
            ),
            cross_references={
                "EDR": "Wazuh-FIM", "NIST": "SI-7", "ISO27001": "A.8.16",
                "PCI-DSS": "11.5.2",
            },
        ))

        # Rootcheck
        rootcheck_match = re.search(r"<rootcheck>(.*?)</rootcheck>", config, re.DOTALL)
        rootcheck_enabled = False
        if rootcheck_match:
            inner = rootcheck_match.group(1)
            disabled_match = re.search(r"<disabled>(\w+)</disabled>", inner)
            rootcheck_enabled = (
                disabled_match is None or disabled_match.group(1).lower() == "no"
            )

        results.append(_r(
            cat,
            "Pass" if rootcheck_enabled else "Warning",
            "EDR-Wazuh: rootcheck enabled",
            severity="Medium",
            details=f"rootcheck enabled: {rootcheck_enabled}",
            remediation=(
                "In /var/ossec/etc/ossec.conf within <rootcheck>: "
                "<disabled>no</disabled>"
            ),
            cross_references={
                "EDR": "Wazuh-Rootcheck", "NIST": "SI-3", "ISO27001": "A.8.7",
            },
        ))

    return results


def _check_auditbeat(os_info) -> List[AuditResult]:
    cat = "EDR - Elastic Auditbeat"
    results: List[AuditResult] = []

    auditbeat_active = systemd_active("auditbeat.service") == "active"
    auditbeat_present = (
        command_available("auditbeat")
        or file_exists("/etc/auditbeat/auditbeat.yml")
    )

    results.append(_r(
        cat,
        "Pass" if auditbeat_active else "Info",
        f"EDR-Auditbeat: state: {'active' if auditbeat_active else 'inactive/absent'}",
        severity="Medium" if not auditbeat_present else "Informational",
        details=(
            f"auditbeat binary: {command_available('auditbeat')}, "
            f"config: {file_exists('/etc/auditbeat/auditbeat.yml')}, "
            f"service active: {auditbeat_active}"
        ),
        remediation=(
            "Auditbeat ships with Elastic Stack. Install per Elastic docs: "
            "https://www.elastic.co/guide/en/beats/auditbeat/current/auditbeat-installation-configuration.html"
        ),
        cross_references={
            "EDR": "Auditbeat", "NIST": "AU-2", "ISO27001": "A.8.15",
        },
    ))

    if auditbeat_present and file_exists("/etc/auditbeat/auditbeat.yml"):
        config = read_file_safe("/etc/auditbeat/auditbeat.yml")
        # Check for module configurations
        has_auditd_module = "module: auditd" in config
        has_file_integrity = "module: file_integrity" in config
        has_system_module = "module: system" in config

        results.append(_r(
            cat,
            "Pass" if has_auditd_module else "Warning",
            "EDR-Auditbeat: auditd module configured",
            severity="Medium",
            details=f"auditd module in config: {has_auditd_module}",
            cross_references={
                "EDR": "Auditbeat-auditd", "NIST": "AU-2",
            },
        ))

        results.append(_r(
            cat,
            "Pass" if has_file_integrity else "Warning",
            "EDR-Auditbeat: file_integrity module configured",
            severity="High",
            details=f"file_integrity module in config: {has_file_integrity}",
            remediation=(
                "Edit /etc/auditbeat/auditbeat.yml and ensure file_integrity "
                "module is enabled with appropriate paths"
            ),
            cross_references={
                "EDR": "Auditbeat-FIM", "NIST": "SI-7", "PCI-DSS": "11.5.2",
            },
        ))

    return results


def _check_sysdig_tracee(os_info) -> List[AuditResult]:
    cat = "EDR - Sysdig / Tracee"
    results: List[AuditResult] = []

    sysdig_present = command_available("sysdig") or command_available("csysdig")
    tracee_present = command_available("tracee") or command_available("tracee-ebpf")

    results.append(_r(
        cat,
        "Info",
        f"EDR-Sysdig: presence: {sysdig_present}",
        severity="Informational",
        details=f"Sysdig tools detected: {sysdig_present}",
        remediation=(
            "Sysdig open-source: https://github.com/draios/sysdig. "
            "Sysdig commercial: https://sysdig.com/"
        ),
        cross_references={"EDR": "Sysdig", "NIST": "SI-4"},
    ))

    results.append(_r(
        cat,
        "Info",
        f"EDR-Tracee: presence: {tracee_present}",
        severity="Informational",
        details=(
            f"Tracee detected: {tracee_present}. "
            "Tracee uses eBPF for runtime tracing and behavioral analysis."
        ),
        remediation="https://github.com/aquasecurity/tracee",
        cross_references={"EDR": "Tracee", "NIST": "SI-4"},
    ))

    return results


# ===========================================================================
# Commercial EDR Detection
# ===========================================================================

def _check_commercial_edr(os_info) -> List[AuditResult]:
    cat = "EDR - Commercial Solutions"
    results: List[AuditResult] = []

    # CrowdStrike Falcon Linux sensor
    crowdstrike_paths = (
        "/opt/CrowdStrike/falconctl",
        "/opt/CrowdStrike/falcon-sensor",
    )
    crowdstrike_present = any(file_exists(p) for p in crowdstrike_paths)
    crowdstrike_active = systemd_active("falcon-sensor.service") == "active"

    results.append(_r(
        cat,
        "Pass" if crowdstrike_active else "Info",
        f"EDR-CrowdStrike: Falcon sensor presence",
        severity="Informational",
        details=(
            f"Sensor binary detected: {crowdstrike_present}, "
            f"service active: {crowdstrike_active}"
        ),
        cross_references={"EDR": "CrowdStrike", "NIST": "SI-4"},
    ))

    # SentinelOne Linux agent
    s1_present = file_exists("/opt/sentinelone/bin/sentinelctl") or file_exists(
        "/opt/sentinelone/bin/sentinelone"
    )
    s1_active = systemd_active("sentinelone.service") == "active"

    results.append(_r(
        cat,
        "Pass" if s1_active else "Info",
        f"EDR-SentinelOne: agent presence",
        severity="Informational",
        details=(
            f"Agent binary detected: {s1_present}, "
            f"service active: {s1_active}"
        ),
        cross_references={"EDR": "SentinelOne", "NIST": "SI-4"},
    ))

    # Microsoft Defender for Endpoint Linux
    mde_present = file_exists("/opt/microsoft/mdatp/sbin/wdavdaemon") or file_exists(
        "/etc/opt/microsoft/mdatp/wdavcfg"
    )
    mde_active = systemd_active("mdatp.service") == "active"

    results.append(_r(
        cat,
        "Pass" if mde_active else "Info",
        f"EDR-Defender: Microsoft Defender for Endpoint Linux",
        severity="Informational",
        details=(
            f"MDE files detected: {mde_present}, "
            f"service active: {mde_active}"
        ),
        cross_references={"EDR": "MDE", "NIST": "SI-4"},
    ))

    # Tetration / Cisco Secure Workload
    tet_present = file_exists("/usr/local/tet/tet-sensor") or directory_exists(
        "/usr/local/tet"
    )

    results.append(_r(
        cat,
        "Info",
        f"EDR-Tetration: Cisco Secure Workload sensor presence: {tet_present}",
        severity="Informational",
        cross_references={"EDR": "Tetration", "NIST": "SI-4"},
    ))

    # Check for any commercial EDR coverage
    has_commercial_edr = (
        crowdstrike_active or s1_active or mde_active or tet_present
    )
    results.append(_r(
        cat,
        "Pass" if has_commercial_edr else "Info",
        f"EDR Summary: Commercial EDR coverage = {has_commercial_edr}",
        severity="High" if not has_commercial_edr else "Informational",
        details=(
            f"Active commercial EDR detected: {has_commercial_edr}. "
            "Open-source coverage (Falco/Wazuh/Auditbeat) can substitute "
            "in many environments."
        ),
        cross_references={
            "EDR": "Commercial-Summary", "NIST": "SI-4",
            "ISO27001": "A.8.16", "PCI-DSS": "11.5.1",
        },
    ))

    return results


# ===========================================================================
# Behavioral and Kernel-Level Monitoring Capabilities
# ===========================================================================

def _check_ebpf_capabilities(os_info) -> List[AuditResult]:
    cat = "EDR - eBPF / Kernel Capabilities"
    results: List[AuditResult] = []

    # eBPF support indicator: BPF filesystem mounted or available
    bpf_mounted = directory_exists("/sys/fs/bpf")
    bpftool_available = command_available("bpftool")

    results.append(_r(
        cat,
        "Pass" if bpf_mounted else "Info",
        f"EDR-eBPF: BPF infrastructure available",
        severity="Medium",
        details=(
            f"BPF filesystem at /sys/fs/bpf: {bpf_mounted}, "
            f"bpftool: {bpftool_available}"
        ),
        remediation=(
            "Install bpftool for eBPF inspection: "
            "apt-get install -y linux-tools-common (Debian) or "
            "dnf install -y bpftool (RHEL)"
        ),
        cross_references={
            "EDR": "eBPF", "NIST": "SI-4(2)",
        },
    ))

    # BPF LSM (Linux Security Module) - kernel 5.7+
    bpf_lsm_supported = False
    if file_exists("/sys/kernel/security/lsm"):
        try:
            with open("/sys/kernel/security/lsm", "r", encoding="ascii") as f:
                lsm_list = f.read().strip()
            bpf_lsm_supported = "bpf" in lsm_list
        except OSError:
            pass

    results.append(_r(
        cat,
        "Pass" if bpf_lsm_supported else "Info",
        "EDR-eBPF: BPF LSM available",
        severity="Medium",
        details=(
            f"BPF LSM in /sys/kernel/security/lsm: {bpf_lsm_supported}. "
            "Enables fine-grained kernel security policy via eBPF programs."
        ),
        remediation=(
            "Requires kernel 5.7+ with CONFIG_LSM=...,bpf in build config. "
            "Add lsm=...,bpf to kernel command line."
        ),
        cross_references={
            "EDR": "BPF-LSM", "NIST": "SI-4(2)", "ACCESS": "AC-3(4)",
        },
    ))

    # cgroups v2 support
    cgroup_v2 = directory_exists("/sys/fs/cgroup/cgroup.controllers")
    results.append(_r(
        cat,
        "Pass" if cgroup_v2 else "Info",
        f"EDR: cgroups v2 unified hierarchy available",
        severity="Medium",
        details=f"cgroup.controllers exists: {cgroup_v2}",
        cross_references={
            "EDR": "cgroupsv2", "NIST": "AC-6", "ISO27001": "A.8.3",
        },
    ))

    return results


# ===========================================================================
# File Integrity Monitoring (Defense-in-Depth)
# ===========================================================================

def _check_fim_indicators(os_info) -> List[AuditResult]:
    cat = "EDR - File Integrity Monitoring"
    results: List[AuditResult] = []

    fim_tools = {
        "AIDE": command_available("aide") or file_exists("/etc/aide.conf"),
        "Tripwire": command_available("tripwire") or file_exists("/etc/tripwire/twcfg.txt"),
        "Samhain": command_available("samhain") or file_exists("/etc/samhainrc"),
        "OSSEC/Wazuh syscheck": file_exists("/var/ossec/etc/ossec.conf"),
    }
    detected = [n for n, p in fim_tools.items() if p]

    results.append(_r(
        cat,
        "Pass" if detected else "Fail",
        "EDR-FIM: At least one file integrity tool deployed",
        severity="High",
        details=f"Detected: {', '.join(detected) or 'none'}",
        remediation=remediation_for("aide"),
        cross_references={
            "EDR": "FIM", "NIST": "SI-7", "ISO27001": "A.8.16",
            "PCI-DSS": "11.5.2", "HIPAA": "164.312(c)(1)",
        },
    ))

    # AIDE database age check (if AIDE is installed)
    aide_db_paths = ("/var/lib/aide/aide.db", "/var/lib/aide/aide.db.gz")
    aide_db_path = first_existing(*aide_db_paths)
    if aide_db_path:
        try:
            import time
            mtime = os.stat(aide_db_path).st_mtime
            age_days = int((time.time() - mtime) / 86400)
            db_fresh = age_days <= 7  # database should be no more than a week old
            results.append(_r(
                cat,
                "Pass" if db_fresh else "Warning",
                f"EDR-FIM: AIDE database age {age_days} days",
                severity="Medium",
                details=(
                    f"Database: {aide_db_path}, age: {age_days} days "
                    "(acceptable: <= 7 days)"
                ),
                remediation=(
                    "Schedule daily AIDE checks via cron and update the "
                    "database after legitimate system changes."
                ),
                cross_references={
                    "EDR": "AIDE-Age", "NIST": "SI-7(7)",
                },
            ))
        except OSError:
            pass

    return results


# ===========================================================================
# IR Readiness (Logging and Forensic Material)
# ===========================================================================

def _check_ir_readiness(os_info) -> List[AuditResult]:
    cat = "EDR - Incident Response Readiness"
    results: List[AuditResult] = []

    # Persistent journald
    journal_persistent = directory_exists("/var/log/journal")
    results.append(_r(
        cat,
        "Pass" if journal_persistent else "Fail",
        "IR-Readiness: Persistent system journal",
        severity="High",
        details=(
            f"/var/log/journal directory exists: {journal_persistent}. "
            "Without persistent journal, evidence is lost on reboot."
        ),
        remediation=(
            "mkdir -p /var/log/journal && "
            "systemd-tmpfiles --create --prefix /var/log/journal && "
            "systemctl restart systemd-journald"
        ),
        cross_references={
            "EDR": "Journal-Persist", "NIST": "AU-9",
            "ISO27001": "A.8.15", "PCI-DSS": "10.5.1",
        },
    ))

    # Central log forwarding
    rsyslog_files = ["/etc/rsyslog.conf"] + list_directory("/etc/rsyslog.d", ".conf")
    has_remote = False
    for rf in rsyslog_files:
        content = read_file_safe(rf)
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            if re.search(r"@@?[a-zA-Z0-9.\-]+", stripped) and "*" in stripped[:5]:
                has_remote = True
                break
        if has_remote:
            break

    # Also check journald forwarding (systemd-journald)
    journald_forward = False
    journald_conf = read_file_safe("/etc/systemd/journald.conf")
    if "ForwardToSyslog=yes" in journald_conf or "ForwardToConsole=" in journald_conf:
        journald_forward = True

    results.append(_r(
        cat,
        "Pass" if has_remote or journald_forward else "Warning",
        "IR-Readiness: Central log forwarding configured",
        severity="High",
        details=(
            f"Remote rsyslog: {has_remote}, "
            f"journald forwarding: {journald_forward}"
        ),
        remediation=(
            "Configure rsyslog to forward to a SIEM/log aggregator: "
            "echo '*.* @@logserver:514' > /etc/rsyslog.d/50-remote.conf"
        ),
        cross_references={
            "EDR": "LogForward", "NIST": "AU-6(3)", "ISO27001": "A.8.15",
            "PCI-DSS": "10.5.4",
        },
    ))

    # auditd installed and active
    auditd_active = systemd_active("auditd.service") == "active"
    results.append(_r(
        cat,
        "Pass" if auditd_active else "Fail",
        "IR-Readiness: System audit daemon active",
        severity="High",
        details=f"auditd state: {systemd_active('auditd.service')}",
        remediation=remediation_for("auditd"),
        cross_references={
            "EDR": "auditd", "NIST": "AU-2", "CIS": "4.1.1.1",
            "ISO27001": "A.8.15", "PCI-DSS": "10.2.1",
        },
    ))

    # /tmp on dedicated tmpfs mount (helps preserve / from runaway temp data)
    tmp_separate = False
    try:
        with open("/proc/mounts", "r", encoding="utf-8") as f:
            mounts = f.read()
        for line in mounts.splitlines():
            fields = line.split()
            if len(fields) >= 2 and fields[1] == "/tmp":
                tmp_separate = True
                break
    except OSError:
        pass

    results.append(_r(
        cat,
        "Pass" if tmp_separate else "Info",
        f"IR-Readiness: /tmp on separate mount",
        severity="Low",
        details=f"/tmp is a separate mount: {tmp_separate}",
        remediation=(
            "Mount /tmp as tmpfs with nodev,nosuid,noexec via /etc/fstab"
        ),
        cross_references={
            "EDR": "TmpSeparate", "NIST": "SC-39", "CIS": "1.1.2.1",
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
        results.extend(_check_falco(os_info))
        results.extend(_check_wazuh_ossec(os_info))
        results.extend(_check_auditbeat(os_info))
        results.extend(_check_sysdig_tracee(os_info))
        results.extend(_check_commercial_edr(os_info))
        results.extend(_check_ebpf_capabilities(os_info))
        results.extend(_check_fim_indicators(os_info))
        results.extend(_check_ir_readiness(os_info))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled exception in EDR module")
        results.append(_r(
            "EDR - Error", "Error",
            f"EDR module encountered an unhandled exception: {exc!r}",
            severity="Medium", details=str(exc),
        ))

    return results



# ===========================================================================
# v3.1 EXPANSION - EDR Comprehensive Vendor & Capability Coverage
# ---------------------------------------------------------------------------
# Adds:
#   - Sophos, ESET, Trend Micro, McAfee additional vendors
#   - Falco rule depth + output configuration
#   - Wazuh ruleset + active response config
#   - Sysmon for Linux (sysmonForLinux)
#   - osquery presence
#   - ATT&CK technique coverage mapping
#   - IR readiness extended (memory acquisition, network capture)
# ===========================================================================


def _check_additional_vendors(os_info) -> List[AuditResult]:
    """Additional commercial EDR vendors."""
    results: List[AuditResult] = []
    cat = "EDR - Commercial Vendors Extended"

    vendors = {
        "Sophos Linux Sensor": file_exists("/opt/sophos-spl/bin/sophos_threat_detector"),
        "ESET File Security": file_exists("/opt/eset/efs/sbin/efs"),
        "Trend Micro Deep Security": file_exists("/opt/ds_agent"),
        "McAfee MVISION ENS": file_exists("/opt/McAfee/ens"),
        "TippingPoint TPS": directory_exists("/opt/tippingpoint"),
        "BitDefender GravityZone": file_exists("/opt/BitDefender/var"),
        "Symantec/Norton CES": directory_exists("/opt/Symantec"),
        "Kaspersky Endpoint Security": directory_exists("/opt/kaspersky/kesl"),
    }
    detected = [k for k, v in vendors.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Info",
        f"Commercial EDR vendor detection: {len(detected)} found",
        severity="Informational",
        details=f"Detected: {detected or 'none in extended vendor list'}",
        remediation=(
            "Verify enterprise EDR is deployed per organizational policy."
        ),
        cross_references={
            "EDR": "Vendor-Coverage", "NIST": "SI-3(2)",
        },
    ))

    return results


def _check_falco_extended(os_info) -> List[AuditResult]:
    """Falco extended depth - rules, outputs, kernel module."""
    results: List[AuditResult] = []
    if not command_available("falco"):
        return results

    cat = "EDR - Falco Extended"

    # Falco engine type (eBPF preferred over kernel module)
    falco_conf = read_file_safe("/etc/falco/falco.yaml")
    if falco_conf:
        ebpf_enabled = (
            "modern_bpf" in falco_conf or
            "ebpf_probe" in falco_conf or
            "modern-bpf" in falco_conf or
            "engine: modern" in falco_conf
        )
        results.append(_r(
            cat, "Pass" if ebpf_enabled else "Info",
            f"Falco engine type (eBPF preferred): {'modern-eBPF' if ebpf_enabled else 'legacy kmod'}",
            severity="Low",
            details=f"modern_bpf in config: {ebpf_enabled}",
            remediation=(
                "In /etc/falco/falco.yaml: engine.kind: modern_ebpf "
                "(better security/portability than kernel module)"
            ),
            cross_references={
                "EDR": "Falco-Engine", "NIST": "SI-4",
            },
        ))

        # Output channels
        outputs_to_check = [
            ("file_output", "log file"),
            ("syslog_output", "syslog"),
            ("http_output", "HTTP webhook"),
            ("program_output", "external program"),
            ("grpc_output", "gRPC"),
        ]
        outputs_enabled = []
        for key, name in outputs_to_check:
            # Look for "<key>:\n  enabled: true" pattern
            pattern = re.compile(
                rf"{re.escape(key)}:\s*\n(\s+\S+:\s*\S+\n)*\s+enabled:\s*true",
                re.MULTILINE
            )
            if pattern.search(falco_conf):
                outputs_enabled.append(name)

        results.append(_r(
            cat, "Pass" if outputs_enabled else "Warning",
            f"Falco output channels enabled ({len(outputs_enabled)})",
            severity="Medium",
            details=f"Outputs: {outputs_enabled or 'none configured'}",
            remediation=(
                "Configure file/syslog/http output in /etc/falco/falco.yaml. "
                "Forward to SIEM for correlation."
            ),
            cross_references={
                "EDR": "Falco-Output", "NIST": "AU-6",
            },
        ))

    # Custom rule files
    rules_d = list_directory("/etc/falco/rules.d")
    custom_rules_count = len([f for f in rules_d if f.endswith(".yaml") or f.endswith(".yml")])
    results.append(_r(
        cat, "Info",
        f"Falco custom rule files in /etc/falco/rules.d: {custom_rules_count}",
        severity="Informational",
        details=f"Custom rule files: {custom_rules_count}",
        remediation=(
            "Add custom rules in /etc/falco/rules.d/<env>-rules.yaml"
        ),
        cross_references={
            "EDR": "Falco-Rules", "NIST": "SI-4(13)",
        },
    ))

    return results


def _check_wazuh_extended(os_info) -> List[AuditResult]:
    """Wazuh agent extended depth."""
    results: List[AuditResult] = []
    ossec_conf_path = "/var/ossec/etc/ossec.conf"
    if not file_exists(ossec_conf_path):
        return results

    cat = "EDR - Wazuh Extended"

    ossec_conf = read_file_safe(ossec_conf_path)

    # FIM enabled
    fim_enabled = "<syscheck>" in ossec_conf and "<disabled>no</disabled>" in ossec_conf
    fim_section = re.search(r"<syscheck>(.*?)</syscheck>", ossec_conf, re.DOTALL)
    fim_dirs = []
    if fim_section:
        fim_dirs = re.findall(r"<directories[^>]*>([^<]+)</directories>", fim_section.group(1))
    results.append(_r(
        cat, "Pass" if fim_enabled and fim_dirs else "Warning",
        f"Wazuh FIM (syscheck) enabled with directories ({len(fim_dirs)})",
        severity="Medium",
        details=f"FIM enabled: {fim_enabled}, monitored dirs: {len(fim_dirs)}",
        remediation=(
            "In /var/ossec/etc/ossec.conf: ensure <syscheck> block contains "
            "<directories check_all=\"yes\" report_changes=\"yes\">/etc,/usr/bin,...</directories>"
        ),
        cross_references={
            "EDR": "Wazuh-FIM", "NIST": "SI-7", "PCI-DSS": "11.5.2",
        },
    ))

    # Rootcheck
    rootcheck = "<rootcheck>" in ossec_conf
    results.append(_r(
        cat, "Pass" if rootcheck else "Warning",
        "Wazuh rootcheck (rootkit detection) configured",
        severity="Medium",
        details=f"<rootcheck> block present: {rootcheck}",
        remediation=(
            "Ensure <rootcheck>...</rootcheck> with frequency configured"
        ),
        cross_references={
            "EDR": "Wazuh-Rootcheck", "NIST": "SI-3",
        },
    ))

    # SCA (Security Configuration Assessment)
    sca = "<sca>" in ossec_conf
    results.append(_r(
        cat, "Pass" if sca else "Info",
        "Wazuh SCA (Security Configuration Assessment) enabled",
        severity="Medium",
        details=f"<sca> block present: {sca}",
        remediation=(
            "SCA performs CIS Benchmark scans automatically. "
            "Enable in ossec.conf <sca><enabled>yes</enabled>...</sca>"
        ),
        cross_references={
            "EDR": "Wazuh-SCA", "NIST": "CA-7", "CIS": "Various",
        },
    ))

    # Active response
    active_response = "<active-response>" in ossec_conf
    results.append(_r(
        cat, "Pass" if active_response else "Info",
        "Wazuh active response (IPS) configured",
        severity="Medium",
        details=f"<active-response> block: {active_response}",
        remediation=(
            "Configure active response for automatic blocking on threat detection. "
            "Default actions: firewall-drop, host-deny."
        ),
        cross_references={
            "EDR": "Wazuh-AR", "NIST": "IR-4(1)",
        },
    ))

    # Vulnerability detector
    vuln_detector = "<vulnerability-detector>" in ossec_conf
    results.append(_r(
        cat, "Pass" if vuln_detector else "Info",
        "Wazuh vulnerability detector module enabled",
        severity="Medium",
        details=f"<vulnerability-detector>: {vuln_detector}",
        remediation=(
            "Enable in ossec.conf: <vulnerability-detector><enabled>yes</enabled>..."
        ),
        cross_references={
            "EDR": "Wazuh-Vuln", "NIST": "RA-5",
        },
    ))

    # Manager connectivity (server defined)
    manager_match = re.search(r"<address>([^<]+)</address>", ossec_conf)
    manager_address = manager_match.group(1) if manager_match else None
    results.append(_r(
        cat, "Pass" if manager_address else "Fail",
        "Wazuh agent points to manager address",
        severity="High",
        details=f"Manager address: {manager_address or 'NOT CONFIGURED'}",
        remediation=(
            "In ossec.conf <client><server><address>wazuh-mgr.example.com</address>..."
        ),
        cross_references={
            "EDR": "Wazuh-Manager", "NIST": "AU-6(3)",
        },
    ))

    return results


def _check_osquery(os_info) -> List[AuditResult]:
    """osquery for endpoint visibility."""
    results: List[AuditResult] = []
    if not command_available("osqueryd") and not command_available("osqueryi"):
        return results

    cat = "EDR - osquery"

    osqueryd_active = systemd_active("osqueryd.service") == "active"
    results.append(_r(
        cat, "Pass" if osqueryd_active else "Info",
        f"osqueryd daemon active: {osqueryd_active}",
        severity="Medium",
        details=f"osqueryd state: {systemd_active('osqueryd.service')}",
        remediation=remediation_for("osquery"),
        cross_references={
            "EDR": "Osquery", "NIST": "SI-4",
        },
    ))

    # Configuration depth
    osquery_conf = read_file_safe("/etc/osquery/osquery.conf")
    if osquery_conf:
        has_packs = "\"packs\"" in osquery_conf
        results.append(_r(
            cat, "Pass" if has_packs else "Warning",
            "osquery query packs configured",
            severity="Low",
            details=f"Packs section in config: {has_packs}",
            remediation=(
                "Add osquery-packs: dnf install osquery-packs (or download). "
                "Reference in /etc/osquery/osquery.conf 'packs' section."
            ),
            cross_references={
                "EDR": "Osquery-Packs", "NIST": "SI-4(2)",
            },
        ))

    return results


def _check_sysmon_for_linux(os_info) -> List[AuditResult]:
    """Sysmon for Linux."""
    results: List[AuditResult] = []
    cat = "EDR - Sysmon for Linux"

    sysmon_present = command_available("sysmon") or file_exists("/opt/sysmon/sysmon")
    sysmon_active = systemd_active("sysmon.service") == "active"

    if sysmon_present:
        results.append(_r(
            cat, "Pass" if sysmon_active else "Warning",
            f"Sysmon for Linux: present={sysmon_present}, active={sysmon_active}",
            severity="Medium",
            details=f"sysmon binary: {sysmon_present}, service: {sysmon_active}",
            remediation=(
                "Sysmon for Linux: detailed process/network/file event logging. "
                "Configure with sysmonconfig.xml, integrates with Microsoft Sentinel."
            ),
            cross_references={
                "EDR": "Sysmon", "NIST": "AU-2", "ISO27001": "A.8.15",
            },
        ))

    return results


def _check_attack_coverage(os_info) -> List[AuditResult]:
    """ATT&CK technique coverage indicators."""
    results: List[AuditResult] = []
    cat = "EDR - ATT&CK Coverage"

    # T1003 OS Credential Dumping detection (auditd watching /etc/shadow)
    audit_rules = read_file_safe("/etc/audit/audit.rules")
    rules_d = list_directory("/etc/audit/rules.d", suffix=".rules")
    for rf in rules_d:
        audit_rules += "\n" + read_file_safe(os.path.join("/etc/audit/rules.d", rf))

    shadow_audited = "/etc/shadow" in audit_rules
    results.append(_r(
        cat, "Pass" if shadow_audited else "Fail",
        "T1003: Credential dumping detection (/etc/shadow audited)",
        severity="High",
        details=f"/etc/shadow watch rule: {shadow_audited}",
        remediation=(
            "Add to /etc/audit/rules.d/30-credentials.rules: "
            "-w /etc/shadow -p wa -k creds"
        ),
        cross_references={
            "EDR": "ATTACK-T1003", "NIST": "AU-2", "MITRE": "T1003.008",
        },
    ))

    # T1059 Command and Scripting Interpreter detection
    bash_history_audited = (
        ".bash_history" in audit_rules or
        "/usr/bin/bash" in audit_rules or
        "/usr/bin/sh" in audit_rules
    )
    results.append(_r(
        cat, "Info",
        f"T1059: Shell execution audit indicators: {bash_history_audited}",
        severity="Informational",
        details=f"Shell audit rules present: {bash_history_audited}",
        remediation=(
            "Add: -a always,exit -F path=/usr/bin/bash -F perm=x -F auid>=1000 "
            "-F auid!=4294967295 -k shell_exec"
        ),
        cross_references={
            "EDR": "ATTACK-T1059", "MITRE": "T1059.004",
        },
    ))

    # T1543 Persistence via systemd services
    audit_systemd_writes = "/etc/systemd/system" in audit_rules
    results.append(_r(
        cat, "Pass" if audit_systemd_writes else "Warning",
        "T1543.002: systemd service modification audited",
        severity="Medium",
        details=f"systemd dir watch: {audit_systemd_writes}",
        remediation=(
            "-w /etc/systemd/system -p wa -k systemd_persistence"
        ),
        cross_references={
            "EDR": "ATTACK-T1543", "MITRE": "T1543.002",
        },
    ))

    # T1136 Account Creation detection
    passwd_audited = "/etc/passwd" in audit_rules and "wa" in audit_rules
    results.append(_r(
        cat, "Pass" if passwd_audited else "Fail",
        "T1136: New account creation detection (/etc/passwd audited)",
        severity="High",
        details=f"/etc/passwd watch rule: {passwd_audited}",
        remediation=(
            "Add to /etc/audit/rules.d/30-identity.rules: "
            "-w /etc/passwd -p wa -k identity"
        ),
        cross_references={
            "EDR": "ATTACK-T1136", "MITRE": "T1136",
        },
    ))

    # T1071 Application Layer Protocol detection (network monitoring)
    network_monitoring = (
        command_available("suricata") or
        command_available("snort") or
        command_available("zeek") or
        command_available("ntopng")
    )
    results.append(_r(
        cat, "Pass" if network_monitoring else "Info",
        f"T1071: Network protocol monitoring tooling: {network_monitoring}",
        severity="Low",
        details=f"Network IDS detected: {network_monitoring}",
        remediation=(
            "Deploy Suricata or Zeek for network-layer detection of "
            "application protocol abuse."
        ),
        cross_references={
            "EDR": "ATTACK-T1071", "MITRE": "T1071",
        },
    ))

    return results


def _check_ir_extended(os_info) -> List[AuditResult]:
    """Incident response readiness extended."""
    results: List[AuditResult] = []
    cat = "EDR - IR Extended"

    # Memory acquisition tooling
    mem_tools = {
        "lime": file_exists("/lib/modules/$(uname -r)/extra/lime.ko") or
                command_available("lime"),
        "avml": command_available("avml"),
        "linpmem": command_available("linpmem"),
    }
    detected_mem = [k for k, v in mem_tools.items() if v]
    results.append(_r(
        cat, "Info",
        f"IR: Memory acquisition tooling ({len(detected_mem)} found)",
        severity="Informational",
        details=f"Memory tools: {detected_mem}",
        remediation=(
            "For IR: install AVML (Microsoft's tool): "
            "wget https://github.com/microsoft/avml/releases/...; "
            "or LiME kernel module."
        ),
        cross_references={
            "EDR": "IR-Memory", "NIST": "IR-4",
        },
    ))

    # Disk imaging tools
    disk_tools = {
        "dc3dd": command_available("dc3dd"),
        "ddrescue": command_available("ddrescue"),
        "dcfldd": command_available("dcfldd"),
        "guymager": command_available("guymager"),
    }
    detected_disk = [k for k, v in disk_tools.items() if v]
    results.append(_r(
        cat, "Info",
        f"IR: Disk imaging tools ({len(detected_disk)} found)",
        severity="Informational",
        details=f"Disk tools: {detected_disk}",
        remediation=(
            "For forensic disk imaging: apt-get install -y dc3dd"
        ),
        cross_references={
            "EDR": "IR-Disk", "NIST": "IR-4",
        },
    ))

    # Network packet capture tools
    pcap_tools = {
        "tcpdump": command_available("tcpdump"),
        "tshark": command_available("tshark"),
        "dumpcap": command_available("dumpcap"),
    }
    detected_pcap = [k for k, v in pcap_tools.items() if v]
    results.append(_r(
        cat, "Pass" if detected_pcap else "Warning",
        f"IR: Network packet capture tooling ({len(detected_pcap)})",
        severity="Low",
        details=f"PCAP tools: {detected_pcap}",
        remediation="apt-get install -y tcpdump tshark",
        cross_references={
            "EDR": "IR-Network", "NIST": "IR-4",
        },
    ))

    # Live process inspection tools
    proc_tools = {
        "lsof": command_available("lsof"),
        "ss": command_available("ss"),
        "strace": command_available("strace"),
        "lsns": command_available("lsns"),
        "psmisc": command_available("pstree"),
    }
    detected_proc = [k for k, v in proc_tools.items() if v]
    results.append(_r(
        cat, "Pass" if len(detected_proc) >= 4 else "Warning",
        f"IR: Process inspection tools ({len(detected_proc)} found)",
        severity="Low",
        details=f"Process tools: {detected_proc}",
        remediation="apt-get install -y lsof psmisc strace",
        cross_references={
            "EDR": "IR-Process", "NIST": "IR-4",
        },
    ))

    return results


def _check_ebpf_extended(os_info) -> List[AuditResult]:
    """eBPF capability extended."""
    results: List[AuditResult] = []
    cat = "EDR - eBPF Extended"

    # bpftool present
    bpftool_present = command_available("bpftool")
    results.append(_r(
        cat, "Pass" if bpftool_present else "Info",
        f"bpftool available for eBPF inspection: {bpftool_present}",
        severity="Low",
        details=f"bpftool command: {bpftool_present}",
        remediation=(
            "apt-get install -y linux-tools-common linux-tools-$(uname -r)"
        ),
        cross_references={
            "EDR": "eBPF-Tools", "NIST": "SI-4",
        },
    ))

    # BPF LSM enabled (Linux 5.7+)
    lsm_path = "/sys/kernel/security/lsm"
    if file_exists(lsm_path):
        lsm_content = read_file_safe(lsm_path).strip()
        bpf_lsm = "bpf" in lsm_content
        results.append(_r(
            cat, "Pass" if bpf_lsm else "Info",
            f"BPF LSM enabled: {bpf_lsm}",
            severity="Low",
            details=f"Active LSMs: {lsm_content}",
            remediation=(
                "Boot with kernel parameter: lsm=bpf,lockdown,yama,integrity,..."
            ),
            cross_references={
                "EDR": "BPF-LSM", "NIST": "SC-39",
            },
        ))

    # Number of loaded BPF programs (operational visibility)
    if bpftool_present:
        rc, out, _ = run_command(["bpftool", "prog", "show"], timeout=5.0)
        if rc == 0:
            prog_count = sum(1 for line in out.splitlines() if line.startswith("0:") or
                            re.match(r"^\d+:", line))
            results.append(_r(
                cat, "Info",
                f"BPF programs loaded: {prog_count}",
                severity="Informational",
                details=f"Loaded eBPF programs: {prog_count}",
                cross_references={
                    "EDR": "BPF-Programs", "NIST": "SI-4",
                },
            ))

    return results


# Save reference to original
_original_run_checks_edr = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the expanded EDR module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_edr(shared_data)

    os_info = shared_data.get("v3_os_info")
    if os_info is None:
        os_info = os_detection.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        results.extend(_check_additional_vendors(os_info))
        results.extend(_check_falco_extended(os_info))
        results.extend(_check_wazuh_extended(os_info))
        results.extend(_check_osquery(os_info))
        results.extend(_check_sysmon_for_linux(os_info))
        results.extend(_check_attack_coverage(os_info))
        results.extend(_check_ir_extended(os_info))
        results.extend(_check_ebpf_extended(os_info))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled exception in EDR v3.1 expansion")
        results.append(_r(
            "EDR - Error", "Error",
            f"EDR v3.1 expansion exception: {exc!r}",
            severity="Medium", details=str(exc),
        ))

    return results

# ===========================================================================
# v3.2 EXPANSION - EDR Additional Coverage
# ---------------------------------------------------------------------------
# Adds:
#   - Additional vendors (Trellix, Tanium, Cortex XDR, BlackBerry CylancePROTECT,
#     Carbon Black Cloud, Cybereason, Fortinet FortiEDR)
#   - ATT&CK technique coverage matrix
#   - eBPF LSM and BPF tooling
#   - Threat-intelligence integration (MISP, YARA, Sigma)
#   - Telemetry pipelines (Vector, Fluent Bit, Cribl)
#   - SIEM forwarding (Splunk, Sentinel, Elastic, etc.)
#   - DFIR runbook readiness
#   - Runtime kernel hardening
# ===========================================================================


def _check_edr_additional_vendors_v32(os_info) -> List[AuditResult]:
    """Additional commercial EDR vendor detection (v3.2)."""
    results: List[AuditResult] = []
    cat = "EDR - Vendors Extended v3.2"

    vendors = {
        "Trellix-ENS": (
            file_exists("/opt/McAfee/ens/tp/bin") or
            directory_exists("/opt/McAfee/ens") or
            file_exists("/opt/Trellix/ens/tp/bin")
        ),
        "Tanium": (
            file_exists("/opt/Tanium/TaniumClient/TaniumClient") or
            directory_exists("/opt/Tanium")
        ),
        "Cortex-XDR": (
            file_exists("/opt/traps/bin/cytool") or
            directory_exists("/opt/traps") or
            directory_exists("/etc/panw")
        ),
        "Cylance-PROTECT": (
            directory_exists("/opt/cylance") or
            file_exists("/opt/cylance/desktop/CylanceSvc")
        ),
        "Carbon-Black-Cloud": (
            file_exists("/opt/carbonblack/psc/bin/cbagentd") or
            directory_exists("/opt/carbonblack")
        ),
        "Cybereason": (
            file_exists("/opt/cybereason/active-probe/CybereasonActiveProbe") or
            directory_exists("/opt/cybereason")
        ),
        "FortiEDR": (
            directory_exists("/opt/FortiEDRCollector") or
            file_exists("/opt/FortiEDRCollector/scripts/fortiedr.sh")
        ),
        "Trend-Micro-DSA": (
            file_exists("/opt/TrendMicro/DSA/dsa_control") or
            directory_exists("/opt/TrendMicro")
        ),
        "Symantec-DLP": (
            file_exists("/opt/Symantec/dlp/Agent/edpa") or
            directory_exists("/opt/Symantec/dlp")
        ),
        "Bitdefender-GravityZone": (
            directory_exists("/opt/Bitdefender") or
            file_exists("/opt/Bitdefender/bin/bdsec")
        ),
    }
    detected = [k for k, v in vendors.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Info",
        f"Commercial EDR vendor footprint ({len(detected)} detected)",
        severity="High" if not detected else "Informational",
        details=f"Detected vendors: {detected or 'none'}",
        remediation=(
            "If no commercial EDR present, consider Microsoft Defender for "
            "Endpoint (Linux), CrowdStrike Falcon, SentinelOne, or open-source "
            "Wazuh + Falco for runtime detection."
        ),
        cross_references={
            "EDR": "Vendor-Coverage", "NIST": "SI-3", "PCI-DSS": "5.2",
            "HIPAA": "164.308(a)(1)(ii)(D)",
        },
    ))

    return results


def _check_edr_attack_coverage_extended(os_info) -> List[AuditResult]:
    """Extended ATT&CK technique coverage check."""
    results: List[AuditResult] = []
    cat = "EDR - ATT&CK Coverage v3.2"

    auditd_rules = read_file_safe("/etc/audit/audit.rules")
    rules_d_files = list_directory("/etc/audit/rules.d", suffix=".rules")
    combined_rules = auditd_rules
    for f in rules_d_files:
        combined_rules += "\n" + read_file_safe(os.path.join("/etc/audit/rules.d", f))

    techniques = {
        "T1059.004-Bash": "execve" in combined_rules.lower(),
        "T1003-Credential-Dumping": "/etc/shadow" in combined_rules,
        "T1547.001-RcCommon": (
            "/etc/rc.local" in combined_rules or
            "/etc/init.d" in combined_rules
        ),
        "T1543.002-Systemd": (
            "systemd" in combined_rules.lower() and "/etc/systemd" in combined_rules
        ),
        "T1546.004-BashInit": (
            "/etc/profile" in combined_rules or
            "/etc/bashrc" in combined_rules or
            "/etc/bash.bashrc" in combined_rules
        ),
        "T1098-AccountManipulation": (
            "/etc/passwd" in combined_rules or
            "/etc/group" in combined_rules
        ),
        "T1110-BruteForce": (
            file_exists("/etc/fail2ban/jail.local") or
            file_exists("/etc/fail2ban/jail.conf")
        ),
        "T1136-CreateAccount": (
            "useradd" in combined_rules or
            "groupadd" in combined_rules
        ),
        "T1070-IndicatorRemoval": (
            "/var/log" in combined_rules or
            "wtmp" in combined_rules
        ),
        "T1562-ImpairDefenses": (
            "auditctl" in combined_rules or
            "iptables" in combined_rules or
            "/etc/selinux" in combined_rules
        ),
        "T1078-ValidAccounts": (
            "pam" in combined_rules.lower() or
            "logins" in combined_rules.lower()
        ),
        "T1574.006-LdPreload": (
            "/etc/ld.so.preload" in combined_rules
        ),
    }
    covered = [k for k, v in techniques.items() if v]

    results.append(_r(
        cat, "Pass" if len(covered) >= 8 else "Warning",
        f"ATT&CK Technique coverage via auditd ({len(covered)}/{len(techniques)})",
        severity="High",
        details=f"Covered: {covered}",
        remediation=(
            "Extend audit rules to cover MITRE ATT&CK Linux techniques. "
            "Use Neo23x0/auditd ruleset as starting point."
        ),
        cross_references={
            "EDR": "ATT&CK-Coverage", "NIST": "SI-4(2)",
            "MITRE": "ATT&CK-Linux-Matrix",
        },
    ))

    sshd_log_level = re.search(
        r"^\s*LogLevel\s+(\S+)", read_file_safe("/etc/ssh/sshd_config"), re.MULTILINE
    )
    log_level = sshd_log_level.group(1).upper() if sshd_log_level else "INFO"
    log_level_ok = log_level in ("VERBOSE", "DEBUG", "DEBUG1", "DEBUG2", "DEBUG3")
    results.append(_r(
        cat, "Pass" if log_level_ok else "Warning",
        f"T1021.004 SSH lateral-movement logging (LogLevel={log_level})",
        severity="Medium",
        details=f"sshd LogLevel = {log_level}",
        remediation=(
            "In /etc/ssh/sshd_config: LogLevel VERBOSE  "
            "(captures key fingerprints used for authentication)"
        ),
        cross_references={
            "EDR": "ATT&CK-T1021", "NIST": "AU-2", "STIG": "V-230230",
        },
    ))

    return results


def _check_edr_ebpf_lsm(os_info) -> List[AuditResult]:
    """eBPF LSM (BPF Linux Security Module) indicators."""
    results: List[AuditResult] = []
    cat = "EDR - eBPF LSM v3.2"

    lsm_active = read_file_safe("/sys/kernel/security/lsm").strip()
    bpf_lsm_present = "bpf" in lsm_active.split(",")
    results.append(_r(
        cat, "Pass" if bpf_lsm_present else "Info",
        f"BPF LSM enabled in kernel: {bpf_lsm_present}",
        severity="Medium",
        details=f"Active LSMs: {lsm_active or '(unable to read)'}",
        remediation=(
            "Enable BPF LSM at boot: add 'lsm=lockdown,yama,bpf,...' to "
            "GRUB_CMDLINE_LINUX in /etc/default/grub. Kernel 5.7+ required."
        ),
        cross_references={
            "EDR": "eBPF-LSM", "NIST": "SC-7", "MITRE": "M1038",
        },
    ))

    bpftool = command_available("bpftool")
    results.append(_r(
        cat, "Pass" if bpftool else "Warning",
        f"bpftool installed: {bpftool}",
        severity="Low",
        details=f"bpftool available: {bpftool}",
        remediation=(
            "apt-get install -y bpftool (Debian/Ubuntu) or "
            "dnf install -y bpftool (RHEL family)"
        ),
        cross_references={
            "EDR": "eBPF-Tooling", "NIST": "SI-4",
        },
    ))

    bcc_tools = command_available("execsnoop") or command_available(
        "execsnoop-bpfcc"
    ) or directory_exists("/usr/share/bcc")
    results.append(_r(
        cat, "Pass" if bcc_tools else "Info",
        f"BCC (BPF Compiler Collection) installed: {bcc_tools}",
        severity="Low",
        details=f"BCC tools detected: {bcc_tools}",
        remediation=(
            "apt-get install -y bpfcc-tools  (provides execsnoop, opensnoop, etc.)"
        ),
        cross_references={
            "EDR": "BCC-Tooling",
        },
    ))

    tetragon = (
        directory_exists("/etc/tetragon") or
        systemd_active("tetragon.service") == "active" or
        command_available("tetra")
    )
    results.append(_r(
        cat, "Pass" if tetragon else "Info",
        f"Tetragon eBPF security observability: {tetragon}",
        severity="Medium",
        details=f"Tetragon detected: {tetragon}",
        remediation=(
            "Tetragon (https://tetragon.io/) provides eBPF-based runtime "
            "security and observability. Install via Helm or systemd."
        ),
        cross_references={
            "EDR": "Tetragon", "MITRE": "M1038",
        },
    ))

    return results


def _check_edr_threat_intelligence(os_info) -> List[AuditResult]:
    """Threat Intelligence integration indicators."""
    results: List[AuditResult] = []
    cat = "EDR - Threat Intelligence v3.2"

    misp_indicators = {
        "misp-modules": directory_exists("/var/www/MISP") or directory_exists(
            "/opt/MISP"
        ),
        "misp-client": command_available("pymisp") or file_exists(
            "/usr/local/bin/misp_query"
        ),
    }
    detected_misp = [k for k, v in misp_indicators.items() if v]
    results.append(_r(
        cat, "Info",
        f"MISP threat intelligence integration: {detected_misp or 'none'}",
        severity="Informational",
        details=f"MISP indicators: {detected_misp}",
        remediation=(
            "Deploy MISP on dedicated server. Subscribe to circl.lu MISP feeds "
            "for IOC ingestion."
        ),
        cross_references={
            "EDR": "TI-MISP", "NIST": "PM-15",
        },
    ))

    yara_indicators = {
        "yara-binary": command_available("yara"),
        "yara-rules": (
            directory_exists("/etc/yara") or
            directory_exists("/var/lib/yara") or
            directory_exists("/opt/yara-rules")
        ),
        "loki-scanner": (
            directory_exists("/opt/loki") or
            command_available("loki.py")
        ),
    }
    detected_yara = [k for k, v in yara_indicators.items() if v]
    results.append(_r(
        cat, "Pass" if detected_yara else "Info",
        f"YARA scanning capability ({len(detected_yara)} indicators)",
        severity="Medium",
        details=f"YARA: {detected_yara}",
        remediation=(
            "Install YARA: apt-get install -y yara. Pull rules: "
            "git clone https://github.com/Yara-Rules/rules /opt/yara-rules"
        ),
        cross_references={
            "EDR": "TI-YARA", "NIST": "SI-3",
        },
    ))

    sigma_indicators = {
        "sigmac": command_available("sigmac"),
        "pysigma": command_available("sigma-cli"),
        "sigma-rules-dir": (
            directory_exists("/opt/sigma") or
            directory_exists("/var/lib/sigma")
        ),
    }
    detected_sigma = [k for k, v in sigma_indicators.items() if v]
    results.append(_r(
        cat, "Info",
        f"Sigma detection rule capability: {detected_sigma or 'none'}",
        severity="Informational",
        details=f"Sigma: {detected_sigma}",
        remediation=(
            "Sigma rules in CSC repository: github.com/SigmaHQ/sigma. "
            "Convert to backend (Splunk, Elastic, etc.) via sigma-cli."
        ),
        cross_references={
            "EDR": "TI-Sigma", "NIST": "SI-4",
        },
    ))

    return results


def _check_edr_telemetry_pipeline(os_info) -> List[AuditResult]:
    """Telemetry pipeline / log shipper detection."""
    results: List[AuditResult] = []
    cat = "EDR - Telemetry Pipeline v3.2"

    pipelines = {
        "filebeat": (
            file_exists("/etc/filebeat/filebeat.yml") or
            systemd_active("filebeat.service") == "active"
        ),
        "auditbeat": (
            file_exists("/etc/auditbeat/auditbeat.yml") or
            systemd_active("auditbeat.service") == "active"
        ),
        "metricbeat": (
            file_exists("/etc/metricbeat/metricbeat.yml") or
            systemd_active("metricbeat.service") == "active"
        ),
        "fluentd": (
            file_exists("/etc/fluentd/fluentd.conf") or
            systemd_active("fluentd.service") == "active"
        ),
        "fluent-bit": (
            file_exists("/etc/fluent-bit/fluent-bit.conf") or
            systemd_active("fluent-bit.service") == "active"
        ),
        "vector": (
            file_exists("/etc/vector/vector.toml") or
            file_exists("/etc/vector/vector.yaml") or
            systemd_active("vector.service") == "active"
        ),
        "cribl": (
            directory_exists("/opt/cribl") or
            systemd_active("cribl.service") == "active"
        ),
        "logstash": (
            file_exists("/etc/logstash/logstash.yml") or
            systemd_active("logstash.service") == "active"
        ),
        "rsyslog-omfwd": False,
        "syslog-ng": (
            file_exists("/etc/syslog-ng/syslog-ng.conf") or
            systemd_active("syslog-ng.service") == "active"
        ),
        "nxlog": (
            file_exists("/etc/nxlog/nxlog.conf") or
            systemd_active("nxlog.service") == "active"
        ),
    }
    rsyslog_d = list_directory("/etc/rsyslog.d", suffix=".conf")
    for f in rsyslog_d + ["/etc/rsyslog.conf"]:
        path = f if f == "/etc/rsyslog.conf" else os.path.join("/etc/rsyslog.d", f)
        c = read_file_safe(path)
        if "@@" in c or "omfwd" in c or "omrelp" in c or "omkafka" in c:
            pipelines["rsyslog-omfwd"] = True
            break

    detected = [k for k, v in pipelines.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Fail",
        f"Telemetry pipeline shippers ({len(detected)} detected)",
        severity="High",
        details=f"Active: {detected or 'none'}",
        remediation=(
            "Deploy at least one shipper: Vector (modern, Rust-based) or "
            "Fluent Bit (lightweight) for centralized log aggregation."
        ),
        cross_references={
            "EDR": "Telemetry-Shipper", "NIST": "AU-6(3)", "PCI-DSS": "10.5",
        },
    ))

    return results


def _check_edr_siem_integration(os_info) -> List[AuditResult]:
    """SIEM integration / forwarding indicators."""
    results: List[AuditResult] = []
    cat = "EDR - SIEM Integration v3.2"

    siems = {
        "Splunk-Forwarder": (
            file_exists("/opt/splunkforwarder/bin/splunk") or
            directory_exists("/opt/splunkforwarder")
        ),
        "Elastic-Agent": (
            file_exists("/opt/Elastic/Agent/elastic-agent") or
            directory_exists("/opt/Elastic/Agent")
        ),
        "QRadar-Agent": directory_exists("/opt/qradar"),
        "ArcSight-Connector": directory_exists("/opt/arcsight"),
        "LogRhythm-Agent": directory_exists("/opt/logrhythm"),
        "Sumo-Logic": (
            directory_exists("/opt/SumoCollector") or
            file_exists("/opt/SumoCollector/collector")
        ),
        "DataDog-Agent": (
            systemd_active("datadog-agent.service") == "active" or
            directory_exists("/etc/datadog-agent")
        ),
        "Sentinel-AMA": (
            directory_exists("/opt/microsoft/azuremonitoragent") or
            systemd_active("azuremonitoragent.service") == "active"
        ),
        "Chronicle-Forwarder": directory_exists("/opt/chronicle"),
        "Devo-Relay": directory_exists("/opt/devo"),
    }
    detected = [k for k, v in siems.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Info",
        f"SIEM agent/forwarder ({len(detected)} detected)",
        severity="Medium",
        details=f"Detected SIEMs: {detected or 'none'}",
        remediation=(
            "Centralize logs to enterprise SIEM (Splunk, Sentinel, Elastic, "
            "Chronicle, etc.) via dedicated forwarder."
        ),
        cross_references={
            "EDR": "SIEM-Integration", "NIST": "AU-6", "PCI-DSS": "10.6.1",
        },
    ))

    return results


def _check_edr_dfir_runbook(os_info) -> List[AuditResult]:
    """DFIR runbook readiness indicators."""
    results: List[AuditResult] = []
    cat = "EDR - DFIR Runbook v3.2"

    live_response_tools = {
        "uac": directory_exists("/opt/uac") or command_available("uac"),
        "linux-explorer": directory_exists("/opt/linux-explorer"),
        "chainsaw": command_available("chainsaw"),
        "tsk-fls": command_available("fls"),
        "tsk-mmls": command_available("mmls"),
        "log2timeline": command_available("log2timeline.py"),
        "plaso": command_available("psort.py"),
    }
    detected = [k for k, v in live_response_tools.items() if v]
    results.append(_r(
        cat, "Pass" if detected else "Info",
        f"DFIR live-response tools ({len(detected)} found)",
        severity="Medium",
        details=f"Detected: {detected or 'none'}",
        remediation=(
            "Pre-stage DFIR toolkit on critical hosts: UAC (Unix-like Artifacts "
            "Collector) is recommended. Plaso/log2timeline for timeline analysis."
        ),
        cross_references={
            "EDR": "DFIR-Tools", "NIST": "IR-4(11)",
        },
    ))

    mem_acq = {
        "avml": command_available("avml"),
        "lime": command_available("lime"),
    }
    detected_mem = [k for k, v in mem_acq.items() if v]
    results.append(_r(
        cat, "Pass" if detected_mem else "Info",
        f"Live memory acquisition ({len(detected_mem)} tools)",
        severity="Medium",
        details=f"Tools: {detected_mem or 'none'}",
        remediation=(
            "Microsoft AVML: github.com/microsoft/avml (statically-linked). "
            "Place in /opt/dfir/avml on hosts requiring memory IR."
        ),
        cross_references={
            "EDR": "DFIR-Memory", "NIST": "IR-4(11)",
        },
    ))

    netcap_tools = {
        "tcpdump": command_available("tcpdump"),
        "tshark": command_available("tshark"),
        "ngrep": command_available("ngrep"),
        "netsniff-ng": command_available("netsniff-ng"),
    }
    detected_nc = [k for k, v in netcap_tools.items() if v]
    results.append(_r(
        cat, "Pass" if detected_nc else "Warning",
        f"Network capture tools ({len(detected_nc)} found)",
        severity="Medium",
        details=f"Tools: {detected_nc}",
        remediation=(
            "apt-get install -y tcpdump tshark. Required for IR network analysis."
        ),
        cross_references={
            "EDR": "DFIR-NetCap", "NIST": "IR-4",
        },
    ))

    return results


def _check_edr_runtime_kernel(os_info) -> List[AuditResult]:
    """Runtime kernel-level detection / hardening."""
    results: List[AuditResult] = []
    cat = "EDR - Runtime Kernel v3.2"

    kaslr = read_sysctl("kernel.randomize_va_space")
    results.append(_r(
        cat, "Pass" if kaslr == "2" else "Warning",
        f"ASLR enabled (kernel.randomize_va_space = {kaslr or 'unset'})",
        severity="High",
        details=f"randomize_va_space = {kaslr}",
        remediation=(
            "echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.d/99-aslr.conf; "
            "sysctl --system"
        ),
        cross_references={
            "EDR": "Runtime-ASLR", "NIST": "SI-16", "STIG": "V-230267",
        },
    ))

    ptrace_scope = read_sysctl("kernel.yama.ptrace_scope")
    ptrace_ok = ptrace_scope in ("1", "2", "3")
    results.append(_r(
        cat, "Pass" if ptrace_ok else "Warning",
        f"Yama ptrace_scope restricted (= {ptrace_scope or 'unset'})",
        severity="High",
        details=f"kernel.yama.ptrace_scope = {ptrace_scope}",
        remediation=(
            "echo 'kernel.yama.ptrace_scope = 2' >> /etc/sysctl.d/99-yama.conf; "
            "sysctl --system. Mitigates T1055 process injection."
        ),
        cross_references={
            "EDR": "Runtime-Ptrace", "MITRE": "M1038", "NIST": "SI-7",
        },
    ))

    kexec_load = read_sysctl("kernel.kexec_load_disabled")
    results.append(_r(
        cat, "Pass" if kexec_load == "1" else "Warning",
        f"kexec_load_disabled (= {kexec_load or 'unset'})",
        severity="Medium",
        details=f"kernel.kexec_load_disabled = {kexec_load}",
        remediation=(
            "echo 'kernel.kexec_load_disabled = 1' >> /etc/sysctl.d/99-kexec.conf"
        ),
        cross_references={
            "EDR": "Runtime-kexec", "NIST": "SC-39",
        },
    ))

    mod_disabled = read_sysctl("kernel.modules_disabled")
    results.append(_r(
        cat, "Info",
        f"Kernel module loading disabled (= {mod_disabled or '0'})",
        severity="Informational",
        details=(
            f"kernel.modules_disabled = {mod_disabled}. "
            "Set to 1 only when no further module loads are required (one-way)."
        ),
        cross_references={
            "EDR": "Runtime-modules", "NIST": "CM-7",
        },
    ))

    bpf_disabled = read_sysctl("kernel.unprivileged_bpf_disabled")
    bpf_ok = bpf_disabled in ("1", "2")
    results.append(_r(
        cat, "Pass" if bpf_ok else "Warning",
        f"Unprivileged BPF disabled (= {bpf_disabled or 'unset'})",
        severity="Medium",
        details=f"kernel.unprivileged_bpf_disabled = {bpf_disabled}",
        remediation=(
            "echo 'kernel.unprivileged_bpf_disabled = 1' >> /etc/sysctl.d/99-bpf.conf"
        ),
        cross_references={
            "EDR": "Runtime-BPF", "NIST": "SC-39",
        },
    ))

    return results


# Save reference to existing run_checks
_original_run_checks_edr_v32 = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the v3.2 expanded EDR module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_edr_v32(shared_data)

    os_info = shared_data.get("v3_os_info")
    if os_info is None:
        os_info = os_detection.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        results.extend(_check_edr_additional_vendors_v32(os_info))
        results.extend(_check_edr_attack_coverage_extended(os_info))
        results.extend(_check_edr_ebpf_lsm(os_info))
        results.extend(_check_edr_threat_intelligence(os_info))
        results.extend(_check_edr_telemetry_pipeline(os_info))
        results.extend(_check_edr_siem_integration(os_info))
        results.extend(_check_edr_dfir_runbook(os_info))
        results.extend(_check_edr_runtime_kernel(os_info))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled exception in EDR v3.2 expansion")
        results.append(_r(
            "EDR - Error", "Error",
            f"EDR v3.2 expansion exception: {exc!r}",
            severity="Medium", details=str(exc),
        ))

    return results


# ===========================================================================
# v3.3 EXPANSION - EDR Comprehensive Detection Coverage
# ---------------------------------------------------------------------------
# Adds:
#   - Persistence detection (cron, systemd, /etc/profile, shell rc files)
#   - Process injection indicators (LD_PRELOAD, ptrace, procfs)
#   - Network behavior monitoring (DNS, egress, suspicious listeners)
#   - Container runtime security (Docker/Podman/K8s)
#   - Cloud-native EDR (Tetragon, Aqua, Sysdig Secure)
#   - Anti-forensics & log integrity indicators
#   - Memory protection (NX/SMEP/SMAP indicators)
#   - Auditd ruleset depth (250+ rules expected)
#   - Process accounting (acct/psacct)
# ===========================================================================


def _check_edr_persistence_detection(os_info) -> List[AuditResult]:
    """Persistence mechanism detection (MITRE ATT&CK T1543/T1547/T1053/T1546)."""
    results: List[AuditResult] = []
    cat = "EDR - Persistence Detection"

    # T1053.003 - cron jobs across all standard locations
    cron_paths = [
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron",
        "/var/spool/cron/crontabs",
    ]
    cron_locations_present = sum(
        1 for p in cron_paths if file_exists(p) or directory_exists(p)
    )

    # Count entries in /var/spool/cron(/crontabs) for user crontabs
    user_crons = 0
    for cron_dir in ["/var/spool/cron", "/var/spool/cron/crontabs"]:
        if directory_exists(cron_dir):
            user_crons += len(list_directory(cron_dir))

    results.append(_r(
        cat, "Info",
        f"EDR-PERSIST-1: cron persistence locations present ({cron_locations_present})",
        severity="Informational",
        details=f"Standard cron paths: {cron_locations_present}, user crontabs: {user_crons}",
        remediation=(
            "Audit cron entries: ls -la /etc/cron* /var/spool/cron*. "
            "Configure auditd rules: -w /etc/cron.d -p wa -k cron"
        ),
        cross_references={
            "MITRE-ATT&CK": "T1053.003", "NIST": "SI-4",
        },
    ))

    # T1543.002 - systemd unit persistence
    systemd_unit_dirs = [
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
        "/run/systemd/system",
        "/lib/systemd/system",
    ]
    user_units_dir = "/etc/systemd/user"

    custom_systemd_units = 0
    if directory_exists("/etc/systemd/system"):
        for f in list_directory("/etc/systemd/system"):
            if f.endswith((".service", ".timer", ".socket", ".path", ".mount")):
                custom_systemd_units += 1

    results.append(_r(
        cat, "Info",
        f"EDR-PERSIST-2: Custom systemd units in /etc/systemd/system ({custom_systemd_units})",
        severity="Informational",
        details=(
            f"Custom unit count: {custom_systemd_units}. Each is a persistence "
            "vector and should be auditd-monitored."
        ),
        remediation=(
            "auditd rule: -w /etc/systemd/system -p wa -k systemd_persistence"
        ),
        cross_references={
            "MITRE-ATT&CK": "T1543.002", "NIST": "SI-4",
        },
    ))

    # T1546 - shell rc files (.bashrc, .profile, /etc/profile.d/, /etc/bashrc)
    shell_rc_paths = [
        "/etc/profile",
        "/etc/bashrc",
        "/etc/bash.bashrc",
        "/etc/zsh/zshrc",
        "/etc/profile.d",
    ]
    profile_d_count = 0
    if directory_exists("/etc/profile.d"):
        profile_d_count = len([
            f for f in list_directory("/etc/profile.d") if f.endswith(".sh")
        ])
    results.append(_r(
        cat, "Info",
        f"EDR-PERSIST-3: /etc/profile.d scripts ({profile_d_count})",
        severity="Informational",
        details=f"Profile-loading scripts in /etc/profile.d: {profile_d_count}",
        remediation=(
            "auditd rules: -w /etc/profile -p wa -k shell_init; "
            "-w /etc/profile.d -p wa -k shell_init"
        ),
        cross_references={
            "MITRE-ATT&CK": "T1546.004", "NIST": "SI-4",
        },
    ))

    # T1037 - Login/logout init scripts
    init_dirs = [
        "/etc/init.d", "/etc/rc.local", "/etc/rc.d",
        "/etc/X11/xinit/xinitrc.d",
    ]
    init_present = sum(1 for p in init_dirs if file_exists(p) or directory_exists(p))
    results.append(_r(
        cat, "Info",
        f"EDR-PERSIST-4: Init script persistence locations ({init_present})",
        severity="Informational",
        details=f"Init paths: {init_present}",
        cross_references={
            "MITRE-ATT&CK": "T1037", "NIST": "SI-4",
        },
    ))

    # T1098 - SSH authorized_keys (potential persistence)
    # Simple count of root authorized_keys
    root_authkeys = "/root/.ssh/authorized_keys"
    root_authkey_count = 0
    if file_exists(root_authkeys):
        c = read_file_safe(root_authkeys)
        root_authkey_count = sum(
            1 for line in c.splitlines()
            if line.strip() and not line.startswith("#")
        )
    results.append(_r(
        cat, "Info" if root_authkey_count <= 5 else "Warning",
        f"EDR-PERSIST-5: Root SSH authorized_keys count: {root_authkey_count}",
        severity="High" if root_authkey_count > 5 else "Informational",
        details=f"/root/.ssh/authorized_keys entries: {root_authkey_count}",
        remediation=(
            "Audit and remove unknown keys. "
            "auditd rule: -w /root/.ssh -p wa -k ssh_keys"
        ),
        cross_references={
            "MITRE-ATT&CK": "T1098.004", "NIST": "AC-3",
        },
    ))

    return results


def _check_edr_process_injection_indicators(os_info) -> List[AuditResult]:
    """Process injection / unauthorized library loading indicators."""
    results: List[AuditResult] = []
    cat = "EDR - Process Injection"

    # T1574.006 - LD_PRELOAD detection
    # Check global ld.so.preload
    ldso_preload = read_file_safe("/etc/ld.so.preload")
    has_global_preload = bool(ldso_preload.strip())
    results.append(_r(
        cat, "Info" if not has_global_preload else "Warning",
        f"EDR-INJECT-1: Global ld.so.preload set: {has_global_preload}",
        severity="High" if has_global_preload else "Informational",
        details=(
            f"/etc/ld.so.preload contents: "
            f"{ldso_preload[:200] if has_global_preload else 'empty (good)'}"
        ),
        remediation=(
            "If unexpected: investigate immediately. "
            "auditd rule: -w /etc/ld.so.preload -p wa -k ld_preload"
        ),
        cross_references={
            "MITRE-ATT&CK": "T1574.006", "NIST": "SI-4",
        },
    ))

    # ld.so.conf.d entries
    ldso_d_count = 0
    if directory_exists("/etc/ld.so.conf.d"):
        ldso_d_count = len([
            f for f in list_directory("/etc/ld.so.conf.d") if f.endswith(".conf")
        ])
    results.append(_r(
        cat, "Info",
        f"EDR-INJECT-2: ld.so.conf.d entries ({ldso_d_count})",
        severity="Informational",
        details=f"Library-search-path config files: {ldso_d_count}",
        remediation=(
            "Audit unusual library paths. "
            "auditd rule: -w /etc/ld.so.conf -p wa -k libraries; "
            "-w /etc/ld.so.conf.d -p wa -k libraries"
        ),
        cross_references={
            "MITRE-ATT&CK": "T1574", "NIST": "SI-4",
        },
    ))

    # T1055 - ptrace-based injection: Yama scope check
    yama = read_sysctl("kernel.yama.ptrace_scope")
    yama_protective = yama in ("1", "2", "3")
    results.append(_r(
        cat, "Pass" if yama_protective else "Fail",
        f"EDR-INJECT-3: Yama ptrace_scope mitigates injection ({yama or '0'})",
        severity="High",
        details=f"kernel.yama.ptrace_scope = {yama}",
        remediation=(
            "echo 'kernel.yama.ptrace_scope = 1' >> /etc/sysctl.d/99-yama.conf"
        ),
        cross_references={
            "MITRE-ATT&CK": "T1055.008", "NIST": "SI-16",
        },
    ))

    # /proc/sys/kernel/protected_fifos / protected_regular
    protected_fifos = read_sysctl("fs.protected_fifos") in ("1", "2")
    protected_regular = read_sysctl("fs.protected_regular") in ("1", "2")
    proto_fr_ok = protected_fifos and protected_regular
    results.append(_r(
        cat, "Pass" if proto_fr_ok else "Warning",
        f"EDR-INJECT-4: Protected FIFOs/regular files settings",
        severity="Medium",
        details=(
            f"protected_fifos = {read_sysctl('fs.protected_fifos')}, "
            f"protected_regular = {read_sysctl('fs.protected_regular')}"
        ),
        remediation=(
            "echo 'fs.protected_fifos = 2' >> /etc/sysctl.d/99-fs.conf; "
            "echo 'fs.protected_regular = 2' >> /etc/sysctl.d/99-fs.conf"
        ),
        cross_references={
            "MITRE-ATT&CK": "T1546", "NIST": "AC-3",
        },
    ))

    return results


def _check_edr_network_behavior(os_info) -> List[AuditResult]:
    """Network behavior monitoring indicators."""
    results: List[AuditResult] = []
    cat = "EDR - Network Behavior"

    # T1071 - DNS query logging capability
    dns_logging_indicators = {
        "systemd-resolved-log": False,
        "unbound-log": file_exists("/etc/unbound/unbound.conf"),
        "dnsmasq-log": False,
        "bind-querylog": False,
    }

    # systemd-resolved
    if file_exists("/etc/systemd/resolved.conf"):
        c = read_file_safe("/etc/systemd/resolved.conf")
        if "DNS=" in c or "FallbackDNS=" in c:
            dns_logging_indicators["systemd-resolved-log"] = True

    # dnsmasq
    if file_exists("/etc/dnsmasq.conf"):
        c = read_file_safe("/etc/dnsmasq.conf")
        if "log-queries" in c:
            dns_logging_indicators["dnsmasq-log"] = True

    # bind/named
    for nf in ["/etc/named.conf", "/etc/bind/named.conf",
               "/etc/bind/named.conf.options"]:
        c = read_file_safe(nf)
        if c and "querylog" in c.lower():
            dns_logging_indicators["bind-querylog"] = True
            break

    detected_dns = [k for k, v in dns_logging_indicators.items() if v]
    results.append(_r(
        cat, "Pass" if detected_dns else "Info",
        f"EDR-NET-1: DNS resolver visibility ({len(detected_dns)} indicators)",
        severity="Medium",
        details=f"DNS visibility tools: {detected_dns}",
        remediation=(
            "Enable DNS query logging on the local resolver, or use "
            "Pi-hole / DNS firewall for centralized DNS monitoring."
        ),
        cross_references={
            "MITRE-ATT&CK": "T1071.004", "NIST": "SI-4(18)",
        },
    ))

    # Suspicious listening ports indicator (uncommon ports)
    rc, out, _ = run_command(["ss", "-tlnH"], timeout=5.0)
    listening_ports = []
    if rc == 0 and out:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                addr = parts[3]
                if ":" in addr:
                    port_str = addr.rsplit(":", 1)[-1]
                    try:
                        listening_ports.append(int(port_str))
                    except ValueError:
                        pass

    # Common ports baseline
    common_ports = {22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
                     3306, 5432, 5900, 6379, 8080, 8443, 27017}
    uncommon_listening = [p for p in listening_ports if p not in common_ports
                          and p >= 1024]
    results.append(_r(
        cat, "Info" if len(uncommon_listening) <= 3 else "Warning",
        f"EDR-NET-2: Uncommon listening ports ({len(uncommon_listening)})",
        severity="Medium",
        details=f"Non-standard listening ports: {sorted(uncommon_listening)[:10]}",
        remediation=(
            "Review with: ss -tlnpH. Document expected services. "
            "Investigate unknown listeners as potential C2."
        ),
        cross_references={
            "MITRE-ATT&CK": "T1571", "NIST": "SI-4",
        },
    ))

    # Outbound connection inspection capability
    egress_tools = {
        "iptables-LOG": False,
        "nftables-LOG": False,
        "suricata": (
            command_available("suricata") or
            file_exists("/etc/suricata/suricata.yaml")
        ),
        "zeek": (
            command_available("zeek") or
            command_available("bro") or
            file_exists("/etc/zeek/site/local.zeek")
        ),
        "snort": (
            command_available("snort") or
            file_exists("/etc/snort/snort.conf")
        ),
    }
    if command_available("iptables"):
        rc, out, _ = run_command(["iptables", "-S", "OUTPUT"], timeout=3.0)
        if rc == 0 and "LOG" in out:
            egress_tools["iptables-LOG"] = True

    detected_egress = [k for k, v in egress_tools.items() if v]
    results.append(_r(
        cat, "Pass" if detected_egress else "Info",
        f"EDR-NET-3: Egress monitoring capability ({len(detected_egress)})",
        severity="Medium",
        details=f"Detected: {detected_egress or 'none'}",
        remediation=(
            "Deploy NDR sensor: Suricata or Zeek for L7 protocol decode "
            "and threat detection."
        ),
        cross_references={
            "MITRE-ATT&CK": "T1041", "NIST": "SC-7(10)",
        },
    ))

    return results


def _check_edr_container_runtime(os_info) -> List[AuditResult]:
    """Container runtime security monitoring."""
    results: List[AuditResult] = []
    cat = "EDR - Container Runtime"

    container_runtimes = {
        "docker": command_available("docker"),
        "podman": command_available("podman"),
        "containerd": (
            command_available("containerd") or
            systemd_active("containerd.service") == "active"
        ),
        "cri-o": command_available("crio") or file_exists("/etc/crio/crio.conf"),
        "kubelet": command_available("kubelet"),
    }
    detected_rt = [k for k, v in container_runtimes.items() if v]

    if not detected_rt:
        results.append(_r(
            cat, "Info",
            "EDR-CONT-1: No container runtimes detected",
            severity="Informational",
            details="Host does not run containers",
            cross_references={"MITRE-ATT&CK": "T1610"},
        ))
        return results

    results.append(_r(
        cat, "Info",
        f"EDR-CONT-1: Container runtimes detected: {', '.join(detected_rt)}",
        severity="Informational",
        details=f"Runtimes: {detected_rt}",
        cross_references={
            "MITRE-ATT&CK": "T1610", "NIST": "SI-4",
        },
    ))

    # Container security tools
    container_security = {
        "falco": command_available("falco"),
        "tetragon": command_available("tetra") or directory_exists("/var/lib/tetragon"),
        "sysdig-secure": command_available("sysdig"),
        "tracee": command_available("tracee"),
        "aqua": directory_exists("/opt/aquasec"),
        "twistlock": directory_exists("/opt/twistlock"),
    }
    detected_cs = [k for k, v in container_security.items() if v]
    results.append(_r(
        cat, "Pass" if detected_cs else "Warning",
        f"EDR-CONT-2: Container security tools ({len(detected_cs)})",
        severity="High",
        details=f"Detected: {detected_cs or 'none'}",
        remediation=(
            "Deploy Falco for runtime security: "
            "https://falco.org/docs/getting-started/installation/. "
            "Or Tetragon (eBPF-based) for cloud-native environments."
        ),
        cross_references={
            "NIST": "SI-4", "MITRE-ATT&CK": "T1610",
        },
    ))

    # Docker daemon security configuration
    if container_runtimes["docker"]:
        docker_daemon = read_file_safe("/etc/docker/daemon.json")
        if docker_daemon:
            security_options = {
                "userns-remap": "userns-remap" in docker_daemon,
                "no-new-privileges": "no-new-privileges" in docker_daemon,
                "icc-disabled": '"icc": false' in docker_daemon,
                "log-driver-set": '"log-driver"' in docker_daemon,
                "live-restore": "live-restore" in docker_daemon,
            }
            enabled_count = sum(security_options.values())
            results.append(_r(
                cat, "Pass" if enabled_count >= 3 else "Warning",
                f"EDR-CONT-3: Docker daemon security options ({enabled_count}/5)",
                severity="High",
                details=f"Enabled: {[k for k, v in security_options.items() if v]}",
                remediation=(
                    "Edit /etc/docker/daemon.json: "
                    '{"userns-remap": "default", "no-new-privileges": true, '
                    '"icc": false, "log-driver": "json-file", '
                    '"live-restore": true}'
                ),
                cross_references={
                    "CIS-Docker": "2.8", "NIST": "SC-39",
                },
            ))
        else:
            results.append(_r(
                cat, "Warning",
                "EDR-CONT-3: /etc/docker/daemon.json not present",
                severity="Medium",
                details="No daemon.json - using all defaults",
                remediation=(
                    "Create /etc/docker/daemon.json with hardening directives"
                ),
                cross_references={
                    "CIS-Docker": "2.8",
                },
            ))

    return results


def _check_edr_anti_forensics(os_info) -> List[AuditResult]:
    """Anti-forensics & log integrity indicators (MITRE T1070, T1562)."""
    results: List[AuditResult] = []
    cat = "EDR - Anti-Forensics Detection"

    # T1070.001 - Log clearing prevention: auditd immutable mode
    audit_rules = read_file_safe("/etc/audit/rules.d/audit.rules") or \
                  read_file_safe("/etc/audit/audit.rules")
    immutable_set = "-e 2" in audit_rules
    results.append(_r(
        cat, "Pass" if immutable_set else "Warning",
        f"EDR-AFOR-1: Auditd immutable mode (-e 2): {immutable_set}",
        severity="High",
        details=(
            f"-e 2 directive present: {immutable_set}. "
            "Locks auditd rules until reboot."
        ),
        remediation=(
            "At end of /etc/audit/rules.d/99-immutable.rules add: -e 2; "
            "augenrules --load"
        ),
        cross_references={
            "MITRE-ATT&CK": "T1562.001", "NIST": "AU-9",
            "STIG": "V-230409",
        },
    ))

    # T1070.002 - history files monitored
    history_audit_keys = [
        ".bash_history", ".zsh_history", "audit_log", "history"
    ]
    history_monitored = any(
        k in audit_rules for k in history_audit_keys
    )
    results.append(_r(
        cat, "Pass" if history_monitored else "Info",
        f"EDR-AFOR-2: Shell history file modifications monitored",
        severity="Medium",
        details=f"audit rules referencing history: {history_monitored}",
        remediation=(
            "Add audit rule: -w /home -p wa -k shell_history "
            "(or specific user paths)"
        ),
        cross_references={
            "MITRE-ATT&CK": "T1070.003", "NIST": "AU-2",
        },
    ))

    # T1562.001 - Auditd watch points for system tampering
    critical_watches = [
        "/var/log/audit",
        "/etc/audit",
        "/etc/sudoers",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
    ]
    watches_set = sum(1 for w in critical_watches if w in audit_rules)
    results.append(_r(
        cat, "Pass" if watches_set >= 4 else "Warning",
        f"EDR-AFOR-3: Critical files watched in audit ({watches_set}/{len(critical_watches)})",
        severity="High",
        details=f"Watched paths in audit rules: {watches_set}",
        remediation=(
            "Add watches in /etc/audit/rules.d/critical-files.rules: "
            "-w /etc/passwd -p wa -k identity; "
            "-w /etc/shadow -p wa -k identity; "
            "-w /etc/sudoers -p wa -k privileged; "
            "-w /etc/sudoers.d -p wa -k privileged"
        ),
        cross_references={
            "MITRE-ATT&CK": "T1562.006", "NIST": "AU-2",
            "CIS": "4.1.3",
        },
    ))

    # T1070.006 - timestamp manipulation: Audit rules for clock_settime
    has_time_audit = (
        "clock_settime" in audit_rules or
        "adjtimex" in audit_rules or
        "settimeofday" in audit_rules
    )
    results.append(_r(
        cat, "Pass" if has_time_audit else "Warning",
        f"EDR-AFOR-4: Time modification syscalls audited: {has_time_audit}",
        severity="Medium",
        details=(
            "clock_settime/adjtimex/settimeofday audit indicators: "
            f"{has_time_audit}"
        ),
        remediation=(
            "Add: -a always,exit -F arch=b64 -S adjtimex,settimeofday,"
            "clock_settime -k time-change"
        ),
        cross_references={
            "MITRE-ATT&CK": "T1070.006", "NIST": "AU-2",
            "CIS": "4.1.4",
        },
    ))

    # /var/log/audit immutable
    rc, out, _ = run_command(["lsattr", "/var/log/audit"], timeout=3.0)
    audit_immutable = rc == 0 and "i" in out.split()[0] if out else False
    results.append(_r(
        cat, "Info",
        f"EDR-AFOR-5: /var/log/audit chattr immutable: {audit_immutable}",
        severity="Informational",
        details=f"chattr +i indicator: {audit_immutable}",
        remediation=(
            "Optional: chattr +i /var/log/audit (prevents log file deletion "
            "without unsetting). Note: complicates rotation."
        ),
        cross_references={
            "MITRE-ATT&CK": "T1070.002", "NIST": "AU-9",
        },
    ))

    return results


def _check_edr_memory_protection(os_info) -> List[AuditResult]:
    """Memory protection features (NX, SMEP/SMAP, KASLR)."""
    results: List[AuditResult] = []
    cat = "EDR - Memory Protection"

    # NX bit / DEP
    cpuinfo = read_file_safe("/proc/cpuinfo")
    has_nx = "nx" in cpuinfo  # CPU flag
    results.append(_r(
        cat, "Pass" if has_nx else "Warning",
        f"EDR-MEM-1: CPU NX (No-Execute) bit support: {has_nx}",
        severity="High",
        details=f"NX flag in /proc/cpuinfo: {has_nx}",
        remediation=(
            "Modern CPUs all support NX. Verify BIOS has 'XD bit' enabled."
        ),
        cross_references={
            "NIST": "SI-16",
        },
    ))

    # SMEP / SMAP
    has_smep = "smep" in cpuinfo
    has_smap = "smap" in cpuinfo
    smep_smap_ok = has_smep and has_smap
    results.append(_r(
        cat, "Pass" if smep_smap_ok else "Info",
        f"EDR-MEM-2: SMEP/SMAP support: SMEP={has_smep}, SMAP={has_smap}",
        severity="Medium",
        details=f"smep flag: {has_smep}, smap flag: {has_smap}",
        remediation=(
            "Modern Intel/AMD CPUs support these. "
            "Required for kernel hardening (mitigates kernel-mode privilege escalation)."
        ),
        cross_references={
            "NIST": "SI-16",
        },
    ))

    # ASLR enabled (full = 2)
    aslr = read_sysctl("kernel.randomize_va_space")
    aslr_full = aslr == "2"
    results.append(_r(
        cat, "Pass" if aslr_full else "Fail",
        f"EDR-MEM-3: ASLR full enabled (randomize_va_space=2): {aslr_full}",
        severity="High",
        details=f"kernel.randomize_va_space = {aslr}",
        remediation=(
            "echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.d/99-aslr.conf"
        ),
        cross_references={
            "NIST": "SI-16", "STIG": "V-230280", "CIS": "1.5.3",
        },
    ))

    # exec-shield indicator (kernel-dependent)
    kernel_cmdline = read_file_safe("/proc/cmdline")
    nokaslr = "nokaslr" in kernel_cmdline
    results.append(_r(
        cat, "Pass" if not nokaslr else "Fail",
        f"EDR-MEM-4: KASLR not disabled in kernel cmdline",
        severity="High",
        details=f"nokaslr in cmdline: {nokaslr}",
        remediation=(
            "Edit GRUB config to remove 'nokaslr'; rebuild grub config; reboot."
        ),
        cross_references={
            "NIST": "SI-16",
        },
    ))

    # Kernel page table isolation (KPTI / Meltdown mitigation)
    kpti_active = False
    if file_exists("/sys/devices/system/cpu/vulnerabilities/meltdown"):
        meltdown = read_file_safe(
            "/sys/devices/system/cpu/vulnerabilities/meltdown"
        )
        kpti_active = "Mitigation" in meltdown
    results.append(_r(
        cat, "Pass" if kpti_active else "Info",
        f"EDR-MEM-5: Meltdown/KPTI mitigation active: {kpti_active}",
        severity="High",
        details=f"meltdown vuln file: "
                f"{read_file_safe('/sys/devices/system/cpu/vulnerabilities/meltdown').strip()[:80]}",
        cross_references={
            "NIST": "SI-2",
        },
    ))

    return results


def _check_edr_process_accounting(os_info) -> List[AuditResult]:
    """Process accounting / acct monitoring."""
    results: List[AuditResult] = []
    cat = "EDR - Process Accounting"

    # acct/psacct
    acct_present = (
        command_available("lastcomm") or
        file_exists("/var/log/account/pacct") or
        file_exists("/var/log/pacct")
    )
    acct_active = (
        systemd_active("acct.service") == "active" or
        systemd_active("psacct.service") == "active"
    )
    results.append(_r(
        cat, "Pass" if acct_active else "Info",
        f"EDR-PROCACCT-1: Process accounting (acct/psacct) active: {acct_active}",
        severity="Low",
        details=f"acct binary present: {acct_present}, service active: {acct_active}",
        remediation=(
            "apt-get install -y acct (Debian) or dnf install -y psacct (RHEL); "
            "systemctl enable --now acct (or psacct)"
        ),
        cross_references={
            "NIST": "AU-2", "CIS": "4.2.3",
        },
    ))

    # systemd-analyze blame would tell us about startup performance / persistence
    # Just check journald is logging successfully
    if command_available("journalctl"):
        rc, out, _ = run_command(
            ["journalctl", "-q", "-n", "5", "--no-pager"], timeout=5.0
        )
        journald_working = rc == 0 and out
        results.append(_r(
            cat, "Pass" if journald_working else "Fail",
            f"EDR-PROCACCT-2: journald query functioning: {bool(journald_working)}",
            severity="Medium",
            details=f"journalctl rc={rc}",
            cross_references={
                "NIST": "AU-2",
            },
        ))

    return results


def _check_edr_auditd_ruleset_depth(os_info) -> List[AuditResult]:
    """Auditd ruleset depth - count of rules across categories."""
    results: List[AuditResult] = []
    cat = "EDR - Auditd Ruleset Depth"

    if not (systemd_active("auditd.service") == "active"):
        return results

    # Read rules from rules.d
    rules_dir = "/etc/audit/rules.d"
    all_rules = ""
    if directory_exists(rules_dir):
        for f in list_directory(rules_dir):
            if f.endswith(".rules"):
                all_rules += "\n" + read_file_safe(os.path.join(rules_dir, f))

    if not all_rules:
        all_rules = read_file_safe("/etc/audit/audit.rules")

    # Count rules by category
    total_rules = sum(
        1 for line in all_rules.splitlines()
        if line.strip() and not line.strip().startswith("#")
    )

    # Watch rules
    watch_rules = sum(
        1 for line in all_rules.splitlines()
        if line.strip().startswith("-w ")
    )
    syscall_rules = sum(
        1 for line in all_rules.splitlines()
        if line.strip().startswith("-a ")
    )

    results.append(_r(
        cat, "Pass" if total_rules >= 50 else (
            "Warning" if total_rules >= 25 else "Fail"
        ),
        f"EDR-AUDIT-1: Total auditd rules ({total_rules})",
        severity="High",
        details=(
            f"Total: {total_rules}, Watch (-w): {watch_rules}, "
            f"Syscall (-a): {syscall_rules}"
        ),
        remediation=(
            "Deploy CIS-recommended ruleset (~75+ rules covering identity, "
            "privileged commands, file access, network, modules). See CIS L1/L2 4.1.3"
        ),
        cross_references={
            "NIST": "AU-2", "CIS": "4.1.3", "PCI-DSS": "10.2",
        },
    ))

    # Specific high-value rule keys
    important_keys = {
        "identity": "identity" in all_rules,
        "privileged": "privileged" in all_rules,
        "perm_mod": "perm_mod" in all_rules,
        "modules": "modules" in all_rules,
        "time-change": "time-change" in all_rules,
        "system-locale": "system-locale" in all_rules,
        "MAC-policy": "MAC-policy" in all_rules,
        "logins": "logins" in all_rules,
        "session": "session" in all_rules,
    }
    detected_keys = [k for k, v in important_keys.items() if v]
    results.append(_r(
        cat, "Pass" if len(detected_keys) >= 7 else "Warning",
        f"EDR-AUDIT-2: Standard audit rule keys present "
        f"({len(detected_keys)}/{len(important_keys)})",
        severity="Medium",
        details=f"Present keys: {detected_keys}",
        remediation=(
            "Apply CIS-recommended audit rule keys. Reference: "
            "https://github.com/Neo23x0/auditd"
        ),
        cross_references={
            "CIS": "4.1.3", "NIST": "AU-2",
        },
    ))

    return results


def _check_edr_ebpf_lsm_extended(os_info) -> List[AuditResult]:
    """eBPF LSM and runtime detection capability extended."""
    results: List[AuditResult] = []
    cat = "EDR - eBPF/LSM Extended"

    # /sys/kernel/security/lsm enumerates active LSMs
    lsm_active = read_file_safe("/sys/kernel/security/lsm").strip()
    if lsm_active:
        active_lsms = lsm_active.split(",")
        bpf_lsm_active = "bpf" in active_lsms
        results.append(_r(
            cat, "Pass" if bpf_lsm_active else "Info",
            f"EDR-EBPF-LSM-1: BPF LSM active: {bpf_lsm_active}",
            severity="Medium",
            details=f"Active LSMs: {active_lsms}",
            remediation=(
                "Enable BPF LSM by adding to GRUB cmdline: lsm=lockdown,yama,bpf"
            ),
            cross_references={
                "NIST": "SI-16",
            },
        ))

    # /proc/sys/kernel/perf_event_paranoid
    perf_par = read_sysctl("kernel.perf_event_paranoid")
    perf_ok = perf_par in ("2", "3")
    results.append(_r(
        cat, "Pass" if perf_ok else "Info",
        f"EDR-EBPF-LSM-2: perf_event_paranoid: {perf_par or 'unset'}",
        severity="Medium",
        details=f"kernel.perf_event_paranoid = {perf_par}",
        remediation=(
            "echo 'kernel.perf_event_paranoid = 2' >> /etc/sysctl.d/99-perf.conf"
        ),
        cross_references={
            "NIST": "AC-3",
        },
    ))

    # bpftool / bpftrace presence
    bpf_tools = {
        "bpftool": command_available("bpftool"),
        "bpftrace": command_available("bpftrace"),
        "bcc-tools": directory_exists("/usr/share/bcc/tools") or
                     command_available("execsnoop-bpfcc"),
    }
    detected_bpf = [k for k, v in bpf_tools.items() if v]
    results.append(_r(
        cat, "Pass" if detected_bpf else "Info",
        f"EDR-EBPF-LSM-3: BPF observability tools ({len(detected_bpf)})",
        severity="Low",
        details=f"Detected: {detected_bpf or 'none'}",
        remediation=(
            "apt-get install -y linux-tools-common linux-tools-generic bpftrace bpfcc-tools"
        ),
        cross_references={
            "NIST": "SI-4",
        },
    ))

    return results


# Save reference to existing run_checks
_original_run_checks_edr_v33 = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the v3.3 expanded EDR module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_edr_v33(shared_data)

    os_info = shared_data.get("v3_os_info")
    if os_info is None:
        os_info = os_detection.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        results.extend(_check_edr_persistence_detection(os_info))
        results.extend(_check_edr_process_injection_indicators(os_info))
        results.extend(_check_edr_network_behavior(os_info))
        results.extend(_check_edr_container_runtime(os_info))
        results.extend(_check_edr_anti_forensics(os_info))
        results.extend(_check_edr_memory_protection(os_info))
        results.extend(_check_edr_process_accounting(os_info))
        results.extend(_check_edr_auditd_ruleset_depth(os_info))
        results.extend(_check_edr_ebpf_lsm_extended(os_info))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled exception in EDR v3.3 expansion")
        results.append(_r(
            "EDR - Error", "Error",
            f"EDR v3.3 expansion exception: {exc!r}",
            severity="Medium", details=str(exc),
        ))

    return results


# ============================================================================
# v3.5 EXPANSION - EDR Detection-as-Code, Forensics, Cloud-Native
# ----------------------------------------------------------------------------
# Synopsis:
#   Adds depth across EDR areas not yet covered:
#     - Sigma / YARA detection-as-code engines
#     - Cloud-native EDR agents (CrowdStrike CSPM, AWS GuardDuty agent)
#     - Container runtime EDR depth (Falco rules count, Tetragon, Tracee)
#     - Endpoint forensics tooling (Velociraptor, GRR, plaso, volatility)
#     - Network traffic analysis (Zeek, Arkime, Brim, full pcap)
#     - Honeypot / decoy / canary detection
#     - EDR agent anti-tamper indicators
#     - MITRE ATT&CK coverage mapping
#     - Memory analysis tools
#     - Live response capability
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


def _v35_edr_result(category, status, message, severity="Medium",
                   details="", remediation="", cross_references=None):
    """Build AuditResult for EDR v3.5 expansion."""
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


def _check_edr_v35_sigma_yara(os_info):
    """Sigma / YARA detection-as-code engines."""
    results = []
    cat = "EDR v3.5 - Detection as Code"

    # YARA presence
    yara_present = _v35_command_available("yara")
    yara_rules_dirs = [
        "/etc/yara/rules",
        "/usr/share/yara/rules",
        "/var/lib/yara/rules",
        "/opt/yara",
    ]
    yara_rules_present = any(
        _v35_directory_exists(p) for p in yara_rules_dirs
    )
    results.append(_v35_edr_result(
        f"{cat} - YARA",
        "Pass" if yara_present else "Info",
        f"YARA scanner present: {yara_present}, rules dir: {yara_rules_present}",
        severity="Medium",
        details=(
            f"yara binary: {yara_present}, "
            f"rules directory: {yara_rules_present}"
        ),
        remediation=(
            "apt-get install -y yara\n"
            "Pull community rules:\n"
            "  git clone https://github.com/Yara-Rules/rules /opt/yara\n"
            "Run: yara -r /opt/yara/index.yar /target"
        ),
        cross_references={
            "MITRE": "ATT&CK Detection",
            "NIST": "SI-3, SI-4",
        },
    ))

    # Sigma + sigmac translator
    sigma_present = (
        _v35_command_available("sigma") or
        _v35_command_available("sigmac") or
        _v35_command_available("pysigma") or
        _v35_directory_exists("/opt/sigma")
    )
    results.append(_v35_edr_result(
        f"{cat} - Sigma",
        "Pass" if sigma_present else "Info",
        f"Sigma rule tooling present: {sigma_present}",
        severity="Low",
        details=f"Sigma tools detected: {sigma_present}",
        remediation=(
            "Install pysigma: pip install --user pysigma\n"
            "Pull community rules: git clone "
            "https://github.com/SigmaHQ/sigma /opt/sigma"
        ),
        cross_references={
            "MITRE": "ATT&CK Detection",
            "NIST": "SI-4(24)",
        },
    ))

    # Engine to consume Sigma/YARA at runtime: Wazuh, Falco, ClamAV
    detection_engines = []
    if _v35_file_exists("/var/ossec/etc/ossec.conf"):
        detection_engines.append("Wazuh/OSSEC")
    if _v35_systemd_active("falco.service") == "active":
        detection_engines.append("Falco")
    if _v35_systemd_active("clamav-daemon.service") == "active" or \
       _v35_systemd_active("clamd.service") == "active":
        detection_engines.append("ClamAV")
    results.append(_v35_edr_result(
        f"{cat} - Detection Engines Active",
        "Pass" if detection_engines else "Warning",
        f"Detection engines active: {detection_engines}",
        severity="High",
        details=f"Active: {detection_engines}",
        cross_references={
            "MITRE": "ATT&CK Detection",
            "NIST": "SI-3, SI-4(2)",
        },
    ))

    return results


def _check_edr_v35_cloud_native(os_info):
    """Cloud-native EDR agents."""
    results = []
    cat = "EDR v3.5 - Cloud-Native"

    cloud_edr = {
        "AWS Inspector": _v35_directory_exists(
            "/opt/aws/inspector"
        ) or _v35_systemd_active(
            "amazon-inspector-agent.service"
        ) == "active",
        "AWS SSM Agent": _v35_systemd_active(
            "amazon-ssm-agent.service"
        ) == "active",
        "Azure Monitor Agent": _v35_systemd_active(
            "azuremonitoragent.service"
        ) == "active" or _v35_directory_exists("/opt/microsoft/azuremonitoragent"),
        "Azure Defender for Cloud": _v35_directory_exists(
            "/opt/microsoft/scx"
        ),
        "Google Cloud Ops Agent": _v35_systemd_active(
            "google-cloud-ops-agent.service"
        ) == "active",
        "Datadog Agent": _v35_systemd_active(
            "datadog-agent.service"
        ) == "active",
        "Wiz Sensor": _v35_directory_exists("/opt/wiz"),
    }
    detected = [k for k, v in cloud_edr.items() if v]
    results.append(_v35_edr_result(
        f"{cat} - Cloud-Native Agents",
        "Pass" if detected else "Info",
        f"Cloud-native security/observability agents: {detected}",
        severity="Informational",
        details=f"Detected: {detected}",
        cross_references={
            "NIST": "SI-4",
            "CSF": "DE.CM-1, DE.CM-7",
        },
    ))

    return results


def _check_edr_v35_container_edr(os_info):
    """Container runtime EDR depth (Falco rules, Tetragon, Tracee)."""
    results = []
    cat = "EDR v3.5 - Container EDR"

    # Falco rules count
    falco_rules_dir = "/etc/falco"
    falco_rule_files = []
    if _v35_directory_exists(falco_rules_dir):
        for f in _v35_list_directory(falco_rules_dir):
            if f.endswith("_rules.yaml") or f.endswith(".yaml"):
                falco_rule_files.append(f)
    falco_active = _v35_systemd_active("falco.service") == "active"
    if falco_active or falco_rule_files:
        results.append(_v35_edr_result(
            f"{cat} - Falco Rules Count",
            "Pass" if len(falco_rule_files) >= 2 else "Info",
            f"Falco active={falco_active}, rule files: {len(falco_rule_files)}",
            severity="Medium",
            details=f"Rule files: {falco_rule_files[:5]}",
            remediation=remediation_for("falco"),
            cross_references={
                "MITRE": "ATT&CK Detection",
                "NIST": "SI-4",
            },
        ))

    # Tetragon (Cilium runtime detection)
    tetragon_active = _v35_systemd_active("tetragon.service") == "active"
    tetragon_present = (
        tetragon_active or _v35_command_available("tetra") or
        _v35_directory_exists("/etc/tetragon")
    )
    if tetragon_present:
        results.append(_v35_edr_result(
            f"{cat} - Tetragon",
            "Pass" if tetragon_active else "Info",
            f"Tetragon (Cilium runtime detection) active: {tetragon_active}",
            severity="Medium",
            details=f"tetragon active: {tetragon_active}",
            cross_references={"NIST": "SI-4(24)"},
        ))

    # Tracee (Aqua Security runtime detection)
    tracee_present = (
        _v35_command_available("tracee") or
        _v35_systemd_active("tracee.service") == "active"
    )
    if tracee_present:
        results.append(_v35_edr_result(
            f"{cat} - Tracee",
            "Info",
            f"Tracee runtime detection: present",
            severity="Informational",
            details="tracee binary or service detected",
            cross_references={"NIST": "SI-4"},
        ))

    return results


def _check_edr_v35_forensics_tooling(os_info):
    """Endpoint forensics tooling (Velociraptor, GRR, plaso, volatility)."""
    results = []
    cat = "EDR v3.5 - Forensics"

    forensics_tools = {
        "Velociraptor": _v35_command_available("velociraptor"),
        "GRR Rapid Response": _v35_systemd_active("grr-client.service") == "active"
                                or _v35_directory_exists("/opt/grr"),
        "log2timeline (plaso)": _v35_command_available("log2timeline.py"),
        "Volatility 3": _v35_command_available("vol.py") or _v35_command_available("vol"),
        "TheHive Cortex": _v35_directory_exists("/opt/cortex"),
        "MISP": _v35_systemd_active("misp.service") == "active",
        "AvmL (memory acq)": _v35_command_available("avml"),
        "LiME (memory acq)": _v35_file_exists("/proc/lime"),
        "dumpe2fs": _v35_command_available("dumpe2fs"),
    }
    available = [k for k, v in forensics_tools.items() if v]
    results.append(_v35_edr_result(
        f"{cat} - Forensics Tooling",
        "Pass" if len(available) >= 2 else "Info",
        f"Forensics tools available: {len(available)}/9",
        severity="Medium",
        details=f"Available: {available}",
        remediation=(
            "Memory acquisition: AVML (Microsoft, no-build):\n"
            "  curl -O -L https://github.com/microsoft/avml/releases/latest/download/avml\n"
            "Memory analysis: pip install --user volatility3\n"
            "Timeline: apt-get install -y plaso\n"
            "Live response: install Velociraptor from velociraptor.app"
        ),
        cross_references={
            "NIST": "IR-4, IR-5",
            "CSF": "RS.AN-1, RS.AN-2",
        },
    ))

    return results


def _check_edr_v35_network_analysis(os_info):
    """Network traffic analysis (Zeek, Arkime, full pcap)."""
    results = []
    cat = "EDR v3.5 - NTA"

    nta_tools = {
        "Zeek": _v35_command_available("zeek") or _v35_command_available("bro"),
        "Arkime / Moloch": (
            _v35_command_available("arkime") or
            _v35_directory_exists("/opt/arkime") or
            _v35_systemd_active("arkimecapture.service") == "active"
        ),
        "Suricata": _v35_systemd_active("suricata.service") == "active",
        "Snort": _v35_command_available("snort"),
        "Brim / Zui": _v35_directory_exists("/opt/Brim"),
        "ntopng": _v35_systemd_active("ntopng.service") == "active",
        "tcpdump": _v35_command_available("tcpdump"),
    }
    available = [k for k, v in nta_tools.items() if v]
    nta_layers = sum([1 for v in nta_tools.values() if v])
    results.append(_v35_edr_result(
        f"{cat} - NTA Tooling",
        "Pass" if nta_layers >= 2 else "Warning",
        f"Network traffic analysis layers: {nta_layers}/7",
        severity="Medium",
        details=f"Available: {available}",
        remediation=(
            f"{remediation_for('suricata')}\n"
            "Combine with Zeek for protocol-aware analysis:\n"
            "  apt-get install -y zeek-lts"
        ),
        cross_references={
            "NIST": "SI-4(4), SI-4(18)",
            "CSF": "DE.CM-1",
        },
    ))

    return results


def _check_edr_v35_honeypots(os_info):
    """Honeypot / decoy / canary detection."""
    results = []
    cat = "EDR v3.5 - Honeypots"

    honeypot_tools = {
        "Cowrie": (
            _v35_systemd_active("cowrie.service") == "active" or
            _v35_directory_exists("/opt/cowrie")
        ),
        "OpenCanary": (
            _v35_systemd_active("opencanary.service") == "active" or
            _v35_command_available("opencanaryd")
        ),
        "Honeyd": _v35_command_available("honeyd"),
        "T-Pot": _v35_directory_exists("/opt/tpot"),
        "Dionaea": _v35_systemd_active("dionaea.service") == "active",
        "Glastopf": _v35_directory_exists("/opt/glastopf"),
        "Canary tokens": _v35_command_available("canarytokens-client"),
        "Honeyfile": False,  # Heuristic check below
    }
    # Honeyfile heuristic: files with 'honey' or 'canary' in /etc audited
    audit_rules_text = ""
    if _v35_directory_exists("/etc/audit/rules.d"):
        for f in _v35_list_directory("/etc/audit/rules.d"):
            if f.endswith(".rules"):
                audit_rules_text += "\n" + _v35_read_file_safe(
                    os.path.join("/etc/audit/rules.d", f)
                )
    if "honey" in audit_rules_text.lower() or "canary" in audit_rules_text.lower():
        honeypot_tools["Honeyfile"] = True

    detected = [k for k, v in honeypot_tools.items() if v]
    results.append(_v35_edr_result(
        f"{cat} - Honeypot/Decoy Tools",
        "Info",
        f"Honeypot/decoy infrastructure: {detected or 'none'}",
        severity="Informational",
        details=f"Detected: {detected}",
        remediation=(
            "Optional defense-in-depth via deception. Install Cowrie SSH "
            "honeypot:\n"
            "  pip install cowrie\n"
            "Or use canary tokens (https://canarytokens.org) for file/folder "
            "tripwires."
        ),
        cross_references={
            "NIST": "SC-26 (Decoys)",
            "CSF": "DE.AE-2",
        },
    ))

    return results


def _check_edr_v35_anti_tamper(os_info):
    """EDR agent anti-tamper indicators."""
    results = []
    cat = "EDR v3.5 - Anti-Tamper"

    # Common EDR services that should be enabled and locked
    edr_services_known = {
        "ossec": "ossec.service",
        "wazuh-agent": "wazuh-agent.service",
        "falco": "falco.service",
        "auditd": "auditd.service",
        "amazon-ssm-agent": "amazon-ssm-agent.service",
        "datadog-agent": "datadog-agent.service",
    }

    enabled_count = 0
    not_enabled = []
    for label, unit in edr_services_known.items():
        # Check whether the unit is active
        active = _v35_systemd_active(unit) == "active"
        if not active:
            continue
        # If active, check whether it's enabled (cannot be casually stopped)
        rc, out, _ = _v35_run_command(
            ["systemctl", "is-enabled", unit], timeout=3.0,
        )
        if rc == 0 and out.strip() == "enabled":
            enabled_count += 1
        else:
            not_enabled.append(label)

    if enabled_count + len(not_enabled) > 0:
        results.append(_v35_edr_result(
            f"{cat} - EDR Service Enabled",
            "Pass" if not not_enabled else "Warning",
            f"Active EDR services enabled (cannot be casually disabled): "
            f"{enabled_count}/{enabled_count + len(not_enabled)}",
            severity="High",
            details=f"Active but not enabled: {not_enabled}",
            remediation=(
                "For each EDR service that's active but not enabled:\n"
                "  systemctl enable <unit>\n"
                "Anti-tamper requires services persist across reboots."
            ),
            cross_references={
                "NIST": "SC-7(13), SI-3",
                "PCI-DSS": "5.3.3",
            },
        ))

    # Audit on EDR config directories
    audit_rules_text = ""
    if _v35_directory_exists("/etc/audit/rules.d"):
        for f in _v35_list_directory("/etc/audit/rules.d"):
            if f.endswith(".rules"):
                audit_rules_text += "\n" + _v35_read_file_safe(
                    os.path.join("/etc/audit/rules.d", f)
                )
    edr_audited = (
        "/var/ossec" in audit_rules_text or
        "/etc/falco" in audit_rules_text or
        "wazuh" in audit_rules_text.lower() or
        "/opt/CrowdStrike" in audit_rules_text or
        "ossec.conf" in audit_rules_text
    )
    results.append(_v35_edr_result(
        f"{cat} - EDR Config Audit",
        "Pass" if edr_audited else "Info",
        f"EDR configuration audit rules: {edr_audited}",
        severity="Medium",
        details=f"EDR paths in audit rules: {edr_audited}",
        remediation=(
            "Add to /etc/audit/rules.d/41-edr-tamper.rules:\n"
            "  -w /var/ossec/etc/ossec.conf -p wa -k edr-tamper\n"
            "  -w /etc/falco -p wa -k edr-tamper\n"
            "Ensures any EDR config tampering is logged."
        ),
        cross_references={
            "NIST": "AU-2, SI-7",
            "PCI-DSS": "10.2.1.6",
        },
    ))

    return results


def _check_edr_v35_mitre_attack_coverage(os_info):
    """MITRE ATT&CK technique-specific detection coverage."""
    results = []
    cat = "EDR v3.5 - MITRE ATT&CK"

    # Aggregate audit rules
    audit_rules_text = ""
    if _v35_directory_exists("/etc/audit/rules.d"):
        for f in _v35_list_directory("/etc/audit/rules.d"):
            if f.endswith(".rules"):
                audit_rules_text += "\n" + _v35_read_file_safe(
                    os.path.join("/etc/audit/rules.d", f)
                )

    # Map common ATT&CK techniques to audit rule indicators
    technique_coverage = {
        "T1003 (Credential Access)": (
            "/etc/shadow" in audit_rules_text or
            "/etc/security/opasswd" in audit_rules_text
        ),
        "T1059 (Command Line Interpreter)": (
            "execve" in audit_rules_text and "auid" in audit_rules_text
        ),
        "T1098 (Account Manipulation)": (
            "/etc/passwd" in audit_rules_text and "wa" in audit_rules_text
        ),
        "T1543 (Create or Modify System Process)": (
            "/etc/systemd/system" in audit_rules_text or
            "/lib/systemd/system" in audit_rules_text or
            "/usr/lib/systemd/system" in audit_rules_text
        ),
        "T1547 (Boot or Logon Autostart)": (
            "/etc/cron" in audit_rules_text or
            "/var/spool/cron" in audit_rules_text or
            "/etc/profile" in audit_rules_text
        ),
        "T1562 (Impair Defenses)": (
            "/var/log/audit" in audit_rules_text or
            "/sbin/auditctl" in audit_rules_text
        ),
        "T1070 (Indicator Removal)": (
            "/var/log/audit" in audit_rules_text or
            "/var/log/syslog" in audit_rules_text or
            "rmdir" in audit_rules_text or "unlink" in audit_rules_text
        ),
    }
    covered = [k for k, v in technique_coverage.items() if v]
    coverage_pct = int(100 * len(covered) / len(technique_coverage))
    results.append(_v35_edr_result(
        f"{cat} - Technique Coverage",
        "Pass" if coverage_pct >= 60 else "Warning",
        f"MITRE ATT&CK technique coverage (audit rules): "
        f"{len(covered)}/{len(technique_coverage)} ({coverage_pct}%)",
        severity="High",
        details=f"Covered: {covered}",
        remediation=(
            "Deploy MITRE-aligned audit rules from "
            "https://github.com/Neo23x0/auditd. The package provides "
            "production-tested rules with ATT&CK technique mapping."
        ),
        cross_references={
            "MITRE": "ATT&CK Mapping",
            "NIST": "SI-4(24), AU-12",
        },
    ))

    return results


def _check_edr_v35_live_response(os_info):
    """Live response capability."""
    results = []
    cat = "EDR v3.5 - Live Response"

    # Process inspection / triage
    triage_tools = {
        "lsof": _v35_command_available("lsof"),
        "strace": _v35_command_available("strace"),
        "gdb": _v35_command_available("gdb"),
        "perf": _v35_command_available("perf"),
        "bpftrace": _v35_command_available("bpftrace"),
        "bcc-tools": _v35_command_available("trace-bpfcc") or
                      _v35_command_available("execsnoop-bpfcc"),
    }
    available = [k for k, v in triage_tools.items() if v]
    results.append(_v35_edr_result(
        f"{cat} - Triage Tooling",
        "Pass" if len(available) >= 3 else "Warning",
        f"Live response triage tools: {len(available)}/6",
        severity="Medium",
        details=f"Available: {available}",
        remediation=(
            "apt-get install -y lsof strace gdb linux-tools-common "
            "linux-tools-generic bpfcc-tools bpftrace\n"
            "Provides comprehensive live process and syscall inspection "
            "for IR triage."
        ),
        cross_references={
            "NIST": "IR-4(1), IR-5",
            "CSF": "RS.AN-1",
        },
    ))

    # Memory acquisition tools
    memacq_tools = {
        "AVML": _v35_command_available("avml"),
        "LiME (loaded)": _v35_file_exists("/proc/lime"),
        "/proc/kcore": _v35_file_exists("/proc/kcore"),
    }
    available_mem = [k for k, v in memacq_tools.items() if v]
    results.append(_v35_edr_result(
        f"{cat} - Memory Acquisition",
        "Pass" if available_mem else "Info",
        f"Memory acquisition capability: {available_mem}",
        severity="Low",
        details=f"Available: {available_mem}",
        cross_references={
            "NIST": "IR-5",
        },
    ))

    return results


# Save reference to existing run_checks
_original_run_checks_edr_v35 = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the v3.5 expanded EDR module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_edr_v35(shared_data)

    os_info = shared_data.get("os_info") or shared_data.get("v3_os_info")
    if os_info is None:
        from shared_components import os_detection as _os_det
        os_info = _os_det.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        results.extend(_check_edr_v35_sigma_yara(os_info))
        results.extend(_check_edr_v35_cloud_native(os_info))
        results.extend(_check_edr_v35_container_edr(os_info))
        results.extend(_check_edr_v35_forensics_tooling(os_info))
        results.extend(_check_edr_v35_network_analysis(os_info))
        results.extend(_check_edr_v35_honeypots(os_info))
        results.extend(_check_edr_v35_anti_tamper(os_info))
        results.extend(_check_edr_v35_mitre_attack_coverage(os_info))
        results.extend(_check_edr_v35_live_response(os_info))
    except Exception as exc:  # noqa: BLE001
        results.append(AuditResult(
            module=MODULE_NAME, category="EDR - Error",
            status="Error",
            message=f"EDR v3.5 expansion exception: {exc!r}",
            details=str(exc), severity="Medium",
        ))

    return results
if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    print("[EDR] ===== Linux EDR Equivalent Detection =====")
    print("[EDR] Module Version: 3.9\n")
    rs = run_checks()
    print(f"[EDR] {len(rs)} checks executed\n")
    counts: Dict[str, int] = {}
    for r in rs:
        counts[r.status] = counts.get(r.status, 0) + 1
    for s, c in sorted(counts.items()):
        print(f"  {s:>8}: {c}")
