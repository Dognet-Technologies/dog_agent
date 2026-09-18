#!/usr/bin/env python3
"""
module_pci.py
PCI DSS v4.0.1 Technical Controls Module for Linux
Version: 3.9

SYNOPSIS
    Linux technical compliance assessment against the Payment Card Industry
    Data Security Standard (PCI DSS) v4.0.1 published by the PCI Security
    Standards Council (March 2024).

DESCRIPTION
    PCI DSS applies to any system in the cardholder data environment (CDE)
    or that connects to it. This module covers the technical control
    requirements applicable to Linux servers and endpoints. Process and
    documentation requirements (e.g. Req 12) are largely out of scope for
    automated tooling and require human-led assessment.

    Coverage by Requirement:
      Req 1  - Install and maintain network security controls
      Req 2  - Apply secure configurations to all system components
      Req 3  - Protect stored account data
      Req 4  - Protect cardholder data with strong cryptography during
               transmission over open, public networks
      Req 5  - Protect all systems and networks from malicious software
      Req 6  - Develop and maintain secure systems and software
      Req 7  - Restrict access to system components and cardholder data
               by business need to know
      Req 8  - Identify users and authenticate access to system components
      Req 10 - Log and monitor all access to system components and
               cardholder data
      Req 11 - Test security of systems and networks regularly
      Req 12 - Support information security with organizational policies
               (selected technical indicators only)

    Each check populates the v3.0 AuditResult.cross_references field with
    the PCI DSS requirement ID plus equivalent identifiers in NIST 800-53,
    CIS Benchmarks, ISO 27001, HIPAA, and STIG where applicable.

PARAMETERS
    shared_data : Dictionary containing shared data from the orchestrator
                  (caching, OS detection, parsed config files).

USAGE
    Standalone module test:
        python3 modules/module_pci.py

    Integration with main audit script:
        python3 linux_security_audit.py --modules PCI
        python3 linux_security_audit.py -m PCI

NOTES
    Version: 3.9
    Reference: https://www.pcisecuritystandards.org/document_library/
    Standards: PCI DSS v4.0.1 (effective 2025-04-01)
    Target: 80+ technical control checks
    Module automatically detects OS via shared_components.os_detection
    Compatible with Debian/Ubuntu, RHEL/CentOS/Fedora/Rocky/Alma, SUSE,
    Arch family distributions through the v3.0 foundation library.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple

# Foundation imports. The orchestrator inserts the project root into sys.path
# before module discovery so these imports resolve regardless of cwd.
from shared_components.audit_common import AuditResult
from shared_components import os_detection

logger = logging.getLogger("audit.module_pci")

MODULE_NAME = "PCI-DSS"
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



# ---------------------------------------------------------------------------
# Helper utilities specific to this module
# ---------------------------------------------------------------------------

def _read_file_safe(path: str, max_bytes: int = 1024 * 1024) -> str:
    """Read a small text file, returning empty string on any error.

    File size is capped at max_bytes to prevent runaway reads on a
    misconfigured /etc/* file. The default 1 MiB ceiling is well above
    realistic security-config sizes.
    """
    try:
        st = os.stat(path)
    except OSError:
        return ""
    if st.st_size > max_bytes:
        logger.debug("File %s exceeds %d byte ceiling; not read", path, max_bytes)
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def _file_exists(path: str) -> bool:
    return os.path.isfile(path)


def _command_available(name: str) -> bool:
    return bool(shutil.which(name))


def _run_command(
    args: List[str],
    timeout: float = 5.0,
) -> Tuple[int, str, str]:
    """Run a command with timeout and capture output.

    Returns (returncode, stdout, stderr). On any execution failure,
    returncode is -1 and stderr contains the exception text. List args
    only - no shell=True invocation anywhere in this module.
    """
    if not args or not isinstance(args, list):
        return -1, "", "invalid args"
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.returncode, result.stdout or "", result.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", f"timeout after {timeout}s"
    except (OSError, ValueError) as exc:
        return -1, "", str(exc)


def _read_sysctl(key: str) -> Optional[str]:
    """Read a sysctl value via /proc/sys without launching sysctl(8).

    Returns the trimmed value or None if unreadable.
    """
    if not key or not re.match(r"^[a-z0-9_.\-]+$", key):
        return None
    proc_path = "/proc/sys/" + key.replace(".", "/")
    try:
        with open(proc_path, "r", encoding="ascii", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return None


def _systemd_active(unit: str) -> str:
    """Return the active state of a systemd unit, or 'unknown'."""
    if not unit or not re.match(r"^[A-Za-z0-9@_.\-:]+$", unit):
        return "unknown"
    if not _command_available("systemctl"):
        return "unknown"
    rc, out, err = _run_command(["systemctl", "is-active", unit])
    return (out or err).strip().lower() or "unknown"


def _file_mode(path: str) -> Optional[int]:
    """Return the permission mode of a file as an integer, or None."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    return st.st_mode & 0o7777


def _result(
    category: str,
    status: str,
    message: str,
    severity: str = "Medium",
    details: str = "",
    remediation: str = "",
    cross_references: Optional[Dict[str, str]] = None,
) -> AuditResult:
    """Construct an AuditResult with module-specific defaults.

    Centralised so every check uses the same module name and consistent
    field handling. cross_references is supplied by the calling check
    when the topic isn't covered by the registry's heuristic resolver.
    """
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


# ---------------------------------------------------------------------------
# Requirement 1 - Network Security Controls (Firewall)
# ---------------------------------------------------------------------------

def _check_req1_firewall(os_info) -> List[AuditResult]:
    """PCI Req 1.2 - Network security controls implemented and active."""
    results: List[AuditResult] = []
    cat = "PCI Req 1.2 - Network Security Controls"

    # 1.2.1 - NSC configuration verified
    has_nftables = _file_exists("/etc/nftables.conf") or os.path.isdir(
        "/etc/nftables.d"
    )
    has_iptables = _file_exists("/etc/iptables/rules.v4")
    has_firewalld = _file_exists("/etc/firewalld/firewalld.conf")
    has_ufw = _file_exists("/etc/ufw/ufw.conf")

    any_firewall = has_nftables or has_iptables or has_firewalld or has_ufw

    results.append(_result(
        category=cat,
        status="Pass" if any_firewall else "Fail",
        severity="Critical",
        message="PCI-1.2.1: A network security control is configured on this host",
        details=(
            f"Detected: nftables={has_nftables}, iptables={has_iptables}, "
            f"firewalld={has_firewalld}, ufw={has_ufw}"
        ),
        remediation=(
            "Install and configure a host firewall. On Debian/Ubuntu: "
            "apt-get install -y ufw; ufw default deny incoming; ufw enable. "
            "On RHEL/Rocky/Alma: dnf install -y firewalld; "
            "systemctl enable --now firewalld."
        ),
        cross_references={
            "PCI-DSS": "1.2.1", "NIST": "SC-7", "ISO27001": "A.8.20",
            "CIS": "3.4.1.1", "STIG": "V-230503",
        },
    ))

    # 1.2.6 - Active firewall enforcement
    active_units = []
    for unit in ("firewalld.service", "ufw.service", "nftables.service",
                 "iptables.service", "ip6tables.service"):
        state = _systemd_active(unit)
        if state == "active":
            active_units.append(unit)

    results.append(_result(
        category=cat,
        status="Pass" if active_units else "Fail",
        severity="Critical",
        message="PCI-1.2.6: A firewall service is currently active",
        details=(
            f"Active firewall units: {', '.join(active_units) or 'none'}"
        ),
        remediation=(
            "Enable a firewall service: systemctl enable --now firewalld "
            "(or ufw, or nftables) depending on which is installed."
        ),
        cross_references={
            "PCI-DSS": "1.2.6", "NIST": "SC-7", "CIS": "3.4.1.2",
        },
    ))

    # 1.2.7 - Documented justification for open ports (informational - manual)
    listening = []
    if _command_available("ss"):
        rc, out, _ = _run_command(["ss", "-tlnH"])
        if rc == 0:
            for line in out.splitlines():
                fields = line.split()
                if len(fields) >= 4:
                    addr = fields[3]
                    # Get last colon-separated segment as port
                    port = addr.rsplit(":", 1)[-1]
                    if port.isdigit():
                        listening.append(int(port))

    listening_ports = sorted(set(listening))
    results.append(_result(
        category=cat,
        status="Info" if listening_ports else "Pass",
        severity="Informational",
        message=f"PCI-1.2.7: Inventory of listening TCP ports ({len(listening_ports)} total)",
        details=(
            f"Listening ports: {', '.join(str(p) for p in listening_ports[:50])}"
            if listening_ports
            else "No listening ports detected via ss(8)"
        ),
        remediation=(
            "Document each listening port with business justification. "
            "Disable any service not required for the cardholder data environment."
        ),
        cross_references={
            "PCI-DSS": "1.2.7", "NIST": "CM-7", "CIS": "2.4",
        },
    ))

    return results


def _check_req1_traffic_restrictions(os_info) -> List[AuditResult]:
    """PCI Req 1.3/1.4 - Traffic restrictions to/from the CDE."""
    results: List[AuditResult] = []
    cat = "PCI Req 1.3 - Traffic Restrictions"

    # 1.3.3 - Outbound traffic from CDE restricted
    # Check if iptables OUTPUT default policy is DROP (best practice)
    if _command_available("iptables"):
        rc, out, _ = _run_command(["iptables", "-S", "OUTPUT"])
        output_policy = "ACCEPT"
        if rc == 0:
            for line in out.splitlines():
                if line.startswith("-P OUTPUT"):
                    output_policy = line.split()[-1]
                    break

        results.append(_result(
            category=cat,
            status="Info",  # Default-deny outbound is recommended but not always practical
            severity="Medium",
            message=f"PCI-1.3.3: iptables OUTPUT default policy is {output_policy}",
            details=(
                "PCI DSS recommends restricting outbound traffic from the CDE. "
                f"Current OUTPUT chain default policy: {output_policy}."
            ),
            remediation=(
                "Configure outbound rules permitting only necessary traffic. "
                "Default-deny outbound with explicit allow-list is recommended "
                "for systems handling cardholder data."
            ),
            cross_references={
                "PCI-DSS": "1.3.3", "NIST": "AC-4", "ISO27001": "A.8.20",
            },
        ))

    # 1.4.4 - System components storing cardholder data not directly
    # accessible from untrusted networks (manual - informational)
    results.append(_result(
        category=cat,
        status="Info",
        severity="Informational",
        message="PCI-1.4.4: System segmentation status (manual review required)",
        details=(
            "PCI DSS Req 1.4.4 requires that system components storing "
            "cardholder data not be directly accessible from untrusted networks. "
            "This requires network architecture review and cannot be fully "
            "verified by host-based audit alone."
        ),
        remediation=(
            "Verify network segmentation through architecture review. "
            "Document VLAN configuration, firewall rules between segments, "
            "and any network address translation in place."
        ),
        cross_references={
            "PCI-DSS": "1.4.4", "NIST": "SC-7(13)", "ISO27001": "A.8.22",
        },
    ))

    return results


# ---------------------------------------------------------------------------
# Requirement 2 - Secure Configurations
# ---------------------------------------------------------------------------

def _check_req2_no_default_passwords(os_info) -> List[AuditResult]:
    """PCI Req 2.2.2 - Default passwords changed."""
    results: List[AuditResult] = []
    cat = "PCI Req 2.2 - Secure Configuration"

    # Check /etc/shadow for accounts with no password (empty password field)
    shadow = _read_file_safe("/etc/shadow")
    empty_pwd_accounts: List[str] = []
    if shadow:
        for line in shadow.splitlines():
            fields = line.split(":")
            if len(fields) >= 2 and fields[1] == "":
                # Empty password field
                empty_pwd_accounts.append(fields[0])
    else:
        # Cannot read shadow - probably not running as root
        results.append(_result(
            category=cat,
            status="Error",
            severity="Medium",
            message="PCI-2.2.2: Empty-password account check requires root privileges",
            details="Cannot read /etc/shadow; check skipped",
            cross_references={"PCI-DSS": "2.2.2"},
        ))
        return results

    results.append(_result(
        category=cat,
        status="Pass" if not empty_pwd_accounts else "Fail",
        severity="Critical",
        message="PCI-2.2.2: No accounts have empty password fields",
        details=(
            f"Accounts with empty passwords: {', '.join(empty_pwd_accounts) or 'none'}"
        ),
        remediation=(
            "Lock accounts with empty passwords: passwd -l <username>. "
            "Or remove unused accounts entirely: userdel -r <username>."
        ),
        cross_references={
            "PCI-DSS": "2.2.2", "NIST": "IA-5", "CIS": "6.2.5",
            "STIG": "V-230345", "HIPAA": "164.308(a)(5)(ii)(D)",
        },
    ))

    # Check for accounts with UID 0 other than root (privilege escalation risk)
    passwd = _read_file_safe("/etc/passwd")
    uid0_accounts: List[str] = []
    if passwd:
        for line in passwd.splitlines():
            fields = line.split(":")
            if len(fields) >= 3:
                try:
                    if int(fields[2]) == 0 and fields[0] != "root":
                        uid0_accounts.append(fields[0])
                except ValueError:
                    continue

    results.append(_result(
        category=cat,
        status="Pass" if not uid0_accounts else "Fail",
        severity="Critical",
        message="PCI-2.2.2: Only root has UID 0",
        details=(
            f"Non-root accounts with UID 0: {', '.join(uid0_accounts) or 'none'}"
        ),
        remediation=(
            "Change the UID of any non-root accounts that have UID 0: "
            "usermod -u <new_uid> <username>"
        ),
        cross_references={
            "PCI-DSS": "2.2.2", "NIST": "AC-6", "CIS": "6.2.10",
            "STIG": "V-230327", "ISO27001": "A.8.2",
        },
    ))

    return results


def _check_req2_disable_unnecessary_services(os_info) -> List[AuditResult]:
    """PCI Req 2.2.4 - Only necessary services, protocols, daemons enabled."""
    results: List[AuditResult] = []
    cat = "PCI Req 2.2 - Service Hardening"

    # Insecure legacy services that should never run on a CDE host
    insecure_services = [
        ("telnet.socket", "telnet"),
        ("rsh.socket", "rsh"),
        ("rlogin.socket", "rlogin"),
        ("rexec.socket", "rexec"),
        ("vsftpd.service", "FTP server"),
        ("tftpd-hpa.service", "TFTP server"),
        ("xinetd.service", "xinetd super-server"),
    ]

    for unit, description in insecure_services:
        state = _systemd_active(unit)
        if state == "active":
            results.append(_result(
                category=cat,
                status="Fail",
                severity="High",
                message=f"PCI-2.2.4: Insecure service {description} is active",
                details=f"Unit {unit} is currently active",
                remediation=f"systemctl disable --now {unit}",
                cross_references={
                    "PCI-DSS": "2.2.4", "NIST": "CM-7", "CIS": "2.2",
                    "STIG": "V-230557",
                },
            ))
        elif state in ("inactive", "not-found", "failed", "unknown"):
            # Service not running - acceptable
            results.append(_result(
                category=cat,
                status="Pass",
                severity="Medium",
                message=f"PCI-2.2.4: Insecure service {description} is not active",
                details=f"Unit {unit} state: {state}",
                cross_references={"PCI-DSS": "2.2.4", "NIST": "CM-7"},
            ))

    return results


def _check_req2_system_hardening(os_info) -> List[AuditResult]:
    """PCI Req 2.2.1 - System hardening standards applied."""
    results: List[AuditResult] = []
    cat = "PCI Req 2.2 - System Hardening"

    # Verify ASLR is enabled (kernel.randomize_va_space = 2)
    aslr = _read_sysctl("kernel.randomize_va_space")
    aslr_full = aslr == "2"
    results.append(_result(
        category=cat,
        status="Pass" if aslr_full else "Fail",
        severity="High",
        message="PCI-2.2.1: ASLR enabled at full strength",
        details=f"kernel.randomize_va_space = {aslr or 'not set'}",
        remediation=(
            "echo 'kernel.randomize_va_space = 2' > /etc/sysctl.d/99-pci.conf "
            "&& sysctl --system"
        ),
        cross_references={
            "PCI-DSS": "2.2.1", "NIST": "SI-16", "CIS": "1.5.3",
            "STIG": "V-230278", "NSA": "KERN-1.1",
        },
    ))

    # Kernel pointer restriction
    kptr = _read_sysctl("kernel.kptr_restrict")
    kptr_ok = kptr in ("1", "2")
    results.append(_result(
        category=cat,
        status="Pass" if kptr_ok else "Fail",
        severity="Medium",
        message="PCI-2.2.1: Kernel pointer addresses restricted",
        details=f"kernel.kptr_restrict = {kptr or 'not set'} (recommended: 2)",
        remediation=(
            "echo 'kernel.kptr_restrict = 2' >> /etc/sysctl.d/99-pci.conf "
            "&& sysctl --system"
        ),
        cross_references={
            "PCI-DSS": "2.2.1", "NIST": "SI-16", "STIG": "V-230279",
        },
    ))

    # Core dump restriction (avoid memory disclosure)
    core_uses_pid = _read_sysctl("kernel.core_uses_pid")
    suid_dumpable = _read_sysctl("fs.suid_dumpable")
    suid_ok = suid_dumpable == "0"
    results.append(_result(
        category=cat,
        status="Pass" if suid_ok else "Fail",
        severity="High",
        message="PCI-2.2.1: SUID program core dumps disabled",
        details=f"fs.suid_dumpable = {suid_dumpable or 'not set'} (must be 0)",
        remediation=(
            "echo 'fs.suid_dumpable = 0' >> /etc/sysctl.d/99-pci.conf "
            "&& sysctl --system"
        ),
        cross_references={
            "PCI-DSS": "2.2.1", "NIST": "SI-16", "CIS": "1.5.1",
            "STIG": "V-230309",
        },
    ))

    # TCP SYN cookies (anti-DoS hardening)
    syncookies = _read_sysctl("net.ipv4.tcp_syncookies")
    sc_ok = syncookies == "1"
    results.append(_result(
        category=cat,
        status="Pass" if sc_ok else "Fail",
        severity="Medium",
        message="PCI-2.2.1: TCP SYN cookies enabled",
        details=f"net.ipv4.tcp_syncookies = {syncookies or 'not set'}",
        remediation=(
            "echo 'net.ipv4.tcp_syncookies = 1' >> /etc/sysctl.d/99-pci.conf "
            "&& sysctl --system"
        ),
        cross_references={
            "PCI-DSS": "2.2.1", "NIST": "SC-5", "CIS": "3.3.8",
            "STIG": "V-230549", "NSA": "NET-1.6",
        },
    ))

    # Disable IP forwarding (host should not act as router unless explicitly needed)
    ip_forward = _read_sysctl("net.ipv4.ip_forward")
    fwd_ok = ip_forward == "0"
    results.append(_result(
        category=cat,
        status="Pass" if fwd_ok else "Warning",
        severity="Medium",
        message="PCI-2.2.1: IP forwarding disabled",
        details=(
            f"net.ipv4.ip_forward = {ip_forward or 'not set'}; "
            "should be 0 unless this host is intentionally routing"
        ),
        remediation=(
            "echo 'net.ipv4.ip_forward = 0' >> /etc/sysctl.d/99-pci.conf "
            "&& sysctl --system"
        ),
        cross_references={
            "PCI-DSS": "2.2.1", "NIST": "SC-7", "CIS": "3.2.1",
            "STIG": "V-230540",
        },
    ))

    return results


# ---------------------------------------------------------------------------
# Requirement 3 - Protect Stored Account Data
# ---------------------------------------------------------------------------

def _check_req3_data_at_rest(os_info) -> List[AuditResult]:
    """PCI Req 3 - Protect stored account data."""
    results: List[AuditResult] = []
    cat = "PCI Req 3 - Stored Data Protection"

    # 3.5.1 - Detect possible cleartext PAN exposure indicators
    # Without scanning the filesystem (which could be slow and contain
    # legitimately stored payment data), check for indicators that the
    # system has cardholder data protections in place.

    # Check if disk encryption is in use (LUKS detection)
    cryptsetup_active = False
    if _command_available("dmsetup"):
        rc, out, _ = _run_command(["dmsetup", "ls", "--target=crypt"])
        if rc == 0 and out and "No devices found" not in out:
            cryptsetup_active = True

    results.append(_result(
        category=cat,
        status="Pass" if cryptsetup_active else "Info",
        severity="High",
        message="PCI-3.5.1: Disk-level encryption active (LUKS)",
        details=(
            f"LUKS-encrypted devices detected: {cryptsetup_active}. "
            "Note: PCI DSS does not mandate disk encryption specifically; "
            "it requires that stored account data be protected by approved means."
        ),
        remediation=(
            "If storing cardholder data on this system, use LUKS for "
            "disk encryption: cryptsetup luksFormat <device>"
        ),
        cross_references={
            "PCI-DSS": "3.5.1", "NIST": "SC-28", "ISO27001": "A.8.10",
            "GDPR": "Art-32", "HIPAA": "164.312(a)(2)(iv)",
        },
    ))

    # 3.6.4 - Cryptographic key management infrastructure
    # Check if crypto-policies tool present (RHEL family) or applicable
    has_crypto_policies = _file_exists("/etc/crypto-policies/config")
    if has_crypto_policies:
        policy = _read_file_safe("/etc/crypto-policies/config").strip()
        modern_policy = policy in ("DEFAULT", "FUTURE", "FIPS")
        results.append(_result(
            category=cat,
            status="Pass" if modern_policy else "Warning",
            severity="High",
            message="PCI-3.6.4: System-wide crypto policy enforces modern algorithms",
            details=f"Active crypto policy: {policy}",
            remediation=(
                "update-crypto-policies --set FUTURE  # for stricter posture"
            ),
            cross_references={
                "PCI-DSS": "3.6.4", "NIST": "SC-13", "ISO27001": "A.8.24",
                "NSA": "CRYPTO-1.1", "CIS": "1.10",
            },
        ))

    return results


# ---------------------------------------------------------------------------
# Requirement 4 - Protect Cardholder Data in Transit
# ---------------------------------------------------------------------------

def _check_req4_transit_encryption(os_info) -> List[AuditResult]:
    """PCI Req 4.2 - Strong cryptography for data in transit."""
    results: List[AuditResult] = []
    cat = "PCI Req 4.2 - Transit Encryption"

    # 4.2.1 - SSH ciphers must be modern
    sshd_config = _read_file_safe("/etc/ssh/sshd_config")
    if sshd_config:
        # Check for explicit Ciphers configuration
        cipher_lines = [
            line for line in sshd_config.splitlines()
            if line.strip().lower().startswith("ciphers ")
        ]
        weak_ciphers_seen = []
        if cipher_lines:
            cipher_line = cipher_lines[-1]  # last definition wins
            for weak in ("3des", "arcfour", "blowfish", "des-cbc",
                         "rc4", "aes128-cbc", "aes256-cbc"):
                if weak in cipher_line.lower():
                    weak_ciphers_seen.append(weak)

        if cipher_lines:
            results.append(_result(
                category=cat,
                status="Pass" if not weak_ciphers_seen else "Fail",
                severity="High",
                message="PCI-4.2.1: SSH cipher suite excludes weak algorithms",
                details=(
                    f"Configured ciphers line: {cipher_lines[-1].strip()[:200]}. "
                    f"Weak ciphers detected: {', '.join(weak_ciphers_seen) or 'none'}"
                ),
                remediation=(
                    "Set in /etc/ssh/sshd_config: Ciphers "
                    "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,"
                    "aes128-gcm@openssh.com,aes256-ctr,aes128-ctr"
                ),
                cross_references={
                    "PCI-DSS": "4.2.1", "NIST": "SC-13", "CIS": "5.2.13",
                    "STIG": "V-255924", "ISO27001": "A.8.24", "NSA": "SSH-2.1",
                },
            ))
        else:
            # No explicit Ciphers line - relying on OpenSSH defaults
            results.append(_result(
                category=cat,
                status="Warning",
                severity="Medium",
                message="PCI-4.2.1: SSH ciphers not explicitly configured",
                details=(
                    "sshd_config does not contain an explicit Ciphers directive. "
                    "Defaults vary by OpenSSH version; explicit configuration "
                    "is recommended for consistent posture."
                ),
                remediation=(
                    "Add to /etc/ssh/sshd_config: Ciphers "
                    "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,"
                    "aes128-gcm@openssh.com,aes256-ctr,aes128-ctr"
                ),
                cross_references={
                    "PCI-DSS": "4.2.1", "NIST": "SC-13", "CIS": "5.2.13",
                },
            ))

        # MAC algorithms
        mac_lines = [
            line for line in sshd_config.splitlines()
            if line.strip().lower().startswith("macs ")
        ]
        weak_macs_seen = []
        if mac_lines:
            mac_line = mac_lines[-1]
            for weak in ("md5", "sha1-96", "ripemd160"):
                if weak in mac_line.lower():
                    weak_macs_seen.append(weak)

            results.append(_result(
                category=cat,
                status="Pass" if not weak_macs_seen else "Fail",
                severity="High",
                message="PCI-4.2.1: SSH MAC algorithms exclude weak hashes",
                details=(
                    f"Configured MACs: {mac_lines[-1].strip()[:200]}. "
                    f"Weak MACs detected: {', '.join(weak_macs_seen) or 'none'}"
                ),
                remediation=(
                    "Set in /etc/ssh/sshd_config: MACs "
                    "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,"
                    "hmac-sha2-512,hmac-sha2-256"
                ),
                cross_references={
                    "PCI-DSS": "4.2.1", "NIST": "SC-13", "CIS": "5.2.14",
                    "STIG": "V-230250", "NSA": "SSH-2.2",
                },
            ))
    else:
        # SSH config file not present or unreadable
        results.append(_result(
            category=cat,
            status="Info",
            severity="Informational",
            message="PCI-4.2.1: SSH not configured on this host",
            details="/etc/ssh/sshd_config not present; OpenSSH server not installed",
            cross_references={"PCI-DSS": "4.2.1"},
        ))

    return results


# ---------------------------------------------------------------------------
# Requirement 5 - Malware Protection
# ---------------------------------------------------------------------------

def _check_req5_malware_protection(os_info) -> List[AuditResult]:
    """PCI Req 5 - Anti-malware protection."""
    results: List[AuditResult] = []
    cat = "PCI Req 5 - Malware Defence"

    # 5.2.1 - Anti-malware solution deployed
    av_indicators = {
        "ClamAV": _command_available("clamscan") or _file_exists("/etc/clamav/clamd.conf"),
        "Sophos": _file_exists("/opt/sophos-spl/bin/sophos_threat_detector"),
        "ESET": _file_exists("/opt/eset/efs/sbin/efs"),
        "TrendMicro": _file_exists("/opt/TrendMicro/SProtectLinux/SPLX.sh"),
        "Falco": _command_available("falco") or _file_exists("/etc/falco/falco.yaml"),
        "Wazuh": _file_exists("/var/ossec/etc/ossec.conf"),
        "ChkRootkit": _command_available("chkrootkit"),
        "RKHunter": _command_available("rkhunter"),
    }

    detected_av = [name for name, present in av_indicators.items() if present]

    results.append(_result(
        category=cat,
        status="Pass" if detected_av else "Fail",
        severity="High",
        message="PCI-5.2.1: Anti-malware or threat detection solution deployed",
        details=f"Detected: {', '.join(detected_av) or 'none'}",
        remediation=(
            "Install an anti-malware solution. ClamAV is open-source and "
            "available across distributions: apt-get install -y clamav clamav-daemon "
            "(Debian/Ubuntu) or dnf install -y clamav clamav-update (RHEL family)."
        ),
        cross_references={
            "PCI-DSS": "5.2.1", "NIST": "SI-3", "ISO27001": "A.8.7",
            "HIPAA": "164.308(a)(5)(ii)(B)",
        },
    ))

    # 5.2.2 - AV definitions current (ClamAV-specific check)
    if av_indicators.get("ClamAV") and _command_available("freshclam"):
        # Check freshclam log for last update time
        log_paths = (
            "/var/log/clamav/freshclam.log",
            "/var/log/freshclam.log",
        )
        last_update_seen = False
        for path in log_paths:
            content = _read_file_safe(path)
            if content and "main.cvd" in content.lower():
                last_update_seen = True
                break

        results.append(_result(
            category=cat,
            status="Info" if last_update_seen else "Warning",
            severity="Medium",
            message="PCI-5.2.2: ClamAV signature update log present",
            details=(
                f"Freshclam log evidence found: {last_update_seen}. "
                "Check log timestamp manually for recency."
            ),
            remediation=(
                "Configure freshclam to update daily: systemctl enable --now clamav-freshclam"
            ),
            cross_references={
                "PCI-DSS": "5.2.2", "NIST": "SI-3", "ISO27001": "A.8.7",
            },
        ))

    return results


# ---------------------------------------------------------------------------
# Requirement 6 - Secure Systems and Software
# ---------------------------------------------------------------------------

def _check_req6_patch_management(os_info) -> List[AuditResult]:
    """PCI Req 6.3 - Vulnerability identification and patching."""
    results: List[AuditResult] = []
    cat = "PCI Req 6.3 - Patch Management"

    # 6.3.3 - Critical/high patches applied within 30 days
    if os_info.is_debian_family() and _command_available("apt-get"):
        rc, out, _ = _run_command(
            ["apt-get", "-s", "upgrade"],
            timeout=30.0,
        )
        # Count security upgrades
        if rc == 0:
            security_count = sum(
                1 for line in out.splitlines()
                if line.startswith("Inst ") and "-security" in line.lower()
            )
            results.append(_result(
                category=cat,
                status="Pass" if security_count == 0 else "Fail",
                severity="High",
                message="PCI-6.3.3: No pending security updates",
                details=(
                    f"Pending security upgrades: {security_count}. "
                    "PCI requires critical/high vulns patched within 30 days "
                    "of vendor release."
                ),
                remediation=(
                    "apt-get update && apt-get -y upgrade  # apply all pending updates"
                ),
                cross_references={
                    "PCI-DSS": "6.3.3", "NIST": "SI-2(2)", "ISO27001": "A.8.8",
                    "HIPAA": "164.308(a)(5)(ii)(B)", "CISA": "BOD-22-01",
                    "CIS": "1.9",
                },
            ))
    elif os_info.is_redhat_family() and _command_available("dnf"):
        rc, out, _ = _run_command(
            ["dnf", "-q", "updateinfo", "list", "security"],
            timeout=30.0,
        )
        if rc == 0:
            security_count = sum(
                1 for line in out.splitlines()
                if line.strip() and not line.startswith("Last metadata")
            )
            results.append(_result(
                category=cat,
                status="Pass" if security_count == 0 else "Fail",
                severity="High",
                message="PCI-6.3.3: No pending security updates",
                details=(
                    f"Pending security advisories: {security_count}. "
                    "PCI requires critical/high vulns patched within 30 days."
                ),
                remediation=patch_for(),
                cross_references={
                    "PCI-DSS": "6.3.3", "NIST": "SI-2(2)", "ISO27001": "A.8.8",
                    "HIPAA": "164.308(a)(5)(ii)(B)", "CISA": "BOD-22-01",
                },
            ))

    # 6.4.1 - Public-facing applications protected (informational - typically WAF)
    return results


# ---------------------------------------------------------------------------
# Requirement 7 - Restrict Access by Need to Know
# ---------------------------------------------------------------------------

def _check_req7_least_privilege(os_info) -> List[AuditResult]:
    """PCI Req 7 - Access restriction by business need to know."""
    results: List[AuditResult] = []
    cat = "PCI Req 7 - Least Privilege"

    # 7.2.4 - Sudoers configuration (no NOPASSWD without justification)
    sudoers_files = ["/etc/sudoers"]
    if os.path.isdir("/etc/sudoers.d"):
        try:
            for entry in sorted(os.listdir("/etc/sudoers.d")):
                if entry == "README":
                    continue
                full = os.path.join("/etc/sudoers.d", entry)
                if os.path.isfile(full):
                    sudoers_files.append(full)
        except OSError:
            pass

    nopasswd_entries: List[str] = []
    for sf in sudoers_files:
        content = _read_file_safe(sf)
        if not content:
            continue
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            if "NOPASSWD" in stripped.upper():
                nopasswd_entries.append(f"{sf}: {stripped[:120]}")

    results.append(_result(
        category=cat,
        status="Pass" if not nopasswd_entries else "Warning",
        severity="High",
        message="PCI-7.2.5: No unauthenticated sudo elevation",
        details=(
            f"NOPASSWD sudoers entries: {len(nopasswd_entries)}. "
            f"First few: {'; '.join(nopasswd_entries[:3])}"
        ),
        remediation=(
            "Review each NOPASSWD entry for business justification. "
            "Replace with PASSWD-required rules where possible."
        ),
        cross_references={
            "PCI-DSS": "7.2.5", "NIST": "AC-6", "CIS": "5.5.4",
            "ISO27001": "A.8.2", "STIG": "V-230363",
        },
    ))

    # 7.2.6 - Default-deny access controls (SELinux/AppArmor enforcing)
    if os_info.mac_framework:
        mac_enforcing = False
        if os_info.mac_framework == "selinux":
            try:
                with open("/sys/fs/selinux/enforce", "r", encoding="ascii") as f:
                    mac_enforcing = f.read().strip() == "1"
            except OSError:
                pass
        elif os_info.mac_framework == "apparmor":
            if _command_available("aa-status"):
                rc, out, _ = _run_command(["aa-status"])
                mac_enforcing = rc == 0 and "profiles are in enforce mode" in out

        results.append(_result(
            category=cat,
            status="Pass" if mac_enforcing else "Fail",
            severity="High",
            message=f"PCI-7.2.6: Mandatory access control ({os_info.mac_framework}) enforcing",
            details=(
                f"Framework: {os_info.mac_framework}, "
                f"enforcing: {mac_enforcing}"
            ),
            remediation=(
                "Set SELinux to enforcing: setenforce 1 (and update /etc/selinux/config). "
                "For AppArmor: ensure profiles are loaded: aa-enforce /etc/apparmor.d/*"
            ),
            cross_references={
                "PCI-DSS": "7.2.6", "NIST": "AC-3(4)", "CIS": "1.6.1.3",
                "STIG": "V-230230", "NSA": "MAC-1.3",
            },
        ))

    return results


# ---------------------------------------------------------------------------
# Requirement 8 - Identification and Authentication
# ---------------------------------------------------------------------------

def _check_req8_authentication(os_info) -> List[AuditResult]:
    """PCI Req 8 - Strong authentication requirements."""
    results: List[AuditResult] = []
    cat = "PCI Req 8 - Authentication"

    # Read login.defs for password policy
    login_defs = _read_file_safe("/etc/login.defs")
    policies: Dict[str, str] = {}
    if login_defs:
        for line in login_defs.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            parts = stripped.split(None, 1)
            if len(parts) == 2:
                policies[parts[0]] = parts[1].split("#", 1)[0].strip()

    # 8.3.6 - Minimum password length 12 characters
    pass_min_len = policies.get("PASS_MIN_LEN", "")
    try:
        min_len_int = int(pass_min_len) if pass_min_len else 0
    except ValueError:
        min_len_int = 0

    # PCI v4.0.1 raised minimum to 12 chars (was 7)
    results.append(_result(
        category=cat,
        status="Pass" if min_len_int >= 12 else "Fail",
        severity="High",
        message="PCI-8.3.6: Password minimum length is 12 characters",
        details=f"PASS_MIN_LEN = {pass_min_len or 'unset'} (PCI v4.0.1 requires >= 12)",
        remediation=(
            "Set PASS_MIN_LEN to 12 or higher in /etc/login.defs. "
            "Configure pam_pwquality minlen=12 in /etc/security/pwquality.conf."
        ),
        cross_references={
            "PCI-DSS": "8.3.6", "NIST": "IA-5(1)", "CIS": "5.4.1.1",
            "HIPAA": "164.308(a)(5)(ii)(D)", "STIG": "V-230369",
        },
    ))

    # 8.3.9 - Password change frequency: every 90 days OR risk-based dynamic
    pass_max_days = policies.get("PASS_MAX_DAYS", "")
    try:
        max_days_int = int(pass_max_days) if pass_max_days else 99999
    except ValueError:
        max_days_int = 99999

    results.append(_result(
        category=cat,
        status="Pass" if max_days_int <= 90 else "Fail",
        severity="Medium",
        message="PCI-8.3.9: Password expiration <= 90 days",
        details=f"PASS_MAX_DAYS = {pass_max_days or 'unset'} (PCI requires <= 90)",
        remediation="sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs",
        cross_references={
            "PCI-DSS": "8.3.9", "NIST": "IA-5(1)", "CIS": "5.4.1.4",
            "STIG": "V-230367",
        },
    ))

    # 8.2.8 - Idle session timeout 15 minutes (900 seconds)
    # Check TMOUT in /etc/profile and /etc/profile.d/
    tmout_set = False
    tmout_value = ""
    profile_paths = ["/etc/profile"]
    if os.path.isdir("/etc/profile.d"):
        try:
            for entry in os.listdir("/etc/profile.d"):
                if entry.endswith(".sh"):
                    profile_paths.append(os.path.join("/etc/profile.d", entry))
        except OSError:
            pass

    for path in profile_paths:
        content = _read_file_safe(path)
        m = re.search(r"^\s*(?:readonly\s+|export\s+)?TMOUT=(\d+)", content, re.MULTILINE)
        if m:
            tmout_set = True
            tmout_value = m.group(1)
            try:
                if int(tmout_value) <= 900 and int(tmout_value) > 0:
                    break
            except ValueError:
                continue

    try:
        tmout_int = int(tmout_value) if tmout_value else 0
    except ValueError:
        tmout_int = 0

    tmout_ok = tmout_set and 0 < tmout_int <= 900
    results.append(_result(
        category=cat,
        status="Pass" if tmout_ok else "Fail",
        severity="Medium",
        message="PCI-8.2.8: Shell idle timeout <= 15 minutes (900 seconds)",
        details=(
            f"TMOUT set: {tmout_set}, value: {tmout_value or 'none'} "
            f"(must be > 0 and <= 900)"
        ),
        remediation=(
            "Create /etc/profile.d/tmout.sh with: "
            "readonly TMOUT=900; export TMOUT"
        ),
        cross_references={
            "PCI-DSS": "8.2.8", "NIST": "AC-12", "CIS": "5.4.4",
            "HIPAA": "164.312(a)(2)(iii)", "STIG": "V-230363",
        },
    ))

    # 8.3.4 - Account lockout after 10 failed attempts (PCI v4.0.1)
    # Check pam_faillock or pam_tally2 configuration
    faillock_files = (
        "/etc/security/faillock.conf",
        "/etc/pam.d/system-auth",
        "/etc/pam.d/common-auth",
        "/etc/pam.d/password-auth",
    )
    deny_value = None
    for path in faillock_files:
        content = _read_file_safe(path)
        if not content:
            continue
        # Look for deny= or deny <number>
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            m = re.search(r"deny\s*=\s*(\d+)", stripped)
            if m:
                deny_value = int(m.group(1))
                break
            if "pam_tally2" in stripped or "pam_faillock" in stripped:
                m = re.search(r"deny\s+(\d+)", stripped)
                if m:
                    deny_value = int(m.group(1))
                    break
        if deny_value is not None:
            break

    lockout_ok = deny_value is not None and 0 < deny_value <= 10
    results.append(_result(
        category=cat,
        status="Pass" if lockout_ok else "Fail",
        severity="High",
        message="PCI-8.3.4: Account lockout after <= 10 failed attempts",
        details=(
            f"Configured deny value: {deny_value or 'not configured'} "
            "(PCI v4.0.1 requires <= 10)"
        ),
        remediation=(
            "Configure pam_faillock with deny=5 in /etc/security/faillock.conf "
            "or in /etc/pam.d/system-auth on RHEL family. "
            "On Debian/Ubuntu, edit /etc/pam.d/common-auth."
        ),
        cross_references={
            "PCI-DSS": "8.3.4", "NIST": "AC-7", "CIS": "5.3.1",
            "HIPAA": "164.308(a)(5)(ii)(D)", "STIG": "V-230333",
        },
    ))

    return results


# ---------------------------------------------------------------------------
# Requirement 10 - Logging and Monitoring
# ---------------------------------------------------------------------------

def _check_req10_logging(os_info) -> List[AuditResult]:
    """PCI Req 10 - Audit logging requirements."""
    results: List[AuditResult] = []
    cat = "PCI Req 10 - Logging"

    # 10.2.1 - Audit logs implemented (auditd)
    auditd_state = _systemd_active("auditd.service")
    auditd_active = auditd_state == "active"

    results.append(_result(
        category=cat,
        status="Pass" if auditd_active else "Fail",
        severity="High",
        message="PCI-10.2.1: System auditing service is active",
        details=f"auditd.service state: {auditd_state}",
        remediation=remediation_for("auditd"),
        cross_references={
            "PCI-DSS": "10.2.1", "NIST": "AU-2", "CIS": "4.1.1.1",
            "STIG": "V-230395", "ISO27001": "A.8.15",
            "HIPAA": "164.312(b)",
        },
    ))

    # 10.5.4 - Audit logs written to internal/centralized log server
    rsyslog_conf = _read_file_safe("/etc/rsyslog.conf")
    rsyslog_d_files = []
    if os.path.isdir("/etc/rsyslog.d"):
        try:
            for entry in sorted(os.listdir("/etc/rsyslog.d")):
                if entry.endswith(".conf"):
                    rsyslog_d_files.append(os.path.join("/etc/rsyslog.d", entry))
        except OSError:
            pass

    # Look for forwarding configuration (@hostname, @@hostname, action with omfwd)
    remote_logging = False
    for content_source in [rsyslog_conf] + [_read_file_safe(f) for f in rsyslog_d_files]:
        if not content_source:
            continue
        for line in content_source.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            # @host or @@host indicates forwarding
            if re.search(r"^[*\.][^\s]+\s+@@?[a-zA-Z0-9.\-]+", stripped):
                remote_logging = True
                break
            if "omfwd" in stripped:
                remote_logging = True
                break
        if remote_logging:
            break

    results.append(_result(
        category=cat,
        status="Pass" if remote_logging else "Warning",
        severity="High",
        message="PCI-10.5.4: Audit logs forwarded to centralized log server",
        details=(
            f"Remote rsyslog forwarding configured: {remote_logging}. "
            "PCI DSS requires log centralization for tamper resistance."
        ),
        remediation=(
            "Configure rsyslog to forward to a remote log server. "
            "Example: echo '*.* @@logserver.example.com:514' > /etc/rsyslog.d/50-remote.conf"
        ),
        cross_references={
            "PCI-DSS": "10.5.4", "NIST": "AU-6(3)", "CIS": "4.2.1.5",
            "ISO27001": "A.8.15",
        },
    ))

    # 10.6.1 - Time synchronization
    chrony_active = _systemd_active("chronyd.service") == "active" or \
                    _systemd_active("chrony.service") == "active"
    ntpd_active = _systemd_active("ntp.service") == "active" or \
                  _systemd_active("ntpd.service") == "active"
    systemd_timesyncd = _systemd_active("systemd-timesyncd.service") == "active"

    time_sync_active = chrony_active or ntpd_active or systemd_timesyncd
    sync_method = (
        "chrony" if chrony_active
        else "ntpd" if ntpd_active
        else "systemd-timesyncd" if systemd_timesyncd
        else "none"
    )

    results.append(_result(
        category=cat,
        status="Pass" if time_sync_active else "Fail",
        severity="Medium",
        message="PCI-10.6.1: Time synchronization service active",
        details=f"Active time sync: {sync_method}",
        remediation=remediation_for("chrony"),
        cross_references={
            "PCI-DSS": "10.6.1", "NIST": "AU-8(1)", "CIS": "2.1.1.1",
            "STIG": "V-230484", "ISO27001": "A.8.17",
        },
    ))

    # 10.5.1 - Audit log retention
    auditd_conf = _read_file_safe("/etc/audit/auditd.conf")
    max_log_file = ""
    num_logs = ""
    for line in auditd_conf.splitlines():
        stripped = line.strip()
        if stripped.startswith("max_log_file ") or stripped.startswith("max_log_file="):
            max_log_file = stripped.split("=", 1)[-1].strip() if "=" in stripped else stripped.split()[-1]
        elif stripped.startswith("num_logs ") or stripped.startswith("num_logs="):
            num_logs = stripped.split("=", 1)[-1].strip() if "=" in stripped else stripped.split()[-1]

    has_retention_config = bool(max_log_file and num_logs)
    results.append(_result(
        category=cat,
        status="Info" if has_retention_config else "Warning",
        severity="Medium",
        message="PCI-10.5.1: Audit log retention configured (>= 12 months effective)",
        details=(
            f"max_log_file = {max_log_file or 'unset'}, "
            f"num_logs = {num_logs or 'unset'}. "
            "Effective retention requires log shipping to long-term storage; "
            "host-only retention is rarely sufficient for 12-month requirement."
        ),
        remediation=(
            "Configure /etc/audit/auditd.conf with appropriate max_log_file "
            "and num_logs, plus log shipping to centralized storage with "
            "12-month online retention."
        ),
        cross_references={
            "PCI-DSS": "10.5.1", "NIST": "AU-11", "ISO27001": "A.8.15",
            "HIPAA": "164.530(j)",
        },
    ))

    return results


# ---------------------------------------------------------------------------
# Requirement 11 - Security Testing
# ---------------------------------------------------------------------------

def _check_req11_security_testing(os_info) -> List[AuditResult]:
    """PCI Req 11 - Security testing and detection."""
    results: List[AuditResult] = []
    cat = "PCI Req 11 - Security Testing"

    # 11.5.1 - Intrusion detection or prevention deployed
    ids_indicators = {
        "Suricata": _command_available("suricata") or _file_exists("/etc/suricata/suricata.yaml"),
        "Snort": _command_available("snort"),
        "OSSEC": _file_exists("/var/ossec/etc/ossec.conf"),
        "Wazuh": _file_exists("/var/ossec/etc/ossec.conf"),  # Wazuh is OSSEC fork
        "Falco": _command_available("falco") or _file_exists("/etc/falco/falco.yaml"),
        "auditd": _systemd_active("auditd.service") == "active",
    }
    detected_ids = [name for name, present in ids_indicators.items() if present]

    results.append(_result(
        category=cat,
        status="Pass" if detected_ids else "Fail",
        severity="High",
        message="PCI-11.5.1: Intrusion detection mechanism in place",
        details=f"Detected: {', '.join(detected_ids) or 'none'}",
        remediation=(
            "Deploy a host or network IDS. Falco for runtime detection, "
            "Suricata for network IDS, Wazuh/OSSEC for HIDS+SIEM integration."
        ),
        cross_references={
            "PCI-DSS": "11.5.1", "NIST": "SI-4", "ISO27001": "A.8.16",
            "NSA": "DETECT-1.1",
        },
    ))

    # 11.5.2 - File integrity monitoring on critical files
    fim_indicators = {
        "AIDE": _command_available("aide") or _file_exists("/etc/aide.conf") or _file_exists("/etc/aide/aide.conf"),
        "Tripwire": _command_available("tripwire") or _file_exists("/etc/tripwire/twcfg.txt"),
        "OSSEC/Wazuh": _file_exists("/var/ossec/etc/ossec.conf"),
        "Samhain": _command_available("samhain"),
    }
    detected_fim = [name for name, present in fim_indicators.items() if present]

    results.append(_result(
        category=cat,
        status="Pass" if detected_fim else "Fail",
        severity="High",
        message="PCI-11.5.2: File integrity monitoring deployed",
        details=f"Detected FIM tools: {', '.join(detected_fim) or 'none'}",
        remediation=remediation_for("aide"),
        cross_references={
            "PCI-DSS": "11.5.2", "NIST": "SI-7", "ISO27001": "A.8.16",
            "HIPAA": "164.312(c)(1)",
        },
    ))

    return results


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the PCI DSS module against the current host.

    Returns a list of AuditResult instances. The orchestrator aggregates
    these with results from other modules and runs the v3.0 pipeline
    (validation, correlation enrichment, risk scoring, compliance scoring)
    before report generation.

    Modules following this convention can be invoked standalone:
        python3 modules/module_pci.py

    or via the orchestrator:
        python3 linux_security_audit.py --modules PCI
    """
    if shared_data is None:
        shared_data = {}

    # Detect OS once. Callers that pre-populate shared_data["os_info"] in
    # an OSInfo-compatible form benefit from cache reuse.
    os_info = shared_data.get("v3_os_info")
    if os_info is None:
        os_info = os_detection.detect_os()
        shared_data["v3_os_info"] = os_info

    results: List[AuditResult] = []

    # Each Requirement family is a separate function so individual sections
    # can be timed, profiled, or selectively skipped during development.
    try:
        results.extend(_check_req1_firewall(os_info))
        results.extend(_check_req1_traffic_restrictions(os_info))
        results.extend(_check_req2_no_default_passwords(os_info))
        results.extend(_check_req2_disable_unnecessary_services(os_info))
        results.extend(_check_req2_system_hardening(os_info))
        results.extend(_check_req3_data_at_rest(os_info))
        results.extend(_check_req4_transit_encryption(os_info))
        results.extend(_check_req5_malware_protection(os_info))
        results.extend(_check_req6_patch_management(os_info))
        results.extend(_check_req7_least_privilege(os_info))
        results.extend(_check_req8_authentication(os_info))
        results.extend(_check_req10_logging(os_info))
        results.extend(_check_req11_security_testing(os_info))
    except Exception as exc:  # noqa: BLE001 - top-level safety net
        logger.exception("Unhandled exception in PCI module")
        results.append(_result(
            category="PCI - Error",
            status="Error",
            severity="Medium",
            message=f"PCI module encountered an unhandled exception: {exc!r}",
            details=str(exc),
        ))

    return results


# Standalone invocation for module-level testing.

# ===========================================================================
# v3.1 EXPANSION - PCI DSS v4.0.1 Targeted Additions
# ---------------------------------------------------------------------------
# Builds on the comprehensive PCI baseline with depth additions:
#   - Req 3 deeper: tokenization indicators, HSM/KMS detection, key rotation
#   - Req 4 deeper: SMTP/IMAP/database TLS, certificate validity tracking
#   - Req 6 deeper: SDLC indicators, code review evidence, container scanning
#   - Req 9 host-applicable: media destruction tooling
#   - Req 12 technical indicators: security awareness training tools
# ===========================================================================



def __directory_exists(path: str) -> bool:
    return os.path.isdir(path)


def _check_req3_extended(os_info) -> List[AuditResult]:
    """PCI Req 3 extended - key management, HSM, tokenization."""
    results: List[AuditResult] = []
    cat = "PCI Req 3 Extended"

    # 3.5/3.6 - HSM/KMS detection
    hsm_indicators = {
        "softhsm": (
            _file_exists("/etc/softhsm/softhsm2.conf") or
            _command_available("softhsm2-util")
        ),
        "yubihsm": _command_available("yubihsm-shell"),
        "azure-keyvault-cli": _command_available("az"),
        "aws-cli": _command_available("aws"),
        "vault": _command_available("vault"),
        "tpm2-tools": _command_available("tpm2_pcrread"),
    }
    detected = [k for k, v in hsm_indicators.items() if v]
    results.append(_result(
        cat, "Info",
        f"Req 3.5: Key management infrastructure indicators ({len(detected)})",
        severity="Informational",
        details=f"Detected: {detected}",
        remediation=(
            "PCI Req 3 requires keys to be: stored separately from data, "
            "rotated annually, and protected by HSM or equivalent. "
            "HashiCorp Vault, AWS KMS, Azure Key Vault, or HSM are acceptable."
        ),
        cross_references={
            "PCI-DSS": "3.5", "NIST": "SC-12", "ISO27001": "A.8.24",
        },
    ))

    # 3.5.3 - Key rotation
    # If LUKS in use, check if header backup exists (rotation enables this)
    luks_present = False
    if _command_available("dmsetup"):
        rc, out, _ = _run_command(["dmsetup", "ls", "--target=crypt"], timeout=5.0)
        if rc == 0 and out and "No devices" not in out:
            luks_present = True

    if luks_present:
        results.append(_result(
            cat, "Info",
            "Req 3.6.4: LUKS device encryption present (key rotation manual review)",
            severity="Medium",
            details="LUKS-encrypted device detected",
            remediation=(
                "LUKS supports key rotation via cryptsetup luksAddKey/luksRemoveKey. "
                "Document rotation cadence (typically annual) per PCI 3.6.4."
            ),
            cross_references={
                "PCI-DSS": "3.6.4", "NIST": "SC-12(2)",
            },
        ))

    # 3.7.1 - Cryptographic key access restricted
    # Check ssh key file permissions
    ssh_key_files = [
        "/etc/ssh/ssh_host_rsa_key",
        "/etc/ssh/ssh_host_ecdsa_key",
        "/etc/ssh/ssh_host_ed25519_key",
    ]
    insecure_keys = []
    for kf in ssh_key_files:
        if _file_exists(kf):
            mode = _file_mode(kf)
            if mode is not None and mode > 0o600:
                insecure_keys.append(f"{kf}: {oct(mode)}")

    results.append(_result(
        cat, "Pass" if not insecure_keys else "Fail",
        f"Req 3.7.1: SSH host keys protected (mode <=600)",
        severity="High",
        details=f"Insecure key permissions: {insecure_keys}",
        remediation="chmod 600 /etc/ssh/ssh_host_*_key",
        cross_references={
            "PCI-DSS": "3.7.1", "NIST": "SC-12", "STIG": "V-230290",
        },
    ))

    return results


def _check_req4_extended(os_info) -> List[AuditResult]:
    """PCI Req 4 extended - additional protocol coverage."""
    results: List[AuditResult] = []
    cat = "PCI Req 4 Extended"

    # Req 4.2.1 - SMTP TLS (Postfix)
    postfix_main = _read_file_safe("/etc/postfix/main.cf")
    if postfix_main:
        smtp_tls_match = re.search(
            r"^\s*smtp_tls_security_level\s*=\s*(\w+)", postfix_main, re.MULTILINE
        )
        smtp_tls = smtp_tls_match.group(1).lower() if smtp_tls_match else "none"
        results.append(_result(
            cat, "Pass" if smtp_tls in ("encrypt", "verify", "secure") else "Fail",
            f"Req 4.2.1: Postfix outbound SMTP TLS: {smtp_tls}",
            severity="High",
            details=f"smtp_tls_security_level: {smtp_tls}",
            remediation=(
                "/etc/postfix/main.cf: smtp_tls_security_level = encrypt"
            ),
            cross_references={
                "PCI-DSS": "4.2.1", "NIST": "SC-8(1)",
            },
        ))

        smtpd_tls_match = re.search(
            r"^\s*smtpd_tls_security_level\s*=\s*(\w+)", postfix_main, re.MULTILINE
        )
        smtpd_tls = smtpd_tls_match.group(1).lower() if smtpd_tls_match else "none"
        results.append(_result(
            cat, "Pass" if smtpd_tls in ("encrypt", "may") else "Warning",
            f"Req 4.2.1: Postfix inbound SMTP TLS: {smtpd_tls}",
            severity="High",
            details=f"smtpd_tls_security_level: {smtpd_tls}",
            remediation=(
                "/etc/postfix/main.cf: smtpd_tls_security_level = may "
                "(opportunistic for general MX) or encrypt (forced for internal)"
            ),
            cross_references={
                "PCI-DSS": "4.2.1", "NIST": "SC-8(1)",
            },
        ))

    # Req 4.2.1 - Database TLS (MySQL/MariaDB)
    mysql_conf_paths = [
        "/etc/mysql/mariadb.conf.d/50-server.cnf",
        "/etc/mysql/mysql.conf.d/mysqld.cnf",
        "/etc/my.cnf",
        "/etc/mysql/my.cnf",
    ]
    mysql_tls_configured = False
    for p in mysql_conf_paths:
        c = _read_file_safe(p)
        if c and ("ssl-ca" in c or "ssl_ca" in c or "require_secure_transport" in c):
            mysql_tls_configured = True
            break
    if any(_file_exists(p) for p in mysql_conf_paths):
        results.append(_result(
            cat, "Pass" if mysql_tls_configured else "Warning",
            f"Req 4.2.1: MySQL/MariaDB TLS configured: {mysql_tls_configured}",
            severity="High",
            details=f"MySQL TLS config detected: {mysql_tls_configured}",
            remediation=(
                "In my.cnf [mysqld]: ssl-ca=/etc/mysql/ca.pem; "
                "ssl-cert=/etc/mysql/server-cert.pem; ssl-key=/etc/mysql/server-key.pem; "
                "require_secure_transport=ON"
            ),
            cross_references={
                "PCI-DSS": "4.2.1", "NIST": "SC-8(1)",
            },
        ))

    # PostgreSQL TLS
    postgres_conf_paths = [
        "/etc/postgresql/14/main/postgresql.conf",
        "/etc/postgresql/15/main/postgresql.conf",
        "/etc/postgresql/16/main/postgresql.conf",
        "/var/lib/pgsql/data/postgresql.conf",
    ]
    pg_conf = ""
    for p in postgres_conf_paths:
        if _file_exists(p):
            pg_conf = _read_file_safe(p)
            break

    if pg_conf:
        ssl_on = re.search(r"^\s*ssl\s*=\s*on", pg_conf, re.MULTILINE)
        results.append(_result(
            cat, "Pass" if ssl_on else "Warning",
            f"Req 4.2.1: PostgreSQL TLS enabled: {bool(ssl_on)}",
            severity="High",
            details=f"PostgreSQL ssl = on: {bool(ssl_on)}",
            remediation=(
                "In postgresql.conf: ssl = on; ssl_cert_file='/etc/ssl/...'; "
                "ssl_key_file='/etc/ssl/...'"
            ),
            cross_references={
                "PCI-DSS": "4.2.1", "NIST": "SC-8(1)",
            },
        ))

    return results


def _check_req6_extended(os_info) -> List[AuditResult]:
    """PCI Req 6 extended - SDLC and container scanning."""
    results: List[AuditResult] = []
    cat = "PCI Req 6 Extended"

    # Req 6.3.2 - Code review tools
    code_review_tools = {
        "sonarqube": __directory_exists("/opt/sonarqube"),
        "git": _command_available("git"),
        "git-hooks-helper": _file_exists("/usr/local/bin/pre-commit"),
        "pre-commit": _command_available("pre-commit"),
    }
    detected = [k for k, v in code_review_tools.items() if v]
    results.append(_result(
        cat, "Info",
        f"Req 6.3.2: Code review tooling indicators ({len(detected)})",
        severity="Informational",
        details=f"Tools: {detected}",
        remediation=(
            "PCI 6.3.2 requires custom code review prior to release. "
            "Tools: SonarQube, Snyk Code, Coverity. Process documentation also required."
        ),
        cross_references={
            "PCI-DSS": "6.3.2", "NIST": "SA-11",
        },
    ))

    # Req 6.4 - Container scanning
    container_scanners = {
        "trivy": _command_available("trivy"),
        "grype": _command_available("grype"),
        "clair": __directory_exists("/opt/clair"),
        "anchore": _command_available("anchore"),
        "syft": _command_available("syft"),
    }
    detected_scanners = [k for k, v in container_scanners.items() if v]
    container_runtime = (
        _command_available("docker") or
        _command_available("podman") or
        _command_available("ctr") or
        _command_available("nerdctl")
    )

    if container_runtime:
        results.append(_result(
            cat, "Pass" if detected_scanners else "Warning",
            f"Req 6.4: Container vulnerability scanner ({len(detected_scanners)}) on container host",
            severity="High",
            details=(
                f"Container runtime detected: {container_runtime}, "
                f"Scanners: {detected_scanners}"
            ),
            remediation=(
                "Install Trivy: apt-get install -y trivy. "
                "Scan images: trivy image <image>. "
                "Integrate with CI/CD."
            ),
            cross_references={
                "PCI-DSS": "6.3.3", "NIST": "RA-5", "ISO27001": "A.5.34",
            },
        ))

    return results


def _check_req9_media_destruction(os_info) -> List[AuditResult]:
    """PCI Req 9 - host-applicable media destruction tooling."""
    results: List[AuditResult] = []
    cat = "PCI Req 9 Media Destruction"

    # 9.4.7 - Hard copy media destruction (host: secure deletion tools)
    deletion_tools = {
        "shred": _command_available("shred"),
        "wipe": _command_available("wipe"),
        "scrub": _command_available("scrub"),
        "blkdiscard": _command_available("blkdiscard"),
        "cryptsetup": _command_available("cryptsetup"),
        "hdparm": _command_available("hdparm"),
    }
    detected = [k for k, v in deletion_tools.items() if v]
    results.append(_result(
        cat, "Pass" if len(detected) >= 2 else "Warning",
        f"Req 9.4.7: Secure deletion tools ({len(detected)} found)",
        severity="Medium",
        details=f"Detected: {detected}",
        remediation=(
            "Install: apt-get install -y coreutils (shred), scrub, hdparm. "
            "Document procedure: shred for files, blkdiscard for SSDs, "
            "hdparm secure-erase for full disk."
        ),
        cross_references={
            "PCI-DSS": "9.4.7", "NIST": "MP-6", "ISO27001": "A.7.14",
        },
    ))

    return results


def _check_req12_technical_indicators(os_info) -> List[AuditResult]:
    """PCI Req 12 - host-applicable technical indicators."""
    results: List[AuditResult] = []
    cat = "PCI Req 12 Technical Indicators"

    # Req 12.6 - Security awareness banner
    issue_net = _read_file_safe("/etc/issue.net")
    has_security_text = (
        len(issue_net) > 100 and
        ("unauthorized" in issue_net.lower() or "security" in issue_net.lower())
    )
    results.append(_result(
        cat, "Pass" if has_security_text else "Warning",
        "Req 12.6.1: Security awareness reminder via login banner",
        severity="Medium",
        details=f"/etc/issue.net length: {len(issue_net)}, has security text: {has_security_text}",
        remediation=(
            "Configure /etc/issue.net with PCI-required warning: monitoring "
            "notice, unauthorized access prohibition, contact info."
        ),
        cross_references={
            "PCI-DSS": "12.6.1", "NIST": "AC-8",
        },
    ))

    # Req 12.10 - Incident response: detection capabilities
    detection_tools = {
        "auditd": _systemd_active("auditd.service") == "active",
        "wazuh": _file_exists("/var/ossec/etc/ossec.conf"),
        "falco": _command_available("falco"),
        "fail2ban": _systemd_active("fail2ban.service") == "active",
    }
    detected = [k for k, v in detection_tools.items() if v]
    results.append(_result(
        cat, "Pass" if len(detected) >= 2 else "Fail",
        f"Req 12.10.1: Multiple incident detection layers ({len(detected)})",
        severity="High",
        details=f"Tools: {detected}",
        remediation=(
            "Deploy defense-in-depth: auditd + Wazuh + Falco + fail2ban"
        ),
        cross_references={
            "PCI-DSS": "12.10.1", "NIST": "IR-4", "ISO27001": "A.5.24",
        },
    ))

    return results


# Save reference to original
_original_run_checks_pci = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the expanded PCI module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_pci(shared_data)

    os_info = shared_data.get("v3_os_info")
    if os_info is None:
        os_info = os_detection.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        results.extend(_check_req3_extended(os_info))
        results.extend(_check_req4_extended(os_info))
        results.extend(_check_req6_extended(os_info))
        results.extend(_check_req9_media_destruction(os_info))
        results.extend(_check_req12_technical_indicators(os_info))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled exception in PCI v3.1 expansion")
        results.append(_result(
            "PCI - Error", "Error",
            f"PCI v3.1 expansion exception: {exc!r}",
            severity="Medium", details=str(exc),
        ))

    return results


# ===========================================================================
# v3.3 EXPANSION - PCI DSS Comprehensive Coverage
# ---------------------------------------------------------------------------
# Adds depth across all 12 PCI DSS v4.0 requirements
# ===========================================================================




def _safe_listdir(path: str) -> List[str]:
    """Safe directory listing for PCI module helpers."""
    try:
        return os.listdir(path)
    except OSError:
        return []


def _check_pci_req1_extended_v33(os_info) -> List[AuditResult]:
    """PCI Req 1 - Network security controls (extended)."""
    results: List[AuditResult] = []
    cat = "PCI Req 1 Extended v3.3"

    # 1.2.5 - Documented network architecture indicators
    rc, out, _ = _run_command(["ip", "-br", "addr"], timeout=3.0)
    iface_count = 0
    if rc == 0 and out:
        iface_count = sum(
            1 for line in out.splitlines()
            if line.strip() and "lo" not in line.split()[0]
        )
    results.append(_result(
        cat, "Info",
        f"PCI-1.2.5: Network interfaces enumerated ({iface_count})",
        severity="Informational",
        details=f"Non-loopback interfaces: {iface_count}",
        cross_references={
            "PCI-DSS": "1.2.5", "NIST": "AC-4",
        },
    ))

    # 1.2.6 - Documented config management for security devices
    nft_rules_present = (
        _file_exists("/etc/nftables.conf") or
        __directory_exists("/etc/nftables.d")
    )
    results.append(_result(
        cat, "Pass" if nft_rules_present else "Info",
        f"PCI-1.2.6: nftables ruleset documented: {nft_rules_present}",
        severity="Medium",
        details=f"nftables config present: {nft_rules_present}",
        remediation=(
            "Document firewall rulesets in /etc/nftables.conf. "
            "Use comments to explain each rule's purpose."
        ),
        cross_references={
            "PCI-DSS": "1.2.6", "NIST": "CM-6",
        },
    ))

    # 1.4.4 - Anti-spoofing measures
    rp_filter = _read_sysctl("net.ipv4.conf.all.rp_filter")
    rp_filter_ok = rp_filter == "1"
    results.append(_result(
        cat, "Pass" if rp_filter_ok else "Fail",
        f"PCI-1.4.4: Reverse path filtering (rp_filter=1): {rp_filter_ok}",
        severity="High",
        details=f"net.ipv4.conf.all.rp_filter = {rp_filter}",
        remediation=(
            "echo 'net.ipv4.conf.all.rp_filter = 1' >> /etc/sysctl.d/99-network.conf"
        ),
        cross_references={
            "PCI-DSS": "1.4.4", "NIST": "SC-7", "CIS": "3.3.7",
        },
    ))

    # 1.4.5 - Outbound traffic restrictions: NAT/masquerade indicator
    nat_rules = ""
    if _command_available("nft"):
        rc, out, _ = _run_command(["nft", "list", "table", "ip", "nat"], timeout=3.0)
        if rc == 0:
            nat_rules = out
    if not nat_rules and _command_available("iptables"):
        rc, out, _ = _run_command(["iptables", "-t", "nat", "-S"], timeout=3.0)
        if rc == 0:
            nat_rules = out
    has_nat = nat_rules and ("MASQUERADE" in nat_rules or "SNAT" in nat_rules
                              or "masquerade" in nat_rules)
    results.append(_result(
        cat, "Info",
        f"PCI-1.4.5: NAT/masquerade rules detected: {bool(has_nat)}",
        severity="Informational",
        details=f"NAT rule indicator: {bool(has_nat)}",
        cross_references={
            "PCI-DSS": "1.4.5", "NIST": "SC-7",
        },
    ))

    return results


def _check_pci_req2_extended_v33(os_info) -> List[AuditResult]:
    """PCI Req 2 - System configuration extended."""
    results: List[AuditResult] = []
    cat = "PCI Req 2 Extended v3.3"

    # 2.2.4 - Insecure services / protocols disabled
    insecure_services = ["telnet.socket", "rsh.socket", "rlogin.socket",
                         "rexec.socket", "tftp.socket", "vsftpd.service",
                         "xinetd.service"]
    enabled_insecure = []
    for svc in insecure_services:
        if _systemd_active(svc) == "active":
            enabled_insecure.append(svc)
    results.append(_result(
        cat, "Pass" if not enabled_insecure else "Fail",
        f"PCI-2.2.4: Insecure services disabled ({len(enabled_insecure)} enabled)",
        severity="High",
        details=f"Active insecure: {enabled_insecure}",
        remediation=(
            "Disable: systemctl disable --now telnet.socket rsh.socket "
            "rlogin.socket rexec.socket tftp.socket"
        ),
        cross_references={
            "PCI-DSS": "2.2.4", "NIST": "CM-7", "STIG": "V-230290",
        },
    ))

    # 2.2.5 - System security parameters configured (key kernel params)
    kernel_params = {
        "net.ipv4.ip_forward": "0",
        "net.ipv4.conf.all.accept_source_route": "0",
        "net.ipv4.conf.all.accept_redirects": "0",
        "net.ipv4.conf.all.secure_redirects": "0",
        "net.ipv4.conf.all.log_martians": "1",
        "net.ipv4.icmp_echo_ignore_broadcasts": "1",
        "net.ipv4.icmp_ignore_bogus_error_responses": "1",
    }
    misconfig = []
    for k, v in kernel_params.items():
        actual = _read_sysctl(k)
        if actual != v:
            misconfig.append(f"{k}={actual or 'unset'}")
    results.append(_result(
        cat, "Pass" if not misconfig else "Warning",
        f"PCI-2.2.5: System security parameters ({len(misconfig)} issues)",
        severity="Medium",
        details=(
            f"Misconfig: {misconfig[:5]}" if misconfig else "All key params set"
        ),
        remediation=(
            "Apply CIS network hardening profile via sysctl.d configuration"
        ),
        cross_references={
            "PCI-DSS": "2.2.5", "NIST": "CM-6", "CIS": "3.3",
        },
    ))

    # 2.2.6 - System security functions configured
    cron_active = _systemd_active("cron.service") == "active" or \
                  _systemd_active("crond.service") == "active"
    results.append(_result(
        cat, "Pass" if cron_active else "Info",
        f"PCI-2.2.6: cron daemon active for scheduled security tasks: {cron_active}",
        severity="Low",
        details=f"cron service active: {cron_active}",
        cross_references={
            "PCI-DSS": "2.2.6", "NIST": "CM-6",
        },
    ))

    return results


def _check_pci_req3_kms_v33(os_info) -> List[AuditResult]:
    """PCI Req 3 - Key management indicators."""
    results: List[AuditResult] = []
    cat = "PCI Req 3 KMS v3.3"

    # 3.5.1 - Cryptographic key management
    kms_indicators = {
        "vault": (
            _command_available("vault") or
            _file_exists("/etc/vault.d/vault.hcl") or
            _systemd_active("vault.service") == "active"
        ),
        "barbican": __directory_exists("/etc/barbican"),
        "softhsm": _command_available("softhsm2-util"),
        "tpm2-tools": _command_available("tpm2_create"),
        "kmip-client": _command_available("kmip-client"),
    }
    detected = [k for k, v in kms_indicators.items() if v]
    results.append(_result(
        cat, "Pass" if detected else "Info",
        f"PCI-3.5.1: Key management infrastructure ({len(detected)})",
        severity="High",
        details=f"Detected: {detected or 'none'}",
        remediation=(
            "Deploy HashiCorp Vault for key management: "
            "https://learn.hashicorp.com/vault. "
            "Or use TPM2 tools for hardware-backed key storage."
        ),
        cross_references={
            "PCI-DSS": "3.5.1", "NIST": "SC-12", "FIPS": "140-3",
        },
    ))

    # 3.6.1 - Cryptographic keys protected (file permissions on key stores)
    key_paths = [
        ("/etc/ssl/private", 0o710),
        ("/etc/pki/tls/private", 0o710),
        ("/root/.gnupg", 0o700),
    ]
    issues = []
    for path, max_mode in key_paths:
        if not __directory_exists(path):
            continue
        try:
            st = os.stat(path)
            actual_mode = st.st_mode & 0o7777
            if actual_mode & 0o077:  # any group/other access
                issues.append(f"{path}={oct(actual_mode)}")
        except OSError:
            continue
    results.append(_result(
        cat, "Pass" if not issues else "Warning",
        f"PCI-3.6.1: Key store directory permissions ({len(issues)} issues)",
        severity="High",
        details=f"Issues: {issues}",
        remediation=(
            "chmod 0700 /etc/ssl/private; chown root:root /etc/ssl/private"
        ),
        cross_references={
            "PCI-DSS": "3.6.1", "NIST": "SC-12(2)",
        },
    ))

    # 3.6.4 - Cryptographic key changes
    cert_age_check = False
    if __directory_exists("/etc/ssl/certs"):
        # Look for ssl-cert-snakeoil and check age
        snakeoil = "/etc/ssl/certs/ssl-cert-snakeoil.pem"
        if _file_exists(snakeoil):
            cert_age_check = True
    results.append(_result(
        cat, "Info",
        f"PCI-3.6.4: Default snakeoil cert detected: {cert_age_check}",
        severity="Informational",
        details=f"Default ssl-cert-snakeoil indicator: {cert_age_check}",
        remediation=(
            "Replace default certificates with organization-issued. "
            "Implement annual key rotation policy."
        ),
        cross_references={
            "PCI-DSS": "3.6.4", "NIST": "SC-12",
        },
    ))

    # 3.7.6 - Cleartext key/PIN guidance: detect potentially exposed keys
    suspicious_paths = [
        "/tmp/key", "/var/tmp/key", "/home/*/key", "/root/key",
        "/tmp/cert", "/tmp/credentials",
    ]
    # Just check /tmp and /var/tmp for key-like filenames
    suspicious_count = 0
    for tmpdir in ["/tmp", "/var/tmp"]:
        if __directory_exists(tmpdir):
            for f in _safe_listdir(tmpdir):
                lf = f.lower()
                if any(k in lf for k in ["key", "cert", "pem", "pfx", "p12",
                                          "credential"]):
                    suspicious_count += 1
    results.append(_result(
        cat, "Pass" if suspicious_count == 0 else "Warning",
        f"PCI-3.7.6: Suspicious key/cert files in /tmp ({suspicious_count})",
        severity="High",
        details=f"Files matching key/cert pattern in /tmp: {suspicious_count}",
        remediation=(
            "Move keys to /etc/ssl/private with chmod 0600. Never store "
            "in world-accessible /tmp."
        ),
        cross_references={
            "PCI-DSS": "3.7.6", "NIST": "SC-12",
        },
    ))

    return results


def _check_pci_req4_tls_depth_v33(os_info) -> List[AuditResult]:
    """PCI Req 4 - TLS depth checks."""
    results: List[AuditResult] = []
    cat = "PCI Req 4 TLS v3.3"

    # 4.2.1.2 - Strong cryptography on web servers
    apache_present = __directory_exists("/etc/apache2") or __directory_exists("/etc/httpd")
    nginx_present = __directory_exists("/etc/nginx")

    if apache_present:
        # Check SSL config
        ssl_configs = []
        for d in ["/etc/apache2/mods-enabled", "/etc/httpd/conf.d",
                   "/etc/httpd/conf.modules.d"]:
            if __directory_exists(d):
                for f in _safe_listdir(d):
                    if "ssl" in f.lower() and f.endswith(".conf"):
                        ssl_configs.append(os.path.join(d, f))

        ssl_protocol_modern = False
        for cfg in ssl_configs:
            c = _read_file_safe(cfg)
            if "SSLProtocol" in c:
                if re.search(r"SSLProtocol\s+.*-TLSv1\s", c) or \
                   re.search(r"SSLProtocol\s+all\s+-SSL", c):
                    ssl_protocol_modern = True
                if "TLSv1.2" in c or "TLSv1.3" in c:
                    ssl_protocol_modern = True
                break

        results.append(_result(
            cat, "Pass" if ssl_protocol_modern else "Warning",
            f"PCI-4.2.1.2: Apache SSLProtocol modern (TLS 1.2+): {ssl_protocol_modern}",
            severity="High",
            details=f"Modern SSLProtocol indicator: {ssl_protocol_modern}",
            remediation=(
                "In Apache SSL config: SSLProtocol -all +TLSv1.2 +TLSv1.3"
            ),
            cross_references={
                "PCI-DSS": "4.2.1.2", "NIST": "SC-13",
            },
        ))

    if nginx_present:
        nginx_main = _read_file_safe("/etc/nginx/nginx.conf")
        nginx_ssl_configs = nginx_main
        for d in ["/etc/nginx/conf.d", "/etc/nginx/sites-enabled"]:
            if __directory_exists(d):
                for f in _safe_listdir(d):
                    nginx_ssl_configs += "\n" + _read_file_safe(os.path.join(d, f))

        ssl_protocols_match = re.search(
            r"ssl_protocols\s+([^;]+);", nginx_ssl_configs
        )
        nginx_modern = False
        if ssl_protocols_match:
            protos = ssl_protocols_match.group(1).strip()
            nginx_modern = (
                "TLSv1.2" in protos or "TLSv1.3" in protos
            ) and "TLSv1 " not in protos and "SSLv" not in protos

        results.append(_result(
            cat, "Pass" if nginx_modern else "Warning",
            f"PCI-4.2.1.2: Nginx ssl_protocols modern: {nginx_modern}",
            severity="High",
            details=(
                f"ssl_protocols: {ssl_protocols_match.group(1) if ssl_protocols_match else 'default'}"
            ),
            remediation=(
                "In nginx.conf: ssl_protocols TLSv1.2 TLSv1.3;"
            ),
            cross_references={
                "PCI-DSS": "4.2.1.2", "NIST": "SC-13",
            },
        ))

    # 4.2.1.4 - Certificate trust validation
    ca_cert_dirs = ["/etc/ssl/certs", "/etc/pki/ca-trust/source/anchors",
                     "/usr/local/share/ca-certificates"]
    ca_certs_present = any(__directory_exists(d) for d in ca_cert_dirs)
    update_ca_present = (
        _command_available("update-ca-certificates") or
        _command_available("update-ca-trust")
    )
    results.append(_result(
        cat, "Pass" if ca_certs_present and update_ca_present else "Warning",
        f"PCI-4.2.1.4: CA certificate management present",
        severity="Medium",
        details=(
            f"CA cert dirs: {ca_certs_present}, "
            f"update tool: {update_ca_present}"
        ),
        remediation=(
            "Ensure system trust store is up-to-date: "
            "update-ca-certificates (Debian) or update-ca-trust (RHEL)"
        ),
        cross_references={
            "PCI-DSS": "4.2.1.4", "NIST": "SC-17",
        },
    ))

    return results


def _check_pci_req5_malware_v33(os_info) -> List[AuditResult]:
    """PCI Req 5 - Malware protection extended."""
    results: List[AuditResult] = []
    cat = "PCI Req 5 v3.3"

    # 5.2 - Anti-malware deployed on all systems
    av_indicators = {
        "ClamAV": _command_available("clamscan"),
        "MDE": _file_exists("/opt/microsoft/mdatp/sbin/wdavdaemon"),
        "CrowdStrike": _file_exists("/opt/CrowdStrike/falconctl"),
        "SentinelOne": _file_exists("/opt/sentinelone/bin/sentinelctl"),
        "Sophos": _file_exists("/opt/sophos-spl/bin/sophos_threat_detector"),
        "ESET": _file_exists("/opt/eset/efs/sbin/efs"),
        "Wazuh-rootcheck": _file_exists("/var/ossec/etc/ossec.conf"),
        "rkhunter": _command_available("rkhunter"),
        "chkrootkit": _command_available("chkrootkit"),
    }
    detected = [k for k, v in av_indicators.items() if v]
    results.append(_result(
        cat, "Pass" if detected else "Fail",
        f"PCI-5.2.1: Anti-malware/rootkit tools deployed ({len(detected)})",
        severity="High",
        details=f"Detected: {detected or 'none'}",
        remediation=(
            "Deploy enterprise EDR (CrowdStrike/MDE/SentinelOne) or "
            "open-source: apt-get install -y clamav rkhunter chkrootkit"
        ),
        cross_references={
            "PCI-DSS": "5.2.1", "NIST": "SI-3",
        },
    ))

    # 5.3 - Anti-malware kept current
    if _command_available("clamscan"):
        freshclam_active = _systemd_active("clamav-freshclam.service") == "active"
        results.append(_result(
            cat, "Pass" if freshclam_active else "Warning",
            f"PCI-5.3.2: ClamAV freshclam updater active: {freshclam_active}",
            severity="High",
            details=f"freshclam active: {freshclam_active}",
            remediation=(
                "systemctl enable --now clamav-freshclam"
            ),
            cross_references={
                "PCI-DSS": "5.3.2", "NIST": "SI-3(2)",
            },
        ))

    # 5.3.4 - Audit logs for anti-malware
    if _file_exists("/var/log/clamav") or __directory_exists("/var/log/clamav"):
        results.append(_result(
            cat, "Pass",
            "PCI-5.3.4: ClamAV log directory present",
            severity="Medium",
            details="/var/log/clamav present",
            cross_references={
                "PCI-DSS": "5.3.4", "NIST": "AU-2",
            },
        ))

    return results


def _check_pci_req6_sdlc_v33(os_info) -> List[AuditResult]:
    """PCI Req 6 - SDLC indicators."""
    results: List[AuditResult] = []
    cat = "PCI Req 6 SDLC v3.3"

    # 6.2.4 - Secure coding training/tools indicators
    sast_tools = {
        "bandit": _command_available("bandit"),
        "semgrep": _command_available("semgrep"),
        "gosec": _command_available("gosec"),
        "shellcheck": _command_available("shellcheck"),
        "pylint": _command_available("pylint"),
        "eslint": _command_available("eslint"),
    }
    detected_sast = [k for k, v in sast_tools.items() if v]
    if detected_sast:
        results.append(_result(
            cat, "Pass" if detected_sast else "Info",
            f"PCI-6.2.4: SAST tooling installed ({len(detected_sast)})",
            severity="Medium",
            details=f"Detected: {detected_sast}",
            remediation=(
                "Install on dev hosts/CI: pip install bandit semgrep; "
                "apt-get install -y shellcheck"
            ),
            cross_references={
                "PCI-DSS": "6.2.4", "NIST": "SA-11",
            },
        ))

    # 6.3.3 - Patch management with severity ratings
    update_active = (
        _systemd_active("unattended-upgrades.service") == "active" or
        _systemd_active("dnf-automatic-install.timer") == "active"
    )
    results.append(_result(
        cat, "Pass" if update_active else "Warning",
        f"PCI-6.3.3: Patch automation active: {update_active}",
        severity="High",
        details=f"Update automation: {update_active}",
        remediation=(
            "Enable: apt-get install -y unattended-upgrades; "
            "dpkg-reconfigure unattended-upgrades"
        ),
        cross_references={
            "PCI-DSS": "6.3.3", "NIST": "SI-2",
        },
    ))

    # 6.4.1 - Web application security indicators (WAF)
    waf_indicators = {
        "modsecurity": (
            _file_exists("/etc/modsecurity/modsecurity.conf") or
            __directory_exists("/etc/modsecurity") or
            __directory_exists("/usr/share/modsecurity-crs")
        ),
        "naxsi": _file_exists("/etc/nginx/naxsi_core.rules"),
        "shadow-daemon": _command_available("shadowd"),
    }
    detected_waf = [k for k, v in waf_indicators.items() if v]
    results.append(_result(
        cat, "Pass" if detected_waf else "Info",
        f"PCI-6.4.1: WAF indicators ({len(detected_waf)})",
        severity="Medium",
        details=f"Detected: {detected_waf}",
        remediation=(
            "Install ModSecurity v3 + OWASP CRS for web app protection."
        ),
        cross_references={
            "PCI-DSS": "6.4.1", "NIST": "SC-7(8)",
        },
    ))

    # 6.4.3 - Public-facing web applications inventory
    web_servers = {
        "apache": (
            _systemd_active("apache2.service") == "active" or
            _systemd_active("httpd.service") == "active"
        ),
        "nginx": _systemd_active("nginx.service") == "active",
        "lighttpd": _systemd_active("lighttpd.service") == "active",
        "caddy": _systemd_active("caddy.service") == "active",
    }
    active_ws = [k for k, v in web_servers.items() if v]
    results.append(_result(
        cat, "Info",
        f"PCI-6.4.3: Active web servers: {active_ws or 'none'}",
        severity="Informational",
        details=f"Active: {active_ws}",
        cross_references={
            "PCI-DSS": "6.4.3", "NIST": "CM-8",
        },
    ))

    return results


def _check_pci_req8_mfa_v33(os_info) -> List[AuditResult]:
    """PCI Req 8 - Authentication MFA depth."""
    results: List[AuditResult] = []
    cat = "PCI Req 8 MFA v3.3"

    # 8.4.2 - MFA for all access into CDE
    pam_files = ["/etc/pam.d/sshd", "/etc/pam.d/system-auth",
                 "/etc/pam.d/common-auth", "/etc/pam.d/login"]
    mfa_modules = ["pam_google_authenticator", "pam_yubico", "pam_oath",
                   "pam_duo", "pam_u2f", "pam_pkcs11", "pam_radius_auth"]
    detected_mfa = set()
    for pf in pam_files:
        c = _read_file_safe(pf)
        if not c:
            continue
        for mod in mfa_modules:
            if mod + ".so" in c:
                detected_mfa.add(mod.replace("pam_", ""))

    results.append(_result(
        cat, "Pass" if detected_mfa else "Fail",
        f"PCI-8.4.2: MFA modules configured ({len(detected_mfa)})",
        severity="Critical",
        details=f"Detected: {sorted(detected_mfa) or 'none'}",
        remediation=(
            "apt-get install -y libpam-google-authenticator. "
            "Configure pam_google_authenticator.so in /etc/pam.d/sshd"
        ),
        cross_references={
            "PCI-DSS": "8.4.2", "NIST": "IA-2(1)",
        },
    ))

    # 8.3.6 - Strong cryptography for password storage
    login_defs = _read_file_safe("/etc/login.defs")
    em_match = re.search(
        r"^\s*ENCRYPT_METHOD\s+(\S+)", login_defs, re.MULTILINE
    )
    method = em_match.group(1).upper() if em_match else ""
    method_ok = method in {"SHA512", "YESCRYPT"}
    results.append(_result(
        cat, "Pass" if method_ok else "Fail",
        f"PCI-8.3.6: Password hash algorithm: {method or 'unset'}",
        severity="High",
        details=f"ENCRYPT_METHOD = {method}",
        remediation=(
            "In /etc/login.defs: ENCRYPT_METHOD SHA512 (or YESCRYPT)"
        ),
        cross_references={
            "PCI-DSS": "8.3.6", "NIST": "IA-5(1)(c)",
        },
    ))

    # 8.3.5 - Account lockout after failed attempts
    pam_files_to_check = ["/etc/pam.d/common-auth", "/etc/pam.d/system-auth",
                           "/etc/pam.d/password-auth"]
    lockout_configured = False
    for pf in pam_files_to_check:
        c = _read_file_safe(pf)
        if "pam_faillock" in c or "pam_tally2" in c:
            lockout_configured = True
            break
    results.append(_result(
        cat, "Pass" if lockout_configured else "Fail",
        f"PCI-8.3.5: Account lockout (faillock/tally2) configured: {lockout_configured}",
        severity="High",
        details=f"PAM lockout module detected: {lockout_configured}",
        remediation=(
            "Configure /etc/security/faillock.conf with deny=10 unlock_time=900; "
            "add pam_faillock.so to /etc/pam.d/system-auth"
        ),
        cross_references={
            "PCI-DSS": "8.3.5", "NIST": "AC-7", "CIS": "5.4.2",
        },
    ))

    # 8.3.7 - Different password from previous 4
    pwhistory_remember = 0
    for pf in pam_files_to_check:
        c = _read_file_safe(pf)
        m = re.search(r"pam_pwhistory.*remember\s*=\s*(\d+)", c)
        if m:
            pwhistory_remember = max(pwhistory_remember, int(m.group(1)))
    pwhistory_ok = pwhistory_remember >= 4
    results.append(_result(
        cat, "Pass" if pwhistory_ok else "Fail",
        f"PCI-8.3.7: Password history (>=4): {pwhistory_remember}",
        severity="Medium",
        details=f"pam_pwhistory remember = {pwhistory_remember}",
        remediation=(
            "Add to /etc/pam.d/system-auth: "
            "password required pam_pwhistory.so remember=24"
        ),
        cross_references={
            "PCI-DSS": "8.3.7", "NIST": "IA-5(1)(e)",
        },
    ))

    # 8.6.2 - Application/system accounts have no interactive login
    passwd = _read_file_safe("/etc/passwd")
    interactive_system = []
    if passwd:
        for line in passwd.splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 7:
                try:
                    uid = int(parts[2])
                except ValueError:
                    continue
                shell = parts[6]
                # System accounts: UID < 1000 (Debian/Ubuntu) or < 500 (RHEL <7)
                if 0 < uid < 1000:
                    if shell not in ("/sbin/nologin", "/bin/false",
                                      "/usr/sbin/nologin", "/usr/bin/nologin"):
                        interactive_system.append(parts[0])
    results.append(_result(
        cat, "Pass" if not interactive_system else "Warning",
        f"PCI-8.6.2: System accounts have no interactive shell "
        f"({len(interactive_system)} exceptions)",
        severity="High",
        details=f"System accounts with shell: {interactive_system[:10]}",
        remediation=(
            "For each system account: usermod -s /sbin/nologin <username>"
        ),
        cross_references={
            "PCI-DSS": "8.6.2", "NIST": "AC-2", "STIG": "V-230364",
        },
    ))

    return results


def _check_pci_req9_media_v33(os_info) -> List[AuditResult]:
    """PCI Req 9 - Physical/media access extended."""
    results: List[AuditResult] = []
    cat = "PCI Req 9 v3.3"

    # 9.4.1 - Media inventory: detect removable mounts
    rc, out, _ = _run_command(["lsblk", "-o", "NAME,RM,MOUNTPOINT", "-n"], timeout=3.0)
    removable_count = 0
    if rc == 0 and out:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "1":
                removable_count += 1
    results.append(_result(
        cat, "Info",
        f"PCI-9.4.1: Removable media currently present: {removable_count}",
        severity="Informational",
        details=f"Removable devices detected: {removable_count}",
        cross_references={
            "PCI-DSS": "9.4.1", "NIST": "MP-3",
        },
    ))

    # 9.4.6 - Media destruction tools
    destruction_tools = {
        "shred": _command_available("shred"),
        "wipe": _command_available("wipe"),
        "scrub": _command_available("scrub"),
        "blkdiscard": _command_available("blkdiscard"),
        "nvme-format": _command_available("nvme"),
    }
    detected = [k for k, v in destruction_tools.items() if v]
    results.append(_result(
        cat, "Pass" if detected else "Warning",
        f"PCI-9.4.6: Media destruction tools ({len(detected)})",
        severity="Medium",
        details=f"Detected: {detected}",
        remediation=(
            "Install: apt-get install -y coreutils secure-delete nvme-cli. "
            "shred for files; blkdiscard for SSDs"
        ),
        cross_references={
            "PCI-DSS": "9.4.6", "NIST": "MP-6",
        },
    ))

    # 9.5 - USB device control
    usbguard_active = _systemd_active("usbguard.service") == "active"
    usb_storage_blocked = False
    # Check for blacklist entries
    if __directory_exists("/etc/modprobe.d"):
        for f in _safe_listdir("/etc/modprobe.d"):
            c = _read_file_safe(os.path.join("/etc/modprobe.d", f))
            if re.search(r"^\s*(blacklist|install)\s+usb-storage", c, re.MULTILINE):
                usb_storage_blocked = True
                break
    results.append(_result(
        cat, "Pass" if (usbguard_active or usb_storage_blocked) else "Info",
        f"PCI-9.5: USB device control enforced",
        severity="Medium",
        details=(
            f"USBGuard: {usbguard_active}, "
            f"usb-storage blocked: {usb_storage_blocked}"
        ),
        remediation=remediation_for("usbguard"),
        cross_references={
            "PCI-DSS": "9.5", "NIST": "MP-7", "STIG": "V-230501",
        },
    ))

    return results


def _check_pci_req10_audit_v33(os_info) -> List[AuditResult]:
    """PCI Req 10 - Audit trail completeness."""
    results: List[AuditResult] = []
    cat = "PCI Req 10 Audit v3.3"

    auditd_active = _systemd_active("auditd.service") == "active"
    if not auditd_active:
        return results

    audit_rules = _read_file_safe("/etc/audit/audit.rules")
    if not audit_rules:
        rules_d = "/etc/audit/rules.d"
        if __directory_exists(rules_d):
            for f in _safe_listdir(rules_d):
                if f.endswith(".rules"):
                    audit_rules += "\n" + _read_file_safe(os.path.join(rules_d, f))

    # 10.2.1.1 - All access to system components and cardholder data
    file_access_rules = sum(
        1 for line in audit_rules.splitlines()
        if line.strip().startswith("-w ") or "open" in line
    )
    results.append(_result(
        cat, "Pass" if file_access_rules >= 5 else "Warning",
        f"PCI-10.2.1.1: File access audit rules ({file_access_rules})",
        severity="High",
        details=f"File-watching/open syscall rules: {file_access_rules}",
        remediation=(
            "Add audit watches for cardholder data paths: "
            "-w /var/lib/cardholder -p rwa -k cardholder_access"
        ),
        cross_references={
            "PCI-DSS": "10.2.1.1", "NIST": "AU-2", "CIS": "4.1.3",
        },
    ))

    # 10.2.1.2 - Actions taken by privileged accounts
    privileged_audit = "privileged" in audit_rules or "execve" in audit_rules
    results.append(_result(
        cat, "Pass" if privileged_audit else "Fail",
        f"PCI-10.2.1.2: Privileged action auditing: {privileged_audit}",
        severity="High",
        details=f"privileged/execve rules detected: {privileged_audit}",
        remediation=(
            "Audit setuid/setgid binaries and execution. CIS recommends: "
            "auditctl -a always,exit -F arch=b64 -S execve -F euid=0 -k privileged"
        ),
        cross_references={
            "PCI-DSS": "10.2.1.2", "NIST": "AU-2",
        },
    ))

    # 10.2.1.3 - Access to all audit trails
    audit_log_watch = "/var/log/audit" in audit_rules
    results.append(_result(
        cat, "Pass" if audit_log_watch else "Fail",
        f"PCI-10.2.1.3: Audit log directory watched: {audit_log_watch}",
        severity="High",
        details=f"-w /var/log/audit directive: {audit_log_watch}",
        remediation=(
            "-w /var/log/audit -k auditlog"
        ),
        cross_references={
            "PCI-DSS": "10.2.1.3", "NIST": "AU-9",
        },
    ))

    # 10.2.1.5 - Use of identification and authentication mechanisms
    auth_audit = (
        "session" in audit_rules or "logins" in audit_rules or
        "/var/log/lastlog" in audit_rules
    )
    results.append(_result(
        cat, "Pass" if auth_audit else "Warning",
        f"PCI-10.2.1.5: Authentication event auditing: {auth_audit}",
        severity="High",
        details=f"Auth audit indicators: {auth_audit}",
        remediation=(
            "-w /var/log/lastlog -p wa -k logins; "
            "-w /var/run/faillock -p wa -k logins"
        ),
        cross_references={
            "PCI-DSS": "10.2.1.5", "NIST": "AU-2",
        },
    ))

    # 10.2.1.7 - System level changes
    sys_changes = "modules" in audit_rules or "init_module" in audit_rules
    results.append(_result(
        cat, "Pass" if sys_changes else "Warning",
        f"PCI-10.2.1.7: Kernel module changes audited: {sys_changes}",
        severity="High",
        details=f"Module load/unload audit: {sys_changes}",
        remediation=(
            "-a always,exit -F arch=b64 -S init_module,delete_module -k modules"
        ),
        cross_references={
            "PCI-DSS": "10.2.1.7", "NIST": "AU-2", "CIS": "4.1.3.18",
        },
    ))

    # 10.5.2 - Audit logs retained for >= 1 year
    auditd_conf = _read_file_safe("/etc/audit/auditd.conf")
    num_logs_match = re.search(r"^\s*num_logs\s*=\s*(\d+)", auditd_conf, re.MULTILINE)
    num_logs = int(num_logs_match.group(1)) if num_logs_match else 0
    results.append(_result(
        cat, "Pass" if num_logs >= 5 else "Info",
        f"PCI-10.5.2: auditd num_logs ({num_logs})",
        severity="Medium",
        details=f"num_logs = {num_logs}",
        remediation=(
            "In /etc/audit/auditd.conf: num_logs = 10 (with rotation policy "
            "supporting 1-year retention)"
        ),
        cross_references={
            "PCI-DSS": "10.5.2", "NIST": "AU-11",
        },
    ))

    # 10.6.1 - Time synchronization
    time_sync_active = (
        _systemd_active("chronyd.service") == "active" or
        _systemd_active("chrony.service") == "active" or
        _systemd_active("ntpd.service") == "active" or
        _systemd_active("systemd-timesyncd.service") == "active"
    )
    results.append(_result(
        cat, "Pass" if time_sync_active else "Fail",
        f"PCI-10.6.1: Time synchronization service active",
        severity="High",
        details=f"NTP/chrony active: {time_sync_active}",
        remediation=(
            "systemctl enable --now chronyd"
        ),
        cross_references={
            "PCI-DSS": "10.6.1", "NIST": "AU-8",
        },
    ))

    return results


def _check_pci_req11_security_testing_v33(os_info) -> List[AuditResult]:
    """PCI Req 11 - Security testing extended."""
    results: List[AuditResult] = []
    cat = "PCI Req 11 v3.3"

    # 11.3.1 - Vulnerability scanning capability
    vuln_scanners = {
        "openvas/gvm": (
            _command_available("gvm-cli") or
            _file_exists("/etc/openvas/openvas.conf")
        ),
        "trivy": _command_available("trivy"),
        "grype": _command_available("grype"),
        "lynis": _command_available("lynis"),
        "openscap": _command_available("oscap"),
        "nikto": _command_available("nikto"),
        "nuclei": _command_available("nuclei"),
    }
    detected = [k for k, v in vuln_scanners.items() if v]
    results.append(_result(
        cat, "Pass" if detected else "Warning",
        f"PCI-11.3.1: Vulnerability scanning tools ({len(detected)})",
        severity="High",
        details=f"Detected: {detected}",
        remediation=(
            "Install: apt-get install -y lynis; "
            "or wget trivy/grype binaries. Schedule weekly scans."
        ),
        cross_references={
            "PCI-DSS": "11.3.1", "NIST": "RA-5",
        },
    ))

    # 11.4 - IDS/IPS deployed
    ids_tools = {
        "suricata": (
            _command_available("suricata") or
            _file_exists("/etc/suricata/suricata.yaml") or
            _systemd_active("suricata.service") == "active"
        ),
        "snort": _command_available("snort"),
        "zeek": (
            _command_available("zeek") or
            _command_available("bro")
        ),
        "wazuh-IDS": _file_exists("/var/ossec/etc/ossec.conf"),
        "ossec-IDS": __directory_exists("/var/ossec"),
    }
    detected_ids = [k for k, v in ids_tools.items() if v]
    results.append(_result(
        cat, "Pass" if detected_ids else "Warning",
        f"PCI-11.4: IDS/IPS deployed ({len(detected_ids)})",
        severity="High",
        details=f"Detected: {detected_ids}",
        remediation=(
            "Deploy Suricata: apt-get install -y suricata; "
            "configure rules; systemctl enable --now suricata"
        ),
        cross_references={
            "PCI-DSS": "11.4", "NIST": "SI-4(2)",
        },
    ))

    # 11.5.1 - File integrity monitoring
    fim_tools = {
        "AIDE": (
            _command_available("aide") or
            _file_exists("/var/lib/aide/aide.db") or
            _file_exists("/var/lib/aide/aide.db.gz")
        ),
        "Tripwire": (
            _command_available("tripwire") or
            _file_exists("/etc/tripwire/tw.cfg")
        ),
        "Wazuh-FIM": _file_exists("/var/ossec/etc/ossec.conf"),
        "OSSEC-FIM": __directory_exists("/var/ossec"),
        "Samhain": _command_available("samhain") or __directory_exists("/etc/samhain"),
    }
    detected_fim = [k for k, v in fim_tools.items() if v]
    results.append(_result(
        cat, "Pass" if detected_fim else "Fail",
        f"PCI-11.5.1: File integrity monitoring ({len(detected_fim)})",
        severity="High",
        details=f"Detected: {detected_fim}",
        remediation=remediation_for("aide"),
        cross_references={
            "PCI-DSS": "11.5.1", "NIST": "SI-7",
        },
    ))

    # 11.5.2 - File integrity check schedule
    aide_scheduled = (
        _file_exists("/etc/cron.d/aide") or
        _file_exists("/etc/cron.daily/aide") or
        _systemd_active("aidecheck.timer") == "active"
    )
    if any("AIDE" in d for d in detected_fim):
        results.append(_result(
            cat, "Pass" if aide_scheduled else "Warning",
            f"PCI-11.5.2: AIDE check scheduled: {aide_scheduled}",
            severity="High",
            details=f"AIDE cron/timer present: {aide_scheduled}",
            remediation=(
                "Create /etc/cron.d/aide with daily check: "
                "0 5 * * * root /usr/sbin/aide --check"
            ),
            cross_references={
                "PCI-DSS": "11.5.2", "NIST": "SI-7(1)",
            },
        ))

    return results


def _check_pci_req12_indicators_v33(os_info) -> List[AuditResult]:
    """PCI Req 12 - Information security policy technical indicators."""
    results: List[AuditResult] = []
    cat = "PCI Req 12 v3.3"

    # 12.5.2 - Inventory tracking
    inv_tools = {
        "dpkg": _command_available("dpkg"),
        "rpm": _command_available("rpm"),
        "pacman": _command_available("pacman"),
        "apk": _command_available("apk"),
    }
    detected_inv = [k for k, v in inv_tools.items() if v]
    results.append(_result(
        cat, "Pass" if detected_inv else "Fail",
        f"PCI-12.5.2: Software inventory capability ({len(detected_inv)})",
        severity="Medium",
        details=f"Detected package managers: {detected_inv}",
        cross_references={
            "PCI-DSS": "12.5.2", "NIST": "CM-8",
        },
    ))

    # 12.10.1 - Incident response plan: aggregator/SIEM connectivity
    siem_indicators = {
        "rsyslog-forward": False,
        "fluentd": (
            _command_available("fluentd") or _command_available("td-agent") or
            _systemd_active("fluentd.service") == "active"
        ),
        "filebeat": (
            _file_exists("/etc/filebeat/filebeat.yml") or
            _systemd_active("filebeat.service") == "active"
        ),
        "vector": (
            _command_available("vector") or
            _file_exists("/etc/vector/vector.toml")
        ),
        "logstash": (
            _file_exists("/etc/logstash/logstash.yml") or
            _systemd_active("logstash.service") == "active"
        ),
    }
    if __directory_exists("/etc/rsyslog.d"):
        for f in [__f for __f in _safe_listdir("/etc/rsyslog.d") if __f.endswith(".conf")]:
            c = _read_file_safe(os.path.join("/etc/rsyslog.d", f))
            if "@@" in c or "omfwd" in c or "omrelp" in c:
                siem_indicators["rsyslog-forward"] = True
                break
    rsy_main = _read_file_safe("/etc/rsyslog.conf")
    if "@@" in rsy_main or "omfwd" in rsy_main:
        siem_indicators["rsyslog-forward"] = True

    detected_siem = [k for k, v in siem_indicators.items() if v]
    results.append(_result(
        cat, "Pass" if detected_siem else "Warning",
        f"PCI-12.10.1: SIEM/log forwarding ({len(detected_siem)})",
        severity="High",
        details=f"Detected: {detected_siem}",
        remediation=(
            "Configure rsyslog forwarding: in /etc/rsyslog.d/50-remote.conf: "
            "*.* @@logserver.example.com:6514"
        ),
        cross_references={
            "PCI-DSS": "12.10.1", "NIST": "IR-4",
        },
    ))

    # 12.10.5 - Incident response includes logging coverage
    logging_layers = {
        "auditd": _systemd_active("auditd.service") == "active",
        "rsyslog": _systemd_active("rsyslog.service") == "active",
        "journald": _systemd_active("systemd-journald.service") == "active",
    }
    active_layers = [k for k, v in logging_layers.items() if v]
    results.append(_result(
        cat, "Pass" if len(active_layers) >= 2 else "Fail",
        f"PCI-12.10.5: Logging layers active ({len(active_layers)})",
        severity="High",
        details=f"Active: {active_layers}",
        remediation=(
            "Activate auditd and rsyslog: systemctl enable --now auditd rsyslog"
        ),
        cross_references={
            "PCI-DSS": "12.10.5", "NIST": "AU-2",
        },
    ))

    return results


# Save reference to existing run_checks
_original_run_checks_pci_v33 = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the v3.3 expanded PCI module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_pci_v33(shared_data)

    os_info = shared_data.get("v3_os_info")
    if os_info is None:
        os_info = os_detection.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        results.extend(_check_pci_req1_extended_v33(os_info))
        results.extend(_check_pci_req2_extended_v33(os_info))
        results.extend(_check_pci_req3_kms_v33(os_info))
        results.extend(_check_pci_req4_tls_depth_v33(os_info))
        results.extend(_check_pci_req5_malware_v33(os_info))
        results.extend(_check_pci_req6_sdlc_v33(os_info))
        results.extend(_check_pci_req8_mfa_v33(os_info))
        results.extend(_check_pci_req9_media_v33(os_info))
        results.extend(_check_pci_req10_audit_v33(os_info))
        results.extend(_check_pci_req11_security_testing_v33(os_info))
        results.extend(_check_pci_req12_indicators_v33(os_info))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled exception in PCI v3.3 expansion")
        results.append(_result(
            "PCI - Error", "Error",
            f"PCI v3.3 expansion exception: {exc!r}",
            severity="Medium", details=str(exc),
        ))

    return results


# ============================================================================
# v3.5 EXPANSION - PCI DSS v4.0.1 Deeper Sub-Requirement Coverage
# ----------------------------------------------------------------------------
# Synopsis:
#   Adds deeper coverage of PCI DSS v4.0.1 sub-requirements not yet
#   addressed by the baseline + v3.3 expansion. Focus areas:
#     - Req 2.2  System component configuration standards (2.2.1-2.2.7)
#     - Req 3.5  Render PAN unreadable (3.5.1, 3.5.1.1, 3.5.1.2)
#     - Req 3.6  Cryptographic keys protection
#     - Req 3.7  Key management lifecycle
#     - Req 5.2  Anti-malware deployment (5.2.1-5.2.3)
#     - Req 5.3  Anti-malware mechanism active (5.3.1-5.3.3)
#     - Req 7.2  Access definition (7.2.1-7.2.6)
#     - Req 7.3  Access enforcement (7.3.1-7.3.3)
#     - Req 8.3  Strong authentication (8.3.1-8.3.11)
#     - Req 8.4  MFA (8.4.1-8.4.3)
#     - Req 8.6  Application credentials (8.6.1-8.6.3)
#     - Req 10.2 Audit log content (10.2.1.1-10.2.1.7 event types)
#     - Req 10.3 Audit log integrity (10.3.1-10.3.4)
#     - Req 10.6 Time synchronization (10.6.1-10.6.3)
#     - Req 11.5 IDS/IPS (11.5.1, 11.5.1.1)
#     - Req 11.6 Change detection (11.6.1)
# ============================================================================

# v3.5 helpers (aliased to avoid host module's helper-name conflicts, per L9)
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


def _v35_pci_result(category, status, message, severity="Medium",
                    details="", remediation="", cross_references=None):
    """Build AuditResult for PCI v3.5 expansion."""
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


def _check_pci_v35_req2_configuration_standards(os_info):
    """PCI Req 2.2 - System component configuration standards."""
    results = []
    cat_prefix = "PCI Req 2.2 v3.5"

    # 2.2.1 - Configuration standards developed and maintained
    # Indicator: presence of configuration management tooling
    cm_present = (
        _v35_command_available("ansible") or
        _v35_command_available("puppet") or
        _v35_command_available("salt-call") or
        _v35_command_available("salt-minion") or
        _v35_command_available("chef-client")
    )
    results.append(_v35_pci_result(
        f"{cat_prefix} - 2.2.1 Config Standards",
        "Pass" if cm_present else "Info",
        f"PCI 2.2.1 Configuration management tooling: {cm_present}",
        severity="Medium",
        details=f"CM agent detected: {cm_present}",
        remediation=(
            "Maintain documented configuration standards via Ansible, Puppet, "
            "Salt, or Chef. PCI DSS v4.0.1 2.2.1 requires standards aligned "
            "with industry-accepted hardening (e.g. CIS Benchmarks)."
        ),
        cross_references={
            "PCI-DSS": "2.2.1", "NIST": "CM-2", "ISO27001": "A.8.9",
            "CIS": "1.0",
        },
    ))

    # 2.2.2 - Vendor default accounts managed (no defaults active)
    passwd = _v35_read_file_safe("/etc/passwd")
    shadow = _v35_read_file_safe("/etc/shadow")
    # Common vendor default accounts that should be locked or removed
    risky_defaults = [
        "games", "news", "uucp", "proxy", "list", "irc", "gnats",
        "tcpdump", "ftp",
    ]
    active_defaults = []
    for line in passwd.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        username = parts[0]
        shell = parts[6]
        if username in risky_defaults and shell not in (
            "/sbin/nologin", "/usr/sbin/nologin", "/bin/false", "/bin/sync"
        ):
            active_defaults.append(username)
    results.append(_v35_pci_result(
        f"{cat_prefix} - 2.2.2 Default Accounts",
        "Pass" if not active_defaults else "Warning",
        f"PCI 2.2.2 Vendor default accounts locked ({len(active_defaults)} active)",
        severity="Medium",
        details=f"Default accounts with login shell: {active_defaults}",
        remediation=(
            "For each unused default account: usermod -s /usr/sbin/nologin "
            "<user> or userdel <user> if confirmed unnecessary. "
            "PCI DSS v4.0.1 2.2.2 requires vendor defaults to be removed or "
            "disabled before placing system into production."
        ),
        cross_references={
            "PCI-DSS": "2.2.2", "NIST": "IA-5", "STIG": "V-230376",
        },
    ))

    # 2.2.3 - Primary functions per system component
    # Indicator: count of distinct services running
    rc, out, _ = _v35_run_command(
        ["systemctl", "list-units", "--type=service",
         "--state=active", "--no-legend", "--no-pager"],
        timeout=10.0,
    )
    active_service_count = len(out.splitlines()) if rc == 0 and out else 0
    # CDE systems should be minimal; >50 services suggests unused functionality
    results.append(_v35_pci_result(
        f"{cat_prefix} - 2.2.3 Primary Function",
        "Pass" if 0 < active_service_count <= 60 else "Info",
        f"PCI 2.2.3 Active services count: {active_service_count}",
        severity="Low",
        details=f"systemd active services: {active_service_count}",
        remediation=(
            "Review active services with `systemctl list-units --type=service "
            "--state=active`. Disable services not required for the primary "
            "function. PCI 2.2.3 requires only one primary function per system."
        ),
        cross_references={
            "PCI-DSS": "2.2.3", "NIST": "CM-7", "CIS": "2.0",
        },
    ))

    # 2.2.4 - Only necessary services, protocols, daemons enabled
    risky_services = {
        "telnet": "telnet.socket",
        "rsh": "rsh.socket",
        "rlogin": "rlogin.socket",
        "rexec": "rexec.socket",
        "tftp": "tftp.socket",
        "nfs": "nfs-server.service",
        "rpcbind": "rpcbind.service",
        "avahi-daemon": "avahi-daemon.service",
        "cups": "cups.service",
    }
    enabled_risky = []
    for svc_name, unit in risky_services.items():
        if _v35_systemd_active(unit) == "active":
            enabled_risky.append(svc_name)
    results.append(_v35_pci_result(
        f"{cat_prefix} - 2.2.4 Unnecessary Services",
        "Pass" if not enabled_risky else "Warning",
        f"PCI 2.2.4 Risky/unnecessary services disabled "
        f"({len(enabled_risky)} active)",
        severity="High" if enabled_risky else "Medium",
        details=f"Active risky services: {enabled_risky}",
        remediation=(
            "For each: systemctl disable --now <unit>. "
            "Telnet, rsh, rlogin, rexec all transmit credentials in cleartext "
            "and are non-compliant for any PCI in-scope system."
        ),
        cross_references={
            "PCI-DSS": "2.2.4", "NIST": "CM-7", "CIS": "2.2",
        },
    ))

    # 2.2.5 - Insecure services/protocols if used must be documented
    # Cleartext: ftp, telnet, http (server), tftp
    cleartext_listeners = []
    rc, out, _ = _v35_run_command(
        ["ss", "-tlnp"], timeout=5.0,
    )
    if rc == 0 and out:
        # Look for common insecure listening ports
        for port_pattern, name in [
            (":21 ", "FTP"), (":23 ", "Telnet"), (":69 ", "TFTP"),
            (":512 ", "rexec"), (":513 ", "rlogin"), (":514 ", "rsh"),
        ]:
            if port_pattern in out:
                cleartext_listeners.append(name)
    results.append(_v35_pci_result(
        f"{cat_prefix} - 2.2.5 Insecure Protocols",
        "Pass" if not cleartext_listeners else "Fail",
        f"PCI 2.2.5 Cleartext-protocol listeners ({len(cleartext_listeners)})",
        severity="High",
        details=f"Active cleartext listeners: {cleartext_listeners}",
        remediation=(
            "Replace cleartext protocols with encrypted equivalents: "
            "FTP->SFTP/FTPS, Telnet->SSH, TFTP->SCP/HTTPS. "
            "If business-justified, PCI 2.2.5 requires documented business "
            "need + additional security features."
        ),
        cross_references={
            "PCI-DSS": "2.2.5", "NIST": "SC-8", "CIS": "2.1",
        },
    ))

    # 2.2.6 - Security parameters configured to prevent misuse
    # Indicators: kernel hardening sysctls
    hardening_sysctls = {
        "kernel.kptr_restrict": ("1", "2"),
        "kernel.dmesg_restrict": ("1",),
        "fs.protected_hardlinks": ("1",),
        "fs.protected_symlinks": ("1",),
        "kernel.randomize_va_space": ("2",),
    }
    pass_count = 0
    fail_list = []
    for sysctl, ok_values in hardening_sysctls.items():
        val = _v35_read_sysctl(sysctl)
        if val in ok_values:
            pass_count += 1
        else:
            fail_list.append(f"{sysctl}={val}")
    results.append(_v35_pci_result(
        f"{cat_prefix} - 2.2.6 Security Parameters",
        "Pass" if pass_count >= 4 else "Warning",
        f"PCI 2.2.6 Kernel hardening parameters "
        f"({pass_count}/{len(hardening_sysctls)})",
        severity="Medium",
        details=f"Non-compliant: {fail_list}",
        remediation=(
            "In /etc/sysctl.d/99-pci-hardening.conf:\n"
            "  kernel.kptr_restrict = 2\n"
            "  kernel.dmesg_restrict = 1\n"
            "  fs.protected_hardlinks = 1\n"
            "  fs.protected_symlinks = 1\n"
            "  kernel.randomize_va_space = 2\n"
            "Then: sysctl --system"
        ),
        cross_references={
            "PCI-DSS": "2.2.6", "NIST": "SI-16", "CIS": "1.5", "STIG": "V-258034",
        },
    ))

    # 2.2.7 - Non-console administrative access encrypted (covered: SSH only)
    sshd = _v35_read_file_safe("/etc/ssh/sshd_config")
    if sshd:
        # Check Protocol = 2 (legacy SSHv1 forbidden)
        protocol_match = re.search(r"^\s*Protocol\s+(\S+)", sshd, re.MULTILINE)
        protocol_ok = (
            protocol_match is None  # default in modern SSH = 2
            or protocol_match.group(1) == "2"
        )
        # Check ChallengeResponseAuthentication, KbdInteractive controlled
        results.append(_v35_pci_result(
            f"{cat_prefix} - 2.2.7 Encrypted Admin",
            "Pass" if protocol_ok else "Fail",
            f"PCI 2.2.7 SSH Protocol 2 (encrypted admin access)",
            severity="Critical",
            details=(
                f"Protocol = {protocol_match.group(1) if protocol_match else 'default(2)'}"
            ),
            remediation=(
                "In /etc/ssh/sshd_config: remove any 'Protocol 1' directive. "
                "Modern OpenSSH builds reject SSHv1 by default but explicit "
                "configuration is best."
            ),
            cross_references={
                "PCI-DSS": "2.2.7", "NIST": "AC-17(2)", "CIS": "5.2",
            },
        ))

    return results


def _check_pci_v35_req3_pan_protection(os_info):
    """PCI Req 3.5/3.6/3.7 - PAN protection, key management."""
    results = []
    cat_prefix = "PCI Req 3 v3.5"

    # 3.5.1 - PAN rendered unreadable
    # Indicators: encryption-at-rest (LUKS) and field-level crypto libs
    rc, out, _ = _v35_run_command(["lsblk", "-o", "TYPE", "-n"], timeout=5.0)
    luks_present = rc == 0 and "crypt" in (out or "").lower()
    crypto_libs = [
        ("/usr/include/openssl", _v35_directory_exists("/usr/include/openssl")),
        ("/usr/include/sodium", _v35_directory_exists("/usr/include/sodium.h")
            or _v35_file_exists("/usr/include/sodium.h")),
    ]
    crypto_lib_present = any(present for _, present in crypto_libs)
    pan_protect_layers = sum([luks_present, crypto_lib_present])
    results.append(_v35_pci_result(
        f"{cat_prefix} - 3.5.1 PAN Unreadable",
        "Pass" if pan_protect_layers >= 1 else "Fail",
        f"PCI 3.5.1 PAN protection layers ({pan_protect_layers}/2)",
        severity="Critical",
        details=f"LUKS at-rest: {luks_present}, crypto libs: {crypto_lib_present}",
        remediation=(
            "PCI DSS v4.0.1 3.5.1 requires PAN to be rendered unreadable "
            "anywhere it is stored. Acceptable approaches:\n"
            "  1. One-way hashes (HMAC, SHA-2)\n"
            "  2. Truncation\n"
            "  3. Index tokens with secure pad\n"
            "  4. Strong cryptography with key management\n"
            "Disk encryption alone is NOT sufficient; field-level "
            "protection is also required."
        ),
        cross_references={
            "PCI-DSS": "3.5.1", "NIST": "SC-28", "ISO27001": "A.8.24",
        },
    ))

    # 3.5.1.1 - Hashes used to render PAN unreadable
    # Indicator: openssl with HMAC support
    if _v35_command_available("openssl"):
        rc, out, _ = _v35_run_command(
            ["openssl", "list", "-digest-algorithms"], timeout=5.0,
        )
        hmac_capable = rc == 0 and (
            "SHA2-256" in out or "sha256" in out.lower()
            or "SHA256" in out
        )
        results.append(_v35_pci_result(
            f"{cat_prefix} - 3.5.1.1 Strong Hash",
            "Pass" if hmac_capable else "Warning",
            f"PCI 3.5.1.1 Strong hash capability (SHA-2 family)",
            severity="High",
            details=f"OpenSSL SHA-2 available: {hmac_capable}",
            cross_references={
                "PCI-DSS": "3.5.1.1", "NIST": "SC-13", "FIPS": "180-4",
            },
        ))

    # 3.6.1 - Cryptographic keys protected from disclosure and misuse
    # Indicator: TPM 2.0 or HSM presence (technical surrogate)
    tpm_present = (
        _v35_directory_exists("/sys/class/tpm/tpm0") or
        _v35_file_exists("/dev/tpm0") or
        _v35_file_exists("/dev/tpmrm0")
    )
    pkcs11_present = (
        _v35_command_available("pkcs11-tool") or
        _v35_file_exists("/usr/lib/softhsm/libsofthsm2.so") or
        _v35_directory_exists("/var/lib/softhsm")
    )
    key_protect_layers = sum([tpm_present, pkcs11_present])
    results.append(_v35_pci_result(
        f"{cat_prefix} - 3.6.1 Key Protection",
        "Pass" if key_protect_layers >= 1 else "Info",
        f"PCI 3.6.1 Hardware key protection ({key_protect_layers})",
        severity="High",
        details=f"TPM: {tpm_present}, PKCS#11/HSM: {pkcs11_present}",
        remediation=(
            "PCI DSS v4.0.1 3.6.1 requires cryptographic keys be stored "
            "with protection mechanisms - TPM 2.0, HSM, or equivalent. "
            "Software-only key storage is acceptable only with strong "
            "compensating controls."
        ),
        cross_references={
            "PCI-DSS": "3.6.1", "NIST": "SC-12", "FIPS": "140-3",
        },
    ))

    # 3.6.1.1 - Keys with same access level only used for one purpose
    # 3.6.1.2 - Key encrypting keys at least as strong as data encryption keys
    # 3.6.1.3 - Documented key management procedures
    # These are largely organizational; technical indicator is /etc/crypttab review

    # 3.7.1 - Key management policies and procedures defined
    crypttab = _v35_read_file_safe("/etc/crypttab")
    crypttab_present = bool(crypttab and not crypttab.startswith("#"))
    results.append(_v35_pci_result(
        f"{cat_prefix} - 3.7.1 Key Management",
        "Info" if not crypttab_present else "Pass",
        f"PCI 3.7.1 Key management config (crypttab present): {crypttab_present}",
        severity="Medium",
        details=f"/etc/crypttab populated: {crypttab_present}",
        remediation=(
            "Document key management procedures per PCI 3.7.1 and reflect "
            "configuration in /etc/crypttab for system-managed encrypted volumes."
        ),
        cross_references={
            "PCI-DSS": "3.7.1", "NIST": "SC-12", "ISO27001": "A.8.24",
        },
    ))

    # 3.7.2 - Generation of strong cryptographic keys
    # Indicator: /dev/urandom and rng-tools
    urandom_ok = _v35_file_exists("/dev/urandom")
    rngd_active = (
        _v35_systemd_active("rngd.service") == "active" or
        _v35_systemd_active("rng-tools.service") == "active"
    )
    rng_layers = sum([urandom_ok, rngd_active])
    results.append(_v35_pci_result(
        f"{cat_prefix} - 3.7.2 Key Generation Entropy",
        "Pass" if urandom_ok else "Fail",
        f"PCI 3.7.2 Key generation entropy ({rng_layers}/2 layers)",
        severity="High",
        details=f"/dev/urandom: {urandom_ok}, rngd active: {rngd_active}",
        remediation=(
            "/dev/urandom must always be available. For low-entropy "
            "environments (VMs without TRNG), install rng-tools or "
            "haveged: apt-get install -y rng-tools"
        ),
        cross_references={
            "PCI-DSS": "3.7.2", "NIST": "SC-12(2)",
        },
    ))

    # 3.7.6 - Cryptographic keys rotated when key custodian changes
    # 3.7.7 - Compromised keys retired
    # 3.7.8 - Cryptographic key custodian acknowledgment
    # Largely organizational; technical surrogate: monitoring of key files
    sensitive_key_paths = [
        "/etc/ssl/private",
        "/etc/pki/tls/private",
        "/var/lib/ssh",
        "/etc/ssh",
    ]
    sensitive_dirs_secure = []
    sensitive_dirs_insecure = []
    for path in sensitive_key_paths:
        if not _v35_directory_exists(path):
            continue
        try:
            st = os.stat(path)
            mode = st.st_mode & 0o7777
            # Should be 0700 or 0750
            if (mode & 0o007) == 0 and (mode & 0o020) == 0:
                sensitive_dirs_secure.append(path)
            else:
                sensitive_dirs_insecure.append(f"{path}({oct(mode)})")
        except OSError:
            pass
    results.append(_v35_pci_result(
        f"{cat_prefix} - 3.7.x Key File Permissions",
        "Pass" if not sensitive_dirs_insecure else "Warning",
        f"PCI 3.7.x Sensitive key dir permissions",
        severity="High",
        details=(
            f"Secure: {sensitive_dirs_secure}, "
            f"Insecure: {sensitive_dirs_insecure}"
        ),
        remediation=(
            "chmod 0700 /etc/ssl/private; chown root:root /etc/ssl/private. "
            "Private key files must be 0400 or 0600, owned by root or the "
            "service account."
        ),
        cross_references={
            "PCI-DSS": "3.7.6, 3.7.7", "NIST": "SC-12", "STIG": "V-230246",
        },
    ))

    return results


def _check_pci_v35_req5_malware(os_info):
    """PCI Req 5.2/5.3 - Anti-malware deployment and operation."""
    results = []
    cat_prefix = "PCI Req 5 v3.5"

    # 5.2.1 - Anti-malware solution deployed
    av_products = {
        "ClamAV": (
            _v35_command_available("clamscan") or
            _v35_command_available("clamd")
        ),
        "MS Defender": _v35_file_exists(
            "/opt/microsoft/mdatp/sbin/wdavdaemon"
        ),
        "CrowdStrike": _v35_file_exists("/opt/CrowdStrike/falconctl"),
        "SentinelOne": _v35_file_exists("/opt/sentinelone/bin/sentinelctl"),
        "Sophos": _v35_command_available("savscan") or _v35_directory_exists("/opt/sophos-spl"),
        "ESET": _v35_directory_exists("/opt/eset"),
        "Trend Micro": _v35_directory_exists("/opt/TrendMicro"),
    }
    av_present = [k for k, v in av_products.items() if v]
    results.append(_v35_pci_result(
        f"{cat_prefix} - 5.2.1 Anti-Malware Deployed",
        "Pass" if av_present else "Fail",
        f"PCI 5.2.1 Anti-malware solution ({len(av_present)})",
        severity="Critical",
        details=f"Detected: {av_present}",
        remediation=remediation_for("clamav") if not av_present else "",
        cross_references={
            "PCI-DSS": "5.2.1", "NIST": "SI-3", "ISO27001": "A.8.7",
        },
    ))

    # 5.2.2 - Anti-malware solution detects all known types
    # Heuristic: ClamAV signature DB freshness
    clamav_sig = "/var/lib/clamav/main.cvd"
    clamav_sig_alt = "/var/lib/clamav/daily.cvd"
    sig_path = (
        clamav_sig if _v35_file_exists(clamav_sig)
        else (clamav_sig_alt if _v35_file_exists(clamav_sig_alt) else "")
    )
    sig_age_days = -1
    if sig_path:
        try:
            import time
            mtime = os.path.getmtime(sig_path)
            sig_age_days = int((time.time() - mtime) / 86400)
        except OSError:
            pass
    sig_fresh = 0 <= sig_age_days <= 7
    results.append(_v35_pci_result(
        f"{cat_prefix} - 5.2.2 Signature Currency",
        "Pass" if sig_fresh else "Warning",
        f"PCI 5.2.2 Anti-malware signatures fresh ({sig_age_days}d)",
        severity="High",
        details=f"Signature DB age: {sig_age_days} days",
        remediation=(
            "Schedule daily signature updates. For ClamAV: "
            "systemctl enable --now clamav-freshclam.timer (or .service). "
            "PCI 5.2.2 requires signatures kept current; vendors typically "
            "release definitions multiple times daily."
        ),
        cross_references={
            "PCI-DSS": "5.2.2", "NIST": "SI-3(2)",
        },
    ))

    # 5.3.1 - Anti-malware mechanism active and current
    av_active = (
        _v35_systemd_active("clamav-daemon.service") == "active" or
        _v35_systemd_active("clamd.service") == "active" or
        _v35_systemd_active("clamd@scan.service") == "active" or
        any(av_products.get(k) for k in [
            "MS Defender", "CrowdStrike", "SentinelOne",
        ])
    )
    results.append(_v35_pci_result(
        f"{cat_prefix} - 5.3.1 Mechanism Active",
        "Pass" if av_active else "Fail",
        f"PCI 5.3.1 Anti-malware mechanism active",
        severity="Critical",
        details=f"AV daemon active: {av_active}",
        remediation=(
            "systemctl enable --now clamav-daemon  (or relevant EDR service). "
            "On-access scanning is required by PCI 5.3.1 for in-scope systems."
        ),
        cross_references={
            "PCI-DSS": "5.3.1", "NIST": "SI-3", "ISO27001": "A.8.7",
        },
    ))

    # 5.3.2 - Anti-malware performs periodic scans + on-access detection
    # Heuristic: ClamAV scan timer or cron job
    scan_scheduled = False
    if _v35_directory_exists("/etc/cron.daily"):
        for f in _v35_list_directory("/etc/cron.daily"):
            if any(s in f.lower() for s in ["clam", "malware", "av", "defender"]):
                scan_scheduled = True
                break
    if not scan_scheduled and _v35_directory_exists("/etc/systemd/system"):
        for f in _v35_list_directory("/etc/systemd/system"):
            if "clamav-scan" in f.lower() or "av-scan" in f.lower():
                scan_scheduled = True
                break
    results.append(_v35_pci_result(
        f"{cat_prefix} - 5.3.2 Periodic Scans",
        "Pass" if scan_scheduled else "Warning",
        f"PCI 5.3.2 Periodic scan scheduled: {scan_scheduled}",
        severity="High",
        details=f"Scheduled scan job detected: {scan_scheduled}",
        remediation=(
            "Schedule daily/weekly full system scans. "
            "Example /etc/cron.daily/clamscan: clamscan -r --infected --quiet "
            "--exclude-dir=/proc --exclude-dir=/sys / | mail -s 'AV scan' root"
        ),
        cross_references={
            "PCI-DSS": "5.3.2", "NIST": "SI-3(2)",
        },
    ))

    # 5.3.3 - Anti-malware mechanism cannot be disabled by users
    # Heuristic: AV daemon service not user-modifiable
    av_protected = False
    for unit in ["clamav-daemon.service", "clamd.service"]:
        rc, out, _ = _v35_run_command(
            ["systemctl", "show", unit, "--property=UnitFileState"],
            timeout=3.0,
        )
        if rc == 0 and "enabled" in out.lower():
            av_protected = True
            break
    results.append(_v35_pci_result(
        f"{cat_prefix} - 5.3.3 Cannot Be Disabled",
        "Pass" if av_protected else "Info",
        f"PCI 5.3.3 AV service enabled (cannot be disabled by users)",
        severity="Medium",
        details=f"AV unit enabled: {av_protected}",
        remediation=(
            "Restrict systemctl access to admin users via polkit and ensure "
            "AV service is enabled with `systemctl enable`. "
            "PCI 5.3.3 requires that the anti-malware mechanism cannot be "
            "disabled or altered by users."
        ),
        cross_references={
            "PCI-DSS": "5.3.3", "NIST": "AC-3, SI-3",
        },
    ))

    return results


def _check_pci_v35_req8_authentication(os_info):
    """PCI Req 8.3/8.4/8.6 - Strong authentication, MFA, application creds."""
    results = []
    cat_prefix = "PCI Req 8 v3.5"

    # 8.3.1 - All user access authenticated
    # Indicator: no nullok in PAM
    pam_files_to_check = [
        "/etc/pam.d/system-auth",
        "/etc/pam.d/common-auth",
        "/etc/pam.d/password-auth",
    ]
    nullok_found = []
    for pf in pam_files_to_check:
        c = _v35_read_file_safe(pf)
        if "nullok" in c:
            nullok_found.append(pf)
    results.append(_v35_pci_result(
        f"{cat_prefix} - 8.3.1 No Null Authentication",
        "Pass" if not nullok_found else "Fail",
        f"PCI 8.3.1 PAM does not allow null passwords",
        severity="Critical",
        details=f"nullok found in: {nullok_found}",
        remediation=(
            "Remove `nullok` directives from PAM auth stack files. "
            "PCI 8.3.1 requires strong authentication for all access."
        ),
        cross_references={
            "PCI-DSS": "8.3.1", "NIST": "IA-5", "STIG": "V-230376",
        },
    ))

    # 8.3.2 - Strong cryptography for all authentication factors
    # Indicator: ENCRYPT_METHOD = SHA512 or YESCRYPT in /etc/login.defs
    login_defs = _v35_read_file_safe("/etc/login.defs")
    encrypt_method_match = re.search(
        r"^\s*ENCRYPT_METHOD\s+(\S+)", login_defs, re.MULTILINE
    )
    encrypt_method = (
        encrypt_method_match.group(1).upper()
        if encrypt_method_match else ""
    )
    strong_hash = encrypt_method in ("SHA512", "YESCRYPT")
    results.append(_v35_pci_result(
        f"{cat_prefix} - 8.3.2 Strong Hash",
        "Pass" if strong_hash else "Fail",
        f"PCI 8.3.2 Password hash algorithm: {encrypt_method or 'unset'}",
        severity="High",
        details=f"ENCRYPT_METHOD = {encrypt_method or 'default(SHA512)'}",
        remediation=(
            "In /etc/login.defs: ENCRYPT_METHOD SHA512 (or YESCRYPT on "
            "modern Debian/Ubuntu). Re-hash existing passwords on next "
            "password change."
        ),
        cross_references={
            "PCI-DSS": "8.3.2", "NIST": "IA-5(1)", "FIPS": "180-4",
        },
    ))

    # 8.3.5 - Initial password set to unique value per user
    # Largely operational; indicator: pam_pwhistory configured
    pwhistory_configured = False
    for pf in pam_files_to_check + ["/etc/pam.d/passwd"]:
        c = _v35_read_file_safe(pf)
        if "pam_pwhistory" in c or "pam_unix.so remember" in c:
            pwhistory_configured = True
            break
    results.append(_v35_pci_result(
        f"{cat_prefix} - 8.3.5 Password Reuse",
        "Pass" if pwhistory_configured else "Warning",
        f"PCI 8.3.5/8.3.7 Password history (reuse prevention)",
        severity="Medium",
        details=f"pam_pwhistory or remember=N: {pwhistory_configured}",
        remediation=(
            "In /etc/pam.d/common-password (Debian) or system-auth (RHEL): "
            "password required pam_pwhistory.so remember=4 enforce_for_root"
        ),
        cross_references={
            "PCI-DSS": "8.3.5, 8.3.7", "NIST": "IA-5(1)", "CIS": "5.4.3",
        },
    ))

    # 8.3.6 - Password complexity (min length 12 per v4.0.1)
    pwq = _v35_read_file_safe("/etc/security/pwquality.conf")
    minlen_match = re.search(r"^\s*minlen\s*=\s*(\d+)", pwq, re.MULTILINE)
    minlen = int(minlen_match.group(1)) if minlen_match else 0
    pci_v4_compliant = minlen >= 12
    results.append(_v35_pci_result(
        f"{cat_prefix} - 8.3.6 Password Complexity",
        "Pass" if pci_v4_compliant else "Fail",
        f"PCI 8.3.6 Password minimum length >= 12 ({minlen})",
        severity="High",
        details=f"pwquality minlen = {minlen}",
        remediation=(
            "In /etc/security/pwquality.conf: minlen = 12. "
            "PCI DSS v4.0 (effective 2025-04-01) raises minimum from 7 to 12."
        ),
        cross_references={
            "PCI-DSS": "8.3.6", "NIST": "IA-5(1)", "CIS": "5.4.2",
        },
    ))

    # 8.3.9 - Passwords changed at least once every 90 days
    pass_max_match = re.search(
        r"^\s*PASS_MAX_DAYS\s+(\d+)", login_defs, re.MULTILINE
    )
    pass_max = int(pass_max_match.group(1)) if pass_max_match else 99999
    pass_max_ok = 0 < pass_max <= 90
    results.append(_v35_pci_result(
        f"{cat_prefix} - 8.3.9 Password Aging",
        "Pass" if pass_max_ok else "Warning",
        f"PCI 8.3.9 PASS_MAX_DAYS <= 90 ({pass_max})",
        severity="Medium",
        details=f"PASS_MAX_DAYS = {pass_max}",
        remediation=(
            "In /etc/login.defs: PASS_MAX_DAYS 90. "
            "Note: PCI DSS v4.0 allows alternative if MFA + risk-based "
            "auth used (8.3.10.1)."
        ),
        cross_references={
            "PCI-DSS": "8.3.9", "NIST": "IA-5(1)", "CIS": "5.5.1.1",
        },
    ))

    # 8.4.1 - MFA for non-console admin access
    sshd = _v35_read_file_safe("/etc/ssh/sshd_config")
    mfa_indicators = {
        "pam_google_authenticator": False,
        "pam_yubico": False,
        "pam_oath": False,
        "pam_u2f": False,
        "pam_duo": False,
        "AuthenticationMethods publickey,keyboard-interactive": False,
    }
    for pf in pam_files_to_check + ["/etc/pam.d/sshd"]:
        c = _v35_read_file_safe(pf)
        for mod in mfa_indicators:
            if mod in c:
                mfa_indicators[mod] = True
    if "AuthenticationMethods" in sshd and "keyboard-interactive" in sshd:
        mfa_indicators["AuthenticationMethods publickey,keyboard-interactive"] = True
    mfa_count = sum(1 for v in mfa_indicators.values() if v)
    results.append(_v35_pci_result(
        f"{cat_prefix} - 8.4.1 MFA Admin Access",
        "Pass" if mfa_count >= 1 else "Fail",
        f"PCI 8.4.1 MFA for admin access ({mfa_count} indicators)",
        severity="Critical",
        details=(
            f"PAM modules detected: "
            f"{[k for k, v in mfa_indicators.items() if v]}"
        ),
        remediation=remediation_for("pam-google-authenticator"),
        cross_references={
            "PCI-DSS": "8.4.1, 8.4.2, 8.4.3", "NIST": "IA-2(1)",
            "CISA-CPG": "2.H",
        },
    ))

    # 8.6.1 - Application/system accounts have unique authentication
    # Indicator: count of system accounts with locked vs nologin shells
    passwd = _v35_read_file_safe("/etc/passwd")
    shadow = _v35_read_file_safe("/etc/shadow")
    system_accounts_secure = 0
    system_accounts_insecure = 0
    if passwd and shadow:
        shadow_map = {}
        for line in shadow.splitlines():
            parts = line.split(":", 2)
            if len(parts) >= 2:
                shadow_map[parts[0]] = parts[1]
        for line in passwd.splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            try:
                uid = int(parts[2])
            except ValueError:
                continue
            username, shell = parts[0], parts[6]
            if uid == 0 or uid >= 1000:
                continue  # not a system account
            shadow_pw = shadow_map.get(username, "")
            # Locked: starts with ! or *
            is_locked = shadow_pw.startswith("!") or shadow_pw == "*"
            is_nologin = shell in (
                "/sbin/nologin", "/usr/sbin/nologin", "/bin/false"
            )
            if is_locked or is_nologin:
                system_accounts_secure += 1
            else:
                system_accounts_insecure += 1
    results.append(_v35_pci_result(
        f"{cat_prefix} - 8.6.1 System Accounts Locked",
        "Pass" if system_accounts_insecure == 0 else "Warning",
        f"PCI 8.6.1 System accounts locked ({system_accounts_secure} locked, "
        f"{system_accounts_insecure} active)",
        severity="High",
        details=(
            f"Locked: {system_accounts_secure}, "
            f"Active: {system_accounts_insecure}"
        ),
        remediation=(
            "For each system account that should not be interactively used: "
            "passwd -l <user>; usermod -s /usr/sbin/nologin <user>"
        ),
        cross_references={
            "PCI-DSS": "8.6.1", "NIST": "AC-6", "STIG": "V-230376",
        },
    ))

    # 8.6.2 - Application credentials not hardcoded in scripts
    # Best-effort heuristic: check common locations for plaintext credentials
    cred_indicators = []
    for path in ["/etc/cron.d", "/etc/cron.daily"]:
        if not _v35_directory_exists(path):
            continue
        for f in _v35_list_directory(path):
            full = os.path.join(path, f)
            if not os.path.isfile(full):
                continue
            try:
                content = _v35_read_file_safe(full)
                if re.search(r"(?i)password\s*=\s*[\"']?\w{4,}", content):
                    cred_indicators.append(full)
            except OSError:
                pass
    results.append(_v35_pci_result(
        f"{cat_prefix} - 8.6.2 No Hardcoded Credentials",
        "Pass" if not cred_indicators else "Warning",
        f"PCI 8.6.2 No hardcoded credentials in cron scripts",
        severity="High",
        details=f"Suspicious files: {cred_indicators[:3]}",
        remediation=(
            "Move credentials to a secure secrets store (HashiCorp Vault, "
            "systemd-creds, etc.). PCI 8.6.2 prohibits hardcoded passwords "
            "in scripts, configuration, or source code."
        ),
        cross_references={
            "PCI-DSS": "8.6.2", "NIST": "IA-5", "ISO27001": "A.5.17",
        },
    ))

    return results


def _check_pci_v35_req10_logging_depth(os_info):
    """PCI Req 10.2/10.3/10.6 - Audit log content, integrity, time sync."""
    results = []
    cat_prefix = "PCI Req 10 v3.5"

    # Aggregate audit rules content
    audit_rules_content = ""
    rules_d = "/etc/audit/rules.d"
    if _v35_directory_exists(rules_d):
        for f in _v35_list_directory(rules_d):
            if f.endswith(".rules"):
                audit_rules_content += "\n" + _v35_read_file_safe(
                    os.path.join(rules_d, f)
                )

    # 10.2.1.1 - All individual user access to cardholder data
    has_user_access = (
        "auid" in audit_rules_content
        and "execve" in audit_rules_content
    )
    results.append(_v35_pci_result(
        f"{cat_prefix} - 10.2.1.1 User Access Logged",
        "Pass" if has_user_access else "Warning",
        f"PCI 10.2.1.1 User access auditing (execve + auid)",
        severity="High",
        details=f"execve+auid rules present: {has_user_access}",
        remediation=(
            "-a always,exit -F arch=b64 -S execve -F auid>=1000 "
            "-F auid!=4294967295 -k user-access"
        ),
        cross_references={
            "PCI-DSS": "10.2.1.1", "NIST": "AU-2, AU-12",
        },
    ))

    # 10.2.1.2 - All actions taken by individuals with admin privileges
    has_priv = "privileged" in audit_rules_content or "euid=0" in audit_rules_content
    results.append(_v35_pci_result(
        f"{cat_prefix} - 10.2.1.2 Admin Actions Logged",
        "Pass" if has_priv else "Fail",
        f"PCI 10.2.1.2 Privileged action auditing",
        severity="High",
        details=f"Privileged audit rules present: {has_priv}",
        remediation=(
            "-a always,exit -F arch=b64 -S execve -F euid=0 -k privileged"
        ),
        cross_references={
            "PCI-DSS": "10.2.1.2", "NIST": "AU-2, AC-6(9)",
        },
    ))

    # 10.2.1.3 - All access to audit logs
    has_audit_access = (
        "/var/log/audit" in audit_rules_content
        or "audit.log" in audit_rules_content
    )
    results.append(_v35_pci_result(
        f"{cat_prefix} - 10.2.1.3 Audit Log Access",
        "Pass" if has_audit_access else "Warning",
        f"PCI 10.2.1.3 Audit log access monitoring",
        severity="High",
        details=f"audit.log access rules: {has_audit_access}",
        remediation=(
            "-w /var/log/audit/ -p wa -k audit-log-access"
        ),
        cross_references={
            "PCI-DSS": "10.2.1.3", "NIST": "AU-9, AU-2",
        },
    ))

    # 10.2.1.4 - Invalid logical access attempts
    has_failed_login = (
        "/var/run/faillock" in audit_rules_content
        or "/var/log/faillog" in audit_rules_content
        or "logins" in audit_rules_content
    )
    results.append(_v35_pci_result(
        f"{cat_prefix} - 10.2.1.4 Failed Login Logged",
        "Pass" if has_failed_login else "Warning",
        f"PCI 10.2.1.4 Failed login auditing",
        severity="High",
        details=f"Login failure audit: {has_failed_login}",
        remediation=(
            "-w /var/run/faillock/ -p wa -k logins"
        ),
        cross_references={
            "PCI-DSS": "10.2.1.4", "NIST": "AU-2",
        },
    ))

    # 10.2.1.5 - Use of and changes to identification & authentication mechanisms
    has_pam_audit = (
        "/etc/pam.d" in audit_rules_content
        or "pam.d" in audit_rules_content
    )
    has_passwd_audit = (
        "/etc/passwd" in audit_rules_content
        or "/etc/shadow" in audit_rules_content
    )
    results.append(_v35_pci_result(
        f"{cat_prefix} - 10.2.1.5 IAM Changes Logged",
        "Pass" if (has_pam_audit and has_passwd_audit) else "Warning",
        f"PCI 10.2.1.5 IAM mechanism auditing",
        severity="High",
        details=(
            f"PAM audit: {has_pam_audit}, passwd/shadow audit: {has_passwd_audit}"
        ),
        remediation=(
            "-w /etc/pam.d/ -p wa -k pam\n"
            "-w /etc/passwd -p wa -k identity\n"
            "-w /etc/shadow -p wa -k identity"
        ),
        cross_references={
            "PCI-DSS": "10.2.1.5", "NIST": "AU-2, IA-5",
        },
    ))

    # 10.2.1.6 - Initialization, stopping, pausing of audit logs
    has_audit_self = (
        "auditd" in audit_rules_content
        or "/sbin/auditctl" in audit_rules_content
        or "audit_log_full" in audit_rules_content
    )
    results.append(_v35_pci_result(
        f"{cat_prefix} - 10.2.1.6 Audit System Events",
        "Pass" if has_audit_self else "Info",
        f"PCI 10.2.1.6 Audit system control auditing",
        severity="Medium",
        details=f"audit-self rules present: {has_audit_self}",
        remediation=(
            "-w /sbin/auditctl -p x -k audittools\n"
            "-w /sbin/auditd -p x -k audittools"
        ),
        cross_references={
            "PCI-DSS": "10.2.1.6", "NIST": "AU-9",
        },
    ))

    # 10.2.1.7 - Creation/deletion of system-level objects
    has_module_audit = (
        "/sbin/insmod" in audit_rules_content
        or "modules" in audit_rules_content
        or "init_module" in audit_rules_content
    )
    results.append(_v35_pci_result(
        f"{cat_prefix} - 10.2.1.7 System Object Changes",
        "Pass" if has_module_audit else "Warning",
        f"PCI 10.2.1.7 Kernel module audit",
        severity="High",
        details=f"Module load/unload audit: {has_module_audit}",
        remediation=(
            "-w /sbin/insmod -p x -k modules\n"
            "-w /sbin/rmmod -p x -k modules\n"
            "-w /sbin/modprobe -p x -k modules\n"
            "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules"
        ),
        cross_references={
            "PCI-DSS": "10.2.1.7", "NIST": "AU-2, CM-7",
        },
    ))

    # 10.3.1 - Read access to audit log files limited
    audit_log_perms = None
    audit_log = "/var/log/audit/audit.log"
    if _v35_file_exists(audit_log):
        try:
            mode = os.stat(audit_log).st_mode & 0o7777
            audit_log_perms = oct(mode)
            ok = (mode & 0o077) == 0  # group/other have no access
        except OSError:
            ok = False
            audit_log_perms = "<error>"
    else:
        ok = False
    results.append(_v35_pci_result(
        f"{cat_prefix} - 10.3.1 Audit Log Permissions",
        "Pass" if ok else "Warning",
        f"PCI 10.3.1 Audit log file permissions ({audit_log_perms})",
        severity="High",
        details=f"audit.log mode: {audit_log_perms}",
        remediation=(
            "chmod 0600 /var/log/audit/audit.log\n"
            "chown root:root /var/log/audit/audit.log\n"
            "In /etc/audit/auditd.conf: log_file_mode = 0600"
        ),
        cross_references={
            "PCI-DSS": "10.3.1", "NIST": "AU-9", "STIG": "V-230400",
        },
    ))

    # 10.3.4 - Audit logs protected via FIM
    fim_present = (
        _v35_file_exists("/var/lib/aide/aide.db") or
        _v35_file_exists("/var/lib/aide/aide.db.gz") or
        _v35_file_exists("/etc/tripwire/tw.cfg")
    )
    results.append(_v35_pci_result(
        f"{cat_prefix} - 10.3.4 FIM on Audit Logs",
        "Pass" if fim_present else "Warning",
        f"PCI 10.3.4 File integrity monitoring (FIM): {fim_present}",
        severity="High",
        details=f"FIM database present: {fim_present}",
        remediation=remediation_for("aide"),
        cross_references={
            "PCI-DSS": "10.3.4, 11.5.2", "NIST": "SI-7", "ISO27001": "A.8.32",
        },
    ))

    # 10.6.1 - Time-synchronization technology in use
    time_sync_active = (
        _v35_systemd_active("chronyd.service") == "active"
        or _v35_systemd_active("chrony.service") == "active"
        or _v35_systemd_active("ntpd.service") == "active"
        or _v35_systemd_active("systemd-timesyncd.service") == "active"
    )
    results.append(_v35_pci_result(
        f"{cat_prefix} - 10.6.1 Time Sync Active",
        "Pass" if time_sync_active else "Fail",
        f"PCI 10.6.1 Time synchronization service active",
        severity="Critical",
        details=f"NTP/chrony/timesyncd active: {time_sync_active}",
        remediation=remediation_for("chrony"),
        cross_references={
            "PCI-DSS": "10.6.1", "NIST": "AU-8", "ISO27001": "A.8.17",
        },
    ))

    # 10.6.2 - Time received from authoritative sources
    chrony_conf = (
        _v35_read_file_safe("/etc/chrony/chrony.conf")
        or _v35_read_file_safe("/etc/chrony.conf")
    )
    ntp_conf = _v35_read_file_safe("/etc/ntp.conf")
    has_servers = bool(
        re.search(r"^\s*(server|pool)\s+\S+", chrony_conf, re.MULTILINE)
        or re.search(r"^\s*(server|pool)\s+\S+", ntp_conf, re.MULTILINE)
    )
    results.append(_v35_pci_result(
        f"{cat_prefix} - 10.6.2 Authoritative Sources",
        "Pass" if has_servers else "Warning",
        f"PCI 10.6.2 NTP/chrony servers configured: {has_servers}",
        severity="High",
        details=f"server/pool directives present: {has_servers}",
        remediation=(
            "In /etc/chrony.conf or /etc/chrony/chrony.conf:\n"
            "  server time.cloudflare.com iburst nts\n"
            "  pool pool.ntp.org iburst"
        ),
        cross_references={
            "PCI-DSS": "10.6.2", "NIST": "AU-8(1)",
        },
    ))

    # 10.6.3 - Time settings received protected
    # Indicator: NTS (Network Time Security) configured
    nts_configured = (
        "nts" in chrony_conf if chrony_conf else False
    )
    results.append(_v35_pci_result(
        f"{cat_prefix} - 10.6.3 Authenticated Time",
        "Pass" if nts_configured else "Info",
        f"PCI 10.6.3 NTS-authenticated time sources",
        severity="Medium",
        details=f"NTS directive in chrony config: {nts_configured}",
        remediation=(
            "In /etc/chrony.conf: server time.cloudflare.com iburst nts. "
            "PCI 10.6.3 requires time settings be authenticated to prevent "
            "MITM tampering."
        ),
        cross_references={
            "PCI-DSS": "10.6.3", "NIST": "AU-8(2)",
        },
    ))

    return results


def _check_pci_v35_req11_security_testing(os_info):
    """PCI Req 11.4/11.5/11.6 - IDS/IPS, change detection, vuln testing."""
    results = []
    cat_prefix = "PCI Req 11 v3.5"

    # 11.4.x - External and internal vulnerability scanning
    scanners = {
        "lynis": _v35_command_available("lynis"),
        "openscap": _v35_command_available("oscap"),
        "trivy": _v35_command_available("trivy"),
        "nuclei": _v35_command_available("nuclei"),
        "nikto": _v35_command_available("nikto"),
    }
    detected_scanners = [k for k, v in scanners.items() if v]
    results.append(_v35_pci_result(
        f"{cat_prefix} - 11.4 Vulnerability Scanning",
        "Pass" if detected_scanners else "Warning",
        f"PCI 11.4 Vulnerability scanners ({len(detected_scanners)})",
        severity="High",
        details=f"Detected: {detected_scanners}",
        remediation=remediation_for("lynis"),
        cross_references={
            "PCI-DSS": "11.4.1, 11.4.5", "NIST": "RA-5",
        },
    ))

    # 11.5.1 - Intrusion-detection or intrusion-prevention deployed
    ids_present = {
        "Suricata": _v35_command_available("suricata"),
        "Snort": _v35_command_available("snort"),
        "Zeek/Bro": _v35_command_available("zeek") or _v35_command_available("bro"),
        "Wazuh": _v35_file_exists("/var/ossec/etc/ossec.conf"),
        "Falco": _v35_command_available("falco"),
        "OSSEC": _v35_file_exists("/var/ossec/bin/ossec-control"),
    }
    detected_ids = [k for k, v in ids_present.items() if v]
    results.append(_v35_pci_result(
        f"{cat_prefix} - 11.5.1 IDS/IPS",
        "Pass" if detected_ids else "Warning",
        f"PCI 11.5.1 IDS/IPS deployed ({len(detected_ids)})",
        severity="High",
        details=f"Detected: {detected_ids}",
        remediation=(
            remediation_for("suricata") if not detected_ids
            else f"Active IDS: {detected_ids}"
        ),
        cross_references={
            "PCI-DSS": "11.5.1", "NIST": "SI-4", "ISO27001": "A.8.16",
        },
    ))

    # 11.5.1.1 - Service Provider only - covert malware channels
    # Covered organizationally; technical surrogate: egress monitoring
    rsy_remote = "@@" in _v35_read_file_safe("/etc/rsyslog.conf")
    if not rsy_remote and _v35_directory_exists("/etc/rsyslog.d"):
        for f in _v35_list_directory("/etc/rsyslog.d"):
            if "@@" in _v35_read_file_safe(os.path.join("/etc/rsyslog.d", f)):
                rsy_remote = True
                break
    results.append(_v35_pci_result(
        f"{cat_prefix} - 11.5.1.1 Egress Monitoring",
        "Pass" if rsy_remote else "Info",
        f"PCI 11.5.1.1 Log forwarding for egress visibility",
        severity="High",
        details=f"rsyslog forwarding configured: {rsy_remote}",
        remediation=(
            "Configure /etc/rsyslog.d/50-remote.conf:\n"
            "  *.* @@logserver.example.com:6514\n"
            "Enables centralized egress monitoring."
        ),
        cross_references={
            "PCI-DSS": "11.5.1.1", "NIST": "SI-4, AU-6",
        },
    ))

    # 11.5.2 - Change-detection mechanism (FIM) - alerts on unauthorized changes
    # We've already checked FIM presence; this checks for cron/scheduled execution
    fim_scheduled = False
    for cron_dir in ["/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.d"]:
        if _v35_directory_exists(cron_dir):
            for f in _v35_list_directory(cron_dir):
                if "aide" in f.lower() or "tripwire" in f.lower():
                    fim_scheduled = True
                    break
        if fim_scheduled:
            break
    results.append(_v35_pci_result(
        f"{cat_prefix} - 11.5.2 FIM Scheduled",
        "Pass" if fim_scheduled else "Warning",
        f"PCI 11.5.2 FIM execution scheduled: {fim_scheduled}",
        severity="High",
        details=f"AIDE/Tripwire cron job present: {fim_scheduled}",
        remediation=(
            "On Debian: aide-common package installs /etc/cron.daily/aide.\n"
            "Verify with: ls -la /etc/cron.daily/aide"
        ),
        cross_references={
            "PCI-DSS": "11.5.2", "NIST": "SI-7(1)",
        },
    ))

    # 11.6.1 - Change/tamper detection on payment pages (web-tier; surrogate)
    # Surrogate: WAF presence
    waf_present = (
        _v35_directory_exists("/etc/modsecurity")
        or _v35_directory_exists("/usr/share/modsecurity-crs")
        or _v35_file_exists("/etc/nginx/naxsi_core.rules")
    )
    results.append(_v35_pci_result(
        f"{cat_prefix} - 11.6.1 Web Tier Tamper Detection",
        "Info" if not waf_present else "Pass",
        f"PCI 11.6.1 WAF/web-tier protection: {waf_present}",
        severity="Medium",
        details=f"ModSecurity/CRS detected: {waf_present}",
        remediation=(
            "If web tier is in scope: install ModSecurity v3 + OWASP CRS.\n"
            "  apt-get install -y libapache2-mod-security2 modsecurity-crs"
        ),
        cross_references={
            "PCI-DSS": "11.6.1", "NIST": "SI-4, SC-7(8)",
        },
    ))

    return results


def _check_pci_v35_req7_access_definition(os_info):
    """PCI Req 7.2/7.3 - Access definition and enforcement."""
    results = []
    cat_prefix = "PCI Req 7 v3.5"

    # 7.2.1 - Access control system covering all components
    # Indicator: PAM stack, sudo, MAC framework
    pam_stack_count = 0
    pam_dir = "/etc/pam.d"
    if _v35_directory_exists(pam_dir):
        pam_stack_count = len(_v35_list_directory(pam_dir))
    sudo_present = _v35_file_exists("/etc/sudoers")
    mac_active = (
        _v35_systemd_active("apparmor.service") == "active"
        or _v35_file_exists("/sys/fs/selinux/enforce")
    )
    ac_layers = sum([pam_stack_count >= 10, sudo_present, mac_active])
    results.append(_v35_pci_result(
        f"{cat_prefix} - 7.2.1 Access Control System",
        "Pass" if ac_layers >= 2 else "Warning",
        f"PCI 7.2.1 Access control layers ({ac_layers}/3)",
        severity="High",
        details=(
            f"PAM modules: {pam_stack_count}, sudo: {sudo_present}, "
            f"MAC: {mac_active}"
        ),
        cross_references={
            "PCI-DSS": "7.2.1", "NIST": "AC-3", "ISO27001": "A.5.15",
        },
    ))

    # 7.2.2 - Access assigned based on job classification (least privilege)
    # Indicator: sudo usage of specific commands rather than ALL=ALL
    sudoers = _v35_read_file_safe("/etc/sudoers")
    sudoers_d_content = ""
    if _v35_directory_exists("/etc/sudoers.d"):
        for f in _v35_list_directory("/etc/sudoers.d"):
            if f != "README":
                sudoers_d_content += "\n" + _v35_read_file_safe(
                    os.path.join("/etc/sudoers.d", f)
                )
    all_sudoers_content = sudoers + "\n" + sudoers_d_content
    # Count NOPASSWD ALL=ALL or wildcard entries
    overly_broad = len(re.findall(
        r"^\s*[^#].*ALL=\(ALL.*?\)\s+(NOPASSWD\s*:\s*)?ALL\s*$",
        all_sudoers_content, re.MULTILINE
    ))
    results.append(_v35_pci_result(
        f"{cat_prefix} - 7.2.2 Least Privilege",
        "Pass" if overly_broad <= 1 else "Warning",
        f"PCI 7.2.2 ALL=(ALL) ALL grants: {overly_broad}",
        severity="High",
        details=f"Broad sudo grants found: {overly_broad}",
        remediation=(
            "Restrict sudo to specific commands per role. "
            "Replace `<user> ALL=(ALL) ALL` with specific command lists. "
            "PCI 7.2.2 requires assignment based on job classification."
        ),
        cross_references={
            "PCI-DSS": "7.2.2", "NIST": "AC-6", "STIG": "V-230267",
        },
    ))

    # 7.2.4 - User access reviewed at least every six months
    # Operational; technical surrogate: account inactivity tracking
    inact_match = re.search(
        r"^\s*INACTIVE\s+(-?\d+)",
        _v35_read_file_safe("/etc/login.defs"),
        re.MULTILINE,
    )
    inactive_days = int(inact_match.group(1)) if inact_match else -1
    inactive_ok = 0 < inactive_days <= 180  # 6 months
    results.append(_v35_pci_result(
        f"{cat_prefix} - 7.2.4 Account Review",
        "Pass" if inactive_ok else "Warning",
        f"PCI 7.2.4 Inactive auto-disable <= 180 days ({inactive_days})",
        severity="Medium",
        details=f"INACTIVE = {inactive_days}",
        remediation=(
            "In /etc/default/useradd: INACTIVE=180. "
            "Existing accounts: chage -I 180 <user>"
        ),
        cross_references={
            "PCI-DSS": "7.2.4", "NIST": "AC-2(3)",
        },
    ))

    # 7.3.1 - Access enforcement via access control system
    # Indicator: PAM is in use (handled by 7.2.1)
    # Additional: nullok absent
    no_nullok = "nullok" not in (
        _v35_read_file_safe("/etc/pam.d/common-auth")
        + _v35_read_file_safe("/etc/pam.d/system-auth")
    )
    results.append(_v35_pci_result(
        f"{cat_prefix} - 7.3.1 Access Enforcement",
        "Pass" if no_nullok else "Fail",
        f"PCI 7.3.1 PAM enforces authentication (no nullok)",
        severity="High",
        details=f"nullok absent: {no_nullok}",
        cross_references={
            "PCI-DSS": "7.3.1", "NIST": "AC-3",
        },
    ))

    # 7.3.2 - Access control system configured to enforce defined access
    # Indicator: deny by default in firewalld/ufw/iptables
    rc, out, _ = _v35_run_command(["ufw", "status", "verbose"], timeout=3.0)
    ufw_default_deny = rc == 0 and (
        "Default: deny" in out or "default deny" in out.lower()
    )
    rc2, out2, _ = _v35_run_command(
        ["firewall-cmd", "--get-default-zone"], timeout=3.0
    )
    firewalld_drop = rc2 == 0 and out2.strip() in ("drop", "block")
    deny_default = ufw_default_deny or firewalld_drop
    results.append(_v35_pci_result(
        f"{cat_prefix} - 7.3.2 Default Deny",
        "Pass" if deny_default else "Warning",
        f"PCI 7.3.2 Network default-deny",
        severity="High",
        details=(
            f"ufw default deny: {ufw_default_deny}, "
            f"firewalld drop zone: {firewalld_drop}"
        ),
        remediation=(
            "ufw default deny incoming  (Debian/Ubuntu)\n"
            "firewall-cmd --set-default-zone=drop  (RHEL family)"
        ),
        cross_references={
            "PCI-DSS": "7.3.2", "NIST": "AC-3, SC-7",
        },
    ))

    # 7.3.3 - Access control system has default deny
    # Same indicator as 7.3.2 - re-check with PAM perspective
    # Default PAM behavior is deny if no explicit allow -> covered

    return results


# Save reference to existing run_checks
_original_run_checks_pci_v35 = run_checks


def run_checks(shared_data: Optional[Dict[str, Any]] = None) -> List[AuditResult]:
    """Execute the v3.5 expanded PCI module."""
    if shared_data is None:
        shared_data = {}

    results = _original_run_checks_pci_v35(shared_data)

    os_info = shared_data.get("os_info") or shared_data.get("v3_os_info")
    if os_info is None:
        from shared_components import os_detection as _os_det
        os_info = _os_det.detect_os()
        shared_data["v3_os_info"] = os_info

    try:
        results.extend(_check_pci_v35_req2_configuration_standards(os_info))
        results.extend(_check_pci_v35_req3_pan_protection(os_info))
        results.extend(_check_pci_v35_req5_malware(os_info))
        results.extend(_check_pci_v35_req7_access_definition(os_info))
        results.extend(_check_pci_v35_req8_authentication(os_info))
        results.extend(_check_pci_v35_req10_logging_depth(os_info))
        results.extend(_check_pci_v35_req11_security_testing(os_info))
    except Exception as exc:  # noqa: BLE001
        results.append(AuditResult(
            module=MODULE_NAME, category="PCI - Error",
            status="Error",
            message=f"PCI v3.5 expansion exception: {exc!r}",
            details=str(exc), severity="Medium",
        ))

    return results
if __name__ == "__main__":
    import json
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    print(f"[PCI-DSS] ===== PCI DSS v4.0.1 Linux Compliance Audit =====")
    print(f"[PCI-DSS] Module Version: 3.9")
    print()

    audit_results = run_checks()
    print(f"[PCI-DSS] {len(audit_results)} checks executed")
    print()

    by_status: Dict[str, int] = {}
    for r in audit_results:
        by_status[r.status] = by_status.get(r.status, 0) + 1

    for status, count in sorted(by_status.items()):
        print(f"  {status:>8}: {count}")
    print()

    # Show failures
    failures = [r for r in audit_results if r.status == "Fail"]
    if failures:
        print("Failures:")
        print("-" * 70)
        for r in failures:
            print(f"  [{r.severity:>13}] {r.category}")
            print(f"                {r.message}")
        print()
