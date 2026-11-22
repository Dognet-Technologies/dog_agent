"""
correlation_registry.py - Cross-framework control identifier registry.

SYNOPSIS
    Maps logical security controls to their identifiers across multiple
    compliance frameworks. Enables a single audit check to be associated
    with equivalent controls in CIS, NIST 800-53, ISO 27001, STIG,
    PCI DSS, HIPAA, and others.

DESCRIPTION
    The registry is structured as a list of correlation records keyed on
    a logical control_topic (e.g. "ssh.permit_root_login"). Each record
    holds the control identifier in each framework that addresses that
    topic. Modules attach the topic key to their results; the orchestrator
    then enriches the results with the full cross-reference dictionary
    using the registry as the source of truth.

    Mappings are sourced from publicly published official documentation:
        - CIS Benchmarks for Linux v3.0.0 (Distribution Independent)
        - NIST SP 800-53 Rev 5 control catalog
        - ISO/IEC 27001:2022 Annex A
        - DISA STIG for RHEL 9 V1R6, Ubuntu 22.04 V1R3
        - PCI DSS v4.0.1
        - HIPAA Security Rule Sec. 164.312
        - GDPR Article 32
        - NSA Network Infrastructure Security Guide
        - CISA Cybersecurity Performance Goals v1.0.1
        - ENISA Baseline Security Recommendations

    Mappings are conservative: a correlation is recorded only when the
    control objective in both frameworks is substantively equivalent, not
    merely topically related. Where a framework lacks a directly equivalent
    control, the field is omitted (not populated with a partial match).

PARAMETERS
    Public API:
        get_correlations(topic) -> Dict[str, str]
        get_topic_for(framework, control_id) -> Optional[str]
        list_topics() -> List[str]
        list_frameworks() -> List[str]

EXAMPLES
    >>> from shared_components.correlation_registry import get_correlations
    >>> get_correlations("ssh.permit_root_login")
    {'CIS': '5.2.7', 'NIST': 'AC-6(2)', 'STIG': 'V-230296',
     'ISO27001': 'A.8.2', 'NSA': 'SSH-1.3', 'CISA': 'CPG-2.E'}

NOTES
    Version: 3.0
    Stdlib only.
    The registry is intentionally append-only at runtime: callers may
    extend it via register_correlation() but should not mutate or remove
    existing entries because module results would silently lose their
    cross-references.
"""

from __future__ import annotations

import logging
import threading
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("audit.correlation")


# Canonical framework codes used as keys in correlation records. Modules
# should use these exact strings when looking up correlations.

FRAMEWORK_CIS = "CIS"
FRAMEWORK_NIST = "NIST"
FRAMEWORK_NIST_CSF = "NIST-CSF"
FRAMEWORK_NIST_171 = "NIST-171"
FRAMEWORK_STIG = "STIG"
FRAMEWORK_ISO27001 = "ISO27001"
FRAMEWORK_PCI = "PCI-DSS"
FRAMEWORK_HIPAA = "HIPAA"
FRAMEWORK_GDPR = "GDPR"
FRAMEWORK_SOC2 = "SOC2"
FRAMEWORK_NSA = "NSA"
FRAMEWORK_CISA = "CISA"
FRAMEWORK_ENISA = "ENISA"
FRAMEWORK_CMMC = "CMMC"
FRAMEWORK_ACSC = "ACSC"

ALL_FRAMEWORKS = (
    FRAMEWORK_CIS, FRAMEWORK_NIST, FRAMEWORK_NIST_CSF, FRAMEWORK_NIST_171,
    FRAMEWORK_STIG, FRAMEWORK_ISO27001, FRAMEWORK_PCI, FRAMEWORK_HIPAA,
    FRAMEWORK_GDPR, FRAMEWORK_SOC2, FRAMEWORK_NSA, FRAMEWORK_CISA,
    FRAMEWORK_ENISA, FRAMEWORK_CMMC, FRAMEWORK_ACSC,
)


# The registry is a list of (topic, correlations) tuples. The list form
# is preserved (rather than a dict) so the natural ordering reflects
# logical grouping (SSH topics together, auditd together, etc.) which
# helps maintenance.

_REGISTRY: List[Tuple[str, Dict[str, str]]] = [
    # ====================================================================
    # SSH Daemon Configuration
    # ====================================================================
    ("ssh.permit_root_login", {
        FRAMEWORK_CIS: "5.2.7",
        FRAMEWORK_NIST: "AC-6(2)",
        FRAMEWORK_STIG: "V-230296",
        FRAMEWORK_ISO27001: "A.8.2",
        FRAMEWORK_NSA: "SSH-1.3",
        FRAMEWORK_CISA: "CPG-2.E",
        FRAMEWORK_PCI: "8.2.1",
    }),
    ("ssh.protocol_version", {
        FRAMEWORK_CIS: "5.2.1",
        FRAMEWORK_NIST: "SC-8",
        FRAMEWORK_STIG: "V-230252",
        FRAMEWORK_ISO27001: "A.8.21",
    }),
    ("ssh.x11_forwarding", {
        FRAMEWORK_CIS: "5.2.6",
        FRAMEWORK_NIST: "AC-17(2)",
        FRAMEWORK_STIG: "V-230382",
        FRAMEWORK_ISO27001: "A.8.21",
    }),
    ("ssh.max_auth_tries", {
        FRAMEWORK_CIS: "5.2.4",
        FRAMEWORK_NIST: "AC-7",
        FRAMEWORK_STIG: "V-230331",
        FRAMEWORK_ISO27001: "A.8.5",
        FRAMEWORK_HIPAA: "164.308(a)(5)(ii)(D)",
    }),
    ("ssh.empty_passwords", {
        FRAMEWORK_CIS: "5.2.9",
        FRAMEWORK_NIST: "IA-5",
        FRAMEWORK_STIG: "V-230380",
        FRAMEWORK_ISO27001: "A.8.5",
        FRAMEWORK_PCI: "8.3.5",
    }),
    ("ssh.client_alive_interval", {
        FRAMEWORK_CIS: "5.2.16",
        FRAMEWORK_NIST: "AC-12",
        FRAMEWORK_STIG: "V-230244",
        FRAMEWORK_ISO27001: "A.8.5",
    }),
    ("ssh.login_grace_time", {
        FRAMEWORK_CIS: "5.2.17",
        FRAMEWORK_NIST: "AC-7",
        FRAMEWORK_STIG: "V-230555",
    }),
    ("ssh.allow_users_groups", {
        FRAMEWORK_CIS: "5.2.18",
        FRAMEWORK_NIST: "AC-3",
        FRAMEWORK_ISO27001: "A.8.3",
    }),
    ("ssh.banner", {
        FRAMEWORK_CIS: "5.2.19",
        FRAMEWORK_NIST: "AC-8",
        FRAMEWORK_STIG: "V-230225",
        FRAMEWORK_ISO27001: "A.8.3",
    }),
    ("ssh.ciphers", {
        FRAMEWORK_CIS: "5.2.13",
        FRAMEWORK_NIST: "SC-13",
        FRAMEWORK_STIG: "V-255924",
        FRAMEWORK_ISO27001: "A.8.24",
        FRAMEWORK_NSA: "SSH-2.1",
    }),
    ("ssh.macs", {
        FRAMEWORK_CIS: "5.2.14",
        FRAMEWORK_NIST: "SC-13",
        FRAMEWORK_STIG: "V-230250",
        FRAMEWORK_ISO27001: "A.8.24",
        FRAMEWORK_NSA: "SSH-2.2",
    }),
    ("ssh.kex_algorithms", {
        FRAMEWORK_CIS: "5.2.15",
        FRAMEWORK_NIST: "SC-13",
        FRAMEWORK_ISO27001: "A.8.24",
        FRAMEWORK_NSA: "SSH-2.3",
    }),
    ("ssh.host_based_auth", {
        FRAMEWORK_CIS: "5.2.8",
        FRAMEWORK_NIST: "IA-2",
        FRAMEWORK_STIG: "V-230377",
    }),
    ("ssh.permit_user_environment", {
        FRAMEWORK_CIS: "5.2.10",
        FRAMEWORK_NIST: "CM-7",
        FRAMEWORK_STIG: "V-230381",
    }),
    ("ssh.ignore_rhosts", {
        FRAMEWORK_CIS: "5.2.5",
        FRAMEWORK_NIST: "IA-2",
        FRAMEWORK_STIG: "V-230378",
    }),

    # ====================================================================
    # Password Policy and PAM
    # ====================================================================
    ("password.minimum_length", {
        FRAMEWORK_CIS: "5.4.1.1",
        FRAMEWORK_NIST: "IA-5(1)",
        FRAMEWORK_STIG: "V-230369",
        FRAMEWORK_ISO27001: "A.8.5",
        FRAMEWORK_PCI: "8.3.6",
        FRAMEWORK_HIPAA: "164.308(a)(5)(ii)(D)",
    }),
    ("password.complexity", {
        FRAMEWORK_CIS: "5.4.1.2",
        FRAMEWORK_NIST: "IA-5(1)",
        FRAMEWORK_STIG: "V-230370",
        FRAMEWORK_ISO27001: "A.8.5",
        FRAMEWORK_PCI: "8.3.6",
    }),
    ("password.history", {
        FRAMEWORK_CIS: "5.4.1.3",
        FRAMEWORK_NIST: "IA-5(1)",
        FRAMEWORK_STIG: "V-230368",
        FRAMEWORK_ISO27001: "A.8.5",
        FRAMEWORK_PCI: "8.3.7",
    }),
    ("password.max_days", {
        FRAMEWORK_CIS: "5.4.1.4",
        FRAMEWORK_NIST: "IA-5(1)",
        FRAMEWORK_STIG: "V-230367",
        FRAMEWORK_ISO27001: "A.8.5",
        FRAMEWORK_HIPAA: "164.308(a)(5)(ii)(D)",
    }),
    ("password.min_days", {
        FRAMEWORK_CIS: "5.4.1.5",
        FRAMEWORK_NIST: "IA-5(1)",
        FRAMEWORK_STIG: "V-230366",
    }),
    ("password.warn_age", {
        FRAMEWORK_CIS: "5.4.1.6",
        FRAMEWORK_NIST: "IA-5(1)",
        FRAMEWORK_ISO27001: "A.8.5",
    }),
    ("password.hash_algorithm", {
        FRAMEWORK_CIS: "5.4.1.7",
        FRAMEWORK_NIST: "IA-5(1)(c)",
        FRAMEWORK_STIG: "V-230231",
        FRAMEWORK_ISO27001: "A.8.24",
        FRAMEWORK_NSA: "AUTH-1.1",
        FRAMEWORK_PCI: "8.3.2",
    }),
    ("password.lockout_attempts", {
        FRAMEWORK_CIS: "5.3.1",
        FRAMEWORK_NIST: "AC-7",
        FRAMEWORK_STIG: "V-230333",
        FRAMEWORK_ISO27001: "A.8.5",
        FRAMEWORK_PCI: "8.3.4",
        FRAMEWORK_HIPAA: "164.308(a)(5)(ii)(D)",
    }),
    ("password.lockout_time", {
        FRAMEWORK_CIS: "5.3.2",
        FRAMEWORK_NIST: "AC-7",
        FRAMEWORK_STIG: "V-230336",
        FRAMEWORK_ISO27001: "A.8.5",
    }),

    # ====================================================================
    # Account Management
    # ====================================================================
    ("account.no_empty_passwords", {
        FRAMEWORK_CIS: "6.2.5",
        FRAMEWORK_NIST: "IA-5",
        FRAMEWORK_STIG: "V-230345",
        FRAMEWORK_ISO27001: "A.8.5",
        FRAMEWORK_PCI: "8.3.5",
    }),
    ("account.uid_zero_only_root", {
        FRAMEWORK_CIS: "6.2.10",
        FRAMEWORK_NIST: "AC-6",
        FRAMEWORK_STIG: "V-230327",
        FRAMEWORK_ISO27001: "A.8.2",
    }),
    ("account.no_duplicate_uid", {
        FRAMEWORK_CIS: "6.2.6",
        FRAMEWORK_NIST: "IA-2",
        FRAMEWORK_STIG: "V-230371",
    }),
    ("account.no_duplicate_gid", {
        FRAMEWORK_CIS: "6.2.7",
        FRAMEWORK_NIST: "IA-2",
        FRAMEWORK_STIG: "V-230372",
    }),
    ("account.shadow_passwords", {
        FRAMEWORK_CIS: "6.2.4",
        FRAMEWORK_NIST: "IA-5(1)",
        FRAMEWORK_ISO27001: "A.8.5",
    }),
    ("account.inactive_lock", {
        FRAMEWORK_CIS: "5.4.1.5",
        FRAMEWORK_NIST: "AC-2(3)",
        FRAMEWORK_STIG: "V-230373",
        FRAMEWORK_ISO27001: "A.8.2",
    }),
    ("account.system_accounts_nologin", {
        FRAMEWORK_CIS: "5.4.2.1",
        FRAMEWORK_NIST: "AC-2",
        FRAMEWORK_ISO27001: "A.8.2",
    }),
    ("account.root_default_group", {
        FRAMEWORK_CIS: "5.4.2.2",
        FRAMEWORK_NIST: "AC-6",
        FRAMEWORK_STIG: "V-230328",
    }),
    ("account.default_umask", {
        FRAMEWORK_CIS: "5.4.5",
        FRAMEWORK_NIST: "AC-3",
        FRAMEWORK_STIG: "V-230337",
        FRAMEWORK_ISO27001: "A.8.3",
    }),
    ("account.shell_timeout", {
        FRAMEWORK_CIS: "5.4.4",
        FRAMEWORK_NIST: "AC-12",
        FRAMEWORK_STIG: "V-230363",
    }),

    # ====================================================================
    # File Permissions on Critical Files
    # ====================================================================
    ("permissions.passwd", {
        FRAMEWORK_CIS: "6.1.2",
        FRAMEWORK_NIST: "AC-3",
        FRAMEWORK_STIG: "V-230322",
        FRAMEWORK_ISO27001: "A.8.3",
    }),
    ("permissions.shadow", {
        FRAMEWORK_CIS: "6.1.3",
        FRAMEWORK_NIST: "AC-3",
        FRAMEWORK_STIG: "V-230323",
        FRAMEWORK_ISO27001: "A.8.3",
    }),
    ("permissions.group", {
        FRAMEWORK_CIS: "6.1.4",
        FRAMEWORK_NIST: "AC-3",
        FRAMEWORK_STIG: "V-230324",
    }),
    ("permissions.gshadow", {
        FRAMEWORK_CIS: "6.1.5",
        FRAMEWORK_NIST: "AC-3",
        FRAMEWORK_STIG: "V-230325",
    }),
    ("permissions.sshd_config", {
        FRAMEWORK_CIS: "5.2.2",
        FRAMEWORK_NIST: "AC-3",
        FRAMEWORK_STIG: "V-230253",
    }),
    ("permissions.cron_files", {
        FRAMEWORK_CIS: "5.1.1",
        FRAMEWORK_NIST: "AC-3",
        FRAMEWORK_STIG: "V-230371",
        FRAMEWORK_ISO27001: "A.8.3",
    }),

    # ====================================================================
    # Network Hardening (sysctl)
    # ====================================================================
    ("network.ip_forward", {
        FRAMEWORK_CIS: "3.2.1",
        FRAMEWORK_NIST: "SC-7",
        FRAMEWORK_STIG: "V-230540",
        FRAMEWORK_ISO27001: "A.8.20",
        FRAMEWORK_NSA: "NET-1.1",
    }),
    ("network.send_redirects", {
        FRAMEWORK_CIS: "3.2.2",
        FRAMEWORK_NIST: "SC-7",
        FRAMEWORK_STIG: "V-230541",
        FRAMEWORK_NSA: "NET-1.2",
    }),
    ("network.accept_source_route", {
        FRAMEWORK_CIS: "3.3.1",
        FRAMEWORK_NIST: "SC-7",
        FRAMEWORK_STIG: "V-230542",
        FRAMEWORK_NSA: "NET-1.3",
    }),
    ("network.accept_redirects", {
        FRAMEWORK_CIS: "3.3.2",
        FRAMEWORK_NIST: "SC-7",
        FRAMEWORK_STIG: "V-230543",
        FRAMEWORK_NSA: "NET-1.4",
    }),
    ("network.secure_redirects", {
        FRAMEWORK_CIS: "3.3.3",
        FRAMEWORK_NIST: "SC-7",
        FRAMEWORK_STIG: "V-230544",
    }),
    ("network.log_martians", {
        FRAMEWORK_CIS: "3.3.4",
        FRAMEWORK_NIST: "AU-12",
        FRAMEWORK_STIG: "V-230545",
    }),
    ("network.icmp_ignore_broadcasts", {
        FRAMEWORK_CIS: "3.3.5",
        FRAMEWORK_NIST: "SC-5",
        FRAMEWORK_STIG: "V-230546",
    }),
    ("network.icmp_ignore_bogus", {
        FRAMEWORK_CIS: "3.3.6",
        FRAMEWORK_NIST: "SC-5",
        FRAMEWORK_STIG: "V-230547",
    }),
    ("network.rp_filter", {
        FRAMEWORK_CIS: "3.3.7",
        FRAMEWORK_NIST: "SC-7",
        FRAMEWORK_STIG: "V-230548",
        FRAMEWORK_NSA: "NET-1.5",
    }),
    ("network.tcp_syncookies", {
        FRAMEWORK_CIS: "3.3.8",
        FRAMEWORK_NIST: "SC-5",
        FRAMEWORK_STIG: "V-230549",
        FRAMEWORK_NSA: "NET-1.6",
    }),
    ("network.ipv6_disable_ra", {
        FRAMEWORK_CIS: "3.3.9",
        FRAMEWORK_NIST: "SC-7",
    }),

    # ====================================================================
    # Kernel Hardening
    # ====================================================================
    ("kernel.aslr", {
        FRAMEWORK_CIS: "1.5.3",
        FRAMEWORK_NIST: "SI-16",
        FRAMEWORK_STIG: "V-230278",
        FRAMEWORK_NSA: "KERN-1.1",
    }),
    ("kernel.kptr_restrict", {
        FRAMEWORK_NIST: "SI-16",
        FRAMEWORK_STIG: "V-230279",
        FRAMEWORK_NSA: "KERN-1.2",
    }),
    ("kernel.dmesg_restrict", {
        FRAMEWORK_NIST: "AC-3",
        FRAMEWORK_STIG: "V-230280",
        FRAMEWORK_NSA: "KERN-1.3",
    }),
    ("kernel.ptrace_scope", {
        FRAMEWORK_NIST: "AC-6",
        FRAMEWORK_NSA: "KERN-1.4",
    }),
    ("kernel.core_dumps", {
        FRAMEWORK_CIS: "1.5.1",
        FRAMEWORK_NIST: "SI-16",
        FRAMEWORK_STIG: "V-230309",
    }),
    ("kernel.module_loading_restricted", {
        FRAMEWORK_NIST: "CM-7",
        FRAMEWORK_NSA: "KERN-2.1",
    }),
    ("kernel.unprivileged_bpf", {
        FRAMEWORK_NIST: "CM-7",
        FRAMEWORK_NSA: "KERN-2.2",
    }),
    ("kernel.unprivileged_userns", {
        FRAMEWORK_NIST: "CM-7",
        FRAMEWORK_NSA: "KERN-2.3",
    }),
    ("kernel.yama_lsm", {
        FRAMEWORK_NIST: "AC-6",
        FRAMEWORK_NSA: "KERN-3.1",
    }),

    # ====================================================================
    # Boot Security
    # ====================================================================
    ("boot.grub_password", {
        FRAMEWORK_CIS: "1.4.1",
        FRAMEWORK_NIST: "AC-3",
        FRAMEWORK_STIG: "V-230234",
        FRAMEWORK_ISO27001: "A.8.1",
    }),
    ("boot.grub_permissions", {
        FRAMEWORK_CIS: "1.4.2",
        FRAMEWORK_NIST: "AC-3",
        FRAMEWORK_STIG: "V-230235",
    }),
    ("boot.single_user_auth", {
        FRAMEWORK_CIS: "1.4.3",
        FRAMEWORK_NIST: "AC-3",
        FRAMEWORK_STIG: "V-230236",
    }),
    ("boot.secure_boot", {
        FRAMEWORK_NIST: "SI-7",
        FRAMEWORK_ISO27001: "A.8.7",
        FRAMEWORK_NSA: "BOOT-1.1",
    }),

    # ====================================================================
    # Audit Logging (auditd)
    # ====================================================================
    ("audit.auditd_installed", {
        FRAMEWORK_CIS: "4.1.1.1",
        FRAMEWORK_NIST: "AU-2",
        FRAMEWORK_STIG: "V-230395",
        FRAMEWORK_ISO27001: "A.8.15",
        FRAMEWORK_PCI: "10.2.1",
        FRAMEWORK_HIPAA: "164.312(b)",
    }),
    ("audit.auditd_enabled", {
        FRAMEWORK_CIS: "4.1.1.2",
        FRAMEWORK_NIST: "AU-2",
        FRAMEWORK_STIG: "V-230410",
        FRAMEWORK_ISO27001: "A.8.15",
    }),
    ("audit.auditd_buffer_size", {
        FRAMEWORK_CIS: "4.1.1.3",
        FRAMEWORK_NIST: "AU-4",
        FRAMEWORK_STIG: "V-230411",
    }),
    ("audit.failure_action", {
        FRAMEWORK_CIS: "4.1.1.4",
        FRAMEWORK_NIST: "AU-5",
        FRAMEWORK_STIG: "V-230412",
    }),
    ("audit.log_storage_size", {
        FRAMEWORK_CIS: "4.1.2.1",
        FRAMEWORK_NIST: "AU-4",
        FRAMEWORK_STIG: "V-230401",
    }),
    ("audit.log_disk_full_action", {
        FRAMEWORK_CIS: "4.1.2.2",
        FRAMEWORK_NIST: "AU-5",
        FRAMEWORK_STIG: "V-230398",
    }),
    ("audit.identity_changes", {
        FRAMEWORK_CIS: "4.1.3.7",
        FRAMEWORK_NIST: "AU-2",
        FRAMEWORK_STIG: "V-230418",
    }),
    ("audit.system_locale_changes", {
        FRAMEWORK_CIS: "4.1.3.4",
        FRAMEWORK_NIST: "AU-2",
        FRAMEWORK_STIG: "V-230419",
    }),
    ("audit.mac_policy_changes", {
        FRAMEWORK_CIS: "4.1.3.14",
        FRAMEWORK_NIST: "AU-2",
        FRAMEWORK_STIG: "V-230420",
    }),
    ("audit.login_logout_events", {
        FRAMEWORK_CIS: "4.1.3.5",
        FRAMEWORK_NIST: "AU-2",
        FRAMEWORK_STIG: "V-230421",
        FRAMEWORK_ISO27001: "A.8.15",
        FRAMEWORK_HIPAA: "164.312(b)",
    }),
    ("audit.session_initiation", {
        FRAMEWORK_CIS: "4.1.3.6",
        FRAMEWORK_NIST: "AU-2",
        FRAMEWORK_STIG: "V-230422",
    }),
    ("audit.dac_modifications", {
        FRAMEWORK_CIS: "4.1.3.9",
        FRAMEWORK_NIST: "AU-2",
        FRAMEWORK_STIG: "V-230386",
    }),
    ("audit.unsuccessful_file_access", {
        FRAMEWORK_CIS: "4.1.3.7",
        FRAMEWORK_NIST: "AU-2",
        FRAMEWORK_STIG: "V-230423",
    }),
    ("audit.privileged_commands", {
        FRAMEWORK_CIS: "4.1.3.6",
        FRAMEWORK_NIST: "AU-2",
        FRAMEWORK_STIG: "V-230424",
        FRAMEWORK_ISO27001: "A.8.18",
    }),
    ("audit.successful_mounts", {
        FRAMEWORK_CIS: "4.1.3.8",
        FRAMEWORK_NIST: "AU-2",
        FRAMEWORK_STIG: "V-230425",
    }),
    ("audit.file_deletion", {
        FRAMEWORK_CIS: "4.1.3.13",
        FRAMEWORK_NIST: "AU-2",
        FRAMEWORK_STIG: "V-230426",
    }),
    ("audit.sudoers_changes", {
        FRAMEWORK_CIS: "4.1.3.10",
        FRAMEWORK_NIST: "AU-2",
        FRAMEWORK_STIG: "V-230427",
    }),
    ("audit.kernel_module_loading", {
        FRAMEWORK_CIS: "4.1.3.19",
        FRAMEWORK_NIST: "CM-7",
        FRAMEWORK_STIG: "V-230428",
    }),

    # ====================================================================
    # Logging (syslog/rsyslog/journald)
    # ====================================================================
    ("logging.daemon_installed", {
        FRAMEWORK_CIS: "4.2.1.1",
        FRAMEWORK_NIST: "AU-3",
        FRAMEWORK_STIG: "V-230311",
        FRAMEWORK_ISO27001: "A.8.15",
        FRAMEWORK_PCI: "10.2.1",
    }),
    ("logging.permissions", {
        FRAMEWORK_CIS: "4.2.1.4",
        FRAMEWORK_NIST: "AU-9",
        FRAMEWORK_STIG: "V-230245",
        FRAMEWORK_ISO27001: "A.8.15",
    }),
    ("logging.remote_logging", {
        FRAMEWORK_CIS: "4.2.1.5",
        FRAMEWORK_NIST: "AU-9(2)",
        FRAMEWORK_ISO27001: "A.8.15",
        FRAMEWORK_PCI: "10.5.4",
    }),
    ("logging.logrotate_configured", {
        FRAMEWORK_CIS: "4.3",
        FRAMEWORK_NIST: "AU-4",
    }),

    # ====================================================================
    # Time Synchronisation
    # ====================================================================
    ("time.ntp_configured", {
        FRAMEWORK_CIS: "2.1.1.1",
        FRAMEWORK_NIST: "AU-8(1)",
        FRAMEWORK_STIG: "V-230484",
        FRAMEWORK_ISO27001: "A.8.17",
        FRAMEWORK_PCI: "10.6",
    }),
    ("time.ntp_servers_authenticated", {
        FRAMEWORK_CIS: "2.1.1.2",
        FRAMEWORK_NIST: "AU-8(2)",
        FRAMEWORK_NSA: "TIME-1.1",
    }),

    # ====================================================================
    # Filesystem Configuration
    # ====================================================================
    ("filesystem.disable_cramfs", {
        FRAMEWORK_CIS: "1.1.1.1",
        FRAMEWORK_NIST: "CM-7",
        FRAMEWORK_STIG: "V-230497",
    }),
    ("filesystem.disable_freevxfs", {
        FRAMEWORK_CIS: "1.1.1.2",
        FRAMEWORK_NIST: "CM-7",
    }),
    ("filesystem.disable_jffs2", {
        FRAMEWORK_CIS: "1.1.1.3",
        FRAMEWORK_NIST: "CM-7",
    }),
    ("filesystem.disable_hfs", {
        FRAMEWORK_CIS: "1.1.1.4",
        FRAMEWORK_NIST: "CM-7",
    }),
    ("filesystem.disable_hfsplus", {
        FRAMEWORK_CIS: "1.1.1.5",
        FRAMEWORK_NIST: "CM-7",
    }),
    ("filesystem.disable_squashfs", {
        FRAMEWORK_CIS: "1.1.1.6",
        FRAMEWORK_NIST: "CM-7",
    }),
    ("filesystem.disable_udf", {
        FRAMEWORK_CIS: "1.1.1.7",
        FRAMEWORK_NIST: "CM-7",
    }),
    ("filesystem.disable_usb_storage", {
        FRAMEWORK_CIS: "1.1.10",
        FRAMEWORK_NIST: "MP-7",
        FRAMEWORK_STIG: "V-230498",
        FRAMEWORK_ISO27001: "A.8.10",
        FRAMEWORK_NSA: "MEDIA-1.1",
    }),
    ("filesystem.tmp_separate", {
        FRAMEWORK_CIS: "1.1.2.1",
        FRAMEWORK_NIST: "SC-39",
        FRAMEWORK_STIG: "V-230295",
    }),
    ("filesystem.tmp_nodev", {
        FRAMEWORK_CIS: "1.1.2.2",
        FRAMEWORK_NIST: "CM-7",
    }),
    ("filesystem.tmp_nosuid", {
        FRAMEWORK_CIS: "1.1.2.3",
        FRAMEWORK_NIST: "AC-6",
    }),
    ("filesystem.tmp_noexec", {
        FRAMEWORK_CIS: "1.1.2.4",
        FRAMEWORK_NIST: "CM-7",
    }),

    # ====================================================================
    # MAC (SELinux/AppArmor)
    # ====================================================================
    ("mac.framework_installed", {
        FRAMEWORK_CIS: "1.6.1.1",
        FRAMEWORK_NIST: "AC-3(4)",
        FRAMEWORK_STIG: "V-230228",
        FRAMEWORK_ISO27001: "A.8.3",
        FRAMEWORK_NSA: "MAC-1.1",
    }),
    ("mac.framework_enabled", {
        FRAMEWORK_CIS: "1.6.1.2",
        FRAMEWORK_NIST: "AC-3(4)",
        FRAMEWORK_STIG: "V-230229",
        FRAMEWORK_NSA: "MAC-1.2",
    }),
    ("mac.framework_enforcing", {
        FRAMEWORK_CIS: "1.6.1.3",
        FRAMEWORK_NIST: "AC-3(4)",
        FRAMEWORK_STIG: "V-230230",
        FRAMEWORK_NSA: "MAC-1.3",
    }),
    ("mac.no_unconfined_processes", {
        FRAMEWORK_CIS: "1.6.1.6",
        FRAMEWORK_NIST: "AC-6",
        FRAMEWORK_NSA: "MAC-1.4",
    }),

    # ====================================================================
    # Firewall
    # ====================================================================
    ("firewall.installed", {
        FRAMEWORK_CIS: "3.4.1.1",
        FRAMEWORK_NIST: "SC-7",
        FRAMEWORK_STIG: "V-230503",
        FRAMEWORK_ISO27001: "A.8.20",
        FRAMEWORK_PCI: "1.2.1",
    }),
    ("firewall.enabled", {
        FRAMEWORK_CIS: "3.4.1.2",
        FRAMEWORK_NIST: "SC-7",
        FRAMEWORK_STIG: "V-230503",
        FRAMEWORK_ISO27001: "A.8.20",
        FRAMEWORK_PCI: "1.2.1",
    }),
    ("firewall.default_deny_input", {
        FRAMEWORK_CIS: "3.4.2.1",
        FRAMEWORK_NIST: "SC-7(5)",
        FRAMEWORK_ISO27001: "A.8.20",
        FRAMEWORK_NSA: "FW-1.1",
        FRAMEWORK_PCI: "1.2.1",
    }),
    ("firewall.loopback_traffic", {
        FRAMEWORK_CIS: "3.4.2.2",
        FRAMEWORK_NIST: "SC-7",
    }),

    # ====================================================================
    # Cron
    # ====================================================================
    ("cron.daemon_enabled", {
        FRAMEWORK_CIS: "5.1.1",
        FRAMEWORK_NIST: "AC-3",
    }),
    ("cron.allow_deny_files", {
        FRAMEWORK_CIS: "5.1.8",
        FRAMEWORK_NIST: "AC-3",
        FRAMEWORK_STIG: "V-230367",
    }),

    # ====================================================================
    # Banners
    # ====================================================================
    ("banner.motd", {
        FRAMEWORK_CIS: "1.7.1",
        FRAMEWORK_NIST: "AC-8",
        FRAMEWORK_STIG: "V-230228",
        FRAMEWORK_ISO27001: "A.8.3",
    }),
    ("banner.issue", {
        FRAMEWORK_CIS: "1.7.2",
        FRAMEWORK_NIST: "AC-8",
        FRAMEWORK_STIG: "V-230228",
    }),
    ("banner.issue_net", {
        FRAMEWORK_CIS: "1.7.3",
        FRAMEWORK_NIST: "AC-8",
    }),

    # ====================================================================
    # Updates and Patching
    # ====================================================================
    ("updates.security_updates_installed", {
        FRAMEWORK_CIS: "1.9",
        FRAMEWORK_NIST: "SI-2",
        FRAMEWORK_STIG: "V-230221",
        FRAMEWORK_ISO27001: "A.8.8",
        FRAMEWORK_PCI: "6.3.3",
        FRAMEWORK_HIPAA: "164.308(a)(5)(ii)(B)",
        FRAMEWORK_CISA: "BOD-22-01",
    }),
    ("updates.gpg_check_enabled", {
        FRAMEWORK_CIS: "1.2.2",
        FRAMEWORK_NIST: "SI-7",
        FRAMEWORK_ISO27001: "A.8.19",
        FRAMEWORK_NSA: "PKG-1.1",
    }),
    ("updates.repo_gpg_keys", {
        FRAMEWORK_CIS: "1.2.1",
        FRAMEWORK_NIST: "SI-7",
        FRAMEWORK_ISO27001: "A.8.19",
    }),

    # ====================================================================
    # Encryption / Cryptography
    # ====================================================================
    ("crypto.fips_mode", {
        FRAMEWORK_NIST: "SC-13",
        FRAMEWORK_STIG: "V-230223",
        FRAMEWORK_ISO27001: "A.8.24",
        FRAMEWORK_NSA: "CRYPTO-1.1",
        FRAMEWORK_PCI: "4.2.1",
    }),
    ("crypto.tls_minimum_version", {
        FRAMEWORK_NIST: "SC-8",
        FRAMEWORK_ISO27001: "A.8.24",
        FRAMEWORK_PCI: "4.2.1",
        FRAMEWORK_HIPAA: "164.312(e)(1)",
    }),
    ("crypto.system_wide_policy", {
        FRAMEWORK_CIS: "1.10",
        FRAMEWORK_NIST: "SC-13",
        FRAMEWORK_ISO27001: "A.8.24",
    }),

    # ====================================================================
    # Service Hardening
    # ====================================================================
    ("services.disable_telnet", {
        FRAMEWORK_CIS: "2.2.16",
        FRAMEWORK_NIST: "CM-7",
        FRAMEWORK_STIG: "V-230557",
    }),
    ("services.disable_rsh", {
        FRAMEWORK_CIS: "2.3.2",
        FRAMEWORK_NIST: "CM-7",
        FRAMEWORK_STIG: "V-230558",
    }),
    ("services.disable_xinetd", {
        FRAMEWORK_CIS: "2.1.1",
        FRAMEWORK_NIST: "CM-7",
    }),
    ("services.disable_avahi", {
        FRAMEWORK_CIS: "2.2.3",
        FRAMEWORK_NIST: "CM-7",
    }),
    ("services.disable_cups", {
        FRAMEWORK_CIS: "2.2.4",
        FRAMEWORK_NIST: "CM-7",
    }),
    ("services.disable_dhcp", {
        FRAMEWORK_CIS: "2.2.5",
        FRAMEWORK_NIST: "CM-7",
    }),
    ("services.disable_x_window", {
        FRAMEWORK_CIS: "2.2.2",
        FRAMEWORK_NIST: "CM-7",
        FRAMEWORK_STIG: "V-230559",
    }),

    # ====================================================================
    # Process Hardening
    # ====================================================================
    ("process.prelink_disabled", {
        FRAMEWORK_CIS: "1.5.4",
        FRAMEWORK_NIST: "SI-7",
        FRAMEWORK_STIG: "V-230484",
    }),
    ("process.no_world_writable_files", {
        FRAMEWORK_CIS: "6.1.10",
        FRAMEWORK_NIST: "AC-3",
        FRAMEWORK_STIG: "V-230311",
    }),
    ("process.no_unowned_files", {
        FRAMEWORK_CIS: "6.1.11",
        FRAMEWORK_NIST: "AC-3",
        FRAMEWORK_STIG: "V-230320",
    }),
    ("process.suid_audit", {
        FRAMEWORK_CIS: "6.1.12",
        FRAMEWORK_NIST: "AC-6(8)",
        FRAMEWORK_STIG: "V-230364",
    }),

    # ====================================================================
    # Sudo
    # ====================================================================
    ("sudo.installed", {
        FRAMEWORK_CIS: "5.5.1",
        FRAMEWORK_NIST: "AC-6",
    }),
    ("sudo.use_pty", {
        FRAMEWORK_CIS: "5.5.2",
        FRAMEWORK_NIST: "AC-6",
        FRAMEWORK_STIG: "V-230331",
    }),
    ("sudo.log_file", {
        FRAMEWORK_CIS: "5.5.3",
        FRAMEWORK_NIST: "AU-12",
        FRAMEWORK_STIG: "V-230332",
        FRAMEWORK_ISO27001: "A.8.18",
    }),
    ("sudo.no_nopasswd", {
        FRAMEWORK_CIS: "5.5.4",
        FRAMEWORK_NIST: "IA-2",
        FRAMEWORK_STIG: "V-230363",
    }),
    ("sudo.timeout", {
        FRAMEWORK_CIS: "5.5.5",
        FRAMEWORK_NIST: "AC-12",
    }),

    # ====================================================================
    # PCI DSS v4.0.1 Specific Topics
    # ====================================================================
    ("pci.network_segmentation", {
        FRAMEWORK_PCI: "1.2.1",
        FRAMEWORK_NIST: "SC-7",
        FRAMEWORK_ISO27001: "A.8.22",
        FRAMEWORK_HIPAA: "164.312(e)(1)",
    }),
    ("pci.dmz_for_public_services", {
        FRAMEWORK_PCI: "1.3.2",
        FRAMEWORK_NIST: "SC-7(13)",
        FRAMEWORK_ISO27001: "A.8.22",
    }),
    ("pci.outbound_traffic_restrictions", {
        FRAMEWORK_PCI: "1.3.3",
        FRAMEWORK_NIST: "AC-4",
        FRAMEWORK_ISO27001: "A.8.20",
    }),
    ("pci.no_default_passwords", {
        FRAMEWORK_PCI: "2.2.2",
        FRAMEWORK_NIST: "IA-5(1)",
        FRAMEWORK_CIS: "5.4.2.1",
        FRAMEWORK_HIPAA: "164.308(a)(5)(ii)(D)",
        FRAMEWORK_CISA: "CPG-1.A",
    }),
    ("pci.system_hardening_standards", {
        FRAMEWORK_PCI: "2.2.1",
        FRAMEWORK_NIST: "CM-6",
        FRAMEWORK_ISO27001: "A.8.9",
    }),
    ("pci.disable_unnecessary_services", {
        FRAMEWORK_PCI: "2.2.4",
        FRAMEWORK_NIST: "CM-7",
        FRAMEWORK_CIS: "2.2.1",
        FRAMEWORK_STIG: "V-230559",
    }),
    ("pci.unique_user_ids", {
        FRAMEWORK_PCI: "8.2.1",
        FRAMEWORK_NIST: "IA-2",
        FRAMEWORK_HIPAA: "164.312(a)(2)(i)",
        FRAMEWORK_ISO27001: "A.8.5",
        FRAMEWORK_SOC2: "CC6.1",
    }),
    ("pci.account_lockout_15min", {
        FRAMEWORK_PCI: "8.3.4",
        FRAMEWORK_NIST: "AC-7",
        FRAMEWORK_CIS: "5.3.1",
        FRAMEWORK_HIPAA: "164.308(a)(5)(ii)(D)",
        FRAMEWORK_STIG: "V-230333",
    }),
    ("pci.session_idle_15min", {
        FRAMEWORK_PCI: "8.2.8",
        FRAMEWORK_NIST: "AC-12",
        FRAMEWORK_CIS: "5.4.4",
        FRAMEWORK_HIPAA: "164.312(a)(2)(iii)",
        FRAMEWORK_STIG: "V-230363",
    }),
    ("pci.password_min_12_chars", {
        FRAMEWORK_PCI: "8.3.6",
        FRAMEWORK_NIST: "IA-5(1)",
        FRAMEWORK_CIS: "5.4.1.1",
        FRAMEWORK_HIPAA: "164.308(a)(5)(ii)(D)",
        FRAMEWORK_SOC2: "CC6.1",
    }),
    ("pci.encrypt_payment_data_transit", {
        FRAMEWORK_PCI: "4.2.1",
        FRAMEWORK_NIST: "SC-8",
        FRAMEWORK_ISO27001: "A.8.24",
        FRAMEWORK_HIPAA: "164.312(e)(1)",
        FRAMEWORK_GDPR: "Art-32",
        FRAMEWORK_NSA: "CRYPTO-1.1",
    }),
    ("pci.tls_v1_2_minimum", {
        FRAMEWORK_PCI: "4.2.1",
        FRAMEWORK_NIST: "SC-8(1)",
        FRAMEWORK_ISO27001: "A.8.24",
        FRAMEWORK_NSA: "CRYPTO-2.1",
    }),
    ("pci.deploy_av_software", {
        FRAMEWORK_PCI: "5.2.1",
        FRAMEWORK_NIST: "SI-3",
        FRAMEWORK_ISO27001: "A.8.7",
        FRAMEWORK_HIPAA: "164.308(a)(5)(ii)(B)",
    }),
    ("pci.security_patches_30day", {
        FRAMEWORK_PCI: "6.3.3",
        FRAMEWORK_NIST: "SI-2(2)",
        FRAMEWORK_ISO27001: "A.8.8",
        FRAMEWORK_HIPAA: "164.308(a)(5)(ii)(B)",
        FRAMEWORK_CISA: "BOD-22-01",
    }),
    ("pci.fim_critical_files", {
        FRAMEWORK_PCI: "11.5.2",
        FRAMEWORK_NIST: "SI-7",
        FRAMEWORK_ISO27001: "A.8.16",
        FRAMEWORK_HIPAA: "164.312(c)(1)",
    }),
    ("pci.audit_log_review_daily", {
        FRAMEWORK_PCI: "10.4.1",
        FRAMEWORK_NIST: "AU-6",
        FRAMEWORK_ISO27001: "A.8.16",
        FRAMEWORK_HIPAA: "164.308(a)(1)(ii)(D)",
    }),
    ("pci.audit_logs_centralized", {
        FRAMEWORK_PCI: "10.5.4",
        FRAMEWORK_NIST: "AU-6(3)",
        FRAMEWORK_CIS: "4.2.1.5",
        FRAMEWORK_ISO27001: "A.8.15",
    }),
    ("pci.audit_log_retention_12mo", {
        FRAMEWORK_PCI: "10.5.1",
        FRAMEWORK_NIST: "AU-11",
        FRAMEWORK_ISO27001: "A.8.15",
        FRAMEWORK_HIPAA: "164.530(j)",
    }),
    ("pci.intrusion_detection_active", {
        FRAMEWORK_PCI: "11.5.1",
        FRAMEWORK_NIST: "SI-4",
        FRAMEWORK_ISO27001: "A.8.16",
        FRAMEWORK_NSA: "DETECT-1.1",
    }),
    ("pci.no_clear_text_pan_storage", {
        FRAMEWORK_PCI: "3.5.1",
        FRAMEWORK_NIST: "SC-28",
        FRAMEWORK_GDPR: "Art-32",
        FRAMEWORK_ISO27001: "A.8.10",
    }),
    ("pci.encryption_key_rotation", {
        FRAMEWORK_PCI: "3.6.4",
        FRAMEWORK_NIST: "SC-12",
        FRAMEWORK_ISO27001: "A.8.24",
        FRAMEWORK_NSA: "CRYPTO-3.1",
    }),
    ("pci.access_least_privilege", {
        FRAMEWORK_PCI: "7.2.1",
        FRAMEWORK_NIST: "AC-6",
        FRAMEWORK_ISO27001: "A.8.2",
        FRAMEWORK_HIPAA: "164.308(a)(4)(ii)(B)",
        FRAMEWORK_SOC2: "CC6.1",
    }),
    ("pci.access_default_deny", {
        FRAMEWORK_PCI: "7.2.5",
        FRAMEWORK_NIST: "AC-3",
        FRAMEWORK_ISO27001: "A.8.3",
    }),

]


# ----------------------------------------------------------------------
# Index construction. Built once at module import. The forward index maps
# topic -> correlations dict; the reverse index maps (framework, control_id)
# -> topic for finding related findings during result correlation.
# ----------------------------------------------------------------------

_topic_index: Dict[str, Dict[str, str]] = {}
_reverse_index: Dict[Tuple[str, str], str] = {}
_index_lock = threading.Lock()


def _build_indexes() -> None:
    global _topic_index, _reverse_index
    forward: Dict[str, Dict[str, str]] = {}
    reverse: Dict[Tuple[str, str], str] = {}
    duplicates: List[str] = []

    for topic, correlations in _REGISTRY:
        if topic in forward:
            duplicates.append(topic)
            continue
        forward[topic] = dict(correlations)
        for framework, control_id in correlations.items():
            key = (framework, control_id)
            # First occurrence wins for the reverse map; collisions are
            # logged but not fatal because some frameworks reuse control
            # IDs across loosely related topics.
            if key not in reverse:
                reverse[key] = topic

    if duplicates:
        logger.warning(
            "Duplicate correlation topics ignored: %s", ", ".join(duplicates)
        )

    with _index_lock:
        _topic_index = forward
        _reverse_index = reverse


_build_indexes()


def get_correlations(topic: str) -> Dict[str, str]:
    """Return the cross-framework correlations for a topic.

    Returns an empty dict if the topic is not in the registry. The returned
    dict is a copy; mutation does not affect the registry.
    """
    if not topic:
        return {}
    with _index_lock:
        entry = _topic_index.get(topic)
    return dict(entry) if entry else {}


def get_topic_for(framework: str, control_id: str) -> Optional[str]:
    """Return the topic that includes the given framework/control_id pair.

    Returns None if no correlation record references that control. Useful
    for finding related findings when a check identifies a violation by
    framework-specific control ID.
    """
    if not framework or not control_id:
        return None
    with _index_lock:
        return _reverse_index.get((framework, control_id))


def list_topics() -> List[str]:
    """List all registered topics in registration order."""
    with _index_lock:
        return [t for t, _ in _REGISTRY]


def list_frameworks() -> List[str]:
    """List all framework codes that appear in at least one correlation."""
    seen = set()
    with _index_lock:
        for _, refs in _REGISTRY:
            seen.update(refs.keys())
    return sorted(seen)


def register_correlation(topic: str, correlations: Dict[str, str]) -> bool:
    """Append a new correlation record at runtime.

    Used by modules to extend the registry with module-specific topics
    that aren't part of the built-in core set. Returns True if the topic
    was new and was added, False if a topic with that name already exists
    (in which case the existing entry is preserved).
    """
    if not topic or not isinstance(correlations, dict):
        return False
    with _index_lock:
        if topic in _topic_index:
            return False
        _REGISTRY.append((topic, dict(correlations)))
    _build_indexes()
    return True


def enrich(result_cross_references: Dict[str, str], topic: str) -> Dict[str, str]:
    """Merge registry correlations into a result's cross_references.

    Module-supplied references take precedence: if a module already
    populated CIS=5.2.7, the registry's value will not overwrite it.
    Used by the orchestrator's enrichment pass after collecting results.
    """
    enriched = dict(result_cross_references) if result_cross_references else {}
    registry_entries = get_correlations(topic)
    for framework, control_id in registry_entries.items():
        enriched.setdefault(framework, control_id)
    return enriched


def registry_size() -> int:
    """Return the number of correlation topics currently registered."""
    with _index_lock:
        return len(_topic_index)
