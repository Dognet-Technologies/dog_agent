"""
remediation_bundles.py - Predefined groups of related remediations.

SYNOPSIS
    Bundles let an operator apply a coherent set of related security
    fixes in a single command rather than approving 150+ individual
    remediations interactively. Each bundle has a documented impact
    profile so the operator knows what services may be affected.

DESCRIPTION
    A bundle is a logical grouping of correlation topics from the
    correlation_registry. The orchestrator resolves a bundle name to its
    member topics, then to the specific findings in the current audit
    that match those topics, and applies their remediations.

    Bundles do not duplicate remediation logic; they are pure metadata
    describing which existing checks belong together. This keeps the
    bundle definitions small and stable while remediation content lives
    where it belongs - in the modules.

    The eight built-in bundles cover the most common hardening goals
    that operators ask for by name:

        HardenSSH               - Comprehensive SSH daemon hardening
        DisableLegacyProtocols  - Remove telnet/rsh/rexec/rlogin/FTP/TFTP
        HardenKernel            - sysctl kernel parameter tuning
        EnableAuditLogging      - Full auditd ruleset
        HardenAuthentication    - PAM + password policy
        LockDownNetwork         - Firewall + service binding restrictions
        SecureBootChain         - GRUB + Secure Boot validation
        HardenSystemd           - Per-service security directives

PARAMETERS
    Public API:
        list_bundles() -> List[str]
        get_bundle(name) -> Optional[Bundle]
        resolve_bundle(name) -> List[str]   # returns correlation topics
        bundle_impact(name) -> ImpactProfile

EXAMPLES
    >>> from shared_components.remediation_bundles import get_bundle
    >>> bundle = get_bundle("HardenSSH")
    >>> bundle.description
    'SSH daemon hardening: protocol, ciphers, MACs, KEX, ...'
    >>> bundle.included_topics
    ['ssh.permit_root_login', 'ssh.protocol_version', ...]

NOTES
    Version: 3.0
    Stdlib only.
    Bundle definitions are deliberately conservative: each bundle's
    member topics are limited to changes whose interactions are
    well-understood and which can be applied together without leaving
    the system in a half-configured state.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("audit.remediation")


# Impact level constants. Used to communicate to the operator what kind
# of disruption applying a bundle may cause.

IMPACT_NONE = "None"
IMPACT_RESTART_SERVICE = "RestartService"
IMPACT_BREAK_SESSIONS = "BreakSessions"
IMPACT_REQUIRE_REBOOT = "RequireReboot"
IMPACT_BREAK_NETWORK = "BreakNetwork"
IMPACT_BREAK_BOOT = "BreakBoot"


@dataclass
class ImpactProfile:
    """Description of what applying a bundle will affect.

    Fields:
        levels: List of impact levels (e.g. RestartService, RequireReboot)
        affected_services: List of systemd unit names that may restart
        reboot_required: True if at least one change needs a reboot to
            take effect (e.g. some sysctl changes that touch early-boot
            initramfs settings)
        ssh_continuity_risk: True if applying the bundle could disconnect
            the operator's SSH session - applies to bundles that change
            sshd_config or firewall rules
        rollback_supported: True if rollback_generator can produce an
            inverse script for this bundle's changes
    """

    levels: List[str] = field(default_factory=list)
    affected_services: List[str] = field(default_factory=list)
    reboot_required: bool = False
    ssh_continuity_risk: bool = False
    rollback_supported: bool = True

    def to_dict(self) -> Dict[str, object]:
        return {
            "levels": list(self.levels),
            "affected_services": list(self.affected_services),
            "reboot_required": self.reboot_required,
            "ssh_continuity_risk": self.ssh_continuity_risk,
            "rollback_supported": self.rollback_supported,
        }


@dataclass
class Bundle:
    """A named group of related remediation topics.

    Fields:
        name: Bundle identifier used on the command line (CamelCase)
        display_name: Human-readable name for reports
        description: One-paragraph explanation of what the bundle does
        included_topics: Correlation registry topic names that belong to
            this bundle
        prerequisites: Other bundles or checks that should be applied
            first; informational only
        impact: ImpactProfile describing operational risk
    """

    name: str
    display_name: str
    description: str
    included_topics: List[str]
    prerequisites: List[str] = field(default_factory=list)
    impact: ImpactProfile = field(default_factory=ImpactProfile)

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "included_topics": list(self.included_topics),
            "prerequisites": list(self.prerequisites),
            "impact": self.impact.to_dict(),
        }


# --------------------------------------------------------------------------
# Built-in bundles
# --------------------------------------------------------------------------

_HARDEN_SSH = Bundle(
    name="HardenSSH",
    display_name="SSH Daemon Hardening",
    description=(
        "Comprehensive OpenSSH server hardening: disable root login, "
        "enforce protocol 2, restrict authentication retries, configure "
        "strong ciphers/MACs/KEX algorithms, enable login banners, set "
        "session timeouts, and remove host-based authentication. Does "
        "not modify authorized_keys or change the listen address."
    ),
    included_topics=[
        "ssh.permit_root_login",
        "ssh.protocol_version",
        "ssh.x11_forwarding",
        "ssh.max_auth_tries",
        "ssh.empty_passwords",
        "ssh.client_alive_interval",
        "ssh.login_grace_time",
        "ssh.banner",
        "ssh.ciphers",
        "ssh.macs",
        "ssh.kex_algorithms",
        "ssh.host_based_auth",
        "ssh.permit_user_environment",
        "ssh.ignore_rhosts",
    ],
    impact=ImpactProfile(
        levels=[IMPACT_RESTART_SERVICE],
        affected_services=["sshd", "ssh"],
        reboot_required=False,
        ssh_continuity_risk=True,
        rollback_supported=True,
    ),
)

_DISABLE_LEGACY_PROTOCOLS = Bundle(
    name="DisableLegacyProtocols",
    display_name="Legacy Protocol Removal",
    description=(
        "Disable and remove insecure legacy network services that "
        "transmit credentials in cleartext or have known design flaws: "
        "telnet, rsh, rlogin, rexec, FTP (anonymous and authenticated), "
        "TFTP, and finger. Both client and server components are removed "
        "where present."
    ),
    included_topics=[
        "services.disable_telnet",
        "services.disable_rsh",
        "services.disable_xinetd",
    ],
    impact=ImpactProfile(
        levels=[IMPACT_RESTART_SERVICE],
        affected_services=[
            "telnet.socket", "telnetd.service", "rsh.socket",
            "rlogin.socket", "rexec.socket", "vsftpd.service",
            "tftpd.socket", "tftpd-hpa.service", "fingerd.socket",
        ],
        reboot_required=False,
        ssh_continuity_risk=False,
        rollback_supported=True,
    ),
)

_HARDEN_KERNEL = Bundle(
    name="HardenKernel",
    display_name="Kernel Parameter Hardening",
    description=(
        "Apply security-focused sysctl tuning: enable ASLR, restrict "
        "kernel pointer exposure (kptr_restrict), restrict dmesg, set "
        "ptrace scope, disable core dumps for SUID binaries, harden "
        "network stack (TCP SYN cookies, reverse path filtering, ICMP "
        "redirect handling), and disable unprivileged BPF. Settings are "
        "written to /etc/sysctl.d/99-hardening.conf and applied immediately."
    ),
    included_topics=[
        "kernel.aslr",
        "kernel.kptr_restrict",
        "kernel.dmesg_restrict",
        "kernel.ptrace_scope",
        "kernel.core_dumps",
        "kernel.unprivileged_bpf",
        "kernel.unprivileged_userns",
        "kernel.yama_lsm",
        "network.ip_forward",
        "network.send_redirects",
        "network.accept_source_route",
        "network.accept_redirects",
        "network.secure_redirects",
        "network.log_martians",
        "network.icmp_ignore_broadcasts",
        "network.icmp_ignore_bogus",
        "network.rp_filter",
        "network.tcp_syncookies",
    ],
    impact=ImpactProfile(
        levels=[IMPACT_RESTART_SERVICE],
        affected_services=["systemd-sysctl.service"],
        reboot_required=False,
        ssh_continuity_risk=False,
        rollback_supported=True,
    ),
)

_ENABLE_AUDIT_LOGGING = Bundle(
    name="EnableAuditLogging",
    display_name="Audit Logging Enablement",
    description=(
        "Install and enable auditd with a comprehensive rule set covering "
        "identity changes (passwd/shadow/group), DAC modifications, "
        "privileged command execution, mount operations, sudoers changes, "
        "kernel module loading/unloading, login/logout events, session "
        "initiation, and critical file access. Configures auditd to "
        "preserve logs across reboots and rotate at appropriate sizes."
    ),
    included_topics=[
        "audit.auditd_installed",
        "audit.auditd_enabled",
        "audit.auditd_buffer_size",
        "audit.failure_action",
        "audit.log_storage_size",
        "audit.log_disk_full_action",
        "audit.identity_changes",
        "audit.system_locale_changes",
        "audit.mac_policy_changes",
        "audit.login_logout_events",
        "audit.session_initiation",
        "audit.dac_modifications",
        "audit.unsuccessful_file_access",
        "audit.privileged_commands",
        "audit.successful_mounts",
        "audit.file_deletion",
        "audit.sudoers_changes",
        "audit.kernel_module_loading",
    ],
    prerequisites=["HardenKernel"],
    impact=ImpactProfile(
        levels=[IMPACT_RESTART_SERVICE],
        affected_services=["auditd.service"],
        reboot_required=True,
        ssh_continuity_risk=False,
        rollback_supported=True,
    ),
)

_HARDEN_AUTHENTICATION = Bundle(
    name="HardenAuthentication",
    display_name="Authentication Hardening",
    description=(
        "Strengthen password policy and PAM configuration: minimum "
        "password length 14, complexity requirements (pam_pwquality), "
        "password history of 24, lockout after 5 failed attempts, "
        "lockout duration 900 seconds, SHA-512 password hashing, "
        "password aging (90-day max, 1-day min, 7-day warn). Disables "
        "empty-password authentication and removes legacy MD5/DES "
        "password hashes."
    ),
    included_topics=[
        "password.minimum_length",
        "password.complexity",
        "password.history",
        "password.max_days",
        "password.min_days",
        "password.warn_age",
        "password.hash_algorithm",
        "password.lockout_attempts",
        "password.lockout_time",
        "account.no_empty_passwords",
        "account.shadow_passwords",
        "account.inactive_lock",
    ],
    impact=ImpactProfile(
        levels=[IMPACT_NONE],
        affected_services=[],
        reboot_required=False,
        ssh_continuity_risk=False,
        rollback_supported=True,
    ),
)

_LOCK_DOWN_NETWORK = Bundle(
    name="LockDownNetwork",
    display_name="Network Lockdown",
    description=(
        "Enable the host firewall with default-deny inbound policy, "
        "permit only loopback and established/related connections, "
        "block uncommon protocols (DCCP, SCTP, RDS, TIPC) at module "
        "load, and disable IPv6 router advertisement acceptance where "
        "not required. Existing administrative SSH sessions are "
        "preserved. Compatible with iptables, nftables, ufw, and "
        "firewalld depending on which is active on the system."
    ),
    included_topics=[
        "firewall.installed",
        "firewall.enabled",
        "firewall.default_deny_input",
        "firewall.loopback_traffic",
        "network.ipv6_disable_ra",
    ],
    prerequisites=["HardenSSH"],
    impact=ImpactProfile(
        levels=[IMPACT_RESTART_SERVICE, IMPACT_BREAK_NETWORK],
        affected_services=[
            "iptables.service", "ip6tables.service", "nftables.service",
            "firewalld.service", "ufw.service",
        ],
        reboot_required=False,
        ssh_continuity_risk=True,
        rollback_supported=True,
    ),
)

_SECURE_BOOT_CHAIN = Bundle(
    name="SecureBootChain",
    display_name="Boot Chain Security",
    description=(
        "Validate and harden the boot chain: GRUB bootloader password, "
        "GRUB configuration file permissions (root-only read), "
        "single-user mode authentication, and reporting of UEFI Secure "
        "Boot status. Does not modify Secure Boot configuration "
        "directly because that requires BIOS/UEFI firmware access."
    ),
    included_topics=[
        "boot.grub_password",
        "boot.grub_permissions",
        "boot.single_user_auth",
    ],
    impact=ImpactProfile(
        levels=[IMPACT_REQUIRE_REBOOT, IMPACT_BREAK_BOOT],
        affected_services=[],
        reboot_required=True,
        ssh_continuity_risk=False,
        rollback_supported=True,
    ),
)

_HARDEN_SYSTEMD = Bundle(
    name="HardenSystemd",
    display_name="systemd Service Hardening",
    description=(
        "Apply systemd security directives to commonly-targeted services: "
        "PrivateTmp, ProtectSystem=strict, ProtectHome=read-only, "
        "NoNewPrivileges, RestrictSUIDSGID, RestrictNamespaces, and "
        "SystemCallFilter where supported by the systemd version on this "
        "host. Drop-in unit overrides are written to /etc/systemd/system/ "
        "rather than modifying vendor unit files."
    ),
    included_topics=[
        # Per-service hardening topics are populated by the systemd
        # module checks; the bundle resolution layer expands these to the
        # specific findings present in the current audit.
        "services.disable_avahi",
        "services.disable_cups",
        "services.disable_x_window",
    ],
    impact=ImpactProfile(
        levels=[IMPACT_RESTART_SERVICE],
        affected_services=["systemd"],  # generic; resolution adds specific units
        reboot_required=False,
        ssh_continuity_risk=False,
        rollback_supported=True,
    ),
)


_BUILTIN_BUNDLES: Dict[str, Bundle] = {
    b.name: b for b in (
        _HARDEN_SSH,
        _DISABLE_LEGACY_PROTOCOLS,
        _HARDEN_KERNEL,
        _ENABLE_AUDIT_LOGGING,
        _HARDEN_AUTHENTICATION,
        _LOCK_DOWN_NETWORK,
        _SECURE_BOOT_CHAIN,
        _HARDEN_SYSTEMD,
    )
}


_registry_lock = threading.Lock()
_extended_bundles: Dict[str, Bundle] = {}


def list_bundles() -> List[str]:
    """Return the names of all registered bundles in sorted order."""
    with _registry_lock:
        names = set(_BUILTIN_BUNDLES) | set(_extended_bundles)
    return sorted(names)


def get_bundle(name: str) -> Optional[Bundle]:
    """Look up a bundle by name. Returns None if unknown.

    Lookup is case-insensitive against the canonical CamelCase names.
    """
    if not name:
        return None
    target = name.strip()

    with _registry_lock:
        # Exact match first
        bundle = _BUILTIN_BUNDLES.get(target) or _extended_bundles.get(target)
        if bundle is not None:
            return bundle

        # Case-insensitive fallback
        lower = target.lower()
        for n, b in _BUILTIN_BUNDLES.items():
            if n.lower() == lower:
                return b
        for n, b in _extended_bundles.items():
            if n.lower() == lower:
                return b
    return None


def resolve_bundle(name: str) -> List[str]:
    """Resolve a bundle name to the list of correlation topic names.

    Returns an empty list for unknown bundles. The result is a copy of
    the bundle's included_topics field; mutation does not affect the
    bundle definition.
    """
    bundle = get_bundle(name)
    if bundle is None:
        return []
    return list(bundle.included_topics)


def bundle_impact(name: str) -> Optional[ImpactProfile]:
    """Return the impact profile for the named bundle, or None."""
    bundle = get_bundle(name)
    return bundle.impact if bundle else None


def register_bundle(bundle: Bundle) -> bool:
    """Register a custom bundle at runtime.

    Returns True if the bundle was added, False if a bundle of the same
    name already exists. Built-in bundles cannot be replaced.
    """
    if not isinstance(bundle, Bundle):
        return False
    with _registry_lock:
        if bundle.name in _BUILTIN_BUNDLES or bundle.name in _extended_bundles:
            return False
        _extended_bundles[bundle.name] = bundle
    return True


def all_bundles() -> List[Bundle]:
    """Return every registered bundle as a list."""
    with _registry_lock:
        out = list(_BUILTIN_BUNDLES.values())
        out.extend(_extended_bundles.values())
    return out


def format_bundle_summary(bundle: Bundle) -> str:
    """Render a bundle for console display.

    Multi-line text suitable for inclusion in --help-bundles output.
    """
    lines: List[str] = []
    lines.append(f"  {bundle.name}")
    lines.append(f"    {bundle.display_name}")
    lines.append("")
    desc_words = bundle.description.split()
    line_buf = "    "
    for word in desc_words:
        if len(line_buf) + len(word) + 1 > 76:
            lines.append(line_buf.rstrip())
            line_buf = "    " + word + " "
        else:
            line_buf += word + " "
    if line_buf.strip():
        lines.append(line_buf.rstrip())
    lines.append("")
    lines.append(f"    Topics: {len(bundle.included_topics)}")
    if bundle.prerequisites:
        lines.append(f"    Prerequisites: {', '.join(bundle.prerequisites)}")
    lines.append(f"    Impact: {', '.join(bundle.impact.levels) or 'minimal'}")
    if bundle.impact.ssh_continuity_risk:
        lines.append("    *** SSH SESSION CONTINUITY RISK ***")
    if bundle.impact.reboot_required:
        lines.append("    *** REBOOT REQUIRED FOR FULL EFFECT ***")
    return "\n".join(lines)
