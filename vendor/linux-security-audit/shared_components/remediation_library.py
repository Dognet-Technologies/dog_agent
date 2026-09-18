"""
remediation_library.py - Comprehensive distro-aware remediation guidance.

SYNOPSIS
    Centralized remediation library that produces distribution-appropriate,
    multi-step remediation guidance for every common Linux security tool
    referenced by the audit modules. Replaces ad-hoc "Install X" one-liner
    remediations with complete guidance: required packages, supporting
    packages, configuration steps, service enable/start commands, and
    verification commands.

DESCRIPTION
    Modules call `get_remediation(tool_id, os_info)` to obtain a rich,
    multi-line remediation string tailored to the detected distribution.
    The library understands four distribution families:
      - Debian (Debian, Ubuntu, Mint, Pop!_OS, Kali, Parrot)
      - RedHat (RHEL, CentOS Stream, Rocky, AlmaLinux, Oracle, Fedora,
        Amazon Linux)
      - SUSE (openSUSE Leap, openSUSE Tumbleweed, SLES)
      - Arch (Arch, Manjaro, EndeavourOS)
      - Alpine (Alpine Linux)

    Each entry encodes distro-specific package names where they differ
    (e.g. AIDE on Debian needs both `aide` AND `aide-common` for the
    update wrapper to function correctly; on RHEL it ships as a single
    `aide` RPM).

PARAMETERS
    get_remediation(tool_id, os_info=None, *, include_verify=True,
                    include_supporting=True)
        tool_id              : str, key into the library
        os_info              : optional OSInfo; if omitted, uses live
                               detection
        include_verify       : append verification commands (default True)
        include_supporting   : install supporting packages (default True)

EXAMPLES
    Basic usage from a check function:
        from shared_components.remediation_library import get_remediation
        results.append(_r(
            cat, "Fail",
            "AIDE not installed",
            severity="High",
            remediation=get_remediation("aide", os_info),
            ...
        ))

    Tool not in library: returns None so caller can fall back to its own
    remediation string. Caller pattern:
        rem = get_remediation("toolx", os_info) or "Install toolx"

NOTES
    Version: 1.1 (v3.5 expanded)
    Stdlib only. No subprocess calls, no I/O.
    All commands assume root or sudo prefix. The library does not insert
    `sudo` because modules typically pre-check for root and the audit
    docs guide the operator to run remediation interactively.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ----------------------------------------------------------------------------
# Family constants matching shared_components.os_detection
# ----------------------------------------------------------------------------

FAMILY_DEBIAN = "Debian"
FAMILY_REDHAT = "RedHat"
FAMILY_SUSE = "SUSE"
FAMILY_ARCH = "Arch"
FAMILY_ALPINE = "Alpine"
FAMILY_GENTOO = "Gentoo"
FAMILY_UNKNOWN = "Unknown"

ALL_FAMILIES = (
    FAMILY_DEBIAN, FAMILY_REDHAT, FAMILY_SUSE,
    FAMILY_ARCH, FAMILY_ALPINE, FAMILY_GENTOO,
)


# ----------------------------------------------------------------------------
# RemediationEntry dataclass
# ----------------------------------------------------------------------------

@dataclass
class RemediationEntry:
    """Structured remediation for a security tool / capability.

    Fields:
        tool_id            : Stable identifier (e.g. "aide", "fail2ban").
        display_name       : Human-readable name shown in remediation text.
        purpose            : One-line description of what this provides.
        primary_packages   : Per-family dict; minimum packages required to
                             obtain the tool's binary on each family.
        supporting_packages: Per-family dict; additional packages that the
                             tool requires for full functionality (e.g.
                             aide-common on Debian provides
                             /usr/sbin/aideinit and update wrappers).
        post_install       : Per-family dict; ordered list of post-install
                             configuration commands (init scripts, db
                             generation, profile generation, etc.).
        services           : Ordered list of systemd unit names to enable
                             and start, e.g. ["fail2ban.service"].
                             Empty if the tool is not service-based.
        verify             : Per-family dict; verification commands the
                             operator can run to confirm successful
                             installation/configuration.
        config_files       : List of config file paths the operator should
                             review/edit. Used for documentation only.
        notes              : Free-form notes (caveats, ordering
                             requirements, distribution quirks).
        references         : Authoritative documentation URLs for the
                             tool. Used for the "see also" line.
    """

    tool_id: str
    display_name: str
    purpose: str = ""
    primary_packages: Dict[str, List[str]] = field(default_factory=dict)
    supporting_packages: Dict[str, List[str]] = field(default_factory=dict)
    post_install: Dict[str, List[str]] = field(default_factory=dict)
    services: List[str] = field(default_factory=list)
    verify: Dict[str, List[str]] = field(default_factory=dict)
    config_files: List[str] = field(default_factory=list)
    notes: str = ""
    references: List[str] = field(default_factory=list)


# ----------------------------------------------------------------------------
# Family-specific package manager templates
# ----------------------------------------------------------------------------

_PKG_INSTALL_CMD: Dict[str, str] = {
    FAMILY_DEBIAN: "apt-get install -y {pkgs}",
    FAMILY_REDHAT: "dnf install -y {pkgs}",
    FAMILY_SUSE: "zypper install -y {pkgs}",
    FAMILY_ARCH: "pacman -S --noconfirm {pkgs}",
    FAMILY_ALPINE: "apk add {pkgs}",
    FAMILY_GENTOO: "emerge {pkgs}",
}

_PKG_UPDATE_CMD: Dict[str, str] = {
    FAMILY_DEBIAN: "apt-get update",
    FAMILY_REDHAT: "dnf check-update || true",
    FAMILY_SUSE: "zypper refresh",
    FAMILY_ARCH: "pacman -Sy",
    FAMILY_ALPINE: "apk update",
    FAMILY_GENTOO: "emerge --sync",
}

# v3.7.1: OS-aware package REMOVAL command templates. Mirrors install
# templates. Used by get_removal_remediation() to emit the correct purge
# command for the detected distribution family.
_PKG_REMOVE_CMD: Dict[str, str] = {
    FAMILY_DEBIAN: "apt-get purge -y {pkgs}",
    FAMILY_REDHAT: "dnf remove -y {pkgs}",
    FAMILY_SUSE: "zypper remove -y {pkgs}",
    FAMILY_ARCH: "pacman -Rns --noconfirm {pkgs}",
    FAMILY_ALPINE: "apk del {pkgs}",
    FAMILY_GENTOO: "emerge --deselect {pkgs}",
}

# v3.7.1: OS-aware SECURITY PATCH command templates. Used by
# get_patch_remediation() to emit the correct security-update command.
_PKG_PATCH_CMD: Dict[str, str] = {
    FAMILY_DEBIAN: "apt-get update && apt-get upgrade -y",
    FAMILY_REDHAT: "dnf -y update --security",
    FAMILY_SUSE: "zypper patch -y",
    FAMILY_ARCH: "pacman -Syu --noconfirm",
    FAMILY_ALPINE: "apk upgrade --available",
    FAMILY_GENTOO: "emerge --update --deep --with-bdeps=y @world",
}

# v3.7.1: Package-name registry for software whose package name differs
# across distribution families. Keyed by a stable canonical token; value
# is a per-family package name. When a family is absent, the canonical
# token is used as the package name (covers the common case where the
# name is identical across families, e.g. cups, samba, vsftpd, telnet).
#
# This registry resolves the inconsistency where the same "remove insecure
# service" check emitted Debian-only or Debian/RHEL-only package names
# (e.g. `apt purge bind9 || yum remove bind`) with no SUSE/Arch/Alpine
# guidance and frequently the wrong package name per distro.
_PACKAGE_NAME_MAP: Dict[str, Dict[str, str]] = {
    # DNS server
    "dns-server": {
        FAMILY_DEBIAN: "bind9", FAMILY_REDHAT: "bind",
        FAMILY_SUSE: "bind", FAMILY_ARCH: "bind", FAMILY_ALPINE: "bind",
    },
    # DHCP server
    "dhcp-server": {
        FAMILY_DEBIAN: "isc-dhcp-server", FAMILY_REDHAT: "dhcp-server",
        FAMILY_SUSE: "dhcp-server", FAMILY_ARCH: "dhcp", FAMILY_ALPINE: "dhcp",
    },
    # NFS server
    "nfs-server": {
        FAMILY_DEBIAN: "nfs-kernel-server", FAMILY_REDHAT: "nfs-utils",
        FAMILY_SUSE: "nfs-kernel-server", FAMILY_ARCH: "nfs-utils",
        FAMILY_ALPINE: "nfs-utils",
    },
    # LDAP server
    "ldap-server": {
        FAMILY_DEBIAN: "slapd", FAMILY_REDHAT: "openldap-servers",
        FAMILY_SUSE: "openldap2", FAMILY_ARCH: "openldap",
        FAMILY_ALPINE: "openldap",
    },
    # SNMP daemon
    "snmp": {
        FAMILY_DEBIAN: "snmpd", FAMILY_REDHAT: "net-snmp",
        FAMILY_SUSE: "net-snmp", FAMILY_ARCH: "net-snmp",
        FAMILY_ALPINE: "net-snmp",
    },
    # rsh client/server
    "rsh": {
        FAMILY_DEBIAN: "rsh-client rsh-server", FAMILY_REDHAT: "rsh rsh-server",
        FAMILY_SUSE: "rsh", FAMILY_ARCH: "rsh", FAMILY_ALPINE: "rsh",
    },
    # NIS (yellow pages)
    "nis": {
        FAMILY_DEBIAN: "nis", FAMILY_REDHAT: "ypserv ypbind",
        FAMILY_SUSE: "ypserv ypbind", FAMILY_ARCH: "ypserv",
        FAMILY_ALPINE: "ypserv",
    },
    # X11 server
    "xserver": {
        FAMILY_DEBIAN: "xserver-xorg*", FAMILY_REDHAT: "xorg-x11-server-Xorg",
        FAMILY_SUSE: "xorg-x11-server", FAMILY_ARCH: "xorg-server",
        FAMILY_ALPINE: "xorg-server",
    },
    # Avahi/mDNS
    "avahi": {
        FAMILY_DEBIAN: "avahi-daemon", FAMILY_REDHAT: "avahi",
        FAMILY_SUSE: "avahi", FAMILY_ARCH: "avahi", FAMILY_ALPINE: "avahi",
    },
    # Dovecot IMAP/POP3
    "dovecot": {
        FAMILY_DEBIAN: "dovecot-imapd dovecot-pop3d", FAMILY_REDHAT: "dovecot",
        FAMILY_SUSE: "dovecot", FAMILY_ARCH: "dovecot", FAMILY_ALPINE: "dovecot",
    },
    # Common single-name packages (identical across families) are handled
    # by the canonical-token fallback and need no explicit entry:
    #   cups, samba, vsftpd, squid, telnet, talk, prelink, rpcbind, tftp
}


def _resolve_family_for_helpers(os_info) -> str:
    """Resolve family for the removal/patch helpers (shares logic with
    _resolve_family but defined early for use throughout the module)."""
    if os_info is not None and hasattr(os_info, "family"):
        return os_info.family or FAMILY_UNKNOWN
    try:
        from shared_components.os_detection import detect_os
        return detect_os().family or FAMILY_UNKNOWN
    except Exception:
        return FAMILY_UNKNOWN


def get_removal_remediation(canonical_token, os_info=None, *,
                            extra_context: str = "") -> str:
    """Return an OS-aware package-removal remediation string.

    Args:
        canonical_token: Either a key in _PACKAGE_NAME_MAP (for packages
            whose name differs across distros, e.g. "dns-server") OR a
            literal package name identical across families (e.g. "telnet").
        os_info: Optional OSInfo; live-detected if omitted.
        extra_context: Optional trailing guidance appended after the command.

    Returns:
        A remediation string with the correct purge command for the
        detected family, plus a cross-distro note. Example (Debian):
            "Remove the package if not required:
               apt-get purge -y bind9
             (RHEL: dnf remove -y bind; SUSE: zypper remove -y bind; ...)"
    """
    family = _resolve_family_for_helpers(os_info)

    def pkg_for(fam: str) -> str:
        mapping = _PACKAGE_NAME_MAP.get(canonical_token)
        if mapping:
            return mapping.get(fam, canonical_token)
        return canonical_token

    # Primary command for the detected family (fall back to Debian style
    # when family is unknown so the operator still gets actionable text).
    primary_family = family if family in _PKG_REMOVE_CMD else FAMILY_DEBIAN
    primary_cmd = _PKG_REMOVE_CMD[primary_family].format(
        pkgs=pkg_for(primary_family)
    )

    lines = ["Remove the package if it is not required for this system:",
             f"  {primary_cmd}"]

    # Cross-distro reference for the other families (so the same finding
    # reads consistently regardless of which distro was audited).
    others = []
    for fam in (FAMILY_DEBIAN, FAMILY_REDHAT, FAMILY_SUSE,
                FAMILY_ARCH, FAMILY_ALPINE):
        if fam == primary_family:
            continue
        cmd = _PKG_REMOVE_CMD[fam].format(pkgs=pkg_for(fam))
        label = {
            FAMILY_DEBIAN: "Debian/Ubuntu", FAMILY_REDHAT: "RHEL/Fedora",
            FAMILY_SUSE: "SUSE", FAMILY_ARCH: "Arch", FAMILY_ALPINE: "Alpine",
        }[fam]
        others.append(f"{label}: {cmd}")
    if others:
        lines.append("Other distributions: " + " | ".join(others))

    if extra_context:
        lines.append(extra_context)

    return "\n".join(lines)


def get_patch_remediation(os_info=None, *, extra_context: str = "") -> str:
    """Return an OS-aware security-patch remediation string."""
    family = _resolve_family_for_helpers(os_info)
    primary_family = family if family in _PKG_PATCH_CMD else FAMILY_DEBIAN
    primary_cmd = _PKG_PATCH_CMD[primary_family]
    lines = ["Apply available security updates:", f"  {primary_cmd}"]
    others = []
    for fam in (FAMILY_DEBIAN, FAMILY_REDHAT, FAMILY_SUSE,
                FAMILY_ARCH, FAMILY_ALPINE):
        if fam == primary_family:
            continue
        label = {
            FAMILY_DEBIAN: "Debian/Ubuntu", FAMILY_REDHAT: "RHEL/Fedora",
            FAMILY_SUSE: "SUSE", FAMILY_ARCH: "Arch", FAMILY_ALPINE: "Alpine",
        }[fam]
        others.append(f"{label}: {_PKG_PATCH_CMD[fam]}")
    if others:
        lines.append("Other distributions: " + " | ".join(others))
    if extra_context:
        lines.append(extra_context)
    return "\n".join(lines)


def _format_install(family: str, pkgs: List[str]) -> str:
    """Render the install command for a family + package list."""
    if not pkgs:
        return ""
    template = _PKG_INSTALL_CMD.get(family, "")
    if not template:
        return ""
    return template.format(pkgs=" ".join(pkgs))


# ----------------------------------------------------------------------------
# Remediation entries - the library content
#
# Each entry follows the pattern:
#   - primary_packages: minimum to get the binary
#   - supporting_packages: needed for full functionality
#   - post_install: distro-specific configuration steps
#   - services: systemd units to enable+start
#   - verify: commands to confirm success
# ----------------------------------------------------------------------------

_LIBRARY: Dict[str, RemediationEntry] = {}


def _register(entry: RemediationEntry) -> None:
    """Register a remediation entry in the global library."""
    _LIBRARY[entry.tool_id] = entry


# Auto-generated by /tmp/build_library.py
# Total entries: 49

_register(RemediationEntry(
    tool_id='aide',
    display_name='AIDE (Advanced Intrusion Detection Environment)',
    purpose='File integrity monitoring; detects unauthorized file changes.',
    primary_packages={
        FAMILY_DEBIAN: ['aide'],
        FAMILY_REDHAT: ['aide'],
        FAMILY_SUSE: ['aide'],
        FAMILY_ARCH: ['aide'],
        FAMILY_ALPINE: ['aide'],
    },
    supporting_packages={
        FAMILY_DEBIAN: ['aide-common'],
        FAMILY_REDHAT: [],
        FAMILY_SUSE: [],
        FAMILY_ARCH: [],
        FAMILY_ALPINE: [],
    },
    post_install={
        FAMILY_DEBIAN: [
            'aideinit',
            'cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db',
            'aide --check',
        ],
        FAMILY_REDHAT: [
            'aide --init',
            'mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz',
            'aide --check',
        ],
        FAMILY_SUSE: [
            'aide --init',
            'mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db',
            'aide --check',
        ],
        FAMILY_ARCH: [
            'aide --init',
            'mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz',
            'aide --check',
        ],
        FAMILY_ALPINE: [
            'aide --init',
            'mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db',
            'aide --check',
        ],
    },
    verify={
        FAMILY_DEBIAN: [
            "test -f /var/lib/aide/aide.db && echo 'AIDE database initialized'",
            'ls -la /etc/cron.daily/aide',
            'aide --version',
        ],
        FAMILY_REDHAT: [
            "test -f /var/lib/aide/aide.db.gz && echo 'AIDE database initialized'",
            'aide --version',
        ],
        FAMILY_SUSE: [
            "test -f /var/lib/aide/aide.db && echo 'AIDE database initialized'",
            'aide --version',
        ],
        FAMILY_ARCH: [
            "test -f /var/lib/aide/aide.db.gz && echo 'AIDE database initialized'",
            'aide --version',
        ],
        FAMILY_ALPINE: [
            "test -f /var/lib/aide/aide.db && echo 'AIDE database initialized'",
            'aide --version',
        ],
    },
    config_files=['/etc/aide/aide.conf', '/etc/aide.conf'],
    notes='Database initialization on first install must complete before any system changes; otherwise the baseline reflects an in-progress configuration. Schedule daily `aide --check` via cron and forward results to your SIEM.',
    references=['https://aide.github.io/', 'https://manpages.debian.org/aide(1)'],
))

_register(RemediationEntry(
    tool_id='auditd',
    display_name='Linux Audit (auditd)',
    purpose='Kernel-level audit logging required by NIST AU-2, PCI 10, STIG.',
    primary_packages={
        FAMILY_DEBIAN: ['auditd'],
        FAMILY_REDHAT: ['audit'],
        FAMILY_SUSE: ['audit'],
        FAMILY_ARCH: ['audit'],
        FAMILY_ALPINE: ['audit'],
    },
    supporting_packages={
        FAMILY_DEBIAN: ['audispd-plugins'],
        FAMILY_REDHAT: ['audit-libs', 'audispd-plugins'],
        FAMILY_SUSE: ['audit-secondary'],
        FAMILY_ARCH: [],
        FAMILY_ALPINE: [],
    },
    post_install={
        FAMILY_DEBIAN: [
            'augenrules --load',
        ],
        FAMILY_REDHAT: [
            'augenrules --load',
        ],
        FAMILY_SUSE: [
            'augenrules --load',
        ],
        FAMILY_ARCH: [
            'augenrules --load',
        ],
        FAMILY_ALPINE: [
            'augenrules --load',
        ],
    },
    services=['auditd.service'],
    verify={
        FAMILY_DEBIAN: [
            'systemctl is-active auditd',
            'auditctl -s',
            'auditctl -l | wc -l',
        ],
        FAMILY_REDHAT: [
            'systemctl is-active auditd',
            'auditctl -s',
            'auditctl -l | wc -l',
        ],
        FAMILY_SUSE: [
            'systemctl is-active auditd',
            'auditctl -s',
            'auditctl -l | wc -l',
        ],
        FAMILY_ARCH: [
            'systemctl is-active auditd',
            'auditctl -s',
            'auditctl -l | wc -l',
        ],
    },
    config_files=['/etc/audit/auditd.conf', '/etc/audit/rules.d/*.rules', '/etc/audit/audit.rules'],
    notes='Drop CIS/STIG-recommended rules into /etc/audit/rules.d/ (e.g. 41-cis-actions.rules). Use `augenrules --load` to merge. Set `-e 2` in /etc/audit/rules.d/99-finalize.rules to make rules immutable until next reboot.',
    references=['https://man7.org/linux/man-pages/man8/auditd.8.html'],
))

_register(RemediationEntry(
    tool_id='tripwire',
    display_name='Open Source Tripwire',
    purpose='Alternative file integrity monitoring (AIDE alternative).',
    primary_packages={
        FAMILY_DEBIAN: ['tripwire'],
        FAMILY_REDHAT: ['tripwire'],
        FAMILY_SUSE: ['tripwire'],
    },
    supporting_packages={
        FAMILY_REDHAT: ['epel-release'],
    },
    post_install={
        FAMILY_DEBIAN: [
            'tripwire --init',
        ],
        FAMILY_REDHAT: [
            'tripwire-setup-keyfiles',
            'tripwire --init',
        ],
        FAMILY_SUSE: [
            'tripwire --init',
        ],
    },
    verify={
        FAMILY_DEBIAN: [
            'tripwire --version',
            "test -f /var/lib/tripwire/$(hostname).twd && echo 'Database initialized'",
        ],
        FAMILY_REDHAT: [
            'tripwire --version',
            "test -f /var/lib/tripwire/$(hostname).twd && echo 'Database initialized'",
        ],
        FAMILY_SUSE: [
            'tripwire --version',
            "test -f /var/lib/tripwire/$(hostname).twd && echo 'Database initialized'",
        ],
    },
    config_files=['/etc/tripwire/tw.cfg', '/etc/tripwire/twpol.txt'],
    notes='On RHEL family, tripwire ships in EPEL. Most modern deployments use AIDE instead; tripwire remains for legacy compatibility.',
    references=['https://github.com/Tripwire/tripwire-open-source'],
))

_register(RemediationEntry(
    tool_id='fail2ban',
    display_name='Fail2ban',
    purpose='Bans IPs after repeated failed authentication attempts.',
    primary_packages={
        FAMILY_DEBIAN: ['fail2ban'],
        FAMILY_REDHAT: ['fail2ban'],
        FAMILY_SUSE: ['fail2ban'],
        FAMILY_ARCH: ['fail2ban'],
        FAMILY_ALPINE: ['fail2ban'],
    },
    supporting_packages={
        FAMILY_REDHAT: ['epel-release', 'fail2ban-firewalld'],
        FAMILY_SUSE: ['fail2ban-firewalld'],
        FAMILY_DEBIAN: [],
        FAMILY_ARCH: [],
        FAMILY_ALPINE: [],
    },
    post_install={
        FAMILY_DEBIAN: [
            'cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local',
            '# Edit /etc/fail2ban/jail.local to enable [sshd] and other jails',
            '# Recommended baseline:',
            '#   [DEFAULT]',
            '#   bantime  = 1h',
            '#   findtime = 10m',
            '#   maxretry = 5',
        ],
        FAMILY_REDHAT: [
            'cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local',
            '# Edit /etc/fail2ban/jail.local to enable [sshd] and other jails',
            '# Recommended baseline:',
            '#   [DEFAULT]',
            '#   bantime  = 1h',
            '#   findtime = 10m',
            '#   maxretry = 5',
        ],
        FAMILY_SUSE: [
            'cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local',
            '# Edit /etc/fail2ban/jail.local to enable [sshd] and other jails',
            '# Recommended baseline:',
            '#   [DEFAULT]',
            '#   bantime  = 1h',
            '#   findtime = 10m',
            '#   maxretry = 5',
        ],
        FAMILY_ARCH: [
            'cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local',
            '# Edit /etc/fail2ban/jail.local to enable [sshd] and other jails',
            '# Recommended baseline:',
            '#   [DEFAULT]',
            '#   bantime  = 1h',
            '#   findtime = 10m',
            '#   maxretry = 5',
        ],
        FAMILY_ALPINE: [
            'cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local',
            '# Edit /etc/fail2ban/jail.local to enable [sshd] and other jails',
            '# Recommended baseline:',
            '#   [DEFAULT]',
            '#   bantime  = 1h',
            '#   findtime = 10m',
            '#   maxretry = 5',
        ],
    },
    services=['fail2ban.service'],
    verify={
        FAMILY_DEBIAN: [
            'systemctl is-active fail2ban',
            'fail2ban-client status',
            'fail2ban-client status sshd',
        ],
        FAMILY_REDHAT: [
            'systemctl is-active fail2ban',
            'fail2ban-client status',
            'fail2ban-client status sshd',
        ],
        FAMILY_SUSE: [
            'systemctl is-active fail2ban',
            'fail2ban-client status',
            'fail2ban-client status sshd',
        ],
        FAMILY_ARCH: [
            'systemctl is-active fail2ban',
            'fail2ban-client status',
            'fail2ban-client status sshd',
        ],
    },
    config_files=['/etc/fail2ban/jail.local', '/etc/fail2ban/jail.d/*.conf'],
    notes='Always edit jail.local (not jail.conf) to survive package upgrades. Default ban time is 10 minutes; raise to 1h+ for production.',
    references=['https://github.com/fail2ban/fail2ban'],
))

_register(RemediationEntry(
    tool_id='usbguard',
    display_name='USBGuard',
    purpose='USB device authorization framework (CISA CPG, STIG PE-3).',
    primary_packages={
        FAMILY_DEBIAN: ['usbguard'],
        FAMILY_REDHAT: ['usbguard'],
        FAMILY_SUSE: ['usbguard'],
        FAMILY_ARCH: ['usbguard'],
    },
    supporting_packages={
        FAMILY_DEBIAN: ['usbguard-applet-qt'],
    },
    post_install={
        FAMILY_DEBIAN: [
            '# IMPORTANT: Generate baseline policy on a known-good system',
            '# BEFORE enabling the service, or you may lock out your keyboard/mouse.',
            'usbguard generate-policy > /etc/usbguard/rules.conf',
            'chmod 600 /etc/usbguard/rules.conf',
            'chown root:root /etc/usbguard/rules.conf',
        ],
        FAMILY_REDHAT: [
            '# IMPORTANT: Generate baseline policy on a known-good system',
            '# BEFORE enabling the service, or you may lock out your keyboard/mouse.',
            'usbguard generate-policy > /etc/usbguard/rules.conf',
            'chmod 600 /etc/usbguard/rules.conf',
            'chown root:root /etc/usbguard/rules.conf',
        ],
        FAMILY_SUSE: [
            '# IMPORTANT: Generate baseline policy on a known-good system',
            '# BEFORE enabling the service, or you may lock out your keyboard/mouse.',
            'usbguard generate-policy > /etc/usbguard/rules.conf',
            'chmod 600 /etc/usbguard/rules.conf',
            'chown root:root /etc/usbguard/rules.conf',
        ],
        FAMILY_ARCH: [
            '# IMPORTANT: Generate baseline policy on a known-good system',
            '# BEFORE enabling the service, or you may lock out your keyboard/mouse.',
            'usbguard generate-policy > /etc/usbguard/rules.conf',
            'chmod 600 /etc/usbguard/rules.conf',
            'chown root:root /etc/usbguard/rules.conf',
        ],
    },
    services=['usbguard.service'],
    verify={
        FAMILY_DEBIAN: [
            'systemctl is-active usbguard',
            'usbguard list-devices',
            'usbguard list-rules',
        ],
        FAMILY_REDHAT: [
            'systemctl is-active usbguard',
            'usbguard list-devices',
            'usbguard list-rules',
        ],
        FAMILY_SUSE: [
            'systemctl is-active usbguard',
            'usbguard list-devices',
            'usbguard list-rules',
        ],
        FAMILY_ARCH: [
            'systemctl is-active usbguard',
            'usbguard list-devices',
            'usbguard list-rules',
        ],
    },
    config_files=['/etc/usbguard/usbguard-daemon.conf', '/etc/usbguard/rules.conf'],
    notes="Generate baseline policy on a known-good system before enabling to avoid blocking the operator's own keyboard/mouse. Use `InsertedDevicePolicy=apply-policy` for production.",
    references=['https://usbguard.github.io/'],
))

_register(RemediationEntry(
    tool_id='apparmor',
    display_name='AppArmor',
    purpose='Mandatory Access Control framework (Debian/SUSE default).',
    primary_packages={
        FAMILY_DEBIAN: ['apparmor', 'apparmor-utils'],
        FAMILY_SUSE: ['apparmor-parser', 'apparmor-utils'],
        FAMILY_ARCH: ['apparmor'],
    },
    supporting_packages={
        FAMILY_DEBIAN: ['apparmor-profiles', 'apparmor-profiles-extra'],
        FAMILY_SUSE: ['apparmor-profiles', 'apparmor-docs'],
        FAMILY_ARCH: [],
    },
    post_install={
        FAMILY_DEBIAN: [
            '# Enable AppArmor on next boot via kernel cmdline:',
            '# Edit /etc/default/grub:',
            '#   GRUB_CMDLINE_LINUX="... apparmor=1 security=apparmor"',
            'update-grub',
            '# Reboot required',
        ],
        FAMILY_SUSE: [
            '# AppArmor is enabled by default on SUSE',
            'aa-enabled',
        ],
        FAMILY_ARCH: [
            '# Edit /etc/default/grub:',
            '#   GRUB_CMDLINE_LINUX_DEFAULT="... lsm=landlock,lockdown,yama,integrity,apparmor,bpf"',
            'grub-mkconfig -o /boot/grub/grub.cfg',
            '# Reboot required',
        ],
    },
    services=['apparmor.service'],
    verify={
        FAMILY_DEBIAN: [
            'systemctl is-active apparmor',
            'aa-enabled',
            'aa-status',
        ],
        FAMILY_SUSE: [
            'systemctl is-active apparmor',
            'aa-enabled',
            'aa-status',
        ],
        FAMILY_ARCH: [
            'systemctl is-active apparmor',
            'aa-enabled',
            'aa-status',
        ],
    },
    config_files=['/etc/apparmor/', '/etc/apparmor.d/'],
    notes='Reboot required after enabling on Debian via kernel cmdline. Use `aa-enforce /etc/apparmor.d/<profile>` to put a specific profile in enforce mode. Verify before deploying broadly.',
    references=['https://apparmor.net/'],
))

_register(RemediationEntry(
    tool_id='selinux',
    display_name='SELinux',
    purpose='Mandatory Access Control framework (RHEL family default).',
    primary_packages={
        FAMILY_REDHAT: ['selinux-policy-targeted', 'policycoreutils', 'selinux-policy'],
        FAMILY_DEBIAN: ['selinux-basics', 'selinux-policy-default'],
    },
    supporting_packages={
        FAMILY_REDHAT: ['policycoreutils-python-utils', 'setroubleshoot-server', 'setools-console'],
        FAMILY_DEBIAN: ['selinux-utils', 'policycoreutils'],
    },
    post_install={
        FAMILY_REDHAT: [
            "sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config",
            'fixfiles -F onboot',
            '# Reboot required (slow first boot due to filesystem relabel)',
        ],
        FAMILY_DEBIAN: [
            'selinux-activate',
            '# Reboot required',
        ],
    },
    verify={
        FAMILY_REDHAT: [
            'getenforce',
            'sestatus',
            'sestatus -v',
        ],
        FAMILY_DEBIAN: [
            'getenforce',
            'sestatus',
            'sestatus -v',
        ],
    },
    config_files=['/etc/selinux/config'],
    notes='Reboot required after enabling. First boot after enforcing will be slow due to filesystem relabel. SELinux and AppArmor are mutually exclusive - disable AppArmor first if migrating.',
    references=['https://github.com/SELinuxProject/selinux'],
))

_register(RemediationEntry(
    tool_id='fapolicyd',
    display_name='fapolicyd (File Access Policy Daemon)',
    purpose='Application allowlisting (RHEL native; ACSC E8.1).',
    primary_packages={
        FAMILY_REDHAT: ['fapolicyd'],
    },
    supporting_packages={
        FAMILY_REDHAT: ['fapolicyd-selinux'],
    },
    post_install={
        FAMILY_REDHAT: [
            '# Review default rules in /etc/fapolicyd/rules.d/',
            'fagenrules --check',
            'fagenrules --load',
            '# Test in permissive mode first:',
            '#   fapolicyd --debug-deny --no-details',
        ],
    },
    services=['fapolicyd.service'],
    verify={
        FAMILY_REDHAT: [
            'systemctl is-active fapolicyd',
            'fapolicyd-cli --status',
            'fapolicyd-cli --list',
        ],
    },
    config_files=['/etc/fapolicyd/fapolicyd.conf', '/etc/fapolicyd/rules.d/'],
    notes='Test in permissive mode first (--debug-deny) to identify legitimate access patterns before enforcing. Misconfiguration can render the system unusable.',
    references=['https://github.com/linux-application-whitelisting/fapolicyd'],
))

_register(RemediationEntry(
    tool_id='clamav',
    display_name='ClamAV',
    purpose='Open-source anti-malware engine (PCI 5).',
    primary_packages={
        FAMILY_DEBIAN: ['clamav', 'clamav-daemon', 'clamav-freshclam'],
        FAMILY_REDHAT: ['clamav', 'clamav-update', 'clamd'],
        FAMILY_SUSE: ['clamav'],
        FAMILY_ARCH: ['clamav'],
        FAMILY_ALPINE: ['clamav', 'clamav-daemon'],
    },
    supporting_packages={
        FAMILY_DEBIAN: ['clamav-base'],
        FAMILY_REDHAT: ['clamav-data'],
        FAMILY_SUSE: [],
        FAMILY_ARCH: [],
        FAMILY_ALPINE: [],
    },
    post_install={
        FAMILY_DEBIAN: [
            'freshclam',
            'systemctl restart clamav-daemon',
        ],
        FAMILY_REDHAT: [
            "# Edit /etc/freshclam.conf - remove or comment 'Example' line",
            "sed -i 's/^Example/#Example/' /etc/freshclam.conf",
            'freshclam',
        ],
        FAMILY_SUSE: [
            'freshclam',
        ],
        FAMILY_ARCH: [
            'freshclam',
        ],
        FAMILY_ALPINE: [
            'freshclam',
        ],
    },
    services=['clamav-daemon.service', 'clamav-freshclam.service'],
    verify={
        FAMILY_DEBIAN: [
            'systemctl is-active clamav-daemon',
            'freshclam --version',
            'clamscan --version',
        ],
        FAMILY_REDHAT: [
            'systemctl is-active clamd',
            'freshclam --version',
        ],
        FAMILY_SUSE: [
            'systemctl is-active clamd',
            'freshclam --version',
        ],
        FAMILY_ARCH: [
            'systemctl is-active clamav-daemon',
            'freshclam --version',
        ],
        FAMILY_ALPINE: [
            'rc-service clamd status',
            'freshclam --version',
        ],
    },
    config_files=['/etc/clamav/clamd.conf', '/etc/clamav/freshclam.conf'],
    notes='Service name differs across families: clamav-daemon (Debian/Arch), clamd (RHEL/SUSE/Alpine). First freshclam run downloads signature database (~250MB). Schedule freshclam.timer for hourly updates.',
    references=['https://www.clamav.net/'],
))

_register(RemediationEntry(
    tool_id='rkhunter',
    display_name='rkhunter (Rootkit Hunter)',
    purpose='Rootkit, backdoor and local exploit detection.',
    primary_packages={
        FAMILY_DEBIAN: ['rkhunter'],
        FAMILY_REDHAT: ['rkhunter'],
        FAMILY_SUSE: ['rkhunter'],
        FAMILY_ARCH: ['rkhunter'],
    },
    supporting_packages={
        FAMILY_REDHAT: ['epel-release'],
    },
    post_install={
        FAMILY_DEBIAN: [
            'rkhunter --update',
            'rkhunter --propupd',
        ],
        FAMILY_REDHAT: [
            'rkhunter --update',
            'rkhunter --propupd',
        ],
        FAMILY_SUSE: [
            'rkhunter --update',
            'rkhunter --propupd',
        ],
        FAMILY_ARCH: [
            'rkhunter --update',
            'rkhunter --propupd',
        ],
    },
    verify={
        FAMILY_DEBIAN: [
            'rkhunter --version',
            'rkhunter --check --skip-keypress --report-warnings-only',
        ],
        FAMILY_REDHAT: [
            'rkhunter --version',
            'rkhunter --check --skip-keypress --report-warnings-only',
        ],
        FAMILY_SUSE: [
            'rkhunter --version',
            'rkhunter --check --skip-keypress --report-warnings-only',
        ],
        FAMILY_ARCH: [
            'rkhunter --version',
            'rkhunter --check --skip-keypress --report-warnings-only',
        ],
    },
    config_files=['/etc/rkhunter.conf'],
    notes='Schedule weekly via cron. Some default checks may produce false positives on rolling-release distributions; tune /etc/rkhunter.conf to whitelist legitimate hashes after each major update.',
    references=['https://rkhunter.sourceforge.net/'],
))

_register(RemediationEntry(
    tool_id='chkrootkit',
    display_name='chkrootkit',
    purpose='Locally-checks for signs of a rootkit (defense in depth).',
    primary_packages={
        FAMILY_DEBIAN: ['chkrootkit'],
        FAMILY_REDHAT: ['chkrootkit'],
        FAMILY_SUSE: ['chkrootkit'],
        FAMILY_ARCH: ['chkrootkit'],
        FAMILY_ALPINE: ['chkrootkit'],
    },
    supporting_packages={
        FAMILY_REDHAT: ['epel-release'],
    },
    post_install={
        FAMILY_DEBIAN: [
            '# No initialization required.',
        ],
        FAMILY_REDHAT: [
            '# No initialization required.',
        ],
        FAMILY_SUSE: [
            '# No initialization required.',
        ],
        FAMILY_ARCH: [
            '# No initialization required.',
        ],
        FAMILY_ALPINE: [
            '# No initialization required.',
        ],
        FAMILY_GENTOO: [
            '# No initialization required.',
        ],
    },
    verify={
        FAMILY_DEBIAN: [
            'command -v chkrootkit',
            'chkrootkit --version',
            'chkrootkit -V',
        ],
        FAMILY_REDHAT: [
            'command -v chkrootkit',
            'chkrootkit --version',
            'chkrootkit -V',
        ],
        FAMILY_SUSE: [
            'command -v chkrootkit',
            'chkrootkit --version',
            'chkrootkit -V',
        ],
        FAMILY_ARCH: [
            'command -v chkrootkit',
            'chkrootkit --version',
            'chkrootkit -V',
        ],
        FAMILY_ALPINE: [
            'command -v chkrootkit',
            'chkrootkit --version',
            'chkrootkit -V',
        ],
        FAMILY_GENTOO: [
            'command -v chkrootkit',
            'chkrootkit --version',
            'chkrootkit -V',
        ],
    },
    notes='Schedule weekly via cron alongside rkhunter for defense-in-depth.',
    references=['https://www.chkrootkit.org/'],
))

_register(RemediationEntry(
    tool_id='lynis',
    display_name='Lynis',
    purpose='Host security auditing and compliance scanner.',
    primary_packages={
        FAMILY_DEBIAN: ['lynis'],
        FAMILY_REDHAT: ['lynis'],
        FAMILY_SUSE: ['lynis'],
        FAMILY_ARCH: ['lynis'],
        FAMILY_ALPINE: ['lynis'],
    },
    supporting_packages={
        FAMILY_REDHAT: ['epel-release'],
    },
    post_install={
        FAMILY_DEBIAN: [
            '# No initialization required.',
            'lynis update info',
        ],
        FAMILY_REDHAT: [
            '# No initialization required.',
            'lynis update info',
        ],
        FAMILY_SUSE: [
            '# No initialization required.',
            'lynis update info',
        ],
        FAMILY_ARCH: [
            '# No initialization required.',
            'lynis update info',
        ],
        FAMILY_ALPINE: [
            '# No initialization required.',
            'lynis update info',
        ],
    },
    verify={
        FAMILY_DEBIAN: [
            'lynis show version',
            'lynis audit system --quick',
        ],
        FAMILY_REDHAT: [
            'lynis show version',
            'lynis audit system --quick',
        ],
        FAMILY_SUSE: [
            'lynis show version',
            'lynis audit system --quick',
        ],
        FAMILY_ARCH: [
            'lynis show version',
            'lynis audit system --quick',
        ],
        FAMILY_ALPINE: [
            'lynis show version',
            'lynis audit system --quick',
        ],
    },
    config_files=['/etc/lynis/lynis.cfg'],
    notes='Repository version is often outdated; for latest, use the CISOfy repository at https://packages.cisofy.com/community/.',
    references=['https://cisofy.com/lynis/'],
))

_register(RemediationEntry(
    tool_id='openscap',
    display_name='OpenSCAP',
    purpose='Security Content Automation Protocol scanner (NIST/STIG).',
    primary_packages={
        FAMILY_DEBIAN: ['libopenscap8', 'openscap-scanner'],
        FAMILY_REDHAT: ['openscap-scanner', 'scap-security-guide'],
        FAMILY_SUSE: ['openscap-utils', 'openscap-content'],
    },
    supporting_packages={
        FAMILY_DEBIAN: ['libopenscap-dev'],
        FAMILY_REDHAT: ['scap-workbench'],
        FAMILY_SUSE: ['scap-workbench'],
    },
    post_install={
        FAMILY_DEBIAN: [
            '# List installed SCAP profiles:',
            'ls /usr/share/xml/scap/ssg/content/ 2>/dev/null || ls /usr/share/openscap/',
        ],
        FAMILY_REDHAT: [
            '# List installed SCAP profiles:',
            'ls /usr/share/xml/scap/ssg/content/ 2>/dev/null || ls /usr/share/openscap/',
        ],
        FAMILY_SUSE: [
            '# List installed SCAP profiles:',
            'ls /usr/share/xml/scap/ssg/content/ 2>/dev/null || ls /usr/share/openscap/',
        ],
    },
    verify={
        FAMILY_DEBIAN: [
            'oscap --version',
        ],
        FAMILY_REDHAT: [
            'oscap --version',
            'ls /usr/share/xml/scap/ssg/content/',
        ],
        FAMILY_SUSE: [
            'oscap --version',
        ],
    },
    notes='Use scap-security-guide content to scan against STIG, CIS, PCI-DSS profiles. Example: `oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_stig --results results.xml /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml`',
    references=['https://www.open-scap.org/'],
))

_register(RemediationEntry(
    tool_id='ufw',
    display_name='UFW (Uncomplicated Firewall)',
    purpose='Front-end for iptables/nftables (Ubuntu/Debian default).',
    primary_packages={
        FAMILY_DEBIAN: ['ufw'],
        FAMILY_ARCH: ['ufw'],
    },
    post_install={
        FAMILY_DEBIAN: [
            '# CRITICAL: Allow SSH BEFORE enabling, or you may lock out remote sessions.',
            'ufw default deny incoming',
            'ufw default allow outgoing',
            'ufw allow OpenSSH',
            'ufw enable',
        ],
        FAMILY_ARCH: [
            '# CRITICAL: Allow SSH BEFORE enabling, or you may lock out remote sessions.',
            'ufw default deny incoming',
            'ufw default allow outgoing',
            'ufw allow OpenSSH',
            'ufw enable',
        ],
    },
    services=['ufw.service'],
    verify={
        FAMILY_DEBIAN: [
            'systemctl is-active ufw',
            'ufw status verbose',
        ],
        FAMILY_ARCH: [
            'systemctl is-active ufw',
            'ufw status verbose',
        ],
    },
    config_files=['/etc/ufw/', '/etc/default/ufw'],
    notes='Always allow SSH BEFORE enabling UFW or you may lock yourself out of remote systems. Test from a second session.',
    references=['https://help.ubuntu.com/community/UFW'],
))

_register(RemediationEntry(
    tool_id='firewalld',
    display_name='firewalld',
    purpose='Dynamic firewall management daemon (RHEL family default).',
    primary_packages={
        FAMILY_REDHAT: ['firewalld'],
        FAMILY_SUSE: ['firewalld'],
        FAMILY_DEBIAN: ['firewalld'],
    },
    supporting_packages={
        FAMILY_REDHAT: ['firewall-config'],
    },
    post_install={
        FAMILY_REDHAT: [
            'firewall-cmd --set-default-zone=drop',
            'firewall-cmd --zone=drop --add-service=ssh --permanent',
            'firewall-cmd --reload',
        ],
        FAMILY_SUSE: [
            'firewall-cmd --set-default-zone=drop',
            'firewall-cmd --zone=drop --add-service=ssh --permanent',
            'firewall-cmd --reload',
        ],
        FAMILY_DEBIAN: [
            'firewall-cmd --set-default-zone=drop',
            'firewall-cmd --zone=drop --add-service=ssh --permanent',
            'firewall-cmd --reload',
        ],
    },
    services=['firewalld.service'],
    verify={
        FAMILY_REDHAT: [
            'systemctl is-active firewalld',
            'firewall-cmd --state',
            'firewall-cmd --list-all',
        ],
        FAMILY_SUSE: [
            'systemctl is-active firewalld',
            'firewall-cmd --state',
            'firewall-cmd --list-all',
        ],
        FAMILY_DEBIAN: [
            'systemctl is-active firewalld',
            'firewall-cmd --state',
            'firewall-cmd --list-all',
        ],
    },
    config_files=['/etc/firewalld/'],
    references=['https://firewalld.org/'],
))

_register(RemediationEntry(
    tool_id='nftables',
    display_name='nftables',
    purpose='Modern netfilter framework (kernel-level firewall).',
    primary_packages={
        FAMILY_DEBIAN: ['nftables'],
        FAMILY_REDHAT: ['nftables'],
        FAMILY_SUSE: ['nftables'],
        FAMILY_ARCH: ['nftables'],
        FAMILY_ALPINE: ['nftables'],
    },
    post_install={
        FAMILY_DEBIAN: [
            '# Place ruleset in /etc/nftables.conf',
            'nft -f /etc/nftables.conf',
        ],
        FAMILY_REDHAT: [
            '# Place ruleset in /etc/nftables.conf',
            'nft -f /etc/nftables.conf',
        ],
        FAMILY_SUSE: [
            '# Place ruleset in /etc/nftables.conf',
            'nft -f /etc/nftables.conf',
        ],
        FAMILY_ARCH: [
            '# Place ruleset in /etc/nftables.conf',
            'nft -f /etc/nftables.conf',
        ],
        FAMILY_ALPINE: [
            '# Place ruleset in /etc/nftables.conf',
            'nft -f /etc/nftables.conf',
        ],
    },
    services=['nftables.service'],
    verify={
        FAMILY_DEBIAN: [
            'systemctl is-active nftables',
            'nft list ruleset',
        ],
        FAMILY_REDHAT: [
            'systemctl is-active nftables',
            'nft list ruleset',
        ],
        FAMILY_SUSE: [
            'systemctl is-active nftables',
            'nft list ruleset',
        ],
        FAMILY_ARCH: [
            'systemctl is-active nftables',
            'nft list ruleset',
        ],
    },
    config_files=['/etc/nftables.conf'],
    references=['https://wiki.nftables.org/'],
))

_register(RemediationEntry(
    tool_id='iptables',
    display_name='iptables (legacy)',
    purpose='Legacy netfilter front-end (still supported but deprecated).',
    primary_packages={
        FAMILY_DEBIAN: ['iptables'],
        FAMILY_REDHAT: ['iptables-services'],
        FAMILY_SUSE: ['iptables'],
        FAMILY_ARCH: ['iptables'],
        FAMILY_ALPINE: ['iptables'],
    },
    supporting_packages={
        FAMILY_DEBIAN: ['iptables-persistent'],
    },
    post_install={
        FAMILY_DEBIAN: [
            '# nftables is the modern replacement; prefer it for new deployments.',
        ],
        FAMILY_REDHAT: [
            '# nftables is the modern replacement; prefer it for new deployments.',
        ],
        FAMILY_SUSE: [
            '# nftables is the modern replacement; prefer it for new deployments.',
        ],
        FAMILY_ARCH: [
            '# nftables is the modern replacement; prefer it for new deployments.',
        ],
        FAMILY_ALPINE: [
            '# nftables is the modern replacement; prefer it for new deployments.',
        ],
        FAMILY_GENTOO: [
            '# nftables is the modern replacement; prefer it for new deployments.',
        ],
    },
    verify={
        FAMILY_DEBIAN: [
            'iptables --version',
            'iptables -L -n -v',
        ],
        FAMILY_REDHAT: [
            'iptables --version',
            'iptables -L -n -v',
        ],
        FAMILY_SUSE: [
            'iptables --version',
            'iptables -L -n -v',
        ],
        FAMILY_ARCH: [
            'iptables --version',
            'iptables -L -n -v',
        ],
        FAMILY_ALPINE: [
            'iptables --version',
            'iptables -L -n -v',
        ],
        FAMILY_GENTOO: [
            'iptables --version',
            'iptables -L -n -v',
        ],
    },
    config_files=['/etc/iptables/rules.v4', '/etc/iptables/rules.v6'],
    notes='Use nftables for new deployments. Migrate via `iptables-translate`.',
    references=['https://netfilter.org/projects/iptables/'],
))

_register(RemediationEntry(
    tool_id='chrony',
    display_name='chrony',
    purpose='Modern NTP implementation with NTS support (PCI 10.6).',
    primary_packages={
        FAMILY_DEBIAN: ['chrony'],
        FAMILY_REDHAT: ['chrony'],
        FAMILY_SUSE: ['chrony'],
        FAMILY_ARCH: ['chrony'],
        FAMILY_ALPINE: ['chrony'],
    },
    supporting_packages={
        FAMILY_DEBIAN: [],
        FAMILY_REDHAT: [],
        FAMILY_SUSE: [],
        FAMILY_ARCH: [],
        FAMILY_ALPINE: [],
    },
    post_install={
        FAMILY_DEBIAN: [
            '# Edit /etc/chrony/chrony.conf',
            '# Recommended NTS-authenticated source:',
            '#   server time.cloudflare.com iburst nts',
            '#   server nts.netnod.se iburst nts',
        ],
        FAMILY_REDHAT: [
            '# Edit /etc/chrony.conf',
            '#   server time.cloudflare.com iburst nts',
        ],
        FAMILY_SUSE: [
            '# Edit /etc/chrony.conf',
            '#   server time.cloudflare.com iburst nts',
        ],
        FAMILY_ARCH: [
            '# Edit /etc/chrony.conf',
            '#   server time.cloudflare.com iburst nts',
        ],
        FAMILY_ALPINE: [
            '# Edit /etc/chrony/chrony.conf',
            '#   server time.cloudflare.com iburst nts',
        ],
    },
    services=['chronyd.service'],
    verify={
        FAMILY_DEBIAN: [
            'systemctl is-active chrony',
            'chronyc tracking',
            'chronyc sources -v',
        ],
        FAMILY_REDHAT: [
            'systemctl is-active chronyd',
            'chronyc tracking',
            'chronyc sources -v',
        ],
        FAMILY_SUSE: [
            'systemctl is-active chronyd',
            'chronyc tracking',
        ],
        FAMILY_ARCH: [
            'systemctl is-active chronyd',
            'chronyc tracking',
        ],
        FAMILY_ALPINE: [
            'rc-service chronyd status',
            'chronyc tracking',
        ],
    },
    config_files=['/etc/chrony/chrony.conf', '/etc/chrony.conf'],
    notes='On Debian/Ubuntu 22.04+, use `time.cloudflare.com` with `nts` option for authenticated time synchronization. Service name differs: `chrony` on Debian, `chronyd` elsewhere.',
    references=['https://chrony-project.org/'],
))

_register(RemediationEntry(
    tool_id='unattended-upgrades',
    display_name='Unattended Upgrades',
    purpose='Automated security update installation (Debian/Ubuntu).',
    primary_packages={
        FAMILY_DEBIAN: ['unattended-upgrades'],
    },
    supporting_packages={
        FAMILY_DEBIAN: ['apt-listchanges', 'update-notifier-common'],
    },
    post_install={
        FAMILY_DEBIAN: [
            'dpkg-reconfigure -plow unattended-upgrades',
            '# OR non-interactively:',
            'echo \'APT::Periodic::Update-Package-Lists "1";\' > /etc/apt/apt.conf.d/20auto-upgrades',
            'echo \'APT::Periodic::Unattended-Upgrade "1";\' >> /etc/apt/apt.conf.d/20auto-upgrades',
            'echo \'APT::Periodic::AutocleanInterval "7";\' >> /etc/apt/apt.conf.d/20auto-upgrades',
        ],
    },
    services=['unattended-upgrades.service', 'apt-daily.timer', 'apt-daily-upgrade.timer'],
    verify={
        FAMILY_DEBIAN: [
            'systemctl is-active unattended-upgrades',
            'unattended-upgrade --dry-run --debug',
            'systemctl list-timers apt-daily*',
        ],
    },
    config_files=['/etc/apt/apt.conf.d/50unattended-upgrades', '/etc/apt/apt.conf.d/20auto-upgrades'],
    references=['https://wiki.debian.org/UnattendedUpgrades'],
))

_register(RemediationEntry(
    tool_id='dnf-automatic',
    display_name='dnf-automatic',
    purpose='Automated security update installation (RHEL family).',
    primary_packages={
        FAMILY_REDHAT: ['dnf-automatic'],
    },
    post_install={
        FAMILY_REDHAT: [
            '# Edit /etc/dnf/automatic.conf:',
            "sed -i 's/^apply_updates = .*/apply_updates = yes/' /etc/dnf/automatic.conf",
            "sed -i 's/^upgrade_type = .*/upgrade_type = security/' /etc/dnf/automatic.conf",
        ],
    },
    services=['dnf-automatic-install.timer', 'dnf-automatic.timer'],
    verify={
        FAMILY_REDHAT: [
            'systemctl is-active dnf-automatic-install.timer',
            'systemctl list-timers dnf-automatic*',
        ],
    },
    config_files=['/etc/dnf/automatic.conf'],
    references=['https://dnf.readthedocs.io/en/latest/automatic.html'],
))

_register(RemediationEntry(
    tool_id='zypper-automatic',
    display_name='zypper automatic updates',
    purpose='Automated security update installation (SUSE).',
    primary_packages={
        FAMILY_SUSE: ['yast2-online-update-configuration'],
    },
    post_install={
        FAMILY_SUSE: [
            '# Configure via YaST or directly:',
            'systemctl enable --now zypp-refresh.timer',
            '# Configure /etc/zypp/zypp.conf and /etc/zypp/zypper.conf',
        ],
    },
    services=['zypp-refresh.timer'],
    verify={
        FAMILY_SUSE: [
            'systemctl is-active zypp-refresh.timer',
        ],
    },
    config_files=['/etc/zypp/zypp.conf'],
    references=['https://en.opensuse.org/SDB:Online_update'],
))

_register(RemediationEntry(
    tool_id='pam-google-authenticator',
    display_name='Google Authenticator PAM',
    purpose='TOTP-based MFA via PAM (NIST IA-2(1), HIPAA 164.312(d)).',
    primary_packages={
        FAMILY_DEBIAN: ['libpam-google-authenticator'],
        FAMILY_REDHAT: ['google-authenticator'],
        FAMILY_SUSE: ['google-authenticator-libpam'],
        FAMILY_ARCH: ['libpam-google-authenticator'],
    },
    supporting_packages={
        FAMILY_REDHAT: ['epel-release'],
    },
    post_install={
        FAMILY_DEBIAN: [
            '# As each user, run:',
            '#   google-authenticator -t -d -f -r 3 -R 30 -W',
            '# Add to /etc/pam.d/sshd:',
            '#   auth required pam_google_authenticator.so',
            '# Add to /etc/ssh/sshd_config:',
            '#   ChallengeResponseAuthentication yes',
            '#   AuthenticationMethods publickey,keyboard-interactive',
            'systemctl restart sshd',
        ],
        FAMILY_REDHAT: [
            '# As each user, run:',
            '#   google-authenticator -t -d -f -r 3 -R 30 -W',
            '# Add to /etc/pam.d/sshd:',
            '#   auth required pam_google_authenticator.so',
            '# Add to /etc/ssh/sshd_config:',
            '#   ChallengeResponseAuthentication yes',
            '#   AuthenticationMethods publickey,keyboard-interactive',
            'systemctl restart sshd',
        ],
        FAMILY_SUSE: [
            '# As each user, run:',
            '#   google-authenticator -t -d -f -r 3 -R 30 -W',
            '# Add to /etc/pam.d/sshd:',
            '#   auth required pam_google_authenticator.so',
            '# Add to /etc/ssh/sshd_config:',
            '#   ChallengeResponseAuthentication yes',
            '#   AuthenticationMethods publickey,keyboard-interactive',
            'systemctl restart sshd',
        ],
        FAMILY_ARCH: [
            '# As each user, run:',
            '#   google-authenticator -t -d -f -r 3 -R 30 -W',
            '# Add to /etc/pam.d/sshd:',
            '#   auth required pam_google_authenticator.so',
            '# Add to /etc/ssh/sshd_config:',
            '#   ChallengeResponseAuthentication yes',
            '#   AuthenticationMethods publickey,keyboard-interactive',
            'systemctl restart sshd',
        ],
    },
    verify={
        FAMILY_DEBIAN: [
            "test -f ~/.google_authenticator && echo 'Configured for current user'",
        ],
        FAMILY_REDHAT: [
            "test -f ~/.google_authenticator && echo 'Configured for current user'",
        ],
        FAMILY_SUSE: [
            "test -f ~/.google_authenticator && echo 'Configured for current user'",
        ],
        FAMILY_ARCH: [
            "test -f ~/.google_authenticator && echo 'Configured for current user'",
        ],
    },
    config_files=['/etc/pam.d/sshd', '~/.google_authenticator'],
    notes='Configure per-user. Test from a second SSH session before logging out. Backup scratch codes generated during setup.',
    references=['https://github.com/google/google-authenticator-libpam'],
))

_register(RemediationEntry(
    tool_id='pam-yubico',
    display_name='Yubico PAM (hardware-backed MFA)',
    purpose='Phishing-resistant MFA via YubiKey (CISA CPG 2.H).',
    primary_packages={
        FAMILY_DEBIAN: ['libpam-yubico'],
        FAMILY_REDHAT: ['pam_yubico'],
        FAMILY_ARCH: ['pam-u2f'],
    },
    supporting_packages={
        FAMILY_REDHAT: ['epel-release'],
    },
    post_install={
        FAMILY_DEBIAN: [
            "# Register each user's YubiKey ID in /etc/yubikey_mappings",
            '# Add to /etc/pam.d/sshd:',
            '#   auth required pam_yubico.so id=<your-api-id> key=<your-api-key>',
        ],
        FAMILY_REDHAT: [
            "# Register each user's YubiKey ID in /etc/yubikey_mappings",
            '# Add to /etc/pam.d/sshd:',
            '#   auth required pam_yubico.so id=<your-api-id> key=<your-api-key>',
        ],
        FAMILY_ARCH: [
            '# Use pam-u2f instead of pam-yubico on Arch',
            '# pamu2fcfg > ~/.config/Yubico/u2f_keys',
        ],
    },
    verify={
        FAMILY_DEBIAN: [
            'dpkg -l libpam-yubico',
        ],
        FAMILY_REDHAT: [
            'rpm -q pam_yubico',
        ],
        FAMILY_ARCH: [
            'pacman -Q pam-u2f',
        ],
    },
    config_files=['/etc/yubikey_mappings', '/etc/pam.d/sshd'],
    references=['https://developers.yubico.com/yubico-pam/'],
))

_register(RemediationEntry(
    tool_id='pam-pwquality',
    display_name='pam_pwquality (password complexity)',
    purpose='Enforces password complexity (CIS 5.4.1.x, NIST IA-5).',
    primary_packages={
        FAMILY_DEBIAN: ['libpam-pwquality'],
        FAMILY_REDHAT: ['libpwquality'],
        FAMILY_SUSE: ['libpwquality-tools'],
        FAMILY_ARCH: ['libpwquality'],
    },
    post_install={
        FAMILY_DEBIAN: [
            '# Edit /etc/security/pwquality.conf:',
            '#   minlen = 14',
            '#   minclass = 4',
            '#   dcredit = -1',
            '#   ucredit = -1',
            '#   ocredit = -1',
            '#   lcredit = -1',
            '#   maxrepeat = 3',
            '#   dictcheck = 1',
        ],
        FAMILY_REDHAT: [
            '# Edit /etc/security/pwquality.conf:',
            '#   minlen = 14',
            '#   minclass = 4',
            '#   dcredit = -1',
            '#   ucredit = -1',
            '#   ocredit = -1',
            '#   lcredit = -1',
            '#   maxrepeat = 3',
            '#   dictcheck = 1',
        ],
        FAMILY_SUSE: [
            '# Edit /etc/security/pwquality.conf:',
            '#   minlen = 14',
            '#   minclass = 4',
            '#   dcredit = -1',
            '#   ucredit = -1',
            '#   ocredit = -1',
            '#   lcredit = -1',
            '#   maxrepeat = 3',
            '#   dictcheck = 1',
        ],
        FAMILY_ARCH: [
            '# Edit /etc/security/pwquality.conf:',
            '#   minlen = 14',
            '#   minclass = 4',
            '#   dcredit = -1',
            '#   ucredit = -1',
            '#   ocredit = -1',
            '#   lcredit = -1',
            '#   maxrepeat = 3',
            '#   dictcheck = 1',
        ],
    },
    verify={
        FAMILY_DEBIAN: [
            "test -f /etc/security/pwquality.conf && echo 'Config present'",
            "grep -E '^(minlen|minclass)' /etc/security/pwquality.conf",
        ],
        FAMILY_REDHAT: [
            "test -f /etc/security/pwquality.conf && echo 'Config present'",
            "grep -E '^(minlen|minclass)' /etc/security/pwquality.conf",
        ],
        FAMILY_SUSE: [
            "test -f /etc/security/pwquality.conf && echo 'Config present'",
            "grep -E '^(minlen|minclass)' /etc/security/pwquality.conf",
        ],
        FAMILY_ARCH: [
            "test -f /etc/security/pwquality.conf && echo 'Config present'",
            "grep -E '^(minlen|minclass)' /etc/security/pwquality.conf",
        ],
    },
    config_files=['/etc/security/pwquality.conf'],
    references=['https://github.com/libpwquality/libpwquality'],
))

_register(RemediationEntry(
    tool_id='pam-faillock',
    display_name='pam_faillock (account lockout)',
    purpose='Lock accounts after repeated failed authentication.',
    primary_packages={
        FAMILY_DEBIAN: ['libpam-modules'],
        FAMILY_REDHAT: ['pam'],
        FAMILY_SUSE: ['pam'],
        FAMILY_ARCH: ['pam'],
    },
    post_install={
        FAMILY_DEBIAN: [
            '# Edit /etc/security/faillock.conf:',
            '#   deny = 5',
            '#   unlock_time = 900',
            '#   fail_interval = 900',
            '# Add to /etc/pam.d/system-auth and /etc/pam.d/password-auth:',
            '#   auth required pam_faillock.so preauth',
            '#   auth required pam_faillock.so authfail',
        ],
        FAMILY_REDHAT: [
            '# Edit /etc/security/faillock.conf:',
            '#   deny = 5',
            '#   unlock_time = 900',
            '#   fail_interval = 900',
            '# Add to /etc/pam.d/system-auth and /etc/pam.d/password-auth:',
            '#   auth required pam_faillock.so preauth',
            '#   auth required pam_faillock.so authfail',
        ],
        FAMILY_SUSE: [
            '# Edit /etc/security/faillock.conf:',
            '#   deny = 5',
            '#   unlock_time = 900',
            '#   fail_interval = 900',
            '# Add to /etc/pam.d/system-auth and /etc/pam.d/password-auth:',
            '#   auth required pam_faillock.so preauth',
            '#   auth required pam_faillock.so authfail',
        ],
        FAMILY_ARCH: [
            '# Edit /etc/security/faillock.conf:',
            '#   deny = 5',
            '#   unlock_time = 900',
            '#   fail_interval = 900',
            '# Add to /etc/pam.d/system-auth and /etc/pam.d/password-auth:',
            '#   auth required pam_faillock.so preauth',
            '#   auth required pam_faillock.so authfail',
        ],
    },
    verify={
        FAMILY_DEBIAN: [
            "test -f /etc/security/faillock.conf && echo 'Config present'",
            'faillock --user root',
        ],
        FAMILY_REDHAT: [
            "test -f /etc/security/faillock.conf && echo 'Config present'",
            'faillock --user root',
        ],
        FAMILY_SUSE: [
            "test -f /etc/security/faillock.conf && echo 'Config present'",
            'faillock --user root',
        ],
        FAMILY_ARCH: [
            "test -f /etc/security/faillock.conf && echo 'Config present'",
            'faillock --user root',
        ],
    },
    config_files=['/etc/security/faillock.conf'],
    references=['https://man7.org/linux/man-pages/man8/pam_faillock.8.html'],
))

_register(RemediationEntry(
    tool_id='cryptsetup',
    display_name='cryptsetup (LUKS)',
    purpose='Disk encryption framework (PCI 3, HIPAA 164.312(a)(2)(iv)).',
    primary_packages={
        FAMILY_DEBIAN: ['cryptsetup', 'cryptsetup-initramfs'],
        FAMILY_REDHAT: ['cryptsetup', 'cryptsetup-libs'],
        FAMILY_SUSE: ['cryptsetup'],
        FAMILY_ARCH: ['cryptsetup'],
        FAMILY_ALPINE: ['cryptsetup'],
    },
    supporting_packages={
        FAMILY_DEBIAN: ['cryptsetup-bin'],
    },
    post_install={
        FAMILY_DEBIAN: [
            '# DESTRUCTIVE: cryptsetup luksFormat erases the target device.',
            '# Back up data before proceeding.',
            '#   cryptsetup luksFormat /dev/sdX',
            '#   cryptsetup luksOpen /dev/sdX <name>',
            '# Add entry to /etc/crypttab',
        ],
        FAMILY_REDHAT: [
            '# DESTRUCTIVE: cryptsetup luksFormat erases the target device.',
            '# Back up data before proceeding.',
            '#   cryptsetup luksFormat /dev/sdX',
            '#   cryptsetup luksOpen /dev/sdX <name>',
            '# Add entry to /etc/crypttab',
        ],
        FAMILY_SUSE: [
            '# DESTRUCTIVE: cryptsetup luksFormat erases the target device.',
            '# Back up data before proceeding.',
            '#   cryptsetup luksFormat /dev/sdX',
            '#   cryptsetup luksOpen /dev/sdX <name>',
            '# Add entry to /etc/crypttab',
        ],
        FAMILY_ARCH: [
            '# DESTRUCTIVE: cryptsetup luksFormat erases the target device.',
            '# Back up data before proceeding.',
            '#   cryptsetup luksFormat /dev/sdX',
            '#   cryptsetup luksOpen /dev/sdX <name>',
            '# Add entry to /etc/crypttab',
        ],
        FAMILY_ALPINE: [
            '# DESTRUCTIVE: cryptsetup luksFormat erases the target device.',
            '# Back up data before proceeding.',
            '#   cryptsetup luksFormat /dev/sdX',
            '#   cryptsetup luksOpen /dev/sdX <name>',
            '# Add entry to /etc/crypttab',
        ],
    },
    verify={
        FAMILY_DEBIAN: [
            'command -v cryptsetup',
            'cryptsetup --version',
            'lsblk -f',
        ],
        FAMILY_REDHAT: [
            'command -v cryptsetup',
            'cryptsetup --version',
            'lsblk -f',
        ],
        FAMILY_SUSE: [
            'command -v cryptsetup',
            'cryptsetup --version',
            'lsblk -f',
        ],
        FAMILY_ARCH: [
            'command -v cryptsetup',
            'cryptsetup --version',
            'lsblk -f',
        ],
        FAMILY_ALPINE: [
            'command -v cryptsetup',
            'cryptsetup --version',
            'lsblk -f',
        ],
        FAMILY_GENTOO: [
            'command -v cryptsetup',
            'cryptsetup --version',
            'lsblk -f',
        ],
    },
    config_files=['/etc/crypttab'],
    notes='luksFormat is destructive; back up data first. For full-disk encryption, configure during OS install rather than retrofitting.',
    references=['https://gitlab.com/cryptsetup/cryptsetup'],
))

_register(RemediationEntry(
    tool_id='gnupg',
    display_name='GnuPG',
    purpose='OpenPGP cryptography (signing, encryption, key management).',
    primary_packages={
        FAMILY_DEBIAN: ['gnupg'],
        FAMILY_REDHAT: ['gnupg2'],
        FAMILY_SUSE: ['gpg2'],
        FAMILY_ARCH: ['gnupg'],
        FAMILY_ALPINE: ['gnupg'],
    },
    supporting_packages={
        FAMILY_DEBIAN: ['gnupg-agent', 'gnupg-utils'],
        FAMILY_REDHAT: ['gnupg2-smime'],
    },
    post_install={
        FAMILY_DEBIAN: [
            '# Generate a keypair for the operator:',
            '# gpg --full-generate-key',
        ],
        FAMILY_REDHAT: [
            '# Generate a keypair for the operator:',
            '# gpg --full-generate-key',
        ],
        FAMILY_SUSE: [
            '# Generate a keypair for the operator:',
            '# gpg --full-generate-key',
        ],
        FAMILY_ARCH: [
            '# Generate a keypair for the operator:',
            '# gpg --full-generate-key',
        ],
        FAMILY_ALPINE: [
            '# Generate a keypair for the operator:',
            '# gpg --full-generate-key',
        ],
        FAMILY_GENTOO: [
            '# Generate a keypair for the operator:',
            '# gpg --full-generate-key',
        ],
    },
    verify={
        FAMILY_DEBIAN: [
            'command -v gpg',
            'gpg --version',
            'gpg --version',
            'gpg --list-keys',
        ],
        FAMILY_REDHAT: [
            'command -v gpg',
            'gpg --version',
            'gpg --version',
            'gpg --list-keys',
        ],
        FAMILY_SUSE: [
            'command -v gpg',
            'gpg --version',
            'gpg --version',
            'gpg --list-keys',
        ],
        FAMILY_ARCH: [
            'command -v gpg',
            'gpg --version',
            'gpg --version',
            'gpg --list-keys',
        ],
        FAMILY_ALPINE: [
            'command -v gpg',
            'gpg --version',
            'gpg --version',
            'gpg --list-keys',
        ],
        FAMILY_GENTOO: [
            'command -v gpg',
            'gpg --version',
            'gpg --version',
            'gpg --list-keys',
        ],
    },
    config_files=['~/.gnupg/gpg.conf'],
    references=['https://gnupg.org/'],
))

_register(RemediationEntry(
    tool_id='openssl',
    display_name='OpenSSL',
    purpose='TLS/SSL cryptography toolkit and library.',
    primary_packages={
        FAMILY_DEBIAN: ['openssl'],
        FAMILY_REDHAT: ['openssl'],
        FAMILY_SUSE: ['openssl'],
        FAMILY_ARCH: ['openssl'],
        FAMILY_ALPINE: ['openssl'],
    },
    supporting_packages={
        FAMILY_DEBIAN: ['ca-certificates'],
        FAMILY_REDHAT: ['ca-certificates'],
        FAMILY_SUSE: ['ca-certificates'],
        FAMILY_ARCH: ['ca-certificates'],
        FAMILY_ALPINE: ['ca-certificates'],
    },
    verify={
        FAMILY_DEBIAN: [
            'command -v openssl',
            'openssl --version',
            'openssl version',
            'openssl version -d',
        ],
        FAMILY_REDHAT: [
            'command -v openssl',
            'openssl --version',
            'openssl version',
            'openssl version -d',
        ],
        FAMILY_SUSE: [
            'command -v openssl',
            'openssl --version',
            'openssl version',
            'openssl version -d',
        ],
        FAMILY_ARCH: [
            'command -v openssl',
            'openssl --version',
            'openssl version',
            'openssl version -d',
        ],
        FAMILY_ALPINE: [
            'command -v openssl',
            'openssl --version',
            'openssl version',
            'openssl version -d',
        ],
        FAMILY_GENTOO: [
            'command -v openssl',
            'openssl --version',
            'openssl version',
            'openssl version -d',
        ],
    },
    config_files=['/etc/ssl/openssl.cnf', '/etc/pki/tls/openssl.cnf'],
    notes='Modern TLS configuration: in [system_default_sect] set MinProtocol = TLSv1.2 and CipherString = DEFAULT@SECLEVEL=2.',
    references=['https://www.openssl.org/'],
))

_register(RemediationEntry(
    tool_id='borg',
    display_name='BorgBackup',
    purpose='Deduplicating, encrypted backup (NIST CP-9, ENISA NIS2 21.2(c)).',
    primary_packages={
        FAMILY_DEBIAN: ['borgbackup'],
        FAMILY_REDHAT: ['borgbackup'],
        FAMILY_SUSE: ['borgbackup'],
        FAMILY_ARCH: ['borg'],
        FAMILY_ALPINE: ['borgbackup'],
    },
    supporting_packages={
        FAMILY_REDHAT: ['epel-release'],
    },
    post_install={
        FAMILY_DEBIAN: [
            '# Initialize a repository:',
            '#   borg init --encryption=repokey-blake2 /path/to/repo',
            '#   borg create /path/to/repo::archive-{now} /home /etc /var',
        ],
        FAMILY_REDHAT: [
            '# Initialize a repository:',
            '#   borg init --encryption=repokey-blake2 /path/to/repo',
            '#   borg create /path/to/repo::archive-{now} /home /etc /var',
        ],
        FAMILY_SUSE: [
            '# Initialize a repository:',
            '#   borg init --encryption=repokey-blake2 /path/to/repo',
            '#   borg create /path/to/repo::archive-{now} /home /etc /var',
        ],
        FAMILY_ARCH: [
            '# Initialize a repository:',
            '#   borg init --encryption=repokey-blake2 /path/to/repo',
            '#   borg create /path/to/repo::archive-{now} /home /etc /var',
        ],
        FAMILY_ALPINE: [
            '# Initialize a repository:',
            '#   borg init --encryption=repokey-blake2 /path/to/repo',
            '#   borg create /path/to/repo::archive-{now} /home /etc /var',
        ],
    },
    verify={
        FAMILY_DEBIAN: [
            'command -v borg',
            'borg --version',
        ],
        FAMILY_REDHAT: [
            'command -v borg',
            'borg --version',
        ],
        FAMILY_SUSE: [
            'command -v borg',
            'borg --version',
        ],
        FAMILY_ARCH: [
            'command -v borg',
            'borg --version',
        ],
        FAMILY_ALPINE: [
            'command -v borg',
            'borg --version',
        ],
        FAMILY_GENTOO: [
            'command -v borg',
            'borg --version',
        ],
    },
    references=['https://www.borgbackup.org/'],
))

_register(RemediationEntry(
    tool_id='restic',
    display_name='restic',
    purpose='Fast, secure cross-platform backup (encrypted).',
    primary_packages={
        FAMILY_DEBIAN: ['restic'],
        FAMILY_REDHAT: ['restic'],
        FAMILY_SUSE: ['restic'],
        FAMILY_ARCH: ['restic'],
        FAMILY_ALPINE: ['restic'],
    },
    post_install={
        FAMILY_DEBIAN: [
            '# Initialize a repository:',
            '#   restic init --repo /path/to/repo',
            '#   restic backup --repo /path/to/repo /home /etc',
        ],
        FAMILY_REDHAT: [
            '# Initialize a repository:',
            '#   restic init --repo /path/to/repo',
            '#   restic backup --repo /path/to/repo /home /etc',
        ],
        FAMILY_SUSE: [
            '# Initialize a repository:',
            '#   restic init --repo /path/to/repo',
            '#   restic backup --repo /path/to/repo /home /etc',
        ],
        FAMILY_ARCH: [
            '# Initialize a repository:',
            '#   restic init --repo /path/to/repo',
            '#   restic backup --repo /path/to/repo /home /etc',
        ],
        FAMILY_ALPINE: [
            '# Initialize a repository:',
            '#   restic init --repo /path/to/repo',
            '#   restic backup --repo /path/to/repo /home /etc',
        ],
    },
    verify={
        FAMILY_DEBIAN: [
            'command -v restic',
            'restic --version',
        ],
        FAMILY_REDHAT: [
            'command -v restic',
            'restic --version',
        ],
        FAMILY_SUSE: [
            'command -v restic',
            'restic --version',
        ],
        FAMILY_ARCH: [
            'command -v restic',
            'restic --version',
        ],
        FAMILY_ALPINE: [
            'command -v restic',
            'restic --version',
        ],
        FAMILY_GENTOO: [
            'command -v restic',
            'restic --version',
        ],
    },
    references=['https://restic.net/'],
))

_register(RemediationEntry(
    tool_id='duplicity',
    display_name='Duplicity',
    purpose='GPG-encrypted bandwidth-efficient backups.',
    primary_packages={
        FAMILY_DEBIAN: ['duplicity'],
        FAMILY_REDHAT: ['duplicity'],
        FAMILY_SUSE: ['duplicity'],
        FAMILY_ARCH: ['duplicity'],
        FAMILY_ALPINE: ['duplicity'],
    },
    supporting_packages={
        FAMILY_REDHAT: ['epel-release'],
    },
    verify={
        FAMILY_DEBIAN: [
            'command -v duplicity',
            'duplicity --version',
        ],
        FAMILY_REDHAT: [
            'command -v duplicity',
            'duplicity --version',
        ],
        FAMILY_SUSE: [
            'command -v duplicity',
            'duplicity --version',
        ],
        FAMILY_ARCH: [
            'command -v duplicity',
            'duplicity --version',
        ],
        FAMILY_ALPINE: [
            'command -v duplicity',
            'duplicity --version',
        ],
        FAMILY_GENTOO: [
            'command -v duplicity',
            'duplicity --version',
        ],
    },
    references=['https://duplicity.gitlab.io/'],
))

_register(RemediationEntry(
    tool_id='suricata',
    display_name='Suricata',
    purpose='Network threat detection engine (IDS/IPS/NSM).',
    primary_packages={
        FAMILY_DEBIAN: ['suricata'],
        FAMILY_REDHAT: ['suricata'],
        FAMILY_SUSE: ['suricata'],
        FAMILY_ARCH: ['suricata'],
    },
    supporting_packages={
        FAMILY_REDHAT: ['epel-release'],
    },
    post_install={
        FAMILY_DEBIAN: [
            'suricata-update',
            '# Edit /etc/suricata/suricata.yaml; set HOME_NET and capture interface',
        ],
        FAMILY_REDHAT: [
            'suricata-update',
            '# Edit /etc/suricata/suricata.yaml; set HOME_NET and capture interface',
        ],
        FAMILY_SUSE: [
            'suricata-update',
            '# Edit /etc/suricata/suricata.yaml; set HOME_NET and capture interface',
        ],
        FAMILY_ARCH: [
            'suricata-update',
            '# Edit /etc/suricata/suricata.yaml; set HOME_NET and capture interface',
        ],
    },
    services=['suricata.service'],
    verify={
        FAMILY_DEBIAN: [
            'systemctl is-active suricata',
            'suricata --build-info',
        ],
        FAMILY_REDHAT: [
            'systemctl is-active suricata',
            'suricata --build-info',
        ],
        FAMILY_SUSE: [
            'systemctl is-active suricata',
            'suricata --build-info',
        ],
        FAMILY_ARCH: [
            'systemctl is-active suricata',
            'suricata --build-info',
        ],
    },
    config_files=['/etc/suricata/suricata.yaml'],
    references=['https://suricata.io/'],
))

_register(RemediationEntry(
    tool_id='snort',
    display_name='Snort',
    purpose='Open-source IDS/IPS (alternative to Suricata).',
    primary_packages={
        FAMILY_DEBIAN: ['snort'],
        FAMILY_REDHAT: ['snort'],
        FAMILY_ARCH: ['snort'],
    },
    supporting_packages={
        FAMILY_REDHAT: ['epel-release'],
    },
    post_install={
        FAMILY_DEBIAN: [
            '# Edit /etc/snort/snort.conf; set HOME_NET and rule paths',
        ],
        FAMILY_REDHAT: [
            '# Edit /etc/snort/snort.conf; set HOME_NET and rule paths',
        ],
        FAMILY_ARCH: [
            '# Edit /etc/snort/snort.conf; set HOME_NET and rule paths',
        ],
    },
    services=['snort.service'],
    verify={
        FAMILY_DEBIAN: [
            'systemctl is-active snort',
            'snort --version',
        ],
        FAMILY_REDHAT: [
            'systemctl is-active snort',
            'snort --version',
        ],
        FAMILY_ARCH: [
            'systemctl is-active snort',
            'snort --version',
        ],
    },
    config_files=['/etc/snort/snort.conf'],
    references=['https://www.snort.org/'],
))

_register(RemediationEntry(
    tool_id='zeek',
    display_name='Zeek (formerly Bro)',
    purpose='Network analysis framework / NSM platform.',
    primary_packages={
        FAMILY_DEBIAN: ['zeek'],
        FAMILY_REDHAT: ['zeek'],
        FAMILY_SUSE: ['zeek'],
        FAMILY_ARCH: ['zeek'],
    },
    supporting_packages={
        FAMILY_REDHAT: ['epel-release'],
    },
    post_install={
        FAMILY_DEBIAN: [
            'zeekctl deploy',
        ],
        FAMILY_REDHAT: [
            'zeekctl deploy',
        ],
        FAMILY_SUSE: [
            'zeekctl deploy',
        ],
        FAMILY_ARCH: [
            'zeekctl deploy',
        ],
    },
    services=['zeek.service'],
    verify={
        FAMILY_DEBIAN: [
            'zeek --version',
            'zeekctl status',
        ],
        FAMILY_REDHAT: [
            'zeek --version',
            'zeekctl status',
        ],
        FAMILY_SUSE: [
            'zeek --version',
            'zeekctl status',
        ],
        FAMILY_ARCH: [
            'zeek --version',
            'zeekctl status',
        ],
    },
    config_files=['/etc/zeek/node.cfg'],
    references=['https://zeek.org/'],
))

_register(RemediationEntry(
    tool_id='osquery',
    display_name='osquery',
    purpose='OS as a relational DB (CISA BOD 23-01 asset visibility).',
    primary_packages={
        FAMILY_DEBIAN: ['osquery'],
        FAMILY_REDHAT: ['osquery'],
    },
    post_install={
        FAMILY_DEBIAN: [
            '# Default config in /etc/osquery/osquery.conf',
        ],
        FAMILY_REDHAT: [
            '# Default config in /etc/osquery/osquery.conf',
        ],
    },
    services=['osqueryd.service'],
    verify={
        FAMILY_DEBIAN: [
            'systemctl is-active osqueryd',
            'osqueryi --version',
        ],
        FAMILY_REDHAT: [
            'systemctl is-active osqueryd',
            'osqueryi --version',
        ],
    },
    config_files=['/etc/osquery/osquery.conf'],
    notes='Distribution packages may be outdated. The official osquery repo at osquery.io provides current builds for major platforms.',
    references=['https://osquery.io/'],
))

_register(RemediationEntry(
    tool_id='falco',
    display_name='Falco',
    purpose='Runtime threat detection for containers and Linux hosts.',
    primary_packages={
        FAMILY_DEBIAN: ['falco'],
        FAMILY_REDHAT: ['falco'],
    },
    supporting_packages={
        FAMILY_DEBIAN: ['dkms', 'linux-headers-generic'],
        FAMILY_REDHAT: ['kernel-devel'],
    },
    post_install={
        FAMILY_DEBIAN: [
            '# Falco postinst will build the kernel module via DKMS',
        ],
        FAMILY_REDHAT: [
            '# Reload kernel modules:',
            'modprobe falco',
        ],
    },
    services=['falco.service'],
    verify={
        FAMILY_DEBIAN: [
            'systemctl is-active falco',
            'falco --version',
        ],
        FAMILY_REDHAT: [
            'systemctl is-active falco',
            'falco --version',
        ],
    },
    config_files=['/etc/falco/falco.yaml', '/etc/falco/falco_rules.yaml'],
    notes='Falco is published from the falcosecurity.org repository, not distribution mainstream repos. Add the repo first; see references.',
    references=['https://falco.org/'],
))

_register(RemediationEntry(
    tool_id='wazuh-agent',
    display_name='Wazuh Agent',
    purpose='Open-source XDR / SIEM agent (HIDS, FIM, SCA).',
    primary_packages={
        FAMILY_DEBIAN: ['wazuh-agent'],
        FAMILY_REDHAT: ['wazuh-agent'],
        FAMILY_SUSE: ['wazuh-agent'],
    },
    post_install={
        FAMILY_DEBIAN: [
            '# Set the manager address:',
            "#   sed -i 's|<address>.*</address>|<address>WAZUH-MANAGER-IP</address>|' /var/ossec/etc/ossec.conf",
        ],
        FAMILY_REDHAT: [
            '# Set the manager address:',
            "#   sed -i 's|<address>.*</address>|<address>WAZUH-MANAGER-IP</address>|' /var/ossec/etc/ossec.conf",
        ],
        FAMILY_SUSE: [
            '# Set the manager address:',
            "#   sed -i 's|<address>.*</address>|<address>WAZUH-MANAGER-IP</address>|' /var/ossec/etc/ossec.conf",
        ],
    },
    services=['wazuh-agent.service'],
    verify={
        FAMILY_DEBIAN: [
            'systemctl is-active wazuh-agent',
            '/var/ossec/bin/wazuh-control status',
        ],
        FAMILY_REDHAT: [
            'systemctl is-active wazuh-agent',
            '/var/ossec/bin/wazuh-control status',
        ],
        FAMILY_SUSE: [
            'systemctl is-active wazuh-agent',
            '/var/ossec/bin/wazuh-control status',
        ],
    },
    config_files=['/var/ossec/etc/ossec.conf'],
    notes='Requires the Wazuh repository; see references for setup steps.',
    references=['https://documentation.wazuh.com/'],
))

_register(RemediationEntry(
    tool_id='syft',
    display_name='Syft (SBOM generator)',
    purpose='Generate SPDX/CycloneDX SBOMs (CISA SbD, NIST 800-161 SR-4).',
    verify={
        FAMILY_DEBIAN: [
            'syft version',
        ],
        FAMILY_REDHAT: [
            'syft version',
        ],
        FAMILY_SUSE: [
            'syft version',
        ],
        FAMILY_ARCH: [
            'syft version',
        ],
        FAMILY_ALPINE: [
            'syft version',
        ],
        FAMILY_GENTOO: [
            'syft version',
        ],
    },
    notes='Install via official script: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin\nThen: syft <image-or-dir> -o spdx-json > sbom.spdx.json',
    references=['https://github.com/anchore/syft'],
))

_register(RemediationEntry(
    tool_id='trivy',
    display_name='Trivy (vulnerability scanner)',
    purpose='Container and IaC vulnerability scanner.',
    primary_packages={
        FAMILY_DEBIAN: ['trivy'],
        FAMILY_REDHAT: ['trivy'],
    },
    post_install={
        FAMILY_DEBIAN: [
            '# Add Aqua Security repo for current builds:',
            '# wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg',
            '# echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(. /etc/os-release; echo $VERSION_CODENAME) main" > /etc/apt/sources.list.d/trivy.list',
        ],
    },
    verify={
        FAMILY_DEBIAN: [
            'trivy --version',
        ],
        FAMILY_REDHAT: [
            'trivy --version',
        ],
    },
    references=['https://github.com/aquasecurity/trivy'],
))

_register(RemediationEntry(
    tool_id='grype',
    display_name='Grype (vulnerability scanner)',
    purpose='Container/filesystem vulnerability scanner.',
    verify={
        FAMILY_DEBIAN: [
            'grype version',
        ],
        FAMILY_REDHAT: [
            'grype version',
        ],
        FAMILY_SUSE: [
            'grype version',
        ],
        FAMILY_ARCH: [
            'grype version',
        ],
        FAMILY_ALPINE: [
            'grype version',
        ],
        FAMILY_GENTOO: [
            'grype version',
        ],
    },
    notes='Install via official script: curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin',
    references=['https://github.com/anchore/grype'],
))

_register(RemediationEntry(
    tool_id='wireguard',
    display_name='WireGuard',
    purpose='Modern VPN (NIST SC-8, GDPR Article 44 transfers).',
    primary_packages={
        FAMILY_DEBIAN: ['wireguard'],
        FAMILY_REDHAT: ['wireguard-tools'],
        FAMILY_SUSE: ['wireguard-tools'],
        FAMILY_ARCH: ['wireguard-tools'],
    },
    supporting_packages={
        FAMILY_DEBIAN: ['wireguard-tools'],
        FAMILY_REDHAT: ['wireguard-tools-doc'],
    },
    post_install={
        FAMILY_DEBIAN: [
            '# Generate keypair:',
            'wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey',
            'chmod 600 /etc/wireguard/privatekey',
        ],
        FAMILY_REDHAT: [
            '# Generate keypair:',
            'wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey',
            'chmod 600 /etc/wireguard/privatekey',
        ],
        FAMILY_SUSE: [
            '# Generate keypair:',
            'wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey',
            'chmod 600 /etc/wireguard/privatekey',
        ],
        FAMILY_ARCH: [
            '# Generate keypair:',
            'wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey',
            'chmod 600 /etc/wireguard/privatekey',
        ],
    },
    services=['wg-quick@wg0.service'],
    verify={
        FAMILY_DEBIAN: [
            'wg show',
            'ip link show',
        ],
        FAMILY_REDHAT: [
            'wg show',
            'ip link show',
        ],
        FAMILY_SUSE: [
            'wg show',
            'ip link show',
        ],
        FAMILY_ARCH: [
            'wg show',
            'ip link show',
        ],
    },
    config_files=['/etc/wireguard/wg0.conf'],
    references=['https://www.wireguard.com/'],
))

_register(RemediationEntry(
    tool_id='shellcheck',
    display_name='ShellCheck (shell SAST)',
    purpose='Static analyzer for shell scripts (ISO27001 A.8.28).',
    primary_packages={
        FAMILY_DEBIAN: ['shellcheck'],
        FAMILY_REDHAT: ['ShellCheck'],
        FAMILY_SUSE: ['ShellCheck'],
        FAMILY_ARCH: ['shellcheck'],
        FAMILY_ALPINE: ['shellcheck'],
    },
    verify={
        FAMILY_DEBIAN: [
            'command -v shellcheck',
            'shellcheck --version',
        ],
        FAMILY_REDHAT: [
            'command -v shellcheck',
            'shellcheck --version',
        ],
        FAMILY_SUSE: [
            'command -v shellcheck',
            'shellcheck --version',
        ],
        FAMILY_ARCH: [
            'command -v shellcheck',
            'shellcheck --version',
        ],
        FAMILY_ALPINE: [
            'command -v shellcheck',
            'shellcheck --version',
        ],
        FAMILY_GENTOO: [
            'command -v shellcheck',
            'shellcheck --version',
        ],
    },
    references=['https://www.shellcheck.net/'],
))

_register(RemediationEntry(
    tool_id='bandit',
    display_name='Bandit (Python SAST)',
    purpose='Security linter for Python code (ISO27001 A.8.28).',
    primary_packages={
        FAMILY_DEBIAN: ['bandit'],
        FAMILY_REDHAT: ['bandit'],
        FAMILY_SUSE: ['python3-bandit'],
        FAMILY_ARCH: ['bandit'],
        FAMILY_ALPINE: ['py3-bandit'],
    },
    verify={
        FAMILY_DEBIAN: [
            'command -v bandit',
            'bandit --version',
        ],
        FAMILY_REDHAT: [
            'command -v bandit',
            'bandit --version',
        ],
        FAMILY_SUSE: [
            'command -v bandit',
            'bandit --version',
        ],
        FAMILY_ARCH: [
            'command -v bandit',
            'bandit --version',
        ],
        FAMILY_ALPINE: [
            'command -v bandit',
            'bandit --version',
        ],
        FAMILY_GENTOO: [
            'command -v bandit',
            'bandit --version',
        ],
    },
    references=['https://github.com/PyCQA/bandit'],
))

_register(RemediationEntry(
    tool_id='rsyslog',
    display_name='rsyslog',
    purpose='System logging daemon with remote forwarding (PCI 10.5).',
    primary_packages={
        FAMILY_DEBIAN: ['rsyslog'],
        FAMILY_REDHAT: ['rsyslog'],
        FAMILY_SUSE: ['rsyslog'],
        FAMILY_ARCH: ['rsyslog'],
    },
    supporting_packages={
        FAMILY_DEBIAN: ['rsyslog-relp'],
        FAMILY_REDHAT: ['rsyslog-relp'],
    },
    post_install={
        FAMILY_DEBIAN: [
            '# For remote forwarding to a SIEM, add to /etc/rsyslog.d/50-remote.conf:',
            '#   *.* @@logserver.example.com:6514',
            '# Then reload:',
            '#   systemctl reload rsyslog',
        ],
        FAMILY_REDHAT: [
            '# For remote forwarding to a SIEM, add to /etc/rsyslog.d/50-remote.conf:',
            '#   *.* @@logserver.example.com:6514',
            '# Then reload:',
            '#   systemctl reload rsyslog',
        ],
        FAMILY_SUSE: [
            '# For remote forwarding to a SIEM, add to /etc/rsyslog.d/50-remote.conf:',
            '#   *.* @@logserver.example.com:6514',
            '# Then reload:',
            '#   systemctl reload rsyslog',
        ],
        FAMILY_ARCH: [
            '# For remote forwarding to a SIEM, add to /etc/rsyslog.d/50-remote.conf:',
            '#   *.* @@logserver.example.com:6514',
            '# Then reload:',
            '#   systemctl reload rsyslog',
        ],
    },
    services=['rsyslog.service'],
    verify={
        FAMILY_DEBIAN: [
            'systemctl is-active rsyslog',
            "logger 'Test message from rsyslog'",
        ],
        FAMILY_REDHAT: [
            'systemctl is-active rsyslog',
            "logger 'Test message from rsyslog'",
        ],
        FAMILY_SUSE: [
            'systemctl is-active rsyslog',
            "logger 'Test message from rsyslog'",
        ],
        FAMILY_ARCH: [
            'systemctl is-active rsyslog',
            "logger 'Test message from rsyslog'",
        ],
    },
    config_files=['/etc/rsyslog.conf', '/etc/rsyslog.d/'],
    references=['https://www.rsyslog.com/'],
))

_register(RemediationEntry(
    tool_id='logrotate',
    display_name='logrotate',
    purpose='Log rotation manager (PCI 10.7 retention).',
    primary_packages={
        FAMILY_DEBIAN: ['logrotate'],
        FAMILY_REDHAT: ['logrotate'],
        FAMILY_SUSE: ['logrotate'],
        FAMILY_ARCH: ['logrotate'],
        FAMILY_ALPINE: ['logrotate'],
    },
    post_install={
        FAMILY_DEBIAN: [
            '# Default config in /etc/logrotate.conf',
            '# Per-service configs in /etc/logrotate.d/',
            '# Test current config:',
            '#   logrotate -d /etc/logrotate.conf',
        ],
        FAMILY_REDHAT: [
            '# Default config in /etc/logrotate.conf',
            '# Per-service configs in /etc/logrotate.d/',
            '# Test current config:',
            '#   logrotate -d /etc/logrotate.conf',
        ],
        FAMILY_SUSE: [
            '# Default config in /etc/logrotate.conf',
            '# Per-service configs in /etc/logrotate.d/',
            '# Test current config:',
            '#   logrotate -d /etc/logrotate.conf',
        ],
        FAMILY_ARCH: [
            '# Default config in /etc/logrotate.conf',
            '# Per-service configs in /etc/logrotate.d/',
            '# Test current config:',
            '#   logrotate -d /etc/logrotate.conf',
        ],
        FAMILY_ALPINE: [
            '# Default config in /etc/logrotate.conf',
            '# Per-service configs in /etc/logrotate.d/',
            '# Test current config:',
            '#   logrotate -d /etc/logrotate.conf',
        ],
        FAMILY_GENTOO: [
            '# Default config in /etc/logrotate.conf',
            '# Per-service configs in /etc/logrotate.d/',
            '# Test current config:',
            '#   logrotate -d /etc/logrotate.conf',
        ],
    },
    services=['logrotate.timer'],
    verify={
        FAMILY_DEBIAN: [
            'logrotate --version',
            'logrotate -d /etc/logrotate.conf 2>&1 | head -20',
        ],
        FAMILY_REDHAT: [
            'logrotate --version',
            'logrotate -d /etc/logrotate.conf 2>&1 | head -20',
        ],
        FAMILY_SUSE: [
            'logrotate --version',
            'logrotate -d /etc/logrotate.conf 2>&1 | head -20',
        ],
        FAMILY_ARCH: [
            'logrotate --version',
            'logrotate -d /etc/logrotate.conf 2>&1 | head -20',
        ],
        FAMILY_ALPINE: [
            'logrotate --version',
            'logrotate -d /etc/logrotate.conf 2>&1 | head -20',
        ],
        FAMILY_GENTOO: [
            'logrotate --version',
            'logrotate -d /etc/logrotate.conf 2>&1 | head -20',
        ],
    },
    config_files=['/etc/logrotate.conf', '/etc/logrotate.d/'],
    references=['https://github.com/logrotate/logrotate'],
))

_register(RemediationEntry(
    tool_id='audisp-remote',
    display_name='audisp-remote (remote audit forwarding)',
    purpose='Remote audit log forwarding (NIST AU-9(2), PCI 10.5.3).',
    primary_packages={
        FAMILY_DEBIAN: ['audispd-plugins'],
        FAMILY_REDHAT: ['audispd-plugins'],
        FAMILY_SUSE: ['audit-secondary'],
    },
    post_install={
        FAMILY_DEBIAN: [
            '# Edit /etc/audit/audisp-remote.conf:',
            '#   remote_server = audit.example.com',
            '#   port = 60',
            '#   transport = tcp',
            '# Activate the plugin in /etc/audit/plugins.d/au-remote.conf:',
            '#   active = yes',
            'systemctl restart auditd',
        ],
        FAMILY_REDHAT: [
            '# Edit /etc/audit/audisp-remote.conf:',
            '#   remote_server = audit.example.com',
            '#   port = 60',
            '#   transport = tcp',
            '# Activate the plugin in /etc/audit/plugins.d/au-remote.conf:',
            '#   active = yes',
            'systemctl restart auditd',
        ],
        FAMILY_SUSE: [
            '# Edit /etc/audit/audisp-remote.conf:',
            '#   remote_server = audit.example.com',
            '#   port = 60',
            '#   transport = tcp',
            '# Activate the plugin in /etc/audit/plugins.d/au-remote.conf:',
            '#   active = yes',
            'systemctl restart auditd',
        ],
    },
    verify={
        FAMILY_DEBIAN: [
            "test -f /etc/audit/audisp-remote.conf && echo 'Config present'",
            "grep -E '^(active|remote_server)' /etc/audit/plugins.d/au-remote.conf",
        ],
        FAMILY_REDHAT: [
            "test -f /etc/audit/audisp-remote.conf && echo 'Config present'",
            "grep -E '^(active|remote_server)' /etc/audit/plugins.d/au-remote.conf",
        ],
        FAMILY_SUSE: [
            "test -f /etc/audit/audisp-remote.conf && echo 'Config present'",
            "grep -E '^(active|remote_server)' /etc/audit/plugins.d/au-remote.conf",
        ],
    },
    config_files=['/etc/audit/audisp-remote.conf', '/etc/audit/plugins.d/au-remote.conf'],
    references=['https://github.com/linux-audit/audit-userspace'],
))

_register(RemediationEntry(
    tool_id='sysstat',
    display_name='sysstat (sar, iostat, pidstat)',
    purpose='System performance monitoring tools.',
    primary_packages={
        FAMILY_DEBIAN: ['sysstat'],
        FAMILY_REDHAT: ['sysstat'],
        FAMILY_SUSE: ['sysstat'],
        FAMILY_ARCH: ['sysstat'],
        FAMILY_ALPINE: ['sysstat'],
    },
    post_install={
        FAMILY_DEBIAN: [
            '# Enable data collection:',
            'sed -i \'s/^ENABLED="false"/ENABLED="true"/\' /etc/default/sysstat',
        ],
        FAMILY_REDHAT: [
        ],
        FAMILY_SUSE: [
        ],
        FAMILY_ARCH: [
        ],
        FAMILY_ALPINE: [
        ],
    },
    services=['sysstat.service'],
    verify={
        FAMILY_DEBIAN: [
            'sar -V',
            'iostat -V',
        ],
        FAMILY_REDHAT: [
            'sar -V',
            'iostat -V',
        ],
        FAMILY_SUSE: [
            'sar -V',
            'iostat -V',
        ],
        FAMILY_ARCH: [
            'sar -V',
            'iostat -V',
        ],
        FAMILY_ALPINE: [
            'sar -V',
            'iostat -V',
        ],
        FAMILY_GENTOO: [
            'sar -V',
            'iostat -V',
        ],
    },
    config_files=['/etc/sysstat/sysstat', '/etc/default/sysstat'],
    references=['http://sebastien.godard.pagesperso-orange.fr/'],
))

_register(RemediationEntry(
    tool_id='sudo',
    display_name='sudo',
    purpose='Privilege delegation (NIST AC-6, PCI 8).',
    primary_packages={
        FAMILY_DEBIAN: ['sudo'],
        FAMILY_REDHAT: ['sudo'],
        FAMILY_SUSE: ['sudo'],
        FAMILY_ARCH: ['sudo'],
        FAMILY_ALPINE: ['sudo'],
    },
    supporting_packages={
        FAMILY_DEBIAN: ['sudo-ldap'],
    },
    post_install={
        FAMILY_DEBIAN: [
            '# Edit /etc/sudoers using:',
            '#   visudo',
            '# Recommended: use sudoers.d for drop-in files',
            '#   visudo -f /etc/sudoers.d/wheel',
        ],
        FAMILY_REDHAT: [
            '# Edit /etc/sudoers using:',
            '#   visudo',
            '# Recommended: use sudoers.d for drop-in files',
            '#   visudo -f /etc/sudoers.d/wheel',
        ],
        FAMILY_SUSE: [
            '# Edit /etc/sudoers using:',
            '#   visudo',
            '# Recommended: use sudoers.d for drop-in files',
            '#   visudo -f /etc/sudoers.d/wheel',
        ],
        FAMILY_ARCH: [
            '# Edit /etc/sudoers using:',
            '#   visudo',
            '# Recommended: use sudoers.d for drop-in files',
            '#   visudo -f /etc/sudoers.d/wheel',
        ],
        FAMILY_ALPINE: [
            '# Edit /etc/sudoers using:',
            '#   visudo',
            '# Recommended: use sudoers.d for drop-in files',
            '#   visudo -f /etc/sudoers.d/wheel',
        ],
        FAMILY_GENTOO: [
            '# Edit /etc/sudoers using:',
            '#   visudo',
            '# Recommended: use sudoers.d for drop-in files',
            '#   visudo -f /etc/sudoers.d/wheel',
        ],
    },
    verify={
        FAMILY_DEBIAN: [
            'sudo --version',
            'visudo -c',
        ],
        FAMILY_REDHAT: [
            'sudo --version',
            'visudo -c',
        ],
        FAMILY_SUSE: [
            'sudo --version',
            'visudo -c',
        ],
        FAMILY_ARCH: [
            'sudo --version',
            'visudo -c',
        ],
        FAMILY_ALPINE: [
            'sudo --version',
            'visudo -c',
        ],
        FAMILY_GENTOO: [
            'sudo --version',
            'visudo -c',
        ],
    },
    config_files=['/etc/sudoers', '/etc/sudoers.d/'],
    references=['https://www.sudo.ws/'],
))

_register(RemediationEntry(
    tool_id='cron',
    display_name='cron / cronie / dcron',
    purpose='Job scheduling daemon.',
    primary_packages={
        FAMILY_DEBIAN: ['cron'],
        FAMILY_REDHAT: ['cronie'],
        FAMILY_SUSE: ['cron'],
        FAMILY_ARCH: ['cronie'],
        FAMILY_ALPINE: ['cronie'],
    },
    supporting_packages={
        FAMILY_DEBIAN: ['anacron'],
    },
    services=['cron.service', 'crond.service', 'cronie.service'],
    verify={
        FAMILY_DEBIAN: [
            'systemctl is-active cron',
            'crontab -l 2>/dev/null',
        ],
        FAMILY_REDHAT: [
            'systemctl is-active crond',
            'crontab -l 2>/dev/null',
        ],
        FAMILY_SUSE: [
            'systemctl is-active cron',
            'crontab -l 2>/dev/null',
        ],
        FAMILY_ARCH: [
            'systemctl is-active cronie',
            'crontab -l 2>/dev/null',
        ],
        FAMILY_ALPINE: [
            'rc-service crond status',
        ],
    },
    config_files=['/etc/crontab', '/etc/cron.d/'],
    notes='Service name varies: cron (Debian/SUSE), crond (RHEL/Alpine), cronie (Arch).',
    references=['https://man7.org/linux/man-pages/man8/cron.8.html'],
))


# ----------------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------------

def list_tools() -> List[str]:
    """Return all tool_ids registered in the library."""
    return sorted(_LIBRARY.keys())


def get_entry(tool_id: str) -> Optional[RemediationEntry]:
    """Return the raw RemediationEntry for a tool_id, or None."""
    return _LIBRARY.get(tool_id)


def _resolve_family(os_info) -> str:
    """Resolve OS family string from an OSInfo or fall back to live detect."""
    if os_info is not None and hasattr(os_info, "family"):
        return os_info.family or FAMILY_UNKNOWN
    # Lazy import so this module doesn't hard-fail if os_detection is absent
    try:
        from shared_components.os_detection import detect_os
        return detect_os().family or FAMILY_UNKNOWN
    except Exception:
        return FAMILY_UNKNOWN


def get_remediation(
    tool_id: str,
    os_info=None,
    *,
    include_verify: bool = True,
    include_supporting: bool = True,
    include_references: bool = True,
) -> Optional[str]:
    """Return a complete, distro-aware remediation string for tool_id.

    Args:
        tool_id: Stable identifier registered in the library.
        os_info: Optional OSInfo object from shared_components.os_detection.
            If omitted, performs live detection.
        include_verify: Append a "Verify:" section with verification commands.
        include_supporting: Include supporting_packages with primary install.
        include_references: Append a "See:" section with documentation URLs.

    Returns:
        Multi-line remediation string, or None if tool_id is not in the
        library. Callers should fall back to their own remediation text
        if None is returned.
    """
    entry = _LIBRARY.get(tool_id)
    if entry is None:
        return None

    family = _resolve_family(os_info)

    # 1. Install command(s)
    primary = entry.primary_packages.get(family, [])
    supporting = (
        entry.supporting_packages.get(family, [])
        if include_supporting else []
    )
    all_pkgs = list(primary) + list(supporting)

    if not all_pkgs and family != FAMILY_UNKNOWN:
        # No packages registered for this family - try to provide guidance
        # by showing the install command set for any family that has one.
        any_family_with_pkgs = next(
            (f for f in ALL_FAMILIES
             if entry.primary_packages.get(f)),
            None,
        )
        if any_family_with_pkgs:
            install_line = (
                f"# {entry.display_name} is not packaged for {family}; "
                f"install on {any_family_with_pkgs} via:\n"
                f"#   {_format_install(any_family_with_pkgs, entry.primary_packages.get(any_family_with_pkgs, []))}"
            )
        else:
            install_line = (
                f"# {entry.display_name}: refer to upstream documentation; "
                f"see {entry.references[0] if entry.references else '<vendor docs>'}"
            )
    else:
        install_cmd = _format_install(family, all_pkgs)
        if not install_cmd and family == FAMILY_UNKNOWN:
            # Show a representative command from one family
            install_line = (
                f"# Install {entry.display_name} (family unknown; "
                f"use your distribution's package manager):\n"
                f"#   Debian/Ubuntu: "
                f"{_format_install(FAMILY_DEBIAN, entry.primary_packages.get(FAMILY_DEBIAN, [tool_id]))}\n"
                f"#   RHEL family:   "
                f"{_format_install(FAMILY_REDHAT, entry.primary_packages.get(FAMILY_REDHAT, [tool_id]))}"
            )
        else:
            install_line = install_cmd

    # 2. Post-install configuration
    post_lines = entry.post_install.get(family, []) or []
    # Fallback to any family if none registered for this one
    if not post_lines:
        for f in ALL_FAMILIES:
            if entry.post_install.get(f):
                post_lines = entry.post_install[f]
                break

    # 3. Service enable/start
    service_lines: List[str] = []
    if entry.services:
        for svc in entry.services:
            service_lines.append(f"systemctl enable --now {svc}")

    # 4. Verification
    verify_lines = entry.verify.get(family, []) or []
    if not verify_lines and include_verify:
        for f in ALL_FAMILIES:
            if entry.verify.get(f):
                verify_lines = entry.verify[f]
                break

    # 5. Compose the final remediation text
    out: List[str] = []
    out.append(f"Install {entry.display_name}:")
    if install_line:
        out.append(f"  {install_line}")

    if post_lines:
        out.append("")
        out.append("Configure:")
        for line in post_lines:
            out.append(f"  {line}")

    if service_lines:
        out.append("")
        out.append("Enable and start service(s):")
        for line in service_lines:
            out.append(f"  {line}")

    if include_verify and verify_lines:
        out.append("")
        out.append("Verify:")
        for line in verify_lines:
            out.append(f"  {line}")

    if entry.notes:
        out.append("")
        out.append(f"Notes: {entry.notes}")

    if include_references and entry.references:
        out.append("")
        out.append("See: " + " | ".join(entry.references))

    return "\n".join(out)


__all__ = [
    "RemediationEntry",
    "get_remediation",
    "get_removal_remediation",
    "get_patch_remediation",
    "get_entry",
    "list_tools",
    "FAMILY_DEBIAN", "FAMILY_REDHAT", "FAMILY_SUSE",
    "FAMILY_ARCH", "FAMILY_ALPINE", "FAMILY_GENTOO",
    "FAMILY_UNKNOWN",
]
