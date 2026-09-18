"""
host_facts.py - Cross-module canonical host facts registry.

SYNOPSIS
    A single canonical source-of-truth for "host facts" that multiple
    audit modules query. Builds on v3.6 helper caching by moving up one
    level: instead of caching primitives (command_available,
    systemd_active), this module caches derived facts (FIM_database_present,
    auditd_active, FIPS_enabled, etc.) that multiple modules consult.

DESCRIPTION
    During a single audit run, modules across the framework repeatedly
    derive the same higher-order facts about the host:
      - "Is AIDE installed and active?" (HIPAA, PCI, ISO27001, GDPR all check)
      - "Is FIPS mode enabled?" (NSA, CMMC, ENISA, GDPR, NIST all check)
      - "Is auditd active and configured?" (every module)
      - "Is a backup tool present?" (HIPAA, PCI, NIST, GDPR, SOC2 all check)

    Pre-v3.7, each module re-computed these facts from raw helpers. v3.7
    introduces a single `HostFacts` dataclass populated once at audit
    start and stored in shared_data["host_facts"] for module consumption.

    Modules can:
      1. Read facts directly: shared_data["host_facts"].auditd_active
      2. Use legacy helpers: helpers.systemd_active("auditd.service") == "active"
    Both paths produce identical results; helpers are now a fallback.

PARAMETERS
    Public API:
        compute_host_facts(os_info, helpers) -> HostFacts
        HostFacts dataclass - typed, immutable record of host state

EXAMPLES
    >>> from shared_components.host_facts import compute_host_facts
    >>> from shared_components import os_detection, module_helpers
    >>> facts = compute_host_facts(os_detection.detect_os(), module_helpers)
    >>> facts.auditd_active
    True
    >>> facts.fim_database_present
    True
    >>> facts.fips_enabled
    False

NOTES
    Version: 3.7
    Stdlib only.
    Computation is read-only; no state mutation occurs.
    All fact-derivation logic uses module_helpers (which itself uses v3.6
    caching), so compute_host_facts is fast on first call and free on
    subsequent calls.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import FrozenSet, Optional


@dataclass(frozen=True)
class HostFacts:
    """Immutable record of derived host facts.

    All fields are computed once at audit start. Consumers should treat
    instances as immutable (the dataclass is frozen=True).

    Field naming convention:
        - <thing>_active: a service is currently in 'active' state
        - <thing>_present: an artifact (file/db/binary) exists
        - <thing>_enabled: a configuration setting is on
        - <thing>_count: integer count of an inventory
        - <thing>_set: FrozenSet of items in an inventory
    """

    # ---- Identity ----------------------------------------------------------
    distro_id: str = ""              # ubuntu, rhel, debian, fedora, alpine, etc.
    distro_family: str = ""          # debian, redhat, suse, arch, alpine
    distro_version: str = ""         # 24.04, 9, 12, etc.
    is_container: bool = False        # /proc/1/cgroup contains docker/lxc/etc.
    is_vm: bool = False               # systemd-detect-virt indicates VM

    # ---- File integrity monitoring (FIM) -----------------------------------
    fim_database_present: bool = False           # Any FIM DB file present
    fim_tool: str = ""                           # AIDE | Tripwire | Samhain | OSSEC | Wazuh | ""
    aide_present: bool = False                   # /var/lib/aide/aide.db*
    tripwire_present: bool = False               # /var/lib/tripwire/tw.db
    samhain_present: bool = False                # /var/lib/samhain/samhain_file
    ossec_present: bool = False                  # /var/ossec/etc/ossec.conf
    wazuh_present: bool = False                  # Wazuh agent present

    # ---- Audit infrastructure ----------------------------------------------
    auditd_active: bool = False                  # auditd.service active
    audit_rules_present: bool = False            # /etc/audit/rules.d/*.rules
    audit_rules_immutable: bool = False          # -e 2 in rules
    audit_rules_text: str = ""                   # concatenated rules content (for substring checks)
    journald_persistent: bool = False            # /var/log/journal exists
    journald_seal: bool = False                  # FSS sealing on (Seal=yes or default)

    # ---- Cryptography ------------------------------------------------------
    fips_enabled: bool = False                   # crypto.fips_enabled = 1
    crypto_policy: str = ""                      # FIPS | FUTURE | DEFAULT | LEGACY | ""
    fips_aligned: bool = False                   # FIPS or FUTURE policy
    openssl_3x: bool = False                     # OpenSSL 3.x
    fips_indicator_files: int = 0                # 0-3, count of /proc + /etc/system-fips + crypto-policies

    # ---- Mandatory Access Control ------------------------------------------
    selinux_enforcing: bool = False              # getenforce == Enforcing
    selinux_permissive: bool = False             # getenforce == Permissive
    apparmor_active: bool = False                # aa-status command available
    mac_active: bool = False                     # selinux_enforcing or apparmor_active

    # ---- Firewall and Network ----------------------------------------------
    firewall_active: bool = False                # Any firewall active
    firewall_tool: str = ""                      # ufw | firewalld | nftables | iptables | ""
    ufw_active: bool = False
    firewalld_active: bool = False
    nftables_present: bool = False               # nft binary available
    nftables_default_drop: bool = False          # input chain default drop
    listening_external_count: int = 0            # Non-loopback TCP listeners

    # ---- Authentication ----------------------------------------------------
    ssh_root_permitted: bool = True              # Default safe-side
    ssh_password_auth_enabled: bool = True        # Default safe-side
    ssh_pubkey_only: bool = False                # PasswordAuthentication=no
    pam_mfa_present: bool = False                # PAM MFA module detected
    pam_mfa_module: str = ""                     # google_authenticator | yubico | u2f | duo | oath | ""
    pam_lockout_present: bool = False            # pam_faillock or pam_tally2

    # ---- Patching ----------------------------------------------------------
    auto_patch_active: bool = False              # unattended-upgrades or dnf-automatic
    auto_patch_tool: str = ""                    # unattended-upgrades | dnf-automatic | ""

    # ---- Time synchronization ----------------------------------------------
    time_sync_active: bool = False               # chrony/ntp/timesyncd active
    time_sync_tool: str = ""                     # chrony | ntp | timesyncd | ""

    # ---- Centralized logging -----------------------------------------------
    rsyslog_remote: bool = False                 # @@ or omfwd in config
    syslog_ng_remote: bool = False               # syslog-ng remote dest
    journal_upload: bool = False                 # systemd-journal-upload active
    siem_forwarding: bool = False                # any centralized log path

    # ---- Storage encryption ------------------------------------------------
    luks_present: bool = False                   # crypt-type devices in lsblk
    swap_in_use: bool = False                    # /proc/swaps has entries
    swap_encrypted: bool = False                 # swap dev is /dev/mapper or crypttab
    fstrim_timer_active: bool = False            # fstrim.timer
    has_ssd: bool = False                        # rotational=0 device present

    # ---- Container/orchestration -------------------------------------------
    container_runtime: str = ""                  # docker | podman | containerd | crio | ""
    container_runtime_active: bool = False
    k8s_present: bool = False                    # kubectl/kubelet/etc-kubernetes
    k8s_kubelet_anon_auth_disabled: bool = False
    k8s_kubelet_readonly_port_disabled: bool = False

    # ---- Anti-malware ------------------------------------------------------
    clamav_active: bool = False
    fail2ban_active: bool = False
    rkhunter_present: bool = False
    chkrootkit_present: bool = False

    # ---- Tool inventories (frozensets for hashability) ---------------------
    backup_tools: FrozenSet[str] = field(default_factory=frozenset)
    # Members from {borg, restic, duplicity, rsync, bacula, amanda, rdiff-backup, tar}

    snapshot_tools: FrozenSet[str] = field(default_factory=frozenset)
    # Members from {zfs, btrfs, snapper, lvm}

    secure_delete_tools: FrozenSet[str] = field(default_factory=frozenset)
    # Members from {shred, scrub, wipe, srm, hdparm, cryptsetup}

    vuln_scanners: FrozenSet[str] = field(default_factory=frozenset)
    # Members from {lynis, oscap, trivy, grype, nuclei, rkhunter, chkrootkit, debsecan}

    sast_tools: FrozenSet[str] = field(default_factory=frozenset)
    # Members from {shellcheck, bandit, semgrep, pylint, flake8, yamllint}

    sbom_tools: FrozenSet[str] = field(default_factory=frozenset)
    # Members from {syft, trivy, cyclonedx}

    signing_tools: FrozenSet[str] = field(default_factory=frozenset)
    # Members from {cosign, minisign, gpg}

    forensic_tools: FrozenSet[str] = field(default_factory=frozenset)
    # Members from {gdb, strace, ltrace, lsof, tcpdump, ss, ausearch, journalctl, perf, bpftrace}

    config_mgmt_tools: FrozenSet[str] = field(default_factory=frozenset)
    # Members from {ansible, puppet, salt, chef, etckeeper}

    pkg_signing_paths: FrozenSet[str] = field(default_factory=frozenset)
    # Members from {/etc/apt/keyrings, /etc/apt/trusted.gpg.d, /etc/pki/rpm-gpg}

    # ---- Boot security -----------------------------------------------------
    secure_boot_efi_present: bool = False        # /sys/firmware/efi/efivars
    tpm_present: bool = False                    # /sys/class/tpm/tpm0
    tpm_tools_present: bool = False              # tpm2_pcrread / tpm2_quote


def _safe_get_command_set(helpers, command_names) -> FrozenSet[str]:
    """Return frozenset of commands from `command_names` that are available."""
    return frozenset(c for c in command_names if helpers.command_available(c))


def _detect_container(helpers) -> bool:
    """Detect if we're inside a container."""
    cgroup = helpers.read_file_safe("/proc/1/cgroup", max_bytes=64 * 1024)
    if not cgroup:
        return False
    return any(token in cgroup for token in
                ("docker", "lxc", "kubepods", "containerd", "crio"))


def _detect_vm(helpers) -> bool:
    """Detect if we're inside a VM (systemd-detect-virt)."""
    if not helpers.command_available("systemd-detect-virt"):
        return False
    rc, out, _ = helpers.run_command(["systemd-detect-virt"], timeout=2.0)
    if rc != 0:
        return False
    out = out.strip()
    return out and out != "none" and out not in ("docker", "lxc", "podman")


def _detect_pam_mfa(helpers) -> tuple:
    """Returns (mfa_present, mfa_module_name)."""
    pam_dirs = [
        "/etc/pam.d/sshd", "/etc/pam.d/system-auth",
        "/etc/pam.d/password-auth", "/etc/pam.d/common-auth",
    ]
    pam_content = ""
    for pf in pam_dirs:
        pam_content += "\n" + helpers.read_file_safe(pf)
    # Order matters: prefer most specific match
    for mod_name, label in [
        ("pam_u2f", "u2f"),
        ("pam_yubico", "yubico"),
        ("pam_fido2", "fido2"),
        ("pam_duo", "duo"),
        ("pam_oath", "oath"),
        ("pam_google_authenticator", "google_authenticator"),
    ]:
        if mod_name in pam_content:
            return True, label
    return False, ""


def _detect_firewall(helpers) -> tuple:
    """Returns (firewall_active, firewall_tool, ufw_active, firewalld_active,
                 nftables_default_drop).

    Detects ufw, firewalld, nftables, and iptables. A tool counts as active
    when it is running and enforcing a ruleset - not only when it has a
    default-drop policy - so a host firewalled with iptables rules or an
    nftables accept-based ruleset is correctly reported rather than shown as
    having no firewall. Tool precedence for the single ``firewall_tool`` label
    is ufw > firewalld > nftables > iptables; ``firewall_active`` is true if
    any tool is active.
    """
    ufw_active = helpers.systemd_active("ufw.service") == "active"
    if not ufw_active and helpers.command_available("ufw"):
        rc, out, _ = helpers.run_command(["ufw", "status"], timeout=3.0)
        ufw_active = rc == 0 and "Status: active" in (out or "")

    firewalld_active = False
    if helpers.command_available("firewall-cmd"):
        rc, out, _ = helpers.run_command(["firewall-cmd", "--state"], timeout=3.0)
        firewalld_active = rc == 0 and "running" in (out or "")

    nftables_active = False
    nftables_default_drop = False
    if helpers.command_available("nft"):
        rc, out, _ = helpers.run_command(["nft", "list", "ruleset"], timeout=5.0)
        if rc == 0 and out and out.strip():
            # A non-empty ruleset with at least one table/chain means nftables
            # is actively enforcing something.
            nftables_active = ("table " in out) or ("chain " in out)
            nftables_default_drop = bool(re.search(
                r"hook\s+input\s+priority\s+\S+;\s*policy\s+drop;",
                out, re.MULTILINE,
            ))

    iptables_active = False
    if helpers.command_available("iptables"):
        rc, out, _ = helpers.run_command(["iptables", "-S"], timeout=3.0)
        if rc == 0 and out:
            has_rules = any(l.startswith("-A") for l in out.splitlines())
            has_drop_policy = any(
                l.startswith("-P INPUT DROP") or l.startswith("-P FORWARD DROP")
                for l in out.splitlines())
            iptables_active = has_rules or has_drop_policy

    if ufw_active:
        tool = "ufw"
    elif firewalld_active:
        tool = "firewalld"
    elif nftables_active:
        tool = "nftables"
    elif iptables_active:
        tool = "iptables"
    else:
        tool = ""

    firewall_active = (ufw_active or firewalld_active or nftables_active
                       or iptables_active)
    return (firewall_active, tool, ufw_active, firewalld_active,
             nftables_default_drop)


def _detect_audit_rules(helpers) -> tuple:
    """Returns (audit_rules_present, audit_rules_immutable, audit_rules_text)."""
    rules_text = ""
    rules_present = False
    if helpers.directory_exists("/etc/audit/rules.d"):
        for f in os.listdir("/etc/audit/rules.d"):
            if not f.endswith(".rules"):
                continue
            try:
                content = helpers.read_file_safe(f"/etc/audit/rules.d/{f}")
                if content.strip():
                    rules_text += "\n" + content
                    rules_present = True
            except OSError:
                pass
    immutable = bool(re.search(r"^\s*-e\s+2", rules_text, re.MULTILINE))
    return rules_present, immutable, rules_text


def _detect_journald(helpers) -> tuple:
    """Returns (journald_persistent, journald_seal)."""
    persistent = helpers.directory_exists("/var/log/journal")
    journald_conf = helpers.read_file_safe("/etc/systemd/journald.conf")
    journald_d = ""
    if helpers.directory_exists("/etc/systemd/journald.conf.d"):
        for f in os.listdir("/etc/systemd/journald.conf.d"):
            if f.endswith(".conf"):
                journald_d += "\n" + helpers.read_file_safe(
                    f"/etc/systemd/journald.conf.d/{f}"
                )
    full = journald_conf + "\n" + journald_d
    storage_match = re.search(
        r"^\s*Storage\s*=\s*(\w+)", full, re.MULTILINE,
    )
    if storage_match:
        persistent = persistent or storage_match.group(1) == "persistent"
    seal_match = re.search(r"^\s*Seal\s*=\s*(\w+)", full, re.MULTILINE)
    seal = (seal_match is None) or seal_match.group(1).lower() in (
        "yes", "true", "1",
    )
    return persistent, seal


def _detect_ssh(helpers) -> tuple:
    """Returns (root_permitted, password_enabled, pubkey_only)."""
    sshd = helpers.read_file_safe("/etc/ssh/sshd_config")
    sshd_d = ""
    if helpers.directory_exists("/etc/ssh/sshd_config.d"):
        for f in os.listdir("/etc/ssh/sshd_config.d"):
            if f.endswith(".conf"):
                sshd_d += "\n" + helpers.read_file_safe(
                    f"/etc/ssh/sshd_config.d/{f}"
                )
    full = sshd + "\n" + sshd_d
    # Default values: PermitRootLogin yes, PasswordAuthentication yes
    root_match = re.search(
        r"^\s*PermitRootLogin\s+(\S+)", full, re.MULTILINE,
    )
    root_permitted = True
    if root_match:
        v = root_match.group(1).lower()
        if v in ("no", "prohibit-password"):
            root_permitted = False
    pwd_match = re.search(
        r"^\s*PasswordAuthentication\s+(yes|no)", full, re.MULTILINE,
    )
    pwd_enabled = True
    if pwd_match and pwd_match.group(1).lower() == "no":
        pwd_enabled = False
    return root_permitted, pwd_enabled, not pwd_enabled


def _detect_centralized_logging(helpers) -> tuple:
    """Returns (rsyslog_remote, syslog_ng_remote, journal_upload)."""
    rsyslog_remote = False
    rsy = helpers.read_file_safe("/etc/rsyslog.conf")
    if "@@" in rsy or "omfwd" in rsy:
        rsyslog_remote = True
    if not rsyslog_remote and helpers.directory_exists("/etc/rsyslog.d"):
        for f in os.listdir("/etc/rsyslog.d"):
            c = helpers.read_file_safe(f"/etc/rsyslog.d/{f}")
            if "@@" in c or "omfwd" in c:
                rsyslog_remote = True
                break
    syslog_ng_remote = False
    syslog_ng_conf = helpers.read_file_safe("/etc/syslog-ng/syslog-ng.conf")
    if "destination" in syslog_ng_conf and (
        "tcp(" in syslog_ng_conf or "udp(" in syslog_ng_conf or
        "syslog(" in syslog_ng_conf
    ):
        syslog_ng_remote = True
    journal_upload = (
        helpers.systemd_active("systemd-journal-upload.service") == "active"
    )
    return rsyslog_remote, syslog_ng_remote, journal_upload


def _detect_swap(helpers) -> tuple:
    """Returns (swap_in_use, swap_encrypted)."""
    proc_swaps = helpers.read_file_safe("/proc/swaps")
    in_use = bool(proc_swaps and len(proc_swaps.splitlines()) > 1)
    if not in_use:
        return False, False
    encrypted = False
    crypttab = helpers.read_file_safe("/etc/crypttab")
    for line in proc_swaps.splitlines()[1:]:
        parts = line.split()
        if not parts:
            continue
        swap_dev = parts[0]
        if "/dev/mapper/" in swap_dev or "/dev/dm-" in swap_dev:
            encrypted = True
            break
        if crypttab and any(
            line.split()[0] in swap_dev
            for line in crypttab.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ):
            encrypted = True
            break
    return in_use, encrypted


def compute_host_facts(os_info, helpers) -> HostFacts:
    """Compute the full HostFacts record for the current host.

    Args:
        os_info: result of os_detection.detect_os()
        helpers: shared_components.module_helpers module

    Returns:
        HostFacts dataclass, fully populated. Computation uses cached
        helpers, so cost is bounded and reproducible across audit runs.
    """
    distro_id = (os_info.distro_id if os_info else "") or ""
    distro_family = ""
    if os_info:
        if os_info.is_debian_family():
            distro_family = "debian"
        elif os_info.is_redhat_family():
            distro_family = "redhat"
        elif os_info.is_suse_family():
            distro_family = "suse"
        elif os_info.is_arch_family():
            distro_family = "arch"
        elif os_info.is_alpine_family():
            distro_family = "alpine"
    distro_version = (os_info.version_id if os_info else "") or ""

    # FIM detection
    aide_present = (
        helpers.file_exists("/var/lib/aide/aide.db") or
        helpers.file_exists("/var/lib/aide/aide.db.gz")
    )
    tripwire_present = helpers.file_exists("/var/lib/tripwire/tw.db")
    samhain_present = helpers.file_exists("/var/lib/samhain/samhain_file")
    ossec_present = helpers.file_exists("/var/ossec/etc/ossec.conf")
    wazuh_present = (
        helpers.file_exists("/var/ossec/queue/fim/db/fim.db") or
        helpers.systemd_active("wazuh-agent.service") == "active"
    )
    fim_database_present = any([
        aide_present, tripwire_present, samhain_present,
        ossec_present, wazuh_present,
    ])
    fim_tool = ""
    if aide_present:
        fim_tool = "AIDE"
    elif tripwire_present:
        fim_tool = "Tripwire"
    elif samhain_present:
        fim_tool = "Samhain"
    elif ossec_present:
        fim_tool = "OSSEC"
    elif wazuh_present:
        fim_tool = "Wazuh"

    # Audit infrastructure
    auditd_active = helpers.systemd_active("auditd.service") == "active"
    audit_rules_present, audit_rules_immutable, audit_rules_text = (
        _detect_audit_rules(helpers)
    )
    journald_persistent, journald_seal = _detect_journald(helpers)

    # Cryptography
    fips_enabled = helpers.read_sysctl("crypto.fips_enabled") == "1"
    crypto_policy_raw = helpers.read_file_safe(
        "/etc/crypto-policies/state/current"
    ).strip()
    crypto_policy = crypto_policy_raw.upper() if crypto_policy_raw else ""
    fips_aligned = fips_enabled or crypto_policy in ("FIPS", "FUTURE")
    fips_indicator_files = sum([
        helpers.file_exists("/proc/sys/crypto/fips_enabled"),
        helpers.file_exists("/etc/system-fips"),
        helpers.file_exists("/etc/crypto-policies/state/current"),
    ])
    openssl_3x = False
    if helpers.command_available("openssl"):
        rc, out, _ = helpers.run_command(["openssl", "version"], timeout=3.0)
        if rc == 0 and out and "OpenSSL 3." in out:
            openssl_3x = True

    # MAC
    selinux_enforcing = False
    selinux_permissive = False
    if helpers.command_available("getenforce"):
        rc, out, _ = helpers.run_command(["getenforce"], timeout=2.0)
        if rc == 0 and out:
            state = out.strip()
            selinux_enforcing = state == "Enforcing"
            selinux_permissive = state == "Permissive"
    apparmor_active = helpers.command_available("aa-status")
    mac_active = selinux_enforcing or apparmor_active

    # Firewall
    (firewall_active, firewall_tool, ufw_active, firewalld_active,
     nftables_default_drop) = _detect_firewall(helpers)
    nftables_present = helpers.command_available("nft")
    listening_external_count = 0
    rc, out, _ = helpers.run_command(["ss", "-tlnp"], timeout=5.0)
    if rc == 0 and out:
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4 or parts[0] != "LISTEN":
                continue
            local = parts[3]
            if not (local.startswith("127.") or local.startswith("[::1]") or
                    local.startswith("[::ffff:127")):
                listening_external_count += 1

    # Authentication
    ssh_root_permitted, ssh_password_enabled, ssh_pubkey_only = (
        _detect_ssh(helpers)
    )
    pam_mfa_present, pam_mfa_module = _detect_pam_mfa(helpers)
    pam_files_content = ""
    for pf in ["/etc/pam.d/sshd", "/etc/pam.d/system-auth",
                "/etc/pam.d/password-auth", "/etc/pam.d/common-auth"]:
        pam_files_content += "\n" + helpers.read_file_safe(pf)
    pam_lockout_present = (
        "pam_faillock" in pam_files_content or
        "pam_tally2" in pam_files_content
    )

    # Patching
    auto_patch_active = False
    auto_patch_tool = ""
    if helpers.systemd_active("unattended-upgrades.service") == "active":
        auto_patch_active = True
        auto_patch_tool = "unattended-upgrades"
    elif helpers.systemd_active("dnf-automatic-install.timer") == "active":
        auto_patch_active = True
        auto_patch_tool = "dnf-automatic"
    elif helpers.systemd_active("dnf-automatic.timer") == "active":
        auto_patch_active = True
        auto_patch_tool = "dnf-automatic"

    # Time sync
    time_sync_active = False
    time_sync_tool = ""
    if (helpers.systemd_active("chronyd.service") == "active" or
        helpers.systemd_active("chrony.service") == "active"):
        time_sync_active = True
        time_sync_tool = "chrony"
    elif (helpers.systemd_active("ntp.service") == "active" or
            helpers.systemd_active("ntpd.service") == "active"):
        time_sync_active = True
        time_sync_tool = "ntp"
    elif helpers.systemd_active("systemd-timesyncd.service") == "active":
        time_sync_active = True
        time_sync_tool = "timesyncd"

    # Centralized logging
    rsyslog_remote, syslog_ng_remote, journal_upload = (
        _detect_centralized_logging(helpers)
    )
    siem_forwarding = rsyslog_remote or syslog_ng_remote or journal_upload

    # Storage encryption
    luks_present = False
    rc, out, _ = helpers.run_command(["lsblk", "-o", "TYPE", "-n"], timeout=5.0)
    if rc == 0 and out and "crypt" in out.lower():
        luks_present = True
    swap_in_use, swap_encrypted = _detect_swap(helpers)
    fstrim_timer_active = helpers.systemd_active("fstrim.timer") == "active"
    has_ssd = False
    rc, out, _ = helpers.run_command(
        ["lsblk", "-d", "-o", "ROTA", "-n"], timeout=5.0,
    )
    if rc == 0 and out and "0" in out:
        has_ssd = True

    # Container/orchestration
    container_runtime = ""
    container_runtime_active = False
    for tool, unit in [
        ("docker", "docker.service"),
        ("containerd", "containerd.service"),
        ("podman", ""),  # Podman is daemonless; just check for binary
        ("crio", "crio.service"),
    ]:
        if unit and helpers.systemd_active(unit) == "active":
            container_runtime = tool
            container_runtime_active = True
            break
        if not unit and helpers.command_available(tool):
            container_runtime = tool
            container_runtime_active = True
            break
    k8s_present = (
        helpers.command_available("kubectl") or
        helpers.command_available("kubelet") or
        helpers.directory_exists("/etc/kubernetes") or
        helpers.systemd_active("kubelet.service") == "active"
    )
    k8s_anon_auth_disabled = False
    k8s_readonly_port_disabled = False
    if k8s_present:
        kubelet_config = ""
        for path in [
            "/var/lib/kubelet/config.yaml",
            "/etc/kubernetes/kubelet/kubelet-config.yaml",
            "/etc/kubernetes/kubelet/kubelet.conf",
        ]:
            if helpers.file_exists(path):
                kubelet_config += "\n" + helpers.read_file_safe(path)
        if kubelet_config:
            k8s_anon_auth_disabled = not bool(re.search(
                r"anonymous-auth:\s*true", kubelet_config, re.IGNORECASE,
            ))
            ro_match = re.search(
                r"readOnlyPort:\s*(\d+)", kubelet_config,
            )
            k8s_readonly_port_disabled = (
                ro_match is None or ro_match.group(1) == "0"
            )

    # Anti-malware
    clamav_active = (
        helpers.systemd_active("clamav-daemon.service") == "active" or
        helpers.systemd_active("clamd.service") == "active"
    )
    fail2ban_active = helpers.systemd_active("fail2ban.service") == "active"
    rkhunter_present = helpers.command_available("rkhunter")
    chkrootkit_present = helpers.command_available("chkrootkit")

    # Tool inventories
    backup_tools = _safe_get_command_set(helpers, [
        "borg", "restic", "duplicity", "rsync", "rdiff-backup", "tar",
    ])
    if helpers.systemd_active("bacula-fd.service") == "active" or \
        helpers.command_available("bconsole"):
        backup_tools = backup_tools | frozenset(["bacula"])
    if helpers.command_available("amanda"):
        backup_tools = backup_tools | frozenset(["amanda"])

    snapshot_tools = _safe_get_command_set(helpers, [
        "zfs", "btrfs", "snapper", "lvcreate",
    ])

    secure_delete_tools = _safe_get_command_set(helpers, [
        "shred", "scrub", "wipe", "srm", "hdparm", "cryptsetup",
    ])

    vuln_scanners = _safe_get_command_set(helpers, [
        "lynis", "oscap", "trivy", "grype", "nuclei", "rkhunter",
        "chkrootkit", "debsecan",
    ])

    sast_tools = _safe_get_command_set(helpers, [
        "shellcheck", "bandit", "semgrep", "pylint", "flake8", "yamllint",
    ])

    sbom_tools = _safe_get_command_set(helpers, [
        "syft", "trivy", "cyclonedx",
    ])

    signing_tools = _safe_get_command_set(helpers, [
        "cosign", "minisign", "gpg", "gpg2",
    ])

    forensic_tools = _safe_get_command_set(helpers, [
        "gdb", "strace", "ltrace", "lsof", "tcpdump",
        "ss", "ausearch", "journalctl", "perf", "bpftrace",
    ])

    config_mgmt_tools = _safe_get_command_set(helpers, [
        "ansible", "puppet", "salt", "chef-client", "etckeeper",
    ])

    pkg_signing_paths = frozenset(p for p in [
        "/etc/apt/keyrings",
        "/etc/apt/trusted.gpg.d",
        "/etc/pki/rpm-gpg",
    ] if helpers.directory_exists(p))

    # Boot security
    secure_boot_efi_present = helpers.directory_exists(
        "/sys/firmware/efi/efivars"
    )
    tpm_present = (
        helpers.directory_exists("/sys/class/tpm/tpm0") or
        helpers.file_exists("/dev/tpm0") or
        helpers.file_exists("/dev/tpmrm0")
    )
    tpm_tools_present = (
        helpers.command_available("tpm2_pcrread") or
        helpers.command_available("tpm2_quote")
    )

    return HostFacts(
        # Identity
        distro_id=distro_id,
        distro_family=distro_family,
        distro_version=distro_version,
        is_container=_detect_container(helpers),
        is_vm=_detect_vm(helpers),

        # FIM
        fim_database_present=fim_database_present,
        fim_tool=fim_tool,
        aide_present=aide_present,
        tripwire_present=tripwire_present,
        samhain_present=samhain_present,
        ossec_present=ossec_present,
        wazuh_present=wazuh_present,

        # Audit
        auditd_active=auditd_active,
        audit_rules_present=audit_rules_present,
        audit_rules_immutable=audit_rules_immutable,
        audit_rules_text=audit_rules_text,
        journald_persistent=journald_persistent,
        journald_seal=journald_seal,

        # Crypto
        fips_enabled=fips_enabled,
        crypto_policy=crypto_policy,
        fips_aligned=fips_aligned,
        openssl_3x=openssl_3x,
        fips_indicator_files=fips_indicator_files,

        # MAC
        selinux_enforcing=selinux_enforcing,
        selinux_permissive=selinux_permissive,
        apparmor_active=apparmor_active,
        mac_active=mac_active,

        # Firewall
        firewall_active=firewall_active,
        firewall_tool=firewall_tool,
        ufw_active=ufw_active,
        firewalld_active=firewalld_active,
        nftables_present=nftables_present,
        nftables_default_drop=nftables_default_drop,
        listening_external_count=listening_external_count,

        # Auth
        ssh_root_permitted=ssh_root_permitted,
        ssh_password_auth_enabled=ssh_password_enabled,
        ssh_pubkey_only=ssh_pubkey_only,
        pam_mfa_present=pam_mfa_present,
        pam_mfa_module=pam_mfa_module,
        pam_lockout_present=pam_lockout_present,

        # Patching
        auto_patch_active=auto_patch_active,
        auto_patch_tool=auto_patch_tool,

        # Time sync
        time_sync_active=time_sync_active,
        time_sync_tool=time_sync_tool,

        # Centralized logging
        rsyslog_remote=rsyslog_remote,
        syslog_ng_remote=syslog_ng_remote,
        journal_upload=journal_upload,
        siem_forwarding=siem_forwarding,

        # Storage encryption
        luks_present=luks_present,
        swap_in_use=swap_in_use,
        swap_encrypted=swap_encrypted,
        fstrim_timer_active=fstrim_timer_active,
        has_ssd=has_ssd,

        # Container/k8s
        container_runtime=container_runtime,
        container_runtime_active=container_runtime_active,
        k8s_present=k8s_present,
        k8s_kubelet_anon_auth_disabled=k8s_anon_auth_disabled,
        k8s_kubelet_readonly_port_disabled=k8s_readonly_port_disabled,

        # Anti-malware
        clamav_active=clamav_active,
        fail2ban_active=fail2ban_active,
        rkhunter_present=rkhunter_present,
        chkrootkit_present=chkrootkit_present,

        # Tool inventories
        backup_tools=backup_tools,
        snapshot_tools=snapshot_tools,
        secure_delete_tools=secure_delete_tools,
        vuln_scanners=vuln_scanners,
        sast_tools=sast_tools,
        sbom_tools=sbom_tools,
        signing_tools=signing_tools,
        forensic_tools=forensic_tools,
        config_mgmt_tools=config_mgmt_tools,
        pkg_signing_paths=pkg_signing_paths,

        # Boot security
        secure_boot_efi_present=secure_boot_efi_present,
        tpm_present=tpm_present,
        tpm_tools_present=tpm_tools_present,
    )


def get_or_compute_facts(shared_data, os_info, helpers) -> HostFacts:
    """Convenience accessor: return cached HostFacts or compute on demand.

    Modules call this to get the host facts record. If the orchestrator
    already populated shared_data["host_facts"], it's returned directly;
    otherwise, computed on first access (graceful fallback for callers
    that bypass the orchestrator).
    """
    facts = shared_data.get("host_facts")
    if isinstance(facts, HostFacts):
        return facts
    facts = compute_host_facts(os_info, helpers)
    shared_data["host_facts"] = facts
    return facts
