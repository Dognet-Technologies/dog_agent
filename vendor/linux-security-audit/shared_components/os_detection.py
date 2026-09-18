"""
os_detection.py - Linux distribution and platform detection.

SYNOPSIS
    Identifies the Linux distribution, version, family, package manager,
    init system, mandatory access control framework, firewall stack,
    container/virtualisation context, and architecture.

DESCRIPTION
    Multiple file sources are consulted in priority order so that detection
    succeeds even on minimal containers, immutable distributions, or systems
    where one source has been overwritten. Detection is purely passive: no
    subprocesses are launched and no network requests are made by this
    module's primary detection path. Optional helper functions that wrap
    subprocess calls (e.g. for kernel version) are explicitly documented.

    The detection result is captured in OSInfo, an immutable-ish dataclass.
    Modules query the resulting object via attribute access. Family-level
    branching in modules should use the family field; only OS-specific
    quirks should branch on distro_id.

    Detection precedence (highest first):
        1. /etc/os-release (systemd standard, present on essentially all
           modern distributions)
        2. /usr/lib/os-release (immutable systems)
        3. /etc/lsb-release (LSB-compliant, common on Ubuntu derivatives)
        4. /etc/redhat-release (RHEL family marker file)
        5. /etc/debian_version (Debian marker file)
        6. /etc/SUSE-brand or /etc/SuSE-release (SUSE marker file)
        7. /etc/arch-release (Arch Linux marker)
        8. /etc/alpine-release (Alpine Linux marker)
        9. /etc/gentoo-release (Gentoo marker)
       10. uname-derived fallback (last resort, family=Unknown)

PARAMETERS
    detect_os() takes no required parameters. Pass force_refresh=True to
    bypass the module-level cache.

EXAMPLES
    Basic usage:
        from shared_components.os_detection import detect_os
        os_info = detect_os()
        if os_info.family == "Debian":
            ...

NOTES
    Version: 3.0
    Stdlib only.
    All file reads are wrapped in try/except for OSError; the module never
    raises during normal operation. Detection failures yield OSInfo with
    family="Unknown" so callers can degrade gracefully.
"""

from __future__ import annotations

import logging
import os
import platform
import re
import shutil
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("audit.os_detection")


# Canonical family codes. Modules should branch on these rather than on
# distro_id when possible, because new derivative distros appear regularly
# and the family is more stable.

FAMILY_DEBIAN = "Debian"
FAMILY_REDHAT = "RedHat"
FAMILY_SUSE = "SUSE"
FAMILY_ARCH = "Arch"
FAMILY_ALPINE = "Alpine"
FAMILY_GENTOO = "Gentoo"
FAMILY_SLACKWARE = "Slackware"
FAMILY_VOID = "Void"
FAMILY_NIXOS = "NixOS"
FAMILY_UNKNOWN = "Unknown"

ALL_FAMILIES = (
    FAMILY_DEBIAN, FAMILY_REDHAT, FAMILY_SUSE, FAMILY_ARCH, FAMILY_ALPINE,
    FAMILY_GENTOO, FAMILY_SLACKWARE, FAMILY_VOID, FAMILY_NIXOS, FAMILY_UNKNOWN,
)


# Mapping from os-release ID/ID_LIKE values to canonical family. Order
# of precedence inside ID_LIKE is preserved (first match wins) because
# many distros list multiple parents (e.g. Pop!_OS lists "ubuntu debian").
# Distribution slugs are matched case-insensitively against this dict.

_ID_TO_FAMILY: Dict[str, str] = {
    # Debian family
    "debian": FAMILY_DEBIAN, "ubuntu": FAMILY_DEBIAN, "linuxmint": FAMILY_DEBIAN,
    "pop": FAMILY_DEBIAN, "elementary": FAMILY_DEBIAN, "kali": FAMILY_DEBIAN,
    "zorin": FAMILY_DEBIAN, "mx": FAMILY_DEBIAN, "deepin": FAMILY_DEBIAN,
    "parrot": FAMILY_DEBIAN, "tails": FAMILY_DEBIAN, "raspbian": FAMILY_DEBIAN,
    "neon": FAMILY_DEBIAN, "lubuntu": FAMILY_DEBIAN, "xubuntu": FAMILY_DEBIAN,
    "kubuntu": FAMILY_DEBIAN, "ubuntu-mate": FAMILY_DEBIAN,
    "ubuntu-budgie": FAMILY_DEBIAN, "antix": FAMILY_DEBIAN,
    "devuan": FAMILY_DEBIAN, "siduction": FAMILY_DEBIAN, "bunsenlabs": FAMILY_DEBIAN,
    "endless": FAMILY_DEBIAN, "kde-neon": FAMILY_DEBIAN, "lxle": FAMILY_DEBIAN,
    "peppermint": FAMILY_DEBIAN, "qubes": FAMILY_DEBIAN,

    # RedHat family
    "rhel": FAMILY_REDHAT, "redhat": FAMILY_REDHAT, "centos": FAMILY_REDHAT,
    "fedora": FAMILY_REDHAT, "rocky": FAMILY_REDHAT, "almalinux": FAMILY_REDHAT,
    "ol": FAMILY_REDHAT, "oracle": FAMILY_REDHAT, "amzn": FAMILY_REDHAT,
    "scientific": FAMILY_REDHAT, "clearos": FAMILY_REDHAT,
    "springdale": FAMILY_REDHAT, "centosstream": FAMILY_REDHAT,
    "circle": FAMILY_REDHAT, "navy": FAMILY_REDHAT, "qubesos": FAMILY_REDHAT,
    "eurolinux": FAMILY_REDHAT, "miraclelinux": FAMILY_REDHAT,
    "openela": FAMILY_REDHAT,

    # SUSE family
    "suse": FAMILY_SUSE, "opensuse": FAMILY_SUSE, "opensuse-leap": FAMILY_SUSE,
    "opensuse-tumbleweed": FAMILY_SUSE, "sles": FAMILY_SUSE, "sled": FAMILY_SUSE,
    "sle_hpc": FAMILY_SUSE, "geckolinux": FAMILY_SUSE,

    # Arch family
    "arch": FAMILY_ARCH, "manjaro": FAMILY_ARCH, "endeavouros": FAMILY_ARCH,
    "garuda": FAMILY_ARCH, "arcolinux": FAMILY_ARCH, "artix": FAMILY_ARCH,
    "blackarch": FAMILY_ARCH, "cachyos": FAMILY_ARCH, "rebornos": FAMILY_ARCH,
    "obarun": FAMILY_ARCH, "parabola": FAMILY_ARCH,

    # Independent
    "alpine": FAMILY_ALPINE,
    "gentoo": FAMILY_GENTOO, "calculate": FAMILY_GENTOO, "funtoo": FAMILY_GENTOO,
    "slackware": FAMILY_SLACKWARE, "salix": FAMILY_SLACKWARE,
    "void": FAMILY_VOID,
    "nixos": FAMILY_NIXOS,
}


# Package manager mapping per family. The first manager listed is the
# preferred/canonical one; others are accepted alternatives. This list
# drives the package_manager field and informs module logic for things
# like security update detection.

_FAMILY_PACKAGE_MANAGERS: Dict[str, List[str]] = {
    FAMILY_DEBIAN: ["apt", "apt-get", "aptitude", "dpkg"],
    FAMILY_REDHAT: ["dnf", "yum", "rpm"],
    FAMILY_SUSE: ["zypper", "rpm"],
    FAMILY_ARCH: ["pacman"],
    FAMILY_ALPINE: ["apk"],
    FAMILY_GENTOO: ["emerge", "portage"],
    FAMILY_SLACKWARE: ["slackpkg", "pkgtool"],
    FAMILY_VOID: ["xbps-install", "xbps-query"],
    FAMILY_NIXOS: ["nix-env", "nix"],
}


# Init system probes. Each entry is (name, check_callable) where the
# callable returns True when that init system is in use. The first
# matching probe wins. Probes use only filesystem inspection; no
# subprocesses are needed because the init system is process 1 and
# its name is exposed via /proc/1/comm.

def _has_systemd() -> bool:
    return os.path.isdir("/run/systemd/system")


def _has_openrc() -> bool:
    return os.path.isdir("/run/openrc") or os.path.isfile("/sbin/openrc")


def _has_runit() -> bool:
    return os.path.isfile("/etc/runit/1") or os.path.isdir("/etc/service")


def _has_s6() -> bool:
    return os.path.isdir("/run/s6") or os.path.isfile("/etc/s6/init")


def _has_dinit() -> bool:
    return os.path.isfile("/etc/dinit.d/boot")


def _has_sysvinit() -> bool:
    # /etc/inittab is the SysVinit signature, but some distros ship a stub
    # inittab even with systemd. Treat as SysVinit only if init is not
    # systemd, openrc, runit, s6, or dinit.
    return os.path.isfile("/etc/inittab")


_INIT_PROBES: List[Tuple[str, callable]] = [
    ("systemd", _has_systemd),
    ("openrc", _has_openrc),
    ("runit", _has_runit),
    ("s6", _has_s6),
    ("dinit", _has_dinit),
    ("sysvinit", _has_sysvinit),
]


# MAC framework probes. Order matters: SELinux and AppArmor coexist on
# some kernels but distributions only enable one in practice. The probe
# returns the active framework or empty string if none is enabled.

def _detect_mac_framework() -> str:
    # SELinux is identifiable by /sys/fs/selinux/ filesystem
    if os.path.isdir("/sys/fs/selinux"):
        try:
            with open("/sys/fs/selinux/enforce", "r", encoding="ascii") as f:
                # Existence of this file is enough; value tells us mode
                return "selinux"
        except OSError:
            return "selinux"  # Filesystem present but file unreadable

    # AppArmor exposes /sys/kernel/security/apparmor/profiles
    if os.path.isfile("/sys/kernel/security/apparmor/profiles"):
        return "apparmor"

    # TOMOYO appears at /sys/kernel/security/tomoyo
    if os.path.isdir("/sys/kernel/security/tomoyo"):
        return "tomoyo"

    # SMACK exposes /sys/fs/smackfs
    if os.path.isdir("/sys/fs/smackfs"):
        return "smack"

    # Yama is a simpler LSM that's commonly enabled alongside others.
    # We detect it but don't return it as the primary MAC unless nothing
    # else is present.
    if os.path.isfile("/proc/sys/kernel/yama/ptrace_scope"):
        return "yama"

    return ""


# Firewall detection. Multiple firewalls can be installed simultaneously
# (e.g. firewalld with iptables backend) but we report the active
# management interface, falling through to the lower-level tooling.

def _detect_firewall() -> str:
    # firewalld presence is a strong signal on RHEL/Fedora/Rocky/Alma
    if os.path.isfile("/etc/firewalld/firewalld.conf"):
        return "firewalld"

    # ufw is the Debian/Ubuntu management interface over iptables/nftables
    if os.path.isfile("/etc/ufw/ufw.conf"):
        return "ufw"

    # nftables config can exist independently or under firewalld
    if os.path.isfile("/etc/nftables.conf") or os.path.isdir("/etc/nftables.d"):
        # Prefer reporting nftables only if no higher-level tool is in use
        return "nftables"

    # iptables-persistent (Debian) or iptables.service (RHEL legacy)
    if os.path.isfile("/etc/iptables/rules.v4"):
        return "iptables"

    # Shorewall
    if os.path.isfile("/etc/shorewall/shorewall.conf"):
        return "shorewall"

    return ""


# Container detection. The presence of any of these markers indicates
# we are running inside a container and certain checks (kernel tuning,
# bootloader configuration) will be inapplicable.

def _detect_container() -> str:
    # Docker creates /.dockerenv at the root. Check first because cheapest.
    if os.path.isfile("/.dockerenv"):
        return "docker"

    # systemd-nspawn sets the container env var via systemd-detect-virt,
    # but the marker file is more reliable from inside the container.
    if os.path.isfile("/run/systemd/container"):
        try:
            with open("/run/systemd/container", "r", encoding="utf-8") as f:
                return f.read().strip().lower() or "systemd-nspawn"
        except OSError:
            return "systemd-nspawn"

    # Container runtime detection via /proc/1/cgroup. Inside a container
    # the cgroup path will reference docker/, kubepods/, lxc/, etc.
    try:
        with open("/proc/1/cgroup", "r", encoding="utf-8") as f:
            cgroup = f.read()
        if "/docker/" in cgroup or cgroup.startswith("0::/docker/"):
            return "docker"
        if "/kubepods" in cgroup:
            return "kubernetes"
        if "/lxc/" in cgroup or "lxc.payload" in cgroup:
            return "lxc"
        if "/podman" in cgroup:
            return "podman"
    except OSError:
        pass

    # Check init process name as a final signal
    try:
        with open("/proc/1/comm", "r", encoding="utf-8") as f:
            comm = f.read().strip()
        if comm in ("docker-init", "tini", "dumb-init"):
            return "container"
    except OSError:
        pass

    return ""


# Cloud provider detection via DMI strings only. No metadata service
# requests are made; that would require a network call.

def _detect_cloud_provider() -> str:
    dmi_paths = (
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/board_vendor",
        "/sys/class/dmi/id/bios_vendor",
        "/sys/class/dmi/id/product_name",
    )
    dmi_data: List[str] = []
    for path in dmi_paths:
        try:
            with open(path, "r", encoding="utf-8") as f:
                dmi_data.append(f.read().strip().lower())
        except OSError:
            continue

    blob = " ".join(dmi_data)
    if "amazon" in blob or "amzn" in blob or "ec2" in blob:
        return "aws"
    if "microsoft" in blob and "azure" in blob:
        return "azure"
    if "microsoft corporation" in blob:
        # Hyper-V on-prem vs Azure - check for additional Azure markers
        if "virtual machine" in blob:
            return "hyperv"
    if "google" in blob:
        return "gcp"
    if "digitalocean" in blob:
        return "digitalocean"
    if "linode" in blob:
        return "linode"
    if "vultr" in blob:
        return "vultr"
    if "openstack" in blob:
        return "openstack"
    if "vmware" in blob:
        return "vmware"
    if "qemu" in blob or "kvm" in blob:
        return "kvm"
    if "xen" in blob:
        return "xen"
    if "virtualbox" in blob or "innotek" in blob:
        return "virtualbox"
    if "parallels" in blob:
        return "parallels"

    return ""


@dataclass
class KernelVersion:
    """Parsed kernel version with semantic component access.

    The full string from uname -r typically looks like:
        5.15.0-91-generic           (Ubuntu)
        4.18.0-553.el8_10.x86_64    (RHEL)
        6.6.8-arch1-1               (Arch)
        5.10.0-26-amd64             (Debian)
    The major/minor/patch fields capture the kernel.org version; the
    flavour field captures distribution-specific suffixes.
    """

    major: int = 0
    minor: int = 0
    patch: int = 0
    flavour: str = ""
    raw: str = ""

    def at_least(self, major: int, minor: int = 0, patch: int = 0) -> bool:
        """True if this kernel is at or above the given version."""
        if self.major != major:
            return self.major > major
        if self.minor != minor:
            return self.minor > minor
        return self.patch >= patch


def _parse_kernel(raw: str) -> KernelVersion:
    """Extract major/minor/patch and flavour from a uname -r string."""
    if not raw:
        return KernelVersion()

    # Split numeric prefix from suffix at first non-version character
    m = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?(.*)$", raw.strip())
    if not m:
        return KernelVersion(raw=raw)

    major = int(m.group(1))
    minor = int(m.group(2))
    patch = int(m.group(3) or 0)
    flavour = m.group(4) or ""
    # Strip leading separators from flavour
    flavour = flavour.lstrip(".-_+")
    return KernelVersion(
        major=major, minor=minor, patch=patch, flavour=flavour, raw=raw
    )


@dataclass
class OSInfo:
    """Detected OS identity and platform context.

    Fields:
        distro_id: Lowercase identifier matching the os-release ID field
            (e.g. "ubuntu", "rhel", "rocky"). May be empty if detection
            failed.
        distro_name: Human-readable distribution name (e.g. "Ubuntu",
            "Red Hat Enterprise Linux"). Capitalisation preserved.
        version_id: Version string in the form used by os-release
            (e.g. "22.04", "9.4", "rolling"). May be empty.
        version_codename: Distribution codename when applicable
            (e.g. "jammy", "bookworm"). Empty for distros without codenames.
        family: Canonical family code (see ALL_FAMILIES).
        package_manager: Canonical package manager command for this distro.
        package_manager_alternatives: Other recognised package managers
            that may be present (used for fallback in module checks).
        init_system: Detected init system (systemd, openrc, runit, etc.).
        mac_framework: Active mandatory access control framework
            (selinux, apparmor, tomoyo, smack, yama). Empty if none.
        firewall: Active firewall management interface
            (firewalld, ufw, nftables, iptables, shorewall). Empty if none
            visible.
        container: Container runtime if running inside one
            (docker, kubernetes, lxc, podman, systemd-nspawn).
        cloud_provider: Detected cloud platform if running on cloud infra
            (aws, azure, gcp, etc.).
        architecture: CPU architecture (x86_64, aarch64, armv7l, etc.).
        kernel: Parsed kernel version.
        eol: True if this distribution version is past end-of-life
            according to the bundled EOL data. Empty/unknown distributions
            return False (caller should not rely on this for compliance).
        detection_source: Which file or method produced the primary
            identification (used for diagnostics).
    """

    distro_id: str = ""
    distro_name: str = ""
    pretty_name: str = ""
    version_id: str = ""
    version_codename: str = ""
    family: str = FAMILY_UNKNOWN
    package_manager: str = ""
    package_manager_alternatives: List[str] = field(default_factory=list)
    init_system: str = ""
    mac_framework: str = ""
    firewall: str = ""
    container: str = ""
    cloud_provider: str = ""
    architecture: str = ""
    kernel: KernelVersion = field(default_factory=KernelVersion)
    eol: bool = False
    detection_source: str = ""

    # ------------------------------------------------------------------
    # v3.7 compatibility properties
    # ------------------------------------------------------------------
    # shared_components/audit_common.py defines a separate OSInfo whose
    # attributes are named `distro` and `version` (rather than `distro_id`
    # and `version_id`). Some modules (module_core, module_enisa) access
    # `os_info.distro` / `os_info.version` directly. When an
    # os_detection.OSInfo flows into those code paths, the missing
    # attributes previously raised AttributeError and aborted entire check
    # functions mid-run (e.g. ENISA aborted at its banner line; ISO27001
    # aborted at check 9). These read-only properties make the two OSInfo
    # implementations interchangeable.
    @property
    def distro(self) -> str:
        """Alias for distro_id (audit_common.OSInfo compatibility)."""
        return self.distro_id

    @property
    def version(self) -> str:
        """Alias for version_id (audit_common.OSInfo compatibility)."""
        return self.version_id

    @property
    def kernel_version(self) -> str:
        """Alias for the raw kernel version string (audit_common compat)."""
        return self.kernel.raw if self.kernel and self.kernel.raw else str(self.kernel)
    def is_debian_family(self) -> bool:
        return self.family == FAMILY_DEBIAN

    def is_redhat_family(self) -> bool:
        return self.family == FAMILY_REDHAT

    def is_suse_family(self) -> bool:
        return self.family == FAMILY_SUSE

    def is_arch_family(self) -> bool:
        return self.family == FAMILY_ARCH

    # ------------------------------------------------------------------
    # v3.7 compatibility aliases
    # ------------------------------------------------------------------
    # shared_components/audit_common.py defines a separate OSInfo with
    # `is_<family>_based()` method names. Some helpers there (e.g.
    # check_package_installed) call those names. To make BOTH OSInfo
    # implementations fully interchangeable wherever an instance flows,
    # we expose `_based` aliases here. Prevents AttributeError aborts that
    # previously killed entire check functions mid-run when an
    # os_detection.OSInfo was passed to an audit_common helper.
    def is_debian_based(self) -> bool:
        return self.is_debian_family()

    def is_redhat_based(self) -> bool:
        return self.is_redhat_family()

    def is_suse_based(self) -> bool:
        return self.is_suse_family()

    def is_arch_based(self) -> bool:
        return self.is_arch_family()

    def is_alpine_family(self) -> bool:
        return self.family == FAMILY_ALPINE

    def is_alpine_based(self) -> bool:
        return self.family == FAMILY_ALPINE

    def is_containerized(self) -> bool:
        return bool(self.container)

    def is_cloud(self) -> bool:
        return bool(self.cloud_provider)

    def __str__(self) -> str:
        parts = [self.distro_name or self.distro_id or "unknown"]
        if self.version_id:
            parts.append(self.version_id)
        if self.version_codename:
            parts.append(f"({self.version_codename})")
        if self.family != FAMILY_UNKNOWN:
            parts.append(f"[{self.family}]")
        return " ".join(parts)


def _parse_os_release(path: str) -> Dict[str, str]:
    """Parse a key=value file in os-release format.

    Returns an empty dict if the file is missing or unreadable. Quotes
    around values are stripped. Keys are uppercased to match the spec.
    """
    data: Dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError:
        return data

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().upper()
        value = value.strip().strip('"').strip("'")
        data[key] = value
    return data


def _read_text(path: str) -> str:
    """Read a small text file, returning empty string on any error."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return ""


def _classify_family(distro_id: str, id_like: str) -> str:
    """Map distro_id (and ID_LIKE fallbacks) to a canonical family.

    The os-release ID_LIKE field is space-separated and lists ancestors
    in priority order. Returns FAMILY_UNKNOWN if nothing matches.
    """
    if not distro_id:
        return FAMILY_UNKNOWN

    # Direct match on distro_id
    family = _ID_TO_FAMILY.get(distro_id.lower())
    if family:
        return family

    # Try each token in ID_LIKE
    for token in id_like.split():
        family = _ID_TO_FAMILY.get(token.strip().lower())
        if family:
            return family

    return FAMILY_UNKNOWN


def _detect_package_manager(family: str) -> Tuple[str, List[str]]:
    """Identify the package manager binary present on PATH.

    Returns (primary, alternatives). The primary is the highest-priority
    manager from the family's ordered list that is actually present.
    Alternatives are other present managers in priority order.
    """
    candidates = _FAMILY_PACKAGE_MANAGERS.get(family, [])
    found = [c for c in candidates if shutil.which(c)]
    if not found:
        return "", []
    return found[0], found[1:]


def _detect_kernel() -> KernelVersion:
    """Identify and parse the running kernel version."""
    # platform.release() reads from uname() and is reliable across distros
    try:
        raw = platform.release()
    except (OSError, AttributeError):
        raw = ""
    return _parse_kernel(raw)


def _detect_architecture() -> str:
    """CPU architecture as reported by uname.

    Returns the raw machine string (e.g. x86_64, aarch64, armv7l, ppc64le,
    s390x, riscv64). Empty on failure.
    """
    try:
        return platform.machine() or ""
    except (OSError, AttributeError):
        return ""


# Module-level cache. Detection is invoked exactly once per process unless
# force_refresh is requested. The lock guards against parallel module
# initialisation racing on the cache slot.

_cache_lock = threading.Lock()
_cached_info: Optional[OSInfo] = None


def detect_os(force_refresh: bool = False) -> OSInfo:
    """Detect the running OS and return a populated OSInfo.

    The result is cached at module level. Pass force_refresh=True to
    bypass the cache, which is useful in tests but should not be needed
    in production.

    This function never raises. Detection failures yield an OSInfo with
    family=FAMILY_UNKNOWN; callers should branch on this rather than
    relying on exceptions.
    """
    global _cached_info

    if not force_refresh:
        with _cache_lock:
            if _cached_info is not None:
                return _cached_info

    info = OSInfo()
    info.architecture = _detect_architecture()
    info.kernel = _detect_kernel()

    # Source 1: /etc/os-release (preferred)
    osrel = _parse_os_release("/etc/os-release")
    source = "/etc/os-release"
    if not osrel:
        # Source 2: /usr/lib/os-release (immutable systems)
        osrel = _parse_os_release("/usr/lib/os-release")
        source = "/usr/lib/os-release"

    if osrel:
        info.distro_id = osrel.get("ID", "").lower()
        info.distro_name = osrel.get("NAME", "") or osrel.get("PRETTY_NAME", "")
        info.pretty_name = osrel.get("PRETTY_NAME", "") or info.distro_name
        info.version_id = osrel.get("VERSION_ID", "")
        info.version_codename = (
            osrel.get("VERSION_CODENAME", "")
            or osrel.get("UBUNTU_CODENAME", "")
            or osrel.get("DEBIAN_CODENAME", "")
        )
        id_like = osrel.get("ID_LIKE", "")
        info.family = _classify_family(info.distro_id, id_like)
        info.detection_source = source

    # Fallback: try LSB release file
    if not info.distro_id:
        lsb = _parse_os_release("/etc/lsb-release")
        if lsb:
            info.distro_id = lsb.get("DISTRIB_ID", "").lower()
            info.distro_name = lsb.get("DISTRIB_DESCRIPTION", "") or info.distro_name
            info.pretty_name = (
                lsb.get("DISTRIB_DESCRIPTION", "")
                or info.pretty_name
                or info.distro_name
            )
            info.version_id = lsb.get("DISTRIB_RELEASE", "") or info.version_id
            info.version_codename = (
                lsb.get("DISTRIB_CODENAME", "") or info.version_codename
            )
            info.family = _classify_family(info.distro_id, "")
            info.detection_source = "/etc/lsb-release"

    # Fallback: marker files
    if not info.distro_id:
        marker_data = [
            ("/etc/redhat-release", FAMILY_REDHAT, "rhel"),
            ("/etc/centos-release", FAMILY_REDHAT, "centos"),
            ("/etc/fedora-release", FAMILY_REDHAT, "fedora"),
            ("/etc/rocky-release", FAMILY_REDHAT, "rocky"),
            ("/etc/almalinux-release", FAMILY_REDHAT, "almalinux"),
            ("/etc/oracle-release", FAMILY_REDHAT, "ol"),
            ("/etc/SUSE-brand", FAMILY_SUSE, "suse"),
            ("/etc/SuSE-release", FAMILY_SUSE, "suse"),
            ("/etc/arch-release", FAMILY_ARCH, "arch"),
            ("/etc/alpine-release", FAMILY_ALPINE, "alpine"),
            ("/etc/gentoo-release", FAMILY_GENTOO, "gentoo"),
            ("/etc/slackware-version", FAMILY_SLACKWARE, "slackware"),
            ("/etc/void-release", FAMILY_VOID, "void"),
            ("/etc/NIXOS", FAMILY_NIXOS, "nixos"),
            ("/etc/debian_version", FAMILY_DEBIAN, "debian"),
        ]
        for path, family, distro_id in marker_data:
            if os.path.isfile(path):
                info.family = family
                info.distro_id = distro_id
                content = _read_text(path)
                if content:
                    if not info.distro_name:
                        info.distro_name = content.splitlines()[0]
                    if not info.pretty_name:
                        info.pretty_name = content.splitlines()[0]
                    if not info.version_id:
                        # Extract first version-like token
                        m = re.search(r"\d+(?:\.\d+)*", content)
                        if m:
                            info.version_id = m.group(0)
                info.detection_source = path
                break

    # Package manager detection always runs (relies on PATH, not files)
    pkg_primary, pkg_alts = _detect_package_manager(info.family)
    info.package_manager = pkg_primary
    info.package_manager_alternatives = pkg_alts

    # Init / MAC / firewall / container / cloud detection
    for name, probe in _INIT_PROBES:
        try:
            if probe():
                info.init_system = name
                break
        except OSError:
            continue

    try:
        info.mac_framework = _detect_mac_framework()
    except OSError:
        info.mac_framework = ""

    try:
        info.firewall = _detect_firewall()
    except OSError:
        info.firewall = ""

    try:
        info.container = _detect_container()
    except OSError:
        info.container = ""

    try:
        info.cloud_provider = _detect_cloud_provider()
    except OSError:
        info.cloud_provider = ""

    # EOL detection. Limited bundled data; expanded in the EOL data file.
    info.eol = _check_eol(info.distro_id, info.version_id)

    # Final pretty_name fallback chain ensures the orchestrator always has a
    # usable display string instead of falling back to "Linux X.Y.Z-generic".
    if not info.pretty_name:
        if info.distro_name and info.version_id:
            info.pretty_name = f"{info.distro_name} {info.version_id}"
        elif info.distro_name:
            info.pretty_name = info.distro_name
        elif info.distro_id and info.version_id:
            info.pretty_name = f"{info.distro_id} {info.version_id}"
        elif info.distro_id:
            info.pretty_name = info.distro_id
        else:
            # Truly unknown; use platform info as last resort but explicit
            info.pretty_name = (
                f"{platform.system()} {platform.release()} (unidentified)"
            )

    with _cache_lock:
        _cached_info = info
    return info


# End-of-life data. Bundled with the module to support offline operation.
# Format: distro_id -> {version_id: eol_iso_date}. A version is treated as
# EOL if today's date is past the recorded EOL date. Missing entries return
# False (the conservative default - we don't claim a system is EOL unless
# we know for sure).

_EOL_DATA: Dict[str, Dict[str, str]] = {
    "ubuntu": {
        "14.04": "2019-04-25", "16.04": "2021-04-30", "18.04": "2023-05-31",
        "19.04": "2020-01-23", "19.10": "2020-07-17", "20.04": "2025-04-29",
        "20.10": "2021-07-22", "21.04": "2022-01-20", "21.10": "2022-07-14",
        "22.04": "2027-04-21", "22.10": "2023-07-20", "23.04": "2024-01-25",
        "23.10": "2024-07-11", "24.04": "2029-05-31", "24.10": "2025-07-10",
    },
    "debian": {
        "8": "2018-06-17", "9": "2020-07-18", "10": "2022-09-10",
        "11": "2024-07-01", "12": "2026-06-30",
    },
    "rhel": {
        "6": "2020-11-30", "7": "2024-06-30", "8": "2029-05-31",
        "9": "2032-05-31",
    },
    "centos": {
        "6": "2020-11-30", "7": "2024-06-30", "8": "2021-12-31",
    },
    "fedora": {
        "35": "2022-12-13", "36": "2023-05-16", "37": "2023-12-05",
        "38": "2024-05-21", "39": "2024-11-26", "40": "2025-05-13",
        "41": "2025-11-26",
    },
    "rocky": {
        "8": "2029-05-31", "9": "2032-05-31",
    },
    "almalinux": {
        "8": "2029-05-31", "9": "2032-05-31",
    },
    "opensuse-leap": {
        "15.3": "2022-12-31", "15.4": "2023-12-07", "15.5": "2024-12-31",
        "15.6": "2025-12-31",
    },
    "sles": {
        "12": "2027-10-31", "15": "2031-07-31",
    },
    "amzn": {
        "1": "2023-12-31", "2": "2026-06-30", "2023": "2028-03-31",
    },
}


def _check_eol(distro_id: str, version_id: str) -> bool:
    """Return True if this distro/version combo is past EOL.

    Returns False if the data is unknown or the date can't be parsed.
    """
    if not distro_id or not version_id:
        return False

    distro_data = _EOL_DATA.get(distro_id.lower())
    if not distro_data:
        return False

    # Try exact match first, then major-version match
    eol_str = distro_data.get(version_id)
    if not eol_str:
        # Try major version (e.g. 22.04 -> 22)
        major = version_id.split(".")[0]
        eol_str = distro_data.get(major)
    if not eol_str:
        return False

    try:
        import datetime as _dt
        eol_date = _dt.date.fromisoformat(eol_str)
        return _dt.date.today() > eol_date
    except (ValueError, TypeError):
        return False


def get_kernel_module_loaded(name: str) -> bool:
    """Check whether a kernel module is currently loaded.

    Reads /proc/modules to avoid the lsmod subprocess. Returns False on
    any error or if the module is not in the loaded list. The check is
    case-sensitive matching the kernel's internal naming.
    """
    if not name or not name.replace("_", "").replace("-", "").isalnum():
        return False
    try:
        with open("/proc/modules", "r", encoding="utf-8") as f:
            for line in f:
                if line.split(" ", 1)[0] == name:
                    return True
    except OSError:
        return False
    return False


def get_kernel_module_blacklisted(name: str) -> bool:
    """Check whether a kernel module is blacklisted via modprobe.d.

    Walks /etc/modprobe.d/ and /usr/lib/modprobe.d/ looking for blacklist
    or install-false directives. Returns True on first match.
    """
    if not name or not name.replace("_", "").replace("-", "").isalnum():
        return False

    pattern_blacklist = re.compile(rf"^\s*blacklist\s+{re.escape(name)}\s*$")
    pattern_install = re.compile(
        rf"^\s*install\s+{re.escape(name)}\s+/bin/(?:false|true)\s*$"
    )

    for d in ("/etc/modprobe.d", "/usr/lib/modprobe.d", "/run/modprobe.d"):
        if not os.path.isdir(d):
            continue
        try:
            entries = os.listdir(d)
        except OSError:
            continue
        for entry in entries:
            if not entry.endswith(".conf"):
                continue
            full = os.path.join(d, entry)
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if pattern_blacklist.match(line):
                            return True
                        if pattern_install.match(line):
                            return True
            except OSError:
                continue
    return False


def get_systemd_unit_state(unit_name: str, timeout: float = 5.0) -> str:
    """Return the systemd unit's active state.

    Possible values: active, inactive, failed, activating, deactivating,
    not-found, unknown. Returns "unknown" on subprocess error or when
    systemctl is not available. The unit_name is validated to prevent
    command injection.
    """
    if not unit_name or not re.match(r"^[A-Za-z0-9@_.\-:]+$", unit_name):
        logger.warning("Refusing systemctl call with invalid unit %r", unit_name)
        return "unknown"

    systemctl = shutil.which("systemctl")
    if not systemctl:
        return "unknown"

    try:
        result = subprocess.run(
            [systemctl, "is-active", unit_name],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("systemctl is-active %s failed: %s", unit_name, exc)
        return "unknown"

    state = (result.stdout or result.stderr or "").strip().lower()
    return state or "unknown"


def is_root() -> bool:
    """True when running as uid 0 (or the equivalent under user namespaces)."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows fallback for development hosts; never True there.
        return False
