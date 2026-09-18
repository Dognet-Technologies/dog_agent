"""
profiles.py - Per-distribution audit profiles.

SYNOPSIS
    Provides a built-in set of audit profiles that filter the modules and
    check categories executed for a given Linux distribution. Profiles are
    SUBTRACTIVE: they may exclude modules or categories that are not
    applicable to the target distribution, but they NEVER add or modify
    checks beyond what the modules themselves implement.

DESCRIPTION
    Audit runs default to "full coverage": all 16 modules execute against
    the host. On a homogeneous fleet (e.g., RHEL-9 only), some checks
    are inherently inapplicable: snap/Ubuntu-specific guidance has no
    bearing on a RHEL host, and DNF-specific checks are inapplicable on
    Debian. Pre-v3.7, modules handled this internally with OS detection
    branches. Profiles add an explicit, opt-in filter at the orchestrator
    level: `--profile rhel9` runs only the modules and categories the
    profile declares applicable.

    Profiles are intentionally conservative. The default behavior (no
    profile specified) runs the full audit and remains unchanged.

SECURITY DESIGN
    Profile selection accepts user input (via --profile CLI flag), so the
    implementation enforces strict input validation:

    1. Profile name must match ^[a-z][a-z0-9_-]{0,30}$
       (no path traversal, no shell metacharacters, no injection vectors)
    2. Profile lookup is via dict membership against a hardcoded
       allowlist; unknown names are rejected with an explicit error.
    3. Profile data is BAKED INTO THIS MODULE - no external file loads,
       no environment variable expansion, no JSON/YAML parsing.
    4. Filter operations are SUBTRACTIVE only:
         - exclude_modules: list of module names to skip entirely
         - exclude_categories: list of category prefix strings; results
           with categories starting with any of these are dropped
       Profiles cannot add modules, modify checks, or change severities.
    5. Every profile is reviewable diffable Python source - no dynamic
       code or eval anywhere.
    6. The filter applies AFTER modules execute, so module behavior is
       unchanged regardless of profile selection.

PARAMETERS
    Public API:
        list_profiles() -> List[str]
            Returns the sorted list of valid profile names.

        get_profile(name) -> Profile
            Returns the Profile dataclass for the given name. Raises
            ValueError if the name is invalid or unknown.

        validate_profile_name(name) -> bool
            Returns True iff name matches the strict regex.

        apply_profile(profile, modules) -> List[str]
            Returns the subset of modules to run for the profile.

        filter_results(profile, results) -> List[AuditResult]
            Returns results with excluded categories dropped.

EXAMPLES
    # CLI:
    $ python3 linux_security_audit.py --list-profiles
    $ python3 linux_security_audit.py --profile rhel9

    # Programmatic:
    >>> from shared_components.profiles import get_profile, list_profiles
    >>> list_profiles()
    ['almalinux', 'alpine', 'centos', 'centosstream', 'debian12', 'elementary',
     'fedora', 'generic', 'kali', 'mint', 'mxlinux', 'rhel8', 'rhel9', 'rocky',
     'suse15', 'ubuntu22', 'ubuntu24', 'zorin']
    >>> p = get_profile("rhel9")
    >>> p.exclude_modules
    []
    >>> p.exclude_categories
    ['Snap ', 'Ubuntu Pro', 'apparmor (Debian-default)']

NOTES
    Version: 3.7
    Stdlib only.
    All profiles are immutable (frozen dataclass).
    Adding a new profile is intentionally a code change (security
    posture review required).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, List, Tuple


# ============================================================================
# Validation
# ============================================================================

# Strict profile-name regex. Allows lowercase letters, digits, hyphens,
# and underscores; must start with a letter; bounded length. Prevents:
#   - Path traversal:    no slashes, no dots
#   - Shell injection:   no metacharacters
#   - Argument injection: no leading hyphens
#   - Resource exhaustion: bounded length (32 chars)
_PROFILE_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,30}$")


def validate_profile_name(name: str) -> bool:
    """Return True iff `name` is a syntactically valid profile name."""
    return bool(name) and isinstance(name, str) and bool(
        _PROFILE_NAME_RE.fullmatch(name)
    )


# ============================================================================
# Profile dataclass
# ============================================================================

@dataclass(frozen=True)
class Profile:
    """Immutable audit profile descriptor.

    Fields:
        name:                Profile identifier (matches _PROFILE_NAME_RE).
        description:         Human-readable summary.
        applicable_distros:  Tuple of distro_id strings this profile is
                             intended for (informational; not enforced).
        exclude_modules:     Module names (case-insensitive) to skip
                             entirely. Module names are normalized to
                             lowercase for comparison.
        exclude_categories:  Category prefix strings; an AuditResult
                             whose `category` starts with any of these
                             is dropped from results.
    """

    name: str
    description: str
    applicable_distros: Tuple[str, ...] = ()
    exclude_modules: Tuple[str, ...] = ()
    exclude_categories: Tuple[str, ...] = ()


# ============================================================================
# Built-in profiles
# ============================================================================

# All profiles are hardcoded data. Names match _PROFILE_NAME_RE. Each
# profile's exclusions are intentional and reviewable.

_PROFILES: dict = {
    "generic": Profile(
        name="generic",
        description=(
            "Generic profile. No exclusions. Equivalent to running without "
            "any --profile flag. Provided for explicitness and to anchor "
            "automation pipelines."
        ),
        applicable_distros=("*",),
        exclude_modules=(),
        exclude_categories=(),
    ),
    "rhel9": Profile(
        name="rhel9",
        description=(
            "Red Hat Enterprise Linux 9 (and binary-compatible: AlmaLinux 9, "
            "Rocky 9, Oracle 9). Excludes Debian-family-specific categories."
        ),
        applicable_distros=("rhel", "almalinux", "rocky", "ol", "centos"),
        exclude_modules=(),
        exclude_categories=(
            # Debian/Ubuntu-specific tooling that's inapplicable on RHEL
            "Snap ",                  # snap/snapd not used on RHEL by default
            "Ubuntu Pro",             # Ubuntu-only subscription tooling
            "AppArmor (Debian)",      # AppArmor is Debian-default; RHEL uses SELinux
        ),
    ),
    "rhel8": Profile(
        name="rhel8",
        description=(
            "Red Hat Enterprise Linux 8 (and binary-compatible). Excludes "
            "Debian-family categories and RHEL-9-only newer-kernel features."
        ),
        applicable_distros=("rhel", "almalinux", "rocky", "ol", "centos"),
        exclude_modules=(),
        exclude_categories=(
            "Snap ",
            "Ubuntu Pro",
            "AppArmor (Debian)",
        ),
    ),
    "ubuntu24": Profile(
        name="ubuntu24",
        description=(
            "Ubuntu 24.04 LTS (Noble). Excludes RHEL-family-specific "
            "categories and snap-deprecated checks."
        ),
        applicable_distros=("ubuntu",),
        exclude_modules=(),
        exclude_categories=(
            # RHEL-family-specific tooling that's inapplicable on Ubuntu
            "DNF ",                   # DNF/YUM not present on Ubuntu
            "RPM ",                   # RPM not present on Ubuntu
            "SELinux (RHEL-default)", # AppArmor is Ubuntu-default
        ),
    ),
    "ubuntu22": Profile(
        name="ubuntu22",
        description=(
            "Ubuntu 22.04 LTS (Jammy). Excludes RHEL-family-specific "
            "categories."
        ),
        applicable_distros=("ubuntu",),
        exclude_modules=(),
        exclude_categories=(
            "DNF ",
            "RPM ",
            "SELinux (RHEL-default)",
        ),
    ),
    "debian12": Profile(
        name="debian12",
        description=(
            "Debian 12 (Bookworm). Excludes RHEL-family-specific and "
            "Ubuntu-specific categories."
        ),
        applicable_distros=("debian",),
        exclude_modules=(),
        exclude_categories=(
            "DNF ",
            "RPM ",
            "Snap ",                  # snap not Debian-default
            "Ubuntu Pro",
            "SELinux (RHEL-default)",
        ),
    ),
    "alpine": Profile(
        name="alpine",
        description=(
            "Alpine Linux. Excludes systemd-specific categories (Alpine uses "
            "OpenRC), DNF/RPM, and Debian/Ubuntu-specific checks."
        ),
        applicable_distros=("alpine",),
        exclude_modules=(),
        exclude_categories=(
            "DNF ",
            "RPM ",
            "Snap ",
            "Ubuntu Pro",
            # Note: many systemd-centric checks remain useful on Alpine
            # for evidence-collection purposes; only deeply systemd-specific
            # categories are filtered.
        ),
    ),
    "suse15": Profile(
        name="suse15",
        description=(
            "SUSE Linux Enterprise 15 / openSUSE Leap 15. Excludes Debian-"
            "family-specific categories. SUSE uses zypper and AppArmor by "
            "default; some RHEL/Debian-specific checks are excluded."
        ),
        applicable_distros=("sles", "opensuse-leap", "opensuse-tumbleweed"),
        exclude_modules=(),
        exclude_categories=(
            "Snap ",
            "Ubuntu Pro",
            "DNF ",   # SUSE uses zypper, not DNF
            "SELinux (RHEL-default)",  # SUSE defaults to AppArmor
        ),
    ),
    # ----- v3.9: Additional Debian-family profiles -----
    # These distributions are Debian/Ubuntu derivatives: apt package
    # management, AppArmor by default. They exclude RHEL-family-specific
    # categories. Ubuntu-derivatives (Mint, Zorin, elementary) retain
    # Ubuntu-specific checks (snap, Ubuntu Pro) since those apply; pure
    # Debian derivatives (Kali, MX) exclude snap/Ubuntu Pro.
    "kali": Profile(
        name="kali",
        description=(
            "Kali Linux (Debian-derived, rolling). Security/pentest "
            "distribution. Excludes RHEL-family categories and "
            "Ubuntu-subscription tooling. Note: many tools normally flagged "
            "as attack surface are expected on Kali; review findings in that "
            "context."
        ),
        applicable_distros=("kali",),
        exclude_modules=(),
        exclude_categories=(
            "DNF ", "RPM ", "SELinux (RHEL-default)",
            "Ubuntu Pro", "Snap ",
        ),
    ),
    "mxlinux": Profile(
        name="mxlinux",
        description=(
            "MX Linux (Debian-derived). Uses sysVinit/systemd hybrid and "
            "apt. Excludes RHEL-family and Ubuntu-subscription categories."
        ),
        applicable_distros=("mx",),
        exclude_modules=(),
        exclude_categories=(
            "DNF ", "RPM ", "SELinux (RHEL-default)",
            "Ubuntu Pro", "Snap ",
        ),
    ),
    "mint": Profile(
        name="mint",
        description=(
            "Linux Mint (Ubuntu-derived). apt + AppArmor. Excludes "
            "RHEL-family-specific categories. Retains Ubuntu-derived tooling "
            "checks (Mint is built on Ubuntu LTS)."
        ),
        applicable_distros=("linuxmint",),
        exclude_modules=(),
        exclude_categories=(
            "DNF ", "RPM ", "SELinux (RHEL-default)",
        ),
    ),
    "zorin": Profile(
        name="zorin",
        description=(
            "Zorin OS (Ubuntu-derived). apt + AppArmor. Excludes "
            "RHEL-family-specific categories."
        ),
        applicable_distros=("zorin",),
        exclude_modules=(),
        exclude_categories=(
            "DNF ", "RPM ", "SELinux (RHEL-default)",
        ),
    ),
    "elementary": Profile(
        name="elementary",
        description=(
            "elementary OS (Ubuntu-derived). apt + AppArmor. Excludes "
            "RHEL-family-specific categories."
        ),
        applicable_distros=("elementary",),
        exclude_modules=(),
        exclude_categories=(
            "DNF ", "RPM ", "SELinux (RHEL-default)",
        ),
    ),
    # ----- v3.9: Additional RHEL-family profiles -----
    # dnf/yum package management, SELinux by default. Exclude Debian-family
    # categories. CentOS Stream and Fedora track newer kernels (retain
    # newer-kernel feature checks); CentOS Linux 7/8 are EOL/older.
    "almalinux": Profile(
        name="almalinux",
        description=(
            "AlmaLinux (RHEL-compatible: 8/9). dnf + SELinux. Excludes "
            "Debian-family-specific categories."
        ),
        applicable_distros=("almalinux",),
        exclude_modules=(),
        exclude_categories=(
            "Snap ", "Ubuntu Pro", "AppArmor (Debian)", "APT ",
        ),
    ),
    "rocky": Profile(
        name="rocky",
        description=(
            "Rocky Linux (RHEL-compatible: 8/9). dnf + SELinux. Excludes "
            "Debian-family-specific categories."
        ),
        applicable_distros=("rocky",),
        exclude_modules=(),
        exclude_categories=(
            "Snap ", "Ubuntu Pro", "AppArmor (Debian)", "APT ",
        ),
    ),
    "centos": Profile(
        name="centos",
        description=(
            "CentOS Linux (7/8, EOL). dnf/yum + SELinux. Excludes "
            "Debian-family-specific categories. Note: CentOS Linux is end of "
            "life; consider AlmaLinux/Rocky/CentOS Stream."
        ),
        applicable_distros=("centos",),
        exclude_modules=(),
        exclude_categories=(
            "Snap ", "Ubuntu Pro", "AppArmor (Debian)", "APT ",
        ),
    ),
    "centosstream": Profile(
        name="centosstream",
        description=(
            "CentOS Stream (9/10, RHEL upstream). dnf + SELinux, newer "
            "kernel. Excludes Debian-family-specific categories."
        ),
        applicable_distros=("centos", "centosstream"),
        exclude_modules=(),
        exclude_categories=(
            "Snap ", "Ubuntu Pro", "AppArmor (Debian)", "APT ",
        ),
    ),
    "fedora": Profile(
        name="fedora",
        description=(
            "Fedora (current). dnf + SELinux, latest kernel and crypto "
            "policies. Excludes Debian-family-specific categories."
        ),
        applicable_distros=("fedora",),
        exclude_modules=(),
        exclude_categories=(
            "Snap ", "Ubuntu Pro", "AppArmor (Debian)", "APT ",
        ),
    ),
}


# ============================================================================
# Public API
# ============================================================================

def list_profiles() -> List[str]:
    """Return the sorted list of valid profile names."""
    return sorted(_PROFILES.keys())


def get_profile(name: str) -> Profile:
    """Return the Profile dataclass for the given name.

    Raises ValueError if the name is syntactically invalid or unknown.
    """
    if not validate_profile_name(name):
        raise ValueError(
            f"Invalid profile name: {name!r}. Must match "
            f"^[a-z][a-z0-9_-]{{0,30}}$. Valid profiles: "
            f"{', '.join(list_profiles())}"
        )
    if name not in _PROFILES:
        raise ValueError(
            f"Unknown profile: {name!r}. Valid profiles: "
            f"{', '.join(list_profiles())}"
        )
    return _PROFILES[name]


def apply_profile(profile: Profile, modules: Iterable[str]) -> List[str]:
    """Return the subset of `modules` that should run under `profile`.

    Excludes any module whose name (case-insensitive) appears in the
    profile's exclude_modules tuple. Order is preserved.
    """
    if not isinstance(profile, Profile):
        raise TypeError(
            f"apply_profile: profile must be a Profile instance, not "
            f"{type(profile).__name__}"
        )
    excluded = {m.lower() for m in profile.exclude_modules}
    return [m for m in modules if m.lower() not in excluded]


def filter_results(profile: Profile, results: list) -> list:
    """Return `results` with category-excluded entries dropped.

    Args:
        profile: a Profile instance whose exclude_categories prefixes
                 will be matched against each result's `category`.
        results: list of AuditResult-shaped objects (have a .category attr).

    Returns:
        A new list (not in-place mutation) containing the kept results.
    """
    if not isinstance(profile, Profile):
        raise TypeError(
            f"filter_results: profile must be a Profile instance, not "
            f"{type(profile).__name__}"
        )
    if not profile.exclude_categories:
        return list(results)
    prefixes = profile.exclude_categories
    kept = []
    for r in results:
        cat = getattr(r, "category", None) or ""
        if any(cat.startswith(p) for p in prefixes):
            continue
        kept.append(r)
    return kept


def describe_profile(profile: Profile) -> str:
    """Return a human-readable multi-line description of a profile."""
    if not isinstance(profile, Profile):
        raise TypeError("describe_profile: profile must be a Profile instance")
    lines = [
        f"Profile: {profile.name}",
        f"  Description: {profile.description}",
        f"  Applicable distros: {', '.join(profile.applicable_distros) or '(any)'}",
    ]
    if profile.exclude_modules:
        lines.append(
            f"  Excluded modules ({len(profile.exclude_modules)}): "
            f"{', '.join(profile.exclude_modules)}"
        )
    else:
        lines.append("  Excluded modules: none")
    if profile.exclude_categories:
        lines.append(
            f"  Excluded category prefixes ({len(profile.exclude_categories)}):"
        )
        for c in profile.exclude_categories:
            lines.append(f"    - {c!r}")
    else:
        lines.append("  Excluded category prefixes: none")
    return "\n".join(lines)
