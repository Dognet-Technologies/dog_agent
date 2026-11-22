"""
shared_assessments.py - Canonical assessments for checks that appear in
multiple framework modules.

SYNOPSIS
    Provides single-source-of-truth assessment helpers for physical system
    facts that many frameworks audit independently (world-writable files,
    SUID/SGID inventory, unowned files, etc.). Each helper enumerates the
    fact ONCE (cached per process), then returns a canonical result with a
    consistent count, the ACTUAL offending items, a standardized status, a
    standardized detail string, and standardized OS-aware remediation text.

DESCRIPTION
    Before this module, the same physical check (e.g. "no world-writable
    files") was reimplemented in CIS, CISA, CORE, ISO27001, NIST, STIG, and
    others with divergent behavior: some returned Pass/Fail, others
    Pass/Warning; some reported a count, others just "found"/"none"; the
    counts themselves differed (0 vs 5 vs 20) because each used a different
    find invocation (some capped with `head -20`); and none listed the
    actual files. That made the report internally contradictory.

    Each framework check still keeps its own control identifier and message
    (CIS 6.1.10, STIG AC-22, CISA DP-7, ...), but pulls the count, file
    list, status, details, and remediation from the canonical assessment
    here so every framework agrees on the facts and the fix.

PARAMETERS
    get_world_writable_assessment(severity_basis="warning") -> Assessment
    get_suid_sgid_assessment() -> Assessment
    get_unowned_files_assessment() -> Assessment
    clear_assessment_cache() -> None

NOTES
    Version: 3.9
    Stdlib only. Read-only enumeration. Results cached per process; call
    clear_assessment_cache() if the filesystem changes mid-run (not normally
    needed during a single audit).
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from typing import List, Optional

# Cap how many offending paths we enumerate and display. We still report the
# TRUE total count; the list is truncated for readability with a note.
_MAX_LIST = 25
_FIND_TIMEOUT = 20


@dataclass
class Assessment:
    """Canonical result of a shared physical-system assessment."""
    count: int                       # true total count (not capped)
    items: List[str] = field(default_factory=list)  # up to _MAX_LIST paths
    truncated: bool = False          # True if more items than items[] holds
    status: str = "Pass"             # Pass | Warning | Fail | Error
    details: str = ""                # standardized, includes the item list
    remediation: str = ""            # standardized OS-aware remediation
    enumerated: bool = True          # False if enumeration failed (Error)


# ---------------------------------------------------------------------------
# Internal enumeration (cached)
# ---------------------------------------------------------------------------

_CACHE = {}


def clear_assessment_cache() -> None:
    """Clear the per-process assessment cache."""
    _CACHE.clear()


def _run_find(find_cmd: str) -> Optional[List[str]]:
    """Run a find command, return list of paths or None on failure."""
    try:
        p = subprocess.run(
            find_cmd, shell=True, capture_output=True, text=True,
            timeout=_FIND_TIMEOUT,
        )
        # find may exit non-zero due to permission-denied on some paths even
        # while producing valid results; treat stdout as authoritative.
        lines = [ln for ln in p.stdout.splitlines() if ln.strip()]
        return lines
    except Exception:
        return None


def _build_assessment(cache_key: str, find_cmd: str, *,
                      zero_status: str, nonzero_status: str,
                      noun: str, remediation: str) -> Assessment:
    """Enumerate via find_cmd and build a canonical Assessment."""
    if cache_key in _CACHE:
        paths = _CACHE[cache_key]
    else:
        paths = _run_find(find_cmd)
        _CACHE[cache_key] = paths

    if paths is None:
        return Assessment(
            count=-1, items=[], truncated=False, status="Error",
            details=f"Could not enumerate {noun} (find unavailable or timed out)",
            remediation=remediation, enumerated=False,
        )

    count = len(paths)
    shown = paths[:_MAX_LIST]
    truncated = count > _MAX_LIST

    if count == 0:
        status = zero_status
        details = f"No {noun} detected on local filesystems"
    else:
        status = nonzero_status
        listing = "; ".join(shown)
        more = f" (+{count - _MAX_LIST} more)" if truncated else ""
        details = f"{count} {noun} on local filesystems: {listing}{more}"

    return Assessment(
        count=count, items=shown, truncated=truncated, status=status,
        details=details, remediation=remediation, enumerated=True,
    )


# ---------------------------------------------------------------------------
# Public canonical assessments
# ---------------------------------------------------------------------------

def get_world_writable_assessment(severity_basis: str = "warning") -> Assessment:
    """Canonical world-writable FILE assessment.

    Enumerates world-writable regular files on local (xdev) filesystems,
    excluding the legitimately world-writable sticky-bit cases is left to
    callers; this counts plain world-writable files.

    Args:
        severity_basis: "warning" -> non-zero yields Warning (default, used
            by baseline modules); "fail" -> non-zero yields Fail (used by
            strict frameworks like STIG/CIS). The COUNT, ITEMS, DETAILS, and
            REMEDIATION are identical regardless; only the status severity
            differs, reflecting each framework's tolerance.

    Returns:
        Assessment with the true count, up to 25 actual file paths, a
        standardized detail string that includes the file list, and
        standardized remediation.
    """
    nonzero = "Fail" if severity_basis == "fail" else "Warning"
    return _build_assessment(
        cache_key="world_writable_files",
        # Exclude /proc, /sys, /dev defensively; -xdev already keeps us on
        # the root filesystem but be explicit about pseudo-filesystems.
        find_cmd=("find / -xdev -type f -perm -0002 "
                  "-not -path '/proc/*' -not -path '/sys/*' "
                  "-not -path '/dev/*' 2>/dev/null"),
        zero_status="Pass",
        nonzero_status=nonzero,
        noun="world-writable file(s)",
        remediation=(
            "Remove world-write permission from each file and investigate why "
            "it became world-writable:\n"
            "  chmod o-w <file>\n"
            "Review the listed files; legitimate shared-write locations "
            "should use a group with the setgid bit and the sticky bit, not "
            "world-write."
        ),
    )


def get_suid_sgid_assessment(threshold: int = 35) -> Assessment:
    """Canonical SUID/SGID binary inventory assessment.

    Args:
        threshold: count at or below which the status is Pass (a small,
            expected set of SUID/SGID binaries is normal). Above it, Warning.

    Returns:
        Assessment with true count and up to 25 actual binary paths.
    """
    a = _build_assessment(
        cache_key="suid_sgid_files",
        find_cmd=("find / -xdev -type f \\( -perm -4000 -o -perm -2000 \\) "
                  "-not -path '/proc/*' -not -path '/sys/*' 2>/dev/null"),
        zero_status="Pass",
        nonzero_status="Pass",  # provisional; adjusted by threshold below
        noun="SUID/SGID binary(ies)",
        remediation=(
            "Audit each SUID/SGID binary and remove the bit from any not "
            "strictly required:\n"
            "  find / -xdev -type f \\( -perm -4000 -o -perm -2000 \\) "
            "-exec ls -l {} \\;\n"
            "  chmod u-s <file>   # remove SUID\n"
            "  chmod g-s <file>   # remove SGID"
        ),
    )
    if a.enumerated and a.count > threshold:
        a.status = "Warning"
        a.details = a.details.replace(
            "on local filesystems",
            f"on local filesystems (above expected baseline of {threshold})",
            1,
        )
    return a


def get_unowned_files_assessment() -> Assessment:
    """Canonical unowned/ungrouped file assessment (no valid user or group)."""
    return _build_assessment(
        cache_key="unowned_files",
        find_cmd=("find / -xdev \\( -nouser -o -nogroup \\) "
                  "-not -path '/proc/*' -not -path '/sys/*' 2>/dev/null"),
        zero_status="Pass",
        nonzero_status="Warning",
        noun="unowned/ungrouped file(s)",
        remediation=(
            "Assign each unowned file to a valid user and group, or remove it "
            "if orphaned:\n"
            "  find / -xdev \\( -nouser -o -nogroup \\) -exec ls -l {} \\;\n"
            "  chown <user>:<group> <file>"
        ),
    )


# ---------------------------------------------------------------------------
# Firewall posture (installed vs active vs configured) across variants
# ---------------------------------------------------------------------------

@dataclass
class FirewallPosture:
    """Comprehensive firewall posture across all common Linux variants."""
    installed: List[str] = field(default_factory=list)   # tools present
    active: List[str] = field(default_factory=list)      # tools running/enforcing
    configured: List[str] = field(default_factory=list)  # tools with real rules
    ipset_present: bool = False
    ipset_sets: int = 0
    status: str = "Fail"             # Pass | Warning | Fail
    summary: str = ""                # one-line human summary
    details: str = ""                # full multi-line detail
    remediation: str = ""


def _cmd_exists(name: str) -> bool:
    try:
        p = subprocess.run(["bash", "-lc", f"command -v {name}"],
                           capture_output=True, text=True, timeout=4)
        return p.returncode == 0 and bool(p.stdout.strip())
    except Exception:
        return False


def _run_capture(cmd: str, timeout: int = 6):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout)
        return p.returncode, p.stdout or "", p.stderr or ""
    except Exception:
        return 1, "", ""


def get_firewall_posture() -> FirewallPosture:
    """Assess firewall posture comprehensively.

    Distinguishes, for each of ufw / firewalld / nftables / iptables (v4+v6)
    / ipset:
      - INSTALLED: the management binary is present
      - ACTIVE: the service is running / the framework is enforcing
      - CONFIGURED: there is a real, non-default ruleset (not just an empty
        or accept-all policy)

    This directly addresses the gap where a host with a firewall package
    installed but disabled, or running with no rules, was previously reported
    the same as a host with no firewall at all.

    Returns:
        FirewallPosture with installed/active/configured tool lists, an
        overall status, a human summary, full details, and remediation.
    """
    if "firewall_posture" in _CACHE:
        return _CACHE["firewall_posture"]

    installed, active, configured = [], [], []
    detail_lines = []

    # --- ufw ---
    if _cmd_exists("ufw"):
        installed.append("ufw")
        rc, out, _ = _run_capture("ufw status 2>/dev/null")
        is_active = "Status: active" in out
        if is_active:
            active.append("ufw")
            # configured if it has explicit rules beyond the header
            rule_lines = [l for l in out.splitlines()
                          if "ALLOW" in l or "DENY" in l or "REJECT" in l]
            if rule_lines:
                configured.append("ufw")
            detail_lines.append(
                f"ufw: installed, ACTIVE, {len(rule_lines)} rule(s)")
        else:
            detail_lines.append("ufw: installed but INACTIVE")

    # --- firewalld ---
    if _cmd_exists("firewall-cmd"):
        installed.append("firewalld")
        rc, out, _ = _run_capture("firewall-cmd --state 2>/dev/null")
        if "running" in out:
            active.append("firewalld")
            rc2, zones, _ = _run_capture(
                "firewall-cmd --list-all 2>/dev/null")
            if zones.strip():
                configured.append("firewalld")
            detail_lines.append("firewalld: installed, ACTIVE")
        else:
            detail_lines.append("firewalld: installed but not running")

    # --- nftables ---
    if _cmd_exists("nft"):
        installed.append("nftables")
        rc, out, _ = _run_capture("nft list ruleset 2>/dev/null")
        if rc == 0 and out.strip():
            active.append("nftables")
            import re as _re
            has_drop = bool(_re.search(
                r"hook\s+input\s+priority\s+\S+;\s*policy\s+drop;",
                out, _re.MULTILINE))
            has_rules = "chain" in out and len(out.splitlines()) > 5
            if has_drop or has_rules:
                configured.append("nftables")
            detail_lines.append(
                "nftables: installed, ruleset present"
                + (", default-drop input" if has_drop else ""))
        else:
            detail_lines.append("nftables: installed, empty ruleset")

    # --- iptables (legacy / nft-backed) ---
    if _cmd_exists("iptables"):
        installed.append("iptables")
        rc, out, _ = _run_capture("iptables -S 2>/dev/null")
        rules = [l for l in out.splitlines() if l.startswith("-A")]
        policies_drop = any(
            l.startswith("-P INPUT DROP") or l.startswith("-P FORWARD DROP")
            for l in out.splitlines())
        if rules or policies_drop:
            active.append("iptables")
            configured.append("iptables")
            detail_lines.append(
                f"iptables: installed, {len(rules)} rule(s)"
                + (", default-drop policy" if policies_drop else ""))
        else:
            detail_lines.append("iptables: installed, no rules (accept-all)")
        # ip6tables
        rc6, out6, _ = _run_capture("ip6tables -S 2>/dev/null")
        rules6 = [l for l in out6.splitlines() if l.startswith("-A")]
        if rules6:
            detail_lines.append(f"ip6tables: {len(rules6)} IPv6 rule(s)")

    # --- ipset ---
    ipset_present = _cmd_exists("ipset")
    ipset_sets = 0
    if ipset_present:
        installed.append("ipset")
        rc, out, _ = _run_capture("ipset list -n 2>/dev/null")
        ipset_sets = len([l for l in out.splitlines() if l.strip()])
        detail_lines.append(
            f"ipset: installed, {ipset_sets} set(s) defined")

    # --- overall posture ---
    if configured:
        status = "Pass"
        summary = ("Firewall enforcing: "
                   + ", ".join(configured))
    elif active:
        status = "Warning"
        summary = ("Firewall framework active but with no/empty rules: "
                   + ", ".join(active) + " (accept-all)")
    elif installed:
        status = "Fail"
        summary = ("Firewall tooling installed but INACTIVE/unconfigured: "
                   + ", ".join(installed))
    else:
        status = "Fail"
        summary = "No firewall tooling installed or active"

    if not detail_lines:
        detail_lines.append("No firewall frameworks detected (ufw, "
                            "firewalld, nftables, iptables, ipset)")

    remediation = (
        "Establish an enforcing host firewall with a default-deny inbound "
        "policy. Pick ONE primary framework for the distribution:\n"
        "  Debian/Ubuntu: ufw enable; ufw default deny incoming\n"
        "  RHEL/Fedora/SUSE: systemctl enable --now firewalld; "
        "firewall-cmd --set-default-zone=drop\n"
        "  Low-level: nft 'add table inet filter; add chain inet filter "
        "input { type filter hook input priority 0; policy drop; }'\n"
        "If only iptables is present, set default-drop policies and add "
        "explicit allow rules. Use ipset for large IP allow/deny lists."
    )

    posture = FirewallPosture(
        installed=installed, active=active, configured=configured,
        ipset_present=ipset_present, ipset_sets=ipset_sets,
        status=status, summary=summary,
        details=summary + ". " + "; ".join(detail_lines),
        remediation=remediation,
    )
    _CACHE["firewall_posture"] = posture
    return posture
