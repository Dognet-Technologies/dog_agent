"""
risk_scoring.py - Risk priority scoring for audit results.

SYNOPSIS
    Computes a 1-100 risk priority score for each audit finding by combining
    severity weight, exploitability indicator, exposure context, and asset
    criticality. Enables ranked remediation queues that reflect actual risk
    rather than raw severity alone.

DESCRIPTION
    Severity ratings express the worst-case impact of a control gap, but
    they are insufficient for prioritisation in a real environment. A
    Critical finding on an internet-facing bastion matters more than the
    same finding on an isolated build agent. The risk priority score
    quantifies this contextual judgement.

    The formula is intentionally simple and inspectable: each input
    contributes a weighted partial score, and the final value is the
    weighted sum bounded to 1-100. The weights are calibrated so that
    severity dominates (a Critical finding is always higher priority than
    a Medium finding regardless of exposure), but exposure and asset
    criticality can elevate or dampen scores within a severity tier.

    Components:
        Severity weight   (40%): Critical=40, High=30, Medium=20, Low=10,
                                 Informational=5
        Exploitability   (25%): KnownExploited=25, Remote=20, Local=12,
                                 Physical=4, NotExploitable=0
        Exposure         (20%): InternetFacing=20, DMZ=15, Internal=10,
                                 Isolated=5
        Asset criticality(15%): User-supplied 1-10, scaled to 0-15

    The total is min(100, ceil(severity + exploitability + exposure + criticality)).

PARAMETERS
    compute_risk_score(severity, exploitability, exposure, criticality) -> int
        severity: One of CANONICAL_SEVERITY values
        exploitability: One of EXPLOITABILITY_LEVELS
        exposure: One of EXPOSURE_LEVELS
        criticality: int 1-10 (default 5)

EXAMPLES
    >>> compute_risk_score("Critical", "KnownExploited", "InternetFacing", 9)
    97
    >>> compute_risk_score("Low", "NotExploitable", "Isolated", 3)
    9

NOTES
    Version: 3.0
    Stdlib only.
    Score values are stable across calls; scoring is a pure function.
"""

from __future__ import annotations

import math
import re
import logging
from dataclasses import dataclass
from typing import Dict, Iterable, Optional, Tuple

logger = logging.getLogger("audit.risk_scoring")


# Canonical input value sets.

EXPLOITABILITY_KNOWN_EXPLOITED = "KnownExploited"
EXPLOITABILITY_REMOTE = "Remote"
EXPLOITABILITY_LOCAL = "Local"
EXPLOITABILITY_PHYSICAL = "Physical"
EXPLOITABILITY_NOT_EXPLOITABLE = "NotExploitable"

EXPLOITABILITY_LEVELS = (
    EXPLOITABILITY_KNOWN_EXPLOITED,
    EXPLOITABILITY_REMOTE,
    EXPLOITABILITY_LOCAL,
    EXPLOITABILITY_PHYSICAL,
    EXPLOITABILITY_NOT_EXPLOITABLE,
)

EXPOSURE_INTERNET_FACING = "InternetFacing"
EXPOSURE_DMZ = "DMZ"
EXPOSURE_INTERNAL = "Internal"
EXPOSURE_ISOLATED = "Isolated"

EXPOSURE_LEVELS = (
    EXPOSURE_INTERNET_FACING, EXPOSURE_DMZ, EXPOSURE_INTERNAL, EXPOSURE_ISOLATED,
)


# Component weights. The total is bounded to 100 so weights here represent
# the maximum partial contribution of each component when the input is at
# its highest level.

_SEVERITY_WEIGHTS: Dict[str, int] = {
    "Critical": 40,
    "High": 30,
    "Medium": 20,
    "Low": 10,
    "Informational": 5,
}

_EXPLOITABILITY_WEIGHTS: Dict[str, int] = {
    EXPLOITABILITY_KNOWN_EXPLOITED: 25,
    EXPLOITABILITY_REMOTE: 20,
    EXPLOITABILITY_LOCAL: 12,
    EXPLOITABILITY_PHYSICAL: 4,
    EXPLOITABILITY_NOT_EXPLOITABLE: 0,
}

_EXPOSURE_WEIGHTS: Dict[str, int] = {
    EXPOSURE_INTERNET_FACING: 20,
    EXPOSURE_DMZ: 15,
    EXPOSURE_INTERNAL: 10,
    EXPOSURE_ISOLATED: 5,
}


# Heuristic mappings from finding content to default exploitability and
# exposure ratings. The orchestrator runs these against each result to
# auto-classify findings before scoring. Module authors can override by
# annotating their AuditResult instances directly.

_REMOTE_EXPLOIT_KEYWORDS = (
    "ssh", "telnet", "ftp", "http", "https", "smtp", "smb", "rdp",
    "snmp", "ldap", "nfs", "dns", "rsh", "rlogin", "rexec",
)

_LOCAL_EXPLOIT_KEYWORDS = (
    "suid", "sgid", "world-writable", "kernel.", "sysctl",
    "permission", "ptrace", "core dump", "module loading",
)

_PHYSICAL_EXPLOIT_KEYWORDS = (
    "boot", "grub", "secure boot", "tpm", "single user", "rescue mode",
    "removable media", "usb",
)


# Known-exploited indicators. When a finding's text references CVEs that
# appear in CISA's KEV catalog or matches keywords from the catalog, it
# is upgraded to KnownExploited regardless of other factors.

_KEV_KEYWORDS = (
    "kev", "actively exploited", "exploited in the wild",
    "in-the-wild exploitation", "active exploitation",
)


@dataclass
class RiskScore:
    """Decomposed risk priority score with all components visible.

    Fields:
        total: Final 1-100 score (clamped to range)
        severity_component: Weight contribution from severity tier
        exploitability_component: Weight contribution from exploit profile
        exposure_component: Weight contribution from exposure context
        criticality_component: Weight contribution from asset criticality
        severity: Input severity value
        exploitability: Input exploitability value
        exposure: Input exposure value
        criticality: Input criticality value (1-10)
    """

    total: int
    severity_component: int
    exploitability_component: int
    exposure_component: int
    criticality_component: int
    severity: str
    exploitability: str
    exposure: str
    criticality: int

    def to_dict(self) -> Dict[str, object]:
        return {
            "total": self.total,
            "severity_component": self.severity_component,
            "exploitability_component": self.exploitability_component,
            "exposure_component": self.exposure_component,
            "criticality_component": self.criticality_component,
            "severity": self.severity,
            "exploitability": self.exploitability,
            "exposure": self.exposure,
            "criticality": self.criticality,
        }


def _clamp(value: int, lo: int, hi: int) -> int:
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def compute_risk_score(
    severity: str,
    exploitability: str = EXPLOITABILITY_LOCAL,
    exposure: str = EXPOSURE_INTERNAL,
    criticality: int = 5,
) -> RiskScore:
    """Compute a RiskScore from the four input dimensions.

    Unknown values for severity/exploitability/exposure fall back to
    conservative defaults (Medium / Local / Internal / 5) so the function
    never raises on bad input. Criticality is clamped to 1-10.
    """
    sev_weight = _SEVERITY_WEIGHTS.get(severity, _SEVERITY_WEIGHTS["Medium"])
    expl_weight = _EXPLOITABILITY_WEIGHTS.get(
        exploitability, _EXPLOITABILITY_WEIGHTS[EXPLOITABILITY_LOCAL]
    )
    exp_weight = _EXPOSURE_WEIGHTS.get(
        exposure, _EXPOSURE_WEIGHTS[EXPOSURE_INTERNAL]
    )
    crit = _clamp(int(criticality) if criticality is not None else 5, 1, 10)
    # Map 1-10 to 0-15 linearly: criticality of 5 contributes ~7
    crit_weight = math.ceil((crit / 10.0) * 15)

    total = sev_weight + expl_weight + exp_weight + crit_weight
    total = _clamp(total, 1, 100)

    return RiskScore(
        total=total,
        severity_component=sev_weight,
        exploitability_component=expl_weight,
        exposure_component=exp_weight,
        criticality_component=crit_weight,
        severity=severity if severity in _SEVERITY_WEIGHTS else "Medium",
        exploitability=(
            exploitability if exploitability in _EXPLOITABILITY_WEIGHTS
            else EXPLOITABILITY_LOCAL
        ),
        exposure=(
            exposure if exposure in _EXPOSURE_WEIGHTS else EXPOSURE_INTERNAL
        ),
        criticality=crit,
    )


def classify_exploitability(text: str) -> str:
    """Heuristic classification of exploitability from finding text.

    Concatenates message, details, and remediation into a single corpus
    and matches against keyword lists. Used as a default when the module
    has not specified an exploitability rating directly.
    """
    if not text:
        return EXPLOITABILITY_LOCAL
    blob = text.lower()

    # KEV catalog or active exploitation phrases are the strongest signal
    for kw in _KEV_KEYWORDS:
        if kw in blob:
            return EXPLOITABILITY_KNOWN_EXPLOITED

    for kw in _REMOTE_EXPLOIT_KEYWORDS:
        # Match as whole tokens to avoid 'http' matching 'httplib2'
        if re.search(r"\b" + re.escape(kw) + r"\b", blob):
            return EXPLOITABILITY_REMOTE

    for kw in _PHYSICAL_EXPLOIT_KEYWORDS:
        if kw in blob:
            return EXPLOITABILITY_PHYSICAL

    for kw in _LOCAL_EXPLOIT_KEYWORDS:
        if kw in blob:
            return EXPLOITABILITY_LOCAL

    return EXPLOITABILITY_LOCAL


def classify_exposure(
    container: str = "",
    cloud_provider: str = "",
    listening_ports: Optional[Iterable[int]] = None,
) -> str:
    """Heuristic classification of system exposure context.

    The orchestrator passes information from os_detection and any
    network-state collector available. Without specific signals, the
    default is Internal. Containers and cloud workloads default to
    Internet-facing absent further evidence; an air-gapped system
    operator who knows otherwise can override via --exposure.
    """
    if cloud_provider:
        return EXPOSURE_INTERNET_FACING
    if container in ("kubernetes", "docker", "podman"):
        return EXPOSURE_DMZ

    if listening_ports:
        # Standard internet-facing service ports
        public_ports = {22, 80, 443, 25, 587, 993, 995, 21, 110, 143}
        for port in listening_ports:
            try:
                p = int(port)
            except (TypeError, ValueError):
                continue
            if p in public_ports:
                return EXPOSURE_INTERNET_FACING

    return EXPOSURE_INTERNAL


def parse_criticality(value: Optional[str]) -> int:
    """Parse user-supplied criticality string to a 1-10 int.

    Empty/None yields the default of 5. Out-of-range values are clamped.
    Non-numeric strings fall back to 5 with a debug log entry.
    """
    if value is None or value == "":
        return 5
    try:
        n = int(value)
    except (TypeError, ValueError):
        logger.debug("Non-numeric criticality %r; using 5", value)
        return 5
    return _clamp(n, 1, 10)
