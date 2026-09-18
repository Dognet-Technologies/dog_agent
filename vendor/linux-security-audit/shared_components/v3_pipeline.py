"""
orchestrator_integration.py - High-level audit pipeline.

SYNOPSIS
    Wires the foundation modules together into a coherent post-execution
    pipeline that the orchestrator invokes after module collection
    completes. Provides a single facade so the orchestrator does not
    need to know about the individual foundation modules.

DESCRIPTION
    The audit pipeline runs in fixed phases:

        1. Validation       - normalise statuses/severities, sanitise fields
        2. Correlation      - enrich each result's cross_references via registry
        3. Risk scoring     - compute 1-100 priority for each finding
        4. Compliance scoring - per-module and overall pass-rate calculations
        5. Baseline diff    - if a baseline file is supplied
        6. Export           - JSON metadata with all v3 fields populated

    Each phase is idempotent and side-effect-free with respect to the
    inputs (new objects are produced; the inputs are not mutated). The
    orchestrator can call individual phases directly or run the full
    pipeline through run_pipeline().

PARAMETERS
    Public API:
        AuditPipeline.run_pipeline(results, ...) -> PipelineResult
        enrich_with_correlations(results) -> List[AuditResult]
        compute_risk_priorities(results, os_info, ...) -> Dict[int, RiskScore]
        compute_compliance_scores(results) -> ComplianceScores
        export_json_v3(results, metadata) -> str

EXAMPLES
    >>> pipeline = AuditPipeline()
    >>> outcome = pipeline.run_pipeline(
    ...     results=raw_results,
    ...     os_info=os_info,
    ...     baseline_path="baseline.json",
    ...     asset_criticality=7,
    ... )
    >>> outcome.compliance_scores
    ComplianceScores(simple=87.3, weighted=82.1, severity_adjusted=78.5)

NOTES
    Version: 3.0
    Stdlib only.
    The pipeline does not perform I/O except for baseline loading and
    JSON export when explicitly requested. All other phases operate
    in memory.
"""

from __future__ import annotations

import datetime
import json
import logging
import math
import os
import platform
import socket
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .audit_common import AuditResult
CANONICAL_STATUS = ("Pass", "Fail", "Warning", "Info", "Error")
CANONICAL_SEVERITY = ("Critical", "High", "Medium", "Low", "Informational")
from .os_detection import OSInfo, detect_os
from .correlation_registry import enrich as registry_enrich, get_correlations
from .risk_scoring import (
    RiskScore, compute_risk_score, classify_exploitability,
    classify_exposure, parse_criticality,
    EXPOSURE_INTERNAL, EXPLOITABILITY_LOCAL,
)
from .baseline_compare import (
    DriftReport, BaselineLoadError, compare_to_baseline,
)
from .remediation_bundles import (
    Bundle, get_bundle, resolve_bundle,
)
from .rollback_generator import RollbackGenerator
# Validation layer uses existing audit_common.AuditResult.validate()
class ValidationReport:
    """Compatibility shim for existing AuditResult.validate() output."""
    def __init__(self):
        self.issues = []
        self.results_validated = 0
        self.results_with_issues = 0
    def has_issues(self):
        return bool(self.issues)
    def summary(self):
        if not self.issues:
            return f"OK: {self.results_validated} results, no issues"
        return f"{self.results_validated} validated; {self.results_with_issues} with issues"

def validate_collection(results, strict=False):
    report = ValidationReport()
    for r in results:
        report.results_validated += 1
        if hasattr(r, "validate"):
            ok, issues = r.validate()
            if not ok:
                report.results_with_issues += 1
                report.issues.extend(issues)
    return report

def normalize_collection(results):
    """Existing AuditResult does not need normalization; return as-is."""
    return list(results)


logger = logging.getLogger("audit.pipeline")


# ---------------------------------------------------------------------------
# Compliance scoring
# ---------------------------------------------------------------------------


@dataclass
class ComplianceScores:
    """Multi-method compliance score for an audit run.

    Three scoring methods are provided so consumers can choose the one
    most appropriate for their reporting context:

        simple           - Pass percentage out of all evaluated checks.
                           Easiest to explain to non-technical stakeholders.
        weighted         - Severity-weighted percentage. Critical/High
                           failures count more; passes are credited at
                           their severity weight too.
        severity_adjusted - As weighted, but penalises Fail more heavily
                           than Warning, and Warning more than Info. Best
                           reflects operational risk posture.

    All three are presented as percentages (0.0-100.0).
    """

    simple: float = 0.0
    weighted: float = 0.0
    severity_adjusted: float = 0.0
    threshold: float = 70.0
    passes_threshold_simple: bool = False
    passes_threshold_weighted: bool = False
    passes_threshold_severity_adjusted: bool = False
    total_checks: int = 0
    passes: int = 0
    failures: int = 0
    warnings: int = 0
    informational: int = 0
    errors: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Severity weights for compliance scoring. Higher weights mean a Fail
# in that category drags the overall score down further. Tuned so that
# 10 Critical fails produce roughly the same score impact as 30 Medium
# fails.

_SCORE_WEIGHTS: Dict[str, float] = {
    "Critical": 5.0,
    "High": 3.0,
    "Medium": 2.0,
    "Low": 1.0,
    "Informational": 0.25,
}

# Status credit factors for severity-adjusted scoring.
# Pass=full credit, Info=partial, Warning=reduced, Fail/Error=zero.

_STATUS_CREDIT: Dict[str, float] = {
    "Pass": 1.0,
    "Info": 0.85,
    "Warning": 0.40,
    "Fail": 0.0,
    "Error": 0.0,
}


def compute_compliance_scores(
    results: Sequence[AuditResult],
    threshold: float = 70.0,
) -> ComplianceScores:
    """Compute simple, weighted, and severity-adjusted compliance scores.

    Returns zeroed ComplianceScores if results is empty. The threshold
    parameter controls the pass/fail cutoffs; defaults to 70.0%.
    """
    scores = ComplianceScores(threshold=threshold)

    if not results:
        return scores

    # Tally counts
    for r in results:
        scores.total_checks += 1
        if r.status == "Pass":
            scores.passes += 1
        elif r.status == "Fail":
            scores.failures += 1
        elif r.status == "Warning":
            scores.warnings += 1
        elif r.status == "Info":
            scores.informational += 1
        elif r.status == "Error":
            scores.errors += 1

    # Simple score: pass percentage of evaluated checks (excluding errors
    # because errors mean the check could not run, not that it failed).
    evaluated = scores.total_checks - scores.errors
    if evaluated > 0:
        scores.simple = round(100.0 * scores.passes / evaluated, 2)

    # Weighted score: every Pass adds its severity weight; every Fail
    # adds 0; the result is normalised against the maximum possible.
    weight_total = 0.0
    weight_earned = 0.0
    for r in results:
        if r.status == "Error":
            continue  # exclude errored checks
        w = _SCORE_WEIGHTS.get(r.severity, _SCORE_WEIGHTS["Medium"])
        weight_total += w
        if r.status == "Pass":
            weight_earned += w
    if weight_total > 0:
        scores.weighted = round(100.0 * weight_earned / weight_total, 2)

    # Severity-adjusted score: every check contributes its weight times
    # its status credit; e.g. a Warning at High severity contributes
    # 0.40 * 3.0 = 1.2 toward the earned total.
    sa_total = 0.0
    sa_earned = 0.0
    for r in results:
        if r.status == "Error":
            continue
        w = _SCORE_WEIGHTS.get(r.severity, _SCORE_WEIGHTS["Medium"])
        credit = _STATUS_CREDIT.get(r.status, 0.0)
        sa_total += w
        sa_earned += w * credit
    if sa_total > 0:
        scores.severity_adjusted = round(100.0 * sa_earned / sa_total, 2)

    scores.passes_threshold_simple = scores.simple >= threshold
    scores.passes_threshold_weighted = scores.weighted >= threshold
    scores.passes_threshold_severity_adjusted = (
        scores.severity_adjusted >= threshold
    )

    return scores


def compute_compliance_scores_per_module(
    results: Sequence[AuditResult],
    threshold: float = 70.0,
) -> Dict[str, ComplianceScores]:
    """Compute compliance scores partitioned by module.

    Returns a dict mapping module name to its ComplianceScores. Useful
    for per-framework reporting where overall scores would mask which
    framework is dragging the result down.
    """
    by_module: Dict[str, List[AuditResult]] = {}
    for r in results:
        by_module.setdefault(r.module, []).append(r)

    return {
        module: compute_compliance_scores(module_results, threshold=threshold)
        for module, module_results in by_module.items()
    }


# ---------------------------------------------------------------------------
# Cross-framework correlation enrichment
# ---------------------------------------------------------------------------


def enrich_with_correlations(
    results: Sequence[AuditResult],
    topic_resolver: Optional[callable] = None,
) -> List[AuditResult]:
    """Apply cross-framework correlations from the registry to each result.

    The topic_resolver callable receives an AuditResult and returns the
    correlation topic name (or None). When None is returned, the result
    is left unchanged. When a topic is found, the registry is queried
    and the result's cross_references is updated with any new mappings
    (existing entries are preserved - module-supplied refs win over
    registry-supplied refs).

    If topic_resolver is not provided, the default heuristic resolver
    is used: messages and categories are scanned for distinctive
    keywords (sshd_config, sysctl key names, control IDs) to infer
    the topic. This is best-effort; modules that want guaranteed
    enrichment should populate their own cross_references directly.
    """
    if not results:
        return []

    resolver = topic_resolver or _default_topic_resolver
    out: List[AuditResult] = []

    for r in results:
        topic = resolver(r)
        if not topic:
            out.append(r)
            continue

        merged = registry_enrich(r.cross_references, topic)
        if merged != r.cross_references:
            from dataclasses import replace as dc_replace
            out.append(dc_replace(r, cross_references=merged))
        else:
            out.append(r)

    return out


# Heuristic topic resolver. Maps message/category text fragments to
# correlation topic names. The mapping is intentionally conservative -
# only high-confidence matches are included to avoid mis-correlating.

_TOPIC_HEURISTICS: List[Tuple[str, str]] = [
    # SSH
    ("permitrootlogin", "ssh.permit_root_login"),
    ("ssh protocol", "ssh.protocol_version"),
    ("x11forwarding", "ssh.x11_forwarding"),
    ("maxauthtries", "ssh.max_auth_tries"),
    ("permitemptypasswords", "ssh.empty_passwords"),
    ("clientaliveinterval", "ssh.client_alive_interval"),
    ("logingracetime", "ssh.login_grace_time"),
    ("ssh banner", "ssh.banner"),
    ("hostbasedauthentication", "ssh.host_based_auth"),
    ("permituserenvironment", "ssh.permit_user_environment"),
    ("ignorerhosts", "ssh.ignore_rhosts"),
    # Password
    ("minlen", "password.minimum_length"),
    ("password complexity", "password.complexity"),
    ("password history", "password.history"),
    ("pass_max_days", "password.max_days"),
    ("pass_min_days", "password.min_days"),
    ("pass_warn_age", "password.warn_age"),
    ("password hash", "password.hash_algorithm"),
    ("pam_faillock", "password.lockout_attempts"),
    # Permissions
    ("/etc/passwd", "permissions.passwd"),
    ("/etc/shadow", "permissions.shadow"),
    ("/etc/group", "permissions.group"),
    ("/etc/gshadow", "permissions.gshadow"),
    ("sshd_config", "permissions.sshd_config"),
    # Network sysctl
    ("net.ipv4.ip_forward", "network.ip_forward"),
    ("net.ipv4.conf.all.send_redirects", "network.send_redirects"),
    ("accept_source_route", "network.accept_source_route"),
    ("accept_redirects", "network.accept_redirects"),
    ("secure_redirects", "network.secure_redirects"),
    ("log_martians", "network.log_martians"),
    ("icmp_echo_ignore_broadcasts", "network.icmp_ignore_broadcasts"),
    ("icmp_ignore_bogus_error_responses", "network.icmp_ignore_bogus"),
    ("rp_filter", "network.rp_filter"),
    ("tcp_syncookies", "network.tcp_syncookies"),
    # Kernel
    ("randomize_va_space", "kernel.aslr"),
    ("kptr_restrict", "kernel.kptr_restrict"),
    ("dmesg_restrict", "kernel.dmesg_restrict"),
    ("ptrace_scope", "kernel.ptrace_scope"),
    ("core dump", "kernel.core_dumps"),
    ("unprivileged_bpf", "kernel.unprivileged_bpf"),
    ("user namespaces", "kernel.unprivileged_userns"),
    # Audit
    ("auditd installed", "audit.auditd_installed"),
    ("auditd enabled", "audit.auditd_enabled"),
    # MAC
    ("selinux enforcing", "mac.framework_enforcing"),
    ("apparmor", "mac.framework_enabled"),
    # Boot
    ("grub password", "boot.grub_password"),
    ("grub permission", "boot.grub_permissions"),
    # Firewall
    ("firewall installed", "firewall.installed"),
    ("firewall enabled", "firewall.enabled"),
    # Time
    ("ntp", "time.ntp_configured"),
    ("chrony", "time.ntp_configured"),
    # Banner
    ("/etc/motd", "banner.motd"),
    ("/etc/issue.net", "banner.issue_net"),
    ("/etc/issue", "banner.issue"),
]


def _default_topic_resolver(result: AuditResult) -> Optional[str]:
    """Heuristic resolver. Returns topic name or None."""
    haystack = (
        f"{result.message} {result.category} {result.details}"
    ).lower()
    for needle, topic in _TOPIC_HEURISTICS:
        if needle in haystack:
            return topic
    return None


# ---------------------------------------------------------------------------
# Risk priority scoring
# ---------------------------------------------------------------------------


def compute_risk_priorities(
    results: Sequence[AuditResult],
    os_info: Optional[OSInfo] = None,
    asset_criticality: int = 5,
    listening_ports: Optional[Iterable[int]] = None,
) -> Dict[int, RiskScore]:
    """Compute risk priority scores for every Fail/Warning result.

    Returns a dict keyed by the index of the result in the input
    sequence. Pass/Info/Error results are not scored (they don't
    represent actionable risk by themselves).

    The function uses the result's text to infer exploitability and
    the OS info (if provided) to infer exposure. Module authors who
    want full control can pre-populate their own scoring metadata in
    the cross_references dict using framework code "RISK".
    """
    scored: Dict[int, RiskScore] = {}
    if not results:
        return scored

    if os_info is None:
        os_info = detect_os()

    default_exposure = classify_exposure(
        container=os_info.container,
        cloud_provider=os_info.cloud_provider,
        listening_ports=listening_ports,
    )

    for idx, r in enumerate(results):
        if r.status not in ("Fail", "Warning"):
            continue

        # Allow module override via RISK-prefixed cross_references
        explicit_expl = r.cross_references.get("RISK_EXPLOITABILITY", "")
        explicit_exp = r.cross_references.get("RISK_EXPOSURE", "")

        exploitability = explicit_expl or classify_exploitability(
            f"{r.message} {r.details} {r.remediation}"
        )
        exposure = explicit_exp or default_exposure

        scored[idx] = compute_risk_score(
            severity=r.severity,
            exploitability=exploitability,
            exposure=exposure,
            criticality=asset_criticality,
        )

    return scored


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


@dataclass
class PipelineResult:
    """Outcome of running the full audit pipeline.

    Fields:
        results: Validated and enriched AuditResult list
        validation_report: Issues found during validation
        risk_scores: Risk priority scores keyed by result index
        compliance_scores: Overall compliance scores
        compliance_scores_per_module: Per-module scores
        drift_report: Drift comparison if a baseline was supplied
        os_info: Detected OS info
        elapsed_seconds: Total pipeline execution time
        timestamp: ISO 8601 pipeline run time
    """

    results: List[AuditResult] = field(default_factory=list)
    validation_report: Optional[ValidationReport] = None
    risk_scores: Dict[int, RiskScore] = field(default_factory=dict)
    compliance_scores: Optional[ComplianceScores] = None
    compliance_scores_per_module: Dict[str, ComplianceScores] = field(default_factory=dict)
    drift_report: Optional[DriftReport] = None
    os_info: Optional[OSInfo] = None
    elapsed_seconds: float = 0.0
    timestamp: str = ""

    def summary(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "timestamp": self.timestamp,
            "elapsed_seconds": self.elapsed_seconds,
            "result_count": len(self.results),
        }
        if self.compliance_scores:
            out["compliance_scores"] = self.compliance_scores.to_dict()
        if self.validation_report:
            out["validation"] = {
                "issues": len(self.validation_report.issues),
                "results_with_issues": self.validation_report.results_with_issues,
            }
        if self.drift_report:
            out["drift"] = self.drift_report.summary()
        if self.os_info:
            out["os"] = {
                "distro": self.os_info.distro_id,
                "version": self.os_info.version_id,
                "family": self.os_info.family,
                "kernel": self.os_info.kernel.raw,
            }
        return out


class AuditPipeline:
    """High-level audit post-processing pipeline.

    Construct once per audit run. Pass collected results to
    run_pipeline() to execute all phases and obtain a PipelineResult.
    """

    def __init__(
        self,
        threshold: float = 70.0,
        validation_strict: bool = False,
        topic_resolver: Optional[callable] = None,
    ) -> None:
        self.threshold = float(threshold)
        self.validation_strict = bool(validation_strict)
        self.topic_resolver = topic_resolver

    def run_pipeline(
        self,
        results: Sequence[AuditResult],
        os_info: Optional[OSInfo] = None,
        baseline_path: str = "",
        asset_criticality: int = 5,
        listening_ports: Optional[Iterable[int]] = None,
    ) -> PipelineResult:
        """Execute all post-execution phases against the given results."""
        import time
        start = time.monotonic()

        outcome = PipelineResult()
        outcome.os_info = os_info or detect_os()

        # Phase 1: Validation
        validation_report = validate_collection(
            results, strict=self.validation_strict
        )
        outcome.validation_report = validation_report

        normalised = normalize_collection(results)
        normalised_list = list(normalised)

        # Phase 2: Correlation enrichment
        enriched = enrich_with_correlations(
            normalised_list, topic_resolver=self.topic_resolver
        )

        # Phase 3: Risk scoring
        risk_scores = compute_risk_priorities(
            enriched,
            os_info=outcome.os_info,
            asset_criticality=asset_criticality,
            listening_ports=listening_ports,
        )

        # Phase 4: Compliance scoring
        outcome.compliance_scores = compute_compliance_scores(
            enriched, threshold=self.threshold
        )
        outcome.compliance_scores_per_module = (
            compute_compliance_scores_per_module(enriched, threshold=self.threshold)
        )

        # Phase 5: Baseline diff (if requested)
        if baseline_path:
            try:
                outcome.drift_report = compare_to_baseline(
                    enriched,
                    baseline_path,
                    current_timestamp=outcome.timestamp,
                )
            except BaselineLoadError as exc:
                logger.error("Baseline load failed: %s", exc)
                # Continue without drift report

        outcome.results = enriched
        outcome.risk_scores = risk_scores
        outcome.timestamp = (
            datetime.datetime.now().astimezone().isoformat(timespec="seconds")
        )
        outcome.elapsed_seconds = round(time.monotonic() - start, 4)

        return outcome


# ---------------------------------------------------------------------------
# Bundle resolution
# ---------------------------------------------------------------------------


def resolve_bundle_to_findings(
    bundle_name: str,
    results: Sequence[AuditResult],
    topic_resolver: Optional[callable] = None,
) -> Tuple[Optional[Bundle], List[AuditResult]]:
    """Translate a bundle name to the findings in the current audit it covers.

    Returns (bundle, matched_findings). If the bundle name is unknown,
    bundle is None and matched_findings is empty. Otherwise matched_findings
    are the AuditResults whose topic falls within the bundle's included_topics
    AND whose status is Fail or Warning (the only statuses that warrant
    remediation).

    The resolver is the same heuristic used by enrich_with_correlations.
    """
    bundle = get_bundle(bundle_name)
    if bundle is None:
        return None, []

    bundle_topics = set(bundle.included_topics)
    resolver = topic_resolver or _default_topic_resolver
    matched: List[AuditResult] = []

    for r in results:
        if r.status not in ("Fail", "Warning"):
            continue
        topic = resolver(r)
        if topic and topic in bundle_topics:
            matched.append(r)

    return bundle, matched


# ---------------------------------------------------------------------------
# v3 JSON export
# ---------------------------------------------------------------------------


def build_metadata(
    os_info: Optional[OSInfo] = None,
    tool_version: str = "3.0.0",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Assemble the metadata block included with v3 JSON exports.

    Includes hostname, OS detection results, tool version, timestamp,
    and any extra fields supplied by the orchestrator (e.g. CLI args).
    """
    if os_info is None:
        os_info = detect_os()

    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = ""

    metadata: Dict[str, Any] = {
        "tool_version": tool_version,
        "schema_version": "3.0",
        "timestamp": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "hostname": hostname,
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "os": {
            "distro_id": os_info.distro_id,
            "distro_name": os_info.distro_name,
            "version_id": os_info.version_id,
            "version_codename": os_info.version_codename,
            "family": os_info.family,
            "package_manager": os_info.package_manager,
            "init_system": os_info.init_system,
            "mac_framework": os_info.mac_framework,
            "firewall": os_info.firewall,
            "container": os_info.container,
            "cloud_provider": os_info.cloud_provider,
            "architecture": os_info.architecture,
            "kernel": {
                "raw": os_info.kernel.raw,
                "major": os_info.kernel.major,
                "minor": os_info.kernel.minor,
                "patch": os_info.kernel.patch,
                "flavour": os_info.kernel.flavour,
            },
            "eol": os_info.eol,
            "detection_source": os_info.detection_source,
        },
    }

    if extra:
        for k, v in extra.items():
            if k not in metadata:
                metadata[k] = v

    return metadata


def export_json_v3(
    pipeline_result: PipelineResult,
    output_path: str = "",
    extra_metadata: Optional[Dict[str, Any]] = None,
    indent: int = 2,
) -> str:
    """Serialise a PipelineResult as v3-format JSON.

    If output_path is provided, write to that path with mode 0o600
    (results may contain sensitive details about the host configuration).
    Returns the JSON string regardless of whether it was written to disk.
    """
    metadata = build_metadata(
        os_info=pipeline_result.os_info,
        extra=extra_metadata,
    )
    if pipeline_result.compliance_scores:
        metadata["compliance_scores"] = pipeline_result.compliance_scores.to_dict()
    if pipeline_result.compliance_scores_per_module:
        metadata["compliance_scores_per_module"] = {
            m: s.to_dict()
            for m, s in pipeline_result.compliance_scores_per_module.items()
        }
    if pipeline_result.validation_report:
        metadata["validation"] = {
            "results_validated": pipeline_result.validation_report.results_validated,
            "results_with_issues": pipeline_result.validation_report.results_with_issues,
            "issue_count": len(pipeline_result.validation_report.issues),
        }

    payload: Dict[str, Any] = {
        "metadata": metadata,
        "results": [],
    }

    risk_scores = pipeline_result.risk_scores
    for idx, r in enumerate(pipeline_result.results):
        record = r.to_dict()
        score = risk_scores.get(idx)
        if score is not None:
            record["risk_priority"] = score.to_dict()
        payload["results"].append(record)

    if pipeline_result.drift_report:
        payload["drift"] = pipeline_result.drift_report.to_dict()

    json_text = json.dumps(payload, indent=indent, default=str)

    if output_path:
        abs_path = os.path.abspath(os.path.expanduser(output_path))
        parent = os.path.dirname(abs_path) or "."
        if not os.path.isdir(parent):
            raise OSError(f"Output directory does not exist: {parent}")

        # Atomic write with secure mode
        tmp = abs_path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(json_text)
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        os.rename(tmp, abs_path)

    return json_text


# ---------------------------------------------------------------------------
# Helpers for the orchestrator
# ---------------------------------------------------------------------------


def auto_log_path(base_dir: str = "logs") -> str:
    """Compute the default log file path used when --log-file is omitted.

    Format: <base_dir>/audit-<hostname>-<YYYYMMDD-HHMMSS>.log
    The directory is created if missing (mode 0o755). Hostname is
    sanitised to filesystem-safe characters.
    """
    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = "unknown"
    # Sanitise hostname to alphanumerics+hyphens
    import re as _re
    hostname = _re.sub(r"[^A-Za-z0-9_-]", "-", hostname)[:64] or "unknown"

    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"audit-{hostname}-{timestamp}.log"

    abs_dir = os.path.abspath(os.path.expanduser(base_dir))
    try:
        os.makedirs(abs_dir, mode=0o755, exist_ok=True)
    except OSError as exc:
        logger.warning("Cannot create log directory %s: %s", abs_dir, exc)

    return os.path.join(abs_dir, filename)


def render_pipeline_summary(outcome: PipelineResult, max_width: int = 78) -> str:
    """Render a PipelineResult as a console summary block."""
    lines: List[str] = []
    sep = "=" * max_width
    lines.append(sep)
    lines.append("AUDIT PIPELINE SUMMARY")
    lines.append(sep)
    lines.append(f"Timestamp:    {outcome.timestamp}")
    lines.append(f"Elapsed:      {outcome.elapsed_seconds:.3f}s")
    lines.append(f"Results:      {len(outcome.results)}")
    if outcome.os_info:
        lines.append(
            f"Platform:     {outcome.os_info.distro_name or outcome.os_info.distro_id} "
            f"{outcome.os_info.version_id} ({outcome.os_info.family})"
        )
    lines.append("")

    cs = outcome.compliance_scores
    if cs:
        lines.append("Compliance Scores:")
        lines.append(
            f"  Simple:            {cs.simple:>6.2f}%  "
            f"({'PASS' if cs.passes_threshold_simple else 'FAIL'} @ {cs.threshold:.0f}%)"
        )
        lines.append(
            f"  Weighted:          {cs.weighted:>6.2f}%  "
            f"({'PASS' if cs.passes_threshold_weighted else 'FAIL'} @ {cs.threshold:.0f}%)"
        )
        lines.append(
            f"  Severity-Adjusted: {cs.severity_adjusted:>6.2f}%  "
            f"({'PASS' if cs.passes_threshold_severity_adjusted else 'FAIL'} @ {cs.threshold:.0f}%)"
        )
        lines.append("")
        lines.append(
            f"  Pass: {cs.passes:>5}   Fail: {cs.failures:>5}   "
            f"Warn: {cs.warnings:>5}   Info: {cs.informational:>5}   "
            f"Error: {cs.errors:>5}"
        )
        lines.append("")

    if outcome.risk_scores:
        # Top-N highest-priority findings
        top = sorted(
            outcome.risk_scores.items(),
            key=lambda kv: kv[1].total,
            reverse=True,
        )[:10]
        if top:
            lines.append("Top 10 Risk Priorities:")
            for idx, score in top:
                if idx >= len(outcome.results):
                    continue
                r = outcome.results[idx]
                msg = r.message[:60]
                lines.append(f"  [{score.total:>3}] {r.severity:>13} {r.module:>10} | {msg}")
            lines.append("")

    if outcome.drift_report:
        d = outcome.drift_report
        lines.append("Baseline Drift:")
        lines.append(f"  Compliance change: {d.compliance_delta:+.2f} pp")
        lines.append(f"  New failures:      {len(d.new_failures)}")
        lines.append(f"  Resolved:          {len(d.resolved)}")
        lines.append(f"  Regressions:       {len(d.regressions)}")
        lines.append("")

    if outcome.validation_report and outcome.validation_report.has_issues():
        vr = outcome.validation_report
        lines.append(f"Validation: {vr.summary()}")
        lines.append("")

    lines.append(sep)
    return "\n".join(lines)
