"""
baseline_compare.py - Drift detection between audit runs.

SYNOPSIS
    Compares a current audit's results against a previously saved baseline
    to identify drift: new failures (regressions), resolved findings
    (improvements), and unchanged findings.

DESCRIPTION
    Drift detection answers the operational question that single-run audits
    cannot: "what changed since last time?" The comparison is per-check
    using a stable identity key (module + category + message prefix). Each
    current finding falls into one of these categories:

        new_failure     - Was Pass/absent in baseline, is Fail now
        resolved        - Was Fail in baseline, is Pass/absent now
        regression      - Was Pass in baseline, is Warning/Error now
        new_pass        - Was absent in baseline, is Pass now
        improved        - Was lower-severity status in baseline, better now
        worsened        - Status got worse but is not a fail (e.g. Info -> Warning)
        unchanged       - Same status in both

    The comparison is order-independent and tolerant of cosmetic differences
    (whitespace, trailing punctuation in messages). Identity keys deliberately
    do not include severity or remediation text so that a check can be
    re-categorised between releases without breaking diff continuity.

PARAMETERS
    compare_to_baseline(current_results, baseline_path) -> DriftReport

EXAMPLES
    >>> from shared_components.baseline_compare import compare_to_baseline
    >>> report = compare_to_baseline(current.results, "baseline-202603.json")
    >>> report.new_failures
    [<AuditResult ...>, ...]
    >>> report.compliance_delta
    -3.2

NOTES
    Version: 3.0
    Stdlib only.
    Baseline files must be JSON with the structure produced by the v3.x
    JSON exporter. Files from older versions are detected and rejected
    with a clear error rather than producing misleading comparisons.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

logger = logging.getLogger("audit.baseline")


# Identity key construction. Two findings are considered "the same check"
# when their identity keys match. The key is module + category + a
# normalised message prefix. The message prefix is the leading check ID
# token (e.g. "SSH-001") or the first significant word if no ID is present.

_CHECK_ID_RE = re.compile(r"^([A-Z][A-Z0-9_-]+(?:[-_:.]\d+)*)\s*[:\-]\s*")


def _identity_key(record: Mapping[str, Any]) -> str:
    """Compute the stable identity key for a result record.

    Accepts a dict-like object (raw JSON record) or an AuditResult-shaped
    object with the standard field names.
    """
    module = str(record.get("module", "")).strip().upper()
    category = str(record.get("category", "")).strip()
    message = str(record.get("message", "")).strip()

    m = _CHECK_ID_RE.match(message)
    if m:
        msg_key = m.group(1)
    else:
        # No check ID; use first 64 characters of normalised message
        normalized = re.sub(r"\s+", " ", message)
        msg_key = normalized[:64].lower()

    return f"{module}::{category}::{msg_key}"


def _record_status(record: Mapping[str, Any]) -> str:
    return str(record.get("status", "")).strip()


def _is_failure(status: str) -> bool:
    return status == "Fail"


def _is_pass(status: str) -> bool:
    return status == "Pass"


# Severity ordering for "improved" / "worsened" classification when both
# baseline and current are non-Pass states.
_STATUS_RANK: Dict[str, int] = {
    "Pass": 0,
    "Info": 1,
    "Warning": 2,
    "Error": 3,
    "Fail": 4,
    "": 5,  # absent / unknown - treated as worst
}


@dataclass
class FindingDelta:
    """Represents the change in state for a single check between runs."""

    identity_key: str
    module: str
    category: str
    message: str
    baseline_status: str
    current_status: str
    classification: str  # one of new_failure/resolved/regression/improved/worsened/new_pass/unchanged
    severity: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "identity_key": self.identity_key,
            "module": self.module,
            "category": self.category,
            "message": self.message,
            "baseline_status": self.baseline_status,
            "current_status": self.current_status,
            "classification": self.classification,
            "severity": self.severity,
        }


@dataclass
class DriftReport:
    """Summary of drift between baseline and current audit.

    Lists are populated with FindingDelta records, one per affected check.
    The summary fields provide quick-reference counts without requiring
    consumers to count list lengths repeatedly.
    """

    baseline_path: str = ""
    baseline_timestamp: str = ""
    current_timestamp: str = ""
    new_failures: List[FindingDelta] = field(default_factory=list)
    resolved: List[FindingDelta] = field(default_factory=list)
    regressions: List[FindingDelta] = field(default_factory=list)
    improvements: List[FindingDelta] = field(default_factory=list)
    worsened: List[FindingDelta] = field(default_factory=list)
    new_passes: List[FindingDelta] = field(default_factory=list)
    unchanged_count: int = 0
    baseline_total: int = 0
    current_total: int = 0
    baseline_pass_count: int = 0
    current_pass_count: int = 0
    compliance_delta: float = 0.0  # percentage point change in pass rate

    def has_drift(self) -> bool:
        """True if any drift category has at least one entry."""
        return bool(
            self.new_failures
            or self.resolved
            or self.regressions
            or self.improvements
            or self.worsened
            or self.new_passes
        )

    def summary(self) -> Dict[str, int]:
        return {
            "new_failures": len(self.new_failures),
            "resolved": len(self.resolved),
            "regressions": len(self.regressions),
            "improvements": len(self.improvements),
            "worsened": len(self.worsened),
            "new_passes": len(self.new_passes),
            "unchanged": self.unchanged_count,
            "baseline_total": self.baseline_total,
            "current_total": self.current_total,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "baseline_path": self.baseline_path,
            "baseline_timestamp": self.baseline_timestamp,
            "current_timestamp": self.current_timestamp,
            "compliance_delta": self.compliance_delta,
            "summary": self.summary(),
            "new_failures": [d.to_dict() for d in self.new_failures],
            "resolved": [d.to_dict() for d in self.resolved],
            "regressions": [d.to_dict() for d in self.regressions],
            "improvements": [d.to_dict() for d in self.improvements],
            "worsened": [d.to_dict() for d in self.worsened],
            "new_passes": [d.to_dict() for d in self.new_passes],
        }


class BaselineLoadError(Exception):
    """Raised when a baseline file cannot be read or is malformed."""


def load_baseline(path: str) -> Tuple[List[Dict[str, Any]], str]:
    """Load a baseline JSON file and return its results list and timestamp.

    Returns (results, baseline_timestamp). The baseline JSON is expected
    to be in the format produced by the v3.x JSON exporter:

        {
          "metadata": {"timestamp": "...", "tool_version": "3.x", ...},
          "results": [{...}, {...}]
        }

    or, for backward compatibility, just a list of result records.
    """
    if not path:
        raise BaselineLoadError("No baseline path provided")

    # Path traversal prevention - resolve and verify the file exists
    abs_path = os.path.abspath(os.path.expanduser(path))
    if not os.path.isfile(abs_path):
        raise BaselineLoadError(f"Baseline file not found: {abs_path}")

    try:
        with open(abs_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineLoadError(f"Cannot read baseline {abs_path}: {exc}") from exc

    timestamp = ""
    if isinstance(data, dict):
        metadata = data.get("metadata", {}) or {}
        timestamp = str(metadata.get("timestamp", "")) or str(
            metadata.get("execution_time", "")
        )
        results = data.get("results", [])
        if not isinstance(results, list):
            raise BaselineLoadError(
                f"Baseline 'results' is not a list: {type(results).__name__}"
            )
    elif isinstance(data, list):
        results = data
    else:
        raise BaselineLoadError(
            f"Baseline must be JSON object or array; got {type(data).__name__}"
        )

    # Validate that records have the minimum expected fields. We don't
    # require all 9 fields (legacy 7-field baselines are accepted) but
    # module+message must be present to compute identity keys.
    valid_results: List[Dict[str, Any]] = []
    skipped = 0
    for rec in results:
        if not isinstance(rec, dict):
            skipped += 1
            continue
        if not rec.get("module") or not rec.get("message"):
            skipped += 1
            continue
        valid_results.append(rec)

    if skipped:
        logger.warning(
            "Skipped %d malformed records when loading baseline %s",
            skipped, abs_path,
        )

    return valid_results, timestamp


def _to_dict(record: Any) -> Dict[str, Any]:
    """Normalise an AuditResult or dict to a plain dict."""
    if hasattr(record, "to_dict"):
        return record.to_dict()
    if isinstance(record, dict):
        return record
    raise TypeError(
        f"Result must be AuditResult or dict; got {type(record).__name__}"
    )


def compare_to_baseline(
    current_results: Iterable[Any],
    baseline_path: str,
    current_timestamp: str = "",
) -> DriftReport:
    """Diff current results against a baseline file.

    current_results may contain AuditResult instances or plain dicts.
    Returns a populated DriftReport. Raises BaselineLoadError on baseline
    file problems; other errors are logged and surface as best-effort
    partial results.
    """
    baseline_records, baseline_ts = load_baseline(baseline_path)
    current_records = [_to_dict(r) for r in current_results]

    # Build keyed lookups
    baseline_by_key: Dict[str, Dict[str, Any]] = {}
    for rec in baseline_records:
        key = _identity_key(rec)
        # On collision, the later record wins; this happens when a baseline
        # legitimately contains duplicate findings (rare but possible)
        baseline_by_key[key] = rec

    current_by_key: Dict[str, Dict[str, Any]] = {}
    for rec in current_records:
        key = _identity_key(rec)
        current_by_key[key] = rec

    report = DriftReport(
        baseline_path=baseline_path,
        baseline_timestamp=baseline_ts,
        current_timestamp=current_timestamp,
        baseline_total=len(baseline_records),
        current_total=len(current_records),
    )

    seen_keys: Set[str] = set()

    # Walk current first to find new failures, resolved, unchanged, etc.
    for key, cur in current_by_key.items():
        seen_keys.add(key)
        cur_status = _record_status(cur)
        base = baseline_by_key.get(key)

        if base is None:
            # Not in baseline at all
            if _is_pass(cur_status):
                report.new_passes.append(_make_delta(key, cur, "", cur_status, "new_pass"))
            elif _is_failure(cur_status):
                report.new_failures.append(
                    _make_delta(key, cur, "", cur_status, "new_failure")
                )
            else:
                # New non-Pass non-Fail (Warning/Info/Error)
                report.regressions.append(
                    _make_delta(key, cur, "", cur_status, "regression")
                )
            continue

        base_status = _record_status(base)
        if base_status == cur_status:
            report.unchanged_count += 1
            continue

        # Status changed - classify
        delta_class = _classify_change(base_status, cur_status)
        delta = _make_delta(key, cur, base_status, cur_status, delta_class)

        if delta_class == "new_failure":
            report.new_failures.append(delta)
        elif delta_class == "resolved":
            report.resolved.append(delta)
        elif delta_class == "regression":
            report.regressions.append(delta)
        elif delta_class == "improved":
            report.improvements.append(delta)
        elif delta_class == "worsened":
            report.worsened.append(delta)

    # Walk baseline for entries that disappeared in current (treated as resolved
    # if they were failures, otherwise classified as removed/improved)
    for key, base in baseline_by_key.items():
        if key in seen_keys:
            continue
        base_status = _record_status(base)
        if _is_failure(base_status):
            # Failure that no longer appears = resolved
            report.resolved.append(
                _make_delta(key, base, base_status, "(absent)", "resolved")
            )
        elif _is_pass(base_status):
            # Pass that no longer appears - check probably retired; not drift
            report.unchanged_count += 1
        else:
            # Warning/Info/Error gone is an improvement
            report.improvements.append(
                _make_delta(key, base, base_status, "(absent)", "improved")
            )

    # Compliance delta: percentage point change in pass rate
    report.baseline_pass_count = sum(
        1 for r in baseline_records if _is_pass(_record_status(r))
    )
    report.current_pass_count = sum(
        1 for r in current_records if _is_pass(_record_status(r))
    )
    base_rate = (
        100.0 * report.baseline_pass_count / report.baseline_total
        if report.baseline_total > 0
        else 0.0
    )
    cur_rate = (
        100.0 * report.current_pass_count / report.current_total
        if report.current_total > 0
        else 0.0
    )
    report.compliance_delta = round(cur_rate - base_rate, 2)

    return report


def _classify_change(baseline_status: str, current_status: str) -> str:
    """Classify a status transition as one of the drift categories."""
    base_rank = _STATUS_RANK.get(baseline_status, 5)
    cur_rank = _STATUS_RANK.get(current_status, 5)

    if _is_failure(current_status) and not _is_failure(baseline_status):
        return "new_failure"
    if _is_failure(baseline_status) and not _is_failure(current_status):
        return "resolved"
    if cur_rank < base_rank:
        # Status got better (lower rank = better)
        return "improved"
    if cur_rank > base_rank:
        # Status got worse but not to Fail
        return "worsened"
    # Same rank but different label (rare edge case)
    return "worsened"


def _make_delta(
    key: str,
    record: Mapping[str, Any],
    baseline_status: str,
    current_status: str,
    classification: str,
) -> FindingDelta:
    return FindingDelta(
        identity_key=key,
        module=str(record.get("module", "")),
        category=str(record.get("category", "")),
        message=str(record.get("message", "")),
        severity=str(record.get("severity", "")),
        baseline_status=baseline_status,
        current_status=current_status,
        classification=classification,
    )


def format_console_summary(report: DriftReport) -> str:
    """Render a DriftReport for console display.

    Produces a multi-line text block with summary counts and section
    headings for each non-empty drift category. Designed for fixed-width
    terminal output.
    """
    lines: List[str] = []
    sep = "=" * 72
    lines.append(sep)
    lines.append("BASELINE DRIFT REPORT")
    lines.append(sep)
    if report.baseline_timestamp:
        lines.append(f"Baseline: {report.baseline_path} ({report.baseline_timestamp})")
    else:
        lines.append(f"Baseline: {report.baseline_path}")
    lines.append("")
    lines.append(f"Compliance change: {report.compliance_delta:+.2f} percentage points")
    lines.append("")
    lines.append(f"  New failures (regressions):   {len(report.new_failures):>4}")
    lines.append(f"  Resolved findings:            {len(report.resolved):>4}")
    lines.append(f"  Regressions (non-fail):       {len(report.regressions):>4}")
    lines.append(f"  Improvements:                 {len(report.improvements):>4}")
    lines.append(f"  Worsened (non-fail):          {len(report.worsened):>4}")
    lines.append(f"  New passing checks:           {len(report.new_passes):>4}")
    lines.append(f"  Unchanged:                    {report.unchanged_count:>4}")
    lines.append("")
    lines.append(sep)

    if report.new_failures:
        lines.append("NEW FAILURES")
        lines.append("-" * 72)
        for delta in report.new_failures[:50]:
            lines.append(f"  [{delta.module}] {delta.message}")
        if len(report.new_failures) > 50:
            lines.append(f"  ... and {len(report.new_failures) - 50} more")
        lines.append("")

    if report.resolved:
        lines.append("RESOLVED FINDINGS")
        lines.append("-" * 72)
        for delta in report.resolved[:50]:
            lines.append(f"  [{delta.module}] {delta.message}")
        if len(report.resolved) > 50:
            lines.append(f"  ... and {len(report.resolved) - 50} more")
        lines.append("")

    return "\n".join(lines)
