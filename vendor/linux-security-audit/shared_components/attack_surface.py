"""
attack_surface.py - Attack-surface assessment synthesis engine.

SYNOPSIS
    Synthesizes an attack-surface assessment from the audit results produced
    by every selected framework module, plus the HostFacts registry. Produces
    a threat-oriented view that reframes scattered compliance findings into
    exposure DOMAINS a security team, pentester, or risk owner can act on.

DESCRIPTION
    The framework modules each answer "are we compliant with standard X?".
    This engine answers a different question: "where is this host exposed,
    and how badly?". It does so WITHOUT re-running checks - it maps the
    existing AuditResult set onto attack-surface domains and computes a
    severity-weighted exposure score per domain.

    Domains:
      - Network Exposure          (listeners, firewall, exposed services)
      - Authentication & Access   (SSH, PAM, MFA, password policy)
      - Privilege & Escalation    (sudo, SUID/SGID, capabilities)
      - Filesystem Exposure       (world-writable, perms, mounts)
      - Service & Daemon Surface  (running/legacy services)
      - Kernel & Boot Surface     (kernel hardening, modules, GRUB)
      - Container & Orchestration (Docker socket, K8s exposure)
      - Credential & Secret       (keys, history, secrets at rest)
      - Cryptographic Posture     (FIPS, TLS, crypto policy)
      - Detection & Response      (audit, logging, FIM - low coverage raises
                                   effective exposure because intrusions go
                                   unnoticed)

    Each AuditResult is mapped to zero or more domains by matching keywords
    against its category and message. A finding that is not a Pass contributes
    to its domain's exposure in proportion to its severity weight.

PARAMETERS
    build_attack_surface(all_results, host_facts=None) -> AttackSurface
    render_attack_surface_html(surface, execution_info) -> str
    attack_surface_to_dict(surface) -> dict

NOTES
    Version: 3.8
    Stdlib only.
    Read-only synthesis; does not mutate the input results.
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# Severity weights for exposure scoring (higher = more exposure contribution)
_SEVERITY_WEIGHT = {
    "Critical": 10.0,
    "High": 6.0,
    "Medium": 3.0,
    "Low": 1.0,
    "Informational": 0.5,
    "": 2.0,  # unspecified severity treated as low-medium
}

# Status multipliers - only non-Pass statuses contribute to exposure.
_STATUS_MULTIPLIER = {
    "Fail": 1.0,
    "Critical": 1.0,
    "Warning": 0.5,
    "Info": 0.15,
    "Error": 0.25,   # an errored check is an unknown - partial exposure
    "Pass": 0.0,
}

# Domain definitions: domain name -> (keywords, description).
# Keywords are matched (case-insensitive substring) against the combined
# "category message details" text of each result.
_DOMAINS: List[Tuple[str, List[str], str]] = [
    ("Network Exposure",
     ["listening", "listener", "open port", "firewall", "iptables",
      "nftables", "ufw", "firewalld", "external-facing", "exposed",
      "network service", "tcp", "udp", "ingress", "egress", "port "],
     "Network-reachable services and perimeter controls. The primary "
     "remote attack surface."),
    ("Authentication & Access",
     ["ssh", "password authentication", "permitrootlogin", "pam",
      "mfa", "multi-factor", "2fa", "faillock", "lockout", "login",
      "pwquality", "password policy", "credential", "authentication"],
     "How identities prove themselves and how access is gated. Weak "
     "authentication is the most-exploited initial-access vector."),
    ("Privilege & Escalation",
     ["sudo", "suid", "sgid", "setuid", "capabilit", "privilege",
      "root", "wheel", "polkit", "escalation"],
     "Paths from limited access to elevated control. Determines blast "
     "radius once a foothold is gained."),
    ("Filesystem Exposure",
     ["world-writable", "world writable", "permission", "mount", "fstab",
      "sticky bit", "umask", "ownership", "/tmp", "noexec", "nosuid",
      "nodev", "file integrity"],
     "Improper permissions and mount options that enable tampering, "
     "persistence, or data exposure."),
    ("Service & Daemon Surface",
     ["legacy", "cleartext", "telnet", "rsh", "ftp", "tftp", "finger",
      "avahi", "cups", "rpcbind", "service is", "daemon", "unnecessary",
      "running service", "inetd"],
     "Installed and running services. Each daemon is code that can be "
     "attacked; legacy/cleartext services are especially dangerous."),
    ("Kernel & Boot Surface",
     ["kernel", "sysctl", "module", "grub", "boot", "kptr", "kaslr",
      "dmesg", "bpf", "ptrace", "secure boot", "lockdown"],
     "Kernel hardening, loadable-module policy, and boot integrity. "
     "Compromise here is total and stealthy."),
    ("Container & Orchestration",
     ["container", "docker", "podman", "kubernetes", "kubelet", "k8s",
      "runc", "containerd", "cri", "namespace", "cgroup", "image"],
     "Container runtime and orchestration exposure, including socket "
     "access and workload isolation."),
    ("Credential & Secret Exposure",
     ["secret", "private key", "ssh key", "id_rsa", "history file",
      "credential file", "token", "api key", "password file", "shadow",
      "world-readable key", "gpg"],
     "Secrets at rest that, if read, grant access elsewhere. Often the "
     "pivot point in lateral movement."),
    ("Cryptographic Posture",
     ["crypto", "fips", "tls", "ssl", "cipher", "certificate", "openssl",
      "encryption", "luks", "at rest", "in transit", "hashing", "sha1",
      "md5", "weak algorithm"],
     "Strength and configuration of cryptography. Weak crypto undermines "
     "confidentiality and integrity guarantees."),
    ("Detection & Response",
     ["audit", "auditd", "logging", "rsyslog", "journald", "siem",
      "monitoring", "fim", "aide", "tripwire", "alert", "detection",
      "log forwarding", "accounting"],
     "Visibility into attacks. Low coverage does not create an opening "
     "but lets intrusions proceed undetected, raising effective risk."),
]


@dataclass
class DomainAssessment:
    """Per-domain attack-surface assessment."""
    name: str
    description: str
    exposure_score: float          # 0-100 (higher = more exposed)
    rating: str                    # Minimal | Low | Moderate | Elevated | High
    total_findings: int
    fail_count: int
    warning_count: int
    info_count: int
    top_findings: List[dict] = field(default_factory=list)


@dataclass
class AttackSurface:
    """Complete attack-surface assessment."""
    overall_score: float           # 0-100 weighted across domains
    overall_rating: str
    domains: List[DomainAssessment]
    total_findings_considered: int
    highlights: List[dict]         # top cross-domain exposure findings
    host_summary: Dict[str, str] = field(default_factory=dict)


def _rating_for(score: float) -> str:
    if score < 10:
        return "Minimal"
    if score < 25:
        return "Low"
    if score < 50:
        return "Moderate"
    if score < 75:
        return "Elevated"
    return "High"


def _match_domains(result) -> List[int]:
    """Return indices of domains a result maps to (may be empty)."""
    text = " ".join([
        getattr(result, "category", "") or "",
        getattr(result, "message", "") or "",
        getattr(result, "details", "") or "",
    ]).lower()
    matched = []
    for idx, (_name, keywords, _desc) in enumerate(_DOMAINS):
        if any(kw in text for kw in keywords):
            matched.append(idx)
    return matched


def build_attack_surface(all_results, host_facts=None) -> AttackSurface:
    """Synthesize the attack-surface assessment from audit results.

    Args:
        all_results: list of AuditResult objects from all modules.
        host_facts: optional HostFacts for the host summary section.

    Returns:
        AttackSurface dataclass.
    """
    # Accumulators per domain
    n = len(_DOMAINS)
    exposure_raw = [0.0] * n          # accumulated severity*status weight
    max_possible = [0.0] * n          # if every mapped finding were a Pass-fail worst case
    totals = [0] * n
    fails = [0] * n
    warns = [0] * n
    infos = [0] * n
    domain_findings: List[List[dict]] = [[] for _ in range(n)]

    considered = 0
    all_exposure_findings = []

    for r in all_results:
        domains = _match_domains(r)
        if not domains:
            continue
        considered += 1
        sev = (getattr(r, "severity", "") or "").strip().capitalize()
        if sev == "Informational" or sev == "":
            sev_key = sev if sev in _SEVERITY_WEIGHT else ""
        else:
            sev_key = sev if sev in _SEVERITY_WEIGHT else "Medium"
        weight = _SEVERITY_WEIGHT.get(sev_key, 3.0)
        status = getattr(r, "status", "") or ""
        mult = _STATUS_MULTIPLIER.get(status, 0.0)
        contribution = weight * mult

        for d in domains:
            totals[d] += 1
            max_possible[d] += weight  # worst case = this finding fully failing
            exposure_raw[d] += contribution
            if status in ("Fail", "Critical"):
                fails[d] += 1
            elif status == "Warning":
                warns[d] += 1
            elif status == "Info":
                infos[d] += 1
            if mult > 0:
                domain_findings[d].append({
                    "module": getattr(r, "module", ""),
                    "category": getattr(r, "category", ""),
                    "message": getattr(r, "message", ""),
                    "status": status,
                    "severity": sev_key or "Medium",
                    "details": getattr(r, "details", ""),
                    "remediation": getattr(r, "remediation", ""),
                    "_weight": contribution,
                })

        if mult > 0:
            all_exposure_findings.append({
                "module": getattr(r, "module", ""),
                "category": getattr(r, "category", ""),
                "message": getattr(r, "message", ""),
                "status": status,
                "severity": sev_key or "Medium",
                "details": getattr(r, "details", ""),
                "remediation": getattr(r, "remediation", ""),
                "_weight": contribution,
                "domains": [_DOMAINS[d][0] for d in domains],
            })

    domains_out: List[DomainAssessment] = []
    weighted_sum = 0.0
    weight_total = 0.0
    for d in range(n):
        name, _kw, desc = _DOMAINS[d]
        if max_possible[d] > 0:
            score = min(100.0, 100.0 * exposure_raw[d] / max_possible[d])
        else:
            score = 0.0
        # Sort domain findings by contribution. Retain ALL findings (not a
        # top-N slice) and the FULL detail text so the interactive report can
        # show, search, filter, and export complete information.
        top = sorted(domain_findings[d], key=lambda x: -x["_weight"])
        for t in top:
            t.pop("_weight", None)
        domains_out.append(DomainAssessment(
            name=name,
            description=desc,
            exposure_score=round(score, 1),
            rating=_rating_for(score),
            total_findings=totals[d],
            fail_count=fails[d],
            warning_count=warns[d],
            info_count=infos[d],
            top_findings=top,
        ))
        # Domains with more findings weigh slightly more in the overall score
        domain_weight = max(1.0, totals[d] ** 0.5)
        weighted_sum += score * domain_weight
        weight_total += domain_weight

    overall = round(weighted_sum / weight_total, 1) if weight_total else 0.0

    # Cross-domain highlights: top exposure findings overall (keep a
    # generous set; the interactive report paginates/searches client-side).
    highlights = sorted(all_exposure_findings, key=lambda x: -x["_weight"])[:40]
    for h in highlights:
        h.pop("_weight", None)

    host_summary = {}
    if host_facts is not None:
        # Full firewall posture (installed vs active) so a host with, e.g.,
        # iptables active and nftables installed-but-inactive is reported
        # accurately rather than as "none".
        fw_summary = getattr(host_facts, "firewall_tool", "") or "none detected"
        try:
            from shared_components.shared_assessments import get_firewall_posture
            _fw = get_firewall_posture()
            if _fw.installed:
                parts = []
                for t in _fw.installed:
                    state = "active" if t in _fw.active else "inactive"
                    parts.append(f"{t} ({state})")
                fw_summary = ", ".join(parts)
            else:
                fw_summary = "none installed"
        except Exception:
            pass
        host_summary = {
            "Distribution": f"{getattr(host_facts, 'distro_id', '')} "
                            f"{getattr(host_facts, 'distro_version', '')}".strip(),
            "Firewall": fw_summary,
            "External TCP listeners": str(
                getattr(host_facts, "listening_external_count", "n/a")),
            "MAC framework": (
                "SELinux (enforcing)" if getattr(host_facts, "selinux_enforcing", False)
                else "AppArmor" if getattr(host_facts, "apparmor_active", False)
                else "none active"),
            "Auditd": "active" if getattr(host_facts, "auditd_active", False) else "inactive",
            "FIM": getattr(host_facts, "fim_tool", "") or "none",
            "Container runtime": getattr(host_facts, "container_runtime", "") or "none",
        }

    return AttackSurface(
        overall_score=overall,
        overall_rating=_rating_for(overall),
        domains=domains_out,
        total_findings_considered=considered,
        highlights=highlights,
        host_summary=host_summary,
    )


def attack_surface_to_dict(surface: AttackSurface) -> dict:
    """Serialize an AttackSurface to a plain dict (for JSON export)."""
    return {
        "overall_score": surface.overall_score,
        "overall_rating": surface.overall_rating,
        "total_findings_considered": surface.total_findings_considered,
        "host_summary": surface.host_summary,
        "domains": [
            {
                "name": d.name,
                "description": d.description,
                "exposure_score": d.exposure_score,
                "rating": d.rating,
                "total_findings": d.total_findings,
                "fail_count": d.fail_count,
                "warning_count": d.warning_count,
                "info_count": d.info_count,
                "top_findings": d.top_findings,
            }
            for d in surface.domains
        ],
        "highlights": surface.highlights,
    }


def _rating_color(rating: str) -> str:
    return {
        "Minimal": "#2e7d32",
        "Low": "#66bb6a",
        "Moderate": "#fbc02d",
        "Elevated": "#ef6c00",
        "High": "#c62828",
    }.get(rating, "#90a4ae")


def _esc_js(s) -> str:
    """Escape a string for safe embedding inside a JS single-quoted literal."""
    if s is None:
        return ""
    return (str(s).replace("\\", "\\\\").replace("'", "\\'")
            .replace("\n", "\\n").replace("\r", "")
            .replace("<", "\\u003c").replace(">", "\\u003e"))


def render_attack_surface_html(surface: AttackSurface, execution_info) -> str:
    """Render the attack-surface assessment as a fully interactive,
    self-contained HTML report.

    Feature parity with the main compliance report:
      - Light/dark theme toggle (persisted to localStorage)
      - Collapsible domain sections
      - Per-column filters + global search (include/exclude)
      - Sortable columns; column visibility toggles
      - Word-wrapped cells showing FULL (untruncated) finding info
      - Per-table and global export to CSV / JSON / XML
    """
    import json as _json

    hostname = getattr(execution_info, "hostname", "unknown")
    scan_date = getattr(execution_info, "scan_date", "")
    os_version = getattr(execution_info, "os_version", "")
    overall_color = _rating_color(surface.overall_rating)

    # ---- Assemble client-side data model -------------------------------
    # Each table: {id, title, rating, score, rows:[{severity,status,module,
    #   domain(s),finding,details,remediation}]}
    tables = []

    # Table 0: cross-domain highlights
    hl_rows = []
    for h in surface.highlights:
        hl_rows.append({
            "severity": h.get("severity", "Medium"),
            "status": h.get("status", ""),
            "module": h.get("module", ""),
            "domains": ", ".join(h.get("domains", [])),
            "finding": h.get("message", ""),
            "details": h.get("details", ""),
            "remediation": h.get("remediation", ""),
        })
    tables.append({
        "id": "highlights",
        "title": "Top Exposure Findings (cross-domain)",
        "rating": surface.overall_rating,
        "score": surface.overall_score,
        "columns": ["Severity", "Status", "Module", "Domain(s)",
                    "Finding", "Details", "Remediation"],
        "keys": ["severity", "status", "module", "domains",
                 "finding", "details", "remediation"],
        "rows": hl_rows,
    })

    # One table per domain
    for d in surface.domains:
        rows = []
        for f in d.top_findings:
            rows.append({
                "severity": f.get("severity", "Medium"),
                "status": f.get("status", ""),
                "module": f.get("module", ""),
                "finding": f.get("message", ""),
                "details": f.get("details", ""),
                "remediation": f.get("remediation", ""),
            })
        tables.append({
            "id": "dom_" + "".join(ch for ch in d.name.lower()
                                   if ch.isalnum()),
            "title": d.name,
            "rating": d.rating,
            "score": d.exposure_score,
            "description": d.description,
            "meta": {"total": d.total_findings, "fail": d.fail_count,
                     "warn": d.warning_count, "info": d.info_count},
            "columns": ["Severity", "Status", "Module",
                        "Finding", "Details", "Remediation"],
            "keys": ["severity", "status", "module",
                     "finding", "details", "remediation"],
            "rows": rows,
        })

    data_json = _json.dumps({
        "host": {
            "hostname": hostname, "os": os_version, "scan_date": scan_date,
            "overall_score": surface.overall_score,
            "overall_rating": surface.overall_rating,
            "summary": surface.host_summary,
        },
        "tables": tables,
    })

    # Host summary rows (static)
    host_rows = "".join(
        f"<tr><td class='k'>{html.escape(str(k))}</td>"
        f"<td>{html.escape(str(v))}</td></tr>"
        for k, v in surface.host_summary.items()
    )

    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Attack Surface Assessment - """ + html.escape(hostname) + """</title>
<style>
  :root {
    --bg-primary:#ffffff; --bg-secondary:#f5f6f8; --bg-hover:#e8e8e8;
    --text-primary:#1a1a2e; --text-secondary:#666; --border-color:#d9dce1;
    --header-bg:#1a237e; --header-text:#ffffff; --button-bg:#3949ab;
    --button-hover:#283593; --input-bg:#ffffff; --shadow:rgba(0,0,0,0.08);
    --accent:#1a237e; --card:#ffffff;
  }
  [data-theme="dark"] {
    --bg-primary:#15171c; --bg-secondary:#1e2128; --bg-hover:#2a2e37;
    --text-primary:#e4e6eb; --text-secondary:#9aa0a6; --border-color:#3a3f4b;
    --header-bg:#283593; --header-text:#ffffff; --button-bg:#3949ab;
    --button-hover:#5c6bc0; --input-bg:#23262e; --shadow:rgba(0,0,0,0.4);
    --accent:#7986cb; --card:#1e2128;
  }
  * { box-sizing:border-box; }
  body { font-family:Garamond,'Times New Roman',serif; background:var(--bg-secondary);
    color:var(--text-primary); margin:0; padding:0; line-height:1.5;
    transition:background .25s,color .25s; }
  .wrap { max-width:1280px; margin:0 auto; padding:24px; }
  header.main { background:linear-gradient(135deg,#1a237e,#283593); color:#fff;
    padding:24px; display:flex; justify-content:space-between; align-items:center; }
  header.main h1 { margin:0 0 4px 0; font-size:1.8em; }
  header.main .sub { opacity:.85; }
  .theme-toggle { cursor:pointer; background:rgba(255,255,255,.15); border:1px solid rgba(255,255,255,.4);
    color:#fff; border-radius:20px; padding:8px 16px; font-family:inherit; font-size:1em; }
  .theme-toggle:hover { background:rgba(255,255,255,.28); }
  .score-hero { display:flex; align-items:center; gap:28px; background:var(--card);
    border-radius:12px; padding:24px; margin:20px 0; border:1px solid var(--border-color);
    box-shadow:0 2px 8px var(--shadow); }
  .score-dial { min-width:150px; height:150px; border-radius:50%; display:flex;
    flex-direction:column; align-items:center; justify-content:center; color:#fff;
    background:""" + overall_color + """; box-shadow:0 4px 14px var(--shadow); }
  .score-dial .num { font-size:2.8em; font-weight:800; line-height:1; }
  .score-dial .lbl { font-size:1em; letter-spacing:1px; margin-top:4px; }
  section { background:var(--card); border-radius:12px; padding:20px; margin:18px 0;
    border:1px solid var(--border-color); box-shadow:0 2px 8px var(--shadow); }
  section > h2 { margin-top:0; color:var(--accent); border-bottom:2px solid var(--accent);
    padding-bottom:8px; }
  .host-table { width:100%; border-collapse:collapse; }
  .host-table td { padding:5px 10px; border-bottom:1px solid var(--border-color); }
  .host-table td.k { font-weight:700; width:230px; color:var(--accent); }
  .global-controls { display:flex; flex-wrap:wrap; gap:10px; align-items:center;
    background:var(--card); border:1px solid var(--border-color); border-radius:10px;
    padding:14px; margin:18px 0; box-shadow:0 2px 8px var(--shadow); }
  .global-controls input[type=text], .global-controls select { font-family:inherit;
    background:var(--input-bg); color:var(--text-primary); border:1px solid var(--border-color);
    border-radius:6px; padding:7px 10px; font-size:.95em; }
  .global-controls input#globalSearch { min-width:280px; flex:1; }
  button { font-family:inherit; background:var(--button-bg); color:#fff; border:none;
    border-radius:6px; padding:7px 12px; cursor:pointer; font-size:.9em; }
  button:hover { background:var(--button-hover); }
  button.ghost { background:transparent; color:var(--accent); border:1px solid var(--accent); }
  .domain-card { border:1px solid var(--border-color); border-radius:10px; margin:16px 0; overflow:hidden; }
  .domain-head { padding:12px 16px; background:var(--bg-secondary); display:flex;
    align-items:center; justify-content:space-between; gap:12px; cursor:pointer; }
  .domain-head .left { display:flex; align-items:center; gap:12px; flex-wrap:wrap; }
  .domain-head h3 { margin:0; font-size:1.2em; }
  .domain-rating { color:#fff; padding:3px 12px; border-radius:14px; font-weight:700; font-size:.9em; }
  .domain-desc { color:var(--text-secondary); font-size:.92em; margin:4px 0 0 0; flex-basis:100%; }
  .domain-meta { font-size:.85em; color:var(--text-secondary); }
  .domain-meta .m-fail { color:#e53935; font-weight:700; }
  .domain-meta .m-warn { color:#fb8c00; font-weight:700; }
  .domain-meta .m-info { color:#1e88e5; font-weight:700; }
  .caret { transition:transform .2s; display:inline-block; }
  .collapsed .caret { transform:rotate(-90deg); }
  .domain-body { padding:10px 12px; }
  .collapsed .domain-body { display:none; }
  .table-toolbar { display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin-bottom:8px; }
  .table-toolbar .colvis { display:flex; flex-wrap:wrap; gap:8px; font-size:.85em; color:var(--text-secondary); }
  .table-toolbar label { display:inline-flex; align-items:center; gap:3px; }
  table.findings { width:100%; border-collapse:collapse; table-layout:fixed; }
  table.findings th { background:var(--header-bg); color:var(--header-text); text-align:left;
    padding:7px 10px; font-size:.9em; position:relative; cursor:pointer; user-select:none; }
  table.findings th .resize-handle { position:absolute; right:0; top:0; width:6px; height:100%;
    cursor:col-resize; }
  table.findings td { padding:6px 10px; border-bottom:1px solid var(--border-color);
    font-size:.9em; vertical-align:top; white-space:normal; word-break:break-word; overflow-wrap:anywhere; }
  table.findings tr:nth-child(even) td { background:var(--bg-secondary); }
  .col-filter { width:100%; box-sizing:border-box; font-family:inherit; font-size:.85em;
    background:var(--input-bg); color:var(--text-primary); border:1px solid var(--border-color);
    border-radius:4px; padding:3px 5px; }
  .sev,.st { padding:1px 8px; border-radius:10px; font-size:.8em; font-weight:700;
    white-space:nowrap; color:#fff; display:inline-block; }
  .sev-critical{background:#c62828;} .sev-high{background:#ef6c00;}
  .sev-medium{background:#f9a825;color:#222;} .sev-low{background:#66bb6a;}
  .sev-informational{background:#90a4ae;}
  .st-fail{background:#c62828;} .st-warning{background:#ef6c00;}
  .st-info{background:#1565c0;} .st-error{background:#6a1b9a;} .st-pass{background:#2e7d32;}
  .clean { color:#2e7d32; font-style:italic; padding:8px; }
  .disclaimer { background:#fff8e1; border:1px solid #ffe082; border-radius:8px;
    padding:12px 16px; margin:16px 0; font-size:.92em; color:#6d4c00; }
  [data-theme="dark"] .disclaimer { background:#2e2a17; border-color:#5d4d12; color:#e8d9a0; }
  footer { text-align:center; color:var(--text-secondary); padding:20px; font-size:.9em; }
  .rowcount { font-size:.82em; color:var(--text-secondary); }
  @media (max-width:768px){ .score-hero{flex-direction:column;} header.main{flex-direction:column;gap:10px;} }
</style>
</head>
<body>
<header class="main">
  <div>
    <h1>Attack Surface Assessment</h1>
    <div class="sub">""" + html.escape(hostname) + " &middot; " + html.escape(os_version) + " &middot; " + html.escape(scan_date) + """</div>
  </div>
  <button class="theme-toggle" id="themeToggle" onclick="toggleTheme()">&#127769; Dark</button>
</header>
<div class="wrap">

  <div class="score-hero">
    <div class="score-dial">
      <div class="num">""" + f"{surface.overall_score:.0f}" + """</div>
      <div class="lbl">""" + html.escape(surface.overall_rating).upper() + """</div>
    </div>
    <div>
      <h2 style="margin:0 0 8px 0;">Overall Exposure: """ + html.escape(surface.overall_rating) + """</h2>
      <p style="margin:0;">Severity-weighted synthesis of """ + str(surface.total_findings_considered) + """
      exposure-relevant findings across """ + str(len(surface.domains)) + """ domains. Higher = more exposed.
      This is an <strong>assessment aid</strong>, not a compliance score.</p>
    </div>
  </div>

  <div class="disclaimer"><strong>How to read this report.</strong> The attack-surface
  assessment re-frames the audit findings around exposure rather than standards
  conformance. A domain's exposure rises with the number and severity of non-passing
  findings mapped to it. Tables below are searchable, filterable, sortable, and
  exportable; cells show the full finding text.</div>

  <section>
    <h2>Host Summary</h2>
    <table class="host-table"><tbody>""" + host_rows + """</tbody></table>
  </section>

  <div class="global-controls">
    <input type="text" id="globalSearch" placeholder="Global search across all findings..." oninput="applyGlobal()">
    <select id="globalMode" onchange="applyGlobal()">
      <option value="include">Include matches</option>
      <option value="exclude">Exclude matches</option>
    </select>
    <button class="ghost" onclick="document.getElementById('globalSearch').value='';applyGlobal();">Clear</button>
    <span style="flex:1"></span>
    <span style="color:var(--text-secondary);font-size:.9em;">Export all:</span>
    <button onclick="exportAll('csv')">CSV</button>
    <button onclick="exportAll('json')">JSON</button>
    <button onclick="exportAll('xml')">XML</button>
    <button class="ghost" onclick="setAllCollapsed(false)">Expand all</button>
    <button class="ghost" onclick="setAllCollapsed(true)">Collapse all</button>
  </div>

  <section id="highlightsSection"></section>
  <section>
    <h2>Exposure by Domain</h2>
    <div id="domainContainer"></div>
  </section>

  <footer>Generated by Linux Security Audit Project &middot; Attack Surface Assessment &middot;
  Assessment aid derived from audit findings.</footer>
</div>

<script>
const ASDATA = """ + data_json + """;
const RATING_COLOR = {Minimal:'#2e7d32',Low:'#66bb6a',Moderate:'#f9a825',Elevated:'#ef6c00',High:'#c62828'};
const tableState = {};

function esc(s){ return (s==null?'':String(s)).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function sevClass(s){ return 'sev sev-'+String(s||'').toLowerCase(); }
function stClass(s){ return 'st st-'+String(s||'').toLowerCase(); }

function buildTable(t, mount){
  tableState[t.id] = { sortCol:null, sortDir:1, colFilters:{}, hidden:{} };
  const wrap = document.createElement('div');
  let toolbar = '<div class="table-toolbar">'
    + '<button onclick="exportTable(\\''+t.id+'\\',\\'csv\\')">CSV</button>'
    + '<button onclick="exportTable(\\''+t.id+'\\',\\'json\\')">JSON</button>'
    + '<button onclick="exportTable(\\''+t.id+'\\',\\'xml\\')">XML</button>'
    + '<span class="rowcount" id="rc_'+t.id+'"></span>'
    + '<span style="flex:1"></span><span class="colvis" id="cv_'+t.id+'"></span></div>';
  wrap.innerHTML = toolbar;
  const tbl = document.createElement('table');
  tbl.className='findings'; tbl.id='tbl_'+t.id;
  const thead = document.createElement('thead');
  let hrow = '<tr>';
  t.columns.forEach((c,i)=>{ hrow += '<th onclick="sortBy(\\''+t.id+'\\','+i+')" data-col="'+i+'">'+esc(c)+'<span class="resize-handle"></span></th>'; });
  hrow += '</tr><tr>';
  t.columns.forEach((c,i)=>{ hrow += '<td style="background:var(--bg-secondary);padding:3px 6px;"><input class="col-filter" placeholder="Filter" oninput="colFilter(\\''+t.id+'\\','+i+',this.value)"></td>'; });
  hrow += '</tr>';
  thead.innerHTML = hrow;
  tbl.appendChild(thead);
  const tbody = document.createElement('tbody'); tbody.id='tb_'+t.id;
  tbl.appendChild(tbody);
  wrap.appendChild(tbl);
  mount.appendChild(wrap);

  // column visibility toggles
  const cv = wrap.querySelector('#cv_'+t.id);
  t.columns.forEach((c,i)=>{ const id='cvx_'+t.id+'_'+i;
    cv.innerHTML += '<label><input type="checkbox" id="'+id+'" checked onchange="toggleCol(\\''+t.id+'\\','+i+',this.checked)">'+esc(c)+'</label>'; });

  renderRows(t);
  enableResize(tbl);
}

function visibleRows(t){
  const st = tableState[t.id];
  const g = (document.getElementById('globalSearch')||{}).value || '';
  const gmode = (document.getElementById('globalMode')||{}).value || 'include';
  let rows = t.rows.map((r,idx)=>({r,idx}));
  // column filters
  Object.entries(st.colFilters).forEach(([ci,val])=>{
    if(!val) return; const key=t.keys[ci]; const v=val.toLowerCase();
    rows = rows.filter(o => String(o.r[key]||'').toLowerCase().includes(v));
  });
  // global filter
  if(g){ const gv=g.toLowerCase();
    rows = rows.filter(o=>{ const hay=t.keys.map(k=>String(o.r[k]||'')).join(' ').toLowerCase();
      const match=hay.includes(gv); return gmode==='include'?match:!match; });
  }
  // sort
  if(st.sortCol!=null){ const key=t.keys[st.sortCol];
    rows.sort((a,b)=>{ let x=a.r[key]||'',y=b.r[key]||'';
      const nx=parseFloat(x),ny=parseFloat(y);
      if(!isNaN(nx)&&!isNaN(ny)){return (nx-ny)*st.sortDir;}
      return String(x).toLowerCase()<String(y).toLowerCase()?-st.sortDir:(String(x).toLowerCase()>String(y).toLowerCase()?st.sortDir:0); });
  }
  return rows;
}

function renderRows(t){
  const st = tableState[t.id];
  const tb = document.getElementById('tb_'+t.id);
  const rows = visibleRows(t);
  let html='';
  if(rows.length===0){ html = '<tr><td colspan="'+t.columns.length+'" class="clean">No findings match &mdash; or this domain is well controlled.</td></tr>'; }
  rows.forEach(({r})=>{
    html+='<tr>';
    t.keys.forEach((k,i)=>{
      const hidden = st.hidden[i] ? ' style="display:none"' : '';
      let cell;
      if(k==='severity') cell='<span class="'+sevClass(r[k])+'">'+esc(r[k])+'</span>';
      else if(k==='status') cell='<span class="'+stClass(r[k])+'">'+esc(r[k])+'</span>';
      else cell=esc(r[k]);
      html+='<td'+hidden+'>'+cell+'</td>';
    });
    html+='</tr>';
  });
  tb.innerHTML=html;
  const rc=document.getElementById('rc_'+t.id); if(rc) rc.textContent=rows.length+' / '+t.rows.length+' rows';
}

function colFilter(id,ci,val){ tableState[id].colFilters[ci]=val; const t=findTable(id); renderRows(t); }
function sortBy(id,ci){ const st=tableState[id]; if(st.sortCol===ci){st.sortDir*=-1;}else{st.sortCol=ci;st.sortDir=1;} renderRows(findTable(id)); }
function toggleCol(id,ci,vis){ const st=tableState[id]; st.hidden[ci]=!vis;
  const tbl=document.getElementById('tbl_'+id);
  tbl.querySelectorAll('th')[ci].style.display=vis?'':'none';
  tbl.querySelectorAll('thead tr:nth-child(2) td')[ci].style.display=vis?'':'none';
  renderRows(findTable(id)); }
function findTable(id){ return ASDATA.tables.find(t=>t.id===id); }
function applyGlobal(){ ASDATA.tables.forEach(t=>renderRows(t)); }

function enableResize(tbl){
  tbl.querySelectorAll('th .resize-handle').forEach(h=>{
    let startX,startW,th;
    h.addEventListener('mousedown',e=>{ th=e.target.parentElement; startX=e.pageX; startW=th.offsetWidth;
      const mm=ev=>{ th.style.width=Math.max(50,startW+ev.pageX-startX)+'px'; };
      const mu=()=>{ document.removeEventListener('mousemove',mm); document.removeEventListener('mouseup',mu); };
      document.addEventListener('mousemove',mm); document.addEventListener('mouseup',mu); e.stopPropagation(); });
    h.addEventListener('click',e=>e.stopPropagation());
  });
}

// ---- collapsible domains ----
function setAllCollapsed(c){ document.querySelectorAll('.domain-card').forEach(d=>{ d.classList.toggle('collapsed',c); }); }
function toggleDomain(el){ el.closest('.domain-card').classList.toggle('collapsed'); }

// ---- theme ----
function toggleTheme(){ const cur=document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark';
  document.documentElement.setAttribute('data-theme',cur); try{localStorage.setItem('asTheme',cur);}catch(e){}
  document.getElementById('themeToggle').innerHTML = cur==='dark'?'&#9728; Light':'&#127769; Dark'; }
(function(){ let th='light'; try{th=localStorage.getItem('asTheme')||'light';}catch(e){}
  document.documentElement.setAttribute('data-theme',th);
  window.addEventListener('DOMContentLoaded',()=>{ const b=document.getElementById('themeToggle');
    if(b) b.innerHTML = th==='dark'?'&#9728; Light':'&#127769; Dark'; }); })();

// ---- export ----
function rowsForExport(t){ return visibleRows(t).map(o=>{ const obj={}; t.keys.forEach(k=>obj[k]=o.r[k]); return obj; }); }
function dl(name,text,mime){ const b=new Blob([text],{type:mime}); const u=URL.createObjectURL(b);
  const a=document.createElement('a'); a.href=u; a.download=name; a.click(); URL.revokeObjectURL(u); }
function toCSV(cols,keys,rows){ const esc=s=>'"'+String(s==null?'':s).replace(/"/g,'""')+'"';
  let out=cols.map(esc).join(',')+'\\n'; rows.forEach(r=>{ out+=keys.map(k=>esc(r[k])).join(',')+'\\n'; }); return out; }
function toXML(title,rows){ let x='<?xml version="1.0" encoding="UTF-8"?>\\n<?xml-stylesheet type="text/xsl" href="#s"?>\\n';
  x+='<assessment title="'+title.replace(/[<&"]/g,'')+'">\\n';
  rows.forEach(r=>{ x+='  <finding>\\n'; Object.entries(r).forEach(([k,v])=>{ x+='    <'+k+'>'+String(v==null?'':v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')+'</'+k+'>\\n'; }); x+='  </finding>\\n'; });
  x+='</assessment>\\n'; return x; }
function exportTable(id,fmt){ const t=findTable(id); const rows=rowsForExport(t);
  const base='attack-surface-'+id;
  if(fmt==='csv') dl(base+'.csv',toCSV(t.columns,t.keys,rows),'text/csv');
  else if(fmt==='json') dl(base+'.json',JSON.stringify({table:t.title,rows},null,2),'application/json');
  else dl(base+'.xml',toXML(t.title,rows),'application/xml'); }
function exportAll(fmt){
  if(fmt==='json'){ const payload={host:ASDATA.host,tables:ASDATA.tables.map(t=>({title:t.title,rows:rowsForExport(t)}))};
    dl('attack-surface-all.json',JSON.stringify(payload,null,2),'application/json'); return; }
  if(fmt==='csv'){ let out=''; ASDATA.tables.forEach(t=>{ out+='# '+t.title+'\\n'+toCSV(t.columns,t.keys,rowsForExport(t))+'\\n'; });
    dl('attack-surface-all.csv',out,'text/csv'); return; }
  let x='<?xml version="1.0" encoding="UTF-8"?>\\n<attackSurface>\\n';
  ASDATA.tables.forEach(t=>{ x+=' <table title="'+t.title.replace(/[<&"]/g,'')+'">\\n';
    rowsForExport(t).forEach(r=>{ x+='  <finding>\\n'; Object.entries(r).forEach(([k,v])=>{ x+='   <'+k+'>'+String(v==null?'':v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')+'</'+k+'>\\n'; }); x+='  </finding>\\n'; }); x+=' </table>\\n'; });
  x+='</attackSurface>\\n'; dl('attack-surface-all.xml',x,'application/xml'); }

// ---- build page ----
(function init(){
  // highlights section
  const hs=document.getElementById('highlightsSection');
  hs.innerHTML='<h2>'+esc(ASDATA.tables[0].title)+'</h2>';
  buildTable(ASDATA.tables[0], hs);
  // domain cards
  const dc=document.getElementById('domainContainer');
  ASDATA.tables.slice(1).forEach(t=>{
    const card=document.createElement('div'); card.className='domain-card';
    const color=RATING_COLOR[t.rating]||'#90a4ae';
    const m=t.meta||{total:0,fail:0,warn:0,info:0};
    card.innerHTML='<div class="domain-head" onclick="toggleDomain(this)">'
      +'<div class="left"><span class="caret">&#9660;</span><h3>'+esc(t.title)+'</h3>'
      +'<span class="domain-rating" style="background:'+color+'">'+esc(t.rating)+' &middot; '+Math.round(t.score)+'/100</span>'
      +'<span class="domain-meta">'+m.total+' findings &middot; <span class="m-fail">'+m.fail+' fail</span> &middot; <span class="m-warn">'+m.warn+' warn</span> &middot; <span class="m-info">'+m.info+' info</span></span>'
      +'<span class="domain-desc">'+esc(t.description||'')+'</span></div></div>'
      +'<div class="domain-body" id="body_'+t.id+'"></div>';
    dc.appendChild(card);
    buildTable(t, document.getElementById('body_'+t.id));
  });
})();
</script>
</body>
</html>"""
