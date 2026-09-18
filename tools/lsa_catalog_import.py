#!/usr/bin/env python3
"""
lsa_catalog_import.py - Static catalog extractor for the vendored
Linux-Security-Audit-Project modules.

Does NOT execute any check. Parses the module source with `ast` and
statically reconstructs, for every AuditResult(...) produced by the module
(directly or via a local "_result"-style wrapper function): a stable check
identifier, category, default severity, and remediation text.

Output: one JSON array per module, written to --out-dir, consumed by the
Rust importer in CyberSheppard-Microsiem (backend-rust/src/services/
lsa_catalog_importer.rs). Re-run whenever the vendored LSA source is
updated (see UPSTREAM_COMMIT.txt).

Usage:
    python3 lsa_catalog_import.py --modules-dir ../vendor/linux-security-audit/modules \
        --out-dir ../../CyberSheppard-Microsiem/database/postgresql/lsa-catalog
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# module filename -> (our framework code, native-id regex applied to the
# resolved message, prefix stripped before storing native_id)
MODULE_CONFIG = {
    "module_nist.py": ("nist", re.compile(r"^NIST-[A-Z]+-\d{3}(?=:)")),
    "module_iso27001.py": ("iso27001", re.compile(r"^ISO27001-A\.8\.\d+-\d{3}(?=:)")),
    "module_cis.py": ("cis", re.compile(r"^\d+(?:\.\d+)+(?=\s)")),
    "module_pci.py": ("pci", re.compile(r"^PCI-\d+(?:\.\d+)+(?=:)")),
    "module_gdpr.py": ("gdpr", re.compile(r"^GDPR-\d+(?:\.\d+)+(?=:)")),  # not expected to match anything today
}

# AuditResult field names we care about extracting from a call site.
FIELDS = ("category", "status", "message", "severity", "details", "remediation", "cross_references")

PLACEHOLDER = "…"  # ellipsis, marks a dynamic (non-statically-resolvable) fragment


@dataclass
class Finding:
    module: str
    native_id: str | None
    fallback_id: str
    message_template: str
    message_prefix: str
    category_template: str
    severity_default: str
    remediation_template: str
    cross_references: dict
    source_line: int


def static_prefix(message: str) -> str:
    """The static (non-dynamic) leading portion of a message, up to the first
    unresolved placeholder — this is the only part of message_template
    guaranteed to appear verbatim in a real, rendered scan result at runtime
    (the parts after a placeholder depend on live system state). Used as the
    match key for the ~20% of findings with no native/stable id: hashing the
    *template* (with placeholder markers) would never match a real message,
    since the runtime message has real values there instead of the marker."""
    idx = message.find(PLACEHOLDER)
    prefix = message if idx == -1 else message[:idx]
    return prefix.rstrip()


def const_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def resolve_get_id_call(call: ast.Call) -> str | None:
    """Statically evaluate get_nist_id(family, n) / get_iso_id(control, n)
    without importing the module (they're pure one-liner f-string formatters,
    reimplemented here to match module_nist.py:218-220 / module_iso27001.py:222-224)."""
    if not isinstance(call.func, ast.Name):
        return None
    args = call.args
    if len(args) != 2:
        return None
    a0, a1 = args
    if not (isinstance(a0, ast.Constant) and isinstance(a1, ast.Constant)):
        return None
    if call.func.id == "get_nist_id":
        return f"NIST-{a0.value}-{int(a1.value):03d}"
    if call.func.id == "get_iso_id":
        return f"ISO27001-A.8.{a0.value}-{int(a1.value):03d}"
    return None


def resolve_str_expr(node: ast.AST | None, local_vars: dict[str, ast.AST] | None = None) -> str:
    """Best-effort static reconstruction of a string-valued expression.
    Constant -> literal. JoinedStr (f-string) -> concatenate constant
    fragments, resolve get_nist_id/get_iso_id calls exactly, replace any
    other dynamic fragment with a placeholder. Name -> resolved against
    local_vars (simple last-assignment-wins lookup within the enclosing
    function) when available. Anything else -> placeholder."""
    if node is None:
        return ""
    if isinstance(node, ast.Constant):
        return str(node.value) if node.value is not None else ""
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant):
                parts.append(str(v.value))
            elif isinstance(v, ast.FormattedValue):
                if isinstance(v.value, ast.Call):
                    resolved = resolve_get_id_call(v.value)
                    if resolved is not None:
                        parts.append(resolved)
                        continue
                if isinstance(v.value, ast.Name) and local_vars and v.value.id in local_vars:
                    parts.append(resolve_str_expr(local_vars[v.value.id], local_vars))
                    continue
                parts.append(PLACEHOLDER)
            else:
                parts.append(PLACEHOLDER)
        return "".join(parts)
    if isinstance(node, ast.Name) and local_vars and node.id in local_vars:
        return resolve_str_expr(local_vars[node.id], local_vars)
    return PLACEHOLDER


def build_local_vars(func: ast.FunctionDef) -> dict[str, ast.AST]:
    """Last-assignment-wins map of simple `name = <str-ish expr>` locals
    within a function body (not nested functions), for resolving `category=cat`
    style call sites."""
    local_vars: dict[str, ast.AST] = {}
    for node in ast.walk(func):
        if isinstance(node, ast.FunctionDef) and node is not func:
            continue  # don't descend into nested function defs
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            local_vars[node.targets[0].id] = node.value
    return local_vars


def resolve_dict_expr(node: ast.AST | None) -> dict:
    if node is None:
        return {}
    if isinstance(node, ast.Constant) and node.value is None:
        return {}
    if isinstance(node, ast.Dict):
        out = {}
        for k, v in zip(node.keys, node.values):
            ks = const_str(k)
            vs = const_str(v)
            if ks is not None and vs is not None:
                out[ks] = vs
        return out
    return {}


def find_wrapper_functions(tree: ast.Module) -> dict[str, ast.FunctionDef]:
    """Any function whose body contains `return AuditResult(...)` (optionally
    nested inside if/try) is treated as a pass-through wrapper. We record its
    own FunctionDef so we can bind call-site args against its parameter names."""
    wrappers: dict[str, ast.FunctionDef] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for sub in ast.walk(node):
            if (
                isinstance(sub, ast.Return)
                and isinstance(sub.value, ast.Call)
                and isinstance(sub.value.func, ast.Name)
                and sub.value.func.id == "AuditResult"
            ):
                wrappers[node.name] = node
                break
    return wrappers


def bind_call_kwargs(call: ast.Call, func_def: ast.FunctionDef | None) -> dict[str, ast.AST]:
    """Resolve a call's arguments (positional + keyword) to a dict of
    {field_name: value_node}. If func_def is given (wrapper call), positional
    args are bound against its parameter names; keyword args always bind by
    name directly (works for both AuditResult(...) and wrapper(...) calls)."""
    bound: dict[str, ast.AST] = {}
    if func_def is not None:
        param_names = [a.arg for a in func_def.args.args]
        for i, arg in enumerate(call.args):
            if i < len(param_names):
                bound[param_names[i]] = arg
    for kw in call.keywords:
        if kw.arg is not None:
            bound[kw.arg] = kw.value
    return bound


def iter_own_scope_calls(func: ast.FunctionDef):
    """Yield Call nodes within func's own body, not descending into any
    nested function/async-function defs (those are visited separately)."""
    def walk(node):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if isinstance(child, ast.Call):
                yield child
            yield from walk(child)
    yield from walk(func)


def extract_findings(path: Path, framework: str, id_re: re.Pattern) -> list[Finding]:
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src, filename=str(path))
    wrappers = find_wrapper_functions(tree)
    findings: list[Finding] = []
    seen_fallback: set[str] = set()

    func_defs = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
    for func in func_defs:
        local_vars = build_local_vars(func)
        for node in iter_own_scope_calls(func):
            target_name = node.func.id if isinstance(node.func, ast.Name) else None
            if target_name == "AuditResult":
                bound = bind_call_kwargs(node, None)
            elif target_name in wrappers:
                bound = bind_call_kwargs(node, wrappers[target_name])
            else:
                continue

            message = resolve_str_expr(bound.get("message"), local_vars)
            category = resolve_str_expr(bound.get("category"), local_vars)
            severity = resolve_str_expr(bound.get("severity"), local_vars) or "Medium"
            remediation = resolve_str_expr(bound.get("remediation"), local_vars)
            cross_refs = resolve_dict_expr(bound.get("cross_references"))

            if not message or message == PLACEHOLDER:
                # exception-handler / degenerate call sites with no real message
                continue

            m = id_re.search(message)
            native_id = m.group(0) if m else None
            prefix = static_prefix(message)

            if native_id is None:
                # Hash the STATIC PREFIX, not the full template: the full
                # template may contain a placeholder for dynamic content that
                # a real scan result never reproduces verbatim (see
                # static_prefix() docstring) — hashing it would make the
                # fallback id unmatchable against a live finding at runtime.
                digest_src = f"{framework}|{category}|{prefix}".encode("utf-8")
                fallback_id = f"{framework}-{hashlib.sha1(digest_src).hexdigest()[:16]}"
                # extremely unlikely, but guard against accidental collisions
                suffix = 0
                base = fallback_id
                while fallback_id in seen_fallback:
                    suffix += 1
                    fallback_id = f"{base}-{suffix}"
            else:
                fallback_id = native_id
            seen_fallback.add(fallback_id)

            findings.append(
                Finding(
                    module=framework,
                    native_id=native_id,
                    fallback_id=fallback_id,
                    message_template=message,
                    message_prefix=prefix,
                    category_template=category,
                    severity_default=severity if severity != PLACEHOLDER else "Medium",
                    remediation_template=remediation,
                    cross_references=cross_refs,
                    source_line=node.lineno,
                )
            )
    return findings


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--modules-dir", required=True, type=Path)
    ap.add_argument("--out-dir", required=True, type=Path)
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    total = 0
    for filename, (framework, id_re) in MODULE_CONFIG.items():
        path = args.modules_dir / filename
        if not path.exists():
            print(f"warn: {path} not found, skipping", file=sys.stderr)
            continue
        findings = extract_findings(path, framework, id_re)

        # Collapse duplicates that share the same effective key: these are
        # almost always OS-family branches (apt vs dnf, etc.) of the same
        # logical check producing an identical id+message at a different
        # source line — only one branch ever runs on a given host, so they
        # represent one catalog entry, not two.
        deduped: dict[str, Finding] = {}
        for f in findings:
            key = f.native_id or f.fallback_id
            deduped.setdefault(key, f)
        findings = list(deduped.values())

        out_path = args.out_dir / f"{framework}.json"
        payload = [
            {
                "module": f.module,
                "native_id": f.native_id,
                "fallback_id": f.fallback_id,
                "message_template": f.message_template,
                "message_prefix": f.message_prefix,
                "category_template": f.category_template,
                "severity_default": f.severity_default,
                "remediation_template": f.remediation_template,
                "cross_references": f.cross_references,
                "source_line": f.source_line,
            }
            for f in findings
        ]
        out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        with_native = sum(1 for f in findings if f.native_id)
        print(f"{framework}: {len(findings)} findings ({with_native} with native id, "
              f"{len(findings) - with_native} fallback) -> {out_path}")
        total += len(findings)
    print(f"total: {total} findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
