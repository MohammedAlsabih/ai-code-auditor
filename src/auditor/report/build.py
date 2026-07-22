from __future__ import annotations

from collections import Counter
from dataclasses import asdict, replace
from datetime import datetime, timezone

from auditor import __version__
from auditor.core.baseline import fingerprint_of_serialized, match_findings
from auditor.core.levels import LEGACY_SEVERITY_TO_LEVEL
from auditor.core.models import Finding, Severity
from auditor.core.policy import (
    GatePolicy,
    effective_level,
    gate_action,
    policy_manifest,
)
from auditor.core.scoring import FORMULA, language_score, overall_score, verdict
# ONE redaction policy tool-wide (CP-3): the ENTIRE userinfo goes (a token in
# the username slot must not survive) + the broad sensitive-key list.
from auditor.fetch import _redact

LEVEL_TO_LEGACY = {v: k for k, v in LEGACY_SEVERITY_TO_LEVEL.items()}


def _redact_tree(value):
    """Recursively redact EVERY string reachable in the report — target,
    diagnostics notes/errors, findings, engine labels (CP-8.7). A credential in
    a clone URL or a diagnostic path must never survive into report.json/md."""
    if isinstance(value, str):
        return _redact(value)
    if isinstance(value, dict):
        return {k: _redact_tree(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_tree(v) for v in value]
    return value


def _counts(findings: list[Finding]) -> dict[str, int]:
    return {sev.value: sum(1 for f in findings if f.severity is sev) for sev in Severity}


def build_report(target: str, projects: list[dict], engines: dict,
                 limitations: list[str], diagnostics: dict | None = None,
                 confidence: int | None = None,
                 catalog: list[dict] | None = None,
                 execution: dict | None = None,
                 policy: GatePolicy | None = None,
                 registry: dict | None = None,
                 baseline: Counter[str] | None = None,
                 gate_scope: str = "all") -> dict:
    """`policy` (B2.8B2-A): rule-level overrides + heuristic-error promotion;
    defaults are the tool contract. `registry` (B2.8B2-B): the separate
    verification axis {"status", "confidence"}. `baseline` (B2.8B2-C): a
    fingerprint multiset from a prior report — every current finding gets
    baseline_state new/unchanged; `gate_scope="new"` makes gate_counts and the
    verdict consume NEW findings only (the report still carries everything,
    and code_health/counts stay whole-report)."""
    policy = policy or GatePolicy()
    out_projects = []
    parts = []
    all_counts = {"red": 0, "yellow": 0, "blue": 0}
    lowest: tuple[str, int] | None = None
    for proj in projects:
        raw_findings: list[Finding] = proj["findings"]
        effective: list[Finding] = []          # severity = EFFECTIVE color
        serialized: list[dict] = []
        for f in raw_findings:
            base_level = LEGACY_SEVERITY_TO_LEVEL[f.severity.value]
            level, overridden_from = effective_level(f.rule_id, base_level, policy)
            # an override moves the finding's code_health/count bucket too —
            # that is the intended policy, recorded transparently below.
            # Identity fields (rule/title/file/line/engine) are untouched, so
            # review_id is stable; precision is never rewritten by policy.
            eff = replace(f, severity=Severity(LEVEL_TO_LEGACY[level]))
            effective.append(eff)
            d = dict(asdict(f), severity=eff.severity.value, level=level,
                     gate_action=gate_action(level, f.precision, policy))
            if overridden_from is not None:
                d["default_level"] = overridden_from
                d["level_source"] = "project_policy"
            serialized.append(d)
        score = language_score(effective)
        counts = _counts(effective)
        for k in all_counts:
            all_counts[k] += counts[k]
        parts.append((score, max(1, proj.get("file_count", 1))))
        if lowest is None or score < lowest[1]:
            lowest = (proj["language"], score)
        out_projects.append({
            "language": proj["language"], "root": proj["root"],
            "frameworks": proj.get("frameworks", []),
            "file_count": proj.get("file_count", 0),
            "score": score,
            # DEPRECATED per-project color counts (compat) + canonical levels
            "counts": counts,
            "level_counts": {LEGACY_SEVERITY_TO_LEVEL[k]: v
                             for k, v in counts.items()},
            # `level` is the EFFECTIVE SARIF-compatible level (post-override);
            # `severity` (red/yellow/blue) is DEPRECATED compat. gate_action
            # is the finding's verdict contribution.
            "findings": serialized,
        })
    reg = registry or {}
    reg_status = reg.get("status", "not_applicable")
    analysis_conf = confidence if confidence is not None else 100
    report = {
        "tool": "ai-code-auditor",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "engines": engines,
        "summary": {
            "overall_score": overall_score(parts),
            "score_kind": "code_health (higher = safer; a severity-ordering "
                          "indicator, not a security claim)",
            "lowest_language": {"language": lowest[0], "score": lowest[1]} if lowest else None,
            # DEPRECATED: color-keyed counts, kept for old readers only —
            # `level_counts` below is the canonical summary.
            "counts": all_counts,
            "level_counts": {LEGACY_SEVERITY_TO_LEVEL[k]: v
                             for k, v in all_counts.items()},
            # analysis completeness ONLY (no registry factor, coverage-v3);
            # `confidence` is a DEPRECATED alias of analysis_confidence kept
            # one release for pre-B2.8B2 readers.
            "analysis_confidence": confidence,
            "confidence": confidence,
            "registry_status": reg_status,
            "registry_confidence": reg.get("confidence"),
        },
        "scoring_formula": FORMULA,
        "projects": out_projects,
        "diagnostics": diagnostics or {},
        "limitations": limitations,
    }
    if catalog is not None:
        # analysis_manifest.catalog = TOOL CAPABILITY AT SCAN TIME (the rules
        # this build ships); analysis_manifest.execution = whether/how each
        # rule actually RAN this run (B2-D); analysis_manifest.policy = the
        # gate policy this scan applied (B2.8B2, ids pre-validated against the
        # catalog). Reports without execution stay manifest schema v1;
        # scoring/verdict never read these blocks.
        from auditor.core.catalog import analysis_manifest
        report["analysis_manifest"] = analysis_manifest(
            catalog, execution, policy=policy_manifest(policy))
    # redact EVERY outgoing string in one pass — target, findings, diagnostics,
    # limitations, engines (CP-8.7). Numbers/verdict are untouched by _redact.
    report = _redact_tree(report)

    # ---- fingerprints + baseline + gating (POST-redaction by design) --------
    # Fingerprints hash the fields as they appear IN THE FILE, so recomputing
    # them from an old report.json (a baseline without fingerprint fields)
    # yields identical values — redaction is deterministic.
    flat: list[dict] = []
    for proj in report["projects"]:
        for d in proj["findings"]:
            d["fingerprint"] = fingerprint_of_serialized(proj["root"], d)
            flat.append(d)
    if baseline is not None:
        states, base_summary = match_findings([d["fingerprint"] for d in flat],
                                              baseline)
        for d, state in zip(flat, states):
            d["baseline_state"] = state
        report["summary"]["baseline"] = {
            "enabled": True,
            "gate_scope": gate_scope,
            **base_summary,
        }
    # gate_counts: the verdict's input. Scope "new" counts NEW findings only
    # (--new-only); the full findings list and code_health/counts above are
    # deliberately whole-report either way.
    gated = [d for d in flat if gate_scope != "new"
             or d.get("baseline_state") == "new"]
    gate_counts = {"block": 0, "review": 0, "informational": 0}
    for d in gated:
        gate_counts[d["gate_action"]] += 1
    report["summary"]["gate_counts"] = gate_counts
    report["summary"]["verdict"] = verdict(gate_counts, analysis_conf,
                                           diagnostics or {}, reg_status)
    return report
