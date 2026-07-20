from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone

from auditor import __version__
from auditor.core.levels import LEGACY_SEVERITY_TO_LEVEL
from auditor.core.models import Finding, Severity
from auditor.core.scoring import FORMULA, language_score, overall_score, verdict
# ONE redaction policy tool-wide (CP-3): the ENTIRE userinfo goes (a token in
# the username slot must not survive) + the broad sensitive-key list.
from auditor.fetch import _redact


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
                 execution: dict | None = None) -> dict:
    out_projects = []
    parts = []
    all_counts = {"red": 0, "yellow": 0, "blue": 0}
    lowest: tuple[str, int] | None = None
    for proj in projects:
        findings: list[Finding] = proj["findings"]
        score = language_score(findings)
        counts = _counts(findings)
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
            # `level` (SARIF-compatible error/warning/note) is the semantic
            # contract; `severity` (red/yellow/blue) is DEPRECATED and kept
            # only for backward compatibility with older readers. The identity
            # fields (rule/title/file/line/engine) are untouched, so review_id
            # is stable across this migration.
            "findings": [dict(asdict(f), severity=f.severity.value,
                              level=LEGACY_SEVERITY_TO_LEVEL[f.severity.value])
                         for f in findings],
        })
    report = {
        "tool": "ai-code-auditor",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "engines": engines,
        "summary": {
            "overall_score": overall_score(parts),
            "score_kind": "code_health (higher = safer; experimental indicator)",
            "lowest_language": {"language": lowest[0], "score": lowest[1]} if lowest else None,
            # DEPRECATED: color-keyed counts, kept for old readers only —
            # `level_counts` below is the canonical summary.
            "counts": all_counts,
            "level_counts": {LEGACY_SEVERITY_TO_LEVEL[k]: v
                             for k, v in all_counts.items()},
            "analysis_confidence": confidence,
            # scoring/verdict deliberately still consume the legacy counts —
            # numerically identical either way (1:1 mapping); asserted by test.
            "verdict": verdict(all_counts, confidence if confidence is not None else 100,
                               diagnostics or {}),
        },
        "scoring_formula": FORMULA,
        "projects": out_projects,
        "diagnostics": diagnostics or {},
        "limitations": limitations,
    }
    if catalog is not None:
        # analysis_manifest.catalog = TOOL CAPABILITY AT SCAN TIME (the rules
        # this build ships); analysis_manifest.execution = whether/how each
        # rule actually RAN this run (B2-D). Reports without execution stay
        # manifest schema v1; scoring/verdict never read either block.
        from auditor.core.catalog import analysis_manifest
        report["analysis_manifest"] = analysis_manifest(catalog, execution)
    # redact EVERY outgoing string in one pass — target, findings, diagnostics,
    # limitations, engines (CP-8.7). Numbers/verdict are untouched by _redact.
    return _redact_tree(report)
