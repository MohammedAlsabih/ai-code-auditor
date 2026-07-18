from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone

from auditor import __version__
from auditor.core.models import Finding, Severity
from auditor.core.scoring import FORMULA, language_score, overall_score, verdict
# ONE redaction policy tool-wide (CP-3): the ENTIRE userinfo goes (a token in
# the username slot must not survive) + the broad sensitive-key list.
from auditor.fetch import _redact


def _counts(findings: list[Finding]) -> dict[str, int]:
    return {sev.value: sum(1 for f in findings if f.severity is sev) for sev in Severity}


def build_report(target: str, projects: list[dict], engines: dict,
                 limitations: list[str], diagnostics: dict | None = None,
                 confidence: int | None = None) -> dict:
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
            "score": score, "counts": counts,
            "findings": [dict(asdict(f), severity=f.severity.value,
                              snippet=_redact(f.snippet), detail=_redact(f.detail))
                         for f in findings],
        })
    return {
        "tool": "ai-code-auditor",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "engines": engines,
        "summary": {
            "overall_score": overall_score(parts),
            "score_kind": "code_health (higher = safer; experimental indicator)",
            "lowest_language": {"language": lowest[0], "score": lowest[1]} if lowest else None,
            "counts": all_counts,
            "analysis_confidence": confidence,
            "verdict": verdict(all_counts, confidence if confidence is not None else 100,
                               diagnostics or {}),
        },
        "scoring_formula": FORMULA,
        "projects": out_projects,
        "diagnostics": diagnostics or {},
        "limitations": limitations,
    }
