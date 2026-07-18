from __future__ import annotations

from auditor.core.models import Diagnostics, Finding, Severity

WEIGHTS = {Severity.RED: 15, Severity.YELLOW: 5}
FORMULA = (
    "code_health per language = max(0, 100 - 15*red - 5*yellow) — HIGHER is "
    "safer (this is a health/safety score, deliberately NOT named 'risk'); blue "
    "findings are informational and never affect health; overall = file-count-"
    "weighted average, ALWAYS reported alongside lowest language and red count. "
    "analysis_confidence = coverage-v2 (experimental): round(100 * file_coverage "
    "* manifest_coverage * (0.5 + 0.5*registry_coverage) * rule_health * "
    "parse_factor * semgrep_factor) where file_coverage = read/(read+skipped), "
    "manifest_coverage = 1 - unique_error_files/unique_manifest_files, "
    "registry_coverage = 0 offline else 1 - failures/attempted, "
    "rule_health = 1 - rule_failures/rule_attempted (uncapped), "
    "parse_factor = 1 - min(1, parse_errors/files_read) (uncapped), "
    "semgrep_factor = 1.0 success / 0.97 partial / 0.95 otherwise. "
    "verdict: block if red>0 or confidence<40 or ALL rule invocations failed; "
    "review if yellow>0 or confidence<70 or any manifest/rule/parse failure; "
    "else pass — any rule failure forbids pass."
)


def language_score(findings: list[Finding]) -> int:
    return max(0, 100 - sum(WEIGHTS.get(f.severity, 0) for f in findings))


def overall_score(parts: list[tuple[int, int]]) -> int | None:
    total_files = sum(n for _, n in parts)
    if not total_files:
        return None
    return round(sum(score * n for score, n in parts) / total_files)


def analysis_confidence(diag: Diagnostics, offline: bool, files_read: int) -> int:
    """Coverage-v2 (experimental, ratio-based): skipping 5 of 5 files is NOT the
    same as 5 of 50,000 — every deduction is a denominator-aware ratio, and the
    fourth-round counterexamples are closed: 100% parse failure or 100% rule
    failure drives confidence to 0 (uncapped ratios), never a silent 70/80."""
    seen = files_read + len(diag.skipped_files)
    file_cov = files_read / seen if seen else 1.0
    m_files = len(set(diag.manifest_files))
    m_err = len(set(diag.manifest_errors))
    manifest_cov = 1.0 - m_err / max(1, m_files, m_err)
    if offline:
        registry_cov = 0.0
    elif diag.registry_attempted:
        registry_cov = 1.0 - diag.registry_failures / diag.registry_attempted
    else:
        registry_cov = 1.0
    rule_health = 1.0 - (diag.rule_failures / diag.rule_attempted
                         if diag.rule_attempted else 0.0)
    parse_factor = 1.0 - min(1.0, len(diag.parse_error_files) / max(1, files_read))
    sg = diag.semgrep_status
    sg_factor = 1.0 if sg.endswith("success") else (0.97 if "partial" in sg else 0.95)
    return round(100 * file_cov * manifest_cov * (0.5 + 0.5 * registry_cov)
                 * rule_health * parse_factor * sg_factor)


def verdict(counts: dict, confidence: int, diag: dict) -> str:
    """Product contract: ANY rule failure forbids pass; total collapse of a
    mandatory dimension (all builtin rules failed, or confidence floor) is a
    block; an OPTIONAL engine (semgrep) that actually STARTED and then failed or
    ran partially forbids pass too (partial=97/failed=95 must not slip
    through as pass)."""
    attempted = diag.get("rule_attempted", 0)
    failures = diag.get("rule_failures", 0)
    total_rule_collapse = attempted > 0 and failures >= attempted
    if counts.get("red", 0) > 0 or confidence < 40 or total_rule_collapse:
        return "block"
    sg = diag.get("semgrep_status", "")
    # "not available"/"not attempted"/"success" are fine; a started-then-broken
    # optional engine is a coverage gap the user must see
    sg_degraded = any(k in sg for k in ("partial", "failed", "timed_out",
                                        "invalid_output"))
    if counts.get("yellow", 0) > 0 or confidence < 70 \
            or diag.get("manifest_errors") or failures \
            or diag.get("rule_errors") \
            or diag.get("parse_error_files") or sg_degraded:
        return "review"   # ANY recorded rule error forbids pass, counters aside
    return "pass"
