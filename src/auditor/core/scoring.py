from __future__ import annotations

from auditor.core.models import Diagnostics, Finding, Severity

# internal weights still keyed by the legacy Severity enum (unmigrated this
# round); numerically identical to 15*error + 5*warning via the 1:1 mapping.
WEIGHTS = {Severity.RED: 15, Severity.YELLOW: 5}
FORMULA = (
    "code_health per language = max(0, 100 - 15*error - 5*warning) — HIGHER is "
    "safer (a severity-ORDERING metric, deliberately NOT a security claim); note "
    "findings are informational and never affect health; overall = file-count-"
    "weighted average, ALWAYS reported alongside lowest language and error count. "
    "analysis_confidence = coverage-v3: how COMPLETE the file/manifest/rule "
    "analysis was, with NO registry factor: round(100 * file_coverage * "
    "manifest_coverage * rule_health * parse_factor * semgrep_factor) where "
    "file_coverage = read/(read+skipped), "
    "manifest_coverage = 1 - affected_manifest_files/unique_manifest_files where "
    "affected = union(errored, incomplete) by canonical path (a partially-"
    "extracted manifest or a missing/outside include counts too), "
    "rule_health = 1 - rule_failures/rule_attempted (uncapped), "
    "parse_factor = 1 - min(1, parse_errors/files_read) (uncapped), "
    "semgrep_factor = 1.0 success / 0.97 partial / 0.95 otherwise. "
    "Registry verification is a SEPARATE axis: registry_status = "
    "complete/partial/unavailable/not_applicable and registry_confidence = "
    "round(100*(1-failures/attempted)) when lookups ran, null otherwise — an "
    "intended --offline run never lowers analysis_confidence. summary.confidence "
    "is a DEPRECATED alias of analysis_confidence kept one release for old "
    "readers. verdict consumes per-finding gate_action (error+exact=block, "
    "error+heuristic=review by default and promotable to block by project "
    "policy, warning=review, note=informational): block if any gate_action="
    "block or confidence<40 or ALL rule invocations failed; review if any "
    "gate_action=review or confidence<70 or any manifest/rule/parse failure or "
    "registry_status=partial; else pass — informational findings never gate."
)


def language_score(findings: list[Finding]) -> int:
    return max(0, 100 - sum(WEIGHTS.get(f.severity, 0) for f in findings))


def overall_score(parts: list[tuple[int, int]]) -> int | None:
    total_files = sum(n for _, n in parts)
    if not total_files:
        return None
    return round(sum(score * n for score, n in parts) / total_files)


def _manifest_error_files(errors: list[str]) -> set[str]:
    """The set of manifest FILES that errored — one file may raise several
    distinct error strings, and counting messages (CP-8.1) overstated failure.
    Messages are '<path>: <reason>'; path.as_posix() only contains ':' in a
    drive letter (always ':/', never ': '), so splitting on ': ' recovers the
    file path cleanly on every platform."""
    return {e.split(": ", 1)[0] for e in errors}


def analysis_confidence(diag: Diagnostics, files_read: int) -> int:
    """Coverage-v3 (ratio-based): how complete the ANALYSIS itself was —
    files read, manifests extracted, rules run, parses succeeded, semgrep
    health. Skipping 5 of 5 files is NOT the same as 5 of 50,000 — every
    deduction is a denominator-aware ratio; 100% parse failure or 100% rule
    failure drives confidence to 0 (uncapped ratios), never a silent 70/80.
    CP-8.1: manifest coverage counts affected FILES (not error messages), and
    a partially-extracted manifest lowers it too.

    B2.8B2: the registry axis is GONE from this number by contract — whether
    packages could be verified against a registry is reported separately as
    registry_status/registry_confidence. An intended --offline run therefore
    no longer halves confidence, and a clean offline scan can PASS."""
    seen = files_read + len(diag.skipped_files)
    file_cov = files_read / seen if seen else 1.0
    m_files = len(set(diag.manifest_files))
    err_files = _manifest_error_files(diag.manifest_errors)
    incomplete = set(diag.manifest_incomplete)
    # affected manifest files = errored (unread) UNION partially-extracted, by
    # canonical path (CP-8b.5). UNION, not sum — a file that both errors and is
    # marked incomplete counts once; all three ledgers share the same spelling.
    affected = len(err_files | incomplete)
    manifest_cov = 1.0 - affected / max(1, m_files, affected)
    rule_health = 1.0 - (diag.rule_failures / diag.rule_attempted
                         if diag.rule_attempted else 0.0)
    parse_factor = 1.0 - min(1.0, len(diag.parse_error_files) / max(1, files_read))
    sg = diag.semgrep_status
    sg_factor = 1.0 if sg.endswith("success") else (0.97 if "partial" in sg else 0.95)
    return round(100 * file_cov * manifest_cov * rule_health * parse_factor
                 * sg_factor)


REGISTRY_STATUSES = ("complete", "partial", "unavailable", "not_applicable")


def registry_status(offline: bool, attempted: int, failures: int) -> str:
    """The registry-verification axis, separate from analysis completeness:
    - unavailable:    the run intentionally performed no lookups (--offline);
    - not_applicable: online, but nothing needed a lookup;
    - partial:        lookups ran and some FAILED (network/5xx → H004) —
                      an online run that could not verify is incomplete;
    - complete:       every attempted lookup got an answer (found and
                      not-found are both ANSWERS; only failures degrade this).
    """
    if offline:
        return "unavailable"
    if attempted <= 0:
        return "not_applicable"
    return "partial" if failures > 0 else "complete"


def registry_confidence(status: str, attempted: int, failures: int) -> int | None:
    """A number ONLY when verification actually ran; null (None) when the
    registry axis does not apply — never a fabricated 0 or 100."""
    if status not in ("complete", "partial") or attempted <= 0:
        return None
    return round(100 * (1 - failures / attempted))


def verdict(gate_counts: dict, confidence: int, diag: dict,
            reg_status: str = "not_applicable") -> str:
    """Product contract (B2.8B2): the verdict consumes per-finding
    gate_action — never the level or the legacy color alone. `block` needs a
    blocking finding (exact error, or heuristic error under a promoting
    project policy) or the collapse of a mandatory dimension (confidence
    floor, all builtin rules failed). ANY review-gated finding, rule failure,
    partial manifest extraction, degraded optional engine, or PARTIAL online
    registry verification forbids pass. Informational findings (notes) never
    gate. `confidence` here is analysis_confidence — an intended offline run
    (registry unavailable) does not gate by itself; a clean offline scan
    passes."""
    attempted = diag.get("rule_attempted", 0)
    failures = diag.get("rule_failures", 0)
    total_rule_collapse = attempted > 0 and failures >= attempted
    if gate_counts.get("block", 0) > 0 or confidence < 40 or total_rule_collapse:
        return "block"
    sg = diag.get("semgrep_status", "")
    # "not available"/"not attempted"/"success" are fine; a started-then-broken
    # optional engine is a coverage gap the user must see
    sg_degraded = any(k in sg for k in ("partial", "failed", "timed_out",
                                        "invalid_output"))
    if gate_counts.get("review", 0) > 0 or confidence < 70 \
            or diag.get("manifest_errors") or failures \
            or diag.get("rule_errors") \
            or diag.get("manifest_incomplete") or diag.get("include_gaps") \
            or diag.get("parse_error_files") or sg_degraded \
            or reg_status == "partial":
        # ANY recorded rule error, partial manifest extraction, missing/
        # outside include, or failed online registry lookup forbids pass —
        # an incomplete analysis is never clean
        return "review"
    return "pass"
