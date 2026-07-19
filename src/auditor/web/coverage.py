from __future__ import annotations

from typing import Any

# The panel's core principle: a stage is shown as executed ONLY when the loaded
# report carries actual evidence of it. Absent/zero/malformed evidence renders
# "not_recorded" — never guessed, never filled from a static catalog.

OBSERVED_RULES_DISCLAIMER = (
    "This report version records aggregate rule attempts but not the complete "
    "executed rule catalog. The table below contains rules that produced "
    "findings only."
)

_STATUS = ("complete", "partial", "failed", "unavailable", "not_recorded")


def _stage(key: str, label: str, status: str, evidence: str,
           issues: list[str] | None = None) -> dict[str, Any]:
    assert status in _STATUS
    return {"key": key, "label": label, "status": status,
            "evidence": evidence, "issues": issues or []}


def _diag(report: dict[str, Any]) -> dict[str, Any]:
    d = report.get("diagnostics")
    return d if isinstance(d, dict) else {}


def _strs(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [x for x in value if isinstance(x, str)]


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _nonneg_int(value: Any) -> int | None:
    """A usable counter is a NON-NEGATIVE int; negatives and weird types are
    not evidence."""
    v = _int(value)
    return v if v is not None and v >= 0 else None


def _projects(report: dict[str, Any]) -> list[dict[str, Any]]:
    projects = report.get("projects")
    if not isinstance(projects, list):
        return []
    return [p for p in projects if isinstance(p, dict)]


def _stage_discovery(report: dict[str, Any]) -> dict[str, Any]:
    projects = report.get("projects")
    if not isinstance(projects, list):
        return _stage("discovery", "Project discovery", "not_recorded",
                      "no projects array in the report")
    ps = _projects(report)
    if not ps:
        # an empty (or all-malformed) projects array is not evidence that
        # discovery ran and found nothing — nothing usable was recorded
        return _stage("discovery", "Project discovery", "not_recorded",
                      "no valid projects recorded")
    langs = sorted({lang for p in ps
                    if isinstance(lang := p.get("language"), str)})
    return _stage("discovery", "Project discovery", "complete",
                  f"{len(ps)} project(s) recorded"
                  + (f" ({', '.join(langs)})" if langs else ""))


def _stage_manifests(report: dict[str, Any]) -> dict[str, Any]:
    d = _diag(report)
    ledgers = (d.get("manifest_files"), d.get("manifest_errors"),
               d.get("manifest_incomplete"), d.get("include_gaps"))
    if not all(isinstance(x, list) for x in ledgers):
        # a verdict about manifest parsing needs the WHOLE ledger set recorded;
        # a lone file list with the error/incomplete/gap ledgers absent proves
        # nothing about how those reads went
        return _stage("manifests", "Manifest parsing", "not_recorded",
                      "manifest ledgers missing or malformed (files/errors/"
                      "incomplete/include_gaps must all be recorded lists)")
    files = _strs(ledgers[0])
    if len(files) == 0:
        # 0 manifests read is NOT completeness — nothing was recorded as parsed
        return _stage("manifests", "Manifest parsing", "not_recorded",
                      "no manifest reads recorded (manifest_files is empty)")
    errors = _strs(ledgers[1])
    incomplete = _strs(ledgers[2])
    gaps = _strs(ledgers[3])
    issues = errors + [f"incomplete: {p}" for p in incomplete] \
        + [f"include gap: {g}" for g in gaps]
    unique_files = set(files)                       # failure coverage on UNIQUE paths
    error_files = {e.split(": ", 1)[0] for e in errors}
    evidence = (f"{len(unique_files)} manifest(s) read; {len(errors)} error(s), "
                f"{len(incomplete)} incomplete, {len(gaps)} include gap(s)")
    if error_files and len(error_files) >= len(unique_files):
        return _stage("manifests", "Manifest parsing", "failed", evidence, issues)
    if errors or incomplete or gaps:
        return _stage("manifests", "Manifest parsing", "partial", evidence, issues)
    return _stage("manifests", "Manifest parsing", "complete", evidence)


def _stage_parsing(report: dict[str, Any]) -> dict[str, Any]:
    d = _diag(report)
    # negative or weird-typed file_count is NOT a counter
    counts = [fc for p in _projects(report)
              if (fc := _nonneg_int(p.get("file_count"))) is not None]
    pe_raw, sk_raw = d.get("parse_error_files"), d.get("skipped_files")
    if not isinstance(pe_raw, list) or not isinstance(sk_raw, list):
        # without both ledgers recorded there is no basis for ANY verdict
        return _stage("parsing", "File/syntax parsing", "not_recorded",
                      "parse_error_files/skipped_files ledgers missing or malformed")
    parse_errors = _strs(pe_raw)
    skipped = _strs(sk_raw)
    total = sum(counts)
    if total <= 0:
        # a parsing verdict needs POSITIVE file evidence; 0 files parsed is
        # not a successful parse of anything
        return _stage("parsing", "File/syntax parsing", "not_recorded",
                      "no positive per-project file counts recorded")
    issues = parse_errors + [f"skipped: {s}" for s in skipped]
    evidence = (f"{total} file(s) across {len(counts)} project(s); "
                f"{len(parse_errors)} parse error(s), {len(skipped)} skipped")
    if parse_errors and len(parse_errors) >= total:
        return _stage("parsing", "File/syntax parsing", "failed", evidence, issues)
    if parse_errors or skipped:
        return _stage("parsing", "File/syntax parsing", "partial", evidence, issues)
    return _stage("parsing", "File/syntax parsing", "complete", evidence)


def _attempt_ladder(key: str, label: str, attempted_raw: Any, failures_raw: Any,
                    errors_raw: Any, noun: str,
                    require_errors_ledger: bool) -> dict[str, Any]:
    """Shared ladder for counter-based stages. Evidence discipline:
    - attempted AND failures must BOTH be recorded non-negative ints — a
      missing failures counter is never assumed to be 0;
    - failures > attempted is contradictory data => not_recorded;
    - 0 attempts is NOT success => not_recorded;
    - when require_errors_ledger, COMPLETE additionally demands the error
      ledger be a recorded list (partial/failed verdicts don't need it)."""
    attempted = _nonneg_int(attempted_raw)
    failures = _nonneg_int(failures_raw)
    if attempted is None or failures is None:
        return _stage(key, label, "not_recorded",
                      f"incomplete {noun} counters: attempted and failures must "
                      "both be recorded non-negative integers")
    if failures > attempted:
        return _stage(key, label, "not_recorded",
                      f"contradictory {noun} counters recorded: "
                      f"{failures} failures > {attempted} attempts")
    if attempted == 0:
        return _stage(key, label, "not_recorded",
                      f"0 {noun} attempts recorded (absence of attempts is not success)")
    issues = _strs(errors_raw) if isinstance(errors_raw, list) else []
    evidence = f"{attempted} {noun} attempt(s), {failures} failure(s)"
    if failures >= attempted:
        return _stage(key, label, "failed", evidence, issues)
    if failures > 0:
        return _stage(key, label, "partial", evidence, issues)
    if require_errors_ledger and not isinstance(errors_raw, list):
        return _stage(key, label, "not_recorded",
                      f"{noun} error ledger missing or malformed — cannot "
                      "confirm a clean run")
    return _stage(key, label, "complete", evidence, issues)


def _stage_semgrep(report: dict[str, Any]) -> dict[str, Any]:
    """Maps the scanner's OFFICIAL semgrep_status states only — no generic
    keyword sniffing ('result'/'scanned' prove nothing, and a generic 'error'
    search would misread 'partial (2 file errors)' as failed):
      success            -> complete
      partial (...)      -> partial        (checked BEFORE any failure match)
      failed / failed (exit N) / timed_out / invalid_output -> failed
      not available / unavailable          -> unavailable
      not attempted / absent / anything else -> not_recorded (shown verbatim)
    """
    status = _diag(report).get("semgrep_status")
    if not isinstance(status, str) or not status or status == "not attempted":
        return _stage("semgrep", "Semgrep/OpenGrep", "not_recorded",
                      "no semgrep execution recorded")
    # the CLI prefixes the binary+version ("opengrep 1.25.0: success") — the
    # OFFICIAL state is the suffix after the LAST ": "; the untouched full
    # string always stays as the evidence text.
    state = status.rsplit(": ", 1)[-1].strip().lower()
    if state.startswith("success"):
        return _stage("semgrep", "Semgrep/OpenGrep", "complete", status)
    if state.startswith("partial"):
        return _stage("semgrep", "Semgrep/OpenGrep", "partial", status)
    if state.startswith(("failed", "timed_out", "invalid_output")):
        return _stage("semgrep", "Semgrep/OpenGrep", "failed", status)
    if "not available" in state or "unavailable" in state:
        return _stage("semgrep", "Semgrep/OpenGrep", "unavailable", status)
    # an unrecognized status string is shown verbatim, not upgraded
    return _stage("semgrep", "Semgrep/OpenGrep", "not_recorded",
                  f"unrecognized status: {status}")


def _observed_rules(report: dict[str, Any]) -> list[dict[str, Any]]:
    from auditor.core.levels import normalize_level
    groups: dict[str, dict[str, Any]] = {}
    for p in _projects(report):
        findings = p.get("findings")
        if not isinstance(findings, list):
            continue
        for f in findings:
            if not isinstance(f, dict) or not isinstance(f.get("rule_id"), str):
                continue
            g = groups.setdefault(f["rule_id"], {
                "rule_id": f["rule_id"], "count": 0,
                "languages": set(), "precisions": set(), "levels": set()})
            g["count"] += 1
            for field, target in (("language", "languages"),
                                  ("precision", "precisions")):
                v = f.get(field)
                if isinstance(v, str) and v:
                    g[target].add(v)
            # SARIF-compatible level (normalized); an illegal value is shown
            # VERBATIM as unclassified — the offending level itself when one
            # is present ("unclassified(none)"), the raw severity only when
            # level is absent — never dropped, never promoted.
            lvl = normalize_level(f.get("level"), f.get("severity"))
            if lvl is not None:
                g["levels"].add(lvl)
            else:
                raw = f.get("level")
                if raw is not None:
                    shown = raw if isinstance(raw, str) and raw else "invalid"
                    g["levels"].add(f"unclassified({shown})")
                elif isinstance(f.get("severity"), str) and f["severity"]:
                    g["levels"].add(f"unclassified({f['severity']})")
    return [{**g, "languages": sorted(g["languages"]),
             "precisions": sorted(g["precisions"]),
             "levels": sorted(g["levels"])}
            for g in sorted(groups.values(),
                            key=lambda g: (-g["count"], g["rule_id"]))]


def build_coverage(report: dict[str, Any]) -> dict[str, Any]:
    """Pure function report-dict -> coverage payload. Every status is derived
    from recorded evidence only (see the per-stage rules); malformed or missing
    diagnostics degrade to not_recorded, never to complete, and never raise."""
    d = _diag(report)
    engines_raw = report.get("engines")
    # only string->string pairs may reach the frontend: a dict/list engine
    # value would land as a React child and crash the Coverage view
    engines = {k: v for k, v in engines_raw.items()
               if isinstance(k, str) and isinstance(v, str)} \
        if isinstance(engines_raw, dict) else {}
    provenance = {
        "tool": report.get("tool") if isinstance(report.get("tool"), str) else None,
        "version": report.get("version") if isinstance(report.get("version"), str) else None,
        "generated_at": report.get("generated_at")
        if isinstance(report.get("generated_at"), str) else None,
        "target": report.get("target") if isinstance(report.get("target"), str) else None,
        # engines are PROVENANCE (what the tool ships), deliberately NOT used
        # as completeness evidence for any stage above.
        "engines": engines,
    }
    projects = [{
        "root": p.get("root") if isinstance(p.get("root"), str) else "",
        "language": p.get("language") if isinstance(p.get("language"), str) else "",
        "frameworks": _strs(p.get("frameworks")),
        "file_count": _int(p.get("file_count")),
        "score": _int(p.get("score")),
        "findings_count": len(fnds) if isinstance(fnds := p.get("findings"), list) else None,
    } for p in _projects(report)]
    stages = [
        _stage_discovery(report),
        _stage_manifests(report),
        _stage_parsing(report),
        _attempt_ladder("rules", "Built-in rules", d.get("rule_attempted"),
                        d.get("rule_failures"), d.get("rule_errors"),
                        "rule", require_errors_ledger=True),
        _attempt_ladder("registry", "Registry verification",
                        d.get("registry_attempted"), d.get("registry_failures"),
                        [], "registry lookup", require_errors_ledger=False),
        _stage_semgrep(report),
    ]
    diagnostics = {
        "manifest_errors": _strs(d.get("manifest_errors")),
        "manifest_incomplete": _strs(d.get("manifest_incomplete")),
        "skipped_files": _strs(d.get("skipped_files")),
        "parse_error_files": _strs(d.get("parse_error_files")),
        "rule_errors": _strs(d.get("rule_errors")),
        "rule_attempted": _int(d.get("rule_attempted")),
        "rule_failures": _int(d.get("rule_failures")),
        "registry_attempted": _int(d.get("registry_attempted")),
        "registry_failures": _int(d.get("registry_failures")),
        "notes": _strs(d.get("notes")),
        "include_gaps": _strs(d.get("include_gaps")),
    }
    return {
        "provenance": provenance,
        "projects": projects,
        "stages": stages,
        "diagnostics": diagnostics,
        "limitations": _strs(report.get("limitations")),
        "observed_rules": _observed_rules(report),
        "observed_rules_disclaimer": OBSERVED_RULES_DISCLAIMER,
    }
