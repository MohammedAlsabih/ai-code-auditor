import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from auditor.web.app import create_app
from auditor.web.coverage import OBSERVED_RULES_DISCLAIMER, build_coverage

TABI_REPORT = Path(r"<repo>\tabi-report\report.json")


def _stage(cov, key):
    return next(s for s in cov["stages"] if s["key"] == key)


def _report(diag=None, projects=None, **top):
    rep = {"summary": {"counts": {}},
           "projects": projects if projects is not None else []}
    if diag is not None:
        rep["diagnostics"] = diag
    rep.update(top)
    return rep


# --- status ladders ---------------------------------------------------------

def test_zero_manifest_files_is_not_recorded_not_complete():
    cov = build_coverage(_report(diag={
        "manifest_files": [], "manifest_errors": [],
        "manifest_incomplete": [], "include_gaps": []}))
    s = _stage(cov, "manifests")
    assert s["status"] == "not_recorded"
    assert "no manifest reads recorded" in s["evidence"]


def test_some_manifest_errors_is_partial_all_is_failed():
    partial = build_coverage(_report(diag={
        "manifest_files": ["a/pom.xml", "b/pom.xml"],
        "manifest_errors": ["a/pom.xml: ParseError boom"],
        "manifest_incomplete": [], "include_gaps": []}))
    s = _stage(partial, "manifests")
    assert s["status"] == "partial"
    assert "a/pom.xml: ParseError boom" in s["issues"]
    failed = build_coverage(_report(diag={
        "manifest_files": ["a/pom.xml", "b/pom.xml"],
        "manifest_errors": ["a/pom.xml: X", "b/pom.xml: Y"],
        "manifest_incomplete": [], "include_gaps": []}))
    assert _stage(failed, "manifests")["status"] == "failed"


def test_zero_rule_attempts_is_not_recorded_not_success():
    cov = build_coverage(_report(diag={"rule_attempted": 0, "rule_failures": 0}))
    s = _stage(cov, "rules")
    assert s["status"] == "not_recorded"
    assert "not success" in s["evidence"]


def test_rule_ladder_partial_and_failed():
    partial = build_coverage(_report(diag={"rule_attempted": 10, "rule_failures": 3,
                                           "rule_errors": ["R005 on x.tsx: KeyError"]}))
    s = _stage(partial, "rules")
    assert s["status"] == "partial" and "3 failure(s)" in s["evidence"]
    assert s["issues"] == ["R005 on x.tsx: KeyError"]
    failed = build_coverage(_report(diag={"rule_attempted": 4, "rule_failures": 4,
                                          "rule_errors": []}))
    assert _stage(failed, "rules")["status"] == "failed"


def test_registry_ladder():
    ok = build_coverage(_report(diag={"registry_attempted": 55, "registry_failures": 0}))
    assert _stage(ok, "registry")["status"] == "complete"
    part = build_coverage(_report(diag={"registry_attempted": 10, "registry_failures": 4}))
    assert _stage(part, "registry")["status"] == "partial"
    none = build_coverage(_report(diag={}))
    assert _stage(none, "registry")["status"] == "not_recorded"


def test_semgrep_not_available_is_unavailable_not_complete():
    cov = build_coverage(_report(diag={"semgrep_status": "not available (builtin rules only)"}))
    s = _stage(cov, "semgrep")
    assert s["status"] == "unavailable"
    assert s["evidence"] == "not available (builtin rules only)"
    assert _stage(build_coverage(_report(diag={"semgrep_status": "not attempted"})),
                  "semgrep")["status"] == "not_recorded"
    assert _stage(build_coverage(_report(diag={})), "semgrep")["status"] == "not_recorded"


def test_missing_or_malformed_diagnostics_never_complete_never_crash():
    for rep in (_report(),                                   # no diagnostics at all
                _report(diag="not a dict"),                  # malformed type
                {"summary": {}, "projects": "nope"},         # malformed projects
                _report(diag={"rule_attempted": "many",      # malformed counters
                              "manifest_files": {"a": 1},
                              "semgrep_status": 7})):
        cov = build_coverage(rep)                            # must not raise
        for key in ("manifests", "rules", "registry", "semgrep"):
            assert _stage(cov, key)["status"] == "not_recorded", (rep, key)


def test_parsing_stage_uses_file_counts_and_parse_errors():
    ok = build_coverage(_report(
        projects=[{"root": ".", "language": "python", "file_count": 5, "findings": []}],
        diag={"parse_error_files": [], "skipped_files": []}))
    s = _stage(ok, "parsing")
    assert s["status"] == "complete" and "5 file(s)" in s["evidence"]
    part = build_coverage(_report(
        projects=[{"root": ".", "language": "python", "file_count": 5, "findings": []}],
        diag={"parse_error_files": ["bad.py"], "skipped_files": ["big.py: exceeds cap"]}))
    s2 = _stage(part, "parsing")
    assert s2["status"] == "partial"
    assert "bad.py" in s2["issues"] and "skipped: big.py: exceeds cap" in s2["issues"]
    empty = build_coverage(_report())
    assert _stage(empty, "parsing")["status"] == "not_recorded"


# --- evidence-discipline regressions (independent review of 41c2dac) ---------

def test_empty_projects_array_is_not_recorded_discovery():
    cov = build_coverage(_report(projects=[]))
    s = _stage(cov, "discovery")
    assert s["status"] == "not_recorded"
    # all-malformed entries are equally not evidence
    cov2 = build_coverage(_report(projects=["junk", 5]))
    assert _stage(cov2, "discovery")["status"] == "not_recorded"


def test_parsing_needs_positive_total_and_valid_ledgers():
    zero = build_coverage(_report(
        projects=[{"root": ".", "language": "py", "file_count": 0, "findings": []}],
        diag={"parse_error_files": [], "skipped_files": []}))
    assert _stage(zero, "parsing")["status"] == "not_recorded"
    negative = build_coverage(_report(
        projects=[{"root": ".", "language": "py", "file_count": -5, "findings": []}],
        diag={"parse_error_files": [], "skipped_files": []}))
    assert _stage(negative, "parsing")["status"] == "not_recorded"
    weird = build_coverage(_report(
        projects=[{"root": ".", "language": "py", "file_count": "9", "findings": []}],
        diag={"parse_error_files": [], "skipped_files": []}))
    assert _stage(weird, "parsing")["status"] == "not_recorded"
    # positive counts but a parse ledger missing/malformed => still not complete
    no_ledger = build_coverage(_report(
        projects=[{"root": ".", "language": "py", "file_count": 5, "findings": []}]))
    assert _stage(no_ledger, "parsing")["status"] == "not_recorded"
    bad_ledger = build_coverage(_report(
        projects=[{"root": ".", "language": "py", "file_count": 5, "findings": []}],
        diag={"parse_error_files": "nope", "skipped_files": []}))
    assert _stage(bad_ledger, "parsing")["status"] == "not_recorded"


def test_missing_failures_counter_is_never_assumed_zero():
    rules = build_coverage(_report(diag={"rule_attempted": 5, "rule_errors": []}))
    s = _stage(rules, "rules")
    assert s["status"] == "not_recorded"
    assert "both be recorded" in s["evidence"]
    registry = build_coverage(_report(diag={"registry_attempted": 5}))
    s2 = _stage(registry, "registry")
    assert s2["status"] == "not_recorded"
    assert "both be recorded" in s2["evidence"]


def test_contradictory_counters_are_not_recorded_with_evidence():
    cov = build_coverage(_report(diag={"rule_attempted": 5, "rule_failures": 7,
                                       "rule_errors": []}))
    s = _stage(cov, "rules")
    assert s["status"] == "not_recorded"
    assert "contradictory" in s["evidence"] and "7 failures > 5 attempts" in s["evidence"]
    neg = build_coverage(_report(diag={"rule_attempted": 5, "rule_failures": -1,
                                       "rule_errors": []}))
    assert _stage(neg, "rules")["status"] == "not_recorded"


def test_rules_complete_requires_valid_errors_ledger():
    missing = build_coverage(_report(diag={"rule_attempted": 5, "rule_failures": 0}))
    s = _stage(missing, "rules")
    assert s["status"] == "not_recorded"
    assert "error ledger" in s["evidence"]
    malformed = build_coverage(_report(diag={"rule_attempted": 5, "rule_failures": 0,
                                             "rule_errors": "boom"}))
    assert _stage(malformed, "rules")["status"] == "not_recorded"
    # partial/failed verdicts do NOT need the ledger (only complete does)
    still_failed = build_coverage(_report(diag={"rule_attempted": 4, "rule_failures": 4}))
    assert _stage(still_failed, "rules")["status"] == "failed"


def test_manifest_complete_requires_all_four_ledgers():
    only_files = build_coverage(_report(diag={"manifest_files": ["a"]}))
    s = _stage(only_files, "manifests")
    assert s["status"] == "not_recorded"
    assert "ledgers missing or malformed" in s["evidence"]
    bad_type = build_coverage(_report(diag={
        "manifest_files": ["a"], "manifest_errors": "x",
        "manifest_incomplete": [], "include_gaps": []}))
    assert _stage(bad_type, "manifests")["status"] == "not_recorded"
    all_present = build_coverage(_report(diag={
        "manifest_files": ["a"], "manifest_errors": [],
        "manifest_incomplete": [], "include_gaps": []}))
    assert _stage(all_present, "manifests")["status"] == "complete"


def test_manifest_failure_coverage_uses_unique_files():
    cov = build_coverage(_report(diag={
        "manifest_files": ["a/pom.xml", "a/pom.xml"],      # duplicate path
        "manifest_errors": ["a/pom.xml: boom"],
        "manifest_incomplete": [], "include_gaps": []}))
    s = _stage(cov, "manifests")
    assert s["status"] == "failed"                          # 1 unique file, 1 errored
    assert "1 manifest(s) read" in s["evidence"]


@pytest.mark.parametrize("status,expected", [
    ("success", "complete"),
    ("success (312 files)", "complete"),
    ("partial (2 file errors)", "partial"),                 # the literal counter-case
    ("failed", "failed"),
    ("failed (exit 2)", "failed"),
    ("timed_out", "failed"),
    ("invalid_output", "failed"),
    ("not available (builtin rules only)", "unavailable"),
    ("unavailable", "unavailable"),
    ("not attempted", "not_recorded"),
    ("scanned 5 files, 3 results", "not_recorded"),         # generic words prove nothing
    ("ok", "not_recorded"),
])
def test_semgrep_official_status_mapping(status, expected):
    cov = build_coverage(_report(diag={"semgrep_status": status}))
    assert _stage(cov, "semgrep")["status"] == expected, status


@pytest.mark.parametrize("status,expected", [
    # the CLI writes f"{binary}: {state}" (cli.py: global_diag.semgrep_status)
    ("opengrep 1.25.0: success", "complete"),
    ("semgrep 2.0: partial (2 file errors)", "partial"),
    ("opengrep 1.25.0: failed (exit 7)", "failed"),
    ("opengrep 1.25.0: timed_out", "failed"),
    ("opengrep 1.25.0: invalid_output", "failed"),
    ("not available (builtin rules only)", "unavailable"),  # unprefixed CLI form
    ("opengrep 1.25.0: something weird", "not_recorded"),   # unknown suffix
])
def test_semgrep_cli_version_prefix_is_stripped_for_state(status, expected):
    """The official state is the suffix after the LAST ': '; the evidence must
    keep the ORIGINAL full string untouched."""
    cov = build_coverage(_report(diag={"semgrep_status": status}))
    s = _stage(cov, "semgrep")
    assert s["status"] == expected, status
    assert status in s["evidence"]                          # full text preserved


def test_engines_pass_only_string_pairs_to_frontend():
    cov = build_coverage({"summary": {}, "projects": [], "engines": {
        "ast": "tree-sitter", "weird": {"a": 1}, "list": ["x"], 5: "num-key",
        "none": None}})
    assert cov["provenance"]["engines"] == {"ast": "tree-sitter"}


# --- observed rules + disclaimer --------------------------------------------

def test_observed_rules_only_and_disclaimer_present(tmp_path):
    rep = _report(projects=[
        {"root": ".", "language": "python", "findings": [
            {"rule_id": "P006", "severity": "yellow", "title": "cc", "file": "a.py",
             "line": 1, "language": "python", "precision": "exact"},
            {"rule_id": "P006", "severity": "red", "title": "cc", "file": "b.py",
             "line": 2, "language": "python", "precision": "exact"},
            {"rule_id": "H002", "severity": "yellow", "title": "und", "file": "c.py",
             "line": 3, "language": "python", "precision": "heuristic"}]}])
    cov = build_coverage(rep)
    rules = {r["rule_id"]: r for r in cov["observed_rules"]}
    assert set(rules) == {"P006", "H002"}          # ONLY rules that produced findings
    assert rules["P006"]["count"] == 2
    assert rules["P006"]["levels"] == ["error", "warning"]   # SARIF-compatible levels
    assert cov["observed_rules_disclaimer"] == OBSERVED_RULES_DISCLAIMER
    assert "produced findings only" in cov["observed_rules_disclaimer"]


# --- endpoint + non-regression ----------------------------------------------

def test_coverage_endpoint_serves_payload(tmp_path):
    rp = tmp_path / "report.json"
    rp.write_text(json.dumps(_report(diag={"rule_attempted": 3, "rule_failures": 0})),
                  encoding="utf-8")
    c = TestClient(create_app(rp))
    r = c.get("/api/coverage")
    assert r.status_code == 200
    body = r.json()
    assert {s["key"] for s in body["stages"]} == \
        {"discovery", "manifests", "parsing", "rules", "registry", "semgrep"}
    assert body["observed_rules_disclaimer"] == OBSERVED_RULES_DISCLAIMER
    # sibling endpoints unaffected
    assert c.get("/api/report").status_code == 200
    assert c.get("/api/reviews").status_code == 200
    assert c.get("/api/source", params={"path": "x.py", "line": 1}).status_code in (400, 403, 409)


@pytest.mark.skipif(not TABI_REPORT.exists(), reason="Tabi report not on this machine")
def test_tabi_report_coverage_evidence():
    report = json.loads(TABI_REPORT.read_text(encoding="utf-8"))
    cov = build_coverage(report)
    assert len(cov["projects"]) == 3
    assert sum(r["count"] for r in cov["observed_rules"]) == 104
    d = cov["diagnostics"]
    assert d["rule_attempted"] == 1047 and d["rule_failures"] == 0
    assert d["registry_attempted"] == 55
    assert _stage(cov, "rules")["status"] == "complete"
    assert _stage(cov, "registry")["status"] == "complete"
    assert _stage(cov, "semgrep")["status"] == "unavailable"
    next_notes = [n for n in d["notes"] if n.startswith("next-graph:")]
    assert len(next_notes) == 2
    assert _stage(cov, "manifests")["status"] == "complete"   # 4 manifests, 0 errors
    assert "4 manifest(s) read" in _stage(cov, "manifests")["evidence"]
