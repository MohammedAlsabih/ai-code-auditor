"""B2-D: execution-status derivation + analysis_manifest.execution serialization.
Status describes whether/how a rule RAN — never code safety; findings play no
part; pass/clean/safe are not statuses."""
import json
from pathlib import Path

import pytest

from auditor.core.execution import (
    EXECUTION_STATUSES,
    ExecutionLedger,
    RuleExecution,
    derive_execution_status,
    execution_manifest,
)


def _rec(**kw) -> RuleExecution:
    rec = RuleExecution()
    for k, v in kw.items():
        setattr(rec, k, v)
    return rec


# --- table-driven: one case per legal status ---------------------------------

@pytest.mark.parametrize("kw,want", [
    ({"eligible_inputs": 2, "attempted": 2}, "executed"),
    ({"eligible_inputs": 3, "attempted": 3, "failures": 1}, "partial"),
    ({"eligible_inputs": 2, "attempted": 1, "blocked_inputs": 1}, "partial"),
    ({"eligible_inputs": 1, "attempted": 1, "partial_parse_inputs": 1}, "partial"),
    ({"eligible_inputs": 1, "attempted": 1, "partial_reasons": ["1 skipped"]},
     "partial"),
    ({"eligible_inputs": 2, "attempted": 2, "failures": 2,
      "failure_reasons": ["engine failed"]}, "failed"),
    ({"eligible_inputs": 2, "skipped_reasons": ["disabled by --no-semgrep"]},
     "skipped"),
    ({"eligible_inputs": 3, "unavailable_reasons": ["offline"]}, "unavailable"),
    ({"not_applicable_reasons": ["no java files"]}, "not_applicable"),
    ({"eligible_inputs": 2, "blocked_inputs": 2}, "blocked"),
    ({"eligible_inputs": 1}, "not_recorded"),      # eligible, no attempt, no why
    ({}, "not_recorded"),                          # no facts at all
])
def test_status_table(kw, want):
    assert derive_execution_status(_rec(**kw)) == want
    assert want in EXECUTION_STATUSES


def test_executed_zero_findings_is_executed_not_passed():
    # the function takes ONLY the record — findings cannot participate, and a
    # clean run with zero findings is "executed", never pass/clean/safe
    status = derive_execution_status(_rec(eligible_inputs=1, attempted=1))
    assert status == "executed"
    assert not any(s in ("pass", "clean", "safe") for s in EXECUTION_STATUSES)


# --- table-driven: contradictions => inconsistent (never repaired) ------------

@pytest.mark.parametrize("kw", [
    {"attempted": 1, "failures": 2},                              # failures > attempted
    {"failure_reasons": ["boom"]},                                # reason w/o failure
    {"partial_reasons": ["x"]},                                   # reason w/o attempt
    {"eligible_inputs": 1, "attempted": 1,
     "unavailable_reasons": ["offline"]},                         # attempted+unavailable
    {"eligible_inputs": 1, "attempted": 1,
     "skipped_reasons": ["user"]},                                # attempted+skipped
    {"eligible_inputs": 1, "attempted": 1,
     "not_applicable_reasons": ["na"]},                           # attempted+NA
    {"skipped_reasons": ["a"], "unavailable_reasons": ["b"]},     # both at once
    {"eligible_inputs": 1, "not_applicable_reasons": ["na"]},     # NA + eligible
    {"blocked_inputs": 1, "not_applicable_reasons": ["na"]},      # NA + blocked
    {"attempted": True},                                          # bool is not a count
    {"eligible_inputs": -1},                                      # negative
    {"eligible_inputs": 1, "blocked_inputs": 2},                  # blocked > eligible
    {"attempted": 1, "eligible_inputs": 1, "partial_parse_inputs": 2},
    # closing round: the three NON-execution categories are mutually exclusive
    {"not_applicable_reasons": ["na"], "unavailable_reasons": ["u"]},
    {"not_applicable_reasons": ["na"], "skipped_reasons": ["s"]},
    {"not_applicable_reasons": ["na"], "unavailable_reasons": ["u"],
     "skipped_reasons": ["s"]},
    # closing round: reasons must be lists of unique non-empty strings
    {"attempted": 1, "eligible_inputs": 1,
     "partial_reasons": ["same", "same", 42]},
    {"attempted": 1, "eligible_inputs": 1, "partial_reasons": ["", "x"]},
    {"attempted": 1, "eligible_inputs": 1, "partial_reasons": "not-a-list"},
    {"eligible_inputs": 1, "unavailable_reasons": [None]},
])
def test_contradictions_are_inconsistent(kw):
    assert derive_execution_status(_rec(**kw)) == "inconsistent"


def test_blocked_never_auto_conflicts_with_unavailable():
    # blocked_inputs is an independent fact — files blocked AND the engine
    # unavailable is a coherent record, not a contradiction
    status = derive_execution_status(_rec(eligible_inputs=2, blocked_inputs=1,
                                          unavailable_reasons=["offline"]))
    assert status == "unavailable"


# --- serialization ------------------------------------------------------------

_ENTRY_KEYS = {"status", "eligible_inputs", "attempted", "failures",
               "blocked_inputs", "partial_parse_inputs",
               "not_applicable_reasons", "unavailable_reasons",
               "partial_reasons", "failure_reasons", "skipped_reasons"}


def _two_ledgers():
    a = ExecutionLedger(language="typescript", root="web")
    a.eligible(("N001",), 2)
    a.attempted_ok(("N001",))
    b = ExecutionLedger(language="python", root=".")
    b.eligible(("P001",), 3)
    b.attempted_ok(("P001",))
    b.not_applicable(("P008",), "no requires-python declared in this project")
    return [a, b]


def test_manifest_deterministic_order_and_allowlist():
    out = execution_manifest(_two_ledgers(), {"P001", "P008", "N001"})
    assert out["schema_version"] == 1
    # projects ordered by root then language: "." before "web"
    assert [(p["root"], p["language"]) for p in out["projects"]] == [
        (".", "python"), ("web", "typescript")]
    py = out["projects"][0]
    assert list(py["rules"].keys()) == sorted(py["rules"].keys())
    for entry in py["rules"].values():
        assert set(entry.keys()) == _ENTRY_KEYS          # explicit allowlist
    assert py["rules"]["P001"]["status"] == "executed"
    assert py["rules"]["P008"]["status"] == "not_applicable"
    assert py["contract_errors"] == []


def test_uncataloged_rule_kept_as_inconsistent_with_contract_error():
    led = ExecutionLedger(language="python", root=".")
    led.eligible(("X999",), 1)
    led.attempted_ok(("X999",))
    out = execution_manifest([led], {"P001"})
    entry = out["projects"][0]["rules"]["X999"]
    assert entry["status"] == "inconsistent"             # kept, never dropped
    assert any("X999" in e and "absent from the rule catalog" in e
               for e in out["projects"][0]["contract_errors"])


def test_inconsistent_record_still_serialized():
    led = ExecutionLedger(language="python", root=".")
    led.rules["P001"] = _rec(attempted=2, failures=5)    # impossible counters
    out = execution_manifest([led], {"P001"})
    assert out["projects"][0]["rules"]["P001"]["status"] == "inconsistent"


def test_analysis_manifest_v1_without_execution_v2_with():
    from auditor.core.catalog import analysis_manifest
    v1 = analysis_manifest([{"rule_id": "P001"}])
    assert v1["schema_version"] == 1 and "execution" not in v1
    v2 = analysis_manifest([{"rule_id": "P001"}],
                           execution={"schema_version": 1, "projects": []})
    assert v2["schema_version"] == 2
    assert v2["execution"]["schema_version"] == 1


def test_build_report_summary_identical_with_and_without_execution():
    """Serializing execution must not move scoring/confidence/verdict or the
    findings (=> review_id inputs) by one bit."""
    from auditor.report.build import build_report
    from auditor.core.models import Finding, Severity
    proj = {"language": "python", "root": ".", "frameworks": [], "file_count": 1,
            "findings": [Finding("P001", Severity.YELLOW, "t", "a.py", 1)]}
    kw = dict(engines={}, limitations=[], diagnostics={"semgrep_status": "x"},
              confidence=90, catalog=[{"rule_id": "P001"}])
    base = build_report("t", [dict(proj)], **kw)
    withx = build_report("t", [dict(proj)], **kw,
                         execution=execution_manifest(_two_ledgers(),
                                                      {"P001", "P008", "N001"}))
    assert base["summary"] == withx["summary"]
    assert base["projects"] == withx["projects"]         # identity fields intact
    assert base["analysis_manifest"]["schema_version"] == 1
    assert withx["analysis_manifest"]["schema_version"] == 2


# --- closing round: root confinement + reasons sanitization -------------------

@pytest.mark.parametrize("bad_root", [
    "C:\\Users\\private\\repo", "C:/private/repo", "/home/private/repo",
    "\\\\server\\share", "../outside", "apps/../private", "apps\\api", ""])
def test_invalid_roots_replaced_never_leaked(bad_root):
    led = ExecutionLedger(language="python", root=bad_root)
    led.eligible(("P001",), 1)
    led.attempted_ok(("P001",))
    out = execution_manifest([led], {"P001"})
    proj = out["projects"][0]
    assert proj["root"] == "<invalid-project-root>"
    assert "execution project root is not repository-relative" \
        in proj["contract_errors"]
    # the raw path never appears anywhere; rule status is NOT punished
    text = json.dumps(out)
    for fragment in ("private", "server", "outside", "Users"):
        assert fragment not in text
    assert proj["rules"]["P001"]["status"] == "executed"


@pytest.mark.parametrize("good_root", [".", "apps/api", "apps/my project"])
def test_legal_relative_roots_kept_verbatim(good_root):
    led = ExecutionLedger(language="python", root=good_root)
    led.eligible(("P001",), 1)
    led.attempted_ok(("P001",))
    out = execution_manifest([led], {"P001"})
    assert out["projects"][0]["root"] == good_root
    assert out["projects"][0]["contract_errors"] == []


def test_junk_reason_entries_sanitized_not_leaked():
    led = ExecutionLedger(language="python", root=".")
    led.rules["P001"] = _rec(eligible_inputs=1, attempted=1,
                             partial_reasons=["same", "same", 42])
    led.rules["P002"] = _rec(eligible_inputs=1, attempted=1,
                             partial_reasons=["ok",
                                              {"secret": "C:\\Users\\x\\token"}])
    led.rules["P003"] = _rec(eligible_inputs=1, attempted=1,
                             partial_reasons=None)
    out = execution_manifest([led], {"P001", "P002", "P003"})
    rules = out["projects"][0]["rules"]
    # derive sees the contradiction; serializer emits legal strings only
    assert rules["P001"]["status"] == "inconsistent"
    assert rules["P001"]["partial_reasons"] == ["same"]      # deterministic dedupe
    assert rules["P002"]["partial_reasons"] == ["ok"]
    assert rules["P003"]["partial_reasons"] == []            # None: no crash
    errors = out["projects"][0]["contract_errors"]
    assert "rule P001: invalid entries in partial_reasons" in errors
    assert "rule P002: invalid entries in partial_reasons" in errors
    assert "rule P003: invalid entries in partial_reasons" in errors
    # the offending values (raw object, path, secret) never reach the JSON
    text = json.dumps(out)
    assert "42" not in text and "secret" not in text and "token" not in text


def test_lone_surrogate_reason_sanitized_and_json_writable(tmp_path):
    from auditor.report.json_out import write_json
    bad = "bad\ud800"
    led = ExecutionLedger(language="python", root=".")
    led.rules["P001"] = _rec(eligible_inputs=1, attempted=1,
                             partial_reasons=[bad])
    assert derive_execution_status(led.rules["P001"]) == "inconsistent"
    out = execution_manifest([led], {"P001"})
    entry = out["projects"][0]["rules"]["P001"]
    assert entry["status"] == "inconsistent"
    assert entry["partial_reasons"] == []            # the surrogate is DROPPED
    assert "rule P001: invalid entries in partial_reasons" \
        in out["projects"][0]["contract_errors"]
    assert bad not in json.dumps(out, ensure_ascii=False)
    write_json({"analysis_manifest": {"execution": out}}, tmp_path / "r.json")
    assert (tmp_path / "r.json").is_file()           # no UnicodeEncodeError


def test_lone_surrogate_root_replaced_and_json_writable(tmp_path):
    from auditor.report.json_out import write_json
    led = ExecutionLedger(language="python", root="apps/\ud800")
    led.eligible(("P001",), 1)
    led.attempted_ok(("P001",))
    out = execution_manifest([led], {"P001"})
    proj = out["projects"][0]
    assert proj["root"] == "<invalid-project-root>"
    assert "execution project root is not repository-relative" \
        in proj["contract_errors"]
    assert proj["rules"]["P001"]["status"] == "executed"   # rule not punished
    write_json({"analysis_manifest": {"execution": out}}, tmp_path / "r.json")
    assert (tmp_path / "r.json").is_file()           # no UnicodeEncodeError


# --- end-to-end: real fixture scan --------------------------------------------

@pytest.fixture(scope="module")
def scanned_report(tmp_path_factory):
    from auditor import cli
    out = tmp_path_factory.mktemp("rep")
    cli.main(["scan", "tests/fixtures/monorepo", "--output", str(out),
              "--offline", "--no-semgrep"])
    return json.loads((out / "report.json").read_text(encoding="utf-8"))


def test_e2e_manifest_v2_with_execution_v1(scanned_report):
    manifest = scanned_report["analysis_manifest"]
    assert manifest["schema_version"] == 2
    assert manifest["execution"]["schema_version"] == 1
    assert manifest["catalog"]                            # capability still there
    assert len(manifest["execution"]["projects"]) >= 2    # every ledger arrived


def test_e2e_statuses_are_legal_and_never_pass(scanned_report):
    seen = set()
    for proj in scanned_report["analysis_manifest"]["execution"]["projects"]:
        for entry in proj["rules"].values():
            seen.add(entry["status"])
            assert entry["status"] in EXECUTION_STATUSES
    assert seen.isdisjoint({"pass", "clean", "safe", "passed"})
    assert "executed" in seen                             # builtin rules ran


def test_e2e_executed_skipped_notapplicable_unavailable(scanned_report):
    projects = scanned_report["analysis_manifest"]["execution"]["projects"]
    by_lang = {}
    for p in projects:
        by_lang.setdefault(p["language"], p)
    py = by_lang["python"]["rules"]
    # builtin P-rule with eligible files: executed even where findings differ
    assert py["P001"]["status"] in ("executed", "partial")
    assert py["P001"]["attempted"] >= 1
    # --no-semgrep: S-rule with eligible python files => skipped, never unavailable
    assert py["S:auditor-python-eval-input"]["status"] == "skipped"
    # a python-only S-rule in a non-python project => not_applicable
    other = next(p for lang, p in by_lang.items() if lang not in ("python",))
    assert other["rules"]["S:auditor-python-eval-input"]["status"] == "not_applicable"
    # offline H decisions: whatever registry work existed is unavailable/NA facts
    h_statuses = {rid: e["status"] for rid, e in py.items() if rid.startswith("H")}
    assert h_statuses                                     # H ledger arrived
    assert set(h_statuses.values()) <= {"executed", "partial", "unavailable",
                                        "not_applicable", "not_recorded"}


def test_e2e_no_machine_paths_or_source_in_execution(scanned_report):
    text = json.dumps(scanned_report["analysis_manifest"]["execution"])
    assert "C:\\" not in text and "C:/" not in text and "/Users/" not in text
    for proj in scanned_report["analysis_manifest"]["execution"]["projects"]:
        assert set(proj.keys()) == {"language", "root", "rules", "contract_errors"}
        assert not Path(proj["root"]).is_absolute()


def test_e2e_findings_and_scores_unchanged_by_execution_block(scanned_report):
    # execution lives ONLY under analysis_manifest; projects/summary keys are
    # the same contract as before this slice (structural keys, not the word
    # "execution", which can legitimately appear in finding titles)
    proj_text = json.dumps(scanned_report["projects"])
    for key in ("eligible_inputs", "skipped_reasons", "schema_version"):
        assert key not in proj_text
    assert set(scanned_report["summary"].keys()) == {
        "overall_score", "score_kind", "lowest_language", "counts",
        "level_counts", "analysis_confidence", "verdict"}
