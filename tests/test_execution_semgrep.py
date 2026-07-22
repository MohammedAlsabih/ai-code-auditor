"""B2-C: execution recording for the external Semgrep/OpenGrep S:* rules.
Deterministic — no real binary, no network: subprocess.run is always mocked.
The ledger is driven ONLY by the structured SemgrepRun, never by status text
and never inferred from findings."""
import json

import pytest

from auditor.core.execution import ExecutionLedger
from auditor.core.models import Diagnostics, SourceFile
from auditor.core.semgrep_rules_meta import shipped_semgrep_descriptors
from auditor.core.semgrep_runner import (
    SemgrepRun,
    note_uncataloged_semgrep_rules,
    record_semgrep_execution,
    run_semgrep_structured,
)

EVAL = "S:auditor-python-eval-input"
PICKLE = "S:auditor-python-pickle-load"
JS_CHILD = "S:auditor-js-child-process-concat"
JAVA_EXEC = "S:auditor-java-runtime-exec-concat"
WEAK_HASH = "S:auditor-weak-hash"


@pytest.fixture(scope="module")
def descriptors():
    return shipped_semgrep_descriptors()


def _sf(tmp_path, rel, language):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        p.write_text("x = 1\n", encoding="utf-8")
    return SourceFile(path=p, rel=rel, language=language, text=b"x = 1\n")


def _proc(monkeypatch, payload, returncode=0):
    class P:
        stdout = payload if isinstance(payload, str) else json.dumps(payload)
        stderr = ""
    P.returncode = returncode
    monkeypatch.setattr("subprocess.run", lambda *a, **k: P())


# --- identity: catalog == runner == ledger ------------------------------------

def test_five_shipped_ids_match_runner_output_literally(monkeypatch, tmp_path, descriptors):
    ids = {d.rule_id for d in descriptors}
    assert len(ids) == 5
    canned = {"results": [
        {"check_id": d.rule_id[2:], "path": str(tmp_path / "a.py"),
         "start": {"line": 1}, "extra": {"message": "m", "severity": "WARNING"}}
        for d in descriptors], "errors": [], "paths": {"scanned": [str(tmp_path / "a.py")]}}
    _proc(monkeypatch, canned)
    run = run_semgrep_structured("semgrep", tmp_path, [])
    assert {f.rule_id for f in run.findings} == ids     # literal, no normalization


def test_semgrep_and_opengrep_produce_same_identity(monkeypatch, tmp_path):
    canned = {"results": [{"check_id": "auditor-weak-hash", "path": str(tmp_path / "a.py"),
                           "start": {"line": 2}, "extra": {"message": "m", "severity": "WARNING"}}],
              "errors": [], "paths": {"scanned": [str(tmp_path / "a.py")]}}
    _proc(monkeypatch, canned)
    a = run_semgrep_structured("semgrep", tmp_path, [])
    b = run_semgrep_structured("opengrep", tmp_path, [])
    assert [f.rule_id for f in a.findings] == [f.rule_id for f in b.findings] == [WEAK_HASH]


# --- runner: structured evidence ----------------------------------------------

def test_success_zero_findings_still_attempted(monkeypatch, tmp_path, descriptors):
    py = _sf(tmp_path, "a.py", "python")
    canned = {"results": [], "errors": [], "paths": {"scanned": [str(py.path)]}}
    _proc(monkeypatch, canned)
    run = run_semgrep_structured("semgrep", tmp_path, [], expected_paths={str(py.path)})
    assert run.state == "success" and run.started and run.findings == []
    led = ExecutionLedger(language="python", root=".")
    record_semgrep_execution([(led, [py])], descriptors, run=run)
    rec = led.rules[EVAL]
    assert rec.eligible_inputs == 1 and rec.attempted == 1 and rec.failures == 0
    assert not rec.partial_reasons and not rec.unavailable_reasons \
        and not rec.skipped_reasons


def test_good_finding_with_errors_is_partial_finding_kept(monkeypatch, tmp_path, descriptors):
    py = _sf(tmp_path, "a.py", "python")
    canned = {"results": [{"check_id": "auditor-python-eval-input", "path": str(py.path),
                           "start": {"line": 1}, "extra": {"message": "m", "severity": "ERROR"}}],
              "errors": [{"type": "SyntaxError"}], "paths": {"scanned": [str(py.path)]}}
    _proc(monkeypatch, canned)
    run = run_semgrep_structured("semgrep", tmp_path, [])
    assert run.state == "partial" and len(run.findings) == 1
    led = ExecutionLedger(language="python", root=".")
    record_semgrep_execution([(led, [py])], descriptors, run=run)
    rec = led.rules[EVAL]
    assert rec.attempted == 1 and rec.failures == 0
    assert any("file errors" in r for r in rec.partial_reasons)


def test_expected_file_not_scanned_counts_blocked(monkeypatch, tmp_path, descriptors):
    a = _sf(tmp_path, "a.py", "python")
    b = _sf(tmp_path, "b.py", "python")
    canned = {"results": [], "errors": [], "paths": {"scanned": [str(a.path)]}}
    _proc(monkeypatch, canned)
    run = run_semgrep_structured("semgrep", tmp_path, [],
                                 expected_paths={str(a.path), str(b.path)})
    assert run.state == "partial" and len(run.missing_expected_paths) == 1
    led = ExecutionLedger(language="python", root=".")
    record_semgrep_execution([(led, [a, b])], descriptors, run=run)
    rec = led.rules[EVAL]
    assert rec.eligible_inputs == 2 and rec.attempted == 1
    assert rec.blocked_inputs == 1                # exactly b.py, exact membership


def test_malformed_result_plus_good_is_partial_good_kept(monkeypatch, tmp_path):
    canned = {"results": ["garbage",
                          {"check_id": "auditor-weak-hash", "path": str(tmp_path / "a.py"),
                           "start": {"line": 1}, "extra": {"message": "m", "severity": "WARNING"}}],
              "errors": [], "paths": {"scanned": [str(tmp_path / "a.py")]}}
    _proc(monkeypatch, canned)
    run = run_semgrep_structured("semgrep", tmp_path, [])
    assert run.state == "partial" and [f.rule_id for f in run.findings] == [WEAK_HASH]
    assert any("malformed" in r for r in run.partial_reasons)


def test_missing_or_empty_check_id_never_becomes_s_unknown(monkeypatch, tmp_path):
    canned = {"results": [
        {"path": str(tmp_path / "a.py"), "start": {"line": 1},
         "extra": {"message": "m", "severity": "WARNING"}},              # no check_id
        {"check_id": "  ", "path": str(tmp_path / "a.py"), "start": {"line": 2},
         "extra": {"message": "m", "severity": "WARNING"}}],             # empty id
        "errors": [], "paths": {"scanned": [str(tmp_path / "a.py")]}}
    _proc(monkeypatch, canned)
    run = run_semgrep_structured("semgrep", tmp_path, [])
    assert run.findings == []                       # no fake S:unknown rule
    assert run.state == "partial"
    assert any("malformed" in r for r in run.partial_reasons)


# --- structural output hardening (fix round) -----------------------------------

@pytest.mark.parametrize("payload", [
    [],                                                       # top-level not object
    {"results": [], "paths": "oops"},                         # paths not object
    {"results": [], "paths": {"scanned": [{}]}},              # scanned item not str
    {"results": [], "errors": "oops", "paths": {}},           # errors not list
    {"results": [], "paths": {"scanned": [], "skipped": "nah"}},   # skipped not list
    {"results": [], "paths": {"scanned": ["a.py", 42]}},      # non-str in scanned
])
def test_structural_garbage_is_invalid_output_never_a_crash(monkeypatch, tmp_path,
                                                            payload):
    _proc(monkeypatch, payload)
    run = run_semgrep_structured("semgrep", tmp_path, [])
    assert run.state == "invalid_output" and run.started
    assert run.status_text == "invalid_output"
    # no stdout fragments or machine paths in any reason
    assert all("oops" not in r and "\\" not in r for r in run.partial_reasons)


def test_errors_string_never_counted_as_characters(monkeypatch, tmp_path):
    # 'oops' must NOT become "4 file errors" — it is unusable structure
    _proc(monkeypatch, {"results": [], "errors": "oops", "paths": {}})
    run = run_semgrep_structured("semgrep", tmp_path, [])
    assert run.state == "invalid_output"
    assert not any("4" in r for r in run.partial_reasons)


# --- scanned evidence: requested, proven, never assumed (schema round) -----------

def test_argv_requests_verbose_evidence_not_quiet(monkeypatch, tmp_path):
    captured = {}

    class P:
        returncode = 0
        stdout = json.dumps({"results": [], "errors": [], "paths": {"scanned": []}})
        stderr = ""

    def fake(cmd, **k):
        captured["cmd"] = cmd
        return P()

    monkeypatch.setattr("subprocess.run", fake)
    run_semgrep_structured("semgrep", tmp_path, [])
    assert "--verbose" in captured["cmd"]      # scanned evidence is REQUESTED
    assert "--quiet" not in captured["cmd"]    # opposite verbosity, not combined


def test_scanned_absent_is_no_evidence_not_all_missing(monkeypatch, tmp_path,
                                                       descriptors):
    a = _sf(tmp_path, "a.py", "python")
    _proc(monkeypatch, {"results": [], "errors": [], "paths": {}})
    run = run_semgrep_structured("semgrep", tmp_path, [],
                                 expected_paths={str(a.path)})
    assert run.state == "partial"
    assert run.missing_expected_paths == set()       # nothing CLAIMED unscanned
    assert "scanned path evidence unavailable" in run.shared_partial_reasons
    assert not any("not scanned" in r for r in run.partial_reasons)
    led = ExecutionLedger(language="python", root=".")
    record_semgrep_execution([(led, [a])], descriptors, run=run)
    rec = led.rules[EVAL]
    assert rec.attempted == 1 and rec.blocked_inputs == 0
    assert "scanned path evidence unavailable" in rec.partial_reasons


def test_scanned_present_empty_is_evidence_of_zero_scanned(monkeypatch, tmp_path,
                                                           descriptors):
    a = _sf(tmp_path, "a.py", "python")
    _proc(monkeypatch, {"results": [], "errors": [], "paths": {"scanned": []}})
    run = run_semgrep_structured("semgrep", tmp_path, [],
                                 expected_paths={str(a.path)})
    assert run.state == "partial"
    assert run.missing_expected_paths == {a.path.resolve().as_posix()}
    assert any("1/1 expected files not scanned" in r for r in run.partial_reasons)
    led = ExecutionLedger(language="python", root=".")
    record_semgrep_execution([(led, [a])], descriptors, run=run)
    assert led.rules[EVAL].blocked_inputs == 1


# --- legal skipped_target / cli_error objects (schema round) ----------------------

def test_legal_skipped_target_object_accepted_and_attributed(monkeypatch, tmp_path,
                                                             descriptors):
    py = _sf(tmp_path, "py/a.py", "python")
    ts = _sf(tmp_path, "web/t.ts", "typescript")
    canned = {"results": [], "errors": [],
              "paths": {"scanned": [str(py.path)],
                        "skipped": [{"path": "web/t.ts", "reason": "wrong_language"}]}}
    _proc(monkeypatch, canned)
    run = run_semgrep_structured("semgrep", tmp_path, [])
    assert run.state == "partial"
    assert run.skipped_paths == {ts.path.resolve().as_posix()}
    led_py = ExecutionLedger(language="python", root="py")
    led_ts = ExecutionLedger(language="typescript", root="web")
    record_semgrep_execution([(led_py, [py]), (led_ts, [ts])], descriptors, run=run)
    # the skip belongs to the TS project only, numeric phrasing, no raw path/reason
    rp, rt = led_py.rules[WEAK_HASH], led_ts.rules[WEAK_HASH]
    assert not any("skipped file" in r for r in rp.partial_reasons)
    assert "1 skipped file(s) in this project" in rt.partial_reasons
    assert not any("t.ts" in r or "wrong_language" in r
                   for r in rt.partial_reasons)


@pytest.mark.parametrize("bad", [[42], [{}], [{"path": ""}],
                                 [{"path": "x.py", "reason": 5}]])
def test_garbage_skipped_entries_never_become_a_count(monkeypatch, tmp_path, bad):
    _proc(monkeypatch, {"results": [], "errors": [],
                        "paths": {"scanned": [], "skipped": bad}})
    run = run_semgrep_structured("semgrep", tmp_path, [])
    assert run.state == "invalid_output"
    assert not any("skipped" in r for r in run.partial_reasons)


def test_error_objects_attributed_or_shared(monkeypatch, tmp_path, descriptors):
    py = _sf(tmp_path, "py/a.py", "python")
    ts = _sf(tmp_path, "web/t.ts", "typescript")
    canned = {"results": [],
              "errors": [{"path": "web/t.ts", "message": "SECRET-detail"},
                         {"message": "global failure"}],
              "paths": {"scanned": [str(py.path)]}}
    _proc(monkeypatch, canned)
    run = run_semgrep_structured("semgrep", tmp_path, [])
    assert run.error_paths == {ts.path.resolve().as_posix()}
    assert "1 file errors" in run.shared_partial_reasons     # the path-less one
    led_py = ExecutionLedger(language="python", root="py")
    led_ts = ExecutionLedger(language="typescript", root="web")
    record_semgrep_execution([(led_py, [py]), (led_ts, [ts])], descriptors, run=run)
    rp, rt = led_py.rules[WEAK_HASH], led_ts.rules[WEAK_HASH]
    assert not any("in this project" in r for r in rp.partial_reasons)  # clean py
    assert "1 file error(s) in this project" in rt.partial_reasons
    # shared engine-level reason reaches both; raw message/path never leak
    for rec in (rp, rt):
        assert "1 file errors" in rec.partial_reasons
        assert not any("SECRET-detail" in r or "t.ts" in r or "global failure" in r
                       for r in rec.partial_reasons)
    assert rp.blocked_inputs == 0


def test_non_object_error_entry_fails_closed(monkeypatch, tmp_path):
    _proc(monkeypatch, {"results": [], "errors": [42],
                        "paths": {"scanned": []}})
    run = run_semgrep_structured("semgrep", tmp_path, [])
    assert run.state == "invalid_output"       # not laundered into "1 file errors"
    assert run.partial_reasons == []


# --- started semantics -----------------------------------------------------------

def test_not_started_is_unavailable_never_a_failure(tmp_path, descriptors):
    py = _sf(tmp_path, "a.py", "python")
    led = ExecutionLedger(language="python", root=".")
    run = SemgrepRun(state="failed", started=False, status_text="failed")
    record_semgrep_execution([(led, [py])], descriptors, run=run)
    rec = led.rules[EVAL]
    assert rec.eligible_inputs == 1
    assert rec.attempted == 0 and rec.failures == 0
    assert rec.unavailable_reasons == ["semgrep/opengrep engine failed to start"]
    assert rec.failure_reasons == []            # requires an attempt that began


def test_started_vs_not_started_failure_matrix(tmp_path, descriptors):
    py = _sf(tmp_path, "a.py", "python")
    cases = [
        (SemgrepRun(state="failed", started=False, status_text="failed"), 0, 0),
        (SemgrepRun(state="failed", started=True, exit_code=7,
                    status_text="failed (exit 7)"), 1, 1),
        (SemgrepRun(state="timed_out", started=True, status_text="timed_out"), 1, 1),
        (SemgrepRun(state="invalid_output", started=True,
                    status_text="invalid_output"), 1, 1),
    ]
    for run, want_att, want_fail in cases:
        led = ExecutionLedger(language="python", root=".")
        record_semgrep_execution([(led, [py])], descriptors, run=run)
        rec = led.rules[EVAL]
        assert (rec.attempted, rec.failures) == (want_att, want_fail), run.state


def test_oserror_run_reports_not_started(monkeypatch, tmp_path):
    monkeypatch.setattr("subprocess.run",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("no exec")))
    run = run_semgrep_structured("nope.exe", tmp_path, [])
    assert run.state == "failed" and run.started is False


# --- per-project partial isolation ------------------------------------------------

def test_missing_files_reason_stays_in_its_own_project(tmp_path, descriptors):
    """Python project fully scanned + TS project with an unscanned file in the
    SAME run: the miss belongs to the TS ledger only, phrased locally."""
    py = _sf(tmp_path, "py/a.py", "python")
    ts = _sf(tmp_path, "web/b.ts", "typescript")
    run = SemgrepRun(
        state="partial", started=True,
        status_text="partial (1/2 expected files not scanned)",
        partial_reasons=["1/2 expected files not scanned"],
        shared_partial_reasons=[],
        missing_expected_paths={ts.path.resolve().as_posix()})
    led_py = ExecutionLedger(language="python", root="py")
    led_ts = ExecutionLedger(language="typescript", root="web")
    record_semgrep_execution([(led_py, [py]), (led_ts, [ts])], descriptors, run=run)
    rp, rt = led_py.rules[WEAK_HASH], led_ts.rules[WEAK_HASH]
    assert rp.attempted == 1 and rp.blocked_inputs == 0
    assert not any("not scanned" in r for r in rp.partial_reasons)   # not inherited
    assert rt.attempted == 1 and rt.blocked_inputs == 1
    assert rt.partial_reasons == ["1/1 eligible files not scanned"]  # local phrasing


def test_shared_reasons_still_recorded_everywhere(tmp_path, descriptors):
    py = _sf(tmp_path, "py/a.py", "python")
    ts = _sf(tmp_path, "web/b.ts", "typescript")
    run = SemgrepRun(state="partial", started=True,
                     status_text="partial (2 file errors)",
                     partial_reasons=["2 file errors"],
                     shared_partial_reasons=["2 file errors"])
    led_py = ExecutionLedger(language="python", root="py")
    led_ts = ExecutionLedger(language="typescript", root="web")
    record_semgrep_execution([(led_py, [py]), (led_ts, [ts])], descriptors, run=run)
    assert led_py.rules[WEAK_HASH].partial_reasons == ["2 file errors"]
    assert led_ts.rules[WEAK_HASH].partial_reasons == ["2 file errors"]


def test_runner_splits_shared_from_missing_reasons(monkeypatch, tmp_path):
    a, b = tmp_path / "a.py", tmp_path / "b.py"
    a.write_text("x=1\n", encoding="utf-8")
    b.write_text("x=1\n", encoding="utf-8")
    canned = {"results": [], "errors": [{"type": "E"}],
              "paths": {"scanned": [str(a)]}}
    _proc(monkeypatch, canned)
    run = run_semgrep_structured("semgrep", tmp_path, [],
                                 expected_paths={str(a), str(b)})
    assert run.state == "partial"
    # display keeps the legacy composite; shared excludes the attributable miss
    assert any("not scanned" in r for r in run.partial_reasons)
    assert run.shared_partial_reasons == ["1 file errors"]
    assert run.missing_expected_paths == {b.resolve().as_posix()}


# --- failure states -> one failure each ----------------------------------------

@pytest.mark.parametrize("setup,state", [
    ("timeout", "timed_out"), ("exit7", "failed"), ("garbage", "invalid_output")])
def test_engine_failure_states_one_failure(monkeypatch, tmp_path, descriptors, setup, state):
    import subprocess as sp
    if setup == "timeout":
        monkeypatch.setattr("subprocess.run",
                            lambda *a, **k: (_ for _ in ()).throw(
                                sp.TimeoutExpired(cmd="x", timeout=600)))
    elif setup == "exit7":
        _proc(monkeypatch, "{}", returncode=7)
    else:
        _proc(monkeypatch, "not json {")
    run = run_semgrep_structured("semgrep", tmp_path, [])
    assert run.state == state
    py = _sf(tmp_path, "a.py", "python")
    led = ExecutionLedger(language="python", root=".")
    record_semgrep_execution([(led, [py])], descriptors, run=run)
    rec = led.rules[EVAL]
    assert rec.attempted == 1 and rec.failures == 1
    assert rec.failure_reasons and all("stdout" not in r and "stderr" not in r
                                       and "\\" not in r for r in rec.failure_reasons)


# --- non-execution facts --------------------------------------------------------

def test_binary_absent_unavailable_no_attempt(tmp_path, descriptors):
    py = _sf(tmp_path, "a.py", "python")
    led = ExecutionLedger(language="python", root=".")
    record_semgrep_execution([(led, [py])], descriptors, binary_missing=True)
    rec = led.rules[EVAL]
    assert rec.eligible_inputs == 1 and rec.attempted == 0
    assert rec.unavailable_reasons == ["no semgrep/opengrep binary available"]
    assert not rec.skipped_reasons


def test_no_semgrep_flag_is_skipped_not_unavailable(tmp_path, descriptors):
    py = _sf(tmp_path, "a.py", "python")
    led = ExecutionLedger(language="python", root=".")
    record_semgrep_execution([(led, [py])], descriptors, disabled=True)
    rec = led.rules[EVAL]
    assert rec.attempted == 0
    assert rec.skipped_reasons == ["semgrep engine disabled by --no-semgrep"]
    assert not rec.unavailable_reasons             # a choice is not an inability


def test_project_without_eligible_files_not_applicable(tmp_path, descriptors):
    py = _sf(tmp_path, "a.py", "python")           # python project
    led = ExecutionLedger(language="python", root=".")
    run = SemgrepRun(state="success", started=True, status_text="success")
    record_semgrep_execution([(led, [py])], descriptors, run=run)
    rec = led.rules[JAVA_EXEC]                     # java rule, no java files
    assert rec.attempted == 0 and rec.eligible_inputs == 0
    assert rec.not_applicable_reasons == ["no java files in this project"]


def test_weak_hash_isolated_per_project_ledger(tmp_path, descriptors):
    """Python + TypeScript projects: weak-hash is eligible in EACH project's
    own ledger; python-only rules never look executed in the TS project."""
    py = _sf(tmp_path, "py/a.py", "python")
    ts = _sf(tmp_path, "web/b.ts", "typescript")
    tsx = _sf(tmp_path, "web/c.tsx", "tsx")
    led_py = ExecutionLedger(language="python", root="py")
    led_ts = ExecutionLedger(language="typescript", root="web")
    run = SemgrepRun(state="success", started=True, status_text="success")
    record_semgrep_execution([(led_py, [py]), (led_ts, [ts, tsx])],
                             descriptors, run=run)
    assert led_py.rules[WEAK_HASH].eligible_inputs == 1
    assert led_py.rules[WEAK_HASH].attempted == 1
    assert led_ts.rules[WEAK_HASH].eligible_inputs == 2    # .ts + .tsx both count
    assert led_ts.rules[WEAK_HASH].attempted == 1          # unit = invocation
    # language isolation, both directions
    assert led_ts.rules[EVAL].attempted == 0
    assert led_ts.rules[EVAL].not_applicable_reasons
    assert led_py.rules[JS_CHILD].attempted == 0
    assert led_py.rules[JS_CHILD].not_applicable_reasons


# --- external configs -----------------------------------------------------------

def test_unknown_external_rule_keeps_finding_no_fake_capability(monkeypatch, tmp_path,
                                                                descriptors):
    canned = {"results": [{"check_id": "community.some-external-rule",
                           "path": str(tmp_path / "a.py"), "start": {"line": 1},
                           "extra": {"message": "m", "severity": "WARNING"}}],
              "errors": [], "paths": {"scanned": [str(tmp_path / "a.py")]}}
    _proc(monkeypatch, canned)
    run = run_semgrep_structured("semgrep", tmp_path, [])
    assert [f.rule_id for f in run.findings] == ["S:community.some-external-rule"]
    diag = Diagnostics()
    note_uncataloged_semgrep_rules(run.findings, descriptors, diag)
    assert any("not in the shipped catalog" in n for n in diag.notes)
    # never attributed to a shipped rule's execution
    py = _sf(tmp_path, "a.py", "python")
    led = ExecutionLedger(language="python", root=".")
    record_semgrep_execution([(led, [py])], descriptors, run=run)
    assert "S:community.some-external-rule" not in led.rules


# --- guards ----------------------------------------------------------------------

def test_ledger_guards_forbid_contradictions():
    led = ExecutionLedger()
    rid = (WEAK_HASH,)
    led.partial_reason(rid, "x")                    # partial needs attempted>0
    assert led.rules[WEAK_HASH].partial_reasons == []
    led.skipped(rid, "user disabled")
    led.unavailable(rid, "no binary")               # never alongside skipped
    assert led.rules[WEAK_HASH].unavailable_reasons == []
    led2 = ExecutionLedger()
    led2.unavailable(rid, "no binary")
    led2.skipped(rid, "user disabled")              # nor the other way round
    assert led2.rules[WEAK_HASH].skipped_reasons == []
    led3 = ExecutionLedger()
    led3.attempted_ok(rid)
    led3.skipped(rid, "late skip")                  # not after an attempt
    led3.unavailable(rid, "late unavailable")
    led3.not_applicable(rid, "late NA")
    r3 = led3.rules[WEAK_HASH]
    assert r3.skipped_reasons == [] and r3.unavailable_reasons == [] \
        and r3.not_applicable_reasons == []


# --- diagnostics / scoring stay untouched ----------------------------------------

def test_ledger_recording_never_changes_scoring(tmp_path, descriptors):
    from auditor.core.scoring import analysis_confidence, verdict
    diag = Diagnostics(semgrep_status="semgrep 1.0.0: success")
    before_conf = analysis_confidence(diag, files_read=3)
    before_verdict = verdict({"block": 0, "review": 0}, before_conf,
                             {"rule_attempted": 4, "rule_failures": 0,
                              "semgrep_status": diag.semgrep_status})
    py = _sf(tmp_path, "a.py", "python")
    led = ExecutionLedger(language="python", root=".")
    run = SemgrepRun(state="partial", started=True, status_text="partial (1 skipped)",
                     partial_reasons=["1 skipped"])
    record_semgrep_execution([(led, [py])], descriptors, run=run)
    assert diag.rule_attempted == 0 and diag.rule_failures == 0   # untouched
    after_conf = analysis_confidence(diag, files_read=3)
    assert (before_conf, before_verdict) == (
        after_conf, verdict({"block": 0, "review": 0}, after_conf,
                            {"rule_attempted": 4, "rule_failures": 0,
                             "semgrep_status": diag.semgrep_status}))


def test_pipeline_serializes_semgrep_execution_under_manifest(tmp_path):
    from auditor import cli
    out = tmp_path / "rep"
    cli.main(["scan", "tests/fixtures/monorepo", "--output", str(out),
              "--offline", "--no-semgrep"])
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert "disabled by --no-semgrep" in data["diagnostics"]["semgrep_status"]
    # B2-D: the S:* ledger facts now appear ONLY under analysis_manifest.execution
    manifest = data["analysis_manifest"]
    assert manifest["schema_version"] == 2
    py = next(p for p in manifest["execution"]["projects"]
              if p["language"] == "python")
    rec = py["rules"]["S:auditor-python-eval-input"]
    assert rec["status"] == "skipped" and rec["attempted"] == 0
    assert rec["skipped_reasons"] == ["semgrep engine disabled by --no-semgrep"]
    # execution facts never leak into the findings/projects block
    assert "skipped_reasons" not in json.dumps(data["projects"])
