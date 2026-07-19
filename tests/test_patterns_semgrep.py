import json

from auditor.core import semgrep_runner
from auditor.core.models import Finding, Severity
from auditor.core.patterns import dedupe, run_pattern_engine


def test_pattern_engine_on_python_fixture(fixtures_dir):
    from auditor.adapters.python.adapter import PythonAdapter
    from auditor.core.walk import collect_source_files
    root = fixtures_dir / "python_repo"
    a = PythonAdapter()
    files = collect_source_files(root, a)
    fs = run_pattern_engine(a, root, files, frameworks=[])
    ids = {f.rule_id for f in fs}
    assert {"P001", "P002", "P005", "P006", "P007"} <= ids


def test_framework_filter_skips_react_rules_for_plain_ts(fixtures_dir):
    from auditor.adapters.typescript.adapter import TypeScriptAdapter
    from auditor.core.walk import collect_source_files
    root = fixtures_dir / "ts_repo"
    a = TypeScriptAdapter()
    files = collect_source_files(root, a)
    without = run_pattern_engine(a, root, files, frameworks=[])
    with_fw = run_pattern_engine(a, root, files, frameworks=["react", "next"])
    assert not any(f.rule_id.startswith(("R", "N")) for f in without)
    assert any(f.rule_id.startswith("R") for f in with_fw)
    assert any(f.rule_id == "N001" for f in with_fw)  # .env.local scan


def test_project_rules_failure_counts_and_forbids_pass(tmp_path):
    # a crashing project_rules previously hit rule_errors WITHOUT
    # rule_failures, leaving confidence 100 and verdict PASS
    from auditor.core.models import Diagnostics, SourceFile
    from auditor.core.scoring import analysis_confidence, verdict

    class BoomAdapter:
        name = "python"
        body_entered = False
        def syntax(self):
            from auditor.adapters.python.adapter import PythonAdapter
            return PythonAdapter().syntax()
        def language_rules(self):
            return []
        def project_rules(self, root, frameworks, ledger=None, diag=None):
            BoomAdapter.body_entered = True
            raise RuntimeError("project rule exploded")

    sf = SourceFile(path=tmp_path / "a.py", rel="a.py", language="python", text=b"x = 1\n")
    diag = Diagnostics()
    run_pattern_engine(BoomAdapter(), tmp_path, [sf], [], diag=diag)
    # the body actually RAN and its own RuntimeError is what got recorded —
    # not an unexpected-keyword TypeError from the call site
    assert BoomAdapter.body_entered
    assert any("project_rules(python): RuntimeError" in e for e in diag.rule_errors)
    assert diag.rule_failures >= 1 and diag.rule_attempted >= 1
    conf = analysis_confidence(diag, offline=False, files_read=1)
    assert conf < 100
    assert verdict({"red": 0, "yellow": 0}, conf,
                   {"rule_attempted": diag.rule_attempted,
                    "rule_failures": diag.rule_failures}) != "pass"


def test_dedupe_keeps_different_findings_on_same_line():
    builtin = Finding("P005", Severity.RED, "t", "a.py", 10)
    sg_other = Finding("S:x.other-rule", Severity.RED, "t", "a.py", 10, engine="semgrep")
    exact_dup = Finding("P005", Severity.RED, "t", "a.py", 10)
    out = dedupe([sg_other, builtin, exact_dup])
    assert [f.rule_id for f in out] == ["P005", "S:x.other-rule"]  # both kept, dup collapsed


def test_find_binary_none_when_absent(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert semgrep_runner.find_binary() is None


def test_run_semgrep_parses_json(monkeypatch, tmp_path):
    canned = {"results": [{
        "check_id": "auditor-python-eval-input",
        "path": str(tmp_path / "x.py"),
        "start": {"line": 3},
        "extra": {"message": "eval bad", "severity": "ERROR"},
    }]}

    class P:
        returncode = 0
        stdout = json.dumps(canned)
        stderr = ""

    monkeypatch.setattr("subprocess.run", lambda *a, **k: P())
    fs, status = semgrep_runner.run_semgrep("semgrep", tmp_path, [])
    assert status == "success" and len(fs) == 1
    f = fs[0]
    assert f.rule_id == "S:auditor-python-eval-input" and f.severity == Severity.RED
    assert f.file == "x.py" and f.line == 3 and f.engine == "semgrep"


def test_run_semgrep_failure_states_are_distinct(monkeypatch, tmp_path):
    import subprocess as sp

    def boom(*a, **k):
        raise OSError("no binary")
    monkeypatch.setattr("subprocess.run", boom)
    assert semgrep_runner.run_semgrep("nope.exe", tmp_path, []) == ([], "failed")

    def slow(*a, **k):
        raise sp.TimeoutExpired(cmd="x", timeout=600)
    monkeypatch.setattr("subprocess.run", slow)
    assert semgrep_runner.run_semgrep("x", tmp_path, [])[1] == "timed_out"

    class BadExit:
        returncode = 7   # measured: semgrep config errors exit 7
        stdout = "{}"
        stderr = ""
    monkeypatch.setattr("subprocess.run", lambda *a, **k: BadExit())
    assert semgrep_runner.run_semgrep("x", tmp_path, [])[1] == "failed (exit 7)"

    class Garbage:
        returncode = 0
        stdout = "not json {"
        stderr = ""
    monkeypatch.setattr("subprocess.run", lambda *a, **k: Garbage())
    assert semgrep_runner.run_semgrep("x", tmp_path, [])[1] == "invalid_output"


def test_run_semgrep_results_and_errors_together_is_partial(monkeypatch, tmp_path):
    canned = {"results": [{"check_id": "r", "path": str(tmp_path / "a.py"),
                           "start": {"line": 1},
                           "extra": {"message": "m", "severity": "WARNING"}}],
              "errors": [{"type": "SyntaxError", "path": str(tmp_path / "broken.py")}],
              "paths": {"scanned": [str(tmp_path / "a.py")]}}

    class P:
        returncode = 0
        stdout = json.dumps(canned)
        stderr = ""
    monkeypatch.setattr("subprocess.run", lambda *a, **k: P())
    fs, status = semgrep_runner.run_semgrep("x", tmp_path, [])
    assert len(fs) == 1                       # findings are kept
    assert "partial" in status and "1 file errors" in status  # completeness not claimed


def test_run_semgrep_unscanned_expected_file_is_partial(monkeypatch, tmp_path):
    # rc=0, errors=0, yet a targeted file silently not scanned => partial
    a, b = tmp_path / "a.py", tmp_path / "b.py"
    canned = {"results": [], "errors": [], "paths": {"scanned": [str(a)]}}

    class P:
        returncode = 0
        stdout = json.dumps(canned)
        stderr = ""
    monkeypatch.setattr("subprocess.run", lambda *a, **k: P())
    fs, status = semgrep_runner.run_semgrep("x", tmp_path, [],
                                            expected_paths={str(a), str(b)})
    assert fs == [] and "partial" in status and "not scanned" in status


def test_run_semgrep_full_coverage_is_success(monkeypatch, tmp_path):
    a = tmp_path / "a.py"
    canned = {"results": [], "errors": [], "paths": {"scanned": [str(a)]}}

    class P:
        returncode = 0
        stdout = json.dumps(canned)
        stderr = ""
    monkeypatch.setattr("subprocess.run", lambda *a, **k: P())
    assert semgrep_runner.run_semgrep("x", tmp_path, [], expected_paths={str(a)})[1] == "success"


def test_bundled_rules_exist_and_bom_free():
    p = semgrep_runner.bundled_rules_path()
    raw = p.read_bytes()
    assert raw and not raw.startswith(b"\xef\xbb\xbf")
