"""W2-B2.8B2-B/C: offline PASS + baseline/new-only.

Fingerprints are line-independent content identity (multiset matched);
--new-only re-scopes gate_counts/verdict to NEW findings without deleting
anything; the baseline loader fails CLOSED and never echoes paths/snippets.
"""
import json
from collections import Counter

import pytest

from auditor.cli import main
from auditor.core.baseline import (
    BASELINE_MAX_BYTES,
    BaselineError,
    finding_fingerprint,
    load_baseline_counter,
    match_findings,
    normalize_anchor,
)
from auditor.core.models import Finding, Severity
from auditor.report.build import build_report


def _f(rule="P002", sev=Severity.RED, precision="exact", file="a.py", line=3,
       title="t", snippet="password = 'x'"):
    return Finding(rule, sev, title, file, line, snippet=snippet,
                   precision=precision)


def _rep(findings, **kw):
    return build_report("tgt", [{"language": "python", "root": ".",
                                 "file_count": 1, "findings": findings}],
                        engines={}, limitations=[], confidence=100, **kw)


# ---- fingerprint contract -----------------------------------------------------

def test_fingerprint_ignores_line_and_whitespace():
    a = finding_fingerprint(".", "a.py", "P002", "auditor",
                            normalize_anchor("x  =\t1", ""))
    b = finding_fingerprint(".", "a.py", "P002", "auditor",
                            normalize_anchor(" x = 1 ", ""))
    assert a == b                        # whitespace collapsed, no line input


def test_fingerprint_changes_with_file_rule_anchor():
    base = finding_fingerprint(".", "a.py", "P002", "auditor", "x = 1")
    assert finding_fingerprint(".", "b.py", "P002", "auditor", "x = 1") != base
    assert finding_fingerprint(".", "a.py", "P003", "auditor", "x = 1") != base
    assert finding_fingerprint(".", "a.py", "P002", "auditor", "y = 2") != base


def test_anchor_falls_back_to_title_when_snippet_empty():
    assert normalize_anchor("", "  Missing   dep ") == "Missing dep"


def test_line_shift_keeps_finding_unchanged():
    old = _rep([_f(line=3)])
    counter = load_counter_from(old)
    new = _rep([_f(line=40)], baseline=counter)         # moved 37 lines down
    f = new["projects"][0]["findings"][0]
    assert f["baseline_state"] == "unchanged"
    assert new["summary"]["baseline"] == {
        "enabled": True, "gate_scope": "all", "new": 0, "unchanged": 1,
        "resolved": 0}


def load_counter_from(report_dict) -> Counter:
    return Counter(f["fingerprint"] for p in report_dict["projects"]
                   for f in p["findings"])


def test_duplicates_match_as_multiset_not_set():
    dup = _f(line=1)
    old = _rep([dup, _f(line=9)])                       # two identical fps
    counter = load_counter_from(old)
    new = _rep([_f(line=2), _f(line=11), _f(line=30)], baseline=counter)
    states = [f["baseline_state"] for f in new["projects"][0]["findings"]]
    assert sorted(states) == ["new", "unchanged", "unchanged"]
    assert new["summary"]["baseline"]["new"] == 1


def test_resolved_is_a_count_only():
    old = _rep([_f(), _f(file="gone.py")])
    new = _rep([_f()], baseline=load_counter_from(old))
    base = new["summary"]["baseline"]
    assert base["resolved"] == 1
    # no baseline finding content is copied into the new report
    assert "gone.py" not in json.dumps(new)


def test_match_findings_pure_counts():
    states, summary = match_findings(["a", "a", "b"], Counter({"a": 1, "c": 2}))
    assert states == ["unchanged", "new", "new"]
    assert summary == {"new": 2, "unchanged": 1, "resolved": 2}


# ---- gate scope (new-only) ------------------------------------------------------

def test_new_only_gates_new_findings_but_keeps_everything():
    old = _rep([_f()])                                   # the old exact error
    counter = load_counter_from(old)
    findings = [_f(),                                    # unchanged exact error
                _f(rule="H008", file="n1.py", precision="heuristic",
                   snippet="import ghost"),              # NEW heuristic error
                _f(rule="P003", file="n2.py", snippet="eval(x)")]  # NEW exact
    scoped = _rep(findings, baseline=counter, gate_scope="new")
    assert scoped["summary"]["baseline"]["gate_scope"] == "new"
    # gate counts contain ONLY the two new findings
    assert scoped["summary"]["gate_counts"] == {"block": 1, "review": 1,
                                                "informational": 0}
    assert scoped["summary"]["verdict"] == "block"       # new exact error
    # nothing was deleted; whole-report counts/health stay whole-report
    assert len(scoped["projects"][0]["findings"]) == 3
    assert scoped["summary"]["counts"]["red"] == 3
    # without new-only the same scan gates everything
    full = _rep(findings, baseline=counter)
    assert full["summary"]["gate_counts"]["block"] == 2


def test_new_only_all_unchanged_passes():
    old = _rep([_f()])
    scoped = _rep([_f(line=99)], baseline=load_counter_from(old),
                  gate_scope="new")
    assert scoped["summary"]["gate_counts"] == {"block": 0, "review": 0,
                                                "informational": 0}
    assert scoped["summary"]["verdict"] == "pass"


# ---- baseline loader: fail closed -----------------------------------------------

def _write_baseline(tmp_path, data):
    p = tmp_path / "old-report.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def test_loader_accepts_pre_b28b2_reports_without_fingerprints(tmp_path):
    old = _rep([_f()])
    for proj in old["projects"]:
        for f in proj["findings"]:
            del f["fingerprint"]                         # simulate old report
    p = _write_baseline(tmp_path, old)
    counter = load_baseline_counter(p)
    new = _rep([_f(line=50)], baseline=counter)
    assert new["projects"][0]["findings"][0]["baseline_state"] == "unchanged"


@pytest.mark.parametrize("data,frag", [
    ({"tool": "other-tool", "projects": []}, "not an ai-code-auditor report"),
    ({"tool": "ai-code-auditor"}, "projects must be a list"),
    ({"tool": "ai-code-auditor", "projects": [{"root": ".",
                                               "findings": [["not", "dict"]]}]},
     "finding must be an object"),
    ({"tool": "ai-code-auditor",
      "projects": [{"root": ".", "findings": [{"fingerprint": "xyz"}]}]},
     "malformed fingerprint"),
])
def test_loader_fails_closed_on_incompatible_or_corrupt(tmp_path, data, frag):
    p = _write_baseline(tmp_path, data)
    with pytest.raises(BaselineError) as ei:
        load_baseline_counter(p)
    assert frag in str(ei.value)


def test_loader_rejects_broken_json_and_missing_file(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{broken", encoding="utf-8")
    with pytest.raises(BaselineError) as ei:
        load_baseline_counter(p)
    assert "not valid JSON" in str(ei.value)
    with pytest.raises(BaselineError):
        load_baseline_counter(tmp_path / "missing.json")


def test_loader_errors_never_echo_machine_paths_or_snippets(tmp_path):
    secret_dir = tmp_path / "C_Users_private"
    secret_dir.mkdir()
    p = secret_dir / "rep.json"
    p.write_text(json.dumps({"tool": "ai-code-auditor", "projects": [
        {"root": ".", "findings": [{"fingerprint": "SECRET-SNIPPET-TEXT"}]}]}),
        encoding="utf-8")
    with pytest.raises(BaselineError) as ei:
        load_baseline_counter(p)
    msg = str(ei.value)
    for frag in ("SECRET", "C_Users_private", str(tmp_path)):
        assert frag not in msg, msg


def test_loader_size_cap_fails_closed(tmp_path, monkeypatch):
    import auditor.core.baseline as bl
    p = _write_baseline(tmp_path, {"tool": "ai-code-auditor", "projects": []})
    monkeypatch.setattr(bl, "BASELINE_MAX_BYTES", 10)
    with pytest.raises(BaselineError) as ei:
        bl.load_baseline_counter(p)
    assert "exceeds" in str(ei.value)
    assert BASELINE_MAX_BYTES >= 1024 * 1024              # the real cap is sane


def test_loader_bounded_even_when_stat_lies(tmp_path, monkeypatch):
    """The closing-round counter-case: stat() reports a tiny size while the
    real content exceeds the cap. stat is only a cheap early refusal — the
    GUARANTEE is the bounded cap+1 binary read, which must still reject."""
    from pathlib import Path

    import auditor.core.baseline as bl
    p = _write_baseline(tmp_path, {"tool": "ai-code-auditor", "projects": [
        {"root": ".", "findings": [
            {"rule_id": "P002", "file": f"f{i}.py", "title": "t",
             "snippet": f"x = {i}"} for i in range(12)]}]})
    assert p.stat().st_size > 64

    class LyingStat:
        st_size = 2

    monkeypatch.setattr(bl, "BASELINE_MAX_BYTES", 64)
    monkeypatch.setattr(Path, "stat", lambda self, **kw: LyingStat())
    with pytest.raises(BaselineError) as ei:
        bl.load_baseline_counter(p)
    msg = str(ei.value)
    assert "exceeds" in msg
    # the safe message: no local path, no baseline content
    assert str(tmp_path) not in msg and "P002" not in msg and "f0.py" not in msg


def test_loader_reads_at_most_cap_plus_one_bytes(tmp_path, monkeypatch):
    """Spy on the binary read: the largest single read must be exactly
    cap+1 — never -1 / unbounded, and no unbounded read_text/read_bytes."""
    import io

    from pathlib import Path

    import auditor.core.baseline as bl
    p = _write_baseline(tmp_path, {"tool": "ai-code-auditor", "projects": []})
    read_sizes: list[object] = []
    real_open = Path.open

    class SpyFile(io.BufferedReader):
        def read(self, size=-1, /):
            read_sizes.append(size)
            return super().read(size)

    def spy_open(self, mode="r", *a, **kw):
        assert mode == "rb", f"unexpected open mode {mode!r} in baseline load"
        return SpyFile(real_open(self, mode).detach())

    monkeypatch.setattr(bl, "BASELINE_MAX_BYTES", 1024)
    monkeypatch.setattr(Path, "open", spy_open)
    monkeypatch.setattr(Path, "read_text",
                        lambda *a, **kw: pytest.fail("unbounded read_text used"))
    monkeypatch.setattr(Path, "read_bytes",
                        lambda *a, **kw: pytest.fail("unbounded read_bytes used"))
    counter = bl.load_baseline_counter(p)
    assert counter == Counter()                       # legal file still accepted
    assert read_sizes, "the loader never read the file"
    assert all(isinstance(s, int) and 0 < s <= 1024 + 1 for s in read_sizes), \
        read_sizes
    assert max(read_sizes) == 1024 + 1                # the bounded read itself


def test_loader_open_failure_is_safe_baseline_error(tmp_path, monkeypatch):
    from pathlib import Path

    import auditor.core.baseline as bl
    p = _write_baseline(tmp_path, {"tool": "ai-code-auditor", "projects": []})

    def boom(self, mode="r", *a, **kw):
        raise OSError(13, "Permission denied", str(p))

    monkeypatch.setattr(Path, "open", boom)
    with pytest.raises(BaselineError) as ei:
        bl.load_baseline_counter(p)
    msg = str(ei.value)
    assert "not found or unreadable" in msg
    assert str(tmp_path) not in msg                   # OSError path not echoed


def test_loader_decode_failure_is_safe_baseline_error(tmp_path):
    p = tmp_path / "bad-utf8.json"
    p.write_bytes(b'{"tool": "ai-code-auditor", "projects": [\xff\xfe]}')
    with pytest.raises(BaselineError) as ei:
        load_baseline_counter(p)
    assert "not readable UTF-8 text" in str(ei.value)


# ---- offline PASS + CLI wiring ---------------------------------------------------

def _clean_project(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "1.0"\n', encoding="utf-8")


def test_offline_clean_scan_passes_even_strict(tmp_path):
    _clean_project(tmp_path)
    out = tmp_path / "rep"
    assert main(["scan", str(tmp_path), "--output", str(out), "--offline",
                 "--no-semgrep"]) == 0
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert data["summary"]["verdict"] == "pass"
    assert data["summary"]["registry_status"] == "unavailable"
    assert data["summary"]["registry_confidence"] is None
    # strict stays 0 when there is nothing to review
    assert main(["scan", str(tmp_path), "--output", str(out), "--offline",
                 "--no-semgrep", "--strict"]) == 0


def test_offline_exact_error_still_blocks(tmp_path):
    _clean_project(tmp_path)
    (tmp_path / "app.py").write_text(
        'API_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")
    out = tmp_path / "rep"
    assert main(["scan", str(tmp_path), "--output", str(out), "--offline",
                 "--no-semgrep"]) == 1
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert data["summary"]["verdict"] == "block"


def test_online_registry_failure_reviews():
    # unit-level: the CLI computes registry_status from the diagnostics; a
    # failed lookup during an ONLINE run must forbid pass via reg_status
    from auditor.core.scoring import registry_status, verdict
    status = registry_status(False, 12, 3)
    assert status == "partial"
    assert verdict({"block": 0, "review": 0, "informational": 0}, 100, {},
                   reg_status=status) == "review"


def test_new_only_requires_baseline(tmp_path, capsys):
    _clean_project(tmp_path)
    code = main(["scan", str(tmp_path), "--output", str(tmp_path / "r"),
                 "--offline", "--no-semgrep", "--new-only"])
    assert code == 2
    assert "--new-only requires --baseline" in capsys.readouterr().err


def test_cli_baseline_end_to_end_line_shift(tmp_path):
    _clean_project(tmp_path)
    (tmp_path / "app.py").write_text(
        'API_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")
    out1 = tmp_path / "r1"
    main(["scan", str(tmp_path), "--output", str(out1), "--offline",
          "--no-semgrep"])
    # shift the finding down two lines; content identical
    (tmp_path / "app.py").write_text(
        '\n\nAPI_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")
    out2 = tmp_path / "r2"
    code = main(["scan", str(tmp_path), "--output", str(out2), "--offline",
                 "--no-semgrep", "--baseline", str(out1 / "report.json"),
                 "--new-only"])
    data = json.loads((out2 / "report.json").read_text(encoding="utf-8"))
    base = data["summary"]["baseline"]
    assert base["enabled"] and base["gate_scope"] == "new"
    assert base["new"] == 0 and base["unchanged"] >= 1
    # the old exact error is unchanged => nothing gates => PASS, exit 0
    assert data["summary"]["verdict"] == "pass"
    assert code == 0


def test_reports_without_baseline_have_no_fabricated_states(tmp_path):
    rep = _rep([_f()])
    f = rep["projects"][0]["findings"][0]
    assert "baseline_state" not in f
    assert "baseline" not in rep["summary"]
    assert "fingerprint" in f                # always present for future baselines
