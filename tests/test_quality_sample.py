"""W2-B2.8D Final: tests for the committed deterministic sampler.

The sampler must be path-agnostic (real paths never appear in errors or
output), invariant to JSON ordering, and must implement the fixed plan:
error/block union, full-review aliases, per-rule cap with round-robin across
projects in fingerprint order, dedup on full identity."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from quality_sample import SampleError, sample_id, select_sample  # noqa: E402


def _f(file="a.py", line=1, rule="P001", fp=None, level="warning",
       gate="review"):
    return {"file": file, "line": line, "rule_id": rule,
            "fingerprint": fp or f"{line:02d}" + "a" * 62,
            "level": level, "gate_action": gate}


def _report(tmp_path, name, projects):
    p = tmp_path / name
    p.write_text(json.dumps({"projects": [
        {"root": root, "findings": fs} for root, fs in projects
    ]}), encoding="utf-8")
    return p


def test_sample_id_is_deterministic_over_full_identity():
    a = sample_id("repo-a", "p", "f.py", 3, "P001", "ab" * 32)
    assert a == sample_id("repo-a", "p", "f.py", 3, "P001", "ab" * 32)
    assert a != sample_id("repo-a", "p", "f.py", 4, "P001", "ab" * 32)
    assert a != sample_id("repo-b", "p", "f.py", 3, "P001", "ab" * 32)


def test_error_and_block_findings_always_selected(tmp_path):
    findings = [_f(line=n) for n in range(1, 30)]
    findings.append(_f(line=99, rule="P002", level="error", gate="block"))
    rp = _report(tmp_path, "r.json", [("proj", findings)])
    out = select_sample({"repo-a": rp}, cap=5, full_review=())
    blockers = [s for s in out if s["level"] == "error"]
    assert len(blockers) == 1 and blockers[0]["rule"] == "P002"


def test_full_review_alias_is_taken_entirely(tmp_path):
    findings = [_f(line=n) for n in range(1, 40)]
    rp = _report(tmp_path, "r.json", [("proj", findings)])
    assert len(select_sample({"repo-b": rp}, cap=5,
                             full_review=("repo-b",))) == 39
    assert len(select_sample({"repo-b": rp}, cap=5, full_review=())) == 5


def test_small_strata_taken_in_full_large_strata_capped(tmp_path):
    small = [_f(line=n, rule="R004") for n in range(1, 11)]      # pop 10
    large = [_f(line=n, rule="P006") for n in range(100, 200)]   # pop 100
    rp = _report(tmp_path, "r.json", [("proj", small + large)])
    out = select_sample({"repo-a": rp}, cap=20, full_review=())
    by_rule = {}
    for s in out:
        by_rule[s["rule"]] = by_rule.get(s["rule"], 0) + 1
    assert by_rule == {"R004": 10, "P006": 20}
    pops = {s["rule"]: s["population"] for s in out}
    assert pops == {"R004": 10, "P006": 100}


def test_round_robin_across_projects_in_fingerprint_order(tmp_path):
    pa = [_f(file="a.py", line=n, rule="P006", fp=f"{n:064x}")
          for n in range(1, 30)]
    pb = [_f(file="b.py", line=n, rule="P006", fp=f"{n + 100:064x}")
          for n in range(1, 30)]
    rp = _report(tmp_path, "r.json", [("proj-a", pa), ("proj-b", pb)])
    out = select_sample({"repo-a": rp}, cap=4, full_review=())
    got = {(s["project"], s["fingerprint"]) for s in out}
    # 2 from each project, and each project's 2 lowest fingerprints
    assert got == {("proj-a", f"{1:064x}"), ("proj-a", f"{2:064x}"),
                   ("proj-b", f"{101:064x}"), ("proj-b", f"{102:064x}")}


def test_dedup_is_on_full_identity_not_fingerprint(tmp_path):
    # same fingerprint on two different lines -> both eligible and selected
    fp = "c" * 64
    findings = [_f(line=5, fp=fp), _f(line=9, fp=fp)]
    rp = _report(tmp_path, "r.json", [("proj", findings)])
    out = select_sample({"repo-a": rp}, cap=20, full_review=())
    assert len(out) == 2 and len({s["sample_id"] for s in out}) == 2


def test_selection_is_invariant_to_json_ordering(tmp_path):
    pa = [_f(file="a.py", line=n, rule="P006", fp=f"{n:064x}")
          for n in range(1, 30)]
    pb = [_f(file="b.py", line=n, rule="R004", fp=f"{n + 50:064x}")
          for n in range(1, 8)]
    r1 = _report(tmp_path, "r1.json", [("proj-a", pa), ("proj-b", pb)])
    r2 = _report(tmp_path, "r2.json",
                 [("proj-b", list(reversed(pb))),
                  ("proj-a", list(reversed(pa)))])
    out1 = select_sample({"repo-a": r1}, cap=6, full_review=())
    out2 = select_sample({"repo-a": r2}, cap=6, full_review=())
    assert out1 == out2


def test_errors_name_the_alias_never_the_path(tmp_path):
    secret_dir = tmp_path / "very-secret-location"
    secret_dir.mkdir()
    missing = secret_dir / "report.json"
    with pytest.raises(SampleError) as exc:
        select_sample({"repo-a": missing})
    msg = str(exc.value)
    assert "repo-a" in msg
    assert "very-secret-location" not in msg and str(tmp_path) not in msg

    bad = secret_dir / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(SampleError) as exc:
        select_sample({"repo-a": bad})
    msg = str(exc.value)
    assert "repo-a" in msg and "very-secret-location" not in msg


def test_output_carries_no_absolute_paths(tmp_path):
    rp = _report(tmp_path, "r.json", [("proj", [_f()])])
    out = select_sample({"repo-a": rp})
    blob = json.dumps(out)
    assert str(tmp_path) not in blob and str(rp) not in blob
