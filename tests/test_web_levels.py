import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from auditor.core.levels import (
    CANONICAL_LEVELS,
    LEGACY_SEVERITY_TO_LEVEL,
    normalize_level,
)
from auditor.core.models import Finding, Severity
from auditor.report.build import build_report
from auditor.web.app import create_app
from auditor.web.reviews import review_id

# an optional LOCAL report for extra assertions (never committed): point
# AUDITOR_LOCAL_REPORT at a real report.json; otherwise these tests skip
TABI_REPORT = Path(os.environ.get("AUDITOR_LOCAL_REPORT",
                                  "local-report/report.json"))


# --- normalization unit ------------------------------------------------------

def test_normalize_valid_level_wins_over_conflicting_severity():
    assert normalize_level("note", "red") == "note"       # level beats severity
    assert normalize_level("error", "blue") == "error"


def test_normalize_legacy_severity_mapping():
    assert normalize_level(None, "red") == "error"
    assert normalize_level(None, "yellow") == "warning"
    assert normalize_level(None, "blue") == "note"


def test_normalize_literal_contract_vectors():
    """The exact closure vectors: severity fallback ONLY when level is ABSENT;
    a present-but-invalid level is unclassified — never a severity fallback."""
    assert normalize_level(None, "red") == "error"
    assert normalize_level("error", "blue") == "error"
    assert normalize_level("none", "red") is None
    assert normalize_level("bogus", "red") is None
    assert normalize_level("", "red") is None
    assert normalize_level({}, "red") is None
    assert normalize_level([], "red") is None
    assert normalize_level(5, "red") is None


def test_normalize_unknown_never_silently_promoted():
    assert normalize_level("critical", "purple") is None  # both unknown
    assert normalize_level(None, "purple") is None
    assert normalize_level(5, None) is None
    assert normalize_level("none", None) is None          # SARIF 'none' unused by us
    assert set(LEGACY_SEVERITY_TO_LEVEL.values()) == set(CANONICAL_LEVELS)


# --- new report output -------------------------------------------------------

def _finding(sev: Severity, rule="P002", file="a.py", line=1) -> Finding:
    return Finding(rule_id=rule, severity=sev, title="t", file=file, line=line,
                   language="python", engine="auditor", precision="exact")


def test_new_report_carries_level_and_level_counts_plus_legacy():
    rep = build_report("tgt", [{"language": "python", "root": ".", "file_count": 1,
                                "findings": [_finding(Severity.RED),
                                             _finding(Severity.YELLOW, file="b.py"),
                                             _finding(Severity.BLUE, file="c.py")]}],
                       engines={}, limitations=[], confidence=100)
    f = rep["projects"][0]["findings"]
    assert [x["level"] for x in f] == ["error", "warning", "note"]
    assert [x["severity"] for x in f] == ["red", "yellow", "blue"]   # legacy kept
    assert rep["summary"]["level_counts"] == {"error": 1, "warning": 1, "note": 1}
    assert rep["summary"]["counts"] == {"red": 1, "yellow": 1, "blue": 1}


def test_scoring_and_verdict_identical_before_after_migration():
    """The level migration must not move a single number: same findings =>
    same score/verdict as the legacy-only formula inputs."""
    projects = [{"language": "python", "root": ".", "file_count": 2,
                 "findings": [_finding(Severity.RED), _finding(Severity.YELLOW, file="b.py")]}]
    rep = build_report("tgt", projects, engines={}, limitations=[], confidence=90)
    from auditor.core.scoring import language_score, verdict
    expected_score = language_score(projects[0]["findings"])
    assert rep["projects"][0]["score"] == expected_score
    # B2.8B2: an exact RED gates as block, a YELLOW as review
    assert rep["summary"]["verdict"] == verdict(
        {"block": 1, "review": 1, "informational": 0}, 90, {})


def test_review_id_identical_before_after_level_field():
    """`level` is not an identity field: the id of a finding dict with and
    without it must match (stability across the migration)."""
    a = review_id(".", "a.py", 1, "P002", "t", "auditor")
    rep = build_report("tgt", [{"language": "python", "root": ".", "file_count": 1,
                                "findings": [_finding(Severity.RED)]}],
                       engines={}, limitations=[], confidence=100)
    f = rep["projects"][0]["findings"][0]
    assert review_id(".", f["file"], f["line"], f["rule_id"], f["title"],
                     f["engine"]) == a


# --- web compatibility -------------------------------------------------------

def _legacy_report(tmp_path: Path) -> Path:
    """A report exactly like the pre-migration format: severity only."""
    p = tmp_path / "report.json"
    p.write_text(json.dumps({
        "summary": {"counts": {"red": 1, "yellow": 1, "blue": 1}},
        "projects": [{"language": "python", "root": ".", "findings": [
            {"rule_id": "P002", "severity": "red", "title": "secret", "file": "a.py",
             "line": 1, "language": "python", "engine": "auditor", "precision": "exact"},
            {"rule_id": "P006", "severity": "yellow", "title": "cc", "file": "b.py",
             "line": 2, "language": "python", "engine": "auditor", "precision": "exact"},
            {"rule_id": "P007", "severity": "blue", "title": "todo", "file": "c.py",
             "line": 3, "language": "python", "engine": "auditor", "precision": "exact"},
        ]}],
    }), encoding="utf-8")
    return p


def test_legacy_report_served_with_normalized_levels_disk_untouched(tmp_path):
    rp = _legacy_report(tmp_path)
    before = rp.read_bytes()
    c = TestClient(create_app(rp))
    fs = c.get("/api/report").json()["projects"][0]["findings"]
    assert [f["level"] for f in fs] == ["error", "warning", "note"]
    h = c.get("/api/health").json()
    assert h["level_counts"] == {"error": 1, "warning": 1, "note": 1}
    assert h["counts"] == {"red": 1, "yellow": 1, "blue": 1}   # legacy kept
    assert rp.read_bytes() == before                            # not one byte changed


def test_new_report_served_with_levels(tmp_path):
    rep = build_report("tgt", [{"language": "python", "root": ".", "file_count": 1,
                                "findings": [_finding(Severity.RED)]}],
                       engines={}, limitations=[], confidence=100)
    p = tmp_path / "report.json"
    p.write_text(json.dumps(rep), encoding="utf-8")
    c = TestClient(create_app(p))
    assert c.get("/api/report").json()["projects"][0]["findings"][0]["level"] == "error"
    assert c.get("/api/health").json()["level_counts"]["error"] == 1


def test_unknown_level_not_promoted_in_served_copy(tmp_path):
    p = tmp_path / "report.json"
    p.write_text(json.dumps({
        "summary": {"counts": {}},
        "projects": [{"language": "python", "root": ".", "findings": [
            {"rule_id": "P1", "severity": "purple", "level": "critical",
             "title": "t", "file": "a.py", "line": 1, "engine": "auditor",
             "precision": "exact"}]}],
    }), encoding="utf-8")
    c = TestClient(create_app(p))
    f = c.get("/api/report").json()["projects"][0]["findings"][0]
    assert f.get("level") == "critical"   # raw value passes through UNCHANGED
    # the aggregation surfaces the ILLEGAL LEVEL ITSELF (level was present),
    # not the severity — and never promotes it
    cov = c.get("/api/coverage").json()
    rule = cov["observed_rules"][0]
    assert rule["levels"] == ["unclassified(critical)"]


def test_coverage_unclassified_shows_offending_value(tmp_path):
    p = tmp_path / "report.json"
    p.write_text(json.dumps({
        "summary": {"counts": {}},
        "projects": [{"language": "python", "root": ".", "findings": [
            {"rule_id": "A", "severity": "red", "level": "none",
             "title": "t", "file": "a.py", "line": 1, "engine": "auditor",
             "precision": "exact"},
            {"rule_id": "B", "severity": "red", "level": "bogus",
             "title": "t", "file": "b.py", "line": 1, "engine": "auditor",
             "precision": "exact"},
            {"rule_id": "C", "severity": "purple",
             "title": "t", "file": "c.py", "line": 1, "engine": "auditor",
             "precision": "exact"}]}],
    }), encoding="utf-8")
    c = TestClient(create_app(p))
    levels = {r["rule_id"]: r["levels"] for r in c.get("/api/coverage").json()["observed_rules"]}
    assert levels["A"] == ["unclassified(none)"]     # NOT unclassified(red)
    assert levels["B"] == ["unclassified(bogus)"]
    assert levels["C"] == ["unclassified(purple)"]   # level absent => raw severity


def _batch(client, ids, status, **kw):
    payload = {"review_ids": ids, "status": status, "note_mode": "keep",
               "note": ""}
    payload.update(kw)
    return client.put("/api/review-batch", json=payload)


def test_error_gate_works_on_legacy_and_new_reports(tmp_path):
    for maker in (_legacy_report, None):
        if maker is None:
            rep = build_report("tgt", [{"language": "python", "root": ".",
                                        "file_count": 1,
                                        "findings": [_finding(Severity.RED)]}],
                               engines={}, limitations=[], confidence=100)
            rp = tmp_path / "new" / "report.json"
            rp.parent.mkdir(exist_ok=True)
            rp.write_text(json.dumps(rep), encoding="utf-8")
        else:
            rp = maker(tmp_path)
        c = TestClient(create_app(rp))
        rid = next(f["review_id"] for f in
                   c.get("/api/report").json()["projects"][0]["findings"]
                   if f.get("level") == "error")
        r = _batch(c, [rid], "false_positive")
        assert r.status_code == 409
        assert r.json()["error_count"] == 1 and r.json()["red_count"] == 1
        assert "error-level" in r.json()["error"]
        # canonical flag
        assert _batch(c, [rid], "false_positive", confirm_error=True).status_code == 200
        _batch(c, [rid], "unreviewed")
        # legacy alias still accepted
        assert _batch(c, [rid], "false_positive", confirm_red=True).status_code == 200
        _batch(c, [rid], "unreviewed")


@pytest.mark.skipif(not TABI_REPORT.exists(), reason="Tabi report not on this machine")
def test_tabi_legacy_report_shows_2_error_77_warning_25_note():
    c = TestClient(create_app(TABI_REPORT))
    h = c.get("/api/health").json()
    assert h["level_counts"] == {"error": 2, "warning": 77, "note": 25}
    fs = [f for p in c.get("/api/report").json()["projects"] for f in p["findings"]]
    from collections import Counter
    assert Counter(f["level"] for f in fs) == {"warning": 77, "note": 25, "error": 2}
