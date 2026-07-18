import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from auditor.web.app import (
    ReportError,
    aggregate_findings,
    create_app,
    load_report,
)

VALID = {
    "summary": {
        "verdict": "block",
        "overall_score": 66,
        "analysis_confidence": 86,
        "counts": {"red": 1, "yellow": 1, "blue": 0},
    },
    "projects": [
        {"language": "python", "root": ".", "findings": [
            {"rule_id": "P006", "severity": "yellow", "title": "complexity",
             "file": "a.py", "line": 15, "snippet": "foo", "detail": "cc 32",
             "language": "python", "precision": "exact"}]},
        {"language": "typescript", "root": "web", "findings": [
            {"rule_id": "R001", "severity": "red", "title": "conditional hook",
             "file": "h.ts", "line": 3, "snippet": "useX", "detail": "hooks rule",
             "language": "typescript", "precision": "heuristic"}]},
    ],
}


def _write(tmp_path: Path, obj) -> Path:
    p = tmp_path / "report.json"
    p.write_text(json.dumps(obj), encoding="utf-8")
    return p


def _examples_report() -> Path:
    return Path(__file__).resolve().parents[1] / "examples" / "report.json"


def test_valid_report_is_served(tmp_path):
    app = create_app(_write(tmp_path, VALID))
    client = TestClient(app)
    r = client.get("/api/report")
    assert r.status_code == 200
    body = r.json()
    assert body["summary"]["verdict"] == "block"
    assert len(body["projects"]) == 2


def test_health_endpoint(tmp_path):
    app = create_app(_write(tmp_path, VALID), repo_root=tmp_path)
    r = TestClient(app).get("/api/health")
    h = r.json()
    assert h["status"] == "ok"
    assert h["report_loaded"] is True
    assert h["projects"] == 2
    assert h["findings"] == 2
    assert h["counts"] == {"red": 1, "yellow": 1, "blue": 0}
    assert h["source_available"] is True
    # machine paths never leave the server — not even the repo root
    assert "repo_root" not in h
    assert str(tmp_path) not in r.text and ":\\" not in r.text


def test_corrupt_report_gives_clear_error(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{ this is not json", encoding="utf-8")
    with pytest.raises(ReportError) as ei:
        load_report(p)
    assert "not valid JSON" in str(ei.value)


def test_report_must_be_object(tmp_path):
    p = tmp_path / "arr.json"
    p.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ReportError) as ei:
        load_report(p)
    assert "JSON object" in str(ei.value)


def test_missing_projects_key(tmp_path):
    with pytest.raises(ReportError) as ei:
        load_report(_write(tmp_path, {"summary": {}}))
    assert "projects" in str(ei.value)


def test_missing_report_file(tmp_path):
    with pytest.raises(ReportError) as ei:
        load_report(tmp_path / "nope.json")
    assert "not found" in str(ei.value)


def test_report_over_size_cap_is_rejected(tmp_path):
    p = _write(tmp_path, VALID)
    with pytest.raises(ReportError) as ei:
        load_report(p, max_bytes=10)   # far below the real size
    assert "too large" in str(ei.value)


def test_aggregate_findings_across_projects():
    rows = aggregate_findings(VALID)
    assert len(rows) == 2
    assert {r["project"] for r in rows} == {".", "web"}
    red = next(r for r in rows if r["rule_id"] == "R001")
    assert red["severity"] == "red"
    assert red["project"] == "web"
    assert red["file"] == "h.ts" and red["line"] == 3
    assert red["precision"] == "heuristic"
    assert red["language"] == "typescript"


def test_aggregate_findings_ignores_malformed_rows():
    report = {"summary": {}, "projects": [
        {"root": "x", "findings": ["not a dict", {"rule_id": "P001", "severity": "red"}]},
        {"root": "y", "findings": "not a list"},
        "not a project",
    ]}
    rows = aggregate_findings(report)
    assert len(rows) == 1
    assert rows[0]["rule_id"] == "P001" and rows[0]["project"] == "x"


def test_aggregate_matches_summary_counts_on_examples():
    """Portable end-to-end: every finding in examples/report.json aggregates,
    and the total equals red+yellow+blue in the summary (counts==findings)."""
    path = _examples_report()
    if not path.exists():
        pytest.skip("examples/report.json not present")
    report = load_report(path)
    rows = aggregate_findings(report)
    total = sum(report["summary"]["counts"].values())
    assert len(rows) == total
