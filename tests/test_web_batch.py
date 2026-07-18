import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import auditor.web.reviews as webreviews
from auditor.web.app import create_app


def _report(tmp_path: Path) -> Path:
    p = tmp_path / "report.json"
    p.write_text(json.dumps({
        "summary": {"counts": {"red": 1, "yellow": 2, "blue": 0}},
        "projects": [
            {"language": "python", "root": ".",
             "findings": [
                 {"rule_id": "P002", "severity": "red", "title": "secret",
                  "file": "a.py", "line": 1, "language": "python",
                  "engine": "auditor", "precision": "exact"},
                 {"rule_id": "P006", "severity": "yellow", "title": "cc",
                  "file": "b.py", "line": 2, "language": "python",
                  "engine": "auditor", "precision": "exact"},
                 {"rule_id": "H002", "severity": "yellow", "title": "und",
                  "file": "c.py", "line": 3, "language": "python",
                  "engine": "auditor", "precision": "heuristic"}]},
        ],
    }), encoding="utf-8")
    return p


@pytest.fixture()
def env(tmp_path):
    client = TestClient(create_app(_report(tmp_path)))
    rep = client.get("/api/report").json()
    fs = rep["projects"][0]["findings"]
    ids = {f["file"]: f["review_id"] for f in fs}   # a.py is the RED one
    return client, ids, tmp_path


def _batch(client, **body):
    payload = {"review_ids": [], "status": "confirmed",
               "note_mode": "keep", "note": "", "confirm_red": False}
    payload.update(body)
    return client.put("/api/review-batch", json=payload)


def test_successful_batch_single_write_all_ids_persisted(env, monkeypatch):
    client, ids, tmp_path = env
    writes = []
    real = webreviews._replace

    def counting(src, dst):
        writes.append(dst)
        return real(src, dst)

    monkeypatch.setattr(webreviews, "_replace", counting)
    r = _batch(client, review_ids=[ids["b.py"], ids["c.py"]],
               status="confirmed", note_mode="replace", note="bulk pass")
    assert r.status_code == 200
    body = r.json()
    assert body["applied"] == 2
    assert len(writes) == 1                        # ONE atomic sidecar write
    reviews = client.get("/api/reviews").json()["reviews"]
    assert reviews[ids["b.py"]]["status"] == "confirmed"
    assert reviews[ids["c.py"]]["note"] == "bulk pass"
    # one shared timestamp across the whole batch
    assert reviews[ids["b.py"]]["updated_at"] == reviews[ids["c.py"]]["updated_at"] \
        == body["updated_at"]


def test_unknown_duplicate_empty_oversize_invalid_inputs(env):
    client, ids, _ = env
    ok = ids["b.py"]
    assert _batch(client, review_ids=[]).status_code == 400
    assert _batch(client, review_ids=[ok, ok]).status_code == 400          # duplicate
    r = _batch(client, review_ids=[ok, "0" * 64])                          # unknown
    assert r.status_code == 404 and "nothing was written" in r.json()["error"]
    assert client.get("/api/reviews").json()["reviews"] == {}              # no write
    assert _batch(client, review_ids=["0" * 64] * 5001).status_code == 400  # oversize... duplicates
    many = [f"{i:064x}" for i in range(5001)]
    assert _batch(client, review_ids=many).status_code == 400              # > cap
    assert _batch(client, review_ids=[ok], status="fixed").status_code == 400
    assert _batch(client, review_ids=[ok], note_mode="merge").status_code == 400
    assert _batch(client, review_ids=[ok], note="x" * 2001).status_code == 400


def test_red_findings_require_server_side_confirmation(env):
    client, ids, _ = env
    red = ids["a.py"]
    r = _batch(client, review_ids=[red, ids["b.py"]], status="false_positive")
    assert r.status_code == 409
    assert r.json()["red_count"] == 1
    assert client.get("/api/reviews").json()["reviews"] == {}              # blocked
    ok = _batch(client, review_ids=[red, ids["b.py"]], status="false_positive",
                confirm_red=True)
    assert ok.status_code == 200
    # accepted_risk likewise gated; confirmed is NOT (marking real bugs is safe)
    assert _batch(client, review_ids=[red], status="accepted_risk").status_code == 409
    assert _batch(client, review_ids=[red], status="confirmed").status_code == 200


def test_note_modes_keep_append_replace_and_unreviewed(env):
    client, ids, _ = env
    b, c = ids["b.py"], ids["c.py"]
    client.put(f"/api/reviews/{b}", json={"status": "confirmed", "note": "original"})
    # keep: existing note preserved, absent note stays empty
    _batch(client, review_ids=[b, c], status="accepted_risk", note_mode="keep",
           note="ignored-in-keep")
    rv = client.get("/api/reviews").json()["reviews"]
    assert rv[b]["note"] == "original" and rv[c]["note"] == ""
    # append: new line onto existing, plain set when empty
    _batch(client, review_ids=[b, c], status="accepted_risk", note_mode="append",
           note="second")
    rv = client.get("/api/reviews").json()["reviews"]
    assert rv[b]["note"] == "original\nsecond" and rv[c]["note"] == "second"
    # replace
    _batch(client, review_ids=[b], status="confirmed", note_mode="replace", note="final")
    assert client.get("/api/reviews").json()["reviews"][b]["note"] == "final"
    # unreviewed deletes the records
    r = _batch(client, review_ids=[b, c], status="unreviewed")
    assert r.status_code == 200
    assert client.get("/api/reviews").json()["reviews"] == {}


def test_append_overflow_fails_whole_batch_before_write(env):
    client, ids, tmp_path = env
    b = ids["b.py"]
    client.put(f"/api/reviews/{b}", json={"status": "confirmed", "note": "x" * 1990})
    side = tmp_path / "report.reviews.json"
    before = side.read_bytes()
    r = _batch(client, review_ids=[b, ids["c.py"]], status="confirmed",
               note_mode="append", note="y" * 20)              # 1990+1+20 > 2000
    assert r.status_code == 400 and "exceeds" in r.json()["error"]
    assert side.read_bytes() == before                          # nothing written
    rv = client.get("/api/reviews").json()["reviews"]
    assert rv[b]["note"] == "x" * 1990 and ids["c.py"] not in rv


def test_failed_replace_keeps_disk_memory_no_temp(env, monkeypatch):
    client, ids, tmp_path = env
    b = ids["b.py"]
    client.put(f"/api/reviews/{b}", json={"status": "confirmed", "note": "safe"})
    side = tmp_path / "report.reviews.json"
    before = side.read_bytes()

    def boom(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(webreviews, "_replace", boom)
    r = _batch(client, review_ids=[b, ids["c.py"]], status="accepted_risk")
    assert r.status_code == 503
    monkeypatch.undo()
    assert side.read_bytes() == before
    rv = client.get("/api/reviews").json()["reviews"]
    assert rv[b]["status"] == "confirmed" and ids["c.py"] not in rv
    assert list(tmp_path.glob("*.tmp")) == []


def test_sidecar_never_stores_severity_or_code(env):
    client, ids, tmp_path = env
    _batch(client, review_ids=[ids["a.py"]], status="confirmed",
           note_mode="replace", note="checked")
    raw = (tmp_path / "report.reviews.json").read_text(encoding="utf-8")
    data = json.loads(raw)
    assert set(data["reviews"][ids["a.py"]]) == {"status", "note", "updated_at"}
    for banned in ("severity", "snippet", "source", "red"):
        assert banned not in raw


def test_sibling_apis_not_regressed(env):
    client, ids, _ = env
    assert client.get("/api/report").status_code == 200
    assert client.get("/api/coverage").status_code == 200
    assert client.get("/api/reviews").status_code == 200
    assert client.put(f"/api/reviews/{ids['b.py']}",
                      json={"status": "confirmed"}).status_code == 200
    assert client.delete(f"/api/reviews/{ids['b.py']}").status_code == 200
    assert client.get("/api/source",
                      params={"path": "a.py", "line": 1}).status_code in (400, 403, 409)