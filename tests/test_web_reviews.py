import json
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import auditor.web.reviews as webreviews
from auditor.web.app import create_app
from auditor.web.reviews import ReviewStore, review_id


def _report(tmp_path: Path) -> Path:
    p = tmp_path / "report.json"
    p.write_text(json.dumps({
        "summary": {"counts": {"red": 1, "yellow": 1, "blue": 0}},
        "projects": [
            {"language": "python", "root": ".",
             "findings": [{"rule_id": "P001", "severity": "red", "title": "eval use",
                           "file": "a.py", "line": 3, "snippet": "eval(x)",
                           "detail": "dangerous eval", "language": "python",
                           "engine": "auditor", "precision": "exact"}]},
            {"language": "typescript", "root": "web",
             "findings": [{"rule_id": "R001", "severity": "yellow", "title": "cond hook",
                           "file": "h.ts", "line": 9, "snippet": "useX()",
                           "detail": "hook in branch", "language": "typescript",
                           "engine": "auditor", "precision": "heuristic"}]},
        ],
    }), encoding="utf-8")
    return p


def _client(tmp_path, **kw):
    app = create_app(_report(tmp_path), **kw)
    return TestClient(app)


def _first_rid(client) -> str:
    rep = client.get("/api/report").json()
    return rep["projects"][0]["findings"][0]["review_id"]


# --- identity -------------------------------------------------------------

def test_review_id_deterministic_and_field_sensitive():
    base = review_id(".", "a.py", 3, "P001", "eval use", "auditor")
    assert base == review_id(".", "a.py", 3, "P001", "eval use", "auditor")
    assert len(base) == 64 and int(base, 16) >= 0          # sha256 hex
    # ANY identity field change => different id (decision can't be misattributed)
    assert base != review_id("web", "a.py", 3, "P001", "eval use", "auditor")
    assert base != review_id(".", "b.py", 3, "P001", "eval use", "auditor")
    assert base != review_id(".", "a.py", 4, "P001", "eval use", "auditor")
    assert base != review_id(".", "a.py", 3, "P002", "eval use", "auditor")
    assert base != review_id(".", "a.py", 3, "P001", "other title", "auditor")
    assert base != review_id(".", "a.py", 3, "P001", "eval use", "semgrep")


def test_report_response_carries_review_ids_disk_untouched(tmp_path):
    rp = _report(tmp_path)
    before = rp.read_bytes()
    c = TestClient(create_app(rp))
    rep = c.get("/api/report").json()
    f = rep["projects"][0]["findings"][0]
    assert f["review_id"] == review_id(".", "a.py", 3, "P001", "eval use", "auditor")
    assert rp.read_bytes() == before          # byte-for-byte identical


# --- store lifecycle --------------------------------------------------------

def test_missing_sidecar_means_empty_reviews(tmp_path):
    c = _client(tmp_path)
    r = c.get("/api/reviews").json()
    assert r == {"available": True, "error": None, "reviews": {}}


def test_save_persists_across_app_recreation_and_report_unchanged(tmp_path):
    rp = _report(tmp_path)
    before = rp.read_bytes()
    c1 = TestClient(create_app(rp))
    rid = _first_rid(c1)
    put = c1.put(f"/api/reviews/{rid}", json={"status": "false_positive", "note": "phoenix"})
    assert put.status_code == 200
    assert put.json()["updated_at"].endswith("+00:00")     # server UTC timestamp
    # fresh app over the same report => the review survived
    c2 = TestClient(create_app(rp))
    got = c2.get("/api/reviews").json()
    assert got["reviews"][rid]["status"] == "false_positive"
    assert got["reviews"][rid]["note"] == "phoenix"
    assert rp.read_bytes() == before
    sidecar = json.loads((tmp_path / "report.reviews.json").read_text(encoding="utf-8"))
    assert sidecar["schema_version"] == 1


def test_invalid_id_status_and_oversize_note_rejected(tmp_path):
    c = _client(tmp_path)
    rid = _first_rid(c)
    assert c.put("/api/reviews/" + "0" * 64,
                 json={"status": "confirmed"}).status_code == 404
    assert c.delete("/api/reviews/" + "0" * 64).status_code == 404
    assert c.put(f"/api/reviews/{rid}", json={"status": "fixed"}).status_code == 400
    assert c.put(f"/api/reviews/{rid}",
                 json={"status": "confirmed", "note": "x" * 2001}).status_code == 400
    assert c.put(f"/api/reviews/{rid}",
                 json={"status": "confirmed", "note": "x" * 2000}).status_code == 200


def test_delete_returns_to_unreviewed(tmp_path):
    c = _client(tmp_path)
    rid = _first_rid(c)
    c.put(f"/api/reviews/{rid}", json={"status": "confirmed"})
    assert rid in c.get("/api/reviews").json()["reviews"]
    assert c.delete(f"/api/reviews/{rid}").status_code == 200
    assert rid not in c.get("/api/reviews").json()["reviews"]
    assert c.delete(f"/api/reviews/{rid}").status_code == 200   # idempotent


def test_concurrent_puts_do_not_lose_each_other(tmp_path):
    c = _client(tmp_path)
    rep = c.get("/api/report").json()
    rid1 = rep["projects"][0]["findings"][0]["review_id"]
    rid2 = rep["projects"][1]["findings"][0]["review_id"]
    barrier = threading.Barrier(2)
    results = {}

    def put(rid, status):
        barrier.wait()
        results[rid] = c.put(f"/api/reviews/{rid}",
                             json={"status": status, "note": ""}).status_code

    threads = [threading.Thread(target=put, args=(rid1, "confirmed")),
               threading.Thread(target=put, args=(rid2, "false_positive"))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(5)
    assert results == {rid1: 200, rid2: 200}
    reviews = c.get("/api/reviews").json()["reviews"]
    assert reviews[rid1]["status"] == "confirmed"          # neither write lost
    assert reviews[rid2]["status"] == "false_positive"
    on_disk = json.loads((tmp_path / "report.reviews.json").read_text(encoding="utf-8"))
    assert set(on_disk["reviews"]) == {rid1, rid2}


def test_failed_replace_keeps_old_state_and_cleans_temp(tmp_path, monkeypatch):
    c = _client(tmp_path)
    rid = _first_rid(c)
    assert c.put(f"/api/reviews/{rid}", json={"status": "confirmed"}).status_code == 200
    sidecar = tmp_path / "report.reviews.json"
    before = sidecar.read_bytes()

    def failing_replace(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(webreviews, "_replace", failing_replace)
    r = c.put(f"/api/reviews/{rid}", json={"status": "false_positive"})
    assert r.status_code == 503
    assert "sidecar" in r.json()["error"] and "disk full" not in r.json()["error"]
    monkeypatch.undo()
    # old file intact, old memory state intact, no temp debris
    assert sidecar.read_bytes() == before
    assert c.get("/api/reviews").json()["reviews"][rid]["status"] == "confirmed"
    assert list(tmp_path.glob("*.tmp")) == []


def test_corrupt_sidecar_never_overwritten_but_report_still_served(tmp_path):
    rp = _report(tmp_path)
    sidecar = tmp_path / "report.reviews.json"
    sidecar.write_text("{ definitely not json", encoding="utf-8")
    before = sidecar.read_bytes()
    c = TestClient(create_app(rp))
    assert c.get("/api/report").status_code == 200          # explorer still works
    got = c.get("/api/reviews").json()
    assert got["available"] is False and "corrupt" in got["error"]
    rid = _first_rid(c)
    assert c.put(f"/api/reviews/{rid}", json={"status": "confirmed"}).status_code == 503
    assert c.delete(f"/api/reviews/{rid}").status_code == 503
    assert sidecar.read_bytes() == before                   # never clobbered/reset


def test_sidecar_contains_no_code_content(tmp_path):
    c = _client(tmp_path)
    rid = _first_rid(c)
    c.put(f"/api/reviews/{rid}", json={"status": "confirmed", "note": "checked by hand"})
    raw = (tmp_path / "report.reviews.json").read_text(encoding="utf-8")
    data = json.loads(raw)
    assert set(data) == {"schema_version", "reviews"}
    assert set(data["reviews"][rid]) == {"status", "note", "updated_at"}
    # nothing from the finding's code payload leaks into the sidecar
    for leaked in ("snippet", "detail", "source", "eval(x)", "dangerous eval"):
        assert leaked not in raw


def test_untrusted_host_rejected_trusted_still_works(tmp_path):
    c = _client(tmp_path)
    rid = _first_rid(c)
    bad = c.put(f"/api/reviews/{rid}", json={"status": "confirmed"},
                headers={"host": "evil.example.com"})
    assert bad.status_code == 400
    assert c.get("/api/report", headers={"host": "evil.example.com"}).status_code == 400
    # normal (testserver) host keeps working for reads and writes
    assert c.get("/api/report").status_code == 200
    assert c.put(f"/api/reviews/{rid}", json={"status": "confirmed"}).status_code == 200


def test_store_unit_orphaned_decision_goes_unreviewed(tmp_path):
    """Identity doc-contract: after a re-scan moves the finding (line 3 -> 5),
    the new finding has a new review_id and reads as unreviewed; the old record
    stays orphaned in the sidecar rather than being misattributed."""
    store = ReviewStore(tmp_path / "r.reviews.json")
    old = review_id(".", "a.py", 3, "P001", "eval use", "auditor")
    store.put(old, "confirmed", "")
    new = review_id(".", "a.py", 5, "P001", "eval use", "auditor")
    assert new != old
    assert new not in store.all() and old in store.all()


def test_custom_reviews_path_is_used(tmp_path):
    side = tmp_path / "elsewhere.reviews.json"
    c = TestClient(create_app(_report(tmp_path), reviews_path=side))
    rid = _first_rid(c)
    c.put(f"/api/reviews/{rid}", json={"status": "accepted_risk"})
    assert side.exists()
    assert not (tmp_path / "report.reviews.json").exists()


def test_get_does_not_mutate_state(tmp_path):
    """State changes only via PUT/DELETE with JSON — reads never write."""
    c = _client(tmp_path)
    c.get("/api/reviews")
    c.get("/api/report")
    assert not (tmp_path / "report.reviews.json").exists()


def test_review_id_no_delimiter_injection_collision():
    """The literal counter-case from the independent review of 063842a: with a
    separator join these two DIFFERENT findings collided. The canonical-JSON
    encoding must keep them distinct."""
    a = review_id("a\x1fb", "c.py", 1, "R001", "t", "auditor")
    b = review_id("a", "b\x1fc.py", 1, "R001", "t", "auditor")
    assert a != b
    # a few more structural-ambiguity shapes, all must stay distinct
    assert review_id("x", "y,z", 1, "R", "t", "e") != review_id("x,y", "z", 1, "R", "t", "e")
    assert review_id('a"', "b.py", 1, "R", "t", "e") != review_id("a", '"b.py', 1, "R", "t", "e")


def test_sidecar_future_schema_version_unavailable_never_clobbered(tmp_path):
    rp = _report(tmp_path)
    side = tmp_path / "report.reviews.json"
    side.write_text(json.dumps({"schema_version": 999, "reviews": {
        "0" * 64: {"status": "confirmed", "note": "", "updated_at": "x"}}}),
        encoding="utf-8")
    before = side.read_bytes()
    c = TestClient(create_app(rp))
    assert c.get("/api/report").status_code == 200
    got = c.get("/api/reviews").json()
    assert got["available"] is False
    assert "unsupported schema_version" in got["error"]
    rid = _first_rid(c)
    assert c.put(f"/api/reviews/{rid}", json={"status": "confirmed"}).status_code == 503
    assert side.read_bytes() == before


@pytest.mark.parametrize("entry, reason", [
    ({"status": "bogus", "note": "", "updated_at": "x"}, "invalid status"),
    ({"status": "confirmed", "note": 5, "updated_at": "x"}, "note"),
    ({"status": "confirmed", "note": "x" * 2001, "updated_at": "x"}, "note"),
    ({"status": "confirmed", "note": "", "updated_at": 7}, "updated_at"),
    ({"status": "confirmed", "note": "", "updated_at": "x",
      "source": "eval(x)"}, "exactly"),                       # extra code-ish field
    ({"status": "confirmed", "note": ""}, "exactly"),          # missing key
])
def test_sidecar_malformed_entry_makes_store_unavailable(tmp_path, entry, reason):
    """Strict load: ONE bad entry rejects the whole sidecar — nothing is
    dropped or silently repaired, and the file is never rewritten."""
    rp = _report(tmp_path)
    side = tmp_path / "report.reviews.json"
    side.write_text(json.dumps({"schema_version": 1,
                                "reviews": {"a" * 64: entry}}), encoding="utf-8")
    before = side.read_bytes()
    c = TestClient(create_app(rp))
    got = c.get("/api/reviews").json()
    assert got["available"] is False and reason in got["error"]
    assert c.get("/api/report").status_code == 200            # explorer unaffected
    assert side.read_bytes() == before


def test_sidecar_bad_rid_shape_rejected(tmp_path):
    rp = _report(tmp_path)
    side = tmp_path / "report.reviews.json"
    side.write_text(json.dumps({"schema_version": 1, "reviews": {
        "not-a-hash": {"status": "confirmed", "note": "", "updated_at": "x"}}}),
        encoding="utf-8")
    c = TestClient(create_app(rp))
    got = c.get("/api/reviews").json()
    assert got["available"] is False and "review id shape" in got["error"]


def test_mkstemp_failure_returns_503_and_keeps_state(tmp_path, monkeypatch):
    """Temp-file CREATION failure (e.g. PermissionError on the directory) must
    be a clean 503 — not an internal 500 — with prior file+memory intact."""
    c = _client(tmp_path)
    rid = _first_rid(c)
    assert c.put(f"/api/reviews/{rid}", json={"status": "confirmed"}).status_code == 200
    side = tmp_path / "report.reviews.json"
    before = side.read_bytes()

    def denied(*a, **kw):
        raise PermissionError("temp denied")

    monkeypatch.setattr(webreviews, "_mkstemp", denied)
    r = c.put(f"/api/reviews/{rid}", json={"status": "false_positive"})
    assert r.status_code == 503
    assert "sidecar" in r.json()["error"] and "temp denied" not in r.json()["error"]
    monkeypatch.undo()
    assert side.read_bytes() == before
    assert c.get("/api/reviews").json()["reviews"][rid]["status"] == "confirmed"
    assert list(tmp_path.glob("*.tmp")) == []


def test_fdopen_failure_returns_503_cleans_fd_and_temp(tmp_path, monkeypatch):
    c = _client(tmp_path)
    rid = _first_rid(c)
    assert c.put(f"/api/reviews/{rid}", json={"status": "confirmed"}).status_code == 200
    side = tmp_path / "report.reviews.json"
    before = side.read_bytes()

    def bad_fdopen(fd, *a, **kw):
        raise OSError("fdopen failed")

    monkeypatch.setattr(webreviews, "_fdopen", bad_fdopen)
    r = c.put(f"/api/reviews/{rid}", json={"status": "false_positive"})
    assert r.status_code == 503
    monkeypatch.undo()
    assert side.read_bytes() == before
    assert c.get("/api/reviews").json()["reviews"][rid]["status"] == "confirmed"
    assert list(tmp_path.glob("*.tmp")) == []   # temp cleaned even though fd was raw


def test_oversized_sidecar_unavailable_but_report_served(tmp_path, monkeypatch):
    rp = _report(tmp_path)
    side = tmp_path / "report.reviews.json"
    side.write_text(json.dumps({"schema_version": 1, "reviews": {}}) + " " * 200,
                    encoding="utf-8")
    before = side.read_bytes()
    monkeypatch.setattr(webreviews, "SIDECAR_MAX_BYTES", 64)   # shrink cap, not file
    c = TestClient(create_app(rp))
    assert c.get("/api/report").status_code == 200             # server did not fall over
    got = c.get("/api/reviews").json()
    assert got["available"] is False and "cap" in got["error"]
    rid = _first_rid(c)
    assert c.put(f"/api/reviews/{rid}", json={"status": "confirmed"}).status_code == 503
    assert side.read_bytes() == before


def test_note_with_lone_surrogate_saves_survives_restart_no_temp(tmp_path):
    """A lone surrogate in the note must save cleanly (ASCII-escaped in the
    sidecar), survive an app restart byte-identically, and leave no temp file.
    The raw request body carries the JSON escape \\ud800 — valid JSON text that
    parses to a lone-surrogate string (httpx json= cannot serialize it)."""
    rp = _report(tmp_path)
    c = TestClient(create_app(rp))
    rid = _first_rid(c)
    body = '{"status":"confirmed","note":"x' + chr(92) + 'ud800y"}'
    r = c.put(f"/api/reviews/{rid}", content=body.encode("ascii"),
              headers={"Content-Type": "application/json"})
    assert r.status_code == 200
    assert list(tmp_path.glob("*.tmp")) == []
    surrogate_note = "x" + chr(0xD800) + "y"
    assert r.json()["note"] == surrogate_note
    # restart: the sidecar loads and returns the identical string
    c2 = TestClient(create_app(rp))
    got = c2.get("/api/reviews").json()
    assert got["available"] is True
    assert got["reviews"][rid]["note"] == surrogate_note
    # the sidecar file itself is pure ASCII (escaped), hence always decodable
    raw = (tmp_path / "report.reviews.json").read_bytes()
    assert max(raw) < 0x80


def test_title_with_lone_surrogate_gets_deterministic_review_id(tmp_path):
    """A malformed finding title containing a lone surrogate must not crash
    create_app, and review_id stays deterministic and distinct."""
    bad_title = "t" + chr(0xD800)
    a = review_id(".", "a.py", 1, "P1", bad_title, "auditor")
    assert a == review_id(".", "a.py", 1, "P1", bad_title, "auditor")
    assert a != review_id(".", "a.py", 1, "P1", "t", "auditor")
    assert webreviews._RID_RE.match(a)
    rp = tmp_path / "report.json"
    rp.write_text(json.dumps({
        "summary": {"counts": {}},
        "projects": [{"language": "python", "root": ".",
                      "findings": [{"rule_id": "P1", "severity": "red",
                                    "title": bad_title, "file": "a.py", "line": 1,
                                    "engine": "auditor", "precision": "exact"}]}],
    }, ensure_ascii=True), encoding="utf-8")
    c = TestClient(create_app(rp))                     # must not raise
    f = c.get("/api/report").json()["projects"][0]["findings"][0]
    assert f["review_id"] == a
    assert c.put(f"/api/reviews/{a}", json={"status": "confirmed"}).status_code == 200


def test_sidecar_extra_top_level_field_rejected_never_clobbered(tmp_path):
    """Top-level strictness: exactly schema_version + reviews. Any extra field
    makes the store unavailable and the file is never touched."""
    rp = _report(tmp_path)
    side = tmp_path / "report.reviews.json"
    side.write_text(json.dumps({"schema_version": 1, "reviews": {},
                                "source": "x"}), encoding="utf-8")
    before = side.read_bytes()
    c = TestClient(create_app(rp))
    assert c.get("/api/report").status_code == 200
    got = c.get("/api/reviews").json()
    assert got["available"] is False
    assert "exactly schema_version and reviews" in got["error"]
    rid = _first_rid(c)
    assert c.put(f"/api/reviews/{rid}", json={"status": "confirmed"}).status_code == 503
    assert side.read_bytes() == before


@pytest.mark.parametrize("weird_line", ["3", 3.5, True, None])
def test_malformed_line_type_gets_no_review_id(tmp_path, weird_line):
    rp = tmp_path / "report.json"
    rp.write_text(json.dumps({
        "summary": {"counts": {}},
        "projects": [{"language": "python", "root": ".",
                      "findings": [{"rule_id": "P1", "severity": "red", "title": "t",
                                    "file": "a.py", "line": weird_line,
                                    "engine": "auditor"}]}],
    }), encoding="utf-8")
    c = TestClient(create_app(rp))
    f = c.get("/api/report").json()["projects"][0]["findings"][0]
    assert "review_id" not in f
