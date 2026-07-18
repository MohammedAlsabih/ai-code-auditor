import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import auditor.web.app as webapp
from auditor.web.app import create_app


def _report_for(files: list[tuple[str, int]]) -> dict:
    """A minimal valid report whose findings reference the given (path, line)
    pairs — the /api/source allowlist is derived from exactly this."""
    return {
        "summary": {"counts": {"red": 0, "yellow": len(files), "blue": 0}},
        "projects": [{
            "language": "python", "root": ".",
            "findings": [{"rule_id": "P001", "severity": "yellow", "title": "t",
                          "file": f, "line": ln, "language": "python",
                          "precision": "exact"} for f, ln in files],
        }],
    }


def _mk_app(tmp_path: Path, files: list[tuple[str, int]], *, repo=True):
    report_file = tmp_path / "report.json"
    report_file.write_text(json.dumps(_report_for(files)), encoding="utf-8")
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir(exist_ok=True)
    return create_app(report_file, repo_root=repo_dir if repo else None), repo_dir


def _write(repo: Path, rel: str, text: str) -> Path:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


TWENTY = "\n".join(f"line {i}" for i in range(1, 21)) + "\n"


def test_source_window_around_line(tmp_path):
    app, repo = _mk_app(tmp_path, [("pkg/mod.py", 10)])
    _write(repo, "pkg/mod.py", TWENTY)
    r = TestClient(app).get("/api/source",
                            params={"path": "pkg/mod.py", "line": 10, "context": 3})
    assert r.status_code == 200
    b = r.json()
    assert b["path"] == "pkg/mod.py"
    assert b["requested_line"] == 10
    assert b["start_line"] == 7 and b["end_line"] == 13
    assert b["total_lines"] == 20
    assert [x["number"] for x in b["lines"]] == list(range(7, 14))
    assert b["lines"][3] == {"number": 10, "text": "line 10"}


def test_window_clamps_at_file_start_and_end(tmp_path):
    app, repo = _mk_app(tmp_path, [("a.py", 1), ("b.py", 20)])
    _write(repo, "a.py", TWENTY)
    _write(repo, "b.py", TWENTY)
    c = TestClient(app)
    first = c.get("/api/source", params={"path": "a.py", "line": 1, "context": 5}).json()
    assert first["start_line"] == 1 and first["end_line"] == 6
    assert first["lines"][0] == {"number": 1, "text": "line 1"}
    last = c.get("/api/source", params={"path": "b.py", "line": 20, "context": 5}).json()
    assert last["start_line"] == 15 and last["end_line"] == 20
    assert last["lines"][-1] == {"number": 20, "text": "line 20"}
    # a line beyond EOF clamps to the last line instead of erroring
    over = c.get("/api/source", params={"path": "b.py", "line": 999}).json()
    assert over["requested_line"] == 20


def test_context_is_clamped_to_max(tmp_path):
    app, repo = _mk_app(tmp_path, [("a.py", 100)])
    _write(repo, "a.py", "\n".join(f"l{i}" for i in range(1, 201)))
    b = TestClient(app).get("/api/source",
                            params={"path": "a.py", "line": 100, "context": 9999}).json()
    assert b["start_line"] == 100 - webapp.SOURCE_CONTEXT_MAX
    assert b["end_line"] == 100 + webapp.SOURCE_CONTEXT_MAX
    assert len(b["lines"]) == 2 * webapp.SOURCE_CONTEXT_MAX + 1


ATTACKS = [
    "../secret.txt",                 # parent traversal
    "pkg/../../secret.txt",          # embedded traversal
    "/etc/passwd",                   # absolute posix
    "//server/share/x.py",           # UNC (forward)
    "\\\\server\\share\\x.py",       # UNC (backslash)
    "C:/Windows/win.ini",            # drive path
    "c:\\Windows\\win.ini",          # drive path (backslash)
    "NUL",                           # reserved device
    "pkg/nul.py",                    # reserved device as a segment stem
    "pkg//x.py",                     # empty segment
    "pkg/./x.py",                    # dot segment
    "pkg/mod.py\x00.txt",            # NUL byte
]


@pytest.mark.parametrize("attack", ATTACKS)
def test_attack_paths_rejected_without_leaking_machine_paths(tmp_path, attack):
    app, repo = _mk_app(tmp_path, [("pkg/mod.py", 1)])
    _write(repo, "pkg/mod.py", TWENTY)
    r = TestClient(app).get("/api/source", params={"path": attack, "line": 1})
    assert r.status_code == 400, (attack, r.status_code)
    body = r.text
    # rejection must not echo any machine path (repo root, drives, backslashes)
    assert str(tmp_path) not in body
    assert str(tmp_path.resolve()) not in body
    assert ":\\" not in body


def test_file_inside_repo_but_not_in_findings_is_403(tmp_path):
    app, repo = _mk_app(tmp_path, [("pkg/mod.py", 1)])
    _write(repo, "pkg/mod.py", TWENTY)
    _write(repo, "pkg/other.py", "secret = 1\n")   # real file, NOT in findings
    r = TestClient(app).get("/api/source", params={"path": "pkg/other.py", "line": 1})
    assert r.status_code == 403
    assert "findings" in r.json()["error"]
    assert str(tmp_path) not in r.text


def test_symlink_escaping_repo_is_rejected_real(tmp_path):
    """Real symlink whose target is OUTSIDE the repo => 403. Skips only where
    symlink creation itself is not permitted (non-admin Windows)."""
    app, repo = _mk_app(tmp_path, [("link.py", 1)])
    outside = tmp_path / "outside.py"
    outside.write_text("top_secret = 1\n", encoding="utf-8")
    try:
        os.symlink(outside, repo / "link.py")
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted on this host")
    r = TestClient(app).get("/api/source", params={"path": "link.py", "line": 1})
    assert r.status_code == 403
    assert "escapes" in r.json()["error"]
    assert "top_secret" not in r.text
    assert str(tmp_path) not in r.text


def test_symlink_escape_rejected_deterministic_unit(tmp_path, monkeypatch):
    """Deterministic escape coverage that needs no symlink privilege: the
    confinement resolver is forced to report an outside target for one path —
    exactly what a symlink escape produces — and the endpoint must 403."""
    app, repo = _mk_app(tmp_path, [("link.py", 1)])
    _write(repo, "link.py", "print('stand-in for a symlink')\n")
    outside = (tmp_path / "outside.py")
    outside.write_text("top_secret = 1\n", encoding="utf-8")

    real = webapp.resolve_confined

    def fake(root, rel):
        if rel == "link.py":
            # what resolve() yields for a link targeting outside the repo:
            # a real path NOT under root => resolver must return None
            return real(root.parent, "outside.py") and None
        return real(root, rel)

    monkeypatch.setattr(webapp, "resolve_confined", fake)
    r = TestClient(app).get("/api/source", params={"path": "link.py", "line": 1})
    assert r.status_code == 403
    assert "escapes" in r.json()["error"]
    assert "top_secret" not in r.text


def test_resolve_confined_unit(tmp_path):
    """The resolver itself: inside stays allowed, outside (as a resolve target)
    is None — covers the symlink-escape decision without needing a symlink."""
    root = tmp_path / "repo"
    (root / "pkg").mkdir(parents=True)
    inside = root / "pkg" / "x.py"
    inside.write_text("ok\n", encoding="utf-8")
    assert webapp.resolve_confined(root, "pkg/x.py") == inside.resolve()
    # a path that resolves outside the root (tmp_path/outside.py) is rejected
    (tmp_path / "outside.py").write_text("no\n", encoding="utf-8")
    assert webapp.resolve_confined(root, "../outside.py") is None


def test_missing_file_is_404_with_relative_path_only(tmp_path):
    app, repo = _mk_app(tmp_path, [("gone.py", 3)])
    r = TestClient(app).get("/api/source", params={"path": "gone.py", "line": 3})
    assert r.status_code == 404
    assert "gone.py" in r.json()["error"]
    assert str(tmp_path) not in r.text and ":\\" not in r.text


def test_binary_file_rejected(tmp_path):
    app, repo = _mk_app(tmp_path, [("blob.bin", 1)])
    (repo / "blob.bin").write_bytes(b"MZ\x00\x01\x02binary")
    r = TestClient(app).get("/api/source", params={"path": "blob.bin", "line": 1})
    assert r.status_code == 415
    assert r.json()["error"] == "binary file"


def test_oversize_file_rejected(tmp_path, monkeypatch):
    app, repo = _mk_app(tmp_path, [("big.py", 1)])
    _write(repo, "big.py", "x = 1\n" * 40)
    monkeypatch.setattr(webapp, "SOURCE_MAX_BYTES", 64)   # shrink the cap, not the file
    r = TestClient(app).get("/api/source", params={"path": "big.py", "line": 1})
    assert r.status_code == 413
    assert "cap" in r.json()["error"]


def test_directory_is_not_a_regular_file(tmp_path):
    app, repo = _mk_app(tmp_path, [("pkg", 1)])
    (repo / "pkg").mkdir()
    r = TestClient(app).get("/api/source", params={"path": "pkg", "line": 1})
    assert r.status_code == 400
    assert "regular file" in r.json()["error"]


def test_no_repo_mode_explorer_still_works(tmp_path):
    app, _ = _mk_app(tmp_path, [("pkg/mod.py", 1)], repo=False)
    c = TestClient(app)
    assert c.get("/api/report").status_code == 200
    h = c.get("/api/health").json()
    assert h["status"] == "ok" and h["source_available"] is False
    r = c.get("/api/source", params={"path": "pkg/mod.py", "line": 1})
    assert r.status_code == 409
    assert "--repo" in r.json()["error"]
    assert str(tmp_path) not in r.text


def test_source_max_bytes_matches_scanner_cap():
    from auditor.core.walk import MAX_FILE_BYTES
    assert webapp.SOURCE_MAX_BYTES == MAX_FILE_BYTES == 1_500_000


def test_nested_project_root_uses_repo_relative_path(tmp_path):
    """Monorepo case (the Tabi layout): finding files are PROJECT-relative
    (root='frontend', file='src/page.tsx'); the allowlist and the request must
    both use the REPO-relative join, and the bare project-relative path must
    NOT be accepted."""
    report_file = tmp_path / "report.json"
    report_file.write_text(json.dumps({
        "summary": {"counts": {"red": 0, "yellow": 1, "blue": 0}},
        "projects": [{
            "language": "typescript", "root": "frontend",
            "findings": [{"rule_id": "R006", "severity": "yellow", "title": "t",
                          "file": "src/page.tsx", "line": 2,
                          "language": "typescript", "precision": "exact"}],
        }],
    }), encoding="utf-8")
    repo = tmp_path / "repo"
    _write(repo, "frontend/src/page.tsx", "a\nb\nc\n")
    app = create_app(report_file, repo_root=repo)
    c = TestClient(app)
    ok = c.get("/api/source", params={"path": "frontend/src/page.tsx", "line": 2})
    assert ok.status_code == 200
    assert ok.json()["lines"][1] == {"number": 2, "text": "b"}
    bare = c.get("/api/source", params={"path": "src/page.tsx", "line": 2})
    assert bare.status_code == 403


def test_repo_relative_helper():
    assert webapp.repo_relative(".", "a.py") == "a.py"
    assert webapp.repo_relative("", "a.py") == "a.py"
    assert webapp.repo_relative("backend/Api", "Data/Seeder.cs") == "backend/Api/Data/Seeder.cs"


def test_oversize_read_is_bounded_even_when_stat_lies(tmp_path, monkeypatch):
    """TOCTOU: the file grows between stat and open (simulated by a stat that
    reports 2 bytes for a 1000-byte file). The bounded read — not stat — must
    catch it: with a 64-byte cap the response is 413, and the handler never
    reads more than cap+1 bytes."""
    app, repo = _mk_app(tmp_path, [("grow.py", 1)])
    _write(repo, "grow.py", "A" * 1000)
    target = (repo / "grow.py").resolve()
    monkeypatch.setattr(webapp, "SOURCE_MAX_BYTES", 64)

    real_stat = Path.stat
    lied = os.stat(target)
    fake = os.stat_result(lied[:6] + (2,) + tuple(lied)[7:10])

    def lying_stat(self, **kw):
        if self == target:
            return fake
        return real_stat(self, **kw)

    monkeypatch.setattr(Path, "stat", lying_stat)
    r = TestClient(app).get("/api/source", params={"path": "grow.py", "line": 1})
    assert r.status_code == 413
    assert "cap" in r.json()["error"]


def test_bounded_read_never_slurps_oversize_content(tmp_path, monkeypatch):
    """The handler must issue a BOUNDED read (cap+1), never an unbounded one.
    The early stat reject is bypassed (stat lies small, as in a TOCTOU grow)
    so the request actually reaches the open+read path."""
    app, repo = _mk_app(tmp_path, [("big.py", 1)])
    target = _write(repo, "big.py", "B" * 1000).resolve()
    monkeypatch.setattr(webapp, "SOURCE_MAX_BYTES", 64)
    real_stat = Path.stat
    lied = os.stat(target)
    fake = os.stat_result(lied[:6] + (2,) + tuple(lied)[7:10])
    monkeypatch.setattr(Path, "stat",
                        lambda self, **kw: fake if self == target else real_stat(self, **kw))
    seen: list[int] = []
    real_open = Path.open

    class _CountingFile:
        def __init__(self, fh):
            self._fh = fh

        def read(self, size=-1):
            seen.append(size)
            return self._fh.read(size)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            self._fh.close()
            return False

    def opening(self, *a, **kw):
        fh = real_open(self, *a, **kw)
        return _CountingFile(fh) if self == target else fh

    monkeypatch.setattr(Path, "open", opening)
    r = TestClient(app).get("/api/source", params={"path": "big.py", "line": 1})
    assert r.status_code == 413
    assert seen and all(s == 65 for s in seen), seen   # cap+1, never -1/unbounded


def test_nul_after_8k_prefix_is_still_binary(tmp_path):
    """A NUL byte anywhere in the served content marks the file binary — not
    just in the first 8192 bytes."""
    app, repo = _mk_app(tmp_path, [("late.bin", 1)])
    (repo / "late.bin").write_bytes(b"B" * 8500 + b"\x00" + b"C" * 100)
    r = TestClient(app).get("/api/source", params={"path": "late.bin", "line": 1})
    assert r.status_code == 415
    assert r.json()["error"] == "binary file"


def test_health_never_leaks_repo_root(tmp_path):
    app, repo = _mk_app(tmp_path, [("a.py", 1)])
    _write(repo, "a.py", "x = 1\n")
    r = TestClient(app).get("/api/health")
    assert r.status_code == 200
    assert r.json()["source_available"] is True
    assert "repo_root" not in r.json()
    assert str(tmp_path) not in r.text
    assert str(repo) not in r.text
    assert ":\\" not in r.text and ":/" not in r.text.replace("http://", "")


@pytest.mark.parametrize("weird", [{"a": 1}, ["x.py"], 5, True, 0, None, ""])
def test_non_string_finding_file_does_not_crash_startup(tmp_path, weird):
    """A malformed report whose finding.file is a dict/list/int/bool must not
    crash create_app; the junk entry is skipped (never stringified) and the
    good finding stays servable."""
    report_file = tmp_path / "report.json"
    report_file.write_text(json.dumps({
        "summary": {"counts": {}},
        "projects": [{
            "language": "python", "root": ".",
            "findings": [
                {"rule_id": "P1", "severity": "yellow", "title": "t",
                 "file": weird, "line": 1, "language": "python", "precision": "exact"},
                {"rule_id": "P1", "severity": "yellow", "title": "t",
                 "file": "good.py", "line": 1, "language": "python", "precision": "exact"},
            ],
        }],
    }), encoding="utf-8")
    repo = tmp_path / "repo"
    _write(repo, "good.py", "ok = 1\n")
    app = create_app(report_file, repo_root=repo)         # must not raise
    c = TestClient(app)
    assert c.get("/api/source", params={"path": "good.py", "line": 1}).status_code == 200
    # the weird entry never became an allowlisted path
    if isinstance(weird, (dict, list)):
        assert c.get("/api/source", params={"path": str(weird), "line": 1}).status_code in (400, 403)


def test_non_string_project_root_is_skipped_not_stringified(tmp_path):
    report_file = tmp_path / "report.json"
    report_file.write_text(json.dumps({
        "summary": {"counts": {}},
        "projects": [
            {"language": "python", "root": {"odd": 1},
             "findings": [{"rule_id": "P1", "severity": "yellow", "title": "t",
                           "file": "a.py", "line": 1, "language": "python",
                           "precision": "exact"}]},
            {"language": "python", "root": ".",
             "findings": [{"rule_id": "P1", "severity": "yellow", "title": "t",
                           "file": "b.py", "line": 1, "language": "python",
                           "precision": "exact"}]},
        ],
    }), encoding="utf-8")
    repo = tmp_path / "repo"
    _write(repo, "b.py", "ok = 1\n")
    app = create_app(report_file, repo_root=repo)         # must not raise
    c = TestClient(app)
    assert c.get("/api/source", params={"path": "b.py", "line": 1}).status_code == 200
    # nothing derived from the dict root exists in the allowlist
    assert c.get("/api/source", params={"path": "a.py", "line": 1}).status_code == 403
