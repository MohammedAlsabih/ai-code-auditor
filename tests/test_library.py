"""W4-A1: Project Library — store, validation, jobs, security, API.
No network, no real git, no real scans (fake spawn only)."""
from __future__ import annotations

import json
import os
import subprocess

import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import auditor.web.library as lib_mod
from auditor.web.app import create_app
from auditor.web.library import (
    JOB_KEYS,
    MAX_REPORTS_PER_PROJECT,
    JobRunner,
    LibraryPaths,
    LibraryStore,
    LibraryStoreError,
    bad_git_url,
    git_clone_argv,
    job_env,
    job_timeout,
    new_id,
    resolve_local_registration,
    safe_location,
    scan_argv,
)
from auditor.web.library_app import CONTROL_HEADER, create_library_app

# ---- fixtures ----------------------------------------------------------------------

GOOD_REPORT = {
    "summary": {"counts": {}, "verdict": "pass"},
    "analysis_manifest": {"catalog": [], "execution": {"projects": []},
                          "policy": {}},
    "projects": [{"language": "python", "root": ".",
                  "findings": [{"rule_id": "P001", "severity": "yellow",
                                "level": "warning", "precision": "heuristic",
                                "language": "python", "file": "app.py",
                                "line": 1, "title": "t", "detail": "d",
                                "snippet": "s", "engine": "patterns"}]}],
}


def make_source(root: Path, marker: str = "m") -> Path:
    src = root / f"repo-{marker}"
    src.mkdir(parents=True, exist_ok=True)
    (src / "app.py").write_text(f"# {marker}\nx = 1\n", encoding="utf-8")
    (src / "requirements.txt").write_text("requests\n", encoding="utf-8")
    return src


class FakeProc:
    def __init__(self, rc: int = 0, block: bool = False) -> None:
        self.pid = 424242
        self.rc = rc
        self.block = block
        self.killed = False

    def wait(self, timeout: float | None = None) -> int:
        deadline = time.monotonic() + (timeout if timeout is not None
                                       else 3600)
        while self.block and not self.killed:
            if time.monotonic() > deadline:
                raise subprocess.TimeoutExpired(cmd="job", timeout=timeout)
            time.sleep(0.01)
        return self.rc

    def kill(self) -> None:
        self.killed = True


class FakeSpawn:
    """Simulates the clone/scan subprocess WITHOUT any process, shell, git,
    or network. Successful scans write a valid report.json to --output;
    successful clones create the destination directory."""

    def __init__(self, rc: int = 0, block: bool = False,
                 write_report: bool = True,
                 report: dict | None = None) -> None:
        self.rc = rc
        self.block = block
        self.write_report = write_report
        self.report = report or GOOD_REPORT
        self.calls: list[list[str]] = []
        self.procs: list[FakeProc] = []

    def __call__(self, argv, cwd, stdout_path, stderr_path, env):
        self.calls.append(list(argv))
        Path(stdout_path).write_bytes(b"")
        Path(stderr_path).write_bytes(b"")
        if not self.block:
            if "clone" in argv:
                dest = Path(argv[-1])
                dest.mkdir(parents=True, exist_ok=True)
                (dest / "app.py").write_text("x = 1\n", encoding="utf-8")
            elif self.write_report and "--output" in argv:
                out = Path(argv[argv.index("--output") + 1])
                out.mkdir(parents=True, exist_ok=True)
                (out / "report.json").write_text(
                    json.dumps(self.report), encoding="utf-8")
        proc = FakeProc(rc=self.rc, block=self.block)
        self.procs.append(proc)
        return proc


@pytest.fixture(autouse=True)
def _no_real_kill(monkeypatch):
    """kill_process_tree must NEVER run taskkill against a fake pid."""
    monkeypatch.setattr(lib_mod, "kill_process_tree",
                        lambda proc: proc.kill())


def make_client(tmp_path: Path, spawn=None, port: int = 8765):
    library = tmp_path / "library"
    allowed = tmp_path / "allowed"
    allowed.mkdir(exist_ok=True)
    app = create_library_app(library, [allowed], port,
                             spawn=spawn or FakeSpawn())
    client = TestClient(app)
    token = client.get("/api/library/session").json()["token"]
    return client, token, app, allowed


def H(token: str) -> dict[str, str]:
    return {CONTROL_HEADER: token}


def add_local(client, token, allowed: Path, marker: str = "a") -> str:
    src = make_source(allowed, marker)
    r = client.post("/api/library/projects",
                    json={"kind": "local", "path": str(src)},
                    headers=H(token))
    assert r.status_code == 201, r.text
    return r.json()["project"]["project_id"]


def run_scan(client, token, app, pid: str, **body) -> str:
    r = client.post(f"/api/library/projects/{pid}/scans",
                    json=body or {}, headers=H(token))
    assert r.status_code == 202, r.text
    jid = r.json()["job_id"]
    app.library.runner.wait(jid)
    job = client.get(f"/api/library/scans/{jid}").json()["job"]
    return job


# ---- git url validation ---------------------------------------------------------------

def test_git_url_rejections_are_safe_and_complete():
    cases = {
        "https://user:pass@github.com/a/b": "credentials",
        "https://user@github.com/a/b": "credentials",
        "http://github.com/a/b": "https",
        "file:///c/secrets": "https",
        "ssh://git@github.com/a/b": "https",
        "git://github.com/a/b": "https",
        "git@github.com:a/b.git": "scp-like",
        "github.com:a/b.git": "scp-like",
        "https://github.com/a/b?token=x": "query",
        "https://github.com/a/b#frag": "query",
        "https://github.com": "repository path",
        "https:///a/b": "hostname",
        "-https://github.com/a/b": "dash",
        "https://github.com/a b": "whitespace",
        "https://github.com/a\\b": "whitespace",
    }
    for url, hint in cases.items():
        reason = bad_git_url(url)
        assert reason is not None, url
        assert url not in reason        # never echo the input
        assert hint.split()[0] in reason, (url, reason)
    assert bad_git_url("https://github.com/octocat/hello.git") is None
    assert bad_git_url(None) is not None
    assert bad_git_url("x" * 501) is not None


def test_clone_argv_is_hardened_and_shell_free():
    argv = git_clone_argv("https://github.com/a/b.git", Path("dest"))
    assert argv[0] == "git" and "clone" in argv
    assert "--no-recurse-submodules" in argv and "--depth" in argv
    assert "--" in argv                          # dash-injection barrier
    assert argv.index("--") < argv.index("https://github.com/a/b.git")
    joined = " ".join(argv)
    assert "core.hooksPath=" in joined and "filter.lfs.smudge=" in joined
    assert "protocol.allow=never" in joined
    env = job_env()
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_LFS_SKIP_SMUDGE"] == "1"
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull


def test_scan_argv_offline_by_default():
    a = scan_argv(Path("src"), Path("out"), online=False, semgrep=False)
    assert "--offline" in a and "--no-semgrep" in a and "-c" in a
    b = scan_argv(Path("src"), Path("out"), online=True, semgrep=True)
    assert "--offline" not in b and "--no-semgrep" not in b


def test_job_timeout_is_clamped():
    assert job_timeout({}) == 1800.0
    assert job_timeout({"AUDITOR_LIBRARY_JOB_TIMEOUT": "5"}) == 60.0
    assert job_timeout({"AUDITOR_LIBRARY_JOB_TIMEOUT": "999999"}) == 7200.0
    assert job_timeout({"AUDITOR_LIBRARY_JOB_TIMEOUT": "junk"}) == 1800.0


# ---- local registration validation ---------------------------------------------------

def test_local_registration_rejects_escapes(tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    inside = allowed / "proj"
    inside.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    for bad in ("rel/path", str(outside), "\\\\server\\share",
                "//server/share", str(allowed / ".." / "outside"),
                str(tmp_path / "nul" / "x"), "", None, "a\x00b"):
        resolved, reason = resolve_local_registration(bad, [allowed])
        assert resolved is None, bad
        assert isinstance(reason, str) and reason
        if isinstance(bad, str) and bad:
            assert bad not in reason     # rejection never echoes the path
    ok, _ = resolve_local_registration(str(inside), [allowed])
    assert ok == inside.resolve()


def test_local_registration_rejects_symlink_escape(tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "secret"
    outside.mkdir()
    link = allowed / "innocent"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this host")
    resolved, reason = resolve_local_registration(str(link), [allowed])
    assert resolved is None and "allowed root" in reason


def test_safe_location_never_leaks_full_paths():
    loc = safe_location("local", r"C:\Users\someone\code\deep\proj")
    assert "C:" not in loc and "Users" not in loc and "someone" not in loc
    assert loc.startswith("…/")
    assert safe_location("git", "https://github.com/a/hello.git") \
        == "github.com/hello"


# ---- store ---------------------------------------------------------------------------

def _project_row(pid: str | None = None, kind: str = "local") -> dict:
    pid = pid or new_id()
    if kind == "git":
        return {"project_id": pid, "name": "n", "kind": "git",
                "location": "github.com/n", "created_at": "2026-01-01",
                "git_url": "https://github.com/a/n.git", "local_path": "",
                "managed": True}
    return {"project_id": pid, "name": "n", "kind": "local",
            "location": "…/x/y", "created_at": "2026-01-01",
            "git_url": "", "local_path": "C:/somewhere/x/y",
            "managed": False}


def test_store_roundtrip_and_allowlist(tmp_path):
    store = LibraryStore(tmp_path / "library.json")
    row = _project_row()
    store.put_project(row)
    assert store.project(row["project_id"]) == row
    with pytest.raises(LibraryStoreError):
        store.put_project({**row, "extra": 1})
    with pytest.raises(LibraryStoreError):
        store.put_project({**row, "kind": "svn"})
    with pytest.raises(LibraryStoreError):
        store.put_report({"report_id": new_id(), "project_id": new_id(),
                          "created_at": "x", "verdict": "pass",
                          "findings": 0, "duration_ms": 0})  # unknown project


def test_store_load_rejects_malformed_and_marks_interrupted(tmp_path):
    p = tmp_path / "library.json"
    jid, pid = new_id(), new_id()
    job = dict.fromkeys(JOB_KEYS, "")
    job.update({"job_id": jid, "project_id": pid, "kind": "scan",
                "state": "running", "online": False, "semgrep": False,
                "created_at": "2026-01-01"})
    data = {"schema_version": "library-1", "projects": {}, "reports": {},
            "jobs": {jid: job}}
    p.write_text(json.dumps(data), encoding="utf-8")
    store = LibraryStore(p)
    assert store.available
    assert store.job(jid)["state"] == "interrupted"
    # restart never resumes: the persisted state is interrupted too
    again = LibraryStore(p)
    assert again.job(jid)["state"] == "interrupted"

    p.write_text(json.dumps({**data, "surprise": {}}), encoding="utf-8")
    assert not LibraryStore(p).available
    poisoned = json.loads(json.dumps(data))
    poisoned["jobs"][jid]["prompt"] = "x"
    p.write_text(json.dumps(poisoned), encoding="utf-8")
    assert not LibraryStore(p).available


def test_store_write_failure_rolls_back(tmp_path, monkeypatch):
    store = LibraryStore(tmp_path / "library.json")
    row = _project_row()
    store.put_project(row)

    def boom(src, dst):
        raise OSError("disk detached")
    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(LibraryStoreError):
        store.put_project(_project_row())
    monkeypatch.undo()
    assert len(store.projects()) == 1            # memory unchanged
    assert not list(tmp_path.glob("*.tmp"))      # no litter
    fresh = LibraryStore(tmp_path / "library.json")
    assert len(fresh.projects()) == 1            # disk unchanged


# ---- confined delete -------------------------------------------------------------------

def test_confined_delete_guards(tmp_path):
    paths = LibraryPaths(tmp_path / "library")
    inside = paths.root / "reports" / "aaaa"
    inside.mkdir(parents=True)
    (inside / "f.txt").write_text("x", encoding="utf-8")
    outside = tmp_path / "victim"
    outside.mkdir()
    assert paths.confined_delete(outside) is False
    assert outside.exists()
    assert paths.confined_delete(paths.root) is False
    link = paths.root / "reports" / "linked"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        link = None
    if link is not None:
        assert paths.confined_delete(link) is False   # symlink refused
        assert outside.exists()
    assert paths.confined_delete(inside) is True
    assert not inside.exists()


# ---- job runner -------------------------------------------------------------------------

def _runner(tmp_path, spawn, allowed=None) -> tuple[JobRunner, LibraryStore,
                                                    LibraryPaths, dict]:
    paths = LibraryPaths(tmp_path / "library")
    paths.root.mkdir(parents=True, exist_ok=True)
    store = LibraryStore(paths.store_path())
    src = make_source(allowed or tmp_path)
    project = {**_project_row(), "local_path": str(src)}
    store.put_project(project)
    runner = JobRunner(store, paths, spawn=spawn)
    return runner, store, paths, project


def test_scan_job_completes_and_promotes_atomically(tmp_path):
    spawn = FakeSpawn()
    runner, store, paths, project = _runner(tmp_path, spawn)
    jid = runner.start(project, "scan")
    runner.wait(jid)
    job = store.job(jid)
    assert job["state"] == "completed" and job["report_id"]
    rid = job["report_id"]
    assert paths.report_json(rid).is_file()
    assert store.report(rid)["findings"] == 1
    assert store.report(rid)["verdict"] == "pass"
    assert not (paths.root / "tmp" / jid).exists()   # tmp cleaned
    argv = spawn.calls[0]
    assert "--offline" in argv                        # offline by default


def test_failed_scan_keeps_last_good_report(tmp_path):
    ok_spawn = FakeSpawn()
    runner, store, paths, project = _runner(tmp_path, ok_spawn)
    jid = runner.start(project, "scan")
    runner.wait(jid)
    good_rid = store.job(jid)["report_id"]
    good_bytes = paths.report_json(good_rid).read_bytes()

    bad = FakeSpawn(rc=1, write_report=False)
    runner2 = JobRunner(store, paths, spawn=bad)
    jid2 = runner2.start(project, "scan")
    runner2.wait(jid2)
    job2 = store.job(jid2)
    assert job2["state"] == "failed"
    assert "valid report" in job2["error"]
    assert paths.report_json(good_rid).read_bytes() == good_bytes
    assert store.reports_for(project["project_id"])[0]["report_id"] \
        == good_rid
    assert not (paths.root / "tmp" / jid2).exists()   # no partial litter
    # the slot is free again
    jid3 = JobRunner(store, paths, spawn=FakeSpawn()) \
        .start(project, "scan")
    assert jid3


def test_invalid_report_json_is_a_failure_not_a_promotion(tmp_path):
    spawn = FakeSpawn(report={"not": "a report"})
    runner, store, paths, project = _runner(tmp_path, spawn)
    jid = runner.start(project, "scan")
    runner.wait(jid)
    assert store.job(jid)["state"] == "failed"
    assert store.reports_for(project["project_id"]) == []
    assert not (paths.root / "reports").exists() \
        or not any((paths.root / "reports").iterdir())


def test_cancel_stops_the_job_safely(tmp_path):
    spawn = FakeSpawn(block=True)
    runner, store, paths, project = _runner(tmp_path, spawn)
    jid = runner.start(project, "scan")
    deadline = time.monotonic() + 5
    while not spawn.procs and time.monotonic() < deadline:
        time.sleep(0.01)
    assert runner.cancel(jid) is True
    runner.wait(jid)
    job = store.job(jid)
    assert job["state"] == "canceled"
    assert spawn.procs[0].killed
    assert store.reports_for(project["project_id"]) == []
    assert runner.active_job_id() is None


def test_timeout_kills_and_fails(tmp_path):
    spawn = FakeSpawn(block=True)
    paths = LibraryPaths(tmp_path / "library")
    paths.root.mkdir(parents=True, exist_ok=True)
    store = LibraryStore(paths.store_path())
    src = make_source(tmp_path)
    project = {**_project_row(), "local_path": str(src)}
    store.put_project(project)
    runner = JobRunner(store, paths, spawn=spawn,
                       env={"AUDITOR_LIBRARY_JOB_TIMEOUT": "60"})

    real_wait = FakeProc.wait

    def quick_wait(self, timeout=None):
        return real_wait(self, timeout=0.05 if timeout else None)
    FakeProc.wait = quick_wait
    try:
        jid = runner.start(project, "scan")
        runner.wait(jid, timeout=10)
    finally:
        FakeProc.wait = real_wait
    job = store.job(jid)
    assert job["state"] == "failed" and "timed out" in job["error"]
    assert spawn.procs[0].killed


def test_one_job_at_a_time(tmp_path):
    spawn = FakeSpawn(block=True)
    runner, store, paths, project = _runner(tmp_path, spawn)
    jid = runner.start(project, "scan")
    with pytest.raises(LibraryStoreError):
        runner.start(project, "scan")
    runner.cancel(jid)
    runner.wait(jid)


def test_retention_prunes_oldest_beyond_policy(tmp_path):
    spawn = FakeSpawn()
    runner, store, paths, project = _runner(tmp_path, spawn)
    rids = []
    for _ in range(MAX_REPORTS_PER_PROJECT + 2):
        jid = runner.start(project, "scan")
        runner.wait(jid)
        rids.append(store.job(jid)["report_id"])
        time.sleep(0.01)
    kept = store.reports_for(project["project_id"])
    assert len(kept) == MAX_REPORTS_PER_PROJECT
    pruned = set(rids) - {r["report_id"] for r in kept}
    assert len(pruned) == 2
    for rid in pruned:
        assert not paths.report_dir(rid).exists()
    for row in kept:
        assert paths.report_json(row["report_id"]).is_file()


def test_default_spawn_uses_no_shell(tmp_path):
    """The REAL spawner runs an argv list (no shell) and captures output to
    the given files — proven with this interpreter, no git or network."""
    import sys as _sys
    out, err = tmp_path / "o.log", tmp_path / "e.log"
    proc = lib_mod._default_spawn(
        [_sys.executable, "-c", "print('argv-ok')"],
        tmp_path, out, err, dict(os.environ))
    assert proc.wait(timeout=60) == 0
    assert b"argv-ok" in out.read_bytes()


# ---- web API: security ------------------------------------------------------------------

def test_mutating_endpoints_require_token_with_zero_side_effects(tmp_path):
    spawn = FakeSpawn()
    client, token, app, allowed = make_client(tmp_path, spawn)
    src = make_source(allowed)
    attempts = [
        ("POST", "/api/library/projects",
         {"kind": "local", "path": str(src)}),
        ("POST", f"/api/library/projects/{new_id()}/scans", {}),
        ("POST", f"/api/library/scans/{new_id()}/cancel", None),
        ("DELETE", f"/api/library/projects/{new_id()}?confirm=true", None),
        ("DELETE", f"/api/library/reports/{new_id()}?confirm=true", None),
        ("POST", f"/api/library/projects/{new_id()}/delete-source",
         {"confirm": True}),
    ]
    for method, url, body in attempts:
        r = client.request(method, url, json=body)          # no token
        assert r.status_code == 403, (method, url)
        r = client.request(method, url, json=body,
                           headers={CONTROL_HEADER: "wrong"})
        assert r.status_code == 403
    assert spawn.calls == []                                 # zero processes
    assert client.get("/api/library/projects").json()["projects"] == []
    assert not (tmp_path / "library" / "projects").exists()  # zero filesystem


def test_cross_origin_is_refused_even_with_a_valid_token(tmp_path):
    spawn = FakeSpawn()
    client, token, app, allowed = make_client(tmp_path, spawn)
    src = make_source(allowed)
    r = client.post("/api/library/projects",
                    json={"kind": "local", "path": str(src)},
                    headers={**H(token), "Origin": "http://evil.example"})
    assert r.status_code == 403
    assert "cross-origin" in r.json()["error"]
    assert spawn.calls == []
    # the server's own origin is accepted
    r = client.post("/api/library/projects",
                    json={"kind": "local", "path": str(src)},
                    headers={**H(token), "Origin": "http://127.0.0.1:8765"})
    assert r.status_code == 201


def test_forwarded_mutations_need_the_token_too(tmp_path):
    client, token, app, allowed = make_client(tmp_path)
    pid = add_local(client, token, allowed)
    job = run_scan(client, token, app, pid)
    rid = job["report_id"]
    report = client.get(f"/api/library/reports/{rid}/report").json()
    rid_review = report["projects"][0]["findings"][0]["review_id"]
    r = client.put(f"/api/library/reports/{rid}/reviews/{rid_review}",
                   json={"status": "confirmed", "note": ""})
    assert r.status_code == 403                       # no token
    r = client.put(f"/api/library/reports/{rid}/reviews/{rid_review}",
                   json={"status": "confirmed", "note": ""},
                   headers=H(token))
    assert r.status_code == 200


def test_no_absolute_paths_in_any_library_payload(tmp_path):
    client, token, app, allowed = make_client(tmp_path)
    pid = add_local(client, token, allowed)
    run_scan(client, token, app, pid)
    blob = json.dumps(client.get("/api/library/projects").json()) \
        + json.dumps(client.get(
            f"/api/library/projects/{pid}/reports").json()) \
        + json.dumps(client.get("/api/library/capabilities").json())
    assert str(tmp_path) not in blob
    assert str(tmp_path).replace("\\", "\\\\") not in blob
    assert ":\\\\" not in blob and ":\\" not in blob


# ---- web API: lifecycle -------------------------------------------------------------------

def test_add_scan_open_report_flow(tmp_path):
    client, token, app, allowed = make_client(tmp_path)
    pid = add_local(client, token, allowed)
    rows = client.get("/api/library/projects").json()["projects"]
    assert rows[0]["kind"] == "local" and rows[0]["source_available"]
    job = run_scan(client, token, app, pid)
    assert job["state"] == "completed"
    rid = job["report_id"]
    # forwarded single-report endpoints, no server restart, no global state
    health = client.get(f"/api/library/reports/{rid}/health").json()
    assert health["report_loaded"] and health["source_available"]
    rep = client.get(f"/api/library/reports/{rid}/report").json()
    assert rep["projects"][0]["findings"]
    cov = client.get(f"/api/library/reports/{rid}/coverage")
    assert cov.status_code == 200
    src = client.get(f"/api/library/reports/{rid}/source",
                     params={"path": "app.py", "line": 1})
    assert src.status_code == 200
    assert "x = 1" in json.dumps(src.json())


def test_git_project_add_clone_and_delete_source(tmp_path):
    spawn = FakeSpawn()
    client, token, app, allowed = make_client(tmp_path, spawn)
    r = client.post("/api/library/projects",
                    json={"kind": "git",
                          "url": "https://github.com/a/hello.git"},
                    headers=H(token))
    assert r.status_code == 201, r.text
    pid = r.json()["project"]["project_id"]
    jid = r.json()["job_id"]
    app.library.runner.wait(jid)
    assert client.get(
        f"/api/library/scans/{jid}").json()["job"]["state"] == "completed"
    clone_argv = spawn.calls[0]
    assert clone_argv[0] == "git" and "--" in clone_argv
    row = client.get("/api/library/projects").json()["projects"][0]
    assert row["source_available"] and row["location"] == "github.com/hello"
    # delete-source: git-managed only, confirmed only
    r = client.post(f"/api/library/projects/{pid}/delete-source",
                    json={"confirm": False}, headers=H(token))
    assert r.status_code == 409
    r = client.post(f"/api/library/projects/{pid}/delete-source",
                    json={"confirm": True}, headers=H(token))
    assert r.status_code == 200 and r.json()["source_deleted"]
    row = client.get("/api/library/projects").json()["projects"][0]
    assert not row["source_available"]


def test_git_url_rejected_at_the_api_surface(tmp_path):
    spawn = FakeSpawn()
    client, token, app, allowed = make_client(tmp_path, spawn)
    for url in ("git@github.com:a/b.git", "https://u:p@github.com/a/b",
                "file:///etc", "https://github.com/a/b?x=1"):
        r = client.post("/api/library/projects",
                        json={"kind": "git", "url": url}, headers=H(token))
        assert r.status_code == 400, url
        assert url not in r.text
    assert spawn.calls == []


def test_local_folder_rejected_at_the_api_surface(tmp_path):
    client, token, app, allowed = make_client(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    for path in (str(outside), "..\\..\\x", "\\\\srv\\share", "C:\\Windows"):
        r = client.post("/api/library/projects",
                        json={"kind": "local", "path": path},
                        headers=H(token))
        assert r.status_code == 400, path
        assert path not in r.text                # no echo
    r = client.post("/api/library/projects",
                    json={"kind": "local", "path": str(outside),
                          "extra": "field"}, headers=H(token))
    assert r.status_code == 422                  # extra=forbid


def test_delete_report_is_confined_and_confirmed(tmp_path):
    client, token, app, allowed = make_client(tmp_path)
    pid = add_local(client, token, allowed)
    rid1 = run_scan(client, token, app, pid)["report_id"]
    rid2 = run_scan(client, token, app, pid)["report_id"]
    lib = app.library
    src_dir = Path(lib.store.project(pid)["local_path"])
    r = client.delete(f"/api/library/reports/{rid1}", headers=H(token))
    assert r.status_code == 409                              # no confirm
    r = client.delete(f"/api/library/reports/{rid1}?confirm=true",
                      headers=H(token))
    assert r.status_code == 200
    assert not lib.paths.report_dir(rid1).exists()
    assert lib.paths.report_json(rid2).is_file()             # other kept
    assert src_dir.is_dir()                                  # source kept
    r = client.delete(f"/api/library/reports/{rid1}?confirm=true",
                      headers=H(token))
    assert r.status_code == 404
    # a path shape can never reach the delete route's id (hex-only ids)
    r = client.delete("/api/library/reports/..%2F..%2Fsecrets?confirm=true",
                      headers=H(token))
    assert r.status_code in (403, 404, 405)   # refused, nothing resolved
    assert lib.store.report(rid2) is not None


def test_delete_report_in_use_is_refused(tmp_path):
    client, token, app, allowed = make_client(tmp_path)
    pid = add_local(client, token, allowed)
    rid = run_scan(client, token, app, pid)["report_id"]
    lib = app.library
    assert lib.acquire_context(rid) is not None    # a request is in flight
    r = client.delete(f"/api/library/reports/{rid}?confirm=true",
                      headers=H(token))
    assert r.status_code == 409 and "open" in r.json()["error"]
    lib.release_context(rid)
    r = client.delete(f"/api/library/reports/{rid}?confirm=true",
                      headers=H(token))
    assert r.status_code == 200


def test_remove_registration_keeps_local_source(tmp_path):
    client, token, app, allowed = make_client(tmp_path)
    pid = add_local(client, token, allowed)
    rid = run_scan(client, token, app, pid)["report_id"]
    src_dir = Path(app.library.store.project(pid)["local_path"])
    r = client.delete(f"/api/library/projects/{pid}", headers=H(token))
    assert r.status_code == 409                    # confirmation required
    r = client.delete(f"/api/library/projects/{pid}?confirm=true",
                      headers=H(token))
    assert r.status_code == 200
    assert r.json()["source_deleted"] is False
    assert src_dir.is_dir()                        # source NEVER deleted here
    assert not app.library.paths.report_dir(rid).exists()
    assert client.get("/api/library/projects").json()["projects"] == []


def test_two_projects_do_not_mix_reports_reviews_or_sources(tmp_path):
    client, token, app, allowed = make_client(tmp_path)
    report_b = json.loads(json.dumps(GOOD_REPORT))
    report_b["projects"][0]["findings"][0]["file"] = "beta.py"
    pid_a = add_local(client, token, allowed, marker="alpha")
    (Path(app.library.store.project(pid_a)["local_path"])
     / "app.py").write_text("# alpha\nx = 1\n", encoding="utf-8")
    rid_a = run_scan(client, token, app, pid_a)["report_id"]

    src_b = make_source(allowed, "beta")
    (src_b / "beta.py").write_text("# beta\ny = 2\n", encoding="utf-8")
    app.library.runner._spawn = FakeSpawn(report=report_b)
    r = client.post("/api/library/projects",
                    json={"kind": "local", "path": str(src_b)},
                    headers=H(token))
    pid_b = r.json()["project"]["project_id"]
    rid_b = run_scan(client, token, app, pid_b)["report_id"]

    # review written on A only
    rep_a = client.get(f"/api/library/reports/{rid_a}/report").json()
    rva = rep_a["projects"][0]["findings"][0]["review_id"]
    client.put(f"/api/library/reports/{rid_a}/reviews/{rva}",
               json={"status": "confirmed", "note": "A only"},
               headers=H(token))
    reviews_a = client.get(
        f"/api/library/reports/{rid_a}/reviews").json()["reviews"]
    reviews_b = client.get(
        f"/api/library/reports/{rid_b}/reviews").json()["reviews"]
    assert rva in reviews_a and reviews_b == {}
    # sidecars live in EACH report's own directory
    lib = app.library
    assert (lib.paths.report_dir(rid_a) / "report.reviews.json").is_file()
    assert not (lib.paths.report_dir(rid_b)
                / "report.reviews.json").exists()
    # sources resolve against each project's own folder
    src_view_a = client.get(f"/api/library/reports/{rid_a}/source",
                            params={"path": "app.py", "line": 1}).json()
    assert "alpha" in json.dumps(src_view_a)
    src_view_b = client.get(f"/api/library/reports/{rid_b}/source",
                            params={"path": "beta.py", "line": 1}).json()
    assert "beta" in json.dumps(src_view_b)


def test_scan_conflicts_and_unknown_ids(tmp_path):
    spawn = FakeSpawn(block=True)
    client, token, app, allowed = make_client(tmp_path, spawn)
    pid = add_local(client, token, allowed)
    r = client.post(f"/api/library/projects/{pid}/scans", json={},
                    headers=H(token))
    jid = r.json()["job_id"]
    r2 = client.post(f"/api/library/projects/{pid}/scans", json={},
                     headers=H(token))
    assert r2.status_code == 409                       # one job at a time
    r3 = client.post(f"/api/library/scans/{jid}/cancel", headers=H(token))
    assert r3.status_code == 200
    app.library.runner.wait(jid)
    assert client.get(f"/api/library/scans/{jid}") \
        .json()["job"]["state"] == "canceled"
    assert client.get(f"/api/library/scans/{new_id()}").status_code == 404
    assert client.post(f"/api/library/projects/{new_id()}/scans", json={},
                       headers=H(token)).status_code == 404


def test_online_and_semgrep_are_explicit_flags(tmp_path):
    spawn = FakeSpawn()
    client, token, app, allowed = make_client(tmp_path, spawn)
    pid = add_local(client, token, allowed)
    run_scan(client, token, app, pid, online=True, semgrep=True)
    argv = spawn.calls[-1]
    assert "--offline" not in argv and "--no-semgrep" not in argv
    run_scan(client, token, app, pid)
    argv = spawn.calls[-1]
    assert "--offline" in argv and "--no-semgrep" in argv
    r = client.post(f"/api/library/projects/{pid}/scans",
                    json={"online": True, "prompt": "x"}, headers=H(token))
    assert r.status_code == 422                        # extra=forbid


def test_capabilities_and_session_shape(tmp_path):
    client, token, app, allowed = make_client(tmp_path)
    caps = client.get("/api/library/capabilities").json()
    assert caps["mode"] == "library"
    assert isinstance(caps["git_available"], bool)
    assert isinstance(caps["semgrep_available"], bool)
    assert caps["registry_default"] == "offline"
    assert caps["reports_kept_per_project"] == MAX_REPORTS_PER_PROJECT
    ses = client.get("/api/library/session").json()
    assert ses["mode"] == "library" and len(ses["token"]) >= 32


def test_classic_serve_still_works_without_library_metadata(tmp_path):
    """`auditor serve <report>` mode: create_app on a plain report, no
    library.json anywhere, no control token required for reviews."""
    rp = tmp_path / "report.json"
    rp.write_text(json.dumps(GOOD_REPORT), encoding="utf-8")
    client = TestClient(create_app(rp))
    assert client.get("/api/health").json()["report_loaded"]
    rep = client.get("/api/report").json()
    rid = rep["projects"][0]["findings"][0]["review_id"]
    r = client.put(f"/api/reviews/{rid}",
                   json={"status": "confirmed", "note": ""})
    assert r.status_code == 200
    assert not (tmp_path / "library.json").exists()


def test_forwarding_rejects_non_hex_report_ids(tmp_path):
    client, token, app, allowed = make_client(tmp_path)
    r = client.get("/api/library/reports/not-a-real-id/report")
    assert r.status_code == 404
    r = client.get(f"/api/library/reports/{new_id()}/report")
    assert r.status_code == 404                        # unknown but well-formed


def test_store_unavailable_is_surfaced_not_crashed(tmp_path):
    library = tmp_path / "library"
    library.mkdir()
    (library / "library.json").write_text("{corrupt", encoding="utf-8")
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    app = create_library_app(library, [allowed], 8765, spawn=FakeSpawn())
    client = TestClient(app)
    caps = client.get("/api/library/capabilities").json()
    assert caps["store_available"] is False and caps["store_error"]
    token = client.get("/api/library/session").json()["token"]
    src = make_source(allowed)
    r = client.post("/api/library/projects",
                    json={"kind": "local", "path": str(src)},
                    headers=H(token))
    assert r.status_code == 503
