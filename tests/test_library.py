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
                 report: dict | None = None,
                 block_scans_only: bool = False) -> None:
        self.rc = rc
        self.block = block
        # clones complete, scans block — lets a git project finish cloning
        # and then hold an active scan job
        self.block_scans_only = block_scans_only
        self.write_report = write_report
        self.report = report or GOOD_REPORT
        self.calls: list[list[str]] = []
        self.procs: list[FakeProc] = []

    def __call__(self, argv, cwd, stdout_path, stderr_path, env):
        self.calls.append(list(argv))
        Path(stdout_path).write_bytes(b"")
        Path(stderr_path).write_bytes(b"")
        is_clone = "clone" in argv
        block = self.block or (self.block_scans_only and not is_clone)
        if not block:
            if is_clone:
                dest = Path(argv[-1])
                dest.mkdir(parents=True, exist_ok=True)
                (dest / "app.py").write_text("x = 1\n", encoding="utf-8")
            elif self.write_report and "--output" in argv:
                out = Path(argv[argv.index("--output") + 1])
                out.mkdir(parents=True, exist_ok=True)
                (out / "report.json").write_text(
                    json.dumps(self.report), encoding="utf-8")
        proc = FakeProc(rc=self.rc, block=block)
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
    ctx, why = lib.acquire_context(rid)            # a request is in flight
    assert ctx is not None and why == ""
    r = client.delete(f"/api/library/reports/{rid}?confirm=true",
                      headers=H(token))
    assert r.status_code == 409 and "open" in r.json()["error"]
    assert lib.store.report(rid) is not None       # metadata intact
    assert lib.paths.report_json(rid).is_file()    # files intact
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


# ---- W4-A3 closing regressions -------------------------------------------------------

def test_w4a3_git_hosts_are_allowlisted():
    """Case 1: IP literals, localhost, custom ports, and non-allowlisted
    hosts are refused BEFORE any network/subprocess, without echoing."""
    rejected = ("https://127.0.0.1/private/repo.git",
                "https://localhost/x/y.git",
                "https://10.0.0.5/a/b.git",
                "https://169.254.169.254/a/b.git",
                "https://github.com:8443/a/b.git",
                "https://git.internal.corp/a/b.git")
    for url in rejected:
        reason = bad_git_url(url)
        assert reason is not None, url
        assert url not in reason
        assert "supported" in reason or "ports" in reason, (url, reason)
    for url in ("https://github.com/octocat/hello.git",
                "https://gitlab.com/group/project.git",
                "https://bitbucket.org/team/repo.git",
                "https://GITHUB.com/case/insensitive"):
        assert bad_git_url(url) is None, url


def test_w4a3_git_host_rejected_at_api_before_subprocess(tmp_path):
    spawn = FakeSpawn()
    client, token, app, allowed = make_client(tmp_path, spawn)
    r = client.post("/api/library/projects",
                    json={"kind": "git",
                          "url": "https://127.0.0.1/private/repo.git"},
                    headers=H(token))
    assert r.status_code == 400
    assert "127.0.0.1" not in r.json()["error"]
    assert spawn.calls == []                       # zero subprocess/network
    assert client.get("/api/library/projects").json()["projects"] == []


def test_w4a3_clone_argv_disables_redirects():
    argv = git_clone_argv("https://github.com/a/b.git", Path("d"))
    assert "http.followRedirects=false" in " ".join(argv)


def test_w4a3_confined_delete_never_lies(tmp_path, monkeypatch):
    """Case 2: success MEANS the target is gone; a no-op or failing rmtree
    returns False; an already-absent target is True (retry-safe)."""
    paths = LibraryPaths(tmp_path / "library")
    target = paths.root / "reports" / "aaaa"
    target.mkdir(parents=True)
    (target / "f").write_text("x", encoding="utf-8")

    monkeypatch.setattr(lib_mod.shutil, "rmtree", lambda *a, **k: None)
    assert paths.confined_delete(target) is False          # no-op rmtree
    assert target.exists()

    def boom(*a, **k):
        raise OSError("locked")
    monkeypatch.setattr(lib_mod.shutil, "rmtree", boom)
    assert paths.confined_delete(target) is False          # raising rmtree
    assert target.exists()
    monkeypatch.undo()
    assert paths.confined_delete(target) is True
    assert paths.confined_delete(target) is True           # absent -> gone


def test_w4a3_delete_report_failure_keeps_metadata(tmp_path, monkeypatch):
    client, token, app, allowed = make_client(tmp_path)
    pid = add_local(client, token, allowed)
    rid = run_scan(client, token, app, pid)["report_id"]
    monkeypatch.setattr(lib_mod.shutil, "rmtree", lambda *a, **k: None)
    r = client.delete(f"/api/library/reports/{rid}?confirm=true",
                      headers=H(token))
    assert r.status_code == 503
    assert str(tmp_path) not in r.text                     # safe message
    assert app.library.store.report(rid) is not None       # metadata KEPT
    assert app.library.paths.report_json(rid).is_file()    # files KEPT
    monkeypatch.undo()
    r = client.delete(f"/api/library/reports/{rid}?confirm=true",
                      headers=H(token))                    # retry succeeds
    assert r.status_code == 200
    assert app.library.store.report(rid) is None
    assert not app.library.paths.report_dir(rid).exists()


def test_w4a3_delete_report_store_failure_is_retryable(tmp_path, monkeypatch):
    client, token, app, allowed = make_client(tmp_path)
    pid = add_local(client, token, allowed)
    rid = run_scan(client, token, app, pid)["report_id"]

    def store_boom(_rid):
        raise LibraryStoreError("store detached")
    monkeypatch.setattr(app.library.store, "remove_report", store_boom)
    r = client.delete(f"/api/library/reports/{rid}?confirm=true",
                      headers=H(token))
    assert r.status_code == 503 and "metadata" in r.json()["error"]
    assert not app.library.paths.report_dir(rid).exists()  # files ARE gone
    assert app.library.store.report(rid) is not None       # row remains
    monkeypatch.undo()
    r = client.delete(f"/api/library/reports/{rid}?confirm=true",
                      headers=H(token))                    # absent == gone
    assert r.status_code == 200
    assert app.library.store.report(rid) is None


def test_w4a3_partial_project_removal_keeps_all_metadata(tmp_path,
                                                         monkeypatch):
    client, token, app, allowed = make_client(tmp_path)
    pid = add_local(client, token, allowed)
    rid1 = run_scan(client, token, app, pid)["report_id"]
    rid2 = run_scan(client, token, app, pid)["report_id"]
    src_dir = Path(app.library.store.project(pid)["local_path"])
    blocked = app.library.paths.report_dir(rid2).resolve()
    real_rmtree = lib_mod.shutil.rmtree

    def selective(path, *a, **k):
        if Path(path) == blocked:
            raise OSError("locked")
        return real_rmtree(path, *a, **k)
    monkeypatch.setattr(lib_mod.shutil, "rmtree", selective)
    r = client.delete(f"/api/library/projects/{pid}?confirm=true",
                      headers=H(token))
    assert r.status_code == 503
    assert app.library.store.project(pid) is not None      # registration kept
    assert app.library.store.report(rid1) is not None      # ALL rows kept
    assert app.library.store.report(rid2) is not None
    assert src_dir.is_dir()                                # source untouched
    monkeypatch.undo()
    r = client.delete(f"/api/library/projects/{pid}?confirm=true",
                      headers=H(token))                    # retry finishes
    assert r.status_code == 200
    assert src_dir.is_dir()                                # source still kept


def test_w4a3_retention_never_deletes_an_open_report(tmp_path, monkeypatch):
    # deterministic, strictly increasing created_at stamps: the real
    # _now_iso has 1-second granularity, which makes "oldest" ambiguous
    # inside a same-second burst of scans (test-only concern)
    counter = {"n": 0}

    def ticking_now():
        counter["n"] += 1
        return f"2026-07-24T00:00:{counter['n']:02d}Z"
    monkeypatch.setattr(lib_mod, "_now_iso", ticking_now)
    client, token, app, allowed = make_client(tmp_path)
    pid = add_local(client, token, allowed)
    first = run_scan(client, token, app, pid)["report_id"]
    ctx, why = app.library.acquire_context(first)          # OPEN context
    assert ctx is not None and why == ""
    for _ in range(MAX_REPORTS_PER_PROJECT + 1):
        run_scan(client, token, app, pid)
        time.sleep(0.01)
    rows = app.library.store.reports_for(pid)
    kept = {r["report_id"] for r in rows}
    assert first in kept                     # kept ABOVE the cap, not deleted
    assert app.library.paths.report_json(first).is_file()
    assert len(rows) == MAX_REPORTS_PER_PROJECT + 1
    # refs -> 0 but the context stays CACHED: still counted as loaded, so
    # retention keeps it above the cap (W4-A closing contract)
    app.library.release_context(first)
    run_scan(client, token, app, pid)
    kept = {r["report_id"] for r in app.library.store.reports_for(pid)}
    assert first in kept
    # only after the context is evicted may the next prune reclaim it
    app.library.evict_context(first)
    run_scan(client, token, app, pid)
    kept = {r["report_id"] for r in app.library.store.reports_for(pid)}
    assert first not in kept
    assert len(kept) == MAX_REPORTS_PER_PROJECT


def test_w4a3_store_load_is_a_bounded_read(tmp_path, monkeypatch):
    """Case 3: one bounded read of cap+1; read_bytes() never used; an
    oversized file is refused before parse; a lying stat cannot bypass."""
    import pathlib as _pl
    p = tmp_path / "library.json"
    p.write_bytes(b'{"x": "' + b"A" * (3 * 1024 * 1024) + b'"}')

    def no_read_bytes(self):
        raise AssertionError("read_bytes() used for the store load")
    monkeypatch.setattr(_pl.Path, "read_bytes", no_read_bytes)
    read_sizes = []
    orig_open = _pl.Path.open

    def spy_open(self, *a, **k):
        fh = orig_open(self, *a, **k)
        if self.name == "library.json" and a and a[0] == "rb":
            orig_read = fh.read

            def bounded_read(n=-1):
                read_sizes.append(n)
                return orig_read(n)
            fh.read = bounded_read
        return fh
    monkeypatch.setattr(_pl.Path, "open", spy_open)
    store = LibraryStore(p)
    monkeypatch.undo()
    assert store.available is False and "cap" in store.error
    assert str(tmp_path) not in store.error
    # stat pre-rejected the 3MB file: zero reads is legal; any read that DID
    # happen must have been bounded (never -1 / unbounded)
    assert all(n != -1 and n <= lib_mod.STORE_MAX_BYTES + 1
               for n in read_sizes)

    # lying stat: claims a tiny size; the bounded read still catches it
    class FakeStat:
        st_size = 10

        def __getattr__(self, name):
            return 0
    real_stat = _pl.Path.stat

    def lying_stat(self, *a, **k):
        if self.name == "library.json":
            return FakeStat()
        return real_stat(self, *a, **k)
    monkeypatch.setattr(_pl.Path, "stat", lying_stat)
    store2 = LibraryStore(p)
    monkeypatch.undo()
    assert store2.available is False and "cap" in store2.error


def test_w4a3_git_registration_is_atomic(tmp_path, monkeypatch):
    """Case 4: a busy runner or a store failure leaves ZERO project rows,
    directories, and subprocesses; success lands project+job together."""
    spawn = FakeSpawn(block=True)
    client, token, app, allowed = make_client(tmp_path, spawn)
    pid = add_local(client, token, allowed)
    r = client.post(f"/api/library/projects/{pid}/scans", json={},
                    headers=H(token))
    jid = r.json()["job_id"]                     # runner busy (blocked)
    deadline = time.monotonic() + 5              # wait for the scan spawn
    while len(spawn.calls) < 1 and time.monotonic() < deadline:
        time.sleep(0.01)
    clone_calls_before = len(spawn.calls)
    r = client.post("/api/library/projects",
                    json={"kind": "git",
                          "url": "https://github.com/a/hello.git"},
                    headers=H(token))
    assert r.status_code == 409
    rows = client.get("/api/library/projects").json()["projects"]
    assert [p for p in rows if p["kind"] == "git"] == []    # NO orphan
    assert len(spawn.calls) == clone_calls_before           # no subprocess
    assert not (tmp_path / "library" / "projects").exists()
    client.post(f"/api/library/scans/{jid}/cancel", headers=H(token))
    app.library.runner.wait(jid)

    # store failure inside the transaction -> nothing persisted
    def txn_boom(project_row, job_row):
        raise LibraryStoreError("store detached")
    monkeypatch.setattr(app.library.store, "put_project_and_job", txn_boom)
    r = client.post("/api/library/projects",
                    json={"kind": "git",
                          "url": "https://github.com/a/hello.git"},
                    headers=H(token))
    assert r.status_code == 409
    monkeypatch.undo()
    rows = client.get("/api/library/projects").json()["projects"]
    assert [p for p in rows if p["kind"] == "git"] == []
    assert app.library.runner.active_job_id() is None       # slot free

    # normal registration still lands project + clone job TOGETHER
    app.library.runner._spawn = FakeSpawn()
    r = client.post("/api/library/projects",
                    json={"kind": "git",
                          "url": "https://github.com/a/hello.git"},
                    headers=H(token))
    assert r.status_code == 201
    jid2 = r.json()["job_id"]
    pid2 = r.json()["project"]["project_id"]
    assert app.library.store.project(pid2) is not None
    assert app.library.store.job(jid2)["project_id"] == pid2
    app.library.runner.wait(jid2)


# ---- W4-A closing: deletion-lease race regressions (real concurrency) ----------------

def test_w4a4_delete_lease_blocks_concurrent_acquire(tmp_path, monkeypatch):
    """The reproduced race, gated by Events (no timing assumptions):
    DELETE takes the lease, a concurrent request tries to acquire the
    context MID-DELETE and must be refused with 'deleting'; the deletion
    then completes normally."""
    import threading
    client, token, app, allowed = make_client(tmp_path)
    pid = add_local(client, token, allowed)
    rid = run_scan(client, token, app, pid)["report_id"]
    lib = app.library

    inside_delete = threading.Event()
    acquired = threading.Event()
    result = {}
    real_confined = LibraryPaths.confined_delete

    def gated(self, target, _real=real_confined):
        if target.name == rid:
            inside_delete.set()          # lease already taken by the route
            assert acquired.wait(10)
        return _real(self, target)
    monkeypatch.setattr(LibraryPaths, "confined_delete", gated)

    def deleter():
        result["delete"] = client.delete(
            f"/api/library/reports/{rid}?confirm=true", headers=H(token))

    def requester():
        assert inside_delete.wait(10)
        result["ctx"] = lib.acquire_context(rid)
        acquired.set()

    t1 = threading.Thread(target=deleter)
    t2 = threading.Thread(target=requester)
    t1.start()
    t2.start()
    t1.join(15)
    t2.join(15)
    monkeypatch.undo()

    ctx, why = result["ctx"]
    assert ctx is None and why == "deleting"       # race window CLOSED
    assert result["delete"].status_code == 200
    assert lib.store.report(rid) is None
    assert not lib.paths.report_dir(rid).exists()
    with lib._ctx_lock:
        assert rid not in lib._deleting            # lease released


def test_w4a4_dispatcher_answers_409_while_deleting(tmp_path, monkeypatch):
    """An HTTP request for a report under deletion gets a stable, safe 409
    'report is being deleted' — never a misleading 404."""
    import threading
    client, token, app, allowed = make_client(tmp_path)
    pid = add_local(client, token, allowed)
    rid = run_scan(client, token, app, pid)["report_id"]

    inside_delete = threading.Event()
    proceed = threading.Event()
    result = {}
    real_confined = LibraryPaths.confined_delete

    def gated(self, target, _real=real_confined):
        if target.name == rid:
            inside_delete.set()
            assert proceed.wait(10)
        return _real(self, target)
    monkeypatch.setattr(LibraryPaths, "confined_delete", gated)

    def deleter():
        result["delete"] = client.delete(
            f"/api/library/reports/{rid}?confirm=true", headers=H(token))

    t1 = threading.Thread(target=deleter)
    t1.start()
    assert inside_delete.wait(10)
    r = client.get(f"/api/library/reports/{rid}/report")
    proceed.set()
    t1.join(15)
    monkeypatch.undo()
    assert r.status_code == 409
    assert r.json()["error"] == "report is being deleted"
    assert str(tmp_path) not in r.text
    assert result["delete"].status_code == 200


def test_w4a4_lease_released_on_rmtree_and_store_failures(tmp_path,
                                                          monkeypatch):
    client, token, app, allowed = make_client(tmp_path)
    pid = add_local(client, token, allowed)
    rid = run_scan(client, token, app, pid)["report_id"]
    lib = app.library

    # rmtree failure -> 503, lease is FREE again (acquire + retry work)
    monkeypatch.setattr(lib_mod.shutil, "rmtree", lambda *a, **k: None)
    r = client.delete(f"/api/library/reports/{rid}?confirm=true",
                      headers=H(token))
    assert r.status_code == 503
    monkeypatch.undo()
    with lib._ctx_lock:
        assert rid not in lib._deleting
    ctx, why = lib.acquire_context(rid)
    assert ctx is not None                          # acquirable again
    lib.release_context(rid)
    lib.evict_context(rid)

    # store failure after files gone -> 503, lease free, retry finishes
    def store_boom(_rid):
        raise LibraryStoreError("store detached")
    monkeypatch.setattr(lib.store, "remove_report", store_boom)
    r = client.delete(f"/api/library/reports/{rid}?confirm=true",
                      headers=H(token))
    assert r.status_code == 503
    monkeypatch.undo()
    with lib._ctx_lock:
        assert rid not in lib._deleting
    r = client.delete(f"/api/library/reports/{rid}?confirm=true",
                      headers=H(token))
    assert r.status_code == 200


def test_w4a4_project_removal_reserves_all_or_none(tmp_path):
    client, token, app, allowed = make_client(tmp_path)
    pid = add_local(client, token, allowed)
    rid1 = run_scan(client, token, app, pid)["report_id"]
    rid2 = run_scan(client, token, app, pid)["report_id"]
    lib = app.library
    ctx, _ = lib.acquire_context(rid2)              # rid2 is open
    assert ctx is not None
    r = client.delete(f"/api/library/projects/{pid}?confirm=true",
                      headers=H(token))
    assert r.status_code == 409
    with lib._ctx_lock:
        assert rid1 not in lib._deleting            # NO partial lease
        assert rid2 not in lib._deleting
    got, why = lib.acquire_context(rid1)            # rid1 fully usable
    assert got is not None and why == ""
    lib.release_context(rid1)
    assert lib.store.report(rid1) is not None
    assert lib.paths.report_json(rid1).is_file()
    lib.release_context(rid2)
    lib.evict_context(rid1)
    lib.evict_context(rid2)
    r = client.delete(f"/api/library/projects/{pid}?confirm=true",
                      headers=H(token))
    assert r.status_code == 200


def test_w4a4_stress_no_delete_under_live_refs(tmp_path, monkeypatch):
    """Short concurrency hammer: acquire/release threads race a deleting
    thread. Invariant, checked AT DELETE TIME inside confined_delete: the
    report never has a cached context when its files are removed."""
    import threading
    client, token, app, allowed = make_client(tmp_path)
    pid = add_local(client, token, allowed)
    rid = run_scan(client, token, app, pid)["report_id"]
    lib = app.library

    violations = []
    real_confined = LibraryPaths.confined_delete

    def checking(self, target, _real=real_confined):
        if target.name == rid:
            with lib._ctx_lock:
                if rid in lib._contexts:
                    violations.append("context alive at delete time")
        return _real(self, target)
    monkeypatch.setattr(LibraryPaths, "confined_delete", checking)

    stop = threading.Event()
    outcomes = []

    def hammer():
        while not stop.is_set():
            ctx, why = lib.acquire_context(rid)
            if ctx is not None:
                lib.release_context(rid)
            elif why == "unknown":
                return                              # deleted -> done

    def deleter():
        for _ in range(200):
            r = client.delete(f"/api/library/reports/{rid}?confirm=true",
                              headers=H(token))
            outcomes.append(r.status_code)
            if r.status_code in (200, 404):
                break
        stop.set()

    threads = [threading.Thread(target=hammer) for _ in range(4)]
    dt = threading.Thread(target=deleter)
    for t in threads:
        t.start()
    dt.start()
    dt.join(30)
    stop.set()
    for t in threads:
        t.join(10)
    monkeypatch.undo()
    assert violations == []
    assert 200 in outcomes                          # the delete DID happen
    assert lib.store.report(rid) is None


# ---- W4-A closing: project-operation lease (start_scan / remove / delete-source) -----

def _blocking_client(tmp_path):
    """A client whose scans block until killed, with the project source
    registered. Returns (client, token, app, allowed, pid, spawn)."""
    spawn = FakeSpawn(block=True)
    client, token, app, allowed = make_client(tmp_path, spawn)
    pid = add_local(client, token, allowed)
    return client, token, app, allowed, pid, spawn


def test_w4a5_remove_reserves_then_scan_is_refused(tmp_path, monkeypatch):
    """Event-gated: remove_project takes the project lease first; a
    concurrent scan is refused 409 with ZERO subprocess; then remove
    completes 200 and the runner is not left active."""
    import threading
    client, token, app, allowed, pid, spawn = _blocking_client(tmp_path)
    inside = threading.Event()
    scan_done = threading.Event()
    result = {}
    real_remove = app.library.store.remove_project

    def gated(_pid):
        inside.set()
        assert scan_done.wait(10)
        return real_remove(_pid)
    monkeypatch.setattr(app.library.store, "remove_project", gated)

    def remover():
        result["remove"] = client.delete(
            f"/api/library/projects/{pid}?confirm=true", headers=H(token))

    def scanner():
        assert inside.wait(10)
        result["scan"] = client.post(
            f"/api/library/projects/{pid}/scans", json={}, headers=H(token))
        scan_done.set()

    t1 = threading.Thread(target=remover)
    t2 = threading.Thread(target=scanner)
    t1.start()
    t2.start()
    t1.join(15)
    t2.join(15)
    monkeypatch.undo()
    assert result["scan"].status_code == 409
    assert "another operation is in progress" in result["scan"].json()["error"]
    assert spawn.calls == []                       # zero subprocess
    assert result["remove"].status_code == 200
    assert app.library.store.project(pid) is None
    assert app.library.runner.active_job_id() is None
    with app.library._proj_lock:
        assert pid not in app.library._proj_busy   # lease freed


def test_w4a5_scan_reserves_then_remove_is_refused(tmp_path):
    """A live scan (blocked) holds an active job; remove_project sees it and
    refuses 409; then the scan is cancelable and project/job rows survive."""
    client, token, app, allowed, pid, spawn = _blocking_client(tmp_path)
    r = client.post(f"/api/library/projects/{pid}/scans", json={},
                    headers=H(token))
    assert r.status_code == 202
    jid = r.json()["job_id"]
    rr = client.delete(f"/api/library/projects/{pid}?confirm=true",
                       headers=H(token))
    assert rr.status_code == 409
    assert app.library.store.project(pid) is not None
    assert app.library.store.job(jid) is not None      # job row readable
    # invariant: job accepted with 202 stays readable + cancelable via API
    assert client.get(f"/api/library/scans/{jid}").status_code == 200
    assert client.post(f"/api/library/scans/{jid}/cancel",
                       headers=H(token)).status_code == 200
    app.library.runner.wait(jid)


def test_w4a5_delete_source_reserves_then_scan_refused(tmp_path):
    """delete_source on a managed clone excludes a concurrent scan; the
    source is deleted safely and no scan reads it mid-delete."""
    spawn = FakeSpawn(block_scans_only=True)   # clone completes, scan blocks
    client, token, app, allowed = make_client(tmp_path, spawn)
    r = client.post("/api/library/projects",
                    json={"kind": "git",
                          "url": "https://github.com/a/hello.git"},
                    headers=H(token))
    pid = r.json()["project"]["project_id"]
    app.library.runner.wait(r.json()["job_id"])        # clone completes
    # hold the project lease manually to model an in-flight delete_source,
    # then prove a scan is refused
    assert app.library.reserve_project(pid) is True
    try:
        rs = client.post(f"/api/library/projects/{pid}/scans", json={},
                         headers=H(token))
        assert rs.status_code == 409
    finally:
        app.library.release_project(pid)
    # now the real delete_source succeeds and a later scan is refused only
    # because the source is gone
    rd = client.post(f"/api/library/projects/{pid}/delete-source",
                     json={"confirm": True}, headers=H(token))
    assert rd.status_code == 200 and rd.json()["source_deleted"]
    rs = client.post(f"/api/library/projects/{pid}/scans", json={},
                     headers=H(token))
    assert rs.status_code == 409                        # source not available


def test_w4a5_active_scan_blocks_remove_and_delete_source(tmp_path):
    spawn = FakeSpawn(block_scans_only=True)   # clone completes, scan blocks
    client, token, app, allowed = make_client(tmp_path, spawn)
    r = client.post("/api/library/projects",
                    json={"kind": "git",
                          "url": "https://github.com/a/hello.git"},
                    headers=H(token))
    pid = r.json()["project"]["project_id"]
    app.library.runner.wait(r.json()["job_id"])
    assert app.library.store.job(r.json()["job_id"])["state"] == "completed"
    r = client.post(f"/api/library/projects/{pid}/scans", json={},
                    headers=H(token))
    assert r.status_code == 202
    jid = r.json()["job_id"]                            # scan now active
    assert client.delete(f"/api/library/projects/{pid}?confirm=true",
                         headers=H(token)).status_code == 409
    assert client.post(f"/api/library/projects/{pid}/delete-source",
                       json={"confirm": True},
                       headers=H(token)).status_code == 409
    client.post(f"/api/library/scans/{jid}/cancel", headers=H(token))
    app.library.runner.wait(jid)


def test_w4a5_lease_released_on_runner_failure(tmp_path, monkeypatch):
    """A runner.start failure frees the project lease and leaves no job,
    process, or slot; a retry then works."""
    client, token, app, allowed, pid, spawn = _blocking_client(tmp_path)

    def boom(*a, **k):
        raise LibraryStoreError("runner detached")
    monkeypatch.setattr(app.library.runner, "start", boom)
    r = client.post(f"/api/library/projects/{pid}/scans", json={},
                    headers=H(token))
    assert r.status_code == 409
    monkeypatch.undo()
    with app.library._proj_lock:
        assert pid not in app.library._proj_busy       # lease freed
    assert app.library.runner.active_job_id() is None
    r = client.post(f"/api/library/projects/{pid}/scans", json={},
                    headers=H(token))                   # retry works
    assert r.status_code == 202
    app.library.runner.cancel(r.json()["job_id"])
    app.library.runner.wait(r.json()["job_id"])


def test_w4a5_stress_invariants_hold(tmp_path):
    """Short concurrency hammer across scan / remove / delete-source. The
    invariant checked throughout: the runner is never active without a
    matching project row AND job row (the reproduced orphan state)."""
    import threading
    client, token, app, allowed, pid, spawn = _blocking_client(tmp_path)
    lib = app.library
    stop = threading.Event()
    violations = []

    def invariant_watch():
        # The reproduced orphan condition, tied to THIS project: the project
        # row is removed while the runner is still active for it. (A just-
        # cancelled job's row may briefly be pruned while _active clears —
        # that transient is not the orphan bug and is not flagged here.)
        while not stop.is_set():
            jid = lib.runner.active_job_id()
            if jid is not None and lib.store.project(pid) is None:
                # the only job the runner can hold here is this project's
                job = lib.store.job(jid)
                if job is None or job["project_id"] == pid:
                    violations.append("runner active after project removed")
            time.sleep(0.001)

    def scanner():
        while not stop.is_set():
            r = client.post(f"/api/library/projects/{pid}/scans", json={},
                            headers=H(token))
            if r.status_code == 202:
                jid = r.json()["job_id"]
                client.post(f"/api/library/scans/{jid}/cancel",
                            headers=H(token))
                lib.runner.wait(jid)
            elif r.status_code == 404:
                return                                  # project removed

    def remover():
        for _ in range(40):
            r = client.delete(f"/api/library/projects/{pid}?confirm=true",
                              headers=H(token))
            if r.status_code == 200:
                return
            time.sleep(0.005)

    watch = threading.Thread(target=invariant_watch)
    watch.start()
    scanners = [threading.Thread(target=scanner) for _ in range(3)]
    for t in scanners:
        t.start()
    rm = threading.Thread(target=remover)
    rm.start()
    rm.join(30)
    stop.set()
    for t in scanners:
        t.join(10)
    watch.join(10)
    assert violations == []
    # end state is coherent: either fully removed, or present with no
    # orphaned runner
    if lib.store.project(pid) is None:
        assert lib.runner.active_job_id() is None
