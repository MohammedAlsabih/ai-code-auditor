"""W4-B: Scan History & Changes — the library's side of the comparison.

The counting rules themselves (fingerprints, multiset matching, --new-only
gating) are proved in `test_baseline.py`. What is proved HERE is the library
path: which baseline a rescan picks, what it refuses, what the store records,
and that a report in use as a baseline cannot be deleted underneath the scan
that is reading it.

No network, no semgrep, no git, no subprocess: the scan "subprocess" is the
REAL CLI executed in-process from the argv the runner built, so the argv
contract is under test too, not assumed.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import auditor.web.library as lib_mod
from auditor.web.library import (
    JOB_KEYS,
    MAX_REPORTS_PER_PROJECT,
    REPORT_INPUT_KEYS,
    BaselineRefused,
    JobRunner,
    LibraryPaths,
    LibraryStore,
    LibraryStoreError,
    baseline_row_fields,
    baseline_source,
    new_id,
    resolve_baseline,
    scan_argv,
)
from auditor.web.library_app import CONTROL_HEADER, create_library_app

# ---- an in-process "subprocess" that is the real scanner --------------------------


class RealScanProc:
    def __init__(self, rc: int) -> None:
        self.pid = 424243
        self.rc = rc

    def wait(self, timeout: float | None = None) -> int:
        return self.rc

    def kill(self) -> None:                       # never reached: already done
        pass


class RealScanSpawn:
    """Executes the scan the runner asked for, with the runner's own argv,
    in this process. Everything after the `scan` token is handed to the real
    CLI verbatim — so a missing `--baseline`, a wrong path, or a stray
    `--new-only` fails the test rather than being simulated away."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, argv, cwd, stdout_path, stderr_path, env):
        from auditor.cli import main
        self.calls.append(list(argv))
        Path(stdout_path).write_bytes(b"")
        Path(stderr_path).write_bytes(b"")
        return RealScanProc(main(argv[argv.index("scan"):]))

    # -- helpers the assertions read ------------------------------------------
    @property
    def last(self) -> list[str]:
        return self.calls[-1]

    def baseline_arg(self, call: list[str] | None = None) -> str | None:
        call = self.last if call is None else call
        return (call[call.index("--baseline") + 1]
                if "--baseline" in call else None)


class BlockingProc:
    """A scan that never finishes until it is killed — for the cancel and
    concurrency cases, where the point is that the job is still running."""

    def __init__(self) -> None:
        self.pid = 424244
        self.killed = False

    def wait(self, timeout: float | None = None) -> int:
        deadline = time.monotonic() + (timeout if timeout is not None else 3600)
        while not self.killed:
            if time.monotonic() > deadline:
                raise TimeoutError
            time.sleep(0.01)
        return 1

    def kill(self) -> None:
        self.killed = True


class BlockingSpawn:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.procs: list[BlockingProc] = []

    def __call__(self, argv, cwd, stdout_path, stderr_path, env):
        self.calls.append(list(argv))
        Path(stdout_path).write_bytes(b"")
        Path(stderr_path).write_bytes(b"")
        proc = BlockingProc()
        self.procs.append(proc)
        return proc


class FailingSpawn:
    """A scan that exits without writing a report — the failure path."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, argv, cwd, stdout_path, stderr_path, env):
        self.calls.append(list(argv))
        Path(stdout_path).write_bytes(b"")
        Path(stderr_path).write_bytes(b"")
        return RealScanProc(1)


@pytest.fixture(autouse=True)
def _no_real_kill(monkeypatch):
    monkeypatch.setattr(lib_mod, "kill_process_tree", lambda proc: proc.kill())


# ---- fixtures ---------------------------------------------------------------------

# AWS's own documented example key. A second file holding the SAME line is a
# SECOND finding — the fingerprint covers the file — so one string is enough
# to build "a finding was added" and "a finding was resolved". Inventing a
# lookalike key instead would trip secret scanners for no benefit.
CREDENTIAL = 'API_KEY = "AKIAIOSFODNN7EXAMPLE"\n'


def make_source(root: Path, name: str = "repo") -> Path:
    """A project with exactly one deterministic offline finding."""
    src = root / name
    src.mkdir(parents=True, exist_ok=True)
    (src / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "1.0"\n', encoding="utf-8")
    (src / "app.py").write_text(CREDENTIAL, encoding="utf-8")
    return src


def make_client(tmp_path: Path, spawn=None, port: int = 8765):
    library = tmp_path / "library"
    allowed = tmp_path / "allowed"
    allowed.mkdir(exist_ok=True)
    spawn = spawn if spawn is not None else RealScanSpawn()
    app = create_library_app(library, [allowed], port, spawn=spawn)
    client = TestClient(app)
    token = client.get("/api/library/session").json()["token"]
    return client, token, app, allowed, spawn


def register(client, token, src: Path, name: str = "p") -> str:
    r = client.post("/api/library/projects",
                    json={"kind": "local", "path": str(src), "name": name},
                    headers={CONTROL_HEADER: token})
    assert r.status_code == 201, r.text
    return r.json()["project"]["project_id"]


def scan(client, token, pid: str, **body):
    r = client.post(f"/api/library/projects/{pid}/scans", json=body,
                    headers={CONTROL_HEADER: token})
    if r.status_code == 202:
        _wait(client, r.json()["job_id"])
    return r


def _wait(client, jid: str, timeout: float = 120.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = client.get(f"/api/library/scans/{jid}")
        if r.status_code != 200:
            # the store went unavailable while the job ran; there is nothing
            # left to poll and the caller asserts on that condition itself
            return {"state": "", "http": r.status_code}
        job = r.json()["job"]
        if job["state"] in ("completed", "failed", "canceled", "interrupted"):
            return job
        time.sleep(0.02)
    raise AssertionError("job did not finish")


def reports(client, pid: str) -> list[dict]:
    return client.get(f"/api/library/projects/{pid}/reports").json()["reports"]


# ---- 1. the first scan ------------------------------------------------------------


def test_first_scan_needs_no_baseline_and_invents_no_states(tmp_path):
    client, token, app, allowed, spawn = make_client(tmp_path)
    pid = register(client, token, make_source(allowed))
    r = scan(client, token, pid)                  # compare_previous defaults on

    assert r.status_code == 202
    assert r.json()["baseline_enabled"] is False
    assert r.json()["baseline_report_id"] == ""
    assert "--baseline" not in spawn.last and "--new-only" not in spawn.last

    row = reports(client, pid)[0]
    assert row["baseline_enabled"] is False
    assert row["baseline_report_id"] == ""
    assert row["new"] == row["unchanged"] == row["resolved"] == 0
    assert row["gate_scope"] == "all"
    assert row["findings"] >= 1                   # the report itself is whole

    # and the report on disk carries no comparison it was never asked for
    data = json.loads(
        (app.library.paths.report_dir(row["report_id"]) / "report.json")
        .read_text(encoding="utf-8"))
    assert "baseline" not in data["summary"]


def test_new_only_is_refused_when_there_is_nothing_to_compare(tmp_path):
    client, token, app, allowed, spawn = make_client(tmp_path)
    pid = register(client, token, make_source(allowed))
    r = scan(client, token, pid, new_only=True)
    assert r.status_code == 400
    assert "previous report" in r.json()["error"]
    assert spawn.calls == []                      # refused BEFORE any scan
    assert reports(client, pid) == []


# ---- 2-5. what a rescan counts ----------------------------------------------------


def test_rescan_of_unchanged_source_reports_zero_new(tmp_path):
    client, token, app, allowed, spawn = make_client(tmp_path)
    src = make_source(allowed)
    pid = register(client, token, src)
    scan(client, token, pid)
    first = reports(client, pid)[0]

    r = scan(client, token, pid)
    assert r.json()["baseline_report_id"] == first["report_id"]
    # the path is the SERVER's, derived from the id, under the library root
    arg = spawn.baseline_arg()
    assert arg == str(app.library.paths.report_json(first["report_id"]))
    assert "--new-only" not in spawn.last

    row = reports(client, pid)[0]
    assert row["baseline_enabled"] is True
    assert row["baseline_report_id"] == first["report_id"]
    assert row["new"] == 0 and row["resolved"] == 0
    assert row["unchanged"] == row["findings"] == first["findings"]
    assert row["gate_scope"] == "all"


def test_line_shift_alone_keeps_findings_unchanged(tmp_path):
    client, token, app, allowed, spawn = make_client(tmp_path)
    src = make_source(allowed)
    pid = register(client, token, src)
    scan(client, token, pid)
    (src / "app.py").write_text("\n\n" + CREDENTIAL, encoding="utf-8")
    scan(client, token, pid)

    row = reports(client, pid)[0]
    assert row["new"] == 0 and row["resolved"] == 0
    assert row["unchanged"] >= 1


def test_an_added_finding_is_counted_as_new(tmp_path):
    client, token, app, allowed, spawn = make_client(tmp_path)
    src = make_source(allowed)
    pid = register(client, token, src)
    scan(client, token, pid)
    before = reports(client, pid)[0]["findings"]
    (src / "extra.py").write_text(
        CREDENTIAL, encoding="utf-8")
    scan(client, token, pid)

    row = reports(client, pid)[0]
    assert row["new"] == 1
    assert row["resolved"] == 0
    assert row["findings"] == before + 1          # the whole report, not the delta
    assert row["unchanged"] == before


def test_a_removed_finding_is_counted_as_resolved(tmp_path):
    client, token, app, allowed, spawn = make_client(tmp_path)
    src = make_source(allowed)
    (src / "extra.py").write_text(
        CREDENTIAL, encoding="utf-8")
    pid = register(client, token, src)
    scan(client, token, pid)
    before = reports(client, pid)[0]["findings"]
    (src / "extra.py").unlink()
    scan(client, token, pid)

    row = reports(client, pid)[0]
    assert row["resolved"] == 1
    assert row["new"] == 0
    assert row["findings"] == before - 1
    assert row["unchanged"] == before - 1


# ---- 6-7. the gate's scope --------------------------------------------------------


def test_new_only_moves_the_verdict_but_not_the_findings(tmp_path):
    client, token, app, allowed, spawn = make_client(tmp_path)
    src = make_source(allowed)
    pid = register(client, token, src)
    scan(client, token, pid)                       # the credential is now old
    first = reports(client, pid)[0]
    assert first["verdict"] == "block"             # it blocked when it was new

    scan(client, token, pid, new_only=True)
    assert "--new-only" in spawn.last
    row = reports(client, pid)[0]
    assert row["gate_scope"] == "new"
    assert row["findings"] == first["findings"]    # nothing was hidden
    assert row["new"] == 0 and row["unchanged"] == first["findings"]
    assert row["verdict"] == "pass"                # ...but nothing NEW gates


def test_new_only_narrows_the_gate_but_silences_no_other_signal():
    """From the field runs: on the larger real project a new-only rescan with
    nothing new still returned `review`, not `pass` — 12 files had failed to
    parse. That is the intended contract, and it is the thing that stops
    "gate new findings only" from becoming a way to launder an incomplete
    analysis into a clean-looking verdict."""
    from auditor.core.scoring import verdict

    empty = {"block": 0, "review": 0, "informational": 0}
    assert verdict(empty, 95, {}) == "pass"
    assert verdict(empty, 94, {"parse_error_files": ["a.ts"]}) == "review"
    assert verdict(empty, 94, {"manifest_incomplete": ["b/pkg.json"]}) \
        == "review"
    assert verdict(empty, 94, {"rule_failures": 1}) == "review"
    assert verdict(empty, 39, {}) == "block"      # confidence floor still bites


def test_the_full_gate_is_what_you_get_by_default(tmp_path):
    client, token, app, allowed, spawn = make_client(tmp_path)
    src = make_source(allowed)
    pid = register(client, token, src)
    scan(client, token, pid)
    scan(client, token, pid)                       # default: no --new-only

    row = reports(client, pid)[0]
    assert row["gate_scope"] == "all"
    assert row["verdict"] == "block"               # the old credential still gates


def test_comparison_can_be_turned_off(tmp_path):
    client, token, app, allowed, spawn = make_client(tmp_path)
    src = make_source(allowed)
    pid = register(client, token, src)
    scan(client, token, pid)
    r = scan(client, token, pid, compare_previous=False)

    assert r.json()["baseline_enabled"] is False
    assert "--baseline" not in spawn.last
    row = reports(client, pid)[0]
    assert row["baseline_enabled"] is False and row["gate_scope"] == "all"


def test_an_explicit_baseline_may_be_an_older_report(tmp_path):
    client, token, app, allowed, spawn = make_client(tmp_path)
    src = make_source(allowed)
    pid = register(client, token, src)
    scan(client, token, pid)
    oldest = reports(client, pid)[0]["report_id"]
    (src / "extra.py").write_text(
        CREDENTIAL, encoding="utf-8")
    scan(client, token, pid)                       # newest now has 2 findings

    r = scan(client, token, pid, baseline_report_id=oldest)
    assert r.json()["baseline_report_id"] == oldest
    row = reports(client, pid)[0]
    assert row["baseline_report_id"] == oldest
    assert row["new"] == 1                         # new RELATIVE TO THE CHOICE


# ---- 8. every illegal baseline is refused before the scan starts -------------------


def test_a_foreign_projects_report_is_refused(tmp_path):
    client, token, app, allowed, spawn = make_client(tmp_path)
    other = register(client, token, make_source(allowed, "other"), "other")
    scan(client, token, other)
    stolen = reports(client, other)[0]["report_id"]

    mine = register(client, token, make_source(allowed, "mine"), "mine")
    calls_before = len(spawn.calls)
    r = scan(client, token, mine, baseline_report_id=stolen)

    assert r.status_code == 400
    assert "not a report of this project" in r.json()["error"]
    assert len(spawn.calls) == calls_before        # nothing was started
    assert reports(client, mine) == []
    # the refusal cannot be used to learn that the id exists elsewhere
    unknown = scan(client, token, mine, baseline_report_id="0" * 16)
    assert unknown.json()["error"] == r.json()["error"]


def test_a_missing_or_corrupt_baseline_is_refused_before_the_subprocess(
        tmp_path):
    client, token, app, allowed, spawn = make_client(tmp_path)
    src = make_source(allowed)
    pid = register(client, token, src)
    scan(client, token, pid)
    rid = reports(client, pid)[0]["report_id"]
    target = app.library.paths.report_json(rid)

    target.write_text("{not json", encoding="utf-8")
    calls = len(spawn.calls)
    r = scan(client, token, pid, baseline_report_id=rid)
    assert r.status_code == 400
    assert "cannot be read" in r.json()["error"]
    assert len(spawn.calls) == calls
    assert len(reports(client, pid)) == 1          # no partial second report

    target.unlink()
    r = scan(client, token, pid, baseline_report_id=rid)
    assert r.status_code == 400
    assert len(spawn.calls) == calls


def test_a_symlinked_report_directory_is_never_used(tmp_path):
    client, token, app, allowed, spawn = make_client(tmp_path)
    src = make_source(allowed)
    pid = register(client, token, src)
    scan(client, token, pid)
    rid = reports(client, pid)[0]["report_id"]
    directory = app.library.paths.report_dir(rid)

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "report.json").write_text(
        (directory / "report.json").read_text(encoding="utf-8"),
        encoding="utf-8")
    for child in directory.iterdir():
        child.unlink()
    directory.rmdir()
    try:
        directory.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available to this user")

    assert baseline_source(app.library.paths, rid) is None
    calls = len(spawn.calls)
    r = scan(client, token, pid, baseline_report_id=rid)
    assert r.status_code == 400
    assert len(spawn.calls) == calls


def test_a_symlinked_baseline_is_refused_without_needing_the_privilege(
        tmp_path, monkeypatch):
    """Creating a real symlink needs a privilege this machine may not grant,
    so the guard itself is exercised directly: the moment either the report
    directory or the file reports as a link, the answer is no."""
    client, token, app, allowed, spawn = make_client(tmp_path)
    src = make_source(allowed)
    pid = register(client, token, src)
    scan(client, token, pid)
    rid = reports(client, pid)[0]["report_id"]
    paths = app.library.paths
    real_is_symlink = Path.is_symlink

    for pretend in (paths.report_dir(rid), paths.report_json(rid)):
        monkeypatch.setattr(
            Path, "is_symlink",
            lambda self, _t=pretend: self == _t or real_is_symlink(self))
        assert baseline_source(paths, rid) is None
        calls = len(spawn.calls)
        r = scan(client, token, pid, baseline_report_id=rid)
        assert r.status_code == 400
        assert len(spawn.calls) == calls
        monkeypatch.undo()

    assert baseline_source(paths, rid) is not None   # ...and it works when not


def test_a_damaged_newest_report_is_never_replaced_by_an_older_one(tmp_path):
    """The counter-case for "compare with previous". Walking past the newest
    report to the newest USABLE one silently changes what the answer means:
    the user is shown "new since the previous scan" measured against a
    baseline they did not choose and are not told about. Refusing says what
    is true — and naming an older report explicitly still works."""
    client, token, app, allowed, spawn = make_client(tmp_path)
    src = make_source(allowed)
    pid = register(client, token, src)
    scan(client, token, pid)
    older = reports(client, pid)[0]["report_id"]
    scan(client, token, pid)
    newest = reports(client, pid)[0]["report_id"]
    assert newest != older

    for damage in ("corrupt", "delete"):
        target = app.library.paths.report_json(newest)
        if damage == "corrupt":
            target.write_text("{", encoding="utf-8")
        else:
            target.unlink()
        calls = len(spawn.calls)
        r = scan(client, token, pid)
        assert r.status_code == 409, damage
        assert "previous report cannot be read" in r.json()["error"]
        assert len(spawn.calls) == calls           # refused before the scan
        assert len(reports(client, pid)) == 2      # and nothing was recorded

    # the older report is still reachable — by NAMING it
    r = scan(client, token, pid, baseline_report_id=older)
    assert r.status_code == 202
    assert r.json()["baseline_report_id"] == older


def test_a_newest_report_being_deleted_answers_409_not_an_older_baseline(
        tmp_path):
    client, token, app, allowed, spawn = make_client(tmp_path)
    src = make_source(allowed)
    pid = register(client, token, src)
    scan(client, token, pid)
    older = reports(client, pid)[0]["report_id"]
    scan(client, token, pid)
    newest = reports(client, pid)[0]["report_id"]

    # hold the newest under a deletion lease, exactly as a live delete would
    assert app.library.reserve_for_delete([newest]) is None
    try:
        calls = len(spawn.calls)
        r = scan(client, token, pid)
        assert r.status_code == 409
        assert "being deleted" in r.json()["error"]
        assert len(spawn.calls) == calls
        assert older not in r.text                 # no quiet substitution
    finally:
        app.library.release_delete([newest])
    assert scan(client, token, pid).status_code == 202   # released: fine again


def test_a_baseline_cannot_be_named_while_comparison_is_off(tmp_path):
    client, token, app, allowed, spawn = make_client(tmp_path)
    src = make_source(allowed)
    pid = register(client, token, src)
    scan(client, token, pid)
    rid = reports(client, pid)[0]["report_id"]

    r = scan(client, token, pid, compare_previous=False,
             baseline_report_id=rid)
    assert r.status_code == 400
    r = scan(client, token, pid, compare_previous=False, new_only=True)
    assert r.status_code == 400


def test_the_scan_request_has_no_field_for_a_path(tmp_path):
    client, token, app, allowed, spawn = make_client(tmp_path)
    pid = register(client, token, make_source(allowed))
    for body in ({"baseline_path": "C:/x/report.json"},
                 {"baseline": "/etc/passwd"}):
        r = client.post(f"/api/library/projects/{pid}/scans", json=body,
                        headers={CONTROL_HEADER: token})
        assert r.status_code == 422                # extra='forbid'
    assert spawn.calls == []


# ---- 9-11. the lease ---------------------------------------------------------------


def test_a_baseline_in_use_cannot_be_deleted(tmp_path):
    spawn = BlockingSpawn()
    client, token, app, allowed, _ = make_client(tmp_path, spawn=None)
    src = make_source(allowed)
    pid = register(client, token, src)
    scan(client, token, pid)                       # first scan: real, quick
    rid = reports(client, pid)[0]["report_id"]

    app.library.runner._spawn = spawn                # the rescan will hang
    started = client.post(f"/api/library/projects/{pid}/scans", json={},
                          headers={CONTROL_HEADER: token})
    assert started.json()["baseline_report_id"] == rid
    _spin(lambda: spawn.procs)

    r = client.delete(f"/api/library/reports/{rid}?confirm=true",
                      headers={CONTROL_HEADER: token})
    assert r.status_code == 409
    assert "baseline" in r.json()["error"]
    # the file is intact: the running scan is still reading it
    assert app.library.paths.report_json(rid).is_file()
    assert client.get(f"/api/library/reports/{rid}").status_code == 200

    client.post(f"/api/library/scans/{started.json()['job_id']}/cancel",
                headers={CONTROL_HEADER: token})
    _wait(client, started.json()["job_id"])
    # cancellation released it — the same deletion now succeeds
    assert client.delete(f"/api/library/reports/{rid}?confirm=true",
                         headers={CONTROL_HEADER: token}).status_code == 200


def test_a_failed_scan_releases_the_lease(tmp_path):
    client, token, app, allowed, _ = make_client(tmp_path)
    src = make_source(allowed)
    pid = register(client, token, src)
    scan(client, token, pid)
    rid = reports(client, pid)[0]["report_id"]

    app.library.runner._spawn = FailingSpawn()
    r = scan(client, token, pid)
    assert r.status_code == 202
    assert client.get(
        f"/api/library/scans/{r.json()['job_id']}").json()["job"]["state"] \
        == "failed"
    # the job row reaches its terminal state a moment BEFORE the job thread
    # finishes unwinding, and the lease is released in that unwind — so this
    # is waited for, not assumed. (A deletion issued inside that window is
    # refused with a retryable 409, never served against a live baseline.)
    _spin(lambda: app.library._baselines == {})
    assert client.delete(f"/api/library/reports/{rid}?confirm=true",
                         headers={CONTROL_HEADER: token}).status_code == 200


def test_a_store_failure_finishing_a_scan_releases_the_lease(
        tmp_path, monkeypatch):
    client, token, app, allowed, _ = make_client(tmp_path)
    src = make_source(allowed)
    pid = register(client, token, src)
    scan(client, token, pid)
    rid = reports(client, pid)[0]["report_id"]

    def boom(self, report_row, job_row):
        raise LibraryStoreError("metadata write failed")
    monkeypatch.setattr(LibraryStore, "put_report_and_finish_job", boom)
    r = scan(client, token, pid)
    _spin(lambda: app.library._baselines == {})    # released in the unwind
    monkeypatch.undo()

    # nothing was committed, so nothing is shown as committed
    assert app.library.store.available is False
    assert "could not be recorded" in app.library.store.error
    assert [row["report_id"] for row in app.library.store.reports_for(pid)] \
        == [rid]
    assert app.library.paths.report_json(rid).is_file()   # baseline survived
    # and the report directory that had already been promoted is gone
    promoted = [d.name for d in (app.library.paths.root / "reports").iterdir()]
    assert promoted == [rid]
    # the API says the library is out of date rather than guessing
    assert client.get(
        f"/api/library/scans/{r.json()['job_id']}").status_code == 503


def test_a_project_cannot_be_removed_while_its_baseline_is_read(tmp_path):
    spawn = BlockingSpawn()
    client, token, app, allowed, _ = make_client(tmp_path)
    src = make_source(allowed)
    pid = register(client, token, src)
    scan(client, token, pid)
    app.library.runner._spawn = spawn
    jid = client.post(f"/api/library/projects/{pid}/scans", json={},
                      headers={CONTROL_HEADER: token}).json()["job_id"]
    _spin(lambda: spawn.procs)

    r = client.delete(f"/api/library/projects/{pid}?confirm=true",
                      headers={CONTROL_HEADER: token})
    assert r.status_code == 409
    assert client.get(f"/api/library/projects/{pid}/reports").status_code == 200

    client.post(f"/api/library/scans/{jid}/cancel",
                headers={CONTROL_HEADER: token})
    _wait(client, jid)


def test_retention_never_prunes_the_report_it_is_comparing_against(
        tmp_path, monkeypatch):
    """The prune runs at the END of the same scan that used the baseline, so
    this is the case where the two really do collide."""
    monkeypatch.setattr(lib_mod, "MAX_REPORTS_PER_PROJECT", 1)
    client, token, app, allowed, spawn = make_client(tmp_path)
    src = make_source(allowed)
    pid = register(client, token, src)
    scan(client, token, pid)
    base = reports(client, pid)[0]["report_id"]

    scan(client, token, pid)                       # prunes down to the cap...
    ids = [r["report_id"] for r in reports(client, pid)]
    assert base in ids                             # ...but not the baseline
    assert app.library.paths.report_json(base).is_file()

    # once the lease is gone the next prune collects it normally
    scan(client, token, pid, compare_previous=False)
    assert base not in [r["report_id"] for r in reports(client, pid)]


def _spin(predicate, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("condition never became true")


# ---- a job's state is recorded, or the library says it does not know ---------------


class _FailingWrite:
    """Make ONE kind of store write fail, so the cases stay distinguishable.
    A real trigger is a read-only or full library directory: `_write` turns
    every OSError into LibraryStoreError."""

    def __init__(self, monkeypatch, when) -> None:
        self.when, self.calls = when, 0
        real = LibraryStore.put_job
        real_txn = LibraryStore.put_report_and_finish_job

        def put_job(store, row):
            if when(row):
                self.calls += 1
                raise LibraryStoreError("library store write failed")
            return real(store, row)

        def txn(store, report_row, job_row):
            if when(job_row):
                self.calls += 1
                raise LibraryStoreError("library store write failed")
            return real_txn(store, report_row, job_row)

        monkeypatch.setattr(LibraryStore, "put_job", put_job)
        monkeypatch.setattr(LibraryStore, "put_report_and_finish_job", txn)


def test_a_start_that_cannot_be_recorded_runs_nothing(tmp_path, monkeypatch):
    """Reproduced before the fix: the pending->running write failed, the
    failure was swallowed, and the scan spawned anyway — a real subprocess
    that every later reader believed had never started."""
    client, token, app, allowed, spawn = make_client(tmp_path)
    pid = register(client, token, make_source(allowed))
    injected = _FailingWrite(monkeypatch, lambda row: row["state"] == "running")

    r = client.post(f"/api/library/projects/{pid}/scans", json={},
                    headers={CONTROL_HEADER: token})
    assert r.status_code == 202
    jid = r.json()["job_id"]
    _spin(lambda: app.library.runner.active_job_id() is None)
    monkeypatch.undo()

    assert injected.calls == 1
    assert spawn.calls == []                       # nothing was ever run
    assert not list((app.library.paths.root / "tmp").glob("*")) \
        if (app.library.paths.root / "tmp").is_dir() else True
    assert app.library.store.available is False
    assert "could not be recorded" in app.library.store.error
    assert app.library.runner.active_job_id() is None   # slot freed
    assert app.library._baselines == {}                 # lease freed
    assert app.library._proj_busy == set()
    # the API refuses to characterise the job rather than guessing
    assert client.get(f"/api/library/scans/{jid}").status_code == 503
    # ...and a restart resolves the pending row under the existing contract
    fresh = LibraryStore(app.library.paths.store_path())
    assert fresh.available, fresh.error
    assert fresh.job(jid)["state"] == "interrupted"


def test_a_finished_scan_commits_the_report_and_the_job_together(tmp_path):
    """The success path is ONE transaction. Before the fix these were two
    commits, so a failure in between left a usable report that no job
    claimed — and the next scan picked that orphan as its baseline."""
    client, token, app, allowed, spawn = make_client(tmp_path)
    pid = register(client, token, make_source(allowed))
    r = scan(client, token, pid)
    jid = r.json()["job_id"]

    row = app.library.store.job(jid)
    reports_now = app.library.store.reports_for(pid)
    assert row["state"] == "completed"
    assert len(reports_now) == 1
    assert row["report_id"] == reports_now[0]["report_id"]   # they agree
    # and the pairing survives a reload, because it was one write
    fresh = LibraryStore(app.library.paths.store_path())
    assert fresh.job(jid)["report_id"] == \
        fresh.reports_for(pid)[0]["report_id"]


def test_a_finish_that_cannot_be_recorded_commits_nothing(tmp_path,
                                                          monkeypatch):
    client, token, app, allowed, spawn = make_client(tmp_path)
    pid = register(client, token, make_source(allowed))
    injected = _FailingWrite(monkeypatch,
                             lambda row: row["state"] == "completed")

    r = client.post(f"/api/library/projects/{pid}/scans", json={},
                    headers={CONTROL_HEADER: token})
    jid = r.json()["job_id"]
    _spin(lambda: app.library.runner.active_job_id() is None)
    monkeypatch.undo()

    assert injected.calls == 1
    assert app.library.store.available is False
    assert "could not be recorded" in app.library.store.error
    # neither half landed: no report row, and no promoted directory either
    assert app.library.store.reports_for(pid) == []
    reports_dir = app.library.paths.root / "reports"
    assert not reports_dir.is_dir() or list(reports_dir.iterdir()) == []
    # the stale row is never served as though the scan were still running
    assert client.get(f"/api/library/scans/{jid}").status_code == 503
    assert client.get("/api/library/projects").status_code == 503
    fresh = LibraryStore(app.library.paths.store_path())
    assert fresh.job(jid)["state"] == "interrupted"
    assert fresh.reports_for(pid) == []


@pytest.mark.parametrize("terminal", ["failed", "canceled"])
def test_a_terminal_state_that_cannot_be_recorded_says_so(
        tmp_path, monkeypatch, terminal):
    """failed and canceled obey the same rule as completed — and neither
    leaves the runner slot or a baseline lease held."""
    client, token, app, allowed, real = make_client(tmp_path)
    pid = register(client, token, make_source(allowed))
    blocking = BlockingSpawn()
    # a scan that writes no report FAILS; a scan that hangs gets CANCELED
    app.library.runner._spawn = (blocking if terminal == "canceled"
                                 else FailingSpawn())
    injected = _FailingWrite(monkeypatch,
                             lambda row: row["state"] == terminal)

    r = client.post(f"/api/library/projects/{pid}/scans", json={},
                    headers={CONTROL_HEADER: token})
    assert r.status_code == 202
    jid = r.json()["job_id"]
    if terminal == "canceled":
        _spin(lambda: blocking.procs)
        client.post(f"/api/library/scans/{jid}/cancel",
                    headers={CONTROL_HEADER: token})
    _spin(lambda: app.library.runner.active_job_id() is None)
    monkeypatch.undo()

    assert injected.calls == 1
    assert app.library.store.available is False
    assert "could not be recorded" in app.library.store.error
    assert app.library.runner.active_job_id() is None   # runner not wedged
    assert app.library._baselines == {}                 # no lease held
    assert app.library._proj_busy == set()
    assert client.get(f"/api/library/scans/{jid}").status_code == 503
    assert LibraryStore(app.library.paths.store_path()) \
        .job(jid)["state"] == "interrupted"


# ---- 12. the store: migration, coupling, rollback ----------------------------------


LEGACY_REPORT = {"report_id": "a" * 16, "project_id": "b" * 16,
                 "created_at": "2026-01-01T00:00:00Z", "verdict": "pass",
                 "findings": 7, "duration_ms": 12}
LEGACY_JOB = {"job_id": "c" * 16, "project_id": "b" * 16, "kind": "scan",
              "state": "completed", "online": False, "semgrep": False,
              "created_at": "2026-01-01T00:00:00Z",
              "started_at": "2026-01-01T00:00:01Z",
              "finished_at": "2026-01-01T00:00:02Z", "error": "",
              "report_id": "a" * 16}


def _legacy_store(path: Path, project: dict) -> None:
    path.write_text(json.dumps({
        "schema_version": "library-1",
        "projects": {project["project_id"]: project},
        "reports": {LEGACY_REPORT["report_id"]: LEGACY_REPORT},
        "jobs": {LEGACY_JOB["job_id"]: LEGACY_JOB}}), encoding="utf-8")


def _project_row(pid: str = "b" * 16) -> dict:
    return {"project_id": pid, "name": "n", "kind": "local",
            "location": "local: repo", "created_at": "2026-01-01",
            "git_url": "", "local_path": "C:/x/repo", "managed": False}


def _report_row(pid: str, **over) -> dict:
    """A valid uncompared report row (the caller's shape — no `seq`)."""
    row = {"report_id": new_id(), "project_id": pid,
           "created_at": "2026-01-01T00:00:00.000Z", "verdict": "pass",
           "findings": 0, "duration_ms": 1,
           "baseline_report_id": "", "baseline_enabled": False,
           "baseline_findings": 0,
           "new": 0, "unchanged": 0, "resolved": 0, "gate_scope": "all"}
    row.update(over)
    return row


def test_a_library_1_store_migrates_to_a_first_scan_not_a_comparison(tmp_path):
    p = tmp_path / "library.json"
    _legacy_store(p, _project_row())
    store = LibraryStore(p)

    assert store.available, store.error
    row = store.report(LEGACY_REPORT["report_id"])
    assert row["findings"] == 7                    # untouched
    assert row["baseline_enabled"] is False
    assert row["baseline_report_id"] == ""
    assert row["new"] == row["unchanged"] == row["resolved"] == 0
    assert row["baseline_findings"] == 0
    assert row["gate_scope"] == "all"
    assert row["seq"] == 1                         # a place in the history
    job = store.job(LEGACY_JOB["job_id"])
    assert job["baseline_report_id"] == "" and job["new_only"] is False

    # persisted, so the next load needs no migration at all
    assert json.loads(p.read_text(encoding="utf-8"))["schema_version"] \
        == "library-2"
    assert LibraryStore(p).available


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_a_failed_migration_write_commits_nothing_and_says_so(
        tmp_path, monkeypatch):
    """Rollback contract. This replaces a test that asserted the OPPOSITE —
    that memory could hold `library-2` while the file still held `library-1`,
    with `available` True. Nothing was lost by that (the image is a pure
    function of an intact file), but it was an uncommitted state, served, and
    with no signal at all that the library directory could not be written."""
    p = tmp_path / "library.json"
    _legacy_store(p, _project_row())
    before = _sha256(p)

    def boom(src, dst):
        raise OSError("disk detached")
    monkeypatch.setattr(os, "replace", boom)
    store = LibraryStore(p)
    monkeypatch.undo()

    assert _sha256(p) == before                    # byte-identical
    assert json.loads(p.read_text(encoding="utf-8"))["schema_version"] \
        == "library-1"
    assert not list(tmp_path.glob("*.tmp"))        # no litter
    assert store.available is False
    assert store.error and "could not be updated" in store.error
    assert "\\" not in store.error and "/" not in store.error
    # and it serves nothing from the uncommitted image
    assert store.report(LEGACY_REPORT["report_id"]) is None
    assert store.projects() == []
    with pytest.raises(LibraryStoreError):
        store.put_report({**_report_row(_project_row()["project_id"]),
                          "report_id": new_id()})

    # the file is untouched, so a retry with a working disk simply works
    healthy = LibraryStore(p)
    assert healthy.available, healthy.error
    assert json.loads(p.read_text(encoding="utf-8"))["schema_version"] \
        == "library-2"


def test_a_failed_interrupted_job_write_obeys_the_same_contract(
        tmp_path, monkeypatch):
    """The same rule for a store that needs no migration at all: marking a
    persisted running job `interrupted` is a state change like any other."""
    p = tmp_path / "library.json"
    project = _project_row()
    store = LibraryStore(p)
    store.put_project(project)
    job = dict.fromkeys(JOB_KEYS, "")
    job.update({"job_id": new_id(), "project_id": project["project_id"],
                "kind": "scan", "state": "running", "online": False,
                "semgrep": False, "new_only": False,
                "created_at": "2026-01-01T00:00:00.000Z"})
    store.put_job(job)
    before = _sha256(p)

    def boom(src, dst):
        raise OSError("disk detached")
    monkeypatch.setattr(os, "replace", boom)
    reloaded = LibraryStore(p)
    monkeypatch.undo()

    assert _sha256(p) == before
    assert not list(tmp_path.glob("*.tmp"))
    assert reloaded.available is False
    assert reloaded.job(job["job_id"]) is None     # nothing uncommitted served
    assert json.loads(p.read_text(encoding="utf-8")) \
        ["jobs"][job["job_id"]]["state"] == "running"
    # the transition still happens the moment it can be recorded
    assert LibraryStore(p).job(job["job_id"])["state"] == "interrupted"


# ---- the unavailable-store matrix --------------------------------------------------

DOWN = "library store is not readable"


def _library_endpoints(pid: str, rid: str, jid: str, allowed: Path):
    """(label, method, url, body, mutating) for every library route that
    reads or writes store data, plus the two that must keep answering."""
    return [
        ("projects list", "GET", "/api/library/projects", None, False),
        ("projects add", "POST", "/api/library/projects",
         {"kind": "local", "path": str(allowed / "another"), "name": "x"},
         True),
        ("project remove", "DELETE",
         f"/api/library/projects/{pid}?confirm=true", None, True),
        ("delete-source", "POST",
         f"/api/library/projects/{pid}/delete-source", {"confirm": True},
         True),
        ("scan start", "POST", f"/api/library/projects/{pid}/scans", {}, True),
        ("scan status", "GET", f"/api/library/scans/{jid}", None, False),
        ("scan cancel", "POST", f"/api/library/scans/{jid}/cancel", None,
         True),
        ("reports list", "GET", f"/api/library/projects/{pid}/reports", None,
         False),
        ("report meta", "GET", f"/api/library/reports/{rid}", None, False),
        ("report delete", "DELETE",
         f"/api/library/reports/{rid}?confirm=true", None, True),
        ("forwarder report", "GET", f"/api/library/reports/{rid}/report",
         None, False),
        ("forwarder health", "GET", f"/api/library/reports/{rid}/health",
         None, False),
        ("forwarder coverage", "GET", f"/api/library/reports/{rid}/coverage",
         None, False),
    ]


def _call(client, method: str, url: str, body, headers=None):
    kw = {"headers": headers or {}}
    if body is not None:
        kw["json"] = body
    return getattr(client, method.lower())(url, **kw)


def test_every_store_backed_endpoint_answers_503_when_the_store_is_down(
        tmp_path, monkeypatch):
    """An unavailable store cannot tell "no such id" from "I cannot read the
    file that would say". Answering 404 asserts the first while the reports
    are still on disk — which is what this reproduced before the fix."""
    client, token, app, allowed, spawn = make_client(tmp_path)
    (allowed / "another").mkdir()
    pid = register(client, token, make_source(allowed))
    r = scan(client, token, pid)
    jid = r.json()["job_id"]
    rid = reports(client, pid)[0]["report_id"]
    report_file = app.library.paths.report_json(rid)
    assert report_file.is_file()

    # count every side effect the refusals must NOT have
    spawned = len(spawn.calls)
    monkeypatch.setattr(
        lib_mod.LibraryPaths, "confined_delete",
        lambda self, target: pytest.fail(f"deleted {target.name}"))
    app.library.store.available, app.library.store.error = False, DOWN

    for label, method, url, body, mutating in _library_endpoints(
            pid, rid, jid, allowed):
        head = {CONTROL_HEADER: token} if mutating else {}
        got = _call(client, method, url, body, head)
        assert got.status_code == 503, f"{label} -> {got.status_code}"
        assert got.json() == {"error": DOWN}, label
        # no path, no snippet, no row leaked in the refusal
        assert str(app.library.paths.root) not in got.text, label

    # nothing was touched by any of it
    assert len(spawn.calls) == spawned            # zero subprocesses
    assert report_file.is_file()                  # zero filesystem deletes
    assert app.library._contexts == {}            # zero report contexts built
    assert app.library._deleting == set()         # zero deletion leases
    assert app.library._baselines == {}           # zero baseline leases
    assert app.library._proj_busy == set()        # zero project leases
    assert not list((app.library.paths.root).glob("*.tmp"))


def test_capabilities_and_session_still_answer_so_the_state_is_explainable(
        tmp_path):
    client, token, app, allowed, spawn = make_client(tmp_path)
    register(client, token, make_source(allowed))
    app.library.store.available, app.library.store.error = False, DOWN

    caps = client.get("/api/library/capabilities")
    assert caps.status_code == 200
    assert caps.json()["store_available"] is False
    assert caps.json()["store_error"] == DOWN
    session = client.get("/api/library/session")
    assert session.status_code == 200
    assert session.json()["token"] == token       # a retry can authenticate


def test_an_unauthorized_caller_never_learns_the_stores_condition(
        tmp_path, allowed_headers=None):
    """WHO before CAN-WE: the 403 must come first, so the store's state is
    not readable by someone who could not have used it anyway."""
    client, token, app, allowed, spawn = make_client(tmp_path)
    pid = register(client, token, make_source(allowed))
    r = scan(client, token, pid)
    jid, rid = r.json()["job_id"], reports(client, pid)[0]["report_id"]
    app.library.store.available, app.library.store.error = False, DOWN

    bad_headers = [
        ("no token", {}),
        ("wrong token", {CONTROL_HEADER: "not-the-token"}),
        ("bad origin", {CONTROL_HEADER: token,
                        "Origin": "http://evil.example"}),
    ]
    for label, method, url, body, mutating in _library_endpoints(
            pid, rid, jid, allowed):
        if not mutating:
            continue
        for why, head in bad_headers:
            got = _call(client, method, url, body, head)
            assert got.status_code == 403, f"{label} / {why}"
            assert DOWN not in got.text, f"{label} / {why}"


def test_a_healthy_load_writes_only_when_something_actually_changed(
        tmp_path, monkeypatch):
    """A store that needs neither migration nor an interrupted transition
    must not rewrite the file on every open — otherwise a read-only library
    would be reported as broken for no reason."""
    p = tmp_path / "library.json"
    store = LibraryStore(p)
    store.put_project(_project_row())
    before = _sha256(p)

    calls: list[int] = []
    real_replace = os.replace

    def counting(src, dst):
        calls.append(1)
        return real_replace(src, dst)
    monkeypatch.setattr(os, "replace", counting)
    reopened = LibraryStore(p)
    monkeypatch.undo()

    assert reopened.available, reopened.error
    assert calls == []                             # no write at all
    assert _sha256(p) == before


@pytest.mark.parametrize("mutate", [
    lambda d: d["reports"][LEGACY_REPORT["report_id"]].pop("verdict"),
    lambda d: d["reports"][LEGACY_REPORT["report_id"]].update(surprise=1),
    lambda d: d["jobs"][LEGACY_JOB["job_id"]].update(new_only=True),
    lambda d: d.update(schema_version="library-99"),
    lambda d: d.update(schema_version="library-0"),
])
def test_an_unknown_schema_or_malformed_legacy_row_fails_closed(tmp_path,
                                                                mutate):
    p = tmp_path / "library.json"
    _legacy_store(p, _project_row())
    data = json.loads(p.read_text(encoding="utf-8"))
    mutate(data)
    p.write_text(json.dumps(data), encoding="utf-8")

    store = LibraryStore(p)
    assert not store.available
    assert store.error and "\\" not in store.error and "/" not in store.error


def _store_with_baseline(tmp_path) -> tuple[LibraryStore, str, str]:
    """A store holding one project and one uncompared report of 5 findings,
    ready to be compared against."""
    store = LibraryStore(tmp_path / "library.json")
    project = _project_row()
    store.put_project(project)
    pid = project["project_id"]
    base = _report_row(pid, findings=5)
    store.put_report(base)
    return store, pid, base["report_id"]


def _compared(pid: str, base_id: str, **over) -> dict:
    """A coherent rescan of the 5-finding baseline: 2 new, 4 unchanged (so 6
    findings now), 1 of the baseline's 5 resolved."""
    row = _report_row(pid)
    row.update(findings=6, baseline_report_id=base_id, baseline_enabled=True,
               baseline_findings=5, new=2, unchanged=4, resolved=1)
    row.update(over)
    return row


@pytest.mark.parametrize("over, why", [
    ({"new": 90, "unchanged": 90, "resolved": 90, "findings": 100,
      "baseline_findings": 5}, "the round's own example: 90+90 is not 100"),
    ({"new": 3}, "new + unchanged must equal findings"),
    ({"unchanged": 5}, "changing unchanged breaks BOTH equations"),
    ({"resolved": 2}, "unchanged + resolved must equal baseline_findings"),
    ({"baseline_findings": 6}, "the baseline did not hold that many"),
    ({"baseline_enabled": False}, "no comparison cannot carry counts"),
    ({"baseline_report_id": ""}, "a comparison names what it compared with"),
    ({"gate_scope": "some"}, "unknown scope"),
    ({"new": -1, "unchanged": 7}, "counts are never negative"),
    ({"new": True, "unchanged": 5}, "a bool is not a count"),
])
def test_a_report_row_must_add_up(tmp_path, over, why):
    store, pid, base_id = _store_with_baseline(tmp_path)
    store.put_report(_compared(pid, base_id))       # the coherent row works
    with pytest.raises(LibraryStoreError):
        store.put_report(_compared(pid, base_id, report_id=new_id(), **over))


def test_a_comparison_must_name_a_real_baseline_of_this_project(tmp_path):
    store, pid, base_id = _store_with_baseline(tmp_path)
    other = _project_row(pid="c" * 16)
    store.put_project(other)
    foreign = _report_row(other["project_id"], findings=5)
    store.put_report(foreign)

    # a row whose OWN arithmetic is fine but whose account of the baseline
    # contradicts what the store recorded that report actually held. This is
    # the check that cannot be satisfied by editing one row consistently:
    # it compares two independently produced numbers.
    with pytest.raises(LibraryStoreError, match="does not match the baseline"):
        store.put_report(_compared(pid, base_id, findings=6, new=2,
                                   unchanged=4, resolved=3,
                                   baseline_findings=7))
    # a baseline that does not exist at all
    with pytest.raises(LibraryStoreError, match="not in this library"):
        store.put_report(_compared(pid, "d" * 16))
    # a baseline belonging to another project
    with pytest.raises(LibraryStoreError, match="another project"):
        store.put_report(_compared(pid, foreign["report_id"]))
    # a report that names ITSELF
    self_ref = _compared(pid, base_id)
    self_ref["baseline_report_id"] = self_ref["report_id"]
    with pytest.raises(LibraryStoreError):
        store.put_report(self_ref)
    assert len(store.reports_for(pid)) == 1         # nothing bad committed


def test_a_report_cannot_compare_against_a_later_one(tmp_path):
    """Unreachable through `put_report` — a new row always takes the highest
    sequence — so this is proved where it CAN be violated: a file."""
    store, pid, base_id = _store_with_baseline(tmp_path)
    row = _compared(pid, base_id)
    store.put_report(row)

    raw = json.loads(store._path.read_text(encoding="utf-8"))
    a, b = raw["reports"][base_id], raw["reports"][row["report_id"]]
    a["seq"], b["seq"] = b["seq"], a["seq"]         # the baseline is now later
    store._path.write_text(json.dumps(raw), encoding="utf-8")

    reloaded = LibraryStore(store._path)
    assert reloaded.available is False
    assert "inconsistent report comparison" in reloaded.error


def test_the_sequence_belongs_to_the_store_not_the_caller(tmp_path):
    store, pid, base_id = _store_with_baseline(tmp_path)
    supplied = _report_row(pid)
    assert set(supplied) == set(REPORT_INPUT_KEYS)  # no `seq` to supply
    assert "seq" not in REPORT_INPUT_KEYS

    store.put_report(supplied)
    assert store.report(supplied["report_id"])["seq"] == 2
    # a caller that tries to choose its own place is refused outright
    with pytest.raises(LibraryStoreError):
        store.put_report({**_report_row(pid), "seq": 99})


def test_the_equations_survive_the_baselines_deletion(tmp_path):
    """`baseline_findings` is copied onto the row for this: a history is not
    made false by deleting what it was measured against."""
    store, pid, base_id = _store_with_baseline(tmp_path)
    row = _compared(pid, base_id)
    store.put_report(row)
    store.remove_report(base_id)

    reloaded = LibraryStore(store._path)
    assert reloaded.available, reloaded.error
    kept = reloaded.report(row["report_id"])
    assert kept["baseline_report_id"] == base_id    # still named
    assert kept["baseline_findings"] == 5           # still checkable
    assert kept["unchanged"] + kept["resolved"] == kept["baseline_findings"]
    assert kept["new"] + kept["unchanged"] == kept["findings"]


@pytest.mark.parametrize("corrupt, why", [
    (lambda r: r.update(new=90, unchanged=90, resolved=90, findings=100),
     "the round's own example, written straight into the file"),
    (lambda r: r.update(baseline_findings=99), "counts vs the baseline"),
    (lambda r: r.update(seq=0), "a sequence starts at one"),
])
def test_an_incoherent_row_on_disk_makes_the_store_unavailable(
        tmp_path, corrupt, why):
    store, pid, base_id = _store_with_baseline(tmp_path)
    row = _compared(pid, base_id)
    store.put_report(row)

    raw = json.loads(store._path.read_text(encoding="utf-8"))
    corrupt(raw["reports"][row["report_id"]])
    store._path.write_text(json.dumps(raw), encoding="utf-8")

    reloaded = LibraryStore(store._path)
    assert reloaded.available is False, why
    assert reloaded.error and "/" not in reloaded.error


def test_two_reports_cannot_claim_the_same_place_in_the_history(tmp_path):
    store, pid, base_id = _store_with_baseline(tmp_path)
    second = _report_row(pid, findings=1)
    store.put_report(second)
    raw = json.loads(store._path.read_text(encoding="utf-8"))
    a, b = raw["reports"][base_id], raw["reports"][second["report_id"]]
    assert a["seq"] != b["seq"]
    b["seq"] = a["seq"]
    b["baseline_enabled"] = False                   # keep it otherwise valid
    store._path.write_text(json.dumps(raw), encoding="utf-8")

    reloaded = LibraryStore(store._path)
    assert reloaded.available is False
    assert "sequence" in reloaded.error


# ---- 13. nothing leaks through the API --------------------------------------------


def test_no_api_response_carries_a_machine_path(tmp_path):
    client, token, app, allowed, spawn = make_client(tmp_path)
    src = make_source(allowed)
    pid = register(client, token, src)
    scan(client, token, pid)
    scan(client, token, pid)
    rid = reports(client, pid)[0]["report_id"]

    bodies = [client.get("/api/library/projects").text,
              client.get(f"/api/library/projects/{pid}/reports").text,
              client.get(f"/api/library/reports/{rid}").text,
              scan(client, token, pid).text,
              scan(client, token, pid, baseline_report_id="z").text]
    for body in bodies:
        assert str(app.library.paths.root) not in body
        assert "report.json" not in body
        assert str(src) not in body
        assert CREDENTIAL.strip() not in body


# ---- 14. two projects can never reach each other's history -------------------------


def test_two_projects_keep_separate_histories_and_baselines(tmp_path):
    client, token, app, allowed, spawn = make_client(tmp_path)
    a = register(client, token, make_source(allowed, "a"), "a")
    b = register(client, token, make_source(allowed, "b"), "b")
    scan(client, token, a)
    scan(client, token, b)
    scan(client, token, a)
    scan(client, token, b)

    a_ids = {r["report_id"] for r in reports(client, a)}
    b_ids = {r["report_id"] for r in reports(client, b)}
    assert a_ids.isdisjoint(b_ids)
    for row in reports(client, a):
        assert row["baseline_report_id"] in ({""} | a_ids)
    for row in reports(client, b):
        assert row["baseline_report_id"] in ({""} | b_ids)
    # ...and neither can be pointed at the other's newest report
    assert scan(client, token, a,
                baseline_report_id=sorted(b_ids)[0]).status_code == 400


# ---- unit-level: the pieces the API composes ---------------------------------------


def test_scan_argv_never_asks_for_new_only_without_a_baseline():
    out, src = Path("out"), Path("src")
    with pytest.raises(lib_mod.LibraryStoreError):
        scan_argv(src, out, online=False, semgrep=False, new_only=True)
    argv = scan_argv(src, out, online=False, semgrep=False,
                     baseline=Path("b.json"), new_only=True)
    assert argv[argv.index("--baseline") + 1] == "b.json"
    assert argv.index("--new-only") > argv.index("--baseline")


def test_baseline_row_fields_refuses_a_report_that_did_something_else():
    full = {"baseline": {"enabled": True, "gate_scope": "all", "new": 1,
                         "unchanged": 2, "resolved": 3}}
    rid = "d" * 16
    assert baseline_row_fields(full, baseline_report_id=rid,
                               new_only=False) == {
        "baseline_report_id": rid, "baseline_enabled": True,
        # the baseline held everything that matched plus everything that is
        # gone — recorded so the row can be checked without it
        "baseline_findings": 5,
        "gate_scope": "all", "new": 1, "unchanged": 2, "resolved": 3}
    # gated on a different scope than the one requested
    assert baseline_row_fields(full, baseline_report_id=rid,
                               new_only=True) is None
    # asked for a comparison, got none
    assert baseline_row_fields({}, baseline_report_id=rid,
                               new_only=False) is None
    # a comparison nobody asked for
    assert baseline_row_fields(full, baseline_report_id="",
                               new_only=False) is None
    # counts that are not counts
    broken = {"baseline": {"enabled": True, "gate_scope": "all", "new": "1",
                           "unchanged": 2, "resolved": 3}}
    assert baseline_row_fields(broken, baseline_report_id=rid,
                               new_only=False) is None
    # no comparison requested and none made
    assert baseline_row_fields({}, baseline_report_id="", new_only=False) == {
        "baseline_report_id": "", "baseline_enabled": False, "new": 0,
        "baseline_findings": 0,
        "unchanged": 0, "resolved": 0, "gate_scope": "all"}


def test_resolve_baseline_releases_every_lease_it_does_not_return(tmp_path):
    """A refusal must not leave the report leased, or a damaged report would
    wedge deletion forever — the one thing that would make the fail-closed
    rule worse than the silent fallback it replaced."""
    paths = LibraryPaths(tmp_path / "library")
    store = LibraryStore(paths.store_path())
    paths.root.mkdir(parents=True)
    project = _project_row(new_id())
    store.put_project(project)
    pid = project["project_id"]
    held: dict[str, int] = {}

    def hold(rid: str) -> str | None:
        held[rid] = held.get(rid, 0) + 1
        return None

    def release(rid: str) -> None:
        held[rid] = held[rid] - 1
        if not held[rid]:
            held.pop(rid)

    def resolve(**over):
        kw = {"requested_id": "", "compare_previous": True,
              "new_only": False, "hold": hold, "release": release, **over}
        return resolve_baseline(store, paths, pid, **kw)

    # no history at all: nothing to hold, nothing to release
    assert resolve() == ("", None)
    assert held == {}
    with pytest.raises(BaselineRefused):
        resolve(new_only=True)
    assert held == {}

    # three reports, none of them readable on disk
    ids = []
    for _ in range(3):
        row = _report_row(pid)
        store.put_report(row)
        ids.append(row["report_id"])
    with pytest.raises(BaselineRefused) as refusal:
        resolve()
    assert refusal.value.status == 409
    assert held == {}                              # the newest was given back
    with pytest.raises(BaselineRefused):
        resolve(requested_id=ids[0])               # explicit: same discipline
    assert held == {}

    # a hold that is REFUSED must not be released as though it were taken
    def refusing_hold(rid: str) -> str | None:
        return "report is being deleted"
    with pytest.raises(BaselineRefused) as conflict:
        resolve(hold=refusing_hold)
    assert conflict.value.status == 409
    assert held == {}


def test_the_runner_refuses_a_baseline_it_was_not_given_a_path_for(tmp_path):
    paths = LibraryPaths(tmp_path / "library")
    store = LibraryStore(paths.store_path())
    paths.root.mkdir(parents=True)
    project = _project_row(new_id())
    store.put_project(project)
    runner = JobRunner(store, paths, spawn=RealScanSpawn())

    with pytest.raises(lib_mod.LibraryStoreError):
        runner.start(project, "scan", baseline_report_id="d" * 16)
    with pytest.raises(lib_mod.LibraryStoreError):
        runner.start(project, "scan", baseline_path=tmp_path / "r.json")
    with pytest.raises(lib_mod.LibraryStoreError):
        runner.start(project, "scan", new_only=True)
    assert store.active_job() is None              # nothing was persisted


# ---- 15. single-report mode is untouched ------------------------------------------


def test_plain_serve_mode_has_no_library_endpoints(tmp_path):
    from auditor.web.app import create_app
    report = tmp_path / "report.json"
    report.write_text(json.dumps({
        "summary": {"counts": {}, "verdict": "pass"},
        "analysis_manifest": {"catalog": [], "execution": {"projects": []},
                              "policy": {}},
        "projects": [{"language": "python", "root": ".", "findings": []}],
    }), encoding="utf-8")
    client = TestClient(create_app(report))

    assert client.get("/api/report").status_code == 200
    assert client.get("/api/library/projects").status_code == 404
    assert client.post("/api/library/projects/x/scans",
                       json={}).status_code in (404, 405)


def test_the_retention_cap_is_still_what_it_was():
    assert MAX_REPORTS_PER_PROJECT == 10


# ---- the ordering the default baseline depends on ---------------------------------


def test_row_stamps_carry_milliseconds():
    """The counter-case, stated as the property that fixes it. Found while
    writing these tests: a small project scans in well under a second, so
    second-granularity stamps tied, the tie broke on the RANDOM report id,
    and "the newest report" — the default baseline — was a coin flip.

    This is asserted on the FORMAT rather than on two live scans: two real
    scans usually land in different seconds anyway, so an end-to-end check
    alone would pass even with the precision taken back out."""
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z",
                        lib_mod._now_iso())


def test_two_scans_inside_one_second_still_order_correctly(tmp_path):
    """The end-to-end half: consecutive rescans chain onto each other in the
    order they ran."""
    client, token, app, allowed, spawn = make_client(tmp_path)
    src = make_source(allowed)
    pid = register(client, token, src)

    ids = []
    for _ in range(4):
        r = scan(client, token, pid)
        ids.append(client.get(f"/api/library/scans/{r.json()['job_id']}")
                   .json()["job"]["report_id"])
    stamps = [row["created_at"] for row in reports(client, pid)]
    assert len(set(stamps)) == 4                   # no two rows tie
    assert [r["report_id"] for r in reports(client, pid)] == ids[::-1]
    # every rescan compared against the one immediately before it
    chain = [r["baseline_report_id"] for r in reports(client, pid)][::-1]
    assert chain == [""] + ids[:-1]


def test_the_order_is_the_committed_sequence_not_the_clock(tmp_path,
                                                           monkeypatch):
    """The counter-case, in the form that killed the old answer: freeze the
    clock so every row carries an IDENTICAL stamp. Under timestamp ordering
    the tie fell through to `report_id` — `secrets.token_hex` — and "newest"
    became a coin flip (measured: the truly-last report won 30.5-38.3 % of
    the time over 600 migrated stores, against a uniform 33.3 %)."""
    monkeypatch.setattr(lib_mod, "_now_iso",
                        lambda: "2026-01-01T00:00:02.000Z")
    store = LibraryStore(tmp_path / "library.json")
    project = _project_row()
    store.put_project(project)
    pid = project["project_id"]

    inserted = []
    for n in range(8):
        row = _report_row(pid, created_at=lib_mod._now_iso(), findings=n)
        store.put_report(row)
        inserted.append(row["report_id"])

    stamps = {r["created_at"] for r in store.reports_for(pid)}
    assert stamps == {"2026-01-01T00:00:02.000Z"}   # every row ties
    assert [r["report_id"] for r in store.reports_for(pid)] == inserted[::-1]
    assert [r["seq"] for r in store.reports_for(pid)] == list(range(8, 0, -1))

    # ...and it is the same after a reload, because the order is IN the file
    reloaded = LibraryStore(store._path)
    assert [r["report_id"] for r in reloaded.reports_for(pid)] \
        == inserted[::-1]
    # the default baseline of the next scan is the one that really was last
    assert reloaded.reports_for(pid)[0]["report_id"] == inserted[-1]


def test_a_legacy_store_gets_one_frozen_order_not_a_fresh_guess(tmp_path):
    """`library-1` stamps only resolve to the second, so the order inside a
    second is genuinely unknown. It is decided ONCE, at migration, and
    persisted — re-deriving it per load would let "newest" change under a
    user who only restarted the server."""
    p = tmp_path / "library.json"
    project = _project_row()
    same_second = "2026-07-30T10:00:00Z"
    rows = {rid: {"report_id": rid, "project_id": project["project_id"],
                  "created_at": same_second, "verdict": "pass",
                  "findings": n, "duration_ms": 1}
            for n, rid in enumerate(("f" * 16, "0" * 16, "a" * 16))}
    p.write_text(json.dumps({"schema_version": "library-1",
                             "projects": {project["project_id"]: project},
                             "reports": rows, "jobs": {}}), encoding="utf-8")

    first = LibraryStore(p)
    assert first.available, first.error
    order = [r["report_id"] for r in first.reports_for(project["project_id"])]
    seqs = sorted(r["seq"] for r in first.reports_for(project["project_id"]))
    assert seqs == [1, 2, 3]                        # a real order was assigned
    for _ in range(3):                              # and it never moves again
        again = LibraryStore(p)
        assert [r["report_id"] for r in
                again.reports_for(project["project_id"])] == order
