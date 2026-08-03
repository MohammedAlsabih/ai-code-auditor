"""LIBRARY-REFACTOR-1A2: the two concurrency contracts.

Every wait here is on a `threading.Event`. There is not one `sleep` in this
file: a test that passes because a thread happened to be slow is not evidence
of anything, and the defect these tests cover was itself an intermittent one.

The two contracts:

A. `POST /scans/{jid}/cancel` answers what the RUNTIME did. It never claims to
   have accepted a cancellation that was refused, and it never signals a job
   that is past being stoppable.
B. A terminal state is not published until the job has released its baseline
   lease, deleted its tmp directory and freed the runner slot.
"""
from __future__ import annotations

import threading
from pathlib import Path

import pytest

from auditor.web.library_runtime import (CANCEL_ACCEPTED,
                                         CANCEL_ALREADY_REQUESTED,
                                         CANCEL_NOT_ACTIVE)
from auditor.web.library_app import CONTROL_HEADER
from test_library_baseline import make_client, make_source, register, scan


def H(token):
    return {CONTROL_HEADER: token}


class Paused:
    """Freeze the job thread at a chosen store write, deterministically.

    `reached` is set once the write has happened; the thread then blocks on
    `release` until the test lets it go. The window between the terminal
    commit and the unwind is exactly what the old code published from."""

    def __init__(self, store, method: str, *, skip: int = 0) -> None:
        self.reached = threading.Event()
        self.release = threading.Event()
        self._store = store
        self._method = method
        self._real = getattr(store, method)
        self._skip = skip
        self._seen = 0
        setattr(store, method, self)

    def __call__(self, *args, **kwargs):
        out = self._real(*args, **kwargs)
        self._seen += 1
        if self._seen <= self._skip:
            return out          # e.g. the PENDING row, written by the caller
        self.reached.set()
        assert self.release.wait(30), "the test never released the job"
        return out

    def restore(self) -> None:
        setattr(self._store, self._method, self._real)


@pytest.fixture
def lib(tmp_path: Path):
    client, token, app, allowed, spawn = make_client(tmp_path)
    yield client, token, app, allowed
    # never leave a frozen job behind for the next test
    jid = app.library.runner.active_job_id()
    if jid:
        app.library.runner.wait(jid, timeout=30)


def _start(client, token, pid):
    r = client.post(f"/api/library/projects/{pid}/scans", json={}, headers=H(token))
    assert r.status_code == 202, r.text
    return r.json()["job_id"]


# ---- A. the cancel contract ----------------------------------------------------------

def test_an_unknown_job_id_is_404(lib):
    client, token, app, allowed = lib
    r = client.post("/api/library/scans/0123456789abcdef/cancel",
                    headers=H(token))
    assert r.status_code == 404


def test_a_terminal_job_can_no_longer_be_canceled(lib):
    """The defect: this answered 200 `cancel_requested: true` for a job that
    had finished, while `runner.cancel` had returned False."""
    client, token, app, allowed = lib
    pid = register(client, token, make_source(allowed))
    jid = scan(client, token, pid).json()["job_id"]
    assert client.get(f"/api/library/scans/{jid}").json()["job"]["state"] \
        == "completed"

    assert app.library.runner.cancel(jid) == CANCEL_NOT_ACTIVE
    r = client.post(f"/api/library/scans/{jid}/cancel", headers=H(token))
    assert r.status_code == 409
    assert "cancel" in r.json()["error"]
    # the safe message names no path, no pid, no process
    assert str(tmp_free(r.json()["error"])) == r.json()["error"]


def tmp_free(msg: str) -> str:
    assert ":" not in msg and "\\" not in msg and "/" not in msg, msg
    return msg


def test_a_job_being_finalized_is_refused_and_nothing_is_killed(lib):
    """MANDATORY, the race direction the old code got wrong: the terminal row
    is committed and the thread is still unwinding. There is nothing left to
    stop, and the process is already gone — so a kill here would be aimed at
    a pid that may since have been reused."""
    client, token, app, allowed = lib
    pid = register(client, token, make_source(allowed))
    paused = Paused(app.library.store, "put_report_and_finish_job")
    try:
        jid = _start(client, token, pid)
        assert paused.reached.wait(30)

        killed: list[object] = []
        import auditor.web.library_runtime as runtime_mod
        real_kill = runtime_mod.kill_process_tree
        runtime_mod.kill_process_tree = lambda p: killed.append(p)
        try:
            assert app.library.runner.cancel(jid) == CANCEL_NOT_ACTIVE
            r = client.post(f"/api/library/scans/{jid}/cancel",
                            headers=H(token))
            assert r.status_code == 409
            assert killed == [], "a finalizing job must never be signalled"
        finally:
            runtime_mod.kill_process_tree = real_kill
    finally:
        paused.release.set()
        paused.restore()
    app.library.runner.wait(jid, timeout=30)


def test_a_repeat_cancel_is_idempotent_and_honest(lib):
    """The second request does not kill anything a second time, and it says
    so rather than pretending to be the one that took effect."""
    client, token, app, allowed = lib
    pid = register(client, token, make_source(allowed))
    # call 1 is the PENDING row, written inside the POST itself; call 2 is
    # the job thread moving to `running`, which is where a cancel is live
    paused = Paused(app.library.store, "put_job", skip=1)
    try:
        jid = _start(client, token, pid)
        assert paused.reached.wait(30)
        first = client.post(f"/api/library/scans/{jid}/cancel", headers=H(token))
        second = client.post(f"/api/library/scans/{jid}/cancel", headers=H(token))
        assert first.status_code == 202
        assert first.json()["cancel_requested"] is True
        assert first.json()["already_requested"] is False
        assert second.status_code == 202
        assert second.json()["cancel_requested"] is True
        assert second.json()["already_requested"] is True
    finally:
        paused.release.set()
        paused.restore()
    app.library.runner.wait(jid, timeout=30)


def test_the_endpoint_never_announces_a_cancel_the_runtime_refused(lib):
    """The property behind the whole contract: a 2xx from this endpoint
    implies the runtime accepted, for every reachable runtime answer."""
    client, token, app, allowed = lib
    pid = register(client, token, make_source(allowed))
    jid = scan(client, token, pid).json()["job_id"]
    for outcome, expected in ((CANCEL_ACCEPTED, 202),
                              (CANCEL_ALREADY_REQUESTED, 202),
                              (CANCEL_NOT_ACTIVE, 409)):
        app.library.runner.cancel = lambda _j, _o=outcome: _o
        r = client.post(f"/api/library/scans/{jid}/cancel", headers=H(token))
        assert r.status_code == expected, outcome
        if r.status_code == 202:
            assert r.json()["cancel_requested"] is True
        else:
            assert "cancel_requested" not in r.json()


# ---- B. terminal is published only after the unwind ----------------------------------

def test_terminal_is_not_published_while_the_runner_still_holds_the_job(lib):
    """MANDATORY. At the moment the terminal row is committed the job still
    owns the slot, the baseline lease and its tmp directory. The API must not
    call that finished."""
    client, token, app, allowed = lib
    pid = register(client, token, make_source(allowed))
    scan(client, token, pid)                              # a baseline exists
    base = client.get(f"/api/library/projects/{pid}/reports"
                      ).json()["reports"][0]["report_id"]

    paused = Paused(app.library.store, "put_report_and_finish_job")
    try:
        jid = _start(client, token, pid)
        assert paused.reached.wait(30)

        job = client.get(f"/api/library/scans/{jid}").json()["job"]
        assert job["state"] == "running", "not terminal until the unwind ends"
        assert job["finalizing"] is True
        # the STORE already holds the terminal row — the transaction is
        # unchanged; only its visibility is gated
        assert app.library.store.job(jid)["state"] == "completed"
        # and every resource is provably still held
        assert app.library.runner.is_unwinding(jid) is True
        assert client.delete(f"/api/library/reports/{base}?confirm=true",
                             headers=H(token)).status_code == 409
        assert client.post(f"/api/library/projects/{pid}/scans", json={},
                           headers=H(token)).status_code == 409
    finally:
        paused.release.set()
        paused.restore()

    app.library.runner.wait(jid, timeout=30)
    job = client.get(f"/api/library/scans/{jid}").json()["job"]
    assert job["state"] == "completed" and job["finalizing"] is False


def test_after_the_unwind_the_next_scan_starts_immediately(lib):
    """MANDATORY, and the retention flake's fix: a caller that waits for a
    terminal state may start the next scan at once. Deterministically — the
    terminal state IS the signal that the slot is free."""
    client, token, app, allowed = lib
    pid = register(client, token, make_source(allowed))
    for _ in range(5):
        jid = _start(client, token, pid)
        job = _poll_terminal(client, jid)
        assert job["state"] == "completed"
        assert job["finalizing"] is False
        assert app.library.runner.active_job_id() is None
        assert app.library.runner.is_unwinding(jid) is False


def _poll_terminal(client, jid, timeout: float = 60.0) -> dict:
    """Exactly what a real caller does: poll until a terminal state. No
    grace period, no retry-on-409 afterwards."""
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = client.get(f"/api/library/scans/{jid}").json()["job"]
        if job["state"] in ("completed", "failed", "canceled", "interrupted"):
            return job
    raise AssertionError("job never reached a terminal state")


def test_the_last_job_view_is_gated_the_same_way(lib):
    """The project list shows `last_job`. It goes through the same gate, or a
    screen could show a scan as finished while it is still unwinding."""
    client, token, app, allowed = lib
    pid = register(client, token, make_source(allowed))
    paused = Paused(app.library.store, "put_report_and_finish_job")
    try:
        jid = _start(client, token, pid)
        assert paused.reached.wait(30)
        row = client.get("/api/library/projects").json()["projects"][0]
        assert row["last_job"]["state"] == "running"
        assert row["last_job"]["finalizing"] is True
    finally:
        paused.release.set()
        paused.restore()
    app.library.runner.wait(jid, timeout=30)


def test_a_failing_unwind_still_frees_the_slot_and_the_lease(lib, monkeypatch):
    """A store failure, an rmtree failure and a kill failure must all leave
    the runner empty and the baseline deletable — otherwise one bad job
    wedges the library for the life of the process."""
    client, token, app, allowed = lib
    pid = register(client, token, make_source(allowed))
    scan(client, token, pid)
    base = client.get(f"/api/library/projects/{pid}/reports"
                      ).json()["reports"][0]["report_id"]

    import auditor.web.library_runtime as runtime_mod
    from auditor.web.library_store import LibraryPaths

    # Break the unwind SPECIFICALLY — the tmp delete and the kill. Patching
    # `shutil.rmtree` globally instead takes the store's own writes down with
    # it, which proves nothing about the unwind and only makes the library
    # unavailable.
    monkeypatch.setattr(LibraryPaths, "confined_delete",
                        _boom("rmtree failed"))
    monkeypatch.setattr(runtime_mod, "kill_process_tree",
                        _boom("kill failed"))
    jid = _start(client, token, pid)
    app.library.runner.wait(jid, timeout=60)

    # whatever failed, the runner let go of everything
    assert app.library.runner.active_job_id() is None
    assert app.library.runner.is_unwinding(jid) is False
    monkeypatch.undo()
    # the baseline lease was released too: the report is deletable again
    assert client.delete(f"/api/library/reports/{base}?confirm=true",
                         headers=H(token)).status_code in (200, 404)
    # and the library still accepts work
    assert client.post(f"/api/library/projects/{pid}/scans", json={},
                       headers=H(token)).status_code == 202


def _boom(msg: str):
    def raiser(*_a, **_k):
        raise OSError(msg)
    return raiser


# ---- the post-subprocess window, and both race directions -----------------------------

class PausedLoad:
    """Freeze the job thread inside post-processing: the subprocess has
    EXITED and the report is being read. Nothing here is cancellable, but
    nothing here has written a terminal row either."""

    def __init__(self, monkeypatch) -> None:
        import auditor.web.app as app_mod
        self.reached = threading.Event()
        self.release = threading.Event()
        real = app_mod.load_report

        def paused(path):
            out = real(path)
            self.reached.set()
            assert self.release.wait(30), "the test never released the job"
            return out

        monkeypatch.setattr(app_mod, "load_report", paused)


def test_post_processing_is_finalizing_and_cannot_be_canceled(lib, monkeypatch):
    """CLOSING DEFECT 1. Between the subprocess exiting and the terminal
    write there is load_report, validation and promotion. That window used to
    report itself cancellable: `cancel` returned ACCEPTED, the endpoint
    answered 202, and the job completed anyway — a cancellation accepted that
    changed nothing."""
    client, token, app, allowed = lib
    pid = register(client, token, make_source(allowed))
    paused = PausedLoad(monkeypatch)

    import auditor.web.library_runtime as runtime_mod
    kills: list[object] = []
    monkeypatch.setattr(runtime_mod, "kill_process_tree",
                        lambda p: kills.append(p))

    jid = _start(client, token, pid)
    assert paused.reached.wait(60)

    # the store row is STILL `running` here — this is not the unwind
    assert app.library.store.job(jid)["state"] == "running"
    assert app.library.runner.is_finalizing(jid) is True

    assert app.library.runner.cancel(jid) == CANCEL_NOT_ACTIVE
    r = client.post(f"/api/library/scans/{jid}/cancel", headers=H(token))
    assert r.status_code == 409
    assert kills == [], "nothing may be signalled once the outcome is settled"

    job = client.get(f"/api/library/scans/{jid}").json()["job"]
    assert job["state"] == "running" and job["finalizing"] is True

    paused.release.set()
    app.library.runner.wait(jid, timeout=60)
    job = client.get(f"/api/library/scans/{jid}").json()["job"]
    assert job["state"] == "completed", "the refusal did not change the result"
    assert job["finalizing"] is False


def test_a_cancel_that_wins_the_lock_actually_cancels(tmp_path):
    """RACE DIRECTION 1: the cancel takes `active.lock` before the process
    finishes. It must be honoured — the job ends `canceled`.

    Its own client, because it needs a subprocess that blocks until the test
    says otherwise."""
    started, release = threading.Event(), threading.Event()

    class Blocking:
        pid = 4242

        def wait(self, timeout=None):
            started.set()
            assert release.wait(30)
            return 0

        def kill(self):
            release.set()

    def spawn(argv, cwd, stdout_path, stderr_path, env):
        Path(stdout_path).write_bytes(b"")
        Path(stderr_path).write_bytes(b"")
        return Blocking()

    client, token, app, allowed, _ = make_client(tmp_path, spawn=spawn)
    pid = register(client, token, make_source(allowed))
    jid = _start(client, token, pid)
    assert started.wait(30)

    r = client.post(f"/api/library/scans/{jid}/cancel", headers=H(token))
    assert r.status_code == 202
    release.set()
    app.library.runner.wait(jid, timeout=60)
    assert client.get(f"/api/library/scans/{jid}").json()["job"]["state"] \
        == "canceled"


def test_a_completion_that_wins_the_lock_refuses_the_cancel(lib, monkeypatch):
    """RACE DIRECTION 2: the process finishes first, so cancellability closes
    in the same critical section that reads it. The later cancel is refused
    with 409 and the job completes."""
    client, token, app, allowed = lib
    pid = register(client, token, make_source(allowed))
    paused = PausedLoad(monkeypatch)
    jid = _start(client, token, pid)
    assert paused.reached.wait(60)
    assert client.post(f"/api/library/scans/{jid}/cancel",
                       headers=H(token)).status_code == 409
    paused.release.set()
    app.library.runner.wait(jid, timeout=60)
    assert client.get(f"/api/library/scans/{jid}").json()["job"]["state"] \
        == "completed"


# ---- a kill that really fails ---------------------------------------------------------

def test_a_failing_kill_does_not_break_the_endpoint(tmp_path, monkeypatch):
    """CLOSING DEFECT 2. `kill_process_tree` can raise for real — a pid that
    already exited, a permission error. The exception escaped `cancel` and
    turned POST /cancel into a 500, losing the fact that the cancellation had
    already been RECORDED.

    Delivery of the signal is best-effort; the record is not. The call
    counter is asserted, so this test cannot pass without the kill having
    genuinely been attempted."""
    started, release = threading.Event(), threading.Event()
    kills: list[object] = []

    class Blocking:
        pid = 4243

        def wait(self, timeout=None):
            started.set()
            assert release.wait(30)
            return 0

        def kill(self):
            pass

    def spawn(argv, cwd, stdout_path, stderr_path, env):
        Path(stdout_path).write_bytes(b"")
        Path(stderr_path).write_bytes(b"")
        return Blocking()

    def exploding_kill(proc):
        kills.append(proc)
        raise OSError("kill failed")

    client, token, app, allowed, _ = make_client(tmp_path, spawn=spawn)
    import auditor.web.library_runtime as runtime_mod
    monkeypatch.setattr(runtime_mod, "kill_process_tree", exploding_kill)

    pid = register(client, token, make_source(allowed))
    jid = _start(client, token, pid)
    assert started.wait(30)

    first = client.post(f"/api/library/scans/{jid}/cancel", headers=H(token))
    assert first.status_code == 202, "no exception may escape the endpoint"
    assert len(kills) == 1, "the kill was genuinely attempted once"

    # idempotent, and it does NOT retry the kill
    second = client.post(f"/api/library/scans/{jid}/cancel", headers=H(token))
    assert second.status_code == 202
    assert second.json()["already_requested"] is True
    assert len(kills) == 1, "a repeat must not re-signal"

    # the logical cancellation survived the failed signal
    release.set()
    app.library.runner.wait(jid, timeout=60)
    job = client.get(f"/api/library/scans/{jid}").json()["job"]
    assert job["state"] == "canceled"
    assert job["finalizing"] is False
    assert app.library.runner.active_job_id() is None
    assert client.post(f"/api/library/projects/{pid}/scans", json={},
                       headers=H(token)).status_code == 202
