"""The Project Library's runtime: the single active job, its
subprocess, its cancellation, the leases it holds, and retention.

LIBRARY-REFACTOR-1A1. This is the only module that starts a process, takes a
lease, or deletes a report. Everything it records goes through the store;
everything it validates comes from the contract.
"""
from __future__ import annotations

import os
import subprocess  # noqa: S404 - argv lists only, shell=False everywhere
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

# By name for the pure contracts; as a module for what a test replaces —
# `_now_iso` (job timestamps) and `MAX_REPORTS_PER_PROJECT` (the
# retention cap, lowered to 1 to exercise pruning).
from auditor.web import library_contract as contract
from auditor.web.library_contract import (
    ERROR_MAX_CHARS,
    JOB_KINDS,
    OUTPUT_TAIL_BYTES,
    REPORT_INPUT_KEYS,
    LibraryStoreError,
    _valid_report,
    baseline_row_fields,
    git_clone_argv,
    job_env,
    job_timeout,
    new_id,
    scan_argv,
)
from auditor.web.library_store import LibraryPaths, LibraryStore

# ---- jobs ----------------------------------------------------------------------------

def _default_spawn(argv: list[str], cwd: Path, stdout_path: Path,
                   stderr_path: Path, env: dict[str, str]) -> Any:
    """Real subprocess launcher: argv list, shell NEVER, stdin closed,
    output to bounded-read files, own process group on Windows so the whole
    tree can be killed."""
    creation = 0
    if sys.platform == "win32":
        creation = subprocess.CREATE_NEW_PROCESS_GROUP
    with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
        return subprocess.Popen(          # noqa: S603 - fixed argv, no shell
            argv, cwd=str(cwd), env=env, stdin=subprocess.DEVNULL,
            stdout=out, stderr=err, shell=False, creationflags=creation)


def kill_process_tree(proc: Any) -> None:
    """Terminate the job process AND its children. On Windows a plain
    terminate() orphans grandchildren (git spawns helpers), so taskkill /T
    is used; elsewhere kill() on the group leader suffices for our argv."""
    try:
        if sys.platform == "win32":
            subprocess.run(              # noqa: S603 - fixed argv, no shell
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True, shell=False, timeout=30)
        else:
            proc.kill()
    except (OSError, subprocess.SubprocessError):
        try:
            proc.kill()
        except OSError:
            pass


def tail_of(path: Path, cap: int = OUTPUT_TAIL_BYTES) -> str:
    """Bounded read of a captured stream file: the LAST `cap` bytes only."""
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            if size > cap:
                fh.seek(size - cap)
            return fh.read(cap).decode("utf-8", errors="replace")
    except OSError:
        return ""


@dataclass
class _ActiveJob:
    job_id: str
    project_id: str = ""
    proc: Any = None
    cancel_requested: bool = False
    thread: threading.Thread | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)
    # W4-B. The id is persisted on the job row; the PATH is not — it exists
    # only for the argv of this one subprocess and never reaches the store,
    # the API, or an error message.
    baseline_report_id: str = ""
    baseline_path: Path | None = None
    new_only: bool = False


class JobRunner:
    """One clone/scan job at a time. State machine per the contract:
    pending → running → completed | failed | canceled; a restart turns any
    persisted active job into `interrupted` (LibraryStore._load). A new
    report is validated and promoted ATOMICALLY; any failure keeps the last
    good report and leaves no tmp litter."""

    def __init__(self, store: LibraryStore, paths: LibraryPaths,
                 spawn: Callable[..., Any] | None = None,
                 env: dict[str, str] | None = None,
                 reserve: Callable[[list[str]], str | None] | None = None,
                 release: Callable[[list[str]], None] | None = None,
                 release_baseline: Callable[[str], None] | None = None
                 ) -> None:
        self._store = store
        self._paths = paths
        self._spawn = spawn if spawn is not None else _default_spawn
        self._env = env
        # W4-B: the baseline lease is TAKEN by the caller (it has to be, to
        # keep resolution and leasing one step) and handed over on a
        # successful start(); from then on this runner owns it and releases
        # it exactly once, in the job thread's finally.
        self._release_baseline = release_baseline
        # W4-A closing: retention takes the SAME deletion lease as manual
        # deletion (reserve -> delete files -> metadata -> release in
        # finally). reserve returns a safe refusal reason or None; a report
        # whose context is cached (even idle) is refused and kept above the
        # retention cap temporarily.
        self._reserve = reserve
        self._release = release
        self._lock = threading.Lock()
        self._active: _ActiveJob | None = None

    # -- public ------------------------------------------------------------

    def start(self, project: dict[str, Any], kind: str, *,
              online: bool = False, semgrep: bool = False,
              register_project: bool = False,
              baseline_report_id: str = "", baseline_path: Path | None = None,
              new_only: bool = False) -> str:
        """Start a job. With register_project=True the project row itself is
        committed IN THE SAME store transaction as the job, under the SAME
        runner slot reservation — a busy runner or a store failure leaves
        zero project rows, zero directories, zero subprocesses (the
        active-slot check and the commit happen inside one lock, so there is
        no separate racy pre-check).

        W4-B: `baseline_report_id`/`baseline_path` must already be resolved
        and leased by the caller. A raise here means the lease did NOT
        transfer and the caller still owns it."""
        if kind not in JOB_KINDS:
            raise LibraryStoreError("unknown job kind")
        if bool(baseline_report_id) != (baseline_path is not None):
            raise LibraryStoreError("baseline id and path must agree")
        if new_only and not baseline_report_id:
            raise LibraryStoreError("gating new findings only requires a "
                                    "baseline")
        with self._lock:
            if self._active is not None:
                raise LibraryStoreError("another job is already running")
            jid = new_id()
            row = {"job_id": jid, "project_id": project["project_id"],
                   "kind": kind, "state": "pending", "online": online,
                   "semgrep": semgrep, "created_at": contract._now_iso(),
                   "started_at": "", "finished_at": "", "error": "",
                   "report_id": "",
                   "baseline_report_id": baseline_report_id,
                   "new_only": new_only}
            # raises before the slot is taken — nothing persisted on failure
            if register_project:
                self._store.put_project_and_job(project, row)
            else:
                self._store.put_job(row)
            active = _ActiveJob(job_id=jid,
                                project_id=project["project_id"],
                                baseline_report_id=baseline_report_id,
                                baseline_path=baseline_path,
                                new_only=new_only)
            self._active = active
        thread = threading.Thread(
            target=self._run, args=(active, project, row), daemon=True)
        active.thread = thread
        thread.start()
        return jid

    def cancel(self, jid: str) -> bool:
        with self._lock:
            active = self._active
        if active is None or active.job_id != jid:
            return False
        with active.lock:
            active.cancel_requested = True
            proc = active.proc
        if proc is not None:
            kill_process_tree(proc)
        return True

    def wait(self, jid: str, timeout: float = 30.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                active = self._active
            if active is None or active.job_id != jid:
                return
            time.sleep(0.02)

    def active_job_id(self) -> str | None:
        with self._lock:
            return self._active.job_id if self._active else None

    def active_project_id(self) -> str | None:
        """The project whose job currently holds the runner slot, in-memory
        and authoritative — set the instant a job is accepted and cleared
        only after the job thread fully unwinds. Unlike store.active_job()
        (which reads the persisted row state), this still reports the
        project during a job's cancel/finish transition, so a removal
        checking it never races the slot to an orphan."""
        with self._lock:
            return self._active.project_id if self._active else None

    # -- internals ----------------------------------------------------------

    @staticmethod
    def _terminal(row: dict[str, Any], state: str, *, error: str = "",
                  report_id: str = "") -> dict[str, Any]:
        row = dict(row)
        row["state"] = state
        row["finished_at"] = contract._now_iso()
        row["error"] = error[:ERROR_MAX_CHARS]
        row["report_id"] = report_id
        return row

    def _finish(self, row: dict[str, Any], state: str, *,
                error: str = "", report_id: str = "") -> None:
        """Record a job's final state. If it cannot be recorded, the store
        is declared unavailable.

        This used to swallow the failure with the comment "job outcome is
        best-effort metadata". It is not: it is the only record of whether a
        scan finished, and of which report it produced. Losing it silently
        left a finished job reading `running` for the life of the process
        and `interrupted` after a restart — while its report sat in the
        library, eligible to be the next scan's baseline."""
        try:
            self._store.put_job(self._terminal(row, state, error=error,
                                               report_id=report_id))
        except LibraryStoreError:
            self._store.mark_unavailable(
                "a job's final state could not be recorded, so the library "
                "no longer describes what has run")

    def _run(self, active: _ActiveJob, project: dict[str, Any],
             row: dict[str, Any]) -> None:
        tmp = self._paths.tmp_dir(active.job_id)
        try:
            self._execute(active, project, row, tmp)
        except BaseException:          # noqa: BLE001 - the slot MUST free
            self._finish(row, "failed", error="internal job error")
        finally:
            self._paths.confined_delete(tmp)
            # W4-B: the baseline lease is released on EVERY exit — success,
            # failure, cancellation, or an internal error — and after the
            # retention prune inside _execute, so a scan can never delete the
            # report it was still comparing against.
            if active.baseline_report_id and self._release_baseline is not None:
                self._release_baseline(active.baseline_report_id)
            with self._lock:
                if self._active is active:
                    self._active = None

    def _source_dir(self, project: dict[str, Any]) -> Path | None:
        if project["kind"] == "git":
            src = self._paths.clone_dir(project["project_id"])
            return src if src.is_dir() else None
        p = Path(project["local_path"])
        return p if p.is_dir() else None

    def _execute(self, active: _ActiveJob, project: dict[str, Any],
                 row: dict[str, Any], tmp: Path) -> None:
        row = dict(row)
        row["state"] = "running"
        row["started_at"] = contract._now_iso()
        try:
            self._store.put_job(row)
        except LibraryStoreError:
            # Nothing has been created yet and nothing has been spawned. If
            # the store cannot even record that this job started, a running
            # subprocess would be invisible to every later reader — so it is
            # not started at all. `_run`'s finally frees the slot and the
            # baseline lease; the row stays `pending` on disk and a restart
            # turns it into `interrupted` under the existing contract.
            self._store.mark_unavailable(
                "a job's start could not be recorded, so no scan was run")
            return
        tmp.mkdir(parents=True, exist_ok=True)
        stdout_p, stderr_p = tmp / "stdout.log", tmp / "stderr.log"

        if row["kind"] == "clone":
            dest = tmp / "src"
            argv = git_clone_argv(project["git_url"], dest)
            ok, reason = self._wait_proc(active, argv, tmp, stdout_p,
                                         stderr_p, allow_rc=(0,))
            if not ok:
                self._finish(row, "canceled" if reason == "canceled"
                             else "failed", error=reason)
                return
            final = self._paths.clone_dir(project["project_id"])
            if not self._paths.confined_delete(final):
                self._finish(row, "failed", error="clone promotion failed")
                return
            try:
                final.parent.mkdir(parents=True, exist_ok=True)
                os.replace(dest, final)
            except OSError:
                self._finish(row, "failed", error="clone promotion failed")
                return
            self._finish(row, "completed")
            return

        # scan
        src = self._source_dir(project)
        if src is None:
            self._finish(row, "failed",
                         error="project source is not available")
            return
        out_dir = tmp / "out"
        argv = scan_argv(src, out_dir, online=row["online"],
                         semgrep=row["semgrep"],
                         baseline=active.baseline_path,
                         new_only=active.new_only)
        started = time.monotonic()
        # the scan CLI exits non-zero on block/review verdicts — those are
        # REPORTS, not failures. Any rc is fine as long as report.json is
        # valid; a missing/invalid report is the failure signal.
        ok, reason = self._wait_proc(active, argv, tmp, stdout_p, stderr_p,
                                     allow_rc=None)
        if not ok:
            self._finish(row, "canceled" if reason == "canceled"
                         else "failed", error=reason)
            return
        duration_ms = int((time.monotonic() - started) * 1000)
        from auditor.web.app import ReportError, load_report
        report_json = out_dir / "report.json"
        try:
            data = load_report(report_json)
        except ReportError:
            self._finish(row, "failed",
                         error="scan produced no valid report")
            return
        raw_summary = data.get("summary")
        summary: dict[str, Any] = raw_summary \
            if isinstance(raw_summary, dict) else {}
        # W4-B: the comparison is validated against the request BEFORE
        # promotion, so a report that did not do what it was asked to do is
        # never promoted, never recorded, and never shown as a rescan.
        baseline_fields = baseline_row_fields(
            summary, baseline_report_id=active.baseline_report_id,
            new_only=active.new_only)
        if baseline_fields is None:
            self._finish(row, "failed",
                         error="scan did not apply the requested comparison")
            return
        verdict = summary.get("verdict")
        # the WHOLE report's findings, whatever the gate counted. This count
        # and the comparison above come from DIFFERENT parts of the report —
        # the project lists and `summary.baseline` — so requiring
        # `new + unchanged == findings` is a real cross-check, not a tautology.
        findings = sum(len(p.get("findings", []))
                       for p in data.get("projects", [])
                       if isinstance(p, dict)
                       and isinstance(p.get("findings"), list))
        rid = new_id()
        report_row = {"report_id": rid, "project_id": project["project_id"],
                      "created_at": contract._now_iso(),
                      "verdict": verdict if isinstance(verdict, str) else "",
                      "findings": findings, "duration_ms": duration_ms,
                      **baseline_fields}
        # checked BEFORE promotion: a report whose own numbers disagree is
        # never moved into the library at all
        if not _valid_report(report_row, keys=REPORT_INPUT_KEYS):
            self._finish(row, "failed",
                         error="scan produced an inconsistent comparison")
            return
        final_dir = self._paths.report_dir(rid)
        try:
            final_dir.parent.mkdir(parents=True, exist_ok=True)
            os.replace(out_dir, final_dir)
        except OSError:
            self._finish(row, "failed", error="report promotion failed")
            return
        # ONE transaction: the report and the job that claims it, or neither.
        # Committing them separately left an orphan report — usable, and
        # picked as the next scan's baseline — behind a job still reading
        # `running`.
        try:
            self._store.put_report_and_finish_job(
                report_row, self._terminal(row, "completed", report_id=rid))
        except LibraryStoreError:
            # nothing was committed, so the promoted directory has no row to
            # belong to: remove it, and say the library is out of date rather
            # than leave a half-recorded run
            self._paths.confined_delete(final_dir)
            self._store.mark_unavailable(
                "a finished scan could not be recorded, so the library no "
                "longer describes what has run")
            return
        self._prune_reports(project["project_id"])

    def _prune_reports(self, pid: str) -> None:
        """Retention: FILES first, metadata second — the same contract as
        report deletion. A report with a loaded context or an unsafe/failed
        file delete is kept ABOVE the cap temporarily; a files-gone-but-
        store-failed row is retried on the next prune."""
        rows = self._store.reports_for(pid)     # newest first
        for row in rows[contract.MAX_REPORTS_PER_PROJECT:]:
            rid = row["report_id"]
            if self._reserve is not None \
                    and self._reserve([rid]) is not None:
                continue          # loaded/being-deleted: kept above the cap
            try:
                if not self._paths.confined_delete(
                        self._paths.report_dir(rid)):
                    continue                    # keep the metadata aligned
                try:
                    self._store.remove_report(rid)
                except LibraryStoreError:
                    continue                    # retried next prune
            finally:
                if self._release is not None:
                    self._release([rid])        # ALWAYS frees the lease


    def _wait_proc(self, active: _ActiveJob, argv: list[str], cwd: Path,
                   stdout_p: Path, stderr_p: Path,
                   allow_rc: tuple[int, ...] | None) -> tuple[bool, str]:
        """Spawn and wait with timeout + cancel. Returns (ok, safe_reason).
        allow_rc=None accepts ANY return code (the artifact is validated
        separately); otherwise the rc must be in the tuple."""
        env = job_env() if self._env is None else dict(self._env)
        try:
            proc = self._spawn(argv, cwd, stdout_p, stderr_p, env)
        except OSError:
            return False, "the job process could not be started"
        with active.lock:
            if active.cancel_requested:
                kill_process_tree(proc)
                return False, "canceled"
            active.proc = proc
        timeout = job_timeout(self._env)
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            kill_process_tree(proc)
            try:
                proc.wait(timeout=10)
            except (subprocess.TimeoutExpired, OSError):
                pass
            return False, f"timed out after {int(timeout)}s"
        finally:
            with active.lock:
                active.proc = None
        if active.cancel_requested:
            return False, "canceled"
        if allow_rc is not None and rc not in allow_rc:
            return False, f"the job process exited with code {rc}"
        return True, ""
