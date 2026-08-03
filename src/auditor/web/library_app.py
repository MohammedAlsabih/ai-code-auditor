"""W4-A: the Library web application.

One server, many reports. The classic `auditor serve <report>` app is reused
UNCHANGED per report: every report id gets its own sub-application (with its
own reviews/AI sidecars living next to that report.json), and requests to
/api/library/reports/{rid}/... are forwarded to it. There is NO global
"active report" — the report context is explicit in every URL.

Security model (Alpha):
- loopback bind only (the CLI hardcodes the host, like `serve`);
- Host header allowlist (DNS-rebinding guard);
- every MUTATING endpoint requires the in-memory control token, which the
  SPA obtains from same-origin GET /api/library/session (no CORS middleware
  is registered, so a cross-origin page can never read it);
- an Origin header, when present, must be one of this server's own origins;
- browser-supplied paths exist ONLY for local-project registration and are
  validated against the CLI's allowed roots; deletion and report resolution
  work on opaque ids confined to the library root.
"""
from __future__ import annotations

import hmac
import re
import secrets
import shutil
import threading
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from auditor.web.app import _STATIC_DIR, ReportError, _AsciiJSON, create_app
from auditor.web.library_runtime import (
    CANCEL_ACCEPTED,
    CANCEL_ALREADY_REQUESTED,
)
from auditor.web.library import (
    MAX_REPORTS_PER_PROJECT,
    BaselineRefused,
    JobRunner,
    LibraryPaths,
    LibraryStore,
    LibraryStoreError,
    _now_iso as _now,
    bad_git_url,
    new_id,
    repo_name_from_url,
    resolve_baseline,
    resolve_local_registration,
    safe_location,
)

CONTROL_HEADER = "x-auditor-control"
CONTEXT_CACHE_MAX = 4

_FORWARD_RE = re.compile(r"^/api/library/reports/([0-9a-f]{16})/(.+)$")


def _err(status: int, msg: str) -> JSONResponse:
    return _AsciiJSON({"error": msg}, status_code=status)


def _store_down(state: "LibraryState") -> JSONResponse | None:
    """503 with the store's own reason, or None when the store is healthy.

    Every endpoint that reads or writes library metadata goes through this,
    because an unavailable store cannot tell "this id does not exist" from
    "I cannot read the file that would say". Answering 404 asserts the first
    when only the second is known — and the reports are still sitting on
    disk while it says so.

    Two endpoints deliberately do NOT call it. `capabilities` carries
    `store_available`/`store_error` and is how a screen learns WHY everything
    else is refusing; `session` hands back the control token, without which
    the caller could not even authenticate a retry. Neither reads a row."""
    if state.store.available:
        return None
    return _err(503, state.store.error or "library store unavailable")


class ProjectIn(BaseModel):
    """extra='forbid': nothing beyond the declared registration fields can
    be smuggled in (422 before any validation code runs)."""
    model_config = {"extra": "forbid"}

    kind: str
    name: str = ""
    path: str = ""      # local registration only — validated against roots
    url: str = ""       # git registration only — https, no credentials


class ScanIn(BaseModel):
    model_config = {"extra": "forbid"}

    online: bool = False       # registry lookups are an EXPLICIT opt-in
    semgrep: bool = False
    # W4-B. Comparison with the previous scan is the DEFAULT and costs
    # nothing when there is no history. `baseline_report_id` is an opaque id
    # from this project's own history — there is deliberately no field for a
    # path, so a browser can never point the scanner at a file.
    compare_previous: bool = True
    baseline_report_id: str = ""
    new_only: bool = False     # narrowing the gate is an EXPLICIT opt-in


class ConfirmIn(BaseModel):
    model_config = {"extra": "forbid"}

    confirm: bool = False


class _Ctx:
    """One open report context: the classic single-report app plus an
    in-flight request counter so a report can never be deleted while a
    request is being served from it."""

    def __init__(self, app: FastAPI) -> None:
        self.app = app
        self.refs = 0


class LibraryDispatch:
    """ASGI wrapper: /api/library/reports/{rid}/<rest> is forwarded to that
    report's own sub-application (path rewritten to /api/<rest>); everything
    else goes to the library API + SPA. Mutating forwarded requests carry
    the same token/Origin requirements as the library endpoints."""

    def __init__(self, api: FastAPI, library: "LibraryState") -> None:
        self.api = api
        self.library = library

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.api(scope, receive, send)
            return
        m = _FORWARD_RE.match(scope.get("path", ""))
        if m is None:
            await self.api(scope, receive, send)
            return
        rid, rest = m.group(1), m.group(2)
        lib = self.library
        headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                   for k, v in scope.get("headers", [])}
        if scope.get("method", "GET").upper() not in ("GET", "HEAD"):
            reason = lib.guard_headers(headers)
            if reason is not None:
                await _err(403, reason)(scope, receive, send)
                return
        # The forwarder resolves a report id through the store before it can
        # open anything, so it answers the same way the rest of the API does:
        # an unreadable store is 503, never "unknown report id". Checked
        # before acquire_context, so no context is built or cached either.
        down = _store_down(lib)
        if down is not None:
            await down(scope, receive, send)
            return
        ctx, why = lib.acquire_context(rid)
        if ctx is None:
            if why == "deleting":
                await _err(409, "report is being deleted")(scope, receive,
                                                           send)
            else:
                await _err(404, "unknown report id")(scope, receive, send)
            return
        sub_scope = dict(scope)
        sub_scope["path"] = "/api/" + rest
        sub_scope["raw_path"] = sub_scope["path"].encode("ascii",
                                                         errors="ignore")
        try:
            await ctx.app(sub_scope, receive, send)
        finally:
            lib.release_context(rid)


class LibraryState:
    """Server-side state shared by the API routes and the dispatcher."""

    def __init__(self, library_root: Path, allowed_roots: list[Path],
                 port: int, spawn: Any = None,
                 env: dict[str, str] | None = None) -> None:
        self.paths = LibraryPaths(library_root)
        self.store = LibraryStore(self.paths.store_path())
        self._ctx_lock = threading.Lock()
        self._contexts: dict[str, _Ctx] = {}
        self._deleting: set[str] = set()   # deletion leases (under _ctx_lock)
        # W4-B: reports currently serving as a scan baseline, counted, under
        # the SAME lock as the deletion lease — so "is it being deleted?" and
        # "is it being read by a scan?" are answered in one critical section
        # and can never both be true.
        self._baselines: dict[str, int] = {}
        # W4-A closing: project-operation lease, SEPARATE from the report
        # deletion lease and its own lock. Serializes start_scan /
        # remove_project / delete_source per project so a scan can never
        # begin between a removal's active-job check and its store mutation.
        self._proj_lock = threading.Lock()
        self._proj_busy: set[str] = set()
        # retention pruning takes the same lease as manual deletion, with
        # the stricter rule that ANY cached context counts as loaded
        self.runner = JobRunner(self.store, self.paths, spawn=spawn, env=env,
                                reserve=self.reserve_for_prune,
                                release=self.release_delete,
                                release_baseline=self.release_baseline)
        self.allowed_roots = allowed_roots
        self.token = secrets.token_urlsafe(32)
        self.origins = {f"http://127.0.0.1:{port}",
                        f"http://localhost:{port}"}

    # -- security ----------------------------------------------------------

    def guard_headers(self, headers: dict[str, str]) -> str | None:
        """Token + Origin verification from a plain header dict. Runs BEFORE
        any filesystem, network, or subprocess work. Returns a safe refusal
        reason or None."""
        origin = headers.get("origin")
        if origin is not None and origin not in self.origins:
            return "cross-origin requests are refused"
        supplied = headers.get(CONTROL_HEADER, "")
        if not supplied or not hmac.compare_digest(supplied, self.token):
            return "missing or invalid control token"
        return None

    def guard(self, request: Request) -> JSONResponse | None:
        reason = self.guard_headers(
            {k.lower(): v for k, v in request.headers.items()})
        return _err(403, reason) if reason is not None else None

    # -- project-operation lease (W4-A closing) -----------------------------
    # A per-project mutual-exclusion held across a whole scan-start /
    # removal / source-delete. Distinct from the report deletion lease
    # (different lock, different set); the two never merge. No I/O or
    # waiting happens under _proj_lock.

    def reserve_project(self, pid: str) -> bool:
        """Atomically claim the project. Returns False if another operation
        already holds it (the caller answers a stable 409)."""
        with self._proj_lock:
            if pid in self._proj_busy:
                return False
            self._proj_busy.add(pid)
            return True

    def release_project(self, pid: str) -> None:
        """ALWAYS called in finally — success, error, or exception — so a
        failed operation is retryable and never wedges a project id."""
        with self._proj_lock:
            self._proj_busy.discard(pid)

    # -- report contexts ----------------------------------------------------

    def source_dir_for(self, project: dict[str, Any]) -> Path | None:
        if project["kind"] == "git":
            src = self.paths.clone_dir(project["project_id"])
            return src if src.is_dir() else None
        p = Path(project["local_path"])
        return p if p.is_dir() else None

    # -- deletion leases (W4-A closing) --------------------------------------
    # The lease and the context check live in ONE critical section, so the
    # old TOCTOU window (delete passes the in-use check, a request acquires
    # a context, delete removes the files under it) cannot open. No I/O or
    # waiting ever happens while _ctx_lock is held here.

    def reserve_for_delete(self, rids: list[str]) -> str | None:
        """Atomic ALL-OR-NONE lease for manual deletion. Refuses if any id
        is already being deleted, has in-flight requests, or is serving as
        the baseline of a running scan; idle cached contexts are evicted
        inside the same critical section. Returns a safe refusal reason or
        None (all ids leased)."""
        with self._ctx_lock:
            for rid in rids:
                if rid in self._deleting:
                    return "report is being deleted"
                if rid in self._baselines:
                    return "report is in use as a scan baseline"
                ctx = self._contexts.get(rid)
                if ctx is not None and ctx.refs > 0:
                    return "report is currently open"
            for rid in rids:
                self._contexts.pop(rid, None)      # evict the idle context
                self._deleting.add(rid)
            return None

    def reserve_for_prune(self, rids: list[str]) -> str | None:
        """Retention lease: stricter — a report that is in the context
        cache AT ALL (even with refs == 0) counts as loaded and is kept
        above the cap temporarily instead of pruned."""
        with self._ctx_lock:
            for rid in rids:
                if rid in self._deleting:
                    return "report is being deleted"
                if rid in self._baselines:
                    return "report is in use as a scan baseline"
                if rid in self._contexts:
                    return "report context is loaded"
            self._deleting.update(rids)
            return None

    def hold_baseline(self, rid: str) -> str | None:
        """Lease a report as a scan's baseline. Refuses only if it is
        already leased for deletion — the check and the hold are one step,
        so the deleter and the scan can never both believe they won. Held
        for the WHOLE scan, released exactly once by the job thread."""
        with self._ctx_lock:
            if rid in self._deleting:
                return "report is being deleted"
            self._baselines[rid] = self._baselines.get(rid, 0) + 1
            return None

    def release_baseline(self, rid: str) -> None:
        """Counted, so an id is only freed when the LAST holder is done."""
        with self._ctx_lock:
            remaining = self._baselines.get(rid, 0) - 1
            if remaining > 0:
                self._baselines[rid] = remaining
            else:
                self._baselines.pop(rid, None)

    def release_delete(self, rids: list[str]) -> None:
        """ALWAYS called in finally by every lease holder — including
        filesystem or store failures — so a failed deletion is retryable
        and can never wedge a report id."""
        with self._ctx_lock:
            for rid in rids:
                self._deleting.discard(rid)

    def acquire_context(self, rid: str) -> tuple[_Ctx | None, str]:
        """Returns (ctx, "") or (None, reason) where reason is 'deleting'
        (the id is leased for deletion — the caller answers 409, never a
        misleading 404) or 'unknown'."""
        with self._ctx_lock:
            if rid in self._deleting:
                return None, "deleting"
            ctx = self._contexts.get(rid)
            if ctx is not None:
                ctx.refs += 1
                return ctx, ""
            row = self.store.report(rid)
            if row is None:
                return None, "unknown"
            project = self.store.project(row["project_id"])
            repo = self.source_dir_for(project) if project else None
            try:
                app = create_app(self.paths.report_json(rid), repo_root=repo)
            except ReportError:
                return None, "unknown"
            ctx = _Ctx(app)
            ctx.refs += 1
            # bounded cache: evict the oldest idle context beyond the cap
            while len(self._contexts) >= CONTEXT_CACHE_MAX:
                idle = next((k for k, c in self._contexts.items()
                             if c.refs == 0), None)
                if idle is None:
                    break
                del self._contexts[idle]
            self._contexts[rid] = ctx
            return ctx, ""

    def release_context(self, rid: str) -> None:
        with self._ctx_lock:
            ctx = self._contexts.get(rid)
            if ctx is not None and ctx.refs > 0:
                ctx.refs -= 1

    def context_in_use(self, rid: str) -> bool:
        with self._ctx_lock:
            ctx = self._contexts.get(rid)
            return ctx is not None and ctx.refs > 0

    def evict_context(self, rid: str) -> None:
        with self._ctx_lock:
            self._contexts.pop(rid, None)


def _job_view(state: LibraryState, row: dict[str, Any]) -> dict[str, Any]:
    """A job row as a CALLER may act on it.

    LIBRARY-REFACTOR-1A2. The store row and the runtime are two different
    facts. The report and the job commit in ONE transaction — unchanged, and
    it must stay that way — but that transaction happens BEFORE the job
    releases its baseline lease, deletes its tmp directory and frees the
    runner slot. Publishing `completed` inside that window told callers a job
    was over while it still held everything: the next scan was refused as
    busy and the baseline could not be deleted. A poll-until-terminal loop
    resumes inside that window, which is the retention flake — about one run
    in four.

    A terminal state is therefore published only once the runtime has let go.
    Until then the job keeps its last non-final state and carries
    `finalizing: true`. `running` is reused rather than a new state name on
    purpose: every existing client already reads it as "not done, keep
    polling", which is exactly right, so none of them has to learn a new word
    in order to stay correct.

    `finalizing` covers the WHOLE settled phase, not only the unwind. It goes
    true the moment the subprocess ends, so post-processing, validation and
    promotion report it too — and at that point the store row still reads
    `running`. Publishing it only after the terminal write would leave a
    window where a cancel is refused with 409 while the API showed nothing
    that explained why."""
    jid = row["job_id"]
    terminal = row["state"] in ("completed", "failed", "canceled",
                                "interrupted")
    if state.runner.is_unwinding(jid) and terminal:
        return {**row, "state": "running", "finalizing": True}
    return {**row, "finalizing": state.runner.is_finalizing(jid)}


def _project_view(state: LibraryState, row: dict[str, Any]) -> dict[str, Any]:
    """The API-facing project row: NO absolute machine paths, ever."""
    reports = state.store.reports_for(row["project_id"])
    last_job = state.store.latest_job_for(row["project_id"])
    latest = reports[0] if reports else None
    return {
        "project_id": row["project_id"],
        "name": row["name"],
        "kind": row["kind"],
        "location": row["location"],
        "created_at": row["created_at"],
        "source_available":
            state.source_dir_for(row) is not None,
        "reports_count": len(reports),
        "latest_report": ({k: latest[k] for k in
                           ("report_id", "created_at", "verdict",
                            "findings", "duration_ms",
                            # W4-B: the comparison, so the table can show
                            # new/resolved and the verdict's scope without a
                            # second request per project
                            "baseline_report_id", "baseline_enabled",
                            "new", "unchanged", "resolved", "gate_scope")}
                          if latest else None),
        "last_job": ({k: v for k, v in _job_view(state, last_job).items()
                      if k in ("job_id", "kind", "state", "online", "semgrep",
                               "created_at", "finished_at", "error",
                               "report_id", "baseline_report_id", "new_only",
                               "finalizing")}
                     if last_job else None),
    }


def create_library_app(library_root: Path, allowed_roots: list[Path],
                       port: int, spawn: Any = None,
                       env: dict[str, str] | None = None) -> LibraryDispatch:
    """Build the Library-mode ASGI application. `spawn`/`env` exist for
    tests only (fake subprocess; bounded env)."""
    state = LibraryState(library_root, allowed_roots, port,
                         spawn=spawn, env=env)
    api = FastAPI(title="AI Code Auditor Library", version="0.1.0",
                  docs_url=None, redoc_url=None, openapi_url=None)
    api.add_middleware(TrustedHostMiddleware,
                       allowed_hosts=["127.0.0.1", "localhost", "testserver"])

    # -- session / capabilities (read-only, no network) ---------------------

    @api.get("/api/library/session")
    def session() -> JSONResponse:
        # same-origin JS can read this; a cross-origin page cannot (no CORS)
        return _AsciiJSON({"mode": "library", "token": state.token})

    @api.get("/api/library/capabilities")
    def capabilities() -> JSONResponse:
        semgrep_bin = next((n for n in ("semgrep", "opengrep")
                            if shutil.which(n)), None)
        return _AsciiJSON({
            "mode": "library",
            "git_available": shutil.which("git") is not None,
            "semgrep_available": semgrep_bin is not None,
            "semgrep_engine": semgrep_bin or "",
            "registry_default": "offline",
            "registry_modes": ["offline", "online"],
            "reports_kept_per_project": MAX_REPORTS_PER_PROJECT,
            "store_available": state.store.available,
            "store_error": state.store.error,
            "projects": len(state.store.projects()),
        })

    # -- projects ------------------------------------------------------------

    @api.get("/api/library/projects")
    def list_projects() -> JSONResponse:
        down = _store_down(state)
        if down is not None:
            return down
        rows = [_project_view(state, r) for r in state.store.projects()]
        return _AsciiJSON({"projects": rows,
                           "active_job": state.runner.active_job_id() or ""})

    @api.post("/api/library/projects")
    def add_project(body: ProjectIn, request: Request) -> JSONResponse:
        # Order matters and is the same in every mutating handler: WHO first,
        # then CAN WE, then anything that touches the disk, the network, a
        # subprocess, a lease or a context. An unauthenticated caller must
        # not learn the store's condition, and a broken store must not cause
        # a filesystem probe that will be thrown away.
        denied = state.guard(request)
        if denied is not None:
            return denied
        down = _store_down(state)
        if down is not None:
            return down
        if body.kind == "local":
            resolved, reason = resolve_local_registration(
                body.path, state.allowed_roots)
            if resolved is None:
                return _err(400, f"invalid folder: {reason}")
            name = (body.name.strip() or resolved.name)[:100]
            row = {"project_id": new_id(), "name": name, "kind": "local",
                   "location": safe_location("local", str(resolved)),
                   "created_at": _now(), "git_url": "",
                   "local_path": str(resolved), "managed": False}
            try:
                state.store.put_project(row)
            except LibraryStoreError as e:
                return _err(503, str(e))
            return _AsciiJSON({"project": _project_view(state, row)},
                              status_code=201)
        if body.kind == "git":
            if shutil.which("git") is None:
                return _err(409, "git is not available on this machine")
            url_reason = bad_git_url(body.url)
            if url_reason is not None:
                return _err(400, f"invalid git url: {url_reason}")
            name = (body.name.strip()
                    or repo_name_from_url(body.url))[:100]
            row = {"project_id": new_id(), "name": name, "kind": "git",
                   "location": safe_location("git", body.url),
                   "created_at": _now(), "git_url": body.url,
                   "local_path": "", "managed": True}
            # W4-A3: registration + clone job are ONE store transaction under
            # the runner's slot lock — a busy runner or a store failure
            # leaves zero project rows, directories, or subprocesses.
            try:
                jid = state.runner.start(row, "clone",
                                         register_project=True)
            except LibraryStoreError as e:
                return _err(409, str(e))
            return _AsciiJSON({"project": _project_view(state, row),
                               "job_id": jid}, status_code=201)
        return _err(400, "kind must be 'local' or 'git'")

    @api.delete("/api/library/projects/{pid}")
    def remove_project(pid: str, request: Request,
                       confirm: bool = False) -> JSONResponse:
        denied = state.guard(request)
        if denied is not None:
            return denied
        down = _store_down(state)
        if down is not None:
            return down                   # before any lease is taken
        if not confirm:
            return _err(409, "removal requires confirm=true")
        # W4-A closing: take the project lease FIRST — a scan cannot start
        # between the active-job check below and the store mutation.
        if not state.reserve_project(pid):
            return _err(409, "another operation is in progress for this "
                             "project")
        try:
            project = state.store.project(pid)
            if project is None:
                return _err(404, "unknown project id")
            # authoritative in-memory slot check under the project lease:
            # catches a job that is still winding down (its store row may
            # already show a terminal state) so no orphan slot survives
            if state.runner.active_project_id() == pid:
                return _err(409, "a job is running for this project")
            report_rows = state.store.reports_for(pid)
            rids = [r["report_id"] for r in report_rows]
            # report deletion lease: ALL ids in one atomic step or none (no
            # partial lease); a request after it cannot acquire a context.
            # Distinct lock from the project lease — both are held here.
            denied_reason = state.reserve_for_delete(rids)
            if denied_reason is not None:
                return _err(409, denied_reason)
            try:
                # W4-A3 contract: report FILES first — if any tree cannot be
                # verified gone, stop with 503 and keep ALL metadata
                # (already-deleted trees count as gone on retry). Only then
                # drop the registration. The SOURCE is never touched here: a
                # local folder is external; a managed clone needs
                # delete-source.
                for rid in rids:
                    if not state.paths.confined_delete(
                            state.paths.report_dir(rid)):
                        return _err(503, "a report of this project could not "
                                         "be deleted — nothing was "
                                         "unregistered; retry")
                try:
                    removed = state.store.remove_project(pid)
                except LibraryStoreError:
                    return _err(503, "report files are deleted but the "
                                     "library metadata update failed — retry "
                                     "to finish")
            finally:
                state.release_delete(rids)    # ALWAYS, even on failures
        finally:
            state.release_project(pid)        # ALWAYS, even on failures
        return _AsciiJSON({"removed": pid, "reports_removed": len(removed),
                           "source_deleted": False})

    @api.post("/api/library/projects/{pid}/delete-source")
    def delete_source(pid: str, body: ConfirmIn,
                      request: Request) -> JSONResponse:
        denied = state.guard(request)
        if denied is not None:
            return denied
        down = _store_down(state)
        if down is not None:
            return down                   # before any lease or filesystem work
        if not body.confirm:
            return _err(409, "source deletion requires confirm=true")
        # W4-A closing: same project lease — no scan can start (and thus
        # read the source) between the active-job check and the delete.
        if not state.reserve_project(pid):
            return _err(409, "another operation is in progress for this "
                             "project")
        try:
            project = state.store.project(pid)
            if project is None:
                return _err(404, "unknown project id")
            if project["kind"] != "git" or not project["managed"]:
                return _err(409, "only managed git clones can be deleted")
            # authoritative in-memory slot check under the project lease:
            # catches a job that is still winding down (its store row may
            # already show a terminal state) so no orphan slot survives
            if state.runner.active_project_id() == pid:
                return _err(409, "a job is running for this project")
            target = state.paths.clone_dir(pid).parent
            existed = target.exists()
            if not state.paths.confined_delete(target):
                return _err(503, "the managed clone could not be deleted — "
                                 "nothing was changed; retry")
        finally:
            state.release_project(pid)        # ALWAYS, even on failures
        return _AsciiJSON({"project_id": pid, "source_deleted": existed})

    # -- scans ----------------------------------------------------------------

    @api.post("/api/library/projects/{pid}/scans")
    def start_scan(pid: str, body: ScanIn, request: Request) -> JSONResponse:
        denied = state.guard(request)
        if denied is not None:
            return denied
        down = _store_down(state)
        if down is not None:
            # before the lease, before resolve_baseline reads a report file,
            # and long before a subprocess
            return down
        # W4-A closing: the project lease is held across the WHOLE start —
        # the job row and runner slot exist before it is released, so a
        # concurrent removal/source-delete sees the active job and refuses.
        if not state.reserve_project(pid):
            return _err(409, "another operation is in progress for this "
                             "project")
        baseline_id, held = "", False
        try:
            project = state.store.project(pid)
            if project is None:
                return _err(404, "unknown project id")
            if state.source_dir_for(project) is None:
                return _err(409, "project source is not available "
                                 "(clone it first or restore the folder)")
            # W4-B: resolution, legality and the lease happen HERE — before
            # any subprocess exists. A refusal leaves no job row, no report,
            # and no lease behind.
            try:
                baseline_id, baseline_path = resolve_baseline(
                    state.store, state.paths, pid,
                    requested_id=body.baseline_report_id,
                    compare_previous=body.compare_previous,
                    new_only=body.new_only,
                    hold=state.hold_baseline, release=state.release_baseline)
            except BaselineRefused as e:
                return _err(e.status, str(e))
            held = bool(baseline_id)
            try:
                jid = state.runner.start(project, "scan", online=body.online,
                                         semgrep=body.semgrep,
                                         baseline_report_id=baseline_id,
                                         baseline_path=baseline_path,
                                         new_only=body.new_only)
            except LibraryStoreError as e:
                # runner.start rolls back its own slot/job on failure; the
                # lease is freed here so a retry works and nothing leaks
                return _err(409, str(e))
            held = False           # the runner owns the baseline lease now
        finally:
            if held:
                state.release_baseline(baseline_id)
            state.release_project(pid)
        return _AsciiJSON({"job_id": jid, "state": "pending",
                           "baseline_report_id": baseline_id,
                           "baseline_enabled": bool(baseline_id),
                           "new_only": body.new_only}, status_code=202)

    @api.get("/api/library/scans/{jid}")
    def scan_status(jid: str) -> JSONResponse:
        down = _store_down(state)
        if down is not None:
            return down
        row = state.store.job(jid)
        if row is None:
            return _err(404, "unknown job id")
        return _AsciiJSON({"job": _job_view(state, row)})

    @api.post("/api/library/scans/{jid}/cancel")
    def cancel_scan(jid: str, request: Request) -> JSONResponse:
        denied = state.guard(request)
        if denied is not None:
            return denied
        down = _store_down(state)
        if down is not None:
            return down                   # never signal a cancel we cannot record
        if state.store.job(jid) is None:
            return _err(404, "unknown job id")
        # LIBRARY-REFACTOR-1A2: answer what the RUNTIME did, never what was
        # asked for. This used to discard the runner's verdict and reply 200
        # `cancel_requested: true` unconditionally — for a job that finished
        # long ago, and for one already past the point of being stoppable.
        outcome = state.runner.cancel(jid)
        if outcome == CANCEL_ACCEPTED:
            return _AsciiJSON({"job_id": jid, "cancel_requested": True,
                               "already_requested": False}, status_code=202)
        if outcome == CANCEL_ALREADY_REQUESTED:
            # idempotent and honest: the first request stands, and nothing
            # was killed a second time
            return _AsciiJSON({"job_id": jid, "cancel_requested": True,
                               "already_requested": True}, status_code=202)
        # terminal, or finalizing: there is nothing left to stop, and no
        # signal is sent. The message names no path and no process.
        return _err(409, "this job can no longer be canceled")

    # -- reports ---------------------------------------------------------------

    @api.get("/api/library/projects/{pid}/reports")
    def list_reports(pid: str) -> JSONResponse:
        down = _store_down(state)
        if down is not None:
            return down
        if state.store.project(pid) is None:
            return _err(404, "unknown project id")
        return _AsciiJSON({"reports": state.store.reports_for(pid)})

    @api.delete("/api/library/reports/{rid}")
    def delete_report(rid: str, request: Request,
                      confirm: bool = False) -> JSONResponse:
        denied = state.guard(request)
        if denied is not None:
            return denied
        # BEFORE the existence check, and therefore before confined_delete.
        # Reproducing this round found the reason: with a stale in-memory row
        # and an unwritable store, the existence check PASSED, the report
        # files were really deleted, and only the metadata commit then failed
        # — a 503 handed back after the data was already gone.
        down = _store_down(state)
        if down is not None:
            return down
        if not confirm:
            return _err(409, "report deletion requires confirm=true")
        if state.store.report(rid) is None:
            return _err(404, "unknown report id")
        active = state.store.active_job()
        if active is not None and active.get("report_id") == rid:
            return _err(409, "report is being written by a running job")
        # W4-A closing: the in-use check and the deletion lease are ONE
        # atomic step — a request that arrives after the lease cannot
        # acquire the context (it gets 409 "report is being deleted").
        denied_reason = state.reserve_for_delete([rid])
        if denied_reason is not None:
            return _err(409, denied_reason)
        try:
            # W4-A3 contract: FILES first (verified gone), metadata second.
            # A file-delete failure changes nothing and returns 503; a
            # metadata failure after the files are gone is retryable (the
            # absent directory counts as deleted on the retry).
            if not state.paths.confined_delete(state.paths.report_dir(rid)):
                return _err(503, "report files could not be deleted — "
                                 "nothing was changed; retry the deletion")
            try:
                state.store.remove_report(rid)
            except LibraryStoreError:
                return _err(503, "report files are deleted but the library "
                                 "metadata update failed — retry to finish")
        finally:
            state.release_delete([rid])       # ALWAYS, even on failures
        return _AsciiJSON({"deleted": rid})

    @api.get("/api/library/reports/{rid}")
    def report_meta(rid: str) -> JSONResponse:
        down = _store_down(state)
        if down is not None:
            return down
        row = state.store.report(rid)
        if row is None:
            return _err(404, "unknown report id")
        return _AsciiJSON({"report": row})

    # SPA last, so /api/* wins
    if (_STATIC_DIR / "index.html").is_file():
        api.mount("/", StaticFiles(directory=str(_STATIC_DIR), html=True),
                  name="spa")

    dispatch = LibraryDispatch(api, state)
    return dispatch
