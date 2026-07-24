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
from auditor.web.library import (
    MAX_REPORTS_PER_PROJECT,
    JobRunner,
    LibraryPaths,
    LibraryStore,
    LibraryStoreError,
    _now_iso as _now,
    bad_git_url,
    new_id,
    repo_name_from_url,
    resolve_local_registration,
    safe_location,
)

CONTROL_HEADER = "x-auditor-control"
CONTEXT_CACHE_MAX = 4

_FORWARD_RE = re.compile(r"^/api/library/reports/([0-9a-f]{16})/(.+)$")


def _err(status: int, msg: str) -> JSONResponse:
    return _AsciiJSON({"error": msg}, status_code=status)


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
        ctx = lib.acquire_context(rid)
        if ctx is None:
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
        self.runner = JobRunner(self.store, self.paths, spawn=spawn, env=env)
        self.allowed_roots = allowed_roots
        self.token = secrets.token_urlsafe(32)
        self.origins = {f"http://127.0.0.1:{port}",
                        f"http://localhost:{port}"}
        self._ctx_lock = threading.Lock()
        self._contexts: dict[str, _Ctx] = {}

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

    # -- report contexts ----------------------------------------------------

    def source_dir_for(self, project: dict[str, Any]) -> Path | None:
        if project["kind"] == "git":
            src = self.paths.clone_dir(project["project_id"])
            return src if src.is_dir() else None
        p = Path(project["local_path"])
        return p if p.is_dir() else None

    def acquire_context(self, rid: str) -> _Ctx | None:
        with self._ctx_lock:
            ctx = self._contexts.get(rid)
            if ctx is not None:
                ctx.refs += 1
                return ctx
            row = self.store.report(rid)
            if row is None:
                return None
            project = self.store.project(row["project_id"])
            repo = self.source_dir_for(project) if project else None
            try:
                app = create_app(self.paths.report_json(rid), repo_root=repo)
            except ReportError:
                return None
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
            return ctx

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
                            "findings", "duration_ms")}
                          if latest else None),
        "last_job": ({k: last_job[k] for k in
                      ("job_id", "kind", "state", "online", "semgrep",
                       "created_at", "finished_at", "error", "report_id")}
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
        rows = [_project_view(state, r) for r in state.store.projects()]
        return _AsciiJSON({"projects": rows,
                           "active_job": state.runner.active_job_id() or ""})

    @api.post("/api/library/projects")
    def add_project(body: ProjectIn, request: Request) -> JSONResponse:
        denied = state.guard(request)
        if denied is not None:
            return denied
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
            try:
                state.store.put_project(row)
                jid = state.runner.start(row, "clone")
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
        if not confirm:
            return _err(409, "removal requires confirm=true")
        project = state.store.project(pid)
        if project is None:
            return _err(404, "unknown project id")
        active = state.store.active_job()
        if active is not None and active["project_id"] == pid:
            return _err(409, "a job is running for this project")
        if any(state.context_in_use(r["report_id"])
               for r in state.store.reports_for(pid)):
            return _err(409, "a report of this project is currently open")
        try:
            removed = state.store.remove_project(pid)
        except LibraryStoreError as e:
            return _err(503, str(e))
        for rid in removed:
            state.evict_context(rid)
            state.paths.confined_delete(state.paths.report_dir(rid))
        # the SOURCE is never deleted here: a local folder is external by
        # definition; a managed clone needs the separate delete-source call.
        return _AsciiJSON({"removed": pid, "reports_removed": len(removed),
                           "source_deleted": False})

    @api.post("/api/library/projects/{pid}/delete-source")
    def delete_source(pid: str, body: ConfirmIn,
                      request: Request) -> JSONResponse:
        denied = state.guard(request)
        if denied is not None:
            return denied
        if not body.confirm:
            return _err(409, "source deletion requires confirm=true")
        project = state.store.project(pid)
        if project is None:
            return _err(404, "unknown project id")
        if project["kind"] != "git" or not project["managed"]:
            return _err(409, "only managed git clones can be deleted")
        active = state.store.active_job()
        if active is not None and active["project_id"] == pid:
            return _err(409, "a job is running for this project")
        deleted = state.paths.confined_delete(
            state.paths.clone_dir(pid).parent)
        return _AsciiJSON({"project_id": pid, "source_deleted": deleted})

    # -- scans ----------------------------------------------------------------

    @api.post("/api/library/projects/{pid}/scans")
    def start_scan(pid: str, body: ScanIn, request: Request) -> JSONResponse:
        denied = state.guard(request)
        if denied is not None:
            return denied
        project = state.store.project(pid)
        if project is None:
            return _err(404, "unknown project id")
        if state.source_dir_for(project) is None:
            return _err(409, "project source is not available "
                             "(clone it first or restore the folder)")
        try:
            jid = state.runner.start(project, "scan", online=body.online,
                                     semgrep=body.semgrep)
        except LibraryStoreError as e:
            return _err(409, str(e))
        return _AsciiJSON({"job_id": jid, "state": "pending"},
                          status_code=202)

    @api.get("/api/library/scans/{jid}")
    def scan_status(jid: str) -> JSONResponse:
        row = state.store.job(jid)
        if row is None:
            return _err(404, "unknown job id")
        return _AsciiJSON({"job": row})

    @api.post("/api/library/scans/{jid}/cancel")
    def cancel_scan(jid: str, request: Request) -> JSONResponse:
        denied = state.guard(request)
        if denied is not None:
            return denied
        if state.store.job(jid) is None:
            return _err(404, "unknown job id")
        state.runner.cancel(jid)
        return _AsciiJSON({"job_id": jid, "cancel_requested": True})

    # -- reports ---------------------------------------------------------------

    @api.get("/api/library/projects/{pid}/reports")
    def list_reports(pid: str) -> JSONResponse:
        if state.store.project(pid) is None:
            return _err(404, "unknown project id")
        return _AsciiJSON({"reports": state.store.reports_for(pid)})

    @api.delete("/api/library/reports/{rid}")
    def delete_report(rid: str, request: Request,
                      confirm: bool = False) -> JSONResponse:
        denied = state.guard(request)
        if denied is not None:
            return denied
        if not confirm:
            return _err(409, "report deletion requires confirm=true")
        if state.store.report(rid) is None:
            return _err(404, "unknown report id")
        if state.context_in_use(rid):
            return _err(409, "report is currently open")
        active = state.store.active_job()
        if active is not None and active.get("report_id") == rid:
            return _err(409, "report is being written by a running job")
        try:
            state.store.remove_report(rid)
        except LibraryStoreError as e:
            return _err(503, str(e))
        state.evict_context(rid)
        # the report DIRECTORY (report.json + its own sidecars) — nothing else
        state.paths.confined_delete(state.paths.report_dir(rid))
        return _AsciiJSON({"deleted": rid})

    @api.get("/api/library/reports/{rid}")
    def report_meta(rid: str) -> JSONResponse:
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
