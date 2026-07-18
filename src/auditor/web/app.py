from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from auditor.core.walk import MAX_FILE_BYTES

# A report is small (the field-online run is ~110 KB; a large offline run a few
# MB). Cap well above realistic reports but low enough that a hostile/blob file
# can't be slurped into memory. Not configurable from the browser.
DEFAULT_MAX_REPORT_BYTES = 25 * 1024 * 1024  # 25 MB

# /api/source limits: the scanner's own per-file cap is reused so the viewer
# never reads a file the engine itself would refuse; the context window is
# small by design — the endpoint returns a WINDOW, never the whole file.
SOURCE_MAX_BYTES = MAX_FILE_BYTES
SOURCE_CONTEXT_DEFAULT = 8
SOURCE_CONTEXT_MAX = 50

_DRIVE_RE = re.compile(r"^[A-Za-z]:")
# Windows reserved device names are dangerous even as a NAME ("NUL", "con.py"):
# opening them touches a device, not a file. Rejected as any path segment stem.
_WIN_DEVICES = {"con", "prn", "aux", "nul"} \
    | {f"com{i}" for i in range(1, 10)} | {f"lpt{i}" for i in range(1, 10)}


def bad_source_path(path: str) -> str | None:
    """Pure string validation of a requested source path BEFORE any filesystem
    access. Returns a rejection reason (safe to echo: contains no machine
    paths) or None if the shape is a clean repo-relative posix path."""
    if not path or "\x00" in path:
        return "path is empty or contains a NUL byte"
    if "\\" in path:
        return "backslashes are not allowed (repo-relative posix paths only)"
    if path.startswith("/"):
        return "absolute and UNC paths are not allowed"
    if _DRIVE_RE.match(path):
        return "drive paths are not allowed"
    parts = path.split("/")
    if any(seg in ("", ".", "..") for seg in parts):
        return "path traversal or empty segments are not allowed"
    if any(seg.split(".", 1)[0].lower() in _WIN_DEVICES for seg in parts):
        return "reserved device names are not allowed"
    return None

# The built SPA is bundled next to this module (web/vite build -> here), so it
# ships inside the wheel and resolves the same from source or installed.
_STATIC_DIR = Path(__file__).resolve().parent / "static"


class ReportError(Exception):
    """The report path is missing, too large, unreadable, not JSON, or not a
    valid auditor report. Raised at load time so the CLI can print a clear,
    single-line message and exit — the server is never started with a bad
    report, so a browser never sees an internal traceback."""


def load_report(path: Path, max_bytes: int = DEFAULT_MAX_REPORT_BYTES) -> dict[str, Any]:
    """Read + validate report.json ONCE. Returns the parsed object or raises
    ReportError with a human-readable reason. Validation is deliberately shallow
    (shape, not full schema): it must be a JSON object carrying a `summary`
    object and a `projects` array — enough for the explorer to render."""
    if not path.exists() or not path.is_file():
        raise ReportError(f"report not found: {path}")
    size = path.stat().st_size
    if size > max_bytes:
        raise ReportError(
            f"report too large: {size} bytes exceeds the {max_bytes}-byte cap")
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise ReportError(f"cannot read report: {e.__class__.__name__}") from e
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ReportError(f"report is not valid JSON: {e}") from e
    if not isinstance(data, dict):
        raise ReportError("report must be a JSON object")
    if not isinstance(data.get("summary"), dict):
        raise ReportError("report is missing a 'summary' object")
    if not isinstance(data.get("projects"), list):
        raise ReportError("report is missing a 'projects' array")
    return data


def aggregate_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten every project's findings into one list, tagging each with its
    owning project's `project` root so the table can show a project column.
    Missing/oddly-typed fields degrade gracefully — a malformed row never
    aborts the aggregation."""
    rows: list[dict[str, Any]] = []
    projects = report.get("projects")
    if not isinstance(projects, list):
        return rows
    for proj in projects:
        if not isinstance(proj, dict):
            continue
        proj_root = str(proj.get("root", ""))
        proj_lang = str(proj.get("language", ""))
        findings = proj.get("findings")
        if not isinstance(findings, list):
            continue
        for f in findings:
            if not isinstance(f, dict):
                continue
            rows.append({
                "rule_id": f.get("rule_id", ""),
                "severity": f.get("severity", ""),
                "precision": f.get("precision", ""),
                "language": f.get("language", "") or proj_lang,
                "project": proj_root,
                "file": f.get("file", ""),
                "line": f.get("line", 0),
                "title": f.get("title", ""),
                "detail": f.get("detail", ""),
                "snippet": f.get("snippet", ""),
                "engine": f.get("engine", ""),
            })
    return rows


def repo_relative(project_root: str, file: str) -> str:
    """Finding paths are PROJECT-relative; /api/source addresses files by
    REPO-relative path. Compose the two exactly the way reports write roots
    (posix, '.' for the repository root)."""
    root = (project_root or "").strip("/")
    if root in ("", "."):
        return file
    return f"{root}/{file}"


def resolve_confined(root: Path, rel: str) -> Path | None:
    """Resolve root/rel with symlinks FOLLOWED and return the real path only if
    it stays inside the resolved root — otherwise None. A symlink (or chain)
    whose target lands outside the repository is rejected here; one that stays
    inside is fine."""
    try:
        resolved = (root / rel).resolve(strict=True)
        real_root = root.resolve(strict=True)
    except (OSError, RuntimeError):        # vanished mid-request, loop, perms
        return None
    if resolved != real_root and real_root not in resolved.parents:
        return None
    return resolved


def create_app(report_path: Path, repo_root: Path | None = None,
               max_bytes: int = DEFAULT_MAX_REPORT_BYTES) -> FastAPI:
    """Build the app around ONE already-resolved report path. The path is fixed
    here at startup and never taken from a request, so the browser cannot point
    the server at another file. `repo_root` (optional) enables the read-only
    /api/source window; without it the explorer still works and /api/source
    returns a clear error."""
    report = load_report(report_path, max_bytes)   # may raise ReportError (caller handles)

    # source-viewer state, all fixed at startup: the repository root (only if it
    # actually is a directory) and the ALLOWLIST — the exact file paths carried
    # by the loaded report's findings. /api/source serves nothing else. Built
    # from the RAW report accepting only non-empty STRING root/file pairs —
    # a malformed report (dict/list/int file) is skipped, never stringified,
    # and never crashes server startup.
    repo: Path | None = None
    if repo_root is not None and repo_root.is_dir():
        repo = repo_root
    allowed_files: set[str] = set()
    for _proj in report.get("projects", []):
        if not isinstance(_proj, dict):
            continue
        _root = _proj.get("root", "")
        _findings = _proj.get("findings")
        if not isinstance(_root, str) or not isinstance(_findings, list):
            continue
        for _f in _findings:
            if isinstance(_f, dict) and isinstance(_f.get("file"), str) and _f["file"]:
                allowed_files.add(repo_relative(_root, _f["file"]))

    app = FastAPI(
        title="AI Code Auditor Report Explorer",
        version="0.1.0",
        docs_url=None, redoc_url=None, openapi_url=None,   # no interactive docs surface
    )

    @app.get("/api/health")
    def health() -> JSONResponse:
        counts = report.get("summary", {}).get("counts", {}) \
            if isinstance(report.get("summary"), dict) else {}
        # deliberately NO absolute machine paths here (or anywhere the browser
        # sees): source_available carries everything the UI needs.
        return JSONResponse({
            "status": "ok",
            "report_loaded": True,
            "projects": len(report.get("projects", [])),
            "findings": len(aggregate_findings(report)),
            "counts": counts,
            "source_available": repo is not None,
        })

    @app.get("/api/report")
    def get_report() -> JSONResponse:
        return JSONResponse(report)

    def _err(status: int, msg: str) -> JSONResponse:
        # every /api/source error goes through here: msg must never contain a
        # machine path — only repo-relative paths and plain reasons.
        return JSONResponse({"error": msg}, status_code=status)

    @app.get("/api/source")
    def get_source(path: str, line: int = 1,
                   context: int = SOURCE_CONTEXT_DEFAULT) -> JSONResponse:
        if repo is None:
            return _err(409, "source viewing unavailable: the server was "
                             "started without --repo (or the root is not a "
                             "directory)")
        reason = bad_source_path(path)
        if reason is not None:
            return _err(400, f"invalid path: {reason}")
        if path not in allowed_files:
            return _err(403, "path is not one of the loaded report's findings")
        candidate = repo / path
        if not candidate.exists():                 # broken symlink counts as missing
            return _err(404, f"file not found in repository: {path}")
        resolved = resolve_confined(repo, path)
        if resolved is None:
            return _err(403, "path escapes the repository root")
        if not resolved.is_file():
            return _err(400, "not a regular file")
        # size enforcement is the BOUNDED READ, not stat: stat is only a cheap
        # early reject and can lie (file grew between stat and open — TOCTOU).
        # Reading cap+1 bytes proves oversize without ever slurping the file.
        try:
            if resolved.stat().st_size > SOURCE_MAX_BYTES:
                return _err(413, f"file exceeds the {SOURCE_MAX_BYTES}-byte viewer cap")
            with resolved.open("rb") as fh:
                raw = fh.read(SOURCE_MAX_BYTES + 1)
        except OSError:
            return _err(404, f"file not readable: {path}")
        if len(raw) > SOURCE_MAX_BYTES:
            return _err(413, f"file exceeds the {SOURCE_MAX_BYTES}-byte viewer cap")
        if b"\x00" in raw:            # whole bounded content, not a prefix sniff
            return _err(415, "binary file")
        text_lines = raw.decode("utf-8", errors="replace").splitlines()
        total = len(text_lines)
        if total == 0:
            text_lines, total = [""], 1            # empty file still renders one blank line
        ctx = min(max(context, 0), SOURCE_CONTEXT_MAX)
        target = min(max(line, 1), total)
        start = max(1, target - ctx)
        end = min(total, target + ctx)
        return JSONResponse({
            "path": path,
            "requested_line": target,
            "start_line": start,
            "end_line": end,
            "total_lines": total,
            "lines": [{"number": n, "text": text_lines[n - 1]}
                      for n in range(start, end + 1)],
        })

    # Serve the bundled SPA last so /api/* wins. html=True makes "/" return
    # index.html. Mount only if the build exists — the API is usable without it.
    if (_STATIC_DIR / "index.html").is_file():
        app.mount("/", StaticFiles(directory=str(_STATIC_DIR), html=True), name="spa")

    return app
