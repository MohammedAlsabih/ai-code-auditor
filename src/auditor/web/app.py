from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

# A report is small (the field-online run is ~110 KB; a large offline run a few
# MB). Cap well above realistic reports but low enough that a hostile/blob file
# can't be slurped into memory. Not configurable from the browser.
DEFAULT_MAX_REPORT_BYTES = 25 * 1024 * 1024  # 25 MB

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


def create_app(report_path: Path, repo_root: Path | None = None,
               max_bytes: int = DEFAULT_MAX_REPORT_BYTES) -> FastAPI:
    """Build the app around ONE already-resolved report path. The path is fixed
    here at startup and never taken from a request, so the browser cannot point
    the server at another file. `repo_root` is accepted for W2 (source viewer)
    and only surfaced read-only in /api/health for now."""
    report = load_report(report_path, max_bytes)   # may raise ReportError (caller handles)

    app = FastAPI(
        title="AI Code Auditor Report Explorer",
        version="0.1.0",
        docs_url=None, redoc_url=None, openapi_url=None,   # no interactive docs surface
    )

    @app.get("/api/health")
    def health() -> JSONResponse:
        counts = report.get("summary", {}).get("counts", {}) \
            if isinstance(report.get("summary"), dict) else {}
        return JSONResponse({
            "status": "ok",
            "report_loaded": True,
            "projects": len(report.get("projects", [])),
            "findings": len(aggregate_findings(report)),
            "counts": counts,
            "repo_root": str(repo_root) if repo_root else None,
        })

    @app.get("/api/report")
    def get_report() -> JSONResponse:
        return JSONResponse(report)

    # Serve the bundled SPA last so /api/* wins. html=True makes "/" return
    # index.html. Mount only if the build exists — the API is usable without it.
    if (_STATIC_DIR / "index.html").is_file():
        app.mount("/", StaticFiles(directory=str(_STATIC_DIR), html=True), name="spa")

    return app
