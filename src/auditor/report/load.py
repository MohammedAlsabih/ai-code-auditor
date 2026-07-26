"""Report loading and repo-relative path validation — the FastAPI-free home.

W3-E5 closing: these primitives are needed by the CLI and by the AI layer,
neither of which requires the web extra. They used to live in
`auditor.web.app`, whose module-level `from fastapi import FastAPI` made a
`pip install .[agent]` (no FastAPI) install unable to run `auditor ai audit`
at all. Nothing here imports FastAPI, pydantic, or anything outside the
standard library, so importing it stays free for every install shape.

`auditor.web.app` re-exports every name below, so existing web callers and
`auditor.web.__init__` are unaffected.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

# A report is small (the field-online run is ~110 KB; a large offline run a few
# MB). Cap well above realistic reports but low enough that a hostile/blob file
# can't be slurped into memory. Not configurable from the browser.
DEFAULT_MAX_REPORT_BYTES = 25 * 1024 * 1024  # 25 MB

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


class ReportError(Exception):
    """The report path is missing, too large, unreadable, not JSON, or not a
    valid auditor report. Raised at load time so the CLI can print a clear,
    single-line message and exit — the server is never started with a bad
    report, so a browser never sees an internal traceback."""


def load_report(path: Path,
                max_bytes: int = DEFAULT_MAX_REPORT_BYTES) -> dict[str, Any]:
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
