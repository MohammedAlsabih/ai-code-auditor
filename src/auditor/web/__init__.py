"""Local, read-only web UI for exploring an AI Code Auditor report.json.

W1 scope: a FastAPI app that loads ONE report at startup and serves it read-only
to a bundled React SPA. It never runs a scan/build/install, never touches the
engine, and binds to 127.0.0.1 only (enforced in the CLI `serve` command)."""

from auditor.web.app import (
    DEFAULT_MAX_REPORT_BYTES,
    SOURCE_CONTEXT_DEFAULT,
    SOURCE_CONTEXT_MAX,
    SOURCE_MAX_BYTES,
    ReportError,
    aggregate_findings,
    bad_source_path,
    create_app,
    load_report,
    resolve_confined,
)

__all__ = [
    "DEFAULT_MAX_REPORT_BYTES",
    "SOURCE_CONTEXT_DEFAULT",
    "SOURCE_CONTEXT_MAX",
    "SOURCE_MAX_BYTES",
    "ReportError",
    "aggregate_findings",
    "bad_source_path",
    "create_app",
    "load_report",
    "resolve_confined",
]
