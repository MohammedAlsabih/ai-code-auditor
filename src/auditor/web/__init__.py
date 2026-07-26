"""Local, read-only web UI for exploring an AI Code Auditor report.json.

W1 scope: a FastAPI app that loads ONE report at startup and serves it read-only
to a bundled React SPA. It never runs a scan/build/install, never touches the
engine, and binds to 127.0.0.1 only (enforced in the CLI `serve` command).

W3-E5 closing: the FastAPI-backed names are resolved LAZILY (PEP 562). Importing
any sibling submodule — e.g. `auditor.web.reviews`, which is itself FastAPI-free
— used to execute this file and, through it, `auditor.web.app`'s
`from fastapi import FastAPI`. That made a `pip install .[agent]` (no web extra)
unable to run the CLI. The public API is unchanged: `from auditor.web import
create_app` still works, it just imports FastAPI at attribute-access time.
"""

from typing import Any

# FastAPI-free primitives: importing these is free on every install shape.
from auditor.report.load import (
    DEFAULT_MAX_REPORT_BYTES,
    ReportError,
    bad_source_path,
    load_report,
    resolve_confined,
)

# resolved on demand from auditor.web.app (which requires the [web] extra)
_LAZY = ("SOURCE_CONTEXT_DEFAULT", "SOURCE_CONTEXT_MAX", "SOURCE_MAX_BYTES",
         "aggregate_findings", "create_app")


def __getattr__(name: str) -> Any:
    if name in _LAZY:
        from auditor.web import app as _app
        return getattr(_app, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(__all__)


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
