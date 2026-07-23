from __future__ import annotations

import json
import re
import threading
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from auditor.core.levels import LEGACY_SEVERITY_TO_LEVEL, normalize_level
from auditor.core.walk import MAX_FILE_BYTES
from auditor.web.coverage import build_coverage
from auditor.web.reviews import (
    NOTE_MAX_CHARS,
    VALID_STATUSES,
    ReviewStore,
    ReviewStoreError,
    review_id,
)

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


class _AsciiJSON(JSONResponse):
    """Canonical-safe JSON rendering for EVERY response: ensure_ascii=True
    escapes all non-ASCII — including a lone surrogate from a malformed
    finding title or note — as \\uXXXX, so the byte-encode can never raise
    (starlette's default renderer uses ensure_ascii=False + utf-8 encode and
    crashes on surrogates). Browsers decode the escapes back losslessly."""

    def render(self, content: Any) -> bytes:
        return json.dumps(content, ensure_ascii=True, allow_nan=False,
                          separators=(",", ":")).encode("ascii")


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
                "severity": f.get("severity", ""),   # DEPRECATED legacy color
                "level": normalize_level(f.get("level"), f.get("severity")),
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


def _finding_review_id(root: str, f: dict[str, Any]) -> str | None:
    """Identity of one finding for the review sidecar — or None when a field
    has a malformed type (never stringify junk into an identity)."""
    file, rule = f.get("file"), f.get("rule_id")
    title, engine = f.get("title"), f.get("engine", "")
    line = f.get("line", 0)
    if not (isinstance(file, str) and file and isinstance(rule, str)
            and isinstance(title, str) and isinstance(engine, str)):
        return None
    if isinstance(line, bool) or not isinstance(line, int):
        return None
    return review_id(root, file, line, rule, title, engine)


class ReviewIn(BaseModel):
    status: str
    note: str = ""


class BatchIn(BaseModel):
    review_ids: list[str]
    status: str
    note_mode: str = "keep"
    note: str = ""
    # canonical confirmation flag for dismissing error-level findings;
    # confirm_red is the DEPRECATED legacy alias, accepted for compatibility.
    confirm_error: bool = False
    confirm_red: bool = False


BATCH_MAX_IDS = 5000
_NOTE_MODES = ("keep", "append", "replace")


class AIRequestIn(BaseModel):
    """W3-A: the browser may name a provider (and a model) — NOTHING else.
    extra='forbid' hard-rejects any attempt to smuggle an api_key or a
    base_url through the request body (422 before any code runs)."""
    model_config = {"extra": "forbid"}

    provider: str
    model: str = ""


class AIReviewIn(BaseModel):
    """W3-B/C: the browser names ONE finding + provider + model — plus, for
    a REMOTE provider, the one-time consent token from /api/ai/
    consent-preview. No prompt, no source, no api_key, no base_url
    (extra='forbid')."""
    model_config = {"extra": "forbid"}

    review_id: str
    provider: str
    model: str
    consent_token: str = ""


class AIConsentPreviewIn(BaseModel):
    """W3-C: what WOULD be sent for these findings — counts and byte sizes
    only, never code. extra='forbid'."""
    model_config = {"extra": "forbid"}

    review_ids: list[str]
    provider: str
    model: str


class AIBatchLimitsIn(BaseModel):
    model_config = {"extra": "forbid"}

    max_requests: int
    max_output_tokens: int
    max_input_bytes: int | None = None
    max_input_tokens: int | None = None
    max_cost_usd: float | None = None


class AIBatchIn(BaseModel):
    """W3-D: a batch names findings + provider + model + MANDATORY limits —
    and, for a remote provider, the consent token from the batch preview."""
    model_config = {"extra": "forbid"}

    review_ids: list[str]
    provider: str
    model: str
    limits: AIBatchLimitsIn
    consent_token: str = ""


class AIAuditPreviewIn(BaseModel):
    """W3-E: the browser picks a PROFILE, projects, provider and model —
    never a prompt, query text, api_key, or base_url (extra='forbid')."""
    model_config = {"extra": "forbid"}

    profile: str
    provider: str
    model: str
    projects: list[str] = []


class AIAuditIn(BaseModel):
    model_config = {"extra": "forbid"}

    profile: str
    provider: str
    model: str
    limits: AIBatchLimitsIn
    projects: list[str] = []
    consent_token: str = ""


class AICandidateReviewIn(BaseModel):
    model_config = {"extra": "forbid"}

    decision: str
    note: str = ""


# ONE probe/models call at a time per process: a second concurrent request
# gets 409 WITHOUT any outbound connection. Module-level on purpose — the
# guard covers every app instance in the process.
_AI_PROBE_LOCK = threading.Lock()


def create_app(report_path: Path, repo_root: Path | None = None,
               max_bytes: int = DEFAULT_MAX_REPORT_BYTES,
               reviews_path: Path | None = None) -> FastAPI:
    """Build the app around ONE already-resolved report path. The path is fixed
    here at startup and never taken from a request, so the browser cannot point
    the server at another file. `repo_root` (optional) enables the read-only
    /api/source window; without it the explorer still works and /api/source
    returns a clear error. The reviews sidecar path is likewise fixed here
    (default: <report>.reviews.json next to the report) — the report itself
    stays read-only forever; the sidecar is the ONLY thing the server writes."""
    report = load_report(report_path, max_bytes)   # may raise ReportError (caller handles)

    # /api/report serves an ENRICHED COPY carrying review_id per finding; the
    # original dict and report.json on disk are never touched.
    enriched: dict[str, Any] = json.loads(json.dumps(report))
    valid_review_ids: set[str] = set()
    error_review_ids: set[str] = set()  # server gate for bulk FP/AR on error-level
    for _proj in enriched.get("projects", []):
        if not isinstance(_proj, dict) or not isinstance(_proj.get("root"), str):
            continue
        if not isinstance(_proj.get("findings"), list):
            continue
        for _f in _proj["findings"]:
            if isinstance(_f, dict):
                # normalized SARIF-compatible level in the SERVED copy only
                # (report.json on disk is never touched). Unknown values stay
                # unclassified — never silently promoted.
                _lvl = normalize_level(_f.get("level"), _f.get("severity"))
                if _lvl is not None:
                    _f["level"] = _lvl
                _rid = _finding_review_id(_proj["root"], _f)
                if _rid is not None:
                    _f["review_id"] = _rid
                    valid_review_ids.add(_rid)
                    if _lvl == "error":
                        error_review_ids.add(_rid)

    store = ReviewStore(reviews_path if reviews_path is not None
                        else report_path.parent / (report_path.stem + ".reviews.json"))

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
    # DNS-rebinding guard for the write endpoints: the server is loopback-only
    # (CLI hardcodes 127.0.0.1) and additionally refuses any request whose Host
    # header is not a local name. Deliberately NO CORS middleware — cross-origin
    # writes stay blocked by the browser's same-origin policy.
    app.add_middleware(TrustedHostMiddleware,
                       allowed_hosts=["127.0.0.1", "localhost", "testserver"])

    @app.get("/api/health")
    def health() -> JSONResponse:
        counts = report.get("summary", {}).get("counts", {}) \
            if isinstance(report.get("summary"), dict) else {}
        # canonical level_counts: the report's own summary.level_counts when
        # present, else translated from the legacy color counts.
        lc = report.get("summary", {}).get("level_counts") \
            if isinstance(report.get("summary"), dict) else None
        if not isinstance(lc, dict):
            lc = {LEGACY_SEVERITY_TO_LEVEL[k]: v for k, v in counts.items()
                  if k in LEGACY_SEVERITY_TO_LEVEL and isinstance(v, int)}
        # deliberately NO absolute machine paths here (or anywhere the browser
        # sees): source_available carries everything the UI needs.
        return _AsciiJSON({
            "status": "ok",
            "report_loaded": True,
            "projects": len(report.get("projects", [])),
            "findings": len(aggregate_findings(report)),
            "level_counts": lc,
            "counts": counts,   # DEPRECATED legacy colors, kept temporarily
            "source_available": repo is not None,
        })

    @app.get("/api/report")
    def get_report() -> JSONResponse:
        return _AsciiJSON(enriched)   # the review_id-carrying copy, disk untouched

    # evidence-only coverage payload, built ONCE from the loaded report
    coverage = build_coverage(report)

    @app.get("/api/coverage")
    def get_coverage() -> JSONResponse:
        return _AsciiJSON(coverage)

    def _err(status: int, msg: str) -> JSONResponse:
        # every API error goes through here: msg must never contain a machine
        # path — only repo-relative paths and plain reasons.
        return _AsciiJSON({"error": msg}, status_code=status)

    @app.get("/api/reviews")
    def get_reviews() -> JSONResponse:
        return _AsciiJSON({"available": store.available, "error": store.error,
                             "reviews": store.all()})

    @app.put("/api/reviews/{rid}")
    def put_review(rid: str, body: ReviewIn) -> JSONResponse:
        if rid not in valid_review_ids:
            return _err(404, "unknown review id for the loaded report")
        if body.status not in VALID_STATUSES:
            return _err(400, f"invalid status (expected one of {', '.join(VALID_STATUSES)})")
        if len(body.note) > NOTE_MAX_CHARS:
            return _err(400, f"note exceeds {NOTE_MAX_CHARS} characters")
        try:
            entry = store.put(rid, body.status, body.note)
        except ReviewStoreError as e:
            return _err(503, str(e))
        return _AsciiJSON({"review_id": rid, **entry})

    @app.delete("/api/reviews/{rid}")
    def delete_review(rid: str) -> JSONResponse:
        if rid not in valid_review_ids:
            return _err(404, "unknown review id for the loaded report")
        try:
            store.delete(rid)
        except ReviewStoreError as e:
            return _err(503, str(e))
        return _AsciiJSON({"review_id": rid, "status": "unreviewed"})

    @app.put("/api/review-batch")
    def review_batch(body: BatchIn) -> JSONResponse:
        """Atomic bulk review update. EVERYTHING is validated before any write;
        one unknown id fails the whole batch. One lock, one sidecar write, one
        shared updated_at. Dedicated static route — no clash with the dynamic
        /api/reviews/{rid}."""
        ids = body.review_ids
        if not ids:
            return _err(400, "empty batch")
        if len(ids) > BATCH_MAX_IDS:
            return _err(400, f"batch exceeds the {BATCH_MAX_IDS}-id cap")
        if len(set(ids)) != len(ids):
            return _err(400, "duplicate review ids in batch")
        unknown = sum(1 for r in ids if r not in valid_review_ids)
        if unknown:
            return _err(404, f"{unknown} unknown review id(s) for the loaded "
                             "report — nothing was written")
        if body.status not in (*VALID_STATUSES, "unreviewed"):
            return _err(400, "invalid status (expected one of "
                             f"{', '.join(VALID_STATUSES)}, unreviewed)")
        if body.note_mode not in _NOTE_MODES:
            return _err(400, f"invalid note_mode (expected one of {', '.join(_NOTE_MODES)})")
        if len(body.note) > NOTE_MAX_CHARS:
            return _err(400, f"note exceeds {NOTE_MAX_CHARS} characters")
        confirmed = body.confirm_error or body.confirm_red   # legacy alias accepted
        if body.status in ("false_positive", "accepted_risk") and not confirmed:
            errors_n = sum(1 for r in ids if r in error_review_ids)
            if errors_n:
                # enforced HERE, not just in the UI: dismissing ERROR-level
                # findings in bulk needs an explicit second confirmation.
                # red_count is the DEPRECATED alias of error_count.
                return JSONResponse(
                    {"error": f"batch touches {errors_n} error-level finding(s); "
                              "resend with confirm_error=true to proceed",
                     "error_count": errors_n, "red_count": errors_n},
                    status_code=409)
        try:
            result = store.apply_batch(
                ids, None if body.status == "unreviewed" else body.status,
                body.note_mode, body.note)
        except ValueError as e:                # e.g. append overflow — no write
            return _err(400, str(e))
        except ReviewStoreError as e:
            return _err(503, str(e))
        return _AsciiJSON({"applied": result["applied"], "status": body.status,
                           "updated_at": result["updated_at"]})

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
        return _AsciiJSON({
            "path": path,
            "requested_line": target,
            "start_line": start,
            "end_line": end,
            "total_lines": total,
            "lines": [{"number": n, "text": text_lines[n - 1]}
                      for n in range(start, end + 1)],
        })

    # ---- AI provider layer (W3-A): connection testing ONLY -------------------
    # No findings, snippets, or source paths are ever sent; the probe is a
    # fixed string. GET /api/ai/providers is LOCAL metadata (no network).
    # POST endpoints are the only ones that go outbound, one at a time.
    from auditor.ai import AIError, Provider, create_client, provider_metadata

    def _ai_provider(name: str) -> Provider | None:
        try:
            return Provider(name)
        except ValueError:
            return None

    @app.get("/api/ai/providers")
    def ai_providers() -> JSONResponse:
        rows = [{k: m[k] for k in ("provider", "display", "configured",
                                   "key_present", "locality")}
                for m in provider_metadata()]
        return _AsciiJSON({"providers": rows,
                           "note": "Connection tests send a fixed probe only. "
                                   "Reports and source code are not sent."})

    @app.post("/api/ai/models")
    def ai_models(body: AIRequestIn) -> JSONResponse:
        provider = _ai_provider(body.provider)
        if provider is None:
            return _err(400, "unknown provider")
        if not _AI_PROBE_LOCK.acquire(blocking=False):
            return _err(409, "another AI request is already in flight")
        try:
            try:
                client = create_client(provider)
                models = client.list_models()
            except AIError as e:
                return _AsciiJSON({"provider": provider.value,
                                   "status": e.code, "message": str(e)})
            return _AsciiJSON({"provider": provider.value, "status": "ok",
                               "models": [m.id for m in models]})
        finally:
            _AI_PROBE_LOCK.release()

    @app.post("/api/ai/test")
    def ai_test(body: AIRequestIn) -> JSONResponse:
        provider = _ai_provider(body.provider)
        if provider is None:
            return _err(400, "unknown provider")
        if not body.model.strip():
            return _err(400, "model is required")
        if not _AI_PROBE_LOCK.acquire(blocking=False):
            return _err(409, "another AI request is already in flight")
        try:
            try:
                client = create_client(provider)
            except AIError as e:
                return _AsciiJSON({"provider": provider.value,
                                   "model": body.model,
                                   "status": e.code, "message": str(e)})
            result = client.test_connection(body.model.strip())
            out: dict[str, Any] = {"provider": provider.value,
                                   "model": body.model.strip(),
                                   "status": result.status,
                                   "message": result.message}
            if result.ok:
                out["latency_ms"] = result.latency_ms
            return _AsciiJSON(out)
        finally:
            _AI_PROBE_LOCK.release()

    # ---- AI single-finding review (W3-B) -------------------------------------
    # The context pack is built HERE from the loaded report + confined repo
    # reads; the browser can only name a finding. Local providers only until
    # the W3-C privacy gate. Results land in a separate git-ignored sidecar.
    from auditor.ai.consent import (
        ConsentAudit,
        ConsentError,
        ConsentRegistry,
        binding_hash,
        build_consent_preview,
        remote_reviews_enabled,
    )
    from auditor.ai.review import (
        AIReviewRequest,
        ContextTooLargeError,
        PrivacyGateError,
        build_context_pack,
        is_local_review_provider,
        run_review,
    )
    from auditor.ai.review_store import AIReviewStore, AIReviewStoreError
    from auditor.ai.transport import RequestsTransport
    from auditor.ai.providers import resolve_config as _ai_resolve_config

    ai_store = AIReviewStore(
        report_path.parent / (report_path.stem + ".ai-reviews.json"))
    ai_consents = ConsentRegistry()
    ai_audit = ConsentAudit(
        report_path.parent / (report_path.stem + ".ai-consent.json"))
    _ai_review_inflight: set[str] = set()
    _ai_review_lock = threading.Lock()

    def _ai_local(provider: Provider) -> bool:
        try:
            return is_local_review_provider(provider,
                                            _ai_resolve_config(provider))
        except AIError:
            return False

    @app.post("/api/ai/consent-preview")
    def ai_consent_preview(body: AIConsentPreviewIn) -> JSONResponse:
        provider = _ai_provider(body.provider)
        if provider is None:
            return _err(400, "unknown provider")
        if not body.model.strip():
            return _err(400, "model is required")
        ids = body.review_ids
        if not ids or len(ids) != len(set(ids)):
            return _err(400, "review_ids must be a non-empty, "
                             "duplicate-free list")
        unknown = [r for r in ids if r not in valid_review_ids]
        if unknown:
            return _err(404, f"{len(unknown)} unknown review id(s) for the "
                             "loaded report")
        local = _ai_local(provider)
        if not local and not remote_reviews_enabled():
            ai_audit.record("denied", provider.value, body.model.strip(),
                            len(ids), "-",
                            {"reason_remote_disabled": 1})
            return _AsciiJSON(
                {"error": "remote AI reviews are disabled by server policy "
                          "(set AUDITOR_AI_REMOTE_REVIEWS=confirm to allow "
                          "the consent flow)",
                 "status": "privacy_gate_required"}, status_code=403)
        packs = []
        for rid in ids:
            try:
                pack = build_context_pack(report, repo, rid)
            except ContextTooLargeError as e:
                return _AsciiJSON({"error": str(e), "status": e.code},
                                  status_code=413)
            if pack is None:
                return _err(404, "unknown review id for the loaded report")
            packs.append(pack)
        try:
            cfg = _ai_resolve_config(provider)
            locality = cfg.locality
        except AIError:
            locality = "remote"
        preview = build_consent_preview(provider.value, body.model.strip(),
                                        locality, packs)
        if not local:
            digests = [p["digest"] for p in packs]
            token = ai_consents.issue(provider.value, body.model.strip(),
                                      ids, digests)
            preview["consent_token"] = token
            preview["consent_expires_in_seconds"] = 600
            ai_audit.record(
                "issued", provider.value, body.model.strip(), len(ids),
                binding_hash(provider.value, body.model.strip(), ids,
                             digests),
                {"input_bytes": preview["input_bytes"],
                 "redactions": preview["redaction_total"]})
        else:
            preview["consent_token"] = ""
            preview["note"] = ("local provider — no remote consent needed; "
                               "nothing leaves this machine")
        return _AsciiJSON(preview)

    @app.post("/api/ai/reviews")
    def ai_review(body: AIReviewIn) -> JSONResponse:
        provider = _ai_provider(body.provider)
        if provider is None:
            return _err(400, "unknown provider")
        if not body.model.strip():
            return _err(400, "model is required")
        if body.review_id not in valid_review_ids:
            return _err(404, "unknown review id for the loaded report")
        with _ai_review_lock:
            if body.review_id in _ai_review_inflight:
                return _err(409, "an AI review for this finding is already "
                                 "in flight")
            _ai_review_inflight.add(body.review_id)
        try:
            try:
                pack = build_context_pack(report, repo, body.review_id)
            except ContextTooLargeError as e:
                return _AsciiJSON({"error": str(e), "status": e.code},
                                  status_code=413)
            if pack is None:
                return _err(404, "unknown review id for the loaded report")
            request = AIReviewRequest(review_id=body.review_id,
                                      provider=provider,
                                      model=body.model.strip())
            consented = False
            if not _ai_local(provider):
                # remote path: BOTH the admin switch and a one-time token
                # bound to exactly this payload — checked before any network
                if not remote_reviews_enabled():
                    return _AsciiJSON(
                        {"error": "remote AI reviews are disabled by server "
                                  "policy", "status": "privacy_gate_required"},
                        status_code=403)
                try:
                    ai_consents.redeem(body.consent_token, provider.value,
                                       request.model, [body.review_id],
                                       [pack["digest"]])
                except ConsentError as e:
                    ai_audit.record("denied", provider.value, request.model,
                                    1, "-", {e.code: 1})
                    return _AsciiJSON({"error": str(e), "status": e.code},
                                      status_code=403)
                consented = True
                ai_audit.record(
                    "redeemed", provider.value, request.model, 1,
                    binding_hash(provider.value, request.model,
                                 [body.review_id], [pack["digest"]]),
                    (pack.get("privacy_manifest") or {}).get("redactions"))
            try:
                result = run_review(request, pack, RequestsTransport(),
                                    consented=consented)
            except PrivacyGateError as e:
                return _AsciiJSON({"error": str(e),
                                   "status": e.code}, status_code=403)
            except AIError as e:
                return _AsciiJSON({"provider": provider.value,
                                   "model": body.model.strip(),
                                   "status": e.code, "message": str(e)},
                                  status_code=502)
            try:
                ai_store.put(result)
            except AIReviewStoreError as e:
                return _err(503, str(e))
            return _AsciiJSON({**result, "stale": False})
        finally:
            with _ai_review_lock:
                _ai_review_inflight.discard(body.review_id)

    @app.get("/api/ai/reviews")
    def ai_reviews_summary() -> JSONResponse:
        """Latest AI assessment per finding (for the table filter). Fresh
        results only carry their assessment; stale ones are flagged. Local
        sidecar read — no provider call."""
        out: dict[str, Any] = {}
        for rid in valid_review_ids:
            rows = ai_store.for_review_id(rid, None)
            if not rows:
                continue
            latest = rows[0]
            out[rid] = {"assessment": latest["assessment"],
                        "provider": latest["provider"],
                        "created_at": latest["created_at"]}
        return _AsciiJSON({"available": ai_store.available,
                           "results": out})

    # ---- W3-D: batch AI review -----------------------------------------------
    from auditor.ai.batch import (
        BatchError,
        BatchLimits,
        BatchRunner,
        BatchStore,
        enforce_limits,
        load_pricing,
    )

    batch_store = BatchStore(
        report_path.parent / (report_path.stem + ".ai-batches.json"))
    batch_runner = BatchRunner(
        build_pack=lambda rid: build_context_pack(report, repo, rid),
        ai_store=ai_store, batch_store=batch_store,
        transport_factory=lambda: RequestsTransport())

    def _batch_ids_ok(ids: list[str]) -> JSONResponse | None:
        if not ids:
            return _err(400, "review_ids must be a non-empty list")
        unknown = [r for r in ids if r not in valid_review_ids]
        if unknown:
            return _err(404, f"{len(unknown)} unknown review id(s) for the "
                             "loaded report")
        return None

    @app.post("/api/ai/batches/preview")
    def ai_batch_preview(body: AIConsentPreviewIn) -> JSONResponse:
        provider = _ai_provider(body.provider)
        if provider is None:
            return _err(400, "unknown provider")
        if not body.model.strip():
            return _err(400, "model is required")
        deduped = list(dict.fromkeys(body.review_ids))
        bad = _batch_ids_ok(deduped)
        if bad is not None:
            return bad
        local = _ai_local(provider)
        if not local and not remote_reviews_enabled():
            return _AsciiJSON(
                {"error": "remote AI reviews are disabled by server policy",
                 "status": "privacy_gate_required"}, status_code=403)
        try:
            preview = batch_runner.preview(deduped, provider,
                                           body.model.strip(), local=local)
        except ContextTooLargeError as e:
            return _AsciiJSON({"error": str(e), "status": e.code},
                              status_code=413)
        except BatchError as e:
            return _err(400, str(e))
        preview["provider"] = provider.value
        preview["model"] = body.model.strip()
        if not local:
            token = ai_consents.issue(provider.value, body.model.strip(),
                                      preview["review_ids"],
                                      preview["context_digests"])
            preview["consent_token"] = token
            ai_audit.record("issued", provider.value, body.model.strip(),
                            preview["findings"],
                            binding_hash(provider.value, body.model.strip(),
                                         preview["review_ids"],
                                         preview["context_digests"]),
                            {"input_bytes": preview["input_bytes"],
                             "redactions": preview["redaction_total"]})
        else:
            preview["consent_token"] = ""
        return _AsciiJSON(preview)

    @app.post("/api/ai/batches")
    def ai_batch_start(body: AIBatchIn) -> JSONResponse:
        provider = _ai_provider(body.provider)
        if provider is None:
            return _err(400, "unknown provider")
        if not body.model.strip():
            return _err(400, "model is required")
        if len(body.review_ids) != len(set(body.review_ids)):
            return _err(400, "duplicate review ids in batch")
        bad = _batch_ids_ok(body.review_ids)
        if bad is not None:
            return bad
        local = _ai_local(provider)
        # build the context packs ONCE. The SAME objects feed the consent
        # check, the budget checks, and run_review — no rebuild after
        # redeem, so the digest that was approved is the digest that is
        # sent (no TOCTOU window between consent and send).
        packs: dict[str, Any] = {}
        for rid in body.review_ids:
            try:
                pack = build_context_pack(report, repo, rid)
            except ContextTooLargeError as e:
                return _AsciiJSON({"error": str(e), "status": e.code},
                                  status_code=413)
            if pack is None:
                return _err(404, "unknown review id for the loaded report")
            packs[rid] = pack
        consented = False
        if not local:
            if not remote_reviews_enabled():
                return _AsciiJSON(
                    {"error": "remote AI reviews are disabled by server "
                              "policy", "status": "privacy_gate_required"},
                    status_code=403)
            # the token must bind to EXACTLY these packs' digests; a source
            # change since the preview surfaces as consent_mismatch with
            # zero provider network
            try:
                ai_consents.redeem(body.consent_token, provider.value,
                                   body.model.strip(), body.review_ids,
                                   [packs[r]["digest"]
                                    for r in body.review_ids])
            except ConsentError as e:
                ai_audit.record("denied", provider.value, body.model.strip(),
                                len(body.review_ids), "-", {e.code: 1})
                return _AsciiJSON({"error": str(e), "status": e.code},
                                  status_code=403)
            consented = True
        try:
            limits = BatchLimits.parse(body.limits.model_dump(),
                                       load_pricing() is not None)
            batch_id = batch_runner.start(body.review_ids, provider,
                                          body.model.strip(), limits,
                                          consented, local, packs=packs)
        except BatchError as e:
            msg = str(e)
            return _err(409 if "already running" in msg else 400, msg)
        return _AsciiJSON({"batch_id": batch_id, "state": "running"},
                          status_code=202)

    @app.get("/api/ai/batches/{batch_id}")
    def ai_batch_status(batch_id: str) -> JSONResponse:
        row = batch_runner.status(batch_id)
        if row is None:
            return _err(404, "unknown batch id")
        return _AsciiJSON(row)

    @app.post("/api/ai/batches/{batch_id}/cancel")
    def ai_batch_cancel(batch_id: str) -> JSONResponse:
        if batch_runner.status(batch_id) is None:
            return _err(404, "unknown batch id")
        batch_runner.cancel(batch_id)
        return _AsciiJSON({"batch_id": batch_id, "cancel_requested": True})

    # ---- W3-E: independent AI audit -------------------------------------------
    # The user picks a PROFILE; the versioned catalog picks the queries; the
    # deterministic index retrieves bounded context. No prompt anywhere.
    from auditor.ai.audit import (
        AUDIT_MAX_OUTPUT_TOKENS,
        AuditContextError,
        AuditRunner,
        build_audit_pack,
        estimate_units,
    )
    from auditor.ai.audit_index import RepositoryAuditIndex
    from auditor.ai.audit_queries import PROFILES, queries_for_profile
    from auditor.ai.audit_store import AIAuditStore, AIAuditStoreError
    from auditor.ai.review import review_timeout

    ai_audit_store = AIAuditStore(
        report_path.parent / (report_path.stem + ".ai-audit.json"))
    audit_runner = AuditRunner(
        audit_store=ai_audit_store,
        transport_factory=lambda: RequestsTransport())

    _report_projects: list[tuple[str, str]] = [
        (str(p.get("root", "")), str(p.get("language", "")))
        for p in report.get("projects", [])
        if isinstance(p, dict) and isinstance(p.get("root"), str)]

    # static findings by repo-relative (file, line) — for candidate LINKS only
    _static_by_line: dict[tuple[str, int], list[str]] = {}
    for _proj in report.get("projects", []):
        if not isinstance(_proj, dict):
            continue
        for _f in _proj.get("findings") or []:
            if not isinstance(_f, dict):
                continue
            _rid2 = _finding_review_id(str(_proj.get("root", "")), _f)
            if _rid2 is None:
                continue
            _rel = repo_relative(str(_proj.get("root", "")),
                                 str(_f.get("file", "")))
            _static_by_line.setdefault(
                (_rel, int(_f.get("line", 0))), []).append(_rid2)

    def _build_audit_packs(profile: str,
                           projects: list[str]) -> tuple[list, dict]:
        """Index + packs, built ONCE per request; the same objects feed
        consent, budgets, and sending. Returns (packs, skip_info)."""
        assert repo is not None            # _audit_gate 409s before this
        index = RepositoryAuditIndex(repo, _report_projects)
        wanted = projects or sorted({r for r, _ in _report_projects})
        packs = []
        skipped: dict[str, int] = {}
        for project in sorted(wanted):
            langs = {lang for r, lang in _report_projects if r == project}
            for query in queries_for_profile(profile):
                if langs and not (langs & set(query.languages)):
                    skipped["language not covered"] = \
                        skipped.get("language not covered", 0) + 1
                    continue
                pack = build_audit_pack(index, project, query)
                if pack is None:
                    skipped["no candidate files"] = \
                        skipped.get("no candidate files", 0) + 1
                    continue
                packs.append(pack)
        return packs, {"skipped_units": skipped,
                       "index_skipped": index.skipped}

    def _audit_gate(provider: Provider) -> JSONResponse | None:
        if repo is None:
            return _err(409, "AI audit needs the repository: start the "
                             "server with --repo")
        if not _ai_local(provider) and not remote_reviews_enabled():
            return _AsciiJSON(
                {"error": "remote AI reviews are disabled by server policy",
                 "status": "privacy_gate_required"}, status_code=403)
        return None

    @app.post("/api/ai/audits/preview")
    def ai_audit_preview(body: AIAuditPreviewIn) -> JSONResponse:
        provider = _ai_provider(body.provider)
        if provider is None:
            return _err(400, "unknown provider")
        if body.profile not in PROFILES:
            return _err(400, "unknown audit profile")
        if not body.model.strip():
            return _err(400, "model is required")
        bad = _audit_gate(provider)
        if bad is not None:
            return bad
        known_roots = {r for r, _ in _report_projects}
        unknown = [p for p in body.projects if p not in known_roots]
        if unknown:
            return _err(404, f"{len(unknown)} unknown project root(s)")
        try:
            packs, skip_info = _build_audit_packs(body.profile,
                                                  body.projects)
        except AuditContextError as e:
            return _AsciiJSON({"error": str(e), "status": e.code},
                              status_code=413)
        preview = estimate_units(packs)
        preview.update(skip_info)
        preview["profile"] = body.profile
        preview["provider"] = provider.value
        preview["model"] = body.model.strip()
        preview["queries"] = sorted({p["query_id"] for p in packs})
        preview["projects"] = sorted({p["project"] for p in packs})
        preview["cached"] = sum(
            1 for p in packs
            if ai_audit_store.result_for_unit(p["unit_id"]) is not None)
        preview["fresh"] = preview["units"] - preview["cached"]
        preview["concurrency"] = 1               # local AND remote
        preview["request_timeout_seconds"] = int(review_timeout())
        pricing = load_pricing()
        row = ((pricing or {}).get(provider.value) or {}) \
            .get(body.model.strip()) if pricing else None
        if isinstance(row, dict):
            cost = (preview["estimated_input_tokens"] / 1_000_000) \
                * row["input_per_mtok"] \
                + (preview["max_output_tokens"] / 1_000_000) \
                * row["output_per_mtok"]
            preview["cost_status"] = "estimated"
            preview["estimated_cost_usd"] = round(cost, 4)
        else:
            preview["cost_status"] = "unknown"
        if not _ai_local(provider) and packs:
            token = ai_consents.issue(provider.value, body.model.strip(),
                                      preview["unit_ids"],
                                      preview["context_digests"])
            preview["consent_token"] = token
            ai_audit.record("issued", provider.value, body.model.strip(),
                            preview["units"],
                            binding_hash(provider.value, body.model.strip(),
                                         preview["unit_ids"],
                                         preview["context_digests"]),
                            {"input_bytes": preview["input_bytes"],
                             "redactions": preview["redaction_total"]})
        else:
            preview["consent_token"] = ""
        return _AsciiJSON(preview)

    @app.post("/api/ai/audits")
    def ai_audit_start(body: AIAuditIn) -> JSONResponse:
        provider = _ai_provider(body.provider)
        if provider is None:
            return _err(400, "unknown provider")
        if body.profile not in PROFILES:
            return _err(400, "unknown audit profile")
        if not body.model.strip():
            return _err(400, "model is required")
        bad = _audit_gate(provider)
        if bad is not None:
            return bad
        # packs are built ONCE; the same objects feed consent, budgets, and
        # the requests — no rebuild after redeem (no TOCTOU window)
        try:
            packs, _skip = _build_audit_packs(body.profile, body.projects)
        except AuditContextError as e:
            return _AsciiJSON({"error": str(e), "status": e.code},
                              status_code=413)
        if not packs:
            return _err(400, "no audit units for this profile/projects")
        local = _ai_local(provider)
        # ALL W3-D budgets (incl. max_cost_usd) via the shared helper,
        # checked BEFORE redeem so an over-budget request never consumes the
        # one-time consent token — and before any network either way
        est = estimate_units(packs)
        try:
            limits = BatchLimits.parse(body.limits.model_dump(),
                                       load_pricing() is not None)
            enforce_limits(limits, request_count=est["request_count"],
                           input_bytes=est["input_bytes"],
                           est_input_tokens=est["estimated_input_tokens"],
                           output_tokens_total=len(packs)
                           * AUDIT_MAX_OUTPUT_TOKENS,
                           provider=provider.value,
                           model=body.model.strip())
        except BatchError as e:
            return _err(400, str(e))
        consented = False
        if not local:
            # (unit_id, digest) PAIRS aligned by unit_id — exactly what the
            # preview issued the token against
            pairs = sorted((p["unit_id"], p["digest"]) for p in packs)
            try:
                ai_consents.redeem(body.consent_token, provider.value,
                                   body.model.strip(),
                                   [u for u, _ in pairs],
                                   [d for _, d in pairs])
            except ConsentError as e:
                ai_audit.record("denied", provider.value, body.model.strip(),
                                len(packs), "-", {e.code: 1})
                return _AsciiJSON({"error": str(e), "status": e.code},
                                  status_code=403)
            consented = True
        try:
            audit_id = audit_runner.start(packs, provider,
                                          body.model.strip(), consented,
                                          _static_by_line)
        except RuntimeError as e:
            return _err(409, str(e))
        except (ValueError, AIAuditStoreError) as e:
            return _err(400, str(e))
        return _AsciiJSON({"audit_id": audit_id, "state": "running"},
                          status_code=202)

    @app.get("/api/ai/audits/{audit_id}")
    def ai_audit_status(audit_id: str) -> JSONResponse:
        row = ai_audit_store.audit(audit_id)
        if row is None:
            return _err(404, "unknown audit id")
        counts = {"completed": 0, "failed": 0, "pending": 0, "running": 0,
                  "canceled": 0}
        outcomes = {"issues_found": 0, "no_issue_observed": 0,
                    "insufficient_context": 0}
        for u in row.get("units", []):
            counts[u.get("state", "pending")] = \
                counts.get(u.get("state", "pending"), 0) + 1
            oc = u.get("outcome")
            if oc in outcomes:
                outcomes[oc] += 1
        row["counts"] = counts
        row["outcomes"] = outcomes
        row["remaining"] = counts["pending"] + counts["running"]
        return _AsciiJSON(row)

    @app.post("/api/ai/audits/{audit_id}/cancel")
    def ai_audit_cancel(audit_id: str) -> JSONResponse:
        if ai_audit_store.audit(audit_id) is None:
            return _err(404, "unknown audit id")
        audit_runner.cancel(audit_id)
        return _AsciiJSON({"audit_id": audit_id, "cancel_requested": True})

    @app.put("/api/ai/audit-candidates/{candidate_id}")
    def ai_audit_candidate_review(candidate_id: str,
                                  body: "AICandidateReviewIn") -> JSONResponse:
        """W3-E2: the HUMAN classifies a candidate (confirmed /
        false_positive / uncertain). Stored in the audit sidecar only —
        completely separate from the static findings' review_ids, and it
        never changes the report or the verdict."""
        try:
            entry = ai_audit_store.put_candidate_review(
                candidate_id, body.decision, body.note)
        except AIAuditStoreError as e:
            msg = str(e)
            return _err(404 if "unknown" in msg else 400, msg)
        return _AsciiJSON({"candidate_id": candidate_id, **entry})

    @app.get("/api/ai/audit-results")
    def ai_audit_results() -> JSONResponse:
        return _AsciiJSON({"available": ai_audit_store.available,
                           "error": ai_audit_store.error,
                           "candidates": ai_audit_store.all_candidates(),
                           "note": ("AI-generated candidates are advisory "
                                    "only. Absence of candidates is NOT "
                                    "evidence the project is safe.")})

    @app.get("/api/ai/reviews/{rid}")
    def ai_review_get(rid: str) -> JSONResponse:
        if rid not in valid_review_ids:
            return _err(404, "unknown review id for the loaded report")
        try:
            pack = build_context_pack(report, repo, rid)
        except ContextTooLargeError:
            pack = None
            digest: str | None = ""     # never matches → stored rows are stale
        else:
            digest = pack["digest"] if pack else None
        return _AsciiJSON({"review_id": rid,
                           "available": ai_store.available,
                           "error": ai_store.error,
                           "results": ai_store.for_review_id(rid, digest)})

    # Serve the bundled SPA last so /api/* wins. html=True makes "/" return
    # index.html. Mount only if the build exists — the API is usable without it.
    if (_STATIC_DIR / "index.html").is_file():
        app.mount("/", StaticFiles(directory=str(_STATIC_DIR), html=True), name="spa")

    return app
