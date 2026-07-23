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
