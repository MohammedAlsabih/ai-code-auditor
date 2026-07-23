"""W3-D: batch AI review — one request per finding, hard budgets, safe stop.

Contract highlights (enforced here, not by callers):

- EVERY finding is reviewed by its OWN request with its OWN context pack —
  snippets are never pooled into one prompt.
- Batch states: pending | running | completed | failed | canceled |
  interrupted. A process restart turns a persisted `running` batch into
  `interrupted`; it never resumes silently.
- Hard defaults: at most 100 findings; conservative concurrency (remote = 1;
  local = 1, with 2 as an explicit server-environment opt-in and hard cap);
  NO automatic retry. Cancel stops the NEXT request from starting and never
  corrupts the one in flight.
- Duplicate review_ids are rejected BEFORE any network. The review_ids and
  their context packs are FROZEN at start: the API builds each pack ONCE
  and the same objects feed the consent check, the budget checks, and
  run_review — the digest that was approved is the digest that is sent.
- The user supplies MANDATORY caps: max_requests, max_input_bytes (or an
  estimated-token cap), max_output_tokens; max_cost_usd only together with
  an explicit local pricing config. Breaching any cap before or during the
  run stops safely WITHOUT the next request.
- Cost estimates exist ONLY when prices were explicitly configured locally
  (AUDITOR_AI_PRICING = path to a JSON file); no provider price is ever
  hardcoded. Otherwise cost_status="unknown".
- Batch metadata lives in `<report>.ai-batches.json` — separate, ignored,
  atomic, no source and no prompts. Finding results land in the normal
  ai-reviews sidecar, advisory as ever.
"""
from __future__ import annotations

import json
import math
import os
import secrets
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from auditor.ai.consent import (
    TOKEN_ESTIMATE_BYTES_PER_TOKEN,
    ConsentError,
)
from auditor.ai.contract import AIError, Provider
from auditor.ai.review import (
    PROMPT_VERSION,
    REVIEW_MAX_TOKENS,
    AIReviewRequest,
    PrivacyGateError,
    review_timeout,
    run_review,
)

BATCH_MAX_FINDINGS = 100
BATCH_STATES = ("pending", "running", "completed", "failed", "canceled",
                "interrupted")
ITEM_STATES = ("pending", "running", "completed", "failed", "canceled")
REMOTE_CONCURRENCY = 1
# field-calibrated by the live W3-D smokes: concurrent requests to a local
# model starve each other into timeouts, so LOCAL defaults to 1 and 2 is an
# explicit server-side opt-in with a hard upper bound.
LOCAL_CONCURRENCY_DEFAULT = 1
LOCAL_CONCURRENCY_MAX = 2
LOCAL_CONCURRENCY_ENV = "AUDITOR_AI_LOCAL_CONCURRENCY"
PRICING_ENV = "AUDITOR_AI_PRICING"
SIDECAR_MAX_BYTES = 10 * 1024 * 1024


def local_concurrency(env: dict[str, str] | None = None) -> int:
    """1 by default. EXACTLY "2" in the server environment opts into two
    local workers (the hard cap); any other value stays at the default."""
    e = os.environ if env is None else env
    raw = (e.get(LOCAL_CONCURRENCY_ENV) or "").strip()
    return 2 if raw == "2" else LOCAL_CONCURRENCY_DEFAULT


class BatchError(Exception):
    """Invalid batch input or state. Fixed safe messages only."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_pricing(env: dict[str, str] | None = None) -> dict[str, Any] | None:
    """Explicit local pricing config or None. Shape:
    {provider: {model: {"input_per_mtok": float, "output_per_mtok": float}}}
    Anything malformed → None (cost stays unknown; never guessed)."""
    e = os.environ if env is None else env
    path = (e.get(PRICING_ENV) or "").strip()
    if not path:
        return None
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    for models in data.values():
        if not isinstance(models, dict):
            return None
        for row in models.values():
            if not isinstance(row, dict):
                return None
            for k in ("input_per_mtok", "output_per_mtok"):
                v = row.get(k)
                # json.loads parses NaN/Infinity happily, and a NaN price
                # makes every cost comparison silently false — prices must
                # be FINITE and strictly positive or the config is void
                if not isinstance(v, (int, float)) or isinstance(v, bool) \
                        or not math.isfinite(v) or v <= 0:
                    return None
    return data


@dataclass
class BatchLimits:
    """User-supplied MANDATORY budget. max_cost_usd is legal only when a
    pricing config exists."""
    max_requests: int
    max_output_tokens: int
    max_input_bytes: int | None = None
    max_input_tokens: int | None = None
    max_cost_usd: float | None = None

    @staticmethod
    def parse(raw: Any, pricing_available: bool) -> "BatchLimits":
        if not isinstance(raw, dict):
            raise BatchError("limits must be an object")
        allowed = {"max_requests", "max_output_tokens", "max_input_bytes",
                   "max_input_tokens", "max_cost_usd"}
        if set(raw) - allowed:
            raise BatchError("limits carries an unknown field")

        def pos_int(name: str, required: bool) -> int | None:
            v = raw.get(name)
            if v is None:
                if required:
                    raise BatchError(f"limits.{name} is required")
                return None
            if not isinstance(v, int) or isinstance(v, bool) or v <= 0:
                raise BatchError(f"limits.{name} must be a positive integer")
            return v

        max_requests = pos_int("max_requests", True)
        max_output = pos_int("max_output_tokens", True)
        in_bytes = pos_int("max_input_bytes", False)
        in_tokens = pos_int("max_input_tokens", False)
        if in_bytes is None and in_tokens is None:
            raise BatchError(
                "limits needs max_input_bytes or max_input_tokens")
        cost = raw.get("max_cost_usd")
        if cost is not None:
            if not pricing_available:
                raise BatchError("max_cost_usd requires an explicit local "
                                 "pricing config (AUDITOR_AI_PRICING)")
            if not isinstance(cost, (int, float)) or isinstance(cost, bool) \
                    or not math.isfinite(cost) or cost <= 0:
                raise BatchError("limits.max_cost_usd must be a finite "
                                 "positive number")
        assert max_requests is not None and max_output is not None
        return BatchLimits(max_requests=max_requests,
                           max_output_tokens=max_output,
                           max_input_bytes=in_bytes,
                           max_input_tokens=in_tokens,
                           max_cost_usd=float(cost) if cost else None)


class BatchStore:
    """Atomic, bounded metadata sidecar. On load, any batch persisted as
    running/pending becomes `interrupted` — a restart never resumes."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._batches: dict[str, dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            raw = self._path.read_bytes()[:SIDECAR_MAX_BYTES + 1]
            data = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return
        if not isinstance(data, dict) \
                or not isinstance(data.get("batches"), dict):
            return
        changed = False
        for bid, row in data["batches"].items():
            if not isinstance(row, dict):
                continue
            if row.get("state") in ("running", "pending"):
                row["state"] = "interrupted"
                for item in row.get("items", []):
                    if isinstance(item, dict) \
                            and item.get("state") in ("running", "pending"):
                        item["state"] = "canceled"
                changed = True
            self._batches[bid] = row
        if changed:
            try:
                self._write_locked()
            except BatchError:
                pass

    def _write_candidate(self, candidate: dict[str, dict[str, Any]]) -> None:
        """Serialize + size-check + atomic replace; raises WITHOUT touching
        memory or leaving tmp litter — the caller commits after success."""
        payload = json.dumps({"schema_version": 1, "batches": candidate},
                             ensure_ascii=True, sort_keys=True, indent=1)
        if len(payload.encode("utf-8")) > SIDECAR_MAX_BYTES:
            raise BatchError("batch sidecar would exceed its size cap")
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(dir=str(self._path.parent),
                                       prefix=self._path.name + ".",
                                       suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._path)
        except OSError as e:
            if tmp is not None:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
            raise BatchError(
                f"batch sidecar write failed: {e.__class__.__name__}") from e

    def _write_locked(self) -> None:
        self._write_candidate(self._batches)

    def put(self, batch: dict[str, Any]) -> None:
        with self._lock:
            candidate = dict(self._batches)
            candidate[batch["batch_id"]] = batch
            self._write_candidate(candidate)
            self._batches = candidate

    def get(self, batch_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._batches.get(batch_id)
            return json.loads(json.dumps(row)) if row is not None else None


@dataclass
class _RunState:
    cancel: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = None


class BatchRunner:
    """One batch at a time per process. Deterministic budgets, conservative
    concurrency, no retries, safe stop."""

    def __init__(self, build_pack: Callable[[str], dict[str, Any] | None],
                 ai_store: Any, batch_store: BatchStore,
                 transport_factory: Callable[[], Any],
                 env: dict[str, str] | None = None) -> None:
        self._build_pack = build_pack
        self._ai_store = ai_store
        self._batch_store = batch_store
        self._transport_factory = transport_factory
        self._env = env
        self._lock = threading.Lock()
        self._active: str | None = None
        self._runs: dict[str, _RunState] = {}

    # ---- preview -------------------------------------------------------------
    def preview(self, review_ids: list[str], provider: Provider,
                model: str, local: bool = True) -> dict[str, Any]:
        ids = list(dict.fromkeys(review_ids))     # dedupe, order-preserving
        if not ids:
            raise BatchError("no findings to review")
        if len(ids) > BATCH_MAX_FINDINGS:
            raise BatchError(
                f"a batch may not exceed {BATCH_MAX_FINDINGS} findings")
        packs: dict[str, dict[str, Any]] = {}
        input_bytes = 0
        redactions: dict[str, int] = {}
        cached = fresh = stale = 0
        for rid in ids:
            pack = self._build_pack(rid)
            if pack is None:
                raise BatchError("a review id is unknown for this report")
            packs[rid] = pack
            manifest = pack.get("privacy_manifest") or {}
            input_bytes += int(manifest.get("bytes_after", 0))
            for cat, n in (manifest.get("redactions") or {}).items():
                redactions[cat] = redactions.get(cat, 0) + int(n)
            rows = self._ai_store.for_review_id(rid, pack["digest"])
            same = [r for r in rows
                    if not r.get("stale")
                    and r["provider"] == provider.value
                    and r["model"] == model
                    and r["prompt_version"] == PROMPT_VERSION]
            if same:
                cached += 1
            elif rows:
                stale += 1
            else:
                fresh += 1
        est_tokens = -(-input_bytes // TOKEN_ESTIMATE_BYTES_PER_TOKEN)
        out: dict[str, Any] = {
            "findings": len(ids),
            "review_ids": ids,
            "input_bytes": input_bytes,
            "estimated_input_tokens": est_tokens,
            "max_output_tokens": len(ids) * REVIEW_MAX_TOKENS,
            "request_count": len(ids),
            "redactions": dict(sorted(redactions.items())),
            "redaction_total": sum(redactions.values()),
            "cached": cached, "fresh": fresh, "stale": stale,
            "context_digests": sorted(p["digest"] for p in packs.values()),
            # the EFFECTIVE runtime parameters, so the user approves what
            # will actually run — no secrets, just two integers
            "concurrency": (local_concurrency(self._env) if local
                            else REMOTE_CONCURRENCY),
            "request_timeout_seconds": int(review_timeout(self._env)),
        }
        pricing = load_pricing(self._env)
        row = ((pricing or {}).get(provider.value) or {}).get(model) \
            if pricing else None
        if isinstance(row, dict):
            cost = (est_tokens / 1_000_000) * row["input_per_mtok"] \
                + (out["max_output_tokens"] / 1_000_000) \
                * row["output_per_mtok"]
            out["cost_status"] = "estimated"
            out["estimated_cost_usd"] = round(cost, 4)
        else:
            out["cost_status"] = "unknown"
        return out

    # ---- start / cancel / status ----------------------------------------------
    def start(self, review_ids: list[str], provider: Provider, model: str,
              limits: BatchLimits, consented: bool, local: bool,
              packs: dict[str, dict[str, Any]] | None = None) -> str:
        """`packs` (when given) are used VERBATIM for budget checks and for
        run_review — they must be the SAME objects the consent token was
        redeemed against. There is no rebuild after redeem, so the digest
        that was approved is the digest that is sent (no TOCTOU window)."""
        if len(review_ids) != len(set(review_ids)):
            raise BatchError("duplicate review ids in batch")   # pre-network
        if not review_ids:
            raise BatchError("no findings to review")
        if len(review_ids) > BATCH_MAX_FINDINGS:
            raise BatchError(
                f"a batch may not exceed {BATCH_MAX_FINDINGS} findings")
        if packs is None:
            packs = {}
            for rid in review_ids:
                pack = self._build_pack(rid)
                if pack is None:
                    raise BatchError("a review id is unknown for this report")
                packs[rid] = pack
        if set(packs) != set(review_ids):
            raise BatchError("packs do not match the batch review ids")
        input_bytes = sum(int((packs[rid].get("privacy_manifest") or {})
                              .get("bytes_after", 0)) for rid in review_ids)
        est_tokens = -(-input_bytes // TOKEN_ESTIMATE_BYTES_PER_TOKEN)
        # pre-start budget verification — nothing has gone out yet
        if len(review_ids) > limits.max_requests:
            raise BatchError("limits.max_requests is below the batch size")
        if limits.max_input_bytes is not None \
                and input_bytes > limits.max_input_bytes:
            raise BatchError("the batch exceeds limits.max_input_bytes")
        if limits.max_input_tokens is not None \
                and est_tokens > limits.max_input_tokens:
            raise BatchError("the batch exceeds limits.max_input_tokens")
        if len(review_ids) * REVIEW_MAX_TOKENS > limits.max_output_tokens:
            raise BatchError("the batch exceeds limits.max_output_tokens")
        if limits.max_cost_usd is not None:
            pricing = load_pricing(self._env)
            row = ((pricing or {}).get(provider.value) or {}).get(model) \
                if pricing else None
            if not isinstance(row, dict):
                raise BatchError("max_cost_usd requires pricing for this "
                                 "provider/model in the pricing config")
            cost = (est_tokens / 1_000_000) * row["input_per_mtok"] \
                + (len(review_ids) * REVIEW_MAX_TOKENS / 1_000_000) \
                * row["output_per_mtok"]
            if cost > limits.max_cost_usd:
                raise BatchError("the estimated cost exceeds "
                                 "limits.max_cost_usd")
        with self._lock:
            if self._active is not None:
                raise BatchError("another batch is already running")
            batch_id = "b" + secrets.token_hex(8)
            self._active = batch_id
        # ANY failure between claiming _active and a successfully started
        # thread must roll the claim back, or every later batch dies with
        # "another batch is already running"
        try:
            batch = {
                "batch_id": batch_id,
                "state": "running",
                "created_at": _now_iso(),
                "provider": provider.value, "model": model,
                "prompt_version": PROMPT_VERSION,
                "limits": {"max_requests": limits.max_requests,
                           "max_output_tokens": limits.max_output_tokens,
                           "max_input_bytes": limits.max_input_bytes,
                           "max_input_tokens": limits.max_input_tokens,
                           "max_cost_usd": limits.max_cost_usd},
                "reason": "",
                "items": [{"review_id": rid, "state": "pending",
                           "assessment": "", "error": ""}
                          for rid in review_ids],
            }
            self._batch_store.put(batch)
            run = _RunState()
            self._runs[batch_id] = run
            workers = local_concurrency(self._env) if local \
                else REMOTE_CONCURRENCY
            run.thread = threading.Thread(
                target=self._execute,
                args=(batch, packs, provider, model, consented, workers, run),
                daemon=True)
            run.thread.start()
        except BaseException:
            with self._lock:
                if self._active == batch_id:
                    self._active = None
            self._runs.pop(batch_id, None)
            raise
        return batch_id

    def _execute(self, batch: dict[str, Any], packs: dict[str, dict],
                 provider: Provider, model: str, consented: bool,
                 workers: int, run: _RunState) -> None:
        items = batch["items"]
        idx_lock = threading.Lock()
        next_idx = {"i": 0}
        stop_reason = {"reason": ""}

        def take() -> dict[str, Any] | None:
            with idx_lock:
                if run.cancel.is_set() or stop_reason["reason"]:
                    return None
                i = next_idx["i"]
                if i >= len(items):
                    return None
                next_idx["i"] = i + 1
                items[i]["state"] = "running"
                return items[i]

        def worker() -> None:
            while True:
                item = take()
                if item is None:
                    return
                rid = item["review_id"]
                try:
                    result = run_review(
                        AIReviewRequest(review_id=rid, provider=provider,
                                        model=model),
                        packs[rid], self._transport_factory(),
                        env=self._env, consented=consented)
                    self._ai_store.put(result)
                    item["state"] = "completed"
                    item["assessment"] = result["assessment"]
                except (AIError, PrivacyGateError, ConsentError) as e:
                    item["state"] = "failed"
                    item["error"] = getattr(e, "code", "error")
                except Exception:                     # noqa: BLE001
                    item["state"] = "failed"          # never kill the batch
                    item["error"] = "internal_error"
                try:
                    self._batch_store.put(batch)
                except BatchError:
                    # a mid-run metadata failure stops the NEXT request from
                    # starting (safe stop) instead of killing this worker
                    # thread silently
                    with idx_lock:
                        stop_reason["reason"] = \
                            "batch metadata could not be persisted"

        try:
            threads = [threading.Thread(target=worker, daemon=True)
                       for _ in range(max(1, workers))]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            for item in items:
                if item["state"] in ("pending", "running"):
                    item["state"] = "canceled"
            if run.cancel.is_set():
                batch["state"] = "canceled"
                batch["reason"] = "canceled by user"
            elif stop_reason["reason"]:
                batch["state"] = "failed"
                batch["reason"] = stop_reason["reason"]
            else:
                batch["state"] = "completed"
            try:
                self._batch_store.put(batch)
            except BatchError:
                pass          # final persist is best-effort; _active still frees
        finally:
            with self._lock:
                if self._active == batch["batch_id"]:
                    self._active = None

    def cancel(self, batch_id: str) -> bool:
        run = self._runs.get(batch_id)
        if run is None:
            return False
        run.cancel.set()
        return True

    def status(self, batch_id: str) -> dict[str, Any] | None:
        row = self._batch_store.get(batch_id)
        if row is None:
            return None
        counts = {"completed": 0, "failed": 0, "pending": 0, "running": 0,
                  "canceled": 0}
        assessments = {"confirmed": 0, "false_positive": 0, "uncertain": 0}
        for item in row.get("items", []):
            counts[item.get("state", "pending")] = \
                counts.get(item.get("state", "pending"), 0) + 1
            a = item.get("assessment")
            if a in assessments:
                assessments[a] += 1
        row["counts"] = counts
        row["assessments"] = assessments
        row["remaining"] = counts["pending"] + counts["running"]
        return row

    def wait(self, batch_id: str, timeout: float = 30.0) -> None:
        """Test helper: join the batch thread."""
        run = self._runs.get(batch_id)
        if run and run.thread:
            run.thread.join(timeout)
