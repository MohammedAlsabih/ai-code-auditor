"""W3-C: remote-review consent — the server-side gate, the one-time token,
and the local audit trail.

Remote AI review is DISABLED by default. Two independent conditions must
both hold before a single byte reaches a remote provider:

1. an ADMIN enabled it in the server environment:
       AUDITOR_AI_REMOTE_REVIEWS=confirm
2. the USER approved the SPECIFIC payload: a consent-preview names the
   provider/model/locality, the finding and file counts, the input bytes, a
   conservative token estimate, and the redaction counters — and returns a
   short-lived, one-time consent token bound to the exact review_ids +
   context digests + provider + model.

Any context change, any expiry, any reuse → the consent is void and must be
re-granted. Local providers (the W3-B loopback set) never need a token.

The audit sidecar (`<report>.ai-consent.json`, git-ignored, atomic) records
ONLY: event type, timestamp, provider, model, counts, and the binding hash.
Never code, prompts, secrets, or the raw token (its SHA-256 only).
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

REMOTE_REVIEWS_ENV = "AUDITOR_AI_REMOTE_REVIEWS"
REMOTE_REVIEWS_VALUE = "confirm"
CONSENT_TTL_SECONDS = 600.0          # a grant is valid for 10 minutes
AUDIT_MAX_EVENTS = 1000
AUDIT_MAX_BYTES = 5 * 1024 * 1024

# conservative token estimate: 1 token per 3 bytes (over-estimates for code)
TOKEN_ESTIMATE_BYTES_PER_TOKEN = 3


def remote_reviews_enabled(env: dict[str, str] | None = None) -> bool:
    e = os.environ if env is None else env
    return (e.get(REMOTE_REVIEWS_ENV) or "").strip() == REMOTE_REVIEWS_VALUE


class ConsentError(Exception):
    """A consent problem with ONE legal code and a fixed safe message."""

    MESSAGES = {
        "consent_required": "remote review requires an explicit consent "
                            "token for this exact payload",
        "consent_expired": "the consent token expired — request a new "
                           "consent preview",
        "consent_reused": "the consent token was already used — consent is "
                          "one-time per send",
        "consent_mismatch": "the consent token does not match this payload "
                            "(context, findings, provider, or model "
                            "changed) — request a new consent preview",
    }

    def __init__(self, code: str) -> None:
        if code not in self.MESSAGES:
            raise ValueError(f"illegal consent code: {code!r}")
        self.code = code
        super().__init__(self.MESSAGES[code])


def binding_hash(provider: str, model: str, review_ids: list[str],
                 digests: list[str]) -> str:
    """The exact payload identity a grant is bound to: the canonical list of
    (review_id, context_digest) PAIRS sorted by review_id + provider +
    model. Pairing is essential — sorting the two lists separately would let
    two findings SWAP digests without changing the binding. Mismatched
    lengths, duplicate review_ids, or a non-string/empty id or digest raise
    ValueError (redeem maps it to consent_mismatch)."""
    if len(review_ids) != len(digests):
        raise ValueError("review_ids and digests must pair one-to-one")
    if len(set(review_ids)) != len(review_ids):
        raise ValueError("duplicate review_ids in a consent binding")
    for value in (*review_ids, *digests):
        if not isinstance(value, str) or not value:
            raise ValueError("consent binding ids/digests must be "
                             "non-empty strings")
    pairs = sorted(zip(review_ids, digests), key=lambda p: p[0])
    blob = json.dumps([provider, model, [list(p) for p in pairs]],
                      ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class _Grant:
    token_hash: str
    binding: str
    expires_at: float
    used: bool = False


class ConsentRegistry:
    """In-process, short-lived, one-time grants. The raw token exists only in
    the HTTP response to the user; the registry stores its hash."""

    def __init__(self, now: Callable[[], float] = time.monotonic) -> None:
        self._now = now
        self._lock = threading.Lock()
        self._grants: dict[str, _Grant] = {}

    def issue(self, provider: str, model: str, review_ids: list[str],
              digests: list[str]) -> str:
        token = secrets.token_urlsafe(32)
        th = hashlib.sha256(token.encode("ascii")).hexdigest()
        grant = _Grant(token_hash=th,
                       binding=binding_hash(provider, model, review_ids,
                                            digests),
                       expires_at=self._now() + CONSENT_TTL_SECONDS)
        with self._lock:
            # drop anything already expired while we are here
            self._grants = {k: g for k, g in self._grants.items()
                            if g.expires_at > self._now() }
            self._grants[th] = grant
        return token

    def redeem(self, token: str, provider: str, model: str,
               review_ids: list[str], digests: list[str]) -> None:
        """Consume the token for EXACTLY the bound payload or raise. One
        redeem per token, ever."""
        if not token or not isinstance(token, str):
            raise ConsentError("consent_required")
        th = hashlib.sha256(token.encode("ascii", errors="replace")) \
            .hexdigest()
        with self._lock:
            grant = self._grants.get(th)
            if grant is None:
                raise ConsentError("consent_required")
            if self._now() > grant.expires_at:
                del self._grants[th]
                raise ConsentError("consent_expired")
            if grant.used:
                raise ConsentError("consent_reused")
            try:
                offered = binding_hash(provider, model, review_ids, digests)
            except ValueError:
                raise ConsentError("consent_mismatch") from None
            if grant.binding != offered:
                raise ConsentError("consent_mismatch")
            grant.used = True


def build_consent_preview(provider: str, model: str, locality: str,
                          packs: list[dict[str, Any]]) -> dict[str, Any]:
    """The user-facing summary of EXACTLY what would be sent. No code. Cost
    and retention are 'unknown' unless trustworthy evidence exists — W3-C
    ships no provider price table, so they are always 'unknown' here."""
    input_bytes = 0
    files = 0
    redactions: dict[str, int] = {}
    digests: list[str] = []
    for pack in packs:
        manifest = pack.get("privacy_manifest") or {}
        input_bytes += int(manifest.get("bytes_after", 0))
        files += int(manifest.get("files_sent", 0))
        for cat, n in (manifest.get("redactions") or {}).items():
            redactions[cat] = redactions.get(cat, 0) + int(n)
        digests.append(pack["digest"])
    return {
        "provider": provider,
        "model": model,
        "locality": locality,
        "findings": len(packs),
        "files": files,
        "input_bytes": input_bytes,
        "estimated_input_tokens":
            -(-input_bytes // TOKEN_ESTIMATE_BYTES_PER_TOKEN),
        "redactions": dict(sorted(redactions.items())),
        "redaction_total": sum(redactions.values()),
        "retention": "unknown",
        "cost": "unknown",
        "context_digests": sorted(digests),
    }


# ---- local audit sidecar -----------------------------------------------------------

class ConsentAudit:
    """Append-only local audit of consent events. Atomic writes; bounded;
    counters and hashes only — never code, prompts, tokens, or secrets."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._events: list[dict[str, Any]] = []
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            raw = self._path.read_bytes()[:AUDIT_MAX_BYTES + 1]
            data = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return                      # audit is best-effort; never crash
        if isinstance(data, dict) and isinstance(data.get("events"), list):
            self._events = [e for e in data["events"] if isinstance(e, dict)]

    def record(self, event: str, provider: str, model: str,
               n_review_ids: int, binding: str,
               counters: dict[str, int] | None = None) -> None:
        row = {
            "event": event,             # issued | redeemed | denied
            "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "provider": provider, "model": model,
            "review_ids": n_review_ids,
            "binding": binding,
            "counters": {k: int(v) for k, v in (counters or {}).items()},
        }
        with self._lock:
            self._events.append(row)
            self._events = self._events[-AUDIT_MAX_EVENTS:]
            payload = json.dumps({"schema_version": 1,
                                  "events": self._events},
                                 ensure_ascii=True, indent=1)
            try:
                fd, tmp = tempfile.mkstemp(dir=str(self._path.parent),
                                           prefix=self._path.name + ".",
                                           suffix=".tmp")
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(payload)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, self._path)
            except OSError:
                pass                    # audit failure never blocks the flow
