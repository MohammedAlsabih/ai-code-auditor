from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
VALID_STATUSES = ("confirmed", "false_positive", "accepted_risk")
NOTE_MAX_CHARS = 2000
# decisions-only data: even thousands of reviews stay far below this. The
# loader reads cap+1 BOUNDED bytes — an oversized/hostile sidecar can never be
# slurped into memory, it just renders reviews unavailable.
SIDECAR_MAX_BYTES = 5 * 1024 * 1024

_RID_RE = re.compile(r"^[0-9a-f]{64}$")
# indirections so tests can fail each syscall of the atomic write precisely
_replace = os.replace
_mkstemp = tempfile.mkstemp
_fdopen = os.fdopen


def review_id(project: str, file: str, line: int, rule_id: str,
              title: str, engine: str) -> str:
    """Deterministic identity of ONE finding: SHA-256 over the CANONICAL JSON
    ARRAY of the identity fields — a structural encoding, so no delimiter
    injection can collide two different findings (["a\\x1fb","c.py",...] and
    ["a","b\\x1fc.py",...] serialize differently). Never Python's salted
    hash() and never a row index: identical across processes and restarts.

    Consequence (by design): if a re-scan changes ANY identity field — the
    finding moved to another line, the rule retitled, the file renamed — the
    finding gets a NEW review_id and shows as unreviewed. A stored decision is
    therefore never attributed to a different finding; the old record simply
    goes orphaned in the sidecar.

    ensure_ascii=True makes the canonical form pure ASCII: every value —
    including lone surrogates from a malformed title — is \\uXXXX-escaped, so
    the utf-8 encode below can never raise. Deterministic separators keep the
    encoding canonical."""
    key = json.dumps([project, file, line, rule_id, title, engine],
                     ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


class ReviewStoreError(Exception):
    """Sidecar unusable (corrupt or IO failure). Messages are user-safe: no
    machine paths — exception CLASS names only for OS errors."""


def _validate_sidecar(data: Any) -> dict[str, dict[str, Any]] | str:
    """STRICT whole-file validation. Returns the reviews dict, or an error
    string. Any unsupported version or single malformed entry makes the whole
    store unavailable — nothing is dropped, repaired, or rewritten silently."""
    if not isinstance(data, dict):
        return "not a reviews-sidecar object"
    if set(data) != {"schema_version", "reviews"}:
        return "top-level keys must be exactly schema_version and reviews"
    version = data.get("schema_version")
    if version != SCHEMA_VERSION:
        return f"unsupported schema_version {version!r} (supported: {SCHEMA_VERSION})"
    reviews = data.get("reviews")
    if not isinstance(reviews, dict):
        return "'reviews' must be an object"
    out: dict[str, dict[str, Any]] = {}
    for rid, entry in reviews.items():
        if not isinstance(rid, str) or not _RID_RE.match(rid):
            return "invalid review id shape (expected 64 lowercase hex chars)"
        if not isinstance(entry, dict):
            return f"entry for {rid[:12]}… is not an object"
        if set(entry) != {"status", "note", "updated_at"}:
            return (f"entry for {rid[:12]}… must carry exactly "
                    "status/note/updated_at")
        if entry["status"] not in VALID_STATUSES:
            return f"entry for {rid[:12]}… has invalid status {entry['status']!r}"
        if not isinstance(entry["note"], str) or len(entry["note"]) > NOTE_MAX_CHARS:
            return f"entry for {rid[:12]}… has an invalid or oversized note"
        if not isinstance(entry["updated_at"], str):
            return f"entry for {rid[:12]}… has an invalid updated_at"
        out[rid] = dict(entry)
    return out


class ReviewStore:
    """The explorer's ONLY writable artifact: a JSON sidecar next to the report
    (report.json -> report.reviews.json), path fixed at startup — never taken
    from the browser. Loaded once (bounded read + strict validation); every
    mutation is serialized under a lock and written ATOMICALLY (temp file in
    the same directory, then os.replace); the new state is published to memory
    only AFTER the disk write succeeded, so a failed write loses nothing. A
    corrupt, oversized, or future-versioned sidecar is never overwritten or
    silently reset: the store reports unavailable and refuses writes."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._reviews: dict[str, dict[str, Any]] = {}
        self.error: str | None = None
        if not path.exists():
            return
        try:
            with path.open("rb") as fh:
                raw = fh.read(SIDECAR_MAX_BYTES + 1)   # bounded — never a full slurp
        except OSError as e:
            self.error = f"reviews sidecar unreadable: {e.__class__.__name__}"
            return
        if len(raw) > SIDECAR_MAX_BYTES:
            self.error = (f"reviews sidecar exceeds the {SIDECAR_MAX_BYTES}-byte cap")
            return
        try:
            data = json.loads(raw.decode("utf-8", errors="strict"))
        except (ValueError, UnicodeDecodeError) as e:
            # json/unicode errors carry positions, never machine paths
            self.error = f"reviews sidecar corrupt: {e}"
            return
        validated = _validate_sidecar(data)
        if isinstance(validated, str):
            self.error = f"reviews sidecar rejected: {validated}"
            return
        self._reviews = validated

    @property
    def available(self) -> bool:
        return self.error is None

    def all(self) -> dict[str, dict[str, Any]]:
        return {k: dict(v) for k, v in self._reviews.items()}

    def put(self, rid: str, status: str, note: str) -> dict[str, Any]:
        entry = {
            "status": status,
            "note": note,
            "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        with self._lock:
            self._guard()
            new = dict(self._reviews)
            new[rid] = entry
            self._write(new)          # raises WITHOUT touching in-memory state
            self._reviews = new       # publish only after the disk write landed
        return dict(entry)

    def delete(self, rid: str) -> None:
        with self._lock:
            self._guard()
            if rid not in self._reviews:
                return                # already unreviewed — idempotent
            new = dict(self._reviews)
            new.pop(rid)
            self._write(new)
            self._reviews = new

    def _guard(self) -> None:
        if self.error is not None:
            raise ReviewStoreError(self.error)

    def _write(self, reviews: dict[str, dict[str, Any]]) -> None:
        """Atomic write with FULL failure containment: mkstemp, fdopen, write
        and replace all live inside the guarded path — any OSError (including
        PermissionError on temp creation) cleans up the fd/temp file if they
        exist and surfaces as a user-safe ReviewStoreError (API 503, never an
        internal 500)."""
        # ensure_ascii=True => the payload is pure ASCII (a lone surrogate in a
        # note becomes a \uXXXX escape that json.loads reads back identically),
        # so the utf-8 file write cannot raise mid-stream. UnicodeError stays in
        # the cleanup net below anyway as defense in depth.
        payload = json.dumps({"schema_version": SCHEMA_VERSION, "reviews": reviews},
                             ensure_ascii=True, indent=1)
        fd: int | None = None
        tmp: str | None = None
        try:
            fd, tmp = _mkstemp(prefix=self.path.name + ".",
                               suffix=".tmp", dir=str(self.path.parent))
            with _fdopen(fd, "w", encoding="utf-8") as fh:
                fd = None             # the file object owns (and closes) the fd now
                fh.write(payload)
            _replace(tmp, self.path)  # atomic on the same filesystem
            tmp = None
        except (OSError, UnicodeError) as e:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if tmp is not None:
                try:
                    os.unlink(tmp)    # never leave temp debris behind
                except OSError:
                    pass
            raise ReviewStoreError(
                f"could not write reviews sidecar: {e.__class__.__name__}") from e
