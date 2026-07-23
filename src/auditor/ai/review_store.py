"""W3-B: local store for AI review results — `<report>.ai-reviews.json`.

A SEPARATE sidecar: it never touches report.json and never touches the human
reviews sidecar (`<report>.reviews.json`). Git-ignored. Atomic writes
(mkstemp + fsync + os.replace) exactly like the human store.

Keyed by the full result identity — review_id + provider + model +
prompt_version + context_digest — so a re-run with a different model or a
changed context NEVER silently overwrites or reuses an old verdict. Reads
against a CURRENT context digest mark mismatching entries stale; a stale
entry is returned as history but is never presented as a fresh answer.

Only the structured, validated, already-redacted result is stored: no
prompt, no source, no snippet, no API key.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
from pathlib import Path
from typing import Any

from auditor.ai.contract import Provider
from auditor.ai.review import (
    ASSESSMENTS,
    CONFIDENCES,
    EVIDENCE_MAX,
    EVIDENCE_MIN,
    MISSING_MAX,
    MISSING_MAX_CHARS,
    STATEMENT_MAX_CHARS,
    SUGGESTED_ACTIONS,
    SUMMARY_MAX_CHARS,
)

SCHEMA_VERSION = 1
SIDECAR_MAX_BYTES = 10 * 1024 * 1024

_RESULT_KEYS = {"review_id", "provider", "model", "prompt_version",
                "latency_ms", "context_digest", "created_at", "assessment",
                "confidence", "summary", "evidence", "missing_context",
                "suggested_action"}
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_PROMPT_VERSION_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,31}$")
_CREATED_AT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_CONTEXT_ID_MAX_CHARS = 64
_MODEL_MAX_CHARS = 128
_PROVIDERS = {p.value for p in Provider}

# indirections so tests can fail each syscall of the atomic write precisely
_replace = os.replace
_mkstemp = tempfile.mkstemp
_fdopen = os.fdopen


class AIReviewStoreError(Exception):
    """Sidecar unusable (corrupt or IO failure). Messages carry exception
    CLASS names only — never machine paths."""


def result_key(result: dict[str, Any]) -> str:
    """Deterministic composite key over the result identity."""
    blob = json.dumps([result["review_id"], result["provider"],
                       result["model"], result["prompt_version"],
                       result["context_digest"]],
                      ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _ok_text(v: Any, max_chars: int, allow_empty: bool = False) -> bool:
    """Bounded, printable text — the same discipline the AIReviewResult
    parser applies: no control characters beyond \\n and \\t."""
    if not isinstance(v, str):
        return False
    if not v.strip() and not allow_empty:
        return False
    if len(v) > max_chars:
        return False
    return not any(ord(c) < 0x20 and c not in "\n\t" for c in v)


def _valid_result(entry: Any) -> bool:
    """The FULL AIReviewResult v1 contract re-checked at the storage
    boundary: exact keys, legal enums, the same text limits as the parser,
    strictly shaped evidence objects, and well-formed identity fields."""
    if not isinstance(entry, dict) or set(entry) != _RESULT_KEYS:
        return False
    if entry["assessment"] not in ASSESSMENTS \
            or entry["confidence"] not in CONFIDENCES \
            or entry["suggested_action"] not in SUGGESTED_ACTIONS:
        return False
    if not (isinstance(entry["review_id"], str)
            and _HEX64_RE.match(entry["review_id"])):
        return False
    if not (isinstance(entry["context_digest"], str)
            and _HEX64_RE.match(entry["context_digest"])):
        return False
    if entry["provider"] not in _PROVIDERS:
        return False
    if not _ok_text(entry["model"], _MODEL_MAX_CHARS):
        return False
    if not (isinstance(entry["prompt_version"], str)
            and _PROMPT_VERSION_RE.match(entry["prompt_version"])):
        return False
    if not (isinstance(entry["created_at"], str)
            and _CREATED_AT_RE.match(entry["created_at"])):
        return False
    if not _ok_text(entry["summary"], SUMMARY_MAX_CHARS):
        return False
    evidence = entry["evidence"]
    if not isinstance(evidence, list) \
            or not (EVIDENCE_MIN <= len(evidence) <= EVIDENCE_MAX):
        return False
    for item in evidence:
        if not isinstance(item, dict) \
                or set(item) != {"context_id", "statement"}:
            return False
        if not _ok_text(item["context_id"], _CONTEXT_ID_MAX_CHARS):
            return False
        if not _ok_text(item["statement"], STATEMENT_MAX_CHARS):
            return False
    missing = entry["missing_context"]
    if not isinstance(missing, list) or len(missing) > MISSING_MAX:
        return False
    for m in missing:
        if not _ok_text(m, MISSING_MAX_CHARS):
            return False
    return isinstance(entry["latency_ms"], int) \
        and not isinstance(entry["latency_ms"], bool) \
        and entry["latency_ms"] >= 0


class AIReviewStore:
    """Load-on-open, validate strictly, write atomically. A corrupt sidecar
    makes the store unavailable — nothing is repaired or dropped silently."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._entries: dict[str, dict[str, Any]] = {}
        self.available = True
        self.error = ""
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            with self._path.open("rb") as fh:
                raw = fh.read(SIDECAR_MAX_BYTES + 1)
        except OSError as e:
            self.available, self.error = False, \
                f"sidecar unreadable: {e.__class__.__name__}"
            return
        if len(raw) > SIDECAR_MAX_BYTES:
            self.available, self.error = False, "sidecar exceeds the size cap"
            return
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.available, self.error = False, "sidecar is not valid JSON"
            return
        if not isinstance(data, dict) \
                or set(data) != {"schema_version", "results"} \
                or data.get("schema_version") != SCHEMA_VERSION \
                or not isinstance(data.get("results"), dict):
            self.available, self.error = False, \
                "sidecar has an unsupported shape or schema_version"
            return
        for key, entry in data["results"].items():
            if not isinstance(key, str) or not _valid_result(entry) \
                    or result_key(entry) != key:
                self.available, self.error = False, \
                    "sidecar carries a malformed or mis-keyed result"
                return
            self._entries[key] = entry

    def _write_candidate(self, candidate: dict[str, dict[str, Any]]) -> None:
        """Serialize + size-check + atomically replace. Raises WITHOUT
        touching disk or memory on any failure — the caller commits the
        candidate to memory only after this returns."""
        payload = json.dumps(
            {"schema_version": SCHEMA_VERSION, "results": candidate},
            ensure_ascii=True, sort_keys=True, indent=1)
        if len(payload.encode("utf-8")) > SIDECAR_MAX_BYTES:
            raise AIReviewStoreError(
                "refusing to write: the sidecar would exceed its size cap")
        fd, tmp = _mkstemp(dir=str(self._path.parent),
                           prefix=self._path.name + ".", suffix=".tmp")
        try:
            with _fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            _replace(tmp, self._path)
        except OSError as e:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise AIReviewStoreError(
                f"sidecar write failed: {e.__class__.__name__}") from e

    def put(self, result: dict[str, Any]) -> None:
        if not self.available:
            raise AIReviewStoreError(f"sidecar unavailable: {self.error}")
        if not _valid_result(result):
            raise AIReviewStoreError("refusing to store a malformed result")
        with self._lock:
            # build a SEPARATE candidate: a size or write failure leaves both
            # the in-memory state and the on-disk sidecar exactly as they were
            candidate = dict(self._entries)
            candidate[result_key(result)] = result
            self._write_candidate(candidate)
            self._entries = candidate

    def for_review_id(self, review_id: str,
                      current_digest: str | None) -> list[dict[str, Any]]:
        """Every stored result for one finding, newest first, each tagged
        stale=True when its context_digest no longer matches the current
        pack. A stale result is history, never a fresh answer."""
        with self._lock:
            rows = [dict(e) for e in self._entries.values()
                    if e["review_id"] == review_id]
        rows.sort(key=lambda e: e["created_at"], reverse=True)
        for row in rows:
            row["stale"] = (current_digest is not None
                            and row["context_digest"] != current_digest)
        return rows
