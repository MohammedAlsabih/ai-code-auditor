"""W3-E: the AI-audit sidecar — `<report>.ai-audit.json`.

Fully separate from report.json, the human reviews sidecar, and the W3-B/C/D
AI sidecars — none of them changes. Git-ignored. Atomic candidate writes
with rollback (a size or replace failure leaves memory and disk identical,
no tmp litter). Strict validation on load AND store; a persisted `running`
audit becomes `interrupted` on restart — never a silent resume.

Stored content is metadata, structured results, citations, and the HUMAN
review of candidates only — no source, no prompts, no secrets, and no raw
provider responses.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from auditor.ai.audit import (
    AUDIT_CATEGORIES,
    AUDIT_OUTCOMES,
    CONFIDENCES,
    SUGGESTED_ACTIONS,
)

SCHEMA_VERSION = 1
SIDECAR_MAX_BYTES = 15 * 1024 * 1024
CANDIDATE_DECISIONS = ("confirmed", "false_positive", "uncertain")
NOTE_MAX_CHARS = 2000

_AUDIT_STATES = ("pending", "running", "completed", "failed", "canceled",
                 "interrupted")
_UNIT_STATES = ("pending", "running", "completed", "failed", "canceled")


class AIAuditStoreError(Exception):
    """Sidecar unusable or refused input. Safe fixed messages only."""


def _hex64(v: Any) -> bool:
    return isinstance(v, str) and len(v) == 64 \
        and all(c in "0123456789abcdef" for c in v)


def _rel_path_ok(v: Any) -> bool:
    """Repo-relative posix path only: no backslash, no drive, no
    traversal, no absolute path."""
    if not isinstance(v, str) or not v or "\x00" in v or "\\" in v:
        return False
    if v.startswith("/") or (len(v) > 1 and v[1] == ":"):
        return False
    return not any(seg in ("", ".", "..") for seg in v.split("/"))


def _text_ok(v: Any, cap: int, allow_empty: bool = False) -> bool:
    if not isinstance(v, str) or len(v) > cap:
        return False
    if not v and not allow_empty:
        return False
    return not any(ord(c) < 0x20 and c not in "\n\t" for c in v)


def _pos_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


# explicit allowlists — nothing is ever stored or loaded by open copy
RESULT_KEYS = ("audit_unit_id", "project", "query_id", "query_version",
               "provider", "model", "prompt_version", "latency_ms",
               "context_digest", "created_at", "outcome", "issue_count")
_UNIT_KEYS = {"audit_unit_id", "project", "query_id", "state", "outcome",
              "error", "issues"}
_AUDIT_KEYS = {"audit_id", "state", "created_at", "provider", "model",
               "prompt_version", "units"}
_REVIEW_KEYS = {"decision", "note", "updated_at"}


def _valid_evidence(ev: Any) -> bool:
    if not isinstance(ev, dict) or set(ev) != {
            "context_id", "file", "line_start", "line_end", "statement"}:
        return False
    if not _text_ok(ev["context_id"], 64) or not _rel_path_ok(ev["file"]):
        return False
    if not _pos_int(ev["line_start"]) or not _pos_int(ev["line_end"]) \
            or ev["line_start"] > ev["line_end"]:
        return False
    return _text_ok(ev["statement"], 400)


def _valid_candidate(c: Any) -> bool:
    if not isinstance(c, dict):
        return False
    needed = {"candidate_id", "audit_unit_id", "project", "query_id", "file",
              "line", "title", "category", "confidence", "summary",
              "evidence", "missing_context", "suggested_action",
              "related_static_findings", "provider", "model",
              "prompt_version", "context_digest", "created_at"}
    if set(c) != needed:
        return False
    if not _hex64(c["candidate_id"]) or not _hex64(c["audit_unit_id"]) \
            or not _hex64(c["context_digest"]):
        return False
    if c["category"] not in AUDIT_CATEGORIES \
            or c["confidence"] not in CONFIDENCES \
            or c["suggested_action"] not in SUGGESTED_ACTIONS:
        return False
    if not _rel_path_ok(c["file"]) or not _pos_int(c["line"]):
        return False
    if not _text_ok(c["title"], 200) or not _text_ok(c["summary"], 800):
        return False
    if not _text_ok(c["project"], 300) or not _text_ok(c["query_id"], 10):
        return False
    for f in ("provider", "model", "prompt_version", "created_at"):
        if not _text_ok(c[f], 128):
            return False
    if not isinstance(c["evidence"], list) or not (1 <= len(c["evidence"])
                                                   <= 5):
        return False
    if not all(_valid_evidence(ev) for ev in c["evidence"]):
        return False
    if not isinstance(c["missing_context"], list) \
            or len(c["missing_context"]) > 5 \
            or not all(_text_ok(m, 200) for m in c["missing_context"]):
        return False
    return isinstance(c["related_static_findings"], list) \
        and all(_hex64(r) for r in c["related_static_findings"])


def _valid_result_row(r: Any) -> bool:
    if not isinstance(r, dict) or set(r) != set(RESULT_KEYS):
        return False
    if r["outcome"] not in AUDIT_OUTCOMES or not _hex64(r["audit_unit_id"]) \
            or not _hex64(r["context_digest"]):
        return False
    if not _pos_int(r["latency_ms"]) or not _pos_int(r["issue_count"]) \
            or not _pos_int(r["query_version"]):
        return False
    for f in ("project", "query_id", "provider", "model", "prompt_version",
              "created_at"):
        if not _text_ok(r[f], 300):
            return False
    return True


def _valid_unit_row(u: Any) -> bool:
    if not isinstance(u, dict) or set(u) != _UNIT_KEYS:
        return False
    if not _hex64(u["audit_unit_id"]) or u["state"] not in _UNIT_STATES:
        return False
    if u["outcome"] not in ("", *AUDIT_OUTCOMES):
        return False
    return _text_ok(u["project"], 300) and _text_ok(u["query_id"], 10) \
        and _text_ok(u["error"], 64, allow_empty=True) \
        and _pos_int(u["issues"])


def _valid_audit_row(a: Any) -> bool:
    if not isinstance(a, dict) or set(a) != _AUDIT_KEYS:
        return False
    if not _text_ok(a["audit_id"], 64) or a["state"] not in _AUDIT_STATES:
        return False
    for f in ("created_at", "provider", "model", "prompt_version"):
        if not _text_ok(a[f], 128):
            return False
    return isinstance(a["units"], list) \
        and all(_valid_unit_row(u) for u in a["units"])


def _valid_review_row(r: Any) -> bool:
    if not isinstance(r, dict) or set(r) != _REVIEW_KEYS:
        return False
    return r["decision"] in CANDIDATE_DECISIONS \
        and _text_ok(r["note"], NOTE_MAX_CHARS, allow_empty=True) \
        and _text_ok(r["updated_at"], 64)


class AIAuditStore:
    """One sidecar per report: audits + results-by-unit + candidates +
    candidate reviews (human, separate from the static-finding review_ids)."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._data: dict[str, Any] = {
            "audits": {}, "results": {}, "candidates": {},
            "candidate_reviews": {}}
        self.available = True
        self.error = ""
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            raw = self._path.read_bytes()[:SIDECAR_MAX_BYTES + 1]
            data = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            self.available, self.error = False, "sidecar unreadable/corrupt"
            return
        if not isinstance(data, dict) \
                or set(data) != {"schema_version", "audits", "results",
                                 "candidates", "candidate_reviews"} \
                or data.get("schema_version") != SCHEMA_VERSION \
                or not all(isinstance(data.get(k), dict) for k in
                           ("audits", "results", "candidates",
                            "candidate_reviews")):
            self.available, self.error = False, \
                "sidecar has an unsupported shape or schema_version"
            return
        # FULL validation of every collection — one malformed row makes the
        # store unavailable; nothing is repaired, dropped, or echoed
        for c in data["candidates"].values():
            if not _valid_candidate(c):
                self.available, self.error = False, \
                    "sidecar carries a malformed candidate"
                return
        for rid, r in data["results"].items():
            if not _hex64(rid) or not _valid_result_row(r):
                self.available, self.error = False, \
                    "sidecar carries a malformed result"
                return
        for a in data["audits"].values():
            if not _valid_audit_row(a):
                self.available, self.error = False, \
                    "sidecar carries a malformed audit"
                return
        for cid, rv in data["candidate_reviews"].items():
            if not _hex64(cid) or not _valid_review_row(rv):
                self.available, self.error = False, \
                    "sidecar carries a malformed candidate review"
                return
        changed = False
        for audit in data["audits"].values():
            if audit.get("state") in ("running", "pending"):
                audit["state"] = "interrupted"
                for u in audit.get("units", []):
                    if u.get("state") in ("running", "pending"):
                        u["state"] = "canceled"
                changed = True
        self._data = {k: data[k] for k in ("audits", "results", "candidates",
                                           "candidate_reviews")}
        if changed:
            try:
                with self._lock:
                    self._write(self._data)
            except AIAuditStoreError:
                pass

    def _write(self, candidate_data: dict[str, Any]) -> None:
        payload = json.dumps({"schema_version": SCHEMA_VERSION,
                              **candidate_data},
                             ensure_ascii=True, sort_keys=True, indent=1)
        if len(payload.encode("utf-8")) > SIDECAR_MAX_BYTES:
            raise AIAuditStoreError(
                "refusing to write: the audit sidecar would exceed its cap")
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
            raise AIAuditStoreError(
                f"audit sidecar write failed: {e.__class__.__name__}") from e

    def _commit(self, mutate) -> None:
        """Candidate-state pattern: mutate a deep copy, write it, then swap
        memory only on success."""
        if not self.available:
            raise AIAuditStoreError(f"sidecar unavailable: {self.error}")
        with self._lock:
            candidate = json.loads(json.dumps(self._data))
            mutate(candidate)
            self._write(candidate)
            self._data = candidate

    # ---- writes ----------------------------------------------------------------
    def put_audit(self, audit: dict[str, Any]) -> None:
        if not _valid_audit_row(audit):
            raise AIAuditStoreError("refusing to store a malformed audit")
        self._commit(lambda d: d["audits"].__setitem__(
            audit["audit_id"], json.loads(json.dumps(audit))))

    def put_result(self, result: dict[str, Any],
                   candidates: list[dict[str, Any]]) -> None:
        """The stored row is built from an explicit ALLOWLIST — never an
        open copy, so an injected prompt/source/extra field can never ride
        into the sidecar; unexpected keys are a hard refusal."""
        extras = set(result) - set(RESULT_KEYS) - {"issues"}
        if extras:
            raise AIAuditStoreError(
                "refusing to store a result with unexpected fields")
        stored = {k: result.get(k) for k in RESULT_KEYS
                  if k != "issue_count"}
        stored["issue_count"] = len(result.get("issues", []))
        if not _valid_result_row(stored):
            raise AIAuditStoreError("refusing to store a malformed result")
        for c in candidates:
            if not _valid_candidate(c):
                raise AIAuditStoreError(
                    "refusing to store a malformed candidate")

        def mutate(d):
            d["results"][result["audit_unit_id"]] = stored
            for c in candidates:
                d["candidates"][c["candidate_id"]] = c
        self._commit(mutate)

    def put_candidate_review(self, candidate_id: str, decision: str,
                             note: str) -> dict[str, Any]:
        if decision not in CANDIDATE_DECISIONS:
            raise AIAuditStoreError("invalid candidate decision")
        if not isinstance(note, str) or len(note) > NOTE_MAX_CHARS:
            raise AIAuditStoreError("invalid candidate note")
        if candidate_id not in self._data["candidates"]:
            raise AIAuditStoreError("unknown candidate id")
        entry = {"decision": decision, "note": note,
                 "updated_at": datetime.now(timezone.utc)
                 .strftime("%Y-%m-%dT%H:%M:%SZ")}
        self._commit(lambda d: d["candidate_reviews"].__setitem__(
            candidate_id, dict(entry)))
        return entry

    # ---- reads -----------------------------------------------------------------
    def audit(self, audit_id: str) -> dict[str, Any] | None:
        row = self._data["audits"].get(audit_id)
        return json.loads(json.dumps(row)) if row is not None else None

    def result_for_unit(self, unit_id: str) -> dict[str, Any] | None:
        row = self._data["results"].get(unit_id)
        return json.loads(json.dumps(row)) if row is not None else None

    def all_candidates(self) -> list[dict[str, Any]]:
        rows = []
        for c in self._data["candidates"].values():
            row = json.loads(json.dumps(c))
            review = self._data["candidate_reviews"].get(c["candidate_id"])
            row["review"] = json.loads(json.dumps(review)) if review else None
            rows.append(row)
        rows.sort(key=lambda r: (r["project"], r["file"], r["line"],
                                 r["query_id"], r["candidate_id"]))
        return rows
