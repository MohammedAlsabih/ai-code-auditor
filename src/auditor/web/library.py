"""W4-A: the Project Library backend — store, validation, jobs, git.

The library is a server-side directory chosen on the CLI. Everything the
browser can name is an OPAQUE id; every path the server touches is derived
from those ids and confined to the library root (or, for local project
registration only, to the CLI-declared allowed roots). No browser-supplied
path ever reaches a delete or a report resolution.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess  # noqa: S404 - argv lists only, shell=False everywhere
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

# W4-B: report rows now carry the baseline comparison. `library-1` rows are
# migrated deterministically on load (see `migrate_report_row`); any OTHER
# value is refused, because a store written by a newer build may hold fields
# this one would silently drop.
SCHEMA_VERSION = "library-2"
SCHEMA_VERSION_LEGACY = "library-1"

# The verdict's scope. "all" is the default and the historical behaviour;
# "new" means the gate counted only findings absent from the baseline.
GATE_SCOPES = ("all", "new")
STORE_MAX_BYTES = 2 * 1024 * 1024
NAME_MAX_CHARS = 120
LOCATION_MAX_CHARS = 200
URL_MAX_CHARS = 500
ERROR_MAX_CHARS = 300
OUTPUT_TAIL_BYTES = 8192          # per stream, memory + disk bound
MAX_PROJECTS = 200
MAX_JOBS_KEPT = 200               # oldest finished jobs pruned beyond this
# retention policy (declared in /api/library/capabilities and docs): the
# newest N reports per project are kept; older ones are pruned after a
# successful scan — never while loaded in an open explorer context.
MAX_REPORTS_PER_PROJECT = 10

_TIMEOUT_ENV = "AUDITOR_LIBRARY_JOB_TIMEOUT"
_TIMEOUT_DEFAULT = 1800.0
_TIMEOUT_MIN, _TIMEOUT_MAX = 60.0, 7200.0

PROJECT_KINDS = ("local", "git")
JOB_KINDS = ("clone", "scan")
JOB_STATES = ("pending", "running", "completed", "failed", "canceled",
              "interrupted")
_ACTIVE_JOB_STATES = ("pending", "running")

_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_WIN_DEVICES = {"con", "prn", "aux", "nul"} \
    | {f"com{i}" for i in range(1, 10)} | {f"lpt{i}" for i in range(1, 10)}


def job_timeout(env: dict[str, str] | None = None) -> float:
    """Bounded job timeout: env override clamped to [60, 7200] seconds."""
    e = os.environ if env is None else env
    raw = (e.get(_TIMEOUT_ENV) or "").strip()
    if not raw:
        return _TIMEOUT_DEFAULT
    try:
        val = float(raw)
    except ValueError:
        return _TIMEOUT_DEFAULT
    return min(max(val, _TIMEOUT_MIN), _TIMEOUT_MAX)


def new_id() -> str:
    return secrets.token_hex(8)


def _now_iso() -> str:
    # W4-B: MILLISECONDS, not seconds. Report rows are ordered by this string
    # and "the newest report" is what a rescan compares against by default —
    # two scans of a small project really do finish inside the same second
    # (they did in testing), and a tie there would pick a baseline by report
    # id, which is random. One job runs at a time, so a millisecond stamp
    # orders them exactly.
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] \
        + "Z"


def _stamp_key(created_at: str) -> str:
    """Sort key for a `created_at`. A row written by an older build has no
    fractional part, and `'Z' > '.'`, so comparing the raw strings would put
    a second-granularity row AFTER a millisecond one from the same second.
    Normalising the missing fraction to `.000` keeps one order for both."""
    if created_at.endswith("Z") and "." not in created_at:
        return created_at[:-1] + ".000Z"
    return created_at


# ---- validation ---------------------------------------------------------------------

# W4-A3: the FIXED Alpha host policy — public repositories on the three
# major public services only. IP literals, localhost, intranet names,
# custom ports, and anything else are refused BEFORE any network or
# subprocess (SSRF/private-fetch guard, not just hygiene).
ALLOWED_GIT_HOSTS = ("github.com", "gitlab.com", "bitbucket.org")


def bad_git_url(url: Any) -> str | None:
    """Pure validation of a Git URL BEFORE any network or subprocess.
    Returns a safe rejection reason (never echoes the input) or None.
    Alpha policy: public HTTPS on github.com/gitlab.com/bitbucket.org
    only — no credentials, no query, no fragment, no custom port, no
    ssh/git/file/scp-like forms, no IP or localhost hosts."""
    if not isinstance(url, str) or not url:
        return "url must be a non-empty string"
    if len(url) > URL_MAX_CHARS:
        return f"url exceeds {URL_MAX_CHARS} characters"
    if any(ch.isspace() for ch in url) or "\x00" in url or "\\" in url:
        return "url contains whitespace, NUL, or backslashes"
    if url.startswith("-"):
        return "url may not start with a dash"
    if re.match(r"^[A-Za-z0-9._-]+@", url) or ":" in url.split("/", 1)[0] \
            and not url.lower().startswith(("http:", "https:")):
        return "scp-like and ssh addresses are not allowed (https only)"
    try:
        parts = urlsplit(url)
    except ValueError:
        return "url cannot be parsed"
    if parts.scheme.lower() != "https":
        return "only https:// urls are allowed"
    if not parts.hostname:
        return "url has no hostname"
    if parts.username is not None or parts.password is not None \
            or "@" in parts.netloc:
        return "credentials in the url are not allowed"
    try:
        port = parts.port
    except ValueError:
        return "url has an invalid port"
    if port is not None:
        return "custom ports are not allowed"
    if parts.hostname.lower() not in ALLOWED_GIT_HOSTS:
        return ("host is not supported (public repositories on "
                "github.com, gitlab.com, or bitbucket.org only)")
    if parts.query or parts.fragment:
        return "query strings and fragments are not allowed"
    if not parts.path or parts.path == "/":
        return "url has no repository path"
    return None


def repo_name_from_url(url: str) -> str:
    """Safe short display name from a validated https url ('host/name')."""
    parts = urlsplit(url)
    tail = parts.path.rstrip("/").rsplit("/", 1)[-1]
    if tail.endswith(".git"):
        tail = tail[:-4]
    return tail or "repository"


def resolve_local_registration(
        path_str: Any, allowed_roots: list[Path]) -> tuple[Path | None, str]:
    """Validate a browser-supplied LOCAL FOLDER for registration — the only
    endpoint that accepts a path at all. The reason strings are safe to
    echo (they never contain the submitted path)."""
    if not isinstance(path_str, str) or not path_str:
        return None, "path must be a non-empty string"
    if "\x00" in path_str or len(path_str) > 1000:
        return None, "path contains a NUL byte or is too long"
    if path_str.startswith(("\\\\", "//")):
        return None, "UNC paths are not allowed"
    if any(seg.split(".", 1)[0].lower() in _WIN_DEVICES
           for seg in re.split(r"[\\/]+", path_str) if seg):
        return None, "reserved device names are not allowed"
    p = Path(path_str)
    if not p.is_absolute():
        return None, "path must be absolute"
    try:
        resolved = p.resolve(strict=True)
    except (OSError, RuntimeError):
        return None, "path does not exist or cannot be resolved"
    if not resolved.is_dir():
        return None, "path is not a directory"
    for root in allowed_roots:
        try:
            real_root = root.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if resolved == real_root or real_root in resolved.parents:
            return resolved, ""
    return None, "path is not under an allowed root"


def safe_location(kind: str, source: str) -> str:
    """Short, path-free display location for the API. Local folders show the
    LAST TWO segments only; git shows host + repo name."""
    if kind == "git":
        parts = urlsplit(source)
        return f"{parts.hostname}/{repo_name_from_url(source)}"[:LOCATION_MAX_CHARS]
    segs = [s for s in re.split(r"[\\/]+", source) if s and not _DRIVE_RE.match(s)]
    tail = "/".join(segs[-2:]) if segs else "folder"
    return ("…/" + tail)[:LOCATION_MAX_CHARS]


# ---- git ----------------------------------------------------------------------------

def git_clone_argv(url: str, dest: Path) -> list[str]:
    """Hardened clone argv (shell never involved). Prompts are disabled via
    env; external config/hooks/filters are neutralized; submodules are never
    recursed; LFS smudge is skipped; redirects to other protocols refused."""
    return [
        "git",
        "-c", "core.hooksPath=",
        "-c", "core.fsmonitor=false",
        "-c", "filter.lfs.smudge=",
        "-c", "filter.lfs.process=",
        "-c", "filter.lfs.required=false",
        "-c", "protocol.allow=never",
        "-c", "protocol.https.allow=always",
        "-c", "http.followRedirects=false",
        "-c", "credential.helper=",
        "clone", "--depth", "1", "--single-branch",
        "--no-recurse-submodules", "--no-tags",
        "--", url, str(dest),
    ]


def job_env() -> dict[str, str]:
    """Subprocess environment: the current env plus prompt/config lockdown.
    Never contains anything taken from a request."""
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = ""
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    env["GIT_LFS_SKIP_SMUDGE"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    return env


_CLI_BOOTSTRAP = "import sys; from auditor.cli import main; " \
                 "sys.exit(main(sys.argv[1:]))"


def scan_argv(source_dir: Path, out_dir: Path, *, online: bool,
              semgrep: bool, baseline: Path | None = None,
              new_only: bool = False) -> list[str]:
    """The scan subprocess argv: this interpreter, no shell, offline by
    default (registry lookups happen only on an explicit online request).

    W4-B: `baseline` is the CLI's existing `--baseline <report.json>` and is
    ALWAYS a path the server derived from a confined report id — never a
    path any client supplied. `--new-only` narrows the gate and, exactly as
    the CLI contract requires, is only ever passed together with a baseline;
    asking for it without one is a programming error here, not a request the
    subprocess gets to interpret."""
    argv = [sys.executable, "-c", _CLI_BOOTSTRAP, "scan", str(source_dir),
            "--output", str(out_dir)]
    if not online:
        argv.append("--offline")
    if not semgrep:
        argv.append("--no-semgrep")
    if baseline is not None:
        argv += ["--baseline", str(baseline)]
        if new_only:
            argv.append("--new-only")
    elif new_only:
        raise LibraryStoreError("--new-only requires a baseline")
    return argv


# ---- store --------------------------------------------------------------------------

class LibraryStoreError(Exception):
    """Store contract violation or unavailable sidecar (safe message)."""


def _text_ok(v: Any, cap: int, *, allow_empty: bool = False) -> bool:
    return isinstance(v, str) and bool(allow_empty or v) and len(v) <= cap


def _id_ok(v: Any) -> bool:
    return isinstance(v, str) and bool(_ID_RE.match(v))


def _int_ok(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


PROJECT_KEYS = ("project_id", "name", "kind", "location", "created_at",
                "git_url", "local_path", "managed")
# What a CALLER supplies for a report. `seq` is deliberately absent: the store
# owns it, because only the store can hand out an order nobody else can race.
REPORT_INPUT_KEYS = ("report_id", "project_id", "created_at", "verdict",
                     "findings", "duration_ms",
                     # W4-B. `findings` stays the WHOLE report's count; the
                     # fields below describe the comparison and never replace
                     # it. `baseline_findings` is the baseline's own count,
                     # kept HERE so `unchanged + resolved` stays checkable
                     # after the baseline report itself is deleted.
                     "baseline_report_id", "baseline_enabled",
                     "baseline_findings",
                     "new", "unchanged", "resolved", "gate_scope")
# `seq` is a strictly increasing per-store integer assigned at commit time. It
# is what "newest" means — NOT the timestamp. A timestamp cannot order two
# rows that share it, and the old tie-break fell through to `report_id`, which
# is `secrets.token_hex` output: measured over 600 migrated stores, the truly
# newest report was called newest 30.5-38.3 % of the time against a uniform
# 33.3 %. `created_at` remains for display only.
REPORT_KEYS = (*REPORT_INPUT_KEYS, "seq")
JOB_KEYS = ("job_id", "project_id", "kind", "state", "online", "semgrep",
            "created_at", "started_at", "finished_at", "error", "report_id",
            # W4-B: what the scan was ASKED to compare against. Kept on the
            # job so a running scan can be described without guessing, and so
            # the request survives in the record even when the scan fails.
            "baseline_report_id", "new_only")


def _valid_project(row: Any) -> bool:
    if not isinstance(row, dict) or set(row) != set(PROJECT_KEYS):
        return False
    if not (_id_ok(row["project_id"]) and _text_ok(row["name"], NAME_MAX_CHARS)
            and row["kind"] in PROJECT_KINDS
            and _text_ok(row["location"], LOCATION_MAX_CHARS)
            and _text_ok(row["created_at"], 40)
            and isinstance(row["managed"], bool)
            and _text_ok(row["git_url"], URL_MAX_CHARS, allow_empty=True)
            and _text_ok(row["local_path"], 1000, allow_empty=True)):
        return False
    if row["kind"] == "git":
        return bool(row["git_url"]) and bad_git_url(row["git_url"]) is None \
            and row["local_path"] == "" and row["managed"]
    return row["git_url"] == "" and bool(row["local_path"]) \
        and not row["managed"]


def _valid_report(row: Any, *, keys: tuple[str, ...] = REPORT_KEYS) -> bool:
    """Report-row contract. `keys` lets the same rules validate a caller's
    row (no `seq`) and a stored row (with one), so there is exactly one
    definition of a valid report.

    Types alone are not enough: three integers that are each individually
    "a non-negative int" can still describe a comparison that never happened
    (findings=100 with new=90, unchanged=90, resolved=90 was accepted before
    this). The counts are therefore checked as ARITHMETIC, against two
    independently produced quantities — `findings`, counted by the runner
    from the report's own project lists, and `baseline_findings`, taken from
    the scanner's match result — so a row can only be stored if those two
    sources agree."""
    if not (isinstance(row, dict) and set(row) == set(keys)
            and _id_ok(row["report_id"]) and _id_ok(row["project_id"])
            and _text_ok(row["created_at"], 40)
            and _text_ok(row["verdict"], 40, allow_empty=True)
            and _int_ok(row["findings"]) and _int_ok(row["duration_ms"])):
        return False
    if "seq" in keys and not (_int_ok(row["seq"]) and row["seq"] >= 1):
        return False
    if not (isinstance(row["baseline_enabled"], bool)
            and row["gate_scope"] in GATE_SCOPES
            and all(_int_ok(row[k]) for k in
                    ("new", "unchanged", "resolved", "baseline_findings"))):
        return False
    if not row["baseline_enabled"]:
        # without a baseline there is nothing to compare, so every count is
        # zero and the gate cannot have been narrowed to "new"
        return (row["baseline_report_id"] == ""
                and row["new"] == row["unchanged"] == row["resolved"] == 0
                and row["baseline_findings"] == 0
                and row["gate_scope"] == "all")
    # a comparison names the report it compared against, and that cannot be
    # itself — a report is not its own history
    if not _id_ok(row["baseline_report_id"]) \
            or row["baseline_report_id"] == row["report_id"]:
        return False
    # every current finding is either new or unchanged, exactly once ...
    if row["new"] + row["unchanged"] != row["findings"]:
        return False
    # ... and every baseline finding was either matched or is gone
    return row["unchanged"] + row["resolved"] == row["baseline_findings"]


def _report_lineage_ok(row: dict[str, Any],
                       reports: dict[str, Any]) -> bool:
    """Cross-row half of the report contract: a comparison must point at a
    report of the SAME project that actually held `baseline_findings`
    findings and came BEFORE this one.

    A missing baseline is accepted here, and only here. Baselines are
    deleted legitimately — by hand or by retention — and a history is not
    made false by the disappearance of what it was measured against. That is
    exactly why the count is copied onto this row: `unchanged + resolved`
    stays checkable for the life of the row, not for the life of the
    baseline. `put_report` is stricter, because there the baseline is still
    under a lease and therefore must be present."""
    if not row["baseline_enabled"]:
        return True
    base = reports.get(row["baseline_report_id"])
    if base is None:
        return True
    return (base["project_id"] == row["project_id"]
            and base["findings"] == row["baseline_findings"]
            and base["seq"] < row["seq"])


LEGACY_REPORT_KEYS = ("report_id", "project_id", "created_at", "verdict",
                      "findings", "duration_ms")


def migrate_report_row(row: Any, seq: int) -> dict[str, Any] | None:
    """One `library-1` report row -> `library-2`, or None if it is malformed.

    Deterministic and lossless in the only direction that matters: a row
    written before baselines existed describes a scan that HAD no baseline,
    so it becomes `baseline_enabled=false` with zero counts and the full
    gate. Nothing is inferred and no comparison is invented — a migrated row
    is honestly indistinguishable from a first scan, because that is what it
    was.

    `seq` is supplied by the caller because a single row cannot know its own
    place in the history. `library-1` stamps are second-granularity, so the
    order WITHIN one second is genuinely unknown — the caller assigns it from
    `(created_at, report_id)` and that ordering is frozen from then on rather
    than being re-derived, differently, on every load.
    """
    if not isinstance(row, dict) or set(row) != set(LEGACY_REPORT_KEYS):
        return None
    migrated = {**row, "baseline_report_id": "", "baseline_enabled": False,
                "baseline_findings": 0,
                "new": 0, "unchanged": 0, "resolved": 0, "gate_scope": "all",
                "seq": seq}
    return migrated if _valid_report(migrated) else None


def _valid_job(row: Any) -> bool:
    if not (isinstance(row, dict) and set(row) == set(JOB_KEYS)
            and _id_ok(row["job_id"]) and _id_ok(row["project_id"])
            and row["kind"] in JOB_KINDS and row["state"] in JOB_STATES
            and isinstance(row["online"], bool)
            and isinstance(row["semgrep"], bool)
            and _text_ok(row["created_at"], 40)
            and _text_ok(row["started_at"], 40, allow_empty=True)
            and _text_ok(row["finished_at"], 40, allow_empty=True)
            and _text_ok(row["error"], ERROR_MAX_CHARS, allow_empty=True)
            and (row["report_id"] == "" or _id_ok(row["report_id"]))):
        return False
    if not isinstance(row["new_only"], bool):
        return False
    if row["baseline_report_id"] == "":
        return not row["new_only"]      # narrowing needs something to narrow
    return _id_ok(row["baseline_report_id"])


def migrate_job_row(row: Any) -> dict[str, Any] | None:
    """One `library-1` job row -> `library-2`, or None if it is malformed.
    A job recorded before baselines existed asked for no comparison."""
    legacy_keys = tuple(k for k in JOB_KEYS
                        if k not in ("baseline_report_id", "new_only"))
    if not isinstance(row, dict) or set(row) != set(legacy_keys):
        return None
    migrated = {**row, "baseline_report_id": "", "new_only": False}
    return migrated if _valid_job(migrated) else None


class LibraryStore:
    """Atomic, size-capped, fully validated library metadata sidecar.
    Anything malformed makes the store unavailable — nothing is repaired,
    dropped, or echoed. Persisted running/pending jobs become `interrupted`
    on load: a restart never resumes a job."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.RLock()
        self.available = True
        self.error = ""
        self._data: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "projects": {}, "reports": {}, "jobs": {},
        }
        self._load()

    # -- load / persist ---------------------------------------------------

    def _load(self) -> None:
        if not self._path.exists():
            return
        # W4-A3: the size limit is the BOUNDED READ (cap+1), never a full
        # read_bytes() slice. stat is only a cheap early reject — it can lie
        # (TOCTOU), so the read length is the enforced truth, and an
        # oversized file is refused BEFORE any JSON parse.
        try:
            if self._path.stat().st_size > STORE_MAX_BYTES:
                self.available, self.error = False, \
                    "library store exceeds cap"
                return
            with self._path.open("rb") as fh:
                raw = fh.read(STORE_MAX_BYTES + 1)
        except OSError:
            self.available, self.error = False, "library store unreadable"
            return
        if len(raw) > STORE_MAX_BYTES:
            self.available, self.error = False, "library store exceeds cap"
            return
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.available, self.error = False, "library store unreadable"
            return
        if not isinstance(data, dict) \
                or set(data) != {"schema_version", "projects", "reports",
                                 "jobs"} \
                or data.get("schema_version") not in (SCHEMA_VERSION,
                                                      SCHEMA_VERSION_LEGACY) \
                or not all(isinstance(data[k], dict) for k in
                           ("projects", "reports", "jobs")):
            self.available, self.error = False, \
                "library store has an unsupported shape or schema_version"
            return
        # An UNKNOWN schema_version is refused rather than guessed at: it may
        # be a NEWER store whose extra fields this build would silently drop on
        # the next write. Refusing leaves the file intact.
        migrated_from_legacy = data["schema_version"] == SCHEMA_VERSION_LEGACY
        if migrated_from_legacy:
            # `seq` is assigned from `(created_at, report_id)` ONCE, here, and
            # then persisted. `library-1` stamps only resolve to the second, so
            # the order within a second is not recoverable — but re-deriving it
            # on every load would let it change from load to load. Freezing it
            # is the honest option: unknown, then fixed.
            ordered = sorted(data["reports"].items(),
                             key=lambda kv: (_stamp_key(kv[1]["created_at"])
                                             if isinstance(kv[1], dict)
                                             and isinstance(
                                                 kv[1].get("created_at"), str)
                                             else "", kv[0]))
            upgraded: dict[str, Any] = {}
            for position, (rid, legacy_row) in enumerate(ordered, start=1):
                new_row = migrate_report_row(legacy_row, position)
                if new_row is None or new_row["report_id"] != rid:
                    self.available, self.error = False, \
                        "library store has a malformed report row"
                    return
                upgraded[rid] = new_row
            upgraded_jobs: dict[str, Any] = {}
            for jid, legacy_job in data["jobs"].items():
                new_job = migrate_job_row(legacy_job)
                if new_job is None or new_job["job_id"] != jid:
                    self.available, self.error = False, \
                        "library store has a malformed job row"
                    return
                upgraded_jobs[jid] = new_job
            data["reports"] = upgraded
            data["jobs"] = upgraded_jobs
            data["schema_version"] = SCHEMA_VERSION

        for pid, row in data["projects"].items():
            if not _valid_project(row) or row["project_id"] != pid:
                self.available, self.error = False, \
                    "library store has a malformed project row"
                return
        seen_seq: set[int] = set()
        for rid, row in data["reports"].items():
            if not _valid_report(row) or row["report_id"] != rid:
                self.available, self.error = False, \
                    "library store has a malformed report row"
                return
            if row["seq"] in seen_seq:
                # two reports claiming the same place is not an order
                self.available, self.error = False, \
                    "library store has a duplicate report sequence"
                return
            seen_seq.add(row["seq"])
        for rid, row in data["reports"].items():
            if not _report_lineage_ok(row, data["reports"]):
                self.available, self.error = False, \
                    "library store has an inconsistent report comparison"
                return
        interrupted = False
        for jid, row in data["jobs"].items():
            if not _valid_job(row) or row["job_id"] != jid:
                self.available, self.error = False, \
                    "library store has a malformed job row"
                return
            if row["state"] in _ACTIVE_JOB_STATES:
                row = dict(row)
                row["state"] = "interrupted"
                row["finished_at"] = _now_iso()
                data["jobs"][jid] = row
                interrupted = True
        # W4-B closing: WRITE FIRST, PUBLISH SECOND — the same order `_commit`
        # uses. `data` is a candidate until it is on disk. Publishing it first
        # and swallowing the write error (which is what this did) left memory
        # holding `library-2` while the file still held `library-1`, with
        # `available` still True: an uncommitted state, served, silently. A
        # store whose directory cannot be written is a condition the operator
        # has to be told about, not one to paper over — every later mutation
        # would fail anyway, one at a time, with no explanation.
        if migrated_from_legacy or interrupted:
            try:
                self._write(data)
            except LibraryStoreError:
                self.available, self.error = False, \
                    ("library store could not be updated on load "
                     "(migration or interrupted-job state); "
                     "the existing file was left unchanged")
                return
        self._data = data

    def _write(self, data: dict[str, Any]) -> None:
        blob = json.dumps(data, ensure_ascii=True, sort_keys=True,
                          separators=(",", ":")).encode("ascii")
        if len(blob) > STORE_MAX_BYTES:
            raise LibraryStoreError("library store would exceed its size cap")
        tmp = self._path.with_name(self._path.name + ".tmp")
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_bytes(blob)
            os.replace(tmp, self._path)
        except OSError as e:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            raise LibraryStoreError(
                "library store write failed") from e

    def mark_unavailable(self, reason: str) -> None:
        """Declare the store unusable, with a safe message.

        Used when a write the caller CANNOT retry meaningfully fails — a
        job's state transition, above all. The in-memory image is still the
        last committed one (candidate-copy guarantees that), so nothing here
        is corrupt; what is now unknowable is whether the store still
        describes reality. Serving it as though it did is the failure this
        prevents: a scan that finished would go on reading `running` for the
        life of the process, and then be relabelled `interrupted` on restart
        — wrong in the opposite direction, with its report already in the
        library."""
        with self._lock:
            if self.available:
                self.available, self.error = False, reason

    def _commit(self, mutate: Callable[[dict[str, Any]], None]) -> None:
        """Candidate-copy commit: mutate a deep copy, write it, and only
        then swap it in — a failed write leaves memory and disk aligned."""
        with self._lock:
            if not self.available:
                raise LibraryStoreError(f"library store unavailable: "
                                        f"{self.error}")
            candidate = json.loads(json.dumps(self._data))
            mutate(candidate)
            self._write(candidate)
            self._data = candidate

    # -- projects ----------------------------------------------------------

    def put_project(self, row: dict[str, Any]) -> None:
        if not _valid_project(row):
            raise LibraryStoreError("malformed project row")

        def mutate(d: dict[str, Any]) -> None:
            if len(d["projects"]) >= MAX_PROJECTS:
                raise LibraryStoreError(
                    f"library holds the maximum of {MAX_PROJECTS} projects")
            d["projects"][row["project_id"]] = dict(row)
        self._commit(mutate)

    def project(self, pid: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._data["projects"].get(pid)
            return dict(row) if row else None

    def projects(self) -> list[dict[str, Any]]:
        # `_stamp_key`, not the raw string: project rows are never migrated,
        # so a second-granularity stamp written by an older build sits beside
        # millisecond ones forever — and `"…:00Z" > "…:00.500Z"` is True, so
        # comparing raw text INVERTS them. Ties inside one millisecond still
        # fall back to the id; for this list that is display order only.
        with self._lock:
            return sorted((dict(r) for r in self._data["projects"].values()),
                          key=lambda r: (_stamp_key(r["created_at"]),
                                         r["project_id"]))

    def remove_project(self, pid: str) -> list[str]:
        """Remove the registration and its report ROWS (files are the
        caller's confined-delete job). Returns removed report ids."""
        removed: list[str] = []

        def mutate(d: dict[str, Any]) -> None:
            if pid not in d["projects"]:
                raise LibraryStoreError("unknown project id")
            del d["projects"][pid]
            for rid in [r for r, row in d["reports"].items()
                        if row["project_id"] == pid]:
                del d["reports"][rid]
                removed.append(rid)
            for jid in [j for j, row in d["jobs"].items()
                        if row["project_id"] == pid]:
                del d["jobs"][jid]
        self._commit(mutate)
        return removed

    # -- reports -----------------------------------------------------------

    def put_report(self, row: dict[str, Any]) -> None:
        """Commit a report row. The caller supplies everything but `seq`;
        the store assigns that, so "newest" is decided in one place under the
        lock instead of being inferred from a clock.

        The baseline is verified HERE, against the store, before anything is
        committed. The caller holds the baseline's lease for the whole scan,
        so a baseline that cannot be found at this moment is not a race — it
        is a row that names something that was never its history."""
        if not _valid_report(row, keys=REPORT_INPUT_KEYS):
            raise LibraryStoreError("malformed report row")
        self._commit(lambda d: self._put_report_into(d, row))

    @staticmethod
    def _put_report_into(d: dict[str, Any], row: dict[str, Any]) -> None:
        if row["project_id"] not in d["projects"]:
            raise LibraryStoreError("unknown project id")
        stored = dict(row)
        stored["seq"] = 1 + max((r["seq"] for r in d["reports"].values()),
                                default=0)
        if stored["baseline_enabled"]:
            base = d["reports"].get(stored["baseline_report_id"])
            if base is None:
                raise LibraryStoreError(
                    "the baseline report is not in this library")
            if base["project_id"] != stored["project_id"]:
                raise LibraryStoreError(
                    "the baseline report belongs to another project")
            if base["findings"] != stored["baseline_findings"]:
                raise LibraryStoreError(
                    "the comparison does not match the baseline report")
            # "the baseline is older" needs no check here: `seq` was just
            # taken as max+1, so a row committed through this path is always
            # the newest there is. A file that violates it was not written by
            # this code, and `_report_lineage_ok` catches that on load.
        if not _valid_report(stored):
            raise LibraryStoreError("malformed report row")
        d["reports"][stored["report_id"]] = stored

    def report(self, rid: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._data["reports"].get(rid)
            return dict(row) if row else None

    def reports_for(self, pid: str) -> list[dict[str, Any]]:
        """Newest first, by the committed sequence — never by the clock. Two
        reports cannot share a `seq` (the loader refuses a store where they
        do), so this order is total, and it is the same before and after a
        reload because it is read from the file rather than re-derived."""
        with self._lock:
            rows = [dict(r) for r in self._data["reports"].values()
                    if r["project_id"] == pid]
            return sorted(rows, key=lambda r: r["seq"], reverse=True)

    def remove_report(self, rid: str) -> None:
        def mutate(d: dict[str, Any]) -> None:
            if rid not in d["reports"]:
                raise LibraryStoreError("unknown report id")
            del d["reports"][rid]
        self._commit(mutate)

    # -- jobs --------------------------------------------------------------

    @staticmethod
    def _put_job_into(d: dict[str, Any], row: dict[str, Any]) -> None:
        d["jobs"][row["job_id"]] = dict(row)
        # same normalization as everywhere else: raw text would sort a legacy
        # second-granularity stamp AFTER a millisecond one from that second,
        # so retention would drop the newer job and keep the older
        finished = [j for j, r in sorted(
            d["jobs"].items(),
            key=lambda kv: (_stamp_key(kv[1]["created_at"]), kv[0]))
            if r["state"] not in _ACTIVE_JOB_STATES]
        excess = len(d["jobs"]) - MAX_JOBS_KEPT
        for jid in finished[:max(excess, 0)]:
            del d["jobs"][jid]

    def put_job(self, row: dict[str, Any]) -> None:
        if not _valid_job(row):
            raise LibraryStoreError("malformed job row")
        self._commit(lambda d: self._put_job_into(d, row))

    def put_report_and_finish_job(self, report_row: dict[str, Any],
                                  job_row: dict[str, Any]) -> None:
        """A finished scan is ONE transaction: the report row and the job
        row that claims it land together or neither lands.

        Two separate commits let a failure in between leave a report in the
        library that no job says it produced — and the next scan then picks
        that orphan as its baseline, so a run that never completed becomes
        the basis of the history. `put_project_and_job` already exists for
        exactly this reason on the registration path; this is the same rule
        on the finishing path."""
        if not _valid_report(report_row, keys=REPORT_INPUT_KEYS):
            raise LibraryStoreError("malformed report row")
        if not _valid_job(job_row):
            raise LibraryStoreError("malformed job row")
        if job_row["report_id"] != report_row["report_id"]:
            raise LibraryStoreError("the job must name the report it produced")

        def mutate(d: dict[str, Any]) -> None:
            self._put_report_into(d, report_row)
            self._put_job_into(d, job_row)
        self._commit(mutate)

    def put_project_and_job(self, project_row: dict[str, Any],
                            job_row: dict[str, Any]) -> None:
        """W4-A3: git registration is ONE transaction — the project row and
        its clone job land together or not at all (no orphan projects when
        the job cannot be created)."""
        if not _valid_project(project_row):
            raise LibraryStoreError("malformed project row")
        if not _valid_job(job_row):
            raise LibraryStoreError("malformed job row")

        def mutate(d: dict[str, Any]) -> None:
            if len(d["projects"]) >= MAX_PROJECTS:
                raise LibraryStoreError(
                    f"library holds the maximum of {MAX_PROJECTS} projects")
            d["projects"][project_row["project_id"]] = dict(project_row)
            self._put_job_into(d, job_row)
        self._commit(mutate)

    def job(self, jid: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._data["jobs"].get(jid)
            return dict(row) if row else None

    def active_job(self) -> dict[str, Any] | None:
        with self._lock:
            for row in self._data["jobs"].values():
                if row["state"] in _ACTIVE_JOB_STATES:
                    return dict(row)
            return None

    def latest_job_for(self, pid: str) -> dict[str, Any] | None:
        with self._lock:
            rows = [r for r in self._data["jobs"].values()
                    if r["project_id"] == pid]
            if not rows:
                return None
            return dict(max(rows, key=lambda r: (_stamp_key(r["created_at"]),
                                                 r["job_id"])))


# ---- confined paths ------------------------------------------------------------------

class LibraryPaths:
    """Every filesystem location is DERIVED from an opaque id under the
    library root. Deletion is double-guarded: the target must resolve inside
    the library root AND must not itself be a symlink."""

    def __init__(self, library_root: Path) -> None:
        self.root = library_root.resolve()

    def store_path(self) -> Path:
        return self.root / "library.json"

    def clone_dir(self, pid: str) -> Path:
        if not _id_ok(pid):
            raise LibraryStoreError("invalid project id")
        return self.root / "projects" / pid / "src"

    def report_dir(self, rid: str) -> Path:
        if not _id_ok(rid):
            raise LibraryStoreError("invalid report id")
        return self.root / "reports" / rid

    def report_json(self, rid: str) -> Path:
        return self.report_dir(rid) / "report.json"

    def tmp_dir(self, jid: str) -> Path:
        if not _id_ok(jid):
            raise LibraryStoreError("invalid job id")
        return self.root / "tmp" / jid

    def confined_delete(self, target: Path) -> bool:
        """Delete a directory tree ONLY if it is strictly inside the library
        root and is not a symlink itself. W4-A3 contract: True means the
        target is ACTUALLY GONE afterwards (an already-absent target counts
        as gone, so a failed metadata step can be retried); an unsafe target
        (symlink, outside the root, the root itself) or a tree that still
        exists after the attempt is False — never a claimed success."""
        try:
            if target.is_symlink():
                return False
            if not target.exists():
                return True                    # already gone -> retry-safe
            resolved = target.resolve(strict=True)
            root = self.root.resolve(strict=True)
        except (OSError, RuntimeError):
            return False
        if resolved == root or root not in resolved.parents:
            return False
        try:
            shutil.rmtree(resolved)            # NO ignore_errors: verify below
        except OSError:
            pass
        return not target.exists()


# ---- baselines (W4-B) ----------------------------------------------------------------

class BaselineRefused(LibraryStoreError):
    """The requested comparison cannot be made. Carries the status the API
    should answer with: 400 for a request that was never valid, 409 for a
    live conflict (the report is being deleted right now). The message is
    always safe — it never contains a path or a foreign project's id."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def baseline_source(paths: LibraryPaths, rid: str) -> Path | None:
    """The `report.json` of a stored report, or None if it cannot legally
    serve as a baseline.

    Legal means: the report directory and the file itself are real, are NOT
    symlinks, resolve strictly inside the library root, and parse under the
    same loader the scan itself uses. The symlink and confinement checks
    matter because the argv this path lands in is handed to a subprocess —
    a report directory replaced by a link to somewhere else must not become
    a way to make the scanner read an arbitrary file."""
    from auditor.core.baseline import BaselineError, load_baseline_counter
    try:
        directory = paths.report_dir(rid)
    except LibraryStoreError:
        return None
    target = paths.report_json(rid)
    try:
        if directory.is_symlink() or target.is_symlink():
            return None
        if not target.is_file():
            return None
        resolved = target.resolve(strict=True)
        root = paths.root.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if root not in resolved.parents:
        return None
    try:
        load_baseline_counter(resolved)
    except BaselineError:
        return None                    # corrupt/oversize: refused BEFORE spawn
    return resolved


def resolve_baseline(store: LibraryStore, paths: LibraryPaths, pid: str, *,
                     requested_id: str, compare_previous: bool,
                     new_only: bool,
                     hold: Callable[[str], str | None],
                     release: Callable[[str], None]) -> tuple[str, Path | None]:
    """Decide what this scan compares against, and LEASE it.

    Returns `(report_id, path)`, or `("", None)` when there is nothing to
    compare with — a first scan, or a rescan whose history holds no usable
    report. On a non-empty return the caller owns the lease on `report_id`
    and must release it exactly once.

    "The previous report" means THE most recent one, not the most recent one
    that happens to still work. If it is being deleted, or cannot be read,
    the scan is refused — because the alternative is to compare against an
    older report and label the difference "new since the previous scan",
    which is a false statement about a baseline the user never chose. An
    older report is still available, but only by naming it.

    An id the CLIENT named is strict for the same reason. An id from another
    project cannot be distinguished here from one that does not exist, and
    deliberately so: both answer the same way, so this endpoint cannot be
    used to probe whether some other project owns a given id."""
    if requested_id and not compare_previous:
        raise BaselineRefused("a baseline was selected while comparison "
                              "with a previous scan is off")
    if not compare_previous:
        if new_only:
            raise BaselineRefused("gating new findings only requires a "
                                  "comparison with a previous scan")
        return "", None
    if requested_id:
        if not _id_ok(requested_id):
            raise BaselineRefused("invalid baseline report id")
        row = store.report(requested_id)
        if row is None or row["project_id"] != pid:
            raise BaselineRefused(
                "the selected baseline is not a report of this project")
        reason = hold(requested_id)
        if reason is not None:
            raise BaselineRefused(reason, status=409)
        # ... and only now, with deletion locked out, is the file read.
        path = baseline_source(paths, requested_id)
        if path is None:
            release(requested_id)
            raise BaselineRefused(
                "the selected baseline report cannot be read")
        return requested_id, path
    history = store.reports_for(pid)               # newest first, by `seq`
    if not history:
        if new_only:
            raise BaselineRefused("gating new findings only requires a "
                                  "previous report to compare against")
        return "", None                            # a first scan
    newest = history[0]["report_id"]
    reason = hold(newest)
    if reason is not None:
        raise BaselineRefused(reason, status=409)
    path = baseline_source(paths, newest)
    if path is None:
        release(newest)
        raise BaselineRefused(
            "the previous report cannot be read; choose another report to "
            "compare against, or turn the comparison off", status=409)
    return newest, path


def baseline_row_fields(summary: Any, *, baseline_report_id: str,
                        new_only: bool) -> dict[str, Any] | None:
    """The six W4-B report-row fields, read from the REPORT's own
    `summary.baseline` — the authority. Nothing is recomputed here and no
    count is inferred from the findings list.

    None means the report contradicts what the scan was asked to do: it
    claims a comparison that was never requested, omits one that was, or
    gates on a scope that does not match the request. That is a fail-closed
    signal, not a repairable state — a row invented to paper over it would
    show the user a comparison that never happened."""
    block = summary.get("baseline") if isinstance(summary, dict) else None
    enabled = isinstance(block, dict) and block.get("enabled") is True
    if not baseline_report_id:
        if enabled:
            return None                # a comparison nobody asked for
        return {"baseline_report_id": "", "baseline_enabled": False,
                "baseline_findings": 0,
                "new": 0, "unchanged": 0, "resolved": 0, "gate_scope": "all"}
    if not enabled or not isinstance(block, dict):
        return None                    # asked for, not delivered
    raw = {k: block.get(k) for k in ("new", "unchanged", "resolved")}
    if not all(_int_ok(v) for v in raw.values()):
        return None
    # _int_ok has just proved each value is a real int, so this narrowing is
    # a statement of that fact rather than a conversion
    counts: dict[str, int] = {k: v for k, v in raw.items()
                              if isinstance(v, int)}
    if block.get("gate_scope") != ("new" if new_only else "all"):
        return None
    # The baseline's own size, as the MATCHER saw it: everything it held was
    # either matched by a current finding or is gone. Recorded on the row so
    # the arithmetic survives the baseline's deletion — and cross-checked at
    # commit time against what the store says that report actually held, so
    # the two independent accounts have to agree.
    return {"baseline_report_id": baseline_report_id, "baseline_enabled": True,
            "baseline_findings": counts["unchanged"] + counts["resolved"],
            "gate_scope": block["gate_scope"], **counts}


# ---- jobs ----------------------------------------------------------------------------

def _default_spawn(argv: list[str], cwd: Path, stdout_path: Path,
                   stderr_path: Path, env: dict[str, str]) -> Any:
    """Real subprocess launcher: argv list, shell NEVER, stdin closed,
    output to bounded-read files, own process group on Windows so the whole
    tree can be killed."""
    creation = 0
    if sys.platform == "win32":
        creation = subprocess.CREATE_NEW_PROCESS_GROUP
    with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
        return subprocess.Popen(          # noqa: S603 - fixed argv, no shell
            argv, cwd=str(cwd), env=env, stdin=subprocess.DEVNULL,
            stdout=out, stderr=err, shell=False, creationflags=creation)


def kill_process_tree(proc: Any) -> None:
    """Terminate the job process AND its children. On Windows a plain
    terminate() orphans grandchildren (git spawns helpers), so taskkill /T
    is used; elsewhere kill() on the group leader suffices for our argv."""
    try:
        if sys.platform == "win32":
            subprocess.run(              # noqa: S603 - fixed argv, no shell
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True, shell=False, timeout=30)
        else:
            proc.kill()
    except (OSError, subprocess.SubprocessError):
        try:
            proc.kill()
        except OSError:
            pass


def tail_of(path: Path, cap: int = OUTPUT_TAIL_BYTES) -> str:
    """Bounded read of a captured stream file: the LAST `cap` bytes only."""
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            if size > cap:
                fh.seek(size - cap)
            return fh.read(cap).decode("utf-8", errors="replace")
    except OSError:
        return ""


@dataclass
class _ActiveJob:
    job_id: str
    project_id: str = ""
    proc: Any = None
    cancel_requested: bool = False
    thread: threading.Thread | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)
    # W4-B. The id is persisted on the job row; the PATH is not — it exists
    # only for the argv of this one subprocess and never reaches the store,
    # the API, or an error message.
    baseline_report_id: str = ""
    baseline_path: Path | None = None
    new_only: bool = False


class JobRunner:
    """One clone/scan job at a time. State machine per the contract:
    pending → running → completed | failed | canceled; a restart turns any
    persisted active job into `interrupted` (LibraryStore._load). A new
    report is validated and promoted ATOMICALLY; any failure keeps the last
    good report and leaves no tmp litter."""

    def __init__(self, store: LibraryStore, paths: LibraryPaths,
                 spawn: Callable[..., Any] | None = None,
                 env: dict[str, str] | None = None,
                 reserve: Callable[[list[str]], str | None] | None = None,
                 release: Callable[[list[str]], None] | None = None,
                 release_baseline: Callable[[str], None] | None = None
                 ) -> None:
        self._store = store
        self._paths = paths
        self._spawn = spawn if spawn is not None else _default_spawn
        self._env = env
        # W4-B: the baseline lease is TAKEN by the caller (it has to be, to
        # keep resolution and leasing one step) and handed over on a
        # successful start(); from then on this runner owns it and releases
        # it exactly once, in the job thread's finally.
        self._release_baseline = release_baseline
        # W4-A closing: retention takes the SAME deletion lease as manual
        # deletion (reserve -> delete files -> metadata -> release in
        # finally). reserve returns a safe refusal reason or None; a report
        # whose context is cached (even idle) is refused and kept above the
        # retention cap temporarily.
        self._reserve = reserve
        self._release = release
        self._lock = threading.Lock()
        self._active: _ActiveJob | None = None

    # -- public ------------------------------------------------------------

    def start(self, project: dict[str, Any], kind: str, *,
              online: bool = False, semgrep: bool = False,
              register_project: bool = False,
              baseline_report_id: str = "", baseline_path: Path | None = None,
              new_only: bool = False) -> str:
        """Start a job. With register_project=True the project row itself is
        committed IN THE SAME store transaction as the job, under the SAME
        runner slot reservation — a busy runner or a store failure leaves
        zero project rows, zero directories, zero subprocesses (the
        active-slot check and the commit happen inside one lock, so there is
        no separate racy pre-check).

        W4-B: `baseline_report_id`/`baseline_path` must already be resolved
        and leased by the caller. A raise here means the lease did NOT
        transfer and the caller still owns it."""
        if kind not in JOB_KINDS:
            raise LibraryStoreError("unknown job kind")
        if bool(baseline_report_id) != (baseline_path is not None):
            raise LibraryStoreError("baseline id and path must agree")
        if new_only and not baseline_report_id:
            raise LibraryStoreError("gating new findings only requires a "
                                    "baseline")
        with self._lock:
            if self._active is not None:
                raise LibraryStoreError("another job is already running")
            jid = new_id()
            row = {"job_id": jid, "project_id": project["project_id"],
                   "kind": kind, "state": "pending", "online": online,
                   "semgrep": semgrep, "created_at": _now_iso(),
                   "started_at": "", "finished_at": "", "error": "",
                   "report_id": "",
                   "baseline_report_id": baseline_report_id,
                   "new_only": new_only}
            # raises before the slot is taken — nothing persisted on failure
            if register_project:
                self._store.put_project_and_job(project, row)
            else:
                self._store.put_job(row)
            active = _ActiveJob(job_id=jid,
                                project_id=project["project_id"],
                                baseline_report_id=baseline_report_id,
                                baseline_path=baseline_path,
                                new_only=new_only)
            self._active = active
        thread = threading.Thread(
            target=self._run, args=(active, project, row), daemon=True)
        active.thread = thread
        thread.start()
        return jid

    def cancel(self, jid: str) -> bool:
        with self._lock:
            active = self._active
        if active is None or active.job_id != jid:
            return False
        with active.lock:
            active.cancel_requested = True
            proc = active.proc
        if proc is not None:
            kill_process_tree(proc)
        return True

    def wait(self, jid: str, timeout: float = 30.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                active = self._active
            if active is None or active.job_id != jid:
                return
            time.sleep(0.02)

    def active_job_id(self) -> str | None:
        with self._lock:
            return self._active.job_id if self._active else None

    def active_project_id(self) -> str | None:
        """The project whose job currently holds the runner slot, in-memory
        and authoritative — set the instant a job is accepted and cleared
        only after the job thread fully unwinds. Unlike store.active_job()
        (which reads the persisted row state), this still reports the
        project during a job's cancel/finish transition, so a removal
        checking it never races the slot to an orphan."""
        with self._lock:
            return self._active.project_id if self._active else None

    # -- internals ----------------------------------------------------------

    @staticmethod
    def _terminal(row: dict[str, Any], state: str, *, error: str = "",
                  report_id: str = "") -> dict[str, Any]:
        row = dict(row)
        row["state"] = state
        row["finished_at"] = _now_iso()
        row["error"] = error[:ERROR_MAX_CHARS]
        row["report_id"] = report_id
        return row

    def _finish(self, row: dict[str, Any], state: str, *,
                error: str = "", report_id: str = "") -> None:
        """Record a job's final state. If it cannot be recorded, the store
        is declared unavailable.

        This used to swallow the failure with the comment "job outcome is
        best-effort metadata". It is not: it is the only record of whether a
        scan finished, and of which report it produced. Losing it silently
        left a finished job reading `running` for the life of the process
        and `interrupted` after a restart — while its report sat in the
        library, eligible to be the next scan's baseline."""
        try:
            self._store.put_job(self._terminal(row, state, error=error,
                                               report_id=report_id))
        except LibraryStoreError:
            self._store.mark_unavailable(
                "a job's final state could not be recorded, so the library "
                "no longer describes what has run")

    def _run(self, active: _ActiveJob, project: dict[str, Any],
             row: dict[str, Any]) -> None:
        tmp = self._paths.tmp_dir(active.job_id)
        try:
            self._execute(active, project, row, tmp)
        except BaseException:          # noqa: BLE001 - the slot MUST free
            self._finish(row, "failed", error="internal job error")
        finally:
            self._paths.confined_delete(tmp)
            # W4-B: the baseline lease is released on EVERY exit — success,
            # failure, cancellation, or an internal error — and after the
            # retention prune inside _execute, so a scan can never delete the
            # report it was still comparing against.
            if active.baseline_report_id and self._release_baseline is not None:
                self._release_baseline(active.baseline_report_id)
            with self._lock:
                if self._active is active:
                    self._active = None

    def _source_dir(self, project: dict[str, Any]) -> Path | None:
        if project["kind"] == "git":
            src = self._paths.clone_dir(project["project_id"])
            return src if src.is_dir() else None
        p = Path(project["local_path"])
        return p if p.is_dir() else None

    def _execute(self, active: _ActiveJob, project: dict[str, Any],
                 row: dict[str, Any], tmp: Path) -> None:
        row = dict(row)
        row["state"] = "running"
        row["started_at"] = _now_iso()
        try:
            self._store.put_job(row)
        except LibraryStoreError:
            # Nothing has been created yet and nothing has been spawned. If
            # the store cannot even record that this job started, a running
            # subprocess would be invisible to every later reader — so it is
            # not started at all. `_run`'s finally frees the slot and the
            # baseline lease; the row stays `pending` on disk and a restart
            # turns it into `interrupted` under the existing contract.
            self._store.mark_unavailable(
                "a job's start could not be recorded, so no scan was run")
            return
        tmp.mkdir(parents=True, exist_ok=True)
        stdout_p, stderr_p = tmp / "stdout.log", tmp / "stderr.log"

        if row["kind"] == "clone":
            dest = tmp / "src"
            argv = git_clone_argv(project["git_url"], dest)
            ok, reason = self._wait_proc(active, argv, tmp, stdout_p,
                                         stderr_p, allow_rc=(0,))
            if not ok:
                self._finish(row, "canceled" if reason == "canceled"
                             else "failed", error=reason)
                return
            final = self._paths.clone_dir(project["project_id"])
            if not self._paths.confined_delete(final):
                self._finish(row, "failed", error="clone promotion failed")
                return
            try:
                final.parent.mkdir(parents=True, exist_ok=True)
                os.replace(dest, final)
            except OSError:
                self._finish(row, "failed", error="clone promotion failed")
                return
            self._finish(row, "completed")
            return

        # scan
        src = self._source_dir(project)
        if src is None:
            self._finish(row, "failed",
                         error="project source is not available")
            return
        out_dir = tmp / "out"
        argv = scan_argv(src, out_dir, online=row["online"],
                         semgrep=row["semgrep"],
                         baseline=active.baseline_path,
                         new_only=active.new_only)
        started = time.monotonic()
        # the scan CLI exits non-zero on block/review verdicts — those are
        # REPORTS, not failures. Any rc is fine as long as report.json is
        # valid; a missing/invalid report is the failure signal.
        ok, reason = self._wait_proc(active, argv, tmp, stdout_p, stderr_p,
                                     allow_rc=None)
        if not ok:
            self._finish(row, "canceled" if reason == "canceled"
                         else "failed", error=reason)
            return
        duration_ms = int((time.monotonic() - started) * 1000)
        from auditor.web.app import ReportError, load_report
        report_json = out_dir / "report.json"
        try:
            data = load_report(report_json)
        except ReportError:
            self._finish(row, "failed",
                         error="scan produced no valid report")
            return
        raw_summary = data.get("summary")
        summary: dict[str, Any] = raw_summary \
            if isinstance(raw_summary, dict) else {}
        # W4-B: the comparison is validated against the request BEFORE
        # promotion, so a report that did not do what it was asked to do is
        # never promoted, never recorded, and never shown as a rescan.
        baseline_fields = baseline_row_fields(
            summary, baseline_report_id=active.baseline_report_id,
            new_only=active.new_only)
        if baseline_fields is None:
            self._finish(row, "failed",
                         error="scan did not apply the requested comparison")
            return
        verdict = summary.get("verdict")
        # the WHOLE report's findings, whatever the gate counted. This count
        # and the comparison above come from DIFFERENT parts of the report —
        # the project lists and `summary.baseline` — so requiring
        # `new + unchanged == findings` is a real cross-check, not a tautology.
        findings = sum(len(p.get("findings", []))
                       for p in data.get("projects", [])
                       if isinstance(p, dict)
                       and isinstance(p.get("findings"), list))
        rid = new_id()
        report_row = {"report_id": rid, "project_id": project["project_id"],
                      "created_at": _now_iso(),
                      "verdict": verdict if isinstance(verdict, str) else "",
                      "findings": findings, "duration_ms": duration_ms,
                      **baseline_fields}
        # checked BEFORE promotion: a report whose own numbers disagree is
        # never moved into the library at all
        if not _valid_report(report_row, keys=REPORT_INPUT_KEYS):
            self._finish(row, "failed",
                         error="scan produced an inconsistent comparison")
            return
        final_dir = self._paths.report_dir(rid)
        try:
            final_dir.parent.mkdir(parents=True, exist_ok=True)
            os.replace(out_dir, final_dir)
        except OSError:
            self._finish(row, "failed", error="report promotion failed")
            return
        # ONE transaction: the report and the job that claims it, or neither.
        # Committing them separately left an orphan report — usable, and
        # picked as the next scan's baseline — behind a job still reading
        # `running`.
        try:
            self._store.put_report_and_finish_job(
                report_row, self._terminal(row, "completed", report_id=rid))
        except LibraryStoreError:
            # nothing was committed, so the promoted directory has no row to
            # belong to: remove it, and say the library is out of date rather
            # than leave a half-recorded run
            self._paths.confined_delete(final_dir)
            self._store.mark_unavailable(
                "a finished scan could not be recorded, so the library no "
                "longer describes what has run")
            return
        self._prune_reports(project["project_id"])

    def _prune_reports(self, pid: str) -> None:
        """Retention: FILES first, metadata second — the same contract as
        report deletion. A report with a loaded context or an unsafe/failed
        file delete is kept ABOVE the cap temporarily; a files-gone-but-
        store-failed row is retried on the next prune."""
        rows = self._store.reports_for(pid)     # newest first
        for row in rows[MAX_REPORTS_PER_PROJECT:]:
            rid = row["report_id"]
            if self._reserve is not None \
                    and self._reserve([rid]) is not None:
                continue          # loaded/being-deleted: kept above the cap
            try:
                if not self._paths.confined_delete(
                        self._paths.report_dir(rid)):
                    continue                    # keep the metadata aligned
                try:
                    self._store.remove_report(rid)
                except LibraryStoreError:
                    continue                    # retried next prune
            finally:
                if self._release is not None:
                    self._release([rid])        # ALWAYS frees the lease


    def _wait_proc(self, active: _ActiveJob, argv: list[str], cwd: Path,
                   stdout_p: Path, stderr_p: Path,
                   allow_rc: tuple[int, ...] | None) -> tuple[bool, str]:
        """Spawn and wait with timeout + cancel. Returns (ok, safe_reason).
        allow_rc=None accepts ANY return code (the artifact is validated
        separately); otherwise the rc must be in the tuple."""
        env = job_env() if self._env is None else dict(self._env)
        try:
            proc = self._spawn(argv, cwd, stdout_p, stderr_p, env)
        except OSError:
            return False, "the job process could not be started"
        with active.lock:
            if active.cancel_requested:
                kill_process_tree(proc)
                return False, "canceled"
            active.proc = proc
        timeout = job_timeout(self._env)
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            kill_process_tree(proc)
            try:
                proc.wait(timeout=10)
            except (subprocess.TimeoutExpired, OSError):
                pass
            return False, f"timed out after {int(timeout)}s"
        finally:
            with active.lock:
                active.proc = None
        if active.cancel_requested:
            return False, "canceled"
        if allow_rc is not None and rc not in allow_rc:
            return False, f"the job process exited with code {rc}"
        return True, ""
