"""The Project Library's pure contracts: constants, row schemas,
validators, migrations, and the argv/env builders.

LIBRARY-REFACTOR-1A1. This module owns everything that is a STATEMENT about
the data rather than an action on it. It imports nothing from the store or
the runtime, so a validator can never quietly start touching disk and a
schema change cannot be hidden inside an I/O path.
"""
from __future__ import annotations

import os
import re
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

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




# ---- baselines: the refusal contract -------------------------------------------------

class BaselineRefused(LibraryStoreError):
    """The requested comparison cannot be made. Carries the status the API
    should answer with: 400 for a request that was never valid, 409 for a
    live conflict (the report is being deleted right now). The message is
    always safe — it never contains a path or a foreign project's id."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status



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
