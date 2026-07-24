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

SCHEMA_VERSION = "library-1"
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
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---- validation ---------------------------------------------------------------------

def bad_git_url(url: Any) -> str | None:
    """Pure validation of a Git URL BEFORE any network or subprocess.
    Returns a safe rejection reason (never echoes the input) or None.
    Alpha policy: public HTTPS only — no credentials, no query, no
    fragment, no ssh/git/file/scp-like forms."""
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
              semgrep: bool) -> list[str]:
    """The scan subprocess argv: this interpreter, no shell, offline by
    default (registry lookups happen only on an explicit online request)."""
    argv = [sys.executable, "-c", _CLI_BOOTSTRAP, "scan", str(source_dir),
            "--output", str(out_dir)]
    if not online:
        argv.append("--offline")
    if not semgrep:
        argv.append("--no-semgrep")
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
REPORT_KEYS = ("report_id", "project_id", "created_at", "verdict",
               "findings", "duration_ms")
JOB_KEYS = ("job_id", "project_id", "kind", "state", "online", "semgrep",
            "created_at", "started_at", "finished_at", "error", "report_id")


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


def _valid_report(row: Any) -> bool:
    return (isinstance(row, dict) and set(row) == set(REPORT_KEYS)
            and _id_ok(row["report_id"]) and _id_ok(row["project_id"])
            and _text_ok(row["created_at"], 40)
            and _text_ok(row["verdict"], 40, allow_empty=True)
            and _int_ok(row["findings"]) and _int_ok(row["duration_ms"]))


def _valid_job(row: Any) -> bool:
    return (isinstance(row, dict) and set(row) == set(JOB_KEYS)
            and _id_ok(row["job_id"]) and _id_ok(row["project_id"])
            and row["kind"] in JOB_KINDS and row["state"] in JOB_STATES
            and isinstance(row["online"], bool)
            and isinstance(row["semgrep"], bool)
            and _text_ok(row["created_at"], 40)
            and _text_ok(row["started_at"], 40, allow_empty=True)
            and _text_ok(row["finished_at"], 40, allow_empty=True)
            and _text_ok(row["error"], ERROR_MAX_CHARS, allow_empty=True)
            and (row["report_id"] == "" or _id_ok(row["report_id"])))


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
        try:
            raw = self._path.read_bytes()[:STORE_MAX_BYTES + 1]
            data = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            self.available, self.error = False, "library store unreadable"
            return
        if len(raw) > STORE_MAX_BYTES:
            self.available, self.error = False, "library store exceeds cap"
            return
        if not isinstance(data, dict) \
                or set(data) != {"schema_version", "projects", "reports",
                                 "jobs"} \
                or data.get("schema_version") != SCHEMA_VERSION \
                or not all(isinstance(data[k], dict) for k in
                           ("projects", "reports", "jobs")):
            self.available, self.error = False, \
                "library store has an unsupported shape or schema_version"
            return
        for pid, row in data["projects"].items():
            if not _valid_project(row) or row["project_id"] != pid:
                self.available, self.error = False, \
                    "library store has a malformed project row"
                return
        for rid, row in data["reports"].items():
            if not _valid_report(row) or row["report_id"] != rid:
                self.available, self.error = False, \
                    "library store has a malformed report row"
                return
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
        self._data = data
        # persist the interrupted transitions; failure leaves memory correct
        try:
            self._write(self._data)
        except LibraryStoreError:
            pass

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
        with self._lock:
            return sorted((dict(r) for r in self._data["projects"].values()),
                          key=lambda r: (r["created_at"], r["project_id"]))

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
        if not _valid_report(row):
            raise LibraryStoreError("malformed report row")

        def mutate(d: dict[str, Any]) -> None:
            if row["project_id"] not in d["projects"]:
                raise LibraryStoreError("unknown project id")
            d["reports"][row["report_id"]] = dict(row)
        self._commit(mutate)

    def report(self, rid: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._data["reports"].get(rid)
            return dict(row) if row else None

    def reports_for(self, pid: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = [dict(r) for r in self._data["reports"].values()
                    if r["project_id"] == pid]
            return sorted(rows, key=lambda r: (r["created_at"],
                                               r["report_id"]), reverse=True)

    def remove_report(self, rid: str) -> None:
        def mutate(d: dict[str, Any]) -> None:
            if rid not in d["reports"]:
                raise LibraryStoreError("unknown report id")
            del d["reports"][rid]
        self._commit(mutate)

    # -- jobs --------------------------------------------------------------

    def put_job(self, row: dict[str, Any]) -> None:
        if not _valid_job(row):
            raise LibraryStoreError("malformed job row")

        def mutate(d: dict[str, Any]) -> None:
            d["jobs"][row["job_id"]] = dict(row)
            finished = [j for j, r in sorted(
                d["jobs"].items(),
                key=lambda kv: (kv[1]["created_at"], kv[0]))
                if r["state"] not in _ACTIVE_JOB_STATES]
            excess = len(d["jobs"]) - MAX_JOBS_KEPT
            for jid in finished[:max(excess, 0)]:
                del d["jobs"][jid]
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
            return dict(max(rows, key=lambda r: (r["created_at"],
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
        root, is not a symlink itself, and still exists. Returns True when
        something was removed."""
        try:
            if target.is_symlink():
                return False
            if not target.exists():
                return False
            resolved = target.resolve(strict=True)
            root = self.root.resolve(strict=True)
        except (OSError, RuntimeError):
            return False
        if resolved == root or root not in resolved.parents:
            return False
        shutil.rmtree(resolved, ignore_errors=True)
        return True


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
    proc: Any = None
    cancel_requested: bool = False
    thread: threading.Thread | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)


class JobRunner:
    """One clone/scan job at a time. State machine per the contract:
    pending → running → completed | failed | canceled; a restart turns any
    persisted active job into `interrupted` (LibraryStore._load). A new
    report is validated and promoted ATOMICALLY; any failure keeps the last
    good report and leaves no tmp litter."""

    def __init__(self, store: LibraryStore, paths: LibraryPaths,
                 spawn: Callable[..., Any] | None = None,
                 env: dict[str, str] | None = None) -> None:
        self._store = store
        self._paths = paths
        self._spawn = spawn if spawn is not None else _default_spawn
        self._env = env
        self._lock = threading.Lock()
        self._active: _ActiveJob | None = None

    # -- public ------------------------------------------------------------

    def start(self, project: dict[str, Any], kind: str, *,
              online: bool = False, semgrep: bool = False) -> str:
        if kind not in JOB_KINDS:
            raise LibraryStoreError("unknown job kind")
        with self._lock:
            if self._active is not None:
                raise LibraryStoreError("another job is already running")
            jid = new_id()
            row = {"job_id": jid, "project_id": project["project_id"],
                   "kind": kind, "state": "pending", "online": online,
                   "semgrep": semgrep, "created_at": _now_iso(),
                   "started_at": "", "finished_at": "", "error": "",
                   "report_id": ""}
            self._store.put_job(row)      # raises before the slot is taken
            active = _ActiveJob(job_id=jid)
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

    # -- internals ----------------------------------------------------------

    def _finish(self, row: dict[str, Any], state: str, *,
                error: str = "", report_id: str = "") -> None:
        row = dict(row)
        row["state"] = state
        row["finished_at"] = _now_iso()
        row["error"] = error[:ERROR_MAX_CHARS]
        row["report_id"] = report_id
        try:
            self._store.put_job(row)
        except LibraryStoreError:
            pass                      # job outcome is best-effort metadata

    def _run(self, active: _ActiveJob, project: dict[str, Any],
             row: dict[str, Any]) -> None:
        tmp = self._paths.tmp_dir(active.job_id)
        try:
            self._execute(active, project, row, tmp)
        except BaseException:          # noqa: BLE001 - the slot MUST free
            self._finish(row, "failed", error="internal job error")
        finally:
            self._paths.confined_delete(tmp)
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
            pass
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
            try:
                final.parent.mkdir(parents=True, exist_ok=True)
                if final.exists():
                    self._paths.confined_delete(final)
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
                         semgrep=row["semgrep"])
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
        rid = new_id()
        final_dir = self._paths.report_dir(rid)
        try:
            final_dir.parent.mkdir(parents=True, exist_ok=True)
            os.replace(out_dir, final_dir)
        except OSError:
            self._finish(row, "failed", error="report promotion failed")
            return
        raw_summary = data.get("summary")
        summary: dict[str, Any] = raw_summary \
            if isinstance(raw_summary, dict) else {}
        verdict = summary.get("verdict")
        findings = sum(len(p.get("findings", []))
                       for p in data.get("projects", [])
                       if isinstance(p, dict)
                       and isinstance(p.get("findings"), list))
        report_row = {"report_id": rid, "project_id": project["project_id"],
                      "created_at": _now_iso(),
                      "verdict": verdict if isinstance(verdict, str) else "",
                      "findings": findings, "duration_ms": duration_ms}
        try:
            self._store.put_report(report_row)
        except LibraryStoreError:
            # metadata write failed — remove the orphaned promoted report so
            # the store and the filesystem stay aligned
            self._paths.confined_delete(final_dir)
            self._finish(row, "failed", error="report metadata write failed")
            return
        self._prune_reports(project["project_id"])
        self._finish(row, "completed", report_id=rid)

    def _prune_reports(self, pid: str) -> None:
        rows = self._store.reports_for(pid)     # newest first
        for row in rows[MAX_REPORTS_PER_PROJECT:]:
            rid = row["report_id"]
            try:
                self._store.remove_report(rid)
            except LibraryStoreError:
                continue
            self._paths.confined_delete(self._paths.report_dir(rid))

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
