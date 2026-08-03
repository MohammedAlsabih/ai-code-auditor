"""The Project Library's storage: one JSON document, atomic writes,
bounded reads, and the confined path algebra every other module derives its
filesystem access from.

LIBRARY-REFACTOR-1A1. Nothing here starts a process or owns a lease. It
answers what is recorded and commits what it is given, atomically or not at
all.
"""
from __future__ import annotations

import json
import os
import shutil
import threading
from pathlib import Path
from typing import Any, Callable

# The contract module is imported BOTH ways on purpose: by name for the
# pure constants and validators, and as a module for the few callables a
# test needs to intercept. A by-name copy of `_now_iso` could not be
# replaced, and the store's report ordering is asserted against a
# controlled clock.
from auditor.web import library_contract as contract
from auditor.web.library_contract import (
    _ACTIVE_JOB_STATES,
    MAX_JOBS_KEPT,
    MAX_PROJECTS,
    REPORT_INPUT_KEYS,
    SCHEMA_VERSION,
    SCHEMA_VERSION_LEGACY,
    STORE_MAX_BYTES,
    BaselineRefused,
    LibraryStoreError,
    _id_ok,
    _stamp_key,
    _valid_job,
    _valid_project,
    _report_lineage_ok,
    _valid_report,
    migrate_job_row,
    migrate_report_row,
)

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
                row["finished_at"] = contract._now_iso()
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


