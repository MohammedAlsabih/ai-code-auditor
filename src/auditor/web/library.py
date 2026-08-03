"""W4-A: the Project Library backend — compatibility facade.

LIBRARY-REFACTOR-1A1 split this module into three, by ownership:

* `library_contract` — constants, row schemas, validators, migrations and the
  argv/env builders. Pure statements about the data; imports nothing of ours.
* `library_store`    — `LibraryStore` and `LibraryPaths`: atomic commits,
  bounded reads, confined paths. Records and answers; never spawns or leases.
* `library_runtime`  — `JobRunner` and the active-job lifecycle: subprocess,
  cancellation, leases, retention. The only module that starts a process.

Every name the previous single module exported is re-exported here, so
existing imports keep working unchanged. This file adds no behaviour and
holds no state. New code should import from the module that OWNS the name.

One consequence worth knowing: a test that REPLACES a name must patch the
owning module, not this one. Re-exports are bindings, not aliases — rebinding
`library.kill_process_tree` would leave `library_runtime` calling the
original. The names tests replace (`kill_process_tree`, `_now_iso`,
`MAX_REPORTS_PER_PROJECT`) are dereferenced through their owning module at
call time so that patching the owner actually takes effect.
"""
from __future__ import annotations

# `library.shutil` is part of the historical surface: tests reach through it
# to patch `shutil.rmtree`, which is global and therefore still effective.
import shutil  # noqa: F401

from auditor.web.library_contract import (
    ALLOWED_GIT_HOSTS,
    BaselineRefused,
    ERROR_MAX_CHARS,
    GATE_SCOPES,
    JOB_KEYS,
    JOB_KINDS,
    JOB_STATES,
    LOCATION_MAX_CHARS,
    LibraryStoreError,
    MAX_JOBS_KEPT,
    MAX_PROJECTS,
    MAX_REPORTS_PER_PROJECT,
    NAME_MAX_CHARS,
    OUTPUT_TAIL_BYTES,
    PROJECT_KEYS,
    PROJECT_KINDS,
    REPORT_INPUT_KEYS,
    REPORT_KEYS,
    SCHEMA_VERSION,
    SCHEMA_VERSION_LEGACY,
    STORE_MAX_BYTES,
    URL_MAX_CHARS,
    _now_iso,
    bad_git_url,
    baseline_row_fields,
    git_clone_argv,
    job_env,
    job_timeout,
    migrate_job_row,
    migrate_report_row,
    new_id,
    repo_name_from_url,
    resolve_local_registration,
    safe_location,
    scan_argv,
)
from auditor.web.library_store import (
    LibraryPaths,
    LibraryStore,
    baseline_source,
    resolve_baseline,
)
from auditor.web.library_runtime import (
    JobRunner,
    _default_spawn,
    kill_process_tree,
    tail_of,
)

__all__ = [
    "ALLOWED_GIT_HOSTS",
    "BaselineRefused",
    "ERROR_MAX_CHARS",
    "GATE_SCOPES",
    "JOB_KEYS",
    "JOB_KINDS",
    "JOB_STATES",
    "JobRunner",
    "LOCATION_MAX_CHARS",
    "LibraryPaths",
    "LibraryStore",
    "LibraryStoreError",
    "MAX_JOBS_KEPT",
    "MAX_PROJECTS",
    "MAX_REPORTS_PER_PROJECT",
    "NAME_MAX_CHARS",
    "OUTPUT_TAIL_BYTES",
    "PROJECT_KEYS",
    "PROJECT_KINDS",
    "REPORT_INPUT_KEYS",
    "REPORT_KEYS",
    "SCHEMA_VERSION",
    "SCHEMA_VERSION_LEGACY",
    "STORE_MAX_BYTES",
    "URL_MAX_CHARS",
    "_default_spawn",
    "_now_iso",
    "bad_git_url",
    "baseline_row_fields",
    "baseline_source",
    "git_clone_argv",
    "job_env",
    "job_timeout",
    "kill_process_tree",
    "migrate_job_row",
    "migrate_report_row",
    "new_id",
    "repo_name_from_url",
    "resolve_baseline",
    "resolve_local_registration",
    "safe_location",
    "scan_argv",
    "shutil",
    "tail_of",
]
