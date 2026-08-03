"""LIBRARY-REFACTOR-1A: the module boundaries themselves.

The split is only worth having if the boundaries hold. These tests assert
what each module is allowed to know, that the compatibility facade still
exports everything the previous single module did, and that nothing imports
in a circle.
"""
from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import auditor.web.library as facade
import auditor.web.library_contract as contract
import auditor.web.library_runtime as runtime
import auditor.web.library_store as store

WEB = Path(facade.__file__).parent

# Every name the single pre-split module exported and that any importer in
# this repository actually used. A rename that drops one of these breaks a
# caller, so the list is explicit rather than derived from the module.
PUBLIC_SURFACE = (
    "ALLOWED_GIT_HOSTS", "BaselineRefused", "ERROR_MAX_CHARS", "GATE_SCOPES",
    "JOB_KEYS", "JOB_KINDS", "JOB_STATES", "JobRunner", "LOCATION_MAX_CHARS",
    "LibraryPaths", "LibraryStore", "LibraryStoreError", "MAX_JOBS_KEPT",
    "MAX_PROJECTS", "MAX_REPORTS_PER_PROJECT", "NAME_MAX_CHARS",
    "OUTPUT_TAIL_BYTES", "PROJECT_KEYS", "PROJECT_KINDS", "REPORT_INPUT_KEYS",
    "REPORT_KEYS", "SCHEMA_VERSION", "SCHEMA_VERSION_LEGACY",
    "STORE_MAX_BYTES", "URL_MAX_CHARS", "_default_spawn", "_now_iso",
    "bad_git_url", "baseline_row_fields", "baseline_source", "git_clone_argv",
    "job_env", "job_timeout", "kill_process_tree", "migrate_job_row",
    "migrate_report_row", "new_id", "repo_name_from_url", "resolve_baseline",
    "resolve_local_registration", "safe_location", "scan_argv", "shutil",
    "tail_of",
)


def _imports_of(path: Path, *, top_level_only: bool = True) -> set[str]:
    """Every `auditor.web.*` module this file imports.

    `from auditor.web import library_contract` resolves to
    `auditor.web.library_contract`, not to the package — otherwise every
    module would look like it depends on all of `auditor.web`.

    `top_level_only` separates a real module dependency from a DEFERRED one
    written inside a function to break an import cycle. The two are not the
    same thing and the boundary tests below rely on telling them apart."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    if top_level_only:
        nodes: list[ast.AST] = []
        for stmt in tree.body:                    # module level only
            nodes.extend(ast.walk(stmt)) if isinstance(
                stmt, (ast.Import, ast.ImportFrom)) else None
    else:
        nodes = list(ast.walk(tree))
    out: set[str] = set()
    for node in nodes:
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module == "auditor.web":
                out |= {f"auditor.web.{a.name}" for a in node.names}
            elif node.module.startswith("auditor.web"):
                out.add(node.module)
        elif isinstance(node, ast.Import):
            out |= {a.name for a in node.names
                    if a.name.startswith("auditor.web")}
    return out


# ---- the compatibility facade --------------------------------------------------------

@pytest.mark.parametrize("name", PUBLIC_SURFACE)
def test_every_previously_exported_name_still_imports_from_library(name):
    """`from auditor.web.library import X` must keep working for every X the
    single module used to provide."""
    assert hasattr(facade, name), name


def test_the_facade_declares_exactly_what_it_re_exports():
    assert set(facade.__all__) == set(PUBLIC_SURFACE)


def test_the_facade_holds_no_logic_of_its_own():
    """It is a re-export list. A function or class defined here would be a
    fourth home for behaviour, which is what the split removed."""
    tree = ast.parse((WEB / "library.py").read_text(encoding="utf-8"))
    defined = [n.name for n in tree.body
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef))]
    assert defined == [], f"the facade defines {defined}"


def test_names_resolve_to_their_owning_module():
    assert facade.LibraryStore.__module__ == "auditor.web.library_store"
    assert facade.JobRunner.__module__ == "auditor.web.library_runtime"
    assert facade.new_id.__module__ == "auditor.web.library_contract"


# ---- ownership -----------------------------------------------------------------------

def test_the_contract_knows_nothing_about_the_store_or_the_runtime():
    """Pure statements about the data. If a validator could reach the store,
    a schema check could start depending on what is on disk."""
    assert _imports_of(WEB / "library_contract.py") == set()


def test_the_store_knows_the_contract_and_not_the_runtime():
    imports = _imports_of(WEB / "library_store.py")
    assert imports <= {"auditor.web.library_contract"}, imports


def test_the_runtime_knows_the_contract_and_the_store_only():
    imports = _imports_of(WEB / "library_runtime.py")
    assert imports <= {"auditor.web.library_contract",
                       "auditor.web.library_store"}, imports


def test_the_runtimes_only_reach_into_the_app_is_a_deferred_import():
    """The runtime validates a produced report with `auditor.web.app`'s
    loader. `app` imports the library, so this one dependency is written
    inside the function that uses it — a module-level import would be a
    cycle. The test pins BOTH halves: it is absent at module level, and it
    is present somewhere in the file."""
    top = _imports_of(WEB / "library_runtime.py")
    everywhere = _imports_of(WEB / "library_runtime.py", top_level_only=False)
    assert "auditor.web.app" not in top
    assert "auditor.web.app" in everywhere


def test_the_http_layer_copies_no_store_or_runtime_logic():
    """`library_app` composes; it does not re-implement. It may import the
    pieces, but it must not define its own store or runner."""
    tree = ast.parse((WEB / "library_app.py").read_text(encoding="utf-8"))
    classes = {n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}
    assert not {"LibraryStore", "LibraryPaths", "JobRunner"} & classes


# ---- no cycles -----------------------------------------------------------------------

@pytest.mark.parametrize("module", [
    "auditor.web.library_contract",
    "auditor.web.library_store",
    "auditor.web.library_runtime",
    "auditor.web.library",
    "auditor.web.library_app",
])
def test_each_module_imports_alone_in_a_fresh_interpreter(module):
    """A cycle usually hides behind an import order that happens to work in
    the test session. Each module is imported FIRST in its own process."""
    out = subprocess.run([sys.executable, "-c", f"import {module}"],
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stderr[-800:]


def test_the_import_graph_is_acyclic():
    graph = {f"auditor.web.{n}": _imports_of(WEB / f"{n}.py")
             for n in ("library_contract", "library_store", "library_runtime",
                       "library")}
    seen: set[str] = set()

    def walk(node: str, stack: tuple[str, ...]) -> None:
        assert node not in stack, f"cycle: {' -> '.join(stack + (node,))}"
        if node in seen:
            return
        seen.add(node)
        for nxt in graph.get(node, ()):
            walk(nxt, stack + (node,))

    for start in graph:
        walk(start, ())


# ---- the patchable names ---------------------------------------------------------------

def test_the_names_tests_replace_are_dereferenced_at_call_time():
    """A re-export is a binding, not an alias. The store and the runtime read
    these through the contract MODULE so that patching the owner is what
    takes effect — and so a test cannot silently patch nothing."""
    src = (WEB / "library_runtime.py").read_text(encoding="utf-8")
    assert "contract.MAX_REPORTS_PER_PROJECT" in src
    assert "contract._now_iso(" in src
    assert (WEB / "library_store.py").read_text(
        encoding="utf-8").count("contract._now_iso(") >= 1
    # kill_process_tree is runtime-owned, so a module-global call is enough
    assert runtime.kill_process_tree.__module__ == "auditor.web.library_runtime"
    assert contract.MAX_REPORTS_PER_PROJECT == store.contract.MAX_REPORTS_PER_PROJECT
