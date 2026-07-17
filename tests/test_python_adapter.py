from pathlib import Path

from auditor.adapters.python.adapter import PythonAdapter
from auditor.core.models import DeclaredDep, ImportRef
from auditor.core.treesitter import parse_source
from auditor.core.walk import collect_source_files


def _mk(tmp_path: Path, rel: str, content: str) -> None:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _files(tmp_path, adapter):
    files = collect_source_files(tmp_path, adapter)
    for f in files:
        parse_source(f)
    return files


# ---------- T6: detection + dependency parsing ----------

def test_detect(tmp_path):
    a = PythonAdapter()
    assert not a.detect(tmp_path)
    _mk(tmp_path, "requirements.txt", "requests\n")
    assert a.detect(tmp_path)


def test_parse_requirements_variants(tmp_path):
    _mk(tmp_path, "requirements.txt", "\n".join([
        "requests==2.32.3",
        "PyYAML>=6.0 ; python_version >= '3.8'",
        "uvicorn[standard]~=0.30",
        "# comment",
        "-r other.txt",
        "-e .",
        "ghost-pkg @ https://example.com/g.whl",
        "",
    ]))
    deps = PythonAdapter().parse_dependencies(tmp_path)
    by_name = {d.name: d for d in deps}
    assert set(by_name) == {"requests", "pyyaml", "uvicorn", "ghost-pkg"}
    assert by_name["requests"].line == 1
    assert by_name["ghost-pkg"].skip_registry is True  # direct URL, not a registry name


def test_parse_pyproject_project_and_poetry(tmp_path):
    _mk(tmp_path, "pyproject.toml", "\n".join([
        "[project]",
        'name = "x"',
        'dependencies = ["httpx>=0.27", "rich"]',
        "[project.optional-dependencies]",
        'dev = ["pytest>=8"]',
        "[tool.poetry.dependencies]",
        'python = "^3.11"',
        'flask = "^3.0"',
    ]))
    names = {d.name for d in PythonAdapter().parse_dependencies(tmp_path)}
    assert names == {"httpx", "rich", "pytest", "flask"}  # "python" excluded


def test_parse_pipfile(tmp_path):
    _mk(tmp_path, "Pipfile", "\n".join([
        "[packages]",
        'requests = "*"',
        "[dev-packages]",
        'pytest = "*"',
    ]))
    names = {d.name for d in PythonAdapter().parse_dependencies(tmp_path)}
    assert names == {"requests", "pytest"}


def test_parse_setup_py_regex_fallback(tmp_path):
    _mk(tmp_path, "setup.py",
        "from setuptools import setup\n"
        "setup(name='x', install_requires=['numpy>=1.26', \"pandas\"])\n")
    names = {d.name for d in PythonAdapter().parse_dependencies(tmp_path)}
    assert names == {"numpy", "pandas"}


# ---------- verification-pass regressions (dep parsing false positives) ----------

def test_requirements_follows_r_includes(tmp_path):
    # -r includes ARE followed and declare; -c constraints are read but do NOT
    # declare (asserted separately in test_constraints_c_include_does_not_declare)
    _mk(tmp_path, "requirements.txt", "-r deps/base.txt\n-c deps/constraints.txt\n")
    _mk(tmp_path, "deps/base.txt", "flask==3.0\n")
    _mk(tmp_path, "deps/constraints.txt", "urllib3<2\n")
    names = {d.name for d in PythonAdapter().parse_dependencies(tmp_path)}
    assert names == {"flask"}


def test_requirements_include_outside_root_is_ignored(tmp_path):
    root = tmp_path / "repo"
    (root / "sub").mkdir(parents=True)
    (tmp_path / "outside.txt").write_text("evil-pkg\n", encoding="utf-8")
    _mk(root, "requirements.txt", "-r ../outside.txt\nrequests\n")
    names = {d.name for d in PythonAdapter().parse_dependencies(root)}
    assert names == {"requests"}   # the escaping include was not followed


def test_requirements_vcs_url_line_not_mislabeled_as_git(tmp_path):
    _mk(tmp_path, "requirements.txt",
        "git+https://github.com/org/foo.git#egg=foo\n"
        "https://example.com/x-1.0.whl\n")
    deps = PythonAdapter().parse_dependencies(tmp_path)
    by = {d.name: d for d in deps}
    assert "git" not in by                          # scheme not captured as a name
    assert by["foo"].skip_registry is True          # VCS ref => not PyPI-checked
    # the bare wheel URL without #egg contributes no bogus dep
    assert set(by) == {"foo"}


def test_editable_vcs_egg_recorded_skip_registry(tmp_path):
    _mk(tmp_path, "requirements.txt", "-e git+https://x/y.git#egg=mylib\n-e .\n")
    deps = PythonAdapter().parse_dependencies(tmp_path)
    by = {d.name: d for d in deps}
    assert set(by) == {"mylib"} and by["mylib"].skip_registry is True


def test_poetry_table_local_deps_skip_registry(tmp_path):
    _mk(tmp_path, "pyproject.toml", "\n".join([
        "[tool.poetry.dependencies]",
        'python = "^3.11"',
        'localpkg = {path = "../localpkg"}',
        'fromgit = {git = "https://x/y.git"}',
        'normal = "^1.0"',
    ]))
    by = {d.name: d for d in PythonAdapter().parse_dependencies(tmp_path)}
    assert by["localpkg"].skip_registry is True
    assert by["fromgit"].skip_registry is True
    assert by["normal"].skip_registry is False


def test_poetry_group_dependencies_parsed(tmp_path):
    _mk(tmp_path, "pyproject.toml", "\n".join([
        "[tool.poetry.dependencies]",
        'python = "^3.11"',
        "[tool.poetry.group.dev.dependencies]",
        'pytest = "^8"',
    ]))
    names = {d.name for d in PythonAdapter().parse_dependencies(tmp_path)}
    assert "pytest" in names


def test_pep735_dependency_groups_parsed(tmp_path):
    _mk(tmp_path, "pyproject.toml", "\n".join([
        "[project]", 'name = "x"', 'dependencies = ["requests"]',
        "[dependency-groups]",
        'test = ["pytest>=8", {include-group = "lint"}]',
        'lint = ["ruff"]',
    ]))
    names = {d.name for d in PythonAdapter().parse_dependencies(tmp_path)}
    assert {"requests", "pytest", "ruff"} <= names


def test_constraints_c_include_does_not_declare(tmp_path):
    # `-c` pins versions; it must NOT create a DeclaredDep (pip semantics)
    _mk(tmp_path, "requirements.txt", "-r base.txt\n-c constraints.txt\n")
    _mk(tmp_path, "base.txt", "flask\n")
    _mk(tmp_path, "constraints.txt", "claimed-ai-name==1\n")
    names = {d.name for d in PythonAdapter().parse_dependencies(tmp_path)}
    assert names == {"flask"}                 # claimed-ai-name is a constraint, not declared


def test_private_registry_detected_in_included_requirements(tmp_path):
    _mk(tmp_path, "requirements.txt", "-r reqs/private.txt\n")
    _mk(tmp_path, "reqs/private.txt",
        "--index-url https://packages.example/simple\ncorp-lib\n")
    a = PythonAdapter()
    a.parse_dependencies(tmp_path)
    assert a.private_registry_reason(tmp_path) is not None


def test_rfile_attached_form_no_space(tmp_path):
    _mk(tmp_path, "requirements.txt", "-rmore.txt\n")
    _mk(tmp_path, "more.txt", "flask\n")
    names = {d.name for d in PythonAdapter().parse_dependencies(tmp_path)}
    assert names == {"flask"}


def test_pyproject_wrong_schema_does_not_crash_or_explode(tmp_path):
    from auditor.core.models import Diagnostics
    # optional-dependencies as a LIST (not a table) previously crashed
    _mk(tmp_path, "pyproject.toml",
        '[project]\noptional-dependencies = ["requests"]\n')
    diag = Diagnostics()
    deps = PythonAdapter().parse_dependencies(tmp_path, diag=diag)
    assert deps == [] and any("optional-dependencies" in n for n in diag.notes)


def test_pyproject_dependencies_string_is_not_char_exploded(tmp_path):
    from auditor.core.models import Diagnostics
    _mk(tmp_path, "pyproject.toml", '[project]\ndependencies = "requests"\n')
    diag = Diagnostics()
    deps = PythonAdapter().parse_dependencies(tmp_path, diag=diag)
    assert deps == []                          # NOT ['r','e','q',...]
    assert any("project.dependencies" in n for n in diag.notes)


def test_partial_namespace_does_not_make_sibling_internal(tmp_path):
    # a local google.myapp namespace part must NOT make google.cloud.storage internal
    _mk(tmp_path, "requirements.txt", "google-cloud-storage\n")
    _mk(tmp_path, "google/myapp/mod.py", "x=1")   # no __init__ anywhere
    _mk(tmp_path, "app.py", "import google.cloud.storage\nfrom google.myapp import mod\n")
    a = PythonAdapter()
    files = _files(tmp_path, a)
    a.prepare(tmp_path, files)
    by = {i.module: i for i in a.extract_imports(files)}
    assert a.is_internal(by["google.myapp"])           # the local part IS internal
    assert not a.is_internal(by["google.cloud.storage"])  # the external sibling is NOT


def test_allowed_minors_handles_prerelease_specs(tmp_path):
    for spec in ("==3.13.0rc1", ">=3.13.0rc1,<3.13.0rc3"):
        _mk(tmp_path, "pyproject.toml",
            f'[project]\nname = "x"\nrequires-python = "{spec}"\n')
        allowed = PythonAdapter()._allowed_minors(tmp_path)
        assert allowed == [(3, 13)], spec


# ---------- T7: imports, stdlib, locality, mapping ----------

def test_extract_imports_and_locality(tmp_path):
    _mk(tmp_path, "requirements.txt", "requests\n")
    _mk(tmp_path, "app.py", "\n".join([
        "import os, sys",
        "import requests",
        "import yaml",
        "from . import sibling",
        "from helpers import util",
        "import helpers.util",
        "from pathlib import Path",
    ]) + "\n")
    _mk(tmp_path, "helpers/__init__.py", "")
    _mk(tmp_path, "helpers/util.py", "")
    a = PythonAdapter()
    files = _files(tmp_path, a)
    a.prepare(tmp_path, files)
    imps = a.extract_imports(files)
    tops = {i.top_level for i in imps}
    assert {"os", "sys", "requests", "yaml", "helpers", "pathlib"} <= tops
    assert all("sibling" not in i.module for i in imps)  # relative import skipped
    by_top = {i.top_level: i for i in imps}
    assert by_top["requests"].line == 2
    assert a.is_internal(by_top["os"]) and a.is_internal(by_top["pathlib"])
    assert a.is_internal(by_top["helpers"])
    assert not a.is_internal(by_top["yaml"])


def test_match_declared_uses_alias_map():
    a = PythonAdapter()
    declared = [DeclaredDep(name="pyyaml", ecosystem="pypi", source_file="r.txt"),
                DeclaredDep(name="opencv-python", ecosystem="pypi", source_file="r.txt")]
    assert a.match_declared(ImportRef("yaml", "f.py", 1, top_level="yaml"), declared).name == "pyyaml"
    assert a.match_declared(ImportRef("cv2", "f.py", 1, top_level="cv2"), declared).name == "opencv-python"
    assert a.match_declared(ImportRef("numpy", "f.py", 1, top_level="numpy"), declared) is None


def test_registry_candidates_alias_then_canonical():
    a = PythonAdapter()
    assert a.registry_candidates(ImportRef("yaml", "f.py", 1, top_level="yaml")) == ["pyyaml"]
    assert a.registry_candidates(ImportRef("some_pkg", "f.py", 1, top_level="some_pkg")) == ["some-pkg"]


# ---------- T7: P008 requires-python / stdlib drift ----------

def _p008_repo(tmp_path, requires, code, extra_toml=""):
    _mk(tmp_path, "pyproject.toml",
        f'[project]\nname = "x"\nrequires-python = "{requires}"\n'
        f'dependencies = [{extra_toml}]\n')
    _mk(tmp_path, "m.py", code)
    a = PythonAdapter()
    files = _files(tmp_path, a)
    a.prepare(tmp_path, files)
    return a.project_rules(tmp_path, [])


def test_p008_range_crossing_removal_counterexample(tmp_path):
    fs = _p008_repo(tmp_path, ">=3.11", "import distutils\n")
    assert len(fs) == 1 and "CROSSES" in fs[0].detail


def test_p008_range_ends_before_removal_is_clean(tmp_path):
    assert _p008_repo(tmp_path, ">=3.8,<3.12", "import distutils\n") == []


def test_p008_entire_range_after_removal(tmp_path):
    fs = _p008_repo(tmp_path, ">=3.13", "import telnetlib\n")
    assert len(fs) == 1 and "at or above the removal" in fs[0].detail


def test_p008_added_module_below_floor_needs_backport(tmp_path):
    fs = _p008_repo(tmp_path, ">=3.8", "import tomllib\n")
    assert len(fs) == 1 and "tomli" in fs[0].detail


def test_p008_declared_backport_silences(tmp_path):
    assert _p008_repo(tmp_path, ">=3.8", "import tomllib\n", extra_toml='"tomli"') == []


def test_p008_pep440_semantics_not_hand_regex(tmp_path):
    fs = _p008_repo(tmp_path, "~=3.11", "import distutils\n")
    assert len(fs) == 1 and "CROSSES" in fs[0].detail      # ~=3.11 reaches 3.12+
    assert _p008_repo(tmp_path, "==3.11.*", "import distutils\n") == []  # only 3.11
    fs = _p008_repo(tmp_path, "<3.12.1", "import distutils\n")
    assert len(fs) == 1                                     # 3.12.0 IS allowed
    fs = _p008_repo(tmp_path, ">=3.11,!=3.12.*", "import distutils\n")
    assert len(fs) == 1 and "CROSSES" in fs[0].detail       # 3.13+ still lacks it


def test_p008_patch_level_specifiers_reach_the_minor(tmp_path):
    # GATE 2: minor-only containment returned [] for these; patch-boundary
    # candidates must classify 3.12 reachable => P008 for distutils
    for spec in ("==3.12.1", "~=3.12.1", ">=3.12.1,<3.13", "==3.12.26", ">3.12.25,<3.13"):
        fs = _p008_repo(tmp_path, spec, "import distutils\n")
        assert len(fs) == 1, spec


def test_p008_unknown_range_makes_no_claim(tmp_path):
    _mk(tmp_path, "requirements.txt", "requests\n")
    _mk(tmp_path, "m.py", "import distutils\n")
    a = PythonAdapter()
    files = _files(tmp_path, a)
    a.prepare(tmp_path, files)
    assert a.project_rules(tmp_path, []) == []


def test_p008_local_module_shadowing_stdlib_name_is_not_flagged(tmp_path):
    # a repo-local package named `tomllib` means `import tomllib` is local, not
    # the backport-needing stdlib module => no P008
    _mk(tmp_path, "pyproject.toml",
        '[project]\nname = "x"\nrequires-python = ">=3.8"\n')
    _mk(tmp_path, "tomllib/__init__.py", "")
    _mk(tmp_path, "m.py", "import tomllib\n")
    a = PythonAdapter()
    files = _files(tmp_path, a)
    a.prepare(tmp_path, files)
    assert a.project_rules(tmp_path, []) == []


def test_p008_non_string_requires_python_does_not_crash(tmp_path):
    _mk(tmp_path, "pyproject.toml",
        '[project]\nname = "x"\nrequires-python = ["oops-a-list"]\n')
    _mk(tmp_path, "m.py", "import distutils\n")
    a = PythonAdapter()
    files = _files(tmp_path, a)
    a.prepare(tmp_path, files)
    assert a.project_rules(tmp_path, []) == []   # returns [], no AttributeError


def test_namespace_package_import_is_internal(tmp_path):
    # PEP 420 namespace package (no __init__.py) is the project's own code
    _mk(tmp_path, "requirements.txt", "requests\n")
    _mk(tmp_path, "mypkg/sub/mod.py", "VALUE = 1")   # no __init__.py anywhere
    _mk(tmp_path, "app.py", "from mypkg.sub import mod\nimport requests\n")
    a = PythonAdapter()
    files = _files(tmp_path, a)
    a.prepare(tmp_path, files)
    imps = {i.top_level: i for i in a.extract_imports(files)}
    assert a.is_internal(imps["mypkg"])
    assert not a.is_internal(imps["requests"])


def test_extract_imports_registers_grammar_without_prepare():
    # contract: extract_imports must be safe standalone (no prior prepare)
    from auditor.core import treesitter as ts
    from auditor.core.models import SourceFile
    ts.reset_registry()
    try:
        sf = SourceFile(path=Path("a.py"), rel="a.py", language="python",
                        text=b"import requests\n")
        imps = PythonAdapter().extract_imports([sf])
        assert any(i.top_level == "requests" for i in imps)
    finally:
        # restore the conftest registrations for the rest of the session
        import tree_sitter_c_sharp, tree_sitter_java, tree_sitter_python, tree_sitter_typescript
        ts.register_language("python", tree_sitter_python.language())
        ts.register_language("java", tree_sitter_java.language())
        ts.register_language("csharp", tree_sitter_c_sharp.language())
        ts.register_language("typescript", tree_sitter_typescript.language_typescript())
        ts.register_language("tsx", tree_sitter_typescript.language_tsx())
