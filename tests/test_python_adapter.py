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
