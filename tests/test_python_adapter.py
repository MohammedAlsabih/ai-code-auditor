from pathlib import Path

import pytest

from auditor.adapters.python.adapter import PythonAdapter
from auditor.core.models import DeclaredDep, ImportRef, PackageInfo
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
    for spec in ("==3.13.0rc1", ">=3.13.0rc1,<3.13.0rc3", ">3.13.0rc1,<3.13.0rc3"):
        _mk(tmp_path, "pyproject.toml",
            f'[project]\nname = "x"\nrequires-python = "{spec}"\n')
        allowed = PythonAdapter()._allowed_minors(tmp_path)
        assert allowed == [(3, 13)], spec


def test_declared_namespace_package_matches_dotted_import(tmp_path):
    # google-cloud-storage / azure-storage-blob DECLARED must match the
    # namespace imports (no false H002/H008)
    from auditor.core.hallucination import audit_hallucinations
    _mk(tmp_path, "requirements.txt", "google-cloud-storage\nazure-storage-blob\n")
    _mk(tmp_path, "app.py",
        "import google.cloud.storage\nimport azure.storage.blob\n")
    a = PythonAdapter()
    files = _files(tmp_path, a)
    a.prepare(tmp_path, files)
    declared = a.parse_dependencies(tmp_path)
    for imp in a.extract_imports(files):
        assert a.match_declared(imp, declared) is not None, imp.module
    # end-to-end: no finding at all for the two declared namespace imports

    class Reg:
        ecosystem = "pypi"
        def lookup(self, n):
            return PackageInfo(exists=True, created="2019-01-01T00:00:00Z")
    assert audit_hallucinations(a, tmp_path, files, declared, Reg()) == []


def test_undeclared_namespace_import_is_h007_not_red(tmp_path):
    # an UNDECLARED namespace import must not become a RED H008 or a misleading
    # H002 — it degrades to H007 (unresolved, heuristic)
    from auditor.core.hallucination import audit_hallucinations
    _mk(tmp_path, "requirements.txt", "requests\n")
    _mk(tmp_path, "app.py", "import google.cloud.storage\n")
    a = PythonAdapter()
    files = _files(tmp_path, a)
    a.prepare(tmp_path, files)
    declared = a.parse_dependencies(tmp_path)

    class Reg:  # requests exists (declared, fine); google never looked up ([] cands)
        ecosystem = "pypi"
        def lookup(self, n):
            return PackageInfo(exists=True, created="2019-01-01T00:00:00Z")
    fs = audit_hallucinations(a, tmp_path, files, declared, Reg())
    assert [f.rule_id for f in fs] == ["H007"]     # only the unmappable google import
    assert fs[0].precision == "heuristic"


def test_same_file_read_as_constraint_then_requirement(tmp_path):
    # the same file used once as -c and once as -r: the -r read must still
    # declare (cycle key includes the read role)
    for order in ("-c common.txt\n-r common.txt\n", "-r common.txt\n-c common.txt\n"):
        _mk(tmp_path, "requirements.txt", order)
        _mk(tmp_path, "common.txt", "flask\n")
        names = {d.name for d in PythonAdapter().parse_dependencies(tmp_path)}
        assert names == {"flask"}, order


def test_source_file_keeps_full_relative_path(tmp_path):
    _mk(tmp_path, "requirements.txt", "-r reqs/base.txt\n")
    _mk(tmp_path, "reqs/base.txt", "flask\n")
    dep = next(d for d in PythonAdapter().parse_dependencies(tmp_path) if d.name == "flask")
    assert dep.source_file == "reqs/base.txt"   # not just "base.txt"


def test_source_file_disambiguates_same_named_includes(tmp_path):
    _mk(tmp_path, "requirements.txt", "-r a/base.txt\n-r b/base.txt\n")
    _mk(tmp_path, "a/base.txt", "flask\n")
    _mk(tmp_path, "b/base.txt", "django\n")
    by = {d.name: d.source_file for d in PythonAdapter().parse_dependencies(tmp_path)}
    assert by == {"flask": "a/base.txt", "django": "b/base.txt"}


def test_known_divergent_import_matches_declared_distribution(tmp_path):
    # pkg_resources<-setuptools, OpenGL<-pyopengl, cairo<-pycairo, mpl<-matplotlib
    from auditor.core.hallucination import audit_hallucinations
    _mk(tmp_path, "requirements.txt",
        "setuptools\npyopengl\npycairo\nmatplotlib\npywin32\n")
    _mk(tmp_path, "app.py",
        "import pkg_resources\nimport OpenGL.GL\nimport cairo\n"
        "import mpl_toolkits.mplot3d\nimport win32service\n")
    a = PythonAdapter()
    files = _files(tmp_path, a)
    a.prepare(tmp_path, files)
    declared = a.parse_dependencies(tmp_path)
    for imp in a.extract_imports(files):
        assert a.match_declared(imp, declared) is not None, imp.module

    class Reg:
        ecosystem = "pypi"
        def lookup(self, n): return PackageInfo(exists=True, created="2019-01-01T00:00:00Z")
    assert audit_hallucinations(a, tmp_path, files, declared, Reg()) == []


class _MissingReg:
    ecosystem = "pypi"
    def __init__(self, exists=()):
        self._exists = set(exists)
    def lookup(self, n):
        return PackageInfo(exists=True, created="2019-01-01T00:00:00Z") \
            if n in self._exists else PackageInfo(exists=False)


def _audit(tmp_path, reg):
    from auditor.core.hallucination import audit_hallucinations
    a = PythonAdapter()
    files = _files(tmp_path, a)
    a.prepare(tmp_path, files)
    declared = a.parse_dependencies(tmp_path)
    return audit_hallucinations(a, tmp_path, files, declared, reg)


def test_unmapped_multisegment_import_is_h007_not_red_h008(tmp_path):
    # NO declared deps at all => nothing could provide the imports:
    # multi-segment unmapped => H007; single-segment hallucination => H008 red
    # stamped precision=heuristic (identity mapping is a convention, not a fact)
    _mk(tmp_path, "app.py", "import totallymadeup.submodule\nimport superhallucinated\n")
    fs = _audit(tmp_path, _MissingReg())
    assert sorted(f.rule_id for f in fs) == ["H007", "H008"]
    h008 = next(f for f in fs if f.rule_id == "H008")
    assert h008.precision == "heuristic"


def test_trust_gate_unmatched_declared_downgrades_h008_to_h007(tmp_path):
    # an UNMATCHED declared distribution may provide the module (the
    # rest_framework<-djangorestframework shape) => no definitive RED
    _mk(tmp_path, "requirements.txt", "some-unmatched-dist\n")
    _mk(tmp_path, "app.py", "import mystery_module\n")
    fs = _audit(tmp_path, _MissingReg(exists={"some-unmatched-dist"}))
    ids = [f.rule_id for f in fs]
    assert "H008" not in ids and "H007" in ids
    h007 = next(f for f in fs if f.rule_id == "H007")
    assert "some-unmatched-dist" in h007.detail      # names the possible provider


def test_import_dist_corpus_no_false_positives(tmp_path):
    # CORPUS (CP-3): famous import!=dist divergences + namespace packages must
    # produce ZERO findings when the real distribution is declared
    _mk(tmp_path, "requirements.txt",
        "biopython\ndnspython\ngrpcio\ndjangorestframework\n"
        "google-cloud-storage\nazure-storage-blob\npyyaml\npillow\nkafka-python\n")
    _mk(tmp_path, "app.py",
        "import Bio\nimport dns\nimport grpc\nimport rest_framework\n"
        "import google.cloud.storage\nimport azure.storage.blob\n"
        "import yaml\nimport PIL\nimport kafka\n")
    fs = _audit(tmp_path, _MissingReg(exists={
        "biopython", "dnspython", "grpcio", "djangorestframework",
        "google-cloud-storage", "azure-storage-blob", "pyyaml", "pillow",
        "kafka-python"}))
    assert fs == []


def test_import_mapping_trust_levels():
    a = PythonAdapter()
    exact = [ImportRef("yaml", "f", 1, top_level="yaml"),          # curated alias
             ImportRef("Bio", "f", 1, top_level="Bio"),
             ImportRef("win32file", "f", 1, top_level="win32file")]
    for imp in exact:
        assert a.import_mapping_trust(imp) == "exact", imp.module
    conventional = [ImportRef("requests", "f", 1, top_level="requests"),
                    ImportRef("mystery", "f", 1, top_level="mystery")]
    for imp in conventional:
        assert a.import_mapping_trust(imp) == "heuristic", imp.module


def test_missing_and_outside_includes_produce_diagnostics(tmp_path):
    from auditor.core.models import Diagnostics
    root = tmp_path / "repo"
    root.mkdir()
    (tmp_path / "outside.txt").write_text("evil\n", encoding="utf-8")
    _mk(root, "requirements.txt",
        "-r missing.txt\n--constraint=also-missing.txt\n-r ../outside.txt\nrequests\n")
    diag = Diagnostics()
    names = {d.name for d in PythonAdapter().parse_dependencies(root, diag=diag)}
    assert names == {"requests"}
    joined = " ".join(diag.notes)
    assert "missing.txt" in joined and "not found" in joined
    assert "outside the repository" in joined
    # CP-8.1/8.2: a missing/outside include is an incompletely-read manifest —
    # it is recorded, folds into manifest_incomplete, and forbids PASS
    assert diag.include_gaps and "requirements.txt" in diag.manifest_incomplete
    from auditor.core.scoring import verdict
    assert verdict({"red": 0, "yellow": 0}, 100,
                   {"include_gaps": diag.include_gaps}) == "review"


def test_bad_list_element_is_noted(tmp_path):
    from auditor.core.models import Diagnostics
    _mk(tmp_path, "pyproject.toml", '[project]\ndependencies = ["requests", 123]\n')
    diag = Diagnostics()
    names = {d.name for d in PythonAdapter().parse_dependencies(tmp_path, diag=diag)}
    assert names == {"requests"}
    assert any("non-string" in n for n in diag.notes)


def test_uv_sources_local_path_skips_registry(tmp_path):
    _mk(tmp_path, "pyproject.toml",
        '[project]\ndependencies = ["internal-lib", "requests"]\n'
        '[tool.uv.sources]\n'
        'internal-lib = { path = "../internal-lib" }\n')
    by = {d.name: d.skip_registry for d in PythonAdapter().parse_dependencies(tmp_path)}
    assert by["internal-lib"] is True     # local uv source => not PyPI-checked
    assert by["requests"] is False


def test_uv_sources_workspace_and_git_skip_registry(tmp_path):
    _mk(tmp_path, "pyproject.toml",
        '[project]\ndependencies = ["ws-lib", "git-lib"]\n'
        '[tool.uv.sources]\n'
        'ws-lib = { workspace = true }\n'
        'git-lib = { git = "https://x/y.git" }\n')
    by = {d.name: d.skip_registry for d in PythonAdapter().parse_dependencies(tmp_path)}
    assert by["ws-lib"] is True and by["git-lib"] is True


def test_setup_py_comment_and_string_are_not_dependencies(tmp_path):
    _mk(tmp_path, "setup.py",
        'from setuptools import setup\n'
        '# install_requires = ["not-a-real-dependency"]\n'
        'DOCS = \'install_requires = ["fake-from-string"]\'\n'
        'setup(name="x", install_requires=["real-dep>=1.0"])\n')
    names = {d.name for d in PythonAdapter().parse_dependencies(tmp_path)}
    assert names == {"real-dep"}          # AST sees only the real setup(...) kwarg


def test_setup_py_dynamic_install_requires_is_recorded_limitation(tmp_path):
    from auditor.core.models import Diagnostics
    _mk(tmp_path, "setup.py",
        'from setuptools import setup\n'
        'setup(name="x", install_requires=get_reqs())\n')
    diag = Diagnostics()
    deps = PythonAdapter().parse_dependencies(tmp_path, diag=diag)
    assert deps == []
    assert any("dynamic" in n and "install_requires" in n for n in diag.notes)
    assert "setup.py" in diag.manifest_incomplete
    # CP-8.1: the single numeric confidence source reflects the incompleteness
    from auditor.core.scoring import analysis_confidence, verdict
    assert analysis_confidence(diag, offline=False, files_read=1) < 100
    assert verdict({"red": 0, "yellow": 0}, 100,
                   {"manifest_incomplete": diag.manifest_incomplete}) == "review"


def test_setup_py_extras_and_line_numbers(tmp_path):
    _mk(tmp_path, "setup.py",
        'from setuptools import setup\n'
        'setup(\n'
        '    name="x",\n'
        '    install_requires=[\n'
        '        "dep-one",\n'
        '        "dep-two>=2",\n'
        '    ],\n'
        '    extras_require={"dev": ["dep-three"]},\n'
        ')\n')
    deps = {d.name: d.line for d in PythonAdapter().parse_dependencies(tmp_path)}
    assert deps == {"dep-one": 5, "dep-two": 6, "dep-three": 8}


def test_local_module_file_does_not_claim_subtree(tmp_path):
    _mk(tmp_path, "foo.py", "X = 1\n")
    _mk(tmp_path, "pkg/__init__.py", "")
    _mk(tmp_path, "pkg/real.py", "Y = 1\n")
    _mk(tmp_path, "ns/actual.py", "Z = 1\n")     # namespace dir (no __init__)
    _mk(tmp_path, "app.py", "import foo\n")
    a = PythonAdapter()
    files = _files(tmp_path, a)
    a.prepare(tmp_path, files)

    def internal(module):
        return a.is_internal(ImportRef(module, "app.py", 1,
                                       top_level=module.split(".")[0]))
    assert internal("foo") is True               # the module file itself
    assert internal("foo.nonexistent") is False  # foo.py is NOT a package
    assert internal("pkg.anything") is True      # regular package: subtree claim
    assert internal("ns") is True                # namespace dir itself
    assert internal("ns.actual") is True         # existing child
    assert internal("ns.ghost") is False         # nonexistent child not claimed


def test_silent_schema_cases_now_produce_diagnostics(tmp_path):
    from auditor.core.models import Diagnostics
    cases = {
        'project = "oops"\n': "project",
        'tool = "oops"\n': "tool",
        '[tool.poetry.group.dev]\ndependencies = ["a"]\n': "tool.poetry.group.dev",
        '[tool.uv]\nsources = "oops"\n[project]\ndependencies = ["x"]\n': "tool.uv.sources",
    }
    for body, expect in cases.items():
        root = tmp_path / expect.replace(".", "_")
        root.mkdir()
        _mk(root, "pyproject.toml", body)
        diag = Diagnostics()
        PythonAdapter().parse_dependencies(root, diag=diag)
        assert any(expect in n for n in diag.notes), (expect, diag.notes)
        assert "pyproject.toml" in diag.manifest_incomplete, expect
        from auditor.core.scoring import verdict
        assert verdict({"red": 0, "yellow": 0}, 100,
                       {"manifest_incomplete": diag.manifest_incomplete}) == "review", expect


def test_oversized_pyproject_double_read_dedups_ledger(tmp_path):
    from auditor.core.models import Diagnostics
    big = '[project]\ndependencies = ["x"]\n' + "#" + "x" * 2_100_000 + "\n"
    _mk(tmp_path, "pyproject.toml", big)
    a = PythonAdapter()
    diag = Diagnostics()
    a.parse_dependencies(tmp_path, diag=diag)
    a.private_registry_reason(tmp_path)          # second read of the same file
    oversize = [e for e in diag.manifest_errors if "exceeds" in e]
    assert len(oversize) == 1                    # deduped by entry
    assert len(diag.manifest_files) == 1
    from auditor.core.scoring import analysis_confidence
    assert analysis_confidence(diag, offline=False, files_read=1) < 100


def test_uv_conditional_source_list_is_local(tmp_path):
    _mk(tmp_path, "pyproject.toml",
        '[project]\ndependencies = ["dep-a", "dep-b", "dep-c"]\n'
        '[tool.uv.sources]\n'
        'dep-a = [{ path = "../local", marker = "sys_platform == \'win32\'" },'
        ' { index = "corp" }]\n'
        'dep-b = { workspace = true }\n'
        'dep-c = [{ index = "corp" }]\n')
    by = {d.name: d.skip_registry for d in PythonAdapter().parse_dependencies(tmp_path)}
    # conservative: ANY local alternative (even marker-gated, mixed with an
    # index entry) => skip the public-registry H001 claim
    assert by == {"dep-a": True, "dep-b": True, "dep-c": False}


def test_requires_python_dash_prerelease_form(tmp_path):
    # PEP 440: 3.13.0-rc1 IS 3.13.0rc1 — bounds come from SpecifierSet objects
    _mk(tmp_path, "pyproject.toml",
        '[project]\nrequires-python = ">3.13.0-rc1,<3.13.0-rc3"\n')
    assert PythonAdapter()._allowed_minors(tmp_path) == [(3, 13)]


def test_requires_python_wildcard_form(tmp_path):
    _mk(tmp_path, "pyproject.toml", '[project]\nrequires-python = "==3.12.*"\n')
    assert PythonAdapter()._allowed_minors(tmp_path) == [(3, 12)]


def test_symlinked_manifest_outside_scan_root_is_refused(tmp_path):
    import os
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("leaked-dep-name==1.0\n", encoding="utf-8")
    root = tmp_path / "scanroot"
    root.mkdir()
    try:
        os.symlink(outside / "secret.txt", root / "requirements.txt")
    except OSError:
        pytest.skip("symlink creation not permitted in this environment")
    from auditor.core.models import Diagnostics
    diag = Diagnostics()
    deps = PythonAdapter().parse_dependencies(root, diag=diag)
    assert all(d.name != "leaked-dep-name" for d in deps)
    assert any("outside the scan root" in e for e in diag.manifest_errors)


def test_partial_parse_recorded_in_diagnostics(tmp_path):
    from auditor.core.hallucination import audit_hallucinations
    from auditor.core.models import Diagnostics
    _mk(tmp_path, "requirements.txt", "requests\n")
    _mk(tmp_path, "broken.py", "def f(:\n    pass\n")   # syntax error
    a = PythonAdapter()
    files = _files(tmp_path, a)
    a.prepare(tmp_path, files)
    declared = a.parse_dependencies(tmp_path)

    class Reg:
        ecosystem = "pypi"
        def lookup(self, n): return PackageInfo(exists=True, created="2019-01-01T00:00:00Z")
    diag = Diagnostics()
    audit_hallucinations(a, tmp_path, files, declared, Reg(), diag=diag)
    assert "broken.py" in diag.parse_error_files


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
