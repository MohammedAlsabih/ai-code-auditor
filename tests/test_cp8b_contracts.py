"""CP-8b second-round product-contract regressions — one case per counter-case."""
import json
from pathlib import Path

from auditor.core.models import Diagnostics, ImportRef, PackageInfo
from auditor.core.treesitter import parse_source
from auditor.core.walk import collect_source_files


def _mk(root: Path, rel: str, content: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


# ── Point 1: scrubber coverage ───────────────────────────────────────────────
def test_p1_scrubber_covers_common_secret_formats():
    from auditor.fetch import _redact
    cases = {
        "Authorization: Bearer TOPSECRETVALUE": "TOPSECRETVALUE",
        "Authorization: Basic dXNlcjpwYXNz": "dXNlcjpwYXNz",
        '{"token":"JSONSECRET"}': "JSONSECRET",
        "password: 'YAMLSECRET'": "YAMLSECRET",
        'api_key = "TOMLSECRET"': "TOMLSECRET",
        "//registry.npmjs.org/:_authToken=NPMSECRET": "NPMSECRET",
        "X-Api-Key: HEADERSECRET": "HEADERSECRET",
        "https://alice:URLPASS@host/x": "URLPASS",
        "https://ONLYTOKEN@host/x": "ONLYTOKEN",
        "?api_key=QUERYSECRET&x=1": "QUERYSECRET",
        # CP-8b round 3: OAuth token keys, npm _password, known token shapes
        "?access_token=OAUTHSECRET&x=1": "OAUTHSECRET",
        "refresh_token=REFRESHSECRET": "REFRESHSECRET",
        "//registry/:_password=NPMBASE64": "NPMBASE64",
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA": "ghp_AAAA",
        "the key is AKIAIOSFODNN7EXAMPLE here": "AKIAIOSFODNN7EXAMPLE",
    }
    for text, secret in cases.items():
        red = _redact(text)
        assert secret not in red, text
        assert _redact(red) == red, f"not idempotent: {text}"   # idempotent


def test_p1_scrubber_leaves_benign_text_intact():
    from auditor.fetch import _redact
    for benign in ("author=alice&tokenize=no", "the tokenizer settings",
                   '{"token_count": 3}', "use client"):
        assert _redact(benign) == benign


def test_p1_scrubber_formats_never_reach_report_json():
    from auditor.core.models import Finding, Severity
    from auditor.report.build import build_report
    data = build_report(
        target="Authorization: Bearer TOPSECRETVALUE",
        projects=[{"language": "python", "root": ".", "frameworks": [], "file_count": 1,
                   "findings": [Finding("H001", Severity.RED, "t", "r.txt", 1,
                                        detail='{"token":"JSONSECRET"}')]}],
        engines={"npmrc": "//registry.npmjs.org/:_authToken=NPMSECRET"},
        limitations=["X-Api-Key: HEADERSECRET"], diagnostics={})
    blob = json.dumps(data)
    for s in ("TOPSECRETVALUE", "JSONSECRET", "NPMSECRET", "HEADERSECRET"):
        assert s not in blob, s


# ── Point 2: setup.py name binding ───────────────────────────────────────────
def test_p2_setup_binding_all_shapes(tmp_path):
    from auditor.adapters.python.adapter import PythonAdapter
    cases = {
        # (src, expected declared, expected incomplete)
        "local_def": ("import setuptools\ndef setup(**k):\n    pass\n"
                      "setup(install_requires=['fake-local'])\n", set(), True),
        "object_method": ("import setuptools\nclass H:\n    def setup(self, **k):\n        pass\n"
                          "H().setup(install_requires=['fake-object'])\n", set(), True),
        "alias_from": ("from setuptools import setup as configure\n"
                       "configure(install_requires=['requests'])\n", {"requests"}, False),
        "module_alias": ("import setuptools as st\nst.setup(install_requires=['flask'])\n",
                         {"flask"}, False),
        "distutils_alias": ("import distutils.core as dc\ndc.setup(install_requires=['click'])\n",
                            {"click"}, False),
        "rebound": ("from setuptools import setup\nsetup = None\n", set(), True),
    }
    for name, (src, want, want_inc) in cases.items():
        root = tmp_path / name
        _mk(root, "setup.py", src)
        diag = Diagnostics()
        got = {d.name for d in PythonAdapter().parse_dependencies(root, diag=diag)}
        assert got == want, name
        assert bool(diag.manifest_incomplete) == want_inc, name


# ── Point 3: provider policy (H008 red with unverified note, not suppression) ──
def test_p3_single_declared_dep_does_not_suppress_hallucination(tmp_path):
    from auditor.adapters.python.adapter import PythonAdapter
    from auditor.core.hallucination import audit_hallucinations
    _mk(tmp_path, "requirements.txt", "requests\n")
    _mk(tmp_path, "app.py", "import superhallucinated\n")
    a = PythonAdapter()
    files = collect_source_files(tmp_path, a)
    for f in files:
        parse_source(f)
    declared = a.parse_dependencies(tmp_path)
    a.prepare(tmp_path, files)

    class Reg:
        ecosystem = "pypi"
        def lookup(self, n):
            return PackageInfo(exists=True, created="2019-01-01T00:00:00Z") if n == "requests" \
                else PackageInfo(exists=False)
    fs = audit_hallucinations(a, tmp_path, files, declared, Reg())
    from auditor.core.scoring import verdict
    h = next(f for f in fs if f.rule_id == "H007")
    # requests does NOT silence it — it SURFACES as a yellow probable...
    assert h.severity.value == "yellow"
    assert "PROBABLE" in h.detail and "requests" in h.detail
    # ...for REVIEW, not a definitive block on an unproven mapping (CP-8b r3)
    counts = {"red": 0, "yellow": sum(1 for f in fs if f.severity.value == "yellow"),
              "blue": 0}
    assert verdict(counts, 100, {}) == "review"


# ── Point 4: .NET TFM old/modern/unknown ─────────────────────────────────────
def _dotnet_prepare(root):
    from auditor.adapters.dotnet.adapter import DotnetAdapter
    a = DotnetAdapter()
    a.set_repo_root(root)
    files = collect_source_files(root, a)
    for f in files:
        parse_source(f)
    diag = Diagnostics()
    a.parse_dependencies(root, diag=diag)
    a.prepare(root, files)
    return a, diag


def test_p4_missing_tfm_is_unknown_not_modern(tmp_path):
    _mk(tmp_path, "App.csproj", '<Project Sdk="Microsoft.NET.Sdk"></Project>')
    _mk(tmp_path, "P.cs", "using System.Text.Json;\nnamespace X {}")
    a, diag = _dotnet_prepare(tmp_path)
    assert a._tfm_class == "unknown"
    # unknown => System.Text.Json treated conservatively as package-delivered
    assert not a.is_internal(ImportRef("System.Text.Json", "P.cs", 1, top_level="System.Text.Json"))
    # unknown is surfaced, not silent
    assert diag.manifest_incomplete and any("TargetFramework" in n for n in diag.notes)


def test_p4_ancestor_directory_build_props(tmp_path):
    repo = tmp_path / "repo"
    _mk(repo, "Directory.Build.props",
        "<Project><PropertyGroup><TargetFramework>net48</TargetFramework>"
        "</PropertyGroup></Project>")
    _mk(repo, "src/app/App.csproj", '<Project Sdk="Microsoft.NET.Sdk"></Project>')
    _mk(repo, "src/app/P.cs", "using System.Text.Json;\nnamespace X {}")
    from auditor.adapters.dotnet.adapter import DotnetAdapter
    a = DotnetAdapter()
    a.set_repo_root(repo)
    files = collect_source_files(repo / "src" / "app", a)
    for f in files:
        parse_source(f)
    a.parse_dependencies(repo / "src" / "app")
    a.prepare(repo / "src" / "app", files)
    assert a._tfm_class == "old"                  # ancestor props resolves the TFM
    assert not a.is_internal(ImportRef("System.Text.Json", "P.cs", 1, top_level="System.Text.Json"))


def test_p4_dynamic_tfm_is_unknown(tmp_path):
    _mk(tmp_path, "App.csproj",
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
        "<TargetFramework>$(SharedTfm)</TargetFramework></PropertyGroup></Project>")
    _mk(tmp_path, "P.cs", "namespace X {}")
    a, _ = _dotnet_prepare(tmp_path)
    assert a._tfm_class == "unknown"              # $(...) is unresolvable, not modern


def test_p4_explicit_modern_tfm(tmp_path):
    _mk(tmp_path, "App.csproj",
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
        "<TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>")
    _mk(tmp_path, "P.cs", "using System.Text.Json;\nnamespace X {}")
    a, _ = _dotnet_prepare(tmp_path)
    assert a._tfm_class == "modern"
    assert a.is_internal(ImportRef("System.Text.Json", "P.cs", 1, top_level="System.Text.Json"))


# ── Point 5: canonical manifest identity in monorepo ─────────────────────────
def test_p5_two_same_named_incomplete_manifests_stay_distinct(tmp_path):
    from auditor.adapters.python.adapter import PythonAdapter
    repo = tmp_path / "repo"
    dyn = "from setuptools import setup\nsetup(install_requires=get())\n"
    _mk(repo, "services/a/setup.py", dyn)
    _mk(repo, "services/b/setup.py", dyn)
    da, db = Diagnostics(), Diagnostics()
    aa = PythonAdapter()
    aa.set_repo_root(repo)
    aa.parse_dependencies(repo / "services" / "a", diag=da)
    ab = PythonAdapter()
    ab.set_repo_root(repo)
    ab.parse_dependencies(repo / "services" / "b", diag=db)
    da.merge(db)
    assert len(da.manifest_incomplete) == 2       # canonical full paths, not "setup.py" x1


def test_p5_error_and_incomplete_same_file_counted_once():
    from auditor.core.scoring import analysis_confidence
    # one file among two manifests is BOTH errored and marked incomplete -> the
    # affected count unions to 1, not 2 (CP-8b.5)
    d = Diagnostics(
        manifest_files=["/r/a/pyproject.toml", "/r/b/pyproject.toml"],
        manifest_errors=["/r/a/pyproject.toml: TOMLDecodeError"],
        manifest_incomplete=["/r/a/pyproject.toml"],
        semgrep_status="ci: success")
    # affected = union({a}, {a}) = 1 of 2 => manifest_cov 0.5 => confidence 50
    assert analysis_confidence(d, offline=False, files_read=10) == 50


# ── Point 6: semgrep one normalization base ──────────────────────────────────
def test_p6_relative_scanned_reconciles_with_absolute_expected(monkeypatch, tmp_path):
    from auditor.core import semgrep_runner
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "a.py").write_text("x = 1\n", encoding="utf-8")
    canned = {"paths": {"scanned": ["sub/a.py"]}, "errors": [],
              "results": [{"check_id": "r", "path": "sub/a.py", "start": {"line": 1},
                           "extra": {"message": "m", "severity": "WARNING"}}]}

    class P:
        returncode = 0
        stdout = json.dumps(canned)
        stderr = ""
    monkeypatch.setattr("subprocess.run", lambda *a, **k: P())
    fs, status = semgrep_runner.run_semgrep(
        "x", tmp_path, [], expected_paths={str(tmp_path / "sub" / "a.py")})
    assert status == "success"                     # relative scanned matched absolute expected
    assert [f.file for f in fs] == ["sub/a.py"]


# ── Point 7: React member-hook predicate ─────────────────────────────────────
def _tsx(code):
    from auditor.core.models import SourceFile
    sf = SourceFile(path=Path("C.tsx"), rel="C.tsx", language="tsx", text=code.encode())
    parse_source(sf)
    return sf


def test_p7_service_object_hooks_are_not_flagged():
    from auditor.adapters.typescript.react_rules import HookInConditional
    tmpl = "export function C({{f}}:{{f:boolean}}){{ if(f){{ {}.useState(0); }} return null; }}"
    # lowercase service objects are NOT hooks (eslint-plugin-react-hooks 7.1.1)
    for obj in ("api", "client", "hooks"):
        assert HookInConditional().check(_tsx(tmpl.format(obj))) == [], obj
    # PascalCase object OR React namespace OR bare ARE hooks (matches ESLint)
    for obj in ("React", "Hooks"):
        assert [x.rule_id for x in HookInConditional().check(_tsx(tmpl.format(obj)))] == ["R001"], obj
    assert [x.rule_id for x in HookInConditional().check(
        _tsx("export function C({f}:{f:boolean}){ if(f){ useState(0); } return null; }"))] == ["R001"]


def test_p7_react_alias_import_counts():
    from auditor.adapters.typescript.react_rules import HookInConditional
    sf = _tsx("import * as R from 'react';\n"
              "export function C({f}:{f:boolean}){ if(f){ R.useState(0); } return null; }")
    assert [x.rule_id for x in HookInConditional().check(sf)] == ["R001"]


def test_p6_report_paths_are_repository_relative(tmp_path):
    # CP-8b round 3: the report shows repo-relative paths, not absolute machine
    # paths (privacy + reproducibility)
    from auditor.cli import main
    (tmp_path / "pyproject.toml").write_text("[project\nbroken", encoding="utf-8")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    out = tmp_path / "rep"
    main(["scan", str(tmp_path), "--output", str(out), "--offline", "--no-semgrep"])
    blob = (out / "report.json").read_text(encoding="utf-8")
    assert tmp_path.resolve().as_posix() not in blob        # no absolute repo path
    assert "pyproject.toml" in json.loads(blob)["diagnostics"]["manifest_errors"][0]


# ── Round 4 ──────────────────────────────────────────────────────────────────
def test_r4_setup_inside_control_flow(tmp_path):
    from auditor.adapters.python.adapter import PythonAdapter
    cases = {
        "try_except": "try:\n    from setuptools import setup\nexcept ImportError:\n"
                      "    from distutils.core import setup\nsetup(install_requires=['requests'])\n",
        "if_guard": "if True:\n    from setuptools import setup\nsetup(install_requires=['requests'])\n",
        "assign_rhs": "from setuptools import setup\nr = setup(install_requires=['requests'])\n",
    }
    for name, src in cases.items():
        root = tmp_path / name
        _mk(root, "setup.py", src)
        got = {d.name for d in PythonAdapter().parse_dependencies(root)}
        assert got == {"requests"}, name          # imports inside control flow are seen


def test_r4_dotnet_nearest_props_wins(tmp_path):
    from auditor.adapters.dotnet.adapter import DotnetAdapter
    repo = tmp_path / "repo"
    _mk(repo, "Directory.Build.props",
        "<Project><PropertyGroup><TargetFramework>net48</TargetFramework></PropertyGroup></Project>")
    _mk(repo, "src/app/Directory.Build.props",
        "<Project><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>")
    _mk(repo, "src/app/App.csproj", '<Project Sdk="Microsoft.NET.Sdk"></Project>')
    _mk(repo, "src/app/P.cs", "namespace X {}")
    a = DotnetAdapter()
    a.set_repo_root(repo)
    a.parse_dependencies(repo / "src" / "app")
    a.prepare(repo / "src" / "app", [])
    # the NEAREST props (net8.0) applies, not the pooled root net48
    assert a._tfm_class == "modern"


def test_r4_dotnet_reads_ancestor_props_packagerefs(tmp_path):
    from auditor.adapters.dotnet.adapter import DotnetAdapter
    repo = tmp_path / "repo"
    # a PackageReference in an ancestor Directory.Build.props DECLARES; a
    # PackageVersion in Directory.Packages.props is a version CATALOG only
    # (CP-8b round 5) — read but not declared unless referenced
    _mk(repo, "Directory.Build.props",
        '<Project><ItemGroup><PackageReference Include="Serilog" Version="4.0.0"/></ItemGroup></Project>')
    _mk(repo, "Directory.Packages.props",
        '<Project><ItemGroup><PackageVersion Include="Dapper" Version="2.0.0"/></ItemGroup></Project>')
    _mk(repo, "src/App.csproj",
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0'
        "</TargetFramework></PropertyGroup></Project>")
    a = DotnetAdapter()
    a.set_repo_root(repo)
    names = {d.name for d in a.parse_dependencies(repo / "src")}
    assert "Serilog" in names                       # ancestor PackageReference declares
    assert "Dapper" not in names                     # PackageVersion catalog does NOT


def test_r4_react_literal_eslint_semantics():
    from auditor.adapters.typescript.react_rules import HookInConditional
    tmpl = "export function C({{f}}:{{f:boolean}}){{ if(f){{ {} }} return null; }}"
    clean = ["api.useState(0);", "api.Hooks.useState(0);",           # nested member
             "r.useState(0);"]                                        # lowercase alias
    for expr in clean:
        assert HookInConditional().check(_tsx(tmpl.format(expr))) == [], expr
    for expr in ["Hooks.useState(0);", "React.useState(0);", "useState(0);"]:
        assert [x.rule_id for x in HookInConditional().check(_tsx(tmpl.format(expr)))] == ["R001"], expr


def test_r4_outside_repo_path_masked():
    from auditor.cli import _relativize_diag
    out = _relativize_diag(
        {"manifest_errors": ["C:/outside/private/pyproject.toml: unreadable"]},
        Path("C:/repo"))["manifest_errors"][0]
    assert "outside/private" not in out and "C:/outside" not in out
    assert out == "<outside-repository>/pyproject.toml: unreadable"


def test_r4_h007_title_reflects_broadened_contract():
    from auditor.core.hallucination import _TITLES
    assert "Unverified" in _TITLES["H007"]          # no longer "cannot be mapped" only


# ── Round 5 ──────────────────────────────────────────────────────────────────
def test_r5_setup_branch_merge(tmp_path):
    from auditor.adapters.python.adapter import PythonAdapter
    # (src, declared, incomplete)
    cases = {
        "while_false": ("while False:\n    from setuptools import setup\n"
                        "setup(install_requires=['fake-never'])\n", {"fake-never"}, True),
        "lambda": ("from setuptools import setup\n"
                   "f = lambda: setup(install_requires=['fake-lambda'])\n", set(), True),
        "except_setup_none": ("try:\n    from setuptools import setup\nexcept ImportError:\n"
                              "    setup = None\nsetup(install_requires=['requests'])\n",
                              {"requests"}, True),
        # a legitimate try/except import FALLBACK stays DEFINITE (not incomplete)
        "import_fallback": ("try:\n    from setuptools import setup\nexcept ImportError:\n"
                            "    from distutils.core import setup\n"
                            "setup(install_requires=['ok'])\n", {"ok"}, False),
    }
    for name, (src, deps, inc) in cases.items():
        root = tmp_path / name
        _mk(root, "setup.py", src)
        diag = Diagnostics()
        got = {d.name for d in PythonAdapter().parse_dependencies(root, diag=diag)}
        assert got == deps, name
        assert bool(diag.manifest_incomplete) == inc, name


def test_r5_packageversion_is_catalog_not_dependency(tmp_path):
    from auditor.adapters.dotnet.adapter import DotnetAdapter
    # catalog-only PackageVersion => NOT declared; a real PackageReference => yes
    _mk(tmp_path, "Directory.Packages.props",
        '<Project><ItemGroup><PackageVersion Include="Unused.Catalog" Version="1.0.0"/></ItemGroup></Project>')
    _mk(tmp_path, "App.csproj",
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0'
        '</TargetFramework></PropertyGroup><ItemGroup>'
        '<PackageReference Include="Used.Ref"/></ItemGroup></Project>')
    names = {d.name for d in DotnetAdapter().parse_dependencies(tmp_path)}
    assert names == {"Used.Ref"}                     # catalog entry excluded
    # PackageReference Update="X" alone (modifies an existing ref) does not declare
    d2 = tmp_path / "upd"
    _mk(d2, "App.csproj",
        '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>'
        '<PackageReference Update="X"/></ItemGroup></Project>')
    assert {d.name for d in DotnetAdapter().parse_dependencies(d2)} == set()


def test_r5_relativize_is_field_aware():
    from auditor.cli import _relativize_diag
    root = Path("C:/My Repo")     # a repo path WITH a space
    d = {"notes": ["failed https://registry.example/a/b"],   # URL untouched
         "manifest_errors": ["C:/My Repo/app/pyproject.toml: bad",
                             "C:/outside/x/pyproject.toml: unreadable"],
         "manifest_files": ["C:/My Repo/app/pyproject.toml"]}
    out = _relativize_diag(d, root)
    assert out["notes"] == ["failed https://registry.example/a/b"]     # URL intact
    assert out["manifest_errors"][0] == "app/pyproject.toml: bad"      # space-safe, repo-relative
    assert out["manifest_errors"][1] == "<outside-repository>/pyproject.toml: unreadable"
    assert out["manifest_files"] == ["app/pyproject.toml"]


def test_p7_n006_uses_same_predicate():
    from auditor.adapters.typescript.next_graph import analyze
    from auditor.core.models import SourceFile

    def sf(rel, code):
        s = SourceFile(path=Path(rel), rel=rel, language="tsx", text=code.encode())
        parse_source(s)
        return s
    page = sf("app/page.tsx", "import W from '../components/W';\n"
              "export default function P(){ return <W/>; }")
    api = sf("components/W.tsx", "export default function W(){ api.useState(0); return null; }")
    react = sf("components/W.tsx", "export default function W(){ React.useState(0); return null; }")
    assert not any(f.rule_id == "N006" for f in analyze([page, api], alias_map=())[0])
    assert any(f.rule_id == "N006" for f in analyze([page, react], alias_map=())[0])
