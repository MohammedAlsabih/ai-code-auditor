"""CP-8 product-contract regressions — one independent case per counter-case."""
import json
from pathlib import Path

from auditor.core.models import Diagnostics, Finding, ImportRef, PackageInfo, Severity
from auditor.core.treesitter import parse_source
from auditor.core.walk import collect_source_files


def _mk(root: Path, rel: str, content: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


class _Reg:
    ecosystem = "pypi"

    def __init__(self, exists=(), created="2019-01-01T00:00:00Z"):
        self._exists = set(exists)
        self._created = created

    def lookup(self, name):
        return PackageInfo(exists=True, created=self._created) if name in self._exists \
            else PackageInfo(exists=False)


# ── Point 1: unified, by-file confidence source ──────────────────────────────
def test_p1_manifest_incomplete_lowers_confidence_and_forbids_pass():
    from auditor.core.scoring import analysis_confidence, verdict
    base = Diagnostics(semgrep_status="ci: success")
    inc = Diagnostics(manifest_incomplete=["a/pyproject.toml"], semgrep_status="ci: success")
    assert analysis_confidence(base, offline=False, files_read=10) == 100
    assert analysis_confidence(inc, offline=False, files_read=10) < 100
    assert verdict({"red": 0, "yellow": 0}, 100,
                   {"manifest_incomplete": ["a/pyproject.toml"]}) == "review"


def test_p1_include_gaps_forbid_pass():
    from auditor.core.scoring import verdict
    assert verdict({"red": 0, "yellow": 0}, 100,
                   {"include_gaps": ["req.txt: include not found: x"]}) == "review"


def test_p1_manifest_coverage_counts_files_not_messages():
    from auditor.core.scoring import analysis_confidence
    # ONE broken file among THREE manifests, raising TWO distinct error strings,
    # must not read as two failed files (CP-8.1).
    one_file_two_msgs = Diagnostics(
        manifest_files=["/r/a.toml", "/r/b.txt", "/r/c.cfg"],
        manifest_errors=["/r/a.toml: TOMLDecodeError", "/r/a.toml: exceeds 2000000 bytes"],
        semgrep_status="ci: success")
    two_files = Diagnostics(
        manifest_files=["/r/a.toml", "/r/b.txt", "/r/c.cfg"],
        manifest_errors=["/r/a.toml: TOMLDecodeError", "/r/b.txt: TOMLDecodeError"],
        semgrep_status="ci: success")
    c1 = analysis_confidence(one_file_two_msgs, offline=False, files_read=10)
    c2 = analysis_confidence(two_files, offline=False, files_read=10)
    assert c1 > c2                       # 1 affected file scores higher than 2
    assert c1 == 67 and c2 == 33         # manifest_cov 2/3 vs 1/3, by file


def test_p1_dead_string_confidence_method_removed():
    assert not hasattr(Diagnostics(), "analysis_confidence")   # single numeric source


# ── Point 2: repository root vs project root ─────────────────────────────────
def test_p2_shared_include_inside_repo_is_followed(tmp_path):
    from auditor.adapters.python.adapter import PythonAdapter
    repo = tmp_path / "repo"
    _mk(repo, "shared/base.txt", "flask\n")
    _mk(repo, "web/requirements.txt", "-r ../shared/base.txt\nrequests\n")
    a = PythonAdapter()
    a.set_repo_root(repo)                # confinement = whole repo
    names = {d.name for d in a.parse_dependencies(repo / "web")}
    assert names == {"flask", "requests"}   # the same-repo shared file is read


def test_p2_include_outside_repo_still_refused(tmp_path):
    from auditor.adapters.python.adapter import PythonAdapter
    repo = tmp_path / "repo"
    (tmp_path / "outside.txt").write_text("evil\n", encoding="utf-8")
    _mk(repo, "web/requirements.txt", "-r ../../outside.txt\nrequests\n")
    a = PythonAdapter()
    a.set_repo_root(repo)
    diag = Diagnostics()
    names = {d.name for d in a.parse_dependencies(repo / "web", diag=diag)}
    assert names == {"requests"}         # a path escaping the REPO is refused
    assert diag.include_gaps


def test_p2_ancestor_npmrc_found(tmp_path):
    from auditor.adapters.typescript.adapter import TypeScriptAdapter
    repo = tmp_path / "repo"
    _mk(repo, ".npmrc", "@corp:registry=https://npm.corp.example\n")
    _mk(repo, "web/package.json", "{}")
    a = TypeScriptAdapter()
    a.set_repo_root(repo)
    assert a.private_registry_reason(repo / "web") is not None   # repo-level config


# ── Point 3: Java full-coords / .NET guess / TFM ─────────────────────────────
def test_p3_java_wrong_artifact_not_matched_by_group():
    from auditor.adapters.java.adapter import JavaAdapter
    from auditor.core.models import DeclaredDep
    a = JavaAdapter()
    declared = [DeclaredDep(name="com.fasterxml.jackson.core:WRONG-artifact",
                            ecosystem="maven", source_file="pom.xml")]
    imp = ImportRef("com.fasterxml.jackson.databind.ObjectMapper", "M.java", 1,
                    top_level="com.fasterxml.jackson.databind")
    # curated map knows the exact artifact is jackson-databind; a different
    # artifact in the same group must NOT masquerade as the provider
    assert a.match_declared(imp, declared) is None


def test_p3_java_correct_full_coords_still_match():
    from auditor.adapters.java.adapter import JavaAdapter
    from auditor.core.models import DeclaredDep
    a = JavaAdapter()
    declared = [DeclaredDep(name="com.fasterxml.jackson.core:jackson-databind",
                            ecosystem="maven", source_file="pom.xml")]
    imp = ImportRef("com.fasterxml.jackson.databind.ObjectMapper", "M.java", 1,
                    top_level="com.fasterxml.jackson.databind")
    assert a.match_declared(imp, declared).name == "com.fasterxml.jackson.core:jackson-databind"


def test_p3_dotnet_unknown_namespace_is_h007_not_red(tmp_path):
    from auditor.adapters.dotnet.adapter import DotnetAdapter
    from auditor.core.hallucination import audit_hallucinations
    _mk(tmp_path, "App.csproj",
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
        '<TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>')
    _mk(tmp_path, "P.cs", "using Totally.Made.Up.Thing;\nnamespace X {}")
    a = DotnetAdapter()
    files = collect_source_files(tmp_path, a)
    for f in files:
        parse_source(f)
    declared = a.parse_dependencies(tmp_path)
    a.prepare(tmp_path, files)

    class NoReg:
        ecosystem = "nuget"
        def lookup(self, n): return PackageInfo(exists=False)
    fs = audit_hallucinations(a, tmp_path, files, declared, NoReg())
    assert [f.rule_id for f in fs] == ["H007"]           # a guess is never red H008
    assert fs[0].severity.value != "red"


def test_p3_dotnet_tfm_detection():
    from auditor.adapters.dotnet.adapter import _is_old_tfm
    assert _is_old_tfm("netcoreapp2.1") and _is_old_tfm("netcoreapp1.0")
    assert not _is_old_tfm("netcoreapp3.1") and not _is_old_tfm("net8.0")
    assert _is_old_tfm("v4.7.2") and _is_old_tfm("net472") and _is_old_tfm("netstandard2.0")


def test_p3_dotnet_packages_config_is_old_tfm(tmp_path):
    from auditor.adapters.dotnet.adapter import DotnetAdapter
    _mk(tmp_path, "packages.config",
        '<packages><package id="Newtonsoft.Json" version="13.0.4" /></packages>')
    _mk(tmp_path, "P.cs", "using System.Text.Json;\nnamespace X {}")
    a = DotnetAdapter()
    files = collect_source_files(tmp_path, a)
    for f in files:
        parse_source(f)
    a.parse_dependencies(tmp_path)
    a.prepare(tmp_path, files)
    # packages.config => old .NET Framework => System.Text.Json is package-delivered
    assert not a.is_internal(ImportRef("System.Text.Json", "P.cs", 1,
                                       top_level="System.Text.Json"))


# ── Point 4: React.useX member hooks + directive prologue ────────────────────
def _tsx(code):
    from auditor.core.models import SourceFile
    sf = SourceFile(path=Path("C.tsx"), rel="C.tsx", language="tsx", text=code.encode())
    parse_source(sf)
    return sf


def test_p4_member_hook_in_conditional_flagged():
    from auditor.adapters.typescript.react_rules import HookInConditional
    sf = _tsx("export function C({f}:{f:boolean}){ if(f){ React.useState(0); } return null; }")
    assert [x.rule_id for x in HookInConditional().check(sf)] == ["R001"]


def test_p4_member_hook_in_server_graph_flagged():
    from auditor.adapters.typescript.next_graph import analyze
    from auditor.core.models import SourceFile

    def sf(rel, code):
        s = SourceFile(path=Path(rel), rel=rel, language="tsx", text=code.encode())
        parse_source(s)
        return s
    page = sf("app/page.tsx", "import H from '../components/H';\n"
              "export default function P(){ return <H/>; }")
    comp = sf("components/H.tsx",
              "export default function H(){ const [v]=React.useState(0); return <b>{v}</b>; }")
    findings, _ = analyze([page, comp], alias_map=())
    assert any(f.rule_id == "N006" and f.file == "components/H.tsx" for f in findings)


def test_p4_directive_prologue():
    from auditor.adapters.typescript.next_rules import has_use_client
    # "use client" after other directive strings is still honored
    assert has_use_client(_tsx("'use strict';\n\"use client\";\nexport const x=1;"))
    # a leading comment does not end the prologue
    assert has_use_client(_tsx("// banner\n\"use client\";\nexport const x=1;"))
    # a directive AFTER a real statement is NOT a directive (prologue ended)
    assert not has_use_client(_tsx("import x from 'y';\n\"use client\";\n"))
    assert not has_use_client(_tsx("const a=1;\n\"use client\";\n"))


# ── Point 5: R007 forms + heuristic precision ────────────────────────────────
def test_p5_r007_identifier_and_spread_forms():
    from auditor.adapters.typescript.react_rules import DangerousInnerHtml
    r = DangerousInnerHtml()
    ident = _tsx("export function D({p}){ return <div dangerouslySetInnerHTML={p} />; }")
    spread = _tsx("export function D({p}){ return <div dangerouslySetInnerHTML={{...p}} />; }")
    dyn = _tsx("export function D({h}){ return <div dangerouslySetInnerHTML={{__html: h}} />; }")
    lit = _tsx('export function D(){ return <div dangerouslySetInnerHTML={{__html: "<b>hi</b>"}} />; }')
    assert [f.rule_id for f in r.check(ident)] == ["R007"]
    assert [f.rule_id for f in r.check(spread)] == ["R007"]
    assert [f.rule_id for f in r.check(dyn)] == ["R007"]
    assert r.check(lit) == []                       # provable literal is clean
    assert all(f.precision == "heuristic" for f in r.check(ident))   # no taint analysis


# ── Point 6: semgrep path normalization + escape drop ────────────────────────
def test_p6_out_of_root_result_dropped(monkeypatch, tmp_path):
    from auditor.core import semgrep_runner
    outside = tmp_path.parent / "other_evil"
    canned = {"results": [{"check_id": "r", "path": str(outside / "evil.py"),
                           "start": {"line": 9},
                           "extra": {"message": "m", "severity": "ERROR"}}],
              "errors": [], "paths": {"scanned": []}}

    class P:
        returncode = 0
        stdout = json.dumps(canned)
        stderr = ""
    monkeypatch.setattr("subprocess.run", lambda *a, **k: P())
    fs, status = semgrep_runner.run_semgrep("x", tmp_path, [])
    assert fs == [] and "outside scan root dropped" in status   # dropped, not basename'd


def test_p6_relative_result_path_normalized(monkeypatch, tmp_path):
    from auditor.core import semgrep_runner
    (tmp_path / "sub").mkdir()
    canned = {"results": [{"check_id": "r", "path": "sub/a.py", "start": {"line": 3},
                           "extra": {"message": "m", "severity": "WARNING"}}],
              "errors": [], "paths": {"scanned": []}}

    class P:
        returncode = 0
        stdout = json.dumps(canned)
        stderr = ""
    monkeypatch.setattr("subprocess.run", lambda *a, **k: P())
    fs, _ = semgrep_runner.run_semgrep("x", tmp_path, [])
    assert [f.file for f in fs] == ["sub/a.py"]     # relative path anchored to root


# ── Point 7: recursive redaction ─────────────────────────────────────────────
def test_p7_secrets_never_reach_report_json():
    from auditor.report.build import build_report
    data = build_report(
        target="https://alice:S3cretTok@github.com/x/y",
        projects=[{"language": "python", "root": ".", "frameworks": [], "file_count": 1,
                   "findings": [Finding("H001", Severity.RED, "t", "requirements.txt", 1,
                                        detail="see https://u:P4ssw0rd@host/z")]}],
        engines={"note": "token=SUP3RSECRET&x=1"},
        limitations=["fetched from https://x:L1mitSecret@h/p"],
        diagnostics={"notes": ["failed on https://n:D1agSecret@host/z"],
                     "manifest_errors": ["/r/x: token=M4nifestSecret"]})
    blob = json.dumps(data)
    for secret in ("S3cretTok", "P4ssw0rd", "SUP3RSECRET", "L1mitSecret",
                   "D1agSecret", "M4nifestSecret"):
        assert secret not in blob, secret


# ── Point 8: dedupe on full identity ─────────────────────────────────────────
def test_p8_two_secrets_on_one_line_both_kept():
    from auditor.core.patterns import dedupe
    a = Finding("P002", Severity.RED, "t", "a.py", 1, snippet="AKIA...", detail="AWS key")
    b = Finding("P002", Severity.RED, "t", "a.py", 1, snippet="ghp_...", detail="GitHub PAT")
    dup = Finding("P002", Severity.RED, "t", "a.py", 1, snippet="AKIA...", detail="AWS key")
    out = dedupe([a, b, dup])
    assert len(out) == 2                            # distinct kept, exact dup collapsed
    assert {f.detail for f in out} == {"AWS key", "GitHub PAT"}


# ── Point 9: provider may supply multiple modules ────────────────────────────
def test_p9_matched_provider_still_shields_sibling(tmp_path):
    from auditor.adapters.python.adapter import PythonAdapter
    from auditor.core.hallucination import audit_hallucinations
    # one declared dist 'megatool' provides megatool (matched) AND megahelper
    # (unmatched, absent). The sibling must be H007, not a red H008 (CP-8.9).
    _mk(tmp_path, "requirements.txt", "megatool\n")
    _mk(tmp_path, "app.py", "import megatool\nimport megahelper\n")
    a = PythonAdapter()
    files = collect_source_files(tmp_path, a)
    for f in files:
        parse_source(f)
    declared = a.parse_dependencies(tmp_path)
    a.prepare(tmp_path, files)
    fs = audit_hallucinations(a, tmp_path, files, declared, _Reg(exists={"megatool"}))
    by = {f.rule_id for f in fs}
    assert "H008" not in by and "H007" in by
    h007 = next(f for f in fs if f.rule_id == "H007")
    assert "megatool" in h007.detail


def test_p9_no_declared_provider_still_red_h008(tmp_path):
    from auditor.adapters.python.adapter import PythonAdapter
    from auditor.core.hallucination import audit_hallucinations
    # NO existing declared dep => nothing could provide it => the red stands
    _mk(tmp_path, "app.py", "import superhallucinated\n")
    a = PythonAdapter()
    files = collect_source_files(tmp_path, a)
    for f in files:
        parse_source(f)
    declared = a.parse_dependencies(tmp_path)
    a.prepare(tmp_path, files)
    fs = audit_hallucinations(a, tmp_path, files, declared, _Reg())
    assert [f.rule_id for f in fs] == ["H008"]


# ── Point 10: cache semantics + anchored setup() + kwargs ─────────────────────
def test_p10_garbage_cached_date_is_miss(tmp_path):
    import time
    from dataclasses import asdict
    from auditor.registries.base import CachedRegistry, RegistryClient, age_days
    from auditor.registries.cache import Cache
    calls = []

    class Inner(RegistryClient):
        ecosystem = "pypi"
        def cache_key(self, name): return name
        def lookup(self, name):
            calls.append(name)
            return PackageInfo(exists=True, created="2019-01-01T00:00:00Z")
    for bad in ("not-a-date", "2021-13-45T99:99:99Z"):
        calls.clear()
        good = asdict(PackageInfo(exists=True, created="2019-01-01T00:00:00Z"))
        good["created"] = bad
        p = tmp_path / f"c_{bad[:4]}.json"
        p.write_text(json.dumps({"pypi:x": {"expires": time.time() + 999, "value": good}}),
                     encoding="utf-8")
        info = CachedRegistry(Inner(), Cache(p)).lookup("x")
        assert calls == ["x"]                       # garbage date => re-queried, not served
        age_days(info.created)                      # usable


def test_p10_setup_without_setuptools_import_ignored(tmp_path):
    from auditor.adapters.python.adapter import PythonAdapter
    _mk(tmp_path, "setup.py",
        "def setup(**k): pass\nsetup(install_requires=['not-a-real-dep'])\n")
    assert PythonAdapter().parse_dependencies(tmp_path) == []   # local setup(), not packaging


def test_p10_setup_kwargs_recorded_incomplete(tmp_path):
    from auditor.adapters.python.adapter import PythonAdapter
    _mk(tmp_path, "setup.py",
        "from setuptools import setup\nCFG = {'install_requires': ['x']}\nsetup(**CFG)\n")
    diag = Diagnostics()
    assert PythonAdapter().parse_dependencies(tmp_path, diag=diag) == []
    assert "setup.py" in diag.manifest_incomplete
    assert any("kwargs" in n for n in diag.notes)


# ── Point 11: example internal consistency ───────────────────────────────────
def test_p11_examples_counts_equal_serialized_findings():
    root = Path(__file__).resolve().parent.parent / "examples" / "report.json"
    data = json.loads(root.read_text(encoding="utf-8"))
    serialized = sum(len(p["findings"]) for p in data["projects"])
    counts = data["summary"]["counts"]
    assert serialized == counts["red"] + counts["yellow"] + counts["blue"]


# ── Point 12: reproducible dev tooling ───────────────────────────────────────
def test_p12_dev_tools_pinned():
    import tomllib
    root = Path(__file__).resolve().parent.parent / "pyproject.toml"
    data = tomllib.loads(root.read_text(encoding="utf-8"))
    dev = " ".join(data["project"]["optional-dependencies"]["dev"])
    for tool in ("mypy", "ruff", "types-defusedxml"):
        assert tool in dev, tool
    assert data["tool"]["mypy"]["ignore_missing_imports"] is True
