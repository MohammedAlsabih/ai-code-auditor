from pathlib import Path

from auditor.adapters.dotnet.adapter import DotnetAdapter
from auditor.core.models import DeclaredDep, ImportRef
from auditor.core.treesitter import parse_source
from auditor.core.walk import collect_source_files


def _mk(tmp_path: Path, rel: str, content: str) -> None:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


CSPROJ = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.4" />
    <PackageReference Include="FastJsonAI.Helpers" Version="1.0.0" />
  </ItemGroup>
</Project>"""


def test_detect_and_csproj(tmp_path):
    a = DotnetAdapter()
    assert not a.detect(tmp_path)
    _mk(tmp_path, "App.csproj", CSPROJ)
    assert a.detect(tmp_path)
    names = {d.name for d in a.parse_dependencies(tmp_path)}
    assert names == {"Newtonsoft.Json", "FastJsonAI.Helpers"}


def test_packages_config_and_package_reference(tmp_path):
    # packages.config <package id> declares; a PackageReference Include declares.
    # A PackageVersion in Directory.Packages.props is a central-version CATALOG
    # (CP-8b round 5) — an entry with no matching reference is NOT a dependency.
    _mk(tmp_path, "packages.config",
        '<packages><package id="Dapper" version="2.1.0" /></packages>')
    _mk(tmp_path, "App.csproj",
        '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>'
        '<PackageReference Include="Serilog" /></ItemGroup></Project>')
    _mk(tmp_path, "Directory.Packages.props",
        '<Project><ItemGroup><PackageVersion Include="Unused.Catalog" Version="4.0.0" />'
        "</ItemGroup></Project>")
    names = {d.name for d in DotnetAdapter().parse_dependencies(tmp_path)}
    assert names == {"Dapper", "Serilog"}       # Unused.Catalog (PackageVersion) excluded


def test_broken_csproj_is_noted_not_silent(tmp_path):
    from auditor.core.models import Diagnostics
    _mk(tmp_path, "App.csproj", "<Project><ItemGroup>")
    diag = Diagnostics()
    assert DotnetAdapter().parse_dependencies(tmp_path, diag=diag) == []
    assert any("App.csproj" in e for e in diag.manifest_errors)


def test_usings_and_locality(tmp_path):
    _mk(tmp_path, "App.csproj", CSPROJ)
    _mk(tmp_path, "Program.cs", "\n".join([
        "using System;",
        "using System.Text.Json;",
        "global using System.Collections.Generic;",
        "using static System.Math;",
        "using Newtonsoft.Json;",
        "using Dapper;",
        "using HyperSql.Client;",
        "using MyApp.Services;",
        "namespace MyApp { class P { static void Main() {} } }",
    ]))
    a = DotnetAdapter()
    files = collect_source_files(tmp_path, a)
    for f in files:
        parse_source(f)
    a.prepare(tmp_path, files)
    imps = {i.top_level: i for i in a.extract_imports(files)}
    assert "System.Text.Json" in imps and "Newtonsoft.Json" in imps
    assert a.is_internal(imps["System"]) and a.is_internal(imps["System.Text.Json"])
    assert a.is_internal(imps["MyApp.Services"])   # own namespace
    assert not a.is_internal(imps["Dapper"])


def test_old_tfm_makes_system_text_json_external(tmp_path):
    _mk(tmp_path, "App.csproj",
        '<Project><PropertyGroup><TargetFramework>net472</TargetFramework>'
        "</PropertyGroup></Project>")
    _mk(tmp_path, "P.cs", "using System.Text.Json;\nnamespace X {}")
    a = DotnetAdapter()
    files = collect_source_files(tmp_path, a)
    for f in files:
        parse_source(f)
    a.parse_dependencies(tmp_path)
    a.prepare(tmp_path, files)
    imp = ImportRef("System.Text.Json", "P.cs", 1, top_level="System.Text.Json")
    assert not a.is_internal(imp)   # net472 => package-delivered, must be declared


def test_match_and_candidates():
    a = DotnetAdapter()
    declared = [DeclaredDep(name="Newtonsoft.Json", ecosystem="nuget", source_file="App.csproj")]
    linq = ImportRef("Newtonsoft.Json.Linq", "P.cs", 1, top_level="Newtonsoft.Json.Linq")
    assert a.match_declared(linq, declared).name == "Newtonsoft.Json"
    hyper = ImportRef("HyperSql.Client", "P.cs", 1, top_level="HyperSql.Client")
    assert a.match_declared(hyper, declared) is None
    assert a.registry_candidates(hyper) == ["HyperSql.Client"]
    deep = ImportRef("A.B.C.D", "P.cs", 1, top_level="A.B.C.D")
    assert a.registry_candidates(deep) == ["A.B.C.D", "A.B"]
    nunit = ImportRef("NUnit.Framework", "T.cs", 1, top_level="NUnit.Framework")
    assert a.registry_candidates(nunit) == ["NUnit"]   # relic-package alias fixup


def test_dotnet_repo_e2e(fixtures_dir):
    from auditor.core.hallucination import audit_hallucinations
    from auditor.core.models import PackageInfo
    from tests.conftest import FakeRegistry

    root = fixtures_dir / "dotnet_repo"
    a = DotnetAdapter()
    files = collect_source_files(root, a)
    for f in files:
        parse_source(f)
    a.prepare(root, files)
    declared = a.parse_dependencies(root)
    reg = FakeRegistry("nuget", {
        "newtonsoft.json": PackageInfo(True, created="2011-01-08T00:00:00+00:00"),
        "dapper": PackageInfo(True, created="2011-04-14T00:00:00+00:00"),
    })
    findings = audit_hallucinations(a, root, files, declared, reg)
    ids = sorted(f.rule_id for f in findings)
    # CP-8.3: HyperSql.Client is absent, but the .NET namespace->NuGet candidate
    # is a GENERIC GUESS (no curated map), so it degrades to H007 — never a red
    # H008. FastJsonAI.Helpers is a DECLARED name absent from the registry, so it
    # is a legitimate red H001.
    assert ids == ["H001", "H002", "H007"]  # FastJsonAI.Helpers / Dapper / HyperSql.Client
    assert all(f.precision == "heuristic" for f in findings
               if f.rule_id in ("H002", "H007", "H008"))   # namespace guessing is never "exact"
    assert all(f.severity.value != "red" for f in findings
               if f.rule_id in ("H007", "H008"))            # no red from a namespace guess
