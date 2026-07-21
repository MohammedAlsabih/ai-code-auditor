"""W2-B2.8B1: the .NET compile-provider graph — transitive PackageReference
via ProjectReference with NuGet asset-metadata semantics. Deterministic; no
MSBuild, no restore, no obj/project.assets.json, no network."""
import json

import pytest

from auditor.core.models import Diagnostics, ImportRef


def _dotnet():
    from auditor.adapters.dotnet.adapter import DotnetAdapter
    return DotnetAdapter()


def _imp(module):
    return ImportRef(module=module, file="x.cs", line=1, top_level=module)


def _proj(base, rel, body="", sdk="Microsoft.NET.Sdk"):
    d = base / rel
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{d.name}.csproj").write_text(
        f'<Project Sdk="{sdk}">\n<PropertyGroup>'
        "<TargetFramework>net8.0</TargetFramework></PropertyGroup>\n"
        f"{body}\n</Project>", encoding="utf-8")
    return d


def _pkg(pkg_id, extra_attr="", children=""):
    if children:
        return (f'<ItemGroup><PackageReference Include="{pkg_id}"{extra_attr}>'
                f"{children}</PackageReference></ItemGroup>")
    return (f'<ItemGroup><PackageReference Include="{pkg_id}"{extra_attr} />'
            "</ItemGroup>")


def _ref(rel, extra=""):
    return (f'<ItemGroup><ProjectReference Include="{rel}"{extra} />'
            "</ItemGroup>")


def _match(ad, declared, module):
    return ad.match_declared(_imp(module), declared)


# ── acceptance 1-2: direct + multi-level transitivity ─────────────────────────

def test_transitive_package_one_hop_suppresses_h002(tmp_path):
    _proj(tmp_path, "B", _pkg("Dapper"))
    a = _proj(tmp_path, "A", _ref("../B/B.csproj"))
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    declared = ad.parse_dependencies(a, diag=Diagnostics())
    assert "Dapper" not in {d.name for d in declared}    # NOT declared in A
    dep = _match(ad, declared, "Dapper")
    assert dep is not None and dep.skip_registry         # provider, not audited here
    assert dep.presence == "definite"


def test_transitive_package_two_hops(tmp_path):
    _proj(tmp_path, "C", _pkg("Dapper"))
    _proj(tmp_path, "B", _ref("../C/C.csproj"))
    a = _proj(tmp_path, "A", _ref("../B/B.csproj"))
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    declared = ad.parse_dependencies(a, diag=Diagnostics())
    assert _match(ad, declared, "Dapper.SqlMapper") is not None


# ── acceptance 3-7: asset metadata semantics ─────────────────────────────────

def test_privateassets_all_blocks_flow_but_works_locally(tmp_path):
    b = _proj(tmp_path, "B", _pkg("Dapper", ' PrivateAssets="all"'))
    a = _proj(tmp_path, "A", _ref("../B/B.csproj"))
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    declared_a = ad.parse_dependencies(a, diag=Diagnostics())
    assert _match(ad, declared_a, "Dapper") is None      # did NOT flow to A
    ad2 = _dotnet()
    ad2.set_repo_root(tmp_path)
    declared_b = ad2.parse_dependencies(b, diag=Diagnostics())
    assert _match(ad2, declared_b, "Dapper") is not None  # still works IN B


def test_privateassets_compile_blocks_flow(tmp_path):
    _proj(tmp_path, "B", _pkg("Dapper", ' PrivateAssets="compile;runtime"'))
    a = _proj(tmp_path, "A", _ref("../B/B.csproj"))
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    declared = ad.parse_dependencies(a, diag=Diagnostics())
    assert _match(ad, declared, "Dapper") is None


@pytest.mark.parametrize("assets", ["all", "compile"])
def test_excludeassets_not_a_provider_even_locally(tmp_path, assets):
    b = _proj(tmp_path, "B", _pkg("Dapper", f' ExcludeAssets="{assets}"'))
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    declared = ad.parse_dependencies(b, diag=Diagnostics())
    # still DECLARED (registry/security audit keeps it) …
    assert "Dapper" in {d.name for d in declared}
    # … but it provides no namespaces locally, and flows nowhere
    assert _match(ad, declared, "Dapper") is None
    a = _proj(tmp_path, "A", _ref("../B/B.csproj"))
    ad2 = _dotnet()
    ad2.set_repo_root(tmp_path)
    declared_a = ad2.parse_dependencies(a, diag=Diagnostics())
    assert _match(ad2, declared_a, "Dapper") is None


@pytest.mark.parametrize("incl", ["none", "runtime;build"])
def test_includeassets_without_compile_not_a_provider(tmp_path, incl):
    b = _proj(tmp_path, "B", _pkg("Dapper", f' IncludeAssets="{incl}"'))
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    declared = ad.parse_dependencies(b, diag=Diagnostics())
    assert _match(ad, declared, "Dapper") is None


def test_asset_metadata_as_child_elements(tmp_path):
    _proj(tmp_path, "B",
          _pkg("Dapper", "", "<PrivateAssets>all</PrivateAssets>"))
    a = _proj(tmp_path, "A", _ref("../B/B.csproj"))
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    declared = ad.parse_dependencies(a, diag=Diagnostics())
    assert _match(ad, declared, "Dapper") is None        # child form honored


def test_dynamic_asset_metadata_is_possible_not_definite(tmp_path):
    _proj(tmp_path, "B", _pkg("Dapper", ' PrivateAssets="$(Priv)"'))
    a = _proj(tmp_path, "A", _ref("../B/B.csproj"))
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    diag = Diagnostics()
    declared = ad.parse_dependencies(a, diag=diag)
    dep = _match(ad, declared, "Dapper")
    assert dep is not None and dep.presence == "possible"
    assert diag.manifest_incomplete                      # never a silent exact


# ── acceptance 8-11: graph semantics ─────────────────────────────────────────

def test_reference_output_assembly_false_blocks_package_flow(tmp_path):
    _proj(tmp_path, "B", _pkg("Dapper"))
    a = _proj(tmp_path, "A",
              _ref("../B/B.csproj", ' ReferenceOutputAssembly="false"'))
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    declared = ad.parse_dependencies(a, diag=Diagnostics())
    assert _match(ad, declared, "Dapper") is None


def test_conditional_edge_provider_is_possible_plus_incomplete(tmp_path):
    _proj(tmp_path, "B", _pkg("Dapper"))
    cond = ("<ItemGroup Condition=\"'$(X)'=='1'\">"
            '<ProjectReference Include="../B/B.csproj" /></ItemGroup>')
    a = _proj(tmp_path, "A", cond)
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    diag = Diagnostics()
    declared = ad.parse_dependencies(a, diag=diag)
    dep = _match(ad, declared, "Dapper")
    assert dep is not None and dep.presence == "possible"
    assert diag.manifest_incomplete
    assert any("POSSIBLE" in n for n in diag.notes)


@pytest.mark.parametrize("conditional_first", [True, False])
def test_package_diamond_definite_wins(tmp_path, conditional_first):
    _proj(tmp_path, "D", _pkg("Dapper"))
    _proj(tmp_path, "B", _ref("../D/D.csproj"))
    _proj(tmp_path, "C", _ref("../D/D.csproj"))
    cond = ("<ItemGroup Condition=\"'$(X)'=='1'\">"
            '<ProjectReference Include="../B/B.csproj" /></ItemGroup>')
    plain = _ref("../C/C.csproj")
    body = (cond + plain) if conditional_first else (plain + cond)
    a = _proj(tmp_path, "A", body)
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    declared = ad.parse_dependencies(a, diag=Diagnostics())
    dep = _match(ad, declared, "Dapper")
    assert dep is not None and dep.presence == "definite"


def test_package_graph_cycle_terminates(tmp_path):
    _proj(tmp_path, "B", _pkg("Dapper") + _ref("../A/A.csproj"))
    a = _proj(tmp_path, "A", _ref("../B/B.csproj"))
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    declared = ad.parse_dependencies(a, diag=Diagnostics())
    assert _match(ad, declared, "Dapper") is not None


# ── acceptance 12-14: matching + protection ──────────────────────────────────

def test_nuget_ids_match_case_insensitively_with_boundaries(tmp_path):
    b = _proj(tmp_path, "B", _pkg("xunit"))
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    declared = ad.parse_dependencies(b, diag=Diagnostics())
    assert _match(ad, declared, "Xunit") is not None          # case-insensitive
    assert _match(ad, declared, "Xunit.Abstractions") is not None
    assert _match(ad, declared, "XunitX") is None             # boundary kept


def test_mailkit_does_not_silence_mimekit(tmp_path):
    """Package-INTERNAL dependencies (MailKit -> MimeKit) are nupkg metadata we
    deliberately do not read this round: the finding stays unresolved."""
    b = _proj(tmp_path, "B", _pkg("MailKit"))
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    declared = ad.parse_dependencies(b, diag=Diagnostics())
    assert _match(ad, declared, "MimeKit") is None


def test_out_of_repo_project_not_read_no_path_leak(tmp_path):
    outside = tmp_path / "outside"
    repo = tmp_path / "repo"
    _proj(outside, "Evil", _pkg("Dapper"))
    a = _proj(repo, "A", _ref("../../outside/Evil/Evil.csproj"))
    ad = _dotnet()
    ad.set_repo_root(repo)
    diag = Diagnostics()
    declared = ad.parse_dependencies(a, diag=diag)
    assert _match(ad, declared, "Dapper") is None
    assert not any(str(tmp_path).replace("\\", "/") in n.replace("\\", "/")
                   for n in diag.notes)


# ── acceptance 15: direct-package auditing is NOT silenced ───────────────────

def test_pipeline_direct_packages_still_registry_audited(tmp_path):
    """e2e offline scan: B's own Dapper stays in B's declared list (offline =>
    H-rules unavailable, not silently dropped), while A gets no H002 for the
    transitively provided namespace."""
    from auditor import cli
    b = _proj(tmp_path, "B", _pkg("Dapper"))
    (b / "Repo.cs").write_text("using Dapper;\nclass R {}\n", encoding="utf-8")
    a = _proj(tmp_path, "A", _ref("../B/B.csproj"))
    (a / "App.cs").write_text("using Dapper;\nclass App {}\n", encoding="utf-8")
    out = tmp_path / "rep"
    cli.main(["scan", str(tmp_path), "--output", str(out),
              "--offline", "--no-semgrep"])
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    all_f = [(p["root"], f) for p in data["projects"] for f in p["findings"]]
    # neither project flags Dapper as undeclared
    assert not any(f["rule_id"] in ("H002", "H008")
                   and "Dapper" in (f.get("snippet") or "") for _, f in all_f)
    # B's ledger still shows the registry work EXISTED (offline => unavailable)
    execution = data["analysis_manifest"]["execution"]
    b_exec = next(p for p in execution["projects"] if p["root"] == "B")
    assert b_exec["rules"]["H001"]["unavailable_reasons"]     # audit not silenced


# == closing round: provider tri-state, MSBuild fold order, sibling isolation ==

def test_direct_dynamic_metadata_possible_and_incomplete(tmp_path):
    """direct_dynamic = possible, incomplete=true — and the package STAYS
    declared for registry/security auditing."""
    b = _proj(tmp_path, "B",
              _pkg("Dapper", "", "<ExcludeAssets>$(Assets)</ExcludeAssets>"))
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    diag = Diagnostics()
    declared = ad.parse_dependencies(b, diag=diag)
    dep = _match(ad, declared, "Dapper")
    assert dep is not None and dep.presence == "possible"
    assert diag.manifest_incomplete
    assert "Dapper" in {d.name for d in declared}      # audit NOT silenced


def _scoped_props(tmp_path, body):
    (tmp_path / "backend").mkdir(exist_ok=True)
    (tmp_path / "backend" / "Directory.Build.props").write_text(
        f"<Project><ItemGroup>{body}</ItemGroup></Project>", encoding="utf-8")


def test_removed_pkg_does_not_flow(tmp_path):
    """props Include + csproj Remove => no provider, no flow to A."""
    _scoped_props(tmp_path, '<PackageReference Include="Dapper" />')
    _proj(tmp_path, "backend/B",
          '<ItemGroup><PackageReference Remove="Dapper" /></ItemGroup>')
    a = _proj(tmp_path, "A", _ref("../backend/B/B.csproj"))
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    declared = ad.parse_dependencies(a, diag=Diagnostics())
    assert _match(ad, declared, "Dapper") is None      # removed_pkg_flows=false


def test_private_update_does_not_flow_but_local_stays(tmp_path):
    """props Include + csproj Update PrivateAssets=all => local in B, no flow."""
    _scoped_props(tmp_path, '<PackageReference Include="Dapper" />')
    b = _proj(tmp_path, "backend/B",
              '<ItemGroup><PackageReference Update="Dapper" '
              'PrivateAssets="all" /></ItemGroup>')
    a = _proj(tmp_path, "A", _ref("../backend/B/B.csproj"))
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    declared_a = ad.parse_dependencies(a, diag=Diagnostics())
    assert _match(ad, declared_a, "Dapper") is None    # private_update_flows=false
    adb = _dotnet()
    adb.set_repo_root(tmp_path)
    declared_b = adb.parse_dependencies(b, diag=Diagnostics())
    assert _match(adb, declared_b, "Dapper") is not None   # local in B


def test_update_alone_never_creates_a_package(tmp_path):
    b = _proj(tmp_path, "B",
              '<ItemGroup><PackageReference Update="Dapper" /></ItemGroup>')
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    declared = ad.parse_dependencies(b, diag=Diagnostics())
    assert _match(ad, declared, "Dapper") is None


def test_conditional_remove_downgrades_to_possible(tmp_path):
    _scoped_props(tmp_path, '<PackageReference Include="Dapper" />')
    _proj(tmp_path, "backend/B",
          "<ItemGroup Condition=\"'$(X)'=='1'\">"
          '<PackageReference Remove="Dapper" /></ItemGroup>')
    a = _proj(tmp_path, "A", _ref("../backend/B/B.csproj"))
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    declared = ad.parse_dependencies(a, diag=Diagnostics())
    dep = _match(ad, declared, "Dapper")
    assert dep is not None and dep.presence == "possible"


def test_update_with_excludeassets_compile_stops_local_provider(tmp_path):
    _scoped_props(tmp_path, '<PackageReference Include="Dapper" />')
    b = _proj(tmp_path, "backend/B",
              '<ItemGroup><PackageReference Update="Dapper" '
              'ExcludeAssets="compile" /></ItemGroup>')
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    declared = ad.parse_dependencies(b, diag=Diagnostics())
    assert _match(ad, declared, "Dapper") is None      # not a provider locally
    assert "Dapper" in {d.name for d in declared}      # still audited


def test_multi_csproj_sibling_provider_wins(tmp_path):
    """multi_csproj_provider = true: ExcludeAssets in one sibling never
    cancels the plain declaration in the other."""
    d = tmp_path / "P"
    d.mkdir()
    hdr = ('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
           "<TargetFramework>net8.0</TargetFramework></PropertyGroup>")
    (d / "A.csproj").write_text(
        hdr + '<ItemGroup><PackageReference Include="Dapper" '
        'ExcludeAssets="compile" /></ItemGroup></Project>', encoding="utf-8")
    (d / "B.csproj").write_text(
        hdr + '<ItemGroup><PackageReference Include="Dapper" /></ItemGroup>'
        "</Project>", encoding="utf-8")
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    declared = ad.parse_dependencies(d, diag=Diagnostics())
    assert _match(ad, declared, "Dapper") is not None


def test_multi_csproj_possible_plus_definite_is_definite(tmp_path):
    d = tmp_path / "P"
    d.mkdir()
    hdr = ('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
           "<TargetFramework>net8.0</TargetFramework></PropertyGroup>")
    (d / "A.csproj").write_text(
        hdr + '<ItemGroup><PackageReference Include="Dapper">'
        "<ExcludeAssets>$(Assets)</ExcludeAssets></PackageReference>"
        "</ItemGroup></Project>", encoding="utf-8")
    (d / "B.csproj").write_text(
        hdr + '<ItemGroup><PackageReference Include="Dapper" /></ItemGroup>'
        "</Project>", encoding="utf-8")
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    declared = ad.parse_dependencies(d, diag=Diagnostics())
    dep = _match(ad, declared, "Dapper")
    assert dep is not None and dep.presence == "definite"   # definite wins
