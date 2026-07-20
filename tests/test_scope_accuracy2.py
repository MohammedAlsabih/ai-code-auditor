"""W2-B2.8A closing round: transitive FrameworkReference via ProjectReference,
npm_roots end-to-end, and ConfigError value-leak prevention."""
import json

import pytest

from auditor.config import ConfigError, load_config
from auditor.core.models import Diagnostics, ImportRef


def _dotnet():
    from auditor.adapters.dotnet.adapter import DotnetAdapter
    return DotnetAdapter()


def _imp(module):
    return ImportRef(module=module, file="x", line=1, top_level=module)


def _proj(base, rel, body="", sdk="Microsoft.NET.Sdk"):
    d = base / rel
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{d.name}.csproj").write_text(
        f'<Project Sdk="{sdk}">\n<PropertyGroup>'
        "<TargetFramework>net8.0</TargetFramework></PropertyGroup>\n"
        f"{body}\n</Project>", encoding="utf-8")
    return d


def _projref(target_rel, extra=""):
    return (f'<ItemGroup><ProjectReference Include="{target_rel}"{extra} />'
            "</ItemGroup>")


_ASP = ('<ItemGroup><FrameworkReference Include="Microsoft.AspNetCore.App" />'
        "</ItemGroup>")


def _internal(ad, module):
    ad._own_namespaces = ()
    ad._old_tfm = False
    return ad.is_internal(_imp(module))


# ── 1: transitive FrameworkReference ─────────────────────────────────────────

def test_transitive_fwref_one_hop(tmp_path):
    _proj(tmp_path, "B", _ASP)
    a = _proj(tmp_path, "A", _projref("../B/B.csproj"))
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    diag = Diagnostics()
    ad.parse_dependencies(a, diag=diag)
    assert _internal(ad, "Microsoft.AspNetCore.Builder")
    assert not diag.manifest_incomplete          # all-definite chain: no flag


def test_transitive_fwref_two_hops_sdk_web(tmp_path):
    _proj(tmp_path, "C", "", sdk="Microsoft.NET.Sdk.Web")
    _proj(tmp_path, "B", _projref("../C/C.csproj"))
    a = _proj(tmp_path, "A", _projref("../B/B.csproj"))
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    ad.parse_dependencies(a, diag=Diagnostics())
    assert _internal(ad, "Microsoft.AspNetCore.Http.Features")


def test_transitive_fwref_conditional_edge_is_possible(tmp_path):
    _proj(tmp_path, "B", _ASP)
    cond = ("<ItemGroup Condition=\"'$(X)'=='1'\">"
            '<ProjectReference Include="../B/B.csproj" /></ItemGroup>')
    a = _proj(tmp_path, "A", cond)
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    diag = Diagnostics()
    ad.parse_dependencies(a, diag=diag)
    # possible: suppresses definitive H002, but flagged incomplete + noted
    assert _internal(ad, "Microsoft.AspNetCore.Builder")
    assert diag.manifest_incomplete
    assert any("FrameworkReference" in n for n in diag.notes)


def test_transitive_fwref_cycle_terminates(tmp_path):
    _proj(tmp_path, "B", _ASP + _projref("../A/A.csproj"))
    a = _proj(tmp_path, "A", _projref("../B/B.csproj"))
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    ad.parse_dependencies(a, diag=Diagnostics())   # must terminate
    assert _internal(ad, "Microsoft.AspNetCore.Builder")


def test_transitive_fwref_out_of_repo_not_followed(tmp_path):
    outside = tmp_path / "outside"
    repo = tmp_path / "repo"
    _proj(outside, "Evil", _ASP)
    a = _proj(repo, "A", _projref("../../outside/Evil/Evil.csproj"))
    ad = _dotnet()
    ad.set_repo_root(repo)
    diag = Diagnostics()
    ad.parse_dependencies(a, diag=diag)
    assert not _internal(ad, "Microsoft.AspNetCore.Builder")
    assert any("outside the repository" in n for n in diag.notes)
    assert not any(str(tmp_path).replace("\\", "/") in n.replace("\\", "/")
                   for n in diag.notes)          # file NAME only, no machine path


def test_transitive_fwref_reference_output_assembly_false(tmp_path):
    _proj(tmp_path, "B", _ASP)
    a = _proj(tmp_path, "A",
              _projref("../B/B.csproj", ' ReferenceOutputAssembly="false"'))
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    ad.parse_dependencies(a, diag=Diagnostics())
    assert not _internal(ad, "Microsoft.AspNetCore.Builder")


def test_plain_sdk_no_provider_chain_stays_external(tmp_path):
    _proj(tmp_path, "B")                       # nothing to provide
    a = _proj(tmp_path, "A", _projref("../B/B.csproj"))
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    ad.parse_dependencies(a, diag=Diagnostics())
    assert not _internal(ad, "Microsoft.AspNetCore.Http.Features")


def test_tabi_shape_tests_project_inherits_from_sdk_web_api(tmp_path):
    """The literal Tabi case: Tests -> Api(Sdk.Web) => AspNetCore provided."""
    _proj(tmp_path, "backend/Tabi.Api", "", sdk="Microsoft.NET.Sdk.Web")
    tests = _proj(tmp_path, "backend/Tabi.Api.Tests",
                  _projref("../Tabi.Api/Tabi.Api.csproj"))
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    ad.parse_dependencies(tests, diag=Diagnostics())
    assert _internal(ad, "Microsoft.AspNetCore.Hosting")


# ── 2: npm_roots end-to-end ──────────────────────────────────────────────────

def test_npm_roots_e2e_creates_real_project_with_dep_audit(tmp_path):
    from auditor import cli
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "x.js").write_text("import wild from 'somewildpkg'\n",
                                encoding="utf-8")
    (tmp_path / ".auditor.toml").write_text(
        'schema_version = 1\nnpm_roots = ["tools"]\n', encoding="utf-8")
    out = tmp_path / "rep"
    cli.main(["scan", str(tmp_path), "--output", str(out),
              "--offline", "--no-semgrep"])
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    ts_projects = [p for p in data["projects"] if p["language"] == "typescript"]
    assert any(p["root"] == "tools" for p in ts_projects)   # a REAL project
    tools_f = [f for p in ts_projects if p["root"] == "tools"
               for f in p["findings"]]
    assert any(f["rule_id"].startswith("H") for f in tools_f)   # audit RAN
    execution = data["analysis_manifest"]["execution"]
    ts_exec = next(p for p in execution["projects"] if p["root"] == "tools")
    assert ts_exec["rules"]["H002"]["not_applicable_reasons"] == []


def test_npm_roots_nested_package_json_still_wins(tmp_path):
    """A nested real package.json inside a configured root keeps nearest-root
    ownership — nothing is scanned twice."""
    from auditor.adapters import default_adapters
    from auditor.discovery import discover_projects, project_files
    from auditor.config import AuditorConfig
    tools = tmp_path / "tools"
    inner = tools / "webapp"
    inner.mkdir(parents=True)
    (tools / "x.js").write_text("export {}\n", encoding="utf-8")
    (inner / "package.json").write_text('{"name":"webapp"}', encoding="utf-8")
    (inner / "y.ts").write_text("export {}\n", encoding="utf-8")
    adapters = default_adapters()
    for a in adapters:
        a.set_repo_root(tmp_path)
        a.apply_config(AuditorConfig(npm_roots=("tools",)))
    projects = discover_projects(tmp_path, adapters)
    ts = [(a, p) for a, p in projects if a.name == "typescript"]
    roots = sorted(p.relative_to(tmp_path).as_posix() for _, p in ts)
    assert "tools" in roots and "tools/webapp" in roots
    seen = {}
    for a, p in ts:
        for sf in project_files(p, a, projects):
            assert str(sf.path) not in seen
            seen[str(sf.path)] = p.name
    assert seen[str(tools / "x.js")] == "tools"
    assert seen[str(inner / "y.ts")] == "webapp"


def test_npm_roots_reject_globs_and_missing(tmp_path):
    (tmp_path / ".auditor.toml").write_text(
        'schema_version = 1\nnpm_roots = ["tools/*"]\n', encoding="utf-8")
    with pytest.raises(ConfigError) as ei:
        load_config(tmp_path)
    assert "globs are not allowed" in str(ei.value)
    (tmp_path / ".auditor.toml").write_text(
        'schema_version = 1\nnpm_roots = ["nope"]\n', encoding="utf-8")
    with pytest.raises(ConfigError) as ei:
        load_config(tmp_path)
    assert "does not exist" in str(ei.value)


# ── 3: ConfigError never echoes the rejected value ───────────────────────────

@pytest.mark.parametrize("value", [
    "C:/Users/private/repo",
    "/etc/private-secrets",
    "//server/share",
    "a/../SECRETDIR",
    "x\\\\SECRETWIN",
])
def test_config_error_never_echoes_rejected_value(tmp_path, value):
    (tmp_path / ".auditor.toml").write_text(
        f'schema_version = 1\nexclude_paths = ["{value}"]\n', encoding="utf-8")
    with pytest.raises(ConfigError) as ei:
        load_config(tmp_path)
    msg = str(ei.value)
    assert "exclude_paths contains an invalid entry" in msg
    for frag in ("private", "Users", "server", "SECRET", "etc"):
        assert frag not in msg          # no fragment of the value, ever


def test_config_lone_surrogate_rejected_without_crash():
    from auditor.config import _reject_path
    reason = _reject_path("x/bad\ud800")
    assert reason is not None and "UTF-8" in reason
    assert "\ud800" not in reason
