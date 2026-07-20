"""W2-B2.8A: package ownership (A1), framework providers (A2), and the
project config file (A3). All deterministic — no network, no binaries."""
import json

import pytest

from auditor.config import (
    AuditorConfig,
    ConfigError,
    any_match,
    is_vendored,
    load_config,
    path_matches,
)
from auditor.core.models import Diagnostics, ImportRef


def _ts():
    from auditor.adapters.typescript.adapter import TypeScriptAdapter
    return TypeScriptAdapter()


def _dotnet():
    from auditor.adapters.dotnet.adapter import DotnetAdapter
    return DotnetAdapter()


def _imp(module, top=None):
    return ImportRef(module=module, file="x", line=1,
                     top_level=top or module.split("/")[0].split(".")[0])


# ── A1: npm ownership ─────────────────────────────────────────────────────────

def test_npm_owned_project_keeps_dependency_audit(tmp_path):
    (tmp_path / "package.json").write_text('{"name":"a"}', encoding="utf-8")
    ad = _ts()
    ad.set_repo_root(tmp_path)
    assert ad.dependency_audit_reason(tmp_path) is None


def test_manifestless_js_never_npm_audited(tmp_path):
    """A Phoenix asset-pipeline script (no package.json anywhere near it) is
    NOT npm-owned: code rules may run, the npm registry must not."""
    (tmp_path / "assets").mkdir()
    ad = _ts()
    ad.set_repo_root(tmp_path)
    reason = ad.dependency_audit_reason(tmp_path / "assets")
    assert reason is not None
    assert "no npm package root" in reason


def test_config_npm_root_authorizes_manifestless_dir(tmp_path):
    (tmp_path / "tools").mkdir()
    ad = _ts()
    ad.set_repo_root(tmp_path)
    ad.apply_config(AuditorConfig(npm_roots=("tools",)))
    assert ad.dependency_audit_reason(tmp_path / "tools") is None
    assert ad.dependency_audit_reason(tmp_path) is not None   # root not listed


def test_k6_imports_are_runtime_builtins_not_npm():
    ad = _ts()
    assert ad.is_internal(_imp("k6/http", top="k6"))
    assert ad.is_internal(_imp("k6", top="k6"))
    assert not ad.is_internal(_imp("lodash", top="lodash"))


def test_config_runtime_builtins_extend_npm():
    ad = _ts()
    ad.apply_config(AuditorConfig(runtime_builtins={"npm": ("phoenix",)}))
    assert ad.is_internal(_imp("phoenix", top="phoenix"))
    assert ad.is_internal(_imp("k6/http", top="k6"))          # builtin stays


def test_config_internal_packages_component_boundary():
    ad = _ts()
    ad.apply_config(AuditorConfig(internal_packages={"npm": ("@acme", "corelib")}))
    assert ad.is_internal(_imp("@acme/ui", top="@acme/ui"))
    assert ad.is_internal(_imp("corelib", top="corelib"))
    assert not ad.is_internal(_imp("corelibx", top="corelibx"))   # boundary!


def test_vendored_files_are_dependency_excluded():
    assert is_vendored("assets/vendor/heroicons.js")
    assert is_vendored("src/vendored/x.ts")
    assert not is_vendored("src/app/vendorlist.ts")   # segment, not substring
    assert not is_vendored("vendor.js")               # a FILE named vendor.js


def test_manifestless_pipeline_no_npm_findings_code_rules_still_run(tmp_path):
    """END-TO-END: a repo whose only JS is a phoenix-style asset script gets
    NO H002/H008, records the dependency audit as not_applicable, and still
    runs code rules (a planted secret is found)."""
    from auditor import cli
    assets = tmp_path / "assets" / "js"
    assets.mkdir(parents=True)
    (assets / "app.js").write_text(
        'import {Socket} from "phoenix"\n'
        'import topbar from "topbar"\n'
        'const API_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")
    out = tmp_path / "rep"
    cli.main(["scan", str(tmp_path), "--output", str(out),
              "--offline", "--no-semgrep"])
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    all_f = [f for p in data["projects"] for f in p["findings"]]
    assert not any(f["rule_id"] in ("H002", "H007", "H008") for f in all_f)
    assert any(f["rule_id"] == "P002" for f in all_f)          # code rules ran
    execution = data["analysis_manifest"]["execution"]
    ts = next(p for p in execution["projects"] if p["language"] == "typescript")
    assert ts["rules"]["H002"]["status"] == "not_applicable"
    assert any("no npm package root" in r
               for r in ts["rules"]["H002"]["not_applicable_reasons"])


def test_monorepo_nearest_package_root_owns_no_double_scan(tmp_path):
    """Two packages: each file belongs to its NEAREST manifest; the fallback
    never owns nested-package files, and nothing is scanned twice."""
    from auditor.adapters import default_adapters
    from auditor.discovery import discover_projects, project_files
    for name in ("a", "b"):
        pkg = tmp_path / "packages" / name
        pkg.mkdir(parents=True)
        (pkg / "package.json").write_text(json.dumps({"name": name}),
                                          encoding="utf-8")
        (pkg / "index.ts").write_text("export const x = 1\n", encoding="utf-8")
    adapters = default_adapters()
    projects = discover_projects(tmp_path, adapters)
    ts_projects = [(a, p) for a, p in projects if a.name == "typescript"]
    seen: dict[str, str] = {}
    for a, p in ts_projects:
        for sf in project_files(p, a, projects):
            key = str(sf.path)
            assert key not in seen, f"{key} scanned by {seen[key]} AND {p}"
            seen[key] = str(p)
    assert len(seen) == 2                                   # both files, once each
    for path, owner in seen.items():
        assert ("packages" in owner), f"{path} owned by the fallback: {owner}"


def test_react_rules_still_run_on_eligible_files(tmp_path):
    """The ownership gate must not silence CODE rules on npm-owned files."""
    from auditor import cli
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "app", "dependencies": {"react": "18"}}),
        encoding="utf-8")
    (tmp_path / "App.tsx").write_text(
        "import {useState} from 'react'\n"
        "export default function App({flag}: {flag: boolean}) {\n"
        "  if (flag) { const [v] = useState(0) }\n"
        "  return null\n"
        "}\n", encoding="utf-8")
    out = tmp_path / "rep"
    cli.main(["scan", str(tmp_path), "--output", str(out),
              "--offline", "--no-semgrep"])
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    all_f = [f for p in data["projects"] for f in p["findings"]]
    assert any(f["rule_id"] == "R001" for f in all_f)


# ── A2: .NET FrameworkReference providers ────────────────────────────────────

def _csproj(tmp_path, body, sdk="Microsoft.NET.Sdk", name="App.csproj"):
    (tmp_path / name).write_text(
        f'<Project Sdk="{sdk}">\n<PropertyGroup>'
        "<TargetFramework>net8.0</TargetFramework></PropertyGroup>\n"
        f"{body}\n</Project>", encoding="utf-8")


def test_frameworkreference_provides_aspnetcore(tmp_path):
    _csproj(tmp_path,
            '<ItemGroup><FrameworkReference Include="Microsoft.AspNetCore.App" />'
            "</ItemGroup>")
    ad = _dotnet()
    ad.parse_dependencies(tmp_path, diag=Diagnostics())
    ad._own_namespaces = ()
    ad._old_tfm = False
    assert ad.is_internal(_imp("Microsoft.AspNetCore.Http.Features",
                               top="Microsoft.AspNetCore.Http.Features"))
    assert ad.is_internal(_imp("Microsoft.Extensions.Logging",
                               top="Microsoft.Extensions.Logging"))
    # NOT a blanket Microsoft.*: EF Core is a NuGet package, still external
    assert not ad.is_internal(_imp("Microsoft.EntityFrameworkCore",
                                   top="Microsoft.EntityFrameworkCore"))


def test_sdk_web_implies_aspnetcore_app(tmp_path):
    _csproj(tmp_path, "", sdk="Microsoft.NET.Sdk.Web")
    ad = _dotnet()
    ad.parse_dependencies(tmp_path, diag=Diagnostics())
    ad._own_namespaces = ()
    ad._old_tfm = False
    assert ad.is_internal(_imp("Microsoft.AspNetCore.Builder",
                               top="Microsoft.AspNetCore.Builder"))


def test_plain_sdk_without_frameworkref_stays_external(tmp_path):
    _csproj(tmp_path, "")                       # Microsoft.NET.Sdk, no fw ref
    ad = _dotnet()
    ad.parse_dependencies(tmp_path, diag=Diagnostics())
    ad._own_namespaces = ()
    ad._old_tfm = False
    assert not ad.is_internal(_imp("Microsoft.AspNetCore.Http.Features",
                                   top="Microsoft.AspNetCore.Http.Features"))


def test_frameworkreference_remove_cancels(tmp_path):
    _csproj(tmp_path,
            '<ItemGroup><FrameworkReference Include="Microsoft.AspNetCore.App" />'
            '<FrameworkReference Remove="Microsoft.AspNetCore.App" /></ItemGroup>')
    ad = _dotnet()
    ad.parse_dependencies(tmp_path, diag=Diagnostics())
    ad._own_namespaces = ()
    ad._old_tfm = False
    assert not ad.is_internal(_imp("Microsoft.AspNetCore.Builder",
                                   top="Microsoft.AspNetCore.Builder"))


def test_conditional_frameworkreference_possible_plus_incomplete(tmp_path):
    _csproj(tmp_path,
            '<ItemGroup Condition="\'$(X)\'==\'1\'">'
            '<FrameworkReference Include="Microsoft.AspNetCore.App" />'
            "</ItemGroup>")
    ad = _dotnet()
    diag = Diagnostics()
    ad.parse_dependencies(tmp_path, diag=diag)
    ad._own_namespaces = ()
    ad._old_tfm = False
    # POSSIBLE: suppresses a definitive H002 (internal), but the manifest is
    # flagged incomplete with a visible note — never a silent exact claim
    assert ad.is_internal(_imp("Microsoft.AspNetCore.Builder",
                               top="Microsoft.AspNetCore.Builder"))
    assert diag.manifest_incomplete
    assert any("FrameworkReference" in n for n in diag.notes)


def test_frameworkref_from_directory_build_props(tmp_path):
    (tmp_path / "Directory.Build.props").write_text(
        '<Project><ItemGroup>'
        '<FrameworkReference Include="Microsoft.AspNetCore.App" />'
        "</ItemGroup></Project>", encoding="utf-8")
    sub = tmp_path / "src"
    sub.mkdir()
    _csproj(sub, "")
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    ad.parse_dependencies(sub, diag=Diagnostics())
    ad._own_namespaces = ()
    ad._old_tfm = False
    assert ad.is_internal(_imp("Microsoft.AspNetCore.Http",
                               top="Microsoft.AspNetCore.Http"))


def test_frameworkreference_is_never_a_registry_candidate(tmp_path):
    """A FrameworkReference is a shared framework, not a NuGet package: it
    must not appear among declared deps sent to the registry."""
    _csproj(tmp_path,
            '<ItemGroup><FrameworkReference Include="Microsoft.AspNetCore.App" />'
            '<PackageReference Include="Serilog" /></ItemGroup>')
    ad = _dotnet()
    declared = ad.parse_dependencies(tmp_path, diag=Diagnostics())
    names = {d.name for d in declared}
    assert "Serilog" in names
    assert not any("aspnetcore.app" in n.lower() for n in names)


# ── A3: config file ───────────────────────────────────────────────────────────

def _write_cfg(tmp_path, body):
    (tmp_path / ".auditor.toml").write_text(body, encoding="utf-8")


def test_config_defaults_when_absent(tmp_path):
    cfg = load_config(tmp_path)
    assert cfg.exclude_paths == () and cfg.loaded_from == ""


def test_config_loads_known_schema(tmp_path):
    _write_cfg(tmp_path, """
schema_version = 1
exclude_paths = ["third_party", "docs/**"]
dependency_exclude_paths = ["assets/js"]
npm_roots = ["tools/scripts"]
complexity_threshold = 15
[runtime_builtins]
npm = ["phoenix"]
[internal_packages]
npm = ["@acme"]
pypi = ["acme-core"]
""")
    (tmp_path / "tools" / "scripts").mkdir(parents=True)
    cfg = load_config(tmp_path)
    assert cfg.exclude_paths == ("third_party", "docs/**")
    assert cfg.npm_roots == ("tools/scripts",)
    assert cfg.complexity_threshold == 15
    assert cfg.runtime_builtins["npm"] == ("phoenix",)
    assert cfg.internal_packages["pypi"] == ("acme-core",)


@pytest.mark.parametrize("body,needle", [
    ("schema_version = 2\n", "unsupported schema_version"),
    ("exclude_paths = ['x']\n", "unsupported schema_version"),   # missing version
    ("schema_version = 1\nunknown_key = 1\n", "unknown key"),
    ("schema_version = 1\nexclude_paths = 'x'\n", "list of strings"),
    ("schema_version = 1\nexclude_paths = ['C:/x']\n", "drive"),
    ("schema_version = 1\nexclude_paths = ['/abs']\n", "absolute"),
    ("schema_version = 1\nexclude_paths = ['a/../b']\n", "'..'"),
    ("schema_version = 1\nexclude_paths = ['a\\\\b']\n", "backslash"),
    ("schema_version = 1\ncomplexity_threshold = 0\n", "between 1 and 100"),
    ("schema_version = 1\ncomplexity_threshold = true\n", "between 1 and 100"),
    ("schema_version = 1\n[runtime_builtins]\nrust = ['x']\n", "unsupported ecosystem"),
    ("not toml [ at all\n", "not valid TOML"),
])
def test_config_rejects_malformed_loudly(tmp_path, body, needle):
    _write_cfg(tmp_path, body)
    with pytest.raises(ConfigError) as ei:
        load_config(tmp_path)
    assert needle in str(ei.value)


def test_explicit_config_path_missing_fails(tmp_path):
    with pytest.raises(ConfigError):
        load_config(tmp_path, explicit=str(tmp_path / "nope.toml"))


def test_path_matches_component_boundaries():
    assert path_matches("apps/api/x.ts", "apps/api")
    assert not path_matches("apps/api2/x.ts", "apps/api")     # no prefix bleed
    assert not path_matches("apps/ap", "apps/api")
    assert path_matches("apps/api", "apps/api")


def test_path_matches_globs_and_subtrees():
    assert path_matches("docs/a/b.md", "docs/**")
    assert path_matches("a/gen/x.ts", "*/gen")                # glob dir subtree
    assert path_matches("x/y.min.js", "**/*.min.js")
    assert not path_matches("src/genx/x.ts", "*/gen")


def test_exclude_paths_cannot_leak_into_sibling_projects():
    # 'apps/ap' must not exclude apps/api of a NEIGHBOR project
    assert not any_match("apps/api/index.ts", ("apps/ap",))
    assert any_match("apps/ap/index.ts", ("apps/ap",))


def test_e2e_exclude_and_dependency_exclude(tmp_path):
    """exclude_paths removes files entirely; dependency_exclude_paths keeps
    code rules (P002 fires) but no dependency findings from those files."""
    from auditor import cli
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "app"}), encoding="utf-8")
    (tmp_path / "main.ts").write_text(
        "import missingdep from 'missingdep'\n", encoding="utf-8")
    gen = tmp_path / "gen"
    gen.mkdir()
    (gen / "client.ts").write_text(
        "import wild from 'some-wild-generated-pkg'\n"
        'const API_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")
    dead = tmp_path / "dead"
    dead.mkdir()
    (dead / "old.ts").write_text('const PASSWORD = "hunter2secret"\n',
                                 encoding="utf-8")
    _write_cfg(tmp_path, 'schema_version = 1\nexclude_paths = ["dead"]\n'
                         'dependency_exclude_paths = ["gen"]\n')
    out = tmp_path / "rep"
    cli.main(["scan", str(tmp_path), "--output", str(out),
              "--offline", "--no-semgrep"])
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    all_f = [f for p in data["projects"] for f in p["findings"]]
    files = {f["file"] for f in all_f}
    assert not any(f.startswith("dead") for f in files)         # fully excluded
    # gen/: dependency finding suppressed, code rule kept
    assert not any(f["file"].startswith("gen") and f["rule_id"].startswith("H")
                   for f in all_f)
    assert any(f["file"].startswith("gen") and f["rule_id"] == "P002"
               for f in all_f)
    # main.ts keeps its offline dependency note (H003/H007 path still works)
    assert any(f["file"] == "main.ts" and f["rule_id"].startswith("H")
               for f in all_f)


def test_complexity_threshold_passthrough(tmp_path):
    from auditor import cli
    body = "def f(x):\n" + "".join(
        f"    if x == {i}:\n        x += {i}\n" for i in range(8)) + "    return x\n"
    (tmp_path / "app.py").write_text(body, encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("", encoding="utf-8")
    out1 = tmp_path / "r1"
    cli.main(["scan", str(tmp_path), "--output", str(out1), "--offline",
              "--no-semgrep"])
    d1 = json.loads((out1 / "report.json").read_text(encoding="utf-8"))
    p006_default = sum(1 for p in d1["projects"] for f in p["findings"]
                       if f["rule_id"] == "P006")
    _write_cfg(tmp_path, "schema_version = 1\ncomplexity_threshold = 5\n")
    out2 = tmp_path / "r2"
    cli.main(["scan", str(tmp_path), "--output", str(out2), "--offline",
              "--no-semgrep"])
    d2 = json.loads((out2 / "report.json").read_text(encoding="utf-8"))
    p006_low = sum(1 for p in d2["projects"] for f in p["findings"]
                   if f["rule_id"] == "P006")
    assert p006_default == 0 and p006_low == 1      # threshold took effect


def test_config_error_message_has_no_machine_path(tmp_path):
    _write_cfg(tmp_path, "schema_version = 99\n")
    with pytest.raises(ConfigError) as ei:
        load_config(tmp_path)
    msg = str(ei.value)
    assert "\\" not in msg and str(tmp_path) not in msg
