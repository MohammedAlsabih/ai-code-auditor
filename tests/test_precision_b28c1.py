"""W2-B2.8C1 — Precision Correction: safe/unsafe pairs for the five defects
found by the B2.8D quality baseline."""
import tempfile
from pathlib import Path

import pytest

from auditor.adapters.dotnet.adapter import DotnetAdapter
from auditor.adapters.dotnet.rules import RawSqlInterpolation
from auditor.core.models import ImportRef, SourceFile
from auditor.core.rules_common import SecretsRule, SqlStringBuild
from auditor.core.treesitter import parse_source


def _cs(code: str) -> SourceFile:
    sf = SourceFile(path=Path("f.cs"), rel="f.cs", language="csharp",
                    text=code.encode("utf-8"))
    parse_source(sf)
    return sf


def _tsx(code: str, rel="f.tsx") -> SourceFile:
    sf = SourceFile(path=Path(rel), rel=rel, language="tsx",
                    text=code.encode("utf-8"))
    parse_source(sf)
    return sf


def _ids(findings):
    return sorted(f.rule_id for f in findings)


def _sql(sf):
    return SqlStringBuild(DotnetAdapter().syntax()).check(sf)


# ═════ 1. credential severity restored ══════════════════════════════════════════

@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "[::1]"])
def test_c1_localhost_password_is_p002_error_exact(host):
    sf = _cs(f'var cs = "Host={host};Database=d;Username=u;Password=secretpw";\n')
    out = SecretsRule().check(sf)
    assert _ids(out) == ["P002"]
    assert out[0].severity.value == "red" and out[0].precision == "exact"


def test_c1_remote_password_still_p002():
    sf = _cs('var cs = "Server=db.prod.example.com;Uid=app;Password=hunter2pw";\n')
    assert _ids(SecretsRule().check(sf)) == ["P002"]


def test_c1_empty_or_missing_password_no_finding():
    assert SecretsRule().check(
        _cs('var cs = "Host=localhost;Database=d;Username=u;Password=";\n')) == []
    assert SecretsRule().check(
        _cs('var cs = "Host=localhost;Database=d;Trusted_Connection=true";\n')) == []


def test_c1_password_value_never_echoed():
    sf = _cs('var cs = "Host=localhost;Database=d;Username=u;'
             'Password=SuperSecretValue123";\n')
    out = SecretsRule().check(sf)
    assert "SuperSecretValue123" not in out[0].snippet
    assert "SuperSecretValue123" not in out[0].detail


def test_c1_production_guard_comment_does_not_change_level():
    sf = _cs('conn = "Host=localhost;Database=d;Username=u;Password=devpw"; '
             '// dev only, throws in production\n')
    out = SecretsRule().check(sf)
    assert _ids(out) == ["P002"] and out[0].severity.value == "red"


# ═════ 2. EF parameterizing sinks clear P005 ════════════════════════════════════

def test_c1_execute_sql_interpolated_is_parameterized():
    # the Tabi TaskComputedStateTests shape
    sf = _cs('class A { async Task F(DbContext ctx, object ts, int id) {\n'
             '  await ctx.Database.ExecuteSqlInterpolatedAsync('
             '$"UPDATE tasks SET created_at = {ts} WHERE id = {id}");\n'
             '} }')
    assert _sql(sf) == []
    assert RawSqlInterpolation().check(sf) == []


def test_c1_from_sql_interpolated_on_dbset_is_parameterized():
    sf = _cs('class A { void F(DbContext ctx, int id) {\n'
             '  var q = ctx.Tasks.FromSqlInterpolated($"SELECT * FROM t WHERE id = {id}");\n'
             '} }')
    assert _sql(sf) == []


def test_c1_execute_sql_raw_with_interpolation_still_p005():
    sf = _cs('class A { async Task F(DbContext ctx, string t) {\n'
             '  await ctx.Database.ExecuteSqlRawAsync($"DELETE FROM {t}");\n'
             '} }')
    # raw sink: D003 fires; the generic SQL rule also sees composition→sink
    assert "D003" in _ids(RawSqlInterpolation().check(sf))
    assert "P005" in _ids(_sql(sf))


def test_c1_custom_method_named_like_ef_is_not_exempt():
    # a bare-identifier receiver (not .Database / not a DbSet member) with the
    # same name gets NO EF exemption
    sf = _cs('class A { async Task F(string t) {\n'
             '  await ExecuteSqlInterpolatedAsync($"DELETE FROM {t}");\n'
             '} }')
    assert "P005" in _ids(_sql(sf))


def test_c1_execute_interpolated_not_on_database_is_not_exempt():
    sf = _cs('class A { async Task F(Helper h, string t) {\n'
             '  await h.Runner.ExecuteSqlInterpolatedAsync($"DELETE FROM {t}");\n'
             '} }')
    assert "P005" in _ids(_sql(sf))


def test_c1_ef_positional_placeholders_with_params_stay_clean():
    sf = _cs('class A { void F(DbContext db, object p) {\n'
             '  db.Database.ExecuteSqlRaw("SELECT pg_advisory_xact_lock({0})", [p]);\n'
             '} }')
    assert RawSqlInterpolation().check(sf) == []


# ═════ 3. R003 Storybook / renderHook ══════════════════════════════════════════

def _r003(sf):
    from auditor.adapters.typescript.react_rules import HookOutsideComponent
    return _ids(HookOutsideComponent().check(sf))


def test_c1_storybook_render_with_import_is_component():
    # a proven story via StoryObj type annotation (closing round tightened the
    # bar: a bare exported object with render is no longer enough)
    sf = _tsx('import type { Meta, StoryObj } from "@storybook/react";\n'
              'export const Default: StoryObj = { render: () => { '
              'const [x, setX] = React.useState(0); return null; } };\n',
              rel="button.stories.tsx")
    assert _r003(sf) == []


def test_c1_render_without_storybook_evidence_stays_r003():
    sf = _tsx('export const Thing = { render: () => { '
              'const [x, setX] = React.useState(0); return null; } };\n',
              rel="thing.ts")
    assert _r003(sf) == ["R003"]


def test_c1_renderhook_from_testing_library_is_hook_context():
    sf = _tsx('import { renderHook } from "@testing-library/react";\n'
              'test("x", () => { const { result } = renderHook(() => usePagedList(1)); });\n')
    assert _r003(sf) == []


def test_c1_local_renderhook_not_exempt():
    sf = _tsx('function renderHook(fn: any) { return fn(); }\n'
              'const r = renderHook(() => useThing());\n')
    assert _r003(sf) == ["R003"]


def test_c1_hook_in_nested_non_component_helper_still_r003():
    sf = _tsx('import { renderHook } from "@testing-library/react";\n'
              'function Comp() { function helper() { '
              'const [x] = React.useState(0); return x; } return helper(); }\n')
    assert _r003(sf) == ["R003"]


# ═════ 4. R005 member-path deps ═════════════════════════════════════════════════

def _r005(sf):
    from auditor.adapters.typescript.react_rules import EffectDeps
    return _ids(EffectDeps().check(sf))


def test_c1_optional_and_plain_member_dep_cover_the_read():
    for dep in ("client.costModel", "client?.costModel"):
        sf = _tsx('function Page({ client }: any) {\n'
                  '  React.useEffect(() => { if (client?.costModel) '
                  f'setCm(client.costModel); }}, [{dep}]);\n'
                  '  return null;\n}\n')
        assert "R005" not in _r005(sf), dep


def test_c1_broader_object_dep_covers_member_read():
    sf = _tsx('function Page({ client }: any) {\n'
              '  React.useEffect(() => { setCm(client.costModel); }, [client]);\n'
              '  return null;\n}\n')
    assert "R005" not in _r005(sf)


def test_c1_sibling_member_dep_does_not_cover():
    sf = _tsx('function Page({ client }: any) {\n'
              '  React.useEffect(() => { if (client.costModel) '
              'setCm(client.costModel); }, [client.other]);\n'
              '  return null;\n}\n')
    assert _r005(sf) == ["R005"]


def test_c1_genuine_missing_dep_still_fires():
    sf = _tsx('function Map({ lat, lng }: any) {\n'
              '  const [r, setR] = React.useState(false);\n'
              '  React.useEffect(() => { const c = lat != null ? '
              '{ lat, lng } : null; }, []);\n'
              '  return null;\n}\n')
    assert _r005(sf) == ["R005"]


def test_c1_whole_object_read_needs_whole_object_dep():
    # reading the whole `client` while depending only on client.costModel is a
    # real missing dep — conservative, not silenced
    sf = _tsx('function Page({ client }: any) {\n'
              '  React.useEffect(() => { send(client); }, [client.costModel]);\n'
              '  return null;\n}\n')
    assert _r005(sf) == ["R005"]


# ═════ 5. H007 ProjectReference closure ═════════════════════════════════════════

def _dotnet_project(refs: bool):
    tmp = Path(tempfile.mkdtemp())
    for d in ("Api", "Lib", "Orphan"):
        (tmp / d).mkdir()
    ref = ('<ItemGroup><ProjectReference Include="../Lib/Lib.csproj"/>'
           '</ItemGroup>') if refs else ""
    (tmp / "Api" / "Api.csproj").write_text(
        f'<Project Sdk="Microsoft.NET.Sdk">{ref}</Project>', encoding="utf-8")
    (tmp / "Lib" / "Lib.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
        '<RootNamespace>Acme.Lib</RootNamespace></PropertyGroup></Project>',
        encoding="utf-8")
    (tmp / "Orphan" / "Orphan.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
        '<RootNamespace>Acme.Orphan</RootNamespace></PropertyGroup></Project>',
        encoding="utf-8")
    prog = tmp / "Api" / "Program.cs"
    prog.write_text("namespace Acme.Api;\nclass P {}\n", encoding="utf-8")
    sf = SourceFile(path=prog, rel="Program.cs", language="csharp",
                    text=prog.read_bytes())
    parse_source(sf)
    a = DotnetAdapter()
    a.set_repo_root(tmp)
    a.prepare(tmp / "Api", [sf])
    return a


def _imp(m):
    return ImportRef(module=m, file="x.cs", line=1, top_level=m)


def test_c1_referenced_namespace_internal_unreferenced_stays_h007():
    a = _dotnet_project(refs=True)
    assert a.is_internal(_imp("Acme.Api.X"))          # own
    assert a.is_internal(_imp("Acme.Lib.Widgets"))    # referenced
    assert not a.is_internal(_imp("Acme.Orphan.Y"))   # exists, NOT referenced
    assert not a.is_internal(_imp("Contoso.Sdk"))     # external


def test_c1_no_reference_means_sibling_not_suppressed():
    a = _dotnet_project(refs=False)
    assert a.is_internal(_imp("Acme.Api.X"))          # own always internal
    assert not a.is_internal(_imp("Acme.Lib.Widgets"))  # no ref → visible H007
    assert not a.is_internal(_imp("Acme.Orphan.Y"))


# ═════ CLOSING ROUND regressions ═══════════════════════════════════════════════

def test_c1close_custom_from_sql_interpolated_not_ef_stays_p005():
    # member-access receiver + EF name is NOT proof of a DbSet
    sf = _cs('class A { void F(Helper h, string t) {\n'
             '  h.Runner.FromSqlInterpolated($"DELETE FROM {t}");\n} }')
    assert "P005" in _ids(_sql(sf))


def test_c1close_from_sql_interpolated_on_dbcontext_typed_root_is_clean():
    # final closing: the receiver root must be a PROVEN DbContext (bare
    # DbContext or a class that derives from it), not a *Context suffix
    sf = _cs('class AppDbContext : DbContext {}\n'
             'class A { void F(AppDbContext ctx, int id) {\n'
             '  var q = ctx.Tasks.FromSqlInterpolated($"SELECT * FROM t WHERE id = {id}");\n'
             '} }')
    assert _sql(sf) == []


def test_c1close_execute_interpolated_on_dbcontext_still_clean():
    sf = _cs('class A { async Task F(TabiDbContext _ctx, object ts, int id) {\n'
             '  await _ctx.Database.ExecuteSqlInterpolatedAsync('
             '$"UPDATE t SET a = {ts} WHERE id = {id}");\n} }')
    assert _sql(sf) == []


def test_c1close_renderhook_from_local_module_stays_r003():
    sf = _tsx('import { renderHook } from "./local";\n'
              'import { screen } from "@testing-library/react";\n'
              'const r = renderHook(() => useThing());\n')
    assert _r003(sf) == ["R003"]


def test_c1close_shadowed_renderhook_stays_r003():
    sf = _tsx('import { renderHook } from "@testing-library/react";\n'
              'function f() { const renderHook = (fn: any) => fn(); '
              'return renderHook(() => useThing()); }\n')
    assert _r003(sf) == ["R003"]


def test_c1close_renderhook_alias_from_testing_library_is_clean():
    sf = _tsx('import { renderHook as rh } from "@testing-library/react";\n'
              'const r = rh(() => useThing());\n')
    assert _r003(sf) == []


def test_c1close_storybook_helper_render_not_exported_stays_r003():
    sf = _tsx('import type { Meta } from "@storybook/react";\n'
              'const helper = { render: () => useThing() };\n', rel="c.stories.tsx")
    assert _r003(sf) == ["R003"]


def test_c1close_exported_story_render_via_default_meta_is_clean():
    # a proven CSF module (default meta export) — its named exports are stories
    sf = _tsx('import type { Meta } from "@storybook/react";\n'
              'const meta: Meta = { title: "X" };\nexport default meta;\n'
              'export const Primary = { render: () => { '
              'const [x] = React.useState(0); return null; } };\n', rel="c.stories.tsx")
    assert _r003(sf) == []


def test_c1close_exported_story_render_via_satisfies_is_clean():
    sf = _tsx('import type { StoryObj } from "@storybook/react";\n'
              'export const Default = { render: () => { '
              'const [x] = React.useState(0); return null; } } satisfies StoryObj;\n',
              rel="c.stories.tsx")
    assert _r003(sf) == []


def _dotnet_at(csproj_bodies: dict, ref_from: str, program_ns="Acme.Api"):
    """Build a repo from {relpath: csproj_xml}; scan the Api project."""
    tmp = Path(tempfile.mkdtemp())
    for rel, xml in csproj_bodies.items():
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(xml, encoding="utf-8")
    api_dir = tmp / ref_from
    prog = api_dir / "Program.cs"
    prog.write_text(f"namespace {program_ns};\nclass P {{}}\n", encoding="utf-8")
    sf = SourceFile(path=prog, rel="Program.cs", language="csharp",
                    text=prog.read_bytes())
    parse_source(sf)
    a = DotnetAdapter()
    a.set_repo_root(tmp)
    a.prepare(api_dir, [sf])
    return a


def test_c1close_conditional_reference_not_definite_internal():
    a = _dotnet_at({
        "Api/Api.csproj": '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup '
        'Condition="\'$(X)\'==\'1\'"><ProjectReference '
        'Include="../Cond/Cond.csproj"/></ItemGroup></Project>',
        "Cond/Cond.csproj": '<Project Sdk="Microsoft.NET.Sdk"/>',
    }, "Api")
    # a possible (conditional) edge does not definitely-suppress
    assert not a.is_internal(_imp("Cond.Thing"))


def test_c1close_reference_in_second_csproj_of_dir_not_lost():
    a = _dotnet_at({
        # the Api directory has TWO csprojs; the reference is in the second
        "Api/First.csproj": '<Project Sdk="Microsoft.NET.Sdk"/>',
        "Api/Second.csproj": '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>'
        '<ProjectReference Include="../Lib/Lib.csproj"/></ItemGroup></Project>',
        "Lib/Lib.csproj": '<Project Sdk="Microsoft.NET.Sdk"/>',
    }, "Api")
    assert a.is_internal(_imp("Lib.Widgets"))       # reference not lost


def test_c1close_project_reference_in_directory_build_props_enters_closure():
    a = _dotnet_at({
        "Api/Api.csproj": '<Project Sdk="Microsoft.NET.Sdk"/>',
        "Api/Directory.Build.props": '<Project><ItemGroup>'
        '<ProjectReference Include="../Shared/Shared.csproj"/></ItemGroup></Project>',
        "Shared/Shared.csproj": '<Project Sdk="Microsoft.NET.Sdk"/>',
    }, "Api")
    assert a.is_internal(_imp("Shared.Utils"))


# ═════ FINAL closing regressions ══════════════════════════════════════════════

def test_final_fake_context_suffix_not_ef_stays_p005():
    # a *Context type that does NOT derive from DbContext is not EF
    sf = _cs('class FakeContext {}\n'
             'class A { void F(FakeContext ctx, string t) {\n'
             '  ctx.Runner.FromSqlInterpolated($"DELETE FROM {t}");\n} }')
    assert "P005" in _ids(_sql(sf))


def test_final_real_dbcontext_descendant_from_is_clean():
    sf = _cs('class BaseCtx : DbContext {}\n'
             'class AppDbContext : BaseCtx {}\n'   # transitive derivation
             'class A { void F(AppDbContext ctx, int id) {\n'
             '  var q = ctx.Tasks.FromSqlInterpolated($"SELECT * FROM t WHERE id = {id}");\n'
             '} }')
    assert _sql(sf) == []


def test_final_wrong_imported_symbol_aliased_to_renderhook_stays_r003():
    sf = _tsx('import { somethingElse as renderHook } from "@testing-library/react";\n'
              'const r = renderHook(() => useThing());\n')
    assert _r003(sf) == ["R003"]


def test_final_nested_sibling_decl_does_not_shadow_outer_import():
    sf = _tsx('import { renderHook } from "@testing-library/react";\n'
              'function outer() {\n'
              '  function inner() { const renderHook = (fn: any) => fn(); '
              'return renderHook(() => 1); }\n'
              '  return renderHook(() => useThing());\n'   # real import here
              '}\n')
    assert _r003(sf) == []


def test_final_exported_non_story_helper_stays_r003():
    # Storybook import + export, but no type / satisfies / default meta
    sf = _tsx('import type { Meta } from "@storybook/react";\n'
              'export const helper = { render: () => useThing() };\n',
              rel="x.stories.tsx")
    assert _r003(sf) == ["R003"]


def test_c1_reference_output_assembly_false_not_followed():
    tmp = Path(tempfile.mkdtemp())
    for d in ("Api", "Lib"):
        (tmp / d).mkdir()
    (tmp / "Api" / "Api.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>'
        '<ProjectReference Include="../Lib/Lib.csproj" '
        'ReferenceOutputAssembly="false"/></ItemGroup></Project>',
        encoding="utf-8")
    (tmp / "Lib" / "Lib.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk"/>', encoding="utf-8")
    prog = tmp / "Api" / "Program.cs"
    prog.write_text("namespace Acme.Api;\nclass P {}\n", encoding="utf-8")
    sf = SourceFile(path=prog, rel="Program.cs", language="csharp",
                    text=prog.read_bytes())
    parse_source(sf)
    a = DotnetAdapter()
    a.set_repo_root(tmp)
    a.prepare(tmp / "Api", [sf])
    # ReferenceOutputAssembly=false carries no compile reference → Lib not internal
    assert not a.is_internal(_imp("Lib.Thing"))
