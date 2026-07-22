"""W2-B2.8C — Precision Hardening: deterministic SAFE/UNSAFE pairs.

Every benchmark disappearance is tied here to its structural cause, and every
safe pattern has a dangerous counterpart that MUST stay detected."""
from pathlib import Path

import pytest

from auditor.adapters.dotnet.adapter import DotnetAdapter
from auditor.adapters.dotnet.rules import RawSqlInterpolation
from auditor.core.models import SourceFile
from auditor.core.rules_common import SecretsRule, SmellComments, SqlStringBuild
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


def _py(code: str, rel="f.py") -> SourceFile:
    sf = SourceFile(path=Path(rel), rel=rel, language="python",
                    text=code.encode("utf-8"))
    parse_source(sf)
    return sf


def _sql_rules(sf):
    return SqlStringBuild(DotnetAdapter().syntax()).check(sf)


def _ids(findings):
    return sorted(f.rule_id for f in findings)


# ═════ A. SQL precision — P004/P005 ═════════════════════════════════════════════

def test_a_literal_only_concat_is_constant_sql():
    # the madar AttendanceAbsenceService shape: parameterized SQL split over
    # literals with @params in a separate object — compile-time constant
    sf = _cs('''class A { async Task F(IDbConnection conn, string t) {
        await conn.ExecuteAsync(new CommandDefinition(
            "SELECT \\"Id\\" FROM emp.employees WHERE \\"TenantId\\" = @T " +
            "AND (\\"HireDate\\" IS NULL OR \\"HireDate\\" <= @D::date)",
            new { T = t }));
    } }''')
    assert _sql_rules(sf) == []


def test_a_unsafe_concat_with_variable_still_p005():
    sf = _cs('''class A { async Task F(IDbConnection conn, string name) {
        await conn.ExecuteAsync(
            "SELECT * FROM users WHERE name = '" + name + "'");
    } }''')
    assert _ids(_sql_rules(sf)) == ["P005"]


def test_a_generic_call_parse_artifact_is_not_composition():
    # `<string?>` parses as a `<`-binary artifact wrapping constant SQL —
    # never P004/P005
    sf = _cs('''class A { async Task F(IDbConnection conn) {
        var x = await conn.ExecuteScalarAsync<string?>(new CommandDefinition(
            "SELECT \\"FullName\\" FROM emp.employees WHERE \\"Id\\" = @Id",
            new { Id = 1 }));
    } }''')
    assert _sql_rules(sf) == []


def test_a_interpolation_of_ef_model_metadata_is_trusted():
    # the madar RowLevelSecurity shape
    sf = _cs('''class A { async Task F(DbContext db, CancellationToken ct) {
        foreach (var e in db.Model.GetEntityTypes()) {
            var schema = e.GetSchema() ?? "public";
            var table = e.GetTableName();
            var q = $"\\"{schema}\\".\\"{table}\\"";
            await db.Database.ExecuteSqlRawAsync(
                $"SELECT 1 FROM {q} WHERE 1=0;", ct);
        }
    } }''')
    assert _sql_rules(sf) == []
    assert RawSqlInterpolation().check(sf) == []


def test_a_interpolation_of_parameter_still_flagged():
    sf = _cs('''class A { async Task F(DbContext db, string table) {
        await db.Database.ExecuteSqlRawAsync(
            $"SELECT * FROM {table} WHERE 1=0;");
    } }''')
    assert _ids(RawSqlInterpolation().check(sf)) == ["D003"]
    assert "P005" in _ids(_sql_rules(sf)) or "P004" in _ids(_sql_rules(sf))


def test_a_local_helper_with_literal_call_sites_is_trusted():
    # the madar Reporting `Scoped` shape
    sf = _cs('''class A { async Task F(IDbConnection conn, string[] codesArr) {
        string Scoped(string col) => codesArr is null ? "TRUE" : $"{col} = ANY(@codes)";
        var n = await conn.ExecuteScalarAsync<long>(
            $"SELECT COUNT(*) FROM org.tenants WHERE {Scoped("\\"Code\\"")};");
    } }''')
    assert _sql_rules(sf) == []


def test_a_local_helper_with_variable_call_site_stays_flagged():
    sf = _cs('''class A { async Task F(IDbConnection conn, string userCol) {
        string Scoped(string col) => $"{col} = ANY(@codes)";
        var n = await conn.ExecuteScalarAsync<long>(
            $"SELECT COUNT(*) FROM org.tenants WHERE {Scoped(userCol)};");
    } }''')
    assert "P005" in _ids(_sql_rules(sf))


def test_a_mapget_wrapper_is_never_the_sink():
    # dynamic SQL inside a route lambda, handed to a NON-sink helper: the
    # outer MapGet must not be attributed as the execution sink (P004, not
    # P005) — while a REAL sink inside the same lambda still gives P005
    outer = _cs('''class A { void F(WebApplication app) {
        app.MapExecuteGet("/x", async (string v) => {
            var sql = "SELECT * FROM t WHERE a = '" + v + "'";
            await Helper.Send(sql);
        });
    } }''')
    assert _ids(_sql_rules(outer)) == ["P004"]
    inner = _cs('''class A { void F(WebApplication app) {
        app.MapGet("/x", async (IDbConnection conn, string v) => {
            await conn.ExecuteAsync("SELECT * FROM t WHERE a = '" + v + "'");
        });
    } }''')
    assert _ids(_sql_rules(inner)) == ["P005"]


# ═════ A. SQL precision — D003 ══════════════════════════════════════════════════

def test_a_ef_placeholders_with_separate_args_are_constant():
    # the madar InvoiceNumbering shape: {0}/{1} placeholders live inside a RAW
    # LITERAL; `??` in a PARAMETER argument is not SQL composition
    sf = _cs('''class A { async Task F(DbContext db, object? op, long k, CancellationToken ct) {
        await db.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock({0})", [k], ct);
        await foreach (var row in db.Database.SqlQueryRaw<long>(
            """
            INSERT INTO gl.document_sequences ("Id","OperatorOrgId")
            VALUES (gen_random_uuid(), {0}) RETURNING "Id"
            """, (object?)op ?? DBNull.Value).AsAsyncEnumerable()) { break; }
    } }''')
    assert RawSqlInterpolation().check(sf) == []


def test_a_d003_interpolated_sql_argument_still_flagged():
    sf = _cs('''class A { void F(DbContext db, string t) {
        db.Database.ExecuteSqlRaw($"DELETE FROM {t}");
    } }''')
    assert _ids(RawSqlInterpolation().check(sf)) == ["D003"]


def test_a_d003_concatenated_sql_argument_still_flagged():
    sf = _cs('''class A { void F(DbContext db, string t) {
        db.Database.ExecuteSqlRaw("DELETE FROM " + t);
    } }''')
    assert _ids(RawSqlInterpolation().check(sf)) == ["D003"]


# ═════ B. R007 — sanitizer / <style> proofs ═════════════════════════════════════

def _r007(sf, files=None):
    from auditor.adapters.typescript.dom_safety import attach_index, build_safety_index
    from auditor.adapters.typescript.react_rules import DangerousInnerHtml
    group = files if files is not None else [sf]
    attach_index(group, build_safety_index(group))
    return DangerousInnerHtml().check(sf)


DOMPURIFY_WRAPPER = '''
import DOMPurify from "dompurify";
export function sanitizeHtml(html: string | null): string {
  if (typeof window === "undefined") return "";
  return DOMPurify.sanitize(html ?? "", { ALLOWED_TAGS: ["p"] });
}
'''


def test_b_dompurify_wrapper_through_usememo_is_clean():
    sf = _tsx(DOMPURIFY_WRAPPER + '''
import * as React from "react";
export function Viewer({ html }: { html: string }) {
  const clean = React.useMemo(() => sanitizeHtml(html), [html]);
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
''')
    assert _r007(sf) == []


def test_b_direct_dompurify_call_is_clean():
    # closing-round case 3: the DIRECT member call itself must be clean
    sf = _tsx('''
import DOMPurify from "dompurify";
export function V({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
}
''')
    assert _r007(sf) == []
    # and through a local wrapper
    sf2 = _tsx('''
import DOMPurify from "dompurify";
function clean(x: string) { return DOMPurify.sanitize(x); }
export function V({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: clean(html) }} />;
}
''')
    assert _r007(sf2) == []
    # without the real import, a direct-looking member call proves nothing
    sf3 = _tsx('''
const DOMPurify = { sanitize: (x: string) => x };
export function V({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
}
''')
    assert _ids(_r007(sf3)) == ["R007"]


def test_b_fake_sanitizer_name_stays_flagged():
    # no DOMPurify import — a "sanitize" NAME proves nothing
    sf = _tsx('''
function sanitizeHtml(html: string) { return html; }
export function V({ html }: { html: string }) {
  const clean = sanitizeHtml(html);
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
''')
    assert _ids(_r007(sf)) == ["R007"]


def test_b_wrapper_not_returning_sanitizer_output_stays_flagged():
    # DOMPurify imported, but the wrapper leaks the raw value on one path
    sf = _tsx('''
import DOMPurify from "dompurify";
function sanitizeHtml(html: string) {
  if (html.length < 10) return html;
  return DOMPurify.sanitize(html);
}
export function V({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: sanitizeHtml(html) }} />;
}
''')
    assert _ids(_r007(sf)) == ["R007"]


HEX_LIB = '''
const HEX = /^#[0-9a-fA-F]{6}$/;
export const safeHex = (c: string | null | undefined, fallback = "#1b2ac2"): string =>
  c && HEX.test(c.trim()) ? c.trim() : fallback;
export function brandStyleCss(primaryRaw: string, secondaryRaw?: string | null): string {
  const primary = safeHex(primaryRaw);
  const secondary = secondaryRaw && HEX.test(secondaryRaw.trim()) ? secondaryRaw.trim() : null;
  const end = secondary || `color-mix(in srgb, ${primary} 72%, #000)`;
  return `:root{--fill-brand:${primary};--grad:linear-gradient(90deg,${primary} 0%,${end} 100%);}`;
}
'''


def test_b_style_element_with_hex_gated_builder_is_clean():
    lib = _tsx(HEX_LIB, rel="lib/brand.tsx")
    page = _tsx('''
import { brandStyleCss } from "@/lib/brand";
export default function Layout({ brand }: any) {
  return (
    <head>
      <style dangerouslySetInnerHTML={{ __html: brandStyleCss(brand.p, brand.s) }} />
    </head>
  );
}
''', rel="app/layout.tsx")
    assert _r007(page, files=[lib, page]) == []


def test_b_style_element_with_unguarded_value_stays_flagged():
    lib = _tsx('''
export function rawCss(v: string): string {
  return `:root{--x:${v};}`;
}
''', rel="lib/raw.tsx")
    page = _tsx('''
import { rawCss } from "@/lib/raw";
export default function L({ v }: any) {
  return <style dangerouslySetInnerHTML={{ __html: rawCss(v) }} />;
}
''', rel="app/l.tsx")
    assert _ids(_r007(page, files=[lib, page])) == ["R007"]


def test_b_css_proof_never_clears_a_div():
    # the hex-gate proof applies to the <style> CSS context ONLY
    lib = _tsx(HEX_LIB, rel="lib/brand.tsx")
    page = _tsx('''
import { brandStyleCss } from "@/lib/brand";
export default function L({ b }: any) {
  return <div dangerouslySetInnerHTML={{ __html: brandStyleCss(b.p, b.s) }} />;
}
''', rel="app/d.tsx")
    assert _ids(_r007(page, files=[lib, page])) == ["R007"]


def test_b_direct_user_html_stays_flagged():
    sf = _tsx('''
export function V({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
''')
    assert _ids(_r007(sf)) == ["R007"]


# ═════ C. P007 — placeholder noise ══════════════════════════════════════════════

@pytest.mark.parametrize("line", [
    '<input placeholder="Search…" />',
    'placeholder?: string;',
    'const cls = "placeholder:text-slate-400";',
    't("form.placeholder.name")',
    'export function Placeholder({ placeholder }: Props) { return null; }',
    'msg = "أدخل النص placeholder هنا"',
])
def test_c_placeholder_vocabulary_is_not_a_marker(line):
    assert SmellComments().check(_tsx(line + "\n")) == []


@pytest.mark.parametrize("line,lang", [
    ("// TODO: implement error handling", "tsx"),
    ("# FIXME: broken on empty input", "python"),
    ("// HACK: bypasses validation", "tsx"),
    ("# placeholder implementation until the API lands", "python"),
    ("// temporary stub for the payment flow", "tsx"),
    ("// not implemented yet", "tsx"),
])
def test_c_real_markers_in_comments_still_fire(line, lang):
    sf = _tsx(line + "\n") if lang == "tsx" else _py(line + "\n")
    assert _ids(SmellComments().check(sf)) == ["P007"]


def test_c_todo_inside_a_string_is_not_a_comment_marker():
    assert SmellComments().check(_py('x = "TODO: implement"\n')) == []


# ═════ E. blockers — PEM / localhost creds / N001 ═══════════════════════════════

def test_e_mangled_pem_is_not_a_secret():
    # the madar JwtRs256Tests shape: literal \n and a garbage body
    code = ('var pem = "-----BEGIN PRIVATE KEY-----\\\\nMIIBROKEN\\\\n'
            '-----END PRIVATE KEY-----";\n')
    assert SecretsRule().check(_cs(code)) == []


def test_e_real_pem_stays_detected_and_masked():
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ" + "A" * 20
    code = f'var pem = "-----BEGIN PRIVATE KEY-----\\\\n{body}\\\\n-----END PRIVATE KEY-----";\n'
    out = SecretsRule().check(_cs(code))
    assert _ids(out) == ["P002"]
    assert body not in out[0].snippet          # masked


def test_e_multiline_real_pem_stays_detected():
    code = ("-----BEGIN RSA PRIVATE KEY-----\n"
            + "MIIEpAIBAAKCAQEA7v5x" + "B" * 40 + "\n"
            + "-----END RSA PRIVATE KEY-----\n")
    assert _ids(SecretsRule().check(_py(code))) == ["P002"]


def test_e_localhost_dev_connection_string_reviews_not_blocks():
    sf = _cs('var cs = "Host=localhost;Port=5432;Database=d;Username=postgres;'
             'Password=postgres";\n')
    out = SecretsRule().check(sf)
    assert _ids(out) == ["P003"]
    assert out[0].severity.value == "yellow"
    assert "postgres" not in out[0].snippet.split("Password=")[-1][:9] or \
        "***" in out[0].snippet


def test_e_remote_connection_string_password_still_blocks():
    sf = _cs('var cs = "Host=db.prod.example.com;Database=d;Username=app;'
             'Password=hunter2secret";\n')
    assert _ids(SecretsRule().check(sf)) == ["P002"]


def test_e_n001_name_only_is_review_grade():
    from auditor.adapters.typescript.next_rules import PublicEnvSecret
    sf = _tsx('const KEY = process.env.NEXT_PUBLIC_GOOGLE_MAPS_API_KEY ?? "";\n')
    out = PublicEnvSecret().check(sf)
    assert _ids(out) == ["N001"]
    assert out[0].severity.value == "yellow"
    assert out[0].precision == "heuristic"


def test_e_n001_env_value_with_real_token_stays_error(tmp_path):
    from auditor.adapters.typescript.next_rules import scan_one_env_file
    env = tmp_path / ".env.local"
    env.write_text("NEXT_PUBLIC_API_TOKEN=sk-live-" + "a1B2" * 8 + "\n",
                   encoding="utf-8")
    out = scan_one_env_file(env)
    assert _ids(out) == ["N001"] and out[0].severity.value == "red"
    name_only = tmp_path / ".env"
    name_only.write_text("NEXT_PUBLIC_MAPS_API_KEY=AIzaNotARealShape\n",
                         encoding="utf-8")
    out2 = scan_one_env_file(name_only)
    assert _ids(out2) == ["N001"] and out2[0].severity.value == "yellow"


# ═════ closing-round regressions (the six literal counter-cases) ═══════════════

def test_close1_name_collision_across_files_does_not_leak_proof():
    safe = _tsx('import DOMPurify from "dompurify";\n'
                'export function clean(x: string) { return DOMPurify.sanitize(x); }\n',
                rel="lib/safe.tsx")
    unsafe = _tsx('function clean(x: string) { return x; }\n'
                  'export function V({ html }: any) {\n'
                  '  return <div dangerouslySetInnerHTML={{ __html: clean(html) }} />;\n'
                  '}\n', rel="app/evil.tsx")
    # both file orders: the proof is scoped to lib/safe.tsx, never to a name
    assert _ids(_r007(unsafe, files=[safe, unsafe])) == ["R007"]
    assert _ids(_r007(unsafe, files=[unsafe, safe])) == ["R007"]
    # while a REAL import of the proven symbol stays clean
    importer = _tsx('import { clean } from "@/lib/safe";\n'
                    'export function V({ html }: any) {\n'
                    '  return <div dangerouslySetInnerHTML={{ __html: clean(html) }} />;\n'
                    '}\n', rel="app/good.tsx")
    assert _r007(importer, files=[safe, importer]) == []


def test_close1_interleaved_projects_stay_isolated():
    from auditor.adapters.typescript.dom_safety import attach_index, build_safety_index
    from auditor.adapters.typescript.react_rules import DangerousInnerHtml
    p1_lib = _tsx('import DOMPurify from "dompurify";\n'
                  'export function clean(x: string) { return DOMPurify.sanitize(x); }\n',
                  rel="lib/safe.tsx")
    p2_page = _tsx('function clean(x: string) { return x; }\n'
                   'export function V({ html }: any) {\n'
                   '  return <div dangerouslySetInnerHTML={{ __html: clean(html) }} />;\n'
                   '}\n', rel="app/page.tsx")
    # project 1 prepared FIRST, then project 2 — and the reverse
    attach_index([p1_lib], build_safety_index([p1_lib]))
    attach_index([p2_page], build_safety_index([p2_page]))
    assert _ids(DangerousInnerHtml().check(p2_page)) == ["R007"]
    attach_index([p2_page], build_safety_index([p2_page]))
    attach_index([p1_lib], build_safety_index([p1_lib]))
    assert _ids(DangerousInnerHtml().check(p2_page)) == ["R007"]


def test_close2_fake_gate_with_other_regex_stays_flagged():
    sf = _tsx('const HEX = /^#[0-9a-fA-F]{6}$/;\n'
              'const OTHER = /x/;\n'
              'function fakeGate(x: string) { return OTHER.test(x) ? x : x; }\n'
              'export function rawCss(v: string): string {\n'
              '  const c = fakeGate(v);\n'
              '  return `:root{--x:${c};}`;\n'
              '}\n'
              'export function P({ v }: any) {\n'
              '  return <style dangerouslySetInnerHTML={{ __html: rawCss(v) }} />;\n'
              '}\n', rel="app/fake.tsx")
    assert _ids(_r007(sf)) == ["R007"]


def test_close2_gate_returning_input_on_both_branches_is_no_gate():
    sf = _tsx('const HEX = /^#[0-9a-fA-F]{6}$/;\n'
              'function badGate(x: string) { return HEX.test(x) ? x : x; }\n'
              'export function css(v: string): string { return `:root{--x:${badGate(v)};}`; }\n'
              'export function P({ v }: any) {\n'
              '  return <style dangerouslySetInnerHTML={{ __html: css(v) }} />;\n'
              '}\n', rel="app/bad.tsx")
    assert _ids(_r007(sf)) == ["R007"]


def test_close4_ef_metadata_as_argument_does_not_launder():
    sf = _cs('''class A { void F(DbContext db, string user) {
        string Build(string u, object m) { return u; }
        db.Database.ExecuteSqlRaw($"DELETE FROM {Build(user, db.Model)}");
    } }''')
    assert _ids(RawSqlInterpolation().check(sf)) == ["D003"]
    assert "P005" in _ids(_sql_rules(sf))


def test_close5_identifier_sql_from_unknown_source_is_d003():
    sf = _cs('''class A { void F(DbContext db, string user) {
        var sql = GetSql(user);
        db.Database.ExecuteSqlRaw(sql);
    } }''')
    out = RawSqlInterpolation().check(sf)
    assert _ids(out) == ["D003"] and out[0].precision == "heuristic"
    # while a literal-only / trusted identifier stays clean, and the SEPARATE
    # parameter arguments after the SQL are never judged as SQL
    clean = _cs('''class A { void F(DbContext db, object p) {
        var sql = "SELECT 1" + " FROM t WHERE x = @p";
        db.Database.ExecuteSqlRaw(sql, (object?)p ?? DBNull.Value);
    } }''')
    assert RawSqlInterpolation().check(clean) == []


def test_close5_chained_call_after_raw_sql_is_not_the_sql_api():
    # found while closing: `SqlQueryRaw("...").FirstOrDefaultAsync(ct)` — the
    # OUTER chained call must not be classified as a raw-SQL API just because
    # its receiver text mentions one (that judged `ct` as SQL). The madar
    # InvoiceNumbering/RowLevelSecurity literal queries stay clean.
    sf = _cs('''class A { async Task F(DbContext db, CancellationToken ct, string code) {
        var le = await db.Database.SqlQueryRaw<LegalEntityRow>(
            """
            SELECT le."Id" FROM gl.legal_entities le WHERE le."Code" = {0}
            """, code).FirstOrDefaultAsync(ct);
    } }''')
    assert RawSqlInterpolation().check(sf) == []
    # while the chained shape with a DYNAMIC first argument still flags
    bad = _cs('''class A { async Task F(DbContext db, CancellationToken ct, string t) {
        var x = await db.Database.SqlQueryRaw<long>($"SELECT 1 FROM {t}").FirstOrDefaultAsync(ct);
    } }''')
    assert _ids(RawSqlInterpolation().check(bad)) == ["D003"]


def test_close6_marker_inside_a_string_is_not_a_comment():
    sf = _tsx('const url = "https://example.test/TODO:implement";\n')
    assert SmellComments().check(sf) == []
    sf2 = _py('url = "http://x/#FIXME"\n')
    assert SmellComments().check(sf2) == []
    # real comments still fire, including multi-line blocks
    sf3 = _tsx('/*\n * TODO: implement the retry path\n */\nconst x = 1;\n')
    assert _ids(SmellComments().check(sf3)) == ["P007"]


# ═════ D. internal dependencies ═════════════════════════════════════════════════

def test_d_repo_sibling_namespace_is_internal(tmp_path):
    from auditor.core.models import ImportRef
    (tmp_path / "src" / "Acme.Api").mkdir(parents=True)
    (tmp_path / "src" / "Acme.Modules.Billing").mkdir(parents=True)
    (tmp_path / "src" / "Acme.Api" / "Acme.Api.csproj").write_text(
        "<Project Sdk=\"Microsoft.NET.Sdk\"/>", encoding="utf-8")
    (tmp_path / "src" / "Acme.Modules.Billing" / "Acme.Modules.Billing.csproj"
     ).write_text("<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup>"
                  "<RootNamespace>Acme.Billing.Core</RootNamespace>"
                  "</PropertyGroup></Project>", encoding="utf-8")
    a = DotnetAdapter()
    a.set_repo_root(tmp_path)
    internal = ImportRef(module="Acme.Modules.Billing.Domain", file="x.cs",
                         line=1, top_level="Acme.Modules.Billing.Domain")
    by_rootns = ImportRef(module="Acme.Billing.Core.Invoices", file="x.cs",
                          line=1, top_level="Acme.Billing.Core.Invoices")
    external = ImportRef(module="Contoso.External.Sdk", file="x.cs",
                         line=1, top_level="Contoso.External.Sdk")
    assert a.is_internal(internal)
    assert a.is_internal(by_rootns)
    assert not a.is_internal(external)      # unlinked stays a visible finding


def test_d_strip_jsonc_preserves_alias_keys():
    from auditor.adapters.typescript.adapter import _strip_jsonc
    import json
    raw = '''{
  // JSONC comment
  "compilerOptions": {
    /* block comment */
    "baseUrl": ".",
    "paths": { "@/*": ["./*"], "#x/*": ["src/*"] },
    "u": "https://example.com/path", // trailing
  },
}'''
    data = json.loads(_strip_jsonc(raw))
    assert data["compilerOptions"]["paths"]["@/*"] == ["./*"]
    assert data["compilerOptions"]["u"] == "https://example.com/path"


def test_d_tsconfig_alias_import_is_internal_scoped_pkg_is_not(tmp_path):
    from auditor.adapters.typescript.adapter import TypeScriptAdapter
    (tmp_path / "tsconfig.json").write_text(
        '{ "compilerOptions": { "paths": { "@/*": ["./*"] } } }',
        encoding="utf-8")
    (tmp_path / "package.json").write_text('{"name": "app"}', encoding="utf-8")
    a = TypeScriptAdapter()
    a.set_repo_root(tmp_path)
    a.prepare(tmp_path, [])
    sf = _tsx('import { x } from "@/lib/api";\n'
              'import { y } from "@aseesx/ui";\n', rel="a.tsx")
    refs = a.extract_imports([sf])
    mods = [r.module for r in refs]
    assert "@/lib/api" not in mods          # alias = local path in disguise
    assert "@aseesx/ui" in mods             # scoped package still audited
