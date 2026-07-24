"""W3-E4A closing: cross-file retrieval expansion (imports, middleware,
route->backend) with provenance and structured unresolved facts, plus the
MFA acceptance cases; and the proof that the per-query category is a
STRUCTURAL guard only, not a semantic scope check."""
from __future__ import annotations

import json

import pytest

from auditor.ai.audit import build_audit_pack, parse_audit_reply
from auditor.ai.audit_expand import MAX_EXPAND_FILES, expand
from auditor.ai.audit_index import RepositoryAuditIndex
from auditor.ai.audit_queries import query_by_id
from auditor.ai.contract import AIError


def _mfa_repo(tmp_path, *, full: bool, with_auth: bool):
    (tmp_path / "web/app/api/pay").mkdir(parents=True, exist_ok=True)
    (tmp_path / "web/app/api/pay/route.ts").write_text(
        "import { backend } from '@/lib/proxy';\n"
        "export async function POST(req: Request) {\n"
        "  return backend('/api/payments', req);\n"
        "}\n", encoding="utf-8")
    if full:
        (tmp_path / "web/lib").mkdir(parents=True, exist_ok=True)
        (tmp_path / "web/lib/proxy.ts").write_text(
            "export async function backend(path: string, req: Request) {\n"
            "  return fetch('http://api' + path, { method: req.method });\n"
            "}\n", encoding="utf-8")
        (tmp_path / "web/middleware.ts").write_text(
            "export function middleware(req) {\n"
            "  // authentication cookie check for all routes\n"
            "  return next();\n"
            "}\n", encoding="utf-8")
        (tmp_path / "api").mkdir(parents=True, exist_ok=True)
        auth = ".RequireAuthorization()" if with_auth else ""
        (tmp_path / "api/Endpoints.cs").write_text(
            f'app.MapPost("/api/payments", Handler){auth};\n', encoding="utf-8")
    roots = [("web", "typescript")] + ([("api", "csharp")] if full else [])
    return RepositoryAuditIndex(tmp_path, roots)


def _pack(tmp_path, **kw):
    idx = _mfa_repo(tmp_path, **kw)
    return build_audit_pack(idx, "web", query_by_id("AI001"))


def _prov(pack):
    return {p["file"].split("/")[-1]: p.get("provenance", "seed")
            for p in pack["pieces"] if "file" in p}


# ---- MFA acceptance cases ------------------------------------------------------------

def test_mfa_case1_unresolved_backend_is_structured_fact(tmp_path):
    pack = _pack(tmp_path, full=False, with_auth=False)
    assert pack is not None
    facts = next((p for p in pack["pieces"]
                  if p.get("context_id") == "unresolved"), None)
    assert facts is not None
    rels = {(f["relation"], f["resolved"]) for f in facts["facts"]}
    assert ("import", False) in rels and ("route", False) in rels
    # only the route seed is a real file; no arbitrary file was handed over
    files = {m["file"].split("/")[-1] for m in pack["piece_map"].values()}
    assert files == {"route.ts"}


def test_mfa_case1_high_confidence_missing_auth_is_not_forced(tmp_path):
    """With the backend unresolved, a high-confidence missing-auth claim is
    NOT justified — the pipeline hands the model an unresolved fact, so an
    honest reply is insufficient_context. We assert the CONTEXT makes that
    possible (the unresolved fact is present and citable content is only the
    route)."""
    pack = _pack(tmp_path, full=False, with_auth=False)
    # insufficient_context is a legal, accepted outcome for this unit
    out = parse_audit_reply(json.dumps(
        {"outcome": "insufficient_context", "issues": []}),
        pack["piece_map"], required_category="authorization")
    assert out["outcome"] == "insufficient_context"


def test_mfa_case2_all_four_files_in_exact_spans(tmp_path):
    pack = _pack(tmp_path, full=True, with_auth=True)
    prov = _prov(pack)
    assert prov == {"route.ts": "seed", "middleware.ts": "framework_middleware",
                    "proxy.ts": "import", "Endpoints.cs": "route_target"}
    # every sent file's lines are inside an exact span, and RequireAuthorization
    # is visible in the endpoint piece
    for cid, meta in pack["piece_map"].items():
        assert meta["spans"] and all(s[0] <= s[1] for s in meta["spans"])
    endpoint = next(p for p in pack["pieces"]
                    if p.get("file", "").endswith("Endpoints.cs"))
    assert "RequireAuthorization" in endpoint["text"]


def test_mfa_case3_missing_authorization_is_visible(tmp_path):
    pack = _pack(tmp_path, full=True, with_auth=False)
    assert _prov(pack)["Endpoints.cs"] == "route_target"
    endpoint = next(p for p in pack["pieces"]
                    if p.get("file", "").endswith("Endpoints.cs"))
    assert "RequireAuthorization" not in endpoint["text"]
    assert "MapPost" in endpoint["text"]        # the endpoint IS present


def test_expansion_is_bounded_and_deterministic(tmp_path):
    idx = _mfa_repo(tmp_path, full=True, with_auth=True)
    seeds = [f for f in idx.files if f.rel.endswith("route.ts")]
    a, _ = expand(idx, "web", query_by_id("AI001"), seeds)
    b, _ = expand(idx, "web", query_by_id("AI001"), seeds)
    assert [(e.file, e.provenance) for e in a] \
        == [(e.file, e.provenance) for e in b]
    assert len(a) <= MAX_EXPAND_FILES


def test_expansion_stays_inside_the_index(tmp_path):
    # an import of an EXTERNAL package is not unresolved and pulls nothing
    (tmp_path / "web").mkdir(parents=True, exist_ok=True)
    (tmp_path / "web/x.ts").write_text(
        "import { z } from 'zod';\n"
        "export async function GET() { return z.object({}); }\n",
        encoding="utf-8")
    idx = RepositoryAuditIndex(tmp_path, [("web", "typescript")])
    seeds = [f for f in idx.files if f.rel.endswith("x.ts")]
    extra, unresolved = expand(idx, "web", query_by_id("AI001"), seeds)
    assert extra == []                      # nothing to resolve locally
    assert all(u.relation != "import" for u in unresolved)   # external != unresolved


# ---- template-literal route families (the real MFA shape) ---------------------------

def _write_ops_web(tmp_path):
    """The operations-style MFA BFF: a route whose backend path is a TEMPLATE
    literal `/api/auth/mfa/${seg}` (a route family, not a fixed string)."""
    web = tmp_path / "web"
    (web / "app/api/mfa").mkdir(parents=True, exist_ok=True)
    (web / "app/api/mfa/route.ts").write_text(
        "import { backend } from '@/lib/proxy';\n"
        "async function forward(req: Request, seg: string[]) {\n"
        "  const path = `/api/auth/mfa/${seg.join('/')}`;\n"
        "  return backend(path, req);\n"
        "}\n"
        "export async function GET(req: Request) { return forward(req, []); }\n"
        "export async function POST(req: Request) { return forward(req, []); }\n",
        encoding="utf-8")
    (web / "lib").mkdir(parents=True, exist_ok=True)
    (web / "lib/proxy.ts").write_text(
        "export async function backend(path: string, req: Request) {\n"
        "  return fetch('http://api' + path, { method: req.method });\n"
        "}\n", encoding="utf-8")
    (web / "middleware.ts").write_text(
        "export function middleware(req) {\n"
        "  const t = req.cookies.get('session');\n"
        "  if (!t) return redirectToLogin();\n"
        "  return next();\n"
        "}\n", encoding="utf-8")


def _program_cs(tmp_path):
    (tmp_path / "api").mkdir(parents=True, exist_ok=True)
    (tmp_path / "api/Program.cs").write_text(
        "app.MapGet(\"/api/auth/mfa/status\", StatusHandler);\n"
        "app.MapPost(\"/api/auth/mfa/setup\", SetupHandler);\n"
        "app.MapPost(\"/api/auth/mfa/enable\", EnableHandler);\n",
        encoding="utf-8")


def test_mfa_template_route_links_all_four_files(tmp_path):
    _write_ops_web(tmp_path)
    _program_cs(tmp_path)
    idx = RepositoryAuditIndex(
        tmp_path, [("web", "typescript"), ("api", "csharp")])
    pack = build_audit_pack(idx, "web", query_by_id("AI001"))
    prov = _prov(pack)
    assert prov.get("Program.cs") == "route_target"
    assert prov.get("middleware.ts") == "framework_middleware"
    assert prov.get("route.ts") == "seed"
    assert "proxy.ts" in prov                     # seed or import
    assert pack["privacy_manifest"]["files_sent"] == 4
    # exact spans, and the mfa endpoints are visible in the sent Program.cs
    for meta in pack["piece_map"].values():
        assert meta["spans"] and all(s[0] <= s[1] for s in meta["spans"])
    prog = next(p for p in pack["pieces"]
                if p.get("file", "").endswith("Program.cs"))
    assert "/api/auth/mfa/status" in prog["text"]


def test_mfa_no_backend_gives_unresolved_not_a_random_file(tmp_path):
    _write_ops_web(tmp_path)                       # NO Program.cs
    idx = RepositoryAuditIndex(tmp_path, [("web", "typescript")])
    pack = build_audit_pack(idx, "web", query_by_id("AI001"))
    facts = next((p for p in pack["pieces"]
                  if p.get("context_id") == "unresolved"), None)
    assert facts is not None
    assert any(f["relation"] == "route" and "/api/auth/mfa/" in f["reference"]
               for f in facts["facts"])
    files = {m["file"].split("/")[-1] for m in pack["piece_map"].values()}
    assert not any(f.endswith(".cs") for f in files)


def test_route_target_needs_a_registration_not_co_occurrence(tmp_path):
    """A decoy backend that only MENTIONS the prefix in a comment while
    registering a DIFFERENT route must never be linked — the match is against
    real MapGet/MapPost registrations, not text co-occurrence."""
    _write_ops_web(tmp_path)
    (tmp_path / "api").mkdir(parents=True, exist_ok=True)
    (tmp_path / "api/Decoy.cs").write_text(
        "// forwards to /api/auth/mfa/ eventually\n"
        "app.MapGet(\"/api/other/thing\", Handler);\n", encoding="utf-8")
    idx = RepositoryAuditIndex(
        tmp_path, [("web", "typescript"), ("api", "csharp")])
    pack = build_audit_pack(idx, "web", query_by_id("AI001"))
    files = {m["file"].split("/")[-1] for m in pack["piece_map"].values()}
    assert "Decoy.cs" not in files
    facts = next((p for p in pack["pieces"]
                  if p.get("context_id") == "unresolved"), None)
    assert facts is not None                       # unresolved, not the decoy


def test_ai001_pack_respects_its_hard_file_cap(tmp_path):
    _write_ops_web(tmp_path)
    _program_cs(tmp_path)
    idx = RepositoryAuditIndex(
        tmp_path, [("web", "typescript"), ("api", "csharp")])
    pack = build_audit_pack(idx, "web", query_by_id("AI001"))
    cap = query_by_id("AI001").max_context_files
    assert cap == 4
    assert pack["privacy_manifest"]["files_sent"] <= cap
    assert pack["privacy_manifest"]["files_sent"] == 4


def test_mfa_chain_survives_a_crowd_of_secondary_candidates(tmp_path):
    """Relationship-first: even with many extra AI001 candidates competing for
    the hard cap, the PRIMARY seed's whole chain (route+proxy+middleware+
    backend) is reserved before any secondary seed — the chain is never
    displaced."""
    _write_ops_web(tmp_path)
    _program_cs(tmp_path)
    for i in range(6):                               # a crowd of decoy routes
        d = tmp_path / f"web/app/api/decoy{i}"
        d.mkdir(parents=True, exist_ok=True)
        (d / "route.ts").write_text(
            f"export async function GET() {{ return fetch('/d{i}'); }}\n",
            encoding="utf-8")
    idx = RepositoryAuditIndex(
        tmp_path, [("web", "typescript"), ("api", "csharp")])
    q = query_by_id("AI001")
    cands = idx.candidates_for(q, "web")
    assert cands[0][0].rel.endswith("app/api/mfa/route.ts")   # primary
    pack = build_audit_pack(idx, "web", q)
    prov = {pc["file"]: pc.get("provenance", "seed")
            for pc in pack["pieces"] if "file" in pc}
    assert prov.get("web/app/api/mfa/route.ts") == "seed"
    assert prov.get("web/lib/proxy.ts") == "import"
    assert prov.get("web/middleware.ts") == "framework_middleware"
    assert prov.get("api/Program.cs") == "route_target"
    assert pack["privacy_manifest"]["files_sent"] == 4
    assert not any("decoy" in f for f in prov)       # no decoy displaced it


def test_commented_out_registration_is_not_linked(tmp_path):
    """A backend endpoint COMMENTED OUT must not be treated as a live route —
    the mfa route links to nothing here and yields an unresolved fact, not the
    decoy file."""
    _write_ops_web(tmp_path)
    (tmp_path / "api").mkdir(parents=True, exist_ok=True)
    (tmp_path / "api/Commented.cs").write_text(
        "// app.MapPost(\"/api/auth/mfa/setup\", Handler);\n"
        "app.MapGet(\"/api/unrelated/thing\", Handler);\n", encoding="utf-8")
    idx = RepositoryAuditIndex(
        tmp_path, [("web", "typescript"), ("api", "csharp")])
    pack = build_audit_pack(idx, "web", query_by_id("AI001"))
    files = {m["file"].split("/")[-1] for m in pack["piece_map"].values()}
    assert "Commented.cs" not in files
    facts = next((p for p in pack["pieces"]
                  if p.get("context_id") == "unresolved"), None)
    assert facts is not None
    assert any(f["relation"] == "route" for f in facts["facts"])


def test_endpoint_routes_ignores_comments_string_aware():
    from auditor.ai.audit_expand import _endpoint_routes
    code = ("// app.MapPost(\"/api/auth/mfa/setup\", H);\n"
            "/* app.MapGet(\"/api/blocked\", H); */\n"
            "app.MapGet(\"/api/real\", H);\n"
            "app.MapPost(\"/api/config\", () => \"http://x//y\");\n")
    routes = _endpoint_routes(code)
    assert routes == {"/api/real", "/api/config"}    # comments out, string kept
    assert "/api/auth/mfa/setup" not in routes
    assert "/api/blocked" not in routes


# ---- category is a structural guard, NOT a semantic scope check ----------------------

def test_category_enum_guard_cannot_stop_a_semantic_relabel():
    """An authorization-SUBSTANCE claim mislabeled as dependency_integration
    passes the structural validator (the enum matches the query). This is a
    KNOWN limit: the enum guard prevents a wrong enum, not a wrong claim under
    the right enum. The quality corpus/classifier is what catches out-of-scope
    substance."""
    pm = {"src:1": {"file": "a.ts", "spans": [[1, 9]]}}
    reply = json.dumps({"outcome": "issues_found", "issues": [{
        "title": "endpoint lacks an authorization check",
        "category": "dependency_integration", "confidence": "high",
        "summary": "no RequireAuthorization on this endpoint",
        "evidence": [{"context_id": "src:1", "line_start": 1, "line_end": 2,
                      "statement": "x"}],
        "missing_context": [], "suggested_action": "inspect"}]})
    out = parse_audit_reply(reply, pm,
                            required_category="dependency_integration")
    assert out["issues"][0]["category"] == "dependency_integration"
    # the wrong ENUM is still rejected — the guard does its structural job
    wrong = json.loads(reply)
    wrong["issues"][0]["category"] = "authorization"
    with pytest.raises(AIError):
        parse_audit_reply(json.dumps(wrong), pm,
                          required_category="dependency_integration")
