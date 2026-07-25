"""W3-E4A1: case-insensitive retrieval, query-specific AI003 hints,
evidence-strength ranking, and the per-query fixed category contract.
No network — index + schema/validator assertions only."""
from __future__ import annotations

import json

import pytest

from auditor.ai.audit import (
    AUDIT_PROMPT_VERSION, audit_schema_for, build_audit_pack, parse_audit_reply)
from auditor.ai.audit_index import RepositoryAuditIndex
from auditor.ai.audit_queries import (
    AUDIT_QUERIES, CATALOG_VERSION, query_by_id)
from auditor.ai.contract import AIError

PROJECTS = [("svc", "csharp")]


def _repo(tmp_path, files):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return tmp_path


# ---- A: case-insensitive (casefold) retrieval ----------------------------------------

def test_password_matches_capital_password_casefold(tmp_path):
    repo = _repo(tmp_path, {
        "svc/DbFactory.cs": (
            "public class DbFactory {\n"
            "  void Build() {\n"
            "    var o = new Options();\n"
            "    o.UseNpgsql(\"Host=localhost;Username=postgres;"
            "Password=hunter2\");\n"
            "  }\n}\n"),
    })
    index = RepositoryAuditIndex(repo, PROJECTS)
    hits = index.candidates_for(query_by_id("AI003"), "svc")
    files = [f.rel for f, _ in hits]
    assert "svc/DbFactory.cs" in files      # 'password' hint matched 'Password='


def test_random_file_order_is_deterministic(tmp_path):
    files = {f"svc/f{i}.cs": f"// getenv secret token {i}\nvar x = {i};\n"
             for i in range(6)}
    repo = _repo(tmp_path, files)
    a = RepositoryAuditIndex(repo, PROJECTS).candidates_for(
        query_by_id("AI003"), "svc")
    b = RepositoryAuditIndex(repo, PROJECTS).candidates_for(
        query_by_id("AI003"), "svc")
    assert [f.rel for f, _ in a] == [f.rel for f, _ in b]


def test_path_hint_alone_never_qualifies(tmp_path):
    # a file whose NAME screams config but has no symbol evidence is dropped
    repo = _repo(tmp_path, {
        "svc/appsettings_config.cs": "public class C { int Plain() => 1; }\n",
        "svc/Real.cs": "var s = getenv(\"SECRET\");\n",
    })
    index = RepositoryAuditIndex(repo, PROJECTS)
    files = [f.rel for f, _ in index.candidates_for(
        query_by_id("AI003"), "svc")]
    assert "svc/appsettings_config.cs" not in files   # no markers -> not filler
    assert "svc/Real.cs" in files


def test_evidence_diversity_outranks_path_name(tmp_path):
    # a plain config file with ONE generic marker on many lines must NOT
    # outrank the connection factory that carries several credential markers
    repo = _repo(tmp_path, {
        "svc/config/Settings.cs": "".join(
            f"var v{i} = getenv(\"X{i}\");\n" for i in range(30)),
        "svc/Db.cs": (
            "var b = new B();\n"
            "b.UseNpgsql(\"Host=h;Server=s;Username=u;Password=p;pwd=p\");\n"),
    })
    index = RepositoryAuditIndex(repo, PROJECTS)
    top = [f.rel for f, _ in index.candidates_for(
        query_by_id("AI003"), "svc")]
    assert top[0] == "svc/Db.cs"           # strongest evidence leads


def test_connection_factory_enters_exact_sent_span_and_redacts(tmp_path):
    repo = _repo(tmp_path, {
        "svc/AppDbContextFactory.cs": (
            "using X;\n" * 3
            + "class AppDbContextFactory {\n"
            "  void M() {\n"
            "    new B().UseNpgsql(\"Host=h;Username=u;Password=SUPERSECRET\");\n"
            "  }\n}\n"),
    })
    index = RepositoryAuditIndex(repo, PROJECTS)
    pack = build_audit_pack(index, "svc", query_by_id("AI003"))
    assert pack is not None
    files = {m["file"] for m in pack["piece_map"].values()}
    assert "svc/AppDbContextFactory.cs" in files
    # the connection line is inside an exact sent span and the value is gone
    assert "SUPERSECRET" not in pack["canonical"]
    assert "***" in pack["canonical"]


# ---- B: per-query fixed category ------------------------------------------------------

QUERY_CATEGORY = {
    "AI001": "authorization", "AI002": "input_handling",
    "AI003": "credentials", "AI004": "concurrency",
    "AI005": "error_handling", "AI006": "api_contract",
    "AI007": "dependency_integration", "AI008": "incomplete_code"}


def test_every_query_declares_its_fixed_category():
    for q in AUDIT_QUERIES:
        assert q.category == QUERY_CATEGORY[q.id], q.id


PIECE_MAP = {"src:1": {"file": "a.cs", "spans": [[1, 20]]}}


def _reply(category):
    return json.dumps({"outcome": "issues_found", "issues": [{
        "title": "t", "category": category, "confidence": "low",
        "summary": "s", "evidence": [{"context_id": "src:1", "line_start": 2,
                                      "line_end": 3, "statement": "x"}],
        "missing_context": [], "suggested_action": "inspect"}]})


@pytest.mark.parametrize("qid,category", list(QUERY_CATEGORY.items()))
def test_matching_category_accepted_and_others_rejected(qid, category):
    # the query's own category is accepted
    out = parse_audit_reply(_reply(category), PIECE_MAP,
                            required_category=category)
    assert out["issues"][0]["category"] == category
    # any OTHER legal category is invalid_response (no relabel/drop)
    other = "authorization" if category != "authorization" else "credentials"
    with pytest.raises(AIError) as ei:
        parse_audit_reply(_reply(other), PIECE_MAP,
                          required_category=category)
    assert ei.value.code == "invalid_response"


def test_ai007_authorization_rejected_dependency_accepted():
    with pytest.raises(AIError):
        parse_audit_reply(_reply("authorization"), PIECE_MAP,
                          required_category="dependency_integration")
    out = parse_audit_reply(_reply("dependency_integration"), PIECE_MAP,
                            required_category="dependency_integration")
    assert out["issues"][0]["category"] == "dependency_integration"


def test_ollama_schema_enum_is_single_value_per_query():
    for qid, category in QUERY_CATEGORY.items():
        schema = audit_schema_for(category)
        enum = schema["properties"]["issues"]["items"]["properties"][
            "category"]["enum"]
        assert enum == [category], qid
    # None (defensive) falls back to the full enum
    assert len(audit_schema_for(None)["properties"]["issues"]["items"]
               ["properties"]["category"]["enum"]) == 9


def test_pack_carries_required_category_in_query_piece(tmp_path):
    repo = _repo(tmp_path, {
        "svc/Db.cs": "new B().UseNpgsql(\"Password=p;Host=h\");\n"})
    index = RepositoryAuditIndex(repo, PROJECTS)
    pack = build_audit_pack(index, "svc", query_by_id("AI003"))
    assert pack["required_category"] == "credentials"
    qpiece = next(p for p in pack["pieces"] if p.get("context_id") == "query")
    assert qpiece["required_category"] == "credentials"
    assert "credentials" in pack["canonical"]


# ---- C: versioning --------------------------------------------------------------------

def test_versions_bumped_for_the_contract_change():
    # W3-E4C-FINAL: redaction_facts gained a `kind` (literal_credential_proven
    # vs redaction_applied) — a prompt + AI003 contract change => CATALOG 5,
    # AI003 query_version 5, prompt w3e-v5. The other queries' definitions did
    # not change (their digests move anyway because every canonical can now
    # carry the kind-tagged facts piece).
    assert CATALOG_VERSION == 5
    for q in AUDIT_QUERIES:
        assert q.query_version == (5 if q.id == "AI003" else 3), q.id
    assert AUDIT_PROMPT_VERSION == "w3e-v5"
    assert all(q.decision_contract for q in AUDIT_QUERIES)


def test_digest_changes_deterministically_with_category(tmp_path):
    import hashlib
    repo = _repo(tmp_path, {
        "svc/Db.cs": "new B().UseNpgsql(\"Password=p;Host=h\");\n"})
    index = RepositoryAuditIndex(repo, PROJECTS)
    p1 = build_audit_pack(index, "svc", query_by_id("AI003"))
    p2 = build_audit_pack(index, "svc", query_by_id("AI003"))
    assert p1["digest"] == p2["digest"]                 # deterministic
    assert p1["digest"] == hashlib.sha256(
        p1["canonical"].encode("utf-8")).hexdigest()
    assert "required_category" in p1["canonical"]       # part of the digest
