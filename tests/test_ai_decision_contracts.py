"""W3-E4B2: query-specific falsification and evidence contracts.

Each AI001-AI008 query carries a FIXED decision_contract (positive evidence
required, counter-evidence to check first, when insufficient_context is
correct). The contract rides in the query piece — canonical bytes, digest,
consent — and the system prompt is falsification-first. These regressions pin,
for every decision rule that failed the E4A measurement, that the pack
PROVABLY delivers both the counter-evidence and the instruction to check it;
plus the five-provider wire (FakeTransport only, no network)."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from auditor.ai.audit import (
    AUDIT_MAX_OUTPUT_TOKENS, AUDIT_PROMPT_VERSION, AUDIT_SYSTEM_INSTRUCTIONS,
    build_audit_pack, parse_audit_reply, run_audit_unit)
from auditor.ai.audit_index import RepositoryAuditIndex
from auditor.ai.audit_queries import AUDIT_QUERIES, query_by_id
from auditor.ai.contract import HttpResponse, Provider
from auditor.ai.quality_corpus import cases, holdout_cases

LOCAL = {"OLLAMA_HOST": "http://127.0.0.1:11434"}


def _pack_for(case_id: str):
    all_cases = {c.case_id: c for c in cases(None)}
    c = all_cases[case_id]
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        for cf in c.files:
            p = base / cf.rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(cf.text, encoding="utf-8")
        idx = RepositoryAuditIndex(base, c.project_roots)
        return build_audit_pack(idx, c.project, query_by_id(c.query_id))


# ---- the contract is part of the payload, the digest, and the prompt ----------------

def test_every_query_has_a_contract_and_it_enters_the_canonical_bytes():
    for q in AUDIT_QUERIES:
        assert q.decision_contract and len(q.decision_contract) > 100, q.id
        assert "insufficient_context" in q.decision_contract, q.id
    pack = _pack_for("AI001-neg")
    qpiece = next(p for p in pack["pieces"] if p.get("context_id") == "query")
    assert qpiece["decision_contract"] == query_by_id("AI001").decision_contract
    assert query_by_id("AI001").decision_contract[:60] in pack["canonical"]


def test_system_prompt_is_falsification_first():
    s = AUDIT_SYSTEM_INSTRUCTIONS
    assert "FALSIFICATION-FIRST" in s
    assert "decision_contract" in s
    assert "DISPROVES" in s
    # the cross-file high-confidence rule: a missing-control claim needs the
    # protection context present, else insufficient_context
    assert "MISSING across files" in s
    assert AUDIT_PROMPT_VERSION == "w3e-v3"


# ---- per-rule: the counter-evidence is IN the payload, the contract names it --------

@pytest.mark.parametrize("case_id,in_canonical,contract_names", [
    # authorized route across middleware/backend (E4A FP)
    ("AI001-neg", "RequireAuthorization", "middleware"),
    # parameterized SQL (E4A FP)
    ("AI002-neg-sql", "%s", "bound arguments"),
    # real DOMPurify before innerHTML
    ("AI002-neg-dompurify", "DOMPurify", "sanitizer"),
    # explicit transaction (E4A FP)
    ("AI004-neg", "BeginTransaction", "transaction scope"),
    # log + rethrow (E4A FP)
    ("AI005-neg", "raise", "rethrow"),
    # pydantic/schema validation (E4A miss on neg side)
    ("AI006-neg", "model_validate", "schema"),
    # TODO marker inside an analysis tool (E4A FP)
    ("AI008-neg", "TODO", "STRING DATA"),
])
def test_counter_evidence_and_its_instruction_travel_together(
        case_id, in_canonical, contract_names):
    pack = _pack_for(case_id)
    assert pack is not None, case_id
    assert in_canonical in pack["canonical"], case_id      # evidence delivered
    qpiece = next(p for p in pack["pieces"] if p.get("context_id") == "query")
    assert contract_names in qpiece["decision_contract"], case_id


def test_dependency_query_declares_other_problems_out_of_scope():
    # an AI007 unit whose file shows an injection shape: the contract itself
    # tells the model this is OUT OF SCOPE for the dependency category
    pack = _pack_for("AI007-out-of-scope")
    qpiece = next(p for p in pack["pieces"] if p.get("context_id") == "query")
    assert "OUT OF SCOPE" in qpiece["decision_contract"]
    assert "do not report it under this category" in qpiece["decision_contract"]


def test_ai007_without_a_manifest_is_told_to_abstain():
    pack = _pack_for("AI007-hold-abstain")        # project with no manifest
    files = {m["file"] for m in pack["piece_map"].values()}
    assert not any("requirements" in f or "package.json" in f for f in files)
    qpiece = next(p for p in pack["pieces"] if p.get("context_id") == "query")
    assert "WITHOUT a manifest piece" in qpiece["decision_contract"]


def test_missing_context_case_carries_unresolved_facts_and_abstain_parses():
    # the holdout AI001 abstain: the access guard is an unresolved import;
    # insufficient_context is a legal, accepted reply — no transformation
    pack = _pack_for("AI001-hold-abstain")
    facts = next((p for p in pack["pieces"]
                  if p.get("context_id") == "unresolved"), None)
    assert facts is not None
    out = parse_audit_reply(json.dumps(
        {"outcome": "insufficient_context", "issues": []}),
        pack["piece_map"], required_category="authorization")
    assert out["outcome"] == "insufficient_context"
    assert out["issues"] == []


def test_reply_is_never_silently_transformed():
    # what the model said is what the result carries: same outcome, same
    # issue count, same evidence lines — parse validates, never rewrites
    pack = _pack_for("AI002-pos")
    cid, meta = next(iter(pack["piece_map"].items()))
    ls = meta["spans"][0][0]
    reply = {"outcome": "issues_found", "issues": [{
        "title": "input reaches sql text", "category": "input_handling",
        "confidence": "medium", "summary": "s",
        "evidence": [{"context_id": cid, "line_start": ls, "line_end": ls,
                      "statement": "e"}],
        "missing_context": ["x"], "suggested_action": "inspect"}]}
    out = parse_audit_reply(json.dumps(reply), pack["piece_map"],
                            required_category="input_handling")
    assert out["outcome"] == "issues_found"
    assert len(out["issues"]) == 1
    assert out["issues"][0]["confidence"] == "medium"
    assert out["issues"][0]["missing_context"] == ["x"]


# ---- five providers: the contract travels on every wire, limits intact --------------

def _audit_reply_text():
    return json.dumps({"outcome": "no_issue_observed", "issues": []})


_PROVIDERS = [
    (Provider.OLLAMA, LOCAL, False,
     lambda t: {"message": {"role": "assistant", "content": t}}),
    (Provider.OPENAI_COMPATIBLE,
     {"AUDITOR_OPENAI_COMPAT_BASE_URL": "http://127.0.0.1:8080",
      "AUDITOR_OPENAI_COMPAT_API_KEY": "k"}, False,
     lambda t: {"choices": [{"message": {"content": t}}]}),
    (Provider.OPENAI, {"OPENAI_API_KEY": "sk-o",
                       "AUDITOR_AI_REMOTE_REVIEWS": "confirm"}, True,
     lambda t: {"output_text": t}),
    (Provider.ANTHROPIC, {"ANTHROPIC_API_KEY": "sk-a",
                          "AUDITOR_AI_REMOTE_REVIEWS": "confirm"}, True,
     lambda t: {"content": [{"type": "text", "text": t}]}),
    (Provider.XAI, {"XAI_API_KEY": "sk-x",
                    "AUDITOR_AI_REMOTE_REVIEWS": "confirm"}, True,
     lambda t: {"output": [{"type": "message", "content":
                            [{"type": "output_text", "text": t}]}]}),
]


@pytest.mark.parametrize("provider,env,consented,reply", _PROVIDERS)
def test_contract_travels_on_every_provider_wire(provider, env, consented,
                                                 reply):
    calls: list = []

    class T:
        def request(self, method, url, headers, json_body, timeout):
            calls.append(json_body)
            return HttpResponse(200, json.dumps(
                reply(_audit_reply_text())).encode())

    pack = _pack_for("AI001-neg")
    res = run_audit_unit(pack, provider, "m", T(), env=env,
                         consented=consented)
    assert res["outcome"] == "no_issue_observed"
    body = calls[0]
    blob = json.dumps(body)
    # the decision contract reached the wire inside the canonical user content
    assert "Counter-evidence to check FIRST" in blob
    # output cap unchanged per provider shape
    if provider is Provider.OLLAMA:
        assert body["options"]["num_predict"] == AUDIT_MAX_OUTPUT_TOKENS
        cat_enum = body["format"]["properties"]["issues"]["items"][
            "properties"]["category"]["enum"]
        assert cat_enum == ["authorization"]          # single-value enum kept
    elif provider in (Provider.OPENAI, Provider.XAI):
        assert body["max_output_tokens"] == AUDIT_MAX_OUTPUT_TOKENS
    else:
        assert body["max_tokens"] == AUDIT_MAX_OUTPUT_TOKENS
    assert "sk-o" not in blob and "sk-a" not in blob and "sk-x" not in blob


# ---- holdout stays covered under the new versions ------------------------------------

def test_holdout_still_builds_units_under_the_new_query_versions():
    # the contract changed the digest, not the retrieval: every holdout case
    # still builds a real unit
    for c in holdout_cases():
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            for cf in c.files:
                p = base / cf.rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(cf.text, encoding="utf-8")
            idx = RepositoryAuditIndex(base, c.project_roots)
            pack = build_audit_pack(idx, c.project, query_by_id(c.query_id))
            assert pack is not None, c.case_id
            assert pack["query_version"] == 3
