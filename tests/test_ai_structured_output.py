"""W3-E3: Ollama structured-output contract regressions.
No network — FakeTransport / schema-shape assertions only."""
from __future__ import annotations

import json

import pytest

from auditor.ai.audit import (
    AI_AUDIT_RESPONSE_SCHEMA_V1,
    AUDIT_CATEGORIES,
    AUDIT_MAX_OUTPUT_TOKENS,
    AUDIT_OUTCOMES,
    MAX_ISSUES,
    SUGGESTED_ACTIONS as AUDIT_ACTIONS,
    parse_audit_reply,
)
from auditor.ai.contract import AIError, HttpResponse, Provider
from auditor.ai.providers import _ollama_probe
from auditor.ai.review import (
    ACTIONABILITIES,
    AI_REVIEW_RESPONSE_SCHEMA,
    CONFIDENCES,
    DEFECT_ASSESSMENTS,
    IMPACTS,
    MATCH_ASSESSMENTS,
    REVIEW_MAX_TOKENS,
    SUGGESTED_ACTIONS as REVIEW_ACTIONS,
    _review_body,
)

PIECE_MAP = {"src:1": {"file": "svc/a.py", "spans": [[1, 20]]}}


def _audit_body():
    return _review_body(Provider.OLLAMA, "m", "S", "U",
                        schema=AI_AUDIT_RESPONSE_SCHEMA_V1,
                        max_tokens=AUDIT_MAX_OUTPUT_TOKENS)


def _review_ollama_body():
    return _review_body(Provider.OLLAMA, "m", "S", "U",
                        schema=AI_REVIEW_RESPONSE_SCHEMA,
                        max_tokens=REVIEW_MAX_TOKENS)


# 1 + 2: the full schema is carried, per contract
def test_ollama_review_carries_full_review_schema():
    body = _review_ollama_body()
    assert body["format"] is AI_REVIEW_RESPONSE_SCHEMA
    assert isinstance(body["format"], dict) and body["format"]["type"] == "object"


def test_ollama_audit_carries_full_audit_schema():
    body = _audit_body()
    assert body["format"] is AI_AUDIT_RESPONSE_SCHEMA_V1
    assert isinstance(body["format"], dict) and body["format"]["type"] == "object"


# 3: think:false and stream:false present on every Ollama contract request
def test_ollama_bodies_disable_thinking_and_streaming():
    for body in (_review_ollama_body(), _audit_body()):
        assert body["think"] is False
        assert body["stream"] is False


# 4: the wire num_predict matches each contract's declared budget
def test_ollama_token_caps_match_the_contract_budgets():
    assert _audit_body()["options"]["num_predict"] == AUDIT_MAX_OUTPUT_TOKENS == 1536
    assert _review_ollama_body()["options"]["num_predict"] == REVIEW_MAX_TOKENS == 1024


# 5: each schema declares required + enum + limits + additionalProperties:false
def test_review_schema_mirrors_the_contract():
    s = AI_REVIEW_RESPONSE_SCHEMA
    assert s["additionalProperties"] is False
    assert set(s["required"]) == {"match_assessment", "defect_assessment",
                                  "impact", "actionability", "summary",
                                  "evidence", "missing_context",
                                  "suggested_action"}
    p = s["properties"]
    assert p["match_assessment"]["enum"] == list(MATCH_ASSESSMENTS)
    assert p["defect_assessment"]["enum"] == list(DEFECT_ASSESSMENTS)
    assert p["impact"]["enum"] == list(IMPACTS)
    assert p["actionability"]["enum"] == list(ACTIONABILITIES)
    assert "confidence" not in p and "assessment" not in p
    assert p["suggested_action"]["enum"] == list(REVIEW_ACTIONS)
    assert p["evidence"]["maxItems"] == 5 and p["evidence"]["minItems"] == 1
    ev = p["evidence"]["items"]
    assert ev["additionalProperties"] is False
    assert set(ev["required"]) == {"context_id", "statement"}
    assert ev["properties"]["statement"]["maxLength"] == 400
    assert p["summary"]["maxLength"] == 800
    assert p["missing_context"]["maxItems"] == 5


def test_audit_schema_mirrors_the_contract():
    s = AI_AUDIT_RESPONSE_SCHEMA_V1
    assert s["additionalProperties"] is False
    assert set(s["required"]) == {"outcome", "issues"}
    assert s["properties"]["outcome"]["enum"] == list(AUDIT_OUTCOMES)
    issues = s["properties"]["issues"]
    assert issues["maxItems"] == MAX_ISSUES == 5
    it = issues["items"]
    assert it["additionalProperties"] is False
    assert set(it["required"]) == {"title", "category", "confidence",
                                   "summary", "evidence", "missing_context",
                                   "suggested_action"}
    ip = it["properties"]
    assert ip["category"]["enum"] == list(AUDIT_CATEGORIES)
    assert ip["confidence"]["enum"] == list(CONFIDENCES)
    assert ip["suggested_action"]["enum"] == list(AUDIT_ACTIONS)
    assert ip["title"]["maxLength"] == 200
    ev = ip["evidence"]["items"]
    assert set(ev["required"]) == {"context_id", "line_start", "line_end",
                                   "statement"}
    assert ev["properties"]["line_start"]["type"] == "integer"
    assert ev["properties"]["line_end"]["type"] == "integer"


# 6: a legal reply for every outcome parses
def test_every_legal_outcome_parses():
    found = {"outcome": "issues_found", "issues": [{
        "title": "t", "category": "authorization", "confidence": "low",
        "summary": "s", "evidence": [{"context_id": "src:1", "line_start": 2,
                                      "line_end": 5, "statement": "x"}],
        "missing_context": [], "suggested_action": "inspect"}]}
    assert parse_audit_reply(json.dumps(found), PIECE_MAP)["outcome"] \
        == "issues_found"
    for oc in ("no_issue_observed", "insufficient_context"):
        out = parse_audit_reply(json.dumps({"outcome": oc, "issues": []}),
                                PIECE_MAP)
        assert out["outcome"] == oc


# 7: contract violations remain invalid_response (server validator authority)
def test_contract_violations_remain_invalid_response():
    base = {"outcome": "issues_found", "issues": [{
        "title": "t", "category": "authorization", "confidence": "low",
        "summary": "s", "evidence": [{"context_id": "src:1", "line_start": 2,
                                      "line_end": 5, "statement": "x"}],
        "missing_context": [], "suggested_action": "inspect"}]}

    def mut(fn):
        d = json.loads(json.dumps(base))
        fn(d)
        return json.dumps(d)

    cases = [
        mut(lambda d: d.update(extra="x")),                     # extra top key
        mut(lambda d: d["issues"][0].update(category="nope")),  # bad enum
        mut(lambda d: d["issues"][0]["evidence"][0].update(
            line_start=40, line_end=45)),                       # outside span
        mut(lambda d: d.update(outcome="no_issue_observed")),   # issues<->outcome
        mut(lambda d: d["issues"][0].update(extra_field=1)),    # extra issue key
    ]
    for raw in cases:
        with pytest.raises(AIError) as ei:
            parse_audit_reply(raw, PIECE_MAP)
        assert ei.value.code == "invalid_response"


# 8 + 9 + 10: thinking never reaches the parser/store/API; content is the only source
def _ollama_response(content, thinking=None):
    msg = {"role": "assistant"}
    if content is not None:
        msg["content"] = content
    if thinking is not None:
        msg["thinking"] = thinking
    return HttpResponse(200, json.dumps({"message": msg}).encode())


def test_adversarial_thinking_never_reaches_parse():
    from auditor.ai.providers import PROVIDER_SPECS
    spec = PROVIDER_SPECS[Provider.OLLAMA]
    # a malicious 'thinking' carrying fake JSON must be ignored; only content
    poison = json.dumps({"outcome": "issues_found", "issues": []})
    data = json.loads(_ollama_response("", thinking=poison).body.decode())
    assert spec.parse_probe_text(data) == ""        # thinking is not read
    with pytest.raises(AIError):
        parse_audit_reply(spec.parse_probe_text(data), PIECE_MAP)


def test_thinking_present_empty_content_is_invalid_response():
    from auditor.ai.providers import PROVIDER_SPECS
    spec = PROVIDER_SPECS[Provider.OLLAMA]
    data = json.loads(_ollama_response("", thinking="pondering").body.decode())
    assert spec.parse_probe_text(data) == ""
    with pytest.raises(AIError) as ei:
        parse_audit_reply(spec.parse_probe_text(data), PIECE_MAP)
    assert ei.value.code == "invalid_response"


def test_legal_content_with_thinking_reads_content_only():
    from auditor.ai.providers import PROVIDER_SPECS
    spec = PROVIDER_SPECS[Provider.OLLAMA]
    good = json.dumps({"outcome": "no_issue_observed", "issues": []})
    data = json.loads(_ollama_response(good, thinking="noise").body.decode())
    assert spec.parse_probe_text(data) == good
    assert parse_audit_reply(spec.parse_probe_text(data),
                             PIECE_MAP)["outcome"] == "no_issue_observed"


# probe also disables thinking but stays a text probe (no schema)
def test_ollama_probe_disables_thinking_and_has_no_schema():
    p = _ollama_probe("m")
    assert p["think"] is False and p["stream"] is False
    assert "format" not in p


# 11: schema is NOT part of the context digest (request-only hint)
def test_schema_is_not_in_the_context_pack_or_digest(tmp_path):
    import hashlib

    from auditor.ai.audit import build_audit_pack
    from auditor.ai.audit_index import RepositoryAuditIndex
    from auditor.ai.audit_queries import query_by_id
    repo = tmp_path / "r"
    (repo / "api").mkdir(parents=True)
    (repo / "api" / "orders_controller.py").write_text(
        "def get_order(request):\n"
        "    # authorize / tenant check missing\n"
        "    return db.execute(request.params['id'])\n", encoding="utf-8")
    (repo / "api" / "requirements.txt").write_text("requests\n",
                                                   encoding="utf-8")
    index = RepositoryAuditIndex(repo, [(".", "python")])
    pack = build_audit_pack(index, ".", query_by_id("AI001"))
    assert pack is not None
    blob = pack["canonical"]
    assert "additionalProperties" not in blob and "maxLength" not in blob
    assert "AI_AUDIT_RESPONSE_SCHEMA" not in blob
    assert pack["digest"] == hashlib.sha256(blob.encode("utf-8")).hexdigest()


# 12: remote-provider bodies do not regress (byte-identical wire)
def test_remote_bodies_unchanged_by_the_schema_argument():
    oi = _review_body(Provider.OPENAI, "m", "S", "U",
                      schema=AI_REVIEW_RESPONSE_SCHEMA,
                      max_tokens=REVIEW_MAX_TOKENS)
    assert oi == {"model": "m", "instructions": "S", "input": "U",
                  "max_output_tokens": REVIEW_MAX_TOKENS, "temperature": 0,
                  "store": False, "text": {"format": {"type": "json_object"}}}
    an = _review_body(Provider.ANTHROPIC, "m", "S", "U",
                      schema=AI_REVIEW_RESPONSE_SCHEMA,
                      max_tokens=REVIEW_MAX_TOKENS)
    assert "format" not in an and an["max_tokens"] == REVIEW_MAX_TOKENS
    co = _review_body(Provider.OPENAI_COMPATIBLE, "m", "S", "U",
                      schema=AI_REVIEW_RESPONSE_SCHEMA,
                      max_tokens=REVIEW_MAX_TOKENS)
    assert "format" not in co and "response_format" not in co


# ---- W3-E3 closing 1: schema minLength mirrors the validator (no gap) --------------

def test_review_schema_forbids_empty_text_like_the_validator():
    rp = AI_REVIEW_RESPONSE_SCHEMA["properties"]
    assert rp["summary"]["minLength"] == 1
    ev = rp["evidence"]["items"]["properties"]
    assert ev["context_id"]["minLength"] == 1
    assert ev["statement"]["minLength"] == 1
    assert rp["missing_context"]["items"]["minLength"] == 1
    # enum fields carry no minLength (a legal enum can never be empty)
    assert "minLength" not in rp["match_assessment"]
    assert "minLength" not in rp["defect_assessment"]
    assert "minLength" not in rp["impact"]
    assert "minLength" not in rp["actionability"]
    assert "minLength" not in rp["suggested_action"]


def test_audit_schema_forbids_empty_text_like_the_validator():
    ip = AI_AUDIT_RESPONSE_SCHEMA_V1["properties"]["issues"]["items"]["properties"]
    assert ip["title"]["minLength"] == 1
    assert ip["summary"]["minLength"] == 1
    ev = ip["evidence"]["items"]["properties"]
    assert ev["context_id"]["minLength"] == 1
    assert ev["statement"]["minLength"] == 1
    assert ip["missing_context"]["items"]["minLength"] == 1
    assert "minLength" not in ip["category"]
    assert "minLength" not in ip["confidence"]
    assert "minLength" not in ip["suggested_action"]
    assert "minLength" not in AI_AUDIT_RESPONSE_SCHEMA_V1["properties"]["outcome"]


def test_every_validator_rejected_empty_string_is_also_schema_invalid():
    """The parity guard: for each field the validator rejects when empty, the
    schema must ALSO forbid it (minLength). Proven by feeding an empty value
    through the real validator and asserting the matching schema node has
    minLength:1 — the two can never diverge again."""
    from auditor.ai.review import parse_review_reply
    rp = AI_REVIEW_RESPONSE_SCHEMA["properties"]
    good_ev = {"context_id": "src:1", "statement": "x"}

    def review(**over):
        base = {"match_assessment": "uncertain",
                "defect_assessment": "uncertain", "impact": "uncertain",
                "actionability": "uncertain", "summary": "s",
                "evidence": [dict(good_ev)], "missing_context": [],
                "suggested_action": "inspect"}
        base.update(over)
        return json.dumps(base)

    # summary empty -> validator invalid AND schema minLength present
    with pytest.raises(AIError):
        parse_review_reply(review(summary=""), {"src:1"})
    assert rp["summary"]["minLength"] == 1
    # evidence.statement empty
    with pytest.raises(AIError):
        parse_review_reply(review(evidence=[{"context_id": "src:1",
                                             "statement": ""}]), {"src:1"})
    assert rp["evidence"]["items"]["properties"]["statement"]["minLength"] == 1
    # evidence.context_id empty (also not a sent id)
    with pytest.raises(AIError):
        parse_review_reply(review(evidence=[{"context_id": "",
                                             "statement": "x"}]), {"src:1"})
    assert rp["evidence"]["items"]["properties"]["context_id"]["minLength"] == 1
    # missing_context [""]
    with pytest.raises(AIError):
        parse_review_reply(review(missing_context=[""]), {"src:1"})
    assert rp["missing_context"]["items"]["minLength"] == 1

    # audit side: title/summary/statement/context_id/missing empties
    api = AI_AUDIT_RESPONSE_SCHEMA_V1["properties"]["issues"]["items"]["properties"]
    issue = {"title": "t", "category": "authorization", "confidence": "low",
             "summary": "s",
             "evidence": [{"context_id": "src:1", "line_start": 2,
                           "line_end": 5, "statement": "x"}],
             "missing_context": [], "suggested_action": "inspect"}

    def audit(**over):
        it = dict(issue)
        it.update(over)
        return json.dumps({"outcome": "issues_found", "issues": [it]})

    for field, node in (("title", api["title"]), ("summary", api["summary"])):
        with pytest.raises(AIError):
            parse_audit_reply(audit(**{field: ""}), PIECE_MAP)
        assert node["minLength"] == 1
    with pytest.raises(AIError):
        parse_audit_reply(audit(evidence=[{"context_id": "src:1",
                                           "line_start": 2, "line_end": 5,
                                           "statement": ""}]), PIECE_MAP)
    assert api["evidence"]["items"]["properties"]["statement"]["minLength"] == 1
    with pytest.raises(AIError):
        parse_audit_reply(audit(missing_context=[""]), PIECE_MAP)
    assert api["missing_context"]["items"]["minLength"] == 1


# ---- W3-E3 closing 2: the AUDIT remote wire is proven per provider -----------------

@pytest.mark.parametrize("provider,expected", [
    (Provider.OPENAI, {"model": "m", "instructions": "S", "input": "U",
                       "max_output_tokens": AUDIT_MAX_OUTPUT_TOKENS,
                       "temperature": 0, "store": False,
                       "text": {"format": {"type": "json_object"}}}),
    (Provider.XAI, {"model": "m", "instructions": "S", "input": "U",
                    "max_output_tokens": AUDIT_MAX_OUTPUT_TOKENS,
                    "temperature": 0, "store": False,
                    "text": {"format": {"type": "json_object"}}}),
    (Provider.ANTHROPIC, {"model": "m", "max_tokens": AUDIT_MAX_OUTPUT_TOKENS,
                          "system": "S",
                          "messages": [{"role": "user", "content": "U"}],
                          "temperature": 0}),
    (Provider.OPENAI_COMPATIBLE, {"model": "m",
                                  "messages": [
                                      {"role": "system", "content": "S"},
                                      {"role": "user", "content": "U"}],
                                  "max_tokens": AUDIT_MAX_OUTPUT_TOKENS,
                                  "temperature": 0}),
])
def test_audit_remote_wire_keeps_shape_and_takes_1536(provider, expected):
    body = _review_body(provider, "m", "S", "U",
                        schema=AI_AUDIT_RESPONSE_SCHEMA_V1,
                        max_tokens=AUDIT_MAX_OUTPUT_TOKENS)
    assert body == expected                         # byte-for-byte
    # the full audit schema is NEVER sent to a remote provider this round
    assert body.get("format") in (None, {"type": "json_object"}) \
        or "format" not in body
    assert AI_AUDIT_RESPONSE_SCHEMA_V1 not in body.values()
    assert "response_format" not in body
    cap = body.get("max_output_tokens", body.get("max_tokens"))
    assert cap == AUDIT_MAX_OUTPUT_TOKENS == 1536


def test_audit_and_review_remote_caps_differ_by_contract():
    """W3-B remote review stays 1024; W3-E remote audit is 1536 — same
    provider-specific shape, only the output cap follows the audit budget."""
    for provider in (Provider.OPENAI, Provider.XAI):
        r = _review_body(provider, "m", "S", "U",
                         schema=AI_REVIEW_RESPONSE_SCHEMA,
                         max_tokens=REVIEW_MAX_TOKENS)
        a = _review_body(provider, "m", "S", "U",
                         schema=AI_AUDIT_RESPONSE_SCHEMA_V1,
                         max_tokens=AUDIT_MAX_OUTPUT_TOKENS)
        assert r["max_output_tokens"] == 1024
        assert a["max_output_tokens"] == 1536
        # everything else identical
        assert {k: v for k, v in r.items() if k != "max_output_tokens"} \
            == {k: v for k, v in a.items() if k != "max_output_tokens"}
    # Ollama audit still carries the full schema + think:false + 1536
    ob = _review_body(Provider.OLLAMA, "m", "S", "U",
                      schema=AI_AUDIT_RESPONSE_SCHEMA_V1,
                      max_tokens=AUDIT_MAX_OUTPUT_TOKENS)
    assert ob["format"] is AI_AUDIT_RESPONSE_SCHEMA_V1
    assert ob["think"] is False
    assert ob["options"]["num_predict"] == 1536
