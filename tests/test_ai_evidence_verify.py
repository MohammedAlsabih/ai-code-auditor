"""W3-E4C2: deterministic evidence-content verification. A structurally legal
citation whose lines don't carry the claim is rejected; a right-category
citation is accepted; a line-anchored credential fact makes a credential claim
provable without exposing the secret; a pre-existing *** marker never does;
per AI001-AI008 the supported / counter-evidence / insufficient cases hold;
only `supported` is promoted; the model's words are never rewritten. No net."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from auditor.ai.audit import build_audit_pack, candidates_from_result
from auditor.ai.audit_index import RepositoryAuditIndex
from auditor.ai.audit_queries import query_by_id
from auditor.ai.evidence_verify import (
    VERIFY_INSUFFICIENT, VERIFY_STATES, VERIFY_SUPPORTED, VERIFY_UNSUPPORTED,
    verify_result)
from auditor.ai.quality_corpus import cases, holdout_cases

ALL = {c.case_id: c for c in list(cases()) + list(holdout_cases())}


def _pack(case_id: str):
    c = ALL[case_id]
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        for cf in c.files:
            p = base / cf.rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(cf.text, encoding="utf-8")
        idx = RepositoryAuditIndex(base, c.project_roots)
        return build_audit_pack(idx, c.project, query_by_id(c.query_id))


def _first_cid(pack):
    return next(iter(pack["piece_map"]))


def _issue(pack, cid, ls, le, category, confidence="high", statement="x"):
    return {"outcome": "issues_found", "issues": [{
        "title": "t", "category": category, "confidence": confidence,
        "summary": "s",
        "evidence": [{"context_id": cid, "file": pack["piece_map"][cid]["file"],
                      "line_start": ls, "line_end": le, "statement": statement}],
        "missing_context": [], "suggested_action": "inspect"}]}


def _verify_one(pack, cid, ls, le, category, confidence="high"):
    r = verify_result(_issue(pack, cid, ls, le, category, confidence), pack)
    return r["issues"][0]["verification"], r["issues"][0]["verification_reason"]


# ---- the two headline failures ------------------------------------------------------

def test_credential_fact_makes_a_masked_literal_provable_without_the_secret():
    pack = _pack("AI003-pos")            # literal Password= masked to ***
    facts = next(p for p in pack["pieces"]
                 if p.get("context_id") == "redaction_facts")
    f = facts["facts"][0]
    v, reason = _verify_one(pack, f["context_id"], f["line_start"],
                            f["line_end"], "credentials")
    assert v == VERIFY_SUPPORTED
    # nothing outgoing carries the original value (placeholder corpus value)
    assert "hunter2placeholder" not in json.dumps(pack["pieces"])


def test_credential_claim_on_a_line_with_no_literal_and_no_fact_is_rejected():
    # cite a NON-credential, non-fact line under a credential claim (the
    # wrong-file citation shape that two field models produced on P002)
    pack = _pack("AI003-pos")
    cid = _first_cid(pack)
    v, reason = _verify_one(pack, cid, 1, 1, "credentials")  # class decl line
    assert v == VERIFY_UNSUPPORTED
    assert reason == "credential_claim_without_literal_or_fact"


def test_fabricated_statement_in_a_legal_span_without_the_content_is_rejected():
    # AI005 wrap-and-rethrow (sound): a swallow claim citing the rethrow lines
    pack = _pack("AI005-hold-neg")
    cid = next(c for c, m in pack["piece_map"].items())
    spans = pack["piece_map"][cid]["spans"]
    ls = spans[0][0]
    v, reason = _verify_one(pack, cid, ls, spans[0][1], "error_handling")
    assert v != VERIFY_SUPPORTED           # a rethrow is not a swallowed failure


# ---- the AI001-AI008 table ----------------------------------------------------------

_SUPPORTED = ["AI001-pos", "AI002-pos", "AI003-pos", "AI004-pos", "AI005-pos",
              "AI006-pos", "AI007-pos", "AI008-pos", "AI001-hold-pos",
              "AI002-hold-pos", "AI003-hold-pos", "AI004-hold-pos",
              "AI005-hold-pos", "AI006-hold-pos", "AI007-hold-pos",
              "AI008-hold-pos"]


@pytest.mark.parametrize("case_id", _SUPPORTED)
def test_every_positive_target_citation_is_supported(case_id):
    c = ALL[case_id]
    pack = _pack(case_id)
    # cite the case's own target file+span with the query's category
    tf, tls, tle = c.target.file, c.target.line_start, c.target.line_end
    cid = next(k for k, m in pack["piece_map"].items() if m["file"] == tf)
    v, reason = _verify_one(pack, cid, tls, tle, c.category)
    assert v == VERIFY_SUPPORTED, (case_id, reason)


@pytest.mark.parametrize("case_id", [
    "AI002-hold-abstain", "AI006-hold-abstain", "AI005-hold-abstain",
    "AI005-abstain", "AI006-abstain"])
def test_abstain_cases_whose_deciding_code_is_unsent_are_not_supported(case_id):
    c = ALL[case_id]
    pack = _pack(case_id)
    cid = next(iter(pack["piece_map"]))
    spans = pack["piece_map"][cid]["spans"]
    v, reason = _verify_one(pack, cid, spans[0][0], spans[0][1], c.category)
    assert v in (VERIFY_UNSUPPORTED, VERIFY_INSUFFICIENT), (case_id, v)


def test_dependency_claim_without_a_manifest_is_insufficient():
    pack = _pack("AI007-hold-abstain")   # no manifest in this project
    assert not any(str(p.get("context_id", "")).startswith("manifest:")
                   for p in pack["pieces"])
    cid = _first_cid(pack)
    spans = pack["piece_map"][cid]["spans"]
    v, reason = _verify_one(pack, cid, spans[0][0], spans[0][1],
                            "dependency_integration")
    assert v == VERIFY_INSUFFICIENT
    assert reason == "dependency_claim_without_manifest"


def test_out_of_scope_sql_under_dependency_is_not_supported():
    pack = _pack("AI007-out-of-scope")
    cid = _first_cid(pack)
    spans = pack["piece_map"][cid]["spans"]
    v, _ = _verify_one(pack, cid, spans[0][0], spans[0][1],
                       "dependency_integration")
    assert v != VERIFY_SUPPORTED


# ---- promotion, transparency, and immutability of the reply -------------------------

def test_only_supported_is_promoted_but_all_are_kept():
    pack = _pack("AI002-pos")
    cid = _first_cid(pack)
    # one supported (sink line) + one unsupported (credential claim off-line)
    result = {"outcome": "issues_found", "project": "p",
              "query_id": "AI002", "audit_unit_id": "a" * 64,
              "context_digest": "b" * 64, "provider": "ollama", "model": "m",
              "prompt_version": "w3e-v4", "created_at": "2026-07-25T00:00:00Z",
              "issues": [
                  {"title": "sink", "category": "input_handling",
                   "confidence": "high", "summary": "s",
                   "evidence": [{"context_id": cid,
                                 "file": pack["piece_map"][cid]["file"],
                                 "line_start": pack["piece_map"][cid]["spans"][0][0],
                                 "line_end": pack["piece_map"][cid]["spans"][0][1],
                                 "statement": "x"}],
                   "missing_context": [], "suggested_action": "inspect"}]}
    result = verify_result(result, pack)
    cands = candidates_from_result(result)
    assert len(cands) == 1
    assert cands[0]["verification"] in VERIFY_STATES
    supported = [c for c in cands if c["verification"] == VERIFY_SUPPORTED]
    assert len(supported) == 1                      # promoted
    # the non-promoted still exist as candidates (transparency), never dropped
    assert len(cands) == len(result["issues"])


def test_verifier_never_rewrites_the_models_words():
    pack = _pack("AI002-pos")
    cid = _first_cid(pack)
    ls = pack["piece_map"][cid]["spans"][0][0]
    issue = _issue(pack, cid, ls, ls, "input_handling",
                   statement="the exact words the model wrote")
    before = json.loads(json.dumps(issue))
    after = verify_result(issue, pack)
    for k in ("title", "category", "confidence", "summary", "evidence",
              "missing_context", "suggested_action"):
        assert after["issues"][0][k] == before["issues"][0][k]
    assert set(after["issues"][0]) - set(before["issues"][0]) == {
        "verification", "verification_reason"}


def test_run_case_preserves_the_verification_verdict():
    # the quality harness must carry the verifier's verdict through so
    # verified-effective metrics are computable (regression for the E4C2
    # plumbing that had dropped it)
    from auditor.ai.contract import HttpResponse, Provider
    from auditor.ai.quality_harness import run_case

    pack_cid = None
    _cpack = _pack("AI002-pos")
    pack_cid = _first_cid(_cpack)
    ls = _cpack["piece_map"][pack_cid]["spans"][0][0]

    class T:
        def request(self, method, url, headers, json_body, timeout):
            reply = {"outcome": "issues_found", "issues": [{
                "title": "t", "category": "input_handling", "confidence": "high",
                "summary": "s",
                "evidence": [{"context_id": pack_cid, "line_start": ls,
                              "line_end": ls, "statement": "e"}],
                "missing_context": [], "suggested_action": "inspect"}]}
            return HttpResponse(200, json.dumps(
                {"message": {"role": "assistant",
                             "content": json.dumps(reply)}}).encode())

    case = next(c for c in cases() if c.case_id == "AI002-pos")
    r = run_case(case, Provider.OLLAMA, "m", T(),
                 env={"OLLAMA_HOST": "http://127.0.0.1:11434"})
    assert r["state"] == "completed"
    assert r["issues"][0]["verification"] in VERIFY_STATES
    assert r["issues"][0]["verification_reason"]


def test_citation_reasons_carry_no_snippets_or_paths():
    pack = _pack("AI003-pos")
    for cat in ("credentials", "input_handling", "authorization"):
        _, reason = _verify_one(pack, _first_cid(pack), 1, 1, cat)
        assert "/" not in reason and " " not in reason and "." not in reason


# ---- W3-E4C closing: FAIL-CLOSED --------------------------------------------------

def test_fail_closed_never_defaults_to_supported():
    from auditor.ai.evidence_verify import fail_closed
    for bad in ((None, None), ("supported", None), ("supported", "bogus_code"),
                ("bananas", "cited_lines_carry_category_evidence"),
                ("", ""), (VERIFY_SUPPORTED, "")):
        v, r = fail_closed(*bad)
        assert v == VERIFY_INSUFFICIENT and r == "verification_missing", bad
    # a legal pair passes through unchanged
    assert fail_closed(VERIFY_SUPPORTED, "cited_lines_carry_category_evidence") \
        == (VERIFY_SUPPORTED, "cited_lines_carry_category_evidence")


def test_candidate_without_verification_fails_closed_in_backend():
    from auditor.ai.audit import candidates_from_result
    pack = _pack("AI003-pos")
    cid = _first_cid(pack)
    result = {"issues": [{"title": "t", "category": "credentials",
                          "confidence": "high", "summary": "s",
                          "evidence": [{"context_id": cid,
                                        "file": pack["piece_map"][cid]["file"],
                                        "line_start": 1, "line_end": 1,
                                        "statement": "e"}],
                          "missing_context": [], "suggested_action": "inspect"}],
              "audit_unit_id": "a" * 64, "project": "p", "query_id": "AI003",
              "context_digest": "b" * 64, "provider": "ollama", "model": "m",
              "prompt_version": "w3e-v4", "created_at": "2026-07-25T00:00:00Z"}
    c = candidates_from_result(result)[0]     # NOT passed through verify_result
    assert c["verification"] == VERIFY_INSUFFICIENT
    assert c["verification_reason"] == "verification_missing"


def test_legacy_schema1_sidecar_loads_but_never_screened(tmp_path):
    import json as _json

    import auditor.ai.audit_store as store
    cand = {"candidate_id": "a" * 64, "audit_unit_id": "b" * 64, "project": "p",
            "query_id": "AI003", "file": "a.cs", "line": 1, "title": "t",
            "category": "credentials", "confidence": "high", "summary": "s",
            "evidence": [{"context_id": "src:1", "file": "a.cs",
                          "line_start": 1, "line_end": 1, "statement": "e"}],
            "missing_context": [], "suggested_action": "inspect",
            "related_static_findings": [], "provider": "ollama", "model": "m",
            "prompt_version": "w3e-v3", "context_digest": "c" * 64,
            "created_at": "2026-07-25T00:00:00Z"}
    p = tmp_path / "r.ai-audit.json"
    p.write_text(_json.dumps({"schema_version": 1, "audits": {}, "results": {},
                              "candidates": {"a" * 64: cand},
                              "candidate_reviews": {}}), encoding="utf-8")
    s = store.AIAuditStore(p)
    assert s.available and s.legacy                    # viewable, flagged legacy
    got = s.all_candidates()[0]
    assert got["verification"] == VERIFY_INSUFFICIENT
    assert got["verification_reason"] == "verification_missing"


# ---- W3-E4C closing: the SEVEN reproduced screening defects -----------------------

def test_env_reference_is_not_a_credential():
    pack = _pack("AI003-hold-neg")                     # process.env.DB_TOKEN
    cid = _first_cid(pack)
    sp = pack["piece_map"][cid]["spans"][0]
    v, reason = _verify_one(pack, cid, sp[0], sp[1], "credentials")
    assert v == VERIFY_UNSUPPORTED and reason == "counter_evidence_present"


def test_getenv_with_secret_named_arg_is_not_a_credential():
    # a synthetic os.getenv("PASSWORD") citation
    from auditor.ai.evidence_verify import (
        _fact_lines, _lines_by_cid, verify_issue)
    pk = _pack("AI003-pos")
    # override the cited-line reconstruction with a crafted line
    fake_pack = {"pieces": [{"context_id": "src:1", "file": "cfg.py",
                             "text": '1: SECRET = os.getenv("PASSWORD")'}],
                 "piece_map": {"src:1": {"file": "cfg.py", "spans": [[1, 1]]}},
                 "canonical": ""}
    issue = {"category": "credentials", "confidence": "high",
             "evidence": [{"context_id": "src:1", "file": "cfg.py",
                           "line_start": 1, "line_end": 1, "statement": "x"}]}
    v, reason = verify_issue(issue, fake_pack, _lines_by_cid(fake_pack),
                             _fact_lines(fake_pack))
    assert v == VERIFY_UNSUPPORTED and reason == "counter_evidence_present"
    assert pk is not None


def test_parameterized_sql_is_screened_out():
    pack = _pack("AI002-neg-sql")
    cid = _first_cid(pack)
    sp = pack["piece_map"][cid]["spans"][0]
    v, reason = _verify_one(pack, cid, sp[0], sp[1], "input_handling")
    assert v == VERIFY_UNSUPPORTED and reason == "counter_evidence_present"


def test_declared_import_is_not_a_dependency_issue():
    pack = _pack("AI007-neg")                          # dompurify declared
    cid = next(k for k, m in pack["piece_map"].items() if m["file"].endswith(".ts"))
    sp = pack["piece_map"][cid]["spans"][0]
    v, reason = _verify_one(pack, cid, sp[0], sp[1], "dependency_integration")
    assert v == VERIFY_UNSUPPORTED and reason == "counter_evidence_present"


def test_single_savechanges_is_not_a_concurrency_hazard():
    pack = _pack("AI004-pos")                          # cite ONE SaveChanges line
    cid = _first_cid(pack)
    v, _ = _verify_one(pack, cid, 3, 3, "concurrency")
    assert v != VERIFY_SUPPORTED


def test_csharp_namespace_import_is_ambiguous_not_a_finding():
    from auditor.ai.evidence_verify import (
        _fact_lines, _lines_by_cid, verify_issue)
    pack = {"pieces": [{"context_id": "src:1", "file": "A.cs",
                        "text": "1: using Company.Shared.Telemetry;"},
                       {"context_id": "manifest:1", "file": "p.csproj",
                        "text": "1: <PackageReference Include=\"Serilog\" />"}],
            "piece_map": {"src:1": {"file": "A.cs", "spans": [[1, 1]]}},
            "canonical": ""}
    issue = {"category": "dependency_integration", "confidence": "high",
             "evidence": [{"context_id": "src:1", "file": "A.cs",
                           "line_start": 1, "line_end": 1, "statement": "x"}]}
    v, reason = verify_issue(issue, pack, _lines_by_cid(pack), _fact_lines(pack))
    assert v == VERIFY_INSUFFICIENT and reason == "namespace_package_ambiguous"


# ---- W3-E4C closing: fact provenance is class- and location-aware ------------------

def test_a_fact_of_the_wrong_line_does_not_prove_a_credential():
    from auditor.ai.evidence_verify import (
        _fact_lines, _lines_by_cid, verify_issue)
    # fact at line 9, claim cites line 3 (no fact, no literal, no ref)
    pack = {"pieces": [
        {"context_id": "src:1", "file": "a.cs",
         "text": "3:   return Config.Build();"},
        {"context_id": "redaction_facts", "facts": [
            {"context_id": "src:1", "file": "a.cs", "line_start": 9,
             "line_end": 9, "redaction_class": "token_kv", "fact": "x"}]}],
        "piece_map": {"src:1": {"file": "a.cs", "spans": [[3, 3]]}},
        "canonical": ""}
    issue = {"category": "credentials", "confidence": "high",
             "evidence": [{"context_id": "src:1", "file": "a.cs",
                           "line_start": 3, "line_end": 3, "statement": "x"}]}
    v, _ = verify_issue(issue, pack, _lines_by_cid(pack), _fact_lines(pack))
    assert v != VERIFY_SUPPORTED


def test_premasked_source_star_without_a_fact_proves_nothing():
    from auditor.ai.evidence_verify import (
        _fact_lines, _lines_by_cid, verify_issue)
    pack = {"pieces": [{"context_id": "src:1", "file": "a.py",
                        "text": '1: X = "already ***"'}],   # no fact
            "piece_map": {"src:1": {"file": "a.py", "spans": [[1, 1]]}},
            "canonical": ""}
    issue = {"category": "credentials", "confidence": "high",
             "evidence": [{"context_id": "src:1", "file": "a.py",
                           "line_start": 1, "line_end": 1, "statement": "x"}]}
    v, _ = verify_issue(issue, pack, _lines_by_cid(pack), _fact_lines(pack))
    assert v != VERIFY_SUPPORTED
