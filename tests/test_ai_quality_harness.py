"""W3-E4A2 (closing): the auditable quality harness — multi-file plan, strict
one-to-one whose identity is RE-DERIVED from the corpus (a fake identity forged
identically into plan and results is still rejected; a different corpus reusing
a case_id is rejected), the honest classifier, corpus-digest sensitivity,
answer-leak-free source, the per-query file cap, and confined output.
FakeTransport only; no network."""
from __future__ import annotations

import copy
import dataclasses
import json
import tempfile
from pathlib import Path

import pytest

from auditor.ai.audit import build_audit_pack
from auditor.ai.audit_index import RepositoryAuditIndex
from auditor.ai.audit_queries import query_by_id
from auditor.ai.contract import ERROR_CODES, HttpResponse, Provider
from auditor.ai.quality_corpus import (
    EXPECT_NEGATIVE, SPLIT_DEVELOPMENT, SPLIT_HOLDOUT, CorpusCase, CorpusFile,
    cases, corpus_digest, holdout_cases)
from auditor.ai.quality_harness import (
    HarnessError, anonymized_summary, build_plan, classify, run_case,
    run_corpus, verify_one_to_one)

LOCAL = {"OLLAMA_HOST": "http://127.0.0.1:11434"}
CORPUS = cases()


class SmartTransport:
    """Obeys the required_category and cites the first sent span. mode:
    'target' cites the case's target file when present (a correct detection);
    'offtarget' cites a non-target sent file (unrelated candidate);
    'clean' never flags."""

    def __init__(self, mode="target"):
        self.mode = mode

    def request(self, method, url, headers, json_body, timeout):
        content = json_body["messages"][-1]["content"]
        pieces = json.loads(content.split("\n", 1)[1])
        cat = "other"
        srcs = []
        for p in pieces:
            if p.get("context_id") == "query":
                cat = p.get("required_category", "other")
            elif str(p.get("context_id", "")).startswith(("src:", "manifest:")):
                srcs.append(p)
        if self.mode == "clean" or not srcs:
            return self._resp({"outcome": "no_issue_observed", "issues": []})
        pick = srcs[-1] if self.mode == "offtarget" else srcs[0]
        span = pick["spans"][0]
        return self._resp({"outcome": "issues_found", "issues": [{
            "title": "t", "category": cat, "confidence": "high",
            "summary": "s", "evidence": [{"context_id": pick["context_id"],
                "line_start": span[0], "line_end": span[0],
                "statement": "e"}],
            "missing_context": [], "suggested_action": "inspect"}]})

    @staticmethod
    def _resp(reply):
        return HttpResponse(200, json.dumps(
            {"message": {"role": "assistant",
                         "content": json.dumps(reply)}}).encode())


def _run(mode):
    plan = build_plan(CORPUS)
    results = [run_case(c, Provider.OLLAMA, "m", SmartTransport(mode),
                        env=LOCAL) for c in CORPUS]
    return plan, results


# ---- plan carries the auditable facts ------------------------------------------------

def test_plan_stores_sent_files_spans_and_targets():
    plan = build_plan(CORPUS)
    for c in plan["cases"]:
        assert set(c) >= {"sent_files", "sent_spans", "target", "unit_id",
                          "context_digest", "project"}
        if c["kind"] == "positive":
            assert c["target"] is not None and c["unit_id"]


def test_full_result_keeps_every_model_field():
    _, results = _run("target")
    withissues = [r for r in results if r["state"] == "completed"
                  and r.get("issues")]
    assert withissues
    for r in withissues:
        for i in r["issues"]:
            assert set(i) >= {"title", "category", "confidence", "summary",
                              "evidence", "missing_context",
                              "suggested_action"}
        assert {"provider", "model", "prompt_version", "query_version"} <= set(r)


# ---- strict one-to-one: identity RE-DERIVED from the corpus --------------------------

def test_one_to_one_accepts_matching_and_rejects_tampering():
    plan, results = _run("target")
    verify_one_to_one(plan, results, CORPUS)
    swapped = [dict(r) for r in results]
    hit = next(r for r in swapped if r["state"] == "completed")
    hit["context_digest"] = "0" * 64
    with pytest.raises(HarnessError):
        verify_one_to_one(plan, swapped, CORPUS)


def test_forged_identity_is_rejected_even_when_plan_and_result_agree():
    plan, results = _run("target")
    # forge PLAN only
    p1 = copy.deepcopy(plan)
    p1["cases"][0]["unit_id"] = "FORGED"
    with pytest.raises(HarnessError):
        verify_one_to_one(p1, results, CORPUS)
    # forge RESULT only
    r1 = [dict(r) for r in results]
    r1[0]["unit_id"] = "FORGED"
    with pytest.raises(HarnessError):
        verify_one_to_one(plan, r1, CORPUS)
    # forge the SAME fake identity into BOTH — still rejected, because the
    # truth is recomputed from the corpus
    p2 = copy.deepcopy(plan)
    r2 = [dict(r) for r in results]
    vid = p2["cases"][0]["case_id"]
    p2["cases"][0]["unit_id"] = "SAME"
    p2["cases"][0]["context_digest"] = "S" * 64
    for r in r2:
        if r["case_id"] == vid:
            r["unit_id"] = "SAME"
            r["context_digest"] = "S" * 64
    with pytest.raises(HarnessError):
        verify_one_to_one(p2, r2, CORPUS)


def test_different_corpus_with_same_case_id_is_rejected():
    plan, results = _run("target")
    # a corpus that keeps every case_id but changes ONE case's content
    victim = CORPUS[0]
    changed = dataclasses.replace(
        victim,
        files=tuple(dataclasses.replace(f, text=f.text + "\n// drift\n")
                    for f in victim.files))
    other = (changed,) + tuple(CORPUS[1:])
    with pytest.raises(HarnessError):
        verify_one_to_one(plan, results, other)


def test_whole_plan_case_is_verified_not_just_identity_fields():
    # tampering ANY plan field — including reason/project/input_bytes/
    # sent_files — is rejected, because each case is compared structurally to
    # the corpus-rebuilt truth
    plan, results = _run("target")
    for field, bad in (("reason", "TAMPERED"), ("project", "zzz"),
                       ("input_bytes", 999999), ("sent_files", ["x.py"])):
        p = copy.deepcopy(plan)
        p["cases"][0][field] = bad
        with pytest.raises(HarnessError):
            verify_one_to_one(p, results, CORPUS)


def test_no_unit_result_with_a_real_unit_id_is_rejected():
    plan, results = _run("target")
    rs = [dict(r) for r in results]
    victim = next(r for r in rs if r["state"] == "completed")
    victim["state"] = "no_unit"          # but keeps its real unit_id/digest
    with pytest.raises(HarnessError):
        verify_one_to_one(plan, rs, CORPUS)


def test_illegal_result_state_is_rejected():
    plan, results = _run("target")
    rs = [dict(r) for r in results]
    rs[0]["state"] = "banana"
    with pytest.raises(HarnessError):
        verify_one_to_one(plan, rs, CORPUS)


def test_completed_result_for_a_case_that_built_no_unit_is_rejected():
    # a case whose file carries NO AI001 surface -> no pack is built
    empty = CorpusCase(
        "X-empty", "AI001", EXPECT_NEGATIVE, "p",
        (CorpusFile("p/plain.ts", "export const x = 1;\n", "typescript"),),
        "a plain exported constant; nothing here reaches an endpoint.")
    corpus = (empty,)
    plan = build_plan(corpus)
    assert plan["cases"][0]["unit_id"] == ""          # genuinely no unit
    ran = [{"case_id": "X-empty", "query_id": "AI001",
            "category": "authorization", "expected": "negative",
            "state": "completed", "unit_id": "u", "context_digest": "d",
            "provider": "x", "model": "m",
            "prompt_version": plan["prompt_version"], "query_version": 2,
            "issues": []}]
    with pytest.raises(HarnessError):                  # completed w/o a unit
        verify_one_to_one(plan, ran, corpus)
    ok = [{"case_id": "X-empty", "query_id": "AI001",
           "category": "authorization", "expected": "negative",
           "state": "no_unit", "unit_id": "", "context_digest": ""}]
    verify_one_to_one(plan, ok, corpus)               # the only legal result


def test_shuffled_order_with_valid_identities_passes():
    plan, results = _run("target")
    p = copy.deepcopy(plan)
    p["cases"].reverse()
    verify_one_to_one(p, list(reversed(results)), CORPUS)   # no raise


def test_verify_error_messages_leak_no_ids_paths_or_snippets():
    plan, results = _run("target")
    bad = copy.deepcopy(plan)
    bad["cases"][0]["unit_id"] = "FORGED-abc"
    with pytest.raises(HarnessError) as ei:
        verify_one_to_one(bad, results, CORPUS)
    msg = str(ei.value)
    assert "FORGED" not in msg and "/" not in msg and ".cs" not in msg


def test_citation_outside_sent_spans_is_rejected():
    plan, results = _run("target")
    tampered = [dict(r) for r in results]
    r = next(x for x in tampered if x["state"] == "completed" and x.get("issues"))
    r["issues"] = json.loads(json.dumps(r["issues"]))
    r["issues"][0]["evidence"][0]["line_start"] = 99999
    r["issues"][0]["evidence"][0]["line_end"] = 99999
    with pytest.raises(HarnessError):
        verify_one_to_one(plan, tampered, CORPUS)


def test_duplicate_missing_extra_rejected():
    plan, results = _run("target")
    with pytest.raises(HarnessError):
        verify_one_to_one(plan, results + [dict(results[0])], CORPUS)
    with pytest.raises(HarnessError):
        verify_one_to_one(plan, results[:-1], CORPUS)


# ---- classifier contract -------------------------------------------------------------

def test_no_unit_is_retrieval_not_assessed_never_pass():
    # A clean run leaves every positive MISSED, so no query is ever "pass".
    plan2, results = _run("clean")
    cls = classify(plan2, results, CORPUS)
    for qd in cls["per_query"].values():
        assert qd["verdict"] != "pass"


def test_positive_detected_only_on_target_file_and_span():
    plan, results = _run("target")
    cls = classify(plan, results, CORPUS)
    plan2, off = _run("offtarget")
    cls_off = classify(plan2, off, CORPUS)
    total_detected_off = sum(qd["positive"]["detected"]
                             for qd in cls_off["per_query"].values())
    total_unrelated = sum(qd["unrelated_candidates"]
                          for qd in cls_off["per_query"].values())
    assert total_unrelated >= 1
    assert total_detected_off <= sum(
        qd["positive"]["detected"] for qd in cls["per_query"].values())


def test_abstain_no_issue_is_separate_from_honest():
    plan, results = _run("clean")
    cls = classify(plan, results, CORPUS)
    tot = anonymized_summary(cls)["totals"]
    assert tot["abstain_no_issue"] >= 1
    assert tot["honest_insufficient"] == 0


@pytest.mark.parametrize("code", sorted(ERROR_CODES))
def test_every_error_code_classifies_without_crash_or_fake_assessment(code):
    """A legal provider error in ANY kind (positive/negative/abstain) must be
    recorded as an error and NEVER read for outcome/issues, NEVER counted
    assessed/clean/missed/overclaim/honest. timeout & invalid_response are
    quality faults (needs_hardening); the rest are environment faults
    (insufficient_evidence)."""
    plan = build_plan(CORPUS)
    # every unit-bearing case returns this error; no_unit cases stay no_unit
    results = []
    for p in plan["cases"]:
        st = code if p["unit_id"] else "no_unit"
        results.append({"case_id": p["case_id"], "query_id": p["query_id"],
                        "category": p["category"], "expected": p["kind"],
                        "state": st, "unit_id": p["unit_id"],
                        "context_digest": p["context_digest"]})
    cls = classify(plan, results, CORPUS)               # no crash
    for qd in cls["per_query"].values():
        # the error was counted explicitly, nothing was fabricated
        assert qd["errors"][code] >= 1
        assert qd["positive"]["assessed"] == 0
        assert qd["negative"]["assessed"] == 0
        assert qd["abstain"]["assessed"] == 0
        assert qd["negative"]["clean"] == 0
        assert qd["positive"]["missed"] == 0
        assert qd["abstain"]["overclaim"] == 0
        assert qd["abstain"]["honest_insufficient"] == 0
        expected = ("needs_hardening" if code in ("timeout", "invalid_response")
                    else "insufficient_evidence")
        assert qd["verdict"] == expected, (code, qd["verdict"])
    # the anonymized summary carries the explicit, safe error counter
    tot = anonymized_summary(cls)["totals"]
    assert tot["errors"][code] >= 1
    assert tot["clean"] == 0 and tot["detected"] == 0 and tot["overclaim"] == 0


# ---- corpus digest sensitivity -------------------------------------------------------

def test_corpus_digest_is_of_the_passed_corpus():
    full = corpus_digest(CORPUS)
    subset = corpus_digest((CORPUS[0],))
    assert full != subset
    assert corpus_digest(CORPUS) == full


# ---- negatives from source; out-of-scope negative ------------------------------------

def test_negatives_and_out_of_scope_present_from_source():
    negs = {c.case_id for c in CORPUS if c.kind == EXPECT_NEGATIVE}
    assert {"AI002-neg-sql", "AI002-neg-dompurify", "AI001-neg",
            "AI007-out-of-scope"} <= negs


def test_no_answer_leaking_in_source_or_paths():
    banned = ("no authorization", "no transaction", "no schema validation",
              "no ownership", "swallowed", "fully implemented",
              "nothing to fix", "safe", "no issue")
    for c in cases(None):                    # BOTH splits
        blob = " ".join([f.text for f in c.files]
                        + [f.rel for f in c.files]).lower()
        for leak in banned:
            assert leak not in blob, (c.case_id, leak)


def test_ai008_negative_carries_a_real_marker_without_a_verdict_comment():
    neg = next(c for c in CORPUS if c.case_id == "AI008-neg")
    blob = " ".join(f.text for f in neg.files)
    assert "TODO" in blob or "FIXME" in blob        # a real marker, so it retrieves
    assert "//" not in blob or "fixme upstream" not in blob.lower()


# ---- per-query file cap (hard cap) ---------------------------------------------------

def test_files_sent_never_exceeds_max_context_files():
    for c in cases(None):                    # BOTH splits
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            for cf in c.files:
                p = base / cf.rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(cf.text, encoding="utf-8")
            idx = RepositoryAuditIndex(base, c.project_roots)
            pack = build_audit_pack(idx, c.project, query_by_id(c.query_id))
            if pack is None:
                continue
            cap = query_by_id(c.query_id).max_context_files
            assert pack["privacy_manifest"]["files_sent"] <= cap, c.case_id


# ---- W3-E4B1: pre-registered development + holdout splits ----------------------------

def test_holdout_covers_every_query_with_all_three_kinds():
    hold = holdout_cases()
    assert len(hold) >= 24
    assert all(c.split == SPLIT_HOLDOUT for c in hold)
    assert all(c.split == SPLIT_DEVELOPMENT for c in CORPUS)
    by_query: dict[str, set] = {}
    for c in hold:
        by_query.setdefault(c.query_id, set()).add(c.kind)
    for qid in ("AI001", "AI002", "AI003", "AI004", "AI005", "AI006",
                "AI007", "AI008"):
        assert by_query.get(qid) == {"positive", "negative", "abstain"}, qid
    for c in hold:
        if c.kind == "positive":
            assert c.target is not None, c.case_id


def test_holdout_never_repeats_a_development_snippet():
    dev_texts = {f.text for c in CORPUS for f in c.files}
    for c in holdout_cases():
        for f in c.files:
            assert f.text not in dev_texts, c.case_id


def test_every_holdout_case_builds_a_real_unit_with_target_in_spans():
    for c in holdout_cases():
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            for cf in c.files:
                p = base / cf.rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(cf.text, encoding="utf-8")
            idx = RepositoryAuditIndex(base, c.project_roots)
            pack = build_audit_pack(idx, c.project, query_by_id(c.query_id))
            assert pack is not None, c.case_id           # every case retrieves
            if c.kind == "positive":
                spans = {m["file"]: m["spans"]
                         for m in pack["piece_map"].values()}
                s = spans.get(c.target.file)
                assert s and any(a <= c.target.line_start
                                 and c.target.line_end <= b
                                 for a, b in s), c.case_id


def test_split_digests_are_fixed_and_distinct():
    d_dev = corpus_digest(CORPUS)
    d_hold = corpus_digest(holdout_cases())
    d_all = corpus_digest(cases(None))
    assert len({d_dev, d_hold, d_all}) == 3
    # the plan records each case's split, and holdout plans carry it through
    plan = build_plan(holdout_cases())
    assert all(pc["split"] == SPLIT_HOLDOUT for pc in plan["cases"])
    assert plan["corpus_digest"] == d_hold


# ---- confined output -----------------------------------------------------------------

def test_output_confined_to_quality_local(tmp_path):
    good = tmp_path / ".quality-local" / "ai-quality"
    summary = run_corpus(good, "run1", lambda: SmartTransport("target"),
                         env=LOCAL)
    assert (good / "run1" / "corpus_plan.json").is_file()
    assert (good / "run1" / "corpus_results.json").is_file()
    assert "totals" in summary
    with pytest.raises(HarnessError) as ei:
        run_corpus(tmp_path / "elsewhere", "run2",
                   lambda: SmartTransport("target"), env=LOCAL)
    assert "confined" in str(ei.value) and str(tmp_path) not in str(ei.value)


def test_summary_has_no_evidence_or_filenames(tmp_path):
    plan, results = _run("target")
    summary = anonymized_summary(classify(plan, results, CORPUS))
    blob = json.dumps(summary)
    assert ".cs" not in blob and ".py" not in blob and ".ts" not in blob
    assert "statement" not in blob and "title" not in blob
    assert set(summary) == {"verdicts", "totals", "queries"}


# ---- W3-E6: the cross_project group is additive and cannot move the frozen
# ---- pre-registered digests -----------------------------------------------

def test_the_preregistered_digests_are_unmoved_by_the_new_group():
    """The dev/holdout digests are the anchor of every earlier measurement.
    Registering the W3-E6 cross-project group must not touch them, and
    `cases(None)` must keep meaning development+holdout."""
    from auditor.ai.quality_corpus import (
        SPLIT_CROSS_PROJECT, SPLIT_DEVELOPMENT, SPLIT_HOLDOUT, cases,
        corpus_digest, cross_project_cases)

    assert corpus_digest(cases(SPLIT_DEVELOPMENT)) == (
        "104ff8bad0df2183e61612ac8026e29c18d63c820fc769e2cd37c44a0d50d885")
    assert corpus_digest(cases(SPLIT_HOLDOUT)) == (
        "6a8e44605d3689f34a7c238de06abcef448be9728f7b7835e8913aa1d29472b0")
    assert len(cases(None)) == len(cases(SPLIT_DEVELOPMENT)) + len(
        cases(SPLIT_HOLDOUT))
    # the new group is its own tuple, not folded into either split
    xp = cases(SPLIT_CROSS_PROJECT)
    assert xp == cross_project_cases() and len(xp) == 3
    assert not set(c.case_id for c in xp) & set(
        c.case_id for c in cases(None))


def test_the_cross_project_group_is_genuinely_cross_project():
    """Its positive's target must live OUTSIDE the audited project — that is
    the property the pre-registered corpus does not have anywhere."""
    from auditor.ai.quality_corpus import (
        EXPECT_ABSTAIN, EXPECT_NEGATIVE, EXPECT_POSITIVE, cross_project_cases)

    kinds = {c.kind for c in cross_project_cases()}
    assert kinds == {EXPECT_POSITIVE, EXPECT_NEGATIVE, EXPECT_ABSTAIN}
    pos = next(c for c in cross_project_cases() if c.kind == EXPECT_POSITIVE)
    assert pos.target is not None
    assert not pos.target.file.startswith(pos.project + "/")
    assert len(pos.project_roots) == 2          # two sibling projects


def test_the_agent_engine_is_verified_against_what_it_actually_sent():
    """An agent citation outside its OBSERVED spans must still be rejected —
    the verifier stays fail-closed, it just uses the right span source."""
    from auditor.ai.quality_harness import ENGINE_AGENT, _verify_agent_result

    good = {"state": "completed", "provider": "ollama", "model": "m",
            "prompt_version": _agent_prompt_version(), "query_version": 3,
            "unit_id": "u" * 64, "context_digest": "d" * 64,
            "engine": ENGINE_AGENT,
            "observed_sent_spans": {"a/b.cs": [[1, 9]]},
            "issues": [{"evidence": [{"file": "a/b.cs", "line_start": 2,
                                      "line_end": 4}]}]}
    _verify_agent_result(good, {})                      # inside -> accepted

    bad = dict(good, issues=[{"evidence": [{"file": "a/b.cs",
                                            "line_start": 2,
                                            "line_end": 40}]}])
    with pytest.raises(HarnessError):
        _verify_agent_result(bad, {})

    unread = dict(good, issues=[{"evidence": [{"file": "other/x.cs",
                                               "line_start": 1,
                                               "line_end": 1}]}])
    with pytest.raises(HarnessError):
        _verify_agent_result(unread, {})


def _agent_prompt_version() -> str:
    from auditor.ai.audit_agent import AUDIT_AGENT_PROMPT_VERSION
    return AUDIT_AGENT_PROMPT_VERSION
