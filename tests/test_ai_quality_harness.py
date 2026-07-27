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
    ENGINE_AGENT, HarnessError, anonymized_summary, build_plan, classify,
    run_case, run_corpus, verify_one_to_one)

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
            "engine": ENGINE_AGENT, "outcome": "issues_found",
            "guard_downgraded": "",
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


# ---- W3-E7 measurement fix: the guard is not the model -------------------------------
#
# The agent runtime DOWNGRADES a `no_issue_observed` verdict to
# `insufficient_context` when relevant references were left unread. Recording
# only the final word made the runtime's intervention indistinguishable from
# the model's own honest abstention, and the first W3-E7 measurement run was
# voided for exactly that. These regressions pin the separation.


def _agent_result(pc, *, outcome, guarded="", issues=()):
    """One synthetic agent result for a planned case. `guarded` is the guard's
    reason; when set, the model's original word was `no_issue_observed` and the
    effective one is what the user saw."""
    return {"case_id": pc["case_id"], "query_id": pc["query_id"],
            "category": pc["category"], "expected": pc["kind"],
            "state": "completed", "engine": ENGINE_AGENT,
            "unit_id": "u" * 64, "context_digest": "d" * 64,
            "provider": "ollama", "model": "m",
            "prompt_version": _agent_prompt_version(), "query_version": 3,
            "outcome": outcome,
            "model_outcome": "no_issue_observed" if guarded else outcome,
            "effective_outcome": outcome,
            "guard_downgraded": guarded,
            "issues": list(issues), "observed_sent_spans": {}}


def _all_guarded(plan):
    """Every case downgraded by the guard: the model said `no_issue_observed`,
    the runtime showed `insufficient_context`."""
    return [_agent_result(pc, outcome="insufficient_context",
                          guarded="evidence_not_closed")
            for pc in plan["cases"] if pc["unit_id"]] + [
        {"case_id": pc["case_id"], "query_id": pc["query_id"],
         "category": pc["category"], "expected": pc["kind"],
         "state": "no_unit", "unit_id": "", "context_digest": "",
         "engine": ENGINE_AGENT}
        for pc in plan["cases"] if not pc["unit_id"]]


def test_a_guard_downgrade_is_never_counted_as_honest_abstention():
    """The rule the voided run broke: honest abstention is read from
    model_outcome, so a guard-produced `insufficient_context` lands in its own
    counter and NEVER in honest_insufficient."""
    plan = build_plan(CORPUS)
    cls = classify(plan, _all_guarded(plan), CORPUS)
    tot = anonymized_summary(cls)["totals"]
    assert tot["abstain_guard_downgraded"] >= 1
    assert tot["honest_insufficient"] == 0
    assert tot["guard_downgraded"] >= tot["abstain_guard_downgraded"]


def test_a_downgraded_negative_is_negative_abstain_not_clean():
    """A negative is `clean` only when the engine CONCLUDED there was nothing
    there. Declining to conclude earns nothing and must not read as success."""
    plan = build_plan(CORPUS)
    cls = classify(plan, _all_guarded(plan), CORPUS)
    tot = anonymized_summary(cls)["totals"]
    assert tot["negative_abstain"] >= 1
    assert tot["clean"] == 0
    assert tot["false_positive"] == 0            # nothing was claimed either


def test_a_model_abstained_negative_is_also_not_clean():
    """Same rule with NO guard involved: the discriminator is the outcome, not
    who produced it."""
    plan = build_plan(CORPUS)
    results = [_agent_result(pc, outcome="insufficient_context")
               for pc in plan["cases"] if pc["unit_id"]]
    results += [r for r in _all_guarded(plan) if r["state"] == "no_unit"]
    cls = classify(plan, results, CORPUS)
    tot = anonymized_summary(cls)["totals"]
    assert tot["clean"] == 0 and tot["negative_abstain"] >= 1
    assert tot["guard_downgraded"] == 0          # the model's own word
    assert tot["honest_insufficient"] >= 1       # and here it IS honest


def test_a_positive_stays_missed_whether_or_not_the_guard_intervened():
    """No supported issue means missed. The guard neither rescues a positive
    nor excuses it."""
    plan = build_plan(CORPUS)
    guarded = classify(plan, _all_guarded(plan), CORPUS)
    plain = [_agent_result(pc, outcome="no_issue_observed")
             for pc in plan["cases"] if pc["unit_id"]]
    plain += [r for r in _all_guarded(plan) if r["state"] == "no_unit"]
    unguarded = classify(plan, plain, CORPUS)
    for cls in (guarded, unguarded):
        tot = anonymized_summary(cls)["totals"]
        assert tot["detected"] == 0 and tot["missed"] >= 1


def test_a_guard_rescued_query_is_not_a_pass():
    """An undecided negative or abstain leaves the question open, so the query
    may not launder into a pass on the strength of its positives."""
    plan = build_plan(CORPUS)
    cls = classify(plan, _all_guarded(plan), CORPUS)
    for qd in cls["per_query"].values():
        assert qd["verdict"] != "pass"


def test_the_window_engine_asserts_it_has_no_guard():
    """The fixed window has no verdict guard; its records say so explicitly
    rather than leaving the reader to infer it from an absent field."""
    _, results = _run("clean")
    ran = [r for r in results if r["state"] == "completed"]
    assert ran
    for r in ran:
        assert r["guard_downgraded"] == ""
        assert r["model_outcome"] == r["outcome"] == r["effective_outcome"]


def test_a_guard_intervention_reaches_the_measurement_record():
    """End-to-end, through the REAL runtime and the REAL `run_pair`: when the
    agent answers clean with a relevant reference unread, the runtime downgrades
    the verdict — and the recorded result must keep BOTH words apart.

    This is the exact link that was broken. It is asserted end-to-end rather
    than on a hand-built dict, because a hand-built dict cannot fail the way the
    voided run did: the defect was that the runtime's fact never arrived."""
    from auditor.ai.quality_corpus import (
        EXPECT_NEGATIVE, CorpusCase, CorpusFile)
    from auditor.ai.quality_harness import ENGINE_AGENT, run_pair

    endpoints = ('public class InvoiceEndpoints {\n'
                 '  public void Register(WebApplication app) {\n'
                 '    app.MapDelete("/invoices/{id}", Drop);\n'
                 '  }\n'
                 '  void Drop(HttpContext http, int id) {\n'
                 '    if (!AccessPolicy.MayDelete(http)) { return; }\n'
                 '    Ledger.Erase(id);\n'
                 '  }\n'
                 '}\n')
    policy = ('public static class AccessPolicy {\n'
              '  public static bool MayDelete(HttpContext http) {\n'
              '    var scope = http.User.FindFirst("scope")?.Value;\n'
              '    if (scope != "invoices:delete") { return false; }\n'
              '    return true;\n'
              '  }\n'
              '}\n')
    case = CorpusCase(
        "guard-e2e", "AI001", EXPECT_NEGATIVE, "billing",
        (CorpusFile("billing/InvoiceEndpoints.cs", endpoints, "csharp"),
         CorpusFile("platform/AccessPolicy.cs", policy, "csharp")),
        "the protection lives in a sibling project and is never opened")

    class Dual:
        """One transport for both engines: the agent leg carries `tools` on the
        wire, the fixed window does not. The agent reads the endpoint — which
        is what surfaces `AccessPolicy` as a reference — and then answers clean
        without ever opening it."""

        def __init__(self):
            self.turns = 0

        def request(self, method, url, headers, json_body, timeout):
            if json_body.get("tools"):
                self.turns += 1
                call = ({"name": "read_lines",
                         "arguments": {"file": "billing/InvoiceEndpoints.cs",
                                       "start_line": 1, "end_line": 9}}
                        if self.turns == 1 else
                        {"name": "final_result",
                         "arguments": {"outcome": "no_issue_observed",
                                       "issues": []}})
                return HttpResponse(200, json.dumps({
                    "model": "m", "done_reason": "stop",
                    "message": {"role": "assistant", "content": "",
                                "tool_calls": [{"function": call}]},
                    "prompt_eval_count": 1, "eval_count": 1}).encode())
            return HttpResponse(200, json.dumps({"message": {
                "role": "assistant",
                "content": json.dumps({"outcome": "no_issue_observed",
                                       "issues": []})}}).encode())

    # the agent engine is experimental opt-in; the measurement declares it
    # exactly as the runner does
    out = run_pair(case, Provider.OLLAMA, "m", Dual,
                   env={**LOCAL, "AUDITOR_AI_AGENT_AUDIT": "confirm"})
    agent = out[ENGINE_AGENT]
    assert agent["state"] == "completed"
    # what the model said, what the user saw, and who changed it — all three
    assert agent["model_outcome"] == "no_issue_observed"
    assert agent["effective_outcome"] == "insufficient_context"
    assert agent["outcome"] == agent["effective_outcome"]
    assert agent["guard_downgraded"] == "evidence_not_closed"

    # and the counting rules read it correctly: not honest, not clean
    plan = build_plan((case,))
    cls = classify(plan, [agent], (case,))
    qd = cls["per_query"]["AI001"]
    assert qd["guard_downgraded"] == 1
    assert qd["negative"]["negative_abstain"] == 1
    assert qd["negative"]["clean"] == 0
    assert qd["abstain"]["honest_insufficient"] == 0


def _decided(plan, *, guard_case_ids=()):
    """Every case DECIDED and correct — positives cite their target, negatives
    conclude clean, abstains abstain honestly — except the named cases, which
    the guard downgraded. The discriminating shape for the pass rule: without
    the guard cases this is a clean sweep, so nothing but the undecided case
    can be what withholds the pass."""
    out = []
    for pc in plan["cases"]:
        if not pc["unit_id"]:
            out.append({"case_id": pc["case_id"], "query_id": pc["query_id"],
                        "category": pc["category"], "expected": pc["kind"],
                        "state": "no_unit", "unit_id": "", "context_digest": "",
                        "engine": ENGINE_AGENT})
            continue
        if pc["case_id"] in guard_case_ids:
            out.append(_agent_result(pc, outcome="insufficient_context",
                                     guarded="evidence_not_closed"))
        elif pc["kind"] == "positive":
            f, ls, le = pc["target"]
            hit = _agent_result(pc, outcome="issues_found", issues=[{
                "title": "t", "category": pc["category"], "confidence": "high",
                "summary": "s", "missing_context": [],
                "suggested_action": "inspect",
                "evidence": [{"context_id": "src:1", "file": f,
                              "line_start": ls, "line_end": le,
                              "statement": "e"}]}])
            # the citation must lie inside what this record says it sent —
            # the verifier is fail-closed and would refuse it otherwise
            hit["observed_sent_spans"] = {f: [[ls, le]]}
            out.append(hit)
        elif pc["kind"] == "negative":
            out.append(_agent_result(pc, outcome="no_issue_observed"))
        else:
            out.append(_agent_result(pc, outcome="insufficient_context"))
    return out


def test_one_undecided_case_withholds_the_pass_from_its_whole_query():
    """The pass rule must count DECIDED CASES, not merely one decision per
    kind. A query holding two negatives must not pass on the strength of the
    one that concluded while the other sits undecided.

    Asserted as a difference: the same corpus, scored twice, differing only in
    whether ONE case was downgraded. Anything weaker passes even when the rule
    is reverted — which is exactly how the first version of this test failed to
    catch it."""
    plan = build_plan(CORPUS)
    swept = classify(plan, _decided(plan), CORPUS)
    passes = {q for q, qd in swept["per_query"].items()
              if qd["verdict"] == "pass"}
    assert passes, "the all-correct sweep must produce passing queries"

    # pick a query that passed and holds MORE THAN ONE negative, so a per-kind
    # rule would still see a decided negative and wave it through
    victim = next(
        (pc for pc in plan["cases"]
         if pc["query_id"] in passes and pc["kind"] == "negative"
         and sum(1 for c in plan["cases"]
                 if c["query_id"] == pc["query_id"]
                 and c["kind"] == "negative") > 1), None)
    assert victim is not None, "corpus has no multi-negative query to test"

    guarded = classify(plan, _decided(plan, guard_case_ids={victim["case_id"]}),
                       CORPUS)
    qd = guarded["per_query"][victim["query_id"]]
    assert qd["negative"]["assessed"] > 1                 # the sibling exists
    assert qd["negative"]["clean"] >= 1                   # and it concluded
    assert qd["negative"]["negative_abstain"] == 1        # this one did not
    assert qd["verdict"] != "pass", (
        "a query passed while one of its negatives was left undecided")


def test_a_truncated_result_fails_loudly_instead_of_scoring_as_clean():
    """A completed record with no outcome — truncated, hand-edited, or written
    by an older harness — must be REFUSED, not read as `no_issue_observed`.
    Defaulting here would score an absent verdict as a decided one and let it
    feed a pass."""
    plan = build_plan(CORPUS)
    for missing in ("outcome", "guard_downgraded"):
        results = _decided(plan)
        for r in results:
            r.pop(missing, None)
        with pytest.raises(HarnessError):
            classify(plan, results, CORPUS)


def test_replaying_a_pre_guard_run_requires_naming_its_version():
    """A stored run from before the guard existed may lack the guard fact —
    but only when its version is named explicitly. Absence of the fact must
    never be silently read as `the guard did not fire`."""
    plan = build_plan(CORPUS)
    old = [dict(r) for r in _decided(plan)]
    for r in old:
        r.pop("guard_downgraded", None)
        if r["state"] == "completed":
            r["prompt_version"] = "w3e5-agent-v2"

    with pytest.raises(HarnessError):
        classify(plan, old, CORPUS)              # unnamed -> refused
    classify(plan, old, CORPUS, "w3e5-agent-v2")  # named -> replayed


def test_a_detection_the_verifier_refuses_is_recorded_as_weaker():
    """`detected` is the pre-registered rule — an issue cites the target span.
    The project also runs a deterministic verifier over every issue, and a
    citation it refuses to support is not the same evidence as one it backs.
    Both counts are recorded, so a headline recall number can never quietly
    include claims the project's own verifier rejected."""
    plan = build_plan(CORPUS)

    def _with(verdict):
        out = []
        for r in _decided(plan):
            for i in r.get("issues", []):
                i["verification"] = verdict
            out.append(r)
        return out

    backed = anonymized_summary(classify(plan, _with("supported"),
                                         CORPUS))["totals"]
    refused = anonymized_summary(classify(plan, _with("unsupported"),
                                          CORPUS))["totals"]

    assert backed["detected"] == refused["detected"] > 0   # same citations
    assert backed["detected_verified"] == backed["detected"]
    assert refused["detected_verified"] == 0               # none of them held


# ---- AI-CONTEXT-GATE: the agent-only path and the token instrument -------------------

def test_run_pair_can_run_one_engine_without_reshaping_its_record():
    """A comparison that varies the context window has no reason to spend GPU
    time on the fixed window, which does not grow one. Narrowing the engines
    must leave the surviving record byte-identical to the paired run's — the
    selection may not become a second, less-verified code path."""
    from auditor.ai.quality_corpus import EXPECT_NEGATIVE, CorpusCase, CorpusFile
    from auditor.ai.quality_harness import ENGINE_WINDOW, run_pair

    case = CorpusCase(
        "engines-sel", "AI001", EXPECT_NEGATIVE, "billing",
        (CorpusFile("billing/InvoiceEndpoints.cs",
                    'public class InvoiceEndpoints {\n'
                    '  void Drop(HttpContext http, int id) {\n'
                    '    if (!AccessPolicy.MayDelete(http)) { return; }\n'
                    '  }\n'
                    '}\n', "csharp"),),
        "the protection is not in this project at all")

    class Dual:
        def __init__(self):
            self.turns = 0

        def request(self, method, url, headers, json_body, timeout):
            if json_body.get("tools"):
                self.turns += 1
                call = ({"name": "read_lines",
                         "arguments": {"file": "billing/InvoiceEndpoints.cs",
                                       "start_line": 1, "end_line": 5}}
                        if self.turns == 1 else
                        {"name": "final_result",
                         "arguments": {"outcome": "no_issue_observed",
                                       "issues": []}})
                return HttpResponse(200, json.dumps({
                    "model": "m", "done_reason": "stop",
                    "message": {"role": "assistant", "content": "",
                                "tool_calls": [{"function": call}]},
                    "prompt_eval_count": 11, "eval_count": 3}).encode())
            return HttpResponse(200, json.dumps({"message": {
                "role": "assistant",
                "content": json.dumps({"outcome": "no_issue_observed",
                                       "issues": []})}}).encode())

    e = {**LOCAL, "AUDITOR_AI_AGENT_AUDIT": "confirm"}
    both = run_pair(case, Provider.OLLAMA, "m", Dual, env=e)
    only = run_pair(case, Provider.OLLAMA, "m", Dual, env=e,
                    engines=(ENGINE_AGENT,))

    assert set(both) == {ENGINE_WINDOW, ENGINE_AGENT}
    assert set(only) == {ENGINE_AGENT}                  # nothing else ran
    volatile = {"unit_id", "context_digest", "latency_ms", "execution_id",
                "observed_sent_spans"}
    assert ({k: v for k, v in both[ENGINE_AGENT].items() if k not in volatile}
            == {k: v for k, v in only[ENGINE_AGENT].items()
                if k not in volatile})

    with pytest.raises(HarnessError):
        run_pair(case, Provider.OLLAMA, "m", Dual, env=e, engines=())
    with pytest.raises(HarnessError):
        run_pair(case, Provider.OLLAMA, "m", Dual, env=e, engines=("nope",))
