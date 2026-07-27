"""W3-E4A2 (closing): the auditable quality harness. Builds a one-to-one plan
BEFORE any model call (unit + digest + sent files/spans + target per case),
runs each case once through the REAL audit pipeline, and records the FULL
model result locally. Strict identity (recomputed from content, not string
ids), honest classification (no_unit is NOT a pass/honest signal; a positive
counts detected only when a candidate cites the target file AND span), and
confined output under `.quality-local/ai-quality/<run-id>/` only.
"""
from __future__ import annotations

import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable

from auditor.ai.audit import (
    AUDIT_PROMPT_VERSION, build_audit_pack, run_audit_unit)
from auditor.ai.audit_index import RepositoryAuditIndex
from auditor.ai.audit_queries import CATALOG_VERSION, query_by_id
from auditor.ai.contract import ERROR_CODES, AIError, Provider
from auditor.ai.quality_corpus import (
    CORPUS_VERSION, EXPECT_NEGATIVE, EXPECT_POSITIVE, CasePlan, CorpusCase,
    cases, corpus_digest)
from auditor.ai.review import OllamaNumCtxError

HARNESS_VERSION = 3      # W3-E6: adds the `engine` dimension (window|agent)

ENGINE_WINDOW = "window"
ENGINE_AGENT = "agent"
ENGINES = (ENGINE_WINDOW, ENGINE_AGENT)
_MAX_OUTPUT_BYTES = 4 * 1024 * 1024
_CONFINED_BASE = ("quality-local", "ai-quality")   # .quality-local/ai-quality


class HarnessError(Exception):
    """Safe message only — never a path or a snippet."""


_LANG_EXT = {"csharp": ".cs", "python": ".py", "typescript": ".ts"}


@contextmanager
def _materialised(case: CorpusCase):
    """Materialise one case into a throwaway temp repo and yield the REAL
    RepositoryAuditIndex over it, so retrieval/expansion/redaction/span/digest
    are identical to production.

    W3-E6: both engines are driven from this ONE index, which is what makes
    "the same source snapshot" a fact rather than a hope — the index is an
    in-memory, byte-capped copy, so it cannot drift between the two runs."""
    with tempfile.TemporaryDirectory(prefix="qcorpus-") as tmp:
        base = Path(tmp)
        for cf in case.files:
            p = base / cf.rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(cf.text, encoding="utf-8")
        yield RepositoryAuditIndex(base, case.project_roots)


def _pack_for_case(case: CorpusCase):
    """The fixed-window pack for one case, or None when no candidate."""
    with _materialised(case) as index:
        query = query_by_id(case.query_id)
        assert query is not None
        return build_audit_pack(index, case.project, query)


def _plan_for(case: CorpusCase) -> CasePlan:
    pack = _pack_for_case(case)
    tgt = None if case.target is None else [
        case.target.file, case.target.line_start, case.target.line_end]
    if pack is None:
        return CasePlan(case.case_id, case.query_id, case.category, case.kind,
                        case.reason, case.project, "", "", 0, [], {}, tgt,
                        case.split)
    spans = {m["file"]: [list(s) for s in m["spans"]]
             for m in pack["piece_map"].values()}
    return CasePlan(
        case.case_id, case.query_id, case.category, case.kind, case.reason,
        case.project, pack["unit_id"], pack["digest"],
        len(pack["canonical"].encode("utf-8")), sorted(spans), spans, tgt,
        case.split)


def build_plan(corpus: tuple[CorpusCase, ...] | None = None) -> dict[str, Any]:
    corpus = corpus if corpus is not None else cases()
    plans = [_plan_for(c) for c in corpus]
    if len({p.case_id for p in plans}) != len(plans):
        raise HarnessError("duplicate case ids in the corpus")
    return {
        "harness_version": HARNESS_VERSION, "corpus_version": CORPUS_VERSION,
        "corpus_digest": corpus_digest(corpus), "catalog_version": CATALOG_VERSION,
        "prompt_version": AUDIT_PROMPT_VERSION,
        "cases": [vars(p) for p in plans],
    }


def run_case(case: CorpusCase, provider: Provider, model: str,
             transport: Any, env: dict[str, str] | None = None) -> dict[str, Any]:
    pack = _pack_for_case(case)
    base = {"case_id": case.case_id, "query_id": case.query_id,
            "category": case.category, "expected": case.kind}
    if pack is None:
        return {**base, "state": "no_unit", "unit_id": "",
                "context_digest": ""}
    try:
        res = run_audit_unit(pack, provider, model, transport, env=env)
    except (AIError, OllamaNumCtxError) as e:
        # OllamaNumCtxError is raised BEFORE the wire — a bad server num_ctx
        # fails the case with its fixed code and never sends a request.
        return {**base, "state": e.code, "unit_id": pack["unit_id"],
                "context_digest": pack["digest"]}
    return {
        **base, "state": "completed", "unit_id": pack["unit_id"],
        "context_digest": pack["digest"], "outcome": res["outcome"],
        # the fixed window has NO verdict guard: nothing stands between the
        # model's word and the recorded one. Asserted, not left to inference.
        "model_outcome": res["outcome"],
        "effective_outcome": res["outcome"],
        "guard_downgraded": "",
        "issues": [{
            "title": i["title"], "category": i["category"],
            "confidence": i["confidence"], "summary": i["summary"],
            "evidence": [{"context_id": e["context_id"], "file": e["file"],
                          "line_start": e["line_start"],
                          "line_end": e["line_end"],
                          "statement": e["statement"]}
                         for e in i["evidence"]],
            "missing_context": i["missing_context"],
            "suggested_action": i["suggested_action"],
            # W3-E4C2: carry the deterministic verification verdict so the
            # harness can compute verified-effective metrics (the model's
            # words are still not changed — this is a copy of what
            # run_audit_unit already attached).
            "verification": i.get("verification"),
            "verification_reason": i.get("verification_reason")}
            for i in res["issues"]],
        "provider": res["provider"], "model": res["model"],
        "prompt_version": res["prompt_version"],
        "query_version": res["query_version"], "latency_ms": res["latency_ms"],
        # W3-E4D: carry the effective Ollama context window + execution
        # identity so a 4096 measurement run and an 8192 one are auditable and
        # never conflated in the recorded outputs.
        "num_ctx": res.get("num_ctx"),
        "execution_id": res.get("execution_id"),
    }


def _issue_records(issues) -> list[dict[str, Any]]:
    return [{
        "title": i["title"], "category": i["category"],
        "confidence": i["confidence"], "summary": i["summary"],
        "evidence": [{"context_id": e["context_id"], "file": e["file"],
                      "line_start": e["line_start"],
                      "line_end": e["line_end"],
                      "statement": e["statement"]}
                     for e in i["evidence"]],
        "missing_context": i["missing_context"],
        "suggested_action": i["suggested_action"],
        "verification": i.get("verification"),
        "verification_reason": i.get("verification_reason")} for i in issues]


def run_pair(case: CorpusCase, provider: Provider, model: str,
             transport_factory: Callable[[], Any],
             env: dict[str, str] | None = None,
             engines: tuple[str, ...] = ENGINES) -> dict[str, Any]:
    """W3-E6: run BOTH engines over the SAME unit and the SAME source snapshot,
    one run each, and return {"window": result, "agent": result}.

    `engines` narrows which of them actually runs. A comparison that varies
    something only ONE engine can respond to — the context window, which the
    fixed window does not grow — should not spend GPU time on the other, and
    must not reshape its records to avoid doing so: the selection happens here
    so the surviving engine is recorded by the exact same code either way.

    The two engines are NOT identity-comparable: the fixed window's unit_id and
    digest come from a pack built BEFORE the model is called, while the agent
    freezes its pack from what it actually read, so its identity is only known
    afterwards and legitimately differs between runs. Results are therefore
    paired on (case_id, query_id) and each carries its OWN observed identity."""
    from auditor.ai.audit_agent import (
        AUDIT_AGENT_PROMPT_VERSION, run_agent_unit)

    base = {"case_id": case.case_id, "query_id": case.query_id,
            "category": case.category, "expected": case.kind}
    query = query_by_id(case.query_id)
    assert query is not None
    out: dict[str, Any] = {}

    if not set(engines) <= set(ENGINES) or not engines:
        raise HarnessError("unknown engine requested")

    with _materialised(case) as index:
        # ---- engine 1: the shipped fixed window --------------------------
        pack = build_audit_pack(index, case.project, query)             if ENGINE_WINDOW in engines else None
        if ENGINE_WINDOW not in engines:
            pass
        elif pack is None:
            out[ENGINE_WINDOW] = {**base, "engine": ENGINE_WINDOW,
                                  "state": "no_unit", "unit_id": "",
                                  "context_digest": ""}
        else:
            try:
                res = run_audit_unit(pack, provider, model,
                                     transport_factory(), env=env)
                out[ENGINE_WINDOW] = {
                    **base, "engine": ENGINE_WINDOW, "state": "completed",
                    "unit_id": pack["unit_id"],
                    "context_digest": pack["digest"],
                    "outcome": res["outcome"],
                    # the fixed window has NO verdict guard: nothing between
                    # the model's word and the recorded one. Stated as an
                    # asserted fact rather than an absent field.
                    "model_outcome": res["outcome"],
                    "effective_outcome": res["outcome"],
                    "guard_downgraded": "",
                    "issues": _issue_records(res["issues"]),
                    "provider": res["provider"], "model": res["model"],
                    "prompt_version": res["prompt_version"],
                    "query_version": res["query_version"],
                    "latency_ms": res["latency_ms"],
                    "num_ctx": res.get("num_ctx"),
                    "execution_id": res.get("execution_id"),
                    # observed == planned for this engine, by construction
                    "observed_sent_spans": {
                        m["file"]: [list(s) for s in m["spans"]]
                        for m in pack["piece_map"].values()},
                    "files_sent": pack["privacy_manifest"]["files_sent"],
                    "bytes_after": pack["privacy_manifest"]["bytes_after"],
                }
            except (AIError, OllamaNumCtxError) as e:
                out[ENGINE_WINDOW] = {
                    **base, "engine": ENGINE_WINDOW, "state": e.code,
                    "unit_id": pack["unit_id"],
                    "context_digest": pack["digest"]}

        # ---- engine 2: the experimental agent ----------------------------
        # It builds its own context, so a case with no fixed-window pack can
        # still be a real agent unit. It is given a unit iff the index offers
        # a seed anchor, which is the runtime's own precondition.
        trace: dict[str, Any] = {}
        if ENGINE_AGENT not in engines:
            pass
        elif not index.candidates_for(query, case.project):
            out[ENGINE_AGENT] = {**base, "engine": ENGINE_AGENT,
                                 "state": "no_unit", "unit_id": "",
                                 "context_digest": ""}
        else:
            try:
                res = run_agent_unit(index, case.project, query, provider,
                                     model, env=env, trace=trace,
                                     transport=transport_factory())
                out[ENGINE_AGENT] = {
                    **base, "engine": ENGINE_AGENT, "state": "completed",
                    # the agent's identity is OBSERVED, never planned
                    "unit_id": res["audit_unit_id"],
                    "context_digest": res["context_digest"],
                    "outcome": res["outcome"],
                    # W3-E7 instrumentation fix. The agent runtime may DOWNGRADE
                    # a `no_issue_observed` verdict to `insufficient_context`
                    # when the evidence was not closed. Recording only the final
                    # word made the guard's intervention indistinguishable from
                    # the model's own honest abstention — and the first W3-E7
                    # run was voided for exactly that. The guard fires on, and
                    # only on, `no_issue_observed`, so the model's original word
                    # is EXACTLY recoverable here without touching the runtime.
                    "model_outcome": ("no_issue_observed"
                                      if trace.get("verdict_downgraded")
                                      else res["outcome"]),
                    "effective_outcome": res["outcome"],
                    "guard_downgraded": trace.get("verdict_downgraded", ""),
                    "issues": _issue_records(res["issues"]),
                    "provider": res["provider"], "model": res["model"],
                    "prompt_version": res["prompt_version"],
                    "query_version": res["query_version"],
                    "latency_ms": res["latency_ms"],
                    "num_ctx": res.get("num_ctx"),
                    "execution_id": res.get("execution_id"),
                    "observed_sent_spans": {
                        p["file"]: [list(s) for s in p["spans"]]
                        for p in trace.get("pieces_sent", [])},
                    "files_sent": trace.get(
                        "privacy_manifest", {}).get("files_sent", 0),
                    "bytes_after": trace.get(
                        "privacy_manifest", {}).get("bytes_after", 0),
                    "tool_calls": trace.get("tool_calls"),
                    "repeated_calls": trace.get("repeated_calls"),
                    "stop_reason": trace.get("stop_reason", ""),
                    "cross_project_reached": sorted(
                        trace.get("cross_project", {})),
                }
            except (AIError, OllamaNumCtxError) as e:
                out[ENGINE_AGENT] = {
                    **base, "engine": ENGINE_AGENT, "state": e.code,
                    "unit_id": "", "context_digest": "",
                    "tool_calls": trace.get("tool_calls"),
                    "repeated_calls": trace.get("repeated_calls"),
                    "stop_reason": trace.get("stop_reason", ""),
                    "cross_project_reached": sorted(
                        trace.get("cross_project", {})),
                    "files_sent": trace.get(
                        "privacy_manifest", {}).get("files_sent", 0),
                }
    _ = AUDIT_AGENT_PROMPT_VERSION      # imported for the verifier's contract
    return out


# ---- identity + one-to-one contract --------------------------------------------------

_PLAN_KEYS = {"case_id", "query_id", "category", "kind", "reason", "project",
              "unit_id", "context_digest", "input_bytes", "sent_files",
              "sent_spans", "target", "split"}
_RESULT_MIN = {"case_id", "query_id", "category", "expected", "state",
               "unit_id", "context_digest"}


def _spans_cover(spans: list[list[int]], ls: int, le: int) -> bool:
    return any(s <= ls and le <= e for s, e in spans)


_HEADER_KEYS = ("corpus_digest", "prompt_version", "catalog_version",
                "corpus_version", "harness_version")
# A completed result must carry one of these. Checked rather than defaulted:
# scoring a truncated or hand-edited record as though it had concluded is the
# silent mis-score this harness exists to prevent, and reading `outcome`
# through .get() would quietly turn a missing verdict into `no_issue_observed`.
_LEGAL_OUTCOMES = frozenset({"issues_found", "no_issue_observed",
                             "insufficient_context"})
# a unit was built and sent iff the result RAN; no_unit iff no pack was built.
_RAN_STATES = frozenset({"completed", *ERROR_CODES})
_LEGAL_STATES = frozenset({"no_unit", *_RAN_STATES})
# the model ran but broke its own contract -> a quality fault (needs_hardening);
# every OTHER ERROR_CODE is an environment fault (insufficient_evidence).
_HARDENING_ERRORS = ("timeout", "invalid_response")


def _verify_agent_result(r: dict[str, Any], tc: dict[str, Any],
                         expect_prompt_version: str | None = None) -> None:
    """The agent half of the one-to-one contract. Independent of the runtime:
    it re-checks, from the recorded result alone, that nothing was cited that
    the agent did not send.

    `expect_prompt_version` exists so a STORED run can be re-scored against the
    version it was actually produced with — re-classifying an archived run with
    corrected counting rules is a normal measurement act, and silently accepting
    any version would not be. It must be named explicitly; the default stays the
    current runtime's version, so a live run is still fail-closed on drift."""
    from auditor.ai.audit_agent import AUDIT_AGENT_PROMPT_VERSION
    expected = expect_prompt_version or AUDIT_AGENT_PROMPT_VERSION
    if r["state"] == "no_unit":
        if r.get("unit_id", "") or r.get("context_digest", ""):
            raise HarnessError("no_unit result carries a unit identity")
        return
    if r["state"] != "completed":
        return                                   # a legal error code
    if not {"provider", "model", "prompt_version", "query_version"} <= set(r):
        raise HarnessError("completed result missing run metadata")
    if r.get("outcome") not in _LEGAL_OUTCOMES:
        raise HarnessError("completed result has no legal outcome")
    if r["prompt_version"] != expected:
        raise HarnessError("agent result prompt_version drift")
    # P4: absence of the guard fact must not read as "the guard did not fire".
    # A record claiming the CURRENT runtime version was produced by a runtime
    # that has the verdict guard, so it must carry the guard's verdict. Only a
    # run explicitly replayed at an OLDER named version may lack it.
    if (expect_prompt_version is None
            and "guard_downgraded" not in r):
        raise HarnessError("agent result predates the guard instrumentation")
    if not r.get("unit_id") or not r.get("context_digest"):
        raise HarnessError("completed agent result has no observed identity")
    observed = r.get("observed_sent_spans")
    if not isinstance(observed, dict):
        raise HarnessError("agent result has no observed spans")
    for issue in r.get("issues", []):
        for ev in issue["evidence"]:
            spans = observed.get(ev["file"])
            if spans is None or not _spans_cover(
                    spans, ev["line_start"], ev["line_end"]):
                raise HarnessError("a citation is outside the sent spans")
    _ = tc


def verify_one_to_one(plan: dict[str, Any],
                      results: list[dict[str, Any]],
                      corpus: tuple[CorpusCase, ...],
                      agent_prompt_version: str | None = None) -> None:
    """Both plan AND results must match the truth RE-DERIVED from the corpus —
    never merely each other. `truth` is rebuilt from the passed corpus, so a
    fake identity forged identically into plan and results is rejected, and a
    different corpus reusing a case_id is rejected. Each plan case is compared
    to its truth STRUCTURALLY (the whole dict — reason/project/input_bytes/
    sent_files/target and all), not a hand-picked subset. Each result's state
    must be in an explicit allowlist and must agree with whether a unit was
    actually built: no_unit ONLY when the corpus built no pack, a ran-state
    ONLY when it did. Order is irrelevant (matched by case_id). Error messages
    carry no ids, paths, or snippets."""
    truth = build_plan(corpus)
    truth_by_id = {c["case_id"]: c for c in truth["cases"]}
    plan_by_id = {c["case_id"]: c for c in plan["cases"]}
    if len(plan_by_id) != len(plan["cases"]):
        raise HarnessError("duplicate case ids in the plan")
    if set(plan_by_id) != set(truth_by_id):
        raise HarnessError("plan case set does not match the corpus")
    for k in _HEADER_KEYS:
        if plan.get(k) != truth.get(k):
            raise HarnessError("plan header does not match the corpus")
    for cid, pc in plan_by_id.items():
        if set(pc) != _PLAN_KEYS:
            raise HarnessError("a plan case has an unexpected shape")
        if pc != truth_by_id[cid]:      # WHOLE-dict structural equality
            raise HarnessError("a plan case does not match the corpus")
    seen: set[str] = set()
    for r in results:
        if not _RESULT_MIN <= set(r):
            raise HarnessError("a result is missing required fields")
        cid = str(r["case_id"])
        tc = truth_by_id.get(cid)
        if tc is None:
            raise HarnessError("a result has no matching corpus case")
        if cid in seen:
            raise HarnessError("duplicate result for a case")
        seen.add(cid)
        if r["state"] not in _LEGAL_STATES:
            raise HarnessError("a result has an illegal state")
        if (r["query_id"], r["category"], r["expected"]) != (
                tc["query_id"], tc["category"], tc["kind"]):
            raise HarnessError("result query/category/expected drift")
        engine = r.get("engine", ENGINE_WINDOW)
        if engine not in ENGINES:
            raise HarnessError("a result has an unknown engine")
        if engine == ENGINE_AGENT:
            # The agent's identity is OBSERVED, not planned: it freezes its
            # pack from what it actually read, so unit_id/digest/spans cannot
            # be compared to the fixed-window plan and legitimately differ
            # between runs. Verification stays FAIL-CLOSED on what can be
            # checked: a completed run must carry its own non-empty identity,
            # the agent's own prompt version, and every citation must lie
            # inside the spans it actually sent.
            _verify_agent_result(r, tc, agent_prompt_version)
            continue
        unit_built = bool(tc["unit_id"])
        if unit_built:
            # a real unit exists -> the result must have RUN against it, and
            # carry its exact identity; it can never be no_unit
            if r["state"] == "no_unit":
                raise HarnessError("result claims no_unit but a unit exists")
            if r.get("unit_id", "") != tc["unit_id"] \
                    or r.get("context_digest", "") != tc["context_digest"]:
                raise HarnessError(
                    "result unit/digest does not match the corpus")
        else:
            # no pack was built -> the ONLY legal result is no_unit with an
            # empty identity (a real unit_id/digest here is a forgery)
            if r["state"] != "no_unit":
                raise HarnessError("result claims a unit but none was built")
            if r.get("unit_id", "") or r.get("context_digest", ""):
                raise HarnessError("no_unit result carries a unit identity")
        if r["state"] == "completed":
            if not {"provider", "model", "prompt_version",
                    "query_version"} <= set(r):
                raise HarnessError("completed result missing run metadata")
            if r.get("outcome") not in _LEGAL_OUTCOMES:
                raise HarnessError("completed result has no legal outcome")
            if r["prompt_version"] != truth["prompt_version"]:
                raise HarnessError("result prompt_version drift")
            for issue in r.get("issues", []):
                for ev in issue["evidence"]:
                    spans = tc["sent_spans"].get(ev["file"])
                    if spans is None or not _spans_cover(
                            spans, ev["line_start"], ev["line_end"]):
                        raise HarnessError(
                            "a citation is outside the sent spans")
    missing = set(truth_by_id) - seen
    if missing:
        raise HarnessError("missing result(s) for planned case(s)")


# ---- classification ------------------------------------------------------------------

def _cites_target(issues: list[dict[str, Any]],
                  target: list | None) -> bool:
    if not target:
        return False
    tf, tls, tle = target
    for i in issues:
        for ev in i["evidence"]:
            if ev["file"] == tf and not (
                    ev["line_end"] < tls or ev["line_start"] > tle):
                return True
    return False


def classify(plan: dict[str, Any],
             results: list[dict[str, Any]],
             corpus: tuple[CorpusCase, ...],
             agent_prompt_version: str | None = None) -> dict[str, Any]:
    verify_one_to_one(plan, results, corpus, agent_prompt_version)
    by_id = {r["case_id"]: r for r in results}
    per_query: dict[str, dict[str, Any]] = {}
    for pc in plan["cases"]:
        q = pc["query_id"]
        r = by_id[pc["case_id"]]
        qd = per_query.setdefault(q, {
            # detected_verified is a SECOND, stricter reading of the same
            # cases, recorded beside `detected` and never replacing it. The
            # pre-registered rule is "an issue cites the target span"; the
            # project also runs a deterministic verifier over every issue, and
            # a citation it refuses to support is a weaker detection than one
            # it backs. Both are reported so neither can be quietly assumed.
            "positive": {"assessed": 0, "detected": 0, "missed": 0,
                         "detected_verified": 0},
            # negative_abstain: declined to conclude. NOT a clean negative
            # (nothing was earned) and NOT a false positive (nothing was
            # claimed) — it is its own outcome and must not hide in either.
            "negative": {"assessed": 0, "clean": 0, "false_positive": 0,
                         "negative_abstain": 0},
            # guard_downgraded: the runtime refused the model's clean verdict.
            # Counted apart from honest abstention, which is the MODEL's own.
            "abstain": {"assessed": 0, "honest_insufficient": 0,
                        "no_issue_observed": 0, "overclaim": 0,
                        "guard_downgraded": 0},
            "retrieval_not_assessed": 0,
            "errors": {code: 0 for code in ERROR_CODES},
            "guard_downgraded": 0,
            "unrelated_candidates": 0})
        state = r["state"]
        if state == "no_unit":
            qd["retrieval_not_assessed"] += 1        # NOT clean/honest/pass
            continue
        if state in ERROR_CODES:
            # ANY provider/transport error: record it with its own explicit
            # counter and STOP. A run that errored has no assessable answer —
            # it is never read for outcome/issues and never counted as clean,
            # missed, overclaim, or honest.
            qd["errors"][state] += 1
            continue
        # only a "completed" run reaches here (verify_one_to_one enforced the
        # legal-state allowlist), so outcome/issues are safe to read
        issues = r.get("issues", [])
        same_cat = [i for i in issues if i["category"] == pc["category"]]
        # W3-E7: the model's OWN word, separated from the runtime guard's
        # intervention. Absent on older records -> falls back to the effective
        # outcome, which is correct for any engine/run without a guard.
        guarded = bool(r.get("guard_downgraded"))
        model_outcome = r.get("model_outcome", r.get("outcome"))
        if guarded:
            qd["guard_downgraded"] += 1
        supported = [i for i in same_cat
                     if i.get("verification") == "supported"]
        if pc["kind"] == "positive":
            qd["positive"]["assessed"] += 1
            if _cites_target(same_cat, pc["target"]):
                qd["positive"]["detected"] += 1
                if _cites_target(supported, pc["target"]):
                    qd["positive"]["detected_verified"] += 1
            else:
                qd["positive"]["missed"] += 1
                # a same-category hit NOT on the target is unrelated, not a
                # detection
                if same_cat:
                    qd["unrelated_candidates"] += 1
        elif pc["kind"] == "negative":
            qd["negative"]["assessed"] += 1
            if issues:
                qd["negative"]["false_positive"] += 1
            elif r.get("outcome") == "insufficient_context":
                # a negative is `clean` only when the engine actually CONCLUDED
                # there was nothing there. Declining to conclude is not a clean
                # negative, whether the model abstained or the guard refused it.
                qd["negative"]["negative_abstain"] += 1
            else:
                qd["negative"]["clean"] += 1
        else:  # abstain — the model DID run (state completed)
            qd["abstain"]["assessed"] += 1
            if issues:
                qd["abstain"]["overclaim"] += 1
            elif guarded:
                # the guard produced this abstention, not the model. Tested
                # BEFORE the honest test on purpose: otherwise the mutated
                # outcome wins and the runtime's intervention is credited to
                # the model as honest abstention.
                qd["abstain"]["guard_downgraded"] += 1
            elif model_outcome == "insufficient_context":
                qd["abstain"]["honest_insufficient"] += 1
            else:                                     # no_issue_observed
                qd["abstain"]["no_issue_observed"] += 1

    for qd in per_query.values():
        pos, neg, ab = qd["positive"], qd["negative"], qd["abstain"]
        # timeout/invalid_response are QUALITY faults (the model ran but broke
        # its own contract) -> needs_hardening. The remaining provider errors
        # (not_configured/authentication_failed/model_not_found/rate_limited/
        # connection_failed) are ENVIRONMENT faults that leave the query simply
        # unassessed -> insufficient_evidence, unless a real quality fault also
        # occurred.
        hardening_error = any(qd["errors"][c] for c in _HARDENING_ERRORS)
        # A query is only fully assessed when EVERY case of every kind reached
        # a decision — not merely one of them. Counting per kind rather than
        # per case let a query holding two negatives pass on the strength of
        # the one that concluded while the other sat undecided; the corpus has
        # two such queries, and one of them did exactly that.
        neg_decided = neg["clean"] + neg["false_positive"]
        ab_decided = (ab["honest_insufficient"] + ab["no_issue_observed"]
                      + ab["overclaim"])
        all_assessed = (pos["assessed"]
                        and neg_decided == neg["assessed"]
                        and ab_decided == ab["assessed"]
                        and (neg["assessed"] or ab["assessed"]))
        quality_fault = (hardening_error or pos["missed"]
                         or neg["false_positive"] or ab["overclaim"])
        if all_assessed and not quality_fault:
            qd["verdict"] = "pass"
        elif quality_fault:
            qd["verdict"] = "needs_hardening"
        else:
            qd["verdict"] = "insufficient_evidence"
    return {"per_query": per_query}


def anonymized_summary(classification: dict[str, Any]) -> dict[str, Any]:
    verdicts: dict[str, int] = {}
    totals: dict[str, Any] = {
        "detected": 0, "detected_verified": 0,
        "missed": 0, "false_positive": 0, "clean": 0,
        "negative_abstain": 0, "honest_insufficient": 0,
        "abstain_no_issue": 0, "overclaim": 0,
        "abstain_guard_downgraded": 0, "guard_downgraded": 0,
        "unrelated_candidates": 0, "retrieval_not_assessed": 0,
        "errors": {code: 0 for code in ERROR_CODES}}
    for qd in classification["per_query"].values():
        verdicts[qd["verdict"]] = verdicts.get(qd["verdict"], 0) + 1
        totals["detected"] += qd["positive"]["detected"]
        totals["missed"] += qd["positive"]["missed"]
        totals["false_positive"] += qd["negative"]["false_positive"]
        totals["detected_verified"] += qd["positive"]["detected_verified"]
        totals["clean"] += qd["negative"]["clean"]
        totals["negative_abstain"] += qd["negative"]["negative_abstain"]
        totals["abstain_guard_downgraded"] += qd["abstain"]["guard_downgraded"]
        totals["guard_downgraded"] += qd["guard_downgraded"]
        totals["honest_insufficient"] += qd["abstain"]["honest_insufficient"]
        totals["abstain_no_issue"] += qd["abstain"]["no_issue_observed"]
        totals["overclaim"] += qd["abstain"]["overclaim"]
        totals["unrelated_candidates"] += qd["unrelated_candidates"]
        totals["retrieval_not_assessed"] += qd["retrieval_not_assessed"]
        for code in ERROR_CODES:
            totals["errors"][code] += qd["errors"][code]
    return {"verdicts": verdicts, "totals": totals,
            "queries": len(classification["per_query"])}


# ---- observations + earned evidence --------------------------------------------------
#
# These sit BESIDE the scoring counters and are never folded into them. They
# live here, not in the runner, so the live run and a replay of a stored run
# compute the acceptance rule from ONE definition and cannot drift apart.


def observations(results: list[dict[str, Any]],
                 plan: dict[str, Any]) -> dict[str, Any]:
    """The non-scoring axes: what each engine actually did."""
    by_id = {c["case_id"]: c for c in plan["cases"]}
    rows = []
    for r in results:
        pc = by_id.get(r["case_id"], {})
        target = pc.get("target")
        planned = pc.get("sent_spans") or {}
        rows.append({
            "case_id": r["case_id"],
            "kind": r["expected"],
            "state": r["state"],
            "outcome": r.get("outcome"),
            # could the FIXED-WINDOW pack contain the target at all? where this
            # is false a window `missed` is a retrieval limit, not a model miss
            "target_in_planned_pack": (
                None if target is None else target[0] in planned),
            "files_sent": r.get("files_sent"),
            "bytes_after": r.get("bytes_after"),
            "latency_ms": r.get("latency_ms"),
            "tool_calls": r.get("tool_calls"),
            "repeated_calls": r.get("repeated_calls"),
            "stop_reason": r.get("stop_reason"),
            "cross_project_reached": r.get("cross_project_reached"),
            # W3-E7: the model's own word vs what the user was shown. The agent
            # runtime downgrades an unclosed `no_issue_observed`; without these
            # the guard's intervention is invisible here.
            "model_outcome": r.get("model_outcome", r.get("outcome")),
            "guard_downgraded": r.get("guard_downgraded", ""),
            "target": target,
            "cited_files": sorted({e["file"] for i in r.get("issues", [])
                                   for e in i["evidence"]}),
            "issues": r.get("issues", []),
        })
    return {"rows": rows}


def earned_evidence(rows: list[dict[str, Any]], *,
                    cross_project: bool) -> dict[str, Any]:
    """Did the engine EARN its answer, or was it right for the wrong reason?

    A cross-project case is decided by a file in a sibling project, so its
    acceptance criterion carries a reading requirement the scoring classifier
    cannot see: the classifier records the negative as `clean` whether or not
    the protection was ever opened. W3-E7 states the rule per kind:

      positive  — an issue citing the target AND the sibling actually read;
      negative  — the MODEL concluded `no_issue_observed` (not abstained, not
                  produced by the guard) AND the protection actually read;
      abstain   — the MODEL said `insufficient_context`; a guard-produced
                  abstention is the runtime's judgment, not the model's.

    `cross_project=False` cases have no sibling to reach, so the reading
    requirement does not apply to them and `meets_acceptance` is None — the
    honest value for a criterion that is not defined, and never a False that
    would read as a failure. Their detection is the classifier's job.
    """
    out = []
    for r in rows:
        reached = r.get("cross_project_reached") or []
        guarded = bool(r.get("guard_downgraded"))
        model_outcome = r.get("model_outcome", r.get("outcome"))
        cites = _cites_target(r.get("issues", []), r.get("target"))
        meets: bool | None
        if not cross_project:
            meets = None
        elif r["kind"] == EXPECT_POSITIVE:
            meets = bool(cites and reached)
        elif r["kind"] == EXPECT_NEGATIVE:
            meets = bool(model_outcome == "no_issue_observed"
                         and not guarded and reached)
        else:
            meets = bool(model_outcome == "insufficient_context"
                         and not guarded)
        out.append({"case_id": r["case_id"], "kind": r["kind"],
                    "outcome": r.get("outcome"),
                    "model_outcome": model_outcome,
                    "guard_downgraded": r.get("guard_downgraded", ""),
                    "cites_target": cites,
                    "sibling_reached": bool(reached),
                    "evidence_earned": bool(reached),
                    "meets_acceptance": meets})
    return {"rows": out}


# ---- confined local output -----------------------------------------------------------

def _confined_run_dir(base_dir: Path, run_id: str) -> Path:
    """The ONLY place detailed output may go: <base>/<run-id> where <base>
    resolves to a `.quality-local/ai-quality` directory. Anything else is
    refused with a path-free message. run_id must be a safe token."""
    if not run_id or not run_id.replace("-", "").replace("_", "").isalnum():
        raise HarnessError("run id is not a safe token")
    parts = base_dir.as_posix().rstrip("/").split("/")
    if tuple(p.lstrip(".") for p in parts[-2:]) != _CONFINED_BASE:
        raise HarnessError("detailed output is confined to "
                           ".quality-local/ai-quality only")
    return base_dir / run_id


def _atomic_write(path: Path, data: dict[str, Any]) -> None:
    blob = json.dumps(data, indent=1, ensure_ascii=True).encode("utf-8")
    if len(blob) > _MAX_OUTPUT_BYTES:
        raise HarnessError("harness output exceeds its size cap")
    tmp = path.with_name(path.name + ".tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_bytes(blob)
        os.replace(tmp, path)
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise HarnessError("harness output write failed") from None


def run_corpus(base_dir: Path, run_id: str,
               transport_factory: Callable[[], Any],
               provider: Provider = Provider.OLLAMA,
               model: str = "qwen2.5:7b",
               env: dict[str, str] | None = None,
               corpus: tuple[CorpusCase, ...] | None = None) -> dict[str, Any]:
    out_dir = _confined_run_dir(base_dir, run_id)
    corpus = corpus if corpus is not None else cases()
    plan = build_plan(corpus)
    _atomic_write(out_dir / "corpus_plan.json", plan)
    results = [run_case(c, provider, model, transport_factory(), env=env)
               for c in corpus]
    _atomic_write(out_dir / "corpus_results.json", {"results": results})
    classification = classify(plan, results, corpus)
    _atomic_write(out_dir / "corpus_classification.json", classification)
    return anonymized_summary(classification)
