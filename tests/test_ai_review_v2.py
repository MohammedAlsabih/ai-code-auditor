"""W3-B2: AIReviewResult v2 (w3c-v3) decision semantics.

A rule MATCH is separated from a real DEFECT, the evidence-only IMPACT, and
the ACTIONABILITY. The single `assessment` (which conflated all four) is gone.
A contradictory combination is ONE invalid_response — never silently repaired.
Legacy w3c-v2 rows stay readable as history (Legacy, always stale) and never
drop the store. No network."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from auditor.ai.contract import AIError
from auditor.ai.review import (
    PROMPT_VERSION, REVIEW_CONTRACT_VERSION, parse_review_reply)
from auditor.ai.review_store import (
    AIReviewStore, is_legacy_result, result_key)

ALLOWED = {"finding", "src:1"}


def _reply(match="matched", defect="confirmed", impact="high",
           actionability="actionable", action="fix_code", **over):
    body = {"match_assessment": match, "defect_assessment": defect,
            "impact": impact, "actionability": actionability, "summary": "s",
            "evidence": [{"context_id": "finding", "statement": "e"}],
            "missing_context": [], "suggested_action": action}
    body.update(over)
    return json.dumps(body)


def _parse(**kw):
    return parse_review_reply(_reply(**kw), ALLOWED)


# ---- the four axes are independent and round-trip -----------------------------------

def test_v2_result_carries_the_four_axes_and_version():
    r = _parse()
    assert set(r) == {"contract_version", "match_assessment",
                      "defect_assessment", "impact", "actionability",
                      "summary", "evidence", "missing_context",
                      "suggested_action"}
    assert r["contract_version"] == REVIEW_CONTRACT_VERSION == 2
    assert PROMPT_VERSION == "w3c-v5"
    assert "assessment" not in r and "confidence" not in r


# ---- consistency contract: contradictions are invalid_response ----------------------

@pytest.mark.parametrize("kw", [
    # fix_code without a confirmed, actionable defect
    dict(defect="acceptable", action="fix_code"),
    dict(defect="uncertain", actionability="uncertain", action="fix_code"),
    dict(defect="confirmed", actionability="context_dependent",
         action="fix_code"),
    dict(defect="confirmed", actionability="not_actionable", action="fix_code"),
    # dismiss without an acceptable defect
    dict(defect="confirmed", action="dismiss"),
    dict(defect="uncertain", actionability="uncertain", action="dismiss"),
    # a not_matched rule that still proposes inspect or fix_code
    dict(match="not_matched", defect="acceptable", action="inspect"),
    dict(match="not_matched", defect="confirmed", action="fix_code"),
    # an uncertain axis that does not fall back to inspect
    dict(defect="uncertain", actionability="uncertain", action="adjust_rule"),
    dict(match="uncertain", action="fix_code"),
    dict(actionability="uncertain", defect="confirmed", action="fix_code"),
])
def test_contradictory_combinations_are_one_invalid_response(kw):
    with pytest.raises(AIError) as e:
        _parse(**kw)
    assert e.value.code == "invalid_response"


@pytest.mark.parametrize("kw", [
    # a confirmed, actionable defect => fix_code is the ONLY combo that fixes
    dict(defect="confirmed", actionability="actionable", action="fix_code"),
    # a matched but acceptable behaviour => dismiss
    dict(defect="acceptable", actionability="not_actionable", action="dismiss"),
    # acceptable can also just be inspected
    dict(defect="acceptable", actionability="context_dependent",
         action="inspect"),
    # the rule did not really match => adjust the rule
    dict(match="not_matched", defect="acceptable",
         actionability="not_actionable", impact="none", action="adjust_rule"),
    dict(match="not_matched", defect="acceptable",
         actionability="not_actionable", impact="none", action="dismiss"),
    # missing context => uncertain => inspect
    dict(match="uncertain", defect="uncertain", impact="uncertain",
         actionability="uncertain", action="inspect"),
])
def test_consistent_combinations_are_accepted(kw):
    r = _parse(**kw)
    assert r["suggested_action"] == kw["action"]


# ---- the five reproduced scenarios, now expressible without conflation --------------

def test_p006_slight_threshold_match_is_not_auto_fix_code():
    # matched the >10 complexity threshold, but no proven defect / low impact /
    # not a safe change => inspect, NOT fix_code
    r = _parse(match="matched", defect="uncertain", impact="low",
               actionability="uncertain", action="inspect")
    assert r["match_assessment"] == "matched"
    assert r["suggested_action"] == "inspect"
    # and asking for fix_code on that same non-confirmed judgment is rejected
    with pytest.raises(AIError):
        _parse(match="matched", defect="uncertain", impact="low",
               actionability="uncertain", action="fix_code")


def test_p001_intended_fallback_is_acceptable_not_fixable():
    # a catch returning a constant fallback around localStorage may be a
    # deliberate best-effort fallback => acceptable, dismiss/inspect, NOT
    # fix_code
    r = _parse(match="matched", defect="acceptable", impact="low",
               actionability="context_dependent", action="inspect")
    assert r["defect_assessment"] == "acceptable"
    with pytest.raises(AIError):
        _parse(match="matched", defect="acceptable", action="fix_code")


def test_p002_committed_credential_stays_confirmed_and_fixable():
    r = _parse(match="matched", defect="confirmed", impact="critical",
               actionability="actionable", action="fix_code")
    assert r["defect_assessment"] == "confirmed"
    assert r["suggested_action"] == "fix_code"


def test_safe_parameterized_sql_is_not_a_matched_defect():
    # a parameterized query does not match the injection pattern => not_matched,
    # adjust_rule/dismiss, never a defect
    r = _parse(match="not_matched", defect="acceptable", impact="none",
               actionability="not_actionable", action="adjust_rule")
    assert r["match_assessment"] == "not_matched"
    assert r["suggested_action"] in ("adjust_rule", "dismiss")


def test_missing_context_defaults_to_inspect_not_assumptions():
    r = _parse(match="uncertain", defect="uncertain", impact="uncertain",
               actionability="uncertain", action="inspect",
               missing_context=["the validator is defined in an unsent file"])
    assert r["suggested_action"] == "inspect"


# ---- store: legacy v1 + v2 coexistence, no drop, stale + legacy flags ---------------

def _v2_row(**over):
    r = json.loads(_reply(**{k: v for k, v in over.items()
                             if k in ("match", "defect", "impact",
                                      "actionability", "action")}))
    row = {"review_id": "a" * 64, "provider": "ollama", "model": "m",
           "prompt_version": "w3c-v3", "latency_ms": 5,
           "context_digest": "b" * 64,
           "created_at": "2026-07-26T00:00:00Z", "contract_version": 2,
           **{k: r[k] for k in ("match_assessment", "defect_assessment",
                                "impact", "actionability", "summary",
                                "evidence", "missing_context",
                                "suggested_action")}}
    row.update({k: v for k, v in over.items() if k in row})
    return row


def _v1_row(**over):
    row = {"review_id": "c" * 64, "provider": "ollama", "model": "m",
           "prompt_version": "w3c-v2", "latency_ms": 5,
           "context_digest": "d" * 64,
           "created_at": "2026-07-25T00:00:00Z", "assessment": "confirmed",
           "confidence": "high", "summary": "s",
           "evidence": [{"context_id": "finding", "statement": "e"}],
           "missing_context": [], "suggested_action": "fix_code"}
    row.update(over)
    return row


def _sidecar(tmp: Path, schema: int, rows: list[dict]) -> Path:
    p = tmp / "report.ai-reviews.json"
    p.write_text(json.dumps({"schema_version": schema,
                             "results": {result_key(r): r for r in rows}}),
                 encoding="utf-8")
    return p


def test_legacy_v1_sidecar_loads_and_never_drops_the_store():
    with tempfile.TemporaryDirectory() as t:
        p = _sidecar(Path(t), 1, [_v1_row()])
        s = AIReviewStore(p)
        assert s.available                          # a v1 row is legal
        rows = s.for_review_id("c" * 64, None)
        assert rows and rows[0]["legacy"] is True and rows[0]["stale"] is True


def test_v2_row_is_not_legacy_and_stale_follows_the_digest():
    with tempfile.TemporaryDirectory() as t:
        p = _sidecar(Path(t), 2, [_v2_row()])
        s = AIReviewStore(p)
        assert s.available
        fresh = s.for_review_id("a" * 64, "b" * 64)[0]
        assert fresh["legacy"] is False and fresh["stale"] is False
        stale = s.for_review_id("a" * 64, "e" * 64)[0]
        assert stale["stale"] is True and stale["legacy"] is False


def test_mixed_v1_and_v2_rows_coexist_in_one_schema2_sidecar():
    with tempfile.TemporaryDirectory() as t:
        p = _sidecar(Path(t), 2, [_v1_row(), _v2_row()])
        s = AIReviewStore(p)
        assert s.available
        assert is_legacy_result(_v1_row()) and not is_legacy_result(_v2_row())


def test_a_v2_row_missing_an_axis_makes_the_store_unavailable():
    with tempfile.TemporaryDirectory() as t:
        bad = _v2_row()
        del bad["impact"]                           # not a v1 nor a v2 shape
        p = _sidecar(Path(t), 2, [bad])
        s = AIReviewStore(p)
        assert not s.available


def test_a_new_put_writes_schema_2():
    with tempfile.TemporaryDirectory() as t:
        p = Path(t) / "report.ai-reviews.json"
        s = AIReviewStore(p)
        s.put(_v2_row())
        data = json.loads(p.read_text(encoding="utf-8"))
        assert data["schema_version"] == 2


# ---- W3-B2 closing: real redaction_facts in the single-finding review path ----------

import tempfile as _tf                                            # noqa: E402
from pathlib import Path as _P                                    # noqa: E402

from auditor.ai.contract import (                                 # noqa: E402
    HttpResponse as _Resp, Provider as _Prov)
from auditor.ai.review import (                                   # noqa: E402
    AIReviewRequest as _Req, build_context_pack as _pack,
    finding_review_id as _rid, proven_credential_on_finding_line as _proven,
    run_review as _run)

_LOCAL = {"OLLAMA_HOST": "http://127.0.0.1:11434"}


def _p002_pack(src: str, repo: bool = True, line: int = 3):
    tmp = _P(_tf.mkdtemp())
    (tmp / "Db.cs").write_text(src, encoding="utf-8")
    f = {"rule_id": "P002", "level": "error", "severity": "red",
         "precision": "exact", "gate_action": "block", "title": "P002",
         "detail": "Connection string contains a literal password.",
         "file": "Db.cs", "line": line, "snippet": "x", "language": "csharp",
         "engine": "pattern-engine"}
    rep = {"summary": {"counts": {}}, "analysis_manifest": {"catalog": [
        {"rule_id": "P002", "title": "t", "description": "d",
         "category": "security", "default_level": "error",
         "default_precision": "exact", "engine": "pattern-engine"}],
        "execution": {"projects": [{"root": ".", "rules": {"P002": {
            "status": "completed", "attempted": 1, "failures": 0,
            "partial_parse_inputs": 0}}}]}, "policy": {}},
        "projects": [{"language": "csharp", "root": ".", "findings": [f]}]}
    return _pack(rep, tmp if repo else None, _rid(".", f))


def _facts(p):
    pc = next((x for x in p["pieces"]
               if x["context_id"] == "redaction_facts"), None)
    return pc["facts"] if pc else []


def test_1_conn_string_literal_on_finding_line_is_proven():
    p = _p002_pack('class F{\n void C(){\n  Open("Host=h;Password=postgres");\n }\n}\n')
    fs = _facts(p)
    assert [(f["line_start"], f["kind"]) for f in fs] == \
        [(3, "literal_credential_proven")]


def test_2_env_config_reference_is_redaction_applied_only():
    p = _p002_pack('class F{\n void C(){\n  Open("Host=h;Password=${DB_PASSWORD}");\n }\n}\n')
    fs = _facts(p)
    assert fs and all(f["kind"] == "redaction_applied" for f in fs)
    assert not any(f["kind"] == "literal_credential_proven" for f in fs)


def test_3_pre_masked_source_produces_zero_facts():
    p = _p002_pack('class F{\n void C(){\n  Open("Host=h;Password=***");\n }\n}\n')
    assert _facts(p) == []


def test_4_missing_source_or_dropped_line_produces_zero_facts():
    p = _p002_pack('irrelevant\n', repo=False)      # no repo => no source
    assert _facts(p) == []
    assert not any(x["context_id"] == "source:1" for x in p["pieces"])


def test_5_every_fact_line_is_present_in_the_final_source_piece():
    p = _p002_pack('class F{\n void C(){\n  Open("Host=h;Password=postgres");\n }\n}\n')
    src = next(x for x in p["pieces"] if x["context_id"] == "source:1")
    kept = {int(ln.split(":", 1)[0]) for ln in src["text"].split("\n")
            if ln.split(":", 1)[0].strip().isdigit()}
    for f in _facts(p):
        assert f["line_start"] in kept and f["line_end"] in kept


def test_6_no_original_value_leaks_anywhere():
    import json as _j
    p = _p002_pack('class F{\n void C(){\n  Open("Host=h;Password=postgres");\n }\n}\n')
    blob = p["canonical"] + _j.dumps(p["pieces"]) + _j.dumps(_facts(p))
    assert "postgres" not in blob            # value + its type never sent
    assert p["privacy_manifest"]["redaction_facts"] == 1


class _Fake:
    """A canned Ollama reply carrying whatever four-axis body is given."""

    def __init__(self, body):
        self._raw = json.dumps(body)

    def request(self, method, url, headers, json_body, timeout):
        return _Resp(200, json.dumps(
            {"message": {"role": "assistant", "content": self._raw}}).encode())


_PROVEN_SRC = 'class F{\n void C(){\n  Open("Host=h;Password=postgres");\n }\n}\n'


def test_7_not_matched_contradicting_a_literal_fact_is_invalid():
    p = _p002_pack(_PROVEN_SRC)
    assert _proven(p) is True
    body = {"match_assessment": "not_matched", "defect_assessment": "acceptable",
            "impact": "none", "actionability": "not_actionable", "summary": "s",
            "evidence": [{"context_id": "finding", "statement": "e"}],
            "missing_context": [], "suggested_action": "dismiss"}
    req = _Req(review_id=p["pieces"][0].get("review_id", "r"),
              provider=_Prov.OLLAMA, model="m")
    with pytest.raises(AIError) as e:
        _run(req, p, _Fake(body), env=_LOCAL)
    assert e.value.code == "invalid_response"


def test_8_matched_confirmed_actionable_fix_code_is_accepted():
    p = _p002_pack(_PROVEN_SRC)
    src_cid = next(x["context_id"] for x in p["pieces"]
                   if x["context_id"] == "redaction_facts")
    body = {"match_assessment": "matched", "defect_assessment": "confirmed",
            "impact": "high", "actionability": "actionable",
            "summary": "a committed literal credential",
            "evidence": [{"context_id": src_cid, "statement": "proven fact"}],
            "missing_context": [], "suggested_action": "fix_code"}
    req = _Req(review_id="r", provider=_Prov.OLLAMA, model="m")
    r = _run(req, p, _Fake(body), env=_LOCAL)
    assert r["match_assessment"] == "matched" \
        and r["defect_assessment"] == "confirmed" \
        and r["suggested_action"] == "fix_code"


def test_9_policy_now_binds_p002_but_off_line_facts_stay_context_based():
    # W3-B2 final closing: for P002 + a proven literal ON the finding line the
    # product policy binds — matched-but-acceptable is now REJECTED.
    p = _p002_pack(_PROVEN_SRC)
    body = {"match_assessment": "matched", "defect_assessment": "acceptable",
            "impact": "low", "actionability": "not_actionable",
            "summary": "a test fixture credential",
            "evidence": [{"context_id": "redaction_facts", "statement": "x"}],
            "missing_context": [], "suggested_action": "dismiss"}
    req = _Req(review_id="r", provider=_Prov.OLLAMA, model="m")
    with pytest.raises(AIError):
        _run(req, p, _Fake(body), env=_LOCAL)
    # but a literal on a DIFFERENT line (fact does not cover the finding line)
    # activates neither the policy nor the match fail-closed — the defect axis
    # stays context-based there.
    off = _p002_pack('class F{\n  Open("Host=h;Password=postgres");\n'
                     ' void C(){\n }\n}\n', line=3)     # literal is on line 2
    assert not any(x["context_id"] == "review_policy" for x in off["pieces"])
    r = _run(req, off, _Fake(body), env=_LOCAL)
    assert r["defect_assessment"] == "acceptable"


# ---- W3-B2 final closing: review_policy fact + fail-closed enforcement --------------

from auditor.ai.review import (                                   # noqa: E402
    REVIEW_POLICY, policy_violation as _viol)

_LIT_SRC = ('class F{\n void C(){\n'
            '  Open("Host=localhost;Port=5432;Password=postgres");\n }\n}\n')


def _haspol(p):
    return any(x["context_id"] == "review_policy" for x in p["pieces"])


def _core(**over):
    b = {"match_assessment": "matched", "defect_assessment": "confirmed",
         "impact": "low", "actionability": "actionable",
         "suggested_action": "fix_code"}
    b.update(over)
    return b


def test_policy_piece_only_for_p002_exact_with_proven_fact_on_line():
    assert _haspol(_p002_pack(_LIT_SRC))
    # the policy text is fixed, safe, and value-free
    p = _p002_pack(_LIT_SRC)
    pol = next(x for x in p["pieces"] if x["context_id"] == "review_policy")
    assert pol["policy"] == REVIEW_POLICY["P002"]
    assert "postgres" not in pol["policy"] and "madar" not in pol["policy"].lower()


def test_policy_piece_absent_for_ref_premask_missing_or_other_rule():
    # 6) env/config reference -> no policy fact, no enforcement
    ref = _p002_pack('class F{\n void C(){\n'
                     '  Open("Host=h;Password=${DB_PASSWORD}");\n }\n}\n')
    assert not _haspol(ref)
    assert not _viol(_core(defect_assessment="uncertain",
                           suggested_action="inspect"), ref)
    # 7) pre-masked *** -> no policy fact
    assert not _haspol(_p002_pack('class F{\n void C(){\n'
                                  '  Open("Host=h;Password=***");\n }\n}\n'))
    # 8) missing source -> no policy fact, no enforcement
    missing = _p002_pack(_LIT_SRC, repo=False)
    assert not _haspol(missing)
    assert not _viol(_core(defect_assessment="uncertain",
                           suggested_action="inspect"), missing)


def test_policy_enforced_combinations():
    p = _p002_pack(_LIT_SRC)
    # 1) confirmed/actionable/fix_code accepted (impact low and high both fine)
    assert not _viol(_core(), p)
    assert not _viol(_core(impact="high"), p)
    # 5) localhost permits impact=low (covered above) — but NOT none/uncertain
    assert _viol(_core(impact="none"), p)                              # 4)
    assert _viol(_core(impact="uncertain"), p)                         # 4)
    # 2) defect uncertain/acceptable rejected
    assert _viol(_core(defect_assessment="uncertain",
                       suggested_action="inspect"), p)
    assert _viol(_core(defect_assessment="acceptable",
                       suggested_action="dismiss"), p)
    # 3) not_matched rejected
    assert _viol(_core(match_assessment="not_matched",
                       suggested_action="adjust_rule"), p)


def test_policy_violating_reply_is_invalid_response_end_to_end():
    p = _p002_pack(_LIT_SRC)
    body = {"match_assessment": "matched", "defect_assessment": "uncertain",
            "impact": "uncertain", "actionability": "uncertain",
            "summary": "maybe a dev default",
            "evidence": [{"context_id": "finding", "statement": "e"}],
            "missing_context": [], "suggested_action": "inspect"}
    req = _Req(review_id="r", provider=_Prov.OLLAMA, model="m")
    with pytest.raises(AIError) as e:
        _run(req, p, _Fake(body), env=_LOCAL)
    assert e.value.code == "invalid_response"


def test_policy_conforming_reply_is_accepted_end_to_end():
    p = _p002_pack(_LIT_SRC)
    body = {"match_assessment": "matched", "defect_assessment": "confirmed",
            "impact": "low", "actionability": "actionable",
            "summary": "a committed literal credential; policy applies",
            "evidence": [{"context_id": "review_policy",
                          "statement": "policy binds the verdict"}],
            "missing_context": [], "suggested_action": "fix_code"}
    req = _Req(review_id="r", provider=_Prov.OLLAMA, model="m")
    r = _run(req, p, _Fake(body), env=_LOCAL)
    assert r["defect_assessment"] == "confirmed" \
        and r["suggested_action"] == "fix_code" and r["impact"] == "low"


def test_no_credential_value_in_canonical_or_policy_path():
    import json as _j
    p = _p002_pack(_LIT_SRC)
    blob = p["canonical"] + _j.dumps(p["pieces"])
    assert "postgres" not in blob
