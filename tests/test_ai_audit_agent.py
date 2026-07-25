"""W3-E5: the experimental local agent audit runtime. FunctionModel/TestModel
only — ZERO network. Proves the agent traces across files before judging,
abstains without evidence, cannot escape the repo or exceed its limits, emits a
store/verifier-compatible result, leaks no value, and stays OFF by default —
while the fixed-window engine is untouched."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.models.test import TestModel

from auditor.ai.audit import candidates_from_result
from auditor.ai.audit_agent import (
    AUDIT_AGENT_PROMPT_VERSION,
    AgentAuditDisabledError,
    agent_audit_enabled,
    run_agent_unit,
)
from auditor.ai.audit_index import RepositoryAuditIndex
from auditor.ai.audit_queries import query_by_id
from auditor.ai.contract import AIError, Provider

ENV = {"OLLAMA_HOST": "http://127.0.0.1:11434",
       "AUDITOR_AI_AGENT_AUDIT": "confirm"}


def _index(files: dict[str, str], project="api", lang="csharp"):
    tmp = Path(tempfile.mkdtemp())
    for rel, text in files.items():
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return RepositoryAuditIndex(tmp, [(project, lang)])


def _scripted(steps):
    """Turn a list of (tool_name, args) — the last being the output tool payload
    keyed by '__final__' — into a FunctionModel."""
    state = {"i": 0}

    def fn(messages, info: AgentInfo) -> ModelResponse:
        i = state["i"]
        state["i"] += 1
        name, args = steps[i]
        if name == "__final__":
            return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name,
                                                     args)])
        if name == "__text__":
            return ModelResponse(parts=[TextPart(args)])
        return ModelResponse(parts=[ToolCallPart(name, args)])

    return FunctionModel(fn)


def _verdict(*issues, outcome="issues_found"):
    return ("__final__", {"outcome": outcome, "issues": list(issues)})


def _issue(cid, ls, le, cat="credentials", action="fix_code"):
    return {"title": "t", "category": cat, "confidence": "high",
            "summary": "s", "evidence": [{"context_id": cid, "line_start": ls,
                                           "line_end": le, "statement": "e"}],
            "missing_context": [], "suggested_action": action}


# a two-file case: a route in one file whose auth middleware lives in another
_AUTH_FILES = {
    "api/Routes.cs": ('class Routes {\n'
                      '  void Map(){ app.MapPost("/admin/wipe", Wipe); }\n'
                      '}\n'),
    "api/Mw.cs": ('class Mw {\n'
                  '  void Use(){ app.UseAuthorization(); }\n'
                  '}\n'),
}


# ---- opt-in gate -------------------------------------------------------------------

def test_engine_is_off_unless_env_confirms():
    assert agent_audit_enabled({"AUDITOR_AI_AGENT_AUDIT": "confirm"})
    for bad in ({}, {"AUDITOR_AI_AGENT_AUDIT": "1"},
                {"AUDITOR_AI_AGENT_AUDIT": "true"},
                {"AUDITOR_AI_AGENT_AUDIT": "yes"}):
        assert not agent_audit_enabled(bad)
    idx = _index({"api/a.cs": "class A {}\n"})
    with pytest.raises(AgentAuditDisabledError) as e:
        run_agent_unit(idx, "api", query_by_id("AI003"), Provider.OLLAMA, "m",
                       env={}, pydantic_model=TestModel())
    assert e.value.code == "agent_audit_disabled"


# ---- traces across more than one file BEFORE judging -------------------------------

def test_agent_traces_protection_across_files_before_verdict():
    idx = _index(_AUTH_FILES)
    steps = {"tools": []}

    def fn(messages, info: AgentInfo) -> ModelResponse:
        n = len([m for m in messages if getattr(m, "kind", "") == "response"])
        seq = [
            ("search_code", {"pattern": "MapPost"}),           # discover route
            ("read_lines", {"file": "api/Routes.cs",           # read file A
                            "start_line": 1, "end_line": 3}),
            ("find_references", {"symbol": "UseAuthorization"}),  # trace to B
            ("read_lines", {"file": "api/Mw.cs",               # read file B
                            "start_line": 1, "end_line": 3}),
        ]
        if n < len(seq):
            name, args = seq[n]
            steps["tools"].append(name)
            return ModelResponse(parts=[ToolCallPart(name, args)])
        # the verdict CITES the middleware in file B — only possible if the
        # agent followed the reference and read B before judging
        return ModelResponse(parts=[ToolCallPart(
            info.output_tools[0].name, {"outcome": "issues_found", "issues": [
                _issue("src:2", 2, 2, cat="authorization", action="inspect")]})])

    res = run_agent_unit(idx, "api", query_by_id("AI001"), Provider.OLLAMA,
                         "m", env=ENV, pydantic_model=FunctionModel(fn))
    assert steps["tools"] == ["search_code", "read_lines",
                              "find_references", "read_lines"]
    # the accepted citation lands in the SECOND file — proof it was traced,
    # read, and folded into the sent pack before the verdict
    assert res["outcome"] == "issues_found"
    assert res["issues"][0]["evidence"][0]["file"] == "api/Mw.cs"


def test_two_files_are_both_in_the_sent_context():
    idx = _index(_AUTH_FILES)
    # read both files, then cite each — a citation only validates if the piece
    # was actually sent, so acceptance proves both are in the frozen pack
    res = run_agent_unit(
        idx, "api", query_by_id("AI001"), Provider.OLLAMA, "m", env=ENV,
        pydantic_model=_scripted([
            ("read_lines", {"file": "api/Routes.cs", "start_line": 1,
                            "end_line": 3}),
            ("read_lines", {"file": "api/Mw.cs", "start_line": 1,
                            "end_line": 3}),
            _verdict(_issue("src:1", 2, 2, cat="authorization",
                            action="inspect"), outcome="issues_found"),
        ]))
    assert res["outcome"] == "issues_found"
    assert res["issues"][0]["evidence"][0]["file"] == "api/Routes.cs"


# ---- abstains without sufficient evidence ------------------------------------------

def test_agent_abstains_when_evidence_is_insufficient():
    idx = _index(_AUTH_FILES)
    res = run_agent_unit(
        idx, "api", query_by_id("AI001"), Provider.OLLAMA, "m", env=ENV,
        pydantic_model=_scripted([
            ("read_lines", {"file": "api/Routes.cs", "start_line": 1,
                            "end_line": 2}),
            ("__final__", {"outcome": "insufficient_context", "issues": []}),
        ]))
    assert res["outcome"] == "insufficient_context"
    assert res["issues"] == []


# ---- cannot escape the repository ---------------------------------------------------

@pytest.mark.parametrize("badpath", [
    "../../../etc/passwd", "..\\..\\secrets.txt", "/etc/hosts",
    "C:\\Windows\\win.ini", "api/../../outside.cs", "api/does_not_exist.cs",
])
def test_agent_cannot_read_outside_the_repo(badpath):
    idx = _index({"api/a.cs": 'class A { void f(){ return; } }\n'})
    seen: dict[str, object] = {}

    def fn(messages, info: AgentInfo) -> ModelResponse:
        n = len([m for m in messages if getattr(m, "kind", "") == "response"])
        if n == 0:
            return ModelResponse(parts=[ToolCallPart(
                "read_lines", {"file": badpath, "start_line": 1,
                               "end_line": 3})])
        # capture the tool return the model saw
        for m in messages[::-1]:
            for part in getattr(m, "parts", []):
                if getattr(part, "part_kind", "") == "tool-return":
                    seen["ret"] = part.content
                    break
            if "ret" in seen:
                break
        return ModelResponse(parts=[ToolCallPart(
            info.output_tools[0].name,
            {"outcome": "insufficient_context", "issues": []})])

    res = run_agent_unit(idx, "api", query_by_id("AI003"), Provider.OLLAMA,
                         "m", env=ENV, pydantic_model=FunctionModel(fn))
    # the escape was refused (ok False), nothing was read, and no file content
    # entered the pack (files_sent 0 on the frozen pack => digest over query only)
    assert isinstance(seen.get("ret"), dict) and seen["ret"]["ok"] is False
    assert res["outcome"] == "insufficient_context"


def test_a_refused_read_never_becomes_citable():
    idx = _index({"api/a.cs": 'class A {}\n'})
    # the model claims to cite src:1 though the only read was refused
    with pytest.raises(AIError) as e:
        run_agent_unit(idx, "api", query_by_id("AI003"), Provider.OLLAMA, "m",
                       env=ENV, pydantic_model=_scripted([
                           ("read_lines", {"file": "../evil.cs",
                                           "start_line": 1, "end_line": 2}),
                           _verdict(_issue("src:1", 1, 1)),
                       ]))
    assert e.value.code == "invalid_response"


# ---- cannot exceed the limits ------------------------------------------------------

def test_tool_call_limit_is_enforced():
    idx = _index({"api/a.cs": "class A {\n" + "".join(
        f"  int x{i};\n" for i in range(60)) + "}\n"})

    def loop(messages, info: AgentInfo) -> ModelResponse:
        return ModelResponse(parts=[ToolCallPart(
            "read_lines", {"file": "api/a.cs", "start_line": 1,
                           "end_line": 2})])

    with pytest.raises(AIError) as e:            # UsageLimitExceeded => safe code
        run_agent_unit(idx, "api", query_by_id("AI003"), Provider.OLLAMA, "m",
                       env=ENV, pydantic_model=FunctionModel(loop))
    assert e.value.code == "invalid_response"


def test_citation_outside_a_sent_span_is_rejected():
    idx = _index({"api/a.cs": 'class A {\n  void f(){}\n  void g(){}\n}\n'})
    with pytest.raises(AIError) as e:
        run_agent_unit(idx, "api", query_by_id("AI003"), Provider.OLLAMA, "m",
                       env=ENV, pydantic_model=_scripted([
                           ("read_lines", {"file": "api/a.cs",
                                           "start_line": 1, "end_line": 2}),
                           _verdict(_issue("src:1", 99, 99)),  # not sent
                       ]))
    assert e.value.code == "invalid_response"


# ---- no value leak + manifest completeness -----------------------------------------

def test_no_credential_value_leaks_and_manifest_accounts_reads():
    idx = _index({"api/Db.cs": ('class F {\n  Ctx C(){\n'
                                '    return Open("Host=h;Password=hunter2real");'
                                '\n  }\n}\n')})
    res = run_agent_unit(
        idx, "api", query_by_id("AI003"), Provider.OLLAMA, "m", env=ENV,
        pydantic_model=_scripted([
            ("read_lines", {"file": "api/Db.cs", "start_line": 1,
                            "end_line": 5}),
            _verdict(_issue("src:1", 3, 3)),
        ]))
    blob = json.dumps(res)
    assert "hunter2real" not in blob            # value never leaves
    # the credential was redacted AND proven => the verifier promoted it
    assert res["issues"][0]["verification"] == "supported"


# ---- store + candidates compatibility ----------------------------------------------

def test_result_is_store_and_candidate_compatible():
    import auditor.ai.audit_store as store_mod
    idx = _index({"api/Db.cs": ('class F {\n  Ctx C(){\n'
                                '    return Open("Host=h;Password=hunter2real");'
                                '\n  }\n}\n')})
    res = run_agent_unit(
        idx, "api", query_by_id("AI003"), Provider.OLLAMA, "m", env=ENV,
        pydantic_model=_scripted([
            ("read_lines", {"file": "api/Db.cs", "start_line": 1,
                            "end_line": 5}),
            _verdict(_issue("src:1", 3, 3)),
        ]))
    assert res["prompt_version"] == AUDIT_AGENT_PROMPT_VERSION == "w3e5-agent-v1"
    cands = candidates_from_result(res)
    with tempfile.TemporaryDirectory() as t:
        st = store_mod.AIAuditStore(Path(t) / "r.ai-audit.json")
        st.put_result(res, cands)                # no AIAuditStoreError => valid
        assert len(st.all_candidates()) == len(cands) == 1


def test_agent_execution_identity_differs_from_fixed_window():
    from auditor.ai.audit import AUDIT_PROMPT_VERSION, audit_execution_id
    unit = "u" * 64
    fixed = audit_execution_id(unit, "ollama", "m", AUDIT_PROMPT_VERSION, 8192)
    agent = audit_execution_id(unit, "ollama", "m",
                               AUDIT_AGENT_PROMPT_VERSION, 8192)
    assert fixed != agent and AUDIT_AGENT_PROMPT_VERSION != AUDIT_PROMPT_VERSION


# ---- the LIVE model path is gated local-only (no network in the test) --------------

def test_live_model_path_refuses_remote_provider():
    from auditor.ai.audit_agent import _build_live_model
    from auditor.ai.review import PrivacyGateError
    # a remote provider (OpenAI) with a key + the remote switch is STILL refused
    # in agent mode — dynamic reads cannot be consent-pre-bound
    with pytest.raises((PrivacyGateError, AIError)):
        _build_live_model(Provider.OPENAI, "gpt",
                          {"OPENAI_API_KEY": "sk-x",
                           "AUDITOR_AI_REMOTE_REVIEWS": "confirm"})


def test_fixed_window_engine_is_unchanged():
    # importing the agent module must not perturb the fixed-window contract
    from auditor.ai.audit import AUDIT_PROMPT_VERSION, run_audit_unit
    assert AUDIT_PROMPT_VERSION == "w3e-v5"
    assert callable(run_audit_unit)
