"""W3-E5 closing: what the agent runtime actually puts on the Ollama wire, the
limits it actually enforces, and how far it may reach across the repository.

Zero network — the project's own transport seam is filled with a scripted fake
that records every request body. The point is that the guarantees are checked
where they are made (the wire), not merely configured: the OpenAI-compatible
/v1 shim silently DROPS `options.num_ctx`, `think`, and `max_completion_tokens`,
which is exactly why this runtime talks to the native /api/chat endpoint.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from auditor.ai.audit import AUDIT_MAX_OUTPUT_TOKENS
from auditor.ai.audit_agent import (
    MAX_AGENT_TURNS,
    MAX_TOOL_CALLS,
    run_agent_unit,
)
from auditor.ai.audit_index import RepositoryAuditIndex
from auditor.ai.audit_queries import query_by_id
from auditor.ai.contract import AIError, HttpResponse, Provider

ENV = {"OLLAMA_HOST": "http://127.0.0.1:11434",
       "AUDITOR_AI_AGENT_AUDIT": "confirm",
       "AUDITOR_OLLAMA_NUM_CTX": "8192"}

# one repository, TWO sibling projects: the route lives in `api`, the guard it
# calls lives in `shared` — the deciding evidence is never project-local.
XPROJ = {
    "api/AdminRoutes.cs": (
        'public class AdminRoutes {\n'
        '  public void Map(WebApplication app) {\n'
        '    app.MapPost("/admin/purge", Purge);\n'
        '  }\n'
        '  void Purge(HttpContext ctx) {\n'
        '    SharedAuth.RequireAdmin(ctx);\n'
        '    Db.WipeAll();\n'
        '  }\n'
        '}\n'),
    "shared/SharedAuth.cs": (
        'public static class SharedAuth {\n'
        '  public static void RequireAdmin(HttpContext ctx) {\n'
        '    var role = ctx.User.FindFirst("role")?.Value;\n'
        '    if (role != "admin") { throw new UnauthorizedAccessException(); }\n'
        '  }\n'
        '}\n'),
}


# the POSITIVE twin: same shape, but the sibling guard is a STUB, so the defect
# is real and provable ONLY by reading the other project.
XPROJ_STUB = {
    "api/AdminRoutes.cs": (
        'public class AdminRoutes {\n'
        '  public void Map(WebApplication app) {\n'
        '    app.MapPost("/admin/purge", Purge);\n'
        '  }\n'
        '  void Purge(HttpContext ctx) {\n'
        '    if (!SharedAuth.IsAdmin(ctx)) { return; }\n'
        '    Db.WipeAll();\n'
        '  }\n'
        '}\n'),
    "shared/SharedAuth.cs": (
        'public static class SharedAuth {\n'
        '  public static bool IsAdmin(HttpContext ctx) {\n'
        '    // not implemented yet\n'
        '    return true;\n'
        '  }\n'
        '}\n'),
}
BOTH = (("api", "csharp"), ("shared", "csharp"))


def _index(files, projects=(("api", "csharp"),)):
    tmp = Path(tempfile.mkdtemp())
    for rel, text in files.items():
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return RepositoryAuditIndex(tmp, list(projects))


class ScriptedOllama:
    """A transport with the project's exact signature that replays scripted
    NATIVE /api/chat replies and records every outgoing body."""

    def __init__(self, steps, in_tokens=10, out_tokens=10):
        self.steps = list(steps)
        self.bodies: list[dict] = []
        self.urls: list[str] = []
        self._in, self._out = in_tokens, out_tokens

    def request(self, method, url, headers, json_body, timeout):
        self.bodies.append(json_body)
        self.urls.append(url)
        step = self.steps[min(len(self.bodies) - 1, len(self.steps) - 1)]
        if step == "__loop__":
            step = self.steps[-2]
        elif step == "__distinct_reads__":
            # a DIFFERENT span every turn, so the dedup cache never hits and
            # the tool-call budget is genuinely consumed
            n = len(self.bodies)
            step = ("read_lines", {"file": "api/Big.cs",
                                   "start_line": n, "end_line": n + 1})
        message: dict = {"role": "assistant", "content": ""}
        if step is not None:
            name, args = step
            message["tool_calls"] = [{"function": {"name": name,
                                                   "arguments": args}}]
        else:
            message["content"] = "done"
        return HttpResponse(200, json.dumps({
            "model": "qwen3:14b", "message": message, "done_reason": "stop",
            "prompt_eval_count": self._in, "eval_count": self._out,
        }).encode("utf-8"))


def _verdict_args(cid="src:1", ls=3, le=3, cat="authorization"):
    return {"outcome": "issues_found", "issues": [{
        "title": "t", "category": cat, "confidence": "high", "summary": "s",
        "evidence": [{"context_id": cid, "line_start": ls, "line_end": le,
                      "statement": "e"}],
        "missing_context": [], "suggested_action": "inspect"}]}


def _run(index, transport, project="api", query="AI001", trace=None):
    return run_agent_unit(index, project, query_by_id(query), Provider.OLLAMA,
                          "qwen3:14b", env=ENV, transport=transport,
                          trace=trace)


# ---- the wire shape -----------------------------------------------------------------

def test_the_ollama_request_body_is_exactly_the_agreed_shape():
    idx = _index(XPROJ)
    t = ScriptedOllama([
        ("read_lines", {"file": "api/AdminRoutes.cs", "start_line": 1,
                        "end_line": 9}),
        ("final_result", _verdict_args()),
    ])
    _run(idx, t)

    assert t.urls and all(u.endswith("/api/chat") for u in t.urls), t.urls
    for body in t.bodies:
        # exact key set — an unknown key would be silently IGNORED by Ollama,
        # which is the failure mode that made /v1 drop num_ctx unnoticed.
        assert set(body) == {"model", "messages", "stream", "think", "tools",
                             "options"}, sorted(body)
        assert body["model"] == "qwen3:14b"
        assert body["stream"] is False
        assert body["think"] is False              # thinking really disabled
        assert body["options"] == {
            "temperature": 0,
            "num_predict": AUDIT_MAX_OUTPUT_TOKENS,  # the real output cap
            "num_ctx": 8192,                         # the real context window
        }
        assert "keep_alive" not in body
        assert "format" not in body    # structured output rides the tool call
        assert "max_tokens" not in body and "max_completion_tokens" not in body


def test_every_read_only_tool_and_the_output_tool_are_on_the_wire():
    idx = _index(XPROJ)
    t = ScriptedOllama([("final_result", _verdict_args(cid="query"))])
    with pytest.raises(AIError):        # citing the query piece is invalid
        _run(idx, t)
    names = {tool["function"]["name"] for tool in t.bodies[0]["tools"]}
    assert {"search_code", "find_references", "read_lines",
            "read_manifest"} <= names
    assert "final_result" in names      # the structured-output tool
    for tool in t.bodies[0]["tools"]:
        assert tool["type"] == "function"
        assert isinstance(tool["function"]["parameters"], dict)


def test_num_ctx_follows_the_server_env_not_the_request():
    idx = _index(XPROJ)
    t = ScriptedOllama([("final_result", _verdict_args(cid="query"))])
    env = dict(ENV, AUDITOR_OLLAMA_NUM_CTX="4096")
    with pytest.raises(AIError):
        run_agent_unit(idx, "api", query_by_id("AI001"), Provider.OLLAMA,
                       "qwen3:14b", env=env, transport=t)
    assert t.bodies[0]["options"]["num_ctx"] == 4096


# ---- the limits are real ------------------------------------------------------------

def test_tool_call_limit_stops_the_unit():
    """A model that keeps making DISTINCT tool calls (so the dedup cache never
    helps) is stopped by the budget — the unit fails safely, never loops."""
    big = dict(XPROJ)
    big["api/Big.cs"] = ("class Big {\n"
                         + "".join(f"  int x{i};\n" for i in range(200))
                         + "}\n")
    idx = _index(big)
    t = ScriptedOllama(["__distinct_reads__"])
    with pytest.raises(AIError) as e:
        _run(idx, t)
    assert e.value.code == "invalid_response"
    assert len(t.bodies) <= MAX_TOOL_CALLS + MAX_AGENT_TURNS


def test_request_limit_stops_a_model_that_never_finishes():
    idx = _index(XPROJ)
    # plain text every turn: no tool calls, so only request_limit can stop it
    t = ScriptedOllama([None, "__loop__"])
    with pytest.raises(AIError) as e:
        _run(idx, t)
    assert e.value.code == "invalid_response"
    assert len(t.bodies) <= MAX_AGENT_TURNS


def test_token_limits_stop_a_runaway_unit():
    """Token limits are checked against the usage the runtime maps out of
    Ollama's prompt_eval_count / eval_count — a wrong mapping would silently
    disable them, so this asserts they actually bite."""
    idx = _index(XPROJ)
    t = ScriptedOllama([("read_lines", {"file": "api/AdminRoutes.cs",
                                        "start_line": 1, "end_line": 2}),
                        "__loop__"],
                       in_tokens=10_000_000, out_tokens=10_000_000)
    with pytest.raises(AIError) as e:
        _run(idx, t)
    assert e.value.code == "invalid_response"
    assert len(t.bodies) <= 2       # stopped on the FIRST response's usage


# ---- cross-project tracing, without repository browsing -----------------------------

def test_a_traced_symbol_reaches_a_sibling_project():
    """The guard lives in `shared`. The agent reads the call site, traces the
    symbol it just saw, and only then may read the sibling file."""
    idx = _index(XPROJ, projects=(("api", "csharp"), ("shared", "csharp")))
    trace: dict = {}
    t = ScriptedOllama([
        ("read_lines", {"file": "api/AdminRoutes.cs", "start_line": 1,
                        "end_line": 9}),                  # sees RequireAdmin
        ("find_references", {"symbol": "RequireAdmin"}),  # traces it out
        ("read_lines", {"file": "shared/SharedAuth.cs", "start_line": 1,
                        "end_line": 6}),                  # now permitted
        ("final_result", _verdict_args(cid="src:2", ls=2, le=4)),
    ])
    res = _run(idx, t, trace=trace)

    assert res["outcome"] == "issues_found"
    # the accepted citation lands in the SIBLING project — only possible if the
    # trace, the read, and the pack all crossed the project boundary
    assert res["issues"][0]["evidence"][0]["file"] == "shared/SharedAuth.cs"
    # W3-E7: the sibling may now be admitted as soon as a symbol the agent has
    # READ is found DECLARED there — the same predicate find_references applies,
    # just evaluated eagerly. What matters is that the opener is a genuinely
    # declared symbol, never a passing mention.
    opened = [e for e in trace["events"]
              if e["event"] == "cross_project_reachable"
              and e["path"] == "shared/SharedAuth.cs"]
    assert opened, trace["events"]
    assert trace["cross_project"]["shared/SharedAuth.cs"] in {
        "SharedAuth", "RequireAdmin"}
    assert {p["file"] for p in trace["pieces_sent"]} == {
        "api/AdminRoutes.cs", "shared/SharedAuth.cs"}


def test_naming_a_sibling_file_directly_is_refused():
    """No browsing: an untraced path in another project cannot be read even
    though it is in the same repository index."""
    idx = _index(XPROJ, projects=(("api", "csharp"), ("shared", "csharp")))
    seen: dict = {}
    t = ScriptedOllama([
        ("read_lines", {"file": "shared/SharedAuth.cs", "start_line": 1,
                        "end_line": 6}),
        ("final_result", {"outcome": "insufficient_context", "issues": []}),
    ])
    res = _run(idx, t, trace=seen)
    assert res["outcome"] == "insufficient_context"
    assert not seen["pieces_sent"]             # nothing crossed
    assert any(e["event"] == "read_denied" and e["reason"] == "not_traced"
               for e in seen["events"])


def test_tracing_requires_a_symbol_the_agent_actually_read():
    """Guessing a symbol without having read it does NOT open the sibling
    project — that would be a crawl, not a trace."""
    idx = _index(XPROJ, projects=(("api", "csharp"), ("shared", "csharp")))
    seen: dict = {}
    t = ScriptedOllama([
        ("find_references", {"symbol": "RequireAdmin"}),   # never read it
        ("read_lines", {"file": "shared/SharedAuth.cs", "start_line": 1,
                        "end_line": 6}),
        ("final_result", {"outcome": "insufficient_context", "issues": []}),
    ])
    res = _run(idx, t, trace=seen)
    assert res["outcome"] == "insufficient_context"
    assert not seen["pieces_sent"]
    assert any(e["event"] == "find_references" and e["traceable"] is False
               for e in seen["events"])


def test_a_sibling_that_declares_nothing_read_is_never_opened():
    """REPRODUCED LIVE before W3-E5's fix: qwen3:14b traced `HttpContext` — a
    framework type named in both files — and that alone unlocked the sibling.
    The invariant is that a sibling opens ONLY on a symbol the agent has read
    AND that the sibling actually DECLARES. Here a third project shares no
    declared symbol with anything read, so it must stay closed no matter what
    the model asks for."""
    files = dict(XPROJ)
    files["vendorlib/Telemetry.cs"] = (
        'public static class Telemetry {\n'
        '  public static void Emit(string name) { }\n'
        '}\n')
    idx = _index(files, projects=(("api", "csharp"), ("shared", "csharp"),
                                  ("vendorlib", "csharp")))
    seen: dict = {}
    t = ScriptedOllama([
        ("read_lines", {"file": "api/AdminRoutes.cs", "start_line": 1,
                        "end_line": 9}),
        ("find_references", {"symbol": "HttpContext"}),   # mentioned, undeclared
        ("read_lines", {"file": "vendorlib/Telemetry.cs", "start_line": 1,
                        "end_line": 3}),                  # must be refused
        ("final_result", {"outcome": "insufficient_context", "issues": []}),
    ])
    res = _run(idx, t, trace=seen)
    assert res["outcome"] == "insufficient_context"
    assert "vendorlib/Telemetry.cs" not in seen["cross_project"]
    assert "vendorlib/Telemetry.cs" not in {p["file"]
                                            for p in seen["pieces_sent"]}
    assert any(e["event"] == "read_denied" and e["reason"] == "not_traced"
               for e in seen["events"])
    assert all(e.get("via") != "HttpContext" for e in seen["events"]
               if e["event"] == "cross_project_reachable")


def test_a_refusal_still_explains_itself():
    """A unit that fails must leave a value-free trace behind — otherwise an
    operator cannot tell 'read nothing' from 'ran out of turns'."""
    idx = _index(XPROJ)
    seen: dict = {}
    t = ScriptedOllama([("read_lines", {"file": "api/AdminRoutes.cs",
                                        "start_line": 1, "end_line": 3}),
                        "__loop__"])
    with pytest.raises(AIError):
        _run(idx, t, trace=seen)
    assert seen["stop_reason"] == "usage_limit"     # actionable, not opaque
    assert seen["tool_calls"] >= 1
    assert seen["pieces_sent"]                      # what it HAD read is shown
    assert seen["verdict_outcome"] is None


def test_search_code_never_leaves_the_audited_project():
    """search_code is a discovery tool, so it stays project-local: there is no
    path from 'search the repo' to 'read another project'."""
    idx = _index(XPROJ, projects=(("api", "csharp"), ("shared", "csharp")))
    seen: dict = {}
    t = ScriptedOllama([
        ("search_code", {"pattern": "RequireAdmin"}),
        ("final_result", {"outcome": "insufficient_context", "issues": []}),
    ])
    _run(idx, t, trace=seen)
    # the scripted model saw the hits; assert none pointed outside `api`
    tool_msgs = [m for b in t.bodies for m in b["messages"]
                 if m.get("role") == "tool"]
    assert tool_msgs
    for m in tool_msgs:
        for hit in json.loads(m["content"]).get("hits", []):
            assert hit["file"].startswith("api/"), hit


# ---- closing round: the two acceptance cases, and no wasted calls -------------------

def _tool_returns(transport) -> list[dict]:
    """Every tool result the model was actually shown, in order."""
    out = []
    for body in transport.bodies:
        for m in body["messages"]:
            if m.get("role") == "tool":
                out.append(json.loads(m["content"]))
    # each request replays the whole history, so keep only the newest prefix
    return out[-max((len(b["messages"]) for b in transport.bodies), default=0):]


def test_an_identical_tool_call_is_answered_from_memory_not_repeated():
    """REPRODUCED LIVE: qwen3:14b re-issued the SAME find_references three
    times and re-read overlapping spans until it ran out of turns. A repeat now
    replays the stored answer, says so, and does NOT spend the tool budget."""
    idx = _index(XPROJ)
    seen: dict = {}
    same = ("read_lines", {"file": "api/AdminRoutes.cs", "start_line": 1,
                           "end_line": 9})
    t = ScriptedOllama([
        same, same, same,                       # the identical call, 3x
        ("final_result", _verdict_args(cid="src:1", ls=3, le=3)),
    ])
    res = _run(idx, t, trace=seen)

    assert res["outcome"] == "issues_found"
    # three identical calls, but only the FIRST did any work
    assert seen["tool_calls"] == 1
    assert seen["repeated_calls"] == 2
    assert sum(1 for e in seen["events"] if e["event"] == "repeat") == 2
    assert sum(1 for e in seen["events"] if e["event"] == "read") == 1
    replays = [r for r in _tool_returns(t) if r.get("repeated")]
    assert replays and all("Do not repeat a call" in r["note"] for r in replays)


def test_every_tool_result_reports_the_remaining_budget():
    idx = _index(XPROJ)
    t = ScriptedOllama([
        ("search_code", {"pattern": "MapPost"}),
        ("read_lines", {"file": "api/AdminRoutes.cs", "start_line": 1,
                        "end_line": 9}),
        ("final_result", _verdict_args(cid="src:1", ls=3, le=3)),
    ])
    _run(idx, t)
    rets = _tool_returns(t)
    assert rets and all("calls_left" in r for r in rets)
    # strictly decreasing: the model can see exploration running out
    lefts = [r["calls_left"] for r in rets]
    assert lefts == sorted(lefts, reverse=True) and lefts[0] < MAX_TOOL_CALLS


def test_positive_cross_project_completes_within_the_limits():
    """ACCEPTANCE 1: trace the real reference into the sibling project and
    return a LEGAL verdict cited from the context that decides it — without
    reaching usage_limit."""
    idx = _index(XPROJ_STUB, projects=BOTH)
    seen: dict = {}
    t = ScriptedOllama([
        ("read_lines", {"file": "api/AdminRoutes.cs", "start_line": 1,
                        "end_line": 9}),
        ("find_references", {"symbol": "SharedAuth"}),
        ("read_lines", {"file": "shared/SharedAuth.cs", "start_line": 1,
                        "end_line": 6}),
        ("final_result", _verdict_args(cid="src:2", ls=2, le=4)),
    ])
    res = _run(idx, t, trace=seen)

    assert res["outcome"] == "issues_found"
    assert res["issues"][0]["evidence"][0]["file"] == "shared/SharedAuth.cs"
    assert seen["stop_reason"] == ""                 # never hit a limit
    assert seen["tool_calls"] <= MAX_TOOL_CALLS
    assert len(t.bodies) <= MAX_AGENT_TURNS
    assert seen["cross_project"] == {"shared/SharedAuth.cs": "SharedAuth"}


def test_negative_cross_project_completes_after_reading_the_protection():
    """ACCEPTANCE 2: reach the protection that lives in the sibling project and
    return a LEGAL no_issue_observed — not issues_found with an empty list, and
    not invalid_response."""
    idx = _index(XPROJ, projects=BOTH)
    seen: dict = {}
    t = ScriptedOllama([
        ("read_lines", {"file": "api/AdminRoutes.cs", "start_line": 1,
                        "end_line": 9}),
        ("find_references", {"symbol": "SharedAuth"}),
        ("read_lines", {"file": "shared/SharedAuth.cs", "start_line": 1,
                        "end_line": 6}),
        ("final_result", {"outcome": "no_issue_observed", "issues": []}),
    ])
    res = _run(idx, t, trace=seen)

    assert res["outcome"] == "no_issue_observed"
    assert res["issues"] == []
    assert seen["stop_reason"] == ""
    # the protection was genuinely read before the verdict
    assert "shared/SharedAuth.cs" in {p["file"] for p in seen["pieces_sent"]}
    assert seen["cross_project"] == {"shared/SharedAuth.cs": "SharedAuth"}


def test_issues_found_with_no_issues_is_not_representable():
    """The sent schema now carries the SAME coupling the server enforces, so an
    empty issues_found comes back to the model as a correctable retry instead
    of dying as invalid_response. The server validator stays fail-closed."""
    idx = _index(XPROJ)
    t = ScriptedOllama([
        ("read_lines", {"file": "api/AdminRoutes.cs", "start_line": 1,
                        "end_line": 9}),
        ("final_result", {"outcome": "issues_found", "issues": []}),  # illegal
        ("final_result", {"outcome": "no_issue_observed", "issues": []}),
    ])
    res = _run(idx, t)
    assert res["outcome"] == "no_issue_observed"     # self-corrected
    # the model was told exactly what was wrong, in its own retry channel
    retries = [m for b in t.bodies for m in b["messages"]
               if m.get("role") == "tool"
               and "issues_found" in str(m.get("content", ""))
               and "at least one issue" in str(m.get("content", ""))]
    assert retries


def test_the_wire_schema_offers_only_legal_enum_values():
    """Drift guard: the JSON Schema the model sees must carry the server's
    enums, including this query's single legal category."""
    idx = _index(XPROJ)
    t = ScriptedOllama([("final_result", _verdict_args(cid="query"))])
    with pytest.raises(AIError):
        _run(idx, t)
    out_tool = next(tool for tool in t.bodies[0]["tools"]
                    if tool["function"]["name"] == "final_result")
    schema = json.dumps(out_tool["function"]["parameters"])
    assert '"enum": ["authorization"]' in schema.replace(", ", ", ")
    for legal in ("issues_found", "no_issue_observed", "insufficient_context"):
        assert legal in schema
    assert "input_handling" not in schema      # other categories are illegal


def test_a_spent_budget_asks_for_a_verdict_instead_of_killing_the_unit():
    """Exhausting the tool budget must END in a verdict, not a usage_limit
    death: the tools refuse, tell the model to conclude, and the model can."""
    big = dict(XPROJ)
    big["api/Big.cs"] = ("class Big {\n"
                         + "".join(f"  int x{i};\n" for i in range(200))
                         + "}\n")
    idx = _index(big)
    steps = [("read_lines", {"file": "api/Big.cs", "start_line": n,
                             "end_line": n + 1})
             for n in range(1, MAX_TOOL_CALLS + 1)]           # spend it all
    assert MAX_TOOL_CALLS + 2 <= MAX_AGENT_TURNS   # room left to conclude
    steps.append(("read_lines", {"file": "api/Big.cs", "start_line": 190,
                                 "end_line": 191}))           # one too many
    steps.append(("final_result", {"outcome": "insufficient_context",
                                   "issues": []}))
    seen: dict = {}
    res = _run(idx, ScriptedOllama(steps), trace=seen)

    assert res["outcome"] == "insufficient_context"   # concluded, not killed
    assert seen["stop_reason"] == ""
    assert seen["tool_calls"] == MAX_TOOL_CALLS       # never exceeded
    assert any(e["event"] == "budget_exhausted" for e in seen["events"])


def test_the_seed_hint_names_a_span_that_covers_the_handler_body():
    """REPRODUCED LIVE: a bare seed LINE made the model read three lines around
    the route registration and stop one line short of the call it had to trace.
    The hint must name a bounded span, like the fixed-window engine's seed."""
    idx = _index(XPROJ_STUB, projects=BOTH)
    t = ScriptedOllama([("final_result", {"outcome": "insufficient_context",
                                          "issues": []})])
    _run(idx, t)
    prompt = "\n".join(m["content"] for m in t.bodies[0]["messages"]
                       if m.get("role") == "user")
    assert "api/AdminRoutes.cs lines 1-9" in prompt, prompt
    assert "the file has 9 lines" in prompt
    # the span must reach the SharedAuth call (line 6), not stop at the match
    assert "ONE call" in prompt
