"""W3-E7: the two principles the W3-E6 measurement showed the agent violating.

1. A reference read must contain the whole declaration it opens — not a line
   window that can stop above the deciding line. Live, the agent reached the
   right sibling file, read two lines of a six-line class, and never saw the
   stub body that made the case a defect.
2. `no_issue_observed` is not an EARNED verdict while relevant references
   remain unread. Live, the agent answered clean twice without ever reading
   the code that decides the question.

Every fixture here uses names and paths that appear NOWHERE in the measurement
corpus, so a fix cannot pass by memorising the corpus. Zero network.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from auditor.ai.audit_agent import WINDOW_LINES, _block_end, run_agent_unit
from auditor.ai.audit_index import RepositoryAuditIndex
from auditor.ai.audit_queries import query_by_id
from auditor.ai.contract import AIError, HttpResponse, Provider

ENV = {"OLLAMA_HOST": "http://127.0.0.1:11434",
       "AUDITOR_AI_AGENT_AUDIT": "confirm",
       "AUDITOR_OLLAMA_NUM_CTX": "8192"}

# Deliberately unlike the corpus: a billing service whose permission helper
# lives in a `platform` project. No corpus case uses these names or paths.
BILLING_STUB = {
    "billing/InvoiceEndpoints.cs": (
        'public class InvoiceEndpoints {\n'
        '  public void Register(WebApplication app) {\n'
        '    app.MapDelete("/invoices/{id}", Drop);\n'
        '  }\n'
        '  void Drop(HttpContext http, int id) {\n'
        '    if (!AccessPolicy.MayDelete(http)) { return; }\n'
        '    Ledger.Erase(id);\n'
        '  }\n'
        '}\n'),
    "platform/AccessPolicy.cs": (
        'public static class AccessPolicy {\n'
        '  public static bool MayDelete(HttpContext http) {\n'
        '    // pending\n'
        '    return true;\n'
        '  }\n'
        '}\n'),
}
BILLING_REAL = {
    "billing/InvoiceEndpoints.cs": BILLING_STUB["billing/InvoiceEndpoints.cs"],
    "platform/AccessPolicy.cs": (
        'public static class AccessPolicy {\n'
        '  public static bool MayDelete(HttpContext http) {\n'
        '    var scope = http.User.FindFirst("scope")?.Value;\n'
        '    if (scope != "invoices:delete") { return false; }\n'
        '    return true;\n'
        '  }\n'
        '}\n'),
}
BOTH = (("billing", "csharp"), ("platform", "csharp"))


def _index(files, projects):
    tmp = Path(tempfile.mkdtemp())
    for rel, text in files.items():
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return RepositoryAuditIndex(tmp, list(projects))


class Scripted:
    """Replays scripted native /api/chat turns and records every request."""

    def __init__(self, steps):
        self.steps = list(steps)
        self.bodies: list[dict] = []

    def request(self, method, url, headers, json_body, timeout):
        self.bodies.append(json_body)
        step = self.steps[min(len(self.bodies) - 1, len(self.steps) - 1)]
        name, args = step
        return HttpResponse(200, json.dumps({
            "model": "qwen3:14b", "done_reason": "stop",
            "message": {"role": "assistant", "content": "",
                        "tool_calls": [{"function": {"name": name,
                                                     "arguments": args}}]},
            "prompt_eval_count": 10, "eval_count": 10}).encode("utf-8"))


def _tool_returns(t) -> list[dict]:
    out = []
    for body in t.bodies:
        for m in body["messages"]:
            if m.get("role") == "tool":
                out.append(json.loads(m["content"]))
    return out


def _run(index, transport, project, query="AI001", trace=None):
    return run_agent_unit(index, project, query_by_id(query), Provider.OLLAMA,
                          "qwen3:14b", env=ENV, transport=transport,
                          trace=trace)


# ---- principle 1: a read completes the declaration it opens ------------------------

def test_a_short_read_is_completed_to_the_end_of_the_declaration():
    """Asking for the first two lines of a brace-delimited class must return
    the whole class, so the deciding body line cannot be missed."""
    idx = _index(BILLING_STUB, BOTH)
    trace: dict = {}
    t = Scripted([
        ("read_lines", {"file": "billing/InvoiceEndpoints.cs",
                        "start_line": 1, "end_line": 9}),
        ("find_references", {"symbol": "AccessPolicy"}),
        ("read_lines", {"file": "platform/AccessPolicy.cs",
                        "start_line": 1, "end_line": 2}),   # deliberately short
        ("final_result", {"outcome": "issues_found", "issues": [{
            "title": "t", "category": "authorization", "confidence": "high",
            "summary": "s",
            "evidence": [{"context_id": "src:2", "line_start": 2,
                          "line_end": 4, "statement": "e"}],
            "missing_context": [], "suggested_action": "inspect"}]}),
    ])
    res = _run(idx, t, "billing", trace=trace)

    spans = trace["pieces_sent"]
    got = next(p for p in spans if p["file"] == "platform/AccessPolicy.cs")
    # asked for [1,2]; the class closes on line 6, and `return true;` is line 4
    assert got["spans"] == [[1, 6]], got
    assert res["outcome"] == "issues_found"
    assert res["issues"][0]["evidence"][0]["file"] == "platform/AccessPolicy.cs"


def test_block_completion_never_exceeds_the_per_read_cap():
    """The completion must stay inside the SAME hard cap a read already had —
    it may not become a way to pull in an unbounded file."""
    body = "\n".join(f"    int x{i};" for i in range(200))
    huge = {"svc/Big.cs": "public class Big {\n" + body + "\n}\n"}
    idx = _index(huge, (("svc", "csharp"),))
    trace: dict = {}
    t = Scripted([
        ("read_lines", {"file": "svc/Big.cs", "start_line": 1, "end_line": 2}),
        ("final_result", {"outcome": "insufficient_context", "issues": []}),
    ])
    _run(idx, t, "svc", query="AI003", trace=trace)
    got = trace["pieces_sent"][0]["spans"][0]
    assert got[1] - got[0] + 1 <= 2 * WINDOW_LINES + 1


def test_block_completion_handles_indented_declarations():
    """Colon-and-indent languages get the same guarantee as brace languages."""
    lines = ("def outer():\n"
             "    secret = compute()\n"
             "    return secret\n"
             "def after():\n"
             "    return 1\n").splitlines()
    # asking for lines 1-1 must run to the end of the suite (line 3), not 1
    assert _block_end(lines, 1, 1, len(lines)) == 3
    # a line that opens nothing is left alone
    assert _block_end(lines, 5, 5, len(lines)) == 5


def test_block_completion_is_language_and_symbol_agnostic():
    """No rule, symbol or path is consulted — only structure."""
    braces = "class A {\n  void m() {\n    x();\n  }\n}\n".splitlines()
    assert _block_end(braces, 1, 2, len(braces)) == 5
    flat = "a = 1\nb = 2\nc = 3\n".splitlines()
    assert _block_end(flat, 1, 2, len(flat)) == 2      # nothing opened


# ---- principle 2: a clean verdict must be earned -----------------------------------

def test_clean_is_refused_while_a_relevant_reference_is_unread():
    """The negative shape: the guard genuinely enforces, but answering clean
    WITHOUT reading it is not an earned verdict."""
    idx = _index(BILLING_REAL, BOTH)
    trace: dict = {}
    t = Scripted([
        ("read_lines", {"file": "billing/InvoiceEndpoints.cs",
                        "start_line": 1, "end_line": 9}),
        ("final_result", {"outcome": "no_issue_observed", "issues": []}),
    ])
    res = _run(idx, t, "billing", trace=trace)

    assert res["outcome"] == "insufficient_context"      # downgraded
    assert trace["verdict_downgraded"] == "evidence_not_closed"
    gaps = trace["evidence_gaps"]["unread_references"]
    assert any(g["file"] == "platform/AccessPolicy.cs" for g in gaps), gaps


def test_clean_is_accepted_once_the_protection_has_been_read():
    """Same case, but the agent closes the evidence first — now the clean
    verdict stands. This is the behaviour the downgrade is meant to produce."""
    idx = _index(BILLING_REAL, BOTH)
    trace: dict = {}
    t = Scripted([
        ("read_lines", {"file": "billing/InvoiceEndpoints.cs",
                        "start_line": 1, "end_line": 9}),
        ("find_references", {"symbol": "AccessPolicy"}),
        ("read_lines", {"file": "platform/AccessPolicy.cs",
                        "start_line": 1, "end_line": 7}),
        ("final_result", {"outcome": "no_issue_observed", "issues": []}),
    ])
    res = _run(idx, t, "billing", trace=trace)

    assert res["outcome"] == "no_issue_observed"
    assert trace["verdict_downgraded"] == ""
    assert "platform/AccessPolicy.cs" in {p["file"]
                                          for p in trace["pieces_sent"]}
    assert trace["cross_project"] == {"platform/AccessPolicy.cs": "AccessPolicy"}


def test_the_model_is_told_about_the_gap_before_the_gate_fires():
    """The gate can never surprise the model: the same gaps ride on every tool
    result, with an explicit instruction."""
    idx = _index(BILLING_REAL, BOTH)
    t = Scripted([
        ("read_lines", {"file": "billing/InvoiceEndpoints.cs",
                        "start_line": 1, "end_line": 9}),
        ("final_result", {"outcome": "insufficient_context", "issues": []}),
    ])
    _run(idx, t, "billing")
    rets = [r for r in _tool_returns(t) if r.get("evidence_gaps")]
    assert rets, "no tool result advertised the gap"
    assert any("insufficient_context" in r["gap_note"] for r in rets)


def test_abstention_when_the_reference_cannot_be_resolved_at_all():
    """The protection's project is absent from the repository, so the evidence
    can never be closed — a clean answer must not survive."""
    only_caller = {"billing/InvoiceEndpoints.cs":
                   BILLING_STUB["billing/InvoiceEndpoints.cs"]}
    idx = _index(only_caller, (("billing", "csharp"),))
    trace: dict = {}
    t = Scripted([
        ("read_lines", {"file": "billing/InvoiceEndpoints.cs",
                        "start_line": 1, "end_line": 9}),
        ("final_result", {"outcome": "insufficient_context", "issues": []}),
    ])
    res = _run(idx, t, "billing", trace=trace)
    assert res["outcome"] == "insufficient_context"
    # nothing was invented: no file outside the audited project was reached
    assert trace["cross_project"] == {}
    assert {p["file"] for p in trace["pieces_sent"]} == {
        "billing/InvoiceEndpoints.cs"}


def test_a_manifest_query_is_not_closed_until_the_manifest_is_read():
    """Driven by the query catalog's needs_manifest flag — no path or rule
    knowledge. Two live positives were lost exactly this way."""
    proj = {
        "svc/loader.py": "import flask\nimport unlisted_helper\n"
                         "def go(d):\n    return unlisted_helper.run(d)\n",
        "svc/requirements.txt": "flask==3.0.0\n",
    }
    idx = _index(proj, (("svc", "python"),))
    trace: dict = {}
    t = Scripted([
        ("read_lines", {"file": "svc/loader.py", "start_line": 1,
                        "end_line": 4}),
        ("final_result", {"outcome": "no_issue_observed", "issues": []}),
    ])
    res = _run(idx, t, "svc", query="AI007", trace=trace)

    assert res["outcome"] == "insufficient_context"
    assert trace["verdict_downgraded"] == "evidence_not_closed"
    assert "svc/requirements.txt" in trace["evidence_gaps"]["unread_manifests"]
    # and the seed told the model to fetch it in the first place
    prompt = "\n".join(m["content"] for m in t.bodies[0]["messages"]
                       if m.get("role") == "user")
    assert "read_manifest" in prompt


def test_the_gate_does_not_fire_when_there_is_nothing_left_to_read():
    """A single-file project with no outstanding reference must still be able
    to answer clean — the gate must not make every verdict abstain."""
    solo = {"svc/util.py": "def add(a, b):\n    return a + b\n"}
    idx = _index(solo, (("svc", "python"),))
    trace: dict = {}
    t = Scripted([
        ("read_lines", {"file": "svc/util.py", "start_line": 1,
                        "end_line": 2}),
        ("final_result", {"outcome": "no_issue_observed", "issues": []}),
    ])
    res = _run(idx, t, "svc", query="AI003", trace=trace)
    assert res["outcome"] == "no_issue_observed"
    assert trace["verdict_downgraded"] == ""


# ---- the guarantees W3-E5 established must still hold -------------------------------

def test_an_untraced_sibling_path_is_still_refused():
    idx = _index(BILLING_REAL, BOTH)
    trace: dict = {}
    t = Scripted([
        ("read_lines", {"file": "platform/AccessPolicy.cs", "start_line": 1,
                        "end_line": 7}),
        ("final_result", {"outcome": "insufficient_context", "issues": []}),
    ])
    _run(idx, t, "billing", trace=trace)
    assert not trace["pieces_sent"]
    assert any(e["event"] == "read_denied" and e["reason"] == "not_traced"
               for e in trace["events"])


def test_a_citation_outside_what_was_read_is_still_rejected():
    idx = _index(BILLING_REAL, BOTH)
    t = Scripted([
        ("read_lines", {"file": "billing/InvoiceEndpoints.cs",
                        "start_line": 1, "end_line": 9}),
        ("final_result", {"outcome": "issues_found", "issues": [{
            "title": "t", "category": "authorization", "confidence": "high",
            "summary": "s",
            "evidence": [{"context_id": "src:9", "line_start": 1,
                          "line_end": 1, "statement": "e"}],
            "missing_context": [], "suggested_action": "inspect"}]}),
    ])
    with pytest.raises(AIError) as e:
        _run(idx, t, "billing")
    assert e.value.code == "invalid_response"
