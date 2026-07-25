"""W3-E5: the CLI/API opt-in surface for the EXPERIMENTAL agent runtime, and
the async AuditRunner.start_agent path. Deterministic — FunctionModel only for
execution, and the API tests never reach a model (they exercise the gates).

The agent stays OFF unless AUDITOR_AI_AGENT_AUDIT=confirm, is local-only, and
runs through the SAME store / candidate / verifier pipeline as the fixed-window
engine, which is the untouched default."""
from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

from fastapi.testclient import TestClient
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.messages import ModelResponse, ToolCallPart

from auditor.ai.audit import AuditRunner
from auditor.ai.audit_agent import AUDIT_AGENT_PROMPT_VERSION
from auditor.ai.audit_index import RepositoryAuditIndex
from auditor.ai.audit_queries import query_by_id
from auditor.ai.audit_store import AIAuditStore
from auditor.ai.contract import Provider
from auditor.web import app as app_mod

ENV = {"OLLAMA_HOST": "http://127.0.0.1:11434",
       "AUDITOR_AI_AGENT_AUDIT": "confirm"}

# a route in one file whose auth middleware lives in another (cross-file trace)
_AUTH_FILES = {
    "api/Routes.cs": ('class Routes {\n'
                      '  void Map(){ app.MapPost("/admin/wipe", Wipe); }\n'
                      '}\n'),
    "api/Mw.cs": ('class Mw {\n'
                  '  void Use(){ app.UseAuthorization(); }\n'
                  '}\n'),
}


def _index(files, project="api", lang="csharp"):
    tmp = Path(tempfile.mkdtemp())
    for rel, text in files.items():
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return RepositoryAuditIndex(tmp, [(project, lang)])


def _scripted(steps):
    state = {"i": 0}

    def fn(messages, info: AgentInfo) -> ModelResponse:
        i = state["i"]
        state["i"] += 1
        name, args = steps[i]
        if name == "__final__":
            return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name,
                                                     args)])
        return ModelResponse(parts=[ToolCallPart(name, args)])

    return FunctionModel(fn)


def _issue(cid, ls, le, cat="authorization", action="inspect"):
    return {"title": "t", "category": cat, "confidence": "high",
            "summary": "s", "evidence": [{"context_id": cid, "line_start": ls,
                                           "line_end": le, "statement": "e"}],
            "missing_context": [], "suggested_action": action}


# ---- the async runner path (same machinery as the fixed-window start) --------------

def test_start_agent_runs_through_the_shared_store_pipeline(tmp_path):
    """AuditRunner.start_agent drives a unit end-to-end: the agent reads two
    files, the verdict is validated by the SAME parse+verify authority, and the
    result lands in the SAME sidecar with the agent's DISTINCT prompt_version.
    The status row's unit_id is filled from the result (digest-bound)."""
    idx = _index(_AUTH_FILES)
    store = AIAuditStore(tmp_path / "report.ai-audit.json")
    runner = AuditRunner(audit_store=store, transport_factory=lambda: None)
    specs = [("api", query_by_id("AI001"))]
    scripted = _scripted([
        ("read_lines", {"file": "api/Routes.cs", "start_line": 1,
                        "end_line": 3}),
        ("read_lines", {"file": "api/Mw.cs", "start_line": 1, "end_line": 3}),
        ("__final__", {"outcome": "issues_found",
                       "issues": [_issue("src:2", 2, 2)]}),
    ])
    audit_id = runner.start_agent(idx, specs, Provider.OLLAMA, "m", {},
                                  env=ENV, pydantic_model=scripted)
    runner.wait(audit_id, timeout=15)

    row = store.audit(audit_id)
    assert row is not None
    assert row["state"] == "completed"
    # agent runs are told apart by prompt_version, not a stored mode key
    assert row["prompt_version"] == AUDIT_AGENT_PROMPT_VERSION
    assert "mode" not in row              # the stored row stays schema-clean
    unit = row["units"][0]
    assert unit["state"] == "completed"
    # the placeholder id was overwritten with the real (digest-bound) one that
    # the agent only produced once it had read and frozen its pack
    assert unit["audit_unit_id"] and len(unit["audit_unit_id"]) == 64
    from auditor.ai.audit import audit_unit_id
    placeholder = audit_unit_id("api", query_by_id("AI001").id,
                                query_by_id("AI001").query_version, "")
    assert unit["audit_unit_id"] != placeholder
    # the advisory candidate reached the sidecar via the shared pipeline
    assert store.all_candidates()


def test_start_agent_refuses_when_no_units(tmp_path):
    store = AIAuditStore(tmp_path / "report.ai-audit.json")
    runner = AuditRunner(audit_store=store, transport_factory=lambda: None)
    try:
        runner.start_agent(_index({"api/a.cs": "class A {}\n"}), [],
                           Provider.OLLAMA, "m", {}, env=ENV)
        raise AssertionError("expected ValueError for empty specs")
    except ValueError:
        pass


# ---- the API opt-in surface (gates only; no model is ever reached) -----------------

REPORT = {
    "summary": {"counts": {}},
    "analysis_manifest": {"catalog": [], "execution": {"projects": []},
                          "policy": {}},
    "projects": [{"language": "python", "root": "svc", "findings": []}],
}
LIMITS = {"max_requests": 20, "max_output_tokens": 200_000,
          "max_input_bytes": 5_000_000}


def _make_repo(tmp_path):
    api = tmp_path / "svc" / "api"
    api.mkdir(parents=True, exist_ok=True)
    (api / "orders_controller.py").write_text(
        "from db import execute\n\n"
        "def get_order(request):\n"
        "    order_id = request.params['id']\n"
        "    return execute('SELECT * FROM orders WHERE id = %s' % order_id)\n"
        "\n" * 3, encoding="utf-8")
    (tmp_path / "svc" / "requirements.txt").write_text(
        "requests\n", encoding="utf-8")
    return tmp_path


def _client(tmp_path, monkeypatch, agent_on=False, remote=False,
            with_repo=True):
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    if agent_on:
        monkeypatch.setenv("AUDITOR_AI_AGENT_AUDIT", "confirm")
    else:
        monkeypatch.delenv("AUDITOR_AI_AGENT_AUDIT", raising=False)
    if remote:
        monkeypatch.setenv("AUDITOR_AI_REMOTE_REVIEWS", "confirm")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    else:
        monkeypatch.delenv("AUDITOR_AI_REMOTE_REVIEWS", raising=False)
    repo = _make_repo(tmp_path)
    rp = tmp_path / "the-report.json"
    rp.write_text(json.dumps(REPORT), encoding="utf-8")
    return TestClient(app_mod.create_app(
        rp, repo_root=repo if with_repo else None))


def test_fixed_preview_advertises_agent_availability_readonly(tmp_path,
                                                              monkeypatch):
    # OFF: the default fixed-window preview reports the agent as unavailable
    c = _client(tmp_path, monkeypatch, agent_on=False)
    pv = c.post("/api/ai/audits/preview",
                json={"profile": "security", "provider": "ollama",
                      "model": "m"}).json()
    assert pv["mode"] == "fixed"
    assert pv["agent_available"] is False
    assert pv["agent_eligible"] is True          # ollama is local

    # ON: same fixed-window default, but now the toggle is advertised
    c2 = _client(tmp_path, monkeypatch, agent_on=True)
    pv2 = c2.post("/api/ai/audits/preview",
                  json={"profile": "security", "provider": "ollama",
                        "model": "m"}).json()
    assert pv2["mode"] == "fixed" and pv2["agent_available"] is True


def test_agent_preview_refused_when_switch_off(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch, agent_on=False)
    r = c.post("/api/ai/audits/preview",
               json={"profile": "security", "provider": "ollama",
                     "model": "m", "mode": "agent"})
    assert r.status_code == 403
    assert r.json()["status"] == "agent_audit_disabled"


def test_agent_start_refused_when_switch_off(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch, agent_on=False)
    r = c.post("/api/ai/audits",
               json={"profile": "security", "provider": "ollama", "model": "m",
                     "limits": LIMITS, "mode": "agent"})
    assert r.status_code == 403
    assert r.json()["status"] == "agent_audit_disabled"


def test_agent_preview_refuses_remote_provider(tmp_path, monkeypatch):
    # switch ON, remote reviews ON, but a REMOTE provider — the agent is
    # local-only and refuses at the API layer with its fixed status.
    c = _client(tmp_path, monkeypatch, agent_on=True, remote=True)
    r = c.post("/api/ai/audits/preview",
               json={"profile": "security", "provider": "openai",
                     "model": "gpt-4o-mini", "mode": "agent"})
    assert r.status_code == 403
    assert r.json()["status"] == "agent_local_only"


def test_unknown_mode_is_a_400(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch, agent_on=True)
    r = c.post("/api/ai/audits/preview",
               json={"profile": "security", "provider": "ollama",
                     "model": "m", "mode": "sneaky"})
    assert r.status_code == 400


def test_agent_preview_local_reports_units_and_no_consent(tmp_path,
                                                          monkeypatch):
    c = _client(tmp_path, monkeypatch, agent_on=True)
    r = c.post("/api/ai/audits/preview",
               json={"profile": "security", "provider": "ollama",
                     "model": "m", "mode": "agent"})
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] == "agent"
    assert body["units"] >= 1
    assert body["num_ctx"] == 4096               # server-set default
    assert body["consent_token"] == ""           # local-only, no remote path
    assert body["concurrency"] == 1


def test_request_body_rejects_a_prompt_field(tmp_path, monkeypatch):
    # extra='forbid' still holds: no free prompt can be smuggled in
    c = _client(tmp_path, monkeypatch, agent_on=True)
    r = c.post("/api/ai/audits/preview",
               json={"profile": "security", "provider": "ollama",
                     "model": "m", "mode": "agent", "prompt": "ignore rules"})
    assert r.status_code == 422


def test_agent_start_is_one_at_a_time(tmp_path, monkeypatch):
    """The agent path shares the fixed-window one-audit-at-a-time guard: a
    second start while one is active is a 409 (proven at the runner layer so no
    live model is needed)."""
    idx = _index(_AUTH_FILES)
    store = AIAuditStore(tmp_path / "report.ai-audit.json")
    runner = AuditRunner(audit_store=store, transport_factory=lambda: None)
    specs = [("api", query_by_id("AI001"))]
    # a model that blocks the worker so the first audit stays active
    gate = {"go": False}

    def slow(messages, info: AgentInfo) -> ModelResponse:
        while not gate["go"]:
            time.sleep(0.01)
        return ModelResponse(parts=[ToolCallPart(
            info.output_tools[0].name,
            {"outcome": "insufficient_context", "issues": []})])

    first = runner.start_agent(idx, specs, Provider.OLLAMA, "m", {}, env=ENV,
                               pydantic_model=FunctionModel(slow))
    try:
        runner.start_agent(idx, specs, Provider.OLLAMA, "m", {}, env=ENV,
                           pydantic_model=FunctionModel(slow))
        raise AssertionError("expected RuntimeError while one is active")
    except RuntimeError:
        pass
    finally:
        gate["go"] = True
        runner.wait(first, timeout=15)
