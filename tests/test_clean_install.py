"""W3-E5 closing: the three install shapes must each behave correctly.

    pip install .[agent]      -> `auditor ai audit --agent` runs; no FastAPI.
    pip install .[web]        -> the server runs and reports Agent UNAVAILABLE.
    pip install .[web,agent]  -> the full path.

Nothing is uninstalled: a missing optional dependency is simulated by patching
the import system for ONE test, exactly the way tests/test_web_cli.py already
simulates a missing `uvicorn`. Every direction carries the mandatory negative
twin — an UNRELATED ModuleNotFoundError must still propagate, so a genuine
import bug can never be masked as "the extra is missing"."""
from __future__ import annotations

import builtins
import importlib
import importlib.util
import json
import sys
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic_ai.messages import ModelResponse, ToolCallPart
from pydantic_ai.models.function import AgentInfo, FunctionModel

from auditor import cli
from auditor.ai.audit_agent import run_agent_unit
from auditor.ai.audit_index import RepositoryAuditIndex
from auditor.ai.audit_queries import query_by_id
from auditor.ai.contract import Provider
from auditor.web import app as app_mod

LIMITS = json.dumps({"max_requests": 20, "max_output_tokens": 200_000,
                     "max_input_bytes": 5_000_000})


# ---- the simulator ------------------------------------------------------------------

def hide_packages(monkeypatch, *tops: str) -> None:
    """Make `import <top>` (and `<top>.<sub>`) fail exactly as on a clean
    install, for ONE test. All three doors into the import system are covered:
    the `__import__` builtin (fires on every IMPORT_NAME regardless of the
    sys.modules cache), importlib.import_module, and find_spec (which the
    availability probe uses)."""
    real_import = builtins.__import__
    real_module = importlib.import_module
    real_spec = importlib.util.find_spec

    def hidden(name: str) -> str | None:
        return next((t for t in tops
                     if name == t or name.startswith(t + ".")), None)

    def fake_import(name, *a, **k):
        t = hidden(name)
        if t is not None:
            raise ModuleNotFoundError(f"No module named '{t}'", name=t)
        return real_import(name, *a, **k)

    def fake_import_module(name, package=None):
        t = hidden(name)
        if t is not None:
            raise ModuleNotFoundError(f"No module named '{t}'", name=t)
        return real_module(name, package)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    monkeypatch.setattr(importlib, "import_module", fake_import_module)
    monkeypatch.setattr(importlib.util, "find_spec",
                        lambda n, p=None: None if hidden(n)
                        else real_spec(n, p))
    for key in [k for k in list(sys.modules) if hidden(k) is not None]:
        monkeypatch.delitem(sys.modules, key, raising=False)


def forget(monkeypatch, *mods: str) -> None:
    """Drop auditor modules so they RE-EXECUTE under the hook — otherwise the
    sys.modules cache hides the very top-level import under test."""
    for key in [k for k in list(sys.modules)
                if any(k == m or k.startswith(m + ".") for m in mods)]:
        monkeypatch.delitem(sys.modules, key, raising=False)


def test_the_simulator_itself_is_faithful(monkeypatch):
    hide_packages(monkeypatch, "pydantic_ai")
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("pydantic_ai")
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("pydantic_ai.models.function")
    assert importlib.util.find_spec("pydantic_ai") is None
    assert importlib.util.find_spec("json") is not None      # unrelated intact


# ---- fixtures -----------------------------------------------------------------------

REPORT = {
    "summary": {"counts": {}},
    "analysis_manifest": {"catalog": [], "execution": {"projects": []},
                          "policy": {}},
    "projects": [{"language": "python", "root": "svc", "findings": []}],
}


def _repo_and_report(tmp_path):
    api = tmp_path / "svc" / "api"
    api.mkdir(parents=True, exist_ok=True)
    (api / "orders.py").write_text(
        "from db import execute\n\n"
        "def get_order(request):\n"
        "    order_id = request.params['id']\n"
        "    return execute('SELECT * FROM orders WHERE id = %s' % order_id)\n",
        encoding="utf-8")
    (tmp_path / "svc" / "requirements.txt").write_text("requests\n",
                                                       encoding="utf-8")
    rp = tmp_path / "the-report.json"
    rp.write_text(json.dumps(REPORT), encoding="utf-8")
    return tmp_path, rp


def _local_agent_env(monkeypatch) -> None:
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    monkeypatch.setenv("AUDITOR_AI_AGENT_AUDIT", "confirm")
    monkeypatch.delenv("AUDITOR_AI_REMOTE_REVIEWS", raising=False)


# ---- direction A: the [agent] extra is NOT installed --------------------------------

def test_web_still_serves_and_reports_agent_unavailable(tmp_path, monkeypatch):
    """A `pip install .[web]` box: the explorer works completely; it just says
    the experimental agent is not available."""
    _local_agent_env(monkeypatch)
    repo, rp = _repo_and_report(tmp_path)
    hide_packages(monkeypatch, "pydantic_ai")

    client = TestClient(app_mod.create_app(rp, repo_root=repo))
    assert client.get("/api/report").status_code == 200      # serves normally
    pv = client.post("/api/ai/audits/preview",
                     json={"profile": "security", "provider": "ollama",
                           "model": "m"})
    assert pv.status_code == 200
    body = pv.json()
    assert body["mode"] == "fixed"          # the default engine is unaffected
    assert body["agent_available"] is False  # switch is ON, runtime is absent
    assert body["units"] >= 1


@pytest.mark.parametrize("endpoint,payload", [
    ("/api/ai/audits/preview",
     {"profile": "security", "provider": "ollama", "model": "m",
      "mode": "agent"}),
    ("/api/ai/audits",
     {"profile": "security", "provider": "ollama", "model": "m",
      "mode": "agent",
      "limits": {"max_requests": 20, "max_output_tokens": 200_000,
                 "max_input_bytes": 5_000_000}}),
])
def test_agent_request_is_a_clean_503_not_a_crash(tmp_path, monkeypatch,
                                                  endpoint, payload):
    _local_agent_env(monkeypatch)
    repo, rp = _repo_and_report(tmp_path)
    hide_packages(monkeypatch, "pydantic_ai")

    client = TestClient(app_mod.create_app(rp, repo_root=repo))
    r = client.post(endpoint, json=payload)
    assert r.status_code == 503
    assert r.json()["status"] == "agent_runtime_missing"
    assert "ai-code-auditor[agent]" in r.json()["error"]


def test_cli_agent_without_the_extra_is_a_clean_error(tmp_path, monkeypatch,
                                                      capsys):
    _local_agent_env(monkeypatch)
    repo, rp = _repo_and_report(tmp_path)
    hide_packages(monkeypatch, "pydantic_ai")

    rc = cli.main(["ai", "audit", "--report", str(rp), "--repo", str(repo),
                   "--provider", "ollama", "--model", "m",
                   "--profile", "security", "--limits", LIMITS, "--agent"])
    err = capsys.readouterr().err
    assert rc == 2
    assert 'pip install "ai-code-auditor[agent]"' in err
    assert "Traceback" not in err


def test_an_unrelated_missing_module_still_propagates(tmp_path, monkeypatch):
    """The negative twin: only the KNOWN extra becomes a friendly message. A
    genuine import bug must never be reported as 'the extra is missing'."""
    _local_agent_env(monkeypatch)
    repo, rp = _repo_and_report(tmp_path)
    hide_packages(monkeypatch, "hashlib")     # not an extra: a real breakage
    forget(monkeypatch, "auditor.ai.audit_agent")
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("auditor.ai.audit_agent")


# ---- direction B: the [web] extra is NOT installed ----------------------------------

def _index(files, project="api", lang="csharp"):
    tmp = Path(tempfile.mkdtemp())
    for rel, text in files.items():
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return RepositoryAuditIndex(tmp, [(project, lang)])


def test_agent_engine_runs_with_no_fastapi(monkeypatch):
    """The agent runtime itself must not need the web extra — its path guard
    used to be imported from the FastAPI-importing module."""
    idx = _index({"api/a.cs": 'class A { void f(){ var p = "x"; } }\n'})
    steps = [
        ("read_lines", {"file": "api/a.cs", "start_line": 1, "end_line": 1}),
        ("__final__", {"outcome": "insufficient_context", "issues": []}),
    ]
    state = {"i": 0}

    def fn(messages, info: AgentInfo) -> ModelResponse:
        name, args = steps[state["i"]]
        state["i"] += 1
        if name == "__final__":
            return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name,
                                                     args)])
        return ModelResponse(parts=[ToolCallPart(name, args)])

    hide_packages(monkeypatch, "fastapi", "uvicorn", "starlette")
    res = run_agent_unit(idx, "api", query_by_id("AI003"), Provider.OLLAMA, "m",
                         env={"OLLAMA_HOST": "http://127.0.0.1:11434",
                              "AUDITOR_AI_AGENT_AUDIT": "confirm"},
                         pydantic_model=FunctionModel(fn))
    assert res["outcome"] == "insufficient_context"


def test_cli_ai_audit_agent_does_not_need_fastapi(tmp_path, monkeypatch,
                                                  capsys):
    """Probed with a deliberately bad --repo so NO model is ever contacted:
    the only legal outcome is the CLI's own usage error, which proves the
    command got past every import."""
    _local_agent_env(monkeypatch)
    _, rp = _repo_and_report(tmp_path)
    hide_packages(monkeypatch, "fastapi", "uvicorn", "starlette")
    forget(monkeypatch, "auditor.cli", "auditor.web")
    fresh_cli = importlib.import_module("auditor.cli")

    rc = fresh_cli.main(["ai", "audit", "--report", str(rp),
                         "--repo", str(tmp_path / "does-not-exist"),
                         "--provider", "ollama", "--model", "m",
                         "--profile", "security", "--limits", LIMITS,
                         "--agent"])
    assert rc == 2
    assert "--repo is not a directory" in capsys.readouterr().err


def test_audit_agent_module_imports_with_no_fastapi(monkeypatch):
    hide_packages(monkeypatch, "fastapi", "uvicorn", "starlette")
    forget(monkeypatch, "auditor.ai.audit_agent", "auditor.web")
    mod = importlib.import_module("auditor.ai.audit_agent")
    assert mod.AUDIT_AGENT_PROMPT_VERSION.startswith("w3e5-agent-v")


def test_no_web_or_agent_module_is_pulled_in_by_the_runtime():
    """Regression guard on the closure itself: importing the agent runtime
    must not drag in FastAPI, uvicorn, starlette or any auditor.web module."""
    import subprocess
    code = (
        "import sys; import auditor.ai.audit_agent;"
        "bad=[m for m in sys.modules"
        " if m.split('.')[0] in ('fastapi','uvicorn','starlette')"
        " or m.startswith('auditor.web')];"
        "print(sorted(bad))"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                         text=True, check=True,
                         cwd=str(Path(__file__).resolve().parent.parent))
    assert out.stdout.strip() == "[]", out.stdout
