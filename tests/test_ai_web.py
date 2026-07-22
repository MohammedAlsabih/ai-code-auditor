"""W3-A: the /api/ai/* surface + CLI commands. Fake transports only."""
import json

import pytest
from fastapi.testclient import TestClient

from auditor.ai.contract import HttpResponse
from auditor.cli import main
from auditor.web import app as app_mod


@pytest.fixture()
def client(tmp_path):
    report = {"tool": "ai-code-auditor", "summary": {}, "projects": []}
    p = tmp_path / "report.json"
    p.write_text(json.dumps(report), encoding="utf-8")
    return TestClient(app_mod.create_app(p))


class CountingTransport:
    calls = 0

    def request(self, method, url, headers, json_body, timeout):
        CountingTransport.calls += 1
        return HttpResponse(200, b'{"data": [{"id": "m1"}]}')


def test_get_providers_is_local_only(client, monkeypatch):
    """GET /api/ai/providers must not execute ANY network call and must not
    leak base URLs or keys."""
    CountingTransport.calls = 0
    monkeypatch.setattr("auditor.ai.transport.RequestsTransport",
                        CountingTransport)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-SECRET-999")
    r = client.get("/api/ai/providers")
    assert r.status_code == 200
    body = r.json()
    rows = {p["provider"]: p for p in body["providers"]}
    assert set(rows) == {"openai", "anthropic", "xai", "ollama",
                         "openai_compatible"}
    assert rows["xai"]["display"] == "xAI (Grok)"
    assert rows["openai"]["key_present"] is True
    assert rows["ollama"]["locality"] == "local"
    text = r.text
    assert "sk-SECRET-999" not in text
    assert "api.openai.com" not in text and "11434" not in text  # no base URLs
    assert CountingTransport.calls == 0
    assert "fixed probe only" in body["note"]


def test_post_rejects_api_key_and_base_url_from_browser(client):
    for extra in ({"api_key": "sk-x"}, {"base_url": "https://evil.example"}):
        r = client.post("/api/ai/test", json={"provider": "openai",
                                              "model": "m", **extra})
        assert r.status_code == 422        # extra=forbid — rejected pre-handler


def test_post_models_and_test_envelopes(client, monkeypatch):
    class T:
        def request(self, method, url, headers, json_body, timeout):
            if url.endswith("/v1/models"):
                return HttpResponse(200, b'{"data": [{"id": "m2"}, {"id": "m1"}]}')
            return HttpResponse(200, b'{"output_text": "OK"}')

    monkeypatch.setattr("auditor.ai.transport.RequestsTransport", T)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-SECRET-1")
    r = client.post("/api/ai/models", json={"provider": "openai"})
    assert r.status_code == 200
    assert r.json() == {"provider": "openai", "status": "ok",
                        "models": ["m1", "m2"]}
    r2 = client.post("/api/ai/test", json={"provider": "openai", "model": "m1"})
    assert r2.status_code == 200
    body = r2.json()
    assert body["status"] == "ok" and isinstance(body["latency_ms"], int)
    # ONLY the safe fields — no reply text, key, or URL
    assert set(body) == {"provider", "model", "status", "message", "latency_ms"}
    assert "OK" not in body["message"] and "sk-SECRET" not in r2.text


def test_post_error_envelope_is_safe(client, monkeypatch):
    class T:
        def request(self, method, url, headers, json_body, timeout):
            return HttpResponse(401, b'{"error": {"message": "bad sk-LEAK"}}')

    monkeypatch.setattr("auditor.ai.transport.RequestsTransport", T)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-SECRET-1")
    r = client.post("/api/ai/test", json={"provider": "openai", "model": "m"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "authentication_failed"
    assert "sk-LEAK" not in r.text and "sk-SECRET" not in r.text


def test_unknown_provider_400_and_missing_model_400(client):
    assert client.post("/api/ai/models",
                       json={"provider": "groq"}).status_code == 400
    assert client.post("/api/ai/test",
                       json={"provider": "openai", "model": ""}).status_code == 400


def test_concurrent_probe_gets_409_without_network(client, monkeypatch):
    CountingTransport.calls = 0
    monkeypatch.setattr("auditor.ai.transport.RequestsTransport",
                        CountingTransport)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-1")
    assert app_mod._AI_PROBE_LOCK.acquire(blocking=False)   # simulate in-flight
    try:
        r = client.post("/api/ai/models", json={"provider": "openai"})
        assert r.status_code == 409
        assert CountingTransport.calls == 0                 # no outbound call
        r2 = client.post("/api/ai/test", json={"provider": "openai",
                                               "model": "m"})
        assert r2.status_code == 409
    finally:
        app_mod._AI_PROBE_LOCK.release()
    # released → works again
    r3 = client.post("/api/ai/models", json={"provider": "openai"})
    assert r3.status_code == 200


def test_ai_endpoints_never_touch_report_or_sidecar(client, tmp_path,
                                                    monkeypatch):
    monkeypatch.setattr("auditor.ai.transport.RequestsTransport",
                        CountingTransport)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-1")
    before = client.get("/api/report").json()
    client.post("/api/ai/models", json={"provider": "openai"})
    client.post("/api/ai/test", json={"provider": "openai", "model": "m1"})
    assert client.get("/api/report").json() == before
    assert client.get("/api/reviews").json()["reviews"] == {}


# ---- CLI ----------------------------------------------------------------------

def test_cli_providers_is_local_and_lists_five(capsys, monkeypatch):
    CountingTransport.calls = 0
    monkeypatch.setattr("auditor.ai.transport.RequestsTransport",
                        CountingTransport)
    assert main(["ai", "providers"]) == 0
    out = capsys.readouterr().out
    for pid in ("openai", "anthropic", "xai", "ollama", "openai_compatible"):
        assert pid in out
    assert "xAI (Grok)" in out
    assert CountingTransport.calls == 0
    assert "groq " not in out.lower()


def test_cli_models_and_test_success(capsys, monkeypatch):
    class T:
        def request(self, method, url, headers, json_body, timeout):
            if url.endswith("/v1/models"):
                return HttpResponse(200, b'{"data": [{"id": "m1"}]}')
            return HttpResponse(200, b'{"output_text": "OK"}')

    monkeypatch.setattr("auditor.ai.transport.RequestsTransport", T)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-SECRET-7")
    assert main(["ai", "models", "--provider", "openai"]) == 0
    out = capsys.readouterr().out
    assert "m1" in out and "sk-SECRET" not in out
    assert main(["ai", "test", "--provider", "openai", "--model", "m1"]) == 0
    out = capsys.readouterr().out
    assert "ok:" in out and "no code or findings were sent" in out
    assert "sk-SECRET" not in out and "api.openai.com" not in out


def test_cli_failures_are_safe_and_nonzero(capsys, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert main(["ai", "models", "--provider", "openai"]) == 1
    err = capsys.readouterr().err
    assert "not configured" in err
    assert main(["ai", "test", "--provider", "nope", "--model", "m"]) == 2
    assert "unknown provider" in capsys.readouterr().err

    class T:
        def request(self, method, url, headers, json_body, timeout):
            return HttpResponse(401, b'{"error": "sk-LEAK C:\\\\Users\\\\x"}')

    monkeypatch.setattr("auditor.ai.transport.RequestsTransport", T)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-1")
    assert main(["ai", "test", "--provider", "openai", "--model", "m"]) == 1
    err = capsys.readouterr().err
    assert "authentication" in err
    assert "sk-LEAK" not in err and "C:\\Users" not in err and "Traceback" not in err


def test_cli_test_requires_a_model(capsys, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-1")
    monkeypatch.delenv("AUDITOR_AI_MODEL", raising=False)
    assert main(["ai", "test", "--provider", "openai"]) == 2
    assert "no model given" in capsys.readouterr().err
