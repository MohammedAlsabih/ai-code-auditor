"""W3-A: the unified AI provider layer — request contracts per provider,
error mapping, secrecy, and bounded/hardened transport behavior. Everything
runs against a fake transport; no test touches the network."""
import json

import pytest

from auditor.ai import (
    ERROR_CODES,
    PROBE_PROMPT,
    AIError,
    Provider,
    create_client,
)
from auditor.ai.contract import (
    MODEL_ID_MAX_CHARS,
    HttpResponse,
    TransportFailure,
    sanitize_model_ids,
    validate_base_url,
)
from auditor.ai.providers import ANTHROPIC_VERSION, PROVIDER_SPECS

# assembled from parts so secret scanners never flag a "hardcoded key"
# (publish hygiene) — the value itself is synthetic
SECRET = "sk-" + "SECRET-KEY-" + "abc123"
ENV_ALL = {
    "OPENAI_API_KEY": SECRET,
    "ANTHROPIC_API_KEY": SECRET,
    "XAI_API_KEY": SECRET,
    "AUDITOR_OPENAI_COMPAT_API_KEY": SECRET,
    "AUDITOR_OPENAI_COMPAT_BASE_URL": "https://llm.internal.example",
}


class FakeTransport:
    """Records every request; replies from a queue (default: a canned OK)."""

    def __init__(self, *replies):
        self.calls: list[dict] = []
        self.replies = list(replies)

    def request(self, method, url, headers, json_body, timeout):
        self.calls.append({"method": method, "url": url, "headers": headers,
                           "body": json_body, "timeout": timeout})
        if not self.replies:
            return HttpResponse(200, b"{}")
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


def ok(payload) -> HttpResponse:
    return HttpResponse(200, json.dumps(payload).encode())


PROBE_OK = {
    Provider.OPENAI: {"output_text": "OK"},
    Provider.XAI: {"output": [{"type": "message",
                               "content": [{"type": "output_text", "text": "OK"}]}]},
    Provider.ANTHROPIC: {"content": [{"type": "text", "text": "OK"}]},
    Provider.OLLAMA: {"message": {"role": "assistant", "content": "OK"}},
    Provider.OPENAI_COMPATIBLE: {"choices": [{"message": {"content": "OK"}}]},
}
MODELS_OK = {
    Provider.OPENAI: {"data": [{"id": "gpt-x"}, {"id": "gpt-a"}]},
    Provider.XAI: {"data": [{"id": "grok-b"}, {"id": "grok-a"}]},
    Provider.ANTHROPIC: {"data": [{"id": "claude-z"}, {"id": "claude-a"}]},
    Provider.OLLAMA: {"models": [{"name": "llama-b"}, {"name": "llama-a"}]},
    Provider.OPENAI_COMPATIBLE: {"data": [{"id": "m2"}, {"id": "m1"}]},
}

ALL_PROVIDERS = list(Provider)


# ---- per-provider request contracts -----------------------------------------

@pytest.mark.parametrize("provider,path,auth_header", [
    (Provider.OPENAI, "https://api.openai.com/v1/models", "authorization"),
    (Provider.ANTHROPIC, "https://api.anthropic.com/v1/models", "x-api-key"),
    (Provider.XAI, "https://api.x.ai/v1/models", "authorization"),
    (Provider.OLLAMA, "http://127.0.0.1:11434/api/tags", None),
    (Provider.OPENAI_COMPATIBLE, "https://llm.internal.example/v1/models",
     "authorization"),
])
def test_models_endpoint_and_auth(provider, path, auth_header):
    t = FakeTransport(ok(MODELS_OK[provider]))
    client = create_client(provider, transport=t, env=ENV_ALL)
    models = client.list_models()
    call = t.calls[0]
    assert call["method"] == "GET" and call["url"] == path
    if auth_header == "authorization":
        assert call["headers"]["authorization"] == f"Bearer {SECRET}"
    elif auth_header == "x-api-key":
        assert call["headers"]["x-api-key"] == SECRET
        assert call["headers"]["anthropic-version"] == ANTHROPIC_VERSION
    else:
        assert "authorization" not in call["headers"]
    assert [m.id for m in models] == sorted(m.id for m in models)  # sorted


@pytest.mark.parametrize("provider,path", [
    (Provider.OPENAI, "https://api.openai.com/v1/responses"),
    (Provider.ANTHROPIC, "https://api.anthropic.com/v1/messages"),
    (Provider.XAI, "https://api.x.ai/v1/responses"),
    (Provider.OLLAMA, "http://127.0.0.1:11434/api/chat"),
    (Provider.OPENAI_COMPATIBLE, "https://llm.internal.example/v1/chat/completions"),
])
def test_probe_endpoint_body_and_caps(provider, path):
    t = FakeTransport(ok(PROBE_OK[provider]))
    client = create_client(provider, transport=t, env=ENV_ALL)
    result = client.test_connection("m1")
    assert result.ok and result.status == "ok" and result.latency_ms is not None
    call = t.calls[0]
    assert call["method"] == "POST" and call["url"] == path
    body = call["body"]
    assert body["model"] == "m1"
    # the fixed probe and the hard 8-token cap
    if provider in (Provider.OPENAI, Provider.XAI):
        assert body["input"] == PROBE_PROMPT
        assert body["max_output_tokens"] == 8
        assert body["store"] is False                    # store=false REQUIRED
        assert "tools" not in body and "messages" not in body
    elif provider is Provider.ANTHROPIC:
        assert body["messages"] == [{"role": "user", "content": PROBE_PROMPT}]
        assert body["max_tokens"] == 8
        assert "tools" not in body
    elif provider is Provider.OLLAMA:
        assert body["messages"][0]["content"] == PROBE_PROMPT
        assert body["stream"] is False
    else:
        assert body["messages"][0]["content"] == PROBE_PROMPT
        assert body["max_tokens"] == 8
        # NOTHING optional a compatible server might reject
        assert set(body) == {"model", "messages", "max_tokens"}
    # the model's reply text is never surfaced
    assert "OK" not in result.message


@pytest.mark.parametrize("provider", ALL_PROVIDERS)
def test_no_findings_snippets_or_source_paths_in_requests(provider):
    t = FakeTransport(ok(PROBE_OK[provider]))
    client = create_client(provider, transport=t, env=ENV_ALL)
    client.test_connection("m1")
    wire = json.dumps(t.calls, default=str)
    for needle in ("finding", "snippet", "report", "rule_id", "C:\\", "/home/",
                   "src/", ".py"):
        assert needle not in wire.replace("sk-SECRET", ""), needle
    assert PROBE_PROMPT in wire                     # the ONLY content sent


def test_xai_never_uses_chat_completions_and_pins_no_model():
    spec = PROVIDER_SPECS[Provider.XAI]
    assert spec.probe_path == "/v1/responses"
    assert "chat/completions" not in spec.probe_path
    import inspect

    import auditor.ai.providers as mod
    src = inspect.getsource(mod)
    assert "grok-" not in src                       # no hardcoded Grok model


# ---- configuration / secrecy --------------------------------------------------

@pytest.mark.parametrize("provider", [Provider.OPENAI, Provider.ANTHROPIC,
                                      Provider.XAI])
def test_missing_key_blocks_before_any_network(provider):
    t = FakeTransport()
    client = create_client(provider, transport=t, env={})
    with pytest.raises(AIError) as ei:
        client.list_models()
    assert ei.value.code == "not_configured"
    assert t.calls == []                            # zero outbound traffic
    r = client.test_connection("m")
    assert r.status == "not_configured" and t.calls == []


def test_compat_without_base_url_is_not_configured_no_echo():
    with pytest.raises(AIError) as ei:
        create_client(Provider.OPENAI_COMPATIBLE, transport=FakeTransport(),
                      env={"AUDITOR_OPENAI_COMPAT_BASE_URL": ""})
    assert ei.value.code == "not_configured"


def test_ollama_needs_no_key_and_defaults_local():
    t = FakeTransport(ok(MODELS_OK[Provider.OLLAMA]))
    client = create_client(Provider.OLLAMA, transport=t, env={})
    assert client.config.locality == "local"
    client.list_models()                            # no key, still allowed
    assert "authorization" not in t.calls[0]["headers"]


@pytest.mark.parametrize("bad", [
    "ftp://x.example", "https://user:pw@x.example", "https://x.example?q=1",
    "https://x.example#frag", "not a url", "file:///etc/passwd",
])
def test_base_url_gate(bad):
    with pytest.raises(AIError) as ei:
        validate_base_url(bad)
    assert ei.value.code == "not_configured"
    assert bad not in str(ei.value)                 # value never echoed


def test_official_endpoints_are_pinned():
    assert PROVIDER_SPECS[Provider.OPENAI].fixed_base == "https://api.openai.com"
    assert PROVIDER_SPECS[Provider.ANTHROPIC].fixed_base == "https://api.anthropic.com"
    assert PROVIDER_SPECS[Provider.XAI].fixed_base == "https://api.x.ai"
    # env base URLs exist ONLY for ollama + compatible
    assert PROVIDER_SPECS[Provider.OLLAMA].base_env == "OLLAMA_HOST"
    assert PROVIDER_SPECS[Provider.OPENAI_COMPATIBLE].base_env == \
        "AUDITOR_OPENAI_COMPAT_BASE_URL"


# ---- error mapping --------------------------------------------------------------

@pytest.mark.parametrize("status,code", [(401, "authentication_failed"),
                                         (403, "authentication_failed"),
                                         (429, "rate_limited"),
                                         (500, "invalid_response"),
                                         (503, "invalid_response")])
def test_status_mapping(status, code):
    t = FakeTransport(HttpResponse(status, b"{}"))
    client = create_client(Provider.OPENAI, transport=t, env=ENV_ALL)
    r = client.test_connection("m")
    assert r.status == code and not r.ok


def test_probe_404_and_proven_model_error_map_to_model_not_found():
    t = FakeTransport(HttpResponse(404, b"{}"))
    client = create_client(Provider.OPENAI, transport=t, env=ENV_ALL)
    assert client.test_connection("m").status == "model_not_found"
    t2 = FakeTransport(HttpResponse(
        400, json.dumps({"error": {"code": "model_not_found",
                                   "message": "The model does not exist"}}).encode()))
    client2 = create_client(Provider.OPENAI, transport=t2, env=ENV_ALL)
    assert client2.test_connection("m").status == "model_not_found"
    # an UNPROVEN 400 is invalid_response, never guessed as a model error
    t3 = FakeTransport(HttpResponse(400, json.dumps(
        {"error": {"code": "bad_request", "message": "nope"}}).encode()))
    client3 = create_client(Provider.OPENAI, transport=t3, env=ENV_ALL)
    assert client3.test_connection("m").status == "invalid_response"


def test_timeout_and_network_failures():
    t = FakeTransport(TransportFailure("timeout"))
    client = create_client(Provider.OPENAI, transport=t, env=ENV_ALL)
    assert client.test_connection("m").status == "timeout"
    t2 = FakeTransport(TransportFailure("connection_failed"))
    client2 = create_client(Provider.OPENAI, transport=t2, env=ENV_ALL)
    assert client2.test_connection("m").status == "connection_failed"


def test_malformed_json_and_unexpected_schema_are_invalid_response():
    t = FakeTransport(HttpResponse(200, b"not json"))
    client = create_client(Provider.OPENAI, transport=t, env=ENV_ALL)
    assert client.test_connection("m").status == "invalid_response"
    t2 = FakeTransport(ok({"unexpected": "shape"}))
    client2 = create_client(Provider.OPENAI, transport=t2, env=ENV_ALL)
    assert client2.test_connection("m").status == "invalid_response"
    t3 = FakeTransport(ok({"nope": []}))
    client3 = create_client(Provider.OPENAI, transport=t3, env=ENV_ALL)
    with pytest.raises(AIError) as ei:
        client3.list_models()
    assert ei.value.code == "invalid_response"


def test_redirects_are_rejected_not_followed():
    # the transport never follows redirects; a 3xx surfaces as
    # invalid_response and NO second request is made (Authorization is
    # therefore never re-sent anywhere)
    t = FakeTransport(HttpResponse(302, b""))
    client = create_client(Provider.OPENAI, transport=t, env=ENV_ALL)
    r = client.test_connection("m")
    assert r.status == "invalid_response"
    assert len(t.calls) == 1


def test_secret_and_paths_never_leak_from_errors():
    hostile = json.dumps({"error": {"message":
                                    f"boom {SECRET} at C:\\Users\\x\\y"}}).encode()
    for status in (400, 401, 429, 500):
        t = FakeTransport(HttpResponse(status, hostile))
        client = create_client(Provider.OPENAI, transport=t, env=ENV_ALL)
        r = client.test_connection("m")
        assert SECRET not in r.message and "C:\\" not in r.message
        assert r.status in ERROR_CODES


def test_oversize_response_is_rejected_bounded():
    # the REAL transport enforces the cap with a bounded read; here we assert
    # the failure surfaces as invalid_response through the client
    t = FakeTransport(TransportFailure("invalid_response"))
    client = create_client(Provider.OPENAI, transport=t, env=ENV_ALL)
    assert client.test_connection("m").status == "invalid_response"


def test_real_transport_bounded_read_and_no_redirects(monkeypatch):
    """The requests-based transport: stream read of cap+1 only, oversize →
    invalid_response, allow_redirects=False always."""
    import auditor.ai.transport as tr

    captured = {}

    class FakeRaw:
        def __init__(self, size):
            self._data = b"x" * size

        def read(self, n, decode_content=True):
            captured["read_n"] = n
            return self._data[:n]

    class FakeResp:
        status_code = 200

        def __init__(self, size):
            self.raw = FakeRaw(size)

        def close(self):
            pass

    monkeypatch.setattr(tr.requests, "request",
                        lambda method, url, **kw: (captured.update(kw),
                                                   FakeResp(10))[1])
    t = tr.RequestsTransport(max_response_bytes=64)
    resp = t.request("GET", "https://x.example", {}, None, 5.0)
    assert resp.status == 200
    assert captured["allow_redirects"] is False
    assert captured["stream"] is True
    assert "verify" not in captured               # TLS default (ON), never disabled
    assert captured["read_n"] == 65               # cap + 1, never -1
    monkeypatch.setattr(tr.requests, "request",
                        lambda method, url, **kw: FakeResp(100))
    with pytest.raises(TransportFailure) as ei:
        t.request("GET", "https://x.example", {}, None, 5.0)
    assert ei.value.code == "invalid_response"


# ---- model id hygiene ------------------------------------------------------------

def test_model_ids_sanitized_bounded_deduped_sorted():
    raw = ["b", "a", "b", "  c  ", "", "bad\x00ctl", "x" * (MODEL_ID_MAX_CHARS + 1),
           123, None, "ok\ttab"]
    assert sanitize_model_ids(raw) == ["a", "b", "c"]  # type: ignore[arg-type]


def test_empty_model_list_is_legal():
    t = FakeTransport(ok({"data": []}))
    client = create_client(Provider.OPENAI, transport=t, env=ENV_ALL)
    assert client.list_models() == []


# ---- layer independence ------------------------------------------------------------

def test_ai_layer_is_independent_of_report_schema():
    import auditor.ai.contract as c
    import auditor.ai.providers as p
    import auditor.ai.transport as t
    import inspect
    for mod in (c, p, t):
        src = inspect.getsource(mod)
        for forbidden in ("auditor.report", "auditor.core.scoring",
                          "auditor.core.baseline", "review_id", "fingerprint",
                          "verdict"):
            assert forbidden not in src, (mod.__name__, forbidden)


def test_groq_is_not_a_provider_anywhere():
    assert [p.value for p in Provider] == [
        "openai", "anthropic", "xai", "ollama", "openai_compatible"]
    import inspect

    import auditor.ai.contract
    import auditor.ai.providers
    import auditor.ai.transport
    import auditor.cli
    import auditor.web.app
    for mod in (auditor.ai.contract, auditor.ai.providers,
                auditor.ai.transport, auditor.cli, auditor.web.app):
        assert "groq" not in inspect.getsource(mod).lower(), mod.__name__
