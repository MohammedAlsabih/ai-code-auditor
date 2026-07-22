"""Provider specs + the ONE spec-driven client (W3-A).

Per-provider knowledge lives in a declarative `ProviderSpec` row — request
shapes, endpoints, auth style, parsers. `AIClient` is the single engine that
executes any spec; there are deliberately no per-provider client classes and
no scattered `if provider == ...` conditions outside this table.

Endpoints for OpenAI / Anthropic / xAI are PINNED — not configurable from
env, a request, or the browser. Only Ollama and openai_compatible take a
base URL, and only from the SERVER's environment, validated by
validate_base_url. Secrets come from the environment only.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Any, Callable

from auditor.ai.contract import (
    PROBE_MAX_TOKENS,
    PROBE_PROMPT,
    AIError,
    ConnectionResult,
    HttpTransport,
    ModelInfo,
    Provider,
    ProviderConfig,
    SAFE_MESSAGES,
    TransportFailure,
    sanitize_model_ids,
    validate_base_url,
)

_CHAT_MESSAGES = [{"role": "user", "content": PROBE_PROMPT}]


def _openai_style_probe(model: str) -> dict[str, Any]:
    # OpenAI + xAI Responses API: fixed prompt, hard output cap, no storage,
    # and NO tools / files / web search fields at all.
    return {"model": model, "input": PROBE_PROMPT,
            "max_output_tokens": PROBE_MAX_TOKENS, "store": False}


def _anthropic_probe(model: str) -> dict[str, Any]:
    return {"model": model, "max_tokens": PROBE_MAX_TOKENS,
            "messages": _CHAT_MESSAGES}


def _ollama_probe(model: str) -> dict[str, Any]:
    return {"model": model, "messages": _CHAT_MESSAGES, "stream": False}


def _compat_probe(model: str) -> dict[str, Any]:
    # plain Chat Completions with REQUIRED fields only — no optional fields
    # that a compatible server might not implement (and no Responses API).
    return {"model": model, "messages": _CHAT_MESSAGES,
            "max_tokens": PROBE_MAX_TOKENS}


def _parse_data_ids(data: Any) -> list[Any]:
    """{"data": [{"id": ...}]} — OpenAI / xAI / Anthropic / compatible.
    Entries are UNTRUSTED (may be None/junk); sanitize_model_ids filters."""
    if not isinstance(data, dict) or not isinstance(data.get("data"), list):
        raise AIError("invalid_response")
    return [m.get("id") for m in data["data"] if isinstance(m, dict)]


def _parse_ollama_tags(data: Any) -> list[Any]:
    """GET /api/tags — {"models": [{"name": ...}]}."""
    if not isinstance(data, dict) or not isinstance(data.get("models"), list):
        raise AIError("invalid_response")
    return [m.get("name") or m.get("model")
            for m in data["models"] if isinstance(m, dict)]


def _text_openai_responses(data: Any) -> str:
    if not isinstance(data, dict):
        return ""
    text = data.get("output_text")
    if isinstance(text, str) and text.strip():
        return text
    for item in data.get("output") or []:
        if isinstance(item, dict) and item.get("type") == "message":
            for part in item.get("content") or []:
                if isinstance(part, dict) \
                        and isinstance(part.get("text"), str) \
                        and part["text"].strip():
                    return part["text"]
    return ""


def _text_anthropic(data: Any) -> str:
    if isinstance(data, dict):
        content = data.get("content")
        if isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str) \
                        and part["text"].strip():
                    return part["text"]
    return ""


def _text_ollama(data: Any) -> str:
    if isinstance(data, dict) and isinstance(data.get("message"), dict):
        text = data["message"].get("content")
        if isinstance(text, str) and text.strip():
            return text
    return ""


def _text_chat_completions(data: Any) -> str:
    if isinstance(data, dict) and isinstance(data.get("choices"), list) \
            and data["choices"]:
        first = data["choices"][0]
        if isinstance(first, dict) and isinstance(first.get("message"), dict):
            text = first["message"].get("content")
            if isinstance(text, str) and text.strip():
                return text
    return ""


@dataclass(frozen=True)
class ProviderSpec:
    provider: Provider
    display: str
    key_env: str | None          # environment variable carrying the secret
    key_required: bool
    fixed_base: str | None       # pinned official endpoint (None = env-based)
    base_env: str | None         # ollama / openai_compatible only
    default_base: str | None
    auth_style: str              # "bearer" | "anthropic" | "none"
    models_path: str
    probe_path: str
    probe_body: Callable[[str], dict[str, Any]]
    parse_models: Callable[[Any], list[Any]]
    parse_probe_text: Callable[[Any], str]


PROVIDER_SPECS: dict[Provider, ProviderSpec] = {s.provider: s for s in (
    ProviderSpec(Provider.OPENAI, "OpenAI", "OPENAI_API_KEY", True,
                 "https://api.openai.com", None, None, "bearer",
                 "/v1/models", "/v1/responses",
                 _openai_style_probe, _parse_data_ids, _text_openai_responses),
    ProviderSpec(Provider.ANTHROPIC, "Anthropic (Claude)", "ANTHROPIC_API_KEY",
                 True, "https://api.anthropic.com", None, None, "anthropic",
                 "/v1/models", "/v1/messages",
                 _anthropic_probe, _parse_data_ids, _text_anthropic),
    ProviderSpec(Provider.XAI, "xAI (Grok)", "XAI_API_KEY", True,
                 "https://api.x.ai", None, None, "bearer",
                 "/v1/models", "/v1/responses",
                 _openai_style_probe, _parse_data_ids, _text_openai_responses),
    ProviderSpec(Provider.OLLAMA, "Ollama", None, False,
                 None, "OLLAMA_HOST", "http://127.0.0.1:11434", "none",
                 "/api/tags", "/api/chat",
                 _ollama_probe, _parse_ollama_tags, _text_ollama),
    ProviderSpec(Provider.OPENAI_COMPATIBLE, "OpenAI-compatible",
                 "AUDITOR_OPENAI_COMPAT_API_KEY", False,
                 None, "AUDITOR_OPENAI_COMPAT_BASE_URL", None, "bearer",
                 "/v1/models", "/v1/chat/completions",
                 _compat_probe, _parse_data_ids, _text_chat_completions),
)}

ANTHROPIC_VERSION = "2023-06-01"


def resolve_config(provider: Provider,
                   env: dict[str, str] | None = None) -> ProviderConfig:
    """Resolve a provider's runtime config from the environment ONLY (an
    explicit mapping is accepted for tests). Missing base URL for a provider
    that needs one raises not_configured; a missing API KEY does not raise
    here — it blocks at request time so `providers` can still report
    configured=false without a network call."""
    e = os.environ if env is None else env
    spec = PROVIDER_SPECS[provider]
    if spec.fixed_base is not None:
        base = spec.fixed_base
    else:
        raw = (e.get(spec.base_env or "") or spec.default_base or "").strip()
        # Ollama convention allows bare host:port — normalize before the gate
        if raw and "://" not in raw and provider is Provider.OLLAMA:
            raw = "http://" + raw
        base = validate_base_url(raw)   # raises not_configured when empty/bad
    key = e.get(spec.key_env) if spec.key_env else None
    return ProviderConfig(provider=provider, base_url=base,
                          api_key=(key or None),
                          model=(e.get("AUDITOR_AI_MODEL") or None))


class AIClient:
    """The single engine. `transport` is injectable; the default is the
    hardened RequestsTransport."""

    def __init__(self, spec: ProviderSpec, config: ProviderConfig,
                 transport: HttpTransport) -> None:
        self.spec = spec
        self.config = config
        self._transport = transport

    # ---- request plumbing ----------------------------------------------------
    def _headers(self) -> dict[str, str]:
        h = {"content-type": "application/json"}
        if self.spec.auth_style == "anthropic":
            h["x-api-key"] = self.config.api_key or ""
            h["anthropic-version"] = ANTHROPIC_VERSION
        elif self.spec.auth_style == "bearer" and self.config.api_key:
            h["authorization"] = f"Bearer {self.config.api_key}"
        return h

    def _require_key(self) -> None:
        if self.spec.key_required and not self.config.api_key:
            raise AIError("not_configured")

    def _call(self, method: str, path: str,
              body: dict[str, Any] | None, probe: bool) -> Any:
        """One request → parsed JSON, or AIError with a legal code. All
        provider/transport details die here."""
        self._require_key()
        try:
            resp = self._transport.request(
                method, self.config.base_url + path, self._headers(), body,
                self.config.timeout)
        except TransportFailure as e:
            raise AIError(e.code) from None    # original chain dropped on purpose
        s = resp.status
        if s in (401, 403):
            raise AIError("authentication_failed")
        if s == 429:
            raise AIError("rate_limited")
        if s == 404:
            # a missing MODEL on the probe endpoint; on the models endpoint a
            # 404 means the server shape is wrong, not a missing model
            raise AIError("model_not_found" if probe else "invalid_response")
        if 300 <= s < 400:
            raise AIError("invalid_response")  # redirects are never followed
        if s >= 500:
            raise AIError("invalid_response")
        try:
            data = json.loads(resp.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise AIError("invalid_response") from None
        if s != 200:
            # remaining 4xx: a PROVEN model error maps to model_not_found;
            # anything else is invalid_response. Only the provider's own
            # error/type/code fields are consulted — never echoed.
            if probe and _looks_like_model_error(data):
                raise AIError("model_not_found")
            raise AIError("invalid_response")
        return data

    # ---- the unified interface -----------------------------------------------
    def list_models(self) -> list[ModelInfo]:
        data = self._call("GET", self.spec.models_path, None, probe=False)
        ids = sanitize_model_ids(self.spec.parse_models(data))
        return [ModelInfo(id=i) for i in ids]   # an empty list is legal

    def test_connection(self, model: str) -> ConnectionResult:
        """Send the FIXED probe. Success = a legal response carrying any
        non-empty text (never required to literally be 'OK'); the text itself
        is discarded — callers get ok/latency only. No retries, no streaming,
        no tools."""
        if not model or not isinstance(model, str):
            return ConnectionResult(False, "model_not_found",
                                    SAFE_MESSAGES["model_not_found"])
        started = time.perf_counter()
        try:
            data = self._call("POST", self.spec.probe_path,
                              self.spec.probe_body(model), probe=True)
        except AIError as e:
            return ConnectionResult(False, e.code, SAFE_MESSAGES[e.code])
        latency = int((time.perf_counter() - started) * 1000)
        if not self.spec.parse_probe_text(data).strip():
            return ConnectionResult(False, "invalid_response",
                                    SAFE_MESSAGES["invalid_response"])
        return ConnectionResult(True, "ok", "connection ok", latency_ms=latency)


def _looks_like_model_error(data: Any) -> bool:
    """True only when the provider's structured error clearly names a model
    problem (OpenAI: error.code == 'model_not_found'; generic: the error
    message mentions the word 'model'). Checked, never echoed."""
    if not isinstance(data, dict):
        return False
    err = data.get("error")
    if isinstance(err, dict):
        code = err.get("code") or err.get("type") or ""
        msg = err.get("message") or ""
        if isinstance(code, str) and "model" in code.lower():
            return True
        if isinstance(msg, str) and "model" in msg.lower():
            return True
    elif isinstance(err, str) and "model" in err.lower():
        return True
    return False


def create_client(provider: Provider,
                  transport: HttpTransport | None = None,
                  env: dict[str, str] | None = None) -> AIClient:
    """The ONE factory. Raises AIError('not_configured') when the provider
    needs a base URL and none is configured."""
    if transport is None:
        from auditor.ai.transport import RequestsTransport
        transport = RequestsTransport()
    return AIClient(PROVIDER_SPECS[provider], resolve_config(provider, env),
                    transport)


def provider_metadata(env: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """Safe, LOCAL-ONLY metadata for every provider — used by `auditor ai
    providers` and GET /api/ai/providers. Performs no network I/O and never
    includes the base URL, only local/remote + configured booleans."""
    out: list[dict[str, Any]] = []
    for spec in PROVIDER_SPECS.values():
        key_present = False
        configured = True
        locality = "remote"
        try:
            cfg = resolve_config(spec.provider, env)
            key_present = cfg.key_present
            locality = cfg.locality
            if spec.key_required and not key_present:
                configured = False
        except AIError:
            configured = False                 # base URL missing/invalid
            if spec.provider is Provider.OPENAI_COMPATIBLE:
                locality = "remote"
        out.append({
            "provider": spec.provider.value,
            "display": spec.display,
            "configured": configured,
            "key_present": key_present,
            "key_env": spec.key_env,
            "locality": locality,
        })
    return out
