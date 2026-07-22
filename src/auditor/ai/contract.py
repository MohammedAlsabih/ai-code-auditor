"""The unified AI-provider contract (W3-A).

One contract for every provider — no per-provider special cases leak out of
this package:

- `Provider`: the five legal identifiers.
- `ProviderConfig`: resolved, validated runtime configuration (secrets come
  from the environment ONLY; they live in this in-memory object and are
  never serialized, logged, or echoed).
- `ModelInfo` / `ConnectionResult`: the only shapes callers see.
- `AIError`: carries exactly one LEGAL error code and a FIXED safe message.
  Raw exceptions, response bodies, headers, API keys, base URLs, and machine
  paths never leave this layer.
- `HttpTransport`: the injectable HTTP seam — tests run against a fake, the
  real one (transport.py) enforces TLS verification, no redirects, bounded
  reads, and a hard timeout.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol
from urllib.parse import urlsplit


class Provider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    XAI = "xai"
    OLLAMA = "ollama"
    OPENAI_COMPATIBLE = "openai_compatible"


# the ONLY legal error codes. Anything a provider does maps onto one of
# these; there is no "other".
ERROR_CODES = (
    "not_configured",
    "authentication_failed",
    "model_not_found",
    "rate_limited",
    "timeout",
    "connection_failed",
    "invalid_response",
)

# FIXED safe messages — never interpolated with response/exception content.
SAFE_MESSAGES = {
    "not_configured": "provider is not configured (missing API key or base URL)",
    "authentication_failed": "authentication failed — the provider rejected the key",
    "model_not_found": "the requested model was not found on the provider",
    "rate_limited": "the provider rate-limited the request — try again later",
    "timeout": "the request timed out",
    "connection_failed": "could not connect to the provider",
    "invalid_response": "the provider returned an unexpected or oversized response",
}

# the connection probe is a FIXED string: no report, no finding, no snippet,
# no source path — ever. Its output is capped at 8 tokens and the model's
# reply text is never shown to the user.
PROBE_PROMPT = "Reply with OK only."
PROBE_MAX_TOKENS = 8

REQUEST_TIMEOUT_SECONDS = 20.0
# bounded response read: a model list or an 8-token probe reply is tiny;
# anything above this cap is rejected as invalid_response, never slurped.
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MODEL_ID_MAX_CHARS = 128


class AIError(Exception):
    """One legal code + its fixed safe message. `str(err)` is always safe to
    print and to send to a browser."""

    def __init__(self, code: str) -> None:
        if code not in ERROR_CODES:
            raise ValueError(f"illegal AI error code: {code!r}")
        self.code = code
        super().__init__(SAFE_MESSAGES[code])


@dataclass(frozen=True)
class ProviderConfig:
    provider: Provider
    base_url: str                 # validated; NEVER shown in full to callers
    api_key: str | None = None    # in-memory only
    model: str | None = None      # default model (AUDITOR_AI_MODEL)
    timeout: float = REQUEST_TIMEOUT_SECONDS

    @property
    def key_present(self) -> bool:
        return bool(self.api_key)

    @property
    def locality(self) -> str:
        """'local' or 'remote' — the ONLY location detail ever exposed."""
        host = urlsplit(self.base_url).hostname or ""
        return "local" if host in ("127.0.0.1", "localhost", "::1") else "remote"


@dataclass(frozen=True)
class ModelInfo:
    id: str
    display: str = ""


@dataclass(frozen=True)
class ConnectionResult:
    ok: bool
    status: str                   # "ok" or one of ERROR_CODES
    message: str                  # fixed safe message; never the model's reply
    latency_ms: int | None = None


@dataclass(frozen=True)
class HttpResponse:
    """What a transport returns: status + a BOUNDED body. Transports never
    follow redirects; a 3xx lands here as-is and is rejected upstream."""
    status: int
    body: bytes


class TransportFailure(Exception):
    """Internal transport-level failure with a legal code (timeout /
    connection_failed / invalid_response for oversized bodies). The original
    exception is deliberately not carried — nothing unsafe can propagate."""

    def __init__(self, code: str) -> None:
        assert code in ("timeout", "connection_failed", "invalid_response")
        self.code = code
        super().__init__(SAFE_MESSAGES[code])


class HttpTransport(Protocol):
    def request(self, method: str, url: str, headers: dict[str, str],
                json_body: dict[str, Any] | None,
                timeout: float) -> HttpResponse: ...


def validate_base_url(url: str) -> str:
    """The gate every base URL passes BEFORE any request: http/https only, no
    credentials, no query/fragment, a real host. Returns the normalized URL
    (no trailing slash). Raises AIError('not_configured') — the offending
    value is never echoed (it may carry credentials or an internal host)."""
    url = (url or "").strip().rstrip("/")
    if not url:
        raise AIError("not_configured")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname \
            or parts.username or parts.password \
            or parts.query or parts.fragment:
        raise AIError("not_configured")
    return url


def sanitize_model_ids(raw_ids: list[Any]) -> list[str]:
    """Defensive normalization of provider-supplied model ids: strings only,
    trimmed, non-empty, no control characters, bounded length, deduplicated,
    sorted. A violating entry is dropped, never echoed."""
    out: set[str] = set()
    for rid in raw_ids:
        if not isinstance(rid, str):
            continue
        rid = rid.strip()
        if not rid or len(rid) > MODEL_ID_MAX_CHARS:
            continue
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in rid):
            continue
        out.add(rid)
    return sorted(out)
