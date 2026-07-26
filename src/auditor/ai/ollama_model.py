"""A Pydantic AI `Model` that speaks Ollama's NATIVE `/api/chat` endpoint.

WHY NOT the OpenAI-compatible route (`/v1/chat/completions`)
-----------------------------------------------------------
Verified against live Ollama 0.18.0 (qwen3:14b), the OpenAI-compatible shim:

* SILENTLY DROPS `options.num_ctx` — request 8192, `/api/ps` still reports
  `context_length: 4096`. No error, no warning; the model just truncates.
* IGNORES `think: false` — a reasoning model still burns the budget on a
  thinking channel.
* IGNORES `max_completion_tokens`, which is exactly what `OpenAIChatModel`
  emits for pydantic-ai's `ModelSettings.max_tokens`.

The native `/api/chat` endpoint honours all three: `options.num_ctx`
(`/api/ps` reports 8192), `think: false`, and `options.num_predict`.

THE WIRE BODY (fixed shape, mirrors `auditor.ai.review._review_body`)
---------------------------------------------------------------------
    {"model": <str>,
     "messages": [...],
     "stream": false,
     "think": false,
     "tools": [...],                        # ONLY when tools exist
     "options": {"temperature": 0, "num_predict": <int>, "num_ctx": <int>}}

Nothing else. No `keep_alive`. No `format` — when tools are on the wire the
structured output arrives as a `final_result` tool call, and Ollama would
otherwise grammar-constrain the whole reply to the schema and make the tool
call impossible.

TRANSPORT
---------
The constructor takes an INJECTED transport with the project's exact
signature `request(method, url, headers, json_body, timeout) -> HttpResponse`
(see `auditor.ai.transport.RequestsTransport` / `auditor.ai.contract`).
There is NO default: `transport=` is a required keyword argument, because the
project's transport is what enforces TLS verification, no-redirect, a hard
timeout, and a bounded cap+1 read. A model that quietly fell back to a bare
`requests.post` would silently drop every one of those guarantees.

`Model.request` is async and that transport is synchronous, so the call is
made through `asyncio.to_thread`.

This module is self-contained: it imports nothing from `auditor`. The
transport contract is expressed structurally (a `Protocol`), so the project's
`RequestsTransport` satisfies it by shape. A `TransportFailure` raised by the
project transport propagates unchanged — the integrator maps `.code` onto
`AIError` at the layer that owns that mapping.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

from pydantic_ai.exceptions import ModelHTTPError, UnexpectedModelBehavior, UserError
from pydantic_ai.messages import (
    FinishReason,
    ModelMessage,
    ModelRequest,
    ModelResponse,
    RetryPromptPart,
    SystemPromptPart,
    TextPart,
    ThinkingPart,
    ToolCallPart,
    ToolReturnPart,
    UserPromptPart,
)
from pydantic_ai.models import Model, ModelRequestParameters
from pydantic_ai.settings import ModelSettings
from pydantic_ai.tools import ToolDefinition
from pydantic_ai.usage import RequestUsage

__all__ = ("OllamaNativeModel", "HttpResponseLike", "HttpTransportLike")

DEFAULT_TIMEOUT_SECONDS = 300.0


# --------------------------------------------------------------------------
# transport seam (structural — the project's RequestsTransport satisfies it)
# --------------------------------------------------------------------------
@runtime_checkable
class HttpResponseLike(Protocol):
    """What a transport returns: a status and a BOUNDED body."""

    status: int
    body: bytes


class HttpTransportLike(Protocol):
    """`auditor.ai.contract.HttpTransport`, structurally."""

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        json_body: dict[str, Any] | None,
        timeout: float,
    ) -> HttpResponseLike: ...


# --------------------------------------------------------------------------
# the model
# --------------------------------------------------------------------------
@dataclass(init=False)
class OllamaNativeModel(Model):
    """A `pydantic_ai.models.Model` that POSTs to `<base_url>/api/chat`."""

    _model_name: str
    _base_url: str
    _transport: HttpTransportLike
    _num_ctx: int
    _num_predict: int
    _temperature: float
    _think: bool
    _timeout: float

    def __init__(
        self,
        model_name: str,
        *,
        transport: HttpTransportLike,
        base_url: str = "http://127.0.0.1:11434",
        num_ctx: int,
        num_predict: int,
        temperature: float = 0.0,
        think: bool = False,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        settings: ModelSettings | None = None,
        profile: Any = None,
    ) -> None:
        """Args:

        model_name: the Ollama tag, e.g. `"qwen3:14b"`.
        transport: REQUIRED. `request(method, url, headers, json_body,
            timeout) -> HttpResponse`. No default on purpose — the caller
            injects the transport that enforces TLS/no-redirect/bounded read.
        base_url: Ollama root; `/api/chat` is appended.
        num_ctx: server-side context window. Sent as `options.num_ctx` on
            EVERY request. Ollama applies it when the model is (re)loaded, so
            a model already resident at a different context keeps the old one
            until it is unloaded (POST /api/generate with `keep_alive: 0`).
        num_predict: default output cap; `ModelSettings.max_tokens` overrides
            it per request.
        temperature: default sampling temperature; `ModelSettings.temperature`
            overrides it per request.
        think: emitted as the top-level `think` key. `False` (the default)
            makes a reasoning model spend its budget on the answer.
        timeout: seconds, handed to the transport.
        """
        super().__init__(settings=settings, profile=profile)
        self._model_name = model_name
        self._base_url = base_url.rstrip("/")
        self._transport = transport
        self._num_ctx = num_ctx
        self._num_predict = num_predict
        self._temperature = temperature
        self._think = think
        self._timeout = timeout

    # ---- the three abstract members --------------------------------------
    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def system(self) -> str:
        return "ollama"

    async def request(
        self,
        messages: list[ModelMessage],
        model_settings: ModelSettings | None,
        model_request_parameters: ModelRequestParameters,
    ) -> ModelResponse:
        # Resolves output_mode 'auto' -> 'tool', merges self.settings, and
        # applies customize_request_parameters. Skipping it leaves
        # output_tools unresolved and structured output silently broken.
        model_settings, model_request_parameters = self.prepare_request(
            model_settings, model_request_parameters
        )
        body = self.build_body(messages, model_settings, model_request_parameters)
        data = await self._post(body)
        return self._process_response(data)

    # ---- base_url is a documented Model property --------------------------
    @property
    def base_url(self) -> str:
        return self._base_url

    # ---- wire body --------------------------------------------------------
    def build_body(
        self,
        messages: list[ModelMessage],
        model_settings: ModelSettings | None,
        model_request_parameters: ModelRequestParameters,
    ) -> dict[str, Any]:
        """The ONE request body. Public so a wire test can assert on it
        without a transport."""
        settings = model_settings or {}
        options: dict[str, Any] = {
            "temperature": settings.get("temperature", self._temperature),
            "num_predict": settings.get("max_tokens", self._num_predict),
            "num_ctx": self._num_ctx,
        }
        body: dict[str, Any] = {
            "model": self._model_name,
            "messages": self._map_messages(messages, model_request_parameters),
            "stream": False,
            "think": self._think,
        }
        tools = self._map_tools(model_request_parameters)
        if tools:                       # key omitted entirely when empty
            body["tools"] = tools
        body["options"] = options
        return body

    # ---- tools ------------------------------------------------------------
    def _map_tools(self, params: ModelRequestParameters) -> list[dict[str, Any]]:
        """function_tools + output_tools. The OUTPUT tool (`final_result`)
        MUST be on the wire — pydantic-ai delivers structured output as a
        tool call, so omitting it makes structured output impossible."""
        return [
            self._tool_def_to_ollama(td)
            for td in (*params.function_tools, *params.output_tools)
        ]

    @staticmethod
    def _tool_def_to_ollama(td: ToolDefinition) -> dict[str, Any]:
        fn: dict[str, Any] = {
            "name": td.name,
            "description": td.description or "",
            "parameters": td.parameters_json_schema,
        }
        return {"type": "function", "function": fn}

    # ---- messages ---------------------------------------------------------
    def _map_messages(
        self, messages: list[ModelMessage], params: ModelRequestParameters
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []

        # `Agent(instructions=...)` never lands in a SystemPromptPart; it
        # arrives via ModelRequestParameters.instruction_parts (or, for direct
        # model.request() callers, ModelRequest.instructions). Both are
        # resolved by the base class helper. They lead the conversation.
        if instruction_parts := self._get_instruction_parts(messages, params):
            text = "\n\n".join(p.content for p in instruction_parts if p.content)
            if text:
                out.append({"role": "system", "content": text})

        for message in messages:
            if isinstance(message, ModelRequest):
                out.extend(self._map_request(message))
            elif isinstance(message, ModelResponse):
                out.extend(self._map_response(message))
            else:  # pragma: no cover - the union has exactly two members
                raise UserError(f"unsupported ModelMessage: {type(message).__name__}")
        return out

    def _map_request(self, message: ModelRequest) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for part in message.parts:
            if isinstance(part, SystemPromptPart):
                out.append({"role": "system", "content": part.content})
            elif isinstance(part, UserPromptPart):
                out.append({"role": "user", "content": self._user_text(part)})
            elif isinstance(part, ToolReturnPart):
                # VERIFIED against Ollama 0.18.0: `content` must be a STRING,
                # `tool_name` is accepted (and is the documented native field);
                # extra keys are tolerated but we send only what the API
                # documents. There is no `tool_call_id` in the native schema.
                out.append(
                    {
                        "role": "tool",
                        "content": part.model_response_str(),
                        "tool_name": part.tool_name,
                    }
                )
            elif isinstance(part, RetryPromptPart):
                # A retry after a tool call goes back on the tool channel so
                # the model sees which call failed; a bare retry (e.g. plain
                # text where a structured output was required) is a user turn.
                if part.tool_name is None:
                    out.append({"role": "user", "content": part.model_response()})
                else:
                    out.append(
                        {
                            "role": "tool",
                            "content": part.model_response(),
                            "tool_name": part.tool_name,
                        }
                    )
            else:
                raise UserError(
                    f"{type(self).__name__} cannot send request part "
                    f"{type(part).__name__!r} to Ollama /api/chat"
                )
        return out

    @staticmethod
    def _user_text(part: UserPromptPart) -> str:
        content = part.content
        if isinstance(content, str):
            return content
        chunks: list[str] = []
        for item in content:
            if isinstance(item, str):
                chunks.append(item)
            else:
                # Images/audio/documents would need Ollama's `images` field
                # (base64) and are deliberately NOT guessed at here — a silent
                # drop would lose user content.
                raise UserError(
                    "OllamaNativeModel prototype supports text user content only; "
                    f"got {type(item).__name__}"
                )
        return "\n".join(chunks)

    def _map_response(self, message: ModelResponse) -> list[dict[str, Any]]:
        """One assistant message per ModelResponse: text joined into
        `content`, every ToolCallPart appended to `tool_calls`."""
        text: list[str] = []
        tool_calls: list[dict[str, Any]] = []
        for part in message.parts:
            if isinstance(part, TextPart):
                if part.content:
                    text.append(part.content)
            elif isinstance(part, ToolCallPart):
                tool_calls.append(
                    {
                        "function": {
                            "name": part.tool_name,
                            # VERIFIED: Ollama 0.18.0 REJECTS a JSON-string
                            # `arguments` with HTTP 400 ("Value looks like
                            # object, but can't find closing '}' symbol").
                            # It must be a real JSON object.
                            "arguments": _args_as_object(part.args),
                        }
                    }
                )
            elif isinstance(part, ThinkingPart):
                # think:false means we never asked for these; a ThinkingPart
                # carried over from another provider is dropped rather than
                # replayed as assistant text (it is not a real turn).
                continue
            else:
                raise UserError(
                    f"{type(self).__name__} cannot send response part "
                    f"{type(part).__name__!r} to Ollama /api/chat"
                )
        if not text and not tool_calls:
            return []
        msg: dict[str, Any] = {"role": "assistant", "content": "\n\n".join(text)}
        if tool_calls:
            msg["tool_calls"] = tool_calls
        return [msg]

    # ---- HTTP -------------------------------------------------------------
    async def _post(self, body: dict[str, Any]) -> dict[str, Any]:
        url = f"{self._base_url}/api/chat"
        headers = {"content-type": "application/json"}
        # The injected transport is SYNCHRONOUS; Model.request is async.
        resp = await asyncio.to_thread(
            self._transport.request, "POST", url, headers, body, self._timeout
        )
        if resp.status != 200:
            # `body=None`: the provider's raw body is never carried into the
            # exception message (the project forbids echoing response bodies).
            raise ModelHTTPError(status_code=resp.status, model_name=self._model_name)
        try:
            data = json.loads(resp.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise UnexpectedModelBehavior("Ollama returned a non-JSON body") from e
        if not isinstance(data, dict) or not isinstance(data.get("message"), dict):
            raise UnexpectedModelBehavior("Ollama response has no `message` object")
        return data

    # ---- response parsing --------------------------------------------------
    def _process_response(self, data: dict[str, Any]) -> ModelResponse:
        message: dict[str, Any] = data["message"]
        parts: list[Any] = []

        content = message.get("content") or ""
        if content:                                   # skip when empty
            parts.append(TextPart(content=content))

        raw_calls = message.get("tool_calls") or []
        for index, call in enumerate(raw_calls):
            fn = (call or {}).get("function") or {}
            name = fn.get("name")
            if not name:
                raise UnexpectedModelBehavior("Ollama tool_call without a function name")
            parts.append(
                ToolCallPart(
                    tool_name=name,
                    args=fn.get("arguments") or {},
                    # Ollama 0.18.0 DOES mint an id ("call_gta37wai"); older
                    # builds do not. Fall back to a stable synthetic id so a
                    # retry can be correlated to the call it came from.
                    tool_call_id=call.get("id") or f"ollama_{name}_{index}",
                )
            )

        usage = RequestUsage(
            input_tokens=int(data.get("prompt_eval_count") or 0),
            output_tokens=int(data.get("eval_count") or 0),
        )

        return ModelResponse(
            parts=parts,
            usage=usage,
            model_name=data.get("model") or self._model_name,
            timestamp=_parse_created_at(data.get("created_at")),
            provider_name=self.system,
            provider_url=self._base_url,
            finish_reason=_finish_reason(data.get("done_reason"), bool(raw_calls)),
            provider_details={
                k: data[k]
                for k in ("done_reason", "total_duration", "load_duration",
                          "prompt_eval_duration", "eval_duration")
                if k in data
            }
            or None,
        )


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _args_as_object(args: str | dict[str, Any] | None) -> dict[str, Any]:
    """Ollama requires a real JSON object for `tool_calls[].function.arguments`
    (a JSON string is a hard 400). pydantic-ai's `ToolCallPart.args` may be a
    dict, a JSON string, or None depending on which provider produced it."""
    if args is None:
        return {}
    if isinstance(args, dict):
        return args
    try:
        parsed = json.loads(args)
    except json.JSONDecodeError as e:
        raise UnexpectedModelBehavior(
            "ToolCallPart.args is a string that is not valid JSON"
        ) from e
    if not isinstance(parsed, dict):
        raise UnexpectedModelBehavior("ToolCallPart.args did not decode to an object")
    return parsed


def _finish_reason(done_reason: Any, had_tool_calls: bool) -> FinishReason | None:
    if had_tool_calls:
        return "tool_call"
    if done_reason == "stop":
        return "stop"
    if done_reason == "length":
        return "length"
    if done_reason == "load":                          # pragma: no cover
        return "error"
    return None


def _parse_created_at(value: Any) -> datetime:
    if isinstance(value, str):
        try:
            # Ollama emits RFC3339 with nanosecond precision; trim to micros.
            head, _, tail = value.partition(".")
            if tail:
                frac, _, tz = tail.partition("Z")
                value = f"{head}.{frac[:6]}+00:00" if not tz else value
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(tz=timezone.utc)
