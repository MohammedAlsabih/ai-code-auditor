"""W3-A2: locally-installed coding CLIs as AI providers.

These are `claude_cli` and `codex_cli`: programs already on the machine, driven
as subprocesses, authenticating with the login session the user already has.
No API key is read, passed, or required.

**Local execution is not local data.** The process runs here; the payload goes
to the vendor's service. So these providers sit on the REMOTE side of the
privacy gate and need the same admin switch and one-time consent as any remote
provider — which they inherit for free, because `is_local_review_provider` is
an explicit allowlist that does not contain them.

What this module refuses to do, by construction:

* **No repository access.** The child runs in a fresh EMPTY temp directory, so
  its own file tools have nothing to find even before they are switched off.
* **No tools, no skills, no MCP.** Passed explicitly on argv.
* **No shell.** argv is a list and `shell=False`; nothing is ever interpolated
  into a command string.
* **No secrets.** The child's environment is built from an ALLOWLIST. Anything
  that looks like a credential is dropped even if it would have been allowed,
  and the allowlist deliberately keeps HOME/USERPROFILE so the CLI can find
  the session the user already established.
* **No unbounded anything.** Wall-clock timeout, stdout and stderr byte caps,
  and a kill that takes the whole process tree, not just the direct child.
* **No echo.** A failure is reported with the project's fixed safe message for
  one of the seven legal error codes. CLI stdout/stderr never reaches a
  caller, a log, or a report — a coding CLI's output can contain anything.

The success path is fail-closed for a reason discovered by probing the real
CLI: it exits **0** on an API error and still reports `"subtype":"success"`,
with the truth in `is_error`/`api_error_status`. So neither the exit code nor
`subtype` is trusted here.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

from auditor.ai.contract import (
    PROBE_PROMPT, REQUEST_TIMEOUT_SECONDS, SAFE_MESSAGES, AIError,
    ConnectionResult, Provider, ProviderConfig)

# ---- bounds ---------------------------------------------------------------

CLI_TIMEOUT_SECONDS = REQUEST_TIMEOUT_SECONDS
CLI_MAX_STDOUT_BYTES = 2 * 1024 * 1024
CLI_MAX_STDERR_BYTES = 64 * 1024
CLI_KILL_GRACE_SECONDS = 5.0

# Capabilities are declared PER PROVIDER on its CliSpec, never as one shared
# list. A shared list is a claim about a category, and a category cannot be
# tested; only a specific command can. `agent_audit` appears nowhere: the agent
# runtime is a PydanticAI tool loop against a model API and these CLIs expose
# no such contract.
# STABLE means: proven against the real command, live. Only the connection
# test qualifies -- it asks for text and gets text.
CLAUDE_CLI_STABLE = ("test",)

# EXPERIMENTAL means: the contract is implemented and pinned by deterministic
# tests, but the real command has NOT been shown to honour it. Both live
# attempts returned `invalid_response` because the CLI answered in prose
# instead of emitting `structured_output`. Refusing that is safe; it is not
# evidence the feature works. So these are OFF unless an operator turns them on
# for themselves, and they are never listed as executable while off.
CLAUDE_CLI_EXPERIMENTAL = ("review", "fixed_audit")

# Codex declares NOTHING in either tier. A capability is a promise that a path
# has been exercised, and no runnable Codex CLI has ever been observed here, so
# every promise would be a guess -- including an experimental one.
CODEX_CLI_STABLE: tuple[str, ...] = ()
CODEX_CLI_EXPERIMENTAL: tuple[str, ...] = ()

# The opt-in. Mirrors the project's other switches: the EXACT value `confirm`,
# never a truthy coincidence.
CLI_EXPERIMENTAL_ENV = "AUDITOR_AI_CLI_EXPERIMENTAL"
CLI_EXPERIMENTAL_VALUE = "confirm"


def cli_experimental_enabled(env: dict[str, str] | None = None) -> bool:
    e = os.environ if env is None else env
    return e.get(CLI_EXPERIMENTAL_ENV) == CLI_EXPERIMENTAL_VALUE


# Environment the child may see. Everything else is dropped. HOME/USERPROFILE
# are here on purpose — that is where the CLI's existing login lives, and the
# whole point is to use it instead of a key.
_ENV_ALLOW = (
    "PATH", "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
    "SystemRoot", "SystemDrive", "windir", "COMSPEC", "PATHEXT",
    "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL", "TZ",
    "APPDATA", "LOCALAPPDATA", "USERNAME", "USER", "LOGNAME",
    "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "OS",
)

# Dropped even when the name is in the allowlist. A credential must not reach a
# child that is supposed to be using an interactive login instead.
_SECRET_MARKERS = (
    "KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL",
    "AUTH", "SESSION", "COOKIE", "BEARER", "PRIVATE", "SIGNATURE",
)


class CliUnavailable(Exception):
    """The CLI is not usable on this machine. Carries a SAFE reason only."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# Fixed, safe reasons. Never built from CLI output or an exception string.
REASON_NOT_INSTALLED = "the command was not found on this machine"
REASON_NOT_EXECUTABLE = "the command was found but could not be executed"
REASON_NO_VERSION = "the command did not report a usable version"
REASON_DENIED = "the operating system denied permission to run the command"
REASON_UNSUPPORTED = ("the command is installed, but this build has no "
                      "verified contract for it and will not guess one")
REASON_EXPERIMENTAL_OFF = (
    "the command is installed and its connection test works, but the "
    "structured-output workflows are experimental and not enabled")


@dataclass(frozen=True)
class CliSpec:
    provider: Provider
    display: str
    executable: str               # looked up on PATH
    path_env: str                 # env var that may override the executable
    default_model: str | None
    build_argv: Callable[["CliSpec", str | None, dict[str, Any] | None],
                         list[str]]
    parse_result: Callable[[Any], dict[str, Any]]
    # Proven live against the real command.
    stable: tuple[str, ...] = ()
    # Implemented and unit-proven, but NOT shown to work live. Requires the
    # operator's explicit opt-in before it is executable or even listed.
    experimental: tuple[str, ...] = ()
    version_argv: tuple[str, ...] = ("--version",)


# ---- claude ----------------------------------------------------------------

def _claude_argv(spec: CliSpec, model: str | None,
                 schema: dict[str, Any] | None) -> list[str]:
    """Non-interactive, isolated, structured.

    `--bare` is NOT used and must not be: it forces authentication through
    ANTHROPIC_API_KEY or an apiKeyHelper and never reads the OAuth session,
    which is precisely the credential path this provider exists to avoid.
    """
    argv = [
        spec.executable,
        "--print",                      # non-interactive: answer and exit
        "--output-format", "json",      # one machine-readable result object
        "--tools", "",                  # no tools at all
        "--disable-slash-commands",     # no skills
        "--strict-mcp-config",          # and no MCP servers, since none passed
        "--no-session-persistence",     # nothing about this run is stored
        "--setting-sources", "",        # ignore user/project/local settings
    ]
    if schema is not None:
        # the CLI validates its own output against this before returning it;
        # the project's contracts then validate it again, fail-closed
        argv += ["--json-schema", json.dumps(schema, separators=(",", ":"))]
    if model:
        argv += ["--model", model]
    return argv


def _claude_parse(data: Any) -> dict[str, Any]:
    """Map one `--output-format json` result onto the project's contract.

    Trusts NEITHER the exit code NOR `subtype`: a 404 on the model comes back
    as exit 0 with `subtype: "success"` and `is_error: true`.
    """
    if not isinstance(data, dict) or data.get("type") != "result":
        raise AIError("invalid_response")
    if data.get("is_error"):
        raise AIError(_status_to_code(data.get("api_error_status")))
    payload = data.get("structured_output")
    if payload is None:
        text = data.get("result")
        if not isinstance(text, str) or not text.strip():
            raise AIError("invalid_response")
        return {"text": text, "structured": None, "usage": _usage(data)}
    if not isinstance(payload, dict):
        raise AIError("invalid_response")
    return {"text": "", "structured": payload, "usage": _usage(data)}


def _usage(data: Any) -> dict[str, int]:
    u = data.get("usage") if isinstance(data, dict) else None
    u = u if isinstance(u, dict) else {}
    return {"input_tokens": int(u.get("input_tokens") or 0),
            "output_tokens": int(u.get("output_tokens") or 0)}


def _status_to_code(status: Any) -> str:
    """HTTP-ish status the CLI reports -> one of the seven legal codes."""
    try:
        s = int(status)
    except (TypeError, ValueError):
        return "invalid_response"
    if s in (401, 403):
        return "authentication_failed"
    if s == 404:
        return "model_not_found"
    if s == 429:
        return "rate_limited"
    if s in (408, 504):
        return "timeout"
    if 500 <= s < 600:
        return "connection_failed"
    return "invalid_response"


# ---- codex -----------------------------------------------------------------

def _codex_argv(spec: CliSpec, model: str | None,
                schema: dict[str, Any] | None) -> list[str]:
    """Placeholder argv for a Codex CLI.

    No runnable Codex CLI was found during capability discovery, so this shape
    is UNVERIFIED. It is never reached while the executable is missing —
    availability is checked first and the provider reports `not_configured`.
    It exists so the provider is a real, listed entry rather than a hidden
    special case, and so the day a CLI does appear the work is discovery and
    a test, not a new subsystem.
    """
    argv = [spec.executable, "exec", "--json"]
    if model:
        argv += ["--model", model]
    _ = schema
    return argv


def _codex_parse(data: Any) -> dict[str, Any]:
    """Refuses, always.

    Capability discovery found no runnable Codex CLI, so there is no verified
    output contract to parse against. Guessing one would mean shipping a code
    path whose success case has never been observed — the exact thing that
    turns "supported" into a claim rather than a fact. Until a real CLI can be
    probed and pinned by a test, a reply is `invalid_response`, which is
    unreachable in practice because availability is checked first.
    """
    _ = data
    raise AIError("invalid_response")


CLI_SPECS: dict[Provider, CliSpec] = {s.provider: s for s in (
    CliSpec(Provider.CLAUDE_CLI, "Claude Code CLI", "claude",
            "AUDITOR_CLAUDE_CLI_PATH", None, _claude_argv, _claude_parse,
            stable=CLAUDE_CLI_STABLE, experimental=CLAUDE_CLI_EXPERIMENTAL),
    CliSpec(Provider.CODEX_CLI, "Codex CLI", "codex",
            "AUDITOR_CODEX_CLI_PATH", None, _codex_argv, _codex_parse,
            stable=CODEX_CLI_STABLE, experimental=CODEX_CLI_EXPERIMENTAL),
)}


def is_cli_provider(provider: Provider) -> bool:
    return provider in CLI_SPECS


def executable_capabilities(spec: CliSpec,
                            env: dict[str, str] | None = None
                            ) -> tuple[str, ...]:
    """What this provider may ACTUALLY be asked to do right now.

    Stable always; experimental only behind the opt-in. This is the single
    definition of "executable", so the listing, the UI and the run path cannot
    disagree about what is on offer.
    """
    if cli_experimental_enabled(env):
        return tuple(spec.stable) + tuple(spec.experimental)
    return tuple(spec.stable)


def cli_supports(provider: Provider, capability: str,
                 env: dict[str, str] | None = None) -> bool:
    """Is this EXACT provider allowed to do this EXACT thing right now?

    Asked before every use. A provider with nothing executable answers False
    for everything, however healthy its executable looks, and an experimental
    capability answers False until the operator opts in.
    """
    spec = CLI_SPECS.get(provider)
    return bool(spec and capability in executable_capabilities(spec, env))


# ---- environment + process -------------------------------------------------

def child_env(env: dict[str, str] | None = None) -> dict[str, str]:
    """The child's WHOLE environment, built from nothing.

    Allowlist first, then a credential sweep over what survived — belt and
    braces, because the allowlist is a list of names and a name is a weak
    promise. `AUDITOR_*` never crosses: the child is not part of this
    application and has no business reading its configuration.
    """
    src = os.environ if env is None else env
    out: dict[str, str] = {}
    for name in _ENV_ALLOW:
        val = src.get(name)
        if val is None:
            continue
        upper = name.upper()
        if any(m in upper for m in _SECRET_MARKERS):
            continue
        out[name] = val
    return out


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kill the child AND its descendants.

    A coding CLI spawns helpers; killing only the direct child can leave them
    running and holding the pipe, which turns a cancellation into a hang.
    """
    if proc.poll() is not None:
        return
    try:
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                capture_output=True, timeout=CLI_KILL_GRACE_SECONDS,
                check=False)
        else:
            os.killpg(os.getpgid(proc.pid), 9)
    except Exception:                                    # noqa: BLE001
        pass
    try:
        proc.wait(timeout=CLI_KILL_GRACE_SECONDS)
    except Exception:                                    # noqa: BLE001
        try:
            proc.kill()
        except Exception:                                # noqa: BLE001
            pass


def _popen_isolation() -> dict[str, Any]:
    """Put the child in its own group so the whole tree can be signalled."""
    if sys.platform == "win32":
        return {"creationflags": getattr(subprocess,
                                         "CREATE_NEW_PROCESS_GROUP", 0)}
    return {"start_new_session": True}


def resolve_executable(spec: CliSpec,
                       env: dict[str, str] | None = None) -> str:
    """Absolute path to the CLI, or CliUnavailable with a safe reason.

    An explicit override is honoured but still has to exist and be executable;
    a configured-but-broken path is reported as unavailable, never guessed
    around.
    """
    import shutil
    src = os.environ if env is None else env
    override = (src.get(spec.path_env) or "").strip()
    if override:
        if not os.path.isfile(override):
            raise CliUnavailable(REASON_NOT_INSTALLED)
        if not os.access(override, os.X_OK):
            raise CliUnavailable(REASON_NOT_EXECUTABLE)
        return override
    # Look on the SAME PATH the child will get, never a wider one. Falling
    # back to the process PATH here while the child is handed a narrower one
    # would find a command the child then cannot run, and report the confusing
    # "no usable version" instead of the true "not installed".
    found = shutil.which(spec.executable, path=child_env(env).get("PATH", ""))
    if not found:
        raise CliUnavailable(REASON_NOT_INSTALLED)
    return found


# A `--version` that does not answer promptly is a broken install, not a slow
# one. This bound is deliberately tight because provider listing is a UI call:
# a hanging CLI must degrade to "unavailable", never stall the page.
CLI_VERSION_TIMEOUT_SECONDS = 10.0


def probe_version(spec: CliSpec, env: dict[str, str] | None = None,
                  timeout: float = CLI_VERSION_TIMEOUT_SECONDS) -> str:
    """Run `--version` and return the reported version.

    This is the availability check. It runs the same isolated way as a real
    call, so "it is installed" means "it can actually be executed the way this
    provider will execute it" — not merely that a file exists.
    """
    exe = resolve_executable(spec, env)
    try:
        out = _run_capped([exe, *spec.version_argv], stdin_text=None,
                          env=child_env(env), timeout=timeout)
    except AIError as e:
        raise CliUnavailable(
            REASON_DENIED if e.code == "not_configured" else REASON_NO_VERSION
        ) from None
    version = (out["stdout"] or "").strip().splitlines()
    if not version or not version[0].strip():
        raise CliUnavailable(REASON_NO_VERSION)
    return version[0].strip()[:120]


def _drain(stream: Any, limit: int, sink: list[bytes],
           over: "threading.Event") -> None:
    """Read a pipe with a HARD byte budget, keeping nothing past it.

    The budget is enforced WHILE reading, not after. `communicate()` returns
    only once the child is done, so a cap applied to its result is not a cap at
    all — a child that prints a gigabyte gets a gigabyte of our memory first,
    and is refused afterwards. Here the excess is never stored and never even
    read: the moment the budget is gone the event fires and the caller kills
    the tree.
    """
    kept = 0
    try:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                return
            if kept < limit:
                room = limit - kept
                sink.append(chunk[:room])
                kept += min(room, len(chunk))
            if kept >= limit:
                over.set()
                return
    except (ValueError, OSError):
        return                      # the pipe closed under us: nothing to add
    finally:
        try:
            stream.close()
        except Exception:                                # noqa: BLE001
            pass


def _feed(stream: Any, text: str | None) -> None:
    """Write the prompt and close, in a thread so a child that never reads its
    stdin cannot deadlock the parent against a full pipe buffer."""
    try:
        if text:
            stream.write(text.encode("utf-8"))
        stream.flush()
    except (ValueError, OSError):
        pass
    finally:
        try:
            stream.close()
        except Exception:                                # noqa: BLE001
            pass


def _run_capped(argv: list[str], stdin_text: str | None,
                env: dict[str, str], timeout: float) -> dict[str, Any]:
    """Run argv with every bound applied. Returns capped stdout/stderr.

    The working directory is a fresh EMPTY temp dir that is removed
    afterwards: whatever the child decides to look at, the repository is not
    reachable from where it stands.
    """
    with tempfile.TemporaryDirectory(prefix="auditor-cli-") as cwd:
        try:
            proc = subprocess.Popen(
                argv,                       # a LIST: never a shell string
                shell=False,
                cwd=cwd,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                **_popen_isolation(),
            )
        except FileNotFoundError:
            raise AIError("not_configured") from None
        except PermissionError:
            raise AIError("not_configured") from None
        except OSError:
            raise AIError("connection_failed") from None

        over = threading.Event()
        out_sink: list[bytes] = []
        err_sink: list[bytes] = []
        readers = [
            threading.Thread(target=_drain, daemon=True,
                             args=(proc.stdout, CLI_MAX_STDOUT_BYTES,
                                   out_sink, over)),
            threading.Thread(target=_drain, daemon=True,
                             args=(proc.stderr, CLI_MAX_STDERR_BYTES,
                                   err_sink, over)),
            threading.Thread(target=_feed, daemon=True,
                             args=(proc.stdin, stdin_text)),
        ]
        for th in readers:
            th.start()

        deadline = time.monotonic() + timeout
        try:
            while True:
                if proc.poll() is not None:
                    break
                if over.is_set():
                    # STOP the producer, do not drain it politely: a child that
                    # has already blown the cap has nothing left worth reading,
                    # and continuing would let it dictate our memory use.
                    _kill_tree(proc)
                    break
                if time.monotonic() >= deadline:
                    _kill_tree(proc)
                    raise AIError("timeout") from None
                time.sleep(0.02)
        except AIError:
            raise
        except BaseException:
            # cancellation included: the tree dies with the request
            _kill_tree(proc)
            raise
        for th in readers:
            th.join(timeout=CLI_KILL_GRACE_SECONDS)

        return {
            "returncode": proc.returncode,
            "stdout": b"".join(out_sink).decode("utf-8", "replace"),
            "stderr": b"".join(err_sink).decode("utf-8", "replace"),
            "oversized": over.is_set(),
        }


def run_cli(provider: Provider, capability: str, prompt: str,
            schema: dict[str, Any] | None = None,
            model: str | None = None,
            env: dict[str, str] | None = None,
            timeout: float = CLI_TIMEOUT_SECONDS) -> dict[str, Any]:
    """One non-interactive call. The prompt goes in on STDIN and nowhere else.

    Putting the payload on argv would leak it into the process table and any
    shell history, and would collide with the CLI's own flag parsing.

    `capability` is REQUIRED and checked here, at the single point every caller
    must pass through. Putting the check only at the call sites would mean a
    future call site could forget it; putting it here means it cannot.
    """
    spec = CLI_SPECS[provider]
    if not cli_supports(provider, capability, env):
        # Refuse BEFORE spawning anything. An override pointing at a real
        # executable does not make its answers meaningful, and an experimental
        # workflow that nobody opted into is not on offer.
        raise AIError("not_configured")
    try:
        exe = resolve_executable(spec, env)
    except CliUnavailable:
        raise AIError("not_configured") from None

    argv = spec.build_argv(spec, model or spec.default_model, schema)
    argv[0] = exe
    res = _run_capped(argv, stdin_text=prompt, env=child_env(env),
                      timeout=timeout)
    if res["oversized"]:
        raise AIError("invalid_response")
    text = res["stdout"].strip()
    if not text:
        # the exit code is NOT consulted: a CLI that printed nothing has said
        # nothing this code is willing to act on, whatever it returned
        raise AIError("invalid_response")
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        raise AIError("invalid_response") from None
    return spec.parse_result(data)


def cli_availability(provider: Provider,
                     env: dict[str, str] | None = None,
                     probe: bool = False) -> dict[str, Any]:
    """What the UI shows. **Spawns nothing unless `probe=True`.**

    Provider listing is a page load, and a page load must not execute programs:
    it would put a subprocess on the critical path of every render, and turn a
    hanging CLI into a hanging page. So `installed` is answered from the
    filesystem — the command resolves on the PATH the child would get — and the
    version, which requires actually running it, is only fetched when a caller
    explicitly asks.

    Three facts are kept apart because they answer different questions:

    * `installed`  — the command is there and looks executable.
    * `supported`  — this build has a verified contract for it at all.
    * `capabilities` — what may be executed RIGHT NOW: stable always,
      experimental only behind `AUDITOR_AI_CLI_EXPERIMENTAL=confirm`.

    Never asks for an API key, because there is nothing to ask for: the CLI
    either has a session or it does not, and that is its business.
    """
    spec = CLI_SPECS[provider]
    declared = tuple(spec.stable) + tuple(spec.experimental)
    executable = executable_capabilities(spec, env)
    entry: dict[str, Any] = {
        "provider": spec.provider.value,
        "display": spec.display,
        "kind": "cli",
        "locality": "remote",
        "requires_api_key": False,
        # what may run now -- EMPTY for a provider with nothing on offer, never
        # a category default
        "capabilities": list(executable),
        # declared but gated, so the UI can say "experimental, not enabled"
        # instead of pretending the workflow does not exist
        "experimental_capabilities": list(spec.experimental),
        "experimental_enabled": cli_experimental_enabled(env),
        "supports_agent_audit": False,
        "supported": bool(declared),
        "version": None,
    }
    try:
        resolve_executable(spec, env)
    except CliUnavailable as e:
        return {**entry, "installed": False, "available": False,
                "reason": e.reason}
    if probe:
        try:
            entry["version"] = probe_version(spec, env)
        except CliUnavailable as e:
            return {**entry, "installed": False, "available": False,
                    "reason": e.reason}
    if not declared:
        # installed and healthy, and still not offered: being able to start a
        # program is not the same as knowing what its answers mean
        return {**entry, "installed": True, "available": False,
                "reason": REASON_UNSUPPORTED}
    if not executable:
        # everything it can do is experimental and nobody opted in
        return {**entry, "installed": True, "available": False,
                "reason": REASON_EXPERIMENTAL_OFF}
    return {**entry, "installed": True, "available": True, "reason": ""}


def resolve_cli_config(provider: Provider,
                       env: dict[str, str] | None = None) -> ProviderConfig:
    """A ProviderConfig for a CLI provider: no base URL, no key, and a
    locality of `remote` that the consent gate will act on."""
    src = os.environ if env is None else env
    return ProviderConfig(
        provider=provider, base_url="", api_key=None,
        model=(src.get("AUDITOR_AI_MODEL") or None),
        transport_kind="cli")


def test_cli_connection(provider: Provider, model: str | None = None,
                        env: dict[str, str] | None = None) -> ConnectionResult:
    """The same FIXED probe the HTTP providers send, over the CLI wire.

    Success means a legal reply carrying any non-empty text. The reply itself
    is DISCARDED: a connection test tells the user whether the pipe works, and
    a coding CLI's words are not something this project puts on a screen.
    """
    if not cli_supports(provider, "test", env):
        return ConnectionResult(ok=False, status="not_configured",
                                message=SAFE_MESSAGES["not_configured"])
    started = time.perf_counter()
    try:
        out = run_cli(provider, "test", PROBE_PROMPT, schema=None,
                      model=model, env=env,
                      timeout=CLI_VERSION_TIMEOUT_SECONDS * 6)
    except AIError as e:
        return ConnectionResult(ok=False, status=e.code,
                                message=SAFE_MESSAGES[e.code])
    latency_ms = int((time.perf_counter() - started) * 1000)
    spoke = bool((out.get("text") or "").strip()) or bool(out.get("structured"))
    if not spoke:
        return ConnectionResult(ok=False, status="invalid_response",
                                message=SAFE_MESSAGES["invalid_response"])
    return ConnectionResult(ok=True, status="ok", message="connection ok",
                            latency_ms=latency_ms)
