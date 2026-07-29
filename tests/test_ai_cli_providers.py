"""W3-A2: the CLI provider layer, proven with FAKE executables.

Every claim the module makes about isolation is asserted here against a real
subprocess — a small Python script standing in for the CLI — because these are
security properties, and a security property that is only described in a
docstring is not a property.

No network. No real CLI is ever invoked.
"""
from __future__ import annotations

import json
import os
import sys
import textwrap
import time
from pathlib import Path

import pytest

from auditor.ai.cli_providers import (
    CLAUDE_CLI_EXPERIMENTAL, CLAUDE_CLI_STABLE, CLI_MAX_STDOUT_BYTES,
    CLI_SPECS, CliUnavailable, child_env, cli_availability, is_cli_provider,
    probe_version, resolve_cli_config, resolve_executable, run_cli)
from auditor.ai.contract import ERROR_CODES, AIError, Provider

# review/fixed_audit are experimental opt-in; wire-level tests turn them on
EXPERIMENTAL_ON = {"AUDITOR_AI_CLI_EXPERIMENTAL": "confirm"}

CLAUDE = Provider.CLAUDE_CLI
CODEX = Provider.CODEX_CLI


def _fake(tmp_path: Path, body: str, name: str = "claude") -> dict[str, str]:
    """Write a fake executable and return an env whose PATH finds it.

    On Windows a bare script is not executable, so the fake is a .bat that
    re-invokes this interpreter — which also proves the layer works through
    whatever the platform actually treats as a program.
    """
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    script = bindir / f"{name}_impl.py"
    script.write_text(textwrap.dedent(body), encoding="utf-8")
    if sys.platform == "win32":
        launcher = bindir / f"{name}.bat"
        launcher.write_text(
            f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n',
            encoding="utf-8")
    else:
        launcher = bindir / name
        launcher.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n',
                            encoding="utf-8")
        launcher.chmod(0o755)
    env = {"PATH": str(bindir) + os.pathsep + os.environ.get("PATH", ""),
           "SystemRoot": os.environ.get("SystemRoot", ""),
           "COMSPEC": os.environ.get("COMSPEC", ""),
           "PATHEXT": os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD"),
           "TEMP": os.environ.get("TEMP", "/tmp")}
    return {k: v for k, v in env.items() if v}


_RESULT = textwrap.dedent('''
    import json, sys
    sys.stdin.read()
    print(json.dumps({"type": "result", "subtype": "success",
                      "is_error": False, "api_error_status": None,
                      "result": "ok",
                      "structured_output": {"answer": "ok"},
                      "usage": {"input_tokens": 5, "output_tokens": 2}}))
''')


# ---- the happy path --------------------------------------------------------

def test_a_structured_reply_is_returned(tmp_path):
    env = _fake(tmp_path, _RESULT)
    out = run_cli(CLAUDE, "review", "hello", schema={"type": "object"}, env={**env, **EXPERIMENTAL_ON})
    assert out["structured"] == {"answer": "ok"}
    assert out["usage"] == {"input_tokens": 5, "output_tokens": 2}


def test_the_prompt_travels_on_stdin_and_never_on_argv(tmp_path):
    """A payload on argv would land in the process table and any shell
    history. This asserts where it actually went."""
    env = _fake(tmp_path, '''
        import json, sys
        got = sys.stdin.read()
        print(json.dumps({"type": "result", "is_error": False,
                          "structured_output": {"stdin": got,
                                                "argv": sys.argv[1:]}}))
    ''')
    secret_shaped = "REVIEW-PAYLOAD-8e21"
    out = run_cli(CLAUDE, "review", secret_shaped, schema={"type": "object"}, env={**env, **EXPERIMENTAL_ON})
    assert out["structured"]["stdin"] == secret_shaped
    assert not any(secret_shaped in a for a in out["structured"]["argv"])


# ---- isolation -------------------------------------------------------------

def test_no_secret_environment_variable_reaches_the_child(tmp_path):
    env = _fake(tmp_path, '''
        import json, os, sys
        sys.stdin.read()
        print(json.dumps({"type": "result", "is_error": False,
                          "structured_output": {"env": sorted(os.environ)}}))
    ''')
    leaky = {**env,
             "ANTHROPIC_API_KEY": "sk-should-never-cross",
             "OPENAI_API_KEY": "sk-nor-this",
             "AWS_SECRET_ACCESS_KEY": "x", "GITHUB_TOKEN": "y",
             "MY_SESSION_COOKIE": "z", "AUDITOR_AI_REMOTE_REVIEWS": "confirm"}
    out = run_cli(CLAUDE, "review", "p", schema={"type": "object"}, env={**leaky, **EXPERIMENTAL_ON})
    seen = set(out["structured"]["env"])
    for name in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY",
                 "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN",
                 "MY_SESSION_COOKIE"):
        assert name not in seen, name
    # the application's own configuration is not the child's business either
    assert not any(n.startswith("AUDITOR_") for n in seen)


def test_the_login_session_location_is_deliberately_preserved(tmp_path):
    """The whole point is to use the session already on the machine, so the
    home directory must survive the scrub even though everything else is
    dropped."""
    kept = child_env({"HOME": "/home/u", "USERPROFILE": r"C:\\Users\\u",
                      "PATH": "/usr/bin", "ANTHROPIC_API_KEY": "sk-x"})
    assert kept.get("HOME") == "/home/u"
    assert kept.get("USERPROFILE") == r"C:\\Users\\u"
    assert "ANTHROPIC_API_KEY" not in kept


def test_the_child_runs_in_an_empty_directory_that_is_not_the_repo(tmp_path):
    """Even with its own file tools switched off, the child must not be
    standing anywhere near the repository."""
    env = _fake(tmp_path, '''
        import json, os, sys
        sys.stdin.read()
        print(json.dumps({"type": "result", "is_error": False,
                          "structured_output": {"cwd": os.getcwd(),
                                                "entries": os.listdir(".")}}))
    ''')
    out = run_cli(CLAUDE, "review", "p", schema={"type": "object"}, env={**env, **EXPERIMENTAL_ON})
    assert out["structured"]["entries"] == []
    cwd = Path(out["structured"]["cwd"]).resolve()
    repo = Path(__file__).resolve().parent.parent
    assert repo not in cwd.parents and cwd != repo


def test_the_isolating_flags_are_actually_on_the_command_line(tmp_path):
    env = _fake(tmp_path, '''
        import json, sys
        sys.stdin.read()
        print(json.dumps({"type": "result", "is_error": False,
                          "structured_output": {"argv": sys.argv[1:]}}))
    ''')
    argv = run_cli(CLAUDE, "review", "p", schema={"type": "object"},
                   env={**env, **EXPERIMENTAL_ON})["structured"]["argv"]
    assert "--print" in argv                       # non-interactive
    assert argv[argv.index("--tools") + 1] == ""   # no tools at all
    assert "--disable-slash-commands" in argv      # no skills
    assert "--strict-mcp-config" in argv           # no MCP
    assert "--no-session-persistence" in argv      # nothing persisted
    assert "--bare" not in argv                    # would force an API key


# ---- adversarial output ----------------------------------------------------

def test_exit_zero_with_is_error_true_is_still_a_failure(tmp_path):
    """The real CLI does exactly this on a bad model: exit 0, subtype
    'success', is_error true. Trusting either of the first two would report a
    404 as a clean answer."""
    env = _fake(tmp_path, '''
        import json, sys
        sys.stdin.read()
        print(json.dumps({"type": "result", "subtype": "success",
                          "is_error": True, "api_error_status": 404,
                          "result": "no such model"}))
        sys.exit(0)
    ''')
    with pytest.raises(AIError) as e:
        run_cli(CLAUDE, "review", "p", schema={"type": "object"}, env={**env, **EXPERIMENTAL_ON})
    assert e.value.code == "model_not_found"


@pytest.mark.parametrize("status,code", [
    (401, "authentication_failed"), (403, "authentication_failed"),
    (404, "model_not_found"), (429, "rate_limited"),
    (408, "timeout"), (503, "connection_failed"),
    (418, "invalid_response"), (None, "invalid_response"),
])
def test_every_error_status_maps_onto_a_legal_code(tmp_path, status, code):
    env = _fake(tmp_path, f'''
        import json, sys
        sys.stdin.read()
        print(json.dumps({{"type": "result", "is_error": True,
                           "api_error_status": {json.dumps(status)}}}))
    ''')
    with pytest.raises(AIError) as e:
        run_cli(CLAUDE, "review", "p", schema={"type": "object"}, env={**env, **EXPERIMENTAL_ON})
    assert e.value.code == code
    assert e.value.code in ERROR_CODES


@pytest.mark.parametrize("body,label", [
    ('print("not json at all")', "non-JSON"),
    ('print("{}")', "no result type"),
    ('print(json.dumps({"type": "result", "is_error": False}))', "no payload"),
    ('print(json.dumps({"type": "result", "is_error": False,'
     ' "structured_output": "a string, not an object"}))', "wrong type"),
    ('pass', "silent"),
])
def test_malformed_output_is_refused_not_interpreted(tmp_path, body, label):
    env = _fake(tmp_path, f'''
        import json, sys
        sys.stdin.read()
        {body}
    ''')
    with pytest.raises(AIError) as e:
        run_cli(CLAUDE, "review", "p", schema={"type": "object"}, env={**env, **EXPERIMENTAL_ON})
    assert e.value.code == "invalid_response", label


def test_an_oversized_reply_is_refused_rather_than_buffered(tmp_path):
    env = _fake(tmp_path, f'''
        import sys
        sys.stdin.read()
        sys.stdout.write("x" * {CLI_MAX_STDOUT_BYTES + 4096})
    ''')
    with pytest.raises(AIError) as e:
        run_cli(CLAUDE, "review", "p", schema={{"type": "object"}}
                if False else {"type": "object"}, env={**env, **EXPERIMENTAL_ON})
    assert e.value.code == "invalid_response"


def test_cli_output_is_never_echoed_in_the_error(tmp_path):
    """A coding CLI can print anything — including whatever it was given. The
    message a caller sees must be the project's fixed one."""
    marker = "SENSITIVE-a41c7f-DO-NOT-ECHO"
    env = _fake(tmp_path, f'''
        import sys
        sys.stdin.read()
        sys.stdout.write({marker!r})
        sys.stderr.write({marker!r})
    ''')
    with pytest.raises(AIError) as e:
        run_cli(CLAUDE, "review", "p", schema={"type": "object"}, env={**env, **EXPERIMENTAL_ON})
    assert marker not in str(e.value)
    assert marker not in repr(e.value)


# ---- time and cancellation -------------------------------------------------

def test_a_hanging_cli_times_out_instead_of_hanging(tmp_path):
    env = _fake(tmp_path, '''
        import sys, time
        sys.stdin.read()
        time.sleep(120)
    ''')
    started = time.time()
    with pytest.raises(AIError) as e:
        run_cli(CLAUDE, "review", "p", schema={"type": "object"}, env={**env, **EXPERIMENTAL_ON}, timeout=2.0)
    assert e.value.code == "timeout"
    assert time.time() - started < 30, "the timeout did not actually bound it"


def test_a_timeout_leaves_no_child_still_running(tmp_path):
    """The process tree dies with the request. A survivor would hold the pipe
    and turn the next cancellation into a hang."""
    marker = tmp_path / "still-alive.txt"
    env = _fake(tmp_path, f'''
        import sys, time
        sys.stdin.read()
        for _ in range(200):
            time.sleep(0.1)
            open({str(marker)!r}, "a").write("tick\\n")
    ''')
    with pytest.raises(AIError):
        run_cli(CLAUDE, "review", "p", schema={"type": "object"}, env={**env, **EXPERIMENTAL_ON}, timeout=2.0)
    time.sleep(1.5)
    size_after_kill = marker.stat().st_size if marker.exists() else 0
    time.sleep(1.5)
    size_later = marker.stat().st_size if marker.exists() else 0
    assert size_later == size_after_kill, "the child kept running after kill"


# ---- availability ----------------------------------------------------------

def test_a_missing_cli_is_unavailable_with_a_safe_reason():
    env = {"PATH": os.pathsep.join(["/nonexistent-dir-a2"])}
    entry = cli_availability(CODEX, env={**env, **EXPERIMENTAL_ON})
    assert entry["available"] is False
    assert entry["reason"] and "\\" not in entry["reason"]
    assert entry["requires_api_key"] is False          # never asks for a key
    assert entry["version"] is None


def test_an_available_cli_reports_its_version(tmp_path):
    env = _fake(tmp_path, '''
        import sys
        print("9.9.9 (Fake CLI)")
    ''')
    # listing does not run the program, so it reports no version
    listed = cli_availability(CLAUDE, env={**env, **EXPERIMENTAL_ON})
    assert listed["installed"] is True and listed["available"] is True
    assert listed["version"] is None

    # asking for the version is an explicit, separate act
    probed = cli_availability(CLAUDE, env={**env, **EXPERIMENTAL_ON},
                              probe=True)
    assert probed["version"].startswith("9.9.9")
    assert probed["reason"] == ""


def test_a_configured_but_broken_path_is_unavailable_not_guessed_around(tmp_path):
    missing = tmp_path / "nope" / "claude"
    env = {"PATH": "", "AUDITOR_CLAUDE_CLI_PATH": str(missing)}
    with pytest.raises(CliUnavailable):
        resolve_executable(CLI_SPECS[CLAUDE], env)


def test_a_cli_that_prints_no_version_is_not_treated_as_available(tmp_path):
    env = _fake(tmp_path, 'pass')
    with pytest.raises(CliUnavailable):
        probe_version(CLI_SPECS[CLAUDE], env)


# ---- contract placement ----------------------------------------------------

def test_the_ids_are_their_own_and_not_the_http_vendors():
    assert CLAUDE.value == "claude_cli" and CODEX.value == "codex_cli"
    assert CLAUDE is not Provider.ANTHROPIC and CODEX is not Provider.OPENAI
    assert is_cli_provider(CLAUDE) and is_cli_provider(CODEX)
    assert not is_cli_provider(Provider.OLLAMA)


def test_local_execution_does_not_make_the_data_local():
    """The process is local; the payload is not. If `locality` answered
    'local' here the consent gate would be skipped for a remote send."""
    for p in (CLAUDE, CODEX):
        cfg = resolve_cli_config(p, env={})
        assert cfg.locality == "remote"
        assert cfg.api_key is None and cfg.base_url == ""


def test_a_cli_provider_is_not_in_the_no_consent_set():
    from auditor.ai.review import is_local_review_provider
    for p in (CLAUDE, CODEX):
        assert not is_local_review_provider(p, resolve_cli_config(p, env={}))


def test_agent_audit_is_not_claimed(tmp_path):
    """Only capabilities with a real, testable contract are advertised."""
    declared = set(CLAUDE_CLI_STABLE) | set(CLAUDE_CLI_EXPERIMENTAL)
    assert "agent_audit" not in declared
    assert declared == {"test", "review", "fixed_audit"}
    entry = cli_availability(CODEX, env={"PATH": "/nonexistent-dir-a2"})
    assert entry["supports_agent_audit"] is False


def test_codex_has_no_verified_output_contract_so_it_refuses(tmp_path):
    """No runnable Codex CLI was found, so no success path has ever been
    observed. It must not appear to work.

    The refusal is `not_configured` and happens BEFORE the process is spawned:
    the closing round moved it from "run it, then fail to parse" to "declare no
    capability, so never run it". A fake that WOULD have answered correctly is
    used deliberately -- the point is that its answer is never sought.
    """
    env = _fake(tmp_path, _RESULT, name="codex")
    with pytest.raises(AIError) as e:
        run_cli(CODEX, "review", "p", schema={"type": "object"}, env={**env, **EXPERIMENTAL_ON})
    assert e.value.code == "not_configured"


# ---- wiring: the CLI reaches the real surfaces ------------------------------

def test_the_cli_providers_are_listed_with_a_reason_and_no_key_field():
    from auditor.ai.providers import provider_metadata
    rows = {m["provider"]: m for m in provider_metadata(env={"PATH": ""})}
    for name in ("claude_cli", "codex_cli"):
        m = rows[name]
        assert m["kind"] == "cli"
        assert m["key_env"] is None and m["key_present"] is False
        assert m["locality"] == "remote"
        assert m["configured"] is False and m["reason"]
        assert "agent_audit" not in m["capabilities"]


def test_a_review_through_a_cli_uses_the_same_gate_and_validator(tmp_path):
    """The privacy gate must fire BEFORE the process is spawned, and the reply
    must go through the project's own parser, not a softer CLI-only one."""
    from auditor.ai.review import PrivacyGateError, run_review

    spawned = tmp_path / "spawned.txt"
    env = _fake(tmp_path, f'''
        import json, sys
        sys.stdin.read()
        open({str(spawned)!r}, "a").write("x")
        print(json.dumps({{"type": "result", "is_error": False,
                           "structured_output": {{"not": "a review"}}}}))
    ''')

    class Req:
        provider = CLAUDE
        model = "m"
        review_id = "r1"

    pack = {"pieces": [], "digest": "d" * 64}
    # no admin switch, no consent -> blocked, and NOTHING is executed
    with pytest.raises(PrivacyGateError):
        run_review(Req(), pack, transport=None, env=env, consented=False)
    assert not spawned.exists(), "the gate let a process start"


def test_the_connection_probe_sends_only_the_fixed_prompt(tmp_path):
    from auditor.ai.cli_providers import test_cli_connection
    from auditor.ai.contract import PROBE_PROMPT

    seen = tmp_path / "seen.txt"
    env = _fake(tmp_path, f'''
        import json, sys
        got = sys.stdin.read()
        open({str(seen)!r}, "w", encoding="utf-8").write(got)
        print(json.dumps({{"type": "result", "is_error": False,
                           "result": "OK"}}))
    ''')
    res = test_cli_connection(CLAUDE, "m", env={**env, **EXPERIMENTAL_ON})
    assert res.ok and res.status == "ok"
    assert seen.read_text(encoding="utf-8") == PROBE_PROMPT
    # the model's words are never surfaced
    assert "OK" not in res.message


def test_a_failing_probe_reports_a_safe_status_not_the_cli_text(tmp_path):
    from auditor.ai.cli_providers import test_cli_connection
    env = _fake(tmp_path, '''
        import json, sys
        sys.stdin.read()
        print(json.dumps({"type": "result", "is_error": True,
                          "api_error_status": 401,
                          "result": "your token 12345 expired"}))
    ''')
    res = test_cli_connection(CLAUDE, "m", env={**env, **EXPERIMENTAL_ON})
    assert res.ok is False and res.status == "authentication_failed"
    assert "12345" not in res.message
