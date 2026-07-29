"""W3-A2-FINAL: the experimental opt-in, and the promises it must keep.

The decision this file encodes: both real live attempts at `review` and
`fixed_audit` through the Claude CLI returned `invalid_response`, because the
command answered in prose instead of emitting `structured_output`. Refusing
that is safe, but a safe refusal is not evidence a feature works. So those two
workflows ship as EXPERIMENTAL, off unless an operator turns them on for
themselves, and `test` — which was proven live — ships as the only stable one.

Fake executables and pure functions only. No network, no real CLI.
"""
from __future__ import annotations

import json
import os
import sys
import textwrap
from pathlib import Path

import pytest

from auditor.ai.cli_providers import (
    CLI_EXPERIMENTAL_ENV, CLI_EXPERIMENTAL_VALUE, CLI_SPECS, cli_availability,
    cli_experimental_enabled, cli_supports, executable_capabilities,
    run_cli)
from auditor.ai.cli_providers import (  # noqa: E402
    test_cli_connection as probe_connection)
from auditor.ai.contract import AIError, Provider
from auditor.ai.providers import provider_metadata

CLAUDE = Provider.CLAUDE_CLI
CODEX = Provider.CODEX_CLI
ON = {CLI_EXPERIMENTAL_ENV: CLI_EXPERIMENTAL_VALUE}


def _fake(tmp_path: Path, body: str, name: str = "claude") -> dict[str, str]:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    script = bindir / (name + "_impl.py")
    script.write_text(textwrap.dedent(body), encoding="utf-8")
    if sys.platform == "win32":
        launcher = bindir / (name + ".bat")
        launcher.write_text(
            '@echo off\r\n"' + sys.executable + '" "' + str(script) + '" %*\r\n',
            encoding="utf-8")
    else:
        launcher = bindir / name
        launcher.write_text(
            '#!/bin/sh\nexec "' + sys.executable + '" "' + str(script) + '" "$@"\n',
            encoding="utf-8")
        launcher.chmod(0o755)
    env = {"PATH": str(bindir), "SystemRoot": os.environ.get("SystemRoot", ""),
           "COMSPEC": os.environ.get("COMSPEC", ""),
           "PATHEXT": os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD"),
           "TEMP": os.environ.get("TEMP", "/tmp")}
    return {k: v for k, v in env.items() if v}


# ---- the switch itself -----------------------------------------------------

def test_only_the_exact_value_turns_the_experiment_on():
    """Mirrors the project's other switches: an exact value, never a truthy
    coincidence. `1`, `true` and `yes` are not consent."""
    assert cli_experimental_enabled({CLI_EXPERIMENTAL_ENV: "confirm"}) is True
    for junk in ("1", "true", "TRUE", "yes", "on", "confirm ", "Confirm", ""):
        assert cli_experimental_enabled({CLI_EXPERIMENTAL_ENV: junk}) is False
    assert cli_experimental_enabled({}) is False


# ---- what is on offer, with and without the key ----------------------------

def test_without_the_key_only_the_proven_capability_is_executable():
    assert executable_capabilities(CLI_SPECS[CLAUDE], {}) == ("test",)
    assert cli_supports(CLAUDE, "test", {})
    for gated in ("review", "fixed_audit"):
        assert not cli_supports(CLAUDE, gated, {}), gated


def test_with_the_key_the_experimental_capabilities_appear_for_claude_only():
    assert executable_capabilities(CLI_SPECS[CLAUDE], ON) == (
        "test", "review", "fixed_audit")
    for gated in ("review", "fixed_audit"):
        assert cli_supports(CLAUDE, gated, ON), gated
    # the key is not a blanket permission: Codex declares nothing in either
    # tier, so turning the experiment on grants it nothing
    assert executable_capabilities(CLI_SPECS[CODEX], ON) == ()
    for cap in ("test", "review", "fixed_audit", "agent_audit"):
        assert not cli_supports(CODEX, cap, ON), cap


def test_the_listing_separates_declared_from_executable(tmp_path):
    env = _fake(tmp_path, "\nprint('9.9.9')\n")
    off = cli_availability(CLAUDE, env=env)
    assert off["installed"] is True
    assert off["supported"] is True                 # a contract exists
    assert off["capabilities"] == ["test"]          # ...and only this may run
    assert off["experimental_capabilities"] == ["review", "fixed_audit"]
    assert off["experimental_enabled"] is False
    assert off["available"] is True                 # test alone is enough

    on = cli_availability(CLAUDE, env={**env, **ON})
    assert on["capabilities"] == ["test", "review", "fixed_audit"]
    assert on["experimental_enabled"] is True


def test_a_provider_whose_every_capability_is_gated_is_not_available(tmp_path):
    """If `test` were experimental too, the provider would be installed and
    still not on offer, with a reason that says exactly that."""
    from dataclasses import replace
    from auditor.ai import cli_providers as mod

    env = _fake(tmp_path, "\nprint('9.9.9')\n")
    gated = replace(CLI_SPECS[CLAUDE], stable=(), experimental=("test",))
    saved = mod.CLI_SPECS[CLAUDE]
    mod.CLI_SPECS[CLAUDE] = gated
    try:
        off = cli_availability(CLAUDE, env=env)
        assert off["installed"] is True and off["supported"] is True
        assert off["available"] is False
        assert off["capabilities"] == []
        assert "experimental" in off["reason"]
    finally:
        mod.CLI_SPECS[CLAUDE] = saved


# ---- provider listing must not execute anything ----------------------------

def test_provider_listing_spawns_no_process_and_touches_no_network(monkeypatch):
    """A page load must not run programs. Both Popen and the HTTP transport are
    replaced with things that explode if used."""
    import subprocess

    def exploding_popen(*a, **k):
        raise AssertionError("provider listing spawned a subprocess")

    class ExplodingTransport:
        def request(self, *a, **k):
            raise AssertionError("provider listing made a network call")

    monkeypatch.setattr(subprocess, "Popen", exploding_popen)
    monkeypatch.setattr(subprocess, "run", exploding_popen)
    monkeypatch.setattr("auditor.ai.transport.RequestsTransport",
                        ExplodingTransport)

    rows = {m["provider"]: m for m in provider_metadata()}
    assert "claude_cli" in rows and "codex_cli" in rows
    # and it still answered the question it is asked
    assert isinstance(rows["claude_cli"]["installed"], bool)
    assert rows["claude_cli"]["version"] is None      # no version without a run


def test_the_web_endpoint_carries_the_tiers(tmp_path):
    from fastapi.testclient import TestClient

    from auditor.web.app import create_app

    report = tmp_path / "report.json"
    report.write_text(
        json.dumps({"tool": "ai-code-auditor", "summary": {},
                    "projects": []}), encoding="utf-8")
    with TestClient(create_app(report)) as client:
        rows = {p["provider"]: p
                for p in client.get("/api/ai/providers").json()["providers"]}
    cli = rows["claude_cli"]
    assert cli["kind"] == "cli" and cli["key_env"] is None
    assert "review" not in cli["capabilities"]
    assert cli["experimental_capabilities"] == ["review", "fixed_audit"]
    assert cli["experimental_enabled"] is False


# ---- calling a gated capability -------------------------------------------

def test_a_gated_call_is_refused_before_any_process_starts(tmp_path):
    ran = tmp_path / "ran.txt"
    env = _fake(tmp_path,
                "\nimport sys\nsys.stdin.read()\n"
                "open(r'" + str(ran) + "', 'a').write('x')\n")
    for gated in ("review", "fixed_audit"):
        with pytest.raises(AIError) as e:
            run_cli(CLAUDE, gated, "p", schema={"type": "object"}, env=env)
        assert e.value.code == "not_configured", gated
    assert not ran.exists(), "a gated capability spawned a process"


def test_the_refusal_message_is_the_projects_fixed_safe_one(tmp_path):
    from auditor.ai.contract import SAFE_MESSAGES
    env = _fake(tmp_path, "\nprint('9.9.9')\n")
    with pytest.raises(AIError) as e:
        run_cli(CLAUDE, "review", "p", env=env)
    assert str(e.value) == SAFE_MESSAGES["not_configured"]


def test_the_connection_test_still_works_without_the_key(tmp_path):
    """`test` is the one capability the real command was proven on, so it must
    keep working with no opt-in at all."""
    env = _fake(tmp_path,
                "\nimport json, sys\nsys.stdin.read()\n"
                "print(json.dumps({'type': 'result', 'is_error': False,\n"
                "                  'result': 'OK'}))\n")
    res = probe_connection(CLAUDE, "m", env=env)
    assert res.ok is True and res.status == "ok"


def test_the_review_and_audit_paths_refuse_without_the_key(tmp_path):
    """Not just `run_cli`: the two engine entry points refuse too, so a caller
    that bypasses the wire helper still cannot reach a gated workflow."""
    from auditor.ai.audit import run_audit_unit
    from auditor.ai.quality_corpus import cases
    from auditor.ai.quality_harness import _pack_for_case
    from auditor.ai.review import AIReviewRequest, run_review

    spawned = tmp_path / "spawned.txt"
    env = _fake(tmp_path,
                "\nimport sys\nsys.stdin.read()\n"
                "open(r'" + str(spawned) + "', 'a').write('x')\n")
    consented = {**env, "AUDITOR_AI_REMOTE_REVIEWS": "confirm"}

    case = next(c for c in cases() if c.kind == "positive")
    pack = _pack_for_case(case)
    with pytest.raises(AIError) as e:
        run_audit_unit(pack, CLAUDE, "m", None, env=consented, consented=True)
    assert e.value.code == "not_configured"

    req = AIReviewRequest(review_id="r", provider=CLAUDE, model="m")
    with pytest.raises(AIError) as e:
        run_review(req, {"pieces": [], "digest": "d" * 64}, transport=None,
                   env=consented, consented=True)
    assert e.value.code == "not_configured"

    assert not spawned.exists(), "a gated engine path spawned a process"


# ---- with the key, the contract is unchanged and still fail-closed ---------

def test_with_the_key_a_prose_reply_is_still_invalid_response(tmp_path):
    """This is what the real command did on both live attempts. There is no
    prose fallback, no retry, and no silent repair of the model's answer."""
    env = _fake(tmp_path,
                "\nimport json, sys\nsys.stdin.read()\n"
                "print(json.dumps({'type': 'result', 'is_error': False,\n"
                "  'result': 'Reported a medium-confidence issue in prose.'}))\n")
    out = run_cli(CLAUDE, "review", "p", schema={"type": "object"},
                  env={**env, **ON})
    # the wire helper surfaces the text; it does not pretend it is structured
    assert out["structured"] is None
    assert out["text"]

    from auditor.ai.audit import run_audit_unit
    from auditor.ai.quality_corpus import cases
    from auditor.ai.quality_harness import _pack_for_case

    pack = _pack_for_case(next(c for c in cases() if c.kind == "positive"))
    with pytest.raises(AIError) as e:
        run_audit_unit(pack, CLAUDE, "m", None,
                       env={**env, **ON,
                            "AUDITOR_AI_REMOTE_REVIEWS": "confirm"},
                       consented=True)
    assert e.value.code == "invalid_response"


def test_with_the_key_a_missing_structured_output_is_invalid_response(tmp_path):
    env = _fake(tmp_path,
                "\nimport json, sys\nsys.stdin.read()\n"
                "print(json.dumps({'type': 'result', 'is_error': False,\n"
                "                  'structured_output': None,\n"
                "                  'result': ''}))\n")
    with pytest.raises(AIError) as e:
        run_cli(CLAUDE, "review", "p", schema={"type": "object"},
                env={**env, **ON})
    assert e.value.code == "invalid_response"


def test_with_the_key_a_legal_audit_still_passes_the_verifier(tmp_path):
    """Turning the experiment on changes WHO may call, never HOW strictly the
    answer is judged."""
    from auditor.ai.audit import run_audit_unit
    from auditor.ai.quality_corpus import cases
    from auditor.ai.quality_harness import _pack_for_case

    case = next(c for c in cases() if c.kind == "positive")
    pack = _pack_for_case(case)
    src = next(p for p in pack["pieces"]
               if p["context_id"].startswith("src:"))
    span = src["spans"][0]
    reply = {"outcome": "issues_found", "issues": [{
        "title": "t", "category": pack["required_category"],
        "confidence": "high", "summary": "s",
        "evidence": [{"context_id": src["context_id"],
                      "line_start": span[0], "line_end": span[0],
                      "statement": "e"}],
        "missing_context": [], "suggested_action": "inspect"}]}
    env = _fake(tmp_path,
                "\nimport json, sys\nsys.stdin.read()\n"
                "print(json.dumps({'type': 'result', 'is_error': False,\n"
                "  'structured_output': " + json.dumps(reply) + "}))\n")
    out = run_audit_unit(pack, CLAUDE, "m", None,
                         env={**env, **ON,
                              "AUDITOR_AI_REMOTE_REVIEWS": "confirm"},
                         consented=True)
    assert out["provider"] == "claude_cli"
    assert out["context_digest"] == pack["digest"]
    assert out["issues"] and all("verification" in i for i in out["issues"])
