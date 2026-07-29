"""W3-A2 closing: end-to-end proofs for the four defects found at 2039a09.

Each test corresponds to a defect that was REPRODUCED before it was fixed: the
audit path crashed before the privacy gate ever ran, capabilities were a shared
category claim rather than a per-command fact, the output cap was applied after
buffering the whole reply, and tool disabling was argued from
`permission_denials: []` rather than shown.

Fake executables only. No network, no real CLI.
"""
from __future__ import annotations

import json
import os
import sys
import textwrap
import time
from pathlib import Path

import pytest

from auditor.ai.audit import run_audit_unit
from auditor.ai.cli_providers import (
    CLI_MAX_STDOUT_BYTES, CLI_SPECS, cli_availability, cli_supports, run_cli)
from auditor.ai.contract import AIError, Provider
from auditor.ai.quality_corpus import cases
from auditor.ai.quality_harness import _pack_for_case
from auditor.ai.review import PrivacyGateError

CLAUDE = Provider.CLAUDE_CLI
CODEX = Provider.CODEX_CLI
# W3-A2-FINAL: review and fixed_audit are EXPERIMENTAL opt-in. These tests
# exercise the contract, so they turn it on explicitly -- which is itself part
# of the proof that it is off by default.
CONSENTED_ENV = {"AUDITOR_AI_REMOTE_REVIEWS": "confirm",
                 "AUDITOR_AI_CLI_EXPERIMENTAL": "confirm"}
EXPERIMENTAL_ON = {"AUDITOR_AI_CLI_EXPERIMENTAL": "confirm"}


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


def _emit(payload: str) -> str:
    """A fake that drains stdin and prints one CLI result object."""
    return ("\nimport json, sys\nsys.stdin.read()\n"
            "print(json.dumps({'type': 'result', 'is_error': False,\n"
            "                  'structured_output': " + payload + "}))\n")


def _positive_pack():
    case = next(c for c in cases() if c.kind == "positive")
    pack = _pack_for_case(case)
    assert pack is not None
    return pack


# ---- defect 1: the audit path never routed a CLI ---------------------------

def test_the_privacy_gate_blocks_an_audit_before_any_process_starts(tmp_path):
    """It used to raise KeyError on PROVIDER_SPECS *before* the gate ran. The
    gate must come first, and nothing may be spawned."""
    spawned = tmp_path / "spawned.txt"
    env = _fake(tmp_path, "\nimport sys\nsys.stdin.read()\n"
                          "open(r'" + str(tmp_path / "spawned.txt") +
                          "', 'a').write('x')\n")
    with pytest.raises(PrivacyGateError):
        run_audit_unit(_positive_pack(), CLAUDE, "m", None, env=env,
                       consented=False)
    assert not spawned.exists(), "a process started before the gate allowed it"


def test_a_legal_cli_audit_passes_the_verifier_and_matches_the_envelope(tmp_path):
    """A well-formed CLI reply comes back through the SAME parser and verifier,
    in the SAME result shape the HTTP wire produces."""
    pack = _positive_pack()
    src = next(p for p in pack["pieces"] if p["context_id"].startswith("src:"))
    span = src["spans"][0]
    reply = {
        "outcome": "issues_found",
        "issues": [{
            "title": "t", "category": pack["required_category"],
            "confidence": "high", "summary": "s",
            "evidence": [{"context_id": src["context_id"],
                          "line_start": span[0], "line_end": span[0],
                          "statement": "e"}],
            "missing_context": [], "suggested_action": "inspect"}]}
    env = _fake(tmp_path, _emit(json.dumps(reply)))
    out = run_audit_unit(pack, CLAUDE, "m", None,
                         env={**env, **CONSENTED_ENV}, consented=True)

    for k in ("audit_unit_id", "project", "query_id", "query_version",
              "provider", "model", "prompt_version", "latency_ms",
              "context_digest", "num_ctx", "execution_id", "created_at",
              "outcome", "issues"):
        assert k in out, k
    assert out["provider"] == "claude_cli"
    assert out["audit_unit_id"] == pack["unit_id"]
    assert out["context_digest"] == pack["digest"]
    assert out["num_ctx"] is None            # a CLI has no Ollama window
    # the deterministic verifier ran: every issue carries its verdict
    assert out["issues"] and all("verification" in i for i in out["issues"])


def test_a_cli_audit_citing_something_never_sent_is_refused(tmp_path):
    """The CLI wire gets no softer validation than the HTTP wire."""
    pack = _positive_pack()
    reply = {"outcome": "issues_found", "issues": [{
        "title": "t", "category": pack["required_category"],
        "confidence": "high", "summary": "s",
        "evidence": [{"context_id": "src:999", "line_start": 1,
                      "line_end": 1, "statement": "e"}],
        "missing_context": [], "suggested_action": "inspect"}]}
    env = _fake(tmp_path, _emit(json.dumps(reply)))
    with pytest.raises(AIError) as e:
        run_audit_unit(pack, CLAUDE, "m", None,
                       env={**env, **CONSENTED_ENV}, consented=True)
    assert e.value.code == "invalid_response"


# ---- defect 2: capabilities were a shared category claim -------------------

def test_an_installed_codex_is_still_not_usable(tmp_path):
    """A real executable answering `--version` used to make Codex look fully
    capable. Installed and supported are different questions."""
    env = _fake(tmp_path, "\nprint('codex-cli 1.0.0')\n", name="codex")
    entry = cli_availability(CODEX, env=env)
    assert entry["installed"] is True           # the program really ran
    assert entry["supported"] is False          # but nothing is verified
    assert entry["available"] is False
    assert entry["capabilities"] == []
    assert entry["reason"]
    for cap in ("test", "review", "fixed_audit", "agent_audit"):
        assert not cli_supports(CODEX, cap)


def test_an_unsupported_provider_refuses_before_spawning(tmp_path):
    ran = tmp_path / "ran.txt"
    env = _fake(tmp_path, "\nimport sys\nsys.stdin.read()\n"
                          "open(r'" + str(ran) + "', 'a').write('x')\n",
                name="codex")
    with pytest.raises(AIError) as e:
        run_cli(CODEX, "review", "p", env=env)
    assert e.value.code == "not_configured"
    assert not ran.exists(), "an unsupported provider was executed"


def test_capabilities_are_declared_per_provider_not_shared():
    assert CLI_SPECS[CLAUDE].stable == ("test",)
    assert CLI_SPECS[CLAUDE].experimental == ("review", "fixed_audit")
    assert CLI_SPECS[CODEX].stable == () and CLI_SPECS[CODEX].experimental == ()
    assert cli_supports(CLAUDE, "fixed_audit", EXPERIMENTAL_ON)
    assert not cli_supports(CLAUDE, "agent_audit", EXPERIMENTAL_ON)


# ---- defect 3: the cap was applied after buffering everything --------------

def test_the_output_cap_stops_the_child_instead_of_buffering_it(tmp_path):
    """A 2 MiB cap that reads 64 MiB first is not a cap. The child must be
    stopped at the budget, and the excess never stored."""
    counter = tmp_path / "written.txt"
    env = _fake(tmp_path,
                "\nimport sys\nsys.stdin.read()\n"
                "chunk = 'x' * (1024 * 1024)\n"
                "for _ in range(64):\n"
                "    sys.stdout.write(chunk)\n"
                "    sys.stdout.flush()\n"
                "    open(r'" + str(counter) + "', 'a').write('1')\n")
    with pytest.raises(AIError) as e:
        run_cli(CLAUDE, "review", "p", schema={"type": "object"},
                env={**env, **EXPERIMENTAL_ON}, timeout=60)
    assert e.value.code == "invalid_response"

    produced_mib = counter.stat().st_size if counter.exists() else 0
    cap_mib = CLI_MAX_STDOUT_BYTES // (1024 * 1024)
    assert produced_mib <= cap_mib + 2, (
        "child produced " + str(produced_mib) + " MiB against a "
        + str(cap_mib) + " MiB cap")

    # and it is dead, not merely ignored
    time.sleep(1.5)
    after = counter.stat().st_size if counter.exists() else 0
    time.sleep(1.5)
    assert (counter.stat().st_size if counter.exists() else 0) == after


def test_a_child_that_never_reads_stdin_cannot_deadlock_the_parent(tmp_path):
    """The prompt is written from its own thread, so a child that ignores
    stdin and answers anyway is still handled."""
    env = _fake(tmp_path,
                "\nimport json, sys\n"
                "print(json.dumps({'type': 'result', 'is_error': False,\n"
                "                  'structured_output': {'ok': True}}))\n")
    out = run_cli(CLAUDE, "review", "x" * 200000, schema={"type": "object"},
                  env={**env, **EXPERIMENTAL_ON}, timeout=30)
    assert out["structured"] == {"ok": True}


# ---- defect 4: tool disabling was argued, not shown ------------------------

def test_a_canary_outside_the_working_directory_never_reaches_the_reply(tmp_path):
    """`permission_denials: []` says nothing was denied — not that nothing was
    read. This puts a real file OUTSIDE the child's cwd and proves its content
    does not come back, with tools, skills, MCP and settings all off.

    The fake stands in for a CLI that WOULD read it if the flags were missing:
    it checks for `--tools ""` and only reaches for the file when the flag is
    absent, so a regression that drops the flag fails this test loudly.
    """
    canary = tmp_path / "canary-secret.txt"
    canary.write_text("CANARY-9f13c7-MUST-NOT-APPEAR", encoding="utf-8")
    env = _fake(tmp_path,
                "\nimport json, os, sys\nsys.stdin.read()\n"
                "argv = sys.argv[1:]\n"
                "tools_off = ('--tools' in argv and\n"
                "             argv[argv.index('--tools') + 1] == '')\n"
                "leaked = ''\n"
                "if not tools_off:\n"
                "    leaked = open(r'" + str(canary) + "', encoding='utf-8').read()\n"
                "print(json.dumps({'type': 'result', 'is_error': False,\n"
                " 'structured_output': {\n"
                "   'tools_disabled': tools_off,\n"
                "   'skills_disabled': '--disable-slash-commands' in argv,\n"
                "   'mcp_locked': '--strict-mcp-config' in argv,\n"
                "   'settings_ignored': ('--setting-sources' in argv and\n"
                "        argv[argv.index('--setting-sources') + 1] == ''),\n"
                "   'no_persistence': '--no-session-persistence' in argv,\n"
                "   'cwd_entries': os.listdir('.'),\n"
                "   'leaked': leaked}}))\n")
    out = run_cli(CLAUDE, "review", "read the canary",
                  schema={"type": "object"},
                  env={**env, **EXPERIMENTAL_ON}, timeout=30)
    s = out["structured"]
    assert s["tools_disabled"] is True
    assert s["skills_disabled"] is True
    assert s["mcp_locked"] is True
    assert s["settings_ignored"] is True
    assert s["no_persistence"] is True
    assert s["cwd_entries"] == []              # nothing reachable from cwd
    assert s["leaked"] == ""
    assert "CANARY-9f13c7" not in json.dumps(out)
    # the file is still there and untouched: nothing was moved or consumed
    assert canary.read_text(encoding="utf-8") == "CANARY-9f13c7-MUST-NOT-APPEAR"
