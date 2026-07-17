import os
import stat
import subprocess
from pathlib import Path

import pytest

import auditor.fetch as fetch
from auditor.errors import AuditorError
from auditor.fetch import resolve_target


def _make_source_repo(path: Path) -> None:
    path.mkdir()
    (path / "a.txt").write_text("hi", encoding="utf-8")
    for cmd in (["git", "init", "-q", "-b", "main"], ["git", "add", "."],
                ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "x"]):
        subprocess.run(cmd, cwd=path, check=True, capture_output=True)


def test_local_path_passthrough(tmp_path):
    path, cleanup = resolve_target(str(tmp_path))
    assert path == tmp_path.resolve()
    cleanup()
    assert tmp_path.exists()


def test_missing_local_path_raises():
    with pytest.raises(AuditorError):
        resolve_target(r"C:\definitely\not\here_xyz")


def test_clone_from_local_git_url(tmp_path):
    src = tmp_path / "srcrepo"
    _make_source_repo(src)
    path, cleanup = resolve_target(src.as_uri())  # file:// URL exercises the clone path
    try:
        assert (path / "a.txt").exists() and path != src
    finally:
        cleanup()
    assert not path.exists()


def test_clone_failure_is_friendly_mocked(monkeypatch):
    # deterministic, no network: git "returns" a non-zero clone failure
    class Fail:
        returncode = 128
        stdout = ""
        stderr = "fatal: repository not found"
    monkeypatch.setattr(fetch.subprocess, "run", lambda *a, **k: Fail())
    with pytest.raises(AuditorError) as exc:
        resolve_target("https://example.invalid/nope.git")
    assert "clone" in str(exc.value).lower()


def test_missing_git_cleans_temp_and_raises(monkeypatch, tmp_path):
    created = tmp_path / "auditor-tmp"

    def fake_mkdtemp(**kw):
        created.mkdir()
        return str(created)

    def boom(*a, **k):
        raise FileNotFoundError("git")

    monkeypatch.setattr(fetch.tempfile, "mkdtemp", fake_mkdtemp)
    monkeypatch.setattr(fetch.subprocess, "run", boom)
    with pytest.raises(AuditorError) as exc:
        resolve_target("https://example.invalid/x.git")
    assert "git" in str(exc.value).lower()
    assert not created.exists()   # temp dir removed even on launch failure


def test_clone_neutralizes_hooks_and_config(monkeypatch, tmp_path):
    # deterministic defense assertion (environment-independent): whatever git
    # does, resolve_target MUST pass an empty hooksPath override and empty
    # global/system config so a hostile global core.hooksPath cannot run.
    recorded = {}

    class Ok:
        returncode = 0
        stdout = ""
        stderr = ""

    def capture(cmd, **kw):
        recorded["cmd"] = cmd
        recorded["env"] = kw.get("env", {})
        return Ok()

    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(tmp_path / "attacker-global"))
    monkeypatch.setattr(fetch.subprocess, "run", capture)
    path, cleanup = resolve_target("https://example.invalid/x.git")
    try:
        cmd, env = recorded["cmd"], recorded["env"]
        joined = " ".join(cmd)
        assert "core.hooksPath=" in joined and "no-hooks" in joined
        assert "core.symlinks=false" in cmd and "core.fsmonitor=false" in cmd
        assert "--no-recurse-submodules" in cmd
        # global/system config redirected AWAY from the attacker's file
        assert env["GIT_CONFIG_GLOBAL"] != str(tmp_path / "attacker-global")
        assert env["GIT_CONFIG_GLOBAL"] == env["GIT_CONFIG_SYSTEM"]
        assert env["GIT_LFS_SKIP_SMUDGE"] == "1"
        assert "ext" not in env["GIT_ALLOW_PROTOCOL"].split(":")
    finally:
        cleanup()


def test_inherited_git_config_env_is_stripped(monkeypatch, tmp_path):
    # deterministic: an inherited inline GIT_CONFIG_* injection must NOT survive
    # into the env passed to git; only the tool's own GLOBAL/SYSTEM remain
    recorded = {}

    class Ok:
        returncode = 0
        stdout = ""
        stderr = ""

    for k, v in {"GIT_CONFIG_COUNT": "1",
                 "GIT_CONFIG_KEY_0": "filter.x.smudge",
                 "GIT_CONFIG_VALUE_0": "sh -c 'touch owned'",
                 "GIT_CONFIG_PARAMETERS": "'filter.x.smudge=sh -c owned'"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(fetch.subprocess, "run",
                        lambda cmd, **kw: (recorded.update(env=kw.get("env", {})), Ok())[1])
    _, cleanup = resolve_target("https://example.invalid/x.git")
    try:
        env = recorded["env"]
        leaked = [k for k in env if k.startswith("GIT_CONFIG_")
                  and k not in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM")]
        assert leaked == []                                   # COUNT/KEY_n/VALUE_n/PARAMETERS gone
        assert env["GIT_CONFIG_GLOBAL"].endswith("empty.gitconfig")
        assert env["GIT_CONFIG_GLOBAL"] == env["GIT_CONFIG_SYSTEM"]
    finally:
        cleanup()


def test_inherited_smudge_filter_does_not_execute(monkeypatch, tmp_path):
    # e2e with positive control: a .gitattributes-bound smudge filter defined via
    # inherited inline GIT_CONFIG_* runs in a raw clone but NOT via resolve_target
    src = tmp_path / "src"
    src.mkdir()
    (src / ".gitattributes").write_text("*.txt filter=reviewprobe\n", encoding="utf-8")
    (src / "a.txt").write_text("hi\n", encoding="utf-8")
    for cmd in (["git", "init", "-q", "-b", "main"], ["git", "add", "."],
                ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "x"]):
        subprocess.run(cmd, cwd=src, check=True, capture_output=True)

    marker = tmp_path / "SMUDGE_MARKER"
    attacker = {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "filter.reviewprobe.smudge",
        "GIT_CONFIG_VALUE_0": f"sh -c 'printf hooked > \"{marker.as_posix()}\"; cat'",
    }

    # positive control: raw clone inheriting the attacker inline config
    pos = tmp_path / "pos_clone"
    subprocess.run(["git", "clone", "-q", "--depth", "1", src.as_uri(), str(pos)],
                   env={**os.environ, **attacker, "GIT_TERMINAL_PROMPT": "0"},
                   capture_output=True)
    if not marker.exists():
        pytest.skip("inline GIT_CONFIG smudge does not fire on this git build")
    marker.unlink()

    # the defense: resolve_target inherits the same attacker env yet must not run it
    for k, v in attacker.items():
        monkeypatch.setenv(k, v)
    path, cleanup = resolve_target(src.as_uri())
    try:
        assert not marker.exists()   # smudge filter suppressed
    finally:
        cleanup()


def test_clone_env_strips_git_ssh_command_and_friends(monkeypatch, tmp_path):
    # deterministic: command-executing env vars must NOT survive into git's env
    for k in ("GIT_SSH_COMMAND", "GIT_SSH", "GIT_ASKPASS", "GIT_PROXY_COMMAND",
              "GIT_TEMPLATE_DIR", "GIT_EXTERNAL_DIFF", "SSH_ASKPASS"):
        monkeypatch.setenv(k, "sh -c 'touch owned'")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")  # benign, kept
    recorded = {}

    class Ok:
        returncode = 0
        stdout = ""
        stderr = ""
    monkeypatch.setattr(fetch.subprocess, "run",
                        lambda cmd, **kw: (recorded.update(env=kw.get("env", {})), Ok())[1])
    _, cleanup = resolve_target("ssh://example.invalid/x.git")
    try:
        env = recorded["env"]
        leaked = [k for k in env if k.startswith("GIT_")
                  and k not in ("GIT_TERMINAL_PROMPT", "GIT_LFS_SKIP_SMUDGE",
                                "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                                "GIT_ALLOW_PROTOCOL")]
        assert leaked == []                          # every hostile GIT_* dropped
        assert "SSH_ASKPASS" not in env
        assert env.get("SSH_AUTH_SOCK") == "/tmp/agent.sock"  # agent key auth kept
    finally:
        cleanup()


def test_git_ssh_command_does_not_execute_end_to_end(monkeypatch, tmp_path):
    src = tmp_path / "src"
    _make_source_repo(src)
    marker = tmp_path / "SSH_MARKER"
    attacker = f"sh -c 'printf hooked > \"{marker.as_posix()}\"; exit 1'"

    # positive control: a raw clone honoring GIT_SSH_COMMAND fires the marker
    subprocess.run(["git", "clone", "-q", "--depth", "1",
                    "ssh://example.invalid/repo.git", str(tmp_path / "pos")],
                   env={**os.environ, "GIT_SSH_COMMAND": attacker,
                        "GIT_TERMINAL_PROMPT": "0"}, capture_output=True)
    if not marker.exists():
        pytest.skip("GIT_SSH_COMMAND does not fire on this git build")
    marker.unlink()

    monkeypatch.setenv("GIT_SSH_COMMAND", attacker)
    try:
        resolve_target("ssh://example.invalid/repo.git")
    except AuditorError:
        pass
    assert not marker.exists()                       # GIT_SSH_COMMAND suppressed


def test_clone_error_redacts_credentials(monkeypatch):
    class Fail:
        returncode = 128
        stdout = ""
        stderr = ("fatal: unable to access "
                  "'https://alice:TOPSECRET@example.invalid/repo.git/': 403")
    monkeypatch.setattr(fetch.subprocess, "run", lambda *a, **k: Fail())
    with pytest.raises(AuditorError) as exc:
        resolve_target("https://alice:TOPSECRET@example.invalid/repo.git")
    msg = str(exc.value)
    assert "TOPSECRET" not in msg                    # secret redacted
    # ENTIRE userinfo goes: a token in the username slot must not survive
    assert "alice" not in msg
    assert "***@example.invalid" in msg              # message still informative
    assert "403" in msg


def test_redact_covers_userinfo_and_sensitive_query_keys():
    from auditor.fetch import _redact
    cases = [
        "https://INERTSECRET@example.invalid/repo.git",        # token-as-username
        "https://u:INERTSECRET@example.invalid/x.git",
        "https://example.invalid/x?api_key=INERTSECRET",
        "https://example.invalid/x?a=1&access-key=INERTSECRET&b=2",
        "https://example.invalid/x?private-token=INERTSECRET",
        "password=INERTSECRET",
        "Authorization: INERTSECRET",
        "auth_token = INERTSECRET",
    ]
    for c in cases:
        assert "INERTSECRET" not in _redact(c), c
    # non-sensitive text passes through untouched
    assert _redact("author=alice&tokenize=no") == "author=alice&tokenize=no"


def test_global_post_checkout_hook_does_not_execute(monkeypatch, tmp_path):
    # end-to-end negative test with a positive control so it can't false-green:
    # if the global-hooksPath mechanism does not fire on THIS machine, skip.
    src = tmp_path / "src"
    _make_source_repo(src)
    marker = tmp_path / "HOOK_MARKER"
    hooks = tmp_path / "attacker-hooks"
    hooks.mkdir()
    hook = hooks / "post-checkout"
    hook.write_text(f'#!/bin/sh\nprintf hooked > "{marker.as_posix()}"\n', encoding="utf-8")
    hook.chmod(hook.stat().st_mode | stat.S_IEXEC | stat.S_IRWXU)
    fake_global = tmp_path / "attacker-global"
    fake_global.write_text(f"[core]\n\thooksPath = {hooks.as_posix()}\n", encoding="utf-8")

    # positive control: a raw clone honoring the attacker global config
    pos = tmp_path / "pos_clone"
    subprocess.run(["git", "clone", "-q", "--depth", "1", src.as_uri(), str(pos)],
                   env={**os.environ, "GIT_CONFIG_GLOBAL": str(fake_global),
                        "GIT_TERMINAL_PROMPT": "0"},
                   capture_output=True)
    if not marker.exists():
        pytest.skip("global hooksPath post-checkout does not fire on this git build")
    marker.unlink()

    # the defense: resolve_target inherits the attacker global config yet must
    # NOT run the hook
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(fake_global))
    path, cleanup = resolve_target(src.as_uri())
    try:
        assert not marker.exists()   # hook suppressed
    finally:
        cleanup()
