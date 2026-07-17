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
