from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable

from auditor.errors import AuditorError

_URL_PREFIXES = ("http://", "https://", "git@", "ssh://", "file://")
# userinfo (user:password@) and inline tokens in URLs / stderr must never be echoed
_CRED_URL = re.compile(r"(\b[a-z][a-z0-9+.\-]*://)([^/\s:@'\"]{1,128})(:[^@/\s'\"]{1,256})?@")
_TOKEN_KV = re.compile(r"(?i)((?:token|password|pwd|secret|access[_-]?key)=)([^&\s'\"]{3,})")


def _redact(text: str) -> str:
    text = _CRED_URL.sub(lambda m: m.group(1) + m.group(2) + (":***" if m.group(3) else "") + "@", text)
    return _TOKEN_KV.sub(r"\1***", text)


def _force_remove(path: Path) -> None:
    """rmtree that survives Windows read-only .git objects."""
    def _onerr(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=lambda f, p, e: _onerr(f, p, e))
    else:
        shutil.rmtree(path, onerror=_onerr)


def _clone_env(empty_cfg: Path) -> dict[str, str]:
    """Environment that neutralizes command execution and config injection during
    clone. EVERY inherited `GIT_*` variable is dropped, plus `SSH_ASKPASS` —
    otherwise `GIT_SSH_COMMAND`/`GIT_SSH`/`GIT_ASKPASS`/`GIT_PROXY_COMMAND`/
    `GIT_TEMPLATE_DIR` (hook injection)/`GIT_CONFIG_*` (filter.smudge etc.) let a
    clone run arbitrary commands. `SSH_AUTH_SOCK` is KEPT (ssh-agent key auth runs
    no command). Only the tool's own safe GIT_* vars are then re-added: empty
    global/system config, LFS off, prompts off, and a protocol allowlist without
    `ext::`."""
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("GIT_") and k != "SSH_ASKPASS"}
    env.update({
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "never",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_CONFIG_GLOBAL": str(empty_cfg),
        "GIT_CONFIG_SYSTEM": str(empty_cfg),
        "GIT_ALLOW_PROTOCOL": "http:https:ssh:git:file",
    })
    return env


def _clone_cmd(hooks_dir: Path, target: str, dest: Path) -> list[str]:
    # -c core.hooksPath=<empty dir> is a per-command override with highest
    # precedence — belt-and-suspenders on top of the neutralized global config.
    return [
        "git",
        "-c", f"core.hooksPath={hooks_dir.as_posix()}",
        "-c", "core.symlinks=false",
        "-c", "core.fsmonitor=false",
        "clone", "--depth", "1", "--no-recurse-submodules",
        target, str(dest),
    ]


def resolve_target(target: str) -> tuple[Path, Callable[[], None]]:
    if target.startswith(_URL_PREFIXES):
        tmp = Path(tempfile.mkdtemp(prefix="auditor-"))
        empty_cfg = tmp / "empty.gitconfig"
        empty_cfg.write_text("", encoding="utf-8")
        hooks_dir = tmp / "no-hooks"
        hooks_dir.mkdir()
        try:
            proc = subprocess.run(
                _clone_cmd(hooks_dir, target, tmp / "repo"),
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                env=_clone_env(empty_cfg), timeout=300,
            )
        except subprocess.TimeoutExpired:
            _force_remove(tmp)
            raise AuditorError("git clone timed out after 300s | انتهت مهلة الاستنساخ")
        except OSError as e:
            # git not installed / not launchable (FileNotFoundError is an OSError)
            _force_remove(tmp)
            raise AuditorError(
                "git executable not found or could not be launched "
                f"({e.__class__.__name__}) — is git installed and on PATH? | "
                "تعذّر تشغيل git: تأكد من تثبيته وإدراجه في PATH"
            )
        if proc.returncode != 0:
            _force_remove(tmp)
            tail = [_redact(ln) for ln in (proc.stderr or "").strip().splitlines()[-3:]]
            hint = ""
            low = (proc.stderr or "").lower()
            if "authentication" in low or "could not read username" in low or "repository not found" in low:
                hint = " (private or nonexistent repository? | مستودع خاص أو غير موجود؟)"
            raise AuditorError(
                "git clone failed" + hint + " | فشل الاستنساخ:\n" + "\n".join(tail)
            )
        return tmp / "repo", lambda: _force_remove(tmp)
    path = Path(target).expanduser().resolve()
    if not path.is_dir():
        raise AuditorError(f"path not found or not a directory | المسار غير موجود: {target}")
    return path, lambda: None
