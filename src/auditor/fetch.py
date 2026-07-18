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
# The ENTIRE userinfo is redacted — `https://TOKEN@host` puts the secret in the
# username slot, so preserving "user" while masking "pass" leaks tokens.
_CRED_URL = re.compile(r"(\b[a-z][a-z0-9+.\-]*://)([^/\s@'\"]{1,384})@")
_SENSITIVE_KEYS = (
    "api[-_]?key|access[-_]?key|private[-_]?token|auth[-_]?token|"
    "session[-_]?token|_auth(?:token)?|token|password|passwd|pwd|secret|"
    "authorization|credentials?|auth"
)
# 1) auth-carrying HEADERS eat the REST of the line/segment: the value of
#    `Authorization: Bearer XXX` is scheme + token — masking only the first
#    word leaked the token (CP-8b.1)
_AUTH_HEADER = re.compile(
    r"(?im)\b((?:proxy-)?authorization|x-api-key|api-key|x-auth-token|"
    r"www-authenticate)(\s*[:=]\s*)([^\r\n]+)")
# 2) QUOTED values (JSON/YAML/TOML): `"token": "XXX"` — the bare-KV value class
#    deliberately excludes quotes, so quoted secrets survived (CP-8b.1)
_QUOTED_KV = re.compile(
    rf"(?i)([\"']?(?:{_SENSITIVE_KEYS})[\"']?\s*[=:]\s*)([\"'])((?:[^\"'\\]|\\.){{1,512}})\2")
# 3) bare KV (query strings, .ini): value stops at delimiters
_TOKEN_KV = re.compile(rf"(?i)\b({_SENSITIVE_KEYS})(\s*[=:]\s*)([^&\s'\";,]{{1,512}})")


def _redact(text: str) -> str:
    """The ONE redaction policy tool-wide. Order matters: URLs first (userinfo),
    then headers (rest-of-line), then quoted KV, then bare KV. Every rule
    rewrites the secret to *** and matches its own output onto *** again, so the
    function is idempotent."""
    text = _CRED_URL.sub(r"\1***@", text)
    text = _AUTH_HEADER.sub(r"\1\g<2>***", text)
    text = _QUOTED_KV.sub(r"\1\g<2>***\g<2>", text)
    return _TOKEN_KV.sub(r"\1\g<2>***", text)


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
