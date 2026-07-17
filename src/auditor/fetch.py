from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable

from auditor.errors import AuditorError

_URL_PREFIXES = ("http://", "https://", "git@", "ssh://", "file://")


def _force_remove(path: Path) -> None:
    """rmtree that survives Windows read-only .git objects."""
    def _onerr(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=lambda f, p, e: _onerr(f, p, e))
    else:
        shutil.rmtree(path, onerror=_onerr)


def resolve_target(target: str) -> tuple[Path, Callable[[], None]]:
    if target.startswith(_URL_PREFIXES):
        tmp = Path(tempfile.mkdtemp(prefix="auditor-"))
        # GIT_TERMINAL_PROMPT=0: fail fast, never prompt; LFS smudge and symlink
        # creation are disabled — we scan text, we never materialize repo tricks
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never",
               "GIT_LFS_SKIP_SMUDGE": "1"}
        try:
            proc = subprocess.run(
                ["git", "-c", "core.symlinks=false", "clone", "--depth", "1",
                 target, str(tmp / "repo")],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                env=env, timeout=300,
            )
        except subprocess.TimeoutExpired:
            _force_remove(tmp)
            raise AuditorError("git clone timed out after 300s | انتهت مهلة الاستنساخ")
        if proc.returncode != 0:
            _force_remove(tmp)
            tail = (proc.stderr or "").strip().splitlines()[-3:]
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
