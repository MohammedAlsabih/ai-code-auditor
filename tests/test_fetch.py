import subprocess
from pathlib import Path

import pytest

from auditor.errors import AuditorError
from auditor.fetch import resolve_target


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
    src.mkdir()
    (src / "a.txt").write_text("hi", encoding="utf-8")
    for cmd in (["git", "init", "-b", "main"], ["git", "add", "."],
                ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "x"]):
        subprocess.run(cmd, cwd=src, check=True, capture_output=True)
    path, cleanup = resolve_target(src.as_uri())  # file:// URL exercises the clone path
    try:
        assert (path / "a.txt").exists() and path != src
    finally:
        cleanup()
    assert not path.exists()


def test_clone_failure_is_friendly():
    with pytest.raises(AuditorError) as exc:
        resolve_target("https://github.com/this-org-does-not-exist-xyz9/this-repo-neither-xyz9")
    assert "clone" in str(exc.value).lower()
