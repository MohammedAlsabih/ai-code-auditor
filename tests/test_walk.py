from pathlib import Path

from auditor.core.models import Diagnostics
from auditor.core.walk import (IGNORE_DIRS, collect_source_files,
                               read_text_capped)


class StubAdapter:
    name = "python"
    source_globs = (".py",)

    def file_language(self, path: Path) -> str:
        return "python"


def _mk(tmp_path: Path, rel: str, content: str = "x = 1\n") -> Path:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def test_walker_collects_and_ignores(tmp_path):
    _mk(tmp_path, "app.py")
    _mk(tmp_path, "pkg/mod.py")
    _mk(tmp_path, "node_modules/junk.py")
    _mk(tmp_path, ".venv/lib.py")
    _mk(tmp_path, "notes.txt")
    files = collect_source_files(tmp_path, StubAdapter())
    rels = sorted(f.rel for f in files)
    assert rels == ["app.py", "pkg/mod.py"]
    assert all(f.text for f in files) and files[0].language == "python"


def test_walker_excludes_nested_project_roots(tmp_path):
    _mk(tmp_path, "main.py")
    _mk(tmp_path, "sub/inner.py")
    files = collect_source_files(tmp_path, StubAdapter(), exclude_roots=(tmp_path / "sub",))
    assert [f.rel for f in files] == ["main.py"]


def test_ignore_dirs_contains_the_usual_suspects():
    for d in ("node_modules", ".git", "__pycache__", "dist", "target", "obj", ".next"):
        assert d in IGNORE_DIRS


def test_read_text_capped_oversized_uses_full_path(tmp_path):
    # GATE 4: two same-named manifests in different roots must stay distinct
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    big = "x" * 2_100_000
    (tmp_path / "a" / "pyproject.toml").write_text(big, encoding="utf-8")
    (tmp_path / "b" / "pyproject.toml").write_text(big, encoding="utf-8")
    diag = Diagnostics()
    assert read_text_capped(tmp_path / "a" / "pyproject.toml", diag) == ""
    assert read_text_capped(tmp_path / "b" / "pyproject.toml", diag) == ""
    assert len(diag.manifest_errors) == 2                     # NOT merged by name
    assert all("pyproject.toml" in e and "exceeds" in e for e in diag.manifest_errors)


def test_read_text_capped_unreadable_records_full_path(tmp_path):
    missing = tmp_path / "sub" / "requirements.txt"
    diag = Diagnostics()
    assert read_text_capped(missing, diag) == ""
    assert len(diag.manifest_errors) == 1
    assert missing.as_posix() in diag.manifest_errors[0]


def test_walker_records_skipped_oversized(tmp_path):
    p = _mk(tmp_path, "big.py", "x" * 1_600_000)
    diag = Diagnostics()
    files = collect_source_files(tmp_path, StubAdapter(), diag=diag)
    assert files == []
    assert any("big.py" in s and "exceeds" in s for s in diag.skipped_files)
