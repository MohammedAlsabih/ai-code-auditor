from __future__ import annotations

import os
from pathlib import Path

from auditor.core.models import SourceFile

IGNORE_DIRS = frozenset({
    ".git", "node_modules", ".venv", "venv", "env", ".tox", "__pycache__",
    "dist", "build", "target", "bin", "obj", ".next", "out", ".output",
    "coverage", ".idea", ".vs", ".vscode", "site-packages", ".mypy_cache",
    ".pytest_cache", ".gradle", ".dart_tool", ".terraform",
})
MAX_FILE_BYTES = 1_500_000
MAX_MANIFEST_BYTES = 2_000_000


def _note(diag, field_name: str, message: str) -> None:
    # dedup per entry: the SAME file read twice (parse_dependencies +
    # private_registry_reason) must not double its ledger entry
    if diag is not None:
        entries = getattr(diag, field_name)
        if message not in entries:
            entries.append(message)


def collect_source_files(root: Path, adapter, exclude_roots: tuple[Path, ...] = (),
                         diag=None) -> list[SourceFile]:
    root = root.resolve()
    excluded = tuple(p.resolve() for p in exclude_roots)
    out: list[SourceFile] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in IGNORE_DIRS)
        here = Path(dirpath).resolve()
        if any(here == ex or ex in here.parents for ex in excluded):
            dirnames[:] = []
            continue
        for fn in sorted(filenames):
            p = here / fn
            if p.suffix.lower() not in adapter.source_globs:
                continue
            rel = p.relative_to(root).as_posix()
            try:
                if p.is_symlink():
                    _note(diag, "skipped_files", f"{rel}: symlink (not followed)")
                    continue
                if p.stat().st_size > MAX_FILE_BYTES:
                    _note(diag, "skipped_files", f"{rel}: exceeds {MAX_FILE_BYTES} bytes")
                    continue
                data = p.read_bytes()
            except OSError as e:
                _note(diag, "skipped_files", f"{rel}: unreadable ({e.__class__.__name__})")
                continue
            out.append(SourceFile(path=p, rel=rel, language=adapter.file_language(p), text=data))
    return out


def read_text_capped(path: Path, diag=None) -> str:
    """Bounded manifest read: adversarial XML/JSON size is capped BEFORE parsing
    (expat's amplification limits are build-specific; the cap is the real defense).
    Error entries use the FULL posix path so two same-named manifests in
    different monorepo roots stay distinct (GATE 4)."""
    try:
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            _note(diag, "manifest_errors",
                  f"{path.as_posix()}: exceeds {MAX_MANIFEST_BYTES} bytes, skipped")
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        _note(diag, "manifest_errors", f"{path.as_posix()}: unreadable ({e.__class__.__name__})")
        return ""
