from __future__ import annotations

import os
from pathlib import Path

from auditor.core.interfaces import LanguageAdapter
from auditor.core.models import SourceFile
from auditor.core.walk import IGNORE_DIRS, collect_source_files


def discover_projects(root: Path, adapters: list[LanguageAdapter]) -> list[tuple[LanguageAdapter, Path]]:
    root = root.resolve()
    found: list[tuple[LanguageAdapter, Path]] = []
    for dirpath, dirnames, _ in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in IGNORE_DIRS)
        here = Path(dirpath)
        for adapter in adapters:
            if adapter.detect(here):
                found.append((adapter, here))
    # A missing dependency manifest must not stop the scan: add a root fallback
    # project for a language ONLY when that language has source files OUTSIDE all
    # of its already-detected project roots. Detecting the language somewhere
    # (e.g. services/api) must NOT suppress the fallback for a manifestless tail
    # (e.g. tools/audit.py) — project_files then excludes the nested detected
    # roots from the fallback, so nothing is covered twice.
    for adapter in adapters:
        adapter_roots = [p for a, p in found if a.name == adapter.name]
        if root in adapter_roots:
            continue  # root itself is a project for this adapter => it covers the tail
        if _has_uncovered_source(root, adapter, adapter_roots):
            found.append((adapter, root))
    found.sort(key=lambda t: (str(t[1]).lower(), t[0].name))
    return found


def _has_uncovered_source(root: Path, adapter: LanguageAdapter,
                          adapter_roots: list[Path]) -> bool:
    """True if a source file for `adapter` exists that is NOT inside any of the
    adapter's already-detected project roots."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        here = Path(dirpath)
        if any(here == pr or pr in here.parents for pr in adapter_roots):
            continue  # covered by a detected project of this adapter
        if any(Path(f).suffix.lower() in adapter.source_globs for f in filenames):
            return True
    return False


def project_files(project_root: Path, adapter: LanguageAdapter,
                  all_projects: list[tuple[LanguageAdapter, Path]],
                  diag=None) -> list[SourceFile]:
    nested = tuple(
        p for a, p in all_projects
        if a.name == adapter.name and p != project_root and project_root in p.parents
    )
    return collect_source_files(project_root, adapter, exclude_roots=nested, diag=diag)
