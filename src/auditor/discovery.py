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
    detected = {a.name for a, _ in found}
    for adapter in adapters:
        # spec: a missing dependency manifest must not stop the scan
        if adapter.name not in detected and _has_source_files(root, adapter):
            found.append((adapter, root))
    found.sort(key=lambda t: (str(t[1]).lower(), t[0].name))
    return found


def _has_source_files(root: Path, adapter: LanguageAdapter) -> bool:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
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
