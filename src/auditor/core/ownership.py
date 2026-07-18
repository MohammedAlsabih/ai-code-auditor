from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

from auditor.core.models import Finding


def fs_case_insensitive(sample: Path | None) -> bool:
    """Probe the ACTUAL filesystem instead of assuming per-OS: swap the sample
    file's case and check it resolves to the same file. Case-normalization is
    only applied when the filesystem itself is insensitive — on sensitive
    filesystems Foo.ts and foo.ts are DIFFERENT files and must stay distinct."""
    if sample is not None:
        try:
            swapped = sample.with_name(sample.name.swapcase())
            if swapped.name != sample.name and swapped.exists():
                return os.path.samefile(sample, swapped)
            if swapped.name != sample.name:
                return False
        except OSError:
            pass
    return os.name == "nt"


def norm(path: str, insensitive: bool) -> str:
    p = path.replace("\\", "/")
    return p.casefold() if insensitive else p


def assign_findings(findings: list[Finding], owner: dict[str, int],
                    proj_meta: list[tuple[tuple[str, ...], int]],
                    prefixes: dict[int, str], globs: dict[int, tuple[str, ...]],
                    insensitive: bool) -> tuple[dict[int, list[Finding]], list[Finding], list[str]]:
    """exact full-file ownership first; deepest-root component fallback ONLY when
    the file's suffix belongs to that project's adapter (a Dockerfile/YAML at
    repo root goes to the repository bucket, never to 'the first language');
    '..' components are rejected (path-escape guard)."""
    assigned: dict[int, list[Finding]] = {}
    repo_bucket: list[Finding] = []
    dropped: list[str] = []
    meta = sorted(proj_meta, key=lambda t: -len(t[0]))
    for f in findings:
        rel = f.file.replace("\\", "/")
        if ".." in rel.split("/"):
            dropped.append(f.file)
            continue
        key = norm(rel, insensitive)
        idx = owner.get(key)
        if idx is None:
            parts = tuple(norm(rel, insensitive).split("/"))
            suffix = Path(rel).suffix.lower()
            idx = next((i for root_parts, i in meta
                        if parts[:len(root_parts)] == root_parts
                        and suffix in globs.get(i, ())), None)
        if idx is None:
            repo_bucket.append(f)
            continue
        prefix = prefixes.get(idx, "")
        if prefix and norm(rel, insensitive).startswith(norm(prefix, insensitive)):
            rel = rel[len(prefix):]
        assigned.setdefault(idx, []).append(replace(f, file=rel))
    return assigned, repo_bucket, dropped
