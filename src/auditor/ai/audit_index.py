"""W3-E: deterministic, confined repository index for AI-audit retrieval.

Everything is local and bounded — no embeddings, no vector store, no
network. The index:

- walks ONLY inside the repository root with the scanner's own IGNORE_DIRS,
  honors `.auditor.toml` exclude_paths / dependency_exclude_paths, and skips
  vendored trees, report output directories, and every auditor sidecar;
- never follows symlinks, never reads binaries (NUL probe on the bounded
  read), never reads a file past the scanner's byte cap;
- orders files and candidates DETERMINISTICALLY (score desc, path asc), so
  shuffled directory listings produce identical retrieval;
- records, per query: eligible_files, candidate_files, contexts_sent, and
  skipped/blocked counts by reason — silence is never coverage.

Retrieval is query-specific: path/filename hints, structural symbol hints,
manifests when the query needs them, bounded source windows around actual
matches — never the whole repository, and never filler files to reach a cap.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from auditor.ai.audit_queries import AuditQuery
from auditor.config import any_match, is_vendored, load_config
from auditor.core.walk import IGNORE_DIRS, MAX_FILE_BYTES

_EXT_LANGUAGE = {
    ".py": "python",
    ".ts": "typescript", ".tsx": "typescript",
    ".cs": "csharp",
    ".java": "java",
}
# auditor outputs and sidecars must never feed an AI audit
_SIDECAR_SUFFIXES = (".reviews.json", ".ai-reviews.json", ".ai-consent.json",
                     ".ai-batches.json", ".ai-audit.json")
_REPORT_NAMES = ("report.json", "report.md", "report.sarif")

MANIFEST_NAMES = ("package.json", "pyproject.toml", "requirements.txt",
                  "pom.xml", "build.gradle", "build.gradle.kts",
                  "Directory.Packages.props", "Directory.Build.props",
                  "NuGet.config")

MAX_CANDIDATES_PER_QUERY = 12       # ranked candidates kept per (query, project)
_MATCH_SCAN_CAP = 200               # content-hint hits counted per file at most


@dataclass
class IndexedFile:
    rel: str                        # repo-relative posix path
    project: str                    # owning project root ('.' for repo root)
    language: str
    size: int
    text: str                       # capped, NUL-free, utf-8-replaced


@dataclass
class QueryAccounting:
    eligible_files: int = 0
    candidate_files: int = 0
    contexts_sent: int = 0
    skipped: dict[str, int] = field(default_factory=dict)

    def skip(self, reason: str, n: int = 1) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + n


class RepositoryAuditIndex:
    """Build once per audit; read-only afterwards."""

    def __init__(self, repo_root: Path,
                 project_roots: list[tuple[str, str]]) -> None:
        """project_roots: [(root, language)] exactly as the loaded report
        declares them."""
        self._repo = repo_root.resolve()
        self._projects = sorted(project_roots)
        self._config = load_config(repo_root)
        self.files: list[IndexedFile] = []
        self.skipped: dict[str, int] = {}
        self.accounting: dict[str, QueryAccounting] = {}
        self._build()

    # ---- build -----------------------------------------------------------------
    def _skip(self, reason: str) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1

    def _project_of(self, rel: str) -> str | None:
        best: str | None = None
        for root, _lang in self._projects:
            r = root.strip("/")
            if r in ("", "."):
                best = best or "."
            elif rel == r or rel.startswith(r + "/"):
                if best is None or best in (".",) or len(r) > len(best):
                    best = root
        return best

    def _build(self) -> None:
        import os
        for dirpath, dirnames, filenames in os.walk(self._repo):
            dirnames[:] = sorted(
                d for d in dirnames
                if d not in IGNORE_DIRS
                and not (d.endswith("-report") or "-report-" in d))
            here = Path(dirpath)
            for fn in sorted(filenames):
                p = here / fn
                try:
                    rel = p.relative_to(self._repo).as_posix()
                except ValueError:
                    continue
                if fn in _REPORT_NAMES \
                        or any(fn.endswith(s) for s in _SIDECAR_SUFFIXES):
                    self._skip("auditor output/sidecar")
                    continue
                suffix = p.suffix.lower()
                is_manifest = fn in MANIFEST_NAMES
                if suffix not in _EXT_LANGUAGE and not is_manifest:
                    continue                       # not audit material
                if any_match(rel, self._config.exclude_paths):
                    self._skip("excluded by .auditor.toml")
                    continue
                if is_manifest and any_match(
                        rel, self._config.dependency_exclude_paths):
                    # dependency auditing is OFF for this path — its
                    # manifests never feed an AI audit context
                    self._skip("dependency-excluded manifest")
                    continue
                if is_vendored(rel):
                    self._skip("vendored")
                    continue
                try:
                    if p.is_symlink():
                        self._skip("symlink (not followed)")
                        continue
                    # stat is only a CHEAP early reject; the bounded cap+1
                    # read below is the real guarantee — if stat lied or the
                    # file grew mid-read, the read still proves oversize
                    if p.stat().st_size > MAX_FILE_BYTES:
                        self._skip("exceeds byte cap")
                        continue
                    with p.open("rb") as fh:
                        raw = fh.read(MAX_FILE_BYTES + 1)
                except OSError:
                    self._skip("unreadable")
                    continue
                if len(raw) > MAX_FILE_BYTES:
                    self._skip("exceeds byte cap")
                    continue
                if b"\x00" in raw:
                    self._skip("binary")
                    continue
                project = self._project_of(rel)
                if project is None:
                    self._skip("outside declared projects")
                    continue
                language = _EXT_LANGUAGE.get(suffix, "manifest")
                self.files.append(IndexedFile(
                    rel=rel, project=project, language=language,
                    size=len(raw),
                    text=raw.decode("utf-8", errors="replace")))
        self.files.sort(key=lambda f: f.rel)

    # ---- retrieval -------------------------------------------------------------
    def manifests_for(self, project: str) -> list[IndexedFile]:
        root = project.strip("/")
        prefix = "" if root in ("", ".") else root + "/"
        out = [f for f in self.files
               if f.language == "manifest"
               and f.rel.startswith(prefix)
               and "/" not in f.rel[len(prefix):]]
        return sorted(out, key=lambda f: f.rel)

    def candidates_for(self, query: AuditQuery,
                       project: str) -> list[tuple[IndexedFile, list[int]]]:
        """Deterministically ranked candidate files for one query in one
        project, each with the 1-based line numbers of its symbol-hint
        matches. Only files with REAL hint evidence qualify — no filler."""
        acct = self.accounting.setdefault(
            f"{project}::{query.id}", QueryAccounting())
        scored: list[tuple[float, str, IndexedFile, list[int]]] = []
        for f in self.files:
            if f.project != project or f.language == "manifest":
                continue
            if f.language not in query.languages:
                acct.skip("language not covered by query")
                continue
            acct.eligible_files += 1
            path_l = f.rel.lower()
            score = sum(2.0 for h in query.path_hints if h in path_l)
            match_lines: list[int] = []
            for n, line in enumerate(f.text.splitlines(), start=1):
                if len(match_lines) >= _MATCH_SCAN_CAP:
                    break
                if any(h in line for h in query.symbol_hints):
                    match_lines.append(n)
            score += float(len(match_lines))
            if not match_lines:
                continue                    # no structural evidence — never filler
            scored.append((score, f.rel, f, match_lines))
        scored.sort(key=lambda t: (-t[0], t[1]))
        top = scored[:MAX_CANDIDATES_PER_QUERY]
        acct.candidate_files = len(top)
        if len(scored) > len(top):
            acct.skip("ranked below candidate cap", len(scored) - len(top))
        return [(f, lines) for _, _, f, lines in top]
