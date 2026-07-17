from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from auditor.core.models import DeclaredDep, Finding, ImportRef, Severity, SourceFile


class Rule(ABC):
    id: str
    severity: Severity
    title: str
    frameworks: tuple[str, ...] = ()   # () = applies regardless of framework
    precision: str = "exact"           # "exact" | "heuristic" — printed in reports

    @abstractmethod
    def check(self, sf: SourceFile) -> list[Finding]: ...


@dataclass(frozen=True)
class SyntaxProfile:
    """Language-specific syntax knowledge, supplied BY the adapter TO core rules.
    Core never branches on language names — it consumes this profile."""
    catch_query: str = ""                       # e.g. "(catch_clause) @c" / "(except_clause) @c"
    catch_body_types: tuple[str, ...] = ("block", "statement_block")
    comment_types: tuple[str, ...] = ("comment", "line_comment", "block_comment")
    # a statement that swallows silently even though the body is non-empty (python: pass/...)
    is_swallow_stmt: Callable[[object], bool] = staticmethod(lambda node: False)
    sql_concat_query: str = ""                  # binary/concat node query, "" = skip
    sql_interp_query: str = ""                  # interpolated/template string query, "" = skip
    sql_dynamic_types: tuple[str, ...] = ()     # node types proving dynamic content
    sql_sink_call_types: tuple[str, ...] = (
        "call", "call_expression", "invocation_expression",
        "method_invocation", "object_creation_expression")


class LanguageAdapter(ABC):
    name: str                          # "python" | "typescript" | "java" | "dotnet"
    ecosystem: str                     # "pypi" | "npm" | "maven" | "nuget"
    source_globs: tuple[str, ...]      # file suffixes, e.g. (".py",)
    # "exact" when import names ARE registry identifiers (python via canonical
    # names, npm literally); "heuristic" when curated prefix/namespace maps are
    # involved (java, dotnet) — stamped onto H002/H007/H008/H010 findings.
    mapping_precision: str = "exact"

    _diag = None   # set by parse_dependencies(diag=...); manifest helpers report into it

    @abstractmethod
    def detect(self, root: Path) -> bool: ...

    @abstractmethod
    def parse_dependencies(self, root: Path, diag=None) -> list[DeclaredDep]:
        """Adapters MUST: set `self._diag = diag` first, read every manifest via
        `self._read(path)` (capped + unreadable-safe), and report parse failures
        via `self._manifest_error(path, err)` — a corrupt manifest yields [] PLUS
        a diagnostics entry, never a silent []."""

    def _read(self, path: Path) -> str:
        from auditor.core.walk import read_text_capped
        # CENTRAL symlink-escape guard (verified empirically under WSL): a
        # manifest whose RESOLVED location is outside the scan root (a symlink
        # planted inside the repo) is refused, with a ledger entry — adapters
        # that set self._scan_root get this for free on every manifest read.
        scan_root = getattr(self, "_scan_root", None)
        if scan_root is not None:
            try:
                rp = path.resolve()
            except OSError:
                rp = path
            if rp != scan_root and scan_root not in rp.parents:
                if self._diag is not None:
                    msg = (f"{path.as_posix()}: resolves outside the scan root "
                           "(symlink?) — NOT read")
                    if msg not in self._diag.manifest_errors:
                        self._diag.manifest_errors.append(msg)
                return ""
        if self._diag is not None:
            key = str(path)
            if key not in self._diag.manifest_files:   # UNIQUE files, not read ops
                self._diag.manifest_files.append(key)
        return read_text_capped(path, self._diag)

    def _manifest_error(self, path: Path, err: Exception) -> None:
        if self._diag is not None:
            # FULL path, not path.name: two broken pyproject.toml in different
            # monorepo roots must be TWO errors over TWO files (=> manifest
            # coverage 0), not collapsed to one by name (fifth-round)
            msg = f"{path.as_posix()}: {err.__class__.__name__}"
            if msg not in self._diag.manifest_errors:   # one entry per broken file
                self._diag.manifest_errors.append(msg)

    def _note(self, message: str) -> None:
        if self._diag is not None and message not in self._diag.notes:
            self._diag.notes.append(message)

    def _mark_incomplete(self, path: Path) -> None:
        """Record a manifest whose extraction was partial (drives
        analysis_confidence to 'partial')."""
        if self._diag is None:
            return
        rel = path.name
        scan_root = getattr(self, "_scan_root", None)
        if scan_root is not None:
            try:
                rel = path.resolve().relative_to(scan_root).as_posix()
            except (ValueError, OSError):
                pass
        if rel not in self._diag.manifest_incomplete:
            self._diag.manifest_incomplete.append(rel)

    def _schema_note(self, path: Path, what: str) -> None:
        """A schema-invalid manifest section was skipped: never silent, and the
        manifest counts as partially extracted."""
        self._note(f"{path.name}: unexpected schema for {what} — section skipped")
        self._mark_incomplete(path)

    @abstractmethod
    def extract_imports(self, files: list[SourceFile]) -> list[ImportRef]: ...

    @abstractmethod
    def match_declared(self, imp: ImportRef, declared: list[DeclaredDep]) -> DeclaredDep | None: ...

    @abstractmethod
    def registry_candidates(self, imp: ImportRef) -> list[str]: ...

    @abstractmethod
    def is_internal(self, imp: ImportRef) -> bool:
        """True for stdlib/builtin/local-to-repo imports. Uses state built in prepare()."""

    @abstractmethod
    def grammars(self) -> dict[str, object]:
        """language-name -> grammar pointer (wheel .language() PyCapsule).
        The adapter OWNS its grammar imports; core/treesitter just registers them."""

    @abstractmethod
    def syntax(self) -> SyntaxProfile:
        """Syntax knowledge consumed by core common rules."""

    def prepare(self, root: Path, files: list[SourceFile]) -> None:
        """Build per-project state (local modules, aliases, own namespaces)."""

    def frameworks(self, root: Path, declared: list[DeclaredDep]) -> list[str]:
        return []

    def language_rules(self) -> list[Rule]:
        return []

    def project_rules(self, root: Path, frameworks: list[str]) -> list[Finding]:
        """Project-level checks that need the root, not a single source file
        (e.g. .env scanning). Core calls this; core never imports adapter modules."""
        return []

    def private_registry_reason(self, root: Path) -> str | None:
        """Non-None when the project configures a custom/private package source
        (=> missing packages become H010, not H001/H008)."""
        return None

    def import_mapping_trust(self, imp: ImportRef) -> str:
        """Per-IMPORT mapping confidence: "exact" only when the import→registry
        mapping for THIS import is authoritative (curated alias table, literal
        identity as in npm paths); "heuristic" when it rests on a naming
        convention. Gates the definitive RED H008 on the import path — a
        convention guess must never produce a red "hallucinated" verdict that a
        declared distribution could explain. Default: the adapter-wide level."""
        return self.mapping_precision

    def unresolvable_hint(self, identifier: str) -> str | None:
        """Ecosystem-specific reason a not-found identifier might still be valid
        rather than hallucinated (e.g. an npm private scope `@corp/x` that 404s
        without auth). Default: none. Keeps scoped/private semantics in the
        adapter so core/hallucination.py stays registry-neutral."""
        return None

    def ensure_grammars(self) -> None:
        """Idempotent: registers this adapter's grammars with core/treesitter.
        Adapters call it at the top of prepare()/extract_imports() so direct
        adapter usage (tests, library callers) never hits an unregistered grammar."""
        from auditor.core import treesitter
        treesitter.register_adapters([self])

    def file_language(self, path: Path) -> str:
        return self.name
