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
