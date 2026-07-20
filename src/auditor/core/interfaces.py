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
    # True (default): the check reads sf.tree and cannot run if parsing failed.
    # False: the check reads only sf.text, so a parse failure does NOT block it.
    # Declared explicitly per rule — never inferred from the rule name or from
    # whether it happens to touch sf.tree.
    requires_syntax_tree: bool = True

    @property
    def output_ids(self) -> tuple[str, ...]:
        """EVERY rule_id this check can emit — declared, never inferred from
        findings (zero findings must still prove all declared ids ran).
        Multi-output checks override with a class attribute."""
        return (self.id,)

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
    _repo_root = None   # repository root; the confinement boundary. A shared file
    #                     elsewhere in the SAME repo is legitimate — only paths
    #                     resolving OUTSIDE the repo are refused (CP-8.2). Falls
    #                     back to the per-project scan_root when unset.

    def set_repo_root(self, path: Path) -> None:
        self._repo_root = path.resolve()

    # ── project configuration hooks (W2-B2.8A) ──────────────────────────────
    _config_internal: tuple[str, ...] = ()   # user-declared internal names/prefixes

    def apply_config(self, config) -> None:
        """Consume the loaded AuditorConfig. The base stores this ecosystem's
        internal package names/prefixes; adapters extend for runtime builtins
        and npm roots. Core stays neutral: `config` is plain data."""
        self._config_internal = tuple(
            config.internal_packages.get(self.ecosystem, ()))

    def _config_internal_match(self, name: str) -> bool:
        """User-declared internal package: exact name, or a prefix on a real
        component boundary ('.', '/', or npm-scope) — 'acme' never swallows
        'acmex'."""
        for p in self._config_internal:
            if name == p or name.startswith(p + ".") or name.startswith(p + "/"):
                return True
        return False

    def dependency_audit_reason(self, root: Path) -> str | None:
        """None => the dependency hallucination audit applies to this project.
        A string => the audit is NOT APPLICABLE here (the reason is recorded in
        the execution ledger; code rules still run). A file suffix alone never
        proves registry ownership — adapters override where a legal package
        root is required (npm)."""
        return None

    def _confinement_root(self):
        return getattr(self, "_repo_root", None) or getattr(self, "_scan_root", None)

    def _config_search_dirs(self, root: Path):
        """The project dir plus every ancestor up to (and including) the
        repository root — so a repo-level .npmrc/settings above the project is
        found (CP-8.2). Without a repo root, only the project dir."""
        root = root.resolve()
        yield root
        repo = getattr(self, "_repo_root", None)
        if repo and repo != root and repo in root.parents:
            cur = root.parent
            while True:
                yield cur
                if cur == repo:
                    break
                cur = cur.parent

    @abstractmethod
    def detect(self, root: Path) -> bool: ...

    @abstractmethod
    def parse_dependencies(self, root: Path, diag=None) -> list[DeclaredDep]:
        """Adapters MUST: set `self._diag = diag` first, read every manifest via
        `self._read(path)` (capped + unreadable-safe), and report parse failures
        via `self._manifest_error(path, err)` — a corrupt manifest yields [] PLUS
        a diagnostics entry, never a silent []."""

    @staticmethod
    def _canon(path: Path) -> str:
        """The CANONICAL full-path identity for a manifest file (CP-8b.5). All
        three ledgers (files / errors / incomplete) key on this same spelling, so
        two same-named files in different monorepo projects (services/a/setup.py
        vs services/b/setup.py) stay distinct AND a file that both errors and is
        incomplete unions to one."""
        try:
            return path.resolve().as_posix()
        except OSError:
            return path.as_posix()

    def _read(self, path: Path) -> str:
        from auditor.core.walk import read_text_capped
        # CENTRAL symlink-escape guard (verified empirically under WSL): a
        # manifest whose RESOLVED location is outside the REPOSITORY root (a
        # symlink escaping the repo) is refused, with a ledger entry. A shared
        # file elsewhere in the same repo is allowed (CP-8.2).
        root = self._confinement_root()
        if root is not None:
            try:
                rp = path.resolve()
            except OSError:
                rp = path
            if rp != root and root not in rp.parents:
                if self._diag is not None:
                    msg = (f"{self._canon(path)}: resolves outside the repository "
                           "root (symlink?) — NOT read")
                    if msg not in self._diag.manifest_errors:
                        self._diag.manifest_errors.append(msg)
                return ""
        if self._diag is not None:
            key = self._canon(path)
            if key not in self._diag.manifest_files:   # UNIQUE files, not read ops
                self._diag.manifest_files.append(key)
        return read_text_capped(path, self._diag, canon=self._canon(path))

    def _manifest_error(self, path: Path, err: Exception) -> None:
        if self._diag is not None:
            # canonical full path: two broken pyproject.toml in different monorepo
            # roots must be TWO errors over TWO files, not collapsed by name
            msg = f"{self._canon(path)}: {err.__class__.__name__}"
            if msg not in self._diag.manifest_errors:   # one entry per broken file
                self._diag.manifest_errors.append(msg)

    def _note(self, message: str) -> None:
        if self._diag is not None and message not in self._diag.notes:
            self._diag.notes.append(message)

    def _mark_incomplete(self, path: Path) -> None:
        """Record a manifest whose extraction was partial, keyed on its CANONICAL
        full path so monorepo same-named manifests never collapse (CP-8b.5)."""
        if self._diag is None:
            return
        key = self._canon(path)
        if key not in self._diag.manifest_incomplete:
            self._diag.manifest_incomplete.append(key)

    def _schema_note(self, path: Path, what: str) -> None:
        """A schema-invalid manifest section was skipped: never silent, and the
        manifest counts as partially extracted."""
        self._note(f"{path.name}: unexpected schema for {what} — section skipped")
        self._mark_incomplete(path)

    def _include_gap(self, including: Path, message: str) -> None:
        """A manifest referenced an include that was missing or escaped the
        repository — an INCOMPLETELY-read manifest. Recorded in include_gaps
        (named in the report) AND folded into manifest_incomplete so the numeric
        confidence drops and the verdict cannot PASS (CP-8.1)."""
        self._note(message)
        if self._diag is not None and message not in self._diag.include_gaps:
            self._diag.include_gaps.append(message)
        self._mark_incomplete(including)

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

    def rule_descriptors(self):
        """Rule Capability Catalog hook: the descriptors this adapter's
        package OWNS (defined next to the rule implementations). Capability
        only — never an execution claim. Core stays neutral: the base returns
        nothing and never names adapters."""
        return []

    def language_rules(self) -> list[Rule]:
        return []

    def project_rules(self, root: Path, frameworks: list[str],
                      ledger=None, diag=None) -> list[Finding]:
        """Project-level checks that need the root, not a single source file
        (e.g. .env scanning, stdlib-drift, module-graph). Core calls this and
        never imports adapter modules. An adapter that runs project passes
        records its OWN execution evidence into `ledger`/`diag` (B2-B); the
        base has no passes, so it records nothing."""
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
