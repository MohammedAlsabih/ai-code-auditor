from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    RED = "red"
    YELLOW = "yellow"
    BLUE = "blue"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    title: str
    file: str            # repo-relative posix path ("src/app.py")
    line: int            # 1-based; 0 = project-level finding
    snippet: str = ""
    detail: str = ""
    language: str = ""
    engine: str = "auditor"
    precision: str = "exact"     # "exact" | "heuristic" — serialized into reports


@dataclass(frozen=True)
class DeclaredDep:
    name: str            # import-matching identifier: pypi/npm/nuget name, or "group:artifact"
    ecosystem: str       # "pypi" | "npm" | "maven" | "nuget"
    source_file: str
    line: int = 0
    raw: str = ""
    skip_registry: bool = False   # workspace:/file:/git+/unresolved-property deps
    registry_name: str = ""       # npm alias "foo": "npm:bar@^1" => name=foo, registry_name=bar

    @property
    def lookup_name(self) -> str:
        return self.registry_name or self.name


@dataclass(frozen=True)
class ImportRef:
    module: str          # as written: "yaml", "com.foo.bar.Baz", "@scope/pkg/sub"
    file: str
    line: int
    top_level: str = ""  # lookup root: "yaml", "com.foo.bar", "@scope/pkg"


@dataclass
class SourceFile:
    path: Path
    rel: str             # posix, relative to project root
    language: str        # "python" | "java" | "csharp" | "typescript" | "tsx"
    text: bytes
    tree: object | None = None   # tree_sitter.Tree, filled lazily


@dataclass
class PackageInfo:
    exists: bool
    created: str | None = None          # ISO-8601 of first publish
    latest: str | None = None           # ISO-8601 of latest publish
    downloads: int | None = None
    downloads_period: str = "weekly"    # "weekly" | "total"
    quarantined: bool = False           # PEP 792 status == "quarantined"
    archived: bool = False              # PEP 792 status == "archived"
    error: str | None = None            # network failure => existence unknown


@dataclass
class Diagnostics:
    """Per-project analysis-completeness ledger. Everything here surfaces in
    report.json (`diagnostics`) and the limitations section — no silent failures."""
    manifest_errors: list[str] = field(default_factory=list)   # "pom.xml: ParseError ..." (unique per file)
    manifest_files: list[str] = field(default_factory=list)    # UNIQUE manifest paths read (denominator)
    skipped_files: list[str] = field(default_factory=list)     # "big.py: exceeds 1.5MB"
    parse_error_files: list[str] = field(default_factory=list)
    rule_errors: list[str] = field(default_factory=list)       # "R005 on x.tsx: KeyError"
    rule_attempted: int = 0                                    # rule.check invocations
    rule_failures: int = 0                                     # invocations that raised
    registry_attempted: int = 0                                # unique lookups issued
    registry_failures: int = 0                                 # lookups ending in H004
    semgrep_status: str = "not attempted"
    notes: list[str] = field(default_factory=list)

    def merge(self, other: "Diagnostics") -> None:
        self.manifest_errors += [e for e in other.manifest_errors
                                 if e not in self.manifest_errors]
        self.manifest_files += [f for f in other.manifest_files
                                if f not in self.manifest_files]
        self.skipped_files += other.skipped_files
        self.parse_error_files += other.parse_error_files
        self.rule_errors += other.rule_errors
        self.rule_attempted += other.rule_attempted
        self.rule_failures += other.rule_failures
        self.registry_attempted += other.registry_attempted
        self.registry_failures += other.registry_failures
        self.notes += other.notes
