"""Rule Capability Catalog (W2-B2.7A).

A RuleDescriptor states what a rule CAN find — "tool capability at scan
time". It is NOT a claim that the rule executed in any particular scan;
execution recording is a separate, later contract (B).

Ownership: descriptors live NEXT TO the rule implementation (the module that
emits the finding) — never in a separate hand-maintained central table that
would drift. This module only defines the model, the validation, and the
conflict-safe merge; collection walks the ACTUAL owners.

Core neutrality: this module never imports adapter packages. Language-neutral
core rules declare languages=() and the collector fills them from the
registered adapters passed in by the caller (the CLI), so core still names no
language adapters.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Iterable, Protocol

CATALOG_SCHEMA_VERSION = 1

VALID_LEVELS = ("error", "warning", "note")
VALID_PRECISIONS = ("exact", "heuristic")
VALID_SCOPES = ("file", "project", "dependency", "module_graph", "external")
VALID_SOURCES = ("builtin", "semgrep-or-opengrep")


class CatalogConflict(Exception):
    """Two descriptors share a rule_id but disagree on semantics — the build
    must fail loudly, never last-write-wins."""


@dataclass(frozen=True)
class RuleDescriptor:
    rule_id: str
    title: str
    description: str
    category: str
    default_level: str                 # error / warning / note — no CVSS
    default_precision: str             # exact / heuristic
    engine: str
    # () on a core-neutral rule means "every registered language"; the
    # collector materializes the actual list from the adapters it is given.
    languages: tuple[str, ...] = ()
    frameworks: tuple[str, ...] = ()
    scope: str = "file"
    source: str = "builtin"

    def __post_init__(self) -> None:
        for name in ("rule_id", "title", "description", "category", "engine"):
            v = getattr(self, name)
            if not isinstance(v, str) or not v.strip():
                raise ValueError(f"descriptor {self.rule_id!r}: {name} must be a "
                                 "non-empty string")
        if self.default_level not in VALID_LEVELS:
            raise ValueError(f"{self.rule_id}: invalid default_level "
                             f"{self.default_level!r}")
        if self.default_precision not in VALID_PRECISIONS:
            raise ValueError(f"{self.rule_id}: invalid default_precision "
                             f"{self.default_precision!r}")
        if self.scope not in VALID_SCOPES:
            raise ValueError(f"{self.rule_id}: invalid scope {self.scope!r}")
        if self.source not in VALID_SOURCES:
            raise ValueError(f"{self.rule_id}: invalid source {self.source!r}")


class HasRuleDescriptors(Protocol):
    def grammars(self) -> dict[str, Any]: ...

    def rule_descriptors(self) -> list[RuleDescriptor]: ...


def _semantics(d: RuleDescriptor) -> tuple:
    """Everything that must MATCH for two same-id descriptors to merge —
    all fields except languages (which union)."""
    return (d.title, d.description, d.category, d.default_level,
            d.default_precision, d.engine, d.frameworks, d.scope, d.source)


def merge_catalog(descriptors: Iterable[RuleDescriptor]) -> list[RuleDescriptor]:
    """Deterministic merged catalog, sorted by rule_id. The same rule_id from
    several owners merges LANGUAGES only when every other field is identical;
    any semantic disagreement raises CatalogConflict."""
    merged: dict[str, RuleDescriptor] = {}
    for d in descriptors:
        prev = merged.get(d.rule_id)
        if prev is None:
            merged[d.rule_id] = d
            continue
        if _semantics(prev) != _semantics(d):
            raise CatalogConflict(
                f"conflicting descriptors for {d.rule_id}: "
                f"{_semantics(prev)} != {_semantics(d)}")
        langs = tuple(sorted(set(prev.languages) | set(d.languages)))
        merged[d.rule_id] = RuleDescriptor(**{**asdict(prev), "languages": langs})
    return [merged[k] for k in sorted(merged)]


def collect_catalog(adapters: Iterable[HasRuleDescriptors],
                    extra: Iterable[RuleDescriptor] = ()) -> list[dict[str, Any]]:
    """Assemble the full capability catalog:
    - core-owned rule families (hallucination engine, common pattern rules,
      complexity) — imported here from CORE modules only;
    - each adapter's own descriptors via its rule_descriptors() hook;
    - shipped semgrep/opengrep YAML rules;
    - `extra` for callers with additional owners.
    Language-neutral core rules (languages=()) are materialized against the
    registered adapter languages. Output is JSON-ready dicts, sorted, stable.
    """
    from auditor.core import complexity, hallucination, rules_common
    from auditor.core.semgrep_rules_meta import shipped_semgrep_descriptors

    adapters = list(adapters)
    # neutral fill source: every language name the registered adapters parse
    # (grammars() keys — includes tsx), still without core naming any adapter
    all_langs = tuple(sorted({lang for a in adapters for lang in a.grammars()}))
    collected: list[RuleDescriptor] = []
    for owner in (hallucination.DESCRIPTORS, rules_common.DESCRIPTORS,
                  complexity.DESCRIPTORS):
        collected.extend(owner)
    for a in adapters:
        collected.extend(a.rule_descriptors())
    collected.extend(shipped_semgrep_descriptors())
    collected.extend(extra)

    materialized = [
        RuleDescriptor(**{**asdict(d), "languages": all_langs})
        if not d.languages else d
        for d in collected
    ]
    merged = merge_catalog(materialized)
    # languages=() has exactly ONE meaning (core-neutral, pre-materialization);
    # nothing may leave the collector without concrete languages.
    empty = [d.rule_id for d in merged if not d.languages]
    if empty:
        raise CatalogConflict(f"descriptor(s) with empty languages after "
                              f"collection: {empty}")
    return [dict(asdict(d), languages=list(d.languages),
                 frameworks=list(d.frameworks))
            for d in merged]


def analysis_manifest(catalog: list[dict[str, Any]]) -> dict[str, Any]:
    """The report block. `catalog` semantics: TOOL CAPABILITY AT SCAN TIME —
    the rules this build ships and could apply; NOT proof any rule executed
    (execution status is a later, separate contract)."""
    return {"schema_version": CATALOG_SCHEMA_VERSION, "catalog": catalog}
