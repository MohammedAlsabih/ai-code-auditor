from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from auditor.core.models import (DeclaredDep, Finding, ImportRef, PackageInfo,
                                 Severity, SourceFile)
from auditor.registries.base import FRESH_DAYS, LOW_DOWNLOADS, age_days

_TITLES = {
    "H001": "Declared dependency not found in the public registry",
    "H002": "Undeclared import (package exists in registry)",
    "H003": "Dependency not verified (offline mode)",
    "H004": "Registry unreachable — dependency unverified",
    "H005": "Brand-new package with near-zero downloads",
    "H006": "Recently published package (< fresh threshold)",
    "H007": "Unverified undeclared import (unmappable, or probable-hallucination via a heuristic mapping)",
    "H008": "Undeclared import not found in the public registry",
    "H009": "Package quarantined by the registry (suspected malware)",
    "H010": "Not found in public registry — private source configured or scoped (unverifiable)",
    "H012": "Package archived by its owner (PEP 792 status)",
}
_SEV = {"H001": Severity.RED, "H002": Severity.YELLOW, "H003": Severity.BLUE,
        "H004": Severity.BLUE, "H005": Severity.YELLOW, "H006": Severity.YELLOW,
        "H007": Severity.YELLOW, "H008": Severity.RED, "H009": Severity.RED,
        "H010": Severity.YELLOW, "H012": Severity.BLUE}
# import→identifier mapping involved (H010 excluded: it is an "unverifiable /
# private-source" fact emitted on BOTH the declared and import paths, not a
# namespace-mapping confidence claim, so it stays precision=exact everywhere)
_MAPPING_RULES = {"H002", "H007", "H008"}


def _finding(rule_id: str, adapter, file: str, line: int, detail: str,
             snippet: str = "", trust: str | None = None) -> Finding:
    if rule_id == "H007":
        precision = "heuristic"   # H007 == "could not map reliably" => never exact
    elif rule_id in _MAPPING_RULES:
        # per-import trust (when the caller knows it) beats the adapter-wide
        # level; only a literal "exact" mapping prints exact — "heuristic" and
        # the weaker "guess" both serialize as heuristic (precision is a 2-value
        # field). The gating logic in _judge_import keys on the raw trust.
        raw = trust or str(getattr(adapter, "mapping_precision", "exact"))
        precision = "exact" if raw == "exact" else "heuristic"
    else:
        precision = "exact"
    return Finding(rule_id=rule_id, severity=_SEV[rule_id], title=_TITLES[rule_id],
                   file=file, line=line, snippet=snippet, detail=detail,
                   language=adapter.name, engine="auditor", precision=precision)


def _import_trust(adapter, imp: ImportRef) -> str:
    fn = getattr(adapter, "import_mapping_trust", None)
    return fn(imp) if callable(fn) else getattr(adapter, "mapping_precision", "exact")


def _bulk_lookup(registry, names: list[str]) -> dict[str, PackageInfo]:
    unique = sorted(set(names))
    if not unique:
        return {}

    def _safe(name: str) -> PackageInfo:
        try:
            return registry.lookup(name)
        except Exception as e:
            # one misbehaving client/name must never kill the whole audit —
            # it degrades to an unverified H004 with a visible reason
            return PackageInfo(exists=False,
                               error=f"lookup crashed: {e.__class__.__name__}")

    with ThreadPoolExecutor(max_workers=8) as pool:
        infos = list(pool.map(_safe, unique))
    return dict(zip(unique, infos))


def _record_parse_errors(files: list[SourceFile], diag) -> None:
    # partial parses must not read as complete analysis; record once, deduped
    for sf in files:
        tree = getattr(sf, "tree", None)
        if tree is not None and tree.root_node.has_error \
                and sf.rel not in diag.parse_error_files:
            diag.parse_error_files.append(sf.rel)


def _collect_checkable(declared: list[DeclaredDep]) -> list[DeclaredDep]:
    out, seen = [], set()
    for dep in declared:
        key = dep.name.lower()
        if key in seen or dep.skip_registry:
            continue
        seen.add(key)
        out.append(dep)
    return out


def _collect_externals(adapter, imports, declared) -> tuple[list[ImportRef], list[str]]:
    """(unmatched external imports, POTENTIAL PROVIDERS). A distribution can
    provide modules under any name (biopython->Bio), so any declared dep may be
    the true source of an unmatched import, and that possibility must temper
    H008 verdicts (CP-8.9)."""
    out: list[ImportRef] = []
    seen: set[str] = set()
    for imp in imports:
        if adapter.is_internal(imp):
            continue
        dep = adapter.match_declared(imp, declared)
        if dep is not None:
            continue
        # dedup by registry candidate(s); with no reliable mapping (shared
        # namespace) fall back to the FULL module so distinct distributions under
        # one namespace (google.cloud.storage vs .bigquery) are not merged
        cands = adapter.registry_candidates(imp)
        key = ("|".join(cands) if cands else imp.module).lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(imp)
    # CP-8.9: a declared distribution matched by ONE import may ALSO provide
    # OTHER top-level modules (biopython -> Bio AND Bio.SeqIO; a single wheel,
    # many modules). So matching one import must NOT remove it from the provider
    # pool for a sibling import — EVERY declared dep is a potential provider
    # (registry-dead ghosts are filtered later by audit_hallucinations).
    providers = sorted({d.name for d in declared})
    return out, providers


def audit_hallucinations(adapter, root: Path, files: list[SourceFile],
                         declared: list[DeclaredDep], registry,
                         diag=None) -> list[Finding]:
    findings: list[Finding] = []
    imports = adapter.extract_imports(files)
    if diag is not None:
        _record_parse_errors(files, diag)
    checkable = _collect_checkable(declared)
    externals, providers = _collect_externals(adapter, imports, declared)

    if registry is None:
        for dep in checkable:
            findings.append(_finding("H003", adapter, dep.source_file, dep.line,
                                     f"{dep.name}: registry check skipped (--offline)", dep.raw))
        for imp in externals:
            findings.append(_finding("H007", adapter, imp.file, imp.line,
                                     f"{imp.top_level or imp.module}: imported but not declared; "
                                     "registry check skipped (--offline)", imp.module))
        return _sorted(findings)

    private_reason = adapter.private_registry_reason(root)

    dep_infos = _bulk_lookup(registry, [d.lookup_name for d in checkable])
    for dep in checkable:
        info = dep_infos[dep.lookup_name]
        findings += _judge_declared(adapter, dep, info, private_reason)
    if private_reason is None:
        # a declared dep CONFIRMED absent from the registry (an H001 ghost)
        # cannot be installed, so it cannot provide any module — it must not
        # soften an H008 verdict. With a private source it stays a candidate.
        dead = {d.name for d in checkable
                if (i := dep_infos[d.lookup_name]).error is None and not i.exists}
        providers = [p for p in providers if p not in dead]

    cand_names = sorted({c for imp in externals for c in adapter.registry_candidates(imp)})
    cand_infos = _bulk_lookup(registry, cand_names)
    for imp in externals:
        findings += _judge_import(adapter, imp, cand_infos, private_reason, providers)
    if diag is not None:
        # count UNIQUE lookups and their failures, not H004 findings — a single
        # crashed candidate shared by N imports must not inflate the failure
        # count past attempted (which would drive rule_health/confidence wrong)
        unique = {**dep_infos, **cand_infos}
        diag.registry_attempted += len(unique)
        diag.registry_failures += sum(1 for i in unique.values() if i.error)
    return _sorted(findings)


def _ambiguity(adapter, name: str, private_reason: str | None) -> str | None:
    # registry-neutral: a private-source reason (project config) OR the adapter's
    # own ecosystem-specific hint — core stays free of per-ecosystem logic
    return private_reason or adapter.unresolvable_hint(name)


def _judge_declared(adapter, dep: DeclaredDep, info: PackageInfo,
                    private_reason: str | None) -> list[Finding]:
    name = dep.lookup_name
    if info.error:
        return [_finding("H004", adapter, dep.source_file, dep.line,
                         f"{name}: {info.error}", dep.raw)]
    if not info.exists:
        reason = _ambiguity(adapter, name, private_reason)
        if reason:
            return [_finding("H010", adapter, dep.source_file, dep.line,
                             f"{name} was not found in the public {adapter.ecosystem} registry, "
                             f"but {reason} — cannot verify; if this name is NOT served by your "
                             "private source, it is dependency-confusion exposure.", dep.raw)]
        if getattr(dep, "presence", "definite") != "definite":
            # CP-8b round 8: the declaration is under an UNRESOLVED condition —
            # a definitive RED "declared (fact)" H001 is not justified. Surface a
            # YELLOW H007 probable/unverified instead (the manifest is already
            # flagged incomplete by the adapter).
            return [_finding("H007", adapter, dep.source_file, dep.line,
                             f"{name} is declared only under an unresolved build condition and "
                             f"was NOT found in the public {adapter.ecosystem} registry — probable "
                             "hallucination, but its presence is conditional (unverified).",
                             dep.raw)]
        return [_finding("H001", adapter, dep.source_file, dep.line,
                         f"{name} is declared in {dep.source_file} but was NOT found in the "
                         f"public {adapter.ecosystem} registry queried at scan time (fact). "
                         "Likely causes: AI-hallucinated name (unregistered names are "
                         "claimable — slopsquatting), a registry-removed/quarantined package, "
                         "or a source this scan cannot see.", dep.raw)]
    # the package EXISTS — its security state (quarantine/archive/newness) is
    # reported regardless of definite/possible (a dangerous package must never be
    # hidden just because its declaration is conditional)
    return _status_findings(adapter, info, dep.source_file, dep.line, name, dep.raw)


def _status_findings(adapter, info: PackageInfo, file: str, line: int,
                     label: str, raw: str) -> list[Finding]:
    """Security/freshness state of an EXISTING package — shared by the declared
    and the undeclared-import paths so an import being undeclared never hides the
    package's quarantine/archive/newness signal."""
    if info.quarantined:
        return [_finding("H009", adapter, file, line,
                         f"{label} is quarantined by the registry (suspected malware).", raw)]
    if info.archived:
        return [_finding("H012", adapter, file, line,
                         f"{label} is archived by its owner (no future updates expected).", raw)]
    if info.created and age_days(info.created) < FRESH_DAYS:
        threshold = LOW_DOWNLOADS.get(info.downloads_period, 500)
        if info.downloads is not None and info.downloads < threshold:
            return [_finding("H005", adapter, file, line,
                             f"{label} first published {info.created[:10]} with only "
                             f"{info.downloads} {info.downloads_period} downloads.", raw)]
        return [_finding("H006", adapter, file, line,
                         f"{label} first published {info.created[:10]} "
                         f"(younger than {FRESH_DAYS} days).", raw)]
    return []


def _provider_hint(providers: list[str]) -> str:
    shown = ", ".join(providers[:3]) + (", …" if len(providers) > 3 else "")
    return (f" A declared-but-unmatched distribution ({shown}) may be the real "
            "provider of this module — verify before treating it as undeclared.")


def _unverified_provider_note(providers: list[str]) -> str:
    shown = ", ".join(providers[:3]) + (", …" if len(providers) > 3 else "")
    return (f" UNVERIFIED: declared distribution(s) ({shown}) could not be linked to "
            "this import, but a single distribution can ship modules under other "
            "names — if one provides this module, this red is a false positive. "
            "This is a heuristic, not a proof.")


def _judge_import_exists(adapter, imp: ImportRef, label: str, exists_name: str,
                         existing: PackageInfo, trust: str,
                         providers: list[str]) -> list[Finding]:
    # keep the undeclared FACT (H002) AND surface the package's security
    # state (quarantine/archive/newness) — undeclared must not hide risk
    detail = (f"{label}: imported but not declared in the manifest "
              f"(exists in registry as '{exists_name}').")
    if trust != "exact" and providers:
        detail += _provider_hint(providers)
    return [_finding("H002", adapter, imp.file, imp.line, detail, imp.module,
                     trust=trust)] \
        + _status_findings(adapter, existing, imp.file, imp.line, label, imp.module)


def _judge_import(adapter, imp: ImportRef, cand_infos: dict[str, PackageInfo],
                  private_reason: str | None, providers: list[str]) -> list[Finding]:
    label = imp.top_level or imp.module
    cands = adapter.registry_candidates(imp)
    trust = _import_trust(adapter, imp)
    if not cands:
        return [_finding("H007", adapter, imp.file, imp.line,
                         f"{label}: imported but not declared; no reliable mapping to a "
                         f"{adapter.ecosystem} identifier (accuracy limit — verify manually)."
                         + (_provider_hint(providers) if providers else ""),
                         imp.module)]
    infos = [cand_infos[c] for c in cands if c in cand_infos]
    if any(i.exists for i in infos):
        idx = [i.exists for i in infos].index(True)
        exists_name = [c for c in cands if c in cand_infos][idx]
        return _judge_import_exists(adapter, imp, label, exists_name, infos[idx],
                                    trust, providers)
    if any(i.error for i in infos):
        return [_finding("H004", adapter, imp.file, imp.line,
                         f"{label}: {next(i.error for i in infos if i.error)}", imp.module)]
    reason = _ambiguity(adapter, label, private_reason)
    if reason:
        return [_finding("H010", adapter, imp.file, imp.line,
                         f"{label}: imported but not declared, and not found in the public "
                         f"registry — {reason}; cannot verify.", imp.module)]
    if trust == "guess":
        # CP-8.3: the candidate came from a GENERIC structural guess (e.g. a
        # .NET namespace -> first-two-segments), with no curated/authoritative
        # map behind it. A definitive RED is never justified — a red H008
        # requires an authoritative mapping.
        return [_finding("H007", adapter, imp.file, imp.line,
                         f"{label}: imported but not declared; the registry id was only "
                         f"guessed from the namespace ({', '.join(cands)}) and is absent "
                         "(accuracy limit — verify manually)."
                         + (_provider_hint(providers) if providers else ""), imp.module)]
    # PRODUCT CONTRACT (CP-8b round 3): verdict() blocks on ANY red and does not
    # read precision, so a "heuristic red" was still a definitive block. The
    # definitive RED H008 therefore requires an EXACT (authoritative) mapping.
    # A heuristic (convention) mapping with an absent name yields a YELLOW
    # probable-hallucination H007 — it always SURFACES for review (never
    # silently suppressed by a declared dep) but never blocks on a guess.
    if trust != "exact":
        detail = (f"{label}: imported but not declared, and the conventional name "
                  f"({', '.join(cands)}) is absent from the registry — PROBABLE "
                  "AI-hallucinated import (unverified: the mapping is a naming "
                  "convention, not a proof; the unregistered name is claimable).")
        if providers:
            detail += _unverified_provider_note(providers)
        return [_finding("H007", adapter, imp.file, imp.line, detail, imp.module)]
    return [_finding("H008", adapter, imp.file, imp.line,
                     f"{label}: imported but not declared AND not found in the public "
                     f"{adapter.ecosystem} registry (candidates tried: {', '.join(cands)}). "
                     "Likely an AI-hallucinated import; the unregistered name is claimable "
                     "(slopsquatting).", imp.module, trust=trust)]


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (f.file, f.line, f.rule_id))
