"""REAL-CORPUS-1A: profile the AI AUDIT packer, on its own terms.

This module exists because the two context paths in this product are not the
same thing and must never be measured against each other's limits:

* **single-finding review** — `auditor.ai.review.build_context_pack`, anchored
  on one emitted finding, bounded by that packer's own `PACK_MAX_BYTES`.
* **repository audit** — `auditor.ai.audit.build_audit_pack`, anchored on a
  (project, query) pair, bounded by the query's OWN `max_context_bytes`:
  AI001 is 16384 and AI002-AI008 are 12288.

The first closing round measured review packs against 12288 — a number that
belongs to the audit queries and to nothing in the review packer. The same
6302-byte pack buckets as `medium` against 12288 and `small` against its real
24576 cap, so the reported distribution was an artefact of the borrowed
number.

Nothing here imports the review packer, and nothing here explains an audit
pack's size by a review-packer limit. No model is contacted and no transport
is constructed: this assembles packs and measures them.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from auditor.ai.audit import AuditContextError, build_audit_pack
from auditor.ai.audit_index import RepositoryAuditIndex
from auditor.ai.audit_queries import AUDIT_QUERIES, query_by_id
from tools.real_corpus import RepoSpec, sample_id

# Size buckets are a fraction of THE QUERY'S OWN cap, never a shared constant.
SIZE_BUCKETS = (("small", 0.0, 0.50), ("medium", 0.50, 0.80),
                ("large", 0.80, 1.00))


class AuditProfilingError(Exception):
    """The profile cannot be built or trusted. Fail closed."""


@dataclass(frozen=True)
class AuditPackProfile:
    """One (repository, project, query) pack, measured.

    `pack_bytes` is the length of the canonical UTF-8 text that would be
    sent — the same bytes the digest covers — and nothing else."""

    profile_id: str
    repo_id: str
    project: str
    language: str
    query_id: str
    query_version: int
    cap_bytes: int                  # the query's own max_context_bytes
    pack_bytes: int                 # canonical UTF-8 bytes of the final pack
    source_bytes: int               # only the source/manifest text
    size_bucket: str
    files_sent: int
    pieces_sent: int

    def public(self) -> dict[str, Any]:
        """Counts and categories. No path, no code, no pack."""
        return {"profile_id": self.profile_id, "repo_id": self.repo_id,
                "language": self.language, "query_id": self.query_id,
                "query_version": self.query_version,
                "cap_bytes": self.cap_bytes, "pack_bytes": self.pack_bytes,
                "source_bytes": self.source_bytes,
                "size_bucket": self.size_bucket,
                "files_sent": self.files_sent,
                "pieces_sent": self.pieces_sent}


def source_text_bytes(pack: dict[str, Any]) -> int:
    """The bytes the query's cap ACTUALLY governs.

    `AuditQuery.max_context_bytes` bounds `total_src_bytes` — the source and
    manifest text — not the whole canonical pack, which also carries the query
    piece, its decision contract, and the unresolved-reference piece. So a
    pack's canonical size can legitimately exceed its cap, and does. Both
    numbers are recorded rather than one being quietly substituted for the
    other; the summary says which is which."""
    total = 0
    for piece in pack.get("pieces", []):
        cid = str(piece.get("context_id", ""))
        if cid.startswith(("src:", "manifest")):
            total += len(str(piece.get("text", "")).encode("utf-8"))
    return total


def audit_size_bucket(pack_bytes: int, cap_bytes: int) -> str:
    """Which bucket a pack falls in, against ITS OWN query cap."""
    if cap_bytes <= 0:
        raise AuditProfilingError("a query cap must be positive")
    fraction = pack_bytes / cap_bytes
    for name, low, high in SIZE_BUCKETS:
        if low <= fraction < high or (name == "large" and fraction >= high):
            return name
    return "large"


def project_roots(report: dict[str, Any]) -> list[tuple[str, str]]:
    """(root, language) exactly as the report declares them — the index takes
    the report's own projects, not a guess from the tree."""
    out: list[tuple[str, str]] = []
    for project in report.get("projects", []):
        if not isinstance(project, dict):
            continue
        root = project.get("root")
        language = project.get("language")
        if isinstance(root, str) and isinstance(language, str) and root:
            out.append((root, language))
    return sorted(set(out))


CATALOG_LANGUAGES = frozenset(
    lang for query in AUDIT_QUERIES for lang in query.languages)


def unsupported_languages(report: dict[str, Any]) -> dict[str, int]:
    """Project languages the report declares that NO query supports.

    This is not bookkeeping. The scanner names .NET projects `dotnet` and the
    audit catalog names its queries for `csharp`, so on this corpus every .NET
    project produces zero legal pairs and the audit path never runs on it at
    all — serilog produced no pack of any kind. A profile that only reported
    the packs it did build would show that as silence."""
    out: dict[str, int] = {}
    for _root, language in project_roots(report):
        if language not in CATALOG_LANGUAGES:
            out[language] = out.get(language, 0) + 1
    return out


def legal_pairs(report: dict[str, Any]
                ) -> list[tuple[str, str, str]]:
    """Every (project, language, query_id) the catalog actually supports.

    A query is legal for a project when the catalog lists the project's
    language. Running an unsupported pair would measure a refusal, not a
    pack."""
    pairs: list[tuple[str, str, str]] = []
    for root, language in project_roots(report):
        for query in AUDIT_QUERIES:
            if language in query.languages:
                pairs.append((root, language, query.id))
    return sorted(pairs)


def profile_repository(spec: RepoSpec, tree: Path, report: dict[str, Any],
                       *, skips: dict[str, int] | None = None
                       ) -> list[AuditPackProfile]:
    """Assemble the real audit pack for every legal (project, query).

    A pair with no genuine candidates returns None from the packer — that is
    an honest skip and is COUNTED, never replaced with filler. A pair whose
    context cannot be reduced under its budget raises, and is counted too."""
    roots = project_roots(report)
    if not roots:
        return []
    index = RepositoryAuditIndex(tree, roots)
    out: list[AuditPackProfile] = []
    for project, language, query_id in legal_pairs(report):
        query = query_by_id(query_id)
        if query is None:                       # catalog changed under us
            raise AuditProfilingError(f"unknown query {query_id!r}")
        try:
            pack = build_audit_pack(index, project, query)
        except AuditContextError:
            if skips is not None:
                skips["irreducible past the query budget"] = \
                    skips.get("irreducible past the query budget", 0) + 1
            continue
        if pack is None:
            if skips is not None:
                skips["no real candidate files for this query"] = \
                    skips.get("no real candidate files for this query", 0) + 1
            continue
        pack_bytes = len(str(pack["canonical"]).encode("utf-8"))
        cap = query.max_context_bytes
        manifest = pack.get("privacy_manifest") or {}
        # The bucket follows the SOURCE bytes, because that is the quantity
        # the query's cap bounds. Bucketing the canonical total against a
        # source cap is the same category error this round removed from the
        # review path — it would put every pack in `large` by construction.
        out.append(AuditPackProfile(
            profile_id=sample_id(spec.repo_id, f"{project}:{query.id}"),
            repo_id=spec.repo_id,
            project=project,
            language=language,
            query_id=query.id,
            query_version=query.query_version,
            cap_bytes=cap,
            pack_bytes=pack_bytes,
            source_bytes=source_text_bytes(pack),
            size_bucket=audit_size_bucket(source_text_bytes(pack), cap),
            files_sent=int(manifest.get("files_sent", 0)),
            pieces_sent=int(manifest.get("pieces_sent", len(pack["pieces"]))),
        ))
    return out


def _dist(items: Iterable[Any], key: Any) -> dict[str, int]:
    out: dict[str, int] = {}
    for item in items:
        k = str(key(item))
        out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items()))


def audit_summary(profiles: list[AuditPackProfile], skips: dict[str, int],
                  unsupported: dict[str, int] | None = None
                  ) -> dict[str, Any]:
    """The committable view of the audit path. Its denominator is packs —
    NOT findings and NOT blind units — and it is reported on its own."""
    unsupported = dict(sorted((unsupported or {}).items()))
    if not profiles:
        return {"packs": 0, "skipped": dict(sorted(skips.items())),
                "project_languages_no_query_supports": unsupported,
                "note": "no legal (project, query) pair produced a pack"}
    sizes = sorted(p.pack_bytes for p in profiles)
    src = sorted(p.source_bytes for p in profiles)
    caps = sorted({p.cap_bytes for p in profiles})
    return {
        "what": "auditor.ai.audit.build_audit_pack. This denominator is PACKS "
                "— not findings and not blind units — and nothing here is "
                "added to either of those tracks.",
        "packs": len(profiles),
        "caps_in_play": caps,
        "cap_governs": "AuditQuery.max_context_bytes bounds the SOURCE text, "
                       "not the canonical pack; the canonical total also "
                       "carries the query piece and its decision contract, so "
                       "canonical/cap above 1.0 is expected, not a breach. "
                       "The bucket follows source_bytes.",
        "by_repo": _dist(profiles, lambda p: p.repo_id),
        "by_language": _dist(profiles, lambda p: p.language),
        "by_query": _dist(profiles, lambda p: p.query_id),
        "by_size_bucket": _dist(profiles, lambda p: p.size_bucket),
        "canonical_pack_bytes": {"min": sizes[0],
                                 "median": sizes[len(sizes) // 2],
                                 "p95": sizes[int(len(sizes) * 0.95)],
                                 "max": sizes[-1]},
        "source_bytes": {"min": src[0], "median": src[len(src) // 2],
                         "p95": src[int(len(src) * 0.95)], "max": src[-1]},
        "largest_source_fraction_of_own_cap": round(
            max(p.source_bytes / p.cap_bytes for p in profiles), 4),
        "packs_at_or_over_80pct_of_own_cap": sum(
            1 for p in profiles if p.source_bytes >= p.cap_bytes * 0.80),
        "files_sent": _dist(profiles, lambda p: p.files_sent),
        "skipped": dict(sorted(skips.items())),
        # A language the catalog does not name is not a small gap: it means
        # the audit path never runs on those projects at all.
        "project_languages_no_query_supports": unsupported,
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    from tools.real_corpus import load_manifest

    p = argparse.ArgumentParser(
        description="REAL-CORPUS-1A AI Audit pack profiling "
                    "(no model, no transport)")
    p.add_argument("--manifest", required=True)
    p.add_argument("--root", required=True)
    args = p.parse_args(argv)

    root = Path(args.root)
    profiles: list[AuditPackProfile] = []
    skips: dict[str, int] = {}
    unsupported: dict[str, int] = {}
    for spec in load_manifest(Path(args.manifest)):
        report = json.loads((root / "reports" / spec.repo_id / "report.json")
                            .read_text(encoding="utf-8"))
        profiles += profile_repository(spec, root / "repos" / spec.repo_id,
                                       report, skips=skips)
        for language, n in unsupported_languages(report).items():
            unsupported[language] = unsupported.get(language, 0) + n
    print(json.dumps(audit_summary(profiles, skips, unsupported), indent=2,
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
