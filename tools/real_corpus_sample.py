"""REAL-CORPUS-1A: build the two unit tracks and the reviewer packets.

Implements the sampling half of `docs/quality/REAL-CORPUS-1A-plan.md`.

Two tracks, deliberately separate:

* **findings** — the scanner's emitted findings, stratified. This track can
  only ever measure PRECISION: it is made of things the tool already said.
* **blind** — code units chosen WITHOUT consulting the scanner's output, so a
  reviewer can mark something the tool never mentioned. This is the only
  track that can say anything about what was missed.

Nothing here is a label. Labels come from two independent humans, and this
module refuses to carry any field that could pre-empt them.
"""
from __future__ import annotations

import hashlib
import json
import random
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from auditor.ai.review import (PACK_MAX_BYTES, SOURCE_CONTEXT_LINES,
                               SOURCE_MAX_BYTES, ContextTooLargeError,
                               build_context_pack, finding_review_id)
from tools.real_corpus import RepoSpec, sample_id

# ---- targets, from the frozen plan ---------------------------------------------------

FINDINGS_TARGET, FINDINGS_MIN = 120, 80
BLIND_TARGET, BLIND_MIN = 80, 60
MAX_REPO_SHARE = 0.20                  # no repository past a fifth of a track

# The plan's Track B composition was 50 % no_finding / 30 % has_finding /
# 20 % random. That mix is GONE from the primary path, and deliberately: every
# one of those strata is a statement about what the scanner found, so drawing
# by them made the blind sample a function of the scanner's output. The
# primary draw is uniform over the population within a repository, and the
# scanner's opinion is joined afterwards for scoring only.

# Size buckets are a fraction of WHICHEVER cap actually governs the thing
# being measured. There is no shared cap in this file: a single-finding review
# pack is bounded by the review packer's own PACK_MAX_BYTES, and a blind code
# unit has no packer at all.
SIZE_BUCKETS = (("small", 0.0, 0.50), ("medium", 0.50, 0.80),
                ("large", 0.80, 1.00))
LARGE_BUCKET_TARGET = 15

# The review packer's OWN hard cap. Not 12288: that is query AI002-AI008's
# source budget in the audit path, which this file must never touch.
REVIEW_PACK_CAP = PACK_MAX_BYTES

REVIEWERS = ("R1", "R2")

_FUNC_PATTERNS = {
    "python": re.compile(r"^[ \t]*(?:async[ \t]+)?def[ \t]+\w+", re.M),
    "typescript": re.compile(
        r"^[ \t]*(?:export[ \t]+)?(?:async[ \t]+)?function[ \t]+\w+"
        r"|^[ \t]*(?:export[ \t]+)?const[ \t]+\w+[ \t]*=[ \t]*(?:async[ \t]*)?\(",
        re.M),
    "csharp": re.compile(
        r"^[ \t]*(?:public|private|protected|internal)[ \t].*\w+[ \t]*\(", re.M),
    "java": re.compile(
        r"^[ \t]*(?:public|private|protected)[ \t].*\w+[ \t]*\(", re.M),
}
_FUNC_PATTERNS["tsx"] = _FUNC_PATTERNS["typescript"]


class SamplingError(Exception):
    """The sample cannot be built or verified. Fail closed: a packet that is
    almost right is a packet whose labels cannot be trusted."""


# ---- units ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Unit:
    """One thing a reviewer will judge.

    `local` holds everything a human needs and nothing that may be committed:
    it is written to the gitignored packet and never to a summary."""

    sample_id: str
    track: str                         # "findings" | "blind"
    repo_id: str
    language: str
    stratum: str
    context_bytes: int
    size_bucket: str
    local: dict[str, Any] = field(default_factory=dict, compare=False)

    def public(self) -> dict[str, Any]:
        """The committed view: counts and categories, never content."""
        return {"sample_id": self.sample_id, "track": self.track,
                "repo_id": self.repo_id, "language": self.language,
                "stratum": self.stratum, "context_bytes": self.context_bytes,
                "size_bucket": self.size_bucket}


def single_finding_review_pack(report: dict[str, Any], repo_root: Path,
                               review_id: str) -> int | None:
    """The REAL size of the SINGLE-FINDING REVIEW pack, from its own packer.

    The name is explicit because this product has two context paths and they
    are not interchangeable. This one is `auditor.ai.review.build_context_pack`
    — anchored on one emitted finding and bounded by that packer's own
    `PACK_MAX_BYTES` (24576). The repository-audit path is a different packer
    with per-query budgets, profiled separately in `tools.real_corpus_audit`,
    and nothing here may be explained by its limits or measured against them.

    The first closing round bucketed these packs against 12288 — a number
    that belongs to queries AI002-AI008 and to nothing in this packer. The
    same 6302-byte pack reads as `medium` against 12288 and `small` against
    24576, so the published distribution was an artefact of the borrowed cap.

    Returns the byte length of exactly the canonical text that would be sent,
    or None when the packer refuses (unknown id, or irreducible past the cap).
    """
    try:
        pack = build_context_pack(report, repo_root, review_id)
    except ContextTooLargeError:
        return None
    if pack is None:
        return None
    return len(str(pack["canonical"]).encode("utf-8"))


def context_bound(report: dict[str, Any], repo_root: Path,
                  review_id: str) -> dict[str, Any] | None:
    """Which limit actually bound this pack — the byte budget, or the window?

    The plan asks for the share of units near the cap, and if there are few,
    for the reason to be recorded rather than guessed. This answers it from
    the built pack: the source piece is a +/-SOURCE_CONTEXT_LINES window
    around the finding line, and it can stop either because the window ran
    out of lines or because it ran out of SOURCE_MAX_BYTES. Those are very
    different explanations for a small pack, and only one of them is about
    the corpus."""
    try:
        pack = build_context_pack(report, repo_root, review_id)
    except ContextTooLargeError:
        return None
    if pack is None:
        return None
    source = next((p for p in pack["pieces"]
                   if str(p.get("context_id", "")).startswith("source:")), None)
    text = str(source["text"]) if source else ""
    source_bytes = len(text.encode("utf-8"))
    # The window the packer ASKED for, versus the lines it actually rendered.
    # Comparing source_bytes against SOURCE_MAX_BYTES does not work: the
    # packer adds whole lines and stops BEFORE the budget would be exceeded,
    # so a budget-bound piece sits under the budget, not on it. The short
    # render is the signal.
    span = (int(source["end_line"]) - int(source["start_line"]) + 1
            if source else 0)
    rendered = len(text.splitlines())
    return {
        "pack_bytes": len(str(pack["canonical"]).encode("utf-8")),
        "source_bytes": source_bytes,
        "source_lines": rendered,
        "window_span": span,
        "files_sent": int(pack["privacy_manifest"]["files_sent"]),
        # the whole window fitted, so the +/-N-line limit is what stopped it
        "bound_by_line_window": bool(source) and rendered == span
        and span >= 2 * SOURCE_CONTEXT_LINES + 1,
        # the budget cut the window short
        "bound_by_byte_budget": bool(source) and rendered < span,
        "source_max_bytes": SOURCE_MAX_BYTES,
    }


def size_bucket(context_bytes: int, cap: int) -> str:
    """Which bucket a REAL pack size falls in. Never padded to reach one."""
    if cap <= 0:
        raise SamplingError("the context cap must be positive")
    fraction = context_bytes / cap
    for name, low, high in SIZE_BUCKETS:
        if low <= fraction < high or (name == "large" and fraction >= high):
            return name
    return "large"


def iter_findings(report: dict[str, Any]) -> Iterable[tuple[str, dict]]:
    """(project_root, finding) for every finding in a report."""
    for project in report.get("projects", []):
        if not isinstance(project, dict):
            continue
        for finding in project.get("findings", []):
            if isinstance(finding, dict):
                yield str(project.get("root", "")), finding


def finding_stratum(finding: dict[str, Any]) -> str:
    """The plan's stratification key, as one comparable string."""
    rule = str(finding.get("rule_id", "?"))
    return "/".join((rule[:1] or "?",
                     str(finding.get("language", "?")),
                     str(finding.get("precision", "?")),
                     str(finding.get("level", "?"))))


def build_findings_units(spec: RepoSpec, report: dict[str, Any],
                         *, repo_root: Path,
                         unpackable: list[str] | None = None) -> list[Unit]:
    """Every emitted finding as a candidate unit. Selection happens later —
    this only turns the report into comparable, identified candidates.

    There is no `cap` parameter any more, on purpose: the only cap that means
    anything here is the review packer's own, so it is not something a caller
    may hand in from the audit path.

    `repo_root` is the local clone: the packer reads the real source through
    it, so the recorded size is the real one. Findings the packer will not
    pack are dropped from the population and appended to `unpackable` — they
    are reported as a coverage gap, never quietly resized."""
    # A fingerprint is a MULTISET key, not a unique id: the baseline matcher
    # deliberately lets duplicates match one-for-one, so one repository can
    # hold several distinct findings with the same fingerprint. Hashing it
    # alone produced colliding sample_ids on the real corpus — caught by the
    # one-to-one verification, which is what it is there for. The identity
    # therefore carries an occurrence ordinal, assigned in a deterministic
    # order so it is stable across runs and machines.
    ordered = sorted(iter_findings(report),
                     key=lambda rf: (str(rf[1].get("fingerprint", "")),
                                     str(rf[0]),
                                     str(rf[1].get("file", "")),
                                     int(rf[1].get("line") or 0),
                                     str(rf[1].get("rule_id", ""))))
    seen: dict[str, int] = {}
    units: list[Unit] = []
    for root, finding in ordered:
        fingerprint = finding.get("fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint:
            # a report without fingerprints cannot be sampled reproducibly
            raise SamplingError(
                f"{spec.repo_id}: a finding carries no fingerprint")
        occurrence = seen.get(fingerprint, 0)
        seen[fingerprint] = occurrence + 1
        identity = f"{fingerprint}#{occurrence}"
        snippet = str(finding.get("snippet", ""))
        detail = str(finding.get("detail", ""))
        review_id = finding_review_id(root, finding)
        context_bytes = single_finding_review_pack(report, repo_root,
                                                   review_id)
        if context_bytes is None:
            if unpackable is not None:
                unpackable.append(f"{spec.repo_id}:{finding.get('rule_id')}")
            continue
        units.append(Unit(
            sample_id=sample_id(spec.repo_id, identity),
            track="findings",
            repo_id=spec.repo_id,
            language=str(finding.get("language", spec.language)),
            stratum=finding_stratum(finding),
            context_bytes=context_bytes,
            size_bucket=size_bucket(context_bytes, REVIEW_PACK_CAP),
            local={"rule_id": finding.get("rule_id"),
                   "title": finding.get("title"),
                   "detail": detail, "snippet": snippet,
                   "file": finding.get("file"), "line": finding.get("line"),
                   "project_root": root,
                   "review_id": review_id,
                   "scanner_level": finding.get("level"),
                   "scanner_gate": finding.get("gate_action"),
                   "scanner_precision": finding.get("precision")},
        ))
    return units


BLIND_MIN_BODY_BYTES = 120          # smaller than this is not judgeable

# A blind unit has no packer and therefore no cap. Its bucket is a fraction of
# the largest unit the corpus itself produced, so the axis is honest about
# being relative — it is NOT a share of any model budget and is never compared
# with a review pack or an audit pack.
BLIND_BUCKET_REFERENCE = "largest blind unit in the corpus"


def build_blind_population(spec: RepoSpec, tree: Path) -> list[Unit]:
    """EVERY judgeable code unit in the repository. No report, no findings.

    This function does not take a report and must never be given one. The
    previous version consulted the report to stratify the draw, which made
    the blind sample a function of the scanner's output: deleting findings
    changed which units were drawn, and two reports that disagreed produced
    two different sets of units to review. A recall estimate computed on a
    sample the scanner chose is not a recall estimate.

    The stratum here is `repo_id/language` — identity the scanner had no hand
    in. Whether a unit overlaps a finding is discovered AFTERWARDS, by
    `scanner_overlap`, and only for scoring."""
    pattern = _FUNC_PATTERNS.get(spec.language)
    suffixes = {"python": (".py",), "typescript": (".ts",), "tsx": (".tsx",),
                "csharp": (".cs",), "java": (".java",)}[spec.language]

    population: list[Unit] = []
    for path in sorted(tree.rglob("*")):
        if path.suffix not in suffixes or not path.is_file():
            continue
        parts = set(path.parts)
        if ".git" in parts or parts & {"node_modules", "vendor"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = path.relative_to(tree).as_posix()
        lines = text.splitlines()
        for start, end, body in _split_units(text, pattern):
            body_bytes = len(body.encode("utf-8"))
            if body_bytes < BLIND_MIN_BODY_BYTES:
                continue
            digest = hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]
            population.append(Unit(
                sample_id=sample_id(spec.repo_id,
                                    f"{rel}:{start}:{end}:{digest}"),
                track="blind",
                repo_id=spec.repo_id,
                language=spec.language,
                stratum=f"{spec.repo_id}/{spec.language}",
                context_bytes=body_bytes,
                size_bucket="",              # assigned once the corpus is known
                local={"file": rel, "start_line": start, "end_line": end,
                       "code": body,
                       "file_header": _file_header(lines, start)},
            ))
    return population


def _file_header(lines: list[str], start: int) -> str:
    """The imports and enclosing declarations above a unit, capped.

    A reviewer judging a function needs to know what is in scope; a bare body
    invites both false alarms and misses. This is confined to the same file
    and stops at the unit itself, so it can never carry another unit's code.
    """
    head: list[str] = []
    used = 0
    for raw in lines[:max(0, start - 1)]:
        stripped = raw.strip()
        if not stripped:
            continue
        if not (stripped.startswith(("import ", "from ", "using ", "package ",
                                     "#include", "const ", "let ", "var ",
                                     "export ", "class ", "namespace ",
                                     "@", "public class", "internal class"))):
            continue
        cost = len(raw.encode("utf-8")) + 1
        if used + cost > BLIND_HEADER_MAX_BYTES:
            break
        head.append(raw)
        used += cost
    return "\n".join(head)


BLIND_HEADER_MAX_BYTES = 2048


def select_blind(population: list[Unit], *, per_repo: int) -> list[Unit]:
    """Freeze the sample from repo/language identity alone.

    Deterministic by `sample_id`, which is a hash of (repo, path, span, body
    digest). Nothing in this function can see a finding, so re-running it
    against a different report cannot move a single unit."""
    if per_repo <= 0 or not population:
        return []
    by_repo: dict[str, list[Unit]] = {}
    for unit in population:
        by_repo.setdefault(unit.repo_id, []).append(unit)
    chosen: list[Unit] = []
    for repo in sorted(by_repo):
        ordered = sorted(by_repo[repo], key=lambda u: u.sample_id)
        chosen.extend(ordered[:per_repo])
    return sorted(chosen, key=lambda u: u.sample_id)


def assign_blind_buckets(units: list[Unit]) -> list[Unit]:
    """Bucket blind units against the largest unit the corpus produced.

    There is no packer and no budget on this track, so there is no cap to be
    a fraction of. Saying so beats borrowing a number from a packer that
    never touches these units."""
    if not units:
        return []
    reference = max(u.context_bytes for u in units)
    return [Unit(**{**u.__dict__,
                    "size_bucket": size_bucket(u.context_bytes, reference)})
            for u in units]


def normalize_finding_path(project_root: str, file: str) -> str:
    """The repository-relative path of a finding, the way the product joins it.

    A monorepo report carries several projects, and a finding's `file` is
    relative to its own project root. Comparing it against a
    repository-relative blind path without joining the root matches units in
    the wrong project — or matches nothing at all."""
    root = (project_root or "").strip("/")
    rel = (file or "").replace("\\", "/").lstrip("./")
    if root in ("", "."):
        return rel
    return rel if rel.startswith(f"{root}/") else f"{root}/{rel}"


def scanner_overlap(units: list[Unit], report: dict[str, Any]
                    ) -> dict[str, list[dict[str, Any]]]:
    """Which frozen blind units a finding actually lands inside.

    Called AFTER the sample is frozen, and used only for scoring — never to
    choose a unit. Overlap is decided per UNIT, not per file: a finding at
    line 146 does not mark the function at lines 60-98. On the real corpus the
    file-level rule mislabelled 504 of 536 units (94 %)."""
    by_path: dict[str, list[Unit]] = {}
    for unit in units:
        if unit.track == "blind":
            by_path.setdefault(unit.local["file"], []).append(unit)
    hits: dict[str, list[dict[str, Any]]] = {u.sample_id: [] for u in units
                                             if u.track == "blind"}
    for root, finding in iter_findings(report):
        path = normalize_finding_path(root, str(finding.get("file", "")))
        line = finding.get("line")
        if not isinstance(line, int) or isinstance(line, bool) or line <= 0:
            continue
        for unit in by_path.get(path, []):
            if unit.local["start_line"] <= line <= unit.local["end_line"]:
                hits[unit.sample_id].append({
                    "rule_id": finding.get("rule_id"),
                    "line": line,
                    "level": finding.get("level"),
                    "precision": finding.get("precision"),
                })
    return hits


def _split_units(text: str, pattern: re.Pattern[str] | None
                 ) -> list[tuple[int, int, str]]:
    """Split a file into function-ish units, or return the whole file when no
    function boundary is recognisable."""
    lines = text.splitlines()
    if pattern is None or not lines:
        return [(1, len(lines), text)] if lines else []
    starts = [text[:m.start()].count("\n") for m in pattern.finditer(text)]
    if not starts:
        return [(1, len(lines), text)]
    starts = sorted(set(starts))
    out: list[tuple[int, int, str]] = []
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else len(lines)
        body = "\n".join(lines[start:end])
        if body.strip():
            out.append((start + 1, end, body))
    return out


def inclusion_probabilities(population: list[Unit], sample: list[Unit]
                            ) -> dict[str, dict[str, float | int]]:
    """Population size and inclusion probability per repository.

    A recall estimate needs a denominator that is a real population, and a
    known chance of any unit being in the sample. Both are recorded here so
    the eventual estimate can be weighted rather than assumed uniform across
    repositories of very different sizes."""
    pop: dict[str, int] = {}
    drawn: dict[str, int] = {}
    for unit in population:
        pop[unit.repo_id] = pop.get(unit.repo_id, 0) + 1
    for unit in sample:
        drawn[unit.repo_id] = drawn.get(unit.repo_id, 0) + 1
    return {repo: {"population": n, "sampled": drawn.get(repo, 0),
                   "inclusion_probability": round(drawn.get(repo, 0) / n, 6)}
            for repo, n in sorted(pop.items())}


# ---- selection -----------------------------------------------------------------------

def select_stratified(units: list[Unit], target: int,
                      max_share: float = MAX_REPO_SHARE) -> list[Unit]:
    """Deterministic stratified selection with a per-repository ceiling.

    Order is by `sample_id` inside every stratum, so the result is a pure
    function of the corpus and the quotas — not of filesystem order, the
    clock, or the machine."""
    if not units:
        return []
    strata: dict[str, list[Unit]] = {}
    for unit in units:
        strata.setdefault(unit.stratum, []).append(unit)
    for group in strata.values():
        group.sort(key=lambda u: u.sample_id)

    def draw(cap_per_repo: int) -> list[Unit]:
        chosen: list[Unit] = []
        per_repo: dict[str, int] = {}
        per_stratum: dict[str, int] = {}
        total = len(units)
        order = sorted(strata, key=lambda k: (-len(strata[k]), k))
        quotas = {k: max(1, int(target * len(strata[k]) / total))
                  for k in order}
        for stratum in order:
            for unit in strata[stratum]:
                if per_stratum.get(stratum, 0) >= quotas[stratum] \
                        or len(chosen) >= target:
                    break
                if per_repo.get(unit.repo_id, 0) >= cap_per_repo:
                    continue
                chosen.append(unit)
                per_repo[unit.repo_id] = per_repo.get(unit.repo_id, 0) + 1
                per_stratum[stratum] = per_stratum.get(stratum, 0) + 1
        # top up across strata, still respecting the repository ceiling
        picked = {u.sample_id for u in chosen}
        for unit in sorted(units, key=lambda u: u.sample_id):
            if len(chosen) >= target:
                break
            if unit.sample_id in picked \
                    or per_repo.get(unit.repo_id, 0) >= cap_per_repo:
                continue
            chosen.append(unit)
            picked.add(unit.sample_id)
            per_repo[unit.repo_id] = per_repo.get(unit.repo_id, 0) + 1
        return chosen

    # The plan's rule is "its quota is capped and the shortfall is reported as
    # a shortfall" — so the ceiling is an absolute count derived from the
    # TARGET, applied once. Tightening it until the achieved share obeys 20 %
    # was tried and is wrong: with fewer than five repositories no draw can
    # satisfy it, and the loop shrinks the sample toward nothing. A corpus too
    # narrow to honour the ceiling is a fact to report, not to sample away.
    return sorted(draw(max(1, int(target * max_share))),
                  key=lambda u: u.sample_id)


def repo_shares(units: list[Unit]) -> dict[str, float]:
    """Each repository's achieved share of a track, for the summary. This is
    what the shortfall is reported against."""
    if not units:
        return {}
    counts: dict[str, int] = {}
    for unit in units:
        counts[unit.repo_id] = counts.get(unit.repo_id, 0) + 1
    return {repo: round(n / len(units), 4)
            for repo, n in sorted(counts.items())}


# ---- packets -------------------------------------------------------------------------

# TWO CONTRACTS, not one vocabulary stretched over two questions.
#
# Track A asks "is this claim true?" — the scanner has already made an
# assertion and the reviewer adjudicates it.
#
# Track B asks "is there anything wrong here?" — there is no claim to
# adjudicate, so `false_positive` is not a thing a reviewer can say. Offering
# it (as the first version did) meant the only way to record a MISS was to
# call a claim that was never made a false positive, and there was nowhere at
# all to write down what the miss actually was.
TRACK_A_LABEL_FIELDS = ("label", "level", "gate", "actionability", "reason",
                        "evidence_sufficiency")
TRACK_A_LABELS = ("confirmed", "false_positive", "uncertain")

TRACK_B_OUTCOMES = ("issues_found", "no_issue_observed", "uncertain")
TRACK_B_ISSUE_FIELDS = ("rule_id", "line", "span", "statement", "evidence",
                        "level", "actionability")

LEVELS = ("error", "warning", "note")
ACTIONABILITY = ("actionable", "not_actionable", "unclear")
EVIDENCE_SUFFICIENCY = ("sufficient", "insufficient")
GATES = ("block", "review", "info")


def build_findings_packet(units: list[Unit], reviewer: str, salt: str, *,
                          evidence: dict[str, dict[str, Any]] | None = None
                          ) -> list[dict[str, Any]]:
    """Track A: adjudicate a claim, with the context the judgement needs.

    A reviewer cannot rule on a claim from a title and a one-line snippet. The
    entry carries the claim, the source window the packer actually sent, the
    rule's own definition, and whatever manifest/execution evidence the report
    recorded — which is the same material the model would see."""
    if reviewer not in REVIEWERS:
        raise SamplingError(f"unknown reviewer {reviewer!r}")
    evidence = evidence or {}
    shuffled = [u for u in units if u.track == "findings"]
    random.Random(f"{salt}:A:{reviewer}").shuffle(shuffled)
    packet = []
    for position, unit in enumerate(shuffled, start=1):
        extra = evidence.get(unit.sample_id, {})
        packet.append({
            "position": position,
            "sample_id": unit.sample_id,
            "track": "findings",
            "language": unit.language,
            "claim": {
                "rule_id": unit.local.get("rule_id"),
                "title": unit.local.get("title"),
                "detail": unit.local.get("detail"),
                "file": unit.local.get("file"),
                "line": unit.local.get("line"),
                "snippet": unit.local.get("snippet"),
            },
            "judged_on": {
                "source_window": extra.get("source_window", ""),
                "source_span": extra.get("source_span", ""),
                "rule_definition": extra.get("rule_definition", {}),
                "manifest_evidence": extra.get("manifest_evidence", []),
                "execution_evidence": extra.get("execution_evidence", {}),
            },
            **{k: "" for k in TRACK_A_LABEL_FIELDS},
        })
    return packet


def build_blind_packet(units: list[Unit], reviewer: str, salt: str, *,
                       catalog_rules: dict[str, list[dict[str, Any]]] | None
                       = None) -> list[dict[str, Any]]:
    """Track B: find issues, with no idea what the scanner thought.

    The entry carries the code unit, the confined file context above it, and
    the catalog rules that apply to THIS unit's language — so a reviewer can
    name what they found in the same vocabulary the scanner uses. It carries
    no rule the scanner fired, no level, no gate, no overlap and no verdict.

    `issues` is an empty list the reviewer fills in. `outcome` is empty."""
    if reviewer not in REVIEWERS:
        raise SamplingError(f"unknown reviewer {reviewer!r}")
    catalog_rules = catalog_rules or {}
    shuffled = [u for u in units if u.track == "blind"]
    random.Random(f"{salt}:B:{reviewer}").shuffle(shuffled)
    packet = []
    for position, unit in enumerate(shuffled, start=1):
        packet.append({
            "position": position,
            "sample_id": unit.sample_id,
            "track": "blind",
            "language": unit.language,
            "code_unit": {
                "file": unit.local.get("file"),
                "start_line": unit.local.get("start_line"),
                "end_line": unit.local.get("end_line"),
                "file_context": unit.local.get("file_header", ""),
                "code": unit.local.get("code"),
            },
            "applicable_rules": catalog_rules.get(unit.language, []),
            "outcome": "",
            "issues": [],
        })
    return packet


# Anything that would tell a blind reviewer what the scanner concluded. The
# `applicable_rules` block deliberately carries rule ids for the whole
# language — that is a menu, not a verdict — so the leak check looks at the
# scanner-specific keys and at the overlap join, never at rule ids as such.
_SCANNER_ONLY_KEYS = ("scanner_level", "scanner_gate", "scanner_precision",
                      "stratum", "overlap", "has_finding", "verdict",
                      "gate_action", "fingerprint", "claim")


def blind_leakage(packet: list[dict[str, Any]]) -> list[str]:
    """Any way a blind entry could betray what the scanner decided."""
    leaks = []
    for entry in packet:
        if entry.get("track") != "blind":
            continue
        blob = json.dumps(entry)
        for key in _SCANNER_ONLY_KEYS:
            if f'"{key}"' in blob:
                leaks.append(f"{entry['sample_id']}: carries {key}")
        if entry.get("issues"):
            leaks.append(f"{entry['sample_id']}: issues are pre-filled")
        if entry.get("outcome"):
            leaks.append(f"{entry['sample_id']}: outcome is pre-filled")
    return leaks


def _verify_ids(track: str, units: list[Unit],
                packets: dict[str, list[dict[str, Any]]]) -> None:
    expected = [u.sample_id for u in units if u.track == track]
    if len(set(expected)) != len(expected):
        dupes = sorted({i for i in expected if expected.count(i) > 1})
        raise SamplingError(
            f"{track}: duplicate sample_id in the sample: {dupes[:5]}")
    for reviewer, packet in sorted(packets.items()):
        got = [e["sample_id"] for e in packet]
        if any(e.get("track") != track for e in packet):
            raise SamplingError(f"{reviewer}: {track} packet carries a "
                                f"unit from another track")
        if len(set(got)) != len(got):
            raise SamplingError(
                f"{reviewer}: duplicate sample_id in the {track} packet")
        if set(got) != set(expected):
            missing = sorted(set(expected) - set(got))
            forged = sorted(set(got) - set(expected))
            raise SamplingError(
                f"{reviewer}: the {track} packet does not match the sample "
                f"(missing {len(missing)}, unknown {len(forged)})")
        if len(got) != len(expected):
            raise SamplingError(f"{reviewer}: {track} packet length differs")
    orders = {r: [e["sample_id"] for e in p] for r, p in packets.items()}
    if len(packets) > 1 and len({tuple(v) for v in orders.values()}) == 1:
        raise SamplingError(
            f"both reviewers received the same {track} order")


def verify_findings_packets(units: list[Unit],
                            packets: dict[str, list[dict[str, Any]]]) -> None:
    """Fail closed on Track A, against Track A's contract alone."""
    _verify_ids("findings", units, packets)
    for reviewer, packet in sorted(packets.items()):
        for entry in packet:
            if any(entry.get(k) not in ("", None)
                   for k in TRACK_A_LABEL_FIELDS):
                raise SamplingError(f"{reviewer}: a Track A label is "
                                    f"pre-filled")
            missing = [k for k in TRACK_A_LABEL_FIELDS if k not in entry]
            if missing:
                raise SamplingError(f"{reviewer}: Track A entry is missing "
                                    f"{missing}")
            if "claim" not in entry:
                raise SamplingError(f"{reviewer}: a Track A entry has no "
                                    f"claim to adjudicate")


def verify_blind_packets(units: list[Unit],
                         packets: dict[str, list[dict[str, Any]]]) -> None:
    """Fail closed on Track B, against Track B's own contract."""
    _verify_ids("blind", units, packets)
    for reviewer, packet in sorted(packets.items()):
        for entry in packet:
            if entry.get("outcome") not in ("", None):
                raise SamplingError(f"{reviewer}: a Track B outcome is "
                                    f"pre-filled")
            if entry.get("issues"):
                raise SamplingError(f"{reviewer}: Track B issues are "
                                    f"pre-filled")
            for key in ("outcome", "issues", "code_unit", "applicable_rules"):
                if key not in entry:
                    raise SamplingError(f"{reviewer}: Track B entry is "
                                        f"missing {key}")


def validate_findings_labels(entry: dict[str, Any]) -> list[str]:
    """Why a returned Track A label may not be accepted."""
    problems: list[str] = []
    label = entry.get("label")
    if label not in TRACK_A_LABELS:
        problems.append(f"label must be one of {TRACK_A_LABELS}")
    if not str(entry.get("reason") or "").strip():
        problems.append("a label without a reason is not a review")
    for field_name, allowed in (("level", LEVELS), ("gate", GATES),
                                ("actionability", ACTIONABILITY),
                                ("evidence_sufficiency",
                                 EVIDENCE_SUFFICIENCY)):
        if entry.get(field_name) not in allowed:
            problems.append(f"{field_name} must be one of {allowed}")
    return problems


def validate_blind_labels(entry: dict[str, Any]) -> list[str]:
    """Why a returned Track B result may not be accepted.

    The rule that matters: `issues_found` is a claim, and a claim with no
    issue behind it is not reviewable. `false_positive` is refused outright —
    there is no claim on this track to be false about."""
    problems: list[str] = []
    outcome = entry.get("outcome")
    if outcome not in TRACK_B_OUTCOMES:
        problems.append(f"outcome must be one of {TRACK_B_OUTCOMES}")
    issues = entry.get("issues")
    if not isinstance(issues, list):
        return problems + ["issues must be a list"]
    if outcome == "issues_found" and not issues:
        problems.append("issues_found with an empty issues list: there is "
                        "nothing to review")
    if outcome in ("no_issue_observed", "uncertain") and issues:
        problems.append(f"{outcome} carries {len(issues)} issues")
    for n, issue in enumerate(issues):
        if not isinstance(issue, dict):
            problems.append(f"issue {n} is not an object")
            continue
        for field_name in TRACK_B_ISSUE_FIELDS:
            if field_name not in issue:
                problems.append(f"issue {n} is missing {field_name}")
        if not str(issue.get("statement") or "").strip():
            problems.append(f"issue {n} has no statement")
        if not str(issue.get("evidence") or "").strip():
            problems.append(f"issue {n} has no evidence")
        if issue.get("level") not in LEVELS:
            problems.append(f"issue {n} level must be one of {LEVELS}")
        if issue.get("actionability") not in ACTIONABILITY:
            problems.append(f"issue {n} actionability must be one of "
                            f"{ACTIONABILITY}")
    if any(str(i.get("label", "")) == "false_positive" for i in issues
           if isinstance(i, dict)):
        problems.append("false_positive has no meaning on the blind track: "
                        "there is no claim to be false")
    return problems


_PATHISH = re.compile(r"[A-Za-z]:[\\/]|(?:^|[\s\"'])/(?:home|Users|tmp|var)/"
                      r"|\.quality-local")


def public_output_problem(blob: str) -> str | None:
    """Why a would-be committed artefact may not be committed."""
    if _PATHISH.search(blob):
        return "contains a filesystem path"
    for key in ("snippet", "code", "detail", "claim", "code_unit", "file"):
        if f'"{key}"' in blob:
            return f"contains {key}"
    return None


# ---- driver ---------------------------------------------------------------------------

def build_corpus(manifest: Path, root: Path,
                 *, salt: str = "REAL-CORPUS-1A") -> dict[str, Any]:
    """Build both tracks, write four packets, return the committable summary.

    Three measurements live in the result and none of them share a
    denominator: single-finding review packs, blind code units, and — from a
    module this one does not share a packer with — AI Audit packs.

    Everything with content goes under `root` (gitignored). The returned
    summary is counts and categories only, and `main` runs it through
    `public_output_problem` before it is allowed anywhere public.
    """
    from tools.real_corpus import load_manifest
    from tools.real_corpus_audit import (audit_summary, profile_repository,
                                         unsupported_languages)

    specs = load_manifest(manifest)
    findings_candidates: list[Unit] = []
    blind_population: list[Unit] = []
    unpackable: list[str] = []
    bounds: list[dict[str, Any]] = []
    evidence: dict[str, dict[str, Any]] = {}
    reports: dict[str, dict[str, Any]] = {}
    audit_profiles: list[Any] = []
    audit_skips: dict[str, int] = {}
    audit_unsupported: dict[str, int] = {}
    per_repo_blind = max(1, round(BLIND_TARGET / max(1, len(specs))))

    for spec in specs:
        report = json.loads((root / "reports" / spec.repo_id / "report.json")
                            .read_text(encoding="utf-8"))
        reports[spec.repo_id] = report
        tree = root / "repos" / spec.repo_id

        # --- Track A: the scanner's claims, sized by the REVIEW packer
        found = build_findings_units(spec, report, repo_root=tree,
                                     unpackable=unpackable)
        findings_candidates += found
        for unit in found:
            evidence[unit.sample_id] = reviewer_evidence(report, tree, unit)
        for proj_root, finding in iter_findings(report):
            row = context_bound(report, tree,
                                finding_review_id(proj_root, finding))
            if row is None:
                continue
            row["no_source_reason"] = (_no_source_reason(tree, finding)
                                       if row["files_sent"] == 0 else "")
            bounds.append(row)

        # --- Track B: the population, built WITHOUT the report
        blind_population += build_blind_population(spec, tree)

        # --- AI Audit: a different packer, its own caps, its own denominator
        audit_profiles += profile_repository(spec, tree, report,
                                             skips=audit_skips)
        for language, n in unsupported_languages(report).items():
            audit_unsupported[language] = audit_unsupported.get(language, 0) + n

    findings_units = select_stratified(findings_candidates, FINDINGS_TARGET)
    blind_units = assign_blind_buckets(
        select_blind(blind_population, per_repo=per_repo_blind))

    # ONLY NOW does the scanner's output touch Track B, and only to score it.
    overlap: dict[str, list[dict[str, Any]]] = {}
    for repo_id, report in sorted(reports.items()):
        mine = [u for u in blind_units if u.repo_id == repo_id]
        overlap.update(scanner_overlap(mine, report))

    catalog = catalog_rules_by_language(reports)
    packets = {
        "findings": {r: build_findings_packet(findings_units, r, salt=salt,
                                              evidence=evidence)
                     for r in REVIEWERS},
        "blind": {r: build_blind_packet(blind_units, r, salt=salt,
                                        catalog_rules=catalog)
                  for r in REVIEWERS},
    }
    # fail closed, each contract against its own rules
    verify_findings_packets(findings_units, packets["findings"])
    verify_blind_packets(blind_units, packets["blind"])
    leaks = [leak for p in packets["blind"].values() for leak in
             blind_leakage(p)]
    if leaks:
        raise SamplingError(f"the blind track would leak: {leaks[:5]}")

    out = root / "packets"
    out.mkdir(parents=True, exist_ok=True)
    for track, per_reviewer in sorted(packets.items()):
        for reviewer, packet in sorted(per_reviewer.items()):
            (out / f"packet_{track}_{reviewer}.json").write_text(
                json.dumps({"corpus": "REAL-CORPUS-1A", "track": track,
                            "reviewer": reviewer, "units": packet}, indent=2),
                encoding="utf-8")
    units = findings_units + blind_units
    (root / "units.json").write_text(
        json.dumps([{**u.public(), "local": u.local} for u in units],
                   indent=2), encoding="utf-8")
    # the join is kept beside the sample, never inside a packet
    (root / "blind_overlap.json").write_text(
        json.dumps(overlap, indent=2, sort_keys=True), encoding="utf-8")

    return _summary(findings_candidates, findings_units, blind_population,
                    blind_units, overlap, packets, bounds, unpackable,
                    audit_summary(audit_profiles, audit_skips,
                                  audit_unsupported))


def reviewer_evidence(report: dict[str, Any], repo_root: Path,
                      unit: Unit) -> dict[str, Any]:
    """The material a Track A reviewer needs to rule on the claim.

    It is taken from the pack the product ACTUALLY builds for this finding —
    the same source window, the same rule descriptor, the same manifest and
    execution pieces — so the human is judging what the model would judge and
    not a summary of it."""
    try:
        pack = build_context_pack(report, repo_root,
                                  str(unit.local.get("review_id", "")))
    except ContextTooLargeError:
        return {}
    if pack is None:
        return {}
    out: dict[str, Any] = {"manifest_evidence": []}
    for piece in pack["pieces"]:
        cid = str(piece.get("context_id", ""))
        if cid.startswith("source:"):
            out["source_window"] = piece.get("text", "")
            out["source_span"] = f"{piece.get('start_line')}-" \
                                 f"{piece.get('end_line')}"
        elif cid == "rule":
            out["rule_definition"] = {k: v for k, v in piece.items()
                                      if k != "context_id"}
        elif cid == "execution":
            out["execution_evidence"] = {k: v for k, v in piece.items()
                                         if k != "context_id"}
        elif cid.startswith("manifest"):
            out["manifest_evidence"].append(
                {k: v for k, v in piece.items() if k != "context_id"})
    return out


def catalog_rules_by_language(reports: dict[str, dict[str, Any]]
                              ) -> dict[str, list[dict[str, Any]]]:
    """Every catalog rule, grouped by the language it applies to.

    A blind reviewer gets the rules for THEIR unit's language and nothing
    else. This is a menu of what the tool is capable of saying — not a hint
    about what it said here. It is derived from the reports' own catalog, so
    it cannot drift from the rules that produced the findings track."""
    by_language: dict[str, dict[str, dict[str, Any]]] = {}
    for report in reports.values():
        catalog = (report.get("analysis_manifest") or {}).get("catalog")
        languages = {str(p.get("language", "")) for p in
                     report.get("projects", []) if isinstance(p, dict)}
        if not isinstance(catalog, list):
            continue
        for row in catalog:
            if not isinstance(row, dict) or not row.get("rule_id"):
                continue
            entry = {k: row.get(k) for k in
                     ("rule_id", "title", "description", "category")}
            for language in languages:
                by_language.setdefault(language, {})[str(row["rule_id"])] = \
                    entry
    return {language: [rules[k] for k in sorted(rules)]
            for language, rules in sorted(by_language.items())}


def _no_source_reason(tree: Path, finding: dict[str, Any]) -> str:
    """Why this finding's pack carries no source at all. The three causes are
    very different — a rule that has no file at all, a path that did not
    resolve, and a file refused whole for being too large — and a summary that
    merged them would hide which one matters."""
    rel = str(finding.get("file") or "")
    line = finding.get("line")
    if not rel or not isinstance(line, int) or isinstance(line, bool) \
            or line <= 0:
        return "finding carries no file/line"
    target = tree / rel
    if not target.is_file():
        return "file not present in the tree"
    if target.stat().st_size > SOURCE_MAX_BYTES * 8:
        return "file over the whole-file read cap"
    return "other"


def _dist(items: Iterable[Any], key: Any) -> dict[str, int]:
    out: dict[str, int] = {}
    for item in items:
        k = str(key(item))
        out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items()))


def _summary(candidates: list[Unit], findings: list[Unit],
             blind_population: list[Unit], blind: list[Unit],
             overlap: dict[str, list[dict[str, Any]]],
             packets: dict[str, dict[str, list[dict[str, Any]]]],
             bounds: list[dict[str, Any]], unpackable: list[str],
             audit: dict[str, Any]) -> dict[str, Any]:
    """THREE measurements, THREE denominators, never added together.

    * `single_finding_review` — one pack per emitted finding, review packer,
      bucketed against that packer's own PACK_MAX_BYTES.
    * `blind_human_review` — code units with no packer and no budget, sized in
      real code bytes and bucketed against the largest unit in the corpus.
    * `ai_audit_packs` — one pack per (project, query), a different packer
      with per-query caps, profiled in `tools.real_corpus_audit`.

    Mixing any two of these was the defect the closing round removed. They
    stay in separate blocks, each carrying the sentence that says what its
    number is a fraction OF.
    """
    def med(values: list[int]) -> int:
        return sorted(values)[len(values) // 2]

    with_overlap = sum(1 for hits in overlap.values() if hits)
    return {
        "corpus": "REAL-CORPUS-1A",
        "labels": "none - two independent human reviews have not been run",

        # ---- Track A: the scanner's own claims (precision only) ------------
        "single_finding_review": {
            "what": "auditor.ai.review.build_context_pack, one pack per "
                    "emitted finding. Denominator: FINDINGS.",
            "cap": REVIEW_PACK_CAP,
            "cap_note": "the review packer's own PACK_MAX_BYTES. The earlier "
                        "12288 came from audit queries AI002-AI008 and moved "
                        "the largest pack from 'small' to 'medium' by "
                        "arithmetic alone.",
            "population": len(candidates),
            "unpackable": len(unpackable),
            "units": len(findings),
            "target": FINDINGS_TARGET, "minimum": FINDINGS_MIN,
            "met_minimum": len(findings) >= FINDINGS_MIN,
            "by_language": _dist(findings, lambda u: u.language),
            "by_rule_family": _dist(findings,
                                    lambda u: u.stratum.split("/")[0]),
            "by_precision": _dist(findings, lambda u: u.stratum.split("/")[2]),
            "by_level": _dist(findings, lambda u: u.stratum.split("/")[3]),
            "by_size_bucket": _dist(findings, lambda u: u.size_bucket),
            "repo_shares": repo_shares(findings),
            "pack_bytes": {
                "min": min(u.context_bytes for u in findings),
                "median": med([u.context_bytes for u in findings]),
                "max": max(u.context_bytes for u in findings),
                "population_median": med([u.context_bytes
                                          for u in candidates]),
                "population_max": max(u.context_bytes for u in candidates),
            },
            "large_bucket_units": sum(1 for u in findings
                                      if u.size_bucket == "large"),
            "large_bucket_target": LARGE_BUCKET_TARGET,
            "large_bucket_met": sum(1 for u in findings
                                    if u.size_bucket == "large"
                                    ) >= LARGE_BUCKET_TARGET,
        },

        # ---- why those packs are the size they are ------------------------
        "what_bounds_a_review_pack": {
            "denominator": len(bounds),
            "applies_to": "single_finding_review only. Nothing here explains "
                          "an AI Audit pack; that packer has its own limits.",
            "packer_limits": {
                "source_context_lines": SOURCE_CONTEXT_LINES,
                "window_lines": 2 * SOURCE_CONTEXT_LINES + 1,
                "source_max_bytes": SOURCE_MAX_BYTES,
                "whole_file_read_cap": SOURCE_MAX_BYTES * 8,
                "pack_max_bytes": REVIEW_PACK_CAP,
            },
            "bound_by_line_window": sum(1 for b in bounds
                                        if b["bound_by_line_window"]),
            "bound_by_byte_budget": sum(1 for b in bounds
                                        if b["bound_by_byte_budget"]),
            "no_source_piece": _dist([b for b in bounds
                                      if b["files_sent"] == 0],
                                     lambda b: b["no_source_reason"]),
            "largest_source_piece_bytes": max(b["source_bytes"]
                                              for b in bounds),
            "packs_at_or_over_50pct_of_cap": sum(
                1 for b in bounds
                if b["pack_bytes"] >= REVIEW_PACK_CAP * 0.50),
            "packs_at_or_over_80pct_of_cap": sum(
                1 for b in bounds
                if b["pack_bytes"] >= REVIEW_PACK_CAP * 0.80),
        },

        # ---- Track B: the only track that can show a miss -----------------
        "blind_human_review": {
            "what": "code units drawn WITHOUT reading the report. No packer, "
                    "no budget. Denominator: CODE UNITS.",
            "size_reference": BLIND_BUCKET_REFERENCE,
            "independence": "the draw uses repo/language identity only; the "
                            "scanner's output is joined afterwards and only "
                            "for scoring, so a different report cannot move a "
                            "single sampled unit.",
            "population": len(blind_population),
            "units": len(blind),
            "target": BLIND_TARGET, "minimum": BLIND_MIN,
            "met_minimum": len(blind) >= BLIND_MIN,
            "by_language": _dist(blind, lambda u: u.language),
            "by_size_bucket": _dist(blind, lambda u: u.size_bucket),
            "repo_shares": repo_shares(blind),
            "inclusion": inclusion_probabilities(blind_population, blind),
            "code_bytes": {
                "min": min(u.context_bytes for u in blind),
                "median": med([u.context_bytes for u in blind]),
                "max": max(u.context_bytes for u in blind),
            },
            # the join, reported as a property of the sample — NOT as a
            # stratum it was drawn by, and NOT shown to any reviewer
            "scanner_overlap_after_freeze": {
                "units_a_finding_lands_inside": with_overlap,
                "units_with_no_finding_inside": len(blind) - with_overlap,
                "matched_by": "normalize(project_root + finding.file), then "
                              "start_line <= finding.line <= end_line",
            },
        },

        # ---- the other packer, entirely on its own ------------------------
        "ai_audit_packs": audit,

        "packets": {track: {r: len(p) for r, p in sorted(per.items())}
                    for track, per in sorted(packets.items())},
        "contracts": {
            "findings": {"labels": list(TRACK_A_LABELS),
                         "fields": list(TRACK_A_LABEL_FIELDS)},
            "blind": {"outcomes": list(TRACK_B_OUTCOMES),
                      "issue_fields": list(TRACK_B_ISSUE_FIELDS),
                      "note": "false_positive is not offered: there is no "
                              "claim on this track to be false about."},
        },
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(
        description="REAL-CORPUS-1A sampling and reviewer packets "
                    "(no labels, no measurement)")
    p.add_argument("--manifest", required=True)
    p.add_argument("--root", required=True)
    args = p.parse_args(argv)
    try:
        summary = build_corpus(Path(args.manifest), Path(args.root))
    except SamplingError as e:
        print(f"sampling refused: {e}", file=sys.stderr)
        return 2
    problem = public_output_problem(json.dumps(summary))
    if problem is not None:                       # never emit a leaky summary
        print(f"summary is not committable: {problem}", file=sys.stderr)
        return 3
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
