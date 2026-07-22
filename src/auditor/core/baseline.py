"""Baseline / New-Findings-Only (W2-B2.8B2-C).

A finding gets a content FINGERPRINT that is independent of review_id and of
the LINE NUMBER: SHA-256 over the canonical JSON of
    {anchor, engine, file, project_root, rule_id}
where anchor = the snippet after whitespace trim/collapse, falling back to
the title when the snippet is empty. Moving code up or down a file therefore
does NOT create a "new" finding; changing the file, the rule, or the matched
text does. review_id (identity for the review sidecar, line included) is a
different contract and never changes here.

Matching is a MULTISET (Counter), never a set: two identical findings in the
baseline absorb exactly two identical current findings — the third is new.

The baseline file is a prior report.json: bounded read, structured JSON only,
fail-CLOSED on corruption/oversize/incompatibility. Baselines produced before
this feature carry no `fingerprint` field — their fingerprints are recomputed
from the same serialized fields (which is exactly how current fingerprints
are computed too, AFTER redaction, so the two sides always hash the same
text). Error messages never echo machine paths or snippet content.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from auditor.errors import AuditorError

FINGERPRINT_VERSION = "auditorFinding/v1"
# report.json is decisions + findings text; field reports run ~1-10 MB.
# The cap is generous but bounded — an oversize file fails closed.
BASELINE_MAX_BYTES = 64 * 1024 * 1024

_FP_RE = re.compile(r"^[0-9a-f]{64}$")


class BaselineError(AuditorError):
    """Baseline unusable (missing, oversize, corrupt, or not an
    ai-code-auditor report). Messages are user-safe: no machine paths, no
    snippet/content echo."""


def normalize_anchor(snippet: str, title: str) -> str:
    """Whitespace-insensitive anchor: trim + collapse every whitespace run to
    one space; an empty snippet falls back to the (collapsed) title."""
    s = " ".join((snippet or "").split())
    return s if s else " ".join((title or "").split())


def finding_fingerprint(project_root: str, file: str, rule_id: str,
                        engine: str, anchor: str) -> str:
    """Line-independent content identity. Canonical JSON (sorted keys, compact
    separators, ensure_ascii so lone surrogates cannot break the encode) —
    structural, so no delimiter injection can collide two findings."""
    key = json.dumps(
        {"anchor": anchor, "engine": engine, "file": file,
         "project_root": project_root, "rule_id": rule_id},
        ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def fingerprint_of_serialized(project_root: str, finding: dict) -> str:
    """Fingerprint from a SERIALIZED finding dict (report.json shape) — the
    single recompute path used for both baseline entries without a stored
    fingerprint and (via build_report) current findings."""
    return finding_fingerprint(
        project_root=project_root,
        file=str(finding.get("file", "")),
        rule_id=str(finding.get("rule_id", "")),
        engine=str(finding.get("engine", "") or "auditor"),
        anchor=normalize_anchor(str(finding.get("snippet", "") or ""),
                                str(finding.get("title", "") or "")),
    )


def _require(cond: bool, reason: str) -> None:
    if not cond:
        raise BaselineError(f"baseline: {reason}")


def load_baseline_counter(path: Path) -> Counter[str]:
    """Fingerprint multiset of every finding in a prior report.json.
    Fail-closed: any structural violation raises BaselineError — nothing is
    skipped or repaired silently, because a silently-shrunken baseline would
    reclassify old findings as new (or worse, hide new ones)."""
    cap = BASELINE_MAX_BYTES
    over = f"file exceeds the {cap // (1024 * 1024)} MB limit"
    try:
        size = path.stat().st_size
    except OSError as e:
        raise BaselineError("baseline: file not found or unreadable") from e
    # stat is a CHEAP EARLY refusal only — it proves nothing about what a
    # later read returns (the file can grow in between, and stat can lie).
    _require(size <= cap, over)
    # the actual guarantee: a BOUNDED binary read of cap+1 bytes, never
    # read_text()/read_bytes() (both unbounded). cap+1 bytes present ⇒ the
    # content exceeds the cap ⇒ fail closed.
    try:
        with path.open("rb") as fh:
            raw = fh.read(cap + 1)
    except OSError as e:
        raise BaselineError("baseline: file not found or unreadable") from e
    _require(len(raw) <= cap, over)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise BaselineError("baseline: file is not readable UTF-8 text") from e
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise BaselineError("baseline: file is not valid JSON") from e
    _require(isinstance(data, dict), "file is not a JSON object")
    # compatibility gate: a report from another tool (or a random JSON file)
    # is never accepted silently as an empty baseline
    _require(data.get("tool") == "ai-code-auditor",
             "not an ai-code-auditor report (tool field mismatch)")
    projects = data.get("projects")
    _require(isinstance(projects, list), "projects must be a list")
    counter: Counter[str] = Counter()
    for proj in projects:
        _require(isinstance(proj, dict), "each project must be an object")
        root = proj.get("root")
        _require(isinstance(root, str), "each project must carry a string root")
        findings = proj.get("findings", [])
        _require(isinstance(findings, list),
                 "each project's findings must be a list")
        for f in findings:
            _require(isinstance(f, dict), "each finding must be an object")
            fp = f.get("fingerprint")
            if isinstance(fp, str) and _FP_RE.match(fp):
                counter[fp] += 1
                continue
            _require(fp is None,
                     "a finding carries a malformed fingerprint field")
            # pre-B2.8B2 baseline: recompute from the serialized fields
            for name in ("file", "rule_id"):
                _require(isinstance(f.get(name), str),
                         f"a finding's {name} field is not a string")
            counter[fingerprint_of_serialized(root, f)] += 1
    return counter


def match_findings(current_fps: list[str],
                   baseline: Counter[str]) -> tuple[list[str], dict[str, int]]:
    """Classify current fingerprints against the baseline multiset.
    Returns (states aligned with current_fps: 'new'|'unchanged', summary
    {new, unchanged, resolved}). Duplicates match one-for-one; order of the
    current list cannot change the totals (pure counting)."""
    remaining = Counter(baseline)
    states: list[str] = []
    for fp in current_fps:
        if remaining[fp] > 0:
            remaining[fp] -= 1
            states.append("unchanged")
        else:
            states.append("new")
    resolved = sum(remaining.values())
    return states, {
        "new": states.count("new"),
        "unchanged": states.count("unchanged"),
        # a COUNT only — baseline finding content is never copied forward
        "resolved": resolved,
    }
