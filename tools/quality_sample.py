"""W2-B2.8D deterministic sampler — committed, path-agnostic, offline.

Selects the reviewed sample from one or more auditor `report.json` files by a
fixed, reproducible rule (NOT a probabilistic draw — no confidence interval):

1. Every finding with level == "error" or gate_action == "block" is taken
   unconditionally.
2. Every alias listed in `full_review` is taken in full.
3. Any (alias, rule) stratum whose population is <= cap is taken in full.
4. Larger strata are capped at `cap`, chosen round-robin across projects in
   fingerprint order, counting anything already taken by step 1.
5. Dedup is on the FULL identity (alias, fingerprint, file, line): a
   fingerprint deliberately excludes the line number, so two findings sharing
   one fingerprint on different lines are distinct and both eligible.

The output order and selection are invariant to the JSON ordering of projects
and findings: everything is canonically sorted before selection.

Real filesystem paths are provided by the caller at runtime and are NEVER
echoed into exceptions or results — errors identify the report only by its
alias. Each selected entry carries a deterministic `sample_id` derived from
the full identity, which is the join key for the local labels file.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from pathlib import Path


class SampleError(Exception):
    """Unreadable or malformed report. Messages name the repo ALIAS only —
    never the filesystem path."""


def sample_id(alias: str, project: str, file: str, line: int, rule: str,
              fingerprint: str) -> str:
    """Deterministic id over the full finding identity."""
    blob = json.dumps([alias, project, file, line, rule, fingerprint],
                      ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _load_findings(alias: str, path: Path) -> list[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as e:
        raise SampleError(
            f"report for {alias!r} unreadable: {e.__class__.__name__}") from e
    except json.JSONDecodeError as e:
        raise SampleError(
            f"report for {alias!r} is not valid JSON: line {e.lineno}") from e
    projects = data.get("projects")
    if not isinstance(projects, list):
        raise SampleError(f"report for {alias!r} has no projects list")
    out = []
    for pr in projects:
        root = pr.get("root")
        for f in pr.get("findings", ()):
            out.append({
                "alias": alias, "project": root, "file": f["file"],
                "line": f["line"], "rule": f["rule_id"],
                "fingerprint": f["fingerprint"], "level": f["level"],
                "gate_action": f["gate_action"],
            })
    # canonical order — selection must not depend on JSON ordering
    out.sort(key=lambda f: (f["project"], f["file"], f["line"], f["rule"],
                            f["fingerprint"]))
    return out


def select_sample(reports: Mapping[str, Path], cap: int = 20,
                  full_review: Iterable[str] = ("repo-b",)) -> list[dict]:
    """Select the deterministic sample. `reports` maps alias -> report.json
    path. Returns entries with identity fields, population, and sample_id."""
    full = set(full_review)
    selected: list[dict] = []
    picked: set[tuple] = set()

    def key(f: dict) -> tuple:
        return (f["alias"], f["fingerprint"], f["file"], f["line"])

    def add(f: dict, pop: int) -> bool:
        k = key(f)
        if k in picked:
            return False
        picked.add(k)
        selected.append({
            "sample_id": sample_id(f["alias"], f["project"], f["file"],
                                   f["line"], f["rule"], f["fingerprint"]),
            "alias": f["alias"], "rule": f["rule"], "population": pop,
            "project": f["project"], "file": f["file"], "line": f["line"],
            "fingerprint": f["fingerprint"], "level": f["level"],
            "gate_action": f["gate_action"],
        })
        return True

    for alias in sorted(reports):
        findings = _load_findings(alias, reports[alias])
        by_rule: dict[str, dict[str, list[dict]]] = {}
        for f in findings:
            by_rule.setdefault(f["rule"], {}).setdefault(f["project"], []) \
                .append(f)
        pop_of = {r: sum(len(v) for v in b.values())
                  for r, b in by_rule.items()}
        # 1) mandatory union: every error-level or gate=block finding
        for f in findings:
            if f["level"] == "error" or f["gate_action"] == "block":
                add(f, pop_of[f["rule"]])
        # 2) per-rule strata
        for rule in sorted(by_rule):
            pop = pop_of[rule]
            buckets = {p: sorted(fs, key=lambda x: (x["fingerprint"],
                                                    x["file"], x["line"]))
                       for p, fs in by_rule[rule].items()}
            order = sorted(buckets)
            if alias in full or pop <= cap:
                for p in order:
                    for f in buckets[p]:
                        add(f, pop)
            else:
                idx = dict.fromkeys(order, 0)
                taken = sum(1 for s in selected
                            if s["alias"] == alias and s["rule"] == rule)
                while taken < cap:
                    progressed = False
                    for p in order:
                        if taken >= cap:
                            break
                        i = idx[p]
                        if i < len(buckets[p]):
                            idx[p] += 1
                            if add(buckets[p][i], pop):
                                taken += 1
                                progressed = True
                    if not progressed:
                        break
    selected.sort(key=lambda s: (s["alias"], s["rule"], s["project"],
                                 s["file"], s["line"], s["fingerprint"]))
    return selected


if __name__ == "__main__":
    import sys
    # usage: quality_sample.py alias=path [alias=path ...] out.json
    *pairs, dst = sys.argv[1:]
    reports = {}
    for pair in pairs:
        alias, _, p = pair.partition("=")
        reports[alias] = Path(p)
    result = select_sample(reports)
    Path(dst).write_text(json.dumps(result, ensure_ascii=False, indent=1)
                         + "\n", encoding="utf-8")
    print(f"selected {len(result)} findings across {len(reports)} report(s)")
