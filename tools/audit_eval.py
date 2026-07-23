"""W3-E2: local evaluator linking AI-audit candidates to their HUMAN
reviews — one sidecar in, aggregate counters out. No precision claims from
smokes: rates are only meaningful once a decided corpus exists.

Future metrics tracked here (all with explicit numerator/denominator):
- confirmed candidate rate on DECIDED candidates only
- uncertainty/abstention share, reported separately (never a failure)
- citation validity is enforced upstream at parse time (a candidate cannot
  exist with an invalid citation), so it is 1.0 by construction for stored
  candidates and re-checked structurally here
- duplicate rate (identical candidate_ids are impossible; this counts
  same-file/line/query collisions across digests)
- latency per query/model from the stored unit results
- per-query false-positive rate — only after a sufficient corpus
"""
from __future__ import annotations

import json
from pathlib import Path


class AuditEvalError(Exception):
    """Bad input. Messages never echo file contents."""


def evaluate_sidecar(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise AuditEvalError(
            f"sidecar unreadable: {e.__class__.__name__}") from e
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise AuditEvalError("not an ai-audit sidecar (schema_version 1)")
    candidates = data.get("candidates", {})
    reviews = data.get("candidate_reviews", {})
    results = data.get("results", {})

    decided = {"confirmed": 0, "false_positive": 0, "uncertain": 0}
    for cid in candidates:
        r = reviews.get(cid)
        if isinstance(r, dict) and r.get("decision") in decided:
            decided[r["decision"]] += 1
    n_decided = decided["confirmed"] + decided["false_positive"]

    per_query: dict[str, dict] = {}
    site_seen: dict[tuple, int] = {}
    for c in candidates.values():
        q = c.get("query_id", "?")
        row = per_query.setdefault(q, {"candidates": 0})
        row["candidates"] += 1
        site = (c.get("project"), c.get("file"), c.get("line"), q)
        site_seen[site] = site_seen.get(site, 0) + 1
    duplicates = sum(n - 1 for n in site_seen.values() if n > 1)

    latency: dict[str, list[int]] = {}
    outcomes = {"issues_found": 0, "no_issue_observed": 0,
                "insufficient_context": 0}
    for r in results.values():
        if not isinstance(r, dict):
            continue
        oc = r.get("outcome")
        if oc in outcomes:
            outcomes[oc] += 1
        key = f"{r.get('query_id', '?')}::{r.get('model', '?')}"
        if isinstance(r.get("latency_ms"), int):
            latency.setdefault(key, []).append(r["latency_ms"])

    return {
        "candidates": len(candidates),
        "reviewed": sum(decided.values()),
        "decided": n_decided,
        "confirmed_candidate_rate": {
            "numerator": decided["confirmed"], "denominator": n_decided,
            "value": round(decided["confirmed"] / n_decided, 4)
            if n_decided else None},
        "uncertain": decided["uncertain"],       # abstention — NOT a failure
        "unit_outcomes": outcomes,
        "duplicate_site_collisions": duplicates,
        "latency_ms_by_query_model": {
            k: {"n": len(v), "min": min(v), "max": max(v),
                "mean": round(sum(v) / len(v))}
            for k, v in sorted(latency.items())},
        "note": ("Rates are meaningless without a sufficiently large DECIDED "
                 "corpus; never derive model quality from a smoke run."),
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("usage: audit_eval.py <report.ai-audit.json>")
        raise SystemExit(2)
    try:
        out = evaluate_sidecar(Path(sys.argv[1]))
    except AuditEvalError as e:
        print(f"error: {e}")
        raise SystemExit(2) from None
    print(json.dumps(out, ensure_ascii=True, indent=1))
