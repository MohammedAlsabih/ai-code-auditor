"""Re-score a STORED quality run with the current counting rules.

Why this exists: the first W3-E7 measurement run was voided because the harness
recorded only the agent's *effective* verdict, so the runtime's evidence guard
was indistinguishable from the model's own abstention. Fixing the counting rules
changes what the numbers mean — which makes the previously published W3-E6
numbers no longer comparable to anything scored afterwards. This tool re-scores
an archived run under the corrected rules so the comparison is apples to apples.

It replays only: nothing is re-run, no model is called, no stored file is
written. Reading a stored run requires naming the agent prompt version it was
produced with — the verifier stays fail-closed on drift for live runs, and an
archived run must be replayed against its own version explicitly, never
silently.

    python tools/quality_rescore.py --run-dir .quality-local/ai-quality/w3e6-gate \\
        --agent-prompt-version w3e5-agent-v2
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from auditor.ai.quality_corpus import (  # noqa: E402
    SPLIT_CROSS_PROJECT,
    SPLIT_DEVELOPMENT,
    SPLIT_HOLDOUT,
    cases,
)
from auditor.ai.quality_harness import (  # noqa: E402
    ENGINES,
    anonymized_summary,
    build_plan,
    classify,
    earned_evidence,
    observations,
)

GROUPS = {"dev": SPLIT_DEVELOPMENT, "holdout": SPLIT_HOLDOUT,
          "cross_project": SPLIT_CROSS_PROJECT}


def main() -> int:
    ap = argparse.ArgumentParser(description="re-score a stored quality run")
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--agent-prompt-version", default=None,
                    help="the version the stored agent results were produced "
                         "with; required when replaying an older run")
    args = ap.parse_args()

    run = Path(args.run_dir)
    out: dict[str, Any] = {"run_dir": run.name, "groups": {}}
    for gname, split in GROUPS.items():
        pairs_f = run / f"pairs-{gname}.json"
        if not pairs_f.exists():
            continue
        pairs = json.loads(pairs_f.read_text(encoding="utf-8"))
        corpus = cases(split)
        plan = build_plan(corpus)
        g: dict[str, Any] = {}
        for engine in ENGINES:
            res = [p[engine] for p in pairs if engine in p]
            if len(res) != len(corpus):
                g[engine] = {"skipped": "partial run"}
                continue
            cl = classify(plan, res, corpus, args.agent_prompt_version)
            obs = observations(res, plan)
            g[engine] = {
                "totals": anonymized_summary(cl)["totals"],
                "acceptance": earned_evidence(
                    obs["rows"],
                    cross_project=split == SPLIT_CROSS_PROJECT)["rows"],
            }
        out["groups"][gname] = g

    print(json.dumps(out, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
