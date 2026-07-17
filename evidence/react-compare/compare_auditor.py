"""Re-run the React comparison corpus against the IMPLEMENTED auditor rules
(not code-derived tests) and reproduce the divergence table vs the recorded
eslint-plugin-react-hooks 7.1.1 baseline (eslint-results.json).

Usage:  .venv\\Scripts\\python evidence\\react-compare\\compare_auditor.py
"""
from __future__ import annotations

import json
from pathlib import Path

import tree_sitter_typescript

from auditor.adapters.typescript.react_rules import REACT_RULES
from auditor.core import treesitter as ts
from auditor.core.models import SourceFile
from auditor.core.treesitter import parse_source

ts.register_language("tsx", tree_sitter_typescript.language_tsx())

HERE = Path(__file__).parent
CORPUS = HERE / "corpus"

eslint = {Path(e["filePath"]).name: e
          for e in json.loads((HERE / "eslint-results.json").read_text(
              encoding="utf-8-sig"))}

rows = []
for path in sorted(CORPUS.glob("*.tsx")):
    sf = SourceFile(path=path, rel=path.name, language="tsx",
                    text=path.read_bytes())
    parse_source(sf)
    ours = [f for rule in REACT_RULES for f in rule.check(sf)]
    our_ids = sorted({f.rule_id for f in ours})
    es = eslint.get(path.name, {})
    es_rules = sorted({m["ruleId"].split("/")[-1] for m in es.get("messages", [])})
    agree = bool(our_ids) == bool(es_rules)
    rows.append((path.name, ",".join(es_rules) or "-", ",".join(our_ids) or "-",
                 "AGREE" if agree else "DIVERGE"))

w = max(len(r[0]) for r in rows)
print(f"{'file':<{w}}  {'eslint 7.1.1':<18} {'auditor':<16} verdict")
print("-" * (w + 44))
diverges = 0
for name, es_r, our_r, verdict in rows:
    if verdict == "DIVERGE":
        diverges += 1
    print(f"{name:<{w}}  {es_r:<18} {our_r:<16} {verdict}")
print(f"\n{len(rows)} files, {diverges} divergence(s)")
