"""Re-run the React comparison corpus against the IMPLEMENTED auditor rules
(not code-derived tests) and reproduce the divergence table vs the recorded
eslint-plugin-react-hooks 7.1.1 baseline (eslint-results.json).

Two scopes:
  * HOOKS family (auditor R001-R005 <-> eslint rules-of-hooks/exhaustive-deps):
    agree/diverge comparison — these rules overlap by design.
  * AUDITOR-EXTRA (R006 index-key, R007 dangerouslySetInnerHTML): NOT covered by
    eslint-plugin-react-hooks, so they are reported as auditor-only coverage,
    never counted as a disagreement.

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
HOOKS_RULES = {"R001", "R002", "R003", "R004", "R005"}   # overlap eslint-hooks
EXTRA_RULES = {"R006", "R007"}                           # outside eslint-hooks scope

eslint = {Path(e["filePath"]).name: e
          for e in json.loads((HERE / "eslint-results.json").read_text(
              encoding="utf-8-sig"))}

rows = []
extra = []
for path in sorted(CORPUS.glob("*.tsx")):
    sf = SourceFile(path=path, rel=path.name, language="tsx", text=path.read_bytes())
    parse_source(sf)
    ours = {f.rule_id for rule in REACT_RULES for f in rule.check(sf)}
    es_rules = sorted({m["ruleId"].split("/")[-1] for m in eslint.get(path.name, {}).get("messages", [])})
    our_hooks = sorted(ours & HOOKS_RULES)
    our_extra = sorted(ours & EXTRA_RULES)
    if our_extra:
        extra.append((path.name, ",".join(our_extra)))
    agree = bool(our_hooks) == bool(es_rules)
    rows.append((path.name, ",".join(es_rules) or "-", ",".join(our_hooks) or "-",
                 "AGREE" if agree else "DIVERGE"))

w = max(len(r[0]) for r in rows)
print(f"{'file':<{w}}  {'eslint 7.1.1':<18} {'auditor (hooks)':<16} verdict")
print("-" * (w + 44))
diverges = 0
for name, es_r, our_r, verdict in rows:
    if verdict == "DIVERGE":
        diverges += 1
    print(f"{name:<{w}}  {es_r:<18} {our_r:<16} {verdict}")
print(f"\n{len(rows)} files, {diverges} hooks divergence(s)")
print("\nauditor-extra coverage (outside eslint-plugin-react-hooks):")
for name, rules in extra:
    print(f"  {name}: {rules}")
