"""CP-8 gate: the ESLint comparison corpus, run against the IMPLEMENTED rules
(not code-derived tests), reproduces exactly the two documented intentional
divergences AND now covers React.useState member hooks + direct
dangerouslySetInnerHTML. Uses the recorded eslint-plugin-react-hooks 7.1.1
baseline (evidence/react-compare/eslint-results.json) — no node required."""
import json
from pathlib import Path

from auditor.adapters.typescript.react_rules import REACT_RULES
from auditor.core.models import SourceFile
from auditor.core.treesitter import parse_source

_ROOT = Path(__file__).resolve().parent.parent / "evidence" / "react-compare"
_CORPUS = _ROOT / "corpus"
_HOOKS = {"R001", "R002", "R003", "R004", "R005"}   # overlap eslint-hooks
_EXTRA = {"R006", "R007"}                           # outside eslint-hooks scope


def _auditor(name: str) -> set[str]:
    p = _CORPUS / name
    sf = SourceFile(path=p, rel=name, language="tsx", text=p.read_bytes())
    parse_source(sf)
    return {f.rule_id for rule in REACT_RULES for f in rule.check(sf)}


def _eslint():
    data = json.loads((_ROOT / "eslint-results.json").read_text(encoding="utf-8-sig"))
    return {Path(e["filePath"]).name:
            sorted({m["ruleId"].split("/")[-1] for m in e["messages"]}) for e in data}


def test_corpus_reproduces_only_the_two_documented_divergences():
    es = _eslint()
    diverges = []
    for p in sorted(_CORPUS.glob("*.tsx")):
        our_hooks = _auditor(p.name) & _HOOKS
        if bool(our_hooks) != bool(es.get(p.name)):
            diverges.append(p.name)
    # ONLY the two intentional, documented divergences survive
    assert set(diverges) == {"effect_no_deps.tsx", "hook_in_try_catch.tsx"}


def test_corpus_covers_react_namespace_hook():
    # ESLint flags React.useState conditional; auditor must now agree (R001)
    assert "rules-of-hooks" in _eslint()["react_namespace_hook.tsx"]
    assert "R001" in _auditor("react_namespace_hook.tsx")


def test_corpus_covers_direct_dangerous_html():
    # dangerouslySetInnerHTML={expr} is outside eslint-plugin-react-hooks, but
    # auditor R007 catches it (auditor-extra coverage)
    assert "R007" in (_auditor("dangerous_html_direct.tsx") & _EXTRA)
