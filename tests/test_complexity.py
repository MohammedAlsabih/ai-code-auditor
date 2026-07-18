from pathlib import Path

from auditor.core.complexity import complexity_findings
from auditor.core.models import SourceFile

COMPLEX_PY = "def classify(n):\n" + "".join(
    f"    {'if' if i == 0 else 'elif'} n < {i + 1}:\n        return {i}\n"
    for i in range(11)) + "    return -1\n"


def test_p006_flags_complex_function():
    sf = SourceFile(path=Path("c.py"), rel="c.py", language="python",
                    text=COMPLEX_PY.encode())
    fs = complexity_findings([sf])
    assert len(fs) == 1 and fs[0].rule_id == "P006"
    assert "classify" in fs[0].detail and fs[0].severity.value == "yellow"


def test_p006_simple_function_clean():
    sf = SourceFile(path=Path("s.py"), rel="s.py", language="python",
                    text=b"def f():\n    return 1\n")
    assert complexity_findings([sf]) == []


def test_p006_works_for_tsx():
    code = "export function big(n: number) {\n" + "".join(
        f"  if (n === {i}) return {i};\n" for i in range(12)) + "  return -1;\n}\n"
    sf = SourceFile(path=Path("b.tsx"), rel="b.tsx", language="tsx", text=code.encode())
    fs = complexity_findings([sf])
    assert [f.rule_id for f in fs] == ["P006"]


def test_lizard_per_file_failure_reaches_failure_counters(monkeypatch):
    # independent-sweep catch: the swallowed per-file lizard exception used to
    # land in rule_errors ONLY — rule_health stayed 1.0 and verdict could PASS
    from auditor.core import complexity as cx
    from auditor.core.models import Diagnostics
    from auditor.core.scoring import verdict

    def boom(name, src):
        raise RuntimeError("lizard exploded")
    monkeypatch.setattr(cx.lizard.analyze_file, "analyze_source_code", boom)
    sf = SourceFile(path=Path("x.py"), rel="x.py", language="python", text=b"x = 1\n")
    diag = Diagnostics()
    assert cx.complexity_findings([sf], diag=diag) == []
    assert diag.rule_attempted == 1 and diag.rule_failures == 1
    assert verdict({"red": 0, "yellow": 0}, 100,
                   {"rule_attempted": diag.rule_attempted,
                    "rule_failures": diag.rule_failures,
                    "rule_errors": diag.rule_errors}) != "pass"
