import json

from auditor.adapters import default_adapters
from auditor.core.complexity import complexity_findings
from auditor.core.execution import ExecutionLedger, merge_ledgers
from auditor.core.interfaces import Rule
from auditor.core.models import Diagnostics, Finding, Severity, SourceFile
from auditor.core.patterns import run_pattern_engine


def _adapter(lang="python"):
    for a in default_adapters():
        if lang in a.grammars():
            return a
    raise AssertionError(lang)


def _sf(tmp_path, name, text, language="python"):
    p = tmp_path / name
    p.write_bytes(text.encode())
    return SourceFile(path=p, rel=name, language=language, text=text.encode())


def _run(tmp_path, files, adapter=None, frameworks=(), extra_rules=None):
    adapter = adapter or _adapter()
    if extra_rules is not None:
        # tiny stub adapter view: reuse real adapter but inject rules
        class _View:
            name = adapter.name
            def syntax(self):
                return adapter.syntax()
            def language_rules(self):
                return extra_rules
            def project_rules(self, root, fw):
                return []
        adapter_used = _View()
    else:
        adapter_used = adapter
    diag = Diagnostics()
    ledger = ExecutionLedger(language=adapter.name, root=".")
    findings = run_pattern_engine(adapter_used, tmp_path, files,
                                  list(frameworks), diag=diag, ledger=ledger)
    return findings, diag, ledger


def test_zero_findings_still_counts_attempts(tmp_path):
    files = [_sf(tmp_path, "a.py", "x = 1\n"), _sf(tmp_path, "b.py", "y = 2\n")]
    _, _, ledger = _run(tmp_path, files)
    rec = ledger.rules["P001"]                    # clean files: no findings
    assert rec.eligible_inputs == 2
    assert rec.attempted == 2                     # execution proven WITHOUT findings
    assert rec.failures == 0 and rec.blocked_inputs == 0


def test_multi_output_ids_share_attempts_even_without_findings(tmp_path):
    files = [_sf(tmp_path, "a.py", "password = 'x'\n")]  # P003 fires, P002 not
    findings, _, ledger = _run(tmp_path, files)
    emitted = {f.rule_id for f in findings}
    assert "P002" not in emitted                  # no known-token secret here
    assert ledger.rules["P002"].attempted == 1    # but P002 provably RAN
    assert ledger.rules["P003"].attempted == 1
    # same contract for P004/P005 (no SQL in file => zero findings, one attempt)
    assert ledger.rules["P004"].attempted == 1
    assert ledger.rules["P005"].attempted == 1


def test_r004_r005_share_attempts(tmp_path):
    ts = _adapter("typescript")
    files = [_sf(tmp_path, "a.tsx", "export const x = 1\n", language="tsx")]
    _, _, ledger = _run(tmp_path, files, adapter=ts, frameworks=("react",))
    assert ledger.rules["R004"].attempted == 1
    assert ledger.rules["R005"].attempted == 1


def test_framework_gated_rules_are_ineligible_not_zero_attempt_claims(tmp_path):
    ts = _adapter("typescript")
    files = [_sf(tmp_path, "a.tsx", "export const x = 1\n", language="tsx")]
    _, _, ledger = _run(tmp_path, files, adapter=ts, frameworks=())  # NO react
    # React rules never appear in the ledger at all — ineligible, not "ran 0x"
    assert "R001" not in ledger.rules
    assert "R004" not in ledger.rules
    # non-framework rules still ran
    assert ledger.rules["P001"].attempted == 1


class _Boom(Rule):
    id = "X999"
    severity = Severity.YELLOW
    title = "boom"

    def check(self, sf):
        raise RuntimeError("boom")


class _Fake(Rule):
    id = "F001"
    severity = Severity.YELLOW
    title = "fake"

    def check(self, sf):
        return [Finding(rule_id="ZZZ9", severity=Severity.YELLOW, title="t",
                        file=sf.rel, line=1, language=sf.language)]


def test_parse_failed_file_blocks_without_attempt(tmp_path, monkeypatch):
    good = _sf(tmp_path, "good.py", "x = 1\n")
    bad = _sf(tmp_path, "bad.py", "y = 2\n")
    import auditor.core.patterns as patterns
    real = patterns.parse_source

    def flaky(sf):
        if sf.rel == "bad.py":
            raise RuntimeError("no grammar")
        return real(sf)

    monkeypatch.setattr(patterns, "parse_source", flaky)
    _, diag, ledger = _run(tmp_path, [good, bad])
    rec = ledger.rules["P001"]
    assert rec.eligible_inputs == 2               # both were scheduled
    assert rec.blocked_inputs == 1                # bad.py never reached check
    assert rec.attempted == 1                     # only good.py ran
    assert any("bad.py" in e for e in diag.parse_error_files)


def test_partial_parse_still_attempts_and_is_recorded(tmp_path):
    broken = _sf(tmp_path, "broken.py", "def f(:\n    pass\n")  # syntax error
    _, diag, ledger = _run(tmp_path, [broken])
    rec = ledger.rules["P001"]
    assert rec.partial_parse_inputs == 1
    assert rec.attempted == 1                     # check still ran on the tree
    assert rec.blocked_inputs == 0


def test_exception_in_one_rule_is_visible_and_does_not_stop_others(tmp_path):
    files = [_sf(tmp_path, "a.py", "x = 1\n")]
    _, diag, ledger = _run(tmp_path, files, extra_rules=[_Boom()])
    assert ledger.rules["X999"].attempted == 1
    assert ledger.rules["X999"].failures == 1
    assert ledger.rules["P001"].attempted == 1    # later/other rules unaffected
    assert any("X999" in e for e in diag.rule_errors)


def test_contract_violation_recorded_not_swallowed(tmp_path):
    files = [_sf(tmp_path, "a.py", "x = 1\n")]
    findings, diag, ledger = _run(tmp_path, files, extra_rules=[_Fake()])
    assert any("F001 emitted undeclared id ZZZ9" in e for e in ledger.contract_errors)
    assert any(e.startswith("contract:") for e in diag.rule_errors)
    assert any(f.rule_id == "ZZZ9" for f in findings)   # data kept, error loud
    assert ledger.rules["F001"].attempted == 1          # audit continued


def test_complexity_success_and_failure_not_double_counted(tmp_path, monkeypatch):
    import auditor.core.complexity as cx
    good = _sf(tmp_path, "ok.py", "def f():\n    return 1\n")
    bad = _sf(tmp_path, "bad.py", "def g():\n    return 2\n")
    real = cx.lizard.analyze_file.analyze_source_code

    def flaky(name, text):
        if "bad" in name:
            raise RuntimeError("lizard exploded")
        return real(name, text)

    monkeypatch.setattr(cx.lizard.analyze_file, "analyze_source_code", flaky)
    diag = Diagnostics()
    ledger = ExecutionLedger(language="python", root=".")
    complexity_findings([good, bad], diag=diag, ledger=ledger)
    rec = ledger.rules["P006"]
    assert rec.eligible_inputs == 2
    assert rec.attempted == 2                     # one ok + one failed — no doubling
    assert rec.failures == 1
    assert rec.blocked_inputs == 0                # lizard needs no tree


def test_merge_keeps_project_contexts_separate():
    a = ExecutionLedger(language="python", root="backend")
    a.eligible(("P001",), n=3)
    a.attempted_ok(("P001",))
    b = ExecutionLedger(language="typescript", root="frontend")
    b.eligible(("P001",), n=5)
    b.attempted_failed(("P001",))
    merged = merge_ledgers([a, b])
    assert len(merged) == 2
    assert merged[0].root == "backend" and merged[0].rules["P001"].eligible_inputs == 3
    assert merged[1].root == "frontend" and merged[1].rules["P001"].failures == 1
    # counters were NOT mixed
    assert merged[0].rules["P001"].failures == 0


def test_text_rules_run_when_parse_fails(tmp_path, monkeypatch):
    """A parse failure blocks TREE rules but text-only rules (P002/P003 secrets,
    P007 comments) still run on sf.text and can emit findings."""
    import auditor.core.patterns as patterns
    f = _sf(tmp_path, "x.py",
            "password = 'definitely-secret-value'\n# TODO: implement\n")
    monkeypatch.setattr(patterns, "parse_source",
                        lambda sf: (_ for _ in ()).throw(RuntimeError("no parse")))
    findings, diag, ledger = _run(tmp_path, [f])
    emitted = {x.rule_id for x in findings}
    assert "P003" in emitted and "P007" in emitted     # text rules produced data
    for text_id in ("P002", "P003", "P007"):
        assert ledger.rules[text_id].attempted == 1
        assert ledger.rules[text_id].blocked_inputs == 0
    for tree_id in ("P001", "P004", "P005"):           # tree rules blocked
        assert ledger.rules[tree_id].blocked_inputs == 1
        assert ledger.rules[tree_id].attempted == 0


def test_partial_parse_flags_tree_rules_only(tmp_path):
    """On a partial tree, tree rules get partial_parse; text rules run normally
    with partial_parse_inputs == 0."""
    broken = _sf(tmp_path, "broken.py", "def f(:\n    password = 'x'\n")
    _, _, ledger = _run(tmp_path, [broken])
    assert ledger.rules["P001"].partial_parse_inputs == 1     # tree rule
    assert ledger.rules["P001"].attempted == 1
    assert ledger.rules["P007"].partial_parse_inputs == 0     # text rule
    assert ledger.rules["P007"].attempted == 1


def test_healthy_path_no_double_attempts(tmp_path):
    f = _sf(tmp_path, "a.py", "x = 1\n")
    _, _, ledger = _run(tmp_path, [f])
    for rid in ("P001", "P002", "P003", "P007"):
        assert ledger.rules[rid].attempted == 1              # exactly once


def test_undeclared_id_is_kept_but_invocation_failed_once(tmp_path):
    class _MultiBad(Rule):
        id = "F002"
        severity = Severity.YELLOW
        title = "t"
        output_ids = ("F002",)

        def check(self, sf):
            return [Finding(rule_id="BAD1", severity=Severity.YELLOW, title="t",
                            file=sf.rel, line=1, language=sf.language),
                    Finding(rule_id="BAD2", severity=Severity.YELLOW, title="t",
                            file=sf.rel, line=2, language=sf.language)]

    f = _sf(tmp_path, "a.py", "x = 1\n")
    findings, diag, ledger = _run(tmp_path, [f], extra_rules=[_MultiBad()])
    kept = {x.rule_id for x in findings}
    assert {"BAD1", "BAD2"} <= kept                          # data kept
    rec = ledger.rules["F002"]
    assert rec.attempted == 1 and rec.failures == 1          # ONE failed invocation
    assert diag.rule_failures >= 1


def test_none_and_non_finding_return_do_not_crash(tmp_path):
    class _NoneRule(Rule):
        id = "N001x"
        severity = Severity.YELLOW
        title = "t"

        def check(self, sf):
            return None

    class _JunkList(Rule):
        id = "J001x"
        severity = Severity.YELLOW
        title = "t"

        def check(self, sf):
            return ["not-a-finding",
                    Finding(rule_id="J001x", severity=Severity.YELLOW, title="t",
                            file=sf.rel, line=1, language=sf.language)]

    class _After(Rule):
        id = "A001x"
        severity = Severity.YELLOW
        title = "t"

        def check(self, sf):
            return []

    f = _sf(tmp_path, "a.py", "x = 1\n")
    findings, diag, ledger = _run(tmp_path, [f],
                                  extra_rules=[_NoneRule(), _JunkList(), _After()])
    # None => failed invocation, no crash
    assert ledger.rules["N001x"].attempted == 1 and ledger.rules["N001x"].failures == 1
    # junk element dropped, valid Finding kept, invocation failed once
    assert ledger.rules["J001x"].attempted == 1 and ledger.rules["J001x"].failures == 1
    assert any(x.rule_id == "J001x" for x in findings)
    assert not any(x == "not-a-finding" for x in findings)
    # a rule AFTER the broken ones still ran
    assert ledger.rules["A001x"].attempted == 1
    assert any(e.startswith("contract:") for e in diag.rule_errors)


def test_no_execution_keys_leak_into_report_json(tmp_path):
    """B1 wires the ledger through the ENGINE only — report.json must carry
    no execution keys yet (a half-finished contract must not leak)."""
    from auditor.report.build import build_report
    rep = build_report("t", [{"language": "python", "root": ".", "file_count": 1,
                              "findings": []}], engines={}, limitations=[],
                       confidence=100)
    text = json.dumps(rep)
    for banned in ("eligible_inputs", "blocked_inputs", "partial_parse_inputs",
                   "execution_ledger", "contract_errors"):
        assert banned not in text
