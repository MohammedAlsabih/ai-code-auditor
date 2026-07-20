"""B2-A: execution recording for the H hallucination decision path."""
from pathlib import Path

from auditor.core.execution import ExecutionLedger
from auditor.core.hallucination import (
    DECLARED_ONLINE,
    IMPORT_ONLINE,
    REGISTRY_DEPENDENT,
    audit_hallucinations,
)
from auditor.core.models import DeclaredDep, Diagnostics, ImportRef, PackageInfo


class _Reg:
    """A tiny stand-in registry returning canned PackageInfo per name."""
    ecosystem = "pypi"

    def __init__(self, infos, raiser=None):
        self.infos = infos
        self.raiser = raiser

    def lookup(self, name):
        return self.infos.get(name, PackageInfo(exists=False))


class _Adapter:
    name = "python"
    ecosystem = "pypi"

    def __init__(self, imports=(), candidates=None):
        self._imports = list(imports)
        self._cands = candidates or {}

    def extract_imports(self, files):
        return self._imports

    def registry_candidates(self, imp):
        return self._cands.get(imp.module, [imp.top_level or imp.module])

    def is_internal(self, imp):
        return False

    def match_declared(self, imp, declared):
        return None

    def import_mapping_trust(self, imp):
        return "exact"

    def private_registry_reason(self, root):
        return None

    def unresolvable_hint(self, name):
        return None


def _dep(name):
    return DeclaredDep(name=name, ecosystem="pypi", source_file="req.txt", line=1, raw=name)


def _imp(module):
    return ImportRef(module=module, file="a.py", line=1, top_level=module)


def _audit(adapter, declared, registry, ledger):
    return audit_hallucinations(adapter, Path("."), [], declared, registry,
                                diag=Diagnostics(), ledger=ledger)


# --- online ------------------------------------------------------------------

def test_online_declared_group_all_attempted_even_without_findings():
    reg = _Reg({"flask": PackageInfo(exists=True, downloads=999999)})   # healthy => no finding
    led = ExecutionLedger(language="python", root=".")
    findings = _audit(_Adapter(), [_dep("flask")], reg, led)
    assert findings == []                                   # nothing wrong with flask
    for rid in DECLARED_ONLINE:
        assert led.rules[rid].attempted == 1                # whole group ran
        assert led.rules[rid].eligible_inputs == 1
        assert led.rules[rid].failures == 0


def test_online_import_group_all_attempted_even_if_one_finding():
    reg = _Reg({"requests": PackageInfo(exists=True, downloads=999999)})
    ad = _Adapter(imports=[_imp("requests")], candidates={"requests": ["requests"]})
    led = ExecutionLedger(language="python", root=".")
    findings = _audit(ad, [], reg, led)
    assert {f.rule_id for f in findings} == {"H002"}        # only H002 emitted
    for rid in IMPORT_ONLINE:
        assert led.rules[rid].attempted == 1                # ...but whole group ran


def test_online_no_inputs_marks_not_applicable_not_complete():
    led = ExecutionLedger(language="python", root=".")
    _audit(_Adapter(), [], _Reg({}), led)
    assert led.rules["H003"].not_applicable_reasons == [
        "declared-dependency verification runs only offline"]
    for rid in DECLARED_ONLINE:
        assert led.rules[rid].attempted == 0
        assert led.rules[rid].not_applicable_reasons        # a clear reason present
        assert not led.rules[rid].unavailable_reasons       # NOT unavailable online


def test_package_info_error_gives_h004_without_ledger_failure():
    reg = _Reg({"ghostlib": PackageInfo(exists=False, error="nuget: ConnectionError")})
    led = ExecutionLedger(language="python", root=".")
    findings = _audit(_Adapter(), [_dep("ghostlib")], reg, led)
    assert {f.rule_id for f in findings} == {"H004"}
    # a lookup error resolved to H004 is a SUCCESSFUL decision, not a failure
    assert led.rules["H004"].attempted == 1
    for rid in DECLARED_ONLINE:
        assert led.rules[rid].failures == 0


# --- offline -----------------------------------------------------------------

def test_offline_h003_h007_attempted_registry_rules_unavailable():
    ad = _Adapter(imports=[_imp("numpy")], candidates={"numpy": ["numpy"]})
    led = ExecutionLedger(language="python", root=".")
    findings = _audit(ad, [_dep("flask")], None, led)      # registry None => offline
    assert {f.rule_id for f in findings} == {"H003", "H007"}
    assert led.rules["H003"].attempted == 1
    assert led.rules["H007"].attempted == 1
    for rid in REGISTRY_DEPENDENT:
        assert led.rules[rid].attempted == 0
        assert led.rules[rid].unavailable_reasons == [
            "offline mode: public registry was not consulted"]
        assert not led.rules[rid].not_applicable_reasons


def test_offline_no_inputs_not_applicable_on_h003_h007():
    led = ExecutionLedger(language="python", root=".")
    _audit(_Adapter(), [], None, led)
    assert led.rules["H003"].not_applicable_reasons == [
        "no declarable dependencies in this project"]
    assert led.rules["H007"].not_applicable_reasons == [
        "no external undeclared imports in this project"]
    # H007 never marked unavailable — it has a real offline path
    assert not led.rules["H007"].unavailable_reasons


# --- failure + contract ------------------------------------------------------

def test_judge_exception_is_visible_and_next_input_continues():
    import auditor.core.hallucination as H

    def flaky_judge(adapter, imp, cand_infos, private_reason, providers):
        if imp.module == "boom":
            raise RuntimeError("judge blew up")
        return []

    ad = _Adapter(imports=[_imp("boom"), _imp("safe")],
                  candidates={"boom": ["boom"], "safe": ["safe"]})
    reg = _Reg({})
    led = ExecutionLedger(language="python", root=".")
    diag = Diagnostics()
    orig = H._judge_import
    H._judge_import = flaky_judge
    try:
        audit_hallucinations(ad, Path("."), [], [], reg, diag=diag, ledger=led)
    finally:
        H._judge_import = orig
    # the boom input failed once, the safe input STILL ran
    assert led.rules["H002"].failures == 1
    assert led.rules["H002"].attempted == 2                # both inputs attempted
    assert any("judge" in e for e in diag.rule_errors)


def test_out_of_group_id_is_contract_failure_once_finding_kept():
    from auditor.core.models import Finding, Severity
    import auditor.core.hallucination as H

    def fake_judge(adapter, imp, cand_infos, private_reason, providers):
        return [Finding(rule_id="H999", severity=Severity.RED, title="t",
                        file=imp.file, line=imp.line, language="python")]

    ad = _Adapter(imports=[_imp("x")], candidates={"x": ["x"]})
    reg = _Reg({"x": PackageInfo(exists=True, downloads=1)})
    led = ExecutionLedger(language="python", root=".")
    orig = H._judge_import
    H._judge_import = fake_judge
    try:
        findings = audit_hallucinations(ad, Path("."), [], [], reg,
                                        diag=Diagnostics(), ledger=led)
    finally:
        H._judge_import = orig
    assert any(f.rule_id == "H999" for f in findings)      # finding KEPT
    assert led.rules["H002"].attempted == 1
    assert led.rules["H002"].failures == 1                 # one failed invocation
    assert any("H999" in e for e in led.contract_errors)


def test_two_projects_do_not_share_counters():
    reg = _Reg({"flask": PackageInfo(exists=True, downloads=1)})
    a = ExecutionLedger(language="python", root="backend")
    b = ExecutionLedger(language="python", root="frontend")
    _audit(_Adapter(), [_dep("flask")], reg, a)
    _audit(_Adapter(), [], reg, b)                          # no inputs
    assert a.rules["H001"].attempted == 1
    assert b.rules["H001"].attempted == 0
    assert b.rules["H001"].not_applicable_reasons


def test_real_pipeline_run_fills_b1_and_h_counters(tmp_path, monkeypatch):
    """A REAL scan of the monorepo fixture (offline) must populate BOTH the B1
    file-rule counters and the H decision counters in the per-project ledgers —
    proving the CLI wiring, not just direct calls. report.json still carries
    no execution keys in B2-A."""
    import json

    from auditor import cli
    import auditor.core.execution as execmod

    captured: list = []
    real_init = execmod.ExecutionLedger.__init__

    def spy_init(self, *a, **kw):
        real_init(self, *a, **kw)
        captured.append(self)

    monkeypatch.setattr(execmod.ExecutionLedger, "__init__", spy_init)
    out = tmp_path / "rep"
    rc = cli.main(["scan", "tests/fixtures/monorepo", "--output", str(out),
                   "--offline", "--no-semgrep"])
    assert rc in (0, 1)                               # scan completed (block ok)
    assert captured, "no ledgers were created by the CLI"
    # B1 file rule ran on real files
    assert any(led.rules.get("P001") and led.rules["P001"].attempted > 0
               for led in captured)
    # H decision path ran: offline => H007 attempted somewhere, registry rules
    # marked unavailable
    assert any(led.rules.get("H007") and led.rules["H007"].attempted > 0
               for led in captured)
    assert any(led.rules.get("H001") and led.rules["H001"].unavailable_reasons
               for led in captured)
    # B2-D: the H facts are serialized under analysis_manifest.execution ONLY
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    execution = data["analysis_manifest"]["execution"]
    assert any("H001" in p["rules"] and p["rules"]["H001"]["unavailable_reasons"]
               for p in execution["projects"])
    assert "eligible_inputs" not in json.dumps(data["projects"])


def test_ledger_guard_never_contradicts_a_rule_that_ran():
    reg = _Reg({"flask": PackageInfo(exists=True, downloads=1)})
    led = ExecutionLedger(language="python", root=".")
    _audit(_Adapter(), [_dep("flask")], reg, led)
    # H001 actually ran online — a later not_applicable/unavailable must be ignored
    led.not_applicable(("H001",), "should be ignored")
    led.unavailable(("H001",), "should be ignored")
    assert led.rules["H001"].not_applicable_reasons == []
    assert led.rules["H001"].unavailable_reasons == []


# --- closure round -----------------------------------------------------------

def test_diag_synced_once_per_decision_success_and_failure():
    """diag.rule_attempted += 1 PER invocation (not per output id); a failing
    input increments rule_failures once, a succeeding input does not; both
    inputs are attempted and the second continues."""
    import auditor.core.hallucination as H

    def flaky(adapter, imp, cand_infos, private_reason, providers):
        if imp.module == "boom":
            raise RuntimeError("blew up")
        return []

    ad = _Adapter(imports=[_imp("boom"), _imp("safe")],
                  candidates={"boom": ["boom"], "safe": ["safe"]})
    led = ExecutionLedger(language="python", root=".")
    diag = Diagnostics()
    orig = H._judge_import
    H._judge_import = flaky
    try:
        audit_hallucinations(ad, Path("."), [], [], _Reg({}), diag=diag, ledger=led)
    finally:
        H._judge_import = orig
    assert diag.rule_attempted == 2          # one per input, NOT per output id
    assert diag.rule_failures == 1           # only the boom input
    assert led.rules["H002"].attempted == 2


def test_diag_attempts_not_multiplied_by_group_size():
    """A single successful decision must add exactly 1 to diag.rule_attempted,
    never len(group)."""
    reg = _Reg({"flask": PackageInfo(exists=True, downloads=1)})
    diag = Diagnostics()
    led = ExecutionLedger(language="python", root=".")
    audit_hallucinations(_Adapter(), Path("."), [], [_dep("flask")], reg,
                         diag=diag, ledger=led)
    assert diag.rule_attempted == 1          # one declared input, one invocation
    assert diag.rule_failures == 0


def test_judge_returning_none_or_junk_does_not_crash():
    import auditor.core.hallucination as H
    from auditor.core.models import Finding, Severity

    calls = {"n": 0}

    def judge(adapter, imp, cand_infos, private_reason, providers):
        calls["n"] += 1
        if imp.module == "none":
            return None
        if imp.module == "junk":
            return ["not-a-finding",
                    Finding(rule_id="H002", severity=Severity.YELLOW, title="t",
                            file=imp.file, line=1, language="python")]
        return []

    ad = _Adapter(imports=[_imp("none"), _imp("junk"), _imp("after")],
                  candidates={"none": ["none"], "junk": ["junk"], "after": ["after"]})
    led = ExecutionLedger(language="python", root=".")
    diag = Diagnostics()
    orig = H._judge_import
    H._judge_import = judge
    try:
        findings = audit_hallucinations(ad, Path("."), [], [], _Reg({}),
                                        diag=diag, ledger=led)
    finally:
        H._judge_import = orig
    assert calls["n"] == 3                    # every input reached the judge
    assert led.rules["H002"].attempted == 3   # none + junk + after
    assert led.rules["H002"].failures == 2    # none (bad type) + junk (bad element)
    assert any(f.rule_id == "H002" for f in findings)   # valid Finding kept
    assert not any(f == "not-a-finding" for f in findings)


def test_unavailable_kept_when_eligible_but_not_attempted():
    led = ExecutionLedger(language="python", root=".")
    led._rec("S:demo").eligible_inputs = 5    # 5 files ready...
    led.unavailable(("S:demo",), "engine not installed")   # ...engine absent
    assert led.rules["S:demo"].unavailable_reasons == ["engine not installed"]


def test_unavailable_rejected_once_attempted():
    led = ExecutionLedger(language="python", root=".")
    led.attempted_ok(("S:demo",))             # it actually ran
    led.unavailable(("S:demo",), "engine not installed")
    assert led.rules["S:demo"].unavailable_reasons == []


def test_not_applicable_reasons_are_per_group_online():
    reg = _Reg({"flask": PackageInfo(exists=True, downloads=1)})
    # dependency only, NO external imports
    only_dep = ExecutionLedger(language="python", root=".")
    _audit(_Adapter(imports=[]), [_dep("flask")], reg, only_dep)
    assert only_dep.rules["H001"].attempted == 1                 # declared ran
    assert only_dep.rules["H001"].not_applicable_reasons == []   # NOT falsely NA
    assert only_dep.rules["H002"].not_applicable_reasons == [
        "no external undeclared imports in this project"]
    assert only_dep.rules["H008"].not_applicable_reasons == [
        "no external undeclared imports in this project"]

    # import only, NO declared deps
    ad = _Adapter(imports=[_imp("requests")], candidates={"requests": ["requests"]})
    only_imp = ExecutionLedger(language="python", root=".")
    _audit(ad, [], reg, only_imp)
    assert only_imp.rules["H002"].attempted == 1
    assert only_imp.rules["H002"].not_applicable_reasons == []
    assert only_imp.rules["H001"].not_applicable_reasons == [
        "no declarable dependencies in this project"]

    # both present: H004/H007/... in both groups ran => NO not_applicable
    both = ExecutionLedger(language="python", root=".")
    _audit(ad, [_dep("flask")], reg, both)
    for rid in ("H004", "H007", "H009", "H010", "H012"):
        assert both.rules[rid].not_applicable_reasons == []
    assert both.rules["H001"].not_applicable_reasons == []
    assert both.rules["H002"].not_applicable_reasons == []

    # neither present: each group gets its own accurate reason
    neither = ExecutionLedger(language="python", root=".")
    _audit(_Adapter(imports=[]), [], reg, neither)
    assert neither.rules["H001"].not_applicable_reasons == [
        "no declarable dependencies in this project"]
    assert neither.rules["H002"].not_applicable_reasons == [
        "no external undeclared imports in this project"]
