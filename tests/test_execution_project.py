"""B2-B: execution recording for special builtin project passes
(P008 stdlib-drift, Next module graph, N001-via-.env)."""
import json

from auditor.adapters import default_adapters
from auditor.core.execution import ExecutionLedger, record_project_pass
from auditor.core.models import Diagnostics, Finding, Severity


def _py():
    for a in default_adapters():
        if "python" in a.grammars():
            return a
    raise AssertionError


def _ts():
    for a in default_adapters():
        if "typescript" in a.grammars():
            return a
    raise AssertionError


# --- record_project_pass output hardening (fix round) -------------------------

def test_project_pass_none_output_one_failure_no_crash():
    led, diag = ExecutionLedger(), Diagnostics()
    kept = record_project_pass(led, diag, ("P008",), None)
    assert kept == []
    rec = led.rules["P008"]
    assert rec.attempted == 1 and rec.failures == 1
    assert diag.rule_attempted == 1 and diag.rule_failures == 1
    assert any("NoneType" in e for e in led.contract_errors)


def test_project_pass_non_finding_item_dropped():
    led, diag = ExecutionLedger(), Diagnostics()
    kept = record_project_pass(led, diag, ("P008",), ["junk"])
    assert kept == []                                    # junk never surfaces
    assert led.rules["P008"].failures == 1
    assert diag.rule_failures == 1


def test_project_pass_mixed_list_keeps_only_valid_findings():
    good = Finding("P008", Severity.BLUE, "t", "a.py", 1)
    led, diag = ExecutionLedger(), Diagnostics()
    kept = record_project_pass(led, diag, ("P008",), ["junk", good, 42])
    assert kept == [good]                                # valid Finding preserved
    assert led.rules["P008"].attempted == 1 and led.rules["P008"].failures == 1


def test_project_pass_many_violations_fail_exactly_once():
    stray = Finding("N001", Severity.RED, "t", "a.py", 2)   # valid but out-of-group
    led, diag = ExecutionLedger(), Diagnostics()
    kept = record_project_pass(led, diag, ("P008",), ["junk", stray, None, 7])
    assert kept == [stray]                       # out-of-group Finding is KEPT
    rec = led.rules["P008"]
    assert rec.attempted == 1 and rec.failures == 1      # once, not per violation
    assert diag.rule_attempted == 1 and diag.rule_failures == 1
    # the NEXT invocation continues and records independently
    ok = Finding("P008", Severity.BLUE, "t", "b.py", 3)
    assert record_project_pass(led, diag, ("P008",), [ok]) == [ok]
    assert rec.attempted == 2 and rec.failures == 1


# --- P008 --------------------------------------------------------------------

def _pyproject(tmp_path, body):
    (tmp_path / "pyproject.toml").write_text(body, encoding="utf-8")


def test_p008_eligible_attempted_when_range_valid_no_findings(tmp_path):
    _pyproject(tmp_path, '[project]\nname="x"\nrequires-python=">=3.11"\n')
    ad = _py()
    ad._last_declared = []
    ad._last_files = []                     # no imports => no P008 findings
    led = ExecutionLedger(language="python", root=".")
    out = ad.project_rules(tmp_path, [], ledger=led, diag=Diagnostics())
    assert out == []
    rec = led.rules["P008"]
    assert rec.eligible_inputs == 1 and rec.attempted == 1 and rec.failures == 0
    assert not rec.not_applicable_reasons and not rec.unavailable_reasons


def test_p008_not_applicable_when_requires_python_absent(tmp_path):
    _pyproject(tmp_path, '[project]\nname="x"\n')     # no requires-python
    ad = _py()
    ad._last_declared = []
    ad._last_files = []
    led = ExecutionLedger(language="python", root=".")
    ad.project_rules(tmp_path, [], ledger=led, diag=Diagnostics())
    rec = led.rules["P008"]
    assert rec.attempted == 0
    assert rec.not_applicable_reasons == ["no requires-python declared in this project"]


def test_p008_unavailable_when_requires_python_unparseable(tmp_path):
    _pyproject(tmp_path, '[project]\nname="x"\nrequires-python="not a spec !!"\n')
    ad = _py()
    ad._last_declared = []
    ad._last_files = []
    led = ExecutionLedger(language="python", root=".")
    diag = Diagnostics()
    out = ad.project_rules(tmp_path, [], ledger=led, diag=diag)
    assert out == []                        # NO fabricated finding
    rec = led.rules["P008"]
    assert rec.attempted == 0
    assert "not analyzable" in rec.unavailable_reasons[0]
    assert any("P008" in e for e in diag.rule_errors)


def test_p008_list_value_is_unavailable_not_absent(tmp_path):
    # the KEY is present — a malformed value is an inability, never "no
    # requires-python declared"
    _pyproject(tmp_path, '[project]\nname="x"\nrequires-python=["bad"]\n')
    ad = _py()
    ad._last_declared = []
    ad._last_files = []
    led = ExecutionLedger(language="python", root=".")
    ad.project_rules(tmp_path, [], ledger=led, diag=Diagnostics())
    rec = led.rules["P008"]
    assert rec.attempted == 0 and rec.not_applicable_reasons == []
    assert "not analyzable" in rec.unavailable_reasons[0]
    assert "list" in rec.unavailable_reasons[0]


def test_p008_valid_range_outside_modeled_minors_not_called_invalid(tmp_path):
    # ">=4" is a perfectly VALID specifier — it just admits no Python 3 minor
    _pyproject(tmp_path, '[project]\nname="x"\nrequires-python=">=4"\n')
    ad = _py()
    ad._last_declared = []
    ad._last_files = []
    led = ExecutionLedger(language="python", root=".")
    ad.project_rules(tmp_path, [], ledger=led, diag=Diagnostics())
    rec = led.rules["P008"]
    assert rec.attempted == 0
    assert rec.unavailable_reasons == [
        "valid requires-python range is outside the modeled Python 3 minors"]
    assert not any("invalid" in r for r in rec.unavailable_reasons)


def test_p008_pyproject_read_once_per_project_rules(tmp_path, monkeypatch):
    _pyproject(tmp_path, '[project]\nname="x"\nrequires-python=">=3.11"\n')
    ad = _py()
    ad._last_declared = []
    ad._last_files = []
    reads = []
    orig = type(ad)._read

    def counting(self, p):
        if p.name == "pyproject.toml":
            reads.append(p)
        return orig(self, p)

    monkeypatch.setattr(type(ad), "_read", counting)
    led = ExecutionLedger(language="python", root=".")
    ad.project_rules(tmp_path, [], ledger=led, diag=Diagnostics())
    assert led.rules["P008"].attempted == 1
    assert len(reads) == 1                     # ONE read for the whole pass


def test_p008_exception_records_one_failure(tmp_path, monkeypatch):
    _pyproject(tmp_path, '[project]\nname="x"\nrequires-python=">=3.11"\n')
    ad = _py()
    ad._last_declared = []
    ad._last_files = []
    monkeypatch.setattr(type(ad), "_p008_findings",
                        lambda self, root, allowed: (_ for _ in ()).throw(RuntimeError("boom")))
    led = ExecutionLedger(language="python", root=".")
    diag = Diagnostics()
    ad.project_rules(tmp_path, [], ledger=led, diag=diag)
    rec = led.rules["P008"]
    assert rec.attempted == 1 and rec.failures == 1
    assert diag.rule_attempted == 1 and diag.rule_failures == 1   # synced once


# --- Next module graph -------------------------------------------------------

def _next_project(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "app", "dependencies": {"next": "14", "react": "18"}}),
        encoding="utf-8")
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "page.tsx").write_text("export default function P(){return null}\n",
                                               encoding="utf-8")


def _prepare_ts(ad, tmp_path):
    from auditor.core.models import SourceFile
    ad.set_repo_root(tmp_path)
    ad._diag = Diagnostics()
    ad.parse_dependencies(tmp_path)
    files = []
    for p in (tmp_path / "app").glob("*.tsx"):
        files.append(SourceFile(path=p, rel=f"app/{p.name}", language="tsx",
                                text=p.read_bytes()))
    ad.prepare(tmp_path, files)
    return files


def test_graph_success_group_attempted_and_supersedes_n003(tmp_path):
    _next_project(tmp_path)
    ad = _ts()
    _prepare_ts(ad, tmp_path)
    led = ExecutionLedger(language="typescript", root=".")
    ad.project_rules(tmp_path, ["next"], ledger=led, diag=Diagnostics())
    for rid in ("N002", "N004", "N005", "N006"):
        assert led.rules[rid].eligible_inputs == 1
        assert led.rules[rid].attempted == 1          # ran even with 0 findings
    assert led.rules["N003"].not_applicable_reasons == [
        "superseded by the N006 module-graph pass"]


def test_graph_partial_flags_group_once(tmp_path):
    _next_project(tmp_path)
    (tmp_path / "app" / "broken.tsx").write_text("export default function(:{\n",
                                                 encoding="utf-8")
    ad = _ts()
    _prepare_ts(ad, tmp_path)
    led = ExecutionLedger(language="typescript", root=".")
    ad.project_rules(tmp_path, ["next"], ledger=led, diag=Diagnostics())
    # partial recorded ONCE per group id, not once per rule_id in diag
    assert led.rules["N006"].partial_parse_inputs == 1
    assert led.rules["N002"].partial_parse_inputs == 1


def _prepare_ts_files(ad, tmp_path, rels):
    """Prepare with an EXPLICIT file list (rel paths under tmp_path)."""
    from auditor.core.models import SourceFile
    ad.set_repo_root(tmp_path)
    ad._diag = Diagnostics()
    ad.parse_dependencies(tmp_path)
    files = []
    for rel in rels:
        p = tmp_path / rel
        lang = "tsx" if p.suffix in (".tsx", ".jsx") else "typescript"
        files.append(SourceFile(path=p, rel=rel, language=lang, text=p.read_bytes()))
    ad.prepare(tmp_path, files)
    return files


def test_graph_partial_ignores_broken_file_outside_graph(tmp_path):
    # scripts/broken.ts is neither reachable from an entry nor an app/ orphan —
    # its syntax errors are NOT evidence about the graph pass
    _next_project(tmp_path)
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "broken.ts").write_text("export default function(:{\n",
                                                    encoding="utf-8")
    ad = _ts()
    _prepare_ts_files(ad, tmp_path, ["app/page.tsx", "scripts/broken.ts"])
    led = ExecutionLedger(language="typescript", root=".")
    ad.project_rules(tmp_path, ["next"], ledger=led, diag=Diagnostics())
    assert led.rules["N006"].partial_parse_inputs == 0
    assert led.rules["N006"].attempted == 1 and led.rules["N006"].failures == 0


def test_graph_partial_set_for_broken_reachable_child(tmp_path):
    _next_project(tmp_path)
    (tmp_path / "app" / "page.tsx").write_text(
        "import B from '../components/Broken';\n"
        "export default function P(){ return <B/>; }\n", encoding="utf-8")
    (tmp_path / "components").mkdir()
    (tmp_path / "components" / "Broken.tsx").write_text("export default function(:{\n",
                                                        encoding="utf-8")
    ad = _ts()
    _prepare_ts_files(ad, tmp_path, ["app/page.tsx", "components/Broken.tsx"])
    led = ExecutionLedger(language="typescript", root=".")
    ad.project_rules(tmp_path, ["next"], ledger=led, diag=Diagnostics())
    assert led.rules["N006"].partial_parse_inputs == 1   # IN the graph => counts


def test_pipeline_graph_failure_n003_fallback_end_to_end(tmp_path, monkeypatch):
    """analyze() raising must leave the project alive AND the per-file N003
    fallback genuinely running through run_pattern_engine — finding emitted,
    attempt recorded — not just '_graph_active is False'."""
    from auditor.core.patterns import run_pattern_engine
    import auditor.adapters.typescript.next_graph as ng
    monkeypatch.setattr(ng, "analyze",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("graph boom")))
    _next_project(tmp_path)
    (tmp_path / "app" / "page.tsx").write_text(
        "import {useState} from 'react';\n"
        "export default function P(){ const [v] = useState(0); return null; }\n",
        encoding="utf-8")
    ad = _ts()
    files = _prepare_ts_files(ad, tmp_path, ["app/page.tsx"])
    led = ExecutionLedger(language="typescript", root=".")
    diag = Diagnostics()
    findings = run_pattern_engine(ad, tmp_path, files, ["next"],
                                  diag=diag, ledger=led)
    assert led.rules["N006"].attempted == 1 and led.rules["N006"].failures == 1
    # the fallback actually RAN and FOUND the server-component hook
    assert any(f.rule_id == "N003" for f in findings)
    assert led.rules["N003"].attempted >= 1 and led.rules["N003"].failures == 0
    assert not led.rules["N003"].not_applicable_reasons


def test_graph_failure_group_fails_once_n003_not_superseded(tmp_path, monkeypatch):
    _next_project(tmp_path)
    ad = _ts()
    import auditor.adapters.typescript.next_graph as ng
    monkeypatch.setattr(ng, "analyze",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("graph boom")))
    _prepare_ts(ad, tmp_path)
    led = ExecutionLedger(language="typescript", root=".")
    diag = Diagnostics()
    ad.project_rules(tmp_path, ["next"], ledger=led, diag=diag)
    assert led.rules["N006"].failures == 1 and led.rules["N006"].attempted == 1
    assert diag.rule_attempted == 1 and diag.rule_failures == 1
    # graph inactive => N003 fallback stays available and is NOT marked superseded
    assert "N003" not in led.rules
    assert ad._graph_active is False


def test_graph_not_claimed_when_next_not_applicable(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"name": "x"}), encoding="utf-8")
    ad = _ts()
    ad._diag = Diagnostics()
    ad.parse_dependencies(tmp_path)
    ad.prepare(tmp_path, [])
    led = ExecutionLedger(language="typescript", root=".")
    ad.project_rules(tmp_path, [], ledger=led, diag=Diagnostics())
    for rid in ("N002", "N004", "N005", "N006"):
        assert rid not in led.rules             # never claimed to run


# --- N001 via .env -----------------------------------------------------------

def test_env_two_files_both_attempted(tmp_path):
    _next_project(tmp_path)
    (tmp_path / ".env").write_text("NEXT_PUBLIC_API=ok\n", encoding="utf-8")
    (tmp_path / ".env.local").write_text("NEXT_PUBLIC_TOKEN=shh\n", encoding="utf-8")
    ad = _ts()
    _prepare_ts(ad, tmp_path)
    led = ExecutionLedger(language="typescript", root=".")
    findings = ad.project_rules(tmp_path, ["next"], ledger=led, diag=Diagnostics())
    # one env file has a secret-shaped var (TOKEN), one does not
    assert sum(1 for f in findings if f.rule_id == "N001") == 1
    assert led.rules["N001"].attempted >= 2      # two env files, both attempted
    # the VALUE is never echoed anywhere
    for f in findings:
        assert "shh" not in f.snippet and "shh" not in f.detail


def test_env_read_failure_continues_next_file(tmp_path, monkeypatch):
    _next_project(tmp_path)
    (tmp_path / ".env").write_text("NEXT_PUBLIC_A=1\n", encoding="utf-8")
    (tmp_path / ".env.local").write_text("NEXT_PUBLIC_TOKEN=x\n", encoding="utf-8")
    ad = _ts()
    _prepare_ts(ad, tmp_path)
    import auditor.adapters.typescript.next_rules as nr
    real = nr.scan_one_env_file

    def flaky(env):
        if env.name == ".env":
            raise RuntimeError("read failed")
        return real(env)

    monkeypatch.setattr(nr, "scan_one_env_file", flaky)
    led = ExecutionLedger(language="typescript", root=".")
    diag = Diagnostics()
    findings = ad.project_rules(tmp_path, ["next"], ledger=led, diag=diag)
    assert led.rules["N001"].failures >= 1               # the bad file failed
    assert any(f.rule_id == "N001" for f in findings)    # the good file still ran
    assert any(".env" in e for e in diag.rule_errors)


def test_no_env_files_no_extra_attempts(tmp_path):
    _next_project(tmp_path)   # no .env* files
    ad = _ts()
    _prepare_ts(ad, tmp_path)
    led = ExecutionLedger(language="typescript", root=".")
    ad.project_rules(tmp_path, ["next"], ledger=led, diag=Diagnostics())
    assert led.rules["N001"].not_applicable_reasons == [
        "no .env* files in this project"]


# --- no double-count + pipeline ---------------------------------------------

def test_adapter_without_project_passes_records_nothing(tmp_path):
    """A Java/.NET-style adapter with no project rules must not look like it ran
    one (the old unconditional wrapper counted a phantom attempt)."""
    from auditor.core.patterns import run_pattern_engine

    class _Bare:
        name = "java"
        def syntax(self):
            return _ts().syntax()
        def language_rules(self):
            return []
        def project_rules(self, root, frameworks, ledger=None, diag=None):
            return []

    diag = Diagnostics()
    run_pattern_engine(_Bare(), tmp_path, [], [], diag=diag,
                       ledger=ExecutionLedger())
    # no phantom project-rule attempt for an adapter with no passes
    assert diag.rule_attempted == 0
    assert diag.rule_failures == 0


def test_legacy_project_rules_signature_still_supported(tmp_path):
    """An adapter written before B2-B — project_rules(self, root, frameworks) —
    must have its BODY actually invoked (old call form), not die on unexpected
    ledger/diag kwargs that then masquerades as a rule failure."""
    from auditor.core.patterns import run_pattern_engine

    class Legacy:
        name = "java"
        body_entered = False
        def syntax(self):
            return _ts().syntax()
        def language_rules(self):
            return []
        def project_rules(self, root, frameworks):
            Legacy.body_entered = True
            return []

    diag = Diagnostics()
    run_pattern_engine(Legacy(), tmp_path, [], [], diag=diag,
                       ledger=ExecutionLedger())
    assert Legacy.body_entered
    assert diag.rule_failures == 0 and diag.rule_attempted == 0
    assert diag.rule_errors == []


def test_real_pipeline_populates_project_passes(tmp_path, monkeypatch):
    from auditor import cli
    import auditor.core.execution as execmod

    captured: list = []
    real = execmod.ExecutionLedger.__init__

    def spy(self, *a, **k):
        real(self, *a, **k)
        captured.append(self)

    monkeypatch.setattr(execmod.ExecutionLedger, "__init__", spy)
    out = tmp_path / "rep"
    cli.main(["scan", "tests/fixtures/monorepo", "--output", str(out),
              "--offline", "--no-semgrep"])
    # B1 still recorded
    assert any(led.rules.get("P001") and led.rules["P001"].attempted > 0
               for led in captured)
    # P008 recorded for a python project (attempted or a not_applicable reason)
    assert any("P008" in led.rules for led in captured)
    # report.json still carries no execution keys
    text = (out / "report.json").read_text(encoding="utf-8")
    for banned in ("eligible_inputs", "unavailable_reasons",
                   "not_applicable_reasons", "execution_ledger"):
        assert banned not in text
    assert "analysis_manifest" in text
