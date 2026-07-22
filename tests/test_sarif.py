"""W2-B2.8B2-D: SARIF 2.1.0 export — structural tests for the fields and the
legal values (no compliance claim without these)."""
import json
from collections import Counter

from auditor.core.models import Finding, Severity
from auditor.report.build import build_report
from auditor.report.sarif import SARIF_SCHEMA, SARIF_VERSION, build_sarif, write_sarif

CATALOG = [
    {"rule_id": "P002", "title": "Hardcoded secret", "description": "A secret.",
     "category": "security", "default_level": "error",
     "default_precision": "exact", "engine": "pattern-engine",
     "languages": ["python"], "frameworks": [], "scope": "file",
     "source": "builtin"},
    {"rule_id": "H008", "title": "Unverified provider",
     "description": "Probable hallucination.", "category": "dependencies",
     "default_level": "error", "default_precision": "heuristic",
     "engine": "hallucination", "languages": ["python"], "frameworks": [],
     "scope": "dependency", "source": "builtin"},
]


def _f(rule="P002", sev=Severity.RED, precision="exact", file="a.py", line=3,
       title="Hardcoded secret", snippet="password = 'x'"):
    return Finding(rule, sev, title, file, line, snippet=snippet,
                   precision=precision)


def _rep(findings, root="backend", **kw):
    return build_report("tgt", [{"language": "python", "root": root,
                                 "file_count": 1, "findings": findings}],
                        engines={}, limitations=[], confidence=100,
                        catalog=CATALOG, **kw)


def test_sarif_envelope_and_driver():
    s = build_sarif(_rep([_f()]))
    assert s["version"] == SARIF_VERSION == "2.1.0"
    assert s["$schema"] == SARIF_SCHEMA
    assert SARIF_SCHEMA.startswith("https://docs.oasis-open.org/sarif/")
    run = s["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "ai-code-auditor"
    assert driver["version"]
    rule_ids = [r["id"] for r in driver["rules"]]
    assert "P002" in rule_ids and "H008" in rule_ids
    p002 = driver["rules"][rule_ids.index("P002")]
    assert p002["defaultConfiguration"]["level"] == "error"
    assert p002["shortDescription"]["text"] == "Hardcoded secret"


def test_result_fields_levels_location_fingerprint():
    rep = _rep([_f(), _f(rule="H008", precision="heuristic", file="b.py",
                         sev=Severity.RED, title="Unverified provider")])
    s = build_sarif(rep)
    results = s["runs"][0]["results"]
    assert len(results) == 2
    by_rule = {r["ruleId"]: r for r in results}
    r = by_rule["P002"]
    assert r["level"] == "error"
    loc = r["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "backend/a.py"   # repo-relative
    assert loc["region"]["startLine"] == 3
    fp = rep["projects"][0]["findings"][0]["fingerprint"]
    assert r["partialFingerprints"]["auditorFinding/v1"] == fp
    assert r["properties"] == {"precision": "exact", "gate_action": "block",
                               "project": "backend"}
    assert by_rule["H008"]["properties"]["gate_action"] == "review"
    # ruleIndex agrees with the driver rules array
    driver_rules = s["runs"][0]["tool"]["driver"]["rules"]
    assert driver_rules[r["ruleIndex"]]["id"] == "P002"


def test_levels_map_yellow_blue_and_project_level_findings():
    rep = _rep([_f(sev=Severity.YELLOW, rule="H008", precision="heuristic",
                   title="Unverified provider"),
                _f(sev=Severity.BLUE, file="c.py", line=0)])
    results = build_sarif(rep)["runs"][0]["results"]
    assert results[0]["level"] == "warning"
    assert results[1]["level"] == "note"
    # line 0 = project-level: no fabricated region
    assert "region" not in results[1]["locations"][0]["physicalLocation"]


def test_no_snippets_machine_paths_or_review_notes():
    rep = _rep([_f(snippet='password = "SNIPPET-BODY-XYZ"')])
    text = json.dumps(build_sarif(rep))
    assert "SNIPPET-BODY-XYZ" not in text          # snippets never exported
    assert "C:\\" not in text and "C:/" not in text and "/Users/" not in text
    assert "review_note" not in text and "reviews" not in text


def test_baseline_state_only_when_baseline_used():
    plain = build_sarif(_rep([_f()]))
    assert all("baselineState" not in r for r in plain["runs"][0]["results"])
    old = _rep([_f()])
    counter = Counter(f["fingerprint"] for p in old["projects"]
                      for f in p["findings"])
    rep = _rep([_f(line=50), _f(rule="H008", precision="heuristic",
                                file="n.py", title="Unverified provider")],
               baseline=counter)
    states = {r["ruleId"]: r.get("baselineState")
              for r in build_sarif(rep)["runs"][0]["results"]}
    assert states == {"P002": "unchanged", "H008": "new"}


def test_uncataloged_rule_gets_minimal_metadata_and_note():
    rep = build_report("t", [{"language": "python", "root": ".",
                              "file_count": 1,
                              "findings": [_f(rule="S:extra.pack-rule")]}],
                       engines={}, limitations=[], confidence=100,
                       catalog=CATALOG)
    s = build_sarif(rep)
    run = s["runs"][0]
    assert run["results"][0]["ruleId"] == "S:extra.pack-rule"   # never dropped
    rules = run["tool"]["driver"]["rules"]
    synth = next(r for r in rules if r["id"] == "S:extra.pack-rule")
    assert synth["properties"]["synthesized"] is True
    assert any("not in the shipped catalog" in n
               for n in run["properties"]["contract_notes"])


def test_execution_successful_is_technical_not_verdict():
    rep = _rep([_f()])                              # verdict = block
    run = build_sarif(rep)["runs"][0]
    assert run["invocations"][0]["executionSuccessful"] is True
    assert run["properties"]["verdict"] == "block"  # travels separately


def test_deterministic_output(tmp_path):
    rep = _rep([_f(), _f(rule="H008", precision="heuristic", file="b.py",
                         title="Unverified provider")])
    a = json.dumps(build_sarif(rep), sort_keys=True)
    b = json.dumps(build_sarif(rep), sort_keys=True)
    assert a == b
    p1, p2 = tmp_path / "one.sarif", tmp_path / "two.sarif"
    write_sarif(rep, p1)
    write_sarif(rep, p2)
    assert p1.read_bytes() == p2.read_bytes()


def test_cli_writes_report_sarif(tmp_path):
    from auditor.cli import main
    (tmp_path / "app.py").write_text(
        'API_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")
    out = tmp_path / "rep"
    main(["scan", str(tmp_path), "--output", str(out), "--offline",
          "--no-semgrep", "--sarif"])
    sarif = json.loads((out / "report.sarif").read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    assert any(r["ruleId"] == "P002" for r in results)
    text = json.dumps(sarif)
    assert "AKIAIOSFODNN7EXAMPLE" not in text         # the secret never leaves
    assert str(tmp_path).replace("\\", "/") not in text.replace("\\\\", "/")
