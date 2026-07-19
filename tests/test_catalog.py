import json
from pathlib import Path

import pytest

from auditor.adapters import default_adapters
from auditor.core.catalog import (
    VALID_LEVELS,
    VALID_PRECISIONS,
    VALID_SCOPES,
    VALID_SOURCES,
    CatalogConflict,
    RuleDescriptor,
    collect_catalog,
    merge_catalog,
)
from auditor.core.models import Finding, Severity
from auditor.report.build import build_report


@pytest.fixture(scope="module")
def catalog():
    return collect_catalog(default_adapters())


def _rd(**over):
    base = dict(rule_id="X001", title="t", description="d", category="c",
                default_level="warning", default_precision="exact",
                engine="pattern-engine", languages=("python",))
    base.update(over)
    return RuleDescriptor(**base)


# --- model validation --------------------------------------------------------

def test_descriptor_validation_rejects_bad_values():
    with pytest.raises(ValueError):
        _rd(title="")                       # empty text field
    with pytest.raises(ValueError):
        _rd(default_level="critical")       # no CVSS-style levels
    with pytest.raises(ValueError):
        _rd(default_precision="fuzzy")
    with pytest.raises(ValueError):
        _rd(scope="galaxy")
    with pytest.raises(ValueError):
        _rd(source="handwritten")


def test_merge_unions_languages_only_when_semantics_identical():
    a = _rd(languages=("python",))
    b = _rd(languages=("java",))
    merged = merge_catalog([a, b])
    assert len(merged) == 1
    assert merged[0].languages == ("java", "python")


def test_conflicting_descriptor_fails_loudly_no_last_write_wins():
    a = _rd(default_level="warning")
    b = _rd(default_level="error")          # same id, different semantics
    with pytest.raises(CatalogConflict):
        merge_catalog([a, b])
    with pytest.raises(CatalogConflict):
        merge_catalog([_rd(), _rd(title="different title")])


# --- assembled catalog -------------------------------------------------------

def test_rule_ids_unique_and_deterministically_sorted(catalog):
    ids = [d["rule_id"] for d in catalog]
    assert ids == sorted(ids)
    assert len(ids) == len(set(ids))
    # determinism across assemblies
    again = collect_catalog(default_adapters())
    assert catalog == again


def test_every_descriptor_complete_and_legal(catalog):
    for d in catalog:
        for f in ("rule_id", "title", "description", "category", "engine"):
            assert isinstance(d[f], str) and d[f].strip(), (d["rule_id"], f)
        assert d["default_level"] in VALID_LEVELS
        assert d["default_precision"] in VALID_PRECISIONS
        assert d["scope"] in VALID_SCOPES
        assert d["source"] in VALID_SOURCES
        assert isinstance(d["languages"], list) and d["languages"]
        assert isinstance(d["frameworks"], list)


def test_multi_output_rules_have_each_id(catalog):
    ids = {d["rule_id"] for d in catalog}
    assert {"P002", "P003"} <= ids          # one check, two ids
    assert {"P004", "P005"} <= ids
    assert {"R004", "R005"} <= ids


def test_all_families_represented(catalog):
    ids = {d["rule_id"] for d in catalog}
    assert {f"H{n:03d}" for n in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12)} <= ids
    assert {f"P{n:03d}" for n in range(1, 9)} <= ids
    assert {f"R{n:03d}" for n in range(1, 8)} <= ids
    assert {f"N{n:03d}" for n in range(1, 7)} <= ids
    assert {"J001", "J002", "D001", "D002", "D003"} <= ids
    assert sum(1 for d in catalog if d["source"] == "semgrep-or-opengrep") == 5
    assert next(d for d in catalog if d["rule_id"] == "N006")["scope"] == "module_graph"
    assert next(d for d in catalog if d["rule_id"] == "P008")["scope"] == "project"


def test_catalog_never_claims_execution(catalog):
    text = json.dumps(catalog)
    for banned in ("executed", '"pass"', '"failed"', "attempted"):
        assert banned not in text


def test_every_fixture_finding_has_exactly_one_descriptor(catalog):
    """Every finding the current corpus/fixtures actually produce (the
    committed examples report, regenerated from one fixture run) maps to
    exactly one descriptor — matched LITERALLY, no prefix stripping and no
    test-side normalization."""
    rep = json.loads((Path(__file__).resolve().parents[1] / "examples" /
                      "report.json").read_text(encoding="utf-8"))
    by_id = {}
    for d in catalog:
        by_id.setdefault(d["rule_id"], []).append(d)
    for p in rep["projects"]:
        for f in p["findings"]:
            rid = f["rule_id"]
            assert rid in by_id, f"finding {rid} has no descriptor (literal match)"
            assert len(by_id[rid]) == 1


# --- report integration ------------------------------------------------------

def _finding(sev=Severity.RED):
    return Finding(rule_id="P002", severity=sev, title="t", file="a.py",
                   line=1, language="python", engine="auditor", precision="exact")


def test_new_report_carries_stable_manifest_and_nothing_else_changes(catalog):
    kw = dict(target="tgt",
              projects=[{"language": "python", "root": ".", "file_count": 1,
                         "findings": [_finding()]}],
              engines={}, limitations=[], confidence=100)
    with_cat = build_report(**kw, catalog=catalog)
    without = build_report(**kw)
    assert with_cat["analysis_manifest"]["schema_version"] == 1
    assert with_cat["analysis_manifest"]["catalog"] == catalog
    assert "analysis_manifest" not in without
    # adding the catalog changes NOTHING else: findings/score/verdict/ids
    for key in ("summary", "projects", "scoring_formula", "limitations"):
        assert with_cat[key] == without[key]
    # determinism: two builds carry the identical catalog
    again = build_report(**kw, catalog=collect_catalog(default_adapters()))
    assert again["analysis_manifest"] == with_cat["analysis_manifest"]


def test_old_report_without_manifest_still_served(tmp_path):
    from fastapi.testclient import TestClient
    from auditor.web.app import create_app
    p = tmp_path / "report.json"
    p.write_text(json.dumps({"summary": {"counts": {}}, "projects": []}),
                 encoding="utf-8")
    c = TestClient(create_app(p))
    body = c.get("/api/report").json()
    assert body["projects"] == []
    # the server must NOT inject the installed build's capabilities into an
    # old scan — that would attribute new-version powers to an old report
    assert "analysis_manifest" not in body


# --- semgrep identity + fail-closed YAML (closure round) ---------------------

def test_semgrep_finding_ids_match_catalog_literally(catalog, tmp_path,
                                                     monkeypatch):
    """A REAL run_semgrep result (mocked semgrep JSON, as the binary emits it)
    must produce Finding.rule_id values that exist in the catalog LITERALLY —
    catalog_by_id[finding.rule_id], no removeprefix anywhere. Level and
    precision must also match the descriptor (metadata is the single source
    of truth; semgrep echoes rule metadata into extra.metadata)."""
    import json as _json
    import subprocess

    import auditor.core.semgrep_runner as runner
    from auditor.core.levels import normalize_level

    by_id = {d["rule_id"]: d for d in catalog}
    shipped = [d for d in catalog if d["source"] == "semgrep-or-opengrep"]
    assert len(shipped) == 5
    target = tmp_path / "a.py"
    target.write_text("x = 1\n", encoding="utf-8")
    payload = {
        "results": [{
            "check_id": d["rule_id"].removeprefix("S:"),  # the BINARY emits bare ids
            "path": str(target),
            "start": {"line": 1},
            "extra": {"severity": {"error": "ERROR", "warning": "WARNING",
                                   "note": "INFO"}[d["default_level"]],
                      "message": d["title"],
                      "metadata": {"auditor-precision": d["default_precision"]}},
        } for d in shipped],
        "paths": {"scanned": [str(target)]},
        "errors": [],
    }

    def fake_run(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 0, stdout=_json.dumps(payload),
                                           stderr="")

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    findings, status = runner.run_semgrep("semgrep", tmp_path, [])
    assert status == "success" and len(findings) == 5
    for f in findings:
        assert f.rule_id in by_id, f.rule_id           # LITERAL identity
        d = by_id[f.rule_id]
        assert normalize_level(None, f.severity.value) == d["default_level"]
        assert f.precision == d["default_precision"]   # both from YAML metadata


def test_shipped_semgrep_rules_are_heuristic_by_metadata(catalog):
    """Independent per-rule review (contract: syntactic checks with no
    data-flow are heuristic — RESEARCH.md 'syntactic لا data-flow'):
    - eval/exec on a non-literal proves dynamism, not untrusted input;
    - pickle.load proves deserialization, not untrusted data;
    - command concatenation proves composition, not user control;
    - MD5/SHA1 use proves the API, not a security (vs checksum) purpose.
    All five are therefore heuristic, sourced from YAML metadata."""
    for d in catalog:
        if d["source"] == "semgrep-or-opengrep":
            assert d["default_precision"] == "heuristic", d["rule_id"]
            assert d["rule_id"].startswith("S:")


@pytest.mark.parametrize("broken, reason", [
    ("rules:\n  - id: broken-rule\n    languages: [ruby]\n    severity: ERROR\n"
     "    message: m\n    metadata: {auditor-precision: heuristic}\n"
     "    pattern: foo(...)\n", "unsupported language"),
    ("rules:\n  - id: broken-rule\n    languages: [python]\n    severity: CRITICAL\n"
     "    message: m\n    metadata: {auditor-precision: heuristic}\n",
     "unsupported severity"),
    ("rules:\n  - id: broken-rule\n    severity: ERROR\n    message: m\n"
     "    metadata: {auditor-precision: heuristic}\n", "missing languages"),
    ("rules:\n  - id: broken-rule\n    languages: [python]\n    severity: ERROR\n"
     "    metadata: {auditor-precision: heuristic}\n", "missing message"),
    ("rules:\n  - id: broken-rule\n    languages: [python]\n    severity: ERROR\n"
     "    message: m\n", "auditor-precision"),
    ("rules: {not: a-list}\n", "'rules' list"),
    ("[ not: valid: yaml\n", "not parseable"),
])
def test_malformed_shipped_yaml_fails_closed(monkeypatch, broken, reason):
    """The literal counter-case family: a rule the parser cannot interpret
    must FAIL the catalog build — never degrade to warning/exact or claim
    every language."""
    import auditor.core.semgrep_rules_meta as meta
    monkeypatch.setattr(meta, "_shipped_yaml_text", lambda: broken)
    with pytest.raises(meta.SemgrepRulesError) as ei:
        meta.shipped_semgrep_descriptors()
    assert reason in str(ei.value)


def test_no_descriptor_leaves_collection_with_empty_languages(catalog):
    for d in catalog:
        assert d["languages"], d["rule_id"]


# --- hardening round: legal-but-odd semgrep JSON shapes ----------------------

def _run_with_payload(monkeypatch, tmp_path, payload):
    import json as _json
    import subprocess

    import auditor.core.semgrep_runner as runner

    def fake_run(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 0, stdout=_json.dumps(payload),
                                           stderr="")

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    return runner.run_semgrep("semgrep", tmp_path, [])


def _result(tmp_path, **over):
    base = {"check_id": "r", "path": str(tmp_path / "a.py"),
            "start": {"line": 1},
            "extra": {"message": "m", "severity": "WARNING"}}
    base.update(over)
    return base


@pytest.mark.parametrize("metadata", ["not-an-object", ["list"], None, 5])
def test_non_dict_metadata_is_legal_and_means_heuristic(monkeypatch, tmp_path,
                                                        metadata):
    """semgrep's spec types extra.metadata as raw_json — dict/string/list/null
    are all LEGAL. A non-dict must mean 'no declared precision' => heuristic,
    with no AttributeError and no invalid_output."""
    (tmp_path / "a.py").write_text("x=1\n", encoding="utf-8")
    extra = {"message": "m", "severity": "WARNING", "metadata": metadata}
    payload = {"results": [_result(tmp_path, extra=extra)],
               "paths": {"scanned": [str(tmp_path / "a.py")]}, "errors": []}
    findings, status = _run_with_payload(monkeypatch, tmp_path, payload)
    assert status == "success"
    assert len(findings) == 1
    assert findings[0].precision == "heuristic"


def test_malformed_single_result_skipped_good_ones_kept(monkeypatch, tmp_path):
    (tmp_path / "a.py").write_text("x=1\n", encoding="utf-8")
    payload = {"results": [
        _result(tmp_path),                              # good
        _result(tmp_path, extra=["boom"]),              # extra not a mapping
        "not-a-result-at-all",                          # result not a mapping
        _result(tmp_path, path={"odd": 1}),             # path not a string
    ], "paths": {"scanned": [str(tmp_path / "a.py")]}, "errors": []}
    findings, status = _run_with_payload(monkeypatch, tmp_path, payload)
    assert len(findings) == 1                           # the good one survives
    assert findings[0].rule_id == "S:r"
    assert status.startswith("partial (")
    assert "3 malformed result(s) skipped" in status


def test_results_not_a_list_is_invalid_output(monkeypatch, tmp_path):
    findings, status = _run_with_payload(
        monkeypatch, tmp_path, {"results": "nope", "paths": {}, "errors": []})
    assert findings == [] and status == "invalid_output"


# --- hardening round: YAML type chaos + duplicate ids -------------------------

@pytest.mark.parametrize("yaml_text, needle", [
    ("rules:\n  - id: r\n    languages: [python]\n    severity: []\n"
     "    message: m\n    metadata: {auditor-precision: heuristic}\n",
     "unsupported severity"),
    ("rules:\n  - id: r\n    languages: [{}]\n    severity: ERROR\n"
     "    message: m\n    metadata: {auditor-precision: heuristic}\n",
     "languages entries must be strings"),
    ("rules:\n"
     "  - id: dup\n    languages: [python]\n    severity: ERROR\n"
     "    message: m\n    metadata: {auditor-precision: heuristic}\n"
     "  - id: dup\n    languages: [python]\n    severity: ERROR\n"
     "    message: m\n    metadata: {auditor-precision: heuristic}\n",
     "duplicate id"),
])
def test_yaml_type_chaos_raises_semgrep_rules_error(monkeypatch, yaml_text, needle):
    """severity:[] and languages:[{}] previously escaped as raw TypeError
    (unhashable); duplicate ids merged silently. All must be a clean
    SemgrepRulesError naming the rule and the field."""
    import auditor.core.semgrep_rules_meta as meta
    monkeypatch.setattr(meta, "_shipped_yaml_text", lambda: yaml_text)
    with pytest.raises(meta.SemgrepRulesError) as ei:
        meta.shipped_semgrep_descriptors()
    msg = str(ei.value)
    assert needle in msg
    assert "Traceback" not in msg


def test_review_id_unchanged_by_catalog(catalog):
    from auditor.web.reviews import review_id
    a = review_id(".", "a.py", 1, "P002", "t", "auditor")
    rep = build_report("tgt", [{"language": "python", "root": ".", "file_count": 1,
                                "findings": [_finding()]}],
                       engines={}, limitations=[], confidence=100,
                       catalog=catalog)
    f = rep["projects"][0]["findings"][0]
    assert review_id(".", f["file"], f["line"], f["rule_id"], f["title"],
                     f["engine"]) == a
