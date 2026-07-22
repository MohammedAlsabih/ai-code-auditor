"""W2-B2.8B2-A: gate policy — gate_action/gate_counts, config v2 policy
tables, rule-level overrides, analysis_manifest.policy."""
import json

import pytest

from auditor.config import ConfigError, load_config
from auditor.core.models import Finding, Severity
from auditor.core.policy import GatePolicy, gate_action, policy_manifest
from auditor.report.build import build_report


def _f(rule="P002", sev=Severity.RED, precision="exact", file="a.py", line=3,
       title="t", snippet="s"):
    return Finding(rule, sev, title, file, line, snippet=snippet,
                   precision=precision)


def _rep(findings, policy=None, **kw):
    return build_report("tgt", [{"language": "python", "root": ".",
                                 "file_count": 1, "findings": findings}],
                        engines={}, limitations=[], confidence=100,
                        policy=policy, **kw)


# ---- the default gate table --------------------------------------------------

def test_default_gate_table():
    p = GatePolicy()
    assert gate_action("error", "exact", p) == "block"
    assert gate_action("error", "heuristic", p) == "review"
    assert gate_action("warning", "exact", p) == "review"
    assert gate_action("warning", "heuristic", p) == "review"
    assert gate_action("note", "exact", p) == "informational"
    assert gate_action("note", "heuristic", p) == "informational"


def test_exact_error_blocks_and_heuristic_error_reviews():
    rep = _rep([_f(precision="exact"),
                _f(rule="H008", precision="heuristic", file="b.py")])
    fs = rep["projects"][0]["findings"]
    by_rule = {f["rule_id"]: f for f in fs}
    assert by_rule["P002"]["gate_action"] == "block"
    assert by_rule["H008"]["gate_action"] == "review"
    # the heuristic error KEEPS its level — precision never rewrites level
    assert by_rule["H008"]["level"] == "error"
    assert rep["summary"]["gate_counts"] == {"block": 1, "review": 1,
                                             "informational": 0}
    assert rep["summary"]["verdict"] == "block"


def test_heuristic_error_alone_reviews_not_blocks():
    rep = _rep([_f(rule="H008", precision="heuristic")])
    assert rep["summary"]["verdict"] == "review"
    assert rep["summary"]["gate_counts"]["block"] == 0


def test_policy_promotion_blocks_heuristic_errors():
    rep = _rep([_f(rule="H008", precision="heuristic")],
               policy=GatePolicy(heuristic_errors="block"))
    assert rep["projects"][0]["findings"][0]["gate_action"] == "block"
    assert rep["summary"]["verdict"] == "block"


def test_notes_never_gate():
    rep = _rep([_f(rule="H003", sev=Severity.BLUE, precision="exact"),
                _f(rule="H007", sev=Severity.BLUE, precision="heuristic",
                   file="b.py")])
    assert rep["summary"]["gate_counts"] == {"block": 0, "review": 0,
                                             "informational": 2}
    assert rep["summary"]["verdict"] == "pass"


# ---- rule level overrides ------------------------------------------------------

def test_override_demotion_is_transparent_and_moves_the_gate():
    rep = _rep([_f(rule="R007", sev=Severity.RED, precision="heuristic")],
               policy=GatePolicy(rule_levels={"R007": "warning"}))
    f = rep["projects"][0]["findings"][0]
    assert f["level"] == "warning" and f["severity"] == "yellow"
    assert f["default_level"] == "error"
    assert f["level_source"] == "project_policy"
    assert f["gate_action"] == "review"
    # code_health follows the EFFECTIVE level (intended policy): 5, not 15
    assert rep["projects"][0]["score"] == 95
    assert rep["summary"]["level_counts"] == {"error": 0, "warning": 1, "note": 0}


def test_override_promotion_note_to_error_blocks():
    rep = _rep([_f(rule="P005", sev=Severity.BLUE, precision="exact")],
               policy=GatePolicy(rule_levels={"P005": "error"}))
    f = rep["projects"][0]["findings"][0]
    assert f["level"] == "error" and f["default_level"] == "note"
    assert f["level_source"] == "project_policy"
    assert rep["summary"]["verdict"] == "block"


def test_noop_override_carries_no_source_fields():
    rep = _rep([_f(rule="P002", sev=Severity.RED)],
               policy=GatePolicy(rule_levels={"P002": "error"}))
    f = rep["projects"][0]["findings"][0]
    assert "default_level" not in f and "level_source" not in f


def test_override_keeps_review_id_identity_fields():
    from auditor.web.reviews import review_id
    plain = _rep([_f(rule="R007", sev=Severity.RED)])
    overridden = _rep([_f(rule="R007", sev=Severity.RED)],
                      policy=GatePolicy(rule_levels={"R007": "note"}))
    def rid(rep):
        f = rep["projects"][0]["findings"][0]
        return review_id(".", f["file"], f["line"], f["rule_id"], f["title"],
                         f["engine"])
    assert rid(plain) == rid(overridden)


# ---- config schema v2 ----------------------------------------------------------

def _write(tmp_path, body):
    (tmp_path / ".auditor.toml").write_text(body, encoding="utf-8")


def test_config_v2_policy_tables_parse(tmp_path):
    _write(tmp_path, "schema_version = 2\n[policy]\nheuristic_errors = 'block'\n"
                     "[rule_levels]\nR007 = 'warning'\nP005 = 'error'\n")
    cfg = load_config(tmp_path)
    assert cfg.heuristic_errors == "block"
    assert cfg.rule_levels == {"R007": "warning", "P005": "error"}


def test_config_v2_defaults_without_policy(tmp_path):
    _write(tmp_path, "schema_version = 2\n")
    cfg = load_config(tmp_path)
    assert cfg.heuristic_errors == "review" and cfg.rule_levels == {}


def test_config_v1_still_loads(tmp_path):
    _write(tmp_path, "schema_version = 1\nexclude_paths = ['x']\n")
    cfg = load_config(tmp_path)
    assert cfg.exclude_paths == ("x",) and cfg.heuristic_errors == "review"


@pytest.mark.parametrize("body,needle", [
    ("schema_version = 2\n[policy]\nheuristic_errors = 'C:/Users/p/SECRET'\n",
     "must be one of: review, block"),
    ("schema_version = 2\n[policy]\nnope = 1\n", "unknown key"),
    ("schema_version = 2\npolicy = 3\n", "must be a table"),
    ("schema_version = 2\n[rule_levels]\nR007 = 'C:/Users/p/SECRET'\n",
     "invalid level"),
    ("schema_version = 2\n[rule_levels]\n\"../C:/SECRET x\" = 'error'\n",
     "invalid rule id"),
])
def test_config_v2_violations_fail_without_echo(tmp_path, body, needle):
    _write(tmp_path, body)
    with pytest.raises(ConfigError) as ei:
        load_config(tmp_path)
    msg = str(ei.value)
    assert needle in msg
    for frag in ("SECRET", "C:/", "Users"):
        assert frag not in msg, msg


def test_cli_rejects_rule_levels_unknown_in_catalog(tmp_path, capsys):
    from auditor.cli import main
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    _write(tmp_path, "schema_version = 2\n[rule_levels]\n"
                     "TOTALLY_UNKNOWN_RULE = 'error'\n")
    code = main(["scan", str(tmp_path), "--output", str(tmp_path / "r"),
                 "--offline", "--no-semgrep"])
    assert code == 2
    err = capsys.readouterr().err
    assert "not present in the tool rule catalog" in err
    assert "TOTALLY_UNKNOWN_RULE" not in err        # names are never echoed


# ---- analysis_manifest.policy ---------------------------------------------------

def test_policy_manifest_recorded_in_report():
    pol = GatePolicy(heuristic_errors="block", rule_levels={"R007": "warning"},
                     source=".auditor.toml")
    rep = _rep([_f()], policy=pol, catalog=[{
        "rule_id": "P002", "title": "x", "description": "d", "category": "c",
        "default_level": "error", "default_precision": "exact",
        "engine": "e", "languages": ["python"], "frameworks": [],
        "scope": "file", "source": "builtin"}])
    block = rep["analysis_manifest"]["policy"]
    assert block["schema_version"] == 1
    assert block["heuristic_errors"] == "block"
    assert block["rule_level_overrides"] == {"R007": "warning"}
    assert block["source"] == ".auditor.toml"
    assert "do NOT block by default" in json.dumps(policy_manifest(GatePolicy()))
