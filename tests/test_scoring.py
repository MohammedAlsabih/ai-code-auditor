from auditor.core.models import Finding, Severity
from auditor.core.scoring import language_score, overall_score


def _f(sev):
    return Finding("X", sev, "t", "f", 1)


def test_language_score_excludes_blue_from_risk():
    fs = [_f(Severity.RED), _f(Severity.YELLOW), _f(Severity.BLUE)]
    assert language_score(fs) == 100 - 15 - 5  # blue is informational, not risk


def test_language_score_floors_at_zero():
    assert language_score([_f(Severity.RED)] * 10) == 0


def test_overall_weighted_by_files():
    assert overall_score([(100, 1), (50, 3)]) == round((100 * 1 + 50 * 3) / 4)
    assert overall_score([]) is None


def test_confidence_is_coverage_ratio_based():
    from auditor.core.models import Diagnostics
    from auditor.core.scoring import analysis_confidence
    clean = Diagnostics(semgrep_status="opengrep 1.25.0: success")
    assert analysis_confidence(clean, offline=False, files_read=10) == 100
    assert analysis_confidence(clean, offline=True, files_read=10) == 50
    # denominators matter: 5-of-5 skipped is a disaster, 5-of-50000 is noise
    tiny = Diagnostics(skipped_files=["a", "b", "c", "d", "e"],
                       semgrep_status="x: success")
    assert analysis_confidence(tiny, offline=False, files_read=0) == 0
    huge = Diagnostics(skipped_files=["a", "b", "c", "d", "e"],
                       semgrep_status="x: success")
    assert analysis_confidence(huge, offline=False, files_read=49_995) == 100


def test_fourth_round_counterexamples_are_closed():
    """100/100 parse errors gave 70=PASS and all-rules-failed gave 80=PASS
    under coverage-v1 (measured). Both must be 0 => block under v2."""
    from auditor.core.models import Diagnostics
    from auditor.core.scoring import analysis_confidence, verdict
    all_parse = Diagnostics(parse_error_files=[f"f{i}.ts" for i in range(100)],
                            semgrep_status="x: success")
    assert analysis_confidence(all_parse, offline=False, files_read=100) == 0
    all_rules = Diagnostics(rule_attempted=400, rule_failures=400,
                            semgrep_status="x: success")
    assert analysis_confidence(all_rules, offline=False, files_read=100) == 0
    assert verdict({"red": 0, "yellow": 0}, 0,
                   {"rule_attempted": 400, "rule_failures": 400}) == "block"


def test_manifest_cov_counts_unique_files_not_reads():
    from auditor.core.models import Diagnostics
    from auditor.core.scoring import analysis_confidence
    # same broken file read 3 times: 1 unique file, 1 unique error => cov 0, not 2/3
    d = Diagnostics(manifest_files=["pyproject.toml"],
                    manifest_errors=["pyproject.toml: TOMLDecodeError"],
                    semgrep_status="x: success")
    d2 = Diagnostics(manifest_files=["pyproject.toml", "requirements.txt", "Pipfile"],
                     manifest_errors=["pyproject.toml: TOMLDecodeError"],
                     semgrep_status="x: success")
    assert analysis_confidence(d, False, 10) < analysis_confidence(d2, False, 10)


def test_monorepo_two_corrupt_manifests_give_zero_coverage(tmp_path):
    # two pyproject.toml in different roots must NOT merge by name
    from auditor.adapters.python.adapter import PythonAdapter
    from auditor.core.models import Diagnostics
    from auditor.core.scoring import analysis_confidence
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "pyproject.toml").write_text("[project\nx", encoding="utf-8")
    (tmp_path / "b" / "pyproject.toml").write_text("[project\ny", encoding="utf-8")
    diag = Diagnostics()
    PythonAdapter().parse_dependencies(tmp_path / "a", diag=diag)
    d2 = Diagnostics()
    PythonAdapter().parse_dependencies(tmp_path / "b", diag=d2)
    diag.merge(d2)
    assert len(set(diag.manifest_errors)) == 2   # distinct by full path
    assert len(set(diag.manifest_files)) == 2
    # both manifests broken => manifest coverage 0
    assert analysis_confidence(diag, offline=False, files_read=5) == 0


def test_verdict_contract():
    from auditor.core.scoring import verdict
    assert verdict({"red": 1, "yellow": 0}, 100, {}) == "block"
    assert verdict({"red": 0, "yellow": 0}, 39, {}) == "block"     # incomplete != passed
    assert verdict({"red": 0, "yellow": 2}, 100, {}) == "review"
    assert verdict({"red": 0, "yellow": 0}, 100,
                   {"manifest_errors": ["x"]}) == "review"
    assert verdict({"red": 0, "yellow": 0}, 100,
                   {"rule_attempted": 50, "rule_failures": 1}) == "review"  # ANY rule failure != pass
    assert verdict({"red": 0, "yellow": 0}, 100, {}) == "pass"
