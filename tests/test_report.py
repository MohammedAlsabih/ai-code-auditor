import json

from auditor.core.models import Finding, Severity
from auditor.report.build import build_report
from auditor.report.json_out import write_json
from auditor.report.markdown import write_markdown


def _data():
    findings = [
        Finding("H001", Severity.RED, "Declared dependency not found in registry",
                "requirements.txt", 2, snippet="ghost-ai-utils==9.9.9",
                detail="ghost-ai-utils ...", language="python"),
        Finding("P001", Severity.YELLOW, "Empty catch", "app.py", 11, language="python"),
        Finding("P005", Severity.RED, "SQL sink", "app.py", 20, language="python",
                precision="heuristic"),
    ]
    return build_report(
        target="https://github.com/x/y",
        projects=[{"language": "python", "root": ".", "frameworks": [],
                   "file_count": 2, "findings": findings}],
        engines={"registry": "online", "semgrep": "not available",
                 "ast": "tree-sitter 0.26", "complexity": "lizard"},
        limitations=["Maven Central exposes no download counts"])


def test_build_report_scores_and_counts():
    data = _data()
    assert data["projects"][0]["score"] == 100 - 2 * 15 - 5   # 2 red + 1 yellow = 65
    assert data["projects"][0]["counts"] == {"red": 2, "yellow": 1, "blue": 0}
    assert data["summary"]["overall_score"] == 65
    assert data["summary"]["verdict"] == "block"
    assert "100" in data["scoring_formula"]


def test_json_report_roundtrip(tmp_path):
    p = tmp_path / "report.json"
    write_json(_data(), p)
    loaded = json.loads(p.read_text(encoding="utf-8"))
    assert loaded["projects"][0]["findings"][0]["severity"] == "red"
    by_rule = {f["rule_id"]: f for f in loaded["projects"][0]["findings"]}
    assert by_rule["P005"]["precision"] == "heuristic"   # never defaults to exact
    assert by_rule["H001"]["precision"] == "exact"


def test_report_redacts_credentials_in_snippets():
    # CP-3 policy (supersedes the earlier partial-userinfo draft): the ENTIRE
    # userinfo is redacted — a token in the username slot must not survive
    data = build_report(
        target="x",
        projects=[{"language": "python", "root": ".", "frameworks": [], "file_count": 1,
                   "findings": [Finding("H001", Severity.RED, "t", "requirements.txt", 1,
                                        snippet="pkg @ https://user:S3cretPass@host/x.whl")]}],
        engines={}, limitations=[])
    snip = data["projects"][0]["findings"][0]["snippet"]
    assert "S3cretPass" not in snip and "user" not in snip
    assert "***@host" in snip


def test_markdown_report_contains_the_essentials(tmp_path):
    p = tmp_path / "report.md"
    write_markdown(_data(), p)
    md = p.read_text(encoding="utf-8")
    for token in ("AI Code Auditor", "🔴", "🟡", "python", "requirements.txt:2",
                  "Limitations", "max(0, 100", "P005*"):
        assert token in md, token
    assert "P001*" not in md   # exact findings carry no heuristic marker
