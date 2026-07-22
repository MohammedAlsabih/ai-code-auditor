import json

from auditor.cli import main


def test_cli_scan_monorepo_offline(fixtures_dir, tmp_path, capsys):
    out = tmp_path / "rep"
    code = main(["scan", str(fixtures_dir / "monorepo"),
                 "--output", str(out), "--offline", "--no-semgrep"])
    assert code == 1  # pattern engines still find RED (secret/SQL sink/react) offline
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    langs = {p["language"] for p in data["projects"]}
    assert langs == {"python", "typescript"}
    all_rules = {f["rule_id"] for p in data["projects"] for f in p["findings"]}
    assert "H003" in all_rules          # offline blue markers
    assert "P002" in all_rules          # secret in python app.py
    assert "R001" in all_rules          # hooks in condition in Widget.tsx
    assert "N001" in all_rules          # .env.local public secret
    assert (out / "report.md").read_text(encoding="utf-8").startswith("# AI Code Auditor Report")
    # coverage-v3 (B2.8B2): NO registry factor — offline no longer halves the
    # number; no semgrep binary => 0.95 factor. Asserted EXACTLY: recompute
    # when the coverage model changes, never leave two numbers.
    assert data["summary"]["analysis_confidence"] == 95
    assert data["summary"]["confidence"] == 95            # deprecated alias
    # the registry axis is SEPARATE: intended offline => unavailable + null
    assert data["summary"]["registry_status"] == "unavailable"
    assert data["summary"]["registry_confidence"] is None
    assert data["summary"]["verdict"] == "block"          # exact errors exist
    assert data["summary"]["gate_counts"]["block"] >= 1
    assert data["summary"]["lowest_language"] is not None
    assert "diagnostics" in data and "semgrep_status" in data["diagnostics"]
    printed = capsys.readouterr().out
    assert "report.md" in printed and "confidence" in printed and "BLOCK" in printed


def test_cli_surfaces_manifest_corruption_end_to_end(tmp_path):
    # the no-silent-failure contract, driven through the FULL path to report.json
    (tmp_path / "pyproject.toml").write_text("[project\nbroken toml", encoding="utf-8")
    (tmp_path / "app.py").write_text("import os\n", encoding="utf-8")
    out = tmp_path / "rep"
    code = main(["scan", str(tmp_path), "--output", str(out), "--offline", "--no-semgrep"])
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert any("pyproject.toml" in e for e in data["diagnostics"]["manifest_errors"])
    assert data["summary"]["verdict"] in ("review", "block")  # never a clean pass
    assert code == 0 or code == 1
    strict = main(["scan", str(tmp_path), "--output", str(out), "--offline",
                   "--no-semgrep", "--strict"])
    assert strict == 1  # incomplete analysis must not exit 0 in strict mode


def test_cli_incomplete_manifest_never_passes(tmp_path):
    # CP-8.1 gate: a partially-extracted manifest (dynamic setup.py) must reach
    # report.json AND forbid a clean PASS, end to end.
    (tmp_path / "setup.py").write_text(
        "from setuptools import setup\nsetup(install_requires=get_reqs())\n",
        encoding="utf-8")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")   # clean code
    out = tmp_path / "rep"
    main(["scan", str(tmp_path), "--output", str(out), "--offline", "--no-semgrep"])
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert data["diagnostics"]["manifest_incomplete"]      # surfaced end to end
    assert data["summary"]["verdict"] != "pass"            # incomplete => never clean


def test_cli_report_never_leaks_target_credentials(tmp_path):
    # CP-8.7 gate: a credential in the scan target must not survive into report.json
    out = tmp_path / "rep"
    main(["scan", str(tmp_path), "--output", str(out), "--offline", "--no-semgrep"])
    # (a local path target has no creds; assert the redaction path is wired by
    # feeding a credential-bearing target string through the report builder)
    from auditor.report.build import build_report
    data = build_report(target="https://u:S3cr3tW1re@github.com/x/y", projects=[],
                        engines={}, limitations=[])
    assert "S3cr3tW1re" not in json.dumps(data)


def test_cli_bad_target_exits_2(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "missing")]) == 2
    assert "خطأ" in capsys.readouterr().err  # bilingual error goes to stderr


def test_cli_survives_legacy_console_codepage(fixtures_dir, tmp_path, monkeypatch):
    # cp1256 console cannot encode the emoji in the summary — must degrade to
    # '?' instead of crashing the scan (found by the live CP-7 run)
    import io
    import sys
    raw = io.BytesIO()
    legacy = io.TextIOWrapper(raw, encoding="cp1256")
    monkeypatch.setattr(sys, "stdout", legacy)
    code = main(["scan", str(fixtures_dir / "monorepo"),
                 "--output", str(tmp_path / "rep"), "--offline", "--no-semgrep"])
    legacy.flush()
    assert code == 1                       # completed, no UnicodeEncodeError
    assert b"scan complete" in raw.getvalue()


def test_cli_empty_dir_exits_0(tmp_path):
    code = main(["scan", str(tmp_path), "--output", str(tmp_path / "r"), "--offline"])
    assert code == 0
    data = json.loads((tmp_path / "r" / "report.json").read_text(encoding="utf-8"))
    assert data["projects"] == [] and data["summary"]["overall_score"] is None
