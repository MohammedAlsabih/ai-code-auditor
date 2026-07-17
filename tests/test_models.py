from dataclasses import asdict
from pathlib import Path

from auditor.core.models import (DeclaredDep, Diagnostics, Finding, ImportRef,
                                 PackageInfo, Severity, SourceFile)


def test_severity_is_json_friendly_string():
    assert Severity.RED.value == "red"
    assert isinstance(Severity.YELLOW, str)


def test_finding_roundtrips_to_dict():
    f = Finding(rule_id="H001", severity=Severity.RED, title="t", file="a.py", line=3)
    d = asdict(f)
    assert d["severity"] == "red" and d["engine"] == "auditor" and d["snippet"] == ""
    assert d["precision"] == "exact"


def test_packageinfo_defaults():
    p = PackageInfo(exists=True)
    assert p.downloads is None and p.downloads_period == "weekly"
    assert not p.quarantined and not p.archived


def test_sourcefile_holds_tree_slot():
    sf = SourceFile(path=Path("x.py"), rel="x.py", language="python", text=b"")
    assert sf.tree is None


def test_declared_and_import_defaults():
    dep = DeclaredDep(name="requests", ecosystem="pypi", source_file="requirements.txt")
    imp = ImportRef(module="yaml", file="a.py", line=1)
    assert not dep.skip_registry and imp.top_level == ""
    assert dep.lookup_name == "requests"


def test_declared_lookup_name_uses_registry_alias():
    dep = DeclaredDep(name="my-react", ecosystem="npm", source_file="package.json",
                      registry_name="react")
    assert dep.lookup_name == "react"


def test_diagnostics_merge_dedups_manifest_but_sums_counters():
    a = Diagnostics(manifest_files=["/r/pyproject.toml"],
                    manifest_errors=["/r/pyproject.toml: TOMLDecodeError"],
                    rule_attempted=3, rule_failures=1)
    b = Diagnostics(manifest_files=["/r/pyproject.toml", "/s/pom.xml"],
                    manifest_errors=["/s/pom.xml: ParseError"],
                    rule_attempted=2, rule_failures=1)
    a.merge(b)
    assert set(a.manifest_files) == {"/r/pyproject.toml", "/s/pom.xml"}
    assert len(a.manifest_errors) == 2
    assert a.rule_attempted == 5 and a.rule_failures == 2
