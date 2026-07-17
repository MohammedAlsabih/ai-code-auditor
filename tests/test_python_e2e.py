from auditor.adapters.python.adapter import PythonAdapter
from auditor.core.hallucination import audit_hallucinations
from auditor.core.models import PackageInfo, Severity
from auditor.discovery import discover_projects, project_files
from tests.conftest import FakeRegistry

OLD = "2019-01-01T00:00:00Z"


def test_python_reference_pipeline(fixtures_dir):
    root = fixtures_dir / "python_repo"
    adapter = PythonAdapter()
    projects = discover_projects(root, [adapter])
    assert [(a.name, p) for a, p in projects] == [("python", root)]

    files = project_files(root, adapter, projects)
    assert {f.rel for f in files} == {"app.py", "localmod.py"}

    declared = adapter.parse_dependencies(root)
    assert {d.name for d in declared} == {"requests", "ghost-ai-utils"}

    adapter.prepare(root, files)
    reg = FakeRegistry("pypi", {
        "requests": PackageInfo(True, created=OLD),
        "pyyaml": PackageInfo(True, created=OLD),
    })
    findings = audit_hallucinations(adapter, root, files, declared, reg)
    got = {(f.rule_id, f.severity, f.file) for f in findings}
    assert got == {
        ("H001", Severity.RED, "requirements.txt"),      # ghost-ai-utils
        ("H002", Severity.YELLOW, "app.py"),             # yaml -> pyyaml exists
        ("H008", Severity.RED, "app.py"),                # superjsonify
    }
    h001 = next(f for f in findings if f.rule_id == "H001")
    assert "ghost-ai-utils" in f"{h001.detail}{h001.snippet}" and h001.line == 2
