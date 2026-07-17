from datetime import datetime, timedelta, timezone
from pathlib import Path

from auditor.core.hallucination import audit_hallucinations
from auditor.core.models import DeclaredDep, ImportRef, PackageInfo, Severity
from tests.conftest import FakeRegistry


class MiniAdapter:
    """Adapter stub: everything is external; declared-matching by exact name."""
    name = "python"
    ecosystem = "pypi"
    mapping_precision = "exact"

    def __init__(self, internal=(), private_reason=None, scoped_hint=False):
        self._internal = set(internal)
        self._private_reason = private_reason
        self._scoped_hint = scoped_hint

    def prepare(self, root, files): ...
    def is_internal(self, imp):
        return imp.top_level in self._internal
    def match_declared(self, imp, declared):
        return next((d for d in declared if d.name == imp.top_level), None)
    def registry_candidates(self, imp):
        return [imp.top_level]
    def extract_imports(self, files):
        return self._imports
    def parse_dependencies(self, root):
        return []
    def private_registry_reason(self, root):
        return self._private_reason
    def unresolvable_hint(self, identifier):
        # stands in for an npm-style scoped hint, kept OUT of core
        if self._scoped_hint and identifier.startswith("@"):
            return "scoped package (private scopes 404 without auth)"
        return None


def run(declared, imports, registry, internal=(), private_reason=None, scoped_hint=False):
    a = MiniAdapter(internal, private_reason, scoped_hint)
    a._imports = imports
    return audit_hallucinations(a, Path("."), [], declared, registry)


def _dep(name, **kw):
    return DeclaredDep(name=name, ecosystem="pypi", source_file="requirements.txt", **kw)


def _imp(name, line=1):
    return ImportRef(module=name, file="app.py", line=line, top_level=name)


OLD = "2019-01-01T00:00:00Z"
FRESH = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()


def test_declared_hallucination_is_red_h001():
    reg = FakeRegistry("pypi", {"requests": PackageInfo(True, created=OLD)})
    fs = run([_dep("requests"), _dep("ghost-ai-utils")], [], reg)
    ids = {(f.rule_id, f.severity) for f in fs}
    assert ("H001", Severity.RED) in ids
    assert all(f.rule_id != "H001" or "ghost-ai-utils" in f.detail for f in fs)


def test_undeclared_existing_import_is_yellow_h002():
    reg = FakeRegistry("pypi", {"yaml": PackageInfo(True, created=OLD)})
    fs = run([], [_imp("yaml", 3)], reg)
    assert [(f.rule_id, f.line) for f in fs] == [("H002", 3)]


def test_undeclared_missing_import_is_red_h008():
    reg = FakeRegistry("pypi", {})
    fs = run([], [_imp("superjsonify")], reg)
    assert [f.rule_id for f in fs] == ["H008"]


def test_fresh_package_yellow_h005_h006():
    reg = FakeRegistry("pypi", {
        "newlow": PackageInfo(True, created=FRESH, downloads=3),
        "newok": PackageInfo(True, created=FRESH, downloads=99999),
    })
    fs = run([_dep("newlow"), _dep("newok")], [], reg)
    got = {f.detail.split()[0]: f.rule_id for f in fs}  # detail starts with the name
    assert got["newlow"] == "H005" and got["newok"] == "H006"


def test_quarantined_is_red_h009():
    reg = FakeRegistry("pypi", {"evil": PackageInfo(True, created=OLD, quarantined=True)})
    assert [f.rule_id for f in run([_dep("evil")], [], reg)] == ["H009"]


def test_archived_is_blue_h012():
    reg = FakeRegistry("pypi", {"oldie": PackageInfo(True, created=OLD, archived=True)})
    fs = run([_dep("oldie")], [], reg)
    assert [(f.rule_id, f.severity) for f in fs] == [("H012", Severity.BLUE)]


def test_private_registry_downgrades_h001_to_h010():
    reg = FakeRegistry("pypi", {})
    fs = run([_dep("internal-corp-lib")], [], reg,
             private_reason="custom index configured in requirements.txt")
    assert [(f.rule_id, f.severity) for f in fs] == [("H010", Severity.YELLOW)]


def test_scoped_missing_is_h010_via_adapter_hint_not_core():
    # the scoped/private-source ambiguity now comes from the adapter, not core
    reg = FakeRegistry("npm", {})
    fs = run([DeclaredDep(name="@corp/secret-lib", ecosystem="npm",
                          source_file="package.json")], [], reg, scoped_hint=True)
    assert [f.rule_id for f in fs] == ["H010"]
    # without the adapter hint the same missing name is a plain H001 (core is neutral)
    fs2 = run([DeclaredDep(name="@corp/secret-lib", ecosystem="npm",
                           source_file="package.json")], [], reg, scoped_hint=False)
    assert [f.rule_id for f in fs2] == ["H001"]


def test_core_has_no_ecosystem_specific_branches():
    import inspect

    import auditor.core.hallucination as mod
    src = inspect.getsource(mod)
    for token in ('"@"', "'@'", "startswith(\"@\")", "npm", "pypi", "maven", "nuget"):
        assert token not in src, f"core neutrality violated: {token!r} in hallucination.py"


def test_distinct_namespace_imports_not_merged():
    # dedup must not collapse two distributions sharing a namespace top-level
    reg = FakeRegistry("pypi", {})

    class NS(MiniAdapter):
        def registry_candidates(self, imp):
            return []   # shared namespace => no candidate => dedup by full module
    a = NS()
    a._imports = [_imp2("google.cloud.storage", "google"),
                  _imp2("google.cloud.bigquery", "google")]
    fs = audit_hallucinations(a, Path("."), [], [], reg)
    assert [f.rule_id for f in fs] == ["H007", "H007"]   # two, not one


def _imp2(module, top):
    return ImportRef(module=module, file="app.py", line=1, top_level=top)


def test_npm_alias_checks_registry_name():
    reg = FakeRegistry("npm", {"react": PackageInfo(True, created=OLD)})
    dep = DeclaredDep(name="my-react", ecosystem="npm", source_file="package.json",
                      registry_name="react")
    assert run([dep], [], reg) == [] and reg.calls == ["react"]


def test_offline_mode_blue_h003_and_h007():
    fs = run([_dep("requests")], [_imp("yaml")], registry=None)
    assert {f.rule_id for f in fs} == {"H003", "H007"}
    assert all(f.severity == Severity.BLUE or f.rule_id == "H007" for f in fs)


def test_registry_error_is_blue_h004():
    class ErrReg:
        ecosystem = "pypi"
        def lookup(self, name):
            return PackageInfo(exists=False, error="pypi: ConnectionError")
    fs = run([_dep("requests")], [], ErrReg())
    assert [f.rule_id for f in fs] == ["H004"]


def test_lookup_exception_is_isolated_per_name():
    class Flaky:
        ecosystem = "pypi"
        def lookup(self, name):
            if name == "bomb":
                raise RuntimeError("driver exploded")
            return PackageInfo(True, created=OLD)
    fs = run([_dep("requests"), _dep("bomb")], [], Flaky())
    assert [f.rule_id for f in fs] == ["H004"]          # bomb => unverified, not a crash
    assert "lookup crashed: RuntimeError" in fs[0].detail
    assert all("requests" not in f.detail for f in fs)   # the healthy name sailed through


def test_skip_registry_and_internal_produce_nothing():
    reg = FakeRegistry("pypi", {})
    fs = run([_dep("local-lib", skip_registry=True)], [_imp("os")], reg, internal={"os"})
    assert fs == [] and reg.calls == []


def test_each_package_reported_once():
    reg = FakeRegistry("pypi", {})
    fs = run([], [_imp("ghost", 1), _imp("ghost", 9)], reg)
    assert len(fs) == 1 and fs[0].line == 1


def test_registry_failures_never_exceed_attempted():
    from auditor.core.models import Diagnostics
    reg = FakeRegistry("pypi", {"requests": PackageInfo(True, created=OLD)})
    a = MiniAdapter()
    a._imports = []
    diag = Diagnostics()
    # two declared names, one existing one missing (missing => not an error)
    audit_hallucinations(a, Path("."), [], [_dep("requests"), _dep("ghostpkg")], reg, diag=diag)
    assert diag.registry_failures <= diag.registry_attempted
    assert diag.registry_failures == 0        # 404 is not a lookup FAILURE


def test_registry_failures_count_unique_errors_not_findings():
    from auditor.core.models import Diagnostics

    class ErrReg:
        ecosystem = "pypi"
        def lookup(self, name):
            return PackageInfo(exists=False, error="boom")
    a = MiniAdapter()
    a._imports = []
    diag = Diagnostics()
    audit_hallucinations(a, Path("."), [], [_dep("a"), _dep("b")], ErrReg(), diag=diag)
    assert diag.registry_attempted == 2 and diag.registry_failures == 2


def test_h010_precision_is_exact_on_declared_path():
    reg = FakeRegistry("pypi", {})
    fs = run([_dep("corp-lib")], [], reg, private_reason="custom index in requirements.txt")
    assert [f.rule_id for f in fs] == ["H010"]
    assert fs[0].precision == "exact"   # H010 is not a namespace-mapping claim


def test_undeclared_import_keeps_package_security_state():
    # an undeclared import of an existing-but-quarantined/archived/fresh package
    # must surface BOTH H002 (undeclared fact) AND the security signal
    reg = FakeRegistry("pypi", {
        "quar": PackageInfo(True, created=OLD, quarantined=True),
        "arch": PackageInfo(True, created=OLD, archived=True),
        "freshlow": PackageInfo(True, created=FRESH, downloads=3),
        "freshok": PackageInfo(True, created=FRESH, downloads=99999),
    })
    assert {f.rule_id for f in run([], [_imp("quar")], reg)} == {"H002", "H009"}
    assert {f.rule_id for f in run([], [_imp("arch")], reg)} == {"H002", "H012"}
    assert {f.rule_id for f in run([], [_imp("freshlow")], reg)} == {"H002", "H005"}
    assert {f.rule_id for f in run([], [_imp("freshok")], reg)} == {"H002", "H006"}
