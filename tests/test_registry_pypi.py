import responses

from auditor.registries.base import CachedRegistry, age_days
from auditor.registries.cache import Cache
from auditor.registries.pypi import PyPIClient, canonical

SIMPLE = "https://pypi.org/simple/{}/"


def test_canonical_pep503():
    assert canonical("Typing_Extensions") == "typing-extensions"
    assert canonical("zope.interface") == "zope-interface"


@responses.activate
def test_existing_package_with_dates():
    responses.get(SIMPLE.format("requests"), json={
        "files": [
            {"filename": "requests-0.1.tar.gz", "upload-time": "2011-02-14T08:49:42.641660Z"},
            {"filename": "requests-2.32.3.tar.gz", "upload-time": "2026-05-14T00:00:00Z"},
        ],
        "project-status": {"status": "active"},
    })
    info = PyPIClient().lookup("Requests")
    assert info.exists and info.created.startswith("2011-02-14")
    assert info.downloads is None  # old package => pypistats not called


@responses.activate
def test_missing_package_404():
    responses.get(SIMPLE.format("zzz-nope"), status=404)
    info = PyPIClient().lookup("zzz_nope")
    assert info.exists is False and info.error is None


@responses.activate
def test_fresh_package_triggers_downloads_lookup(monkeypatch):
    from datetime import datetime, timedelta, timezone
    monkeypatch.setattr("auditor.registries.pypi.time.sleep", lambda *_: None)
    recent = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
    responses.get(SIMPLE.format("newpkg"), json={
        "files": [{"filename": "newpkg-0.1.tar.gz", "upload-time": recent}],
    })
    responses.get("https://pypistats.org/api/packages/newpkg/recent",
                  json={"data": {"last_day": 1, "last_week": 7, "last_month": 9}})
    info = PyPIClient().lookup("newpkg")
    assert info.exists and info.downloads == 7 and info.downloads_period == "weekly"
    assert age_days(info.created) < 90


@responses.activate
def test_quarantined_flag(monkeypatch):
    monkeypatch.setattr("auditor.registries.pypi.time.sleep", lambda *_: None)
    responses.get(SIMPLE.format("evilpkg"), json={
        "files": [{"filename": "evilpkg-1.tar.gz", "upload-time": "2026-07-01T00:00:00Z"}],
        "project-status": {"status": "quarantined"},
    })
    info = PyPIClient().lookup("evilpkg")
    assert info.quarantined is True and info.downloads is None


@responses.activate
def test_archived_flag_via_state_key_alias():
    # PEP 792 prose uses `state`; tolerate it alongside the live `status`
    responses.get(SIMPLE.format("oldpkg"), json={
        "files": [{"filename": "oldpkg-1.tar.gz", "upload-time": "2020-01-01T00:00:00Z"}],
        "project-status": {"state": "archived"},
    })
    info = PyPIClient().lookup("oldpkg")
    assert info.archived is True and info.quarantined is False


@responses.activate
def test_network_error_reports_error_not_crash():
    info = PyPIClient().lookup("whatever")  # no responses registered => ConnectionError
    assert info.error is not None


@responses.activate
def test_cached_registry_hits_network_once(tmp_path):
    responses.get(SIMPLE.format("requests"), json={"files": [
        {"filename": "r-1.tar.gz", "upload-time": "2011-02-14T08:49:42Z"}]})
    reg = CachedRegistry(PyPIClient(), Cache(tmp_path / "c.json"))
    a = reg.lookup("requests")
    b = reg.lookup("requests")
    assert a.exists and b.exists and len(responses.calls) == 1


def test_cache_key_is_per_client_not_forced_lowercase():
    from auditor.registries.base import RegistryClient
    from auditor.core.models import PackageInfo

    class VerbatimClient(RegistryClient):
        ecosystem = "maven"
        def lookup(self, name): return PackageInfo(exists=True)
    # base default preserves case (Maven coordinates are NOT lowercased)
    assert VerbatimClient().cache_key("com.Foo:Bar") == "com.Foo:Bar"
    # PyPI canonicalizes per PEP 503
    assert PyPIClient().cache_key("Requests") == "requests"


def test_foreign_cache_value_shape_is_miss_not_registry_failure(tmp_path):
    import json
    import time

    from auditor.core.models import PackageInfo
    from auditor.registries.base import CachedRegistry, RegistryClient

    p = tmp_path / "c.json"
    # structurally valid entry, but the value has an unexpected field
    p.write_text(json.dumps({"pypi:requests": {
        "expires": time.time() + 9999,
        "value": {"exists": True, "unexpected_field": 1}}}), encoding="utf-8")

    calls = []

    class Inner(RegistryClient):
        ecosystem = "pypi"
        def cache_key(self, name): return name
        def lookup(self, name):
            calls.append(name)
            return PackageInfo(exists=True, created="2019-01-01T00:00:00Z")

    reg = CachedRegistry(Inner(), Cache(p))
    info = reg.lookup("requests")
    assert info.exists and info.error is None        # NOT an H004-inducing error
    assert calls == ["requests"]                     # corrupt hit => re-queried


@responses.activate
def test_pypi_cache_key_shares_entry_across_name_forms(tmp_path):
    responses.get(SIMPLE.format("typing-extensions"), json={"files": [
        {"filename": "te-1.tar.gz", "upload-time": "2016-01-01T00:00:00Z"}]})
    reg = CachedRegistry(PyPIClient(), Cache(tmp_path / "c.json"))
    reg.lookup("Typing_Extensions")
    reg.lookup("typing-extensions")     # same canonical key => cache hit
    assert len(responses.calls) == 1
