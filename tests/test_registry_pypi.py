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
