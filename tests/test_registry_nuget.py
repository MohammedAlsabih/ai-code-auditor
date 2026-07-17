from datetime import datetime, timedelta, timezone

import responses

from auditor.registries.nuget import NuGetClient

INDEX = "https://api.nuget.org/v3/index.json"
FLAT = "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/index.json"
REGN = "https://api.nuget.org/v3/registration5-gz-semver2/newtonsoft.json/index.json"
SEARCH = "https://azuresearch-usnc.nuget.org/query"


def _mock_index():
    responses.get(INDEX, json={"resources": [
        {"@id": "https://api.nuget.org/v3/registration5-gz-semver2/",
         "@type": "RegistrationsBaseUrl/3.6.0"},
        {"@id": "https://api.nuget.org/v3-flatcontainer/",
         "@type": "PackageBaseAddress/3.0.0"},
        {"@id": "https://azuresearch-usnc.nuget.org/query",
         "@type": "SearchQueryService/3.5.0"}]})


@responses.activate
def test_existing_package_skips_1900_unlisted():
    _mock_index()
    responses.get(FLAT, json={"versions": ["12.0.1", "13.0.4"]})
    responses.get(REGN, json={"count": 1, "items": [{"items": [
        {"catalogEntry": {"published": "1900-01-01T00:00:00+00:00", "listed": False}},
        {"catalogEntry": {"published": "2011-01-08T22:12:57.713+00:00", "listed": True}},
        {"catalogEntry": {"published": "2024-06-01T00:00:00+00:00", "listed": True}},
    ]}]})
    info = NuGetClient().lookup("Newtonsoft.Json")   # note the mixed case input
    assert info.exists and info.created.startswith("2011-01-08")
    assert info.latest.startswith("2024-06-01") and info.downloads is None


@responses.activate
def test_external_registration_pages_are_fetched():
    _mock_index()
    responses.get(FLAT, json={"versions": ["1.0.0"]})
    responses.get(REGN, json={"count": 1, "items": [
        {"@id": "https://api.nuget.org/v3/registration5-gz-semver2/newtonsoft.json/page1.json"}]})
    responses.get("https://api.nuget.org/v3/registration5-gz-semver2/newtonsoft.json/page1.json",
                  json={"items": [{"catalogEntry": {"published": "2020-05-05T00:00:00+00:00"}}]})
    info = NuGetClient().lookup("newtonsoft.json")
    assert info.exists and info.created.startswith("2020-05-05")


@responses.activate
def test_fresh_package_downloads_via_search():
    recent = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    flat = "https://api.nuget.org/v3-flatcontainer/shinynew/index.json"
    regn = "https://api.nuget.org/v3/registration5-gz-semver2/shinynew/index.json"
    _mock_index()
    responses.get(flat, json={"versions": ["0.1.0"]})
    responses.get(regn, json={"count": 1, "items": [{"items": [
        {"catalogEntry": {"published": recent}}]}]})
    responses.get(SEARCH, json={"totalHits": 1, "data": [{"totalDownloads": 42}]})
    info = NuGetClient().lookup("ShinyNew")
    assert info.downloads == 42 and info.downloads_period == "total"


@responses.activate
def test_missing_package():
    _mock_index()
    responses.get("https://api.nuget.org/v3-flatcontainer/ghost.pkg/index.json", status=404)
    info = NuGetClient().lookup("Ghost.Pkg")
    assert info.exists is False and info.error is None


@responses.activate
def test_unreachable_index_falls_back_degraded():
    # no INDEX mock registered => ConnectionError => hardcoded fallbacks + degraded flag
    responses.get("https://api.nuget.org/v3-flatcontainer/dapper/index.json", status=404)
    client = NuGetClient()
    assert client.lookup("Dapper").exists is False
    assert client.degraded is True  # CLI surfaces this in diagnostics/limitations


def test_cache_key_lowercases():
    # NuGet ids are case-insensitive; the flat container REQUIRES lowercase —
    # Newtonsoft.Json and newtonsoft.json must share one cache entry
    c = NuGetClient()
    assert c.cache_key("Newtonsoft.Json") == "newtonsoft.json"
