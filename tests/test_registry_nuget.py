import threading
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


def _index_body():
    return {"resources": [
        {"@id": "https://api.nuget.org/v3-flatcontainer/",
         "@type": "PackageBaseAddress/3.0.0"},
        {"@id": "https://api.nuget.org/v3/registration5-gz-semver2/",
         "@type": "RegistrationsBaseUrl/3.6.0"},
        {"@id": "https://azuresearch-usnc.nuget.org/query",
         "@type": "SearchQueryService/3.5.0"}]}


def test_service_index_init_is_atomic_under_race():
    """The service-index map must be published only once FULLY built. The bug
    set self._resources = {} *before* fetching, so a racing caller saw an empty
    dict and raised KeyError('flat'). Deterministic (Events, no sleeps): thread
    A is parked mid-build; while it is parked the shared map must still be None,
    and thread B — racing the init — must get the correct endpoint, never a
    KeyError."""
    client = NuGetClient()
    in_fetch = threading.Event()
    proceed = threading.Event()

    def blocking_get(url, **kw):
        in_fetch.set()          # A is inside _build_resources; nothing published yet
        assert proceed.wait(5)  # hold the critical section open so B races into it
        class _R:
            status_code = 200
            @staticmethod
            def json():
                return _index_body()
        return _R()

    client._get = blocking_get
    out: dict[str, object] = {}

    def call(tag):
        try:
            out[tag] = client._resource("flat")
        except Exception as exc:            # capture, don't lose it in the worker thread
            out[tag] = exc

    a = threading.Thread(target=call, args=("A",))
    a.start()
    assert in_fetch.wait(5)                 # A now holds the lock, parked mid-build
    # deterministic regression catch: the pre-fix code has published {} by here
    assert client._resources is None, "map published before it was complete"
    b = threading.Thread(target=call, args=("B",))
    b.start()                               # B sees None and must block on the lock
    proceed.set()                           # let A finish and publish atomically
    a.join(5)
    b.join(5)

    flat = "https://api.nuget.org/v3-flatcontainer/"
    assert out["A"] == flat, out["A"]       # both callers get the correct endpoint...
    assert out["B"] == flat, out["B"]       # ...and neither raised KeyError
    assert set(client._resources) == {"registration", "flat", "search"}  # complete, no partial state


def test_parallel_lookup_four_packages_zero_keyerror():
    """The four field-trial packages that reported 'lookup crashed: KeyError',
    looked up in parallel from ONE client, must all resolve with zero KeyError.
    Offline/deterministic: the service index and every per-package endpoint are
    stubbed, so no network and no real credentials are used."""
    flat = "https://api.nuget.org/v3-flatcontainer/"
    regn = "https://api.nuget.org/v3/registration5-gz-semver2/"
    client = NuGetClient()

    def stub_get(url, **kw):
        class _R:
            status_code = 200
            def __init__(self, payload):
                self._payload = payload
            def json(self):
                return self._payload
            def raise_for_status(self):
                return None
        if url == "https://api.nuget.org/v3/index.json":
            return _R(_index_body())
        if url.startswith(flat) and url.endswith("/index.json"):
            return _R({"versions": ["1.0.0"]})
        if url.startswith(regn):
            return _R({"count": 1, "items": [{"items": [
                {"catalogEntry": {"published": "2021-03-03T00:00:00+00:00"}}]}]})
        return _R({})

    client._get = stub_get
    packages = ["Grpc.Tools",
                "Microsoft.VisualStudio.Azure.Containers.Tools.Targets",
                "Npgsql.EntityFrameworkCore.PostgreSQL",
                "OpenTelemetry.AutoInstrumentation"]
    out: dict[str, object] = {}

    def worker(pkg):
        try:
            out[pkg] = client.lookup(pkg)
        except Exception as exc:
            out[pkg] = exc

    threads = [threading.Thread(target=worker, args=(p,)) for p in packages]
    for t in threads:
        t.start()
    for t in threads:
        t.join(5)

    assert set(out) == set(packages)
    for pkg in packages:
        assert not isinstance(out[pkg], Exception), f"{pkg} -> {out[pkg]!r}"
        assert out[pkg].exists is True
