from datetime import datetime, timedelta, timezone

import responses

from auditor.registries.npm import NpmClient

REG = "https://registry.npmjs.org/"
DL = "https://api.npmjs.org/downloads/point/last-week/"
FRESH = (datetime.now(timezone.utc) - timedelta(days=4)).isoformat()


@responses.activate
def test_existing_package():
    responses.get(REG + "lodash", json={
        "name": "lodash", "dist-tags": {"latest": "4.17.21"},
        "time": {"created": "2012-04-23T16:37:11.912Z", "modified": "2024-01-01T00:00:00Z"},
    })
    info = NpmClient().lookup("lodash")
    assert info.exists and info.created.startswith("2012-04-23") and info.downloads is None


@responses.activate
def test_missing_package_404():
    responses.get(REG + "nope-xyz", json={"error": "Not found"}, status=404)
    info = NpmClient().lookup("nope-xyz")
    assert info.exists is False and info.error is None


@responses.activate
def test_scoped_name_is_slash_encoded():
    responses.get(REG + "@types%2Fnode", json={
        "name": "@types/node", "time": {"created": "2016-03-01T00:00:00Z"}})
    info = NpmClient().lookup("@types/node")
    assert info.exists


@responses.activate
def test_fresh_package_downloads():
    responses.get(REG + "shiny-new", json={"name": "shiny-new", "time": {"created": FRESH}})
    responses.get(DL + "shiny-new", json={"downloads": 12, "start": "x", "end": "y",
                                          "package": "shiny-new"})
    info = NpmClient().lookup("shiny-new")
    assert info.downloads == 12 and info.downloads_period == "weekly"


@responses.activate
def test_network_error():
    info = NpmClient().lookup("anything")  # no responses registered
    assert info.error is not None and info.exists is False


@responses.activate
def test_giant_doc_is_treated_as_established(monkeypatch):
    import auditor.registries.npm as npm
    monkeypatch.setattr(npm, "MAX_DOC_BYTES", 10)     # force the cap
    responses.get(REG + "react", body='{"name": "react", "time": {}}' + " " * 100)
    info = NpmClient().lookup("react")
    assert info.exists is True and info.error is None


@responses.activate
def test_schema_tolerance_time_not_a_dict():
    # a hostile/broken doc must not crash the client (CP-3 contract)
    responses.get(REG + "weird", json={"name": "weird", "time": "not-a-dict"})
    info = NpmClient().lookup("weird")
    assert info.exists is True and info.error is None and info.created is None


@responses.activate
def test_schema_tolerance_created_not_a_string():
    responses.get(REG + "weird2", json={"name": "weird2", "time": {"created": 123}})
    info = NpmClient().lookup("weird2")
    assert info.exists is True and info.created is None   # never age_days(123)


def test_cache_key_is_verbatim():
    # npm names are case-sensitive identifiers (legacy JSONStream != jsonstream)
    assert NpmClient().cache_key("JSONStream") == "JSONStream"
    assert NpmClient().cache_key("@types/node") == "@types/node"
