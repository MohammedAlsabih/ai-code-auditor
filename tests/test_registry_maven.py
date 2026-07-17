from datetime import datetime, timedelta, timezone

import responses

from auditor.registries.maven import MavenClient

META = "https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-databind/maven-metadata.xml"
OLD_XML = """<metadata>
  <groupId>com.fasterxml.jackson.core</groupId>
  <artifactId>jackson-databind</artifactId>
  <versioning>
    <latest>2.22.1</latest>
    <versions><version>2.0.0</version><version>2.22.1</version></versions>
    <lastUpdated>20240708002519</lastUpdated>
  </versioning>
</metadata>"""


@responses.activate
def test_existing_artifact_old_skips_pom_head():
    responses.get(META, body=OLD_XML)
    info = MavenClient().lookup("com.fasterxml.jackson.core:jackson-databind")
    assert info.exists and info.latest.startswith("2024-07-08")
    assert info.created is None and info.downloads is None
    assert len(responses.calls) == 1  # no HEAD for old artifacts


@responses.activate
def test_fresh_artifact_heads_all_poms_and_takes_oldest():
    recent = datetime.now(timezone.utc) - timedelta(days=10)
    older = datetime.now(timezone.utc) - timedelta(days=40)
    xml = OLD_XML.replace("20240708002519", recent.strftime("%Y%m%d%H%M%S"))
    responses.get(META, body=xml)
    base = "https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-databind"
    # version-sort != publish-sort: the LIST-first version carries the NEWER date
    responses.head(f"{base}/2.0.0/jackson-databind-2.0.0.pom",
                   headers={"Last-Modified": recent.strftime("%a, %d %b %Y %H:%M:%S GMT")})
    responses.head(f"{base}/2.22.1/jackson-databind-2.22.1.pom",
                   headers={"Last-Modified": older.strftime("%a, %d %b %Y %H:%M:%S GMT")})
    info = MavenClient().lookup("com.fasterxml.jackson.core:jackson-databind")
    assert info.exists and info.created is not None
    assert info.created.startswith(older.date().isoformat())  # min across ALL poms
    assert len(responses.calls) == 3  # metadata + 2 HEADs


@responses.activate
def test_missing_artifact():
    responses.get("https://repo1.maven.org/maven2/com/nope/ghost/maven-metadata.xml", status=404)
    info = MavenClient().lookup("com.nope:ghost")
    assert info.exists is False and info.error is None


def test_invalid_coordinates():
    info = MavenClient().lookup("not-coordinates")
    assert info.exists is False and "coordinates" in info.error


@responses.activate
def test_network_error():
    info = MavenClient().lookup("com.x:y")   # nothing registered
    assert info.error is not None


@responses.activate
def test_malformed_xml_is_error_not_crash():
    responses.get(META, body="<metadata><versioning>")
    info = MavenClient().lookup("com.fasterxml.jackson.core:jackson-databind")
    assert info.error is not None and info.exists is False


def test_cache_key_preserves_case():
    # Maven coordinates are case-sensitive (com.zaxxer:HikariCP)
    assert MavenClient().cache_key("com.zaxxer:HikariCP") == "com.zaxxer:HikariCP"
