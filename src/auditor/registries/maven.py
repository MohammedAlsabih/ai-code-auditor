from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import defusedxml.ElementTree as ET
import requests
from defusedxml import DefusedXmlException

from auditor.core.models import PackageInfo
from auditor.registries.base import FRESH_DAYS, RegistryClient, age_days

META_URL = "https://repo1.maven.org/maven2/{}/{}/maven-metadata.xml"
POM_URL = "https://repo1.maven.org/maven2/{}/{}/{}/{}-{}.pom"


def _ts_to_iso(ts: str) -> str | None:
    try:
        return datetime.strptime(ts, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        return None


class MavenClient(RegistryClient):
    """repo1 maven-metadata.xml, NOT the frozen solrsearch API. cache_key stays
    the base verbatim coordinates (case-sensitive: com.zaxxer:HikariCP)."""
    ecosystem = "maven"

    def lookup(self, name: str) -> PackageInfo:
        if ":" not in name:
            return PackageInfo(exists=False,
                               error="invalid maven coordinates (need group:artifact)")
        group, artifact = name.split(":", 1)
        gpath = group.replace(".", "/")
        try:
            r = self._get(META_URL.format(gpath, artifact))
            if r.status_code == 404:
                return PackageInfo(exists=False)
            r.raise_for_status()
            root = ET.fromstring(r.text)   # defused: repo1 responses are external input too
        except (requests.RequestException, ET.ParseError, DefusedXmlException) as e:
            return PackageInfo(exists=False, error=f"maven: {e.__class__.__name__}")
        latest = _ts_to_iso(root.findtext("./versioning/lastUpdated", default=""))
        versions = [v.text for v in root.findall("./versioning/versions/version") if v.text]
        # Review-refuted TWICE: <versions> is VERSION-sorted, not publish-sorted,
        # and a small count does NOT make the order chronological. So for young
        # artifacts (<=10 versions AND recent lastUpdated) we HEAD *every* POM
        # and take the OLDEST Last-Modified; otherwise created stays unknown and
        # the engine simply emits no freshness finding (H005/H006 need created).
        # Last-Modified itself is a server heuristic, not a canonical publish
        # date — documented in report limitations. downloads are ALWAYS None:
        # Maven Central exposes no download counts (documented limitation).
        created = None
        if latest and versions and len(versions) <= 10 and age_days(latest) < 4 * FRESH_DAYS:
            dates = [d for d in (self._pom_date(gpath, artifact, v) for v in versions) if d]
            created = min(dates) if dates else None
        return PackageInfo(exists=True, created=created, latest=latest,
                           downloads=None, downloads_period="weekly")

    def _pom_date(self, gpath: str, artifact: str, version: str) -> str | None:
        try:
            r = self.session.head(POM_URL.format(gpath, artifact, version, artifact, version),
                                  timeout=(5, 15))
            lm = r.headers.get("Last-Modified")
            return parsedate_to_datetime(lm).isoformat() if lm else None
        except (requests.RequestException, TypeError, ValueError):
            return None
