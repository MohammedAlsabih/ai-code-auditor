from __future__ import annotations

import json
from urllib.parse import quote

import requests

from auditor.core.models import PackageInfo
from auditor.registries.base import FRESH_DAYS, RegistryClient, age_days

REGISTRY_URL = "https://registry.npmjs.org/{}"
DOWNLOADS_URL = "https://api.npmjs.org/downloads/point/last-week/{}"
MAX_DOC_BYTES = 2_000_000


class NpmClient(RegistryClient):
    """npm registry metadata. cache_key stays the base VERBATIM name — npm ids
    are case-sensitive identifiers (legacy JSONStream != jsonstream); the
    registry URL encodes the scoped slash, the downloads URL takes it literal."""
    ecosystem = "npm"

    def lookup(self, name: str) -> PackageInfo:
        url = REGISTRY_URL.format(quote(name, safe="@"))
        try:
            r = self._get(url, stream=True)
            if r.status_code == 404:
                return PackageInfo(exists=False)
            r.raise_for_status()
            raw = b""
            for chunk in r.iter_content(65536):
                raw += chunk
                if len(raw) > MAX_DOC_BYTES:
                    r.close()
                    return PackageInfo(exists=True)  # huge doc == long-established
            data = json.loads(raw)
        except (requests.RequestException, json.JSONDecodeError) as e:
            return PackageInfo(exists=False, error=f"npm: {e.__class__.__name__}")
        if not isinstance(data, dict):
            return PackageInfo(exists=True)   # 200 body of unexpected shape
        times = data.get("time")
        times = times if isinstance(times, dict) else {}
        created = times.get("created")
        created = created if isinstance(created, str) else None   # never age_days(123)
        latest = times.get("modified")
        latest = latest if isinstance(latest, str) else None
        downloads = None
        if created and age_days(created) < FRESH_DAYS:
            downloads = self._weekly_downloads(name)
        return PackageInfo(exists=True, created=created, latest=latest,
                           downloads=downloads, downloads_period="weekly")

    def _weekly_downloads(self, name: str) -> int | None:
        try:
            r = self._get(DOWNLOADS_URL.format(name))
            if r.status_code != 200:
                return None
            body = r.json()
            value = body.get("downloads") if isinstance(body, dict) else None
            return int(value) if isinstance(value, (int, float)) else None
        except (requests.RequestException, ValueError):
            return None
