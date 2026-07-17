from __future__ import annotations

import re
import threading
import time

import requests

from auditor.core.models import PackageInfo
from auditor.registries.base import FRESH_DAYS, RegistryClient, age_days

SIMPLE_URL = "https://pypi.org/simple/{}/"
STATS_URL = "https://pypistats.org/api/packages/{}/recent"
_ACCEPT = "application/vnd.pypi.simple.v1+json"  # PEP 691
_stats_lock = threading.Lock()                    # pypistats hard-throttles (~0.5 req/s)


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


class PyPIClient(RegistryClient):
    ecosystem = "pypi"

    def lookup(self, name: str) -> PackageInfo:
        cname = canonical(name)
        try:
            r = self._get(SIMPLE_URL.format(cname), headers={"Accept": _ACCEPT})
            if r.status_code == 404:
                return PackageInfo(exists=False)
            r.raise_for_status()
            data = r.json()
        except requests.RequestException as e:
            return PackageInfo(exists=False, error=f"pypi: {e.__class__.__name__}")
        times = sorted(f["upload-time"] for f in data.get("files", []) if f.get("upload-time"))
        created = times[0] if times else None
        latest = times[-1] if times else None
        # PEP 792: live PyPI + living spec use `status`, but the PEP prose says
        # `state` — tolerate BOTH (absent => active); PyPI implements
        # active/archived/quarantined today
        ps = data.get("project-status", {}) or {}
        status = ps.get("status") or ps.get("state") or "active"
        downloads = None
        if created and age_days(created) < FRESH_DAYS and status == "active":
            downloads = self._weekly_downloads(cname)
        return PackageInfo(exists=True, created=created, latest=latest,
                           downloads=downloads, quarantined=status == "quarantined",
                           archived=status == "archived")

    def _weekly_downloads(self, cname: str) -> int | None:
        with _stats_lock:
            time.sleep(1.2)  # etiquette: stay far under pypistats 429 threshold
            try:
                r = self._get(STATS_URL.format(cname))
                if r.status_code != 200 or "json" not in r.headers.get("Content-Type", ""):
                    return None
                return int(r.json()["data"]["last_week"])
            except (requests.RequestException, KeyError, ValueError):
                return None
