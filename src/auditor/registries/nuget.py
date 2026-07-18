from __future__ import annotations

import threading

import requests

from auditor.core.models import PackageInfo
from auditor.registries.base import FRESH_DAYS, RegistryClient, age_days

INDEX_URL = "https://api.nuget.org/v3/index.json"
# fallbacks only — the docs REQUIRE resolving endpoints from the service index
# ("The base URL ... must be dynamically fetched from the service index"),
# and the semver1 hives 404 on real SemVer2 packages.
REGN_FALLBACK = "https://api.nuget.org/v3/registration5-gz-semver2/"


class NuGetClient(RegistryClient):
    ecosystem = "nuget"

    def __init__(self, session=None):
        super().__init__(session)
        self._resources: dict[str, str] | None = None
        # guards the one-time service-index resolution: _resources must go from
        # None straight to a COMPLETE dict, never a half-filled one, or a racing
        # thread indexes it mid-build and gets KeyError.
        self._resources_lock = threading.Lock()
        self.degraded = False   # True => service index unreachable, hardcoded fallbacks in use

    def cache_key(self, name: str) -> str:
        # NuGet ids are case-insensitive (flat container mandates lowercase) —
        # one cache entry for every case form of the same id
        return name.lower()

    _WANTED = {
        "registration": (("RegistrationsBaseUrl/3.6.0", "RegistrationsBaseUrl/Versioned"),
                         REGN_FALLBACK),
        "flat": (("PackageBaseAddress/3.0.0",), "https://api.nuget.org/v3-flatcontainer/"),
        "search": (("SearchQueryService/3.5.0", "SearchQueryService"),
                   "https://azuresearch-usnc.nuget.org/query"),
    }

    def _resource(self, kind: str) -> str:
        """Resolve ALL used endpoints from the service index (docs mandate),
        highest compatible version first; hardcoded values are a visible
        degraded mode (self.degraded => diagnostics note in the CLI).

        Thread-safe (double-checked lock): self._resources is published only
        after it is FULLY built, so a concurrent caller either waits on the
        lock or reads the finished map — never a partial one. self._resources[
        kind] therefore cannot KeyError mid-initialisation."""
        resources = self._resources
        if resources is None:
            with self._resources_lock:
                resources = self._resources
                if resources is None:
                    resources, degraded = self._build_resources()
                    self.degraded = degraded
                    self._resources = resources   # atomic publish of a complete map
        return resources[kind]

    def _build_resources(self) -> tuple[dict[str, str], bool]:
        """Build the endpoint map into a LOCAL dict and return it with the
        degraded flag. Never touches self._resources, so a partial map is never
        observable by another thread."""
        built: dict[str, str] = {}
        degraded = False
        try:
            r = self._get(INDEX_URL)
            body = r.json() if r.status_code == 200 else {}
            resources = body.get("resources", []) if isinstance(body, dict) else []
        except (requests.RequestException, ValueError):
            resources = []
        if not resources:
            degraded = True
        for name, (types, fallback) in self._WANTED.items():
            hit = next((x["@id"] for t in types for x in resources
                        if isinstance(x, dict) and x.get("@type") == t), None)
            if hit is None:
                built[name] = fallback
                degraded = degraded or bool(resources)
            else:
                built[name] = hit if name == "search" else \
                    (hit if hit.endswith("/") else hit + "/")
        return built, degraded

    def lookup(self, name: str) -> PackageInfo:
        lid = name.lower()
        try:
            r = self._get(self._resource("flat") + lid + "/index.json")
            if r.status_code == 404:
                return PackageInfo(exists=False)
            r.raise_for_status()
        except requests.RequestException as e:
            return PackageInfo(exists=False, error=f"nuget: {e.__class__.__name__}")
        created, latest = self._published_range(lid)
        downloads = None
        period = None
        if created and age_days(created) < FRESH_DAYS:
            downloads = self._total_downloads(name)
            period = "total"
        return PackageInfo(exists=True, created=created, latest=latest,
                           downloads=downloads, downloads_period=period or "weekly")

    def _published_range(self, lid: str) -> tuple[str | None, str | None]:
        try:
            r = self._get(self._resource("registration") + lid + "/index.json")
            if r.status_code != 200:
                return None, None
            body = r.json()
            pages = body.get("items", []) if isinstance(body, dict) else []
            published: list[str] = []
            for page in pages:
                if not isinstance(page, dict):
                    continue
                leaves = page.get("items")
                if leaves is None and page.get("@id"):
                    sub = self._get(page["@id"])
                    sub_body = sub.json() if sub.status_code == 200 else {}
                    leaves = sub_body.get("items", []) if isinstance(sub_body, dict) else []
                for leaf in leaves or []:
                    if not isinstance(leaf, dict):
                        continue
                    entry = leaf.get("catalogEntry")
                    p = entry.get("published") if isinstance(entry, dict) else None
                    # 1900-01-01 marks UNLISTED versions, not real publish dates
                    if isinstance(p, str) and not p.startswith("1900"):
                        published.append(p)
            if not published:
                return None, None
            return min(published), max(published)
        except (requests.RequestException, ValueError):
            return None, None

    def _total_downloads(self, name: str) -> int | None:
        try:
            r = self._get(self._resource("search"),
                          params={"q": f"packageid:{name}",
                                  "prerelease": "true", "semVerLevel": "2.0.0"})
            data = r.json()
            if r.status_code != 200 or not isinstance(data, dict) \
                    or not data.get("totalHits"):
                return None    # search LAGS new packages — never used for existence
            return int(data["data"][0].get("totalDownloads", 0))
        except (requests.RequestException, ValueError, KeyError, IndexError):
            return None
