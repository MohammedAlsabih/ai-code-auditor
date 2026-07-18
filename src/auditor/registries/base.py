from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict
from datetime import datetime, timezone

import requests

from auditor import __version__
from auditor.core.models import PackageInfo
from auditor.registries.cache import Cache

USER_AGENT = f"ai-code-auditor/{__version__} (+https://github.com/local/ai-code-auditor)"
TIMEOUT = (5, 15)
FRESH_DAYS = 90
LOW_DOWNLOADS = {"weekly": 500, "total": 1500}
TTL_EXISTS = 7 * 24 * 3600
TTL_MISSING = 24 * 3600


def make_session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = USER_AGENT
    return s


def parse_iso(s: str) -> datetime:
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def age_days(iso: str) -> int:
    return (datetime.now(timezone.utc) - parse_iso(iso)).days


class RegistryClient(ABC):
    ecosystem: str

    def __init__(self, session: requests.Session | None = None):
        self.session = session or make_session()

    def _get(self, url: str, **kw) -> requests.Response:
        kw.setdefault("timeout", TIMEOUT)
        return self.session.get(url, **kw)

    def cache_key(self, name: str) -> str:
        """The canonical cache key for a package name in THIS ecosystem. The base
        default is the verbatim name (case-preserving) — a global .lower() is
        NOT imposed on every registry. Clients whose ids are case-insensitive
        (e.g. NuGet, lowercased) or normalized (PyPI PEP 503) override this in
        their own task; Maven coordinates stay verbatim."""
        return name

    @abstractmethod
    def lookup(self, name: str) -> PackageInfo: ...


# exact field set AND field TYPES a cached PackageInfo must carry — a value
# like {"exists": "false"} (truthy string!) or created=123 (age_days would
# crash) must be a cold MISS, never served
_HIT_SCHEMA: dict[str, tuple[type, ...]] = {
    "exists": (bool,), "created": (str, type(None)), "latest": (str, type(None)),
    "downloads": (int, type(None)), "downloads_period": (str,),
    "quarantined": (bool,), "archived": (bool,), "error": (str, type(None)),
}


def _valid_hit(hit: object) -> bool:
    if not isinstance(hit, dict) or set(hit) != set(_HIT_SCHEMA):
        return False
    for field_name, types in _HIT_SCHEMA.items():
        value = hit[field_name]
        if isinstance(value, bool) and bool not in types:
            return False           # bool IS an int — reject True where int expected
        if not isinstance(value, types):
            return False
    # CP-8.10: VALUE semantics, not just types. A type-valid but garbage date
    # (created="not-a-date" / "2021-13-45...") would pass the type check and
    # then crash age_days downstream — reject it as a cold miss instead.
    for date_field in ("created", "latest"):
        val = hit[date_field]
        if isinstance(val, str):
            try:
                parse_iso(val)
            except (ValueError, TypeError):
                return False
    downloads = hit["downloads"]
    if isinstance(downloads, int) and downloads < 0:   # a negative count is nonsense
        return False
    return True


class CachedRegistry:
    def __init__(self, inner: RegistryClient, cache: Cache):
        self.inner = inner
        self.cache = cache

    @property
    def ecosystem(self) -> str:
        return self.inner.ecosystem

    def lookup(self, name: str) -> PackageInfo:
        # each client owns its canonical key — no global .lower() forced on Maven
        # coordinates or any case-sensitive ecosystem
        key = f"{self.ecosystem}:{self.inner.cache_key(name)}"
        hit = self.cache.get(key)
        if hit is not None and _valid_hit(hit):
            return PackageInfo(**hit)
        # foreign/corrupt shape or wrong field types => cache MISS, re-query fresh
        info = self.inner.lookup(name)
        if info.error is None:
            ttl = TTL_EXISTS if info.exists else TTL_MISSING
            self.cache.set(key, asdict(info), ttl)
        return info
