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

    @abstractmethod
    def lookup(self, name: str) -> PackageInfo: ...


class CachedRegistry:
    def __init__(self, inner: RegistryClient, cache: Cache):
        self.inner = inner
        self.cache = cache

    @property
    def ecosystem(self) -> str:
        return self.inner.ecosystem

    def lookup(self, name: str) -> PackageInfo:
        key = f"{self.ecosystem}:{name.lower()}"
        hit = self.cache.get(key)
        if hit is not None:
            return PackageInfo(**hit)
        info = self.inner.lookup(name)
        if info.error is None:
            ttl = TTL_EXISTS if info.exists else TTL_MISSING
            self.cache.set(key, asdict(info), ttl)
        return info
