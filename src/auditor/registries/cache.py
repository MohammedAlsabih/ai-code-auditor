from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from pathlib import Path

import platformdirs


def default_cache_path() -> Path:
    return Path(platformdirs.user_cache_dir("ai-code-auditor")) / "registry-cache.json"


class Cache:
    def __init__(self, path: Path | None = None):
        self.path = path or default_cache_path()
        self._lock = threading.Lock()
        self._data: dict[str, dict] = {}
        # the cache is a non-critical optimization: a corrupt/foreign/older file
        # (wrong JSON type, missing keys, bad value shapes) is treated as a cold
        # cache — it must NEVER abort the audit
        if self.path.is_file():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                raw = None
            if isinstance(raw, dict):
                now = time.time()
                self._data = {
                    k: v for k, v in raw.items()
                    if isinstance(v, dict)
                    and isinstance(v.get("expires"), (int, float))
                    and isinstance(v.get("value"), dict)
                    and v["expires"] > now
                }

    def get(self, key: str) -> dict | None:
        with self._lock:
            entry = self._data.get(key)
            if not isinstance(entry, dict) or entry.get("expires", 0) <= time.time():
                self._data.pop(key, None)
                return None
            return entry.get("value")

    def set(self, key: str, value: dict, ttl_seconds: int) -> None:
        with self._lock:
            self._data[key] = {"expires": time.time() + ttl_seconds, "value": value}
            try:
                self._save()
            except OSError:
                pass   # a persistence failure must not discard a good lookup result

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh)
            os.replace(tmp, self.path)
        except OSError:
            try:
                os.unlink(tmp)   # never leak the temp file
            except OSError:
                pass
            raise
