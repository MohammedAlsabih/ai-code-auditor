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
        if self.path.is_file():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                now = time.time()
                self._data = {k: v for k, v in raw.items() if v.get("expires", 0) > now}
            except (OSError, json.JSONDecodeError):
                self._data = {}

    def get(self, key: str) -> dict | None:
        with self._lock:
            entry = self._data.get(key)
            if entry is None or entry["expires"] <= time.time():
                self._data.pop(key, None)
                return None
            return entry["value"]

    def set(self, key: str, value: dict, ttl_seconds: int) -> None:
        with self._lock:
            self._data[key] = {"expires": time.time() + ttl_seconds, "value": value}
            self._save()

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(self._data, fh)
        os.replace(tmp, self.path)
