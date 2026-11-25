"""Bundled and downloadable datasets.

* ``bundled_*``: files shipped in ``v3lum/data`` (TLDs, PSL, site lists, warning lists...).
* ``fetch*``: public datasets downloaded on demand into ``~/.v3lum/datasets`` and refreshed
  after a TTL (CISA KEV, Tor exit list, MITRE ATT&CK, blocklists...). If a refresh fails
  the stale copy is used, so offline work keeps functioning.
"""

from __future__ import annotations

import functools
import json
import os
import threading
import time
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING, Any

from v3lum import paths

if TYPE_CHECKING:  # pragma: no cover
    from v3lum.core.context import Runtime


class DatasetError(Exception):
    pass


# Registry of downloadable datasets (modules register theirs at import time) so that
# ``v3lum data update`` can refresh everything ahead of an offline engagement.
DATASETS: dict[str, dict[str, Any]] = {}


def register_dataset(name: str, url: str, *, ttl: float = 86400, description: str = "", max_bytes: int = 200 * 1024 * 1024) -> str:
    DATASETS[name] = {"url": url, "ttl": ttl, "description": description, "max_bytes": max_bytes}
    return name


class DataStore:
    def __init__(self, runtime: Runtime | None = None) -> None:
        self.runtime = runtime
        self._lock = threading.Lock()
        self._locks: dict[str, threading.Lock] = {}
        self._memo: dict[str, tuple[float, Any]] = {}

    # ------------------------------------------------------------------ bundled
    @staticmethod
    def bundled_path(name: str) -> Path:
        return Path(str(resources.files("v3lum.data").joinpath(name)))

    @staticmethod
    def bundled_exists(name: str) -> bool:
        try:
            return resources.files("v3lum.data").joinpath(name).is_file()
        except (FileNotFoundError, OSError):
            return False

    @staticmethod
    @functools.lru_cache(maxsize=64)
    def bundled_text(name: str) -> str:
        return resources.files("v3lum.data").joinpath(name).read_text(encoding="utf-8")

    @staticmethod
    @functools.lru_cache(maxsize=64)
    def bundled_json(name: str) -> Any:
        return json.loads(DataStore.bundled_text(name))

    @staticmethod
    @functools.lru_cache(maxsize=64)
    def bundled_lines(name: str) -> frozenset[str]:
        lines = DataStore.bundled_text(name).splitlines()
        return frozenset(ln.strip().lower() for ln in lines if ln.strip() and not ln.lstrip().startswith(("#", "//")))

    # ------------------------------------------------------------------ downloadable
    def _lock_for(self, name: str) -> threading.Lock:
        with self._lock:
            if name not in self._locks:
                self._locks[name] = threading.Lock()
            return self._locks[name]

    def fetch(self, name: str, url: str, *, ttl: float = 86400, headers: dict[str, str] | None = None, max_bytes: int = 200 * 1024 * 1024) -> Path:
        """Return a local path for the dataset, downloading/refreshing it if older than ``ttl``."""
        target = paths.datasets_dir() / name
        with self._lock_for(name):
            fresh = target.exists() and (time.time() - target.stat().st_mtime) < ttl
            if fresh:
                return target
            if self.runtime is None:
                if target.exists():
                    return target
                raise DatasetError(f"dataset {name} not available offline")
            try:
                resp = self.runtime.http.request("GET", url, headers=headers or {}, ttl=0, max_bytes=max_bytes, timeout=120)
                if resp.status != 200 or resp.truncated:
                    raise DatasetError(f"download of {name} failed: HTTP {resp.status}{' (truncated)' if resp.truncated else ''}")
                tmp = target.with_suffix(target.suffix + ".part")
                tmp.write_bytes(resp.content)
                os.replace(tmp, target)
            except Exception as exc:
                if target.exists():  # stale copy beats nothing
                    return target
                raise DatasetError(str(exc)) from exc
            return target

    def fetch_text(self, name: str, url: str, *, ttl: float = 86400, **kw: Any) -> str:
        path = self.fetch(name, url, ttl=ttl, **kw)
        return self._memoized(path, lambda p: p.read_text(encoding="utf-8", errors="replace"))

    def fetch_json(self, name: str, url: str, *, ttl: float = 86400, **kw: Any) -> Any:
        path = self.fetch(name, url, ttl=ttl, **kw)
        return self._memoized(path, lambda p: json.loads(p.read_text(encoding="utf-8", errors="replace")))

    def fetch_lines(self, name: str, url: str, *, ttl: float = 86400, **kw: Any) -> frozenset[str]:
        path = self.fetch(name, url, ttl=ttl, **kw)

        def parse(p: Path) -> frozenset[str]:
            out = set()
            for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
                ln = ln.strip()
                if ln and not ln.startswith(("#", ";", "//")):
                    out.add(ln.split()[0].lower())
            return frozenset(out)

        return self._memoized(path, parse)

    def _memoized(self, path: Path, loader: Any) -> Any:
        key = str(path)
        mtime = path.stat().st_mtime
        with self._lock:
            hit = self._memo.get(key)
            if hit and hit[0] == mtime:
                return hit[1]
        value = loader(path)
        with self._lock:
            self._memo[key] = (mtime, value)
        return value

    def cached_info(self) -> list[dict[str, Any]]:
        out = []
        for p in sorted(paths.datasets_dir().glob("*")):
            if p.is_file() and not p.name.endswith(".part"):
                st = p.stat()
                out.append({"name": p.name, "bytes": st.st_size, "age_hours": round((time.time() - st.st_mtime) / 3600, 1)})
        return out
