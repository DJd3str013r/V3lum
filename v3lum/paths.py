"""Where V3LUM keeps its data (config, cache, cases, feeds, plugins).

Default: ``~/.v3lum``. Override with the ``V3LUM_HOME`` environment variable
(tests always point it to a temporary directory).
"""

from __future__ import annotations

import os
from pathlib import Path


def home() -> Path:
    base = os.environ.get("V3LUM_HOME") or os.path.join(os.path.expanduser("~"), ".v3lum")
    path = Path(base)
    path.mkdir(parents=True, exist_ok=True)
    return path


def sub(name: str) -> Path:
    path = home() / name
    path.mkdir(parents=True, exist_ok=True)
    return path


def config_file() -> Path:
    return home() / "config.json"


def db_file() -> Path:
    return home() / "v3lum.db"


def cache_file() -> Path:
    return sub("cache") / "http_cache.db"


def cases_dir() -> Path:
    return sub("cases")


def feeds_dir() -> Path:
    return sub("feeds")


def datasets_dir() -> Path:
    return sub("datasets")


def plugins_dir() -> Path:
    return sub("plugins")
