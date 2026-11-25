"""Runtime (shared plumbing for a session) and Context (what a module run receives)."""

from __future__ import annotations

import datetime as _dt
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from v3lum import paths
from v3lum.config import Config
from v3lum.core.dns import Resolver
from v3lum.core.http import HttpCache, HttpClient, ScopedHttp
from v3lum.core.models import Opsec

EventListener = Callable[[str, dict[str, Any]], None]


@dataclass
class ScanOptions:
    mode: Opsec = Opsec.PASSIVE
    authorized: bool = False
    depth: int = 1
    max_entities: int = 150
    threads: int = 12
    include: set[str] = field(default_factory=set)  # only these modules (by name)
    exclude: set[str] = field(default_factory=set)
    categories: set[str] = field(default_factory=set)  # only modules in these categories
    include_disabled: bool = False  # also run modules with default_enabled=False
    offline: bool = False
    no_cache: bool = False
    timeout_total: float = 0.0  # 0 = no global timeout
    save_evidence: bool = True
    authorization_note: str = ""  # who authorized active testing / scope reference
    tlp: str = "clear"  # clear | green | amber | red  (red = never send inputs to third parties)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tlp": self.tlp,
            "mode": self.mode.label,
            "authorized": self.authorized,
            "depth": self.depth,
            "max_entities": self.max_entities,
            "threads": self.threads,
            "include": sorted(self.include),
            "exclude": sorted(self.exclude),
            "categories": sorted(self.categories),
            "include_disabled": self.include_disabled,
            "offline": self.offline,
            "no_cache": self.no_cache,
            "authorization_note": self.authorization_note,
        }


class EventBus:
    """Synchronous fan-out of engine/HTTP events to UI listeners (must be thread-safe)."""

    def __init__(self, listener: EventListener | None = None) -> None:
        self._listeners: list[EventListener] = [listener] if listener else []
        self._lock = threading.Lock()

    def subscribe(self, listener: EventListener) -> None:
        with self._lock:
            self._listeners.append(listener)

    def unsubscribe(self, listener: EventListener) -> None:
        with self._lock:
            if listener in self._listeners:
                self._listeners.remove(listener)

    def emit(self, kind: str, **payload: Any) -> None:
        for listener in list(self._listeners):
            try:
                listener(kind, payload)
            except Exception:  # pragma: no cover - UI must never break the engine
                pass

    def http(self, method: str, url: str, status: int, elapsed: float, cached: bool, error: str) -> None:
        self.emit("http", method=method, url=url, status=status, elapsed=elapsed, cached=cached, error=error)


class Runtime:
    """Shared, long-lived plumbing: config, HTTP client + cache, datasets, events."""

    def __init__(
        self,
        config: Config | None = None,
        *,
        http_client: Any = None,
        offline: bool = False,
        no_cache: bool = False,
        listener: EventListener | None = None,
        now: Callable[[], _dt.datetime] | None = None,
        proxy: str | None = None,
    ) -> None:
        from v3lum.core.datasets import DataStore

        self.config = config or Config.load()
        self.events = EventBus(listener)
        self.cancel_event = threading.Event()
        self._now = now
        if http_client is None:
            cache = None if no_cache else HttpCache(str(paths.cache_file()))
            http_client = HttpClient(
                user_agent=str(self.config.get("user_agent")),
                timeout=float(self.config.get("timeout")),
                proxy=proxy if proxy is not None else str(self.config.get("proxy") or ""),
                cache=cache,
                default_ttl=float(self.config.get("cache_ttl")),
                offline=offline,
                on_request=self.events.http,
            )
        self.http = http_client
        self.data = DataStore(self)
        self._quota: Any = None

    @property
    def quota(self) -> Any:
        """Daily quota book (created lazily in the V3LUM home)."""
        if self._quota is None:
            from v3lum.core.quota import QuotaBook

            self._quota = QuotaBook(paths.home() / "quota.db")
        return self._quota

    def now(self) -> _dt.datetime:
        return self._now() if self._now else _dt.datetime.now(_dt.timezone.utc)

    def context(self, module_cls: Any, options: ScanOptions | None = None, case_dir: Path | None = None) -> Context:
        return Context(self, module_cls, options or ScanOptions(), case_dir)

    def cancel(self) -> None:
        self.cancel_event.set()


class Context:
    """What ``Module.run(entity, ctx)`` receives."""

    def __init__(self, runtime: Runtime, module_cls: Any, options: ScanOptions, case_dir: Path | None) -> None:
        self.runtime = runtime
        self.module = module_cls
        self.options = options
        self.case_dir = case_dir
        self.config = runtime.config
        self.data = runtime.data
        self.http = ScopedHttp(
            runtime.http,
            ttl=getattr(module_cls, "cache_ttl", None),
            min_interval=float(getattr(module_cls, "min_interval", 0.0) or 0.0),
            user_agent=getattr(module_cls, "user_agent", None),
        )
        self.dns = Resolver(
            self.http,
            mode=str(self.config.get("dns_mode") or "doh"),
            provider=str(self.config.get("doh_provider") or "google"),
        )

    # ---- convenience ---------------------------------------------------------------
    @property
    def mode(self) -> Opsec:
        return self.options.mode

    @property
    def authorized(self) -> bool:
        return self.options.authorized

    def key(self, name: str) -> str:
        return self.config.key(name)

    def has_key(self, name: str) -> bool:
        return bool(self.config.key(name))

    def setting(self, name: str, default: Any = None) -> Any:
        return self.config.get(name, default)

    def log(self, message: str, level: str = "info") -> None:
        self.runtime.events.emit("log", module=getattr(self.module, "name", "?"), message=message, level=level)

    def cancelled(self) -> bool:
        return self.runtime.cancel_event.is_set()

    def now(self) -> _dt.datetime:
        return self.runtime.now()
