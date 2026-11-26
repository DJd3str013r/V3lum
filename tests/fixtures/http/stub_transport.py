"""Test doubles for the WP03 HTTP tests (no network, no real sleeping).

* :class:`StubClock` - ``now``/``monotonic``/``sleep``/``advance``; sleeping only advances time.
* :class:`StubTransport` - the core ``Transport`` protocol (one hop): routes by method + exact URL,
  ``prefix*`` or compiled regex; ``times`` gives response sequences; ``latency`` advances the clock
  (and raises DeadlineExceeded past the deadline, like a slow-drip server); every call is recorded.
* :func:`registry` / :func:`provider` - an injectable provider registry built from real
  ``v3lum.core.providers`` dataclasses, so tests never touch the process-wide registry.
"""

from __future__ import annotations

import json as _json
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from v3lum.core import providers as providers_mod
from v3lum.core.http import DeadlineExceeded, Response

HERE = Path(__file__).parent


def load(name: str) -> bytes:
    """Raw bytes of tests/fixtures/http/<name>."""
    return (HERE / name).read_bytes()


class StubClock:
    """Deterministic clock; ``sleep`` advances time without blocking."""

    def __init__(self, start: datetime | None = None, mono: float = 1000.0) -> None:
        self._start = start or datetime(2026, 11, 26, 12, 0, 0, tzinfo=timezone.utc)
        self._mono = float(mono)
        self._offset = 0.0
        self._lock = threading.Lock()
        self.sleeps: list[float] = []

    def now(self) -> datetime:
        with self._lock:
            return self._start + timedelta(seconds=self._offset)

    def monotonic(self) -> float:
        with self._lock:
            return self._mono + self._offset

    def sleep(self, seconds: float) -> None:
        with self._lock:
            self.sleeps.append(float(seconds))
            self._offset += max(0.0, float(seconds))

    def advance(self, seconds: float) -> None:
        with self._lock:
            self._offset += max(0.0, float(seconds))


@dataclass
class Route:
    method: str
    pattern: Any
    status: int = 200
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    error: Exception | None = None
    final_url: str | None = None
    times: int | None = None
    latency: float = 0.0


class StubTransport:
    """Scripted one-hop transport (see the module docstring)."""

    def __init__(self, clock: StubClock | None = None) -> None:
        self.clock = clock
        self.routes: list[Route] = []
        self.calls: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def add(
        self,
        method: str,
        url: Any,
        *,
        status: int = 200,
        body: bytes | None = None,
        text: str | None = None,
        json: Any = None,
        headers: dict[str, str] | None = None,
        error: Exception | None = None,
        final_url: str | None = None,
        times: int | None = None,
        latency: float = 0.0,
        location: str | None = None,
        content_type: str | None = None,
    ) -> StubTransport:
        hdrs: dict[str, str] = {}
        if json is not None:
            content = _json.dumps(json).encode()
            hdrs["content-type"] = "application/json"
        elif text is not None:
            content = text.encode()
            hdrs["content-type"] = "text/html; charset=utf-8"
        else:
            content = body or b""
        if content_type:
            hdrs["content-type"] = content_type
        if location is not None:
            hdrs["location"] = location
        hdrs.update({k.lower(): v for k, v in (headers or {}).items()})
        self.routes.append(Route(method.upper(), url, status, content, hdrs, error, final_url, times, latency))
        return self

    def _match(self, method: str, url: str) -> Route:
        with self._lock:
            for route in self.routes:
                if route.method != method:
                    continue
                if route.times is not None and route.times <= 0:
                    continue
                pattern = route.pattern
                if isinstance(pattern, re.Pattern):
                    ok = bool(pattern.search(url))
                elif pattern.endswith("*"):
                    ok = url.startswith(pattern[:-1])
                else:
                    ok = pattern == url
                if ok:
                    if route.times is not None:
                        route.times -= 1
                    return route
        known = "\n  ".join(f"{r.method} {r.pattern}" for r in self.routes)
        raise AssertionError(f"unexpected HTTP request: {method} {url}\nknown routes:\n  {known}")

    def send(self, method: str, url: str, *, headers: dict[str, str], body: bytes | None, timeout: float, max_bytes: int, deadline: float | None) -> Response:
        method = method.upper()
        with self._lock:
            self.calls.append({"method": method, "url": url, "headers": dict(headers), "body": body, "timeout": timeout, "max_bytes": max_bytes, "deadline": deadline})
        route = self._match(method, url)
        if route.latency and self.clock is not None:
            self.clock.advance(route.latency)
            if deadline is not None and self.clock.monotonic() > deadline:
                raise DeadlineExceeded(f"deadline exceeded while reading from {url}")
        if route.error is not None:
            raise route.error
        content, truncated = route.body, False
        if len(content) > max_bytes:
            content, truncated = content[:max_bytes], True
        return Response(route.status, route.final_url or url, dict(route.headers), content, route.latency, False, truncated, [])

    # ---- inspection -------------------------------------------------------------------------
    def urls(self) -> list[str]:
        return [c["url"] for c in self.calls]

    def header(self, index: int, name: str) -> str | None:
        """Request header ``name`` (case-insensitive) of call ``index``."""
        for key, value in self.calls[index]["headers"].items():
            if key.lower() == name.lower():
                return value
        return None


def provider(
    pid: str,
    hosts: tuple[str, ...],
    *,
    name: str | None = None,
    tier: str = "trusted",
    sensitive: bool = False,
    profile: dict[str, Any] | None = None,
    markers: tuple[dict[str, Any], ...] = (),
    sources: tuple[str, ...] = ("default",),
) -> providers_mod.Provider:
    """A synthetic Provider (real dataclasses; markers validated with providers.parse_marker)."""
    terms = providers_mod.Terms(class_="open")
    srcs = {sid: providers_mod.Source(id=f"{pid}.{sid}", provider=pid, title=sid, terms=terms, upstream_family=pid) for sid in sources}
    return providers_mod.Provider(
        id=pid,
        name=name or pid,
        operator=name or pid,
        hosts=tuple(hosts),
        tier=tier,
        flags=providers_mod.ProviderFlags(sensitive=sensitive),
        http_profile=providers_mod.HttpProfile(**(profile or {})),
        error_markers=tuple(providers_mod.parse_marker(m) for m in markers),
        sources=srcs,
    )


def registry(*items: providers_mod.Provider) -> providers_mod.ProviderRegistry:
    """An isolated registry holding only ``items``."""
    return providers_mod.ProviderRegistry(list(items))
