"""Per-destination-host politeness shared by every module: interval slots, connection caps and the
LIGHT/ACTIVE hard ceilings (P334 cond 4-5, A7).

* ``reserve(host, interval, *, opsec=None)`` always reserves the next slot for ``host`` (also for an
  interval of 0) and returns how long the caller must wait before sending. The effective interval is
  the largest interval ever declared for that host - by modules, provider profiles and the opsec
  floor (LIGHT 1.0 s = :data:`LIGHT_MAX_RPS`, ACTIVE 0.1 s = :data:`ACTIVE_MAX_RPS`) - so a module
  declaring 0 s still respects another module's 2 s for the same host. Waiting is left to the
  caller, which bounds it by its run deadline.
* ``acquire(host, max_concurrent, *, opsec=None)`` is a context manager holding one of the host's
  connection slots; ACTIVE contact has its own per-host pool capped at
  :data:`ACTIVE_MAX_CONCURRENT` whatever the caller asks.
* ``charge_scan(host, opsec=...)`` counts target requests per host for the current scan and refuses
  the request beyond :data:`LIGHT_MAX_PER_HOST_PER_SCAN` LIGHT requests; ``reset_scan()`` starts a
  new scan.
* ``wait_turn(host, min_interval)`` and ``slot(host)`` are the v1 entry points (kept).

Modules, provider profiles and scope files can only *lower* these ceilings (A7); the HTTP client and
the socket connector enforce them (WP11). ``HostLimiter`` moved here from ``v3lum.core.http`` (which
still re-exports it).
"""

from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Iterator
from typing import Any

from v3lum.core.clock import SYSTEM_CLOCK, Clock

__all__ = [
    "ACTIVE_MAX_CONCURRENT",
    "ACTIVE_MAX_RPS",
    "LIGHT_MAX_PER_HOST_PER_SCAN",
    "LIGHT_MAX_RPS",
    "HostLimiter",
    "opsec_floor",
]

#: LIGHT target contact: at most 1 request per second per target host (A7).
LIGHT_MAX_RPS = 1.0
#: LIGHT target contact: at most 25 requests per target host per scan (A7).
LIGHT_MAX_PER_HOST_PER_SCAN = 25
#: ACTIVE probes: at most 10 requests/probes per second per target host (A7).
ACTIVE_MAX_RPS = 10.0
#: ACTIVE probes: at most 2 concurrent connections per target host (A7).
ACTIVE_MAX_CONCURRENT = 2


def _opsec_label(opsec: Any) -> str:
    """'passive' | 'light' | 'active' for an Opsec member, its value, name or label ('' if unknown)."""
    if opsec is None:
        return ""
    label = getattr(opsec, "label", None)
    if isinstance(label, str):
        return label
    if isinstance(opsec, int) and not isinstance(opsec, bool):
        return {0: "passive", 1: "light", 2: "active"}.get(int(opsec), "")
    return str(opsec).strip().lower()


def opsec_floor(opsec: Any) -> float:
    """Minimum interval (seconds) between requests to one host at ``opsec``: 1.0 for LIGHT, 0.1 for
    ACTIVE, 0.0 for passive or unknown."""
    label = _opsec_label(opsec)
    if label == "light":
        return 1.0 / LIGHT_MAX_RPS
    if label == "active":
        return 1.0 / ACTIVE_MAX_RPS
    return 0.0


class HostLimiter:
    """Minimum interval between requests + maximum concurrent connections, per host."""

    def __init__(self, max_per_host: int = 4, *, clock: Clock | None = None) -> None:
        self.max_per_host = max(1, int(max_per_host or 1))
        self.clock: Clock = clock or SYSTEM_CLOCK
        self._lock = threading.Lock()
        self._next: dict[str, float] = {}
        self._declared: dict[str, float] = {}
        self._sems: dict[str, threading.BoundedSemaphore] = {}
        self._scan: dict[tuple[str, str], int] = {}

    @staticmethod
    def _key(host: str) -> str:
        return (host or "").strip().lower().rstrip(".")

    # ------------------------------------------------------------------ intervals
    def interval_for(self, host: str) -> float:
        """The effective interval of ``host`` (largest declared so far; 0.0 when none)."""
        with self._lock:
            return self._declared.get(self._key(host), 0.0)

    def reserve(self, host: str, interval: float = 0.0, *, opsec: Any = None) -> float:
        """Reserve the next request slot of ``host``; returns the seconds to wait before sending.

        The slot is always reserved (interval 0 included). The interval used is the largest of
        ``interval``, every interval declared earlier for ``host`` and the opsec floor
        (:func:`opsec_floor`); it is remembered for the host.
        """
        key = self._key(host)
        try:
            requested = max(0.0, float(interval or 0.0))
        except (TypeError, ValueError):
            requested = 0.0
        with self._lock:
            declared = max(requested, opsec_floor(opsec), self._declared.get(key, 0.0))
            self._declared[key] = declared
            now = self.clock.monotonic()
            slot = max(now, self._next.get(key, 0.0))
            self._next[key] = slot + declared
        return max(0.0, slot - now)

    def wait_turn(self, host: str, min_interval: float = 0.0) -> None:
        """v1 API: reserve a slot and sleep (on the limiter clock) until it comes."""
        delay = self.reserve(host, min_interval)
        if delay > 0:
            self.clock.sleep(delay)

    # ------------------------------------------------------------------ concurrency
    def slot(self, host: str, max_concurrent: int | None = None) -> threading.BoundedSemaphore:
        """The connection semaphore of ``host`` (created with ``max_concurrent`` or ``max_per_host``)."""
        return self._semaphore(self._key(host), max_concurrent or self.max_per_host)

    def _semaphore(self, key: str, size: int) -> threading.BoundedSemaphore:
        with self._lock:
            sem = self._sems.get(key)
            if sem is None:
                sem = self._sems[key] = threading.BoundedSemaphore(max(1, int(size or 1)))
            return sem

    @contextlib.contextmanager
    def acquire(self, host: str, max_concurrent: int | None = None, *, timeout: float | None = None, opsec: Any = None) -> Iterator[None]:
        """Hold one connection slot of ``host``; raises TimeoutError when none frees up in ``timeout``.

        ACTIVE contact (``opsec``) uses a separate per-host pool of at most
        :data:`ACTIVE_MAX_CONCURRENT` connections; a lower ``max_concurrent`` (a scope file's limit)
        lowers it further for its callers - also when another caller created the host's pool first
        (they then hold a slot of both pools, so the host never sees more than the ceiling).
        """
        key = self._key(host)
        if _opsec_label(opsec) == "active":
            size = max(1, min(ACTIVE_MAX_CONCURRENT, int(max_concurrent or ACTIVE_MAX_CONCURRENT)))
            sems = [self._semaphore(f"{key}#active", ACTIVE_MAX_CONCURRENT)]
            if size < ACTIVE_MAX_CONCURRENT:
                sems.append(self._semaphore(f"{key}#active#{size}", size))
        else:
            sems = [self.slot(host, max_concurrent)]
        end = None if timeout is None else time.monotonic() + max(0.0, float(timeout))
        held: list[threading.BoundedSemaphore] = []
        try:
            for sem in sems:
                if end is None:
                    sem.acquire()
                elif not sem.acquire(timeout=max(0.0, end - time.monotonic())):
                    raise TimeoutError(f"no free connection slot for {key}")
                held.append(sem)
            yield
        finally:
            for sem in reversed(held):
                sem.release()

    # ------------------------------------------------------------------ per-scan ceilings
    def charge_scan(self, host: str, *, opsec: Any, limit: int | None = None) -> bool:
        """Count one target request to ``host`` at ``opsec`` for the current scan. Returns False -
        counting nothing - when the host already received ``limit`` requests at that opsec in this
        scan (default: :data:`LIGHT_MAX_PER_HOST_PER_SCAN` for LIGHT, no per-host limit otherwise;
        a ``limit`` above the LIGHT ceiling is lowered to it)."""
        label = _opsec_label(opsec)
        cap = limit
        if label == "light":
            cap = LIGHT_MAX_PER_HOST_PER_SCAN if limit is None else min(int(limit), LIGHT_MAX_PER_HOST_PER_SCAN)
        key = (label, self._key(host))
        with self._lock:
            used = self._scan.get(key, 0)
            if cap is not None and used >= int(cap):
                return False
            self._scan[key] = used + 1
        return True

    def scan_count(self, host: str, *, opsec: Any) -> int:
        """Target requests counted for ``host`` at ``opsec`` in the current scan."""
        with self._lock:
            return self._scan.get((_opsec_label(opsec), self._key(host)), 0)

    def reset_scan(self) -> None:
        """Start a new scan: forget the per-scan request counts (intervals and slots stay)."""
        with self._lock:
            self._scan.clear()
