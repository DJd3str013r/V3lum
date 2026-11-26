"""Per-destination-host politeness shared by every module: interval slots and connection caps.

* ``reserve(host, interval)`` always reserves the next slot for ``host`` and returns how long the
  caller must wait before sending. The effective interval is the largest interval ever declared for
  that host (modules and provider profiles, P334 cond 4), so a module declaring 0 s still respects
  another module's 2 s for the same host. Waiting is left to the caller, which bounds it by its run
  deadline.
* ``acquire(host, max_concurrent)`` is a context manager holding one of the host's connection slots.
* ``wait_turn(host, min_interval)`` and ``slot(host)`` are the v1 entry points (kept).

``HostLimiter`` moved here from ``v3lum.core.http`` (which still re-exports it).
"""

from __future__ import annotations

import contextlib
import threading
from collections.abc import Iterator

from v3lum.core.clock import SYSTEM_CLOCK, Clock

__all__ = ["HostLimiter"]


class HostLimiter:
    """Minimum interval between requests + maximum concurrent connections, per host."""

    def __init__(self, max_per_host: int = 4, *, clock: Clock | None = None) -> None:
        self.max_per_host = max(1, int(max_per_host or 1))
        self.clock: Clock = clock or SYSTEM_CLOCK
        self._lock = threading.Lock()
        self._next: dict[str, float] = {}
        self._declared: dict[str, float] = {}
        self._sems: dict[str, threading.BoundedSemaphore] = {}

    @staticmethod
    def _key(host: str) -> str:
        return (host or "").strip().lower().rstrip(".")

    # ------------------------------------------------------------------ intervals
    def interval_for(self, host: str) -> float:
        """The effective interval of ``host`` (largest declared so far; 0.0 when none)."""
        with self._lock:
            return self._declared.get(self._key(host), 0.0)

    def reserve(self, host: str, interval: float = 0.0) -> float:
        """Reserve the next request slot of ``host``; returns the seconds to wait before sending."""
        key = self._key(host)
        with self._lock:
            declared = max(float(interval or 0.0), self._declared.get(key, 0.0))
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
        key = self._key(host)
        with self._lock:
            sem = self._sems.get(key)
            if sem is None:
                size = max(1, int(max_concurrent or self.max_per_host))
                sem = self._sems[key] = threading.BoundedSemaphore(size)
            return sem

    @contextlib.contextmanager
    def acquire(self, host: str, max_concurrent: int | None = None, *, timeout: float | None = None) -> Iterator[None]:
        """Hold one connection slot of ``host``; raises TimeoutError when none frees up in ``timeout``."""
        sem = self.slot(host, max_concurrent)
        if timeout is None:
            sem.acquire()
        elif not sem.acquire(timeout=max(0.0, float(timeout))):
            raise TimeoutError(f"no free connection slot for {self._key(host)}")
        try:
            yield
        finally:
            sem.release()
