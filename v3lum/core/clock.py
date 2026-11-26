"""Time source shared by the HTTP client, the socket connector, deadlines and the engine.

Everything that waits, measures a deadline or stamps a record asks a :class:`Clock` instead of
calling ``time``/``datetime`` directly, so tests can freeze time with a fake clock
(``tests.fakes.FakeClock``) and never sleep for real.

* ``now()``       - timezone-aware UTC ``datetime`` (record timestamps, cache ages);
* ``monotonic()`` - seconds on a monotonic scale (deadlines, politeness intervals, elapsed time);
* ``sleep(s)``    - wait ``s`` seconds (fake clocks just advance).

Deadlines (``RunInfo.deadline``, ``ScopedHttp(deadline=...)``, ``Connector(deadline=...)``) are
absolute values on the ``monotonic()`` scale of the clock in use.
"""

from __future__ import annotations

import datetime as _dt
import time
from typing import Protocol, runtime_checkable

__all__ = ["Clock", "SystemClock", "SYSTEM_CLOCK"]


@runtime_checkable
class Clock(Protocol):
    """Protocol of a time source (see the module docstring)."""

    def now(self) -> _dt.datetime:
        """Timezone-aware UTC now."""
        ...

    def monotonic(self) -> float:
        """Seconds on a monotonic scale (only differences are meaningful)."""
        ...

    def sleep(self, seconds: float) -> None:
        """Wait ``seconds`` (non-positive values return at once)."""
        ...


class SystemClock:
    """The real clock: ``datetime.now(UTC)``, ``time.monotonic()`` and ``time.sleep()``."""

    def now(self) -> _dt.datetime:
        return _dt.datetime.now(_dt.timezone.utc)

    def monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        if seconds and seconds > 0:
            time.sleep(seconds)

    def __repr__(self) -> str:
        return "SystemClock()"


#: Process-wide default clock.
SYSTEM_CLOCK = SystemClock()
