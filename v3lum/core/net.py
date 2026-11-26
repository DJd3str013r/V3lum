"""Core socket connector (``ctx.net``): the only sanctioned source of raw sockets for modules.

LIGHT/ACTIVE modules (disclosure 'target') that need raw sockets - TLS handshakes, banners, AXFR,
websockets - get them here, never from ``socket``/``ssl`` directly (the P327 lint enforces it from
wave 2). Wave 1 is thin: it refuses non-target modules, honours the run's cancel flag and deadline
and verifies TLS. WP11 completes it in wave 2 with the same signatures (egress profiles, scope and
SSRF checks after resolution, ACTIVE ceilings, ledger records).

    sock = ctx.net.connect("example.com", 443, timeout=5)
    tls = ctx.net.wrap_tls(sock, "example.com")
"""

from __future__ import annotations

import socket
import ssl
import threading
from typing import Any

from v3lum.core.clock import SYSTEM_CLOCK, Clock
from v3lum.core.http import Cancelled, DeadlineExceeded, PolicyError, _opsec_label
from v3lum.core.models import Opsec

__all__ = ["Connector", "DEFAULT_CONNECT_TIMEOUT"]

#: connect/handshake timeout when the caller gives none (capped by the run deadline).
DEFAULT_CONNECT_TIMEOUT = 10.0


class Connector:
    """Raw TCP/TLS sockets for one module run.

    ``Connector(*, module='', disclosure='target', opsec=Opsec.LIGHT, deadline=None, cancel_event=None,
    clock=None)``. ``deadline`` is absolute on ``clock.monotonic()``'s scale. Modules whose disclosure
    is not 'target' (or whose opsec is PASSIVE) get :class:`PolicyError`; a set cancel flag gives
    :class:`Cancelled` and a passed deadline :class:`DeadlineExceeded`. Socket errors (refused,
    timeout, unreachable) propagate as ``OSError`` so probes can tell them apart.
    """

    def __init__(
        self,
        *,
        module: str = "",
        disclosure: str = "target",
        opsec: Any = Opsec.LIGHT,
        deadline: float | None = None,
        cancel_event: Any = None,
        clock: Clock | None = None,
    ) -> None:
        self.module = module or ""
        self.disclosure = str(disclosure or "")
        self.opsec = _opsec_label(opsec)
        self.deadline = deadline
        self.cancel_event = cancel_event
        self.clock: Clock = clock or SYSTEM_CLOCK
        self.connections = 0
        self._lock = threading.Lock()

    def _label(self) -> str:
        return self.module or "module"

    def _check(self) -> None:
        if self.disclosure != "target":
            raise PolicyError("policy", f"{self._label()}: raw sockets are only for target-contact (LIGHT/ACTIVE) modules (disclosure {self.disclosure!r})")
        if self.opsec == "passive":
            raise PolicyError("policy", f"{self._label()}: a PASSIVE module may not open sockets to a target")
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise Cancelled()
        if self.deadline is not None and self.clock.monotonic() >= self.deadline:
            raise DeadlineExceeded(f"{self._label()}: run deadline reached: connection not opened")

    def _timeout(self, timeout: float | None) -> float:
        value = DEFAULT_CONNECT_TIMEOUT if timeout is None else max(0.001, float(timeout))
        if self.deadline is not None:
            remaining = self.deadline - self.clock.monotonic()
            if remaining <= 0:
                raise DeadlineExceeded(f"{self._label()}: run deadline reached: connection not opened")
            value = min(value, remaining)
        return value

    def connect(self, host: str, port: int, *, timeout: float | None = None) -> socket.socket:
        """Open a TCP connection (``socket.create_connection``) with the timeout capped by the deadline."""
        self._check()
        if not host or not isinstance(host, str):
            raise ValueError("connect() needs a host name or IP address")
        port = int(port)
        if not 0 < port < 65536:
            raise ValueError(f"invalid port {port}")
        sock = socket.create_connection((host, port), timeout=self._timeout(timeout))
        with self._lock:
            self.connections += 1
        return sock

    def wrap_tls(self, sock: socket.socket, server_hostname: str, *, timeout: float | None = None) -> ssl.SSLSocket:
        """TLS handshake over ``sock`` with the default verifying context (verification is never
        disabled; certificate problems raise ``ssl.SSLCertVerificationError``)."""
        try:
            self._check()
            sock.settimeout(self._timeout(timeout))
        except BaseException:
            sock.close()
            raise
        context = ssl.create_default_context()
        return context.wrap_socket(sock, server_hostname=server_hostname)
