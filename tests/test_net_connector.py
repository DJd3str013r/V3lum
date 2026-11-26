"""Core socket connector (ctx.net, wave-1 thin version): target modules only, cancel/deadline,
verifying TLS. Loopback only (the conftest network guard refuses anything else)."""

from __future__ import annotations

import socket
import ssl
import threading

import pytest

from tests.fixtures.http.stub_transport import StubClock
from v3lum.core.http import Cancelled, DeadlineExceeded, PolicyError
from v3lum.core.models import Opsec
from v3lum.core.net import DEFAULT_CONNECT_TIMEOUT, Connector


@pytest.fixture()
def listener():
    """A loopback TCP server answering one line per connection."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    srv.settimeout(0.05)  # short accept poll: teardown never waits
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except (TimeoutError, OSError):
                continue
            with conn:
                conn.sendall(b"220 hello\r\n")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield srv.getsockname()[1]
    stop.set()
    srv.close()
    thread.join(timeout=2)


@pytest.mark.parametrize(
    ("disclosure", "opsec"),
    [("third_party", Opsec.PASSIVE), ("none", Opsec.PASSIVE), ("internal", Opsec.PASSIVE), ("target", Opsec.PASSIVE)],
)
def test_refuses_modules_that_are_not_target_contact(disclosure, opsec, listener):
    conn = Connector(module="t_net", disclosure=disclosure, opsec=opsec)
    with pytest.raises(PolicyError) as err:
        conn.connect("127.0.0.1", listener)
    assert err.value.reason_code == "policy" and "t_net" in str(err.value)
    assert conn.connections == 0


@pytest.mark.parametrize("opsec", [Opsec.LIGHT, Opsec.ACTIVE, "light"])
def test_connects_to_a_loopback_listener(opsec, listener):
    conn = Connector(module="t_net", disclosure="target", opsec=opsec)
    with conn.connect("127.0.0.1", listener, timeout=2) as sock:
        assert sock.recv(64).startswith(b"220")
        assert 0 < sock.gettimeout() <= 2
    assert conn.connections == 1


def test_default_timeout_is_capped_by_the_deadline(listener):
    clock = StubClock()
    conn = Connector(module="t_net", disclosure="target", deadline=clock.monotonic() + 3.0, clock=clock)
    with conn.connect("127.0.0.1", listener) as sock:
        assert sock.gettimeout() == pytest.approx(3.0)
    assert DEFAULT_CONNECT_TIMEOUT > 3.0


def test_cancel_is_honoured(listener):
    cancel = threading.Event()
    conn = Connector(module="t_net", disclosure="target", cancel_event=cancel)
    conn.connect("127.0.0.1", listener, timeout=2).close()
    cancel.set()
    with pytest.raises(Cancelled):
        conn.connect("127.0.0.1", listener, timeout=2)
    assert conn.connections == 1


def test_deadline_passed_refuses_new_connections(listener):
    clock = StubClock()
    conn = Connector(module="t_net", disclosure="target", deadline=clock.monotonic() + 1.0, clock=clock)
    clock.advance(2.0)
    with pytest.raises(DeadlineExceeded) as err:
        conn.connect("127.0.0.1", listener)
    assert err.value.reason_code == "timeout"


def test_invalid_arguments():
    conn = Connector(disclosure="target")
    with pytest.raises(ValueError):
        conn.connect("127.0.0.1", 0)
    with pytest.raises(ValueError):
        conn.connect("", 443)


def test_wrap_tls_uses_a_verifying_context(monkeypatch, listener):
    contexts: list[ssl.SSLContext] = []
    real = ssl.create_default_context

    def spy(*args, **kwargs):
        ctx = real(*args, **kwargs)
        contexts.append(ctx)
        return ctx

    monkeypatch.setattr(ssl, "create_default_context", spy)
    conn = Connector(module="t_tls", disclosure="target")
    sock = conn.connect("127.0.0.1", listener, timeout=2)
    with pytest.raises((ssl.SSLError, OSError)):  # the listener does not speak TLS
        conn.wrap_tls(sock, "localhost", timeout=2)
    assert contexts and contexts[0].verify_mode == ssl.CERT_REQUIRED and contexts[0].check_hostname


def test_wrap_tls_closes_the_socket_when_refused(listener):
    cancel = threading.Event()
    conn = Connector(module="t_tls", disclosure="target", cancel_event=cancel)
    sock = conn.connect("127.0.0.1", listener, timeout=2)
    cancel.set()
    with pytest.raises(Cancelled):
        conn.wrap_tls(sock, "localhost")
    assert sock.fileno() == -1
