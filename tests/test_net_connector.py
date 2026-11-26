"""Core socket connector (ctx.net, WP11): target modules only, egress profile, SSRF and scope checks
after resolution, A7 ceilings (rate, concurrency, ports, pps, case budget), wordlist cap, kill
switch within 2 s, CONNECT records for the ledger, SOCKS and HTTP CONNECT routes. Loopback only
(the conftest network guard refuses anything else)."""

from __future__ import annotations

import copy
import json
import socket
import ssl
import threading
import time

import pytest

from tests.fakes import FakeClock, FakeHttp
from tests.fixtures.http.stub_transport import StubClock
from tests.test_egress import FakeSocks5
from v3lum.config import Config
from v3lum.core import noise
from v3lum.core.context import RunInfo
from v3lum.core.entities import Entity
from v3lum.core.http import Cancelled, ContactCeilings, DeadlineExceeded, HttpClient, PolicyError, RequestCapReached, ScopedHttp
from v3lum.core.models import Opsec
from v3lum.core.net import DEFAULT_CONNECT_TIMEOUT, WORDLIST_MAX, Connector, EgressProfiles, ProbeSocket, cap_wordlist
from v3lum.core.orgprofile import OrgProfile
from v3lum.core.scope import Scope

INTERNAL = RunInfo(internal_seed=True)
SCOPE = {
    "authorization_ref": "PENTEST-2026-042",
    "owner": "ACME S.A.",
    "contacts": ["soc@acme.example"],
    "ticket": "SEC-1",
    "window_start": "2026-01-01T00:00:00Z",
    "window_end": "2099-12-31T23:59:59Z",  # wide: tests on the real clock never age out
    "targets": {"domains": ["acme.example", "*.acme.example"], "cidrs": ["127.0.0.0/29", "93.184.216.0/24"]},
}


def make_scope(**changes) -> Scope:
    data = copy.deepcopy(SCOPE)
    data.update(changes)
    return Scope.from_dict(data)


def cfg(**settings) -> Config:
    config = Config()
    config.settings.update(settings)
    return config


def _serve(srv: socket.socket, stop: threading.Event, greet: bytes | None, held: list[socket.socket]) -> None:
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
        except (TimeoutError, OSError):
            continue
        if greet is None:
            held.append(conn)  # a silent server: keeps the connection open, never answers
            continue
        with conn:
            try:
                conn.sendall(greet)
            except OSError:
                pass


def _listener(greet: bytes | None, host: str = "127.0.0.1"):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, 0))
    srv.listen(16)
    srv.settimeout(0.05)  # short accept poll: teardown never waits
    stop = threading.Event()
    held: list[socket.socket] = []
    thread = threading.Thread(target=_serve, args=(srv, stop, greet, held), daemon=True)
    thread.start()
    return srv, stop, thread, held


@pytest.fixture()
def listener():
    """A loopback TCP server answering one line per connection."""
    srv, stop, thread, _held = _listener(b"220 hello\r\n")
    yield srv.getsockname()[1]
    stop.set()
    srv.close()
    thread.join(timeout=2)


@pytest.fixture()
def silent():
    """A loopback TCP server that accepts and never answers (a probe blocks in recv)."""
    srv, stop, thread, held = _listener(None)
    yield srv.getsockname()[1]
    stop.set()
    srv.close()
    for conn in held:
        conn.close()
    thread.join(timeout=2)


# --------------------------------------------------------------------------------------
# who may open sockets, and to what
# --------------------------------------------------------------------------------------


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


@pytest.mark.parametrize("opsec", [Opsec.LIGHT, "light"])
def test_connects_to_a_loopback_listener_with_an_internal_seed(opsec, listener):
    conn = Connector(module="t_net", disclosure="target", opsec=opsec, run=INTERNAL)
    with conn.connect("127.0.0.1", listener, timeout=2) as sock:
        assert isinstance(sock, ProbeSocket)
        assert sock.recv(64).startswith(b"220")
        assert 0 < sock.gettimeout() <= 2
    assert conn.connections == 1


def test_active_connects_only_inside_the_scope(listener):
    conn = Connector(module="t_net", disclosure="target", opsec=Opsec.ACTIVE, scope=make_scope())
    with conn.connect("127.0.0.1", listener, timeout=2) as sock:
        assert sock.recv(64).startswith(b"220")
    with pytest.raises(PolicyError) as err:
        Connector(module="t_net", opsec=Opsec.ACTIVE).connect("93.184.216.34", 443)
    assert err.value.reason_code == "scope" and "--scope" in str(err.value)
    excluded = make_scope(exclusions={"cidrs": ["127.0.0.1/32"]})
    with pytest.raises(PolicyError) as err:
        Connector(module="t_net", opsec=Opsec.ACTIVE, scope=excluded).connect("127.0.0.1", listener, timeout=2)
    assert err.value.reason_code == "scope" and "excluded" in str(err.value)
    with pytest.raises(PolicyError) as err:
        Connector(module="t_net", opsec=Opsec.ACTIVE, scope=make_scope()).connect("10.9.9.9", 22)
    assert "10.9.9.9" in str(err.value)


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "intranet", "printer.local", "2130706433", "169.254.169.254"])
def test_internal_targets_are_refused_without_an_allowance(host, listener):
    conn = Connector(module="t_net", disclosure="target", opsec=Opsec.LIGHT)
    with pytest.raises(PolicyError) as err:
        conn.connect(host, listener, timeout=1)
    assert err.value.reason_code == "policy" and "SSRF" in str(err.value)
    assert conn.connections == 0 and conn.request_log == []


def test_light_sockets_stay_on_the_typed_seed(listener):
    egress = EgressProfiles(cfg(), resolver=lambda host, profile: ["127.0.0.1"])
    seed = RunInfo(entity=Entity.make("domain", "mail.acme.example"), internal_seed=True, case_id="c")
    conn = Connector(module="t_net", opsec=Opsec.LIGHT, run=seed, egress=egress, config=cfg())
    conn.connect("mail.acme.example", listener, timeout=2).close()
    with pytest.raises(PolicyError) as err:
        conn.connect("other.example.net", listener, timeout=2)
    assert err.value.reason_code == "scope" and "outside the seed" in str(err.value)
    pivot = RunInfo(entity=Entity.make("domain", "mail.acme.example"), is_seed=False, internal_seed=True)
    with pytest.raises(PolicyError) as err:
        Connector(module="t_net", opsec=Opsec.LIGHT, run=pivot, egress=egress, config=cfg()).connect("mail.acme.example", listener)
    assert err.value.reason_code == "scope" and "pivots" in str(err.value)


def test_cdn_and_third_party_hosted_addresses_need_their_ip_listed(tmp_path):
    frag = tmp_path / "noise"
    frag.mkdir()
    (frag / "cdn_t.json").write_text(json.dumps({"schema": "v3lum.noise/1", "kind": "cdn", "source": "t", "licence": "CC0-1.0", "cidrs": ["104.16.0.0/13"]}), encoding="utf-8")
    noise.reload(extra_dirs=[frag])
    try:
        egress = EgressProfiles(cfg(), resolver=lambda host, profile: ["104.16.9.9"] if host == "www.acme.example" else ["93.184.216.40"])
        conn = Connector(module="t_net", opsec=Opsec.ACTIVE, scope=make_scope(shared_infra_hosts=["www.acme.example"]), egress=egress, config=cfg())
        with pytest.raises(PolicyError) as err:  # shared_infra_hosts opens HTTP probes, never port probes
            conn.connect("www.acme.example", 443)
        assert err.value.reason_code == "scope" and "IP/CIDR listed" in str(err.value)
        org = OrgProfile.from_dict({"cidrs": [{"value": "93.184.216.0/26", "third_party_hosted": True}]})
        by_name = make_scope(targets={"domains": ["acme.example", "*.acme.example"], "cidrs": ["127.0.0.0/29"]})
        flagged = Connector(module="t_net", opsec=Opsec.ACTIVE, scope=by_name, egress=egress, config=cfg(), org=org)
        with pytest.raises(PolicyError) as err:
            flagged.connect("shop.acme.example", 443)
        assert "third_party_hosted" in str(err.value)
        assert conn.request_log == [] and flagged.request_log == []  # refused before any socket
    finally:
        noise.reload(extra_dirs=())


def test_onion_needs_tor_light_and_tor_is_never_active():
    with pytest.raises(PolicyError) as err:
        Connector(module="t_net", opsec=Opsec.LIGHT, config=cfg()).connect("a" * 56 + ".onion", 80)
    assert "Tor proxy_light" in str(err.value)
    tor_active = Connector(module="t_net", opsec=Opsec.ACTIVE, scope=make_scope(), config=cfg(proxy_active="socks5h://127.0.0.1:9050"))
    with pytest.raises(PolicyError) as err:
        tor_active.connect("93.184.216.34", 443)
    assert "Tor is allowed for LIGHT reads only" in str(err.value)


# --------------------------------------------------------------------------------------
# deadline, cancel and TLS (wave-1 behaviour kept)
# --------------------------------------------------------------------------------------


def test_default_timeout_is_capped_by_the_deadline(listener):
    clock = StubClock()
    conn = Connector(module="t_net", disclosure="target", deadline=clock.monotonic() + 3.0, clock=clock, run=INTERNAL)
    with conn.connect("127.0.0.1", listener) as sock:
        assert sock.gettimeout() == pytest.approx(3.0)
    assert DEFAULT_CONNECT_TIMEOUT > 3.0


def test_cancel_is_honoured(listener):
    cancel = threading.Event()
    conn = Connector(module="t_net", disclosure="target", cancel_event=cancel, run=INTERNAL)
    conn.connect("127.0.0.1", listener, timeout=2).close()
    cancel.set()
    with pytest.raises(Cancelled):
        conn.connect("127.0.0.1", listener, timeout=2)
    assert conn.connections == 1


def test_deadline_passed_refuses_new_connections(listener):
    clock = StubClock()
    conn = Connector(module="t_net", disclosure="target", deadline=clock.monotonic() + 1.0, clock=clock, run=INTERNAL)
    clock.advance(2.0)
    with pytest.raises(DeadlineExceeded) as err:
        conn.connect("127.0.0.1", listener)
    assert err.value.reason_code == "timeout"


def test_invalid_arguments():
    conn = Connector(disclosure="target", run=INTERNAL)
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
    conn = Connector(module="t_tls", disclosure="target", run=INTERNAL)
    sock = conn.connect("127.0.0.1", listener, timeout=2)
    with pytest.raises((ssl.SSLError, OSError)):  # the listener does not speak TLS
        conn.wrap_tls(sock, "localhost", timeout=2)
    assert contexts and contexts[0].verify_mode == ssl.CERT_REQUIRED and contexts[0].check_hostname


def test_wrap_tls_closes_the_socket_when_refused(listener):
    cancel = threading.Event()
    conn = Connector(module="t_tls", disclosure="target", cancel_event=cancel, run=INTERNAL)
    sock = conn.connect("127.0.0.1", listener, timeout=2)
    cancel.set()
    with pytest.raises(Cancelled):
        conn.wrap_tls(sock, "localhost")
    assert sock.fileno() == -1


def test_cancel_stops_a_blocked_probe_within_two_seconds(silent):
    cancel = threading.Event()
    conn = Connector(module="t_net", opsec=Opsec.LIGHT, cancel_event=cancel, run=INTERNAL)
    sock = conn.connect("127.0.0.1", silent, timeout=10)
    outcome: dict[str, object] = {}

    def probe() -> None:
        start = time.monotonic()
        try:
            outcome["data"] = sock.recv(16)  # blocks: the server never answers
        except OSError as exc:
            outcome["error"] = type(exc).__name__
        outcome["elapsed"] = time.monotonic() - start

    thread = threading.Thread(target=probe, daemon=True)
    thread.start()
    time.sleep(0.15)
    cancel.set()
    thread.join(timeout=2.5)
    assert not thread.is_alive()
    assert outcome["elapsed"] < 2.0
    assert outcome.get("data", b"") == b""
    closed_by = time.monotonic() + 1.0  # the watcher closes right after the shutdown that woke recv
    while sock.fileno() != -1 and time.monotonic() < closed_by:
        time.sleep(0.01)
    assert sock.fileno() == -1


# --------------------------------------------------------------------------------------
# A7 ceilings
# --------------------------------------------------------------------------------------


def test_active_rate_per_host_and_global_pps(listener):
    clock = FakeClock()
    conn = Connector(module="t_net", opsec=Opsec.ACTIVE, scope=make_scope(), clock=clock)
    for _ in range(3):
        conn.connect("127.0.0.1", listener, timeout=2).close()
    assert clock.sleeps == [pytest.approx(0.1), pytest.approx(0.1)]  # <= 10 probes/s per target host
    srv, stop, thread, _held = _listener(b"220 second\r\n", host="127.0.0.2")
    try:
        slow = Connector(module="t_net", opsec=Opsec.ACTIVE, scope=make_scope(limits={"max_pps": 2}), clock=FakeClock())
        slow.connect("127.0.0.1", listener, timeout=2).close()
        slow.connect("127.0.0.2", srv.getsockname()[1], timeout=2).close()  # another host, same global budget
        assert slow.clock.sleeps == [pytest.approx(0.5)]
    finally:
        stop.set()
        srv.close()
        thread.join(timeout=2)


def test_light_is_one_probe_per_second_and_25_per_host(listener):
    clock = FakeClock()
    conn = Connector(module="t_net", opsec=Opsec.LIGHT, run=INTERNAL, clock=clock)
    conn.connect("127.0.0.1", listener, timeout=2).close()
    conn.connect("127.0.0.1", listener, timeout=2).close()
    assert clock.sleeps == [pytest.approx(1.0)]
    conn.ceilings.charge("light", "127.0.0.1", n=23)
    with pytest.raises(RequestCapReached) as err:
        conn.connect("127.0.0.1", listener, timeout=2)
    assert "25 requests" in str(err.value)


def test_at_most_two_concurrent_connections_per_host(listener):
    conn = Connector(module="t_net", opsec=Opsec.ACTIVE, scope=make_scope())
    conn.limiter.reserve = lambda host, interval=0.0: 0.0  # isolate concurrency from pacing
    first = conn.connect("127.0.0.1", listener, timeout=2)
    second = conn.connect("127.0.0.1", listener, timeout=2)
    done = threading.Event()

    def third() -> None:
        conn.connect("127.0.0.1", listener, timeout=2).close()
        done.set()

    thread = threading.Thread(target=third, daemon=True)
    thread.start()
    assert not done.wait(0.15)  # waits for a free slot
    first.close()
    assert done.wait(2.0)
    second.close()
    thread.join(timeout=2)


def test_port_scans_are_capped_at_1000_ports_per_host(listener):
    conn = Connector(module="t_net", opsec=Opsec.ACTIVE, scope=make_scope(limits={"max_requests": 50000}))
    for port in [*range(1, 1000), listener]:  # 1000 distinct ports, the listener's among them
        conn.ceilings.port("127.0.0.1", port)
    conn.connect("127.0.0.1", listener, timeout=2).close()  # a counted port stays usable
    with pytest.raises(RequestCapReached) as err:
        conn.connect("127.0.0.1", 1000, timeout=2)  # a 1001st distinct port is refused before any packet
    assert "1000 TCP ports" in str(err.value)
    assert [r.port for r in conn.request_log] == [listener]


def test_active_case_budget(listener):
    conn = Connector(module="t_net", opsec=Opsec.ACTIVE, scope=make_scope(limits={"max_requests": 2}), run=RunInfo(case_id="case-1"))
    conn.connect("127.0.0.1", listener, timeout=2).close()
    conn.connect("127.0.0.1", listener, timeout=2).close()
    with pytest.raises(RequestCapReached) as err:
        conn.connect("127.0.0.1", listener, timeout=2)
    assert "ACTIVE budget" in str(err.value)


def test_ceilings_count_per_case_and_restart_per_scan():
    ceilings = ContactCeilings()
    for _ in range(25):
        ceilings.charge("light", "a.example")
    with pytest.raises(RequestCapReached):
        ceilings.charge("light", "a.example")
    ceilings.charge("light", "b.example")  # per host
    ceilings.charge("light", "a.example", case_id="other")  # per case
    ceilings.reset_scan()
    ceilings.charge("light", "a.example")
    assert ceilings.used("light", "a.example") == 1


def test_wordlists_are_capped_at_5000_entries():
    words = [f"w{i}" for i in range(12000)]
    assert len(Connector.cap_wordlist(words)) == WORDLIST_MAX == 5000
    assert Connector(module="t").cap_wordlist(iter(words))[:2] == ["w0", "w1"]
    assert cap_wordlist(range(10)) == list(range(10))


# --------------------------------------------------------------------------------------
# the request ledger
# --------------------------------------------------------------------------------------


def test_every_connection_is_a_connect_record_in_the_ledger(listener):
    infos = []
    clock = FakeClock()
    client = HttpClient(transport=FakeHttp(clock=clock), clock=clock, on_request_info=infos.append)
    scoped = ScopedHttp(client, module="t_net", opsec="light", disclosure="target", run=INTERNAL)
    conn = Connector(module="t_net", opsec=Opsec.LIGHT, http=scoped, clock=clock)
    conn.connect("127.0.0.1", listener, timeout=2).close()
    record = conn.request_log[-1]
    assert (record.method, record.host, record.port, record.resolved_ip, record.egress_profile, record.opsec, record.module) == (
        "CONNECT", "127.0.0.1", listener, "127.0.0.1", "default", "light", "t_net",
    )
    assert record.url == f"tcp://127.0.0.1:{listener}" and record.error == ""
    assert scoped.request_log[-1] is record and scoped.hosts["127.0.0.1"] == 1  # disclosure ledger
    assert infos[-1] is record  # the runtime event bus (hash-chained ledger, WP15)
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    with pytest.raises(OSError):
        conn.connect("127.0.0.1", port, timeout=1)
    assert conn.request_log[-1].error and conn.request_log[-1].port == port  # failures are recorded too


def test_a_bound_connector_shares_the_clients_profiles_and_counters():
    client = HttpClient(transport=FakeHttp(clock=FakeClock()))
    scoped = ScopedHttp(client, module="t", opsec="active", disclosure="target", scope=make_scope(), run=RunInfo(case_id="k"))
    conn = Connector(module="t", opsec=Opsec.ACTIVE, http=scoped)
    assert conn.egress is client.egress and conn.limiter is client.limiter and conn.ceilings is client.ceilings
    assert conn.scope is scoped.scope and conn.case_id == "k"


# --------------------------------------------------------------------------------------
# proxied routes: SOCKS (PySocks) and HTTP CONNECT
# --------------------------------------------------------------------------------------


def test_socks_route_sends_the_checked_address_and_never_resolves_locally(monkeypatch):
    pytest.importorskip("socks")
    server = FakeSocks5(banner=b"220 via socks\r\n")
    looked_up: list[str] = []
    guarded = socket.getaddrinfo

    def spy(host, *args, **kwargs):
        looked_up.append(str(host))
        return guarded(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", spy)
    try:
        settings = cfg(proxy_light=server.url)
        egress = EgressProfiles(settings, resolver=lambda host, profile: ["93.184.216.34"])
        seed = RunInfo(entity=Entity.make("domain", "mx.target.example"), case_id="c")
        conn = Connector(module="t_net", opsec=Opsec.LIGHT, run=seed, egress=egress, config=settings)
        with conn.connect("mx.target.example", 25, timeout=2) as sock:
            assert sock.recv(64).startswith(b"220 via socks")
        assert server.requests[-1] == ("ipv4", "93.184.216.34", 25)  # pinned to the checked address
        assert "mx.target.example" not in looked_up
        assert conn.request_log[-1].egress_profile == "light"
    finally:
        server.close()


def test_a_socks_proxy_refusing_the_target_is_a_socket_error():
    pytest.importorskip("socks")
    server = FakeSocks5(refuse=True)
    try:
        settings = cfg(proxy_light=server.url)
        seed = RunInfo(entity=Entity.make("ipv4", "93.184.216.34"), case_id="c")
        conn = Connector(module="t_net", opsec=Opsec.LIGHT, run=seed, config=settings)
        with pytest.raises(OSError) as err:
            conn.connect("93.184.216.34", 25, timeout=2)
        assert not isinstance(err.value, PolicyError)
    finally:
        server.close()


def _http_proxy(reply: bytes):
    lines: list[bytes] = []
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    srv.settimeout(0.05)
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except (TimeoutError, OSError):
                continue
            with conn:
                try:
                    conn.settimeout(2)
                    data = conn.recv(4096)
                    if not data:
                        continue
                    lines.append(data.split(b"\r\n", 1)[0])
                    conn.sendall(reply)
                    time.sleep(0.05)
                except OSError:
                    pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return srv, stop, thread, lines


def test_http_connect_route_tunnels_to_the_checked_address():
    srv, stop, thread, lines = _http_proxy(b"HTTP/1.1 200 Connection established\r\n\r\n220 tunnelled\r\n")
    try:
        settings = cfg(proxy_active=f"http://127.0.0.1:{srv.getsockname()[1]}")
        conn = Connector(module="t_net", opsec=Opsec.ACTIVE, scope=make_scope(), config=settings)
        with conn.connect("93.184.216.34", 25, timeout=2) as sock:
            assert b"220 tunnelled" in sock.recv(64)
        assert lines[-1] == b"CONNECT 93.184.216.34:25 HTTP/1.1"
        assert conn.request_log[-1].egress_profile == "active"
    finally:
        stop.set()
        srv.close()
        thread.join(timeout=2)


def test_http_connect_refusal_is_a_socket_error():
    srv, stop, thread, _lines = _http_proxy(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
    try:
        settings = cfg(proxy_active=f"http://127.0.0.1:{srv.getsockname()[1]}")
        conn = Connector(module="t_net", opsec=Opsec.ACTIVE, scope=make_scope(), config=settings)
        with pytest.raises(OSError) as err:
            conn.connect("93.184.216.34", 25, timeout=2)
        assert "502" in str(err.value) and not isinstance(err.value, PolicyError)
    finally:
        stop.set()
        srv.close()
        thread.join(timeout=2)


def test_a_tls_probe_frees_its_slot_when_closed(tmp_path, monkeypatch):
    from tests.test_http_ssrf import make_tls_cert

    cert, key = make_tls_cert(tmp_path)
    server_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_ctx.load_cert_chain(str(cert), str(key))
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(2)
    srv.settimeout(5)

    def serve() -> None:
        try:
            raw, _ = srv.accept()
            with server_ctx.wrap_socket(raw, server_side=True) as tls:
                tls.sendall(b"hello over tls")
        except OSError:
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    real = ssl.create_default_context

    def trusting(*args, **kwargs):  # the default verifying context, also trusting the test CA
        ctx = real(*args, **kwargs)
        ctx.load_verify_locations(str(cert))
        return ctx

    monkeypatch.setattr(ssl, "create_default_context", trusting)
    try:
        conn = Connector(module="t_tls", opsec=Opsec.LIGHT, run=INTERNAL)
        tls = conn.wrap_tls(conn.connect("127.0.0.1", srv.getsockname()[1], timeout=3), "tls.example.test", timeout=3)
        assert tls.recv(64) == b"hello over tls" and tls.getpeercert()["subject"]
        sem = conn.limiter.slot("contact:2:127.0.0.1", 2)
        assert sem._value == 1  # held by the TLS socket
        tls.close()
        assert sem._value == 2  # freed with it
    finally:
        srv.close()
        thread.join(timeout=2)


# --------------------------------------------------------------------------------------
# review additions: pending connects and proxy handshakes obey the kill switch, the scope
# window, self-test contexts, ledger URLs and proxy default ports
# --------------------------------------------------------------------------------------


@pytest.fixture()
def blackhole():
    """A loopback port whose accept queue is full: a new connect stays pending (SYNs dropped)."""
    import select

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(0)
    port = srv.getsockname()[1]
    filler: list[socket.socket] = []
    for _ in range(16):
        s = socket.socket()
        s.setblocking(False)
        try:
            s.connect(("127.0.0.1", port))
        except BlockingIOError:
            pass
        filler.append(s)
    probe = socket.socket()
    probe.setblocking(False)
    try:
        probe.connect(("127.0.0.1", port))
    except BlockingIOError:
        pass
    _r, done, _x = select.select([], [probe], [], 0.2)
    probe.close()
    if done:  # e.g. SYN cookies complete the handshake: this kernel cannot hold a connect pending
        for s in filler:
            s.close()
        srv.close()
        pytest.skip("this kernel completes connects to a full accept queue")
    yield port
    for s in filler:
        s.close()
    srv.close()


def _cancel_after(event: threading.Event, seconds: float) -> None:
    threading.Timer(seconds, event.set).start()


def test_cancel_interrupts_a_pending_connect(blackhole):
    cancel = threading.Event()
    conn = Connector(module="t_net", opsec=Opsec.LIGHT, cancel_event=cancel, run=INTERNAL)
    _cancel_after(cancel, 0.2)
    start = time.monotonic()
    with pytest.raises(Cancelled):
        conn.connect("127.0.0.1", blackhole, timeout=10)
    assert time.monotonic() - start < 1.0  # not the 10 s connect timeout
    assert conn.request_log[-1].error == "Cancelled" and conn.connections == 0
    sem = conn.limiter.slot("contact:2:127.0.0.1", 2)
    assert sem._value == 2  # the per-host slot was freed


def test_the_deadline_interrupts_a_pending_connect(blackhole):
    import v3lum.core.clock as clock_mod

    conn = Connector(module="t_net", opsec=Opsec.LIGHT, deadline=clock_mod.SYSTEM_CLOCK.monotonic() + 0.3, run=INTERNAL)
    start = time.monotonic()
    with pytest.raises((DeadlineExceeded, TimeoutError)):
        conn.connect("127.0.0.1", blackhole, timeout=10)
    assert time.monotonic() - start < 1.5


def test_cancel_interrupts_an_http_connect_handshake(silent):
    """A proxy that accepted the TCP connection but never answers the CONNECT."""
    cancel = threading.Event()
    settings = cfg(proxy_active=f"http://127.0.0.1:{silent}")
    conn = Connector(module="t_net", opsec=Opsec.ACTIVE, scope=make_scope(), config=settings, cancel_event=cancel)
    _cancel_after(cancel, 0.2)
    start = time.monotonic()
    with pytest.raises(Cancelled):
        conn.connect("93.184.216.34", 25, timeout=10)
    assert time.monotonic() - start < 1.0


def test_cancel_interrupts_a_socks_handshake(silent):
    pytest.importorskip("socks")
    cancel = threading.Event()
    settings = cfg(proxy_light=f"socks5h://127.0.0.1:{silent}")
    seed = RunInfo(entity=Entity.make("ipv4", "93.184.216.34"), case_id="c")
    conn = Connector(module="t_net", opsec=Opsec.LIGHT, run=seed, config=settings, cancel_event=cancel)
    _cancel_after(cancel, 0.2)
    start = time.monotonic()
    with pytest.raises(Cancelled):
        conn.connect("93.184.216.34", 25, timeout=10)
    assert time.monotonic() - start < 1.0


def test_the_scope_window_bounds_sockets(listener):
    clock = StubClock()  # 2026-11-26 12:00 UTC
    closed = make_scope(window_start="2026-11-01T00:00:00Z", window_end="2026-11-26T11:00:00Z")
    with pytest.raises(Cancelled) as err:
        Connector(module="t_net", opsec=Opsec.ACTIVE, scope=closed, clock=clock).connect("127.0.0.1", listener, timeout=2)
    assert "window closed" in str(err.value)
    later = make_scope(window_start="2026-11-26T13:00:00Z", window_end="2026-11-27T00:00:00Z")
    with pytest.raises(PolicyError) as err:
        Connector(module="t_net", opsec=Opsec.ACTIVE, scope=later, clock=clock).connect("127.0.0.1", listener, timeout=2)
    assert err.value.reason_code == "scope"
    Connector(module="t_net", opsec=Opsec.ACTIVE, scope=make_scope(), clock=clock).connect("127.0.0.1", listener, timeout=2).close()


def test_an_active_self_test_context_reaches_only_internal_hosts(listener):
    """An ACTIVE run without an entity or a scope (a self-test) reaches loopback/internal hosts only,
    and only with internal_seed."""
    conn = Connector(module="t_self", opsec=Opsec.ACTIVE, run=INTERNAL, egress=EgressProfiles(cfg(), resolver=lambda h, p: ["93.184.216.34"]))
    conn.connect("127.0.0.1", listener, timeout=2).close()
    with pytest.raises(PolicyError) as err:
        conn.connect("93.184.216.34", 443, timeout=2)
    assert err.value.reason_code == "scope"
    with pytest.raises(PolicyError):
        conn.connect("www.example.com", 443, timeout=2)  # a public name: refused before any lookup
    with pytest.raises(PolicyError) as err:
        Connector(module="t_self", opsec=Opsec.ACTIVE, run=RunInfo(case_id="c")).connect("127.0.0.1", listener, timeout=2)
    assert err.value.reason_code == "scope"


def test_connect_records_bracket_ipv6_hosts():
    conn = Connector(module="t_net", opsec=Opsec.LIGHT, run=INTERNAL)
    assert conn.record("CONNECT", "2001:db8::1", 443).url == "tcp://[2001:db8::1]:443"
    assert conn.record("CONNECT", "mx.example.com", 25).url == "tcp://mx.example.com:25"


def test_proxy_default_ports_match_the_transport():
    from urllib.parse import urlsplit

    from v3lum.core.net import _proxy_port

    assert _proxy_port(urlsplit("http://proxy.corp.example")) == 80  # what urllib3 uses, not 8080
    assert _proxy_port(urlsplit("https://proxy.corp.example")) == 443
    assert _proxy_port(urlsplit("http://proxy.corp.example:3128")) == 3128
