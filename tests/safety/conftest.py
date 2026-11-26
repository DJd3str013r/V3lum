"""Shared fixtures of the AR20 safety suite (WP28, A7, A16): black-box tests over the integrated core.

Every test in ``tests/safety/`` carries the ``safety`` marker (``pytest -m safety`` runs the suite;
it also runs in the default offline run: the marker is never deselected). The suite drives the real
engine, policy gate, HTTP client, socket connector and tool runner with:

* synthetic PASSIVE / LIGHT / ACTIVE modules (``tests.fakes.define_module``) and synthetic providers
  (``tests.fakes.test_provider``), registered into an isolated, emptied module registry (fixture
  ``registry``: only the modules a test defines are candidates);
* :class:`TrackingHttp` (a ``FakeHttp`` transport that also calls hooks after each send, e.g. to fire
  the kill switch or to hold a request until it fires) and fake DoH answers (:func:`dns`);
* a :class:`~tests.fakes.FakeClock` (fixture ``clock``), and for the "within 2 s" checks real
  loopback servers on the system clock (:class:`LoopbackServer`, :class:`SafetySocks5`);
* scope files written to disk and loaded with ``Scope.load`` (fixture ``scope_file``), a synthetic
  CDN noise list (fixture ``cdn_noise``), recorders for the request ledger (:class:`Ledger`) and the
  socket layer (fixture ``socket_spy``), and helpers that simulate Ctrl+C in the engine loop
  (:func:`interrupt_engine_when`) and time-stamp the kill switch (:class:`KillSwitchProbe`).

Test values: target names under ``acme.example`` (in scope) and ``*.example.net`` / ``*.example.org``
(out of scope); routable addresses outside the documentation ranges (``93.184.216.0/24`` in scope,
``93.184.217.0/24`` out of scope; TEST-NET addresses are refused by the SSRF guard like any
non-routable address).
"""

from __future__ import annotations

import copy
import itertools
import json
import socket
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from tests.fakes import DOH_HOSTS, FakeClock, FakeHttp, add_dns, define_module, source_ids, test_provider
from v3lum.core import engine as engine_mod
from v3lum.core import noise
from v3lum.core.context import ScanOptions
from v3lum.core.engine import CaseResult, Engine
from v3lum.core.entities import Entity, EntityType
from v3lum.core.models import Opsec
from v3lum.core.scope import Scope

SAFETY_DIR = Path(__file__).resolve().parent
SAFETY_MARKER = "safety: AR20 safety suite (gates every LIGHT/ACTIVE merge)"

#: the engagement of the suite (A7): an authorization reference and a scope bound to it
REF = "PENTEST-2026-042"
IN_SCOPE_DOMAIN = "acme.example"
IN_SCOPE_HOST = "www.acme.example"
IN_SCOPE_CIDR = "93.184.216.0/24"
IN_SCOPE_IP = "93.184.216.34"
OUT_OF_SCOPE_IP = "93.184.217.66"
#: a CDN range of the synthetic noise list (fixture ``cdn_noise``; Cloudflare's 104.16.0.0/13)
CDN_CIDR = "104.16.0.0/13"
CDN_IP = "104.16.5.5"
METADATA_IP = "169.254.169.254"
#: the FakeClock of tests.fakes starts at 2026-11-26 12:00 UTC: the default window holds it
WINDOW_START = "2026-11-26T00:00:00Z"
WINDOW_END = "2026-11-27T00:00:00Z"

BASE_SCOPE: dict[str, Any] = {
    "authorization_ref": REF,
    "owner": "Engagement owner (safety suite)",
    "contacts": ["soc@acme.example"],
    "ticket": "SAFETY-1",
    "window_start": WINDOW_START,
    "window_end": WINDOW_END,
    "targets": {"domains": [IN_SCOPE_DOMAIN, f"*.{IN_SCOPE_DOMAIN}"], "cidrs": [IN_SCOPE_CIDR]},
    "exclusions": {"domains": [f"mail.{IN_SCOPE_DOMAIN}"]},
}


# --------------------------------------------------------------------------------------
# marker: every test of tests/safety is a safety test
# --------------------------------------------------------------------------------------


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", SAFETY_MARKER)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Mark every item collected from ``tests/safety/`` with ``safety`` (a file that forgets its
    ``pytestmark`` is still selected by ``pytest -m safety``). Conftest hooks see the whole session,
    so only items under this directory are touched."""
    for item in items:
        path = Path(str(getattr(item, "path", "") or getattr(item, "fspath", "")))
        try:
            path.resolve().relative_to(SAFETY_DIR)
        except ValueError:
            continue
        if item.get_closest_marker("safety") is None:
            item.add_marker(pytest.mark.safety)


# --------------------------------------------------------------------------------------
# HTTP doubles and DNS answers
# --------------------------------------------------------------------------------------


class TrackingHttp(FakeHttp):
    """A ``FakeHttp`` transport that calls ``hooks`` after every answered send.

    Each hook is ``hook(method, url)`` and runs in the sending (module worker) thread after the call
    was recorded and answered: it may fire the kill switch, advance the clock or hold the request
    until something happens (a slow or stalled target)."""

    def __init__(self, *, clock: Any = None) -> None:
        super().__init__(clock=clock)
        self.hooks: list[Callable[[str, str], None]] = []

    def send(self, method: str, url: str, **kw: Any) -> Any:
        resp = super().send(method, url, **kw)
        for hook in list(self.hooks):
            hook(method.upper(), url)
        return resp


def host_of(url: str) -> str:
    try:
        return (urlsplit(str(url)).hostname or "").lower()
    except ValueError:
        return ""


def dns(http: FakeHttp, name: str, a: Iterable[str] = (), aaaa: Iterable[str] = ()) -> None:
    """Answer the A and AAAA DoH queries of ``name`` (Google JSON, the core resolver's default)."""
    add_dns(http, name, "A", list(a))
    add_dns(http, name, "AAAA", list(aaaa))


def is_doh(url: str) -> bool:
    return host_of(url) in DOH_HOSTS


def target_calls(http: FakeHttp) -> list[dict[str, Any]]:
    """Calls that reached a target (DoH lookups excluded)."""
    return [c for c in http.calls if not is_doh(c["url"])]


def calls_to(http: FakeHttp, host: str) -> list[dict[str, Any]]:
    """Calls whose URL host is ``host`` (or one of its subdomains when ``host`` starts with '.')."""
    host = host.lower()
    out = []
    for call in http.calls:
        name = host_of(call["url"])
        if name == host or (host.startswith(".") and name.endswith(host)):
            out.append(call)
    return out


def looked_up(http: FakeHttp) -> set[str]:
    """Names the core resolver asked a DoH resolver about (through this transport)."""
    names: set[str] = set()
    for call in http.calls:
        if is_doh(call["url"]):
            names |= {n.rstrip(".").lower() for n in parse_qs(urlsplit(call["url"]).query).get("name", [])}
    return names


def entity(text: str) -> Entity:
    """'type:value' -> Entity."""
    etype, _, value = text.partition(":")
    return Entity.make(EntityType.parse(etype), value)


# --------------------------------------------------------------------------------------
# registry, clock, transport
# --------------------------------------------------------------------------------------


@pytest.fixture()
def registry(clean_registry: Any) -> Any:
    """The isolated module registry, emptied: only the synthetic modules of the test are
    candidates (the shipped modules and the module batches in flight never interfere)."""
    clean_registry.clear()
    return clean_registry


@pytest.fixture()
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture()
def http(clock: FakeClock) -> TrackingHttp:
    return TrackingHttp(clock=clock)


# --------------------------------------------------------------------------------------
# scope files, noise lists, providers
# --------------------------------------------------------------------------------------


@pytest.fixture()
def scope_file(tmp_path: Path) -> Callable[..., Scope]:
    """Factory: write a JSON scope file (``BASE_SCOPE`` updated with the keyword arguments; ``None``
    removes a key) into the test's directory and load it with ``Scope.load`` - the file an analyst
    passes with ``--scope FILE``."""
    counter = itertools.count(1)

    def make(**changes: Any) -> Scope:
        data = copy.deepcopy(BASE_SCOPE)
        for key, value in changes.items():
            if value is None:
                data.pop(key, None)
            else:
                data[key] = value
        path = tmp_path / f"scope_{next(counter)}.json"
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return Scope.load(path)

    return make


@pytest.fixture()
def cdn_noise(tmp_path: Path) -> Iterator[str]:
    """A synthetic CDN noise list (``CDN_CIDR``): addresses in it are shared infrastructure for the
    scope rules (A7) whatever the shipped lists say. Restored afterwards."""
    folder = tmp_path / "noise_fragments"
    folder.mkdir()
    (folder / "safety_cdn.json").write_text(
        json.dumps({"schema": "v3lum.noise/1", "kind": "cdn", "source": "safety suite", "licence": "CC0-1.0", "cidrs": [CDN_CIDR]}),
        encoding="utf-8",
    )
    noise.reload(extra_dirs=[folder])
    try:
        yield CDN_CIDR
    finally:
        noise.reload(extra_dirs=())


@pytest.fixture()
def ti_provider(registry: Any) -> Iterator[Any]:
    """A synthetic trusted third-party provider (host ``api.safety-ti.example``) for PASSIVE modules."""
    with test_provider("safety_ti", hosts=("api.safety-ti.example",)) as prov:
        yield prov


# --------------------------------------------------------------------------------------
# synthetic modules
# --------------------------------------------------------------------------------------

DEFAULT_ACCEPTS = (EntityType.DOMAIN, EntityType.URL, EntityType.IPV4)


def offline_module(name: str, run: Callable[..., Any], *, accepts: Iterable[EntityType] = DEFAULT_ACCEPTS, **attrs: Any) -> Any:
    """A PASSIVE module with disclosure 'none' (no network at all)."""
    return define_module(name, list(accepts), run, **attrs)


def passive_module(name: str, run: Callable[..., Any], provider: Any, *, accepts: Iterable[EntityType] = DEFAULT_ACCEPTS, **attrs: Any) -> Any:
    """A PASSIVE module of ``provider`` (declares the provider's hosts and sources; disclosure
    'third_party' unless given, e.g. 'internal' for an internal platform)."""
    attrs.setdefault("hosts", tuple(provider.hosts))
    attrs.setdefault("disclosure", "third_party")
    if attrs["disclosure"] == "third_party":
        attrs.setdefault("access_model", "free_noauth_unlimited")
    return define_module(name, list(accepts), run, provider=provider.id, sources=source_ids(provider), **attrs)


def light_module(name: str, run: Callable[..., Any], *, accepts: Iterable[EntityType] = DEFAULT_ACCEPTS, **attrs: Any) -> Any:
    """A LIGHT target-contact module (disclosure 'target', opt-in)."""
    attrs.setdefault("max_requests", 200)
    return define_module(name, list(accepts), run, opsec=Opsec.LIGHT, **attrs)


def active_module(name: str, run: Callable[..., Any], *, accepts: Iterable[EntityType] = DEFAULT_ACCEPTS, **attrs: Any) -> Any:
    """An ACTIVE target-contact module (disclosure 'target', opt-in)."""
    attrs.setdefault("max_requests", 200)
    return define_module(name, list(accepts), run, opsec=Opsec.ACTIVE, **attrs)


def pivot_source(name: str, pivots: Iterable[tuple[str, str, str]], *, accepts: Iterable[EntityType] = DEFAULT_ACCEPTS) -> Any:
    """An offline PASSIVE module that reports ``pivots`` ((type, value, relation) triples) for the
    analyst-typed seed only - the passive results a scan expands."""
    wanted = tuple(pivots)

    def run(self: Any, ent: Entity, ctx: Any) -> Any:
        res = self.result(ent)
        if ctx.is_seed:
            for etype, value, relation in wanted:
                res.pivot(etype, value, relation, confidence=0.9)
        return res

    return offline_module(name, run, accepts=accepts)


# --------------------------------------------------------------------------------------
# options and scans
# --------------------------------------------------------------------------------------


def active_options(scope: Scope, include: Iterable[str], **kw: Any) -> ScanOptions:
    """``--mode active --authorized REF --scope FILE -M <include>``."""
    kw.setdefault("threads", 4)
    kw.setdefault("save_evidence", False)
    return ScanOptions(
        mode=Opsec.ACTIVE, authorized=True, authorization_ref=REF, scope=scope, scope_path=str(getattr(scope, "path", "") or ""),
        include=set(include), **kw,
    )


def light_options(include: Iterable[str], **kw: Any) -> ScanOptions:
    """``--mode light -M <include>``."""
    kw.setdefault("threads", 4)
    kw.setdefault("save_evidence", False)
    return ScanOptions(mode=Opsec.LIGHT, include=set(include), **kw)


def scan(rt: Any, options: ScanOptions, *seeds: Entity | str) -> CaseResult:
    """``Engine(rt, options).investigate(seeds)``; a KeyboardInterrupt escaping the engine (a simulated
    Ctrl+C the engine failed to handle) fails the test instead of aborting the session."""
    ents = [s if isinstance(s, Entity) else entity(s) for s in seeds]
    try:
        return Engine(rt, options).investigate(ents)
    except KeyboardInterrupt:  # pragma: no cover - the engine must turn Ctrl+C into a stopped scan
        pytest.fail("KeyboardInterrupt escaped Engine.investigate (Ctrl+C must stop the scan cleanly)")


def coverage_of(case: CaseResult, module: str, ent: Entity | str) -> dict[str, Any]:
    """The coverage row of (module, entity), {} when the pair was never recorded."""
    key = ent.key if isinstance(ent, Entity) else entity(ent).key
    return dict(case.coverage.get(module, {}).get("entities", {}).get(key) or {})


# --------------------------------------------------------------------------------------
# request ledger and socket layer recorders
# --------------------------------------------------------------------------------------


class Ledger:
    """Every RequestInfo the runtime's event bus carries (``http_request``): HTTP sends, DoH lookups,
    CONNECT and EXEC records - the request ledger of the run as wave 2 records it. ``hooks`` are
    called with each record in the emitting (worker) thread."""

    def __init__(self, rt: Any) -> None:
        self.records: list[Any] = []
        self.hooks: list[Callable[[Any], None]] = []
        self._lock = threading.Lock()
        rt.events.subscribe(self._listen)

    def _listen(self, kind: str, payload: dict[str, Any]) -> None:
        if kind != "http_request":
            return
        info = payload.get("info")
        with self._lock:
            self.records.append(info)
        for hook in list(self.hooks):
            hook(info)

    def to(self, host: str, *, method: str | None = None) -> list[Any]:
        with self._lock:
            return [r for r in self.records if str(getattr(r, "host", "")).lower() == host.lower() and (method is None or r.method == method)]

    def methods(self) -> list[str]:
        with self._lock:
            return [r.method for r in self.records]


class SocketSpy:
    """Records every name lookup and connection attempt at the socket layer (wrapping the test
    network guard, which still refuses anything but loopback)."""

    def __init__(self) -> None:
        self.lookups: list[str] = []
        self.connects: list[tuple[str, int]] = []
        self._lock = threading.Lock()

    def _lookup(self, host: Any) -> None:
        with self._lock:
            self.lookups.append(str(host.decode() if isinstance(host, bytes) else host).lower())

    def _connect(self, address: Any) -> None:
        if isinstance(address, (tuple, list)) and len(address) >= 2:
            with self._lock:
                self.connects.append((str(address[0]).lower(), int(address[1])))


@pytest.fixture()
def socket_spy(monkeypatch: pytest.MonkeyPatch) -> SocketSpy:
    """A :class:`SocketSpy` over ``socket.getaddrinfo`` / ``gethostbyname`` / ``create_connection``
    and ``socket.socket.connect`` / ``connect_ex`` (installed on top of the network guard)."""
    spy = SocketSpy()
    real_getaddrinfo = socket.getaddrinfo
    real_gethostbyname = socket.gethostbyname
    real_create_connection = socket.create_connection
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex

    def getaddrinfo(host, *args, **kwargs):  # noqa: ANN001, ANN202 - socket signature
        spy._lookup(host)
        return real_getaddrinfo(host, *args, **kwargs)

    def gethostbyname(host):  # noqa: ANN001, ANN202
        spy._lookup(host)
        return real_gethostbyname(host)

    def create_connection(address, *args, **kwargs):  # noqa: ANN001, ANN202
        spy._connect(address)
        return real_create_connection(address, *args, **kwargs)

    def connect(self, address):  # noqa: ANN001, ANN202
        spy._connect(address)
        return real_connect(self, address)

    def connect_ex(self, address):  # noqa: ANN001, ANN202
        spy._connect(address)
        return real_connect_ex(self, address)

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(socket, "gethostbyname", gethostbyname)
    monkeypatch.setattr(socket, "create_connection", create_connection)
    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    return spy


# --------------------------------------------------------------------------------------
# kill switch helpers (Ctrl+C, scan deadline, end of the scope window)
# --------------------------------------------------------------------------------------


def interrupt_engine_when(monkeypatch: pytest.MonkeyPatch, condition: Callable[[], bool]) -> None:
    """Simulate Ctrl+C: once ``condition()`` holds, the engine's main loop receives KeyboardInterrupt
    exactly where a SIGINT lands while it waits for module results (``Engine.investigate`` turns it
    into the kill switch, A7). Deterministic: no real signal is raised."""
    real_wait = engine_mod.wait

    def wait(fs: Any, timeout: float | None = None, return_when: Any = engine_mod.FIRST_COMPLETED) -> Any:
        if condition():
            raise KeyboardInterrupt
        return real_wait(fs, timeout=timeout, return_when=return_when)

    monkeypatch.setattr(engine_mod, "wait", wait)


class KillSwitchProbe:
    """Wraps ``Runtime.cancel`` (the kill switch every stop path fires): records the first firing's
    wall-clock time, reason and the value of ``counter()`` at that moment."""

    def __init__(self, rt: Any, counter: Callable[[], int]) -> None:
        self.fired = threading.Event()
        self.at: float | None = None
        self.count_at: int | None = None
        self.reason = ""
        original = rt.cancel

        def cancel(reason: str = "cancelled") -> None:
            if not self.fired.is_set():
                self.at = time.monotonic()
                self.count_at = counter()
                self.reason = reason
                self.fired.set()
            original(reason)

        rt.cancel = cancel


def hold_until_cancelled(rt: Any, *, limit: float = 2.0) -> bool:
    """Block the calling (worker) thread until the runtime's kill switch fires (at most ``limit``
    seconds): a target that is slow to answer while the engine decides to stop."""
    return bool(rt.cancel_event.wait(limit))


# --------------------------------------------------------------------------------------
# loopback servers (real sockets on the system clock: the "within 2 s" checks)
# --------------------------------------------------------------------------------------


def free_port() -> int:
    """A loopback TCP port nothing listens on (the socket is closed again)."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class LoopbackServer:
    """An HTTP server on 127.0.0.1 that records every request (method, path, headers, arrival time).

    From request number ``stall_from`` on (1-based; None = never) it sends the headers and the first
    bytes of a large body, then stalls until the test ends: a slow-drip or silent target that only
    the kill switch can cut off."""

    def __init__(self, *, stall_from: int | None = None) -> None:
        self.stall_from = stall_from
        self.release = threading.Event()
        self.requests: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: Any) -> None:  # silence
                pass

            def _serve(self) -> None:
                with owner._lock:
                    owner.requests.append({"method": self.command, "path": self.path, "headers": dict(self.headers.items()), "at": time.monotonic()})
                    number = len(owner.requests)
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                if owner.stall_from is not None and number >= owner.stall_from:
                    self.send_response(200)
                    self.send_header("Content-Length", "1000000")
                    self.end_headers()
                    self.wfile.write(b"x" * 16)
                    self.wfile.flush()
                    owner.release.wait(10)
                    self.close_connection = True
                    return
                body = b"ok"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            do_GET = do_HEAD = do_OPTIONS = do_POST = do_PUT = do_DELETE = do_PATCH = _serve  # noqa: N815

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    @property
    def count(self) -> int:
        with self._lock:
            return len(self.requests)

    def url(self, path: str = "/") -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def close(self) -> None:
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


@pytest.fixture()
def loopback() -> Iterator[Callable[..., LoopbackServer]]:
    """Factory of :class:`LoopbackServer` instances, all shut down after the test."""
    servers: list[LoopbackServer] = []

    def make(**kw: Any) -> LoopbackServer:
        srv = LoopbackServer(**kw)
        servers.append(srv)
        return srv

    yield make
    for srv in servers:
        srv.close()


class SafetySocks5:
    """A minimal SOCKS5 proxy on loopback (no authentication) standing for proxy_light/proxy_active.

    Records every CONNECT (address type 'name'/'ipv4'/'ipv6', address, port) and the first bytes of
    the request tunnelled through it, then answers that request with HTTP 200 'via-proxy' (a
    socks5h client sends target names, never addresses it resolved itself). Modelled on
    ``tests/test_egress.py::FakeSocks5`` (WP11), with the tunnelled bytes kept for header checks."""

    def __init__(self) -> None:
        self.connects: list[tuple[str, str, int]] = []
        self.payloads: list[bytes] = []
        self._lock = threading.Lock()
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.srv.settimeout(0.05)
        self.port = int(self.srv.getsockname()[1])
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"socks5h://127.0.0.1:{self.port}"

    @staticmethod
    def _recv(conn: socket.socket, n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = conn.recv(n - len(data))
            if not chunk:
                raise OSError("closed")
            data += chunk
        return data

    def _serve(self) -> None:
        while not self.stop.is_set():
            try:
                conn, _ = self.srv.accept()
            except (TimeoutError, OSError):
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        with conn:
            try:
                conn.settimeout(2)
                _ver, nmethods = self._recv(conn, 2)
                self._recv(conn, nmethods)
                conn.sendall(b"\x05\x00")
                _ver, _cmd, _rsv, atyp = self._recv(conn, 4)
                if atyp == 1:
                    addr, kind = socket.inet_ntoa(self._recv(conn, 4)), "ipv4"
                elif atyp == 4:
                    addr, kind = socket.inet_ntop(socket.AF_INET6, self._recv(conn, 16)), "ipv6"
                else:
                    addr, kind = self._recv(conn, self._recv(conn, 1)[0]).decode(), "name"
                port = int.from_bytes(self._recv(conn, 2), "big")
                with self._lock:
                    self.connects.append((kind, addr, port))
                conn.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
                payload = conn.recv(8192)
                with self._lock:
                    self.payloads.append(payload)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 9\r\nConnection: close\r\n\r\nvia-proxy")
            except OSError:
                return

    def close(self) -> None:
        self.stop.set()
        self.srv.close()
        self.thread.join(timeout=2)


@pytest.fixture()
def socks_proxy() -> Iterator[SafetySocks5]:
    server = SafetySocks5()
    try:
        yield server
    finally:
        server.close()
