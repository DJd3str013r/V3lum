"""AR20 (d) - the kill switch (A7, AR05): Ctrl+C, the scan deadline and the end of the scope window
stop a 100-request loop after at most one more request, and all target traffic stops within 2 s.

Two layers of evidence:

* deterministic runs over ``FakeHttp`` and a ``FakeClock`` - the target request in flight is held
  until the engine fires the kill switch, so "at most one more request" is checked exactly;
* real loopback targets on the system clock - a target that stalls in the middle of a response
  body (only the kill switch can cut it off) must release the run within 2 s; raw sockets left open
  by a probe are shut down within 2 s as well.

Ctrl+C is simulated where a SIGINT lands in the engine: a KeyboardInterrupt in its main loop while
it waits for module results (``interrupt_engine_when``); ``Runtime.cancel`` is the kill switch every
stop path fires (``KillSwitchProbe`` time-stamps it).
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import socket
import threading
import time

import pytest

from tests.fakes import make_runtime
from tests.safety.conftest import (
    IN_SCOPE_HOST,
    IN_SCOPE_IP,
    KillSwitchProbe,
    Ledger,
    TrackingHttp,
    active_module,
    active_options,
    calls_to,
    coverage_of,
    dns,
    free_port,
    hold_until_cancelled,
    host_of,
    interrupt_engine_when,
    scan,
)
from v3lum.core.clock import SYSTEM_CLOCK
from v3lum.core.http import RequestsTransport

pytestmark = pytest.mark.safety

SEED = f"domain:{IN_SCOPE_HOST}"
LOOPS = 100
HELD_AT = 3  # the request during which the stop happens
KILL_WITHIN = 2.0  # A7: all target traffic stops within 2 s


def request_loop(finished: threading.Event, url_for, *, n: int = LOOPS, stats: dict | None = None):
    """run(): n GETs to the target (a crawler or a wordlist probe); ``finished`` is set however the
    run ends, with the wall-clock time in ``stats['finished_at']``."""

    def run(self, ent, ctx):
        try:
            for i in range(n):
                ctx.http.get(url_for(i))
            return self.result(ent)
        finally:
            if stats is not None:
                stats["finished_at"] = time.monotonic()
            finished.set()

    return run


def stopped_row_ok(row: dict, code: str, stop: str) -> bool:
    """A run interrupted by the stop is recorded SKIPPED with the stop's code (its late result is
    dropped) or, when it was merged before the scan closed, as a partial run with that stop reason."""
    if row.get("status") == "skipped":
        return row.get("reason_code") == code
    return bool(row.get("partial")) and row.get("stop_reason") == stop


def target_count(http) -> int:
    return len(calls_to(http, IN_SCOPE_HOST))


def held_at(http, k: int, action) -> None:
    """Hook: after the k-th request to the target, run ``action`` in the sending thread."""
    seen = {"n": 0}
    lock = threading.Lock()

    def hook(method: str, url: str) -> None:
        if host_of(url) != IN_SCOPE_HOST:  # DoH lookups of the name are not target requests
            return
        with lock:
            seen["n"] += 1
            fire = seen["n"] == k
        if fire:
            action()

    http.hooks.append(hook)


# --------------------------------------------------------------------------------------
# deterministic: FakeHttp + FakeClock
# --------------------------------------------------------------------------------------


@pytest.fixture()
def looping(registry, http, scope_file):
    """An ACTIVE scan of a 100-request loop against an in-scope target (built lazily per test)."""
    dns(http, IN_SCOPE_HOST, a=[IN_SCOPE_IP])
    http.add("GET", f"https://{IN_SCOPE_HOST}/item/*", text="item")
    finished = threading.Event()
    stats: dict = {}
    active_module("t_safety_loop", request_loop(finished, lambda i: f"https://{IN_SCOPE_HOST}/item/{i}", stats=stats))
    return finished, stats


def test_ctrl_c_stops_a_100_request_loop_after_at_most_one_more_request(looping, http, scope_file, monkeypatch):
    finished, stats = looping
    rt = make_runtime(http)
    reached = threading.Event()
    held_at(http, HELD_AT, lambda: (reached.set(), hold_until_cancelled(rt)))
    interrupt_engine_when(monkeypatch, reached.is_set)
    probe = KillSwitchProbe(rt, lambda: target_count(http))
    case = scan(rt, active_options(scope_file(), {"t_safety_loop"}), SEED)
    assert finished.wait(KILL_WITHIN), "the 100-request loop kept running after Ctrl+C"
    assert probe.fired.is_set() and probe.reason == "cancelled"
    assert probe.count_at == HELD_AT
    assert target_count(http) <= probe.count_at + 1  # at most the request in flight
    assert stats["finished_at"] - probe.at < KILL_WITHIN
    assert case.partial == {"cancelled": True} and case.interrupted
    assert any("Ctrl+C" in n for n in case.notes)
    assert stopped_row_ok(coverage_of(case, "t_safety_loop", SEED), "deadline", "cancelled")


def test_the_kill_switch_from_another_thread_stops_the_loop(looping, http, scope_file):
    """Runtime.cancel - what a signal handler, the shell or any other component calls - refuses every
    new target request at once."""
    finished, _stats = looping
    rt = make_runtime(http)
    held_at(http, HELD_AT, lambda: rt.cancel("cancelled"))
    probe = KillSwitchProbe(rt, lambda: target_count(http))
    case = scan(rt, active_options(scope_file(), {"t_safety_loop"}), SEED)
    assert finished.wait(KILL_WITHIN)
    assert probe.count_at == HELD_AT and target_count(http) == HELD_AT  # nothing after the flag
    assert case.partial == {"cancelled": True}


def test_the_scan_deadline_stops_the_loop(looping, http, scope_file, clock):
    finished, stats = looping
    rt = make_runtime(http)
    held_at(http, HELD_AT, lambda: (clock.advance(31.0), hold_until_cancelled(rt)))  # the target is slow: 31 s pass
    probe = KillSwitchProbe(rt, lambda: target_count(http))
    case = scan(rt, active_options(scope_file(), {"t_safety_loop"}, timeout_total=30.0), SEED)
    assert finished.wait(KILL_WITHIN)
    assert probe.reason == "deadline" and probe.count_at == HELD_AT
    assert target_count(http) <= probe.count_at + 1
    assert stats["finished_at"] - probe.at < KILL_WITHIN
    assert case.partial == {"deadline": True}
    assert any("scan deadline" in n for n in case.notes)
    assert stopped_row_ok(coverage_of(case, "t_safety_loop", SEED), "deadline", "cancelled")


def test_the_end_of_the_scope_window_stops_the_loop(looping, http, scope_file, clock):
    """At or after window_end the HTTP client refuses new target requests by itself and the engine
    fires the kill switch ('window'): the loop stops at the request in flight."""
    finished, _stats = looping
    rt = make_runtime(http)
    held_at(http, HELD_AT, lambda: clock.advance(10.0))  # the window ends while request 3 is answered
    probe = KillSwitchProbe(rt, lambda: target_count(http))
    scope = scope_file(window_start="2026-11-26T11:00:00Z", window_end="2026-11-26T12:00:05Z")
    case = scan(rt, active_options(scope, {"t_safety_loop"}), SEED)
    assert finished.wait(KILL_WITHIN)
    assert target_count(http) == HELD_AT  # nothing was sent after the window closed
    assert probe.fired.is_set() and "window" in probe.reason
    assert case.partial == {"window": True}
    assert any("engagement window ended" in n for n in case.notes)


def concurrent_loops(http, names: list[str], *, n: int = 20) -> list[str]:
    """Register one ACTIVE n-request loop per name (each on its own paths of the target)."""
    finished: list[str] = []
    lock = threading.Lock()

    def loop(name: str):
        def run(self, ent, ctx):
            try:
                for i in range(n):
                    ctx.http.get(f"https://{IN_SCOPE_HOST}/item/{name}-{i}")
                return self.result(ent)
            finally:
                with lock:
                    finished.append(name)

        return run

    for name in names:
        active_module(name, loop(name))
    return finished


def test_the_kill_switch_stops_concurrent_modules_after_at_most_one_more_request(registry, http, scope_file):
    """Two ACTIVE modules hammer the same host from two worker threads (both connection slots of the
    host in use): once the kill switch fires, at most the one other request in flight completes.
    (More modules than slots queue for a slot: that case is the strict xfail below.)"""
    dns(http, IN_SCOPE_HOST, a=[IN_SCOPE_IP])
    http.add("GET", f"https://{IN_SCOPE_HOST}/item/*", text="item")
    names = [f"t_safety_conc_kill_{i}" for i in range(2)]
    concurrent_loops(http, names, n=50)
    rt = make_runtime(http)
    held_at(http, 10, lambda: rt.cancel("cancelled"))
    probe = KillSwitchProbe(rt, lambda: target_count(http))
    case = scan(rt, active_options(scope_file(), set(names), threads=8), SEED)
    assert probe.fired.is_set() and probe.count_at in (10, 11)  # the other thread may have sent between the 10th send and the flag
    assert target_count(http) <= probe.count_at + 1
    assert case.partial == {"cancelled": True}
    for name in names:  # every run is recorded as stopped, none as a complete answer
        assert stopped_row_ok(coverage_of(case, name, SEED), "deadline", "cancelled"), (name, coverage_of(case, name, SEED))


@pytest.mark.xfail(
    strict=True,
    reason="WP11 http.py: HttpClient._send does not re-check the kill switch after it obtains a per-host connection slot, so "
    "requests queued for a slot are sent after Ctrl+C (A7) - see the WP28 report open_issues",
)
def test_requests_queued_for_a_connection_slot_never_leave_after_the_kill_switch(registry, scope_file, clock, monkeypatch):
    """Two requests hold the two connection slots of the host while two more modules queue for a
    slot; the kill switch fires and the held requests finish. The queued requests are new target
    requests: they must be refused, never sent once a slot frees up."""
    after: list[str] = []
    box: dict = {}

    class Recording(TrackingHttp):
        def send(self, method, url, **kw):
            if host_of(url) == IN_SCOPE_HOST and box["rt"].cancel_event.is_set():
                after.append(url)  # a send that started after the kill switch fired
            return super().send(method, url, **kw)

    http = Recording(clock=clock)
    dns(http, IN_SCOPE_HOST, a=[IN_SCOPE_IP])
    http.add("GET", f"https://{IN_SCOPE_HOST}/item/*", text="item")
    names = [f"t_safety_queued_{i}" for i in range(4)]
    concurrent_loops(http, names)
    rt = make_runtime(http)
    box["rt"] = rt
    lock = threading.Lock()
    queued = {"n": 0}
    all_queued = threading.Event()
    real_acquire = rt.http.limiter.acquire

    @contextlib.contextmanager
    def acquire(key, *args, **kw):
        if str(key) == IN_SCOPE_HOST:  # the first slot pool every request to the host passes
            with lock:
                queued["n"] += 1
                if queued["n"] >= len(names):
                    all_queued.set()
        with real_acquire(key, *args, **kw):
            yield

    monkeypatch.setattr(rt.http.limiter, "acquire", acquire)
    entered: list[str] = []
    release = threading.Event()

    def hook(method: str, url: str) -> None:
        if host_of(url) != IN_SCOPE_HOST:
            return
        with lock:
            entered.append(url)
            number = len(entered)
        if number == 1:
            release.wait(KILL_WITHIN)  # holds its slot until the kill switch fired
        elif number == 2:
            all_queued.wait(KILL_WITHIN)  # the other two modules are past their checks, queued for a slot
            rt.cancel("cancelled")
            release.set()

    http.hooks.append(hook)
    scan(rt, active_options(scope_file(), set(names), threads=8), SEED)
    assert all_queued.is_set(), "the scenario did not build up (the modules never queued for a slot)"
    assert after == [], f"sent after the kill switch: {after}"


def test_the_kill_switch_stops_a_100_connection_probe_loop(registry, scope_file, monkeypatch, clock):
    """Raw sockets (port probes) obey the same kill switch: at most one more connection attempt."""
    closed = free_port()  # nothing listens: every attempt is refused at once
    finished = threading.Event()

    def probe_loop(self, ent, ctx):
        try:
            for _ in range(LOOPS):
                try:
                    ctx.net.connect("127.0.0.1", closed, timeout=1).close()
                except OSError:
                    continue
            return self.result(ent)
        finally:
            finished.set()

    active_module("t_safety_ports", probe_loop, accepts=("ipv4",))
    rt = make_runtime(clock=clock)
    ledger = Ledger(rt)
    reached = threading.Event()

    def on_record(info) -> None:
        if getattr(info, "method", "") == "CONNECT" and len(ledger.to("127.0.0.1", method="CONNECT")) == HELD_AT:
            reached.set()
            hold_until_cancelled(rt)

    ledger.hooks.append(on_record)
    interrupt_engine_when(monkeypatch, reached.is_set)
    probe = KillSwitchProbe(rt, lambda: len(ledger.to("127.0.0.1", method="CONNECT")))
    scope = scope_file(targets={"domains": ["acme.example"], "cidrs": ["127.0.0.1/32"]})
    case = scan(rt, active_options(scope, {"t_safety_ports"}), "ipv4:127.0.0.1")
    assert finished.wait(KILL_WITHIN)
    assert probe.count_at == HELD_AT
    assert len(ledger.to("127.0.0.1", method="CONNECT")) <= probe.count_at + 1
    assert case.partial == {"cancelled": True}


# --------------------------------------------------------------------------------------
# real loopback targets: all target traffic stops within 2 s
# --------------------------------------------------------------------------------------


def loopback_scope(scope_file, **changes):
    changes.setdefault("targets", {"domains": ["acme.example"], "cidrs": ["127.0.0.1/32"]})
    return scope_file(**changes)


def real_runtime():
    return make_runtime(RequestsTransport(trust_env=False), clock=SYSTEM_CLOCK)


def real_window(seconds: float) -> dict[str, str]:
    now = _dt.datetime.now(_dt.timezone.utc)
    return {"window_start": (now - _dt.timedelta(hours=1)).isoformat(), "window_end": (now + _dt.timedelta(seconds=seconds)).isoformat()}


def stalled_scan(registry, loopback, scope_file, monkeypatch, *, stop: str):
    """An ACTIVE 100-request loop against a loopback target that stalls in the body of its 3rd
    response; ``stop`` = 'ctrl_c' | 'deadline' | 'window'. Returns (server, probe, stats, finished, case)."""
    srv = loopback(stall_from=HELD_AT)
    finished = threading.Event()
    stats: dict = {}
    active_module("t_safety_stalled", request_loop(finished, lambda i: srv.url(f"/item/{i}"), stats=stats), accepts=("url",))
    rt = real_runtime()
    probe = KillSwitchProbe(rt, lambda: srv.count)
    # the deadline / window end come ~1 s in: requests 1-2 are answered and the 3rd stalls well before
    window = real_window(1.0) if stop == "window" else real_window(3600)
    scope = loopback_scope(scope_file, **window)
    kw = {"timeout_total": 1.0} if stop == "deadline" else {}
    if stop == "ctrl_c":
        interrupt_engine_when(monkeypatch, lambda: srv.count >= HELD_AT)
    case = scan(rt, active_options(scope, {"t_safety_stalled"}, **kw), f"url:{srv.url('/')}")
    return srv, probe, stats, finished, case


@pytest.mark.parametrize(("stop", "reason", "partial"), [("ctrl_c", "cancelled", "cancelled"), ("deadline", "deadline", "deadline"), ("window", "window", "window")])
def test_a_stalled_target_is_cut_off_within_two_seconds(registry, loopback, scope_file, monkeypatch, stop, reason, partial):
    srv, probe, stats, finished, case = stalled_scan(registry, loopback, scope_file, monkeypatch, stop=stop)
    assert probe.fired.wait(KILL_WITHIN), "the kill switch never fired"
    assert finished.wait(KILL_WITHIN), "the run was still reading the stalled response 2 s after the kill switch"
    assert reason in probe.reason
    assert stats["finished_at"] - probe.at < KILL_WITHIN
    assert srv.count <= probe.count_at + 1  # at most one more request reached the target
    assert srv.count >= 1  # the loop was under way (normally requests 1-2 answered and the 3rd stalled)
    assert case.partial == {partial: True}
    if stop == "window":
        end = probe.at
        assert sum(1 for r in srv.requests if r["at"] > end) <= 1


def test_open_probe_sockets_are_shut_down_within_two_seconds(registry, scope_file, monkeypatch):
    """A probe blocked on a silent service (an open socket) is released by the kill switch: the
    connector shuts every open socket of the run down within 2 s."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    accepted: list[socket.socket] = []
    stop_accepting = threading.Event()

    def accept() -> None:
        listener.settimeout(0.05)
        while not stop_accepting.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                continue
            accepted.append(conn)  # never answers: a silent service

    acceptor = threading.Thread(target=accept, daemon=True)
    acceptor.start()
    port = listener.getsockname()[1]
    connected = threading.Event()
    finished = threading.Event()
    stats: dict = {}

    def banner_grab(self, ent, ctx):
        try:
            sock = ctx.net.connect("127.0.0.1", port, timeout=10)
            connected.set()
            try:
                sock.recv(1)  # blocks: the service never sends a banner
            except OSError:
                pass
            return self.result(ent)
        finally:
            stats["finished_at"] = time.monotonic()
            finished.set()

    active_module("t_safety_banner", banner_grab, accepts=("ipv4",))
    rt = make_runtime(clock=SYSTEM_CLOCK)
    probe = KillSwitchProbe(rt, lambda: 0)
    interrupt_engine_when(monkeypatch, connected.is_set)
    try:
        scope = loopback_scope(scope_file, **real_window(3600))
        case = scan(rt, active_options(scope, {"t_safety_banner"}), "ipv4:127.0.0.1")
        assert finished.wait(KILL_WITHIN), "the probe socket stayed open after the kill switch"
        assert stats["finished_at"] - probe.at < KILL_WITHIN
        assert case.partial == {"cancelled": True}
    finally:
        stop_accepting.set()
        acceptor.join(timeout=2)
        for conn in accepted:
            conn.close()
        listener.close()
