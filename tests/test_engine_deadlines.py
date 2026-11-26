"""AR05/A7: run deadlines, the scan deadline and the kill switch (fake clock, fake transport).

* a run past ``Module.timeout`` (+1 s grace) ends ERROR 'timeout' and its findings, pivots and
  evidence are dropped (also when the run hangs: the engine stops waiting for it);
* the scan deadline (``timeout_total``, else setting ``scan_deadline``; 0 = unlimited) cancels the
  runtime, stops scheduling, records every unfinished (module, entity) SKIPPED 'deadline' and marks
  the case partial with a note; results arriving later are dropped (no merge, no evidence);
* Ctrl+C and the end of the scope window set the same kill switch; target traffic stops at once
  (a 100-request loop sends at most one more request after the cancel).
"""

from __future__ import annotations

import threading
import time
from datetime import timedelta
from pathlib import Path

import pytest

from tests.fakes import FakeClock, FakeHttp, allow_vocab, define_module, make_runtime, source_ids, test_provider
from v3lum.core import engine as engine_mod
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status

SEED = Entity.make("domain", "example.org")


@pytest.fixture()
def registry(clean_registry):
    clean_registry.clear()  # only the synthetic modules of the test are candidates
    with allow_vocab(attributes=("ran",)):
        yield clean_registry


def _hostile_finding(res):
    res.finding("found something", "high", tags=["malicious"], criterion="synthetic verdict")


def test_overdue_run_ends_error_timeout_and_drops_its_results(registry):
    def slow(self, entity, ctx):
        res = self.result(entity)
        _hostile_finding(res)
        res.pivot(T.IPV4, "45.33.32.9", "resolves_to")
        res.raw = {"late": True}
        ctx.runtime.clock.advance(10)  # the run takes 10 s: timeout 5 s + 1 s grace
        return res

    def in_grace(self, entity, ctx):
        res = self.result(entity)
        res.attr("ran", True)
        ctx.runtime.clock.advance(5.5)  # within the grace second: kept
        return res

    define_module("t_slow", [T.DOMAIN], slow, timeout=5.0)
    define_module("t_in_grace", [T.DOMAIN], in_grace, timeout=5.0)
    rt = make_runtime(FakeHttp(), clock=FakeClock())
    case = Engine(rt, ScanOptions(include={"t_slow", "t_in_grace"}, threads=1)).investigate([SEED])
    by = {r.module: r for r in case.results}
    late = by["t_slow"]
    assert (late.status, late.reason_code) == (Status.ERROR, "timeout") and "deadline" in late.error
    assert not late.findings and not late.pivots and late.raw is None and not late.evidence
    assert not any(f.module == "t_slow" for f in case.graph.findings())
    assert case.graph.get(Entity.make("ipv4", "45.33.32.9")) is None
    assert (case.coverage["t_slow"]["status"], case.coverage["t_slow"]["reason_code"]) == ("error", "timeout")
    assert next(r for r in case.execution if r["module"] == "t_slow")["outcome"] == "failed"
    assert by["t_in_grace"].status is Status.OK and case.graph.get(SEED).attr("ran") is True
    assert not case.partial  # a run timeout is not a partial case


def test_a_hung_run_is_timed_out_by_the_engine_and_its_late_result_dropped(registry):
    release, exited = threading.Event(), threading.Event()

    def hung(self, entity, ctx):
        try:
            res = self.result(entity)
            _hostile_finding(res)
            ctx.runtime.clock.advance(10)  # past 5 s + 1 s grace, then the run hangs
            release.wait(5)
            return res
        finally:
            exited.set()

    def quick(self, entity, ctx):
        res = self.result(entity)
        res.attr("ran", True)
        return res

    define_module("t_hung", [T.DOMAIN], hung, timeout=5.0)
    define_module("t_quick", [T.DOMAIN], quick)
    rt = make_runtime(FakeHttp(), clock=FakeClock())
    started = time.monotonic()
    try:
        case = Engine(rt, ScanOptions(include={"t_hung", "t_quick"})).investigate([SEED])
        waited = time.monotonic() - started
    finally:
        release.set()
    assert exited.wait(5)
    assert waited < 4  # the engine did not wait for the hung run
    by = {r.module: r for r in case.results}
    assert (by["t_hung"].status, by["t_hung"].reason_code) == (Status.ERROR, "timeout")
    assert by["t_quick"].status is Status.OK
    assert not case.graph.findings()  # the late result never merged
    assert len([r for r in case.results if r.module == "t_hung"]) == 1


def _deadline_modules():
    def first(self, entity, ctx):
        res = self.result(entity)
        res.attr("ran", True)
        res.pivot(T.IPV4, "45.33.32.7", "resolves_to")
        return res

    def second(self, entity, ctx):
        res = self.result(entity)
        res.attr("ran", True)
        return res

    define_module("t_dl_first", [T.DOMAIN], first)
    define_module("t_dl_ip", [T.IPV4], second)


def _advance_on_new_entity(rt, seconds: float) -> None:
    """Advance the fake clock when the first module's pivot reaches the graph (engine thread, before
    the pivot is scheduled): deterministic 'time passed while the seed was investigated'."""

    def listener(kind, payload):
        if kind == "entity":
            rt.clock.advance(seconds)

    rt.events.subscribe(listener)


@pytest.mark.parametrize(("settings", "total"), [({}, 30.0), ({"scan_deadline": 30}, 0.0), ({"scan_deadline": 1000}, 30.0)])
def test_scan_deadline_ends_a_partial_case(registry, settings, total):
    _deadline_modules()
    rt = make_runtime(FakeHttp(), clock=FakeClock(), settings=settings)
    _advance_on_new_entity(rt, 31)
    case = Engine(rt, ScanOptions(include={"t_dl_first", "t_dl_ip"}, timeout_total=total)).investigate([SEED])
    assert case.partial == {"deadline": True} and case.interrupted
    assert rt.cancel_event.is_set() and rt.cancel_reason == "deadline"
    assert [r.module for r in case.results] == ["t_dl_first"]  # back before the deadline: kept
    cov = case.coverage["t_dl_ip"]
    assert (cov["status"], cov["reason_code"]) == ("skipped", "deadline") and cov["runs"] == 0
    assert "before it ran: not run" in cov["reason"]  # never started: its value was never sent
    row = next(r for r in case.execution if r["module"] == "t_dl_ip")
    assert (row["status"], row["reason_code"], row["outcome"], row["entity"]) == ("skipped", "deadline", "skipped", "ipv4:45.33.32.7")
    assert case.skips["deadline"] == ["t_dl_ip"]
    assert any("deadline" in n and "partial results" in n and "1 pending" in n for n in case.notes)
    d = case.to_dict()
    assert d["partial"] == {"deadline": True} and d["summary"]["partial"] is True


def test_scan_deadline_zero_is_unlimited(registry):
    _deadline_modules()
    rt = make_runtime(FakeHttp(), clock=FakeClock(), settings={"scan_deadline": 0})
    _advance_on_new_entity(rt, 100_000)
    case = Engine(rt, ScanOptions(include={"t_dl_first", "t_dl_ip"})).investigate([SEED])
    assert not case.partial and not rt.cancel_event.is_set()
    assert {r.module for r in case.results} == {"t_dl_first", "t_dl_ip"}


def test_results_arriving_after_finish_are_dropped(registry):
    release, exited = threading.Event(), threading.Event()

    def late(self, entity, ctx):
        try:
            ctx.runtime.clock.advance(31)  # past the 30 s scan deadline (not past its own timeout)
            release.wait(5)
            res = self.result(entity)
            _hostile_finding(res)
            res.pivot(T.IPV4, "45.33.32.8", "resolves_to")
            res.raw = {"late": True}
            return res
        finally:
            exited.set()

    define_module("t_late", [T.DOMAIN], late, timeout=6000)
    rt = make_runtime(FakeHttp(), clock=FakeClock())
    try:
        case = Engine(rt, ScanOptions(include={"t_late"}, timeout_total=30)).investigate([SEED])
    finally:
        release.set()
    assert exited.wait(5)
    time.sleep(0.05)  # the worker finishes run_module (sanitizer, finalize) after the module returned
    assert case.partial == {"deadline": True}
    assert not case.results and not case.graph.findings()
    assert case.graph.get(Entity.make("ipv4", "45.33.32.8")) is None
    assert (case.coverage["t_late"]["status"], case.coverage["t_late"]["reason_code"]) == ("skipped", "deadline")
    # it had started (its value may have been sent): the reason says so, never 'not run' (rule 5)
    assert "while it ran: results dropped" in case.coverage["t_late"]["reason"]
    assert list((Path(case.case_dir) / "evidence").glob("*")) == []  # no late evidence file


def _loop_module(prov, exited: threading.Event, stopped_at: list[float]):
    def loop(self, entity, ctx):
        try:
            res = self.result(entity)
            for i in range(100):
                ctx.http.get(f"https://api.example.test/item/{i}")
                time.sleep(0.002)  # real time between requests: the engine loop gets to react
            res.attr("ran", True)
            return res
        finally:
            stopped_at.append(time.monotonic())
            exited.set()

    define_module(
        "t_loop", [T.DOMAIN], loop, disclosure="third_party", provider=prov.id, sources=source_ids(prov), hosts=prov.hosts,
        access_model="free_noauth_unlimited", max_requests=1000, default_enabled=False, timeout=6000,
    )


def _spy_cancel(rt, http, snapshot: list[tuple[int, float]]):
    real = rt.cancel

    def cancel(reason: str = "cancelled") -> None:
        with http._lock:  # no request can be recorded while the flag flips: an exact snapshot
            real(reason)
            snapshot.append((len(http.calls), time.monotonic()))

    rt.cancel = cancel


def test_ctrl_c_style_cancel_stops_a_100_request_loop(registry):
    """Acceptance: target traffic stops within 2 s of the cancel - here at most one more request."""
    exited, stopped_at, snapshot = threading.Event(), [], []
    with test_provider() as prov:
        _loop_module(prov, exited, stopped_at)
        http = FakeHttp().add("GET", "https://api.example.test/item/*", json={})
        rt = make_runtime(http, clock=FakeClock())
        _spy_cancel(rt, http, snapshot)

        def trigger() -> None:
            limit = time.monotonic() + 5
            while time.monotonic() < limit and len(http.calls) < 5:
                time.sleep(0.001)
            rt.cancel("cancelled")  # what the shell's Ctrl+C handler does from another thread

        thread = threading.Thread(target=trigger)
        thread.start()
        case = Engine(rt, ScanOptions(include={"t_loop"})).investigate([SEED])
        thread.join(5)
        assert exited.wait(5)
    sent, cancelled_at = snapshot[0]
    assert len(http.calls) - sent <= 1 and len(http.calls) < 100
    assert stopped_at[0] - cancelled_at < 2.0
    assert case.partial == {"cancelled": True} and rt.cancel_reason == "cancelled"
    assert case.coverage["t_loop"]["status"] in ("ok", "empty", "skipped")


def test_scan_deadline_kill_switch_stops_target_traffic(registry):
    exited, stopped_at, snapshot = threading.Event(), [], []
    with test_provider() as prov:
        _loop_module(prov, exited, stopped_at)
        http = FakeHttp().add("GET", "https://api.example.test/item/*", json={}, latency=1.0)  # 1 s of fake time each
        rt = make_runtime(http, clock=FakeClock())
        _spy_cancel(rt, http, snapshot)
        case = Engine(rt, ScanOptions(include={"t_loop"}, timeout_total=10.5)).investigate([SEED])
        assert exited.wait(5)
    sent, cancelled_at = snapshot[0]
    assert rt.cancel_reason == "deadline" and case.partial == {"deadline": True}
    assert len(http.calls) - sent <= 1 and len(http.calls) < 100
    assert stopped_at[0] - cancelled_at < 2.0


def test_keyboard_interrupt_cancels_with_partial_results(registry, monkeypatch):
    block = threading.Event()

    def slow(self, entity, ctx):
        block.wait(2)
        return self.result(entity)

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    define_module("t_ctrl_c", [T.DOMAIN], slow)
    monkeypatch.setattr(engine_mod, "wait", interrupted)
    rt = make_runtime(FakeHttp(), clock=FakeClock())
    try:
        case = Engine(rt, ScanOptions(include={"t_ctrl_c"})).investigate([SEED])
    finally:
        block.set()
    assert rt.cancel_reason == "cancelled" and case.partial == {"cancelled": True}
    cov = case.coverage["t_ctrl_c"]
    assert (cov["status"], cov["reason_code"]) == ("skipped", "deadline") and "cancelled" in cov["reason"]
    assert any("Ctrl+C" in n for n in case.notes)


class _Window:
    """Local stand-in for a loaded scope: only the engagement window matters here."""

    sha256 = "0" * 64

    def __init__(self, end):
        self.end = end

    def window_expired(self, now):
        return now >= self.end


def test_end_of_the_scope_window_stops_the_scan(registry):
    clock = FakeClock()
    _deadline_modules()
    rt = make_runtime(FakeHttp(), clock=clock, settings={"scan_deadline": 0})
    _advance_on_new_entity(rt, 3600)  # an hour passes: the window closes meanwhile
    scope = _Window(clock.now() + timedelta(minutes=30))
    case = Engine(rt, ScanOptions(include={"t_dl_first", "t_dl_ip"}, scope=scope)).investigate([SEED])
    assert rt.cancel_reason == "window" and case.partial == {"window": True}
    cov = case.coverage["t_dl_ip"]
    assert (cov["status"], cov["reason_code"]) == ("skipped", "scope") and "window" in cov["reason"]
    assert any("engagement window ended" in n for n in case.notes)


def test_each_scan_gets_a_fresh_kill_switch(registry):
    """A run abandoned by a stopped scan keeps the old (set) flag: a new scan on the same runtime
    never revives it, and the new scan starts with a clear flag."""
    _deadline_modules()
    rt = make_runtime(FakeHttp(), clock=FakeClock())
    _advance_on_new_entity(rt, 31)
    eng = Engine(rt, ScanOptions(include={"t_dl_first", "t_dl_ip"}, timeout_total=30))
    eng.investigate([SEED])
    old = rt.cancel_event
    assert old.is_set()
    eng.options.timeout_total = 0
    rt.config.settings["scan_deadline"] = 0
    case = eng.investigate([SEED])
    assert rt.cancel_event is not old and old.is_set() and not rt.cancel_event.is_set()
    assert not case.partial and {r.module for r in case.results} == {"t_dl_first", "t_dl_ip"}


def test_a_run_keeps_its_own_kill_switch(registry):
    """ctx.cancelled() follows the cancel flag the run was built with: a later scan of the same
    runtime installs a fresh flag, and a run that scan abandoned still reads cancelled."""
    define_module("t_ks", [T.DOMAIN], lambda self, e, c: self.result(e))
    rt = make_runtime(FakeHttp(), clock=FakeClock())
    cls = registry["t_ks"]
    old_ctx = rt.context(cls, ScanOptions())
    assert not old_ctx.cancelled()
    rt.cancel("deadline")
    assert old_ctx.cancelled()
    Engine(rt, ScanOptions(include={"t_ks"})).investigate([SEED])  # a new scan: a fresh, clear flag
    assert not rt.cancel_event.is_set() and old_ctx.cancelled() and old_ctx.http.cancel_event is old_ctx.cancel_event
    assert not rt.context(cls, ScanOptions()).cancelled()
