"""ScopedHttp (ctx.http): absent statuses, request cap, cancel, deadlines, host enforcement,
counters and request log, cache-key sink, quota protocol, evict/check, legacy clients."""

from __future__ import annotations

import datetime as dt
import threading
from typing import Any

import pytest

from tests.fixtures.http.stub_transport import StubClock, StubTransport, load, provider, registry
from v3lum.core.http import (
    Blocked,
    Cancelled,
    DeadlineExceeded,
    HttpCache,
    HttpClient,
    HttpError,
    PolicyError,
    QuotaExceeded,
    RequestCapReached,
    RequestInfo,
    Response,
    ScopedHttp,
)
from v3lum.core.models import Opsec


@pytest.fixture()
def cache(tmp_path):
    c = HttpCache(str(tmp_path / "cache.db"))
    yield c
    c.close()


def client_for(transport: StubTransport, cache: HttpCache | None = None, *, reg=None, clock=None, **kw) -> HttpClient:
    clock = clock or StubClock()
    transport.clock = clock
    kw.setdefault("retries", 0)
    return HttpClient(cache=cache, transport=transport, clock=clock, providers=reg if reg is not None else registry(), **kw)


# --------------------------------------------------------------------------------------
# absent statuses (P328 cond 5) and get_json
# --------------------------------------------------------------------------------------


def test_absent_statuses_and_ok404_alias(cache):
    t = StubTransport().add("GET", "https://api.example.test/missing", status=404, json={"detail": "No information available"})
    t.add("GET", "https://api.example.test/gone", status=410, text="gone")
    c = client_for(t, cache)
    assert ScopedHttp(c, absent_statuses={404}).get_json("https://api.example.test/missing") is None
    assert ScopedHttp(c).get_json("https://api.example.test/missing", ok404=True) is None
    assert ScopedHttp(c).get_json("https://api.example.test/gone", absent={410}) is None
    with pytest.raises(HttpError) as err:
        ScopedHttp(c).get_json("https://api.example.test/missing")
    assert err.value.status == 404


def test_a_classified_absent_status_is_never_absent():
    """A challenge page served with 404 raises Blocked even when 404 is a declared absence."""
    t = StubTransport().add("GET", "https://api.example.test/missing", status=404, body=load("cloudflare_challenge.html"), content_type="text/html")
    with pytest.raises(Blocked):
        ScopedHttp(client_for(t), absent_statuses={404}).get_json("https://api.example.test/missing")


def test_get_json_raises_per_classification(cache):
    marker = {"id": "api_count_exceeded", "regex": "API count exceeded", "maps_to": "quota", "reason": "HackerTarget: daily quota exhausted (API count exceeded)"}
    t = StubTransport().add("GET", "https://api.hackertarget.com/aslookup/?q=8.8.8.8", body=load("hackertarget_quota_exceeded.txt"), content_type="text/plain")
    scoped = ScopedHttp(client_for(t, cache), error_markers=(marker,))  # a module-declared marker
    with pytest.raises(QuotaExceeded) as err:
        scoped.get_json("https://api.hackertarget.com/aslookup/?q=8.8.8.8")
    assert err.value.reason_code == "quota"
    assert cache.stats()["entries"] == 0


def test_post_json(cache):
    t = StubTransport().add("POST", "https://api.example.test/graphql", json={"data": {"x": 1}})
    scoped = ScopedHttp(client_for(t, cache))
    assert scoped.post_json("https://api.example.test/graphql", json_body={"query": "{x}"}) == {"data": {"x": 1}}
    assert t.calls[0]["body"] == b'{"query": "{x}"}'
    assert t.header(0, "Content-Type") == "application/json"


# --------------------------------------------------------------------------------------
# request cap (A3), cancel and deadlines (AR05)
# --------------------------------------------------------------------------------------


def test_request_cap_counts_network_sends_only(cache):
    t = StubTransport().add("GET", "https://api.example.test/a", text="a").add("GET", "https://api.example.test/b", text="b")
    t.add("GET", "https://api.example.test/c", text="c")
    scoped = ScopedHttp(client_for(t, cache), module="t_cap", max_requests=2, ttl=3600)
    scoped.get("https://api.example.test/a")
    scoped.get("https://api.example.test/b")
    assert scoped.get("https://api.example.test/a").from_cache  # cache hits are free
    with pytest.raises(RequestCapReached) as err:
        scoped.get("https://api.example.test/c")
    assert err.value.stop_reason == "request_cap" and "t_cap" in str(err.value)
    assert scoped.requests == 2 and scoped.cache_hits == 1
    assert "https://api.example.test/c" not in t.urls()


def test_core_scope_is_not_capped(cache):
    t = StubTransport().add("GET", "https://dns.google/resolve*", json={"Status": 0, "Answer": []}, times=3)
    core = ScopedHttp(client_for(t, cache), core=True, max_requests=1)
    for i in range(3):
        core.get(f"https://dns.google/resolve?name=x{i}.example&type=A")
    assert core.requests == 3


def test_cancel_refuses_new_requests():
    t = StubTransport().add("GET", "https://api.example.test/x", text="x", times=5)
    cancel = threading.Event()
    scoped = ScopedHttp(client_for(t), cancel_event=cancel)
    scoped.get("https://api.example.test/x")
    cancel.set()
    with pytest.raises(Cancelled) as err:
        scoped.get("https://api.example.test/x")
    assert err.value.stop_reason == "cancelled"
    assert len(t.calls) == 1


def test_cancel_inside_the_client_stops_retries():
    clock = StubClock()
    cancel = threading.Event()
    t = StubTransport().add("GET", "https://api.example.test/x", status=503, text="busy", times=1)
    t.add("GET", "https://api.example.test/x", text="ok")

    class CancelOnSleep(StubClock):
        def sleep(self, seconds: float) -> None:
            cancel.set()
            super().sleep(seconds)

    clock = CancelOnSleep()
    c = client_for(t, clock=clock, retries=3)
    with pytest.raises(Cancelled):
        ScopedHttp(c, cancel_event=cancel, clock=clock).get("https://api.example.test/x")
    assert len(t.calls) == 1


def test_deadline_passed_before_sending():
    clock = StubClock()
    t = StubTransport().add("GET", "https://api.example.test/x", text="x")
    scoped = ScopedHttp(client_for(t, clock=clock), deadline=clock.monotonic() + 5, clock=clock)
    clock.advance(6)
    with pytest.raises(DeadlineExceeded) as err:
        scoped.get("https://api.example.test/x")
    assert err.value.reason_code == "timeout"
    assert t.calls == []


def test_deadline_caps_timeout_and_stops_slow_drip_servers():
    clock = StubClock()
    t = StubTransport().add("GET", "https://slow.example.test/drip", text="...", latency=30.0)
    scoped = ScopedHttp(client_for(t, clock=clock, timeout=20.0), deadline=clock.monotonic() + 4.0, clock=clock)
    with pytest.raises(DeadlineExceeded):
        scoped.get("https://slow.example.test/drip")
    assert t.calls[0]["timeout"] == pytest.approx(4.0)  # timeout = min(timeout, remaining)
    assert t.calls[0]["deadline"] == pytest.approx(1004.0)
    assert scoped.request_log[0].error == "DeadlineExceeded"


def test_retry_waits_never_pass_the_deadline():
    clock = StubClock()
    t = StubTransport().add("GET", "https://api.example.test/x", status=429, headers={"Retry-After": "10"}, text="slow down", times=2)
    t.add("GET", "https://api.example.test/x", text="ok")
    c = client_for(t, clock=clock, retries=1)
    resp = ScopedHttp(c, deadline=clock.monotonic() + 5.0, clock=clock).get("https://api.example.test/x")
    assert resp.status == 429 and len(t.calls) == 1  # waiting 10 s would overrun the 5 s left
    resp = ScopedHttp(c, deadline=clock.monotonic() + 60.0, clock=clock).get("https://api.example.test/x")
    assert resp.ok and clock.sleeps == [10.0] and len(t.calls) == 3


def test_long_retry_after_is_returned_not_waited():
    clock = StubClock()
    t = StubTransport().add("GET", "https://api.example.test/x", status=429, headers={"Retry-After": "120"}, text="slow down")
    resp = ScopedHttp(client_for(t, clock=clock, retries=2), clock=clock).get("https://api.example.test/x")
    assert resp.status == 429 and len(t.calls) == 1 and clock.sleeps == []


def test_a_challenge_or_403_is_never_retried():
    clock = StubClock()
    t = StubTransport().add("GET", "https://w.example.test/x", status=503, body=load("cloudflare_challenge.html"), content_type="text/html")
    t.add("GET", "https://f.example.test/x", status=403, text="forbidden")
    c = client_for(t, clock=clock, retries=3)
    assert c.request("GET", "https://w.example.test/x").classification.reason_code == "challenge"
    assert c.request("GET", "https://f.example.test/x").status == 403
    assert len(t.calls) == 2 and clock.sleeps == []


# --------------------------------------------------------------------------------------
# host enforcement (P327 cond 4-5, A8 BR9)
# --------------------------------------------------------------------------------------


def test_disclosure_none_gets_no_network():
    t = StubTransport()
    scoped = ScopedHttp(client_for(t), module="t_offline", disclosure="none", allowed_hosts=())
    with pytest.raises(PolicyError) as err:
        scoped.get("https://api.example.test/x")
    assert err.value.reason_code == "policy" and "offline module" in str(err.value)
    assert t.calls == []


@pytest.mark.parametrize("disclosure", ["third_party", "internal"])
def test_passive_modules_reach_only_declared_hosts(disclosure):
    t = StubTransport().add("GET", "https://api.example.test/x", text="ok").add("GET", "https://A.CDN.example.test/x", text="ok")
    scoped = ScopedHttp(client_for(t), module="t_hosts", disclosure=disclosure, allowed_hosts=("api.example.test", "*.cdn.example.test"))
    assert scoped.get("https://api.example.test/x").ok
    assert scoped.get("https://A.CDN.example.test/x").ok
    for url in ("https://cdn.example.test/x", "https://evil.example.test/x", "https://api.example.test.evil.test/x"):
        with pytest.raises(PolicyError) as err:
            scoped.get(url)
        assert err.value.reason_code == "policy"
    assert len(t.calls) == 2


def test_redirect_to_an_undeclared_host_is_refused():
    t = StubTransport().add("GET", "https://api.example.test/x", status=302, location="https://tracker.example.net/collect")
    scoped = ScopedHttp(client_for(t), module="t_hosts", allowed_hosts=("api.example.test",))
    with pytest.raises(PolicyError):
        scoped.get("https://api.example.test/x")
    assert t.urls() == ["https://api.example.test/x"]


def test_target_modules_and_unscoped_clients_are_not_host_checked():
    t = StubTransport().add("GET", "https://target.example.test/", text="ok", times=2)
    assert ScopedHttp(client_for(t), disclosure="target", opsec=Opsec.LIGHT, allowed_hosts=()).get("https://target.example.test/").ok
    assert ScopedHttp(client_for(t)).get("https://target.example.test/").ok


# --------------------------------------------------------------------------------------
# counters and request log
# --------------------------------------------------------------------------------------


def test_request_log_and_counters(cache):
    t = StubTransport().add("GET", "https://api.example.test/a?q=1", text="hello").add("GET", "https://other.example.test/b", status=302, location="https://api.example.test/c")
    t.add("GET", "https://api.example.test/c", text="world!")
    reg = registry(provider("demo_api", ("api.example.test", "other.example.test"), sources=("lookup",)))
    scoped = ScopedHttp(client_for(t, cache, reg=reg), ttl=3600, module="t_log", provider="demo_api", sources=("demo_api.lookup",), opsec="passive")
    scoped.get("https://api.example.test/a", params={"q": 1})
    scoped.get("https://api.example.test/a", params={"q": 1})
    scoped.get("https://other.example.test/b")
    assert scoped.requests == 2 and scoped.cache_hits == 1
    assert scoped.hosts == {"api.example.test": 2, "other.example.test": 1}
    assert scoped.bytes == len(b"hello") + len(b"world!")
    log = scoped.request_log
    assert all(isinstance(i, RequestInfo) for i in log) and len(log) == 4
    first = log[0]
    assert (first.method, first.url, first.host, first.path, first.status, first.bytes, first.cached) == ("GET", "https://api.example.test/a?q=1", "api.example.test", "/a?q=1", 200, 5, False)
    assert (first.module, first.provider, first.source, first.opsec, first.egress_profile, first.port) == ("t_log", "demo_api", "demo_api.lookup", "passive", "default", 443)
    assert log[1].cached and log[1].bytes == 5
    assert [i.status for i in log[2:]] == [302, 200]
    assert first.to_dict()["classification"] is None and first.ts.startswith("2026-11-26T12:00:00")


def test_on_request_info_and_on_request_events():
    infos: list[RequestInfo] = []
    legacy: list[tuple] = []
    t = StubTransport().add("GET", "https://api.example.test/x", status=403, text="nope")
    c = client_for(t, on_request_info=infos.append, on_request=lambda *a: legacy.append(a))
    ScopedHttp(c, module="t_events", keyless=True).get("https://api.example.test/x")
    assert len(infos) == 1 and infos[0].module == "t_events" and infos[0].classification.reason_code == "challenge"
    assert legacy == [("GET", "https://api.example.test/x", 403, 0.0, False, "")]


# --------------------------------------------------------------------------------------
# cache-key sink, evict, quota protocol, circuit
# --------------------------------------------------------------------------------------


def test_cache_key_sink_gets_written_and_served_keys(cache):
    keys: list[str] = []
    t = StubTransport().add("GET", "https://api.example.test/x", json={"a": 1}).add("GET", "https://api.example.test/denied", status=403, text="no")
    c = client_for(t, cache, cache_key_sink=keys.append)
    scoped = ScopedHttp(c)
    first = scoped.get("https://api.example.test/x")
    second = scoped.get("https://api.example.test/x")
    scoped.get("https://api.example.test/denied")  # never cached, never reported
    assert keys == [first.cache_key, second.cache_key] and len(set(keys)) == 1


def test_evict_drops_the_cache_row(cache):
    t = StubTransport().add("GET", "https://api.example.test/x", json={"a": 1}, times=2)
    scoped = ScopedHttp(client_for(t, cache))
    resp = scoped.get("https://api.example.test/x")
    assert scoped.evict(resp) and cache.stats()["entries"] == 0
    assert not scoped.get("https://api.example.test/x").from_cache
    assert len(t.calls) == 2
    assert not scoped.evict(Response(200, "https://api.example.test/y", {}, b""))  # never cached


class QuotaStub:
    def __init__(self, exhausted: bool = False) -> None:
        self.exhausted = exhausted
        self.reserved: list[tuple[str, str, str]] = []
        self.signals: list[tuple[str, str, Any]] = []

    def reserve(self, provider_id: str, host: str, *, priority: str = "seed") -> None:
        if self.exhausted:
            raise QuotaExceeded(f"{provider_id}: daily budget used")
        self.reserved.append((provider_id, host, priority))

    def signal(self, provider_id: str, *, kind: str, until: Any = None) -> None:
        self.signals.append((provider_id, kind, until))


def test_quota_reserved_before_sending_and_provider_signal_wins(cache):
    marker = {"id": "api_count_exceeded", "regex": "API count exceeded", "maps_to": "quota", "reason": "HackerTarget: daily quota exhausted (API count exceeded)"}
    reg = registry(provider("hackertarget", ("api.hackertarget.com",), name="HackerTarget", markers=(marker,)), provider("busy_api", ("busy.example.test",)))
    t = StubTransport().add("GET", "https://api.hackertarget.com/aslookup/?q=8.8.8.8", body=load("hackertarget_quota_exceeded.txt"), content_type="text/plain")
    t.add("GET", "https://busy.example.test/x", status=429, headers={"Retry-After": "30"}, text="slow down")
    quota = QuotaStub()
    clock = StubClock()
    c = client_for(t, cache, reg=reg, quota=quota, clock=clock)
    resp = ScopedHttp(c, priority="pivot").get("https://api.hackertarget.com/aslookup/?q=8.8.8.8")
    assert resp.classification.status == "quota"
    assert quota.reserved == [("hackertarget", "api.hackertarget.com", "pivot")]
    assert quota.signals == [("hackertarget", "quota", None)]
    ScopedHttp(c).get("https://busy.example.test/x")
    assert quota.signals[1][:2] == ("busy_api", "rate_limited")
    assert quota.signals[1][2] == clock.now() + dt.timedelta(seconds=30)


def test_exhausted_quota_sends_nothing_and_core_scope_is_never_charged():
    reg = registry(provider("demo_api", ("api.example.test",)), provider("google_doh", ("dns.google",)))
    t = StubTransport().add("GET", "https://dns.google/resolve?name=x&type=A", json={"Status": 0})
    quota = QuotaStub(exhausted=True)
    c = client_for(t, reg=reg, quota=quota)
    with pytest.raises(QuotaExceeded):
        ScopedHttp(c).get("https://api.example.test/x")
    assert t.calls == []
    assert ScopedHttp(c, core=True).get("https://dns.google/resolve?name=x&type=A").ok  # DoH is not charged


def test_circuit_hosts_and_reset(cache):
    t = StubTransport().add("GET", "https://geo.example.gov.br/x", status=451, text="unavailable", times=2)
    c = client_for(t, cache)
    scoped = ScopedHttp(c)
    with pytest.raises(Blocked) as first:
        scoped.check(scoped.get("https://geo.example.gov.br/x"))
    assert first.value.reason_code == "geo_block"
    assert c.circuit_hosts() == frozenset({"geo.example.gov.br"})
    with pytest.raises(Blocked) as second:
        scoped.get("https://geo.example.gov.br/y")
    assert second.value.reason_code == "circuit"
    c.reset_circuit()
    assert scoped.get("https://geo.example.gov.br/x").status == 451


# --------------------------------------------------------------------------------------
# check(), default source, legacy clients (tests/test_dns.py wraps FakeHttp directly)
# --------------------------------------------------------------------------------------


class LegacyClient:
    """A v1-style client: request(method, url, **kw) only."""

    def __init__(self, responses: dict[str, Response]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str, dict]] = []

    def request(self, method: str, url: str, **kw: Any) -> Response:
        self.calls.append((method, url, kw))
        return self.responses[url]


def test_check_uses_the_scope_markers_and_keyless_flag():
    legacy = LegacyClient({"https://open.example.test/x": Response(403, "https://open.example.test/x", {}, b"forbidden")})
    scoped = ScopedHttp(legacy, keyless=True)
    resp = scoped.get("https://open.example.test/x")
    with pytest.raises(Blocked) as err:
        scoped.check(resp)
    assert err.value.reason_code == "challenge"
    ok = Response(200, "https://open.example.test/y", {}, b'{"status": "ERROR"}')
    marker = {"id": "status_error", "json_path": "status", "equals": "ERROR", "maps_to": "error", "reason": "Demo: query error"}
    with pytest.raises(HttpError, match="Demo: query error"):
        ScopedHttp(legacy, error_markers=(marker,)).check(ok)


def test_legacy_clients_keep_working_with_counters():
    legacy = LegacyClient(
        {
            "https://api.example.test/a?x=1": Response(200, "https://api.example.test/a?x=1", {}, b"abc"),
            "https://api.example.test/b": Response(200, "https://api.example.test/b", {}, b"de", from_cache=True),
        }
    )
    scoped = ScopedHttp(legacy, ttl=60, min_interval=0.5, user_agent="Legacy/1", max_requests=2)
    assert scoped.get("https://api.example.test/a?x=1").ok
    assert scoped.get("https://api.example.test/b").from_cache
    assert scoped.requests == 1 and scoped.cache_hits == 1 and scoped.hosts == {"api.example.test": 1}
    assert legacy.calls[0][2] == {"ttl": 60, "min_interval": 0.5, "user_agent": "Legacy/1"}
    assert scoped.get("https://api.example.test/a?x=1").ok
    # a legacy client cannot tell a cache hit in advance: the cap is checked before every call
    with pytest.raises(RequestCapReached):
        scoped.get("https://api.example.test/b")
    assert len(scoped.request_log) == 3 and scoped.requests == 2


def test_scope_metadata_reaches_the_client():
    seen: dict[str, Any] = {}

    class Spy(HttpClient):
        def request(self, method: str, url: str, **kw: Any) -> Response:
            seen.update(kw)
            return super().request(method, url, **kw)

    clock = StubClock()
    t = StubTransport(clock).add("GET", "https://api.example.test/x", text="ok")
    reg = registry(provider("demo_api", ("api.example.test",), sources=("one",)))
    c = Spy(transport=t, clock=clock, providers=reg)
    ScopedHttp(c, module="t_meta", provider="demo_api", sources=("demo_api.one",), opsec=Opsec.PASSIVE, priority="pivot2", keyless=True, deadline=clock.monotonic() + 30).get("https://api.example.test/x")
    assert seen["module"] == "t_meta" and seen["provider"] == "demo_api" and seen["source"] == "demo_api.one"
    assert seen["opsec"] == "passive" and seen["priority"] == "pivot2" and seen["keyless"] is True
    assert seen["deadline"] == pytest.approx(1030.0) and callable(seen["hop_check"]) and callable(seen["network_gate"])


# --------------------------------------------------------------------------------------
# review additions: rule 5 on declared absences, scope metadata wins, legacy redirects, cache_if
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(("status", "expected"), [(401, "AuthRequired"), (403, "AuthRequired"), (429, "RateLimited"), (451, "Blocked"), (503, "HttpError")])
def test_could_not_verify_statuses_are_never_a_declared_absence(status, expected):
    """A module declaring 403/429/5xx as 'absent' still gets 'could not verify' (rule 5)."""
    t = StubTransport().add("GET", "https://api.example.test/x", status=status, json={"detail": "nope"})
    scoped = ScopedHttp(client_for(t), absent_statuses={401, 403, 404, 429, 451, 503})
    with pytest.raises(HttpError) as err:
        scoped.get_json("https://api.example.test/x")
    assert type(err.value).__name__ == expected
    with pytest.raises(HttpError):
        ScopedHttp(client_for(StubTransport().add("GET", "https://api.example.test/x", status=status, json={}))).get_json("https://api.example.test/x", absent={status})


def test_scope_metadata_wins_over_per_call_keywords():
    seen: list[dict[str, Any]] = []

    class Spy(HttpClient):
        def request(self, method: str, url: str, **kw: Any) -> Response:
            seen.append(dict(kw))
            return super().request(method, url, **kw)

    clock = StubClock()
    quota = QuotaStub()
    reg = registry(provider("demo_api", ("api.example.test",)))
    t = StubTransport(clock).add("GET", "https://api.example.test/x", text="ok", times=5)
    c = Spy(transport=t, clock=clock, providers=reg, quota=quota, settings={"ua_light": "Mozilla/5.0 (X11) TestBrowser/1.0"}, retries=0)
    cancel = threading.Event()
    scoped = ScopedHttp(c, module="t_light", opsec=Opsec.LIGHT, disclosure="target", priority="pivot2", min_interval=2.0,
                        deadline=clock.monotonic() + 30, cancel_event=cancel, clock=clock)
    scoped.get("https://api.example.test/x", opsec="passive", module="other_module", priority="seed", charge_quota=False,
               deadline=clock.monotonic() + 3600, cancel_event=threading.Event(), min_interval=0.0)
    kw = seen[-1]
    assert (kw["opsec"], kw["module"], kw["priority"], kw["charge_quota"]) == ("light", "t_light", "pivot2", True)
    assert kw["deadline"] == pytest.approx(1030.0) and kw["cancel_event"] is cancel and kw["min_interval"] == 2.0
    assert t.header(0, "User-Agent") == "Mozilla/5.0 (X11) TestBrowser/1.0"  # never the V3LUM UA towards a target
    assert quota.reserved == [("demo_api", "api.example.test", "pivot2")]
    # an earlier per-call deadline is honoured (the 2 s politeness wait fits in it)
    earlier = clock.monotonic() + 10
    scoped.get("https://api.example.test/x", deadline=earlier)
    assert seen[-1]["deadline"] == pytest.approx(earlier) and clock.sleeps == [pytest.approx(2.0)]
    # the scope's kill switch cannot be bypassed with another event
    cancel.set()
    with pytest.raises(Cancelled):
        scoped.get("https://api.example.test/x", cancel_event=threading.Event())


def test_keyless_can_only_be_tightened_per_call():
    t = StubTransport().add("GET", "https://open.example.test/x", status=403, text="Forbidden", times=3)
    c = client_for(t)
    assert ScopedHttp(c, keyless=True).get("https://open.example.test/x", keyless=False).classification.reason_code == "challenge"
    assert ScopedHttp(c).get("https://open.example.test/x", keyless=True).classification.reason_code == "challenge"
    # a bare keyless 403 never short-circuits the host: a keyed caller still reaches it
    assert c.circuit_hosts() == frozenset()
    keyed = ScopedHttp(c).get("https://open.example.test/x")
    assert keyed.status == 403 and keyed.classification is None and len(t.calls) == 3


def test_legacy_client_redirects_to_undeclared_hosts_are_refused():
    legacy = LegacyClient({"https://api.example.test/a": Response(200, "https://tracker.example.net/x", {}, b"data", history=["https://api.example.test/a"])})
    scoped = ScopedHttp(legacy, module="t_legacy", allowed_hosts=("api.example.test",))
    with pytest.raises(PolicyError) as err:
        scoped.get("https://api.example.test/a")
    assert err.value.reason_code == "policy" and "tracker.example.net" in str(err.value)
    assert scoped.requests == 1  # the send happened and is counted


def test_a_failing_cache_if_veto_means_no_store(cache):
    t = StubTransport().add("GET", "https://api.example.test/x", text="not json", times=2)
    scoped = ScopedHttp(client_for(t, cache))

    def veto(resp: Response) -> bool:
        return resp.json()["ok"]  # raises: the body is not JSON

    resp = scoped.get("https://api.example.test/x", cache_if=veto)
    assert resp.text == "not json" and cache.stats()["entries"] == 0
    assert not scoped.get("https://api.example.test/x").from_cache
