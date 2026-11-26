"""HttpClient against a real local HTTP server: caching rules, retries, politeness, offline mode."""

from __future__ import annotations

import gzip
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from v3lum.core.http import AuthRequired, HttpCache, HttpClient, HttpError, NetworkError, OfflineError, RateLimited, ScopedHttp


class Handler(BaseHTTPRequestHandler):
    hits: dict[str, int] = {}

    def log_message(self, *args):  # silence
        pass

    def do_GET(self):  # noqa: N802
        Handler.hits[self.path] = Handler.hits.get(self.path, 0) + 1
        n = Handler.hits[self.path]
        if self.path.startswith("/json"):
            self._send(200, json.dumps({"ok": True, "n": n}).encode(), "application/json")
        elif self.path.startswith("/notfound"):
            self._send(404, b"nope")
        elif self.path.startswith("/forbidden"):
            self._send(403, b"denied")
        elif self.path.startswith("/flaky"):
            # 503 on first try, 200 after
            if n == 1:
                self._send(503, b"busy")
            else:
                self._send(200, b"recovered")
        elif self.path.startswith("/ratelimit"):
            self.send_response(429)
            self.send_header("Retry-After", "120")
            self.end_headers()
            self.wfile.write(b"slow down")
        elif self.path.startswith("/retry10"):
            self.send_response(429)
            self.send_header("Retry-After", "10")
            self.send_header("Content-Length", "9")
            self.end_headers()
            self.wfile.write(b"slow down")
        elif self.path.startswith("/stall"):
            time.sleep(0.15)  # longer than the client's read timeout
            try:
                self._send(200, b"late")
            except OSError:
                pass
        elif self.path.startswith("/big"):
            self._send(200, b"x" * 50000)
        elif self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "/json?from=redirect")
            self.end_headers()
        elif self.path.startswith("/headers"):
            self._send(200, json.dumps({k.lower(): v for k, v in self.headers.items()}).encode(), "application/json")
        elif self.path.startswith("/drip"):
            # slow-drip server: announces 1000 bytes, sends one every 50 ms
            self.send_response(200)
            self.send_header("Content-Length", "1000")
            self.end_headers()
            try:
                for _ in range(1000):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.05)
            except OSError:
                pass
        elif self.path.startswith("/gzip"):
            body = gzip.compress(json.dumps({"compressed": True, "pad": "z" * 5000}).encode())
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path.startswith("/chunked"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for part in (b"chunk-one;", b"chunk-two;", b"chunk-three"):
                self.wfile.write(f"{len(part):x}\r\n".encode() + part + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
        elif self.path.startswith("/setcookie"):
            self.send_response(200)
            self.send_header("Set-Cookie", "sid=tracking123; Path=/")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self._send(200, b"hello")

    def _send(self, code, body, ctype="text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def server():
    Handler.hits = {}
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture()
def client(tmp_path):
    cache = HttpCache(str(tmp_path / "cache.db"))
    c = HttpClient(cache=cache, default_ttl=3600, trust_env=False, retries=1, timeout=5)
    yield c
    cache.close()


def test_cache_hit_on_200(server, client):
    r1 = client.request("GET", server + "/json")
    r2 = client.request("GET", server + "/json")
    assert r1.status == 200 and not r1.from_cache
    assert r2.from_cache and r2.json() == r1.json()
    assert Handler.hits["/json"] == 1


def test_404_cached_403_not(server, client):
    client.request("GET", server + "/notfound")
    assert client.request("GET", server + "/notfound").from_cache
    client.request("GET", server + "/forbidden")
    r = client.request("GET", server + "/forbidden")
    assert not r.from_cache and Handler.hits["/forbidden"] == 2


def test_ttl_zero_bypasses_cache(server, client):
    client.request("GET", server + "/json", ttl=0)
    client.request("GET", server + "/json", ttl=0)
    assert Handler.hits["/json"] == 2


def test_retry_on_503(server, client):
    r = client.request("GET", server + "/flaky")
    assert r.status == 200 and r.text == "recovered"
    assert Handler.hits["/flaky"] == 2


def test_rate_limit_long_retry_after_returns_429(server, client):
    r = client.request("GET", server + "/ratelimit")
    assert r.status == 429
    with pytest.raises(RateLimited):
        r.raise_for_status()


def test_raise_for_status_types(server, client):
    with pytest.raises(AuthRequired):
        client.request("GET", server + "/forbidden").raise_for_status()
    with pytest.raises(HttpError):
        client.request("GET", server + "/notfound").raise_for_status()


def test_size_cap_truncates_and_is_not_cached(server, client):
    r = client.request("GET", server + "/big", max_bytes=1000)
    assert r.truncated and len(r.content) == 1000
    r2 = client.request("GET", server + "/big", max_bytes=1000)
    assert not r2.from_cache


def test_redirect_history(server, client):
    r = client.request("GET", server + "/redirect")
    assert r.json()["ok"] and r.history and r.history[0].endswith("/redirect")


def test_offline_mode(server, tmp_path):
    cache = HttpCache(str(tmp_path / "c.db"))
    online = HttpClient(cache=cache, trust_env=False)
    online.request("GET", server + "/json")
    offline = HttpClient(cache=cache, offline=True, trust_env=False)
    assert offline.request("GET", server + "/json").from_cache
    with pytest.raises(OfflineError):
        offline.request("GET", server + "/other")


def test_network_error():
    c = HttpClient(trust_env=False, retries=0, timeout=2)
    with pytest.raises(NetworkError):
        c.request("GET", "http://127.0.0.1:1/never")


def test_min_interval_politeness(server, client):
    start = time.monotonic()
    for i in range(3):
        client.request("GET", server + f"/json?i={i}", ttl=0, min_interval=0.2)
    assert time.monotonic() - start >= 0.4


def test_scoped_counters_and_get_json(server, client):
    scoped = ScopedHttp(client, ttl=3600)
    assert scoped.get_json(server + "/json")["ok"]
    assert scoped.get_json(server + "/json")["ok"]
    assert scoped.requests == 1 and scoped.cache_hits == 1
    assert scoped.get_json(server + "/notfound", ok404=True) is None


def test_request_hook_and_params(server, client):
    seen = []
    client.on_request = lambda m, u, s, e, c, err: seen.append((m, u, s, c))
    client.request("GET", server + "/json", params={"a": "1 2", "b": None})
    assert seen and "a=1+2" in seen[0][1] and "b=" not in seen[0][1]


def test_cache_clear_and_stats(server, client):
    client.request("GET", server + "/json")
    st = client.cache.stats()
    assert st["entries"] == 1
    assert client.cache.clear(host="127.0.0.1") == 1


def test_block_detection_strong_and_weak_markers():
    from v3lum.core.http import Blocked, Response, block_reason

    challenge = b"<html><head><title>Just a moment...</title></head><body>cf-chl-bypass</body></html>"
    assert block_reason(403, {"server": "cloudflare"}, challenge)
    assert block_reason(200, {}, challenge)  # challenge served with 200 is still a block
    normal = b"<html><script src='/cdn-cgi/challenge-platform/scripts/jsd/main.js'></script><div class='g-recaptcha'></div>profile</html>"
    assert block_reason(200, {}, normal) is None  # weak markers ignored on 200
    assert block_reason(403, {}, normal)  # but count on an error page
    assert block_reason(404, {}, challenge) is None
    r = Response(status=403, url="https://x.example/a", headers={"server": "cloudflare"}, content=b"denied")
    with pytest.raises(Blocked):
        r.raise_for_status()
    r200 = Response(status=200, url="https://x.example/a", headers={}, content=challenge)
    with pytest.raises(Blocked):
        r200.raise_for_status()
    assert Response(status=200, url="https://x.example/a", headers={}, content=b'{"ok":1}').raise_for_status().ok


def test_quota_book(tmp_path):
    from v3lum.core.quota import QuotaBook

    q = QuotaBook(tmp_path / "q.db")
    assert not q.exhausted("hackertarget", 3)
    q.add("hackertarget", 2)
    q.add("hackertarget", 1)
    assert q.used("hackertarget") == 3 and q.exhausted("hackertarget", 3)
    assert not q.exhausted("hackertarget", None)
    assert q.summary() == {"hackertarget": 3}
    q.reset("hackertarget")
    assert q.used("hackertarget") == 0


# --------------------------------------------------------------------------------------
# v2 behaviour over real sockets (WP03): neutral UA, no default Accept-Language, own redirect
# loop, slow-drip deadline, streamed decoding, no cookie state
# --------------------------------------------------------------------------------------


def test_default_user_agent_is_neutral_and_no_accept_language(server, client):
    from v3lum import __version__

    seen = client.request("GET", server + "/headers", ttl=0).json()
    assert seen["user-agent"] == f"V3LUM/{__version__}"
    assert "accept-language" not in seen


def test_slow_drip_server_stops_at_the_deadline(server):
    from v3lum.core.clock import SYSTEM_CLOCK
    from v3lum.core.http import DeadlineExceeded

    c = HttpClient(trust_env=False, retries=0, timeout=5)
    start = time.monotonic()
    with pytest.raises(DeadlineExceeded):
        c.request("GET", server + "/drip", deadline=SYSTEM_CLOCK.monotonic() + 0.15)
    assert time.monotonic() - start < 2.0  # not the 50 s the server would take


def test_gzip_and_chunked_bodies_are_decoded(server, client):
    data = client.request("GET", server + "/gzip", ttl=0).json()
    assert data["compressed"] is True and len(data["pad"]) == 5000
    assert client.request("GET", server + "/chunked", ttl=0).text == "chunk-one;chunk-two;chunk-three"


def test_cookies_are_never_replayed(server, client):
    client.request("GET", server + "/setcookie", ttl=0)
    seen = client.request("GET", server + "/headers", ttl=0).json()
    assert "cookie" not in seen


def test_file_split_keeps_the_v1_imports():
    from v3lum.core import cache, http, limiter

    assert http.HttpCache is cache.HttpCache and http.HostLimiter is limiter.HostLimiter
    assert http.CACHEABLE_STATUS is cache.CACHEABLE_STATUS


def test_system_clock_contract():
    from v3lum.core.clock import SYSTEM_CLOCK, Clock, SystemClock

    now = SYSTEM_CLOCK.now()
    assert now.tzinfo is not None and now.utcoffset().total_seconds() == 0
    a = SYSTEM_CLOCK.monotonic()
    SYSTEM_CLOCK.sleep(0)
    SYSTEM_CLOCK.sleep(-1)
    assert SYSTEM_CLOCK.monotonic() >= a
    assert isinstance(SystemClock(), Clock)


def test_host_limiter_reserves_every_slot_and_caps_concurrency():
    from tests.fixtures.http.stub_transport import StubClock
    from v3lum.core.limiter import HostLimiter

    clock = StubClock()
    lim = HostLimiter(2, clock=clock)
    assert lim.reserve("api.example.test", 1.5) == 0.0
    assert lim.reserve("API.example.test.", 0.0) == pytest.approx(1.5)  # declared interval binds later callers
    assert lim.interval_for("api.example.test") == 1.5
    lim.wait_turn("api.example.test", 0.0)
    assert clock.sleeps == [pytest.approx(3.0)]
    assert lim.reserve("other.example.test", 0.0) == 0.0
    with lim.acquire("busy.example.test", 1), pytest.raises(TimeoutError), lim.acquire("busy.example.test", 1, timeout=0.01):
        pass
    with lim.acquire("busy.example.test", 1, timeout=0.01):
        pass


def test_fetched_at_and_cache_if(server, client):
    from tests.fixtures.http.stub_transport import StubClock, StubTransport, registry

    clock = StubClock()
    t = StubTransport(clock).add("GET", "https://api.example.test/a", json={"a": 1}, times=3)
    c = HttpClient(cache=client.cache, transport=t, clock=clock, providers=registry())
    first = c.request("GET", "https://api.example.test/a")
    assert first.fetched_at == "2026-11-26T12:00:00.000+00:00" and first.request_url == "https://api.example.test/a"
    clock.advance(90)
    hit = c.request("GET", "https://api.example.test/a")
    assert hit.from_cache and hit.fetched_at == "2026-11-26T12:00:00+00:00"  # the cache row time
    t.add("GET", "https://api.example.test/b", json={"b": 1}, times=2)
    ScopedHttp(c).get("https://api.example.test/b", cache_if=lambda r: r.json().get("b") != 1)  # module veto
    assert not ScopedHttp(c).get("https://api.example.test/b").from_cache
    assert [u for u in t.urls() if u.endswith("/b")] == ["https://api.example.test/b"] * 2


def test_identical_concurrent_requests_collapse_into_one_send(tmp_path):
    from tests.fixtures.http.stub_transport import StubTransport, registry

    gate = threading.Event()

    class SlowTransport(StubTransport):
        def send(self, method, url, **kw):
            gate.wait(2)
            return super().send(method, url, **kw)

    t = SlowTransport().add("GET", "https://api.example.test/same", json={"n": 1}, times=1)
    cache = HttpCache(str(tmp_path / "collapse.db"))
    try:
        c = HttpClient(cache=cache, transport=t, providers=registry())
        results = []
        threads = [threading.Thread(target=lambda: results.append(c.request("GET", "https://api.example.test/same"))) for _ in range(4)]
        for th in threads:
            th.start()
        time.sleep(0.05)
        gate.set()
        for th in threads:
            th.join(2)
        assert len(results) == 4 and len(t.calls) == 1
        assert sum(r.from_cache for r in results) == 3
        assert len(c._key_locks) == 0  # per-key locks are released, nothing accumulates
    finally:
        cache.close()


def test_tls_verification_is_always_on(tmp_path):
    from v3lum.core.http import RequestsTransport, Transport

    default = RequestsTransport()
    assert default.verify is True and isinstance(default, Transport)
    bundle = str(tmp_path / "internal-ca.pem")
    assert RequestsTransport(ca_bundle=bundle).verify == bundle
    assert HttpClient(settings={"ca_bundle": bundle}).transport.verify == bundle
    assert RequestsTransport(ca_bundle="").verify is True  # an empty setting never disables verification


def test_netrc_credentials_are_never_attached(server, tmp_path, monkeypatch):
    """trust_env brings proxies and CA bundles, never ~/.netrc logins (no borrowed credentials)."""
    netrc = tmp_path / "netrc"
    netrc.write_text("machine 127.0.0.1 login analyst password netrc-secret-123\n")
    netrc.chmod(0o600)
    monkeypatch.setenv("NETRC", str(netrc))
    c = HttpClient(trust_env=True, retries=0, timeout=5)
    seen = c.request("GET", server + "/headers", ttl=0).json()
    assert "authorization" not in seen
    explicit = c.request("GET", server + "/headers", ttl=0, headers={"Authorization": "Bearer explicit-0123456789"}).json()
    assert explicit["authorization"] == "Bearer explicit-0123456789"  # an explicit header still works


def test_cancel_cuts_a_retry_after_wait_short(server):
    """Kill switch (A7/AR05): a set cancel flag ends a Retry-After wait at once, nothing more is sent."""
    from v3lum.core.http import Cancelled

    class CancelledWhileWaiting(threading.Event):
        """Ctrl+C arrives 50 ms into the client's Retry-After wait (the 429 was already received)."""

        waits: list[float] = []

        def wait(self, timeout=None):
            self.waits.append(timeout)
            threading.Timer(0.05, self.set).start()
            return super().wait(timeout)

    cancel = CancelledWhileWaiting()
    c = HttpClient(trust_env=False, retries=1, timeout=5)
    start = time.monotonic()
    with pytest.raises(Cancelled):
        c.request("GET", server + "/retry10", ttl=0, cancel_event=cancel)
    assert time.monotonic() - start < 2.0  # not the 10 s Retry-After
    assert cancel.waits == [pytest.approx(10.0)] and Handler.hits["/retry10"] == 1


def test_an_unusable_ca_bundle_is_a_network_error_never_unverified(server, tmp_path):
    from v3lum.core.http import RequestsTransport

    transport = RequestsTransport(trust_env=False, ca_bundle=str(tmp_path / "missing-ca.pem"))
    with pytest.raises(NetworkError) as err:
        transport.send("GET", server.replace("http://", "https://") + "/json", headers={}, body=None, timeout=2, max_bytes=1000, deadline=None)
    assert not err.value.retryable
    assert transport.verify == str(tmp_path / "missing-ca.pem")  # never silently downgraded to verify=False


def test_cache_files_are_owner_only_whatever_the_umask(tmp_path):
    import os
    import stat

    from v3lum.core.http import Response

    old = os.umask(0o022)
    try:
        db = tmp_path / "perm.db"
        cache = HttpCache(str(db))
        try:
            assert cache.put("k", Response(200, "https://a.example.test/x", {}, b"body"))
            files = [p for p in tmp_path.iterdir() if p.name.startswith("perm.db")]
            assert {p.name for p in files} >= {"perm.db", "perm.db-wal", "perm.db-shm"}
            for path in files:
                assert stat.S_IMODE(path.stat().st_mode) == 0o600, path.name
        finally:
            cache.close()
        loose = tmp_path / "loose.db"
        loose.touch()
        loose.chmod(0o644)
        HttpCache(str(loose)).close()
        assert stat.S_IMODE(loose.stat().st_mode) == 0o600  # an existing loose file is tightened
    finally:
        os.umask(old)


def test_a_read_timeout_is_a_network_error_with_reason_timeout(server):
    c = HttpClient(trust_env=False, retries=0, timeout=0.03)
    with pytest.raises(NetworkError) as err:
        c.request("GET", server + "/stall", ttl=0)
    assert err.value.reason_code == "timeout" and err.value.retryable
    assert "Timeout" in err.value.kind


# --------------------------------------------------------------------------------------
# wave 2 (WP11): streamed bodies (dataset downloads) and content-driven cache lifetimes
# --------------------------------------------------------------------------------------


def test_stream_to_writes_the_body_to_a_file_and_never_caches(server, client, tmp_path):
    target = tmp_path / "download.bin"
    with target.open("w+b") as sink:
        resp = client.request("GET", server + "/big", stream_to=sink)
    assert resp.status == 200 and resp.streamed_bytes == 50000 and not resp.truncated
    assert target.read_bytes() == b"x" * 50000
    assert resp.content == b"x" * 50000  # the head kept for classification (<= 64 KB)
    with target.open("w+b") as sink:
        again = client.request("GET", server + "/big", stream_to=sink)
    assert not again.from_cache and Handler.hits["/big"] == 2  # a streamed answer is never cached
    with target.open("w+b") as sink:
        capped = client.request("GET", server + "/big", stream_to=sink, max_bytes=1000)
    assert capped.truncated and capped.streamed_bytes == 1000 and target.stat().st_size == 1000


def test_stream_to_follows_redirects_without_keeping_hop_bodies(server, client, tmp_path):
    target = tmp_path / "followed.json"
    with target.open("w+b") as sink:
        resp = client.request("GET", server + "/redirect", stream_to=sink)
    assert resp.status == 200 and json.loads(target.read_bytes())["ok"] is True


def test_stream_to_works_over_a_transport_without_streaming(tmp_path):
    from tests.fakes import FakeClock, FakeHttp

    http = FakeHttp(clock=FakeClock()).add("GET", "https://data.example.test/feed.csv", text="a,b\n" * 30000)
    c = HttpClient(transport=http, clock=http.clock, retries=0)
    target = tmp_path / "feed.csv"
    with target.open("w+b") as sink:
        resp = c.request("GET", "https://data.example.test/feed.csv", stream_to=sink)
    assert resp.streamed_bytes == 120000 and target.stat().st_size == 120000
    assert len(resp.content) == 64 * 1024  # memory keeps only the head


def test_ttl_from_shortens_the_cache_lifetime_of_an_answer(tmp_path):
    from tests.fakes import FakeClock, FakeHttp

    clock = FakeClock()
    http = FakeHttp(clock=clock).add("GET", "https://dns.example.test/q", json={"TTL": 60}, times=2)
    cache = HttpCache(str(tmp_path / "ttl.db"), clock=clock)
    try:
        c = HttpClient(transport=http, clock=clock, cache=cache, default_ttl=3600, retries=0)
        ttl_from = lambda resp: resp.json()["TTL"]  # noqa: E731 - the answer's own lifetime
        c.request("GET", "https://dns.example.test/q", ttl_from=ttl_from)
        clock.advance(30)
        assert c.request("GET", "https://dns.example.test/q", ttl_from=ttl_from).from_cache
        clock.advance(40)  # 70 s > TTL 60 although the request TTL is 3600
        assert not c.request("GET", "https://dns.example.test/q", ttl_from=ttl_from).from_cache
        assert len(http.calls) == 2
        never = FakeHttp(clock=clock).add("GET", "https://dns.example.test/zero", json={"TTL": 0}, times=2)
        c2 = HttpClient(transport=never, clock=clock, cache=cache, default_ttl=3600, retries=0)
        c2.request("GET", "https://dns.example.test/zero", ttl_from=ttl_from)
        assert not c2.request("GET", "https://dns.example.test/zero", ttl_from=ttl_from).from_cache  # TTL 0: never stored
    finally:
        cache.close()


def test_the_kill_switch_stops_a_body_being_read(server):
    """Cancel also interrupts a slow-drip body already being read (target traffic stops within 2 s)."""
    from v3lum.core.http import Cancelled

    c = HttpClient(trust_env=False, retries=0, timeout=5)
    cancel = threading.Event()
    threading.Timer(0.1, cancel.set).start()
    start = time.monotonic()
    with pytest.raises(Cancelled):
        c.request("GET", server + "/drip", cancel_event=cancel, ttl=0)
    assert time.monotonic() - start < 2.0


# ------------------------------------------------------------------ provider token bucket (P334 cond 3)
@pytest.mark.parametrize(("timeout", "second_ok"), [(60.0, True), (10.0, False)])
def test_one_provider_interval_is_waited_within_the_run_deadline(clean_registry, timeout, second_ok):
    """A provider whose paced interval exceeds quota.RATE_WAIT_MAX (VirusTotal-like 4/min at 80% =
    18.75 s apart) still gets its next request after one interval when the run deadline allows
    (RATE_WAIT_MAX caps only the queueing beyond one slot); without the time left it is 'could not
    verify now', never a silent absence."""
    from tests.fakes import FakeClock, FakeHttp, define_module, make_ctx, source_ids, test_provider
    from v3lum.core.entities import EntityType as T

    quota = {"scope": "egress_ip", "rate_per_second": 4 / 60, "burst": 1, "published": True, "evidence_url": "https://api.example.test/limits"}
    with test_provider("t_slow_api", quota=quota) as prov:
        cls = define_module(
            "t_slow_api_mod", [T.DOMAIN], lambda self, e, c: self.result(e), disclosure="third_party", provider=prov.id,
            sources=source_ids(prov), hosts=prov.hosts, access_model="free_noauth_limited", timeout=timeout,
        )
        http = FakeHttp().add("GET", "https://api.example.test/a", json={"n": 1}).add("GET", "https://api.example.test/b", json={"n": 2})
        clock = FakeClock()
        ctx = make_ctx(cls, http, clock=clock, entity="domain:example.org")
        assert ctx.http.get_json("https://api.example.test/a") == {"n": 1}
        start = clock.monotonic()
        if second_ok:
            assert ctx.http.get_json("https://api.example.test/b") == {"n": 2}
            assert clock.monotonic() - start == pytest.approx(18.75, abs=0.5)  # one paced slot, on the runtime clock
        else:
            with pytest.raises(RateLimited):
                ctx.http.get_json("https://api.example.test/b")
            assert http.urls() == ["https://api.example.test/a"]  # never sent early
