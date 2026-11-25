"""HttpClient against a real local HTTP server: caching rules, retries, politeness, offline mode."""

from __future__ import annotations

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
        elif self.path.startswith("/big"):
            self._send(200, b"x" * 50000)
        elif self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "/json?from=redirect")
            self.end_headers()
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
    t = threading.Thread(target=srv.serve_forever, daemon=True)
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
