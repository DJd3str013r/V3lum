"""The client's own redirect loop (AR01/AR02, P327 cond 4): at most 5 hops, history, hop checks,
credential stripping on host change, no https->http downgrade, method rewriting."""

from __future__ import annotations

import pytest

from tests.fixtures.http.stub_transport import StubClock, StubTransport, registry
from v3lum.core import redact
from v3lum.core.http import HttpCache, HttpClient, HttpError, PolicyError

SECRET = "sk_live_FAKE0123456789abcdef"


def client_for(transport: StubTransport, cache: HttpCache | None = None) -> HttpClient:
    clock = StubClock()
    transport.clock = clock
    return HttpClient(cache=cache, transport=transport, clock=clock, providers=registry(), retries=0)


def chain(t: StubTransport, hops: int, *, host: str = "a.example.test") -> str:
    """hops redirects /0 -> /1 -> ... -> /<hops> (200)."""
    for i in range(hops):
        t.add("GET", f"https://{host}/{i}", status=302, location=f"/{i + 1}")
    t.add("GET", f"https://{host}/{hops}", text="final")
    return f"https://{host}/0"


def test_five_hops_are_followed_with_history():
    t = StubTransport()
    start = chain(t, 5)
    resp = client_for(t).request("GET", start)
    assert resp.ok and resp.text == "final" and resp.url == "https://a.example.test/5"
    assert resp.history == [f"https://a.example.test/{i}" for i in range(5)]
    assert resp.request_url == start
    assert len(t.calls) == 6


def test_a_sixth_redirect_is_refused():
    t = StubTransport()
    start = chain(t, 6)
    with pytest.raises(HttpError, match="too many redirects"):
        client_for(t).request("GET", start)
    assert len(t.calls) == 6  # the 7th URL is never requested


def test_allow_redirects_false_returns_the_redirect():
    t = StubTransport().add("GET", "https://a.example.test/0", status=301, location="https://b.example.test/x")
    resp = client_for(t).request("GET", "https://a.example.test/0", allow_redirects=False)
    assert resp.status == 301 and resp.history == [] and resp.headers["location"] == "https://b.example.test/x"
    assert t.urls() == ["https://a.example.test/0"]


def test_hop_check_runs_before_every_hop_and_policy_error_stops():
    t = StubTransport()
    t.add("GET", "https://a.example.test/start", status=302, location="https://b.example.test/next")
    t.add("GET", "https://b.example.test/next", status=302, location="https://evil.example.test/x")
    seen: list[str] = []

    def hop_check(url: str) -> None:
        seen.append(url)
        if "evil.example.test" in url:
            raise PolicyError("policy", "host evil.example.test is not declared")

    with pytest.raises(PolicyError) as err:
        client_for(t).request("GET", "https://a.example.test/start", hop_check=hop_check)
    assert err.value.reason_code == "policy"
    assert seen == ["https://a.example.test/start", "https://b.example.test/next", "https://evil.example.test/x"]
    assert "https://evil.example.test/x" not in t.urls()


def test_credential_headers_are_stripped_when_the_host_changes():
    redact.register_secret(SECRET, label="demo")
    t = StubTransport()
    t.add("GET", "https://api.example.test/v1/a", status=302, location="/v1/b")  # same host: kept
    t.add("GET", "https://api.example.test/v1/b", status=307, location="https://cdn.example.test/blob")  # other host: stripped
    t.add("GET", "https://cdn.example.test/blob", text="ok")
    headers = {
        "Authorization": "Bearer tok-0123456789",
        "X-Api-Key": "k-0123456789",
        "Cookie": "session=abc",
        "Key": "plain-key-value",
        "X-Custom-Auth": SECRET,
        "Accept": "application/json",
    }
    resp = client_for(t).request("GET", "https://api.example.test/v1/a", headers=headers)
    assert resp.ok
    first, second, third = t.calls
    for name in ("Authorization", "X-Api-Key", "Cookie", "Key", "X-Custom-Auth"):
        assert name in first["headers"] and name in second["headers"]
        assert name not in third["headers"], name
    assert third["headers"]["Accept"] == "application/json"  # non-credential headers survive
    assert all(SECRET not in v for v in third["headers"].values())


def test_https_to_http_downgrade_is_refused():
    t = StubTransport().add("GET", "https://a.example.test/x", status=302, location="http://a.example.test/x")
    with pytest.raises(PolicyError) as err:
        client_for(t).request("GET", "https://a.example.test/x")
    assert err.value.reason_code == "policy" and "downgrade" in str(err.value)
    assert t.urls() == ["https://a.example.test/x"]


def test_redirect_to_a_non_http_scheme_is_refused():
    t = StubTransport().add("GET", "https://a.example.test/x", status=302, location="file:///etc/passwd")
    with pytest.raises(PolicyError):
        client_for(t).request("GET", "https://a.example.test/x")


def test_http_to_https_upgrade_is_followed():
    t = StubTransport().add("GET", "http://a.example.test/x", status=301, location="https://a.example.test/x")
    t.add("GET", "https://a.example.test/x", text="secure")
    assert client_for(t).request("GET", "http://a.example.test/x").text == "secure"


def test_303_becomes_get_without_body_and_307_keeps_the_method():
    t = StubTransport()
    t.add("POST", "https://a.example.test/form", status=303, location="/result")
    t.add("GET", "https://a.example.test/result", text="done")
    t.add("POST", "https://a.example.test/api", status=307, location="/api2")
    t.add("POST", "https://a.example.test/api2", json={"ok": True})
    c = client_for(t)
    assert c.request("POST", "https://a.example.test/form", json_body={"q": 1}).text == "done"
    get_call = t.calls[1]
    assert get_call["method"] == "GET" and get_call["body"] is None
    assert not any(k.lower() == "content-type" for k in get_call["headers"])
    assert c.request("POST", "https://a.example.test/api", json_body={"q": 2}).json() == {"ok": True}
    assert t.calls[3]["method"] == "POST" and t.calls[3]["body"] == b'{"q": 2}'


def test_cached_redirect_chain_is_hop_checked_again(tmp_path):
    cache = HttpCache(str(tmp_path / "c.db"))
    try:
        t = StubTransport()
        t.add("GET", "https://a.example.test/start", status=302, location="https://b.example.test/final")
        t.add("GET", "https://b.example.test/final", text="data")
        c = client_for(t, cache)
        assert c.request("GET", "https://a.example.test/start").text == "data"
        assert c.request("GET", "https://a.example.test/start").from_cache

        def only_a(url: str) -> None:
            if "b.example.test" in url:
                raise PolicyError("policy", "b is not declared")

        with pytest.raises(PolicyError):  # same outcome as a live request for this caller
            c.request("GET", "https://a.example.test/start", hop_check=only_a)
        assert len(t.calls) == 2
    finally:
        cache.close()


# --------------------------------------------------------------------------------------
# review additions: parser differentials and credential-bearing bodies
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example.test\\@api.example.test/x",  # urllib3 connects to evil.example.test
        "https://api.example.test\\.evil.example.test/x",
        "https://ex%61mple.test/x",  # the transport decodes the host, the host check does not
        "https://api.example.test\t.evil.example.test/x",
    ],
)
def test_ambiguous_authorities_are_refused_before_sending(url):
    t = StubTransport()
    seen: list[str] = []
    with pytest.raises(PolicyError) as err:
        client_for(t).request("GET", url, hop_check=seen.append)
    assert err.value.reason_code == "policy"
    assert "ambiguous" in str(err.value) or "cannot parse" in str(err.value)
    assert t.calls == [] and seen == []


def test_a_redirect_to_an_ambiguous_authority_is_refused():
    t = StubTransport().add("GET", "https://api.example.test/x", status=302, location="https://evil.example.test\\@api.example.test/y")
    allowed: list[str] = []
    with pytest.raises(PolicyError, match="ambiguous"):
        client_for(t).request("GET", "https://api.example.test/x", hop_check=allowed.append)
    assert t.urls() == ["https://api.example.test/x"] and allowed == ["https://api.example.test/x"]


def test_idn_and_ipv6_hosts_are_not_ambiguous():
    t = StubTransport().add("GET", "https://bücher.example/x", text="idn").add("GET", "https://[2001:db8::1]:8443/x", text="v6")
    c = client_for(t)
    assert c.request("GET", "https://bücher.example/x").text == "idn"
    assert c.request("GET", "https://[2001:db8::1]:8443/x").text == "v6"


def test_a_credential_bearing_body_is_never_re_sent_to_another_origin():
    redact.register_secret(SECRET, label="demo")
    t = StubTransport()
    t.add("POST", "https://api.example.test/v1/check", status=307, location="https://collector.example.net/x", times=3)
    t.add("POST", "https://api.example.test/v1/same", status=308, location="/v1/same2")
    t.add("POST", "https://api.example.test/v1/same2", json={"ok": True})
    t.add("POST", "https://collector.example.net/x", json={"ok": True})
    c = client_for(t)
    for body in ({"data": f"apikey={SECRET}&q=1"}, {"data": "api_key=unregistered-value&q=1"}, {"json_body": {"query": "x", "apikey": "unregistered-value"}}):
        before = len(t.calls)
        with pytest.raises(PolicyError, match="credential-bearing request body"):
            c.request("POST", "https://api.example.test/v1/check", **body)
        assert [call["url"] for call in t.calls[before:]] == ["https://api.example.test/v1/check"]
    # same origin: the body follows a 308 as the method requires
    assert c.request("POST", "https://api.example.test/v1/same", data=f"apikey={SECRET}").json() == {"ok": True}
    assert t.calls[-1]["body"] == f"apikey={SECRET}".encode()
    # another origin without credentials in the body: followed
    t.add("POST", "https://api.example.test/v1/plain", status=307, location="https://collector.example.net/x")
    assert c.request("POST", "https://api.example.test/v1/plain", json_body={"q": 1}).json() == {"ok": True}


def test_a_303_drops_the_body_so_the_cross_origin_hop_is_allowed():
    t = StubTransport().add("POST", "https://api.example.test/form", status=303, location="https://cdn.example.net/result")
    t.add("GET", "https://cdn.example.net/result", text="done")
    assert client_for(t).request("POST", "https://api.example.test/form", data={"apikey": "unregistered-value"}).text == "done"
    assert t.calls[1]["method"] == "GET" and t.calls[1]["body"] is None
