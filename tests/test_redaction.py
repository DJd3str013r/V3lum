"""AR01 central redaction: registered secrets and key-like parameters never leave the HTTP client
(cache rows, events, request records, exception text), path-embedded keys included."""

from __future__ import annotations

import sqlite3
import threading
from urllib.parse import quote

import pytest

from tests.fixtures.http.stub_transport import StubClock, StubTransport, registry
from v3lum.core import redact
from v3lum.core.http import AuthRequired, HttpCache, HttpClient, HttpError, NetworkError, PolicyError, RequestInfo, Response, ScopedHttp

FAKE_KEY = "FAKEabusechAuthKey0123456789abcdef"
FAKE_TOKEN = "ghp_FAKEtoken0123456789"


@pytest.fixture(autouse=True)
def secrets():
    redact.clear()
    redact.register_secret(FAKE_KEY, label="abusech")
    redact.register_secret(FAKE_TOKEN, label="github")
    yield
    redact.clear()


# --------------------------------------------------------------------------------------
# the redactor
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("param", redact.KEY_PARAMS)
def test_key_like_params_are_masked(param):
    url = f"https://api.example.test/v1/lookup?q=example.com&{param}=s3cr3tvalue&page=2"
    out = redact.redact_url(url)
    assert "s3cr3tvalue" not in out
    assert f"{param}={redact.MASK}" in out
    assert "q=example.com" in out and "page=2" in out


def test_param_matching_is_case_insensitive_and_exact():
    out = redact.redact_url("https://a.example.test/x?API_KEY=abcdef123&author=john&tokens=keepme&Key=zzzzzz9")
    assert "abcdef123" not in out and "zzzzzz9" not in out
    assert "author=john" in out and "tokens=keepme" in out  # only exact key-like names
    assert redact.redact_url("https://a.example.test/x?key=") == "https://a.example.test/x?key="


def test_fragment_and_userinfo_are_masked():
    out = redact.redact_url("https://user:hunter2pass@a.example.test/cb#access_token=tok123456&state=1")
    assert "hunter2pass" not in out and "tok123456" not in out
    assert out.startswith(f"https://user:{redact.MASK}@a.example.test/cb#access_token={redact.MASK}")


def test_path_embedded_registered_key_is_masked():
    url = f"https://threatfox-api.abuse.ch/v2/files/exports/{FAKE_KEY}/recent.csv"
    out = redact.redact_url(url)
    assert FAKE_KEY not in out and out == f"https://threatfox-api.abuse.ch/v2/files/exports/{redact.MASK}/recent.csv"


def test_url_encoded_secret_is_masked():
    secret = "AbC+/x=Secret99"
    redact.register_secret(secret)
    out = redact.redact_url(f"https://a.example.test/x?q={quote(secret, safe='')}")
    assert quote(secret, safe="") not in out and secret not in out


def test_registration_rules():
    assert redact.registered_count() == 2
    assert not redact.register_secret("short")  # < 6 characters are ignored
    assert not redact.register_secret("")
    assert not redact.register_secret(None)
    assert redact.register_secret("  padded-secret-1  ")
    assert redact.redact_text("x padded-secret-1 y") == f"x {redact.MASK} y"
    assert redact.registered_count() == 3
    redact.clear()
    assert redact.registered_count() == 0 and redact.redact_text(FAKE_KEY) == FAKE_KEY


def test_registration_is_thread_safe():
    values = [f"thread-secret-{i:04d}" for i in range(200)]
    threads = [threading.Thread(target=lambda v=v: redact.register_secret(v)) for v in values]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert redact.registered_count() == 2 + len(values)
    assert all(redact.MASK in redact.redact_text(v) for v in values)


def test_redact_text_masks_secrets_and_urls_in_free_text():
    text = f"HTTPSConnectionPool(host='a', port=443): Max retries exceeded with url: /x?apikey=abcdef0123 (token {FAKE_TOKEN})"
    out = redact.redact_text(text)
    assert "abcdef0123" not in out and FAKE_TOKEN not in out
    assert redact.redact_text(None) == "" and redact.redact_text("") == ""


def test_redact_headers():
    headers = {"Authorization": "Bearer xyz", "X-Api-Key": "k", "Cookie": "a=b", "Auth-Key": "zz", "X-Custom": FAKE_TOKEN, "Accept": "application/json"}
    out = redact.redact_headers(headers)
    assert out == {"Authorization": "***", "X-Api-Key": "***", "Cookie": "***", "Auth-Key": "***", "X-Custom": "***", "Accept": "application/json"}
    assert redact.is_credential_header("X-Auth-Token") and redact.is_credential_header("Other", FAKE_KEY)
    assert not redact.is_credential_header("Accept", "application/json")
    assert redact.has_secret(f"..{FAKE_KEY}..") and not redact.has_secret("nothing here")


# --------------------------------------------------------------------------------------
# nothing leaves the client unredacted
# --------------------------------------------------------------------------------------


def _db_bytes(path) -> bytes:
    conn = sqlite3.connect(str(path))
    try:
        rows = conn.execute("SELECT key, url, host, headers, body, history FROM cache").fetchall()
    finally:
        conn.close()
    return repr(rows).encode()


def test_cache_url_column_is_redacted_and_lookup_still_works(tmp_path):
    db = tmp_path / "c.db"
    cache = HttpCache(str(db))
    try:
        clock = StubClock()
        url_query = f"https://urlhaus-api.abuse.ch/v1/host/?auth_key={FAKE_KEY}&host=example.com"
        url_path = f"https://threatfox-api.abuse.ch/v2/files/exports/{FAKE_KEY}/recent.csv"
        t = StubTransport(clock).add("GET", url_query, json={"query_status": "no_results"})
        t.add("GET", url_path, status=302, location=f"/v2/files/exports/{FAKE_KEY}/full.csv")
        t.add("GET", f"https://threatfox-api.abuse.ch/v2/files/exports/{FAKE_KEY}/full.csv", text="ioc,type")
        c = HttpClient(cache=cache, transport=t, clock=clock, providers=registry())
        for url in (url_query, url_path):
            first = c.request("GET", url)
            again = c.request("GET", url)
            assert not first.from_cache and again.from_cache
            assert again.content == first.content
        assert again.url.endswith("/full.csv") and FAKE_KEY not in again.url  # stored chains stay redacted
        assert c.request("GET", url_query).url == url_query  # the caller's own URL is restored on hits
        dump = _db_bytes(db)
        assert FAKE_KEY.encode() not in dump
        assert b"auth_key=***" in dump and b"/exports/***/" in dump
        assert len(t.calls) == 3
    finally:
        cache.close()


def test_events_and_request_records_carry_no_secret():
    events: list[tuple] = []
    infos: list[RequestInfo] = []
    clock = StubClock()
    t = StubTransport(clock).add("GET", f"https://api.example.test/v1/x?key={FAKE_KEY}", status=401, text="bad key")
    t.add("GET", f"https://api.example.test/v2/{FAKE_TOKEN}/y", status=503, text="busy")
    c = HttpClient(transport=t, clock=clock, providers=registry(), retries=1, on_request=lambda *a: events.append(a), on_request_info=infos.append)
    scoped = ScopedHttp(c)
    scoped.get(f"https://api.example.test/v1/x?key={FAKE_KEY}")
    scoped.get(f"https://api.example.test/v2/{FAKE_TOKEN}/y")
    blob = repr(events) + repr(infos) + repr([i.to_dict() for i in scoped.request_log])
    assert FAKE_KEY not in blob and FAKE_TOKEN not in blob
    assert len(events) == 3 and len(infos) == 3 and len(scoped.request_log) == 3


def test_exception_text_carries_no_secret():
    clock = StubClock()
    t = StubTransport(clock)
    t.add("GET", f"https://api.example.test/a?apikey={FAKE_KEY}", status=403, text=f"invalid key {FAKE_KEY}")
    t.add("GET", f"https://api.example.test/b/{FAKE_TOKEN}", text="not json")
    t.add("GET", f"https://down.example.test/c?token={FAKE_TOKEN}", error=NetworkError(f"ConnectionError contacting down.example.test: url=/c?token={FAKE_TOKEN}"))
    c = HttpClient(transport=t, clock=clock, providers=registry(), retries=0)
    errors: list[BaseException] = []
    with pytest.raises(AuthRequired) as auth:
        c.request("GET", f"https://api.example.test/a?apikey={FAKE_KEY}").raise_for_status()
    errors.append(auth.value)
    with pytest.raises(HttpError) as bad_json:
        c.request("GET", f"https://api.example.test/b/{FAKE_TOKEN}").json()
    errors.append(bad_json.value)
    with pytest.raises(NetworkError) as net:
        c.request("GET", f"https://down.example.test/c?token={FAKE_TOKEN}")
    errors.append(net.value)
    with pytest.raises(PolicyError) as policy:
        c.request("GET", f"ftp://files.example.test/{FAKE_KEY}")
    errors.append(policy.value)
    for exc in errors:
        text = str(exc) + repr(exc.args) + str(getattr(exc, "url", "")) + str(getattr(exc, "body", ""))
        assert FAKE_KEY not in text and FAKE_TOKEN not in text, text


def test_error_classes_redact_on_construction():
    exc = HttpError(f"HTTP 500 from {FAKE_KEY}", 500, f"https://a.example.test/?key={FAKE_KEY}", f"body {FAKE_TOKEN}".encode())
    assert FAKE_KEY not in str(exc) and FAKE_KEY not in exc.url and FAKE_TOKEN not in exc.body
    assert exc.reason_code == "error" and exc.status == 500


def test_response_url_stays_usable_for_the_module():
    """Redaction applies to what leaves the client; the module still gets its real response."""
    clock = StubClock()
    url = f"https://api.example.test/x?key={FAKE_KEY}"
    t = StubTransport(clock).add("GET", url, json={"ok": True})
    resp = HttpClient(transport=t, clock=clock, providers=registry()).request("GET", url)
    assert resp.url == url and isinstance(resp, Response)


def test_key_params_in_form_bodies_and_free_text_are_masked():
    """Echoed request bodies and error texts carry 'apikey=...' without a URL around it."""
    assert redact.redact_text("apikey=unregistered1&domain=example.com") == f"apikey={redact.MASK}&domain=example.com"
    masked = redact.redact_text("bad request (key=unregistered2) for x")
    assert "unregistered2" not in masked and masked.startswith(f"bad request (key={redact.MASK}")  # over-masking is fine
    assert redact.redact_text("monkey=banana turkey=1 path/key=value") == "monkey=banana turkey=1 path/key=value"  # names must match exactly
    exc = HttpError("HTTP 400 echo: token=unregistered3&q=1", 400, "https://a.example.test/x", b"signature=unregistered4")
    assert "unregistered3" not in str(exc) and "unregistered4" not in exc.body


def test_cache_hits_give_the_module_its_own_url_back(tmp_path):
    """The stored URL is redacted (and may be normalised by the transport); a hit without redirects
    returns the caller's real URL so modules can keep using resp.url."""
    cache = HttpCache(str(tmp_path / "c.db"))
    try:
        clock = StubClock()
        url = f"https://threatfox-api.abuse.ch/v2/files/exports/{FAKE_KEY}/recent.csv"

        class Normalising(StubTransport):
            def send(self, method, url, **kw):
                resp = super().send(method, url, **kw)
                resp.url = url + "?"  # e.g. a transport re-quoting the URL
                return resp

        t = Normalising(clock).add("GET", url, text="ioc,type")
        c = HttpClient(cache=cache, transport=t, clock=clock, providers=registry())
        c.request("GET", url)
        hit = c.request("GET", url)
        assert hit.from_cache and hit.url == url and hit.host == "threatfox-api.abuse.ch"
        assert FAKE_KEY.encode() not in _db_bytes(tmp_path / "c.db")
    finally:
        cache.close()
