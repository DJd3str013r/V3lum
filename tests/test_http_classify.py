"""P321 body-error classification: generic WAF/challenge fingerprints, login walls, geo-blocks,
declared error-in-200 markers, keyless 403, circuit. Classified answers are never cached and never
read as an absence."""

from __future__ import annotations

import re

import pytest

from tests.fixtures.http.stub_transport import StubClock, StubTransport, load, provider, registry
from v3lum.core.http import (
    AuthRequired,
    Blocked,
    Classification,
    HttpCache,
    HttpClient,
    HttpError,
    QuotaExceeded,
    RateLimited,
    Response,
    block_reason,
    classify,
)

NEVER = {"empty", "absent", "ok", "not_found"}


@pytest.fixture()
def cache(tmp_path):
    c = HttpCache(str(tmp_path / "cache.db"))
    yield c
    c.close()


def client_for(transport: StubTransport, cache: HttpCache | None = None, *, providers=None, clock=None, **kw) -> HttpClient:
    clock = clock or StubClock()
    transport.clock = clock
    return HttpClient(cache=cache, transport=transport, clock=clock, providers=providers if providers is not None else registry(), retries=0, **kw)


# --------------------------------------------------------------------------------------
# generic fingerprints (one trimmed fixture per marker)
# --------------------------------------------------------------------------------------

GENERIC = [
    ("cloudflare_challenge.html", 403, "Cloudflare"),
    ("cloudflare_block.html", 403, "Cloudflare"),
    ("aws_waf_challenge.html", 202, "AWS WAF"),
    ("perimeterx_block.html", 403, "PerimeterX"),
    ("incapsula_block.html", 200, "Incapsula"),  # strong markers count on any status
    ("ddos_guard_challenge.html", 403, "DDoS-Guard"),
    ("vercel_checkpoint.html", 429, "Vercel"),
    ("captcha_page.html", 403, "CAPTCHA"),  # weak marker on an error status
]


@pytest.mark.parametrize(("fixture_name", "status", "vendor"), GENERIC, ids=[g[0] for g in GENERIC])
def test_generic_marker_is_blocked_challenge_and_not_cached(fixture_name, status, vendor, cache):
    t = StubTransport().add("GET", "https://site.example.test/profile/x", status=status, body=load(fixture_name), content_type="text/html; charset=utf-8")
    c = client_for(t, cache, providers=registry(provider("demo_site", ("site.example.test",), name="Demo Site")))
    resp = c.request("GET", "https://site.example.test/profile/x")
    cls = resp.classification
    assert cls is not None and cls.status == "blocked" and cls.reason_code == "challenge"
    assert cls.reason.startswith("Demo Site:") and vendor in cls.reason
    assert "could not verify" in cls.reason
    assert not resp.from_cache and cache.stats()["entries"] == 0
    with pytest.raises(Blocked) as err:
        resp.raise_for_status()
    assert err.value.reason_code == "challenge"


@pytest.mark.parametrize(
    "fixture_name",
    ["captcha_page.html", "normal_200_awswaf_sdk.html", "json_api_with_page_titles.json"],
)
def test_normal_200_pages_mentioning_captcha_are_not_blocked(fixture_name, cache):
    """Weak-marker regression: captcha widgets, the AWS WAF SDK and challenge titles stored as JSON data
    on a normal HTTP 200 answer are not a block (and the answer is cached normally)."""
    ctype = "application/json" if fixture_name.endswith(".json") else "text/html; charset=utf-8"
    t = StubTransport().add("GET", "https://portaldatransparencia.gov.br/busca", body=load(fixture_name), content_type=ctype)
    c = client_for(t, cache)
    resp = c.request("GET", "https://portaldatransparencia.gov.br/busca")
    assert resp.classification is None and resp.raise_for_status().ok
    assert resp.blocked is None
    assert c.request("GET", "https://portaldatransparencia.gov.br/busca").from_cache


def test_json_documents_never_match_body_fingerprints():
    body = load("json_api_with_page_titles.json")
    for status in (200, 403, 503):
        assert classify(Response(status, "https://api.example.test/x", {"content-type": "application/json"}, body)) is None
    # a 403 JSON answer of a keyed API is an auth problem, not a challenge
    assert classify(Response(403, "https://api.example.test/x", {"content-type": "application/json", "server": "cloudflare"}, body)) is None


# --------------------------------------------------------------------------------------
# login walls and access-restriction pages (final URL)
# --------------------------------------------------------------------------------------


def test_login_wall_by_final_url(cache):
    t = StubTransport().add(
        "GET",
        "https://www.linkedin.com/in/someone",
        body=load("linkedin_authwall.html"),
        content_type="text/html",
        final_url="https://www.linkedin.com/authwall?trk=TRIMMED&sessionRedirect=https%3A%2F%2Fwww.linkedin.com%2Fin%2Fsomeone",
    )
    c = client_for(t, cache)
    resp = c.request("GET", "https://www.linkedin.com/in/someone")
    assert resp.classification.status == "blocked" and resp.classification.reason_code == "login_wall"
    assert "someone" not in resp.classification.reason  # only the login path is quoted
    assert cache.stats()["entries"] == 0
    with pytest.raises(Blocked) as err:
        resp.raise_for_status()
    assert err.value.reason_code == "login_wall"
    assert "www.linkedin.com" not in c.circuit_hosts()  # login walls do not trip the circuit


@pytest.mark.parametrize(
    "location",
    ["/accounts/login/?next=/someone/", "https://www.facebook.com/login.php?next=x", "/signin?return=%2Fx", "https://login.example.test/oauth"],
)
def test_redirect_to_a_login_page_stops_at_the_redirect(location, cache):
    t = StubTransport().add("GET", "https://www.instagram.com/someone/", status=302, location=location)
    c = client_for(t, cache)
    resp = c.request("GET", "https://www.instagram.com/someone/")
    assert resp.status == 302 and resp.classification.reason_code == "login_wall"
    assert len(t.calls) == 1  # the login page itself is never fetched


def test_a_requested_login_path_is_not_a_wall(cache):
    """Only redirects count: a profile named 'login' requested directly is ordinary data."""
    t = StubTransport().add("GET", "https://api.github.com/users/login", json={"login": "login", "id": 1})
    resp = client_for(t, cache).request("GET", "https://api.github.com/users/login")
    assert resp.classification is None


def test_isc_blockme_redirect_is_a_challenge(cache):
    t = StubTransport()
    t.add("GET", "https://isc.sans.edu/api/ip/203.0.113.9?json", status=302, location="https://isc.sans.edu/blockme.html")
    c = client_for(t, cache)
    resp = c.request("GET", "https://isc.sans.edu/api/ip/203.0.113.9?json")
    assert resp.classification.status == "blocked" and resp.classification.reason_code == "challenge"
    assert "blockme" in resp.classification.reason
    assert "isc.sans.edu" in c.circuit_hosts()


def test_isc_blockme_body_is_a_challenge():
    resp = Response(200, "https://isc.sans.edu/blockme.html", {"content-type": "text/html"}, load("isc_blockme.html"), request_url="https://isc.sans.edu/api/x")
    assert classify(resp).reason_code == "challenge"


# --------------------------------------------------------------------------------------
# geo-blocks
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "fixture_name"),
    [(403, "cloudfront_geo_block.html"), (403, "akamai_access_denied.html"), (451, None)],
    ids=["cloudfront", "akamai", "http451"],
)
def test_geo_block(status, fixture_name, cache):
    body = load(fixture_name) if fixture_name else b"Unavailable For Legal Reasons"
    t = StubTransport().add("GET", "https://www.example.gov.br/consulta", status=status, body=body, content_type="text/html")
    c = client_for(t, cache)
    resp = c.request("GET", "https://www.example.gov.br/consulta")
    cls = resp.classification
    assert cls.status == "blocked" and cls.reason_code == "geo_block"
    assert cls.reason.endswith("needs egress_country / see v3lum doctor --egress")
    assert "www.example.gov.br" in c.circuit_hosts()
    assert cache.stats()["entries"] == 0
    with pytest.raises(Blocked) as err:
        resp.raise_for_status()
    assert err.value.reason_code == "geo_block"


def test_cloudfront_503_is_an_error_not_a_geo_block(cache):
    t = StubTransport().add("GET", "https://feed.example.test/weekly", status=503, body=load("cloudfront_503_not_geo.html"), content_type="text/html")
    resp = client_for(t, cache).request("GET", "https://feed.example.test/weekly")
    assert resp.classification is None
    with pytest.raises(HttpError) as err:
        resp.raise_for_status()
    assert not isinstance(err.value, Blocked) and err.value.reason_code == "error"


# --------------------------------------------------------------------------------------
# declared error-in-200 markers (P321 cond 6), on synthetic providers
# --------------------------------------------------------------------------------------

ERROR_IN_200 = [
    # (provider id, name, host, fixture, marker, expected status, reason_code, reason)
    (
        "hackertarget",
        "HackerTarget",
        "api.hackertarget.com",
        "hackertarget_quota_exceeded.txt",
        {"id": "api_count_exceeded", "regex": "API count exceeded", "maps_to": "quota", "reason": "HackerTarget: daily quota exhausted (API count exceeded)"},
        "quota",
        "quota",
        "HackerTarget: daily quota exhausted (API count exceeded)",
    ),
    (
        "criminalip",
        "Criminal IP",
        "api.criminalip.io",
        "criminalip_nokey.json",
        {"id": "status_403_in_body", "json_path": "status", "equals": 403, "maps_to": "error", "reason": "Criminal IP: access check failed (status 403 in the body)"},
        "error",
        "error",
        "Criminal IP: access check failed (status 403 in the body)",
    ),
    (
        "ipqs",
        "IPQualityScore",
        "www.ipqualityscore.com",
        "ipqs_nokey.json",
        {"id": "success_false", "json_path": "success", "equals": False, "maps_to": "error", "reason": "IPQS: request refused (success=false)"},
        "error",
        "error",
        "IPQS: request refused (success=false)",
    ),
    (
        "etherscan",
        "Etherscan",
        "api.etherscan.io",
        "etherscan_nokey.json",
        {"id": "status_0", "json_path": "status", "equals": "0", "maps_to": "error", "reason": "Etherscan: API error (status 0)"},
        "error",
        "error",
        "Etherscan: API error (status 0)",
    ),
    (
        "checkphish",
        "CheckPhish",
        "developers.checkphish.ai",
        "checkphish_nokey.json",
        {"id": "error_message", "json_path": "errorMessage", "regex": ".", "maps_to": "error", "reason": "CheckPhish: API error (errorMessage)"},
        "error",
        "error",
        "CheckPhish: API error (errorMessage)",
    ),
    (
        "hunter_how",
        "hunter.how",
        "api.hunter.how",
        "hunter_how_nokey.json",
        {"id": "code_401", "json_path": "code", "equals": 401, "maps_to": "error", "reason": "hunter.how: token missing or expired (code 401 in the body)"},
        "error",
        "error",
        "hunter.how: token missing or expired (code 401 in the body)",
    ),
    (
        "leak_lookup",
        "Leak-Lookup",
        "leak-lookup.com",
        "leak_lookup_error.json",
        {"id": "error_true", "json_path": "error", "equals": True, "maps_to": "error", "reason": "Leak-Lookup: API error (error=true)"},
        "error",
        "error",
        "Leak-Lookup: API error (error=true)",
    ),
    (
        "receitaws",
        "ReceitaWS",
        "receitaws.com.br",
        "receitaws_error.json",
        {"id": "status_error", "json_path": "status", "equals": "ERROR", "maps_to": "error", "reason": "ReceitaWS: query error (status ERROR)"},
        "error",
        "error",
        "ReceitaWS: query error (status ERROR)",
    ),
    (
        "tcu",
        "TCU",
        "certidoes-apf.apps.tcu.gov.br",
        "tcu_certidoes_indisponivel.json",
        {
            "id": "sistema_indisponivel",
            "json_path": "certidoes[].situacao",
            "equals": "SISTEMA_INDISPONIVEL",
            "maps_to": "error",
            "reason": "TCU: a certificate system is unavailable (SISTEMA_INDISPONIVEL)",
        },
        "error",
        "error",
        "TCU: a certificate system is unavailable (SISTEMA_INDISPONIVEL)",
    ),
]


@pytest.mark.parametrize(("pid", "name", "host", "fixture_name", "marker", "status", "code", "reason"), ERROR_IN_200, ids=[e[0] for e in ERROR_IN_200])
def test_error_in_200_rules(pid, name, host, fixture_name, marker, status, code, reason, cache):
    body = load(fixture_name)
    ctype = "application/json" if fixture_name.endswith(".json") else "text/plain"
    url = f"https://{host}/api/lookup?q=203.0.113.9"
    t = StubTransport().add("GET", url, body=body, content_type=ctype)
    c = client_for(t, cache, providers=registry(provider(pid, (host,), name=name, markers=(marker,))))
    resp = c.request("GET", url)
    assert resp.status == 200
    assert resp.classification == Classification(status, code, reason, marker["id"])
    assert resp.classification.status not in NEVER
    assert cache.stats()["entries"] == 0  # replayed quota/error bodies were the v1 bug
    expected = QuotaExceeded if status == "quota" else HttpError
    with pytest.raises(expected) as err:
        resp.raise_for_status()
    assert err.value.reason_code == code and str(err.value) == reason


@pytest.mark.parametrize(
    ("fixture_name", "marker"),
    [("tcu_certidoes_ok.json", ERROR_IN_200[8][4]), ("receitaws_ok.json", ERROR_IN_200[7][4])],
    ids=["tcu_ok", "receitaws_ok"],
)
def test_error_markers_leave_good_answers_alone(fixture_name, marker, cache):
    t = StubTransport().add("GET", "https://api.example.test/ok", body=load(fixture_name), content_type="application/json")
    c = client_for(t, cache, providers=registry(provider("demo_ok", ("api.example.test",), markers=(marker,))))
    resp = c.request("GET", "https://api.example.test/ok")
    assert resp.classification is None and resp.json()
    assert c.request("GET", "https://api.example.test/ok").from_cache


def test_caller_markers_come_first_and_accept_dicts_or_objects():
    resp = Response(200, "https://api.example.test/x", {"content-type": "application/json"}, b'{"status": "ERROR", "error": true}')
    module_marker = {"id": "module_rule", "json_path": "error", "equals": True, "maps_to": "rate_limited", "reason": "Example: throttled"}
    provider_marker = provider("p_obj", ("api.example.test",), markers=({"id": "prov_rule", "json_path": "status", "equals": "error", "maps_to": "error", "reason": "Example: error"},)).error_markers[0]
    assert classify(resp, markers=[module_marker, provider_marker]).marker_id == "module_rule"
    assert classify(resp, markers=[provider_marker]).marker_id == "prov_rule"
    # unusable markers (no matcher, bad maps_to, bad regex) are ignored instead of matching everything
    junk = [{"id": "nothing", "maps_to": "error", "reason": "x"}, {"id": "bad", "regex": "(", "maps_to": "error"}, {"id": "map", "regex": "x", "maps_to": "empty"}]
    assert classify(resp, markers=junk) is None


def test_marker_statuses_and_final_url_regex():
    marker = {"id": "only_403", "statuses": [403], "regex": "denied", "final_url_regex": r"/api/", "maps_to": "blocked", "reason": "Example: denied"}
    ok = Response(403, "https://api.example.test/api/x", {}, b"denied")
    assert classify(ok, markers=[marker]).reason_code == "challenge"  # blocked defaults to challenge
    assert classify(Response(200, "https://api.example.test/api/x", {}, b"denied"), markers=[marker]) is None
    assert classify(Response(403, "https://api.example.test/web/x", {}, b"denied"), markers=[marker]) is None


# --------------------------------------------------------------------------------------
# status rules, keyless 403 and headers
# --------------------------------------------------------------------------------------


def test_status_rules():
    assert classify(Response(429, "https://a.example.test/", {"retry-after": "60"}, b"slow down")).status == "rate_limited"
    assert classify(Response(430, "https://a.example.test/", {}, b"")).reason_code == "challenge"
    assert classify(Response(999, "https://a.example.test/", {}, b"Request denied")).reason_code == "challenge"
    assert classify(Response(404, "https://a.example.test/", {}, b"not here")) is None
    assert classify(Response(500, "https://a.example.test/", {}, b"oops")) is None


def test_keyless_403_is_blocked_could_not_verify(cache):
    t = StubTransport().add("GET", "https://open.example.test/v1/x", status=403, text="Forbidden")
    t.add("GET", "https://keyed.example.test/v1/x", status=403, text="Forbidden")
    c = client_for(t, cache)
    keyless = c.request("GET", "https://open.example.test/v1/x", keyless=True)
    assert keyless.classification.reason_code == "challenge"
    assert keyless.classification.reason.endswith("HTTP 403 for a keyless source: could not verify")
    with pytest.raises(Blocked):
        keyless.raise_for_status()
    keyed = c.request("GET", "https://keyed.example.test/v1/x")
    assert keyed.classification is None
    with pytest.raises(AuthRequired):
        keyed.raise_for_status()


def test_challenge_headers():
    assert classify(Response(200, "https://a.example.test/", {"cf-mitigated": "challenge"}, b"<html></html>")).marker_id == "header.cf_mitigated"
    assert classify(Response(405, "https://a.example.test/", {"x-amzn-waf-action": "captcha"}, b"")).marker_id == "header.aws_waf"
    assert classify(Response(403, "https://a.example.test/", {"server": "cloudflare"}, b"denied")).marker_id == "header.cloudflare"


def test_rate_limited_answers_raise_rate_limited(cache):
    t = StubTransport().add("GET", "https://a.example.test/x", status=429, headers={"Retry-After": "120"}, text="slow down")
    resp = client_for(t, cache).request("GET", "https://a.example.test/x")
    assert resp.classification.status == "rate_limited"
    with pytest.raises(RateLimited):
        resp.raise_for_status()


# --------------------------------------------------------------------------------------
# circuit (A9 BR6, P321 cond 10)
# --------------------------------------------------------------------------------------


def test_circuit_short_circuits_the_host_after_a_challenge(cache):
    t = StubTransport().add("GET", re.compile(r"^https://walled\.example\.test/"), status=403, body=load("cloudflare_challenge.html"), content_type="text/html")
    t.add("GET", "https://other.example.test/x", text="fine")
    c = client_for(t, cache)
    first = c.request("GET", "https://walled.example.test/a")
    assert first.classification.reason_code == "challenge"
    assert c.circuit_hosts() == frozenset({"walled.example.test"})
    with pytest.raises(Blocked) as err:
        c.request("GET", "https://walled.example.test/b")
    assert err.value.reason_code == "circuit" and "short-circuited" in str(err.value)
    assert len(t.calls) == 1  # nothing was sent the second time
    assert c.request("GET", "https://other.example.test/x").classification is None
    c.reset_circuit()
    assert c.circuit_hosts() == frozenset()
    assert c.request("GET", "https://walled.example.test/c").classification.reason_code == "challenge"
    assert len([u for u in t.urls() if "walled" in u]) == 2


def test_rate_limits_do_not_trip_the_circuit(cache):
    t = StubTransport().add("GET", "https://busy.example.test/x", status=429, text="slow down", times=1)
    t.add("GET", "https://busy.example.test/x", text="ok")
    c = client_for(t, cache)
    assert c.request("GET", "https://busy.example.test/x").status == 429
    assert c.circuit_hosts() == frozenset()
    assert c.request("GET", "https://busy.example.test/x").ok


def test_stale_cached_challenge_page_is_never_replayed(cache):
    """A challenge page cached by v1 (the P321 bug) is dropped on read and fetched again."""
    url = "https://api.example.test/v1/item"
    key = HttpClient.cache_key("GET", url)
    cache.put(key, Response(200, url, {"content-type": "text/html"}, load("cloudflare_challenge.html")), now=StubClock().now().timestamp())
    assert cache.stats()["entries"] == 1
    t = StubTransport().add("GET", url, json={"ok": True})
    c = client_for(t, cache)
    resp = c.request("GET", url)
    assert not resp.from_cache and resp.json() == {"ok": True} and len(t.calls) == 1


# --------------------------------------------------------------------------------------
# compatibility and invariants
# --------------------------------------------------------------------------------------


def test_block_reason_wrapper_keeps_v1_semantics():
    challenge = load("cloudflare_challenge.html")
    assert block_reason(403, {"Server": "cloudflare"}, challenge)
    assert block_reason(200, {}, challenge)
    assert block_reason(404, {}, challenge) is None  # v1 status pre-filter kept
    assert block_reason(429, {}, b"slow down") is None  # rate limits are not blocks
    assert "egress" in (block_reason(451, {}, b"") or "")


def test_classification_never_means_absent():
    bodies = [load(name) for name in ("cloudflare_challenge.html", "captcha_page.html", "cloudfront_geo_block.html", "hackertarget_quota_exceeded.txt")]
    statuses = (200, 202, 302, 401, 403, 404, 429, 430, 451, 500, 503, 999)
    for body in bodies:
        for status in statuses:
            for keyless in (False, True):
                found = classify(Response(status, "https://x.example.test/a", {"content-type": "text/html"}, body), keyless=keyless)
                assert found is None or (found.status in {"blocked", "rate_limited", "quota", "error"} and found.reason)


def test_a_plain_cloudflare_503_is_an_origin_error_not_a_challenge():
    assert classify(Response(503, "https://a.example.test/", {"server": "cloudflare"}, b"<html>Service Unavailable</html>")) is None
    marked = classify(Response(503, "https://a.example.test/", {"server": "cloudflare", "cf-mitigated": "block"}, b"<html>x</html>"))
    assert marked is not None and marked.reason_code == "challenge"


# --------------------------------------------------------------------------------------
# review additions: interstitials from the research samples served with 200/403
# --------------------------------------------------------------------------------------

SAMPLE_INTERSTITIALS = [
    # (fixture, status, marker id, vendor): trimmed real research samples
    ("abusech_browser_check.html", 200, "generic.abusech_browser_check", "abuse.ch"),  # bazaar/urlhaus/threatfox web UI
    ("domaintools_captcha.html", 200, "generic.domaintools_captcha", "DomainTools"),  # whois.domaintools.com
    ("netcraft_challenge.html", 200, "generic.netcraft_challenge", "Netcraft"),  # searchdns.netcraft.com
    ("facebook_rd_challenge.html", 403, "generic.facebook_challenge", "Facebook"),  # Ad Library JS challenge
    ("cloudflare_custom_block.html", 403, "generic.cloudflare_custom_block", "Cloudflare"),  # custom WAF rule page
    ("incapsula_js_challenge.html", 200, "generic.incapsula_js_challenge", "Incapsula"),  # reconstruction
]


@pytest.mark.parametrize(("fixture_name", "status", "marker_id", "vendor"), SAMPLE_INTERSTITIALS, ids=[s[0] for s in SAMPLE_INTERSTITIALS])
def test_sample_interstitials_are_challenges_and_not_cached(fixture_name, status, marker_id, vendor, cache):
    t = StubTransport().add("GET", "https://site.example.test/page", status=status, body=load(fixture_name), content_type="text/html; charset=utf-8")
    c = client_for(t, cache, providers=registry(provider("demo_site", ("site.example.test",), name="Demo Site")))
    resp = c.request("GET", "https://site.example.test/page")
    cls = resp.classification
    assert cls is not None and (cls.status, cls.reason_code, cls.marker_id) == ("blocked", "challenge", marker_id)
    assert cls.reason.startswith("Demo Site:") and vendor in cls.reason and "could not verify" in cls.reason
    assert cache.stats()["entries"] == 0 and "site.example.test" in c.circuit_hosts()
    with pytest.raises(Blocked):
        resp.raise_for_status()


def test_interstitial_titles_count_on_any_status():
    for title in ("Whois Lookup Captcha", "MalwareBazaar | Checking your browser", "Human Verification", "Bot verification", "Are you a robot?"):
        page = f"<html><head><title>\n  {title}\n</title></head><body>x</body></html>".encode()
        found = classify(Response(200, "https://a.example.test/", {"content-type": "text/html"}, page))
        assert found is not None and found.reason_code == "challenge" and found.marker_id.startswith("generic.title_"), title
    normal = b"<html><head><title>Captain's log - recaptured ships</title></head><body>g-recaptcha</body></html>"
    assert classify(Response(200, "https://a.example.test/", {"content-type": "text/html"}, normal)) is None


def test_a_normal_incapsula_page_is_not_a_challenge(cache):
    """Every page behind Incapsula loads /_Incapsula_Resource: only the near-empty noindex shape is a challenge."""
    t = StubTransport().add("GET", "https://insure.example.test/products", body=load("incapsula_normal_page.html"), content_type="text/html")
    c = client_for(t, cache)
    resp = c.request("GET", "https://insure.example.test/products")
    assert resp.classification is None and c.request("GET", "https://insure.example.test/products").from_cache
    padded = load("incapsula_js_challenge.html").replace(b"<body>", b"<body>" + b"<p>real content</p>" * 200)
    assert classify(Response(200, "https://insure.example.test/", {"content-type": "text/html"}, padded)) is None


def test_block_message_after_a_long_prefix_is_found():
    """Reddit's block page puts its message after ~190 KB of inline CSS: the tail is searched too."""
    page = load("reddit_network_security_block.html")
    head, sep, rest = page.partition(b"</style>")
    big = head + b"/*" + b"x" * (3 * 64 * 1024) + b"*/" + sep + rest
    assert len(big) > 3 * 64 * 1024
    for status in (200, 403):
        found = classify(Response(status, "https://www.reddit.com/user/someone/about.json", {"content-type": "text/html"}, big))
        assert found is not None and found.marker_id == "generic.network_security_block", status
    # weak words in the tail of a normal long page still count on error statuses only
    normal = b"<html><body>" + b"<p>post</p>" * 10000 + b"<div class='g-recaptcha'></div></body></html>"
    assert len(normal) > 64 * 1024
    assert classify(Response(200, "https://a.example.test/", {"content-type": "text/html"}, normal)) is None
    assert classify(Response(403, "https://a.example.test/", {"content-type": "text/html"}, normal)).marker_id == "generic.captcha"


def test_requested_login_flows_are_not_walls():
    """A module that asks for a login URL (or queries an identity provider) is not walled by its redirects."""
    oidc = Response(200, "https://login.example-idp.test/tenant/v2.0/.well-known/openid-configuration", {"content-type": "application/json"}, b"{}",
                    history=["https://login.example-idp.test/tenant/.well-known/openid-configuration"],
                    request_url="https://login.example-idp.test/tenant/.well-known/openid-configuration")
    assert classify(oidc) is None
    flow = Response(200, "https://example.test/login/step2", {"content-type": "text/html"}, b"<html>form</html>",
                    history=["https://example.test/login"], request_url="https://example.test/login")
    assert classify(flow) is None
    walled = Response(200, "https://login.example.test/oauth", {"content-type": "text/html"}, b"<html>sign in</html>",
                      history=["https://www.example.test/profile/x"], request_url="https://www.example.test/profile/x")
    assert classify(walled).reason_code == "login_wall"


def test_the_circuit_trips_only_the_host_that_served_the_challenge(cache):
    t = StubTransport()
    t.add("GET", "https://short.example.test/a", status=302, location="https://walled.example.test/x")
    t.add("GET", "https://walled.example.test/x", status=403, body=load("cloudflare_challenge.html"), content_type="text/html")
    t.add("GET", "https://short.example.test/b", status=302, location="https://fine.example.test/y")
    t.add("GET", "https://fine.example.test/y", text="ok")
    t.add("GET", "https://short.example.test/c", status=302, location="https://walled.example.test/z")
    c = client_for(t, cache)
    assert c.request("GET", "https://short.example.test/a").classification.reason_code == "challenge"
    assert c.circuit_hosts() == frozenset({"walled.example.test"})  # the redirector keeps working
    assert c.request("GET", "https://short.example.test/b").text == "ok"
    with pytest.raises(Blocked) as err:  # ...but a hop to the walled host is short-circuited
        c.request("GET", "https://short.example.test/c")
    assert err.value.reason_code == "circuit"
    assert "https://walled.example.test/z" not in t.urls()


def test_a_module_marker_miss_keeps_the_shared_cache_row(cache):
    """A row another caller may use is not deleted because one module's own marker rejects it."""
    t = StubTransport().add("GET", "https://api.example.test/v1/x", json={"status": "degraded", "items": [1]}, times=2)
    c = client_for(t, cache)
    assert c.request("GET", "https://api.example.test/v1/x").classification is None
    assert cache.stats()["entries"] == 1
    strict = {"id": "degraded", "json_path": "status", "equals": "degraded", "maps_to": "error", "reason": "Example: degraded answer"}
    resp = c.request("GET", "https://api.example.test/v1/x", markers=(strict,))
    assert not resp.from_cache and resp.classification.marker_id == "degraded"
    assert cache.stats()["entries"] == 1  # still there for the other callers
    assert c.request("GET", "https://api.example.test/v1/x").from_cache


def test_rich_pages_with_captcha_titles_or_form_phrases_are_not_walls():
    """A profile named 'captcha' or a contact form saying 'confirm that you are not a robot' on a full page
    is ordinary data; only small interstitial pages are matched by these words."""
    filler = b"<section><p>repositories, followers, activity</p></section>" * 700
    profile = b"<html><head><title>captcha (Captcha Dev) \xc2\xb7 GitHub</title></head><body>" + filler + b"</body></html>"
    contact = b"<html><head><title>Contact us</title></head><body>" + filler + b"<form><p>Please confirm that you are not a robot</p><div class='g-recaptcha'></div></form></body></html>"
    for page in (profile, contact):
        assert len(page) > 32 * 1024
        assert classify(Response(200, "https://github.com/captcha", {"content-type": "text/html"}, page)) is None
    small = b"<html><head><title>captcha (Captcha Dev)</title></head><body>tiny</body></html>"
    assert classify(Response(200, "https://site.example.test/captcha", {"content-type": "text/html"}, small)).marker_id == "generic.title_captcha"
