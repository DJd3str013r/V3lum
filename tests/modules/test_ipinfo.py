"""ipinfo (P036): header-only token, keyless never, status mapping and attribution.

Fixtures in tests/fixtures/ipinfo/: the recorded IPinfo error answers of 2026-11-25/26 (keyless 429
'Rate limit hit' from the shared egress, the bad-token 403 'Unknown token' and the identical Lite 403
without a token) plus two labelled synthetic answers (the documented Lite success shape, to be
replaced by a trimmed capture made with the team token before merge, P036 cond 6; and a bogon answer).
"""

from __future__ import annotations

import json

from tests.fakes import FIXTURES, FakeHttp, assert_no_secret, make_runtime, module_fixture, run_module
from v3lum import paths
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.ip_network.ipinfo import ATTRIBUTION, LITE_URL, IpInfo, lite_request, parse_lite

TOKEN = "ipinfo-test-token-0123456789"
KEYS = {"ipinfo": TOKEN}
URL = LITE_URL.format(ip="8.8.8.8")
CHALLENGE = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body><div id=\"cf-chl-widget\"></div></body></html>"


def fx(name):
    return module_fixture("ipinfo", name)


def ok_http():
    return FakeHttp().add("GET", URL, json=fx("lite_ok_synthetic.json"), match_headers={"Authorization": f"Bearer {TOKEN}"})


# ------------------------------------------------------------------ c1: key required, header only
def test_needs_key_without_a_token_and_never_calls_keyless():
    http = FakeHttp()
    res = run_module(IpInfo, "ipv4:8.8.8.8", http)
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key"
    assert http.calls == []


def test_token_only_in_the_authorization_header():
    url, headers = lite_request("8.8.8.8", TOKEN)
    assert TOKEN not in url and "token=" not in url
    assert headers["Authorization"] == f"Bearer {TOKEN}"
    http = ok_http()
    run_module(IpInfo, "ipv4:8.8.8.8", http, keys=KEYS)
    call = http.calls[0]
    assert TOKEN not in call["url"] and "token=" not in call["url"]
    assert call["headers"].get("Authorization") == f"Bearer {TOKEN}"


# ------------------------------------------------------------------ c3: Lite answer
def test_lite_answer_country_asn_and_pivots():
    http = ok_http()
    res = run_module(IpInfo, "ipv4:8.8.8.8", http, keys=KEYS)
    assert res.status is Status.OK
    assert res.attributes["asn"] == "AS15169" and res.attributes["as_org"] == "Google LLC"
    assert res.attributes["country"] == "US" and res.attributes["continent"] == "NA"
    assert res.attributes["as_domain"] == "google.com"
    assert res.attributes["data_attribution"] == ATTRIBUTION  # c5
    pivots = {(p.entity.type, p.entity.value): p for p in res.pivots}
    asn = pivots[(T.ASN, "AS15169")]
    assert asn.relation == "belongs_to_asn" and asn.expand is True
    dom = pivots[(T.DOMAIN, "google.com")]
    assert dom.relation == "operator_domain" and dom.expand is False
    assert ("IPinfo IP page", "https://ipinfo.io/8.8.8.8") in res.links
    assert ("IPinfo AS page", "https://ipinfo.io/AS15169") in res.links
    http.assert_hosts_within(IpInfo)


def test_core_api_shape_is_understood():
    fields = parse_lite({"ip": "8.8.8.8", "org": "AS15169 Google LLC", "country": "US"})
    assert fields["asn"] == 15169 and fields["as_name"] == "Google LLC" and fields["country_code"] == "US"


def test_ipv6_lookup():
    url = LITE_URL.format(ip="2001:4860:4860::8888")
    body = dict(fx("lite_ok_synthetic.json"), ip="2001:4860:4860::8888")
    http = FakeHttp().add("GET", url, json=body)
    res = run_module(IpInfo, "ipv6:2001:4860:4860::8888", http, keys=KEYS)
    assert res.status is Status.OK and res.attributes["asn"] == "AS15169"


def test_bogon_answer_is_empty():
    http = FakeHttp().add("GET", LITE_URL.format(ip="8.8.4.4"), json=dict(fx("lite_bogon_synthetic.json"), ip="8.8.4.4"))
    assert run_module(IpInfo, "ipv4:8.8.4.4", http, keys=KEYS).status is Status.EMPTY


def test_answer_without_asn_or_country_is_empty():
    http = FakeHttp().add("GET", URL, json={"ip": "8.8.8.8"})
    assert run_module(IpInfo, "ipv4:8.8.8.8", http, keys=KEYS).status is Status.EMPTY


# ------------------------------------------------------------------ c4: status mapping
def test_bad_token_403_is_needs_key_invalid_key():
    http = FakeHttp().add("GET", URL, status=403, json=fx("bad_token_403.json"))
    res = run_module(IpInfo, "ipv4:8.8.8.8", http, keys=KEYS)
    assert res.status is Status.NEEDS_KEY and "invalid key" in res.error and "Unknown token" in res.error


def test_lite_403_without_token_body_is_needs_key():
    http = FakeHttp().add("GET", URL, status=403, json=fx("lite_nokey_403.json"))
    assert run_module(IpInfo, "ipv4:8.8.8.8", http, keys=KEYS).status is Status.NEEDS_KEY


def test_429_is_rate_limited():
    http = FakeHttp().add("GET", URL, status=429, json=fx("nokey_429.json"))
    res = run_module(IpInfo, "ipv4:8.8.8.8", http, keys=KEYS)
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited"


def test_challenge_page_is_blocked():
    http = FakeHttp().add("GET", URL, status=403, text=CHALLENGE, headers={"content-type": "text/html"})
    res = run_module(IpInfo, "ipv4:8.8.8.8", http, keys=KEYS)
    assert res.status is Status.BLOCKED


def test_server_error_is_error():
    http = FakeHttp().add("GET", URL, status=503, text="unavailable", times=5)
    assert run_module(IpInfo, "ipv4:8.8.8.8", http, keys=KEYS).status is Status.ERROR


def test_error_object_inside_200_is_never_empty():
    http = FakeHttp().add("GET", URL, json={"status": 404, "error": {"title": "Wrong ip", "message": "Please provide a valid IP address"}})
    res = run_module(IpInfo, "ipv4:8.8.8.8", http, keys=KEYS)
    assert res.status is Status.ERROR and "Wrong ip" in res.error


def test_malformed_json_is_error():
    http = FakeHttp().add("GET", URL, text="{not json", headers={"content-type": "application/json"})
    assert run_module(IpInfo, "ipv4:8.8.8.8", http, keys=KEYS).status is Status.ERROR
    http2 = FakeHttp().add("GET", URL, json=["not", "an", "object"])
    assert run_module(IpInfo, "ipv4:8.8.8.8", http2, keys=KEYS).status is Status.ERROR


def test_private_addresses_are_never_sent():
    http = FakeHttp()
    for value in ("ipv4:10.0.0.1", "ipv4:192.0.2.1", "ipv6:fe80::1"):
        res = run_module(IpInfo, value, http, keys=KEYS)
        assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert http.calls == []


def test_token_never_reaches_results_cache_or_home():
    rt = make_runtime(ok_http(), keys=KEYS, cache=True)
    res = run_module(IpInfo, "ipv4:8.8.8.8", runtime=rt)
    assert res.status is Status.OK
    assert_no_secret(TOKEN, res.to_dict(), res.raw, res.error, paths.home())


def _replay(etype, module):
    """FakeHttp with the AR21 golden-path routes of tests/fixtures/acceptance/<etype>/<module>.json."""
    import base64

    doc = json.loads((FIXTURES / "acceptance" / etype / f"{module}.json").read_text(encoding="utf-8"))
    assert doc["schema"] == "v3lum.acceptance_routes/1" and doc["module"] == module
    http = FakeHttp()
    for route in doc["routes"]:
        if "json" in route:
            body = {"json": route["json"]}
        elif "body_b64" in route:
            body = {"body": base64.b64decode(route["body_b64"])}
        else:
            body = {"text": route["text"]}
        http.add(route["method"], route["url"], status=route["status"], headers=route.get("headers") or {}, **body)
    return http, doc


def test_acceptance_routes_of_the_golden_ipv4_are_empty_without_a_key():
    http, doc = _replay("ipv4", "ipinfo")
    assert doc["routes"] == []
    res = run_module(IpInfo, "ipv4:8.8.8.8", http)
    assert res.status is Status.NEEDS_KEY and http.calls == []
