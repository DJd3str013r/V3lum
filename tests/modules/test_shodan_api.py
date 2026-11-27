"""shodan_api (P039): keyed only, ?key= masked everywhere, scan endpoints never built, credits and plan rules.

Fixtures in tests/fixtures/shodan_api/: ``host_8.8.8.8_nokey_observed.json`` is the real answer
Shodan gave WITHOUT a key for the documentation demo IP 8.8.8.8 on 2026-11-25 (the observation P039
cond 7 forbids relying on; trimmed). The other files are labelled synthetic shapes of the documented
API (host minified/full with banner vulns, dns/domain, api-info for a membership and a business plan,
host/search, error bodies) on documentation addresses: the team key is needed for real captures,
which P039 cond 8 requires before merge.
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import (
    FIXTURES,
    FakeClock,
    FakeHttp,
    add_dns,
    add_nxdomain_everything,
    assert_no_secret,
    make_runtime,
    module_fixture,
    run_module,
)
from v3lum import paths
from v3lum.core.context import ModuleState, ScanOptions
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.ip_network.shodan_api import (
    ShodanApi,
    ShodanEndpointRefused,
    parse_host,
    search_cost,
    search_query,
    shodan_url,
    vuln_severity,
)

KEY = "shodan-test-key-ABCDEFGHIJ0123456789"
KEYS = {"shodan": KEY}
BUSINESS = {"key_plans": {"shodan": "business"}}
CHALLENGE = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body><div id=\"cf-chl-widget\"></div></body></html>"


def fx(name):
    return module_fixture("shodan_api", name)


def api_info(http, name="api_info_business_synthetic.json", **kw):
    return http.add("GET", shodan_url("api_info", KEY), json=fx(name), **kw)


def host_url(ip, minify=True):
    return shodan_url("host", KEY, ip=ip, minify=minify)


def calls_to(http, fragment):
    return [c for c in http.calls if fragment in c["url"]]


def pivots(res, etype=None):
    return {(p.entity.type, p.entity.value): p for p in res.pivots if etype is None or p.entity.type is etype}


# ------------------------------------------------------------------ c7: keyless never relied on
def test_needs_key_without_a_key_even_though_shodan_answers_demo_ips_keyless():
    keyless = "https://api.shodan.io/shodan/host/8.8.8.8"
    http = FakeHttp().add("GET", keyless + "*", json=fx("host_8.8.8.8_nokey_observed.json"))
    res = run_module(ShodanApi, "ipv4:8.8.8.8", http)
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key"
    assert http.calls == []  # the keyless demo answer is never requested


# ------------------------------------------------------------------ c5: scans are never wired
@pytest.mark.parametrize("endpoint", ["scan", "scan_internet", "scans", "/shodan/scan", "/shodan/scan/internet", "shodan/scan",
                                      "alert", "notifier", "", "host/scan"])
@pytest.mark.parametrize("key", [KEY, ""])
def test_scan_and_unknown_endpoints_cannot_be_built(endpoint, key):
    with pytest.raises(ShodanEndpointRefused):
        shodan_url(endpoint, key, ip="8.8.8.8")


def test_url_builder_key_as_query_parameter_and_minify_by_default():
    url = host_url("8.8.8.8")
    assert url.startswith("https://api.shodan.io/shodan/host/8.8.8.8?") and f"key={KEY}" in url and "minify=true" in url
    with pytest.raises(ValueError):
        shodan_url("host", "", ip="8.8.8.8")  # no key, no URL
    with pytest.raises(ValueError):
        shodan_url("host", KEY, ip="10.0.0.1")  # private space is never sent
    with pytest.raises(ValueError):
        shodan_url("host", KEY, ip="8.8.8.8", query="x")  # parameters are allow-listed per endpoint
    assert search_query(T.FAVICON_HASH, "56641965") == "http.favicon.hash:56641965"
    assert search_query(T.CERT_FP, "AB:" * 19 + "AB") == "ssl.cert.fingerprint:" + "ab" * 20
    assert search_cost("http.favicon.hash:1") == 1 and search_cost("apache") == 0 and search_cost("apache", 2) == 1


# ------------------------------------------------------------------ c4/c6: host lookups
def test_host_banners_from_the_recorded_answer():
    http = api_info(FakeHttp()).add("GET", host_url("8.8.8.8"), json=fx("host_8.8.8.8_nokey_observed.json"))
    res = run_module(ShodanApi, "ipv4:8.8.8.8", http, keys=KEYS, settings=BUSINESS)
    assert res.status is Status.OK
    assert res.attributes["open_ports"] == [53, 443]
    assert res.attributes["hostnames"] == ["dns.google"]
    assert res.attributes["asn"] == "AS15169" and res.attributes["org"] == "Google LLC"
    assert res.attributes["last_seen"] == "2026-11-25T15:26:44Z"  # c6: the latest banner timestamp
    https = next(s for s in res.attributes["services"] if s.get("port") == 443)
    assert https["cert_sha256"].startswith("eae0983719c0") and https["favicon_hash"] == 56641965
    found = pivots(res)
    assert found[(T.CERT_FP, https["cert_sha256"])].relation == "serves_certificate"
    assert found[(T.DOMAIN, "dns.google")].relation == "hosted_domain"
    ports = next(f for f in res.findings if f.title == "Open ports observed by Shodan")
    assert ports.observed_last == "2026-11-25T15:26:44Z" and ports.source == "shodan.api"
    assert ("Shodan host page", "https://www.shodan.io/host/8.8.8.8") in res.links
    assert "query credits left" in res.source_statuses["shodan.api"]["reason"]  # c3: coverage line
    http.assert_hosts_within(ShodanApi)


def test_banner_vulns_are_version_inferred_possible_and_never_critical():
    host = parse_host(fx("host_vulns_synthetic.json"))
    log4j = next(v for v in host["vulns"] if v["cve"] == "CVE-2021-44228")
    assert log4j["cvss"] == 10.0 and log4j["severity"] == "high"  # CVSS 10 capped at HIGH (P291)
    assert host["observed_last"] == "2026-11-20T10:00:00Z"
    http = api_info(FakeHttp()).add("GET", host_url("8.8.4.4"), json=fx("host_vulns_synthetic.json"))
    res = run_module(ShodanApi, "ipv4:8.8.4.4", http, keys=KEYS, settings=BUSINESS)
    vuln = next(f for f in res.findings if f.title == "CVEs by version match (version-inferred)")
    assert vuln.severity.label == "high" and vuln.confidence <= 0.5 and vuln.label.value == "possible"
    assert "version_inferred" in vuln.tags and vuln.observed_last == "2026-11-20T10:00:00Z"
    cves = pivots(res, T.CVE)
    assert set(v for _t, v in cves) == {"CVE-2021-44228", "CVE-2023-44487"}
    assert all(p.relation == "has_vuln" and p.confidence <= 0.5 for p in cves.values())
    assert not any(f.severity.label == "critical" for f in res.findings)
    assert pivots(res)[(T.DOMAIN, "web.example.com")].expand is False  # tag 'cloud': shared address


def test_minified_host_vulns_without_cvss_are_medium():
    http = api_info(FakeHttp()).add("GET", host_url("8.8.4.4"), json=fx("host_minified_synthetic.json"))
    res = run_module(ShodanApi, "ipv4:8.8.4.4", http, keys=KEYS, settings=BUSINESS)
    vuln = next(f for f in res.findings if f.title.startswith("CVEs by version match"))
    assert vuln.severity.label == "medium" and res.attributes["vulns"] == ["CVE-2021-44228"]
    assert vuln_severity(None) == "medium" and vuln_severity(9.8) == "high" and vuln_severity(5.0) == "medium"


def test_full_banners_when_minify_is_switched_off():
    http = api_info(FakeHttp()).add("GET", host_url("8.8.8.8", minify=False), json=fx("host_8.8.8.8_nokey_observed.json"))
    res = run_module(ShodanApi, "ipv4:8.8.8.8", http, keys=KEYS, settings={**BUSINESS, "shodan_api_minify": False})
    assert res.status is Status.OK and calls_to(http, "minify=false")


def test_no_information_404_is_empty():
    http = api_info(FakeHttp()).add("GET", host_url("8.8.4.4"), status=404, json=fx("no_info_synthetic.json"))
    res = run_module(ShodanApi, "ipv4:8.8.4.4", http, keys=KEYS, settings=BUSINESS)
    assert res.status is Status.EMPTY and "no information" in res.error.lower()


def test_other_404_is_could_not_verify():
    http = api_info(FakeHttp()).add("GET", host_url("8.8.4.4"), status=404, text="<html>not found</html>")
    assert run_module(ShodanApi, "ipv4:8.8.4.4", http, keys=KEYS, settings=BUSINESS).status is Status.ERROR


# ------------------------------------------------------------------ error mapping
def test_invalid_key_is_needs_key():
    http = FakeHttp().add("GET", shodan_url("api_info", KEY), status=401, json=fx("invalid_key_synthetic.json"))
    res = run_module(ShodanApi, "ipv4:8.8.8.8", http, keys=KEYS, settings=BUSINESS)
    assert res.status is Status.NEEDS_KEY and "invalid key" in res.error


def test_html_401_page_is_needs_key():
    http = FakeHttp().add("GET", shodan_url("api_info", KEY), status=401, text=fx("unauthorized_html_synthetic.html"))
    assert run_module(ShodanApi, "ipv4:8.8.8.8", http, keys=KEYS, settings=BUSINESS).status is Status.NEEDS_KEY


def test_rate_limit_is_rate_limited():
    http = api_info(FakeHttp()).add("GET", host_url("8.8.4.4"), status=429, json=fx("rate_limited_synthetic.json"))
    res = run_module(ShodanApi, "ipv4:8.8.4.4", http, keys=KEYS, settings=BUSINESS)
    assert res.status is Status.RATE_LIMITED


def test_challenge_page_is_blocked():
    http = api_info(FakeHttp()).add("GET", host_url("8.8.4.4"), status=403, text=CHALLENGE)
    assert run_module(ShodanApi, "ipv4:8.8.4.4", http, keys=KEYS, settings=BUSINESS).status is Status.BLOCKED


def test_error_object_inside_200_is_error_and_credits_text_is_quota():
    http = api_info(FakeHttp()).add("GET", host_url("8.8.4.4"), json={"error": "Something went wrong"})
    res = run_module(ShodanApi, "ipv4:8.8.4.4", http, keys=KEYS, settings=BUSINESS)
    assert res.status is Status.ERROR and "could not verify" in res.error
    http2 = api_info(FakeHttp()).add("GET", host_url("8.8.4.4"), status=401, json=fx("insufficient_credits_synthetic.json"))
    assert run_module(ShodanApi, "ipv4:8.8.4.4", http2, keys=KEYS, settings=BUSINESS).status is Status.QUOTA


def test_malformed_json_is_error():
    http = api_info(FakeHttp()).add("GET", host_url("8.8.4.4"), text="{oops", headers={"content-type": "application/json"})
    assert run_module(ShodanApi, "ipv4:8.8.4.4", http, keys=KEYS, settings=BUSINESS).status is Status.ERROR


def test_api_info_failure_does_not_stop_a_free_host_lookup():
    http = (FakeHttp().add("GET", shodan_url("api_info", KEY), status=503, text="unavailable", times=5)
            .add("GET", host_url("8.8.8.8"), json=fx("host_8.8.8.8_nokey_observed.json")))
    res = run_module(ShodanApi, "ipv4:8.8.8.8", http, keys=KEYS, settings=BUSINESS)
    assert res.status is Status.OK and res.attributes["open_ports"] == [53, 443]


def test_api_info_rate_limit_backs_off_the_whole_provider():
    http = (FakeHttp().add("GET", shodan_url("api_info", KEY), status=429, text="slow down")
            .add("GET", host_url("8.8.8.8"), json=fx("host_8.8.8.8_nokey_observed.json")))
    res = run_module(ShodanApi, "ipv4:8.8.8.8", http, keys=KEYS, settings=BUSINESS)
    assert res.status is Status.RATE_LIMITED  # the core quota book holds every Shodan call after a 429
    assert not calls_to(http, "/shodan/host/")


# ------------------------------------------------------------------ c3: /api-info once a day
def test_api_info_is_read_at_most_once_a_day():
    clock = FakeClock()
    http = api_info(FakeHttp())
    for ip in ("8.8.8.8", "8.8.4.4"):
        http.add("GET", host_url(ip), json=fx("host_8.8.8.8_nokey_observed.json"))
    rt = make_runtime(http, keys=KEYS, settings=BUSINESS, clock=clock)
    run_module(ShodanApi, "ipv4:8.8.8.8", runtime=rt)
    run_module(ShodanApi, "ipv4:8.8.4.4", runtime=rt)
    assert len(calls_to(http, "/api-info")) == 1
    clock.advance(25 * 3600)
    run_module(ShodanApi, "ipv4:8.8.8.8", runtime=rt)
    assert len(calls_to(http, "/api-info")) == 2


# ------------------------------------------------------------------ c2: plan terms
def test_membership_plan_is_noncommercial_under_corporate():
    http = api_info(FakeHttp(), "api_info_dev_synthetic.json")
    res = run_module(ShodanApi, "ipv4:8.8.8.8", http, keys=KEYS, settings=BUSINESS)
    assert res.status is Status.SKIPPED and res.reason_code == "licence"
    assert "noncommercial" in res.error and "fix the recorded plan" in res.error  # recorded 'business' contradicts /api-info
    assert not calls_to(http, "/shodan/host/")


def test_membership_plan_runs_under_the_research_profile():
    http = api_info(FakeHttp(), "api_info_dev_synthetic.json").add("GET", host_url("8.8.8.8"), json=fx("host_8.8.8.8_nokey_observed.json"))
    res = run_module(ShodanApi, "ipv4:8.8.8.8", http, keys=KEYS, options=ScanOptions(licence_profile="research"))
    assert res.status is Status.OK


# ------------------------------------------------------------------ c4: dns/domain through the P016 pipeline
def dns_http(credits_fixture="api_info_business_synthetic.json"):
    http = api_info(FakeHttp(), credits_fixture)
    http.add("GET", shodan_url("dns_domain", KEY, domain="example.com", page=1), json=fx("dns_domain_synthetic.json"))
    add_dns(http, "www.example.com", "A", ["203.0.113.10"])
    add_nxdomain_everything(http)  # wildcard probes and every other name: NXDOMAIN on both resolvers
    return http


def test_dns_domain_candidates_are_validated_before_listing():
    http = dns_http()
    rt = make_runtime(http, keys=KEYS, settings=BUSINESS)
    res = run_module(ShodanApi, "domain:example.com", runtime=rt)
    assert res.status is Status.OK
    assert res.attributes["subdomains"] == ["www.example.com"]  # resolves (non-wildcard zone)
    assert res.attributes["subdomain_provenance"]["mail.example.com"]["state"] == "historical"
    assert res.attributes["subdomain_wildcards"] == ["*.dev.example.com"]
    assert res.attributes["dns_wildcard"]["state"] == "none"
    sub = pivots(res, T.DOMAIN)[(T.DOMAIN, "www.example.com")]
    assert sub.relation == "subdomain" and sub.expand is False
    assert (T.DOMAIN, "mail.example.com") not in pivots(res)
    assert ModuleState("shodan_api").get("api_info")["spent"] == 1  # c3: one credit for the dns/domain page
    http.assert_hosts_within(ShodanApi)


def test_dns_domain_stops_at_the_credit_reserve():
    low = dict(fx("api_info_business_synthetic.json"), query_credits=5)
    http = FakeHttp().add("GET", shodan_url("api_info", KEY), json=low)
    res = run_module(ShodanApi, "domain:example.com", http, keys=KEYS, settings=BUSINESS)
    assert res.status is Status.QUOTA and "reserve" in res.error
    assert not calls_to(http, "/dns/domain/")


def test_dns_domain_runs_on_registrable_domains_only():
    http = api_info(FakeHttp())
    res = run_module(ShodanApi, "domain:www.example.com", http, keys=KEYS, settings=BUSINESS)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert not calls_to(http, "/dns/domain/")


def test_dns_domain_credits_unknown_means_no_credit_spending_call():
    http = FakeHttp().add("GET", shodan_url("api_info", KEY), status=503, text="down", times=5)
    res = run_module(ShodanApi, "domain:example.com", http, keys=KEYS, settings=BUSINESS)
    assert res.status is Status.ERROR and "credit" in res.error
    assert not calls_to(http, "/dns/domain/")


# ------------------------------------------------------------------ c4: seed-only searches
def search_http(plan_fixture="api_info_business_synthetic.json"):
    url = shodan_url("search", KEY, query="http.favicon.hash:56641965", minify=True)
    return api_info(FakeHttp(), plan_fixture).add("GET", url, json=fx("search_favicon_synthetic.json"))


def test_favicon_search_for_a_seed():
    http = search_http()
    res = run_module(ShodanApi, "favicon_hash:56641965", http, keys=KEYS, settings=BUSINESS)
    assert res.status is Status.OK
    ips = pivots(res, T.IPV4)
    assert set(v for _t, v in ips) == {"203.0.113.20", "198.51.100.7"}
    assert all(p.relation == "scanner_match" and p.expand is False for p in ips.values())
    search = res.attributes["scanner_search"]
    assert search["total"] == 2 and search["credits_spent"] == 1


def test_search_never_runs_for_pivots():
    http = search_http()
    res = run_module(ShodanApi, "favicon_hash:56641965", http, keys=KEYS, settings=BUSINESS, is_seed=False, depth=1)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert http.calls == []


def test_free_plan_cannot_run_filtered_searches():
    free = dict(fx("api_info_business_synthetic.json"), plan="oss")
    http = FakeHttp().add("GET", shodan_url("api_info", KEY), json=free)
    res = run_module(ShodanApi, "favicon_hash:56641965", http, keys=KEYS, options=ScanOptions(licence_profile="research"))
    assert res.status is Status.NEEDS_KEY and "cannot run filtered searches" in res.error


# ------------------------------------------------------------------ c1: the key never leaks (AR01)
def test_key_never_reaches_results_cache_state_or_home():
    http = api_info(FakeHttp()).add("GET", host_url("8.8.8.8"), json=fx("host_8.8.8.8_nokey_observed.json"))
    rt = make_runtime(http, keys=KEYS, settings=BUSINESS, cache=True)
    res = run_module(ShodanApi, "ipv4:8.8.8.8", runtime=rt)
    assert res.status is Status.OK
    assert any(KEY in c["url"] for c in http.calls)  # Shodan only accepts ?key= ...
    assert_no_secret(KEY, res.to_dict(), res.raw, res.error, res.source_statuses, paths.home())  # ... masked everywhere else


def test_offline_mode_is_unavailable_and_no_api_info_failure_is_recorded():
    rt = make_runtime(FakeHttp(), keys=KEYS, settings=BUSINESS, offline=True)
    res = run_module(ShodanApi, "ipv4:8.8.8.8", runtime=rt)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "offline"
    state = ModuleState("shodan_api")
    assert state.get("api_info_failed") is None  # offline is not an /api-info failure: no hour-long back-off


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


@pytest.mark.parametrize(("etype", "value"), [("ipv4", "ipv4:8.8.8.8"), ("domain", "domain:example.com")])
def test_acceptance_routes_of_the_golden_inputs_are_empty_without_a_key(etype, value):
    http, doc = _replay(etype, "shodan_api")
    assert doc["routes"] == []
    res = run_module(ShodanApi, value, http)
    assert res.status is Status.NEEDS_KEY and http.calls == []
