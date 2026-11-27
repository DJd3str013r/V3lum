"""posture_third_party (P076, PASSIVE, own assets): offline tests.

Fixtures in tests/fixtures/posture_third_party/ (prep p9-G03-2): ``ssllabs_info.json`` and
``hsts_status_unknown.json`` are real research recordings (2026-11-25); ``ssllabs_analyze_blacklisted_error.json``
is the real 'Hostname blacklisted' answer for example.com; ``observatory_scan_*`` are real Observatory scan answers
(kept for the parser only: Observatory is never called); the getEndpointData bodies are the documented shape
(``ssllabs_endpoint_documented.json``) and synthetic variants (no API call was allowed while preparing them; the
real cache-miss body is undocumented). Endpoint addresses are documentation addresses (192.0.2.x, 198.51.100.x).
"""

from __future__ import annotations

import json
from pathlib import Path

from tests.fakes import FakeHttp, add_dns, add_dns_failure, make_ctx, module_fixture, run_module
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Opsec, Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.url_web import posture_third_party as pt
from v3lum.modules.url_web.posture_third_party import PostureThirdParty

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "posture_third_party"
HOST = "www.example.com"
HSTS = pt.hsts_status_url(HOST)


def fx(name: str):
    return module_fixture(PostureThirdParty, name)


def org(*domains: str) -> OrgProfile:
    return OrgProfile.from_dict({"domains": [{"name": d, "verification": "confirmed"} for d in domains or ("example.com",)]})


def endpoint_url(ip: str, host: str = HOST) -> str:
    return pt.ssllabs_endpoint_url(host, ip)


def base_http(ips=("192.0.2.10",), host: str = HOST) -> FakeHttp:
    http = FakeHttp()
    add_dns(http, host, "A", list(ips))
    add_dns(http, host, "AAAA", [])
    return http


def run(http: FakeHttp, value: str = f"domain:{HOST}", **kw):
    kw.setdefault("org_profile", org())
    return run_module(PostureThirdParty, value, http, **kw)


# ------------------------------------------------------------------ metadata
def test_metadata_noncommercial_own_assets_opt_in():
    cls = PostureThirdParty
    assert cls.opsec is Opsec.PASSIVE and cls.disclosure == "third_party" and cls.run_on == "own_assets"
    assert cls.terms == "noncommercial" and cls.default_enabled is False and "cached_only" in cls.tags
    assert cls.hosts == ("api.ssllabs.com", "hstspreload.org")  # never observatory-api.mdn.mozilla.net
    assert cls.health_check().offline is True


def test_offline_selftest():
    ctx = make_ctx(PostureThirdParty, FakeHttp(), entity=Entity.make(T.DOMAIN, "example.com"))
    assert PostureThirdParty.health_check().selftest(ctx).status == "ok"


# ------------------------------------------------------------------ FC7: forbidden requests cannot be built
def test_passive_module_refuses_forbidden_requests():
    refused = [
        ("POST", "https://observatory-api.mdn.mozilla.net/api/v2/scan?host=example.com"),
        ("GET", "https://observatory-api.mdn.mozilla.net/api/v2/analyze?host=example.com"),
        ("GET", "https://api.ssllabs.com/api/v3/analyze?host=example.com&fromCache=on&maxAge=24"),
        ("GET", "https://api.ssllabs.com/api/v3/analyze?host=example.com&startNew=on"),
        ("GET", "https://api.ssllabs.com/api/v3/getEndpointData?host=example.com&s=192.0.2.10&startNew=on"),
        ("POST", "https://api.ssllabs.com/api/v4/register"),
        ("GET", "https://hstspreload.org/api/v2/preloadable?domain=example.com"),
        ("GET", "https://hstspreload.org/api/v2/removable?domain=example.com"),
        ("GET", "https://hstspreload.org/api/v2/submit?domain=example.com"),
        ("GET", "http://hstspreload.org/api/v2/status?domain=example.com"),
        ("GET", "https://example.com/"),
    ]
    for method, url in refused:
        assert pt.check_passive_request(method, url), url


def test_passive_builders_only_produce_allowed_requests():
    for url in (pt.hsts_status_url("Example.COM."), pt.ssllabs_endpoint_url("example.com", "2001:db8::1"), pt.ssllabs_info_url()):
        assert pt.check_passive_request("GET", url) is None, url
    active = pt.ssllabs_assess_requests("example.com")
    assert pt.check_passive_request("GET", active["start"]) and pt.check_passive_request("GET", active["poll"])


def test_no_observatory_post_or_preloadable_is_ever_sent():
    http = base_http()
    http.add("GET", HSTS, json=fx("hsts_status_via_parent_synthetic.json"))
    http.add("GET", endpoint_url("192.0.2.10"), json=fx("ssllabs_endpoint_documented.json"))
    res = run(http)
    assert res.status is Status.OK
    urls = [c["url"] for c in http.calls]
    assert not [u for u in urls if "observatory" in u or "preloadable" in u or "/analyze" in u]
    assert {c["method"] for c in http.calls} == {"GET"}
    assert ("Mozilla HTTP Observatory (manual; opening a per-host page may start a public scan)", pt.OBSERVATORY_LANDING) in [tuple(x) for x in res.links]
    http.assert_hosts_within(PostureThirdParty)


# ------------------------------------------------------------------ happy paths
def test_hsts_preloaded_via_parent_and_cached_grade():
    http = base_http()
    http.add("GET", HSTS, json=fx("hsts_status_via_parent_synthetic.json"))
    http.add("GET", endpoint_url("192.0.2.10"), json=fx("ssllabs_endpoint_documented.json"))
    res = run(http)
    hsts = res.attributes["hsts_preload"]
    assert hsts["status"] == "preloaded" and hsts["preloaded"] is True and hsts["via_parent"] is True and hsts["preloaded_domain"] == "example.com"
    ep = res.attributes["ssllabs_endpoints"][0]
    assert ep["ip"] == "192.0.2.10" and ep["grade"] == "A" and ep["cached"] is True
    assert res.attributes["posture_sources"] == {"hstspreload": "ok", "ssllabs": "ok", "mozilla_observatory": "manual_link"}
    assert not res.findings  # grade A: no finding
    ips = [p for p in res.pivots if p.entity.type is T.IPV4]
    assert [(p.entity.value, p.expand) for p in ips] == [("192.0.2.10", False)]


def test_vulnerable_endpoint_gives_grade_and_vulnerability_findings():
    http = base_http(ips=("198.51.100.7",))
    http.add("GET", HSTS, json=fx("hsts_status_unknown.json"))
    http.add("GET", endpoint_url("198.51.100.7"), json=fx("ssllabs_endpoint_vulnerable_synthetic.json"))
    res = run(http)
    titles = {f.title: f for f in res.findings}
    assert titles["SSL Labs grade F on 198.51.100.7"].severity.name == "MEDIUM"
    vuln = titles["TLS vulnerabilities flagged by SSL Labs on 198.51.100.7"]
    assert vuln.severity.name == "HIGH" and {"heartbleed", "robot", "goldenDoodle", "sleepingPoodle", "poodleTls"} <= set(vuln.data["vulnerabilities"])
    assert all(f.criterion and f.source == pt.SRC_ENDPOINT for f in res.findings)
    # a cached grade is dated by the SSL Labs assessment time, never presented as current
    assert res.attributes["ssllabs_endpoints"][0].get("assessed_at")
    assert all(f.observed_last for f in res.findings)


def test_cache_miss_is_no_cached_grade_never_a_new_assessment():
    http = base_http()
    http.add("GET", HSTS, json=fx("hsts_status_unknown.json"))
    http.add("GET", endpoint_url("192.0.2.10"), json=fx("ssllabs_endpoint_not_ready_synthetic.json"))
    res = run(http)
    assert res.status is Status.OK
    assert res.attributes["posture_sources"]["ssllabs"] == "no_cached_grade"
    assert len([c for c in http.calls if "ssllabs" in c["url"]]) == 1


# ------------------------------------------------------------------ own assets only (FC6) and the licence filter (FC4)
def test_not_an_own_asset_is_skipped_without_any_request():
    http = FakeHttp()
    res = run(http, "domain:www.example.org")
    assert res.status is Status.SKIPPED and res.reason_code == "own_asset"
    assert http.calls == []


def test_ssl_labs_outside_allowed_sources_is_never_called():
    http = base_http()
    http.add("GET", HSTS, json=fx("hsts_status_preloaded_synthetic.json"))
    res = run(http, allowed_sources={pt.SRC_HSTS})
    assert res.status is Status.OK
    assert res.attributes["posture_sources"]["ssllabs"] == "skipped_licence"
    assert not [c for c in http.calls if "ssllabs" in c["url"]]


# ------------------------------------------------------------------ rule 5: could not verify
def test_blacklisted_error_in_200_is_an_error():
    http = base_http()
    http.add("GET", HSTS, status=500, text="<html>err</html>")
    http.add("GET", endpoint_url("192.0.2.10"), json=fx("ssllabs_analyze_blacklisted_error.json"))
    res = run(http)
    assert res.status is Status.ERROR
    assert "Hostname blacklisted" in json.dumps([s for s in res.source_statuses.values()] if isinstance(res.source_statuses, dict) else res.source_statuses, default=str)


def test_errors_envelope_is_an_error_and_hsts_html_is_an_error():
    http = base_http()
    http.add("GET", HSTS, text=(FIXTURES / "hsts_status_html_error_synthetic.html").read_text(encoding="utf-8"))
    http.add("GET", endpoint_url("192.0.2.10"), status=400, json=fx("ssllabs_errors_400_documented.json"))
    res = run(http)
    assert res.status is Status.ERROR


def test_429_and_529_are_rate_limited():
    for status in (429, 529):
        http = base_http()
        http.add("GET", HSTS, status=429, text="slow down")
        http.add("GET", endpoint_url("192.0.2.10"), status=status, json={"errors": [{"message": "Running at full capacity"}]})
        res = run(http)
        assert res.status is Status.RATE_LIMITED, (status, res.status, res.error)


def test_partial_answer_keeps_data_and_records_the_failed_source():
    http = base_http()
    http.add("GET", HSTS, json=fx("hsts_status_pending_removal_synthetic.json"))
    http.add("GET", endpoint_url("192.0.2.10"), status=503, text="<html>maintenance</html>")
    res = run(http)
    assert res.status is Status.OK and res.attributes["hsts_preload"]["status"] == "pending-removal"
    assert res.attributes["posture_sources"]["ssllabs"] == "could_not_verify"
    assert pt.SRC_ENDPOINT in res.source_statuses


def test_dns_failure_is_could_not_verify_not_no_address():
    http = FakeHttp()
    add_dns_failure(http, HOST, "A", kind="servfail", provider="all")
    add_dns_failure(http, HOST, "AAAA", kind="servfail", provider="all")
    http.add("GET", HSTS, json=fx("hsts_status_unknown.json"))
    res = run(http)
    assert res.attributes["posture_sources"]["ssllabs"] == "could_not_verify"


def test_malformed_json_is_an_error():
    http = base_http()
    http.add("GET", HSTS, body=b"{oops", headers={"content-type": "application/json"})
    http.add("GET", endpoint_url("192.0.2.10"), body=b"[1,2", headers={"content-type": "application/json"})
    assert run(http).status is Status.ERROR


# ------------------------------------------------------------------ recorded fixtures (FC7)
def test_recorded_info_observatory_and_hsts_fixtures_parse():
    info = pt.parse_ssllabs_info(fx("ssllabs_info.json"))
    assert info["max_assessments"] == 7 and info["cool_off_ms"] == 1000 and info["terms_url"] == "https://www.ssllabs.com/about/terms.html"
    obs = pt.parse_observatory_scan(fx("observatory_scan_envelope.json"))
    assert obs["grade"] == "F" and obs["score"] == 10
    assert pt.parse_observatory_scan(fx("observatory_scan_ok.json"))["status"] == "ok"
    assert pt.parse_observatory_scan(fx("observatory_error_documented.json"))["status"] == "error"
    unknown = pt.parse_hsts_status(fx("hsts_status_unknown.json"), "google.com")
    assert unknown["preload_status"] == "unknown" and unknown["preloaded"] is False
    assert pt.parse_hsts_status({"status": "weird"})["status"] == "error"


def test_parsers_never_raise_on_garbage():
    for junk in (None, b"\x00\xff", "<<<", 42, [], {"endpoints": "x", "details": 5}, {"ipAddress": "not-an-ip", "grade": "A"}):
        pt.parse_ssllabs_endpoint(junk)
        pt.parse_ssllabs_host(junk)
        pt.parse_hsts_status(junk)
        pt.parse_observatory_scan(junk)
        pt.parse_ssllabs_info(junk)
