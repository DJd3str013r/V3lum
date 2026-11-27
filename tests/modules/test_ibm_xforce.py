"""Offline tests of ibm_xforce (P155) with the fixtures in tests/fixtures/ibm_xforce/.

Provenance: ``needs_key_401.json`` is the real keyless answer (research 2026-11-25); ``*_docs.json``
are the OpenAPI examples (api.xforce.ibmcloud.com/doc, fetched 2026-11-26; the C2 host and address
moved to documentation values); ``*_synthetic.json`` follow the OpenAPI schemas (ipr, url, malware,
ErrorModel) with documentation values until the team key exists (P155 cond 4, backlog)."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from tests.fakes import FakeHttp, assert_no_secret, make_ctx, module_fixture, run_module
from v3lum import config
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Opsec, Severity, Status
from v3lum.core.providers import registry
from v3lum.modules.threat_intel_ioc import ibm_xforce as mod
from v3lum.modules.threat_intel_ioc.ibm_xforce import IBMXForce, basic_auth, credential, lookup_url, request_allowed, url_value

FIX = "ibm_xforce"
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / FIX
KEY_VALUE = "xforcekey0123456789abcdef:xforcepassword0123456789abcdef"
KEYS = {"xforce": KEY_VALUE}
HEADER = "Basic " + base64.b64encode(KEY_VALUE.encode()).decode()
MD5 = "474b9ccf5ab9d72ca8a333889bbb34f0"


def body(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def route(http: FakeHttp, url: str, *, name: str | None = None, raw: bytes | None = None, status: int = 200) -> FakeHttp:
    content = raw if raw is not None else body(name or "")
    return http.add("GET", url, status=status, body=content, headers={"content-type": "application/json"},
                    match_headers={"authorization": HEADER})


@pytest.fixture(autouse=True)
def doc_ips(monkeypatch):
    monkeypatch.setattr(mod, "public_ip", lambda value: True)


def run(entity: str, http: FakeHttp, **kw):
    return run_module(IBMXForce, entity, http, keys=KEYS, **kw)


# --------------------------------------------------------------------------------------
# metadata, credentials, allow-list (c1-c3)
# --------------------------------------------------------------------------------------


def test_metadata_matches_the_council_decision():
    cls = IBMXForce
    assert (cls.terms, cls.default_enabled, cls.trust_tier, cls.disclosure) == ("key-terms", False, "trusted", "third_party")
    assert cls.opsec is Opsec.PASSIVE and cls.provider == "ibm_xforce" and cls.hosts == ("api.xforce.ibmcloud.com",)
    assert cls.sources == ("ibm_xforce.ibm_xforce_lookup",) and cls.cache_ttl == 86400
    # the key is declared as soon as the core registers it (KNOWN_KEYS); until then the module checks it itself
    assert cls.requires_keys == (("xforce",) if "xforce" in config.key_registry() else ())
    assert registry().provider_for_host("api.xforce.ibmcloud.com").id == "ibm_xforce"
    src = registry().source("ibm_xforce.ibm_xforce_lookup")
    assert src.terms.class_ == "key-terms" and src.terms.free_plan_business_use is False and src.upstream_family == "ibm-xforce"
    assert registry().get("ibm_xforce").tier == "trusted"


def test_one_key_holds_key_and_password_and_builds_the_basic_header():
    assert credential(" abc : def ") == ("abc", "def")
    assert basic_auth("abc:def") == "Basic " + base64.b64encode(b"abc:def").decode()
    for bad in ("abc", "abc:", ":def", "", None):
        with pytest.raises(ValueError):
            credential(bad)


def test_allow_list_only_builds_ipr_url_and_malware_lookups():
    for etype, value in [(T.IPV4, "198.51.100.23"), (T.URL, "http://login.example.net/a?b=1"), (T.DOMAIN, "www.ibm.com"), (T.MD5, MD5),
                         (T.SHA256, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")]:
        assert request_allowed("GET", lookup_url(etype, value)), (etype, value)
    base = "https://api.xforce.ibmcloud.com/api"
    for method, url in [
        ("POST", f"{base}/ipr/198.51.100.23"), ("GET", f"{base}/ipr/history/198.51.100.23"), ("GET", f"{base}/ipr/malware/198.51.100.23"),
        ("GET", f"{base}/url/history/x"), ("POST", f"{base}/casefiles"), ("GET", f"{base}/casefiles/abc"), ("GET", f"{base}/collections"),
        ("POST", f"{base}/auth/api_key"), ("DELETE", f"{base}/auth/api_key"), ("POST", f"{base}/taxii"), ("GET", f"{base}/xfti/x"),
        ("GET", f"{base}/vulnerabilities/search/CVE-2021-44228"), ("GET", f"{base}/malware/3395856ce81f2b7382dee72602f798b642f14140"),
        ("GET", f"{base}/ipr/198.51.100.23?x=1"), ("GET", "http://api.xforce.ibmcloud.com/api/ipr/198.51.100.23"),
        ("GET", "https://exchange.xforce.ibmcloud.com/ip/198.51.100.23"),
    ]:
        assert not request_allowed(method, url), (method, url)


def test_url_value_follows_the_documented_form():
    assert url_value("https://www.ibm.com/smarterplanet") == "www.ibm.com/smarterplanet"
    assert url_value("http://user:pw@login.example.net:8080/a?b=1#frag") == "login.example.net:8080/a?b=1"
    assert url_value("www.ibm.com/") == "www.ibm.com" and url_value("not a url") is None
    assert lookup_url(T.URL, "https://www.ibm.com/smarterplanet").endswith("/url/www.ibm.com%2Fsmarterplanet")


# --------------------------------------------------------------------------------------
# keys (c2)
# --------------------------------------------------------------------------------------


def test_without_a_key_or_with_a_malformed_key_nothing_is_sent():
    http = FakeHttp()
    assert run_module(IBMXForce, "ipv4:198.51.100.23", http).status is Status.NEEDS_KEY
    res = run_module(IBMXForce, "ipv4:198.51.100.23", http, keys={"xforce": "key-without-password"})
    assert res.status is Status.NEEDS_KEY and "key:password" in res.error and not http.calls


# --------------------------------------------------------------------------------------
# reports (c4)
# --------------------------------------------------------------------------------------


def test_malicious_ip_score_is_one_vendor_vote_with_category_tags():
    http = route(FakeHttp(), lookup_url(T.IPV4, "198.51.100.23"), name="ipr_malicious_synthetic.json")
    res = run("ipv4:198.51.100.23", http)
    assert res.status is Status.OK
    finding = res.findings[0]
    assert finding.title == "Malicious per IBM X-Force" and finding.severity is Severity.MEDIUM
    assert {"malicious", "c2", "malware"} <= set(finding.tags) and finding.source == "ibm_xforce.ibm_xforce_lookup"
    assert finding.data["upstream_families"] == ["ibm-xforce"] and "8.6" in finding.criterion
    assert finding.observed_last == "2026-11-20T10:30:00Z"
    assert res.attributes["asn"] == "AS64496" and res.attributes["country"] == "BR"
    assert res.attributes["reputation"] == {"ibm_xforce": 8.6}
    assert any(c["name"] == "Botnet Command and Control Server" and c["confidence"] == 86 for c in res.attributes["xforce"]["categories"])
    http.assert_hosts_within(IBMXForce)
    assert all(request_allowed(c["method"], c["url"]) for c in http.calls)
    assert_no_secret(KEY_VALUE, res.to_dict())
    assert_no_secret(HEADER.split(" ", 1)[1], res.to_dict())


def test_suspicious_ip_band_is_low_without_vote_tags():
    http = route(FakeHttp(), lookup_url(T.IPV4, "198.51.100.44"), name="ipr_suspicious_synthetic.json")
    finding = run("ipv4:198.51.100.44", http).findings[0]
    assert finding.severity is Severity.LOW and finding.title == "Suspicious per IBM X-Force"
    assert set(finding.tags) == {"suspicious", "scanner", "anonymizer"}


def test_low_score_is_facts_only_never_clean():
    http = route(FakeHttp(), lookup_url(T.IPV4, "192.0.2.10"), name="ipr_low_synthetic.json")
    res = run("ipv4:192.0.2.10", http)
    assert res.status is Status.OK and not res.findings and res.attributes["xforce"]["score"] == 1


def test_malicious_url_and_benign_domain():
    http = route(FakeHttp(), lookup_url(T.URL, "http://login.example.net/account/verify"), name="url_malicious_synthetic.json")
    finding = run("url:http://login.example.net/account/verify", http).findings[0]
    assert finding.severity is Severity.MEDIUM and {"malicious", "phishing", "malware"} <= set(finding.tags)
    http2 = route(FakeHttp(), lookup_url(T.DOMAIN, "www.ibm.com"), name="url_ok_docs.json")
    res = run("domain:www.ibm.com", http2)
    assert res.status is Status.OK and not res.findings
    assert res.attributes["xforce"]["associated"][0]["url"] == "ibm.com"


def test_malware_report_maps_risk_and_lists_families_and_c2_servers():
    http = route(FakeHttp(), lookup_url(T.MD5, MD5), name="malware_ok_docs.json")
    res = run(f"md5:{MD5}", http)
    finding = res.findings[0]
    assert finding.severity is Severity.MEDIUM and "risk high" in finding.criterion
    assert res.attributes["malware_family"] == ["tsunami"]
    pivots = {(p.entity.type, p.entity.value, p.relation, p.expand) for p in res.pivots}
    assert (T.MALWARE, "tsunami", "family", False) in pivots
    assert (T.DOMAIN, "c2.example.net", "communicates_with", False) in pivots
    assert (T.IPV4, "203.0.113.86", "communicates_with", False) in pivots
    assert res.attributes["xforce"]["detection_coverage"] == 44


# --------------------------------------------------------------------------------------
# statuses (c4, rule 5)
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(("status", "name", "expected"), [
    (401, "needs_key_401.json", Status.NEEDS_KEY),
    (403, "access_denied_403_synthetic.json", Status.NEEDS_KEY),
    (402, "quota_402_synthetic.json", Status.QUOTA),
    (404, "not_found_404_synthetic.json", Status.EMPTY),
    (429, "rate_limited_429_synthetic.json", Status.RATE_LIMITED),
])
def test_documented_statuses(status, name, expected):
    http = route(FakeHttp(), lookup_url(T.IPV4, "198.51.100.60"), name=name, status=status)
    res = run("ipv4:198.51.100.60", http)
    assert res.status is expected, res.error
    if expected is Status.QUOTA:
        assert res.reason_code == "quota"


def test_errors_inside_200_and_unusable_bodies_are_could_not_verify():
    http = route(FakeHttp(), lookup_url(T.IPV4, "198.51.100.61"), raw=b'{"error": "Internal problem"}')
    assert run("ipv4:198.51.100.61", http).status is Status.ERROR
    http2 = route(FakeHttp(), lookup_url(T.IPV4, "198.51.100.62"), raw=b'{"error": "Monthly quota exceeded."}')
    assert run("ipv4:198.51.100.62", http2).status is Status.QUOTA
    http3 = route(FakeHttp(), lookup_url(T.IPV4, "198.51.100.63"), raw=b'{"ip": "198.51.100.63", "sc')
    assert run("ipv4:198.51.100.63", http3).status is Status.ERROR
    http4 = route(FakeHttp(), lookup_url(T.IPV4, "198.51.100.64"), raw=b"[1, 2]")
    assert run("ipv4:198.51.100.64", http4).status is Status.ERROR
    http5 = route(FakeHttp(), lookup_url(T.IPV4, "198.51.100.65"), raw=b"upstream down", status=503)
    assert run("ipv4:198.51.100.65", http5).status is Status.ERROR


# --------------------------------------------------------------------------------------
# monthly budget (c4)
# --------------------------------------------------------------------------------------


def test_local_monthly_budget_stops_before_sending_and_counts_network_sends():
    entity = Entity.make(T.IPV4, "198.51.100.23")
    http = route(FakeHttp(), lookup_url(T.IPV4, "198.51.100.23"), name="ipr_malicious_synthetic.json")
    ctx = make_ctx(IBMXForce, http, keys=KEYS, settings={"ibm_xforce_month_limit": 10}, entity=entity)
    res = IBMXForce().run(entity, ctx)
    assert res.findings and ctx.state.get("month") == {"month": "2026-11", "used": 1}
    ctx.state.set("month", {"month": "2026-11", "used": 8})  # 80% of 10 spent
    before = len(http.calls)
    res2 = IBMXForce().run(entity, make_ctx(IBMXForce, http, keys=KEYS, settings={"ibm_xforce_month_limit": 10}, entity=entity))
    assert res2.status is Status.QUOTA and len(http.calls) == before


def test_fixture_shapes_are_documented():
    assert module_fixture(FIX, "needs_key_401.json") == {"error": "Not authorized."}
