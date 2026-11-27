"""Offline tests of onyphe (P042) with the fixtures in tests/fixtures/onyphe/.

nokey_400.http.json is the recorded research answer (C0111, 2026-11-25; the echoed caller IP was
replaced by 203.0.113.10). The success fixture is documentation-shaped (envelope from the ONYPHE docs,
per-category fields not verified: no team-key capture exists, P042 cond 5); the credit, rate-limit and
invalid-key answers are synthetic in the documented envelope.
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum import config
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.core.tlp import TLP
from v3lum.modules.ip_network.onyphe import SOURCE, Onyphe, onyphe_url, parse_summary
from v3lum.modules.ip_network.scan_engines import EndpointRefused

FIX = "onyphe"
KEY = "on-test-key-0123456789abcdef"  # fake key
KEYS = {"onyphe": KEY}
URL = "https://www.onyphe.io/api/v2/summary/{kind}/{v}"
EGRESS = "203.0.113.10"


def fx(name: str):
    return module_fixture(FIX, name)


def http_fx(name: str) -> dict:
    resp = fx(name)["response"]
    return {"status": resp["status"], "json": resp["body"], "headers": resp.get("headers") or {}}


def test_metadata_follows_the_council_decision():
    cls = Onyphe
    assert (cls.terms, cls.default_enabled, cls.trust_tier, cls.requires_keys) == ("key-terms", False, "trusted", ("onyphe",))
    assert cls.max_tlp == TLP.AMBER_STRICT and cls.hosts == ("www.onyphe.io",)
    assert config.key_registry()["onyphe"].env == ("V3LUM_ONYPHE_KEY",)
    assert cls.manual_link == ""  # c4: the web search needs sign-in: no manual link


def test_only_summary_and_simple_endpoints_can_be_built():
    assert onyphe_url("summary", "ip", "8.8.8.8") == "https://www.onyphe.io/api/v2/summary/ip/8.8.8.8"
    assert onyphe_url("summary", "domain", "Example.com") == "https://www.onyphe.io/api/v2/summary/domain/example.com"
    assert onyphe_url("simple", "geoloc", "8.8.8.8").endswith("/simple/geoloc/8.8.8.8")
    for op, kind in (("search", "ip"), ("export", "ip"), ("discovery", "ip"), ("alert", "list"), ("bulk", "summary"),
                     ("user", ""), ("scope", "ip"), ("ondemand", "scope"), ("simple", "scan"), ("summary", "cidr")):
        with pytest.raises(EndpointRefused):
            onyphe_url(op, kind, "8.8.8.8")
    with pytest.raises(ValueError):
        onyphe_url("summary", "ip", "not-an-ip")


def test_summary_of_an_ip_with_the_key_only_in_the_header():
    http = FakeHttp().add("GET", URL.format(kind="ip", v="8.8.8.8"), json=fx("summary_ip_ok_synthetic.json"),
                          match_headers={"Authorization": f"bearer {KEY}"})
    res = run_module(Onyphe, "ipv4:8.8.8.8", http, keys=KEYS)
    assert res.status is Status.OK
    (call,) = http.calls
    assert KEY not in call["url"]
    a = res.attributes
    assert a["country"] == "BR" and a["asn"] == "AS64500" and a["as_org"] == "Example Hosting"
    assert a["open_ports"] == [443] and a["whois_network"]["name"] == "EXAMPLE-NET"
    assert a["scan_engine_summary"]["window"] == "last 30 days"
    assert a["vulns"] == [] if "vulns" in a else True
    assert {p.entity.value for p in res.pivots if p.entity.type is T.DOMAIN} == {"example.com", "www.example.com", "api.example.com"}
    assert all(p.expand is False for p in res.pivots)  # IP seeds: every name is listed, never expanded
    cert = [p for p in res.pivots if p.entity.type is T.CERT_FP]
    assert cert and cert[0].relation == "serves_certificate"
    (finding,) = [f for f in res.findings if "threat" in f.title.lower()]
    assert "blocklisted" in finding.tags and finding.confidence_label.value == "possible" and finding.source == SOURCE
    assert_no_secret(KEY, res)
    assert EGRESS not in str(res.raw) and EGRESS not in str(res.attributes)  # 'myip' never copied
    http.assert_hosts_within(Onyphe)


def test_domain_and_hostname_use_their_summary_kind():
    doc = fx("summary_ip_ok_synthetic.json")
    http = FakeHttp().add("GET", URL.format(kind="domain", v="example.com"), json=doc, match_headers={"Authorization": f"bearer {KEY}"})
    res = run_module(Onyphe, "domain:example.com", http, keys=KEYS)
    assert res.status is Status.OK
    rel = {(p.relation, p.entity.value) for p in res.pivots}
    assert ("subdomain", "www.example.com") in rel and ("resolves_to", "198.51.100.20") in rel
    assert ("has_certificate", "90e741dd51738dd484334f5253631c11b599d6c78fbda111a54e7c26a1de7b5d") in rel
    http2 = FakeHttp().add("GET", URL.format(kind="hostname", v="www.example.com"), json=fx("summary_empty_synthetic.json"))
    res2 = run_module(Onyphe, "domain:www.example.com", http2, keys=KEYS)
    assert res2.status is Status.EMPTY and "last 30 days" in res2.error


def test_version_inferred_cves_are_capped_findings():
    doc = fx("summary_ip_ok_synthetic.json")
    doc["results"].append({"@category": "vulnscan", "@timestamp": "2026-11-20T10:00:00.000Z", "ip": "198.51.100.20", "port": 443,
                           "product": "nginx", "productversion": "1.18.0", "cve": ["CVE-2021-23017", "junk"]})
    http = FakeHttp().add("GET", URL.format(kind="ip", v="8.8.8.8"), json=doc)
    res = run_module(Onyphe, "ipv4:8.8.8.8", http, keys=KEYS)
    assert res.attributes["vulns"] == ["CVE-2021-23017"]
    (finding,) = [f for f in res.findings if "version-inferred" in f.title]
    assert finding.severity.name == "MEDIUM" and "version_inferred" in finding.tags and finding.criterion


def test_missing_key_is_needs_key_before_any_request():
    http = FakeHttp()
    res = run_module(Onyphe, "ipv4:8.8.8.8", http)
    assert res.status is Status.NEEDS_KEY and not http.calls


@pytest.mark.parametrize(
    ("fixture", "status", "code"),
    [
        ("nokey_400.http.json", Status.NEEDS_KEY, "needs_key"),
        ("invalid_key_synthetic.http.json", Status.NEEDS_KEY, "needs_key"),
        ("credits_exhausted_synthetic.http.json", Status.QUOTA, "quota"),
        ("rate_limited_429_synthetic.http.json", Status.RATE_LIMITED, "rate_limited"),
    ],
)
def test_error_bodies_are_never_empty(fixture, status, code):
    http = FakeHttp().add("GET", URL.format(kind="ip", v="8.8.8.8"), **http_fx(fixture))
    res = run_module(Onyphe, "ipv4:8.8.8.8", http, keys=KEYS)
    assert res.status is status and res.reason_code == code
    assert EGRESS not in res.error


def test_nok_inside_200_and_malformed_answers_are_errors():
    nok = {"count": 0, "error": 9, "myip": EGRESS, "status": "nok", "text": "Something went wrong", "took": 0, "total": 0}
    res = run_module(Onyphe, "ipv4:8.8.8.8", FakeHttp().add("GET", URL.format(kind="ip", v="8.8.8.8"), json=nok), keys=KEYS)
    assert res.status is Status.ERROR
    for junk in ([1, 2], {"status": "ok"}, {"results": []}):
        res = run_module(Onyphe, "ipv4:8.8.8.8", FakeHttp().add("GET", URL.format(kind="ip", v="8.8.8.8"), json=junk), keys=KEYS)
        assert res.status is Status.ERROR
    http = FakeHttp().add("GET", URL.format(kind="ip", v="8.8.8.8"), status=502, text="bad gateway", times=3)
    assert run_module(Onyphe, "ipv4:8.8.8.8", http, keys=KEYS).status is Status.ERROR


def test_private_addresses_and_deep_pivots_are_not_sent():
    assert run_module(Onyphe, "ipv4:10.1.2.3", FakeHttp(), keys=KEYS).status is Status.SKIPPED
    assert run_module(Onyphe, "ipv4:8.8.8.8", FakeHttp(), keys=KEYS, is_seed=False, depth=2).status is Status.SKIPPED


def test_parser_is_defensive():
    for junk in (None, 1, "x", [], {"status": "ok", "results": "x"}):
        assert parse_summary(junk) is None
    parsed = parse_summary({"status": "ok", "results": [{"@category": "datascan", "port": "x", "cve": "bad"}, "junk"]})
    assert parsed["ports"] == [] and parsed["vulns"] == {} and parsed["categories"] == {"datascan": 1}
