"""securitytrails (P006): APIKEY header, three endpoints, hostname sink, DNS history and statuses.

Fixtures in tests/fixtures/securitytrails/: ``error_401.txt`` is the real research answer without a key
('Please check user credentials', no content type) and ``web_challenge_403.html`` the real Cloudflare
managed challenge of the web UI (tokens redacted). The /domain, /subdomains and /history answers are
synthetic (documented v1 shapes, documentation values; the CDN variants use public Cloudflare,
example.com-era and scanme addresses): trimmed real captures with the team key are still owed (P006
cond 8, docs/backlog/p2-G01-1.md).
"""

from __future__ import annotations

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Severity, Status
from v3lum.modules.domain_dns import securitytrails as mod
from v3lum.modules.domain_dns.securitytrails import SecurityTrails

KEY = "st-test-key-0123456789abcdef0123"
KEYS = {"securitytrails": KEY}
BASE = "https://api.securitytrails.com/v1"
DOMAIN = f"{BASE}/domain/example.com"
SUBS = f"{BASE}/domain/example.com/subdomains?children_only=false"
HIST = f"{BASE}/history/example.com/dns/a"


def fx(name):
    return module_fixture(SecurityTrails, name)


def full_http(domain="domain_ok_synthetic.json", history="history_a_ok_synthetic.json") -> FakeHttp:
    http = FakeHttp()
    http.add("GET", DOMAIN, json=fx(domain), match_headers={"APIKEY": KEY})
    http.add("GET", SUBS, json=fx("subdomains_ok_synthetic.json"), match_headers={"APIKEY": KEY})
    http.add("GET", HIST, json=fx(history), match_headers={"APIKEY": KEY})
    return http


def pivots(res, relation=None):
    return {p.entity.value for p in res.pivots if relation is None or p.relation == relation}


# ------------------------------------------------------------------ metadata
def test_contract_metadata():
    cls = SecurityTrails
    assert (cls.terms, cls.disclosure, cls.provider, cls.sources, cls.hosts) == (
        "key-terms", "third_party", "securitytrails", ("securitytrails.api",), ("api.securitytrails.com",))
    assert cls.requires_keys == ("securitytrails",) and cls.run_on == "seeds" and cls.default_enabled is True
    assert cls.cache_ttl == 604800 and cls.max_requests == 3
    assert cls.manual_link.startswith("https://securitytrails.com/")  # cond 7: web UI behind Cloudflare
    assert cls.trust_tier == "trusted"


def test_without_key_needs_key():
    http = FakeHttp()
    res = run_module(SecurityTrails, "domain:example.com", http)
    assert res.status is Status.NEEDS_KEY and not http.calls


# ------------------------------------------------------------------ parsing (cond 3, 5)
def test_current_dns_subdomains_and_history():
    http = full_http()
    res = run_module(SecurityTrails, "domain:example.com", http, keys=KEYS)
    assert res.status is Status.OK
    assert res.attributes["a_records"] == ["192.0.2.10", "192.0.2.11"] and res.attributes["aaaa_records"] == ["2001:db8::10"]
    assert res.attributes["mx"] == ["mx.example.net"] and res.attributes["nameservers"] == ["ns1.example.net"]
    assert res.attributes["txt"] == ["v=spf1 -all"] and res.attributes["subdomain_count"] == 4
    # labels come without the apex: appended, lower-cased, validated by the P001 sink; '*.cdn' is a wildcard
    assert res.attributes["subdomains"] == ["dev.example.com", "mail.example.com", "www.example.com"]
    assert pivots(res, "subdomain") == {"dev.example.com", "mail.example.com", "www.example.com"}
    assert all(p.expand is False for p in res.pivots)
    assert res.raw["subdomains"]["wildcards"] == ["*.cdn.example.com"] and res.raw["subdomains"]["rejected"] >= 1
    # every historical record keeps first/last seen (cond 5)
    hist = res.attributes["dns_history_a"]
    assert {(r["ip"], r["first_seen"], r["last_seen"]) for r in hist} == {
        ("192.0.2.10", "2024-03-01", "2026-11-25"), ("198.51.100.7", "2019-05-10", "2024-02-28"), ("203.0.113.5", "2016-01-01", "2019-05-09")}
    assert "origin_ip_candidates" not in res.attributes  # the current A records are not on a CDN
    assert "hostmaster@example.com" not in repr(res.to_dict())  # the SOA e-mail is never read
    assert [c["url"] for c in http.calls] == [DOMAIN, SUBS, HIST]
    http.assert_hosts_within(SecurityTrails)


def test_cdn_fronted_domain_gets_unconfirmed_origin_hypotheses():
    res = run_module(SecurityTrails, "domain:example.com", full_http("domain_cdn_synthetic.json", "history_a_cdn_synthetic.json"), keys=KEYS)
    cands = res.attributes["origin_ip_candidates"]
    assert [c["ip"] for c in cands] == ["93.184.215.14", "45.33.32.156"]  # never the current or a CDN address
    finding = next(f for f in res.findings if "cdn_origin_hypothesis" in f.tags)
    assert finding.severity is Severity.INFO and finding.confidence_label.value == "possible" and "historical" in finding.tags
    assert "ACTIVE" in finding.description  # Host-header confirmation is not part of this module
    hist = {p.entity.value: p for p in res.pivots if p.relation == "historical_a_record"}
    assert set(hist) == {"93.184.215.14", "104.20.23.154", "45.33.32.156"} and all(p.expand is False for p in hist.values())
    assert all(p.entity.type is T.IPV4 and "not current infrastructure" in p.note for p in hist.values())
    assert "104.16.132.229" not in hist  # the current address is never a historical pivot


def test_empty_history_is_still_ok_with_current_dns():
    res = run_module(SecurityTrails, "domain:example.com", full_http(history="history_a_empty_synthetic.json"), keys=KEYS)
    assert res.status is Status.OK and "dns_history_a" not in res.attributes


# ------------------------------------------------------------------ statuses (cond 6)
def test_real_401_is_needs_key_invalid_key():
    http = FakeHttp().add("GET", DOMAIN, status=401, body=module_fixture(SecurityTrails, "error_401.txt").encode())
    res = run_module(SecurityTrails, "domain:example.com", http, keys=KEYS)
    assert res.status is Status.NEEDS_KEY and "invalid key" in res.error


def test_403_is_needs_key_and_quota_bodies_are_quota():
    http = FakeHttp().add("GET", DOMAIN, status=403, json=fx("forbidden_403_synthetic.json"))
    assert run_module(SecurityTrails, "domain:example.com", http, keys=KEYS).status is Status.NEEDS_KEY
    http2 = FakeHttp().add("GET", DOMAIN, status=429, json=fx("quota_429_synthetic.json"))
    res2 = run_module(SecurityTrails, "domain:example.com", http2, keys=KEYS)
    assert res2.status is Status.QUOTA and res2.reason_code == "quota"


def test_plain_429_is_rate_limited_and_challenge_is_blocked():
    http = FakeHttp().add("GET", DOMAIN, status=429, text="Too Many Requests")
    assert run_module(SecurityTrails, "domain:example.com", http, keys=KEYS).status is Status.RATE_LIMITED
    http2 = FakeHttp().add("GET", DOMAIN, status=403, text=module_fixture(SecurityTrails, "web_challenge_403.html"))
    res2 = run_module(SecurityTrails, "domain:example.com", http2, keys=KEYS)
    assert res2.status is Status.BLOCKED and res2.reason_code == "challenge"


def test_errors_and_junk_are_never_empty():
    http = FakeHttp().add("GET", DOMAIN, status=500, text="oops")
    assert run_module(SecurityTrails, "domain:example.com", http, keys=KEYS).status is Status.ERROR
    http2 = FakeHttp().add("GET", DOMAIN, body=b"{oops", headers={"content-type": "application/json"})
    assert run_module(SecurityTrails, "domain:example.com", http2, keys=KEYS).status is Status.ERROR
    http3 = FakeHttp().add("GET", DOMAIN, json={"endpoint": "/v1/domain/example.com"})
    res3 = run_module(SecurityTrails, "domain:example.com", http3, keys=KEYS)
    assert res3.status is Status.ERROR and "could not verify" in res3.error


def test_documented_not_found_is_empty():
    http = FakeHttp().add("GET", DOMAIN, status=404, json={"message": "Domain not found"})
    assert run_module(SecurityTrails, "domain:example.com", http, keys=KEYS).status is Status.EMPTY
    http2 = FakeHttp().add("GET", DOMAIN, status=404, text="<html>nginx</html>")
    assert run_module(SecurityTrails, "domain:example.com", http2, keys=KEYS).status is Status.ERROR


def test_endpoint_refused_by_the_plan_keeps_the_rest():
    http = FakeHttp()
    http.add("GET", DOMAIN, json=fx("domain_ok_synthetic.json"))
    http.add("GET", SUBS, json=fx("subdomains_ok_synthetic.json"))
    http.add("GET", HIST, status=403, json=fx("forbidden_403_synthetic.json"))
    res = run_module(SecurityTrails, "domain:example.com", http, keys=KEYS)
    assert res.status is Status.OK and "history (HTTP 403)" in res.error
    assert res.attributes["subdomains"] and "dns_history_a" not in res.attributes


def test_quota_mid_run_keeps_partial_data():
    http = FakeHttp()
    http.add("GET", DOMAIN, json=fx("domain_ok_synthetic.json"))
    http.add("GET", SUBS, status=429, json=fx("quota_429_synthetic.json"))
    res = run_module(SecurityTrails, "domain:example.com", http, keys=KEYS)
    assert res.attributes["a_records"] and (res.status is Status.QUOTA or res.partial)


def test_the_key_never_reaches_the_result():
    res = run_module(SecurityTrails, "domain:example.com", full_http(), keys=KEYS)
    assert_no_secret(KEY, res)


# ------------------------------------------------------------------ helpers
def test_parsers_tolerate_junk():
    assert mod.parse_domain([]) is None and mod.parse_domain({"current_dns": "x"}) is None
    assert mod.parse_subdomains({"subdomains": "x"}, "example.com") is None
    assert mod.parse_history_a({"records": "x"}) is None
    parsed = mod.parse_history_a({"records": [{"values": [{"ip": "999.1.1.1"}, {"ip": "198.51.100.1"}], "first_seen": "bad"}]})
    assert parsed["records"] == [{"ip": "198.51.100.1", "first_seen": None, "last_seen": None, "organizations": []}]


def test_origin_candidates_need_a_cdn_fronted_domain():
    history = [{"ip": "93.184.215.14", "first_seen": "2019-01-01", "last_seen": "2020-01-01"}]
    assert mod.origin_candidates(history, ["93.184.215.14"], lambda ip: False) == []
    assert mod.origin_candidates(history, ["104.16.132.229"], lambda ip: ip.startswith("104.")) == [
        {"ip": "93.184.215.14", "first_seen": "2019-01-01", "last_seen": "2020-01-01"}]
