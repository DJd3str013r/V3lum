"""hackertarget (P014): passive endpoint allow-list, error strings inside HTTP 200, quota, P061, shared hosting.

Fixtures in tests/fixtures/hackertarget/: the six recorded research answers (aslookup 8.8.8.8 twice,
dnslookup example.com, and three 'API count exceeded - Increase Quota with Membership' bodies for
hostsearch, reverseiplookup and a generic call), live answers recorded 2026-11-26 (hostsearch
registro.br: the first 8 rows and the full 51-row free-tier answer; analyticslookup for the placeholder
UA-000000-1 with third-party domains replaced by site-NN.example.com; the response headers of the five
calls) and derived bodies built from the documented formats (no records found, error check your search
parameter, reverse IP with 3 and 60 names, the ASN form of aslookup).
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, assert_no_secret, make_runtime, module_fixture, run_module
from v3lum.core import policy
from v3lum.core.context import RunInfo, ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.domain_dns import hackertarget as H
from v3lum.modules.domain_dns.hackertarget import HackerTarget

API = "https://api.hackertarget.com/{ep}/?q={q}"
KEY = "ht-test-key-0123456789abcdef"
DEDICATED_IP = "93.184.215.14"  # public, on no CDN/resolver/hosting list


def fx(name):
    return module_fixture(HackerTarget, name)


def text_route(http, ep, q, fixture=None, *, body=None, status=200, key=None, headers=None):
    url = API.format(ep=ep, q=q) + (f"&apikey={key}" if key else "")
    hdrs = {"content-type": "text/plain; charset=utf-8", **(headers or {})}
    http.add("GET", url, status=status, body=(body if body is not None else fx(fixture)).encode(), headers=hdrs)
    return http


def run(http, entity, **kw):
    res = run_module(HackerTarget, entity, http, **kw)
    http.assert_hosts_within(HackerTarget)
    return res


# ------------------------------------------------------------------ metadata, c1 allow-list
def test_metadata():
    cls = HackerTarget
    assert (cls.terms, cls.trust_tier, cls.provider, cls.default_enabled) == ("key-terms", "community", "hackertarget", True)
    assert cls.optional_keys == ("hackertarget",) and cls.requires_keys == ()
    assert cls.hosts == ("api.hackertarget.com",) and cls.sources == ("hackertarget.api",)
    assert cls.max_requests == 2 and cls.run_on == "any"


@pytest.mark.parametrize("endpoint", ["nmap", "zonetransfer", "mtr", "httpheaders", "pagelinks", "nping", "reversedns",
                                      "findshareddns", "geoip", "whois", "../nmap", "hostsearch/../nmap"])
def test_active_and_unapproved_endpoints_cannot_be_built(endpoint):
    """P014 c1: the endpoints that make HackerTarget probe the target are never buildable."""
    with pytest.raises(ValueError):
        H.build_url(endpoint, T.DOMAIN, "example.com")
    assert set(H.ENDPOINTS) == {"hostsearch", "reverseiplookup", "aslookup", "dnslookup", "analyticslookup"}


def test_builder_checks_input_types_and_values():
    assert H.build_url("hostsearch", T.DOMAIN, "Registro.BR") == "https://api.hackertarget.com/hostsearch/?q=registro.br"
    assert H.build_url("aslookup", T.ASN, "as15169") == "https://api.hackertarget.com/aslookup/?q=AS15169"
    for endpoint, etype, value in (("reverseiplookup", T.DOMAIN, "example.com"), ("reverseiplookup", T.IPV4, "192.168.1.1"),
                                   ("analyticslookup", T.ANALYTICS_ID, "example.com"), ("hostsearch", T.DOMAIN, "a b.com")):
        with pytest.raises(ValueError):
            H.build_url(endpoint, etype, value)


# ------------------------------------------------------------------ domain: hostsearch
def test_hostsearch_subdomains_and_addresses():
    http = text_route(FakeHttp(), "hostsearch", "registro.br", "hostsearch_ok.txt", headers={"x-api-quota": "21", "x-api-count": "5"})
    res = run(http, "domain:registro.br")
    assert res.status is Status.OK
    subs = res.attributes["subdomains"]
    assert "bankslip.registro.br" in subs and "registro.br" not in subs and len(subs) == 7
    pdns = res.attributes["passive_dns"]
    assert {"hostname": "bankslip.registro.br", "address": "200.160.2.37", "record_type": "A", "source": "hackertarget hostsearch"} in pdns
    rels = {(p.entity.value, p.relation, p.expand) for p in res.pivots}
    assert ("beta.registro.br", "subdomain", True) in rels and ("200.160.2.6", "related", False) in rels
    assert res.raw["queries"][0]["x-api-count"] == 5 and "truncated_answer" not in res.attributes
    assert len(http.calls) == 1  # dnslookup is off by default (the core DoH covers it without quota)


def test_hostsearch_free_tier_cap_is_flagged():
    http = text_route(FakeHttp(), "hostsearch", "registro.br", "hostsearch_capped.txt")
    res = run(http, "domain:registro.br")
    assert "possibly incomplete" in res.attributes["truncated_answer"]
    assert len(res.attributes["subdomains"]) == 50


def test_dnslookup_when_enabled():
    http = text_route(FakeHttp(), "hostsearch", "example.com", "no_records_derived.txt")
    text_route(http, "dnslookup", "example.com", "dnslookup_ok.txt")
    res = run(http, "domain:example.com", settings={"hackertarget_dnslookup": True})
    assert res.attributes["a_records"] == ["104.20.23.154", "172.66.147.243"]
    assert res.attributes["nameservers"] == ["elliott.ns.cloudflare.com", "hera.ns.cloudflare.com"]
    assert {"type": "MX", "value": "0 .", "host": "."} in res.raw["dnslookup"]


# ------------------------------------------------------------------ c2: error strings in HTTP 200, before parsing
@pytest.mark.parametrize("fixture", ["quota_exceeded.txt", "hostsearch_quota_exceeded.txt"])
def test_quota_exceeded_in_200_is_quota_with_one_wording(fixture):
    http = text_route(FakeHttp(), "hostsearch", "example.com", fixture)
    res = run(http, "domain:example.com")
    assert (res.status, res.reason_code) == (Status.QUOTA, "quota")
    assert res.error == H.QUOTA_LINE and res.pivots == [] and "subdomains" not in res.attributes


def test_quota_marks_the_provider_exhausted_for_the_rest_of_the_run():
    http = text_route(FakeHttp(), "reverseiplookup", DEDICATED_IP, "reverseiplookup_quota_exceeded.txt")
    res = run(http, f"ipv4:{DEDICATED_IP}")
    assert res.status is Status.QUOTA and res.error == H.QUOTA_LINE
    assert len(http.calls) == 1  # aslookup is never sent once the provider signalled its quota (P334)


def test_keyed_quota_wording_and_the_key_never_leaks():
    http = text_route(FakeHttp(), "hostsearch", "example.com", "quota_exceeded.txt", key=KEY)
    res = run(http, "domain:example.com", keys={"hackertarget": KEY})
    assert res.status is Status.QUOTA and res.error == H.QUOTA_LINE_KEYED
    assert http.urls() == [f"https://api.hackertarget.com/hostsearch/?q=example.com&apikey={KEY}"]
    assert_no_secret(KEY, res.to_dict(), res.raw, res.error)


def test_error_strings_are_errors_never_empty():
    http = text_route(FakeHttp(), "hostsearch", "example.com", "error_bad_parameter_derived.txt")
    assert run(http, "domain:example.com").status is Status.ERROR
    http2 = text_route(FakeHttp(), "hostsearch", "example.com", body="error invalid api key\n")
    res = run(http2, "domain:example.com")
    assert res.status is Status.ERROR and "error message in an HTTP 200 body" in res.error
    # a record whose host starts with 'error' is data, never an error marker
    http3 = text_route(FakeHttp(), "hostsearch", "example.com", body="error.example.com,192.0.2.1\nwww.example.com,192.0.2.2\n")
    assert set(run(http3, "domain:example.com").attributes["subdomains"]) == {"error.example.com", "www.example.com"}


def test_no_records_is_a_documented_empty():
    http = text_route(FakeHttp(), "hostsearch", "example.com", "no_records_derived.txt")
    assert run(http, "domain:example.com").status is Status.EMPTY
    http2 = text_route(FakeHttp(), "analyticslookup", "UA-58491234-1", "analyticslookup_no_results.txt")
    assert run(http2, "analytics_id:UA-58491234-1").status is Status.EMPTY


def test_html_empty_and_transport_failures_are_could_not_verify():
    page = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    blocked = FakeHttp().add("GET", API.format(ep="hostsearch", q="example.com"), status=403, text=page)
    assert run(blocked, "domain:example.com").status is Status.BLOCKED
    limited = text_route(FakeHttp(), "hostsearch", "example.com", body="slow down", status=429)
    assert run(limited, "domain:example.com").status is Status.RATE_LIMITED
    broken = text_route(FakeHttp(), "hostsearch", "example.com", body="bad gateway", status=502)
    broken.add("GET", API.format(ep="hostsearch", q="example.com"), status=502, body=b"bad gateway")
    assert run(broken, "domain:example.com").status is Status.ERROR
    html = text_route(FakeHttp(), "hostsearch", "example.com", body="<html><body>maintenance</body></html>")
    assert run(html, "domain:example.com").status is Status.ERROR
    empty = text_route(FakeHttp(), "hostsearch", "example.com", body="  \n")
    assert run(empty, "domain:example.com").status is Status.ERROR


# ------------------------------------------------------------------ IPv4: reverse IP (c6) and ASN
def test_dedicated_ip_cohosted_domains_pivot():
    http = text_route(FakeHttp(), "reverseiplookup", DEDICATED_IP, "reverseiplookup_dedicated_derived.txt")
    text_route(http, "aslookup", DEDICATED_IP, body='"93.184.215.14","15133","93.184.215.0/24","EDGECAST, US"')
    res = run(http, f"ipv4:{DEDICATED_IP}")
    hosted = {p.entity.value for p in res.pivots if p.relation == "hosted_domain"}
    assert hosted == {"shop.example.com", "login-update.example.net", "example.org"}
    assert res.attributes["cohosting"]["mode"] == "pivot" and res.attributes["asn"] == "AS15133"
    assert res.attributes["prefix"] == "93.184.215.0/24" and res.attributes["as_country"] == "US"


def test_more_than_50_names_or_a_shared_address_is_a_count_only():
    http = text_route(FakeHttp(), "reverseiplookup", DEDICATED_IP, "reverseiplookup_shared_derived.txt")
    text_route(http, "aslookup", DEDICATED_IP, "aslookup_ok.txt")
    res = run(http, f"ipv4:{DEDICATED_IP}")
    co = res.attributes["cohosting"]
    assert (co["count"], co["mode"], co["exclude_from_shared_infra"]) == (60, "count_only", True)
    assert not [p for p in res.pivots if p.relation == "hosted_domain"] and res.attributes["shared_ip"] is True
    # 8.8.8.8 is a public resolver address (core noise kind 'resolver'): counts only even with 3 names
    http2 = text_route(FakeHttp(), "reverseiplookup", "8.8.8.8", "reverseiplookup_dedicated_derived.txt")
    text_route(http2, "aslookup", "8.8.8.8", "aslookup_ok_live_cti.txt")
    res2 = run(http2, "ipv4:8.8.8.8")
    assert res2.attributes["cohosting"]["mode"] == "count_only" and "resolver" in res2.attributes["cohosting"]["reason"]
    assert res2.attributes["asn"] == "AS15169" and res2.attributes["as_org"] == "GOOGLE"
    assert {(p.entity.value, p.relation) for p in res2.pivots} == {("AS15169", "belongs_to_asn"), ("8.8.8.0/24", "in_network")}


def test_partial_ipv4_run_keeps_data_when_the_quota_ends():
    http = text_route(FakeHttp(), "reverseiplookup", DEDICATED_IP, "reverseiplookup_dedicated_derived.txt")
    text_route(http, "aslookup", DEDICATED_IP, "quota_exceeded.txt")
    res = run(http, f"ipv4:{DEDICATED_IP}")
    assert res.status is Status.OK and res.partial and res.stop_reason == "quota"
    assert {p.entity.value for p in res.pivots} >= {"shop.example.com"}


def test_private_ips_are_never_sent():
    res = run_module(HackerTarget, "ipv4:192.168.10.1", FakeHttp())
    assert (res.status, res.reason_code) == (Status.SKIPPED, "not_applicable")


def test_asn_input_prefixes():
    http = text_route(FakeHttp(), "aslookup", "AS15169", "aslookup_asn_derived.txt")
    res = run(http, "asn:AS15169")
    assert res.attributes["as_org"] == "GOOGLE" and res.attributes["announced_prefix_counts"]["total"] == 4
    assert {p.entity.value for p in res.pivots} == {"8.8.4.0/24", "8.8.8.0/24", "34.64.0.0/10", "2001:4860::/32"}
    assert all(p.relation == "announces" and p.expand is False for p in res.pivots)


# ------------------------------------------------------------------ c5: P061 shared-id rule
def test_template_analytics_id_is_a_shared_id_without_pivots():
    http = text_route(FakeHttp(), "analyticslookup", "UA-000000-1", "analyticslookup_ok.txt")
    res = run(http, "analytics_id:UA-000000-1")
    shared = res.attributes["analytics_shared_id"]
    assert shared["shared"] is True and shared["label"] == "shared ID UA-000000-1: 10 domains"
    assert res.pivots == [] and res.findings[0].confidence <= 0.3


def test_distinct_analytics_id_pivots_capped_without_expansion():
    body = fx("analyticslookup_ok.txt") + "".join(f"site-{i}.example.com\tua\n" for i in range(11, 31))
    http = text_route(FakeHttp(), "analyticslookup", "UA-58491234-1", body=body)
    res = run(http, "analytics_id:UA-58491234-1")
    pivots = [p for p in res.pivots if p.relation == "same_analytics"]
    assert len(pivots) == H.ANALYTICS_PIVOTS and all(p.expand is False and p.confidence <= 0.7 for p in pivots)
    assert res.attributes["analytics_shared_id"]["shared"] is False


def test_more_than_50_domains_is_a_shared_id():
    body = "".join(f"tenant-{i:03d}.example.com\tua\n" for i in range(60))
    http = text_route(FakeHttp(), "analyticslookup", "G-ABCDEF1234", body=body)
    res = run(http, "analytics_id:G-ABCDEF1234")
    assert res.attributes["analytics_shared_id"]["reason"] == "more than 50 domains" and res.pivots == []


# ------------------------------------------------------------------ c3: seeds keyless, pivots with a key
def test_keyless_pivots_are_skipped_but_keyed_pivots_run():
    http = FakeHttp()
    res = run_module(HackerTarget, "domain:example.com", http, is_seed=False, depth=1)
    assert (res.status, res.reason_code) == (Status.SKIPPED, "not_applicable") and http.calls == []
    keyed = text_route(FakeHttp(), "hostsearch", "example.com", "no_records_derived.txt", key=KEY)
    assert run(keyed, "domain:example.com", keys={"hackertarget": KEY}, is_seed=False, depth=1).status is Status.EMPTY


def test_licence_gate_keyless_needs_the_recorded_free_plan_decision():
    rt = make_runtime(FakeHttp())
    ent = Entity.make(T.DOMAIN, "example.com")
    decision = policy.decide(HackerTarget, ent, policy.make_context(rt, ScanOptions()), run=RunInfo(entity=ent, is_seed=True))
    assert (decision.allowed, decision.reason_code) == (False, "licence")
    business = make_runtime(FakeHttp(), keys={"hackertarget": KEY}, settings={"key_plans": {"hackertarget": "business"}})
    assert policy.decide(HackerTarget, ent, policy.make_context(business, ScanOptions()), run=RunInfo(entity=ent, is_seed=True)).allowed


def test_one_quota_line_per_scan_not_one_per_entity():
    """P014 c7: after the first 'API count exceeded' the provider is exhausted for the run; every later
    entity ends QUOTA with the same wording and the case carries one HackerTarget quota line."""
    http = text_route(FakeHttp(), "hostsearch", "example.com", "quota_exceeded.txt", key=KEY)
    text_route(http, "hostsearch", "example.org", "quota_exceeded.txt", key=KEY)
    rt = make_runtime(http, keys={"hackertarget": KEY}, settings={"key_plans": {"hackertarget": "business"}})
    engine = Engine(rt, ScanOptions(include={"hackertarget"}, depth=0))
    case = engine.investigate([Entity.make(T.DOMAIN, "example.com"), Entity.make(T.DOMAIN, "example.org")])
    results = [r for r in case.results if r.module == "hackertarget"]
    assert {r.status for r in results} == {Status.QUOTA} and {r.error for r in results} == {H.QUOTA_LINE_KEYED}
    lines = [line for line in case.meta.get("quota_lines", []) if "HackerTarget" in line]
    assert len(lines) == 1, case.meta.get("quota_lines")


# ------------------------------------------------------------------ AR21 golden-path routes (section 19)
def test_acceptance_routes_are_empty_because_keyless_use_waits_for_legal():
    """tests/fixtures/acceptance/{domain,ipv4}/hackertarget.json hold no route: keyless HackerTarget needs
    free_plan_business_use recorded by legal (P014 c4, A1), so a default scan sends nothing."""
    from tests.fakes import fixture

    rt = make_runtime(FakeHttp())
    for etype, value in (("domain", "example.com"), ("ipv4", "8.8.8.8")):
        doc = fixture(f"acceptance/{etype}/hackertarget.json")
        assert (doc["schema"], doc["module"], doc["routes"]) == ("v3lum.acceptance_routes/1", "hackertarget", [])
        ent = Entity.make(T(etype), value)
        decision = policy.decide(HackerTarget, ent, policy.make_context(rt, ScanOptions()), run=RunInfo(entity=ent, is_seed=True))
        assert (decision.allowed, decision.reason_code) == (False, "licence")
