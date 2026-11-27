"""Offline tests of netlas (P037) with the trimmed real fixtures in tests/fixtures/netlas/.

host_ip_ok.json (8.8.8.8, research 2026-11-25), host_domain_ok.json (example.com),
host_ip_reserved_shared.json (192.0.2.1), domains_count_*.json and domains_search_ok.json are keyless
live answers (2026-11-26), minimised and scrubbed (third-party co-hosted names became documentation
names, the abuse address became @example.com). The 401/quota fixtures are synthetic in the official
SDK error shape; the 429 shape is documented by the SDK.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlencode

import pytest

from tests.fakes import FakeHttp, assert_no_secret, make_runtime, module_fixture, run_module
from v3lum import config
from v3lum.core.context import ScanOptions
from v3lum.core.models import Status
from v3lum.core.tlp import TLP
from v3lum.modules.ip_network.netlas import (
    ENDPOINTS,
    SOURCE_API,
    SOURCE_PAID,
    Netlas,
    cohost_plan,
    domain_query,
    netlas_url,
    parse_count,
    parse_domains,
    parse_host,
)
from v3lum.modules.ip_network.scan_engines import EndpointRefused
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T

FIX = "netlas"
KEY = "nl-test-key-0123456789abcdef"  # fake key
KEYS = {"netlas": KEY}
HOST = "https://app.netlas.io/api/host/{v}/"
COUNT = "https://app.netlas.io/api/domains_count/?{q}"
DOMAINS = "https://app.netlas.io/api/domains/?{q}"
FIXDIR = Path(__file__).resolve().parents[1] / "fixtures" / FIX


def fx(name: str):
    return module_fixture(FIX, name)


def http_fx(name: str) -> dict:
    """A *.http.json wrapper -> FakeHttp route keywords (status, json, headers)."""
    wrapper = fx(name)
    resp = wrapper["response"]
    return {"status": resp["status"], "json": resp["body"], "headers": resp.get("headers") or {}}


def test_metadata_follows_the_council_decision():
    cls = Netlas
    assert (cls.terms, cls.default_enabled, cls.trust_tier, cls.opsec.label) == ("noncommercial", True, "community", "passive")
    assert cls.terms_sources == {SOURCE_API: "noncommercial", SOURCE_PAID: "key-terms"}  # c1: two access modes
    assert cls.optional_keys == ("netlas",) and cls.requires_keys == ()
    assert "V3LUM_NETLAS_KEY" in config.key_registry()["netlas"].env
    assert cls.hosts == ("app.netlas.io",) and cls.shares_input is True
    assert cls.max_tlp == TLP.AMBER and cls.daily_quota == 40 and cls.cache_ttl == 86400
    assert cls.manual_link.startswith("https://app.netlas.io/host/")  # c6: web UI is a manual link only


def test_only_host_and_domain_endpoints_can_be_built():
    assert set(ENDPOINTS) == {"host", "domains_count", "domains"}
    assert netlas_url("host", "8.8.8.8") == "https://app.netlas.io/api/host/8.8.8.8/"
    assert netlas_url("host", "Example.COM.") == "https://app.netlas.io/api/host/example.com/"
    for forbidden in ("scanner", "responses", "domains_download", "certs", "whois_ip", "/api/scanner/"):
        with pytest.raises(EndpointRefused):
            netlas_url(forbidden, "8.8.8.8")
    with pytest.raises(ValueError):
        netlas_url("host", "not a host")
    assert domain_query(Entity.make(T.DOMAIN, "nic.br")) == "domain:*.nic.br"
    assert domain_query(Entity.make(T.KEYWORD, "acme-bank")) == "domain:*acme-bank*"


def test_ip_host_answer_with_key_in_header_only():
    http = FakeHttp().add("GET", HOST.format(v="8.8.8.8"), json=fx("host_ip_ok.json"), match_headers={"X-API-Key": KEY})
    res = run_module(Netlas, "ipv4:8.8.8.8", http, keys=KEYS)
    assert res.status is Status.OK
    (call,) = http.calls
    assert KEY not in call["url"]
    a = res.attributes
    assert a["open_ports"] == [53, 443, 853]
    assert a["asn"] == "AS15169" and a["as_org"] == "GOOGLE - Google LLC" and a["country"] == "US"
    assert a["whois_network"]["cidrs"] == ["8.8.8.0/24"] and a["whois_network"]["source"] == "netlas"
    assert a["abuse_contact"] == "network-abuse@example.com"  # attribute only, never a pivot
    assert a["rdns"] == ["dns.google"]
    # c5: 47137 co-hosted names -> shared hosting, count only
    assert a["cohosted_count"] == 47137 and a["cohosting"]["mode"] == "count_only"
    assert {p.entity.value for p in res.pivots} == {"dns.google"}
    assert not any(p.entity.type is T.EMAIL for p in res.pivots)
    # every IOC record carries Netlas' own fp alarm -> context only, no finding
    assert a["netlas_ioc"]["fp_flagged"] == 2 and a["netlas_ioc"]["credible"] == []
    assert not res.findings
    assert any(url == "https://app.netlas.io/host/8.8.8.8/" for _, url in res.links)
    assert_no_secret(KEY, res)
    http.assert_hosts_within(Netlas)


def test_small_cohosting_set_gives_capped_pivots_and_cdn_ips_give_counts(monkeypatch):
    doc = fx("host_ip_ok.json")
    doc["domains_count"] = 3
    ent = Entity.make(T.IPV4, "93.184.215.14")
    plan = cohost_plan(ent, parse_host(doc))
    assert plan["mode"] == "pivot" and plan["expand"] is True and len(plan["pivots"]) == 3
    http = FakeHttp().add("GET", HOST.format(v="93.184.215.14"), json=doc, match_headers={"X-API-Key": KEY})
    res = run_module(Netlas, "ipv4:93.184.215.14", http, keys=KEYS)
    hosted = [p for p in res.pivots if p.relation == "hosted_domain"]
    assert sorted(p.entity.value for p in hosted) == ["mail.example.net", "portal.example.org", "shop.example.com"]
    assert all(p.expand for p in hosted)
    # a CDN/hosting address (noise lists) never yields co-hosted pivots
    from v3lum.modules.ip_network import netlas as mod
    monkeypatch.setattr(mod.noise, "is_cdn", lambda entity: True)
    plan = cohost_plan(ent, parse_host(doc))
    assert plan["mode"] == "count_only" and plan["pivots"] == []


def test_reserved_ip_answer_with_many_names_is_count_only_and_service_labels_are_dropped():
    parsed = parse_host(fx("host_ip_reserved_shared.json"))
    assert "_dc-mx.0a1b2c3d4e5f.example.com" not in parsed["domains"]  # service label, never a host
    http = FakeHttp().add("GET", HOST.format(v="9.9.9.9"), json=fx("host_ip_reserved_shared.json"), match_headers={"X-API-Key": KEY})
    res = run_module(Netlas, "ipv4:9.9.9.9", http, keys=KEYS)
    assert res.status is Status.OK
    assert res.attributes["cohosting"]["mode"] == "count_only" and res.attributes["cohosted_count"] == 23219
    assert not res.pivots


def test_private_and_reserved_addresses_are_never_sent():
    for value in ("10.0.0.1", "192.0.2.1", "127.0.0.1"):
        res = run_module(Netlas, f"ipv4:{value}", FakeHttp(), keys=KEYS)
        assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_domain_host_answer_then_subdomain_page_for_seeds():
    http = (FakeHttp()
            .add("GET", HOST.format(v="example.com"), json=fx("host_domain_ok.json"))
            .add("GET", DOMAINS.format(q=urlencode({"q": "domain:*.example.com"})), json=fx("domains_search_ok.json")))
    res = run_module(Netlas, "domain:example.com", http, keys=KEYS)
    assert res.status is Status.OK
    a = res.attributes
    assert a["a_records"] == ["104.20.23.154", "172.66.147.243", "8.47.69.0"]
    assert a["nameservers"] == ["elliott.ns.cloudflare.com", "hera.ns.cloudflare.com"]
    assert a["txt"][0] == "v=spf1 -all" and a["is_cdn"] is True and a["subdomain_count"] == 96666
    assert a["created"].startswith("1992-01-01")
    rel = {(p.relation, p.entity.value): p for p in res.pivots}
    assert rel[("resolves_to", "104.20.23.154")].expand is False  # indexed DNS: re-resolve first
    assert rel[("nameserver", "elliott.ns.cloudflare.com")].expand is False
    assert rel[("subdomain", "vps.example.com")].expand is True
    # the nic.br records of the page are outside the queried apex: listed, never expanded
    assert rel[("related", "ipv6.nic.br")].expand is False
    assert any(r["domain"] == "api.simetas.nic.br" for r in a["subdomain_records"])
    # one IOC record without the fp alarm -> one weak vote, never a verdict
    (finding,) = res.findings
    assert finding.severity.name == "LOW" and "weak_signal" in finding.tags and "malicious" not in finding.tags
    assert finding.data["credible"] == 1 and "duke_group" in finding.data["threats"]
    assert finding.criterion and finding.source == SOURCE_API
    http.assert_hosts_within(Netlas)


def test_pivots_at_depth_do_not_spend_the_extra_page():
    http = FakeHttp().add("GET", HOST.format(v="example.com"), json=fx("host_domain_ok.json"))
    res = run_module(Netlas, "domain:example.com", http, keys=KEYS, is_seed=False, depth=1)
    assert res.status is Status.OK and len(http.calls) == 1


def test_keyword_is_sized_with_the_free_count_first():
    http = (FakeHttp()
            .add("GET", COUNT.format(q=urlencode({"q": "domain:*nicbr*"})), json=fx("domains_count_ok.json"))
            .add("GET", DOMAINS.format(q=urlencode({"q": "domain:*nicbr*"})), json=fx("domains_search_ok.json")))
    res = run_module(Netlas, "keyword:nicbr", http, keys=KEYS)
    assert res.status is Status.OK
    assert [c["url"].split("?")[0] for c in http.calls] == ["https://app.netlas.io/api/domains_count/", "https://app.netlas.io/api/domains/"]
    assert all(p.relation == "scanner_match" and p.expand is False for p in res.pivots)
    assert len(res.attributes["keyword_domains"]) == 5


def test_keyword_with_zero_count_is_empty_and_spends_one_request():
    http = FakeHttp().add("GET", COUNT.format(q=urlencode({"q": "domain:*nothing-here*"})), json=fx("domains_count_empty.json"))
    res = run_module(Netlas, "keyword:nothing-here", http, keys=KEYS)
    assert res.status is Status.EMPTY and len(http.calls) == 1


def test_default_scan_without_key_is_needs_key_and_keyless_only_with_explicit_selection():
    dead = FakeHttp()
    rt = make_runtime(dead)
    rt.in_scan = True
    res = run_module(Netlas, "ipv4:8.8.8.8", runtime=rt)
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key" and not dead.calls
    # -M netlas inside a scan: the keyless lookup runs (no key header)
    http = FakeHttp().add("GET", HOST.format(v="8.8.8.8"), json=fx("host_ip_ok.json"))
    rt2 = make_runtime(http)
    rt2.in_scan = True
    res2 = run_module(Netlas, "ipv4:8.8.8.8", runtime=rt2, options=ScanOptions(include={"netlas"}))
    assert res2.status is Status.OK
    (call,) = http.calls
    assert not any(k.lower() == "x-api-key" for k in (call.get("headers") or {}))


def test_licence_mode_selects_the_source():
    http = FakeHttp().add("GET", HOST.format(v="8.8.8.8"), json=fx("host_ip_ok.json"))
    res = run_module(Netlas, "ipv4:8.8.8.8", http, keys=KEYS, settings={"key_plans": {"netlas": "business"}})
    assert res.raw["source"] == SOURCE_PAID
    http2 = FakeHttp().add("GET", HOST.format(v="8.8.8.8"), json=fx("host_ip_ok.json"))
    res2 = run_module(Netlas, "ipv4:8.8.8.8", http2, keys=KEYS, allowed_sources=[SOURCE_PAID])
    assert res2.raw["source"] == SOURCE_PAID
    res3 = run_module(Netlas, "ipv4:8.8.8.8", FakeHttp(), allowed_sources=[SOURCE_PAID])  # keyless: no licensed mode
    assert res3.status is Status.SKIPPED and res3.reason_code == "licence"


def test_empty_host_answer_is_empty():
    http = FakeHttp().add("GET", HOST.format(v="8.8.4.4"), json=fx("host_empty_synthetic.json"))
    res = run_module(Netlas, "ipv4:8.8.4.4", http, keys=KEYS)
    assert res.status is Status.EMPTY and "no host data" in res.error


@pytest.mark.parametrize(
    ("fixture", "status", "code"),
    [
        ("quota_error_in_200_synthetic.http.json", Status.QUOTA, "quota"),
        ("rate_limited_429_documented.http.json", Status.RATE_LIMITED, "rate_limited"),
        ("needs_key_401_synthetic.http.json", Status.NEEDS_KEY, "needs_key"),
    ],
)
def test_error_bodies_are_never_empty(fixture, status, code):
    http = FakeHttp().add("GET", HOST.format(v="8.8.8.8"), **http_fx(fixture))
    res = run_module(Netlas, "ipv4:8.8.8.8", http, keys=KEYS)
    assert res.status is status and res.reason_code == code


def test_auth_and_unknown_error_bodies_inside_200():
    body = {"type": "not_authenticated", "title": "Not authenticated", "detail": "Authentication credentials were not provided."}
    res = run_module(Netlas, "ipv4:8.8.8.8", FakeHttp().add("GET", HOST.format(v="8.8.8.8"), json=body), keys=KEYS)
    assert res.status is Status.NEEDS_KEY
    throttled = {"type": "request_was_throttled", "title": "Throttled", "detail": "Expected available in 30 seconds."}
    res = run_module(Netlas, "ipv4:8.8.8.8", FakeHttp().add("GET", HOST.format(v="8.8.8.8"), json=throttled), keys=KEYS)
    assert res.status is Status.RATE_LIMITED
    other = {"type": "server_error", "title": "Oops", "detail": "something broke"}
    res = run_module(Netlas, "ipv4:8.8.8.8", FakeHttp().add("GET", HOST.format(v="8.8.8.8"), json=other), keys=KEYS)
    assert res.status is Status.ERROR


def test_keyless_403_challenge_and_5xx_are_could_not_verify():
    page = fx("web_ui_challenge.http.json")["response"]
    http = FakeHttp().add("GET", HOST.format(v="8.8.8.8"), status=403, text=page["body"], headers=page["headers"])
    res = run_module(Netlas, "ipv4:8.8.8.8", http)  # explicit single run, keyless
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"
    http = FakeHttp().add("GET", HOST.format(v="8.8.8.8"), status=403, json={"detail": "forbidden"})
    res = run_module(Netlas, "ipv4:8.8.8.8", http)
    assert res.status is Status.BLOCKED
    http = FakeHttp().add("GET", HOST.format(v="8.8.8.8"), status=503, text="upstream down", times=3)
    assert run_module(Netlas, "ipv4:8.8.8.8", http, keys=KEYS).status is Status.ERROR


def test_truncated_and_malformed_answers_are_errors():
    raw = (FIXDIR / "malformed_truncated.json").read_bytes()
    http = FakeHttp().add("GET", HOST.format(v="example.com"), body=raw, headers={"Content-Type": "application/json"})
    res = run_module(Netlas, "domain:example.com", http, keys=KEYS)
    assert res.status is Status.ERROR
    http = FakeHttp().add("GET", HOST.format(v="8.8.8.8"), json=["not", "a", "host"])
    assert run_module(Netlas, "ipv4:8.8.8.8", http, keys=KEYS).status is Status.ERROR


def test_parsers_are_defensive():
    for junk in (None, 42, "x", [], {"unexpected": True}):
        assert parse_host(junk) is None
        assert parse_domains(junk) is None
    assert parse_count({"count": "7"}) == 7 and parse_count({"count": -1}) is None and parse_count([]) is None
    assert parse_host({"type": "ip", "ports": [{"port": 99999}, {"port": "x"}], "ioc": "bad"})["empty"] is True
