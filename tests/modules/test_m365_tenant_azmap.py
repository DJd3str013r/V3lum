"""m365_tenant_azmap (P011 cond 6-7): azmap.dev related tenant domains with DNS confirmation.

Fixtures in tests/fixtures/m365_tenant_azmap/: the recorded microsoft.com answer (140 related domains,
research sample, byte-identical to the 2026-11-26 live answer), the live HTTP 404 DOMAIN_NOT_FOUND
answer for example.invalid, the live example.com answer of an unmanaged test tenant (tenant id and
names replaced by placeholders) and live Google DoH answers (ECS 0.0.0.0/0) for the MX/TXT records of
microsoft.com, github.com and cloudflare.com (TXT minimised to the MS= and SPF records); the null-MX
answer for example.com is derived from the observed record.
"""

from __future__ import annotations

import re

from tests.fakes import FakeHttp, add_dns_failure, doh_url, make_runtime, module_fixture, run_module
from v3lum.core import policy
from v3lum.core.context import RunInfo, ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.domain_dns import m365_tenant_azmap as AZ
from v3lum.modules.domain_dns.m365_tenant_azmap import M365TenantAzmap

API = "https://azmap.dev/api/tenant?domain={d}&extract=true"
MS_TID = "72f988bf-86f1-41af-91ab-2d7cd011db47"
ANY_DOH = re.compile(r"^https://(dns\.google/resolve|cloudflare-dns\.com/dns-query)\?")


def fx(name):
    return module_fixture(M365TenantAzmap, name)


def doh_route(http, name, rtype, fixture):
    http.add("GET", doh_url(name, rtype), json=fx(fixture))


def nodata_everything(http, *, mx=None):
    """Every other DoH query answers NOERROR without records (or the given MX record)."""
    answer = {"Status": 0, "Answer": []}
    if mx is not None:
        answer = {"Status": 0, "Answer": [{"name": "x.", "type": 15, "TTL": 300, "data": mx}]}
    http.add("GET", ANY_DOH, json=answer)


def run(http, entity="domain:microsoft.com", **kw):
    res = run_module(M365TenantAzmap, entity, http, **kw)
    http.assert_hosts_within(M365TenantAzmap)
    return res


def test_metadata_unknown_terms_and_tier_never_default():
    cls = M365TenantAzmap
    assert (cls.terms, cls.trust_tier, cls.default_enabled) == ("unknown", "unknown", False)
    assert (cls.provider, cls.sources, cls.hosts) == ("azmap", ("azmap.tenant",), ("azmap.dev",))
    assert (cls.max_requests, cls.cache_ttl) == (1, 86400)
    assert cls.max_tlp.value_str == "green"  # excluded at AMBER and above (P011 c6)


def test_policy_excludes_it_at_amber_and_needs_allow_unknown_below():
    rt = make_runtime(FakeHttp())
    ent = Entity.make(T.DOMAIN, "microsoft.com")
    seed = RunInfo(entity=ent, is_seed=True)
    amber = policy.decide(M365TenantAzmap, ent, policy.make_context(rt, ScanOptions(include={"m365_tenant_azmap"})), run=seed)
    assert amber.allowed is False
    clear = policy.decide(M365TenantAzmap, ent, policy.make_context(rt, ScanOptions(tlp="clear", include={"m365_tenant_azmap"})),
                          run=RunInfo(entity=ent, is_seed=True, tlp="clear"))
    assert clear.allowed is False  # unknown tier needs --allow-unknown, and unknown terms never run under corporate


def test_related_domains_listed_in_full_and_pivot_only_after_dns_confirmation():
    http = FakeHttp().add("GET", API.format(d="microsoft.com"), json=fx("ok.json"))
    doh_route(http, "github.com", "MX", "doh_mx_github.json")
    nodata_everything(http)
    res = run(http)
    assert res.status is Status.OK
    a = res.attributes
    assert a["m365_tenant_id"] == MS_TID and a["m365_tenant_name"] == "microsoft" and a["m365_brand_name"] == "Microsoft"
    related = a["m365_related_domains"]
    assert related["count"] == 140 and len(related["domains"]) == related["listed"] and "xbox.com" in related["domains"]
    conf = a["m365_dns_confirmation"]
    assert conf["confirmed"] == ["github.com"] and conf["evidence"]["github.com"] == ["MX github-com.mail.protection.outlook.com"]
    assert conf["checked"] <= AZ.MAX_CONFIRMATIONS and conf["doh_queries"] <= AZ.MAX_DOH_QUERIES
    pivots = [(p.entity.value, p.relation, p.confidence_label) for p in res.pivots]
    assert pivots == [("github.com", "same_m365_tenant", "probable")]  # never above PROBABLE
    finding = res.findings[0]
    assert "domains share Microsoft 365 tenant Microsoft" in finding.description and finding.confidence_label == "possible"
    assert len([c for c in http.calls if "azmap.dev" in c["url"]]) == 1  # one call per domain


def test_txt_ms_record_confirms_when_mx_does_not():
    http = FakeHttp().add("GET", API.format(d="microsoft.com"), json={
        "tenant_id": MS_TID, "tenant_name": "microsoft", "brand_name": "Microsoft", "domain": "microsoft.com",
        "related_domains": ["microsoft.com", "cloudflare.com", "github.com"], "related_count": 3})
    doh_route(http, "cloudflare.com", "TXT", "doh_txt_cloudflare.json")
    doh_route(http, "github.com", "TXT", "doh_txt_github.json")
    nodata_everything(http)
    res = run(http)
    conf = res.attributes["m365_dns_confirmation"]
    assert set(conf["confirmed"]) == {"cloudflare.com", "github.com"}
    assert conf["evidence"]["cloudflare.com"] == ["TXT MS=ms70274184"]
    assert "TXT MS=6BF03E6AF5CB689E315FB6199603BABF2C88D805" in conf["evidence"]["github.com"]
    assert conf["doh_queries"] == 4  # MX first, TXT only when MX does not confirm


def test_caps_ten_pivots_fifty_checks_hundred_queries():
    many = [f"brand{i:03d}.example" for i in range(200)]
    body = {"tenant_id": MS_TID, "tenant_name": "contoso", "brand_name": "Contoso", "domain": "contoso.example",
            "related_domains": ["contoso.example", *many], "related_count": 201}
    http = FakeHttp().add("GET", API.format(d="contoso.example"), json=body)
    nodata_everything(http, mx="0 contoso-example.mail.protection.outlook.com.")
    res = run(http, "domain:contoso.example")
    assert len(res.pivots) == AZ.MAX_PIVOTS and res.attributes["m365_dns_confirmation"]["stop_reason"] == "max_pivots"
    http2 = FakeHttp().add("GET", API.format(d="contoso.example"), json=body)
    nodata_everything(http2)  # nothing confirms: MX + TXT per domain
    conf = run(http2, "domain:contoso.example").attributes["m365_dns_confirmation"]
    assert conf["doh_queries"] <= AZ.MAX_DOH_QUERIES and conf["checked"] <= AZ.MAX_CONFIRMATIONS
    doh = [c for c in http2.calls if "dns.google" in c["url"] or "cloudflare-dns" in c["url"]]
    assert len(doh) <= AZ.MAX_DOH_QUERIES and conf["stop_reason"] in ("max_doh_queries", "max_confirmations")


def test_dns_failures_are_could_not_verify_never_unconfirmed():
    http = FakeHttp().add("GET", API.format(d="microsoft.com"), json={
        "tenant_id": MS_TID, "tenant_name": "microsoft", "related_domains": ["microsoft.com", "github.com"], "related_count": 2})
    add_dns_failure(http, "github.com", "MX", kind="servfail", provider="all")
    add_dns_failure(http, "github.com", "TXT", kind="servfail", provider="all")
    res = run(http)
    conf = res.attributes["m365_dns_confirmation"]
    assert conf["could_not_verify"] == 1 and conf["unconfirmed"] == 0 and res.pivots == []


def test_unmanaged_example_com_has_nothing_to_confirm():
    http = FakeHttp().add("GET", API.format(d="example.com"), json=fx("unmanaged_example_com.json"))
    res = run(http, "domain:example.com")
    assert res.attributes["m365_related_domains"]["count"] == 1 and res.pivots == []
    assert res.attributes["m365_dns_confirmation"]["checked"] == 0
    null_mx = FakeHttp().add("GET", API.format(d="example.com"), json={**fx("unmanaged_example_com.json"),
                                                                     "related_domains": ["example.com", "example.org"], "related_count": 2})
    doh_route(null_mx, "example.org", "MX", "doh_mx_null_example_derived.json")
    nodata_everything(null_mx)
    assert run(null_mx, "domain:example.com").attributes["m365_dns_confirmation"]["unconfirmed"] == 1  # null MX '0 .'


def test_not_found_is_empty_without_dns_queries():
    http = FakeHttp().add("GET", API.format(d="example.invalid"), status=404, json=fx("not_found.json"))
    res = run(http, "domain:example.invalid")
    assert res.status is Status.EMPTY and len(http.calls) == 1


def test_failures_are_never_empty():
    rl = FakeHttp().add("GET", API.format(d="microsoft.com"), status=429, text="rate limited")
    assert run_module(M365TenantAzmap, "domain:microsoft.com", rl).status is Status.RATE_LIMITED
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    ch = FakeHttp().add("GET", API.format(d="microsoft.com"), status=403, text=page)
    assert run_module(M365TenantAzmap, "domain:microsoft.com", ch).status is Status.BLOCKED
    changed = FakeHttp().add("GET", API.format(d="microsoft.com"), json={"tenant": {"id": MS_TID}})
    res = run_module(M365TenantAzmap, "domain:microsoft.com", changed)
    assert res.status is Status.ERROR and "schema changed" in res.error
    other404 = FakeHttp().add("GET", API.format(d="microsoft.com"), status=404, text="<html>not found</html>")
    assert run_module(M365TenantAzmap, "domain:microsoft.com", other404).status is Status.ERROR
    broken = FakeHttp().add("GET", API.format(d="microsoft.com"), body=b'{"tenant_id": "72f9', headers={"content-type": "application/json"})
    assert run_module(M365TenantAzmap, "domain:microsoft.com", broken).status is Status.ERROR


def test_dns_evidence_rules():
    assert AZ.dns_evidence(["10 contoso-com.mail.protection.outlook.com"], []) == ["MX contoso-com.mail.protection.outlook.com"]
    assert AZ.dns_evidence(["10 mx.contoso.example"], ["v=spf1 include:spf.protection.outlook.com -all"]) == []  # SPF alone is not proof
    assert AZ.dns_evidence([], ["MS=ms12345678", "ms=0123456789abcdef0123456789abcdef01234567", "MS=short"]) == [
        "TXT MS=ms12345678", "TXT ms=0123456789abcdef0123456789abcdef01234567"]
