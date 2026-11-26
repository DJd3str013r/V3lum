"""dns_records (reference DoH-only module): parsing, pivots and rule-5 semantics (P328 cond 8, P029).

Fixtures in tests/fixtures/dns_records/ are trimmed real DoH answers (research samples recorded
2026-11-25/26: example.com A/AAAA with the resolver AD flag and an RRSIG row, the RFC 7505 null MX,
Cloudflare-quoted TXT, github.com MX/NS/SOA/TXT, google.com CAA, a NOERROR/NODATA answer).
"""

from __future__ import annotations

from tests.fakes import (
    DeadHttp,
    FakeHttp,
    add_dns,
    add_dns_failure,
    add_nxdomain_everything,
    doh_url,
    make_ctx,
    module_fixture,
    run_module,
)
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.domain_dns.dns_records import RECORD_TYPES, DnsRecords


def pivots(res, etype=None):
    return {p.entity.value for p in res.pivots if etype is None or p.entity.type is etype}


def run(http, name):
    return DnsRecords().run(Entity.make("domain", name), make_ctx(DnsRecords, http))


def serve(http, name, answers, *, provider="google"):
    for rtype, answer in answers.items():
        http.add("GET", doh_url(name, rtype, provider=provider), json=answer)


def titles(res):
    return {f.title for f in res.findings}


# ------------------------------------------------------------------ parsing (moved + real fixtures)
def test_dns_records_full():
    http = FakeHttp()
    add_dns(http, "acme.com.br", "A", ["93.184.215.14"], ad=True)
    add_dns(http, "acme.com.br", "AAAA", ["2606:2800:21f:cb07:6820:80da:af6b:8b2c"])
    add_dns(http, "acme.com.br", "CNAME", [])
    add_dns(http, "acme.com.br", "MX", ["10 mx.acme.com.br."])
    add_dns(http, "acme.com.br", "NS", ["a.dns.br.", "b.dns.br."])
    add_dns(http, "acme.com.br", "TXT", ['"v=spf1 include:_spf.google.com ~all"'])
    add_dns(http, "acme.com.br", "SOA", ["a.dns.br. hostmaster.registro.br. 1 2 3 4 5"])
    add_dns(http, "acme.com.br", "CAA", ['0 issue "letsencrypt.org"'])
    res = run(http, "acme.com.br")
    assert res.status is Status.OK and not res.error
    assert res.attributes["a_records"] == ["93.184.215.14"]
    assert res.attributes["spf"].startswith("v=spf1")
    assert res.attributes["dnssec"] is True
    assert res.attributes["caa"] == ['0 issue "letsencrypt.org"']
    assert res.attributes["soa"].startswith("a.dns.br hostmaster.registro.br")
    assert "93.184.215.14" in pivots(res, T.IPV4)
    mx = next(p for p in res.pivots if p.relation == "mx_host")
    assert mx.entity.value == "mx.acme.com.br" and mx.expand is False
    assert not res.findings  # a normal domain: nothing to report
    http.assert_hosts_within(DnsRecords)


def test_real_example_com_answers():
    http = FakeHttp()
    serve(http, "example.com", {k: v for k, v in module_fixture(DnsRecords, "example.com.json").items() if k in RECORD_TYPES})
    for rtype in ("CNAME", "NS", "SOA", "CAA"):
        add_dns(http, "example.com", rtype, [])
    # Google answers 5xx for TXT: the resolver fails over to Cloudflare (P029 cond 1).
    add_dns_failure(http, "example.com", "TXT", kind="http500", provider="google")
    http.add("GET", doh_url("example.com", "TXT", provider="cloudflare"), json=module_fixture(DnsRecords, "example.com_TXT_cloudflare.json"))
    res = run(http, "example.com")
    assert res.status is Status.OK
    assert sorted(res.attributes["a_records"]) == ["104.20.23.154", "172.66.147.243"]  # RRSIG row filtered
    assert res.attributes["dnssec"] is True  # AD flag = validated by resolver
    assert res.attributes["spf"] == "v=spf1 -all"  # Cloudflare quoting removed
    assert titles(res) == {"Null MX: domain explicitly refuses email"}
    null_mx = next(f for f in res.findings if f.title.startswith("Null MX"))
    assert null_mx.criterion and null_mx.source == "core_doh.resolvers"
    http.assert_hosts_within(DnsRecords)


def test_real_github_com_answers():
    http = FakeHttp()
    serve(http, "github.com", module_fixture(DnsRecords, "github.com.json"))
    add_dns(http, "github.com", "A", ["140.82.121.4"])
    add_dns(http, "github.com", "AAAA", [])
    add_dns(http, "github.com", "CNAME", [])
    http.add("GET", doh_url("github.com", "CAA"), json=module_fixture(DnsRecords, "google.com_CAA.json"))
    res = run(http, "github.com")
    assert "ns-520.awsdns-01.net" in res.attributes["nameservers"]
    assert {p.relation for p in res.pivots if p.entity.value == "dns1.p08.nsone.net"} == {"nameserver"}
    assert res.attributes["mx"] == ["github-com.mail.protection.outlook.com"]
    assert res.attributes["spf"].startswith("v=spf1 ip4:192.30.252.0/22")
    assert res.attributes["soa"].startswith("ns-1707.awsdns-21.co.uk awsdns-hostmaster.amazon.com")
    assert res.attributes["caa"] == ['0 issue "pki.goog"']
    assert res.attributes["dnssec"] is False


def test_subdomain_parent_and_confirmed_nxdomain():
    http = FakeHttp()
    add_dns(http, "www.example.org", "CNAME", ["example.org."])
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"):
        add_dns(http, "www.example.org", rtype, [])
    res = run(http, "www.example.org")
    assert "example.org" in pivots(res, T.DOMAIN)
    assert {p.relation for p in res.pivots} >= {"cname_to", "parent_domain"}

    http2 = FakeHttp()
    add_nxdomain_everything(http2)  # both resolvers answer NXDOMAIN (Status 3)
    res2 = run(http2, "nope.example")
    assert res2.attributes.get("valid") is False
    finding = next(f for f in res2.findings if "NXDOMAIN" in f.title)
    assert "second resolver" in finding.criterion
    assert "cloudflare-dns.com" in http2.hosts()  # the confirmation used another resolver


def test_no_web_facing_address_needs_noerror_answers():
    http = FakeHttp()
    for rtype in ("A", "AAAA", "CNAME", "NS", "TXT", "SOA", "CAA"):
        add_dns(http, "mail-only.example", rtype, [])
    add_dns(http, "mail-only.example", "MX", ["10 mx.mail-only.example."])
    res = run(http, "mail-only.example")
    assert "No web-facing address (no A/AAAA/CNAME)" in titles(res)


def test_nodata_sample_is_not_nxdomain():
    http = FakeHttp()
    serve(http, "nonexistent-v3lum-test.example.com", {"A": module_fixture(DnsRecords, "nodata_A.json")})
    for rtype in ("AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"):
        add_dns(http, "nonexistent-v3lum-test.example.com", rtype, [])
    res = run(http, "nonexistent-v3lum-test.example.com")
    assert "valid" not in res.attributes  # NOERROR/NODATA is not NXDOMAIN
    assert not any("NXDOMAIN" in t for t in titles(res))


# ------------------------------------------------------------------ rule 5: could not verify
def test_dead_doh_is_could_not_verify():
    http = DeadHttp()
    res = run(http, "example.com")
    assert res.status is Status.ERROR
    assert "could not verify" in res.error
    assert not res.findings and "valid" not in res.attributes
    assert http.hosts() <= {"dns.google", "cloudflare-dns.com"}


def test_dead_doh_through_the_engine():
    res = run_module(DnsRecords, "domain:example.com", DeadHttp())
    assert res.status is Status.ERROR
    assert not res.findings and "valid" not in res.attributes


def test_unconfirmed_nxdomain_is_not_claimed():
    http = FakeHttp()
    for rtype in RECORD_TYPES:
        add_dns(http, "flaky.example", rtype, [], status=3)  # Google: NXDOMAIN
    add_dns_failure(http, "flaky.example", "A", kind="servfail", provider="cloudflare")  # confirmation fails
    res = run(http, "flaky.example")
    assert res.status is Status.ERROR and "not confirmed" in res.error
    assert "valid" not in res.attributes and not res.findings


def test_partial_failure_never_claims_absence():
    http = FakeHttp()
    add_dns(http, "partial.example", "MX", ["10 mx.partial.example."])
    add_dns(http, "partial.example", "NS", ["ns1.partial.example."])
    for rtype in ("A", "AAAA", "CNAME", "TXT", "SOA", "CAA"):
        add_dns_failure(http, "partial.example", rtype, kind="servfail", provider="all")
    res = run(http, "partial.example")
    assert res.status is Status.OK
    assert "could not verify" in res.error and "A (SERVFAIL)" in res.error
    assert "No web-facing address (no A/AAAA/CNAME)" not in titles(res)
    assert "a_records" not in res.attributes


def test_429_and_challenge_on_both_resolvers_are_could_not_verify():
    for kind in ("http429", "challenge", "http500", "timeout", "refused"):
        http = FakeHttp()
        for rtype in RECORD_TYPES:
            add_dns_failure(http, "blocked.example", rtype, kind=kind, provider="all")
        res = run(http, "blocked.example")
        assert res.status is Status.ERROR, kind
        assert not res.findings and "valid" not in res.attributes, kind


def test_doh_requests_are_not_counted_and_carry_ecs():
    http = FakeHttp()
    add_nxdomain_everything(http)
    ctx = make_ctx(DnsRecords, http)
    DnsRecords().run(Entity.make("domain", "nope.example"), ctx)
    assert ctx.http.requests == 0  # max_requests = 0 is never hit: DoH is not counted
    google = [u for u in http.urls() if u.startswith("https://dns.google/")]
    assert google and all("edns_client_subnet=0.0.0.0" in u for u in google)
