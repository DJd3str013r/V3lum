"""P029 DoH resolver hardening: fixture parsing, status mapping, failover, circuit breaker, ECS,
TLP/disclosure flags, system resolver, wildcard, NXDOMAIN confirmation and DNSBL refusals."""

from __future__ import annotations

import json
import re
import socket
from pathlib import Path
from urllib.parse import parse_qs, parse_qsl, urlsplit

import pytest

from tests.fakes import FakeClock, FakeHttp, add_dns, add_dns_failure, doh, doh_url
from v3lum.core import dns as dns_mod
from v3lum.core import http as http_mod
from v3lum.core.dns import (
    DOH_PROVIDERS,
    PUBLIC_FALLBACK_NOT_ALLOWED,
    PUBLIC_NOT_ALLOWED,
    DnsAnswer,
    Resolver,
    dnsbl_label,
)
from v3lum.core.http import NetworkError, Response, ScopedHttp

FIXTURES = Path(__file__).parent / "fixtures" / "doh"
GOOGLE = "https://dns.google/resolve"
CLOUDFLARE = "https://cloudflare-dns.com/dns-query"
INTERNAL = "https://doh.corp.example/dns-query"


def fx(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def resolver(http, **kw) -> Resolver:
    return Resolver(ScopedHttp(http), **kw)


def internal_url(name: str, rtype: str) -> str:
    return doh_url(name, rtype, provider=INTERNAL)


def google_calls(http) -> list[str]:
    return [u for u in http.urls() if u.startswith(GOOGLE)]


# --------------------------------------------------------------------------------------
# parser tests over the recorded fixtures
# --------------------------------------------------------------------------------------

FIXTURE_CASES = [
    # file, provider, name, rtype, expected records, AD flag
    ("caipora_infra__doh_google_mx.json", "google", "example.com", "MX", ["0 ."], True),
    ("caipora_infra__doh_cloudflare_txt.json", "cloudflare", "example.com", "TXT", ["v=spf1 -all", "_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9"], True),
    ("live_cti__doh_google_a_dnssec.json", "google", "example.com", "A", ["104.20.23.154", "172.66.147.243"], True),
    ("live_cti__doh_cloudflare_a_ad.json", "cloudflare", "example.com", "A", ["172.66.147.243", "104.20.23.154"], True),
    ("live_cti__doh_cloudflare_mx.json", "cloudflare", "github.com", "MX", ["0 github-com.mail.protection.outlook.com"], False),
    ("live_cti__doh_google_aaaa.json", "google", "example.com", "AAAA", ["2606:4700:10::6814:179a", "2606:4700:10::ac42:93f3"], True),
    ("live_cti__doh_google_caa.json", "google", "google.com", "CAA", ['0 issue "pki.goog"'], False),
    (
        "live_cti__doh_google_dmarc.json", "google", "_dmarc.github.com", "TXT",
        ["v=DMARC1; p=quarantine; sp=reject; pct=100; rua=mailto:dmarc@github.com; ruf=mailto:dmarc@github.com; fo=1"], False,
    ),
    ("live_cti__doh_google_ds.json", "google", "example.com", "DS", ["2371 13 2 C988EC423E3880EB8DD8A46FE06CA230EE23F35B578D64E78B29C3E1C83D245A"], True),
    (
        "live_cti__doh_google_https_rr.json", "google", "cloudflare.com", "HTTPS",
        ["1 . alpn=h3,h2 ipv4hint=104.16.132.229,104.16.133.229 ipv6hint=2606:4700::6810:84e5,2606:4700::6810:85e5"], True,
    ),
    ("live_cti__doh_google_mtasts.json", "google", "_mta-sts.google.com", "TXT", ["v=STSv1; id=20210803T010101;"], False),
    ("live_cti__doh_google_mx.json", "google", "github.com", "MX", ["0 github-com.mail.protection.outlook.com"], False),
    (
        "live_cti__doh_google_ns.json", "google", "github.com", "NS",
        [
            "dns2.p08.nsone.net", "ns-520.awsdns-01.net", "ns-421.awsdns-52.com", "dns4.p08.nsone.net",
            "ns-1283.awsdns-32.org", "ns-1707.awsdns-21.co.uk", "dns1.p08.nsone.net", "dns3.p08.nsone.net",
        ],
        False,
    ),
    ("live_cti__doh_google_soa.json", "google", "github.com", "SOA", ["ns-1707.awsdns-21.co.uk awsdns-hostmaster.amazon.com 1 7200 900 1209600 86400"], False),
    ("live_cti__doh_google_ptr.json", "google", "8.8.8.8.in-addr.arpa", "PTR", ["dns.google"], False),
]


@pytest.mark.parametrize("case", FIXTURE_CASES, ids=[c[0] for c in FIXTURE_CASES])
def test_fixture_parsing(case):
    fname, provider, name, rtype, records, ad = case
    http = FakeHttp()
    http.add("GET", doh_url(name, rtype, provider=provider), json=fx(fname))
    ans = resolver(http, providers=[provider]).query(name, rtype)
    assert ans.status == "NOERROR" and ans.ok and not ans.could_not_verify
    assert ans.records == records
    assert ans.authenticated is ad
    assert ans.resolver == provider
    assert ans.ttl > 0


def test_fixture_rrsig_is_filtered_and_ttl_is_rrset_minimum():
    http = FakeHttp()
    http.add("GET", doh_url("example.com", "A"), json=fx("live_cti__doh_google_a_dnssec.json"))
    ans = resolver(http).query("example.com", "A")
    assert len(ans.records) == 2 and all(not r.startswith("a 13") for r in ans.records)
    assert ans.ttl == 160


def test_fixture_txt_tokens_kept_verbatim():
    http = FakeHttp()
    http.add("GET", doh_url("github.com", "TXT"), json=fx("live_cti__doh_google_txt.json"))
    ans = resolver(http).query("github.com", "TXT")
    assert ans.records[0] == "google-site-verification=82Le34Flgtd15ojYhHlGF_6g72muSjamlMVThBOJpks"
    assert ans.records[1] == "MS=ms58704441"
    assert ans.records[2].startswith("v=spf1 ip4:192.30.252.0/22") and ans.records[2].endswith("~all")


def test_fixture_ptr_via_helper():
    http = FakeHttp()
    http.add("GET", doh_url("8.8.8.8.in-addr.arpa", "PTR"), json=fx("live_cti__doh_google_ptr.json"))
    assert resolver(http).ptr("8.8.8.8").records == ["dns.google"]


def test_fixture_nonexistent_name_in_cloudflare_zone_is_nodata_not_nxdomain():
    """The recorded 'nxdomain' probe is NOERROR/NODATA (Cloudflare zone): never read as NXDOMAIN."""
    http = FakeHttp()
    name = "nonexistent-v3lum-test.example.com"
    http.add("GET", doh_url(name, "A"), json=fx("live_cti__doh_google_nxdomain.json"))
    ans = resolver(http).query(name, "A")
    assert ans.nodata and ans.ok
    assert not ans.nxdomain and not ans.could_not_verify
    assert ans.ttl == 1800  # negative TTL from the authority SOA


def test_fixture_real_nxdomain_status_3():
    http = FakeHttp()
    name = "2.0.0.127.zen.spamhaus.org"
    http.add("GET", doh_url(name, "A"), json=fx("caipora_infra__dnsbl_spamhaus_via_public_resolver.json"))
    ans = resolver(http).query(name, "A")
    assert ans.nxdomain and ans.status == "NXDOMAIN"
    assert not ans.could_not_verify and ans.records == []
    assert ans.ttl == 10


def test_fixture_servfail_with_ede_comment_list():
    http = FakeHttp()
    name = "test.surbl.org.multi.surbl.org"
    http.add("GET", doh_url(name, "A", provider="cloudflare"), json=fx("live_cti__dnsbl_surbl_test_cf.json"))
    ans = resolver(http, providers=["cloudflare"]).query(name, "A")
    assert ans.status == "SERVFAIL" and ans.could_not_verify and not ans.nxdomain
    assert "EDE(22)" in ans.error


@pytest.mark.parametrize("provider", ["google", "cloudflare"])
def test_design_posture_record_replayed(provider):
    """The trimmed design record (CAA set, MX, DMARC/MTA-STS, AD) survives both resolver styles."""
    posture = fx("design_email_posture_doh.json")["posture"]
    http = FakeHttp()
    for dom, p in posture.items():
        quote = (lambda s: '"' + s.replace('"', '\\"') + '"') if provider == "cloudflare" else (lambda s: s)
        txt = [quote(p["dmarc_record"])]
        http.add("GET", doh_url(f"_dmarc.{dom}", "TXT", provider=provider), json=doh(f"_dmarc.{dom}", "TXT", txt))
        http.add("GET", doh_url(dom, "CAA", provider=provider), json=doh(dom, "CAA", p["caa"]))
        http.add("GET", doh_url(dom, "MX", provider=provider), json=doh(dom, "MX", p["mx"], ad=p["dnssec"]["ad_flag_on_A"]))
    r = resolver(http, providers=[provider])
    for dom, p in posture.items():
        assert r.query(f"_dmarc.{dom}", "TXT").records == [p["dmarc_record"]]
        assert r.query(dom, "CAA").records == p["caa"]
        mx = r.query(dom, "MX")
        assert mx.records == [m.rstrip(".").lower() if m != "0 ." else m for m in p["mx"]]
        assert mx.authenticated is p["dnssec"]["ad_flag_on_A"]


# --------------------------------------------------------------------------------------
# normalisation helpers
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ('"v=DKIM1; k=rsa; " "p=MIIBIjAN" "BgkqhkiG"', "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG"),  # multi-string
        ('"say \\"hi\\""', 'say "hi"'),  # escaped quote
        ('"caf\\195\\169"', "café"),  # RFC 1035 decimal escapes (UTF-8 bytes)
        ("v=spf1 -all", "v=spf1 -all"),  # Google style: unquoted, already joined
        ('""', ""),
    ],
)
def test_txt_normalisation(raw, expected):
    http = FakeHttp()
    add_dns(http, "t.example", "TXT", [raw])
    assert resolver(http).query("t.example", "TXT").records == [expected]


def test_generic_rfc3597_caa_is_decoded(monkeypatch):
    # Cloudflare may return CAA as '\# <len> <hex>': 0 issue "pki.goog"
    data = "\\# 15 00 05 69 73 73 75 65 70 6b 69 2e 67 6f 6f 67"
    http = FakeHttp()
    add_dns(http, "google.com", "CAA", [data], provider="cloudflare")
    r = resolver(http, providers=["cloudflare"])
    assert r.query("google.com", "CAA").records == ['0 issue "pki.goog"']
    monkeypatch.setattr(dns_mod, "_load_dnspython", lambda: None)  # built-in CAA decoder
    assert resolver(http, providers=["cloudflare"]).query("google.com", "CAA").records == ['0 issue "pki.goog"']


def test_idn_names_are_sent_as_punycode():
    http = FakeHttp()
    add_dns(http, "xn--caf-dma.example", "A", ["192.0.2.1"])
    assert resolver(http).query("café.example.", "A").records == ["192.0.2.1"]


def test_invalid_names_are_never_sent():
    http = FakeHttp()
    ans = resolver(http).query("a" * 64 + ".example", "A")
    assert ans.status == "FORMERR" and ans.could_not_verify
    assert http.urls() == []


# --------------------------------------------------------------------------------------
# status mapping (rule 5): NXDOMAIN only from Status 3
# --------------------------------------------------------------------------------------


def test_status_3_is_nxdomain():
    http = FakeHttp()
    add_dns(http, "gone.example", "A", [], status=3)
    ans = resolver(http).query("gone.example", "A")
    assert ans.nxdomain and not ans.could_not_verify and ans.resolver == "google"


@pytest.mark.parametrize(
    ("kind", "status"),
    [("servfail", "SERVFAIL"), ("refused", "REFUSED")],
)
def test_servfail_and_refused_answers_are_could_not_verify_without_failover(kind, status):
    http = FakeHttp()
    add_dns_failure(http, "x.example", "A", kind=kind)
    ans = resolver(http).query("x.example", "A")
    assert ans.status == status
    assert ans.could_not_verify and not ans.nxdomain and not ans.ok
    assert ans.error  # carries the error text
    assert http.urls() == [doh_url("x.example", "A")]  # a DNS answer: no failover


def test_timeouts_map_to_timeout_status():
    http = FakeHttp()
    add_dns_failure(http, "x.example", "A", kind="timeout", provider="all")
    ans = resolver(http).query("x.example", "A")
    assert ans.status == "TIMEOUT"
    assert ans.could_not_verify and not ans.nxdomain
    assert "timed out" in ans.error and ans.resolver == "google,cloudflare"


@pytest.mark.parametrize("kind", ["servfail", "refused", "http500", "http429", "challenge", "timeout"])
def test_no_nxdomain_is_ever_produced_from_failures(kind):
    http = FakeHttp()
    add_dns_failure(http, "x.example", "A", kind=kind, provider="all")
    ans = resolver(http).query("x.example", "A")
    assert not ans.nxdomain
    assert ans.could_not_verify
    assert ans.records == []


def test_transport_failures_on_all_resolvers_are_servfail_with_text():
    http = FakeHttp()
    add_dns_failure(http, "x.example", "A", kind="http500", provider="all")
    ans = resolver(http).query("x.example", "A")
    assert ans.status == "SERVFAIL" and ans.could_not_verify
    assert "google: HTTP 500" in ans.error and "cloudflare: HTTP 500" in ans.error


# --------------------------------------------------------------------------------------
# failover rules
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["http500", "http429", "timeout"])
def test_failover_on_transport_5xx_and_429(kind):
    http = FakeHttp()
    add_dns_failure(http, "x.example", "A", kind=kind)
    add_dns(http, "x.example", "A", ["192.0.2.7"], provider="cloudflare")
    ans = resolver(http).query("x.example", "A")
    assert ans.records == ["192.0.2.7"] and ans.resolver == "cloudflare"


@pytest.mark.parametrize("status", [502, 504, 408])
def test_failover_on_other_5xx_and_request_timeout(status):
    http = FakeHttp()
    http.add("GET", doh_url("x.example", "A"), status=status, text="upstream trouble")
    add_dns(http, "x.example", "A", ["192.0.2.8"], provider="cloudflare")
    ans = resolver(http).query("x.example", "A")
    assert ans.records == ["192.0.2.8"] and ans.resolver == "cloudflare"


@pytest.mark.parametrize(
    "route",
    [
        {"status": 403, "text": "<html><body>Forbidden by policy</body></html>"},
        {"status": 401, "text": "auth required"},
        {"status": 407, "text": "proxy authentication required"},
        {"status": 451, "text": "unavailable for legal reasons"},
        {"status": 200, "text": "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"},
    ],
    ids=["403", "401", "407", "451", "challenge-in-200"],
)
def test_no_failover_on_refusals(route):
    """P029 cond 1: failover only on transport errors, 5xx and 429 - a refusal is could-not-verify."""
    http = FakeHttp()
    http.add("GET", doh_url("x.example", "A"), **route)
    add_dns(http, "x.example", "A", ["192.0.2.9"], provider="cloudflare")  # never asked
    r = resolver(http)
    ans = r.query("x.example", "A")
    assert ans.status == "SERVFAIL" and ans.could_not_verify and not ans.nxdomain and ans.records == []
    assert ans.resolver == "google" and "could not verify" in ans.error
    assert http.urls() == [doh_url("x.example", "A")]
    assert r.circuit_open() == frozenset()  # a refusal is not a resolver failure


def test_challenge_page_with_failover_status_still_fails_over():
    """A 503 challenge page is a 5xx: the literal failover rule applies."""
    http = FakeHttp()
    http.add("GET", doh_url("x.example", "A"), status=503, text="<html><title>Just a moment...</title>cf-chl-widget</html>")
    add_dns(http, "x.example", "A", ["192.0.2.10"], provider="cloudflare")
    assert resolver(http).query("x.example", "A").resolver == "cloudflare"


@pytest.mark.skipif(not hasattr(http_mod, "Blocked"), reason="Blocked arrives with the HTTP contract v2")
def test_short_circuited_host_is_skipped_without_counting():
    """A9: a host the HTTP layer short-circuited for the run is skipped like an open circuit."""

    class ShortCircuit(FakeHttp):
        def request(self, method, url, **kw):
            if url.startswith(GOOGLE):
                raise http_mod.Blocked("dns.google: short-circuited for this run after an anti-bot challenge", 0, url, reason_code="circuit")
            return super().request(method, url, **kw)

    http = ShortCircuit()
    for i in range(4):
        add_dns(http, f"s{i}.example", "A", ["192.0.2.11"], provider="cloudflare")
    r = resolver(http)
    for i in range(4):
        ans = r.query(f"s{i}.example", "A")
        assert ans.resolver == "cloudflare" and ans.records == ["192.0.2.11"]
    assert r.circuit_open() == frozenset()


@pytest.mark.skipif(not hasattr(http_mod, "Blocked"), reason="Blocked arrives with the HTTP contract v2")
def test_blocked_and_auth_exceptions_are_refusals():
    class Refusing(FakeHttp):
        def request(self, method, url, **kw):
            name = (kw.get("params") or {}).get("name", "")
            if name == "blocked.example":
                raise http_mod.Blocked("anti-bot challenge", 403, url, reason_code="challenge")
            if name == "auth.example":
                raise http_mod.AuthRequired("HTTP 401", 401, url)
            return super().request(method, url, **kw)

    http = Refusing()
    for name in ("blocked.example", "auth.example"):
        ans = resolver(http).query(name, "A")
        assert ans.status == "SERVFAIL" and ans.could_not_verify and not ans.nxdomain
    assert all(u.startswith(GOOGLE) for u in http.urls())


@pytest.mark.skipif(not hasattr(http_mod, "OfflineError"), reason="OfflineError arrives with the HTTP contract v2")
def test_offline_mode_never_trips_the_circuit():
    """Offline (cache only): uncached names fail on every resolver, cached ones keep working."""

    class Offline(FakeHttp):
        def request(self, method, url, **kw):
            if (kw.get("params") or {}).get("name") != "cached.example":
                raise http_mod.OfflineError(f"offline mode: {url} not cached")
            return super().request(method, url, **kw)

    http = Offline()
    add_dns(http, "cached.example", "A", ["192.0.2.12"])
    r = resolver(http)
    for i in range(4):
        miss = r.query(f"miss{i}.example", "A")
        assert miss.could_not_verify and not miss.nxdomain and "offline" in miss.error
    assert r.circuit_open() == frozenset()
    assert r.query("cached.example", "A").records == ["192.0.2.12"]


def test_failover_on_503_and_bad_body():
    http = FakeHttp()
    http.add("GET", doh_url("a.example", "A"), status=503, text="unavailable")
    add_dns(http, "a.example", "A", ["192.0.2.1"], provider="cloudflare")
    http.add("GET", doh_url("b.example", "A"), text="<html><body>captive portal</body></html>")
    add_dns(http, "b.example", "A", ["192.0.2.2"], provider="cloudflare")
    r = resolver(http)
    assert r.query("a.example", "A").resolver == "cloudflare"
    assert r.query("b.example", "A").records == ["192.0.2.2"]


@pytest.mark.parametrize("status", [0, 2, 3, 5])
def test_never_failover_on_a_dns_answer(status):
    http = FakeHttp()
    add_dns(http, "x.example", "A", [] if status else ["192.0.2.1"], status=status)
    resolver(http).query("x.example", "A")
    assert len(http.urls()) == 1 and http.urls()[0].startswith(GOOGLE)


def test_no_failover_on_bad_request():
    http = FakeHttp()
    http.add("GET", doh_url("x.example", "A"), status=400, json={"error": "bad name"})
    ans = resolver(http).query("x.example", "A")
    assert ans.status == "SERVFAIL" and "HTTP 400" in ans.error
    assert len(http.urls()) == 1


def test_client_retries_disabled_and_servfail_never_cached():
    http = FakeHttp()
    add_dns(http, "x.example", "A", ["192.0.2.1"])
    resolver(http).query("x.example", "A")
    call = http.calls[0]
    assert call["retries"] == 0
    cache_if = call["cache_if"]
    ok = Response(200, GOOGLE, {}, json.dumps({"Status": 0}).encode())
    nx = Response(200, GOOGLE, {}, json.dumps({"Status": 3}).encode())
    servfail = Response(200, GOOGLE, {}, json.dumps({"Status": 2}).encode())
    assert cache_if(ok) and cache_if(nx) and not cache_if(servfail)


class LegacyHttp:
    """A pre-v2 client: no retries=/cache_if= keywords, but evict() exists."""

    def __init__(self, fake: FakeHttp) -> None:
        self.fake = fake
        self.evicted: list[str] = []

    def get(self, url, *, params=None, headers=None, ttl=None, timeout=None):
        return self.fake.request("GET", url, params=params, headers=headers, ttl=ttl, timeout=timeout)

    def evict(self, resp) -> None:
        self.evicted.append(resp.url)


def test_legacy_client_without_v2_keywords():
    fake = FakeHttp()
    add_dns(fake, "ok.example", "A", ["192.0.2.1"])
    add_dns_failure(fake, "bad.example", "A", kind="servfail")
    legacy = LegacyHttp(fake)
    r = Resolver(legacy)
    assert r.query("ok.example", "A").records == ["192.0.2.1"]
    assert r.query("bad.example", "A").could_not_verify
    assert legacy.evicted == [doh_url("bad.example", "A")]  # SERVFAIL dropped from the cache


@pytest.mark.skipif(not hasattr(http_mod, "PolicyError"), reason="PolicyError arrives with the HTTP contract v2")
def test_policy_refusal_skips_resolver_without_counting():
    class Refusing(FakeHttp):
        def request(self, method, url, **kw):
            if url.startswith(GOOGLE):
                raise http_mod.PolicyError("host not allowed")
            return super().request(method, url, **kw)

    http = Refusing()
    for i in range(4):
        add_dns(http, f"h{i}.example", "A", ["192.0.2.9"], provider="cloudflare")
    r = resolver(http)
    for i in range(4):
        assert r.query(f"h{i}.example", "A").resolver == "cloudflare"
    assert "google" not in r.circuit_open()


@pytest.mark.skipif(not hasattr(http_mod, "Cancelled"), reason="Cancelled arrives with the HTTP contract v2")
def test_cancel_propagates():
    http = FakeHttp()
    http.add("GET", re.compile(r"^https://dns\.google/"), error=http_mod.Cancelled("kill switch"))
    with pytest.raises(http_mod.Cancelled):
        resolver(http).query("x.example", "A")


# --------------------------------------------------------------------------------------
# ECS on every Google request
# --------------------------------------------------------------------------------------


def test_every_google_request_carries_ecs_and_cloudflare_never():
    http = FakeHttp()
    add_dns(http, "a.example", "A", ["192.0.2.1"])
    add_dns(http, "a.example", "TXT", ["v=spf1 -all"])
    add_dns(http, "gone.example", "A", [], status=3, provider="all")
    add_dns(http, "gone.example", "AAAA", [], status=3)
    add_dns_failure(http, "flaky.example", "A", kind="http500")
    add_dns(http, "flaky.example", "A", ["192.0.2.3"], provider="cloudflare")
    http.add("GET", re.compile(r"^https://dns\.google/resolve\?name=[a-z0-9]{16}\.a\.example&"), json={"Status": 3})
    http.add("GET", re.compile(r"^https://cloudflare-dns\.com/dns-query\?name=evil\.example&"), json={"Status": 0, "Answer": []})
    add_dns(http, "4.3.2.1.in-addr.arpa", "PTR", ["host.example."])
    r = resolver(http)
    r.query("a.example", "A")
    r.query("a.example", "TXT")
    r.addresses("gone.example")
    r.query("flaky.example", "A")
    r.wildcard("a.example")
    r.confirm_nxdomain("gone.example")
    r.query("evil.example", "A", hostile=True)
    r.ptr("1.2.3.4")
    google = google_calls(http)
    assert len(google) >= 7
    for url in google:
        query = parse_qsl(urlsplit(url).query)
        assert [k for k, _ in query] == ["name", "type", "edns_client_subnet"]
        assert dict(query)["edns_client_subnet"] == "0.0.0.0/0"
    for url in http.urls():
        if url.startswith(CLOUDFLARE):
            assert "edns_client_subnet" not in parse_qs(urlsplit(url).query)
            call = next(c for c in http.calls if c["url"] == url)
            assert call["headers"]["Accept"] == "application/dns-json"


def test_ecs_through_the_runtime_doh_scope():
    from tests.fakes import make_runtime

    http = FakeHttp()
    add_dns(http, "a.example", "A", ["192.0.2.1"])
    rt = make_runtime(http)
    r = Resolver(rt.doh_scope(), clock=rt.clock)
    assert r.query("a.example", "A").records == ["192.0.2.1"]
    assert parse_qs(urlsplit(http.urls()[0]).query)["edns_client_subnet"] == ["0.0.0.0/0"]


# --------------------------------------------------------------------------------------
# circuit breaker and failover budget
# --------------------------------------------------------------------------------------


def test_circuit_breaker_after_three_consecutive_failures():
    http = FakeHttp()
    http.add("GET", re.compile(r"^https://dns\.google/"), status=503, text="down")
    http.add("GET", re.compile(r"^https://cloudflare-dns\.com/"), json={"Status": 0, "Answer": [{"type": 1, "data": "192.0.2.1"}]})
    r = resolver(http)
    for i in range(5):
        assert r.query(f"n{i}.example", "A").resolver == "cloudflare"
    assert len(google_calls(http)) == 3  # skipped after the third consecutive failure
    assert "google" in r.circuit_open()


def test_circuit_counter_resets_on_success():
    http = FakeHttp()
    for name in ("a", "b", "d", "e"):
        add_dns_failure(http, f"{name}.example", "A", kind="http500")
        add_dns(http, f"{name}.example", "A", ["192.0.2.1"], provider="cloudflare")
    add_dns(http, "c.example", "A", ["192.0.2.2"])
    add_dns(http, "f.example", "A", ["192.0.2.3"])
    r = resolver(http)
    for name in "abcdef":
        r.query(f"{name}.example", "A")
    assert r.circuit_open() == frozenset()
    assert r.query("f.example", "A").resolver == "google"


class SlowHttp:
    """Every DoH request times out after the timeout it was given (advances the fake clock)."""

    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock
        self.timeouts: list[tuple[str, float]] = []

    def get(self, url, *, params=None, timeout=None, **kw):
        self.timeouts.append((urlsplit(url).hostname, timeout))
        self.clock.advance(timeout)
        raise NetworkError(f"ReadTimeout contacting {urlsplit(url).hostname}: timed out")


def test_failover_budget_is_five_seconds_with_fake_clock():
    clock = FakeClock()
    http = SlowHttp(clock)
    r = Resolver(http, providers=["google", "cloudflare"], internal_url=INTERNAL, clock=clock)
    start = clock.monotonic()
    ans = r.query("slow.example", "A")
    assert clock.monotonic() - start <= 5.0
    assert http.timeouts == [("doh.corp.example", 3.0), ("dns.google", 2.0)]  # min(remaining, 3 s)
    assert ans.status == "TIMEOUT" and ans.could_not_verify and not ans.nxdomain
    assert "budget" in ans.error


def test_route_latency_counts_against_the_budget():
    clock = FakeClock()
    http = FakeHttp(clock=clock)
    timeout = NetworkError("ReadTimeout contacting x: timed out")
    http.add("GET", re.compile(r"^https://doh\.corp\.example/"), error=timeout, latency=4.0)
    http.add("GET", re.compile(r"^https://dns\.google/"), error=timeout, latency=4.0)
    http.add("GET", re.compile(r"^https://cloudflare-dns\.com/"), json={"Status": 0, "Answer": []})
    r = Resolver(ScopedHttp(http), internal_url=INTERNAL, clock=clock)
    ans = r.query("x.example", "A")
    assert [urlsplit(u).hostname for u in http.urls()] == ["doh.corp.example", "dns.google"]
    assert ans.could_not_verify


# --------------------------------------------------------------------------------------
# TLP / disclosure flags (P029 cond 7, A2)
# --------------------------------------------------------------------------------------


def test_allow_public_false_without_internal_sends_nothing():
    http = FakeHttp()
    ans = resolver(http, allow_public=False).query("x.example", "A")
    assert ans.status == "SERVFAIL" and ans.could_not_verify
    assert PUBLIC_NOT_ALLOWED in ans.error
    assert http.urls() == []


def test_allow_public_false_uses_only_internal():
    http = FakeHttp()
    http.add("GET", internal_url("ok.example", "A"), json=doh("ok.example", "A", ["10.1.2.3"]))
    http.add("GET", internal_url("down.example", "A"), status=500, text="err")
    r = resolver(http, allow_public=False, internal_url=INTERNAL)
    ok = r.query("ok.example", "A")
    assert ok.records == ["10.1.2.3"] and ok.resolver == "internal"
    down = r.query("down.example", "A")
    assert down.could_not_verify and PUBLIC_NOT_ALLOWED in down.error and "internal: HTTP 500" in down.error
    assert all(u.startswith(INTERNAL) for u in http.urls())


def test_allow_public_fallback_false_never_moves_to_public():
    http = FakeHttp()
    add_dns_failure(http, "x.example", "A", kind="http500", provider=INTERNAL)
    add_dns(http, "x.example", "A", ["192.0.2.1"], provider="all")
    r = resolver(http, allow_public_fallback=False, internal_url=INTERNAL)
    ans = r.query("x.example", "A")
    assert ans.could_not_verify and PUBLIC_FALLBACK_NOT_ALLOWED in ans.error
    assert http.urls() == [internal_url("x.example", "A")]


def test_allow_public_fallback_false_without_internal_uses_public():
    http = FakeHttp()
    add_dns(http, "x.example", "A", ["192.0.2.1"])
    ans = resolver(http, allow_public_fallback=False).query("x.example", "A")
    assert ans.records == ["192.0.2.1"] and ans.resolver == "google"


def test_internal_listed_first_and_public_fallback_when_allowed():
    http = FakeHttp()
    http.add("GET", internal_url("x.example", "A"), error=NetworkError("ConnectionError contacting doh.corp.example"))
    add_dns(http, "x.example", "A", ["192.0.2.1"])
    r = resolver(http, internal_url=INTERNAL)
    assert r.providers == ["internal", "google", "cloudflare"]
    ans = r.query("x.example", "A")
    assert ans.resolver == "google"
    assert [urlsplit(u).hostname for u in http.urls()] == ["doh.corp.example", "dns.google"]


def test_hostile_names_go_to_cloudflare_first():
    http = FakeHttp()
    add_dns(http, "evil.example", "A", ["198.51.100.1"], provider="cloudflare")
    ans = resolver(http).query("evil.example", "A", hostile=True)
    assert ans.resolver == "cloudflare"
    assert http.urls()[0].startswith(CLOUDFLARE)


def test_hostile_keeps_internal_first():
    http = FakeHttp()
    http.add("GET", internal_url("evil.example", "A"), json=doh("evil.example", "A", ["198.51.100.1"]))
    ans = resolver(http, internal_url=INTERNAL).query("evil.example", "A", hostile=True)
    assert ans.resolver == "internal"


# --------------------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------------------


def test_provider_catalogue():
    assert DOH_PROVIDERS["google"] == {"url": GOOGLE, "kind": "json", "ecs": "zero", "provider_id": "google_public_dns"}
    assert DOH_PROVIDERS["cloudflare"]["ecs"] == "none" and DOH_PROVIDERS["cloudflare"]["provider_id"] == "cloudflare_dns"
    assert DOH_PROVIDERS["quad9"]["kind"] == "wire" and DOH_PROVIDERS["quad9"]["url"] == "https://dns.quad9.net/dns-query"
    assert DOH_PROVIDERS["internal"]["provider_id"] == "internal_doh"
    assert "opendns" not in DOH_PROVIDERS and "cleanbrowsing" not in DOH_PROVIDERS


def test_settings_supply_the_chain():
    r = Resolver(FakeHttp(), settings={"doh_providers": ["cloudflare", "google"], "doh_internal": INTERNAL})
    assert r.providers == ["internal", "cloudflare", "google"]
    assert r.internal_url == INTERNAL
    assert Resolver(FakeHttp(), settings={"doh_providers": "google", "doh_internal": ""}).providers == ["google"]


def test_https_entry_in_doh_providers_is_the_internal_resolver():
    r = Resolver(FakeHttp(), providers=["google", INTERNAL, "cloudflare"])
    assert r.providers == ["internal", "google", "cloudflare"]
    assert r.internal_url == INTERNAL


@pytest.mark.parametrize(
    "url",
    [
        "http://doh.corp.example/dns-query", "https://dns.google/resolve", "https://user:pw@doh.corp.example/q", "doh.corp.example",
        # public resolvers must never pass as the internal one (the only resolver allowed at TLP:RED)
        "https://dns.google./resolve", "https://mozilla.cloudflare-dns.com/dns-query", "https://DNS11.Quad9.net/dns-query",
        "https://[2001:4860:4860::8888]/resolve", "https://1.1.1.1/dns-query", "https://[::ffff:8.8.8.8]/resolve", "https://[::1",
    ],
)
def test_invalid_internal_urls_are_rejected(url):
    r = Resolver(FakeHttp(), internal_url=url)
    assert "internal" not in r.providers and r.internal_url == ""
    assert r.config_errors
    in_list = Resolver(FakeHttp(), providers=["google", url])
    assert "internal" not in in_list.providers and in_list.config_errors


def test_rejected_resolver_urls_never_echo_credentials():
    r = Resolver(FakeHttp(), internal_url="http://svc:S3cretPw@doh.corp.example/dns-query?token=T0ken")
    text = " ".join(r.config_errors)
    assert r.config_errors and "S3cretPw" not in text and "T0ken" not in text


def test_public_doh_host_detection():
    for host in ("dns.google", "dns.google.", "security.cloudflare-dns.com", "doh.opendns.com", "8.8.4.4", "2606:4700:4700::1111", "[2620:fe::fe]"):
        assert dns_mod.is_public_doh_host(host), host
    for host in ("doh.corp.example", "notcloudflare-dns.com", "dns.google.corp.example", "10.0.0.53", "", "2001:db8::53"):
        assert not dns_mod.is_public_doh_host(host), host


def test_resolver_comment_text_is_sanitised():
    """EDE/Comment text is untrusted: one bounded line without control characters (terminal safety)."""
    http = FakeHttp()
    http.add("GET", doh_url("x.example", "A"), json={"Status": 2, "Comment": ["EDE(22): \x1b[31mred\x1b[0m\nline2 " + "y" * 600]})
    ans = resolver(http).query("x.example", "A")
    assert ans.could_not_verify and "\x1b" not in ans.error and "\n" not in ans.error
    assert len(ans.error) < 400 and "EDE(22)" in ans.error


def test_unknown_resolvers_are_rejected():
    r = Resolver(FakeHttp(), providers=["opendns", "google"])
    assert r.providers == ["google"]
    assert any("opendns" in e for e in r.config_errors)
    empty = Resolver(FakeHttp(), providers=[])
    assert empty.providers == [] and empty.config_errors


def test_legacy_preferred_provider_without_list():
    assert Resolver(FakeHttp(), provider="cloudflare").providers == ["cloudflare", "google"]
    assert Resolver(FakeHttp(), provider="cloudflare", providers=["google", "cloudflare"]).providers == ["google", "cloudflare"]


# --------------------------------------------------------------------------------------
# RFC 8484 wire format (quad9) only through dnspython
# --------------------------------------------------------------------------------------


def test_wire_provider_needs_dnspython(monkeypatch):
    monkeypatch.setattr(dns_mod, "_load_dnspython", lambda: None)
    http = FakeHttp()
    ans = resolver(http, providers=["quad9"]).query("example.com", "A")
    assert ans.could_not_verify and "needs dnspython" in ans.error
    assert http.urls() == []


def test_wire_provider_through_dnspython():
    pytest.importorskip("dns.message")
    import dns.flags
    import dns.message
    import dns.rrset

    query = dns.message.make_query("example.com", "A")
    query.id = 0
    response = dns.message.make_response(query)
    response.flags |= dns.flags.AD
    response.answer.append(dns.rrset.from_text("example.com.", 120, "IN", "A", "192.0.2.10", "192.0.2.11"))
    http = FakeHttp()
    http.add("GET", re.compile(r"^https://dns\.quad9\.net/dns-query\?dns="), body=response.to_wire(), headers={"content-type": "application/dns-message"})
    ans = resolver(http, providers=["quad9"]).query("example.com", "A")
    assert sorted(ans.records) == ["192.0.2.10", "192.0.2.11"]
    assert ans.authenticated and ans.ttl == 120 and ans.resolver == "quad9"
    call = http.calls[0]
    assert call["headers"]["Accept"] == "application/dns-message"
    assert "edns_client_subnet" not in call["url"]


def test_wire_nxdomain_and_failover():
    pytest.importorskip("dns.message")
    import dns.message
    import dns.rcode

    query = dns.message.make_query("gone.example", "A")
    response = dns.message.make_response(query)
    response.set_rcode(dns.rcode.NXDOMAIN)
    http = FakeHttp()
    http.add("GET", re.compile(r"^https://dns\.quad9\.net/"), body=response.to_wire())
    assert resolver(http, providers=["quad9"]).query("gone.example", "A").nxdomain
    http2 = FakeHttp()
    http2.add("GET", re.compile(r"^https://dns\.quad9\.net/"), status=502, text="bad gateway")
    add_dns(http2, "gone.example", "A", [], status=3, provider="cloudflare")
    ans = resolver(http2, providers=["quad9", "cloudflare"]).query("gone.example", "A")
    assert ans.nxdomain and ans.resolver == "cloudflare"


# --------------------------------------------------------------------------------------
# system resolver (explicit only; EAI_NONAME is the only NXDOMAIN)
# --------------------------------------------------------------------------------------


def _no_dnspython(monkeypatch):
    monkeypatch.setattr(dns_mod, "_load_dnspython", lambda: None)


def test_system_getaddrinfo_eai_noname_is_nxdomain(monkeypatch):
    _no_dnspython(monkeypatch)

    def fake(host, *a, **kw):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    ans = Resolver(FakeHttp(), mode="system").query("gone.example", "A")
    assert ans.nxdomain and ans.resolver == "system"


@pytest.mark.parametrize(
    "exc",
    [
        socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution"),
        TimeoutError("timed out"),
        OSError(101, "Network is unreachable"),
    ],
    ids=["EAI_AGAIN", "timeout", "oserror"],
)
def test_system_getaddrinfo_other_errors_are_servfail(monkeypatch, exc):
    _no_dnspython(monkeypatch)

    def fake(host, *a, **kw):
        raise exc

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    http = FakeHttp()
    ans = Resolver(http, mode="system").query("x.example", "A")
    assert ans.status == "SERVFAIL" and ans.could_not_verify and not ans.nxdomain
    assert ans.error.startswith("getaddrinfo:")
    assert http.urls() == []  # never a silent fallback to DoH


def test_system_getaddrinfo_success_and_unsupported_type(monkeypatch):
    _no_dnspython(monkeypatch)

    def fake(host, port, family, *a, **kw):
        return [(family, socket.SOCK_STREAM, 6, "", ("192.0.2.5", 0)), (family, socket.SOCK_STREAM, 6, "", ("192.0.2.4", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    r = Resolver(FakeHttp(), mode="system")
    assert r.query("x.example", "A").records == ["192.0.2.4", "192.0.2.5"]
    mx = r.query("x.example", "MX")
    assert mx.status == "NOTIMP" and mx.could_not_verify


def test_system_dnspython_error_mapping(monkeypatch):
    pytest.importorskip("dns.resolver")
    import dns.resolver

    outcomes = {
        "gone.example": dns.resolver.NXDOMAIN(),
        "slow.example": dns.resolver.LifetimeTimeout(timeout=8.0, errors=[]),
        "dead.example": dns.resolver.NoNameservers(),
    }

    class FakeResolver:
        def resolve(self, name, rtype, **kw):
            raise outcomes[name]

    monkeypatch.setattr(dns.resolver, "Resolver", FakeResolver)
    r = Resolver(None, mode="system")
    assert r.query("gone.example", "A").nxdomain
    slow = r.query("slow.example", "A")
    assert slow.status == "TIMEOUT" and slow.could_not_verify
    dead = r.query("dead.example", "A")
    assert dead.status == "SERVFAIL" and dead.could_not_verify and not dead.nxdomain


# --------------------------------------------------------------------------------------
# wildcard probe and NXDOMAIN confirmation
# --------------------------------------------------------------------------------------


def _label(r: Resolver, label: str = "abcdefghij012345") -> str:
    r._random_label = lambda: label  # deterministic probe label
    return label


def test_wildcard_true_when_random_label_resolves():
    http = FakeHttp()
    r = resolver(http)
    label = _label(r)
    add_dns(http, f"{label}.wild.example", "A", ["192.0.2.99"])
    assert r.wildcard("wild.example") is True
    info = r.wildcard_info("wild.example")
    assert info.records == ("192.0.2.99",)
    assert len(http.urls()) == 1  # A had records: no AAAA probe, and the result is cached


def test_wildcard_false_when_both_nxdomain_and_cached():
    http = FakeHttp()
    r = resolver(http)
    label = _label(r)
    add_dns(http, f"{label}.plain.example", "A", [], status=3)
    add_dns(http, f"{label}.plain.example", "AAAA", [], status=3)
    assert r.wildcard("plain.example") is False
    assert r.wildcard("plain.example") is False
    assert len(http.urls()) == 2


def test_wildcard_none_when_could_not_verify_and_not_cached():
    http = FakeHttp()
    r = resolver(http)
    label = _label(r)
    add_dns_failure(http, f"{label}.x.example", "A", kind="servfail")
    add_dns(http, f"{label}.x.example", "AAAA", [], status=3)
    assert r.wildcard("x.example") is None
    r.wildcard("x.example")
    assert len(http.urls()) == 4  # None is not cached


def test_wildcard_nodata_zone():
    """Cloudflare-style zone: random names answer NOERROR/NODATA (the recorded 'nxdomain' probe)."""
    http = FakeHttp()
    r = resolver(http)
    label = _label(r)
    nodata = fx("live_cti__doh_google_nxdomain.json")
    http.add("GET", doh_url(f"{label}.example.com", "A"), json=nodata)
    http.add("GET", doh_url(f"{label}.example.com", "AAAA"), json=nodata)
    info = r.wildcard_info("example.com")
    assert info.wildcard is None and info.nodata is True  # NOERROR/NODATA: existence cannot be told
    assert r.wildcard("example.com") is None
    assert len(http.urls()) == 2  # a definitive DNS answer: cached per Resolver


def test_wildcard_random_label_shape():
    http = FakeHttp()
    http.add("GET", re.compile(r"^https://dns\.google/resolve\?name=[a-z0-9]{16}\.z\.example&type=A&"), json={"Status": 3})
    http.add("GET", re.compile(r"^https://dns\.google/resolve\?name=[a-z0-9]{16}\.z\.example&type=AAAA&"), json={"Status": 3})
    assert resolver(http).wildcard("z.example") is False


def test_confirm_nxdomain_needs_a_second_resolver():
    http = FakeHttp()
    add_dns(http, "gone.example", "A", [], status=3, provider="all")
    r = resolver(http)
    assert r.confirm_nxdomain("gone.example") is True
    assert [urlsplit(u).hostname for u in http.urls()] == ["dns.google", "cloudflare-dns.com"]


def test_confirm_nxdomain_disagreement_and_failures():
    http = FakeHttp()
    add_dns(http, "split.example", "A", [], status=3)
    add_dns(http, "split.example", "A", ["192.0.2.1"], provider="cloudflare")
    add_dns(http, "half.example", "A", [], status=3)
    add_dns_failure(http, "half.example", "A", kind="http500", provider="cloudflare")
    add_dns(http, "alive.example", "A", ["192.0.2.1"])
    add_dns_failure(http, "broken.example", "A", kind="servfail")
    r = resolver(http)
    assert r.confirm_nxdomain("split.example") is False
    assert r.confirm_nxdomain("half.example") is None
    assert r.confirm_nxdomain("alive.example") is False
    assert r.confirm_nxdomain("broken.example") is None


def test_confirm_nxdomain_single_resolver_is_none():
    http = FakeHttp()
    add_dns(http, "gone.example", "A", [], status=3)
    assert resolver(http, providers=["google"]).confirm_nxdomain("gone.example") is None
    http2 = FakeHttp()
    http2.add("GET", internal_url("gone.example", "A"), json={"Status": 3})
    r = resolver(http2, internal_url=INTERNAL, allow_public_fallback=False)
    assert r.confirm_nxdomain("gone.example") is None  # AMBER+: never moved to a public resolver
    assert all(u.startswith(INTERNAL) for u in http2.urls())


# --------------------------------------------------------------------------------------
# DNSBL (never through public resolvers; refusal codes are not 'not listed')
# --------------------------------------------------------------------------------------


def test_dnsbl_label():
    assert dnsbl_label("127.0.0.2") == "2.0.0.127"
    assert dnsbl_label("2001:db8::1").endswith("8.b.d.0.1.0.0.2")
    assert dnsbl_label("Example.COM.") == "example.com"


def test_dnsbl_with_public_resolvers_only_is_unverified():
    http = FakeHttp()
    res = resolver(http).dnsbl("2.0.0.127", "zen.spamhaus.org")
    assert res.listed is None and res.status == "unverified"
    assert res.reason.startswith("DNSBL needs a non-public resolver")
    assert http.urls() == []


def _internal_dnsbl(fixture: str | dict, qname: str = "2.0.0.127.zen.spamhaus.org"):
    http = FakeHttp()
    body = fx(fixture) if isinstance(fixture, str) else fixture
    http.add("GET", internal_url(qname, "A"), json=body)
    return resolver(http, internal_url=INTERNAL), http


def test_dnsbl_spamhaus_public_resolver_refusal_is_blocked():
    r, http = _internal_dnsbl("dnsbl_spamhaus_public_resolver.json")
    res = r.dnsbl("2.0.0.127", "zen.spamhaus.org")
    assert res.listed is None and res.status == "blocked"
    assert res.codes == ["127.255.255.254"] and "public resolver" in res.reason
    assert res.resolver == "internal"
    assert all(u.startswith(INTERNAL) for u in http.urls())


@pytest.mark.parametrize(
    ("code", "status"),
    [("127.255.255.252", "error"), ("127.255.255.254", "blocked"), ("127.255.255.255", "rate_limited")],
)
def test_dnsbl_refusal_codes(code, status):
    r, _http = _internal_dnsbl(doh("2.0.0.127.zen.spamhaus.org", "A", [code]))
    res = r.dnsbl("2.0.0.127", "zen.spamhaus.org")
    assert res.listed is None and res.status == status and res.codes == [code]


def test_dnsbl_zone_specific_refusal():
    r, _http = _internal_dnsbl("live_cti__dnsbl_uribl_test_cf.json", "test.uribl.com.multi.uribl.com")
    res = r.dnsbl("test.uribl.com", "multi.uribl.com")
    assert res.listed is None and res.status == "blocked"


def test_dnsbl_listed_not_listed_and_unverified():
    r, _http = _internal_dnsbl(doh("2.0.0.127.bl.spamcop.net", "A", ["127.0.0.2"]), "2.0.0.127.bl.spamcop.net")
    listed = r.dnsbl("2.0.0.127", "bl.spamcop.net")
    assert listed.listed is True and listed.codes == ["127.0.0.2"] and listed.status == "ok"
    r2, _ = _internal_dnsbl("caipora_infra__dnsbl_spamhaus_via_public_resolver.json")
    clean = r2.dnsbl("2.0.0.127", "zen.spamhaus.org")
    assert clean.listed is False and clean.status == "ok"
    r3, _ = _internal_dnsbl({"Status": 2, "Comment": "SERVFAIL"})
    failed = r3.dnsbl("2.0.0.127", "zen.spamhaus.org")
    assert failed.listed is None and failed.status == "unverified"


def test_dnsbl_answer_outside_loopback_is_not_listed_true():
    r, _http = _internal_dnsbl(doh("2.0.0.127.zen.spamhaus.org", "A", ["198.51.100.7"]))
    res = r.dnsbl("2.0.0.127", "zen.spamhaus.org")
    assert res.listed is None and res.status == "error"


def test_dnsbl_through_system_resolver(monkeypatch):
    _no_dnspython(monkeypatch)
    seen = []

    def fake(host, *a, **kw):
        seen.append(host)
        raise socket.gaierror(socket.EAI_NONAME, "unknown")

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    res = Resolver(FakeHttp(), mode="system").dnsbl(dnsbl_label("192.0.2.1"), "zen.spamhaus.org")
    assert res.listed is False and res.resolver == "system"
    assert seen == ["1.2.0.192.zen.spamhaus.org"]


# --------------------------------------------------------------------------------------
# DnsAnswer
# --------------------------------------------------------------------------------------


def test_dns_answer_properties_and_evidence():
    ok = DnsAnswer("a.example", "A", records=["192.0.2.1"], resolver="google", authenticated=True)
    assert ok.ok and not ok.nodata and not ok.nxdomain and not ok.could_not_verify
    data = ok.to_dict()
    assert data["resolver"] == "google" and "not proof" in data["authenticated_note"]
    assert DnsAnswer("a.example", "A").nodata
    assert DnsAnswer("a.example", "A", status="NXDOMAIN").nxdomain
    for status in ("SERVFAIL", "REFUSED", "TIMEOUT", "NOTIMP", "FORMERR"):
        ans = DnsAnswer("a.example", "A", status=status, error="x")
        assert ans.could_not_verify and not ans.nxdomain and not ans.ok
    assert DnsAnswer("a.example", "A", status="NXDOMAIN", error="odd").could_not_verify
