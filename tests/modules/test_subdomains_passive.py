"""subdomains_passive (P016, default module): THC ip.thc.org + the shared passive-subdomain engine, offline.

Fixtures in tests/fixtures/subdomains_passive/ (batch p2-G01-3 prep, recorded 2026-11-26 from a datacenter
egress, scrubbed): live THC lookup pages for example.com (page 1 with a cursor, page 2 with a '*.' wildcard
name, the empty answer of a non-existent label), a derived last page (cursor emptied), a derived cut body
(malformed JSON), a synthetic 429 with x-ratelimit-remaining 0 (never observed live), live DoH answers
(example.com A through Google, a nic.br NXDOMAIN, Cloudflare NOERROR/NODATA for random example.com labels)
and synthetic DoH answers (loopback and RFC 1918 names, a wildcard zone, SERVFAIL).
"""

from __future__ import annotations

import base64
import json
import re

import pytest

from tests.fakes import (
    FIXTURES,
    FakeHttp,
    add_dns,
    add_dns_failure,
    add_nxdomain_everything,
    doh,
    doh_url,
    fixture,
    module_fixture,
    run_module,
)
from v3lum.core.entities import EntityType as T
from v3lum.core.http import NetworkError
from v3lum.core.models import Severity, Status
from v3lum.modules.domain_dns import subdomains_passive as sp
from v3lum.modules.domain_dns.subdomains_passive import THC_URL, SubdomainsPassive

FX = FIXTURES / "subdomains_passive"
GOOGLE = re.escape("https://dns.google/resolve?name=")
CLOUDFLARE = re.escape("https://cloudflare-dns.com/dns-query?name=")


def fx(name):
    return module_fixture("subdomains_passive", name)


def exchange(name):
    resp = fx(name)["response"]
    return resp["status"], resp.get("headers") or {}, resp.get("body")


def thc_page(names, cursor="", seen="2026-11-01"):
    """A THC lookup page in the live shape (comment, processed_domain, matching_records, domains, cursor)."""
    return {"comment": "Free Service!, Do not abuse", "processed_domain": "example.com", "matching_records": len(names),
            "domains": [{"domain": n, "last_seen_on": seen} for n in names], "next_page_state": cursor}


def random_probe(http, *, answer=None):
    """The two random 16-character wildcard probes (A, then AAAA) on both resolvers: NXDOMAIN by default."""
    body = answer if answer is not None else {"Status": 3, "Answer": []}
    for base in (GOOGLE, CLOUDFLARE):
        http.add("GET", re.compile("^" + base + r"[a-z0-9]{16}\.example\.com&type=(A|AAAA)(&|$)"), json=body)


def thc_http(*pages, headers=None):
    http = FakeHttp()
    for page in pages:
        http.add("POST", THC_URL, json=page, times=1, headers=headers or {"x-ratelimit-limit": "250", "x-ratelimit-remaining": "249"})
    return http


def bodies(http):
    return [json.loads(c["body"]) for c in http.calls if c["method"] == "POST"]


# ------------------------------------------------------------------ metadata (P016 cond 1-4)
def test_contract_metadata():
    cls = SubdomainsPassive
    assert cls.terms == "open" and cls.default_enabled is True and cls.trust_tier == "community"
    assert cls.sources == ("thc.subdomains",) and cls.hosts == ("ip.thc.org",)
    assert cls.max_requests == 10 and cls.max_pivots == 12 and cls.expected_latency <= 10
    assert cls.accepts == {T.DOMAIN} and cls.disclosure == "third_party"
    assert set(cls.settings) == {"subdomains_passive_budget", "subdomains_passive_resolve"}
    assert cls.settings["subdomains_passive_budget"].default == 30 and cls.settings["subdomains_passive_resolve"].default == 300


def test_parse_live_thc_page():
    page = sp.parse_thc_page(json.dumps(fx("thc_lookup_ok.json")).encode())
    assert page["next"] == "00075405226d61696cf07ffffffaf07ffffffa"
    assert page["matching_records"] == 20766 and page["processed_domain"] == "example.com"
    assert ("www.example.com", "2024-12-11") in page["domains"]
    assert sp.parse_thc_page(json.dumps(fx("thc_lookup_last_page.json")))["next"] is None
    with pytest.raises(sp.UnexpectedAnswer):
        sp.parse_thc_page((FX / "thc_malformed.txt").read_bytes())
    with pytest.raises(sp.UnexpectedAnswer):
        sp.parse_thc_page(b"<html><body>502 Bad Gateway</body></html>")
    with pytest.raises(sp.UnexpectedAnswer, match="error object"):
        sp.parse_thc_page(b'{"error": "internal error"}')


# ------------------------------------------------------------------ paging (cond 2)
def test_cursor_paging_merges_names_wildcards_and_stale_flags():
    http = thc_http(fx("thc_lookup_ok.json"), fx("thc_lookup_page2.json"), fx("thc_lookup_last_page.json"))
    add_dns(http, "www.example.com", "A", ["93.184.215.14"])
    random_probe(http)
    add_nxdomain_everything(http)
    res = run_module(SubdomainsPassive, "domain:example.com", http)
    assert res.status is Status.OK and not res.partial
    sent = bodies(http)
    assert [b.get("page_state") for b in sent] == [None, "00075405226d61696cf07ffffffaf07ffffffa", "000354012af07ffffff5f07ffffff5"]
    assert all(b["domain"] == "example.com" and b["limit"] == 1000 for b in sent)
    names = set(res.attributes["subdomains"])
    assert "www.example.com" in names and "server2.example.com" in names and "example.com" not in names  # apex is not a subdomain
    assert res.attributes["subdomain_wildcards"] == ["*.example.com"]  # '*.' entries never become host names
    prov = res.attributes["subdomain_provenance"]
    assert prov["www.example.com"]["sources"] == ["thc.subdomains"] and prov["www.example.com"]["last_seen"] == "2024-12-11"
    assert prov["www.example.com"]["stale"] is True  # last seen more than 365 days before 2026-11-26
    assert prov["mail.example.com"]["state"] == "historical"  # NXDOMAIN confirmed by the second resolver
    cov = res.attributes["subdomain_coverage"]
    assert cov["line"] == "1/1 sources answered" and cov["names"] == len(prov)
    assert res.source_statuses["thc.subdomains"]["status"] == "ok"
    http.assert_hosts_within(SubdomainsPassive)


def test_page_cap_of_ten_is_partial_request_cap():
    http = FakeHttp()
    for i in range(10):
        http.add("POST", THC_URL, json=thc_page([f"h{i}.example.com"], cursor=f"cursor{i}"), times=1)
    add_nxdomain_everything(http)
    res = run_module(SubdomainsPassive, "domain:example.com", http)
    assert len(bodies(http)) == 10  # never an 11th page (max_requests 10)
    assert res.status is Status.OK and res.partial and res.stop_reason == "request_cap"
    assert "request_cap" in res.attributes["subdomain_coverage"]["sources"]["thc.subdomains"]["partial"]


def test_ratelimit_remaining_header_stops_paging():
    http = FakeHttp()
    http.add("POST", THC_URL, json=fx("thc_lookup_ok.json"), headers={"x-ratelimit-limit": "250", "x-ratelimit-remaining": "1"})
    add_nxdomain_everything(http)
    res = run_module(SubdomainsPassive, "domain:example.com", http)
    assert len(bodies(http)) == 1
    assert res.status is Status.OK and res.partial and res.stop_reason == "rate_limited"
    assert "x-ratelimit-remaining" in res.error


def test_429_is_rate_limited_never_empty():
    status, headers, body = exchange("thc_rate_limited.http.json")
    http = FakeHttp().add("POST", THC_URL, status=status, text=body, headers=headers)
    res = run_module(SubdomainsPassive, "domain:example.com", http)
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited"
    assert "could not verify" in res.error and "subdomains" not in res.attributes
    assert res.source_statuses["thc.subdomains"]["status"] == "rate_limited"


def test_429_on_a_later_page_keeps_the_names_partial():
    status, headers, body = exchange("thc_rate_limited.http.json")
    http = FakeHttp()
    http.add("POST", THC_URL, json=fx("thc_lookup_ok.json"), times=1)
    http.add("POST", THC_URL, status=status, text=body, headers=headers, times=1)
    add_nxdomain_everything(http)
    res = run_module(SubdomainsPassive, "domain:example.com", http)
    assert res.status is Status.OK and res.partial and res.stop_reason == "rate_limited"
    assert "www.example.com" in res.attributes["subdomains"]


def test_challenge_page_is_blocked_challenge():
    page = "<html><head><title>Just a moment...</title></head><body><div id='cf-chl-widget'></div></body></html>"
    http = FakeHttp().add("POST", THC_URL, status=403, text=page)
    res = run_module(SubdomainsPassive, "domain:example.com", http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"
    assert len(http.calls) == 1  # never retried with another identity (A9)


@pytest.mark.parametrize("route", [
    {"status": 502, "text": "<html><body>502 Bad Gateway</body></html>"},
    {"error": NetworkError("ReadTimeout contacting ip.thc.org: timed out", kind="ReadTimeout")},
    {"text": (FX / "thc_malformed.txt").read_text(), "headers": {"content-type": "application/json"}},
    {"json": {"error": "backend unavailable"}},
    {"json": ["not", "an", "object"]},
])
def test_failures_are_could_not_verify(route):
    http = FakeHttp().add("POST", THC_URL, **route)
    res = run_module(SubdomainsPassive, "domain:example.com", http)
    assert res.status is Status.ERROR and "could not verify" in res.error
    assert "subdomains" not in res.attributes


def test_empty_answer_is_empty_with_coverage():
    http = FakeHttp().add("POST", THC_URL, json=fx("thc_lookup_empty.json"))
    res = run_module(SubdomainsPassive, "domain:example.com", http)
    assert res.status is Status.EMPTY
    assert res.attributes["subdomain_coverage"]["line"] == "1/1 sources answered"
    assert [c["url"] for c in http.calls] == [THC_URL]  # nothing to resolve: no DoH query


def test_subdomain_entity_is_not_applicable():
    http = FakeHttp()
    res = run_module(SubdomainsPassive, "domain:www.example.com", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert http.calls == []  # once per registrable domain (cond 1)


# ------------------------------------------------------------------ resolution, wildcard, pivots (cond 6-8)
def test_live_doh_answers_and_cloudflare_nodata_quirk():
    http = thc_http(thc_page(["www.example.com", "gone.example.com"]))
    http.add("GET", doh_url("www.example.com", "A"), json=fx("doh_name_live_google.json"))
    http.add("GET", doh_url("gone.example.com", "A"), json=fx("doh_probe_cloudflare_nodata_a.json"))
    http.add("GET", doh_url("gone.example.com", "AAAA"), json=fx("doh_probe_cloudflare_nodata_aaaa.json"))
    random_probe(http, answer=fx("doh_probe_cloudflare_nodata_a.json"))
    res = run_module(SubdomainsPassive, "domain:example.com", http)
    wild = res.attributes["dns_wildcard"]
    assert wild["state"] == "none" and wild["nodata_quirk"] is True  # NOERROR/NODATA for random labels is not a wildcard
    prov = res.attributes["subdomain_provenance"]
    assert prov["www.example.com"]["state"] == "live" and prov["www.example.com"]["addresses"] == ["104.20.23.154", "172.66.147.243"]
    assert prov["gone.example.com"]["state"] == "no_address"  # never 'historical' without a real NXDOMAIN
    # example.com sits on Cloudflare: when the noise lists know the range the name is CDN-only and is
    # listed without a pivot (cond 8); otherwise it pivots - never both
    pivoted = {p.entity.value for p in res.pivots}
    assert pivoted <= {"www.example.com"}
    assert ("www.example.com" in pivoted) is (prov["www.example.com"].get("cdn_only") is False)
    assert all(p.expand is True and p.relation == "subdomain" for p in res.pivots)


def test_wildcard_only_names_are_dropped():
    wildcard = fx("doh_probe_wildcard_synthetic.json")
    http = thc_http(thc_page(["junk1.example.com", "real.example.com"]))
    add_dns(http, "junk1.example.com", "A", ["198.51.100.7"])
    add_dns(http, "real.example.com", "A", ["203.0.113.80"])
    random_probe(http, answer=wildcard)
    res = run_module(SubdomainsPassive, "domain:example.com", http)
    assert res.attributes["dns_wildcard"]["state"] == "wildcard" and res.attributes["dns_wildcard"]["answers"] == ["198.51.100.7"]
    assert res.attributes["subdomains"] == ["real.example.com"]
    assert res.attributes["subdomain_coverage"]["wildcard_only_dropped"] == 1
    assert {p.entity.value for p in res.pivots} == {"real.example.com"}


def test_internal_addresses_give_low_findings_and_never_pivot():
    http = thc_http(thc_page(["vpn.example.com", "localhost.example.com", "www.example.com"]))
    http.add("GET", doh_url("vpn.example.com", "A"), json=fx("doh_name_rfc1918_synthetic.json"))
    http.add("GET", doh_url("localhost.example.com", "A"), json=fx("doh_name_private_synthetic.json"))
    add_dns(http, "www.example.com", "A", ["93.184.215.14"])
    random_probe(http)
    res = run_module(SubdomainsPassive, "domain:example.com", http)
    internal = [f for f in res.findings if f.title == "Internal address in public DNS"]
    assert {f.data["name"] for f in internal} == {"vpn.example.com", "localhost.example.com"}
    assert all(f.severity is Severity.LOW and f.criterion and "misconfiguration" in f.tags for f in internal)
    vpn = next(f for f in internal if f.data["name"] == "vpn.example.com")
    assert vpn.data["addresses"] == ["10.20.30.40"] and vpn.data["kinds"] == ["private"]
    assert {p.entity.value for p in res.pivots} == {"www.example.com"}  # never contacted or pivoted
    assert res.attributes["subdomain_provenance"]["vpn.example.com"]["cnames"] == ["vpn-int.example.com"]


def test_pivots_capped_at_twelve_with_telling_labels_first():
    labels = ["vpn", "sso", "mail", "admin", "dev", "api"] + [f"host{i:02d}" for i in range(14)]
    names = [f"{lab}.example.com" for lab in labels]
    http = thc_http(thc_page(names))
    for i, name in enumerate(names):
        add_dns(http, name, "A", [f"203.0.113.{i + 1}"])
    random_probe(http)
    res = run_module(SubdomainsPassive, "domain:example.com", http)
    pivots = [p.entity.value for p in res.pivots]
    assert len(pivots) == 12
    assert set(pivots[:6]) == {f"{lab}.example.com" for lab in ("vpn", "sso", "mail", "admin", "dev", "api")}
    assert pivots[0] == "vpn.example.com"


def test_cdn_only_names_are_listed_not_pivoted():
    http = thc_http(thc_page(["cdn.example.com", "app.example.com"]))
    http.add("GET", doh_url("cdn.example.com", "A"), json={"Status": 0, "Answer": [
        {"name": "cdn.example.com.", "type": 5, "TTL": 60, "data": "d111111abcdef8.cloudfront.net."},
        {"name": "d111111abcdef8.cloudfront.net.", "type": 1, "TTL": 60, "data": "203.0.113.50"}]})
    add_dns(http, "app.example.com", "A", ["203.0.113.51"])
    random_probe(http)
    res = run_module(SubdomainsPassive, "domain:example.com", http)
    assert {p.entity.value for p in res.pivots} == {"app.example.com"}
    assert res.attributes["subdomain_provenance"]["cdn.example.com"]["cdn_only"] is True
    assert "cdn.example.com" in res.attributes["subdomains"]  # listed, never pivoted


def test_doh_resolution_cap_and_unresolved_names():
    names = [f"n{i}.example.com" for i in range(6)]
    http = thc_http(thc_page(names))
    add_dns_failure(http, "n0.example.com", "A", kind="servfail", provider="all")
    random_probe(http)
    add_nxdomain_everything(http)
    res = run_module(SubdomainsPassive, "domain:example.com", http, settings={"subdomains_passive_resolve": 3})
    cov = res.attributes["subdomain_coverage"]
    assert cov["resolution_cap"] == 3 and cov["not_resolved"] == 3
    states = {n: row["state"] for n, row in res.attributes["subdomain_provenance"].items()}
    assert states["n0.example.com"] == "unresolved"  # SERVFAIL: could not verify, never historical
    assert sum(1 for s in states.values() if s == "not_resolved") == 3
    assert set(res.attributes["subdomains_unresolved"]) >= {"n0.example.com"}
    assert res.pivots == []


def test_unconfirmed_nxdomain_stays_unresolved():
    http = thc_http(thc_page(["flaky.example.com"]))
    http.add("GET", doh_url("flaky.example.com", "A"), json=doh("flaky.example.com", "A", [], status=3))
    http.add("GET", doh_url("flaky.example.com", "A", provider="cloudflare"), json=doh("flaky.example.com", "A", ["203.0.113.9"]))
    random_probe(http)
    res = run_module(SubdomainsPassive, "domain:example.com", http)
    assert res.attributes["subdomain_provenance"]["flaky.example.com"]["state"] == "unresolved"
    assert "subdomains_historical" not in res.attributes


def test_dead_doh_leaves_names_unresolved_but_keeps_thc_answer():
    http = thc_http(thc_page(["www.example.com", "mail.example.com"]))
    http.add("GET", re.compile(r"^https://(dns\.google/resolve|cloudflare-dns\.com/dns-query)\?"),
             error=NetworkError("ConnectError contacting the resolver", kind="ConnectError"))
    res = run_module(SubdomainsPassive, "domain:example.com", http)
    assert res.status is Status.OK
    assert res.attributes["dns_wildcard"]["state"] == "unknown"
    assert set(res.attributes["subdomains_unresolved"]) == {"www.example.com", "mail.example.com"}
    assert res.pivots == []  # nothing resolves: nothing pivots
    assert res.attributes["subdomain_coverage"]["doh_could_not_verify"] == 2


# ------------------------------------------------------------------ pure helpers
@pytest.mark.parametrize(("ip", "kind"), [
    ("10.1.2.3", "private"), ("172.16.0.1", "private"), ("192.168.1.1", "private"), ("fd00::1", "private"),
    ("100.64.0.1", "cgnat"), ("127.0.0.1", "loopback"), ("::1", "loopback"), ("169.254.169.254", "link_local"),
    ("fe80::1", "link_local"), ("0.0.0.0", "null"), ("::", "null"), ("192.0.2.1", "public"), ("8.8.8.8", "public"),
    ("::ffff:10.0.0.1", "private"), ("junk", "invalid"),
])
def test_address_kinds(ip, kind):
    assert sp.address_kind(ip) == kind


def test_wildcard_state_table():
    assert sp.wildcard_state(("nxdomain", []), ("nxdomain", []))["state"] == "none"
    quirk = sp.wildcard_state(("nodata", []), ("nodata", []))
    assert quirk["state"] == "none" and quirk["nodata_quirk"] is True
    assert sp.wildcard_state(("records", ["198.51.100.7"]), ("records", ["198.51.100.8"]))["state"] == "wildcard"
    assert sp.wildcard_state(("records", ["198.51.100.7"]), ("nxdomain", []))["state"] == "unknown"
    assert sp.wildcard_state(("failed", []), ("nxdomain", []))["state"] == "unknown"


def test_confirmation_rules():
    noisy = {"anubisdb.subdomains", "subdomain_center.subdomains"}
    assert sp.confirmed(["thc.subdomains"], "historical", "none", noisy) is True  # community feed
    assert sp.confirmed(["anubisdb.subdomains"], "historical", "none", noisy) is False
    assert sp.confirmed(["anubisdb.subdomains"], "live", "none", noisy) is True  # resolves (non-wildcard)
    assert sp.confirmed(["anubisdb.subdomains"], "live", "unknown", noisy) is False  # wildcard could not be checked
    assert sp.confirmed(["anubisdb.subdomains", "subdomain_center.subdomains"], "unresolved", "unknown", noisy) is True


def test_label_priority_and_resolution_order():
    names = ["zz.example.com", "api-v2.example.com", "vpn2.example.com", "webmail.example.com", "a.b.example.com", "sso.example.com"]
    todo, deferred = sp.resolution_order(names, "example.com", cap=4)
    assert todo[:2] == ["vpn2.example.com", "sso.example.com"] and "api-v2.example.com" in todo
    assert sp.label_priority("webmail.example.com", "example.com")[0] == len(sp.TELLING_LABELS)  # no prefix-free match
    assert len(deferred) == 2


def test_per_source_name_cap():
    feed = sp.Feed("thc.subdomains", "THC")
    feed.sink = sp.HostnameSink("example.com")
    for i in range(sp.PER_SOURCE_CAP + 10):
        feed.add(f"h{i}.example.com")
    assert len(feed.names) == sp.PER_SOURCE_CAP and feed.capped == 10 and "name_cap" in feed.partial_reasons


# ------------------------------------------------------------------ AR21 golden path (tests/fixtures/acceptance/domain/)
def replay_acceptance(doc):
    """The acceptance routes as the README describes them (json / text / body_b64, headers, latency)."""
    http = FakeHttp()
    for route in doc["routes"]:
        body = {}
        if "json" in route:
            body["json"] = route["json"]
        elif "body_b64" in route:
            body["body"] = base64.b64decode(route["body_b64"])
        else:
            body["text"] = route.get("text", "")
        http.add(route["method"], route["url"], status=route["status"], headers=route.get("headers"),
                 latency=route.get("latency_ms", 0) / 1000.0, **body)
    return http


def test_acceptance_routes_cover_the_golden_domain():
    """Recorded live 2026-11-26: a trimmed real THC page for example.com, live Google DoH answers for its names and
    the two random-label wildcard probes (one prefix route: the labels are random by design, P016 cond 6)."""
    doc = fixture("acceptance/domain/subdomains_passive.json")
    assert doc["schema"] == "v3lum.acceptance_routes/1" and doc["module"] == "subdomains_passive"
    http = replay_acceptance(doc)
    res = run_module(SubdomainsPassive, "domain:example.com", http)
    assert res.status is Status.OK and not res.partial and not http.unexpected
    assert res.attributes["subdomain_coverage"]["line"] == "1/1 sources answered"
    assert res.attributes["dns_wildcard"]["state"] == "none" and res.attributes["dns_wildcard"]["nodata_quirk"] is True
    assert set(res.attributes["subdomains"]) == {"www.example.com", "1.example.com", "mail.example.com", "server2.example.com",
                                                 "test3.example.com"}
    assert res.attributes["subdomain_wildcards"] == ["*.example.com"]
    assert not res.pivots  # www resolves only to CDN edges; the other names answer NOERROR/NODATA (Cloudflare quirk)
    assert [f.severity for f in res.findings] == [Severity.INFO]
    assert len(http.calls) == len(doc["routes"]) - 1 + 4  # every exact route once, the prefix route for the 4 probe queries
    http.assert_hosts_within(SubdomainsPassive)


def test_live_nxdomain_zone_historical_and_ede_servfail_unresolved():
    """Live nic.br NXDOMAIN answers (the random wildcard labels and an old name, confirmed by the second
    resolver) and a SERVFAIL with EDE 22 'No Reachable Authority': historical vs could-not-verify (cond 7)."""
    nx, servfail = fx("doh_name_nxdomain_google.json"), fx("doh_servfail_synthetic.json")
    old, broken = "zz-nonexistent-label-7q3.nic.br", "dev.nic.br"
    http = thc_http(thc_page([old, broken]))
    http.add("GET", doh_url(old, "A"), json=nx)
    http.add("GET", doh_url(old, "A", provider="cloudflare"), json=nx)  # confirm_nxdomain: a different resolver
    http.add("GET", doh_url(broken, "A"), json=servfail)
    probe = fx("doh_probe_google_nxdomain.json")  # a live random-label NXDOMAIN (google.com zone)
    http.add("GET", re.compile("^" + GOOGLE + r"[a-z0-9]{16}\.nic\.br&type=(A|AAAA)(&|$)"), json=probe)
    res = run_module(SubdomainsPassive, "domain:nic.br", http)
    assert res.status is Status.OK
    assert res.attributes["dns_wildcard"]["state"] == "none" and res.attributes["dns_wildcard"]["nodata_quirk"] is False
    prov = res.attributes["subdomain_provenance"]
    assert prov[old]["state"] == "historical" and prov[broken]["state"] == "unresolved"
    assert res.attributes["subdomains_historical"] == [old] and res.attributes["subdomains_unresolved"] == [broken]
    assert res.attributes["subdomain_coverage"]["doh_could_not_verify"] == 1
    assert not res.pivots  # neither a historical nor an unverified name pivots (cond 8)
