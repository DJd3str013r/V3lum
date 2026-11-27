"""team_cymru_asn (P032): Team Cymru IP-to-ASN TXT answers through the core DoH resolvers.

Fixtures in tests/fixtures/team_cymru_asn/ are recorded DoH JSON answers (research egress,
2026-11-25/26): Google (unquoted TXT) and Cloudflare (quoted TXT) forms of origin, origin6, AS-name
and peer answers, the Brazilian AS22548 answers and NXDOMAIN answers with their SOA authority. The
seven research samples are origin_ok_google(_alt), asname_ok_google(_alt), origin6_ok_google (a
40-nibble name: kept to prove the module never asks one), origin_ok_cloudflare and peer_ok_google.
"""

from __future__ import annotations

import pytest

from tests.fakes import DeadHttp, FakeHttp, add_dns, add_dns_failure, doh_url, module_fixture, run_module
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.ip_network import team_cymru_asn as tc
from v3lum.modules.ip_network.team_cymru_asn import TeamCymruAsn

V6 = "2001:4860:4860::8888"
V6_ORIGIN = "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.origin6.asn.cymru.com"


def fx(name):
    return module_fixture("team_cymru_asn", name)


def answer(http: FakeHttp, name: str, fixture_name: str, provider: str = "google") -> FakeHttp:
    http.add("GET", doh_url(name, "TXT", provider=provider), json=fx(fixture_name))
    return http


def google_8888(http: FakeHttp | None = None, *, peer: bool = True) -> FakeHttp:
    http = http or FakeHttp()
    answer(http, "8.8.8.8.origin.asn.cymru.com", "origin_ok_google.json")
    answer(http, "as15169.asn.cymru.com", "asname_ok_google.json")
    if peer:
        answer(http, "8.8.8.8.peer.asn.cymru.com", "peer_ok_google.json")
    return http


def pivots(res, relation=None):
    return {(p.entity.type, p.entity.value): p for p in res.pivots if relation is None or p.relation == relation}


# ------------------------------------------------------------------ answers (cond 1-2)
def test_ipv4_google_form():
    http = google_8888()
    res = run_module(TeamCymruAsn, "ipv4:8.8.8.8", http)
    assert res.status is Status.OK and not res.error
    a = res.attributes
    assert (a["asn"], a["as_org"], a["country"], a["prefix"]) == ("AS15169", "Google LLC", "US", "8.8.8.0/24")
    assert a["rir"] == "arin" and a["allocated"] == "2023-12-28" and a["origin_asns"] == ["AS15169"]
    assert a["upstream_asns"] == ["AS3257", "AS6461", "AS6939"]
    assert pivots(res, "belongs_to_asn")[(T.ASN, "AS15169")].expand is True
    prefix = pivots(res, "in_network")[(T.CIDR, "8.8.8.0/24")]
    assert prefix.expand is False
    assert {v for (_t, v) in pivots(res, "upstream_asn")} == {"AS3257", "AS6461", "AS6939"}
    assert all(not p.expand for p in pivots(res, "upstream_asn").values())
    assert res.requests == 0 and "dns.google" in res.hosts  # DoH only: not counted, but in the ledger
    assert res.raw["origin"]["ttl"] == 7021 and res.raw["origin"]["resolver"] == "google"
    http.assert_hosts_within(TeamCymruAsn)


def test_cloudflare_quoted_forms_after_failover():
    http = FakeHttp()
    add_dns_failure(http, "1.1.1.1.origin.asn.cymru.com", "TXT", kind="http500", provider="google")
    answer(http, "1.1.1.1.origin.asn.cymru.com", "origin_ok_cloudflare.json", provider="cloudflare")
    add_dns(http, "as13335.asn.cymru.com", "TXT", [], status=3)  # no AS-name answer recorded: NXDOMAIN
    add_dns_failure(http, "1.1.1.1.peer.asn.cymru.com", "TXT", kind="servfail")
    res = run_module(TeamCymruAsn, "ipv4:1.1.1.1", http)
    assert res.status is Status.OK
    assert (res.attributes["asn"], res.attributes["prefix"], res.attributes["country"]) == ("AS13335", "1.1.1.0/24", "AU")
    assert "as_org" not in res.attributes and res.raw["origin"]["resolver"] == "cloudflare"
    assert "peers: could not verify" in res.error  # SERVFAIL on the peer query is named, never 'no peers'


def test_asname_and_peer_cloudflare_forms():
    http = FakeHttp()
    add_dns_failure(http, "as15169.asn.cymru.com", "TXT", kind="http500", provider="google")
    answer(http, "as15169.asn.cymru.com", "asname_ok_cloudflare.json", provider="cloudflare")
    res = run_module(TeamCymruAsn, "asn:AS15169", http)
    assert res.status is Status.OK and res.attributes["as_org"] == "Google LLC" and res.attributes["country"] == "US"
    assert res.attributes["allocated"] == "2000-03-30" and not res.pivots
    http2 = google_8888(peer=False)
    add_dns_failure(http2, "8.8.8.8.peer.asn.cymru.com", "TXT", kind="http500", provider="google")
    answer(http2, "8.8.8.8.peer.asn.cymru.com", "peer_ok_cloudflare.json", provider="cloudflare")
    res2 = run_module(TeamCymruAsn, "ipv4:8.8.8.8", http2)
    assert res2.attributes["upstream_asns"] == ["AS3257", "AS6461", "AS6939"]


@pytest.mark.parametrize(("provider", "fixture_name"), [("google", "origin6_ok_google_32nib.json"), ("cloudflare", "origin6_ok_cloudflare.json")])
def test_ipv6_uses_the_full_32_nibble_name(provider, fixture_name):
    assert tc.origin_qname(V6) == V6_ORIGIN and len(V6_ORIGIN.split(".")) == 32 + 4
    http = FakeHttp()
    if provider == "cloudflare":
        add_dns_failure(http, V6_ORIGIN, "TXT", kind="http500", provider="google")
    answer(http, V6_ORIGIN, fixture_name, provider=provider)
    answer(http, "as15169.asn.cymru.com", "asname_ok_google.json")
    res = run_module(TeamCymruAsn, f"ipv6:{V6}", http)  # no peer query for IPv6 (an unexpected one would fail)
    assert res.attributes["prefix"] == "2001:4860::/32" and res.attributes["asn"] == "AS15169"
    assert "upstream_asns" not in res.attributes


def test_the_40_nibble_research_name_is_never_asked():
    recorded = fx("origin6_ok_google.json")["Question"][0]["name"].rstrip(".")
    assert recorded != tc.origin_qname(V6) and len(recorded.split(".")) == 40 + 4


def test_ipv4_mapped_ipv6_uses_the_ipv4_zones():
    assert tc.origin_qname("::ffff:8.8.8.8") == "8.8.8.8.origin.asn.cymru.com"
    res = run_module(TeamCymruAsn, "ipv6:::ffff:8.8.8.8", google_8888())
    assert res.attributes["prefix"] == "8.8.8.0/24"


def test_brazilian_origin_and_as_name():
    http = FakeHttp()
    answer(http, "3.2.160.200.origin.asn.cymru.com", "origin_ok_google_br.json")
    answer(http, "as22548.asn.cymru.com", "asname_ok_google_br.json")
    add_dns(http, "3.2.160.200.peer.asn.cymru.com", "TXT", [], status=3)
    res = run_module(TeamCymruAsn, "ipv4:200.160.2.3", http)
    a = res.attributes
    assert a["as_org"] == "Nucleo de Inf. e Coord. do Ponto BR - NIC.BR" and a["country"] == "BR" and a["rir"] == "lacnic"
    assert a["prefix"] == "200.160.0.0/20" and not res.error and "upstream_asns" not in a


SEVEN = [
    ("origin_ok_google.json", tc.parse_origin, {"asn": 15169, "prefix": "8.8.8.0/24", "country": "US"}),
    ("origin_ok_google_alt.json", tc.parse_origin, {"asn": 15169, "prefix": "8.8.8.0/24", "registry": "arin"}),
    ("asname_ok_google.json", tc.parse_asname, {"asn": 15169, "as_org": "Google LLC", "as_handle": "GOOGLE"}),
    ("asname_ok_google_alt.json", tc.parse_asname, {"asn": 15169, "as_org": "Google LLC", "country": "US"}),
    ("origin6_ok_google.json", tc.parse_origin, {"asn": 15169, "prefix": "2001:4860::/32", "allocated": "2005-03-14"}),
    ("origin_ok_cloudflare.json", tc.parse_origin, {"asn": 13335, "prefix": "1.1.1.0/24", "country": "AU"}),
    ("peer_ok_google.json", tc.parse_peer, {"peer_asns": [3257, 6461, 6939], "prefix": "8.8.8.0/24"}),
]


@pytest.mark.parametrize(("fixture_name", "parser", "expected"), SEVEN)
def test_the_seven_recorded_samples_parse(fixture_name, parser, expected):
    data = fx(fixture_name)["Answer"][0]["data"]
    parsed = parser(data)
    assert parsed is not None and {k: parsed[k] for k in expected} == expected


def test_quoted_and_multi_string_txt_normalisation():
    assert tc.normalise_txt('"15169 | 8.8.8.0/24 | US | arin | 2023-12-28"') == "15169 | 8.8.8.0/24 | US | arin | 2023-12-28"
    assert tc.normalise_txt('"15169 | 8.8.8.0/24 " "| US | arin | 2023-12-28"') == "15169 | 8.8.8.0/24 | US | arin | 2023-12-28"
    multi = tc.parse_origin("15169 36040 | 8.8.8.0/24 | US | arin | 2023-12-28")
    assert multi["asns"] == [15169, 36040] and multi["asn"] == 15169
    assert tc.parse_origin("garbage") is None and tc.parse_origin("15169 | not-a-prefix | US") is None
    assert tc.parse_asname("15169 | US | arin | 2000-03-30 |") is None


def test_multi_origin_answers_keep_every_asn_and_the_most_specific_prefix():
    http = FakeHttp()
    add_dns(http, "8.8.8.8.origin.asn.cymru.com", "TXT", ["15169 | 8.0.0.0/9 | US | arin | 1992-12-01", "15169 36040 | 8.8.8.0/24 | US | arin | 2023-12-28"])
    answer(http, "as15169.asn.cymru.com", "asname_ok_google.json")
    add_dns(http, "as36040.asn.cymru.com", "TXT", ["36040 | US | arin | 2005-01-01 | YOUTUBE - Google LLC, US"])
    add_dns(http, "8.8.8.8.peer.asn.cymru.com", "TXT", [], status=3)
    res = run_module(TeamCymruAsn, "ipv4:8.8.8.8", http)
    assert res.attributes["prefix"] == "8.8.8.0/24" and res.attributes["origin_asns"] == ["AS15169", "AS36040"]
    assert set(pivots(res, "belongs_to_asn")) == {(T.ASN, "AS15169"), (T.ASN, "AS36040")}


# ------------------------------------------------------------------ rule 5 (cond 3)
@pytest.mark.parametrize("provider", ["google", "cloudflare"])
def test_nxdomain_is_the_documented_absence(provider):
    http = FakeHttp()
    name = "139.6.0.193.origin.asn.cymru.com"
    if provider == "cloudflare":
        add_dns_failure(http, name, "TXT", kind="http500", provider="google")
    answer(http, name, f"origin_not_found_{provider}.json", provider=provider)
    res = run_module(TeamCymruAsn, "ipv4:193.0.6.139", http)
    assert res.status is Status.EMPTY and not res.error
    assert res.raw["origin"]["status"] == "absent" and res.raw["origin"]["ttl"] == 900  # SOA negative TTL


@pytest.mark.parametrize(("kind", "code"), [("servfail", "error"), ("refused", "error"), ("challenge", "error")])
def test_servfail_refused_and_refusals_are_could_not_verify(kind, code):
    http = FakeHttp()
    add_dns_failure(http, "8.8.8.8.origin.asn.cymru.com", "TXT", kind=kind)
    res = run_module(TeamCymruAsn, "ipv4:8.8.8.8", http)
    assert res.status is Status.ERROR and res.reason_code == code and "could not verify" in res.error


def test_timeouts_on_every_resolver_are_could_not_verify():
    http = FakeHttp()
    add_dns_failure(http, "8.8.8.8.origin.asn.cymru.com", "TXT", kind="timeout", provider="all")
    res = run_module(TeamCymruAsn, "ipv4:8.8.8.8", http)
    assert res.status is Status.ERROR and res.reason_code == "timeout"


def test_nodata_and_unparseable_txt_are_could_not_verify():
    http = FakeHttp()
    add_dns(http, "8.8.8.8.origin.asn.cymru.com", "TXT", [])
    assert run_module(TeamCymruAsn, "ipv4:8.8.8.8", http).status is Status.ERROR
    http2 = FakeHttp()
    add_dns(http2, "8.8.8.8.origin.asn.cymru.com", "TXT", ["<html>not a cymru answer</html>"])
    res = run_module(TeamCymruAsn, "ipv4:8.8.8.8", http2)
    assert res.status is Status.ERROR and "unparseable TXT" in res.error


def test_dead_network_is_could_not_verify():
    res = run_module(TeamCymruAsn, "ipv4:8.8.8.8", DeadHttp())
    assert res.status is Status.ERROR and "could not verify" in res.error and not res.pivots


@pytest.mark.parametrize("value", ["ipv4:10.0.0.1", "ipv4:192.0.2.1", "ipv4:100.64.0.1", "ipv6:::1", "ipv6:2001:db8::1", "asn:AS64512", "asn:AS4200000001"])
def test_private_and_bogon_values_are_never_queried(value):
    http = FakeHttp()
    res = run_module(TeamCymruAsn, value, http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and not http.calls


def test_pivots_of_an_address_reached_as_a_pivot_are_listed_only():
    res = run_module(TeamCymruAsn, "ipv4:8.8.8.8", google_8888(), is_seed=False, depth=1)
    assert pivots(res, "belongs_to_asn")[(T.ASN, "AS15169")].expand is False


def test_query_names():
    assert tc.origin_qname("200.160.2.3") == "3.2.160.200.origin.asn.cymru.com"
    assert tc.peer_qname("8.8.8.8") == "8.8.8.8.peer.asn.cymru.com" and tc.peer_qname(V6) is None
    assert tc.asname_qname("AS15169") == "AS15169.asn.cymru.com" and tc.asname_qname(15169) == "AS15169.asn.cymru.com"
    assert tc.asname_qname("AS23456") is None and tc.origin_qname("10.1.1.1") is None


def test_module_declarations():
    assert TeamCymruAsn.provider == "core_doh" and TeamCymruAsn.sources == ("core_doh.resolvers",)
    assert TeamCymruAsn.hosts == () and TeamCymruAsn.max_requests == 0 and TeamCymruAsn.disclosure == "third_party"
    assert TeamCymruAsn.terms == "open" and TeamCymruAsn.default_enabled is True and TeamCymruAsn.trust_tier == "trusted"
