"""Offline tests of dnsbl (P045) with the recorded DoH answers in tests/fixtures/dnsbl/."""

from __future__ import annotations

import pytest

from tests.fakes import DeadHttp, FakeHttp, add_dns, add_dns_failure, add_nxdomain_everything, assert_no_secret, doh_url, module_fixture, run_module
from v3lum.core import dns as dns_mod
from v3lum.core.dns import DnsAnswer
from v3lum.core.models import Severity, Status
from v3lum.modules.ip_network import dnsbl as mod
from v3lum.modules.ip_network.dnsbl import LIST_BY_ID, LISTS, MAX_LISTS, Dnsbl, check_test_point, classify, query_label, redact_qname, reverse_ip

CORPORATE = ("core_doh.resolvers", "spamcop.bl", "dronebl.dnsbl")  # the open lists (P045 c1)
ALL = Dnsbl.sources
DQS_KEY = "abcdefghij0123456789klmnop"
HTTPBL_KEY = "abcdefghijkl"


def doh_answer(http: FakeHttp, name: str, fixture: str, rtype: str = "A") -> None:
    http.add("GET", doh_url(name, rtype), json=module_fixture("dnsbl", fixture))


def add_test_points(http: FakeHttp) -> None:
    """Recorded test-point answers of SpamCop and DroneBL (2.0.0.127 -> 127.0.0.2 / 127.0.0.1)."""
    doh_answer(http, "2.0.0.127.bl.spamcop.net", "spamcop_test_point_ok.json")
    doh_answer(http, "2.0.0.127.dnsbl.dronebl.org", "dronebl_test_point_ok.json")


def answers_of(fixture: str) -> tuple[str, list[str]]:
    doc = module_fixture("dnsbl", fixture)
    rcode = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN"}[doc["Status"]]
    return rcode, [a["data"] for a in doc.get("Answer", []) if a.get("type") == 1]


# --------------------------------------------------------------------------------------
# pure helpers
# --------------------------------------------------------------------------------------


def test_reverse_ip_and_query_names():
    assert reverse_ip("192.0.2.10") == "10.2.0.192"
    assert reverse_ip("::ffff:192.0.2.10") == "10.2.0.192"  # IPv4-mapped is read as IPv4
    nibbles = reverse_ip("::ffff:7f00:2", unmap=False)  # RFC 5782 IPv6 test point (P045 c6)
    assert nibbles == "2.0.0.0.0.0.f.7.f.f.f.f." + ".".join(["0"] * 20)
    assert len(nibbles.split(".")) == 32
    assert reverse_ip("not an ip") is None
    zen, httpbl, dbl = LIST_BY_ID["spamhaus_zen"], LIST_BY_ID["httpbl"], LIST_BY_ID["spamhaus_dbl"]
    assert query_label(zen, "192.0.2.10", DQS_KEY) == f"10.2.0.192.{DQS_KEY}"  # <rev>.<key>.zen.dq.spamhaus.net
    assert query_label(httpbl, "192.0.2.10", HTTPBL_KEY) == f"{HTTPBL_KEY}.10.2.0.192"  # <key>.<rev>.dnsbl.httpbl.org
    assert query_label(dbl, "Example.COM.", DQS_KEY) == f"example.com.{DQS_KEY}"
    assert query_label(LIST_BY_ID["spamcop"], "example.com") is None  # IP zones never get domains (P045 c9)


def test_redact_qname_masks_keys_even_when_the_value_is_unknown():
    text = f"All nameservers failed to answer 10.2.0.192.{DQS_KEY}.zen.dq.spamhaus.net. IN A"
    assert DQS_KEY not in redact_qname(text, DQS_KEY)
    assert DQS_KEY not in redact_qname(text)  # structural redaction (defence in depth, AR01)
    assert HTTPBL_KEY not in redact_qname(f"{HTTPBL_KEY}.10.2.0.192.dnsbl.httpbl.org timed out")


def test_wiring_tables_and_caps():
    assert all(lst.source in ALL for lst in LISTS)  # a list is wired only with its registry source (P045 c1)
    for kind in ("ip", "domain"):
        assert len([lst for lst in LISTS if lst.kind == kind]) <= MAX_LISTS  # P045 c9
    assert {lst.id for lst in LISTS if lst.route == "doh"} == {"spamcop", "dronebl", "uceprotect_l1", "uceprotect_l2", "uceprotect_l3"}
    assert {lst.id for lst in LISTS if lst.route == "keyed"} == {"spamhaus_zen", "spamhaus_dbl", "httpbl"}
    assert {lst.id for lst in LISTS if lst.kind == "domain"} == {"spamhaus_dbl", "surbl", "uribl"}


def test_refusal_answers_are_blocked_never_listed_or_not_listed():
    zen, dbl, uribl = LIST_BY_ID["spamhaus_zen"], LIST_BY_ID["spamhaus_dbl"], LIST_BY_ID["uribl"]
    # Spamhaus through Cloudflare DoH: 127.255.255.254 (P045 c5)
    rcode, records = answers_of("spamhaus_zen_refused_cf.json")
    out = classify(zen, rcode, records, route="doh", public=True)
    assert (out.state, out.status, out.code) == ("refused", Status.BLOCKED, "challenge")
    rcode, records = answers_of("spamhaus_dbl_refused_cf.json")
    assert classify(dbl, rcode, records, route="doh", public=True).state == "refused"
    # Spamhaus through Google: NXDOMAIN + SOA need.to.know.only is a refusal, never 'not listed'
    for fixture, lst in (("spamhaus_zen_refused_nxdomain_google.json", zen), ("spamhaus_dbl_refused_nxdomain_google.json", dbl)):
        rcode, records = answers_of(fixture)
        out = classify(lst, rcode, records, route="doh", public=True)
        assert out.state == "refused" and out.status is Status.BLOCKED
    # URIBL answers 127.0.0.1 = query refused
    rcode, records = answers_of("uribl_refused.json")
    out = classify(uribl, rcode, records, route="doh", public=True)
    assert out.state == "refused" and "refused" in out.reason
    # the other Spamhaus refusal codes, through the system resolver too
    assert classify(zen, "NOERROR", ["127.255.255.255"], route="system").status is Status.RATE_LIMITED
    assert classify(zen, "NOERROR", ["127.255.255.252"], route="system").status is Status.ERROR
    assert classify(dbl, "NOERROR", ["127.0.1.255"], route="system").status is Status.ERROR
    # any 127.255.255.x is a refusal on any list
    assert classify(LIST_BY_ID["spamcop"], "NOERROR", ["127.255.255.250"], route="doh", public=True).state == "refused"


def test_surbl_never_through_public_doh():
    surbl = LIST_BY_ID["surbl"]
    rcode, records = answers_of("surbl_test_point_google.json")
    assert classify(surbl, rcode, records, route="doh", public=True).state == "refused"  # P045 c4, even when Google answered
    rcode, records = answers_of("surbl_servfail_cf.json")
    assert classify(surbl, rcode, records, route="doh", public=True).state == "error"
    ok, _why = check_test_point(classify(surbl, rcode := "NOERROR", ["127.0.0.254"], route="system"))
    assert ok and rcode == "NOERROR"


def test_barracuda_recorded_doh_answer_is_refused_but_a_registered_resolver_passes_the_test_point():
    barracuda = LIST_BY_ID["barracuda"]
    rcode, records = answers_of("barracuda_test_point_ok.json")
    assert classify(barracuda, rcode, records, route="doh", public=True).state == "refused"  # unregistered: never via DoH
    ok, why = check_test_point(classify(barracuda, rcode, records, route="system"))
    assert ok, why


def test_uceprotect_level1_counts_levels_2_and_3_are_neighbourhood_info():
    l1, l2, l3 = (LIST_BY_ID[f"uceprotect_l{i}"] for i in (1, 2, 3))
    assert classify(l1, *answers_of("uceprotect_l1_test_point_ok.json"), route="doh").counts is True
    for lst, fixture in ((l2, "uceprotect_l2_test_point.json"), (l3, "uceprotect_l3_test_point.json")):
        out = classify(lst, *answers_of(fixture), route="doh")
        assert out.state == "listed" and out.counts is False and out.info_only
        assert "neighbourhood listing" in out.reason and "zero risk" in out.reason


def test_unknown_codes_and_answers_outside_loopback_are_errors():
    rcode, records = answers_of("multi_answer.json")  # 127.0.0.2 + 127.0.0.10..13: codes SpamCop never documents
    out = classify(LIST_BY_ID["spamcop"], rcode, records, route="doh")
    assert out.state == "error" and "not in the bundled table" in out.reason
    out = classify(LIST_BY_ID["dronebl"], "NOERROR", ["10.1.1.1"], route="doh")
    assert out.state == "error" and "outside 127.0.0.0/8" in out.reason
    assert classify(LIST_BY_ID["dronebl"], "SERVFAIL", [], route="doh", error="x").state == "error"
    assert classify(LIST_BY_ID["dronebl"], "TIMEOUT", [], route="doh").code == "timeout"


def test_httpbl_answers_are_decoded_log_scaled():
    httpbl = LIST_BY_ID["httpbl"]
    cases = {c["label"]: c for c in module_fixture("dnsbl", "httpbl_answers_synthetic.json")["cases"]}
    first = classify(httpbl, cases["suspicious, score 1, 1 day"]["rcode"], cases["suspicious, score 1, 1 day"]["a"], route="system")
    assert first.state == "listed" and first.counts and first.httpbl["visitor_types"] == ["suspicious"]
    assert check_test_point(first)[0]  # 127.1.1.1 is the http:BL test answer
    spammer = classify(httpbl, "NOERROR", cases["comment spammer + harvester, score 40, 3 days"]["a"], route="system")
    assert spammer.httpbl == {"threat_score": 40, "score_band": "medium", "days_since_last_activity": 3, "visitor_types": ["harvester", "comment_spammer"]}
    engine = classify(httpbl, "NOERROR", cases["search engine (Google, serial 5)"]["a"], route="system")
    assert engine.info_only and engine.httpbl["search_engine"] == "Google"
    assert classify(httpbl, "NXDOMAIN", [], route="system").state == "not_listed"  # NXDOMAIN = not listed (P045 c9)
    assert classify(httpbl, "NOERROR", cases["malformed first octet"]["a"], route="system").state == "error"
    assert classify(httpbl, "NOERROR", ["127.3.40.6"], route="doh", public=True).state == "refused"  # keyed: never public DoH


# --------------------------------------------------------------------------------------
# module runs (core DoH layer)
# --------------------------------------------------------------------------------------


def test_not_listed_on_the_open_lists_through_doh():
    http = FakeHttp()
    add_test_points(http)
    doh_answer(http, "8.8.8.8.bl.spamcop.net", "spamcop_not_listed.json")
    doh_answer(http, "8.8.8.8.dnsbl.dronebl.org", "dronebl_not_listed.json")
    res = run_module(Dnsbl, "ipv4:8.8.8.8", http, allowed_sources=CORPORATE)
    assert res.status is Status.EMPTY and not res.findings
    assert res.attributes["dnsbl_summary"] == "not listed on 2 queried lists"
    assert {s: row["status"] for s, row in res.source_statuses.items()} == {"spamcop.bl": "empty", "dronebl.dnsbl": "empty"}
    assert "dnsbl_not_queried" not in res.attributes  # under corporate the refusing lists are licence rows, not this line
    http.assert_hosts_within(Dnsbl)
    assert all("edns_client_subnet=0.0.0.0" in u for u in http.urls())


def test_single_spamcop_listing_is_one_low_spam_finding():
    http = FakeHttp()
    add_test_points(http)
    add_dns(http, "9.9.9.9.bl.spamcop.net", "A", ["127.0.0.2"])
    add_dns(http, "9.9.9.9.bl.spamcop.net", "TXT", ["Blocked - see https://www.spamcop.net/bl.shtml?9.9.9.9"])
    add_dns(http, "9.9.9.9.dnsbl.dronebl.org", "A", [], status=3)
    res = run_module(Dnsbl, "ipv4:9.9.9.9", http, allowed_sources=CORPORATE)
    assert res.status is Status.OK
    [finding] = [f for f in res.findings if f.severity >= Severity.LOW]
    assert finding.title == "Listed on DNS blocklists (spam reputation)"
    assert finding.severity is Severity.LOW and finding.tags == ["spam"] and "malicious" not in finding.tags
    assert "listed on 1 of 2 queried lists (SpamCop 127.0.0.2" in finding.description
    assert finding.criterion and finding.source == "spamcop.bl"
    assert res.attributes["blocklist_families"] == ["dnsbl"]  # ONE family vote (P045 c8)
    spamcop = next(r for r in res.attributes["dnsbl_listings"] if r["list"] == "spamcop")
    assert spamcop["txt"].startswith("Blocked - see https://www.spamcop.net/bl.shtml")
    assert ("SpamCop blocking list lookup", "https://www.spamcop.net/bl.shtml?9.9.9.9") in res.links


def test_two_counted_listings_are_medium_never_higher():
    http = FakeHttp()
    add_test_points(http)
    add_dns(http, "112.112.112.149.bl.spamcop.net", "A", ["127.0.0.2"])
    add_dns(http, "112.112.112.149.bl.spamcop.net", "TXT", [])
    add_dns(http, "112.112.112.149.dnsbl.dronebl.org", "A", ["127.0.0.3"])
    res = run_module(Dnsbl, "ipv4:149.112.112.112", http, allowed_sources=CORPORATE)
    [finding] = [f for f in res.findings if f.title.startswith("Listed on")]
    assert finding.severity is Severity.MEDIUM
    assert "listed on 2 of 2 queried lists" in finding.description and "IRC spam drone" in finding.description


def test_failed_test_point_makes_the_list_could_not_verify_for_the_run():
    http = FakeHttp()
    add_dns(http, "2.0.0.127.bl.spamcop.net", "A", [], status=3)  # the test point is not listed: the list cannot be trusted
    doh_answer(http, "2.0.0.127.dnsbl.dronebl.org", "dronebl_test_point_ok.json")
    doh_answer(http, "8.8.8.8.dnsbl.dronebl.org", "dronebl_not_listed.json")
    res = run_module(Dnsbl, "ipv4:8.8.8.8", http, allowed_sources=CORPORATE)  # no route for 8.8.8.8.bl.spamcop.net: never asked
    row = res.source_statuses["spamcop.bl"]
    assert row["status"] in ("blocked", "error") and "test point failed" in row["reason"]
    spamcop = next(r for r in res.attributes["dnsbl_listings"] if r["list"] == "spamcop")
    assert spamcop["state"] == "test_point_failed"
    assert res.attributes["dnsbl_summary"] == "not listed on 1 queried list; could not verify: SpamCop"
    assert res.status is Status.EMPTY


def test_every_list_failing_is_error_never_empty():
    http = FakeHttp()
    for name in ("2.0.0.127.bl.spamcop.net", "2.0.0.127.dnsbl.dronebl.org"):
        add_dns_failure(http, name, "A", kind="servfail")
    res = run_module(Dnsbl, "ipv4:8.8.8.8", http, allowed_sources=CORPORATE)
    assert res.status is Status.ERROR and "could not verify any DNSBL" in res.error
    assert res.attributes["dnsbl_summary"].startswith("could not verify any DNSBL")


def test_429_and_challenge_from_the_resolvers_are_could_not_verify():
    http = FakeHttp()
    for name in ("2.0.0.127.bl.spamcop.net", "2.0.0.127.dnsbl.dronebl.org"):
        add_dns_failure(http, name, "A", kind="http429", provider="all")
    res = run_module(Dnsbl, "ipv4:8.8.8.8", http, allowed_sources=CORPORATE)
    assert res.status.could_not_verify and res.status is not Status.EMPTY
    http2 = FakeHttp()
    for name in ("2.0.0.127.bl.spamcop.net", "2.0.0.127.dnsbl.dronebl.org"):
        add_dns_failure(http2, name, "A", kind="challenge", provider="all")  # a challenge trips the host circuit
    res2 = run_module(Dnsbl, "ipv4:8.8.8.8", http2, allowed_sources=CORPORATE)
    assert res2.status.could_not_verify


def test_dead_network_is_could_not_verify():
    res = run_module(Dnsbl, "ipv4:8.8.8.8", DeadHttp(), allowed_sources=CORPORATE)
    assert res.status is Status.ERROR and "could not verify" in res.error


def test_ipv6_uses_the_nibble_test_point_and_ipv6_zones_only():
    http = FakeHttp()
    doh_answer(http, "2.0.0.0.0.0.f.7.f.f.f.f." + ".".join(["0"] * 20) + ".dnsbl.dronebl.org", "dronebl_test_point_ipv6_ok.json")
    entity = reverse_ip("2606:4700:4700::1111")
    add_dns(http, f"{entity}.dnsbl.dronebl.org", "A", [], status=3)
    res = run_module(Dnsbl, "ipv6:2606:4700:4700::1111", http, allowed_sources=CORPORATE)
    assert res.status is Status.EMPTY
    assert set(res.source_statuses) == {"dronebl.dnsbl"}  # SpamCop has no IPv6 zone
    assert all("spamcop" not in u for u in http.urls())


def test_neighbourhood_listings_are_info_only_and_level1_counts():
    http = FakeHttp()
    add_test_points(http)
    for i in (1, 2, 3):
        doh_answer(http, f"2.0.0.127.dnsbl-{i}.uceprotect.net", f"uceprotect_l{i}_test_point{'_ok' if i == 1 else ''}.json")
    add_dns(http, "1.0.0.1.dnsbl-2.uceprotect.net", "A", ["127.0.0.2"])
    add_dns(http, "1.0.0.1.dnsbl-3.uceprotect.net", "A", ["127.0.0.2"])
    add_nxdomain_everything(http)
    sources = (*CORPORATE, "uceprotect.level1", "uceprotect.level2", "uceprotect.level3")
    res = run_module(Dnsbl, "ipv4:1.0.0.1", http, allowed_sources=sources)
    assert res.status is Status.OK
    assert not [f for f in res.findings if f.severity >= Severity.LOW]  # L2/L3 are never evidence (P045 c7)
    [info] = res.findings
    assert info.title == "DNSBL context listings (no risk)" and info.severity is Severity.INFO and "context_only" in info.tags
    assert "neighbourhood listing" in info.description
    # Level 1 counts
    http2 = FakeHttp()
    add_test_points(http2)
    doh_answer(http2, "2.0.0.127.dnsbl-1.uceprotect.net", "uceprotect_l1_test_point_ok.json")
    add_dns(http2, "1.1.1.1.dnsbl-1.uceprotect.net", "A", ["127.0.0.2"])
    add_nxdomain_everything(http2)
    res2 = run_module(Dnsbl, "ipv4:1.1.1.1", http2, allowed_sources=(*CORPORATE, "uceprotect.level1"))
    [finding] = [f for f in res2.findings if f.title.startswith("Listed on")]
    assert finding.severity is Severity.LOW and "UCEPROTECT L1" in finding.description


def test_lists_refusing_public_resolvers_are_one_coverage_line_and_never_queried():
    http = FakeHttp()
    res = run_module(Dnsbl, "domain:example.com", http, allowed_sources=ALL)
    assert res.status is Status.SKIPPED and res.reason_code == "config"
    line = res.attributes["dnsbl_not_queried"]
    assert line == "Spamhaus DBL, SURBL multi, URIBL multi: not queried through public DoH (needs DQS key/registration)"
    assert res.error == line
    assert http.calls == []  # nothing went to a public resolver (P045 c4)
    http2 = FakeHttp()
    add_test_points(http2)
    add_nxdomain_everything(http2)
    res2 = run_module(Dnsbl, "ipv4:8.8.8.8", http2, allowed_sources=("core_doh.resolvers", "spamcop.bl", "barracuda.brbl", "spamhaus_dqs.zen"))
    assert res2.attributes["dnsbl_not_queried"] == "Spamhaus ZEN, Barracuda BRBL: not queried through public DoH (needs DQS key/registration)"
    assert not any("barracudacentral" in u or "spamhaus" in u for u in http2.urls())


def test_licence_blocked_lists_are_never_queried():
    http = FakeHttp()
    res = run_module(Dnsbl, "ipv4:8.8.8.8", http, allowed_sources=("core_doh.resolvers",))
    assert res.status is Status.SKIPPED and res.reason_code == "licence"
    assert http.calls == []


def test_private_addresses_are_never_sent():
    res = run_module(Dnsbl, "ipv4:10.0.0.1", FakeHttp())
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


# --------------------------------------------------------------------------------------
# keyed zones: system resolver only (P045 c3)
# --------------------------------------------------------------------------------------


@pytest.fixture
def system_resolver(monkeypatch):
    """A fake system resolver (dnspython path): records every name it is asked."""
    asked: list[str] = []
    table: dict[str, DnsAnswer] = {}

    def fake(self, name, rtype):
        asked.append(name)
        if name in table:
            return table[name]
        return DnsAnswer(name, rtype, status="NXDOMAIN", resolver="system")

    monkeypatch.setattr(dns_mod.Resolver, "_system", fake)
    monkeypatch.setattr(mod, "package_available", lambda name: True)
    return asked, table


def answer(name: str, *records: str) -> DnsAnswer:
    return DnsAnswer(name, "A", records=list(records), resolver="system")


def test_keyed_zone_goes_through_the_system_resolver_and_the_key_never_leaks(system_resolver):
    asked, table = system_resolver
    for name, codes in (
        ("2.0.0.127.bl.spamcop.net", ["127.0.0.2"]),
        ("2.0.0.127.dnsbl.dronebl.org", ["127.0.0.1"]),
        (f"2.0.0.127.{DQS_KEY}.zen.dq.spamhaus.net", ["127.0.0.2", "127.0.0.4", "127.0.0.10"]),
        (f"9.9.9.9.{DQS_KEY}.zen.dq.spamhaus.net", ["127.0.0.4"]),
        (f"{HTTPBL_KEY}.1.1.1.127.dnsbl.httpbl.org", ["127.1.1.1"]),
        (f"{HTTPBL_KEY}.9.9.9.9.dnsbl.httpbl.org", ["127.3.40.6"]),
    ):
        table[name] = answer(name, *codes)
    http = FakeHttp()
    sources = (*CORPORATE, "spamhaus_dqs.zen", "projecthoneypot.httpbl")
    res = run_module(Dnsbl, "ipv4:9.9.9.9", http, allowed_sources=sources, settings={"dns_mode": "system"},
                     keys={"spamhaus_dqs": DQS_KEY, "httpbl": HTTPBL_KEY})
    assert http.calls == []  # no DoH at all: the system resolver answered everything
    assert f"9.9.9.9.{DQS_KEY}.zen.dq.spamhaus.net" in asked
    [finding] = [f for f in res.findings if f.title.startswith("Listed on")]
    assert "listed on 2 of 4 queried lists" in finding.description and "XBL" in finding.description
    assert finding.severity is Severity.MEDIUM
    assert res.attributes["httpbl"]["score_band"] == "medium"
    zen = next(r for r in res.attributes["dnsbl_listings"] if r["list"] == "spamhaus_zen")
    assert zen["route"] == "system"
    assert_no_secret(DQS_KEY, res.to_dict(), res.raw, [f.to_dict() for f in res.findings])
    assert_no_secret(HTTPBL_KEY, res.to_dict(), res.raw, [f.to_dict() for f in res.findings])


def test_keyed_zone_resolver_errors_are_redacted(system_resolver):
    asked, table = system_resolver
    name = f"2.0.0.127.{DQS_KEY}.zen.dq.spamhaus.net"
    table[name] = DnsAnswer(name, "A", status="SERVFAIL", error=f"system: All nameservers failed to answer the query {name}. IN A", resolver="system")
    table["2.0.0.127.bl.spamcop.net"] = answer("2.0.0.127.bl.spamcop.net", "127.0.0.2")
    res = run_module(Dnsbl, "ipv4:8.8.4.4", FakeHttp(), allowed_sources=("core_doh.resolvers", "spamcop.bl", "spamhaus_dqs.zen"),
                     settings={"dns_mode": "system"}, keys={"spamhaus_dqs": DQS_KEY})
    row = res.source_statuses["spamhaus_dqs.zen"]
    assert row["status"] == "error" and "test point failed" in row["reason"]
    assert_no_secret(DQS_KEY, res.to_dict(), res.raw)


def test_keyed_zone_without_dnspython_is_unavailable_package(system_resolver, monkeypatch):
    asked, table = system_resolver
    monkeypatch.setattr(mod, "package_available", lambda name: False)
    table["2.0.0.127.bl.spamcop.net"] = answer("2.0.0.127.bl.spamcop.net", "127.0.0.2")
    res = run_module(Dnsbl, "ipv4:9.9.9.10", FakeHttp(), allowed_sources=("core_doh.resolvers", "spamcop.bl", "spamhaus_dqs.zen"),
                     settings={"dns_mode": "system"}, keys={"spamhaus_dqs": DQS_KEY})
    row = res.source_statuses["spamhaus_dqs.zen"]
    assert (row["status"], row["reason_code"]) == ("unavailable", "package")
    assert not any("spamhaus" in name for name in asked)


def test_keyed_zone_is_never_sent_through_public_doh():
    http = FakeHttp()
    add_test_points(http)
    add_nxdomain_everything(http)
    res = run_module(Dnsbl, "ipv4:8.8.8.8", http, allowed_sources=(*CORPORATE, "spamhaus_dqs.zen"), keys={"spamhaus_dqs": DQS_KEY})
    row = res.source_statuses["spamhaus_dqs.zen"]
    assert row["status"] in ("skipped", "unavailable") and "never public DoH" in row["reason"]
    assert not any(DQS_KEY in u for u in http.urls()) and not any("spamhaus" in u for u in http.urls())


def test_registered_list_is_queried_only_through_the_non_public_resolver(system_resolver):
    asked, table = system_resolver
    table["2.0.0.127.b.barracudacentral.org"] = answer("2.0.0.127.b.barracudacentral.org", "127.0.0.2")
    table["4.4.8.8.b.barracudacentral.org"] = answer("4.4.8.8.b.barracudacentral.org", "127.0.0.2")
    res = run_module(Dnsbl, "ipv4:8.8.4.4", FakeHttp(), allowed_sources=("core_doh.resolvers", "barracuda.brbl"),
                     settings={"dns_mode": "system", "dnsbl_registered_lists": ["barracuda"]})
    [finding] = [f for f in res.findings if f.title.startswith("Listed on")]
    assert "Barracuda BRBL" in finding.description and finding.severity is Severity.LOW
    assert "4.4.8.8.b.barracudacentral.org" in asked


def test_domain_with_a_dqs_key_but_without_dnspython_is_unavailable_package(monkeypatch):
    monkeypatch.setattr(mod, "package_available", lambda name: False)
    http = FakeHttp()
    res = run_module(Dnsbl, "domain:example.com", http, allowed_sources=("core_doh.resolvers", "spamhaus_dqs.dbl"),
                     keys={"spamhaus_dqs": DQS_KEY}, settings={"dns_mode": "system"})
    assert res.status is Status.UNAVAILABLE and res.reason_code == "package" and "dnspython" in res.error
    assert http.calls == []
    assert_no_secret(DQS_KEY, res.to_dict())
