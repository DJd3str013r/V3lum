"""passive_dns (P015): per-feed status, pagination, NDJSON robustness, 12-month rule, shared hosting, sinkholes.

Fixtures in tests/fixtures/passive_dns/: recorded mnemonic answers (example.com offset 0 - masked by the
anonymous API - and offset 25, 9.9.9.9 with count 731, the empty object.not.found envelope, the research
limit=2 sample; third-party names scrubbed to alias-NN/cohost-NN example names), recorded Robtex NDJSON
(example.com forward, 18 lines; 1.1.1.1 reverse, first 60 of 200 lines, names scrubbed; the empty answer
'[]'), the real CIRCL 401 page, and derived files: a truncated NDJSON (5 good lines, one malformed, one cut
mid-object), a domain that moved to a known sinkhole (143.215.130.5, core sinkhole list), a dedicated IP
with 3 names (one last seen in 2024), an Argus 429 envelope, a Cloudflare challenge and a synthetic CIRCL
COF answer (documentation values) for the basic-auth header.
"""

from __future__ import annotations

import base64
import json
import re

from tests.fakes import FakeClock, FakeHttp, assert_no_secret, make_runtime, module_fixture, run_module
from v3lum import paths
from v3lum.core import policy
from v3lum.core.context import RunInfo, ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.domain_dns import passive_dns as P
from v3lum.modules.domain_dns.passive_dns import PassiveDns

MN = "https://api.mnemonic.no/pdns/v3/{v}?limit=25&offset={o}"
RB_FWD = "https://freeapi.robtex.com/pdns/forward/{v}"
RB_REV = "https://freeapi.robtex.com/pdns/reverse/{v}"
CIRCL = "https://www.circl.lu/pdns/query/{v}"
USER, PASSWORD = "csirt-team", "circl-pass-0123456789"
DEDICATED_IP = "93.184.215.14"
ALL = {"mnemonic.pdns", "robtex.pdns", "circl.pdns"}


def fx(name):
    return module_fixture(PassiveDns, name)


def raw(name):
    return fx(name) if not name.endswith(".json") else json.dumps(fx(name))


def mnemonic(http, value, offset, fixture, **kw):
    http.add("GET", MN.format(v=value, o=offset), json=fx(fixture), **kw)
    return http


def robtex(http, url, fixture=None, *, body=None, status=200):
    text = body if body is not None else raw(fixture)
    http.add("GET", url, status=status, body=text.encode(), headers={"content-type": "application/x-ndjson"})
    return http


def run(http, entity, *, sources=ALL, **kw):
    res = run_module(PassiveDns, entity, http, allowed_sources=sources, **kw)
    http.assert_hosts_within(PassiveDns)
    return res


# ------------------------------------------------------------------ metadata and the licence gate (c1-c3)
def test_metadata_per_source_terms():
    cls = PassiveDns
    assert cls.terms == "noncommercial" and cls.default_enabled is True and cls.trust_tier == "community"
    assert cls.terms_sources == {"mnemonic.pdns": "license", "robtex.pdns": "noncommercial", "circl.pdns": "license"}
    assert cls.hosts == ("api.mnemonic.no", "freeapi.robtex.com", "www.circl.lu")
    assert cls.optional_keys == ("mnemonic", "circl_pdns_user", "circl_pdns_pass") and cls.max_requests == 6
    assert cls.manual_link == "passive_dns_robtex:robtex_dns_lookup"


def _allow(entries):
    allow = paths.home() / "licence_allow.json"
    allow.write_text(json.dumps({"entries": [{
        "source_id": sid, "basis": "provider_grant", "scope": "own-network defence only", "legal_ref": f"LEGAL-{i}",
        "approver": "legal", "decided_at": "2026-11-01", "review_by": "2027-05-01", "evidence_url": "https://example.com/terms",
        "quote": "permission"} for i, sid in enumerate(entries)]}), encoding="utf-8")
    allow.chmod(0o600)


def test_corporate_profile_skips_every_feed_with_the_robtex_manual_link():
    rt = make_runtime(FakeHttp())
    ent = Entity.make(T.DOMAIN, "example.com")
    decision = policy.decide(PassiveDns, ent, policy.make_context(rt, ScanOptions()), run=RunInfo(entity=ent, is_seed=True))
    assert (decision.allowed, decision.reason_code, decision.emit_manual_link) == (False, "licence", True)
    assert set(decision.blocked_sources) == ALL


def test_legal_can_enable_one_feed_without_the_others():
    _allow(["robtex.pdns"])
    rt = make_runtime(FakeHttp())
    ent = Entity.make(T.DOMAIN, "example.com")
    decision = policy.decide(PassiveDns, ent, policy.make_context(rt, ScanOptions()), run=RunInfo(entity=ent, is_seed=True))
    assert decision.allowed and set(decision.allowed_sources) == {"robtex.pdns"}


def test_skipped_robtex_emits_its_web_page_and_is_never_queried():
    http = mnemonic(FakeHttp(), "example.com", 0, "mnemonic_empty.json")
    res = run(http, "domain:example.com", sources={"mnemonic.pdns"})
    assert res.status is Status.EMPTY
    assert ("Robtex lookup (manual: automation skipped)", "https://www.robtex.com/dns-lookup/example.com") in res.links
    assert not [u for u in http.urls() if "robtex" in u]
    ip = mnemonic(FakeHttp(), "9.9.9.9", 0, "mnemonic_ip_9_9_9_9.json")
    res_ip = run(ip, "ipv4:9.9.9.9", sources={"mnemonic.pdns"})
    assert ("Robtex lookup (manual: automation skipped)", "https://www.robtex.com/ip-lookup/9.9.9.9") in res_ip.links


# ------------------------------------------------------------------ domain: merge, 12-month rule, uncertain Robtex times (c6)
def test_domain_history_merges_feeds_and_keeps_first_last_seen_per_source():
    http = mnemonic(FakeHttp(), "example.com", 0, "mnemonic_domain_masked.json")
    mnemonic(http, "example.com", 25, "mnemonic_domain_page2.json")
    robtex(http, RB_FWD.format(v="example.com"), "robtex_forward_ok.ndjson")
    res = run(http, "domain:example.com")
    assert res.status is Status.OK
    st = res.source_statuses
    assert st["mnemonic.pdns"]["status"] == "ok" and st["robtex.pdns"]["status"] == "ok" and st["circl.pdns"]["status"] == "needs_key"
    assert res.attributes["pdns_summary"].startswith("resolved to ") and "IPs since 2009-07-04" in res.attributes["pdns_summary"]
    table = res.attributes["passive_dns"]
    assert len(table) <= P.TABLE_ROWS and all({"first_seen", "last_seen", "sources", "historical"} <= set(row) for row in table)
    lasts = [row["last_seen"] or "" for row in table]
    assert lasts == sorted(lasts, reverse=True)  # ordered by last_seen
    both = [row for row in res.raw["records"] if row["address"] == "104.20.23.154"]
    assert both and both[0]["sources"] == ["mnemonic", "robtex"]
    # the 2009 address known only to Robtex has an uncertain last_seen (uniform time_last): never current, no pivot
    old = [row for row in res.raw["records"] if row["address"] == "208.77.188.166"][0]
    assert old["historical"] is None and old["last_seen_uncertain"] is True
    resolved = {p.entity.value for p in res.pivots if p.relation == "resolves_to"}
    assert "208.77.188.166" not in resolved and "93.184.216.34" not in resolved
    assert "104.20.23.154" in resolved and "172.66.147.243" in resolved
    assert res.attributes["names_pointing_here"] >= 2  # PTR/alias names answering example.com: counted, never pivoted
    assert res.raw["sources"]["mnemonic"]["masked"] > 0  # anonymous offset-0 page: approximate times flagged
    counts = res.attributes["pdns_record_count"]
    assert counts["provider_total"] == 997 and counts["kept"] <= P.RECORD_CAP


def test_records_last_seen_more_than_12_months_ago_are_historical_and_never_pivot():
    body = "\n".join(json.dumps(r) for r in [
        {"rrname": "old.example.net", "rrdata": "192.0.2.50", "rrtype": "A", "time_first": 1600000000, "time_last": 1700000000, "count": 3},
        {"rrname": "old.example.net", "rrdata": "198.51.100.60", "rrtype": "A", "time_first": 1790000000, "time_last": 1795000000, "count": 2},
        {"rrname": "old.example.net", "rrdata": "ns1.example.org", "rrtype": "NS", "time_first": 1600000000, "time_last": 1650000000, "count": 2},
    ]) + "\n"
    http = robtex(FakeHttp(), RB_FWD.format(v="old.example.net"), body=body)
    res = run(http, "domain:old.example.net", sources={"robtex.pdns"})
    rows = {row["address"]: row for row in res.raw["records"]}
    assert rows["192.0.2.50"]["historical"] is True and rows["198.51.100.60"]["historical"] is False
    assert {(p.entity.value, p.relation) for p in res.pivots} == {("198.51.100.60", "resolves_to")}
    assert res.attributes["pdns_record_count"]["historical"] == 2


def test_current_ns_mx_cname_targets_are_weak_pivots():
    body = "\n".join(json.dumps(r) for r in [
        {"rrname": "shop.example.net", "rrdata": "ns1.example.org.", "rrtype": "NS", "time_first": 1790000000, "time_last": 1795000000},
        {"rrname": "shop.example.net", "rrdata": "10 mx.example.org.", "rrtype": "MX", "time_first": 1790000000, "time_last": 1794000000},
        {"rrname": "shop.example.net", "rrdata": "edge.example.com.", "rrtype": "CNAME", "time_first": 1791000000, "time_last": 1793000000},
    ]) + "\n"
    http = robtex(FakeHttp(), RB_FWD.format(v="shop.example.net"), body=body)
    res = run(http, "domain:shop.example.net", sources={"robtex.pdns"})
    assert {(p.entity.value, p.relation, p.expand) for p in res.pivots} == {
        ("ns1.example.org", "nameserver", False), ("mx.example.org", "mx_host", False), ("edge.example.com", "cname_to", False)}


# ------------------------------------------------------------------ c4: mnemonic pagination
def test_mnemonic_pagination_limit_25_offsets_and_cap():
    http = mnemonic(FakeHttp(), "example.com", 0, "mnemonic_domain_masked.json")
    for offset in (25, 50, 75):
        mnemonic(http, "example.com", offset, "mnemonic_domain_page2.json")
    res = run(http, "domain:example.com", sources={"mnemonic.pdns"}, options=ScanOptions(preset="deep"))
    urls = [u for u in http.urls() if "mnemonic" in u]
    assert urls == [MN.format(v="example.com", o=o) for o in (0, 25, 50, 75)]  # 4 pages at most (count is 997)
    assert res.raw["sources"]["mnemonic"]["pages"] == 4
    default = mnemonic(FakeHttp(), "example.com", 0, "mnemonic_domain_masked.json")
    mnemonic(default, "example.com", 25, "mnemonic_domain_page2.json")
    run(default, "domain:example.com", sources={"mnemonic.pdns"})
    assert len(default.calls) == 2  # default setting: two pages
    one = mnemonic(FakeHttp(), "example.com", 0, "mnemonic_domain_masked.json")
    run(one, "domain:example.com", sources={"mnemonic.pdns"}, settings={"passive_dns_mnemonic_pages": 1})
    assert len(one.calls) == 1


def test_short_pages_and_a_low_run_budget_stop_the_pagination():
    small = mnemonic(FakeHttp(), "example.com", 0, "mnemonic_limit2_recorded.json")
    run(small, "domain:example.com", sources={"mnemonic.pdns"}, options=ScanOptions(preset="deep"))
    assert len(small.calls) == 1  # fewer than 25 records: last page
    clock = FakeClock()
    slow = FakeHttp(clock=clock)
    mnemonic(slow, "example.com", 0, "mnemonic_domain_masked.json", latency=35.0)
    res = run(slow, "domain:example.com", sources={"mnemonic.pdns"}, options=ScanOptions(preset="deep"), clock=clock)
    assert len(slow.calls) == 1 and res.raw["sources"]["mnemonic"]["stopped"] == "run budget"


def test_mnemonic_key_goes_only_into_the_header():
    key = "mnemonic-key-0123456789abcdef"
    http = FakeHttp().add("GET", MN.format(v="example.com", o=0), json=fx("mnemonic_empty.json"), match_headers={"Argus-API-Key": key})
    res = run(http, "domain:example.com", sources={"mnemonic.pdns"}, keys={"mnemonic": key})
    assert res.status is Status.EMPTY and all(key not in u for u in http.urls())
    assert_no_secret(key, res.to_dict(), res.raw)


# ------------------------------------------------------------------ c4: Robtex NDJSON robustness
def test_robtex_ndjson_with_malformed_and_truncated_lines():
    http = robtex(FakeHttp(), RB_FWD.format(v="example.com"), "robtex_forward_truncated.ndjson")
    res = run(http, "domain:example.com", sources={"robtex.pdns"})
    info = res.raw["sources"]["robtex"]
    assert info["records"] == 5 and info["malformed"] == 2 and info["truncated_tail"] is True
    assert res.source_statuses["robtex.pdns"]["status"] == "ok" and "malformed" in res.source_statuses["robtex.pdns"]["reason"]
    assert P.parse_cof(b'{"rrname": "a.example.com"', "robtex")["truncated_tail"] is True


def test_empty_answers_are_empty_and_failures_never_are():
    http = mnemonic(FakeHttp(), "nothing.example.com", 0, "mnemonic_empty.json")
    robtex(http, RB_FWD.format(v="nothing.example.com"), "robtex_forward_empty.json")
    res = run(http, "domain:nothing.example.com", sources={"mnemonic.pdns", "robtex.pdns"})
    assert res.status is Status.EMPTY and res.source_statuses["robtex.pdns"]["status"] == "empty"
    fails = FakeHttp().add("GET", MN.format(v="example.com", o=0), json=fx("mnemonic_rate_limited_derived.json"))
    robtex(fails, RB_FWD.format(v="example.com"), "robtex_challenge_derived.html", status=403)
    res2 = run(fails, "domain:example.com")
    assert res2.status is Status.RATE_LIMITED  # nothing answered: could not verify, never EMPTY
    st = res2.source_statuses
    assert st["mnemonic.pdns"]["status"] == "rate_limited" and st["robtex.pdns"]["status"] == "blocked"
    assert st["circl.pdns"]["status"] == "needs_key"
    broken = FakeHttp().add("GET", MN.format(v="example.com", o=0), body=b'{"data": [', headers={"content-type": "application/json"})
    assert run(broken, "domain:example.com", sources={"mnemonic.pdns"}).status is Status.ERROR


def test_robtex_reverse_timeout_is_could_not_verify():
    from v3lum.core.http import NetworkError

    http = FakeHttp().add("GET", RB_REV.format(v=DEDICATED_IP), error=NetworkError("ReadTimeout contacting freeapi.robtex.com: timed out"))
    res = run(http, f"ipv4:{DEDICATED_IP}", sources={"robtex.pdns"})
    assert res.status is Status.ERROR and res.source_statuses["robtex.pdns"]["reason_code"] == "timeout"


# ------------------------------------------------------------------ c7: shared hosting counts, dedicated IP pivots
def test_shared_or_cdn_ips_are_counts_only():
    http = robtex(FakeHttp(), RB_REV.format(v="1.1.1.1"), "robtex_reverse_shared.ndjson")
    res = run(http, "ipv4:1.1.1.1", sources={"robtex.pdns"})
    co = res.attributes["cohosting"]
    assert co["mode"] == "count_only" and co["exclude_from_shared_infra"] is True and co["count"] == 60
    assert res.pivots == [] and res.attributes["shared_ip"] is True
    quad9 = mnemonic(FakeHttp(), "9.9.9.9", 0, "mnemonic_ip_9_9_9_9.json")
    res9 = run(quad9, "ipv4:9.9.9.9", sources={"mnemonic.pdns"}, settings={"passive_dns_mnemonic_pages": 1})
    assert res9.attributes["cohosting"]["mode"] == "count_only" and res9.attributes["cohosting"]["count"] == 731
    assert "mnemonic reports 731 records" in res9.attributes["pdns_summary"] and res9.pivots == []


def test_dedicated_ip_current_names_become_hosted_domain_pivots():
    http = robtex(FakeHttp(), RB_REV.format(v=DEDICATED_IP), "robtex_reverse_dedicated_derived.ndjson")
    res = run(http, f"ipv4:{DEDICATED_IP}", sources={"robtex.pdns"})
    hosted = {(p.entity.value, p.expand) for p in res.pivots if p.relation == "hosted_domain"}
    assert hosted == {("login-portal.example.net", True), ("secure-update.example.org", True)}  # the 2024 name is historical
    assert res.attributes["cohosting"]["mode"] == "pivot" and res.attributes["pdns_summary"].startswith("3 names seen on this IP")


def test_dedicated_ip_expands_only_the_ten_most_recent_names():
    rows = [{"rrname": f"site-{i:02d}.example.com", "rrdata": DEDICATED_IP, "rrtype": "A", "time_first": 1790000000 + i,
             "time_last": 1795000000 + i, "count": 1} for i in range(30)]
    http = robtex(FakeHttp(), RB_REV.format(v=DEDICATED_IP), body="\n".join(json.dumps(r) for r in rows) + "\n")
    res = run(http, f"ipv4:{DEDICATED_IP}", sources={"robtex.pdns"})
    expanded = [p.entity.value for p in res.pivots if p.expand]
    assert len(res.pivots) == 30 and len(expanded) == P.EXPAND_COHOSTED and "site-29.example.com" in expanded


# ------------------------------------------------------------------ c8: sinkhole tag, caps
def test_resolution_to_a_known_sinkhole_tags_the_domain_and_never_pivots():
    http = robtex(FakeHttp(), RB_FWD.format(v="bad.example.net"), "robtex_forward_sinkholed_derived.ndjson")
    res = run(http, "domain:bad.example.net", sources={"robtex.pdns"})
    sink = res.attributes["sinkholed"]
    assert sink["current"] is True and sink["ips"] == ["143.215.130.5"] and sink["since"] == "2026-11-06"
    finding = [f for f in res.findings if f.title == "Domain resolved to a known sinkhole"][0]
    assert "sinkhole" in finding.tags and finding.severity.label.lower() == "info"
    resolved = {p.entity.value for p in res.pivots if p.relation == "resolves_to"}
    assert resolved == {"203.0.113.7"}  # the pre-sinkhole address pivots, the sinkhole never does


def test_cap_200_records_and_a_20_row_table():
    rows = [{"rrname": "busy.example.net", "rrdata": f"198.51.100.{i % 250}", "rrtype": "A", "time_first": 1790000000 + i,
             "time_last": 1795000000 + i} for i in range(250)]
    rows += [{"rrname": "busy.example.net", "rrdata": f"192.0.2.{i}", "rrtype": "A", "time_first": 1790000000, "time_last": 1794000000 - i}
             for i in range(10)]
    http = robtex(FakeHttp(), RB_FWD.format(v="busy.example.net"), body="\n".join(json.dumps(r) for r in rows) + "\n")
    res = run(http, "domain:busy.example.net", sources={"robtex.pdns"})
    counts = res.attributes["pdns_record_count"]
    assert counts["total"] == 260 and counts["kept"] == 200 and res.raw["capped"] is True
    assert len(res.attributes["passive_dns"]) == 20 and len(res.raw["records"]) == 200


# ------------------------------------------------------------------ c5: CIRCL basic auth, export restriction
def test_circl_credentials_only_in_the_authorization_header():
    token = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
    http = FakeHttp().add("GET", CIRCL.format(v="www.example.com"), body=fx("circl_cof_synthetic.ndjson").encode(),
                          headers={"content-type": "application/x-ndjson"}, match_headers={"Authorization": token})
    res = run(http, "domain:www.example.com", sources={"circl.pdns"}, keys={"circl_pdns_user": USER, "circl_pdns_pass": PASSWORD})
    assert res.status is Status.OK and res.source_statuses["circl.pdns"]["status"] == "ok"
    assert all(USER not in u and PASSWORD not in u for u in http.urls())  # never in a URL
    rows = {row["address"]: row for row in res.raw["records"]}
    assert rows["192.0.2.10"]["export_restricted"] is True and rows["2001:db8::10"]["record_type"] == "AAAA"
    assert res.tlp == "amber"  # CIRCL TLP/handling rules: not exported outside the team
    assert_no_secret(PASSWORD, res.to_dict(), res.raw)


def test_circl_refusal_is_needs_key_for_that_feed_only():
    http = FakeHttp().add("GET", CIRCL.format(v="example.com"), status=401, text=fx("circl_unauthorized.html"),
                          headers={"www-authenticate": 'Basic realm="Access to CIRCL Passive DNS"'})
    robtex(http, RB_FWD.format(v="example.com"), "robtex_forward_ok.ndjson")
    res = run(http, "domain:example.com", sources={"circl.pdns", "robtex.pdns"}, keys={"circl_pdns_user": USER, "circl_pdns_pass": PASSWORD})
    assert res.status is Status.OK and res.source_statuses["circl.pdns"]["status"] == "needs_key"
    assert res.tlp in ("", None)  # nothing came from CIRCL


def test_basic_auth_refuses_unsafe_credentials():
    import pytest

    for user, password in (("", "x"), ("a:b", "c"), ("user", "pa\nss")):
        with pytest.raises(ValueError):
            P.basic_auth(user, password)


def test_parsers_tolerate_junk():
    assert P.parse_mnemonic(b"<html>")["state"] == "error"
    assert P.parse_mnemonic({"data": [{"query": None, "answer": None}]})["state"] == "error"
    out = P.parse_cof(b'[1, {"rrname": "x.example.com", "rrdata": ["192.0.2.1", 7], "rrtype": "A"}]', "circl")
    assert len(out["records"]) == 1 and out["malformed"] == 2
    assert re.match(r"^\d{4}-\d{2}-\d{2}T", P.iso(1795000000))


# ------------------------------------------------------------------ AR21 golden-path routes (section 19)
def test_acceptance_routes_are_empty_because_the_default_profile_skips_every_feed():
    """tests/fixtures/acceptance/{domain,ipv4}/passive_dns.json hold no route: under the default corporate
    profile every feed is licence-skipped (P015 c2-c3), so a default scan of the golden inputs sends nothing."""
    from tests.fakes import fixture

    rt = make_runtime(FakeHttp())
    for etype, value in (("domain", "example.com"), ("ipv4", "8.8.8.8")):
        doc = fixture(f"acceptance/{etype}/passive_dns.json")
        assert (doc["schema"], doc["module"], doc["routes"]) == ("v3lum.acceptance_routes/1", "passive_dns", [])
        ent = Entity.make(T(etype), value)
        decision = policy.decide(PassiveDns, ent, policy.make_context(rt, ScanOptions()), run=RunInfo(entity=ent, is_seed=True))
        assert (decision.allowed, decision.reason_code) == (False, "licence")
