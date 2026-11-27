"""asn_context (P033): PeeringDB, CIRCL BGP Ranking and Shadowserver with one status per source.

Fixtures in tests/fixtures/asn_context/ are trimmed real answers recorded on 2026-11-25/26 from a
datacenter egress: PeeringDB net AS22548 (NIC.br, depth=2; the poc_set values were replaced by
documentation values so the drop can be asserted) and AS13335 (Cloudflare, trimmed lists), org 1245
(address fields replaced by placeholders), the 404 'Entity not found' answer and a company-name search
for 'Google'; CIRCL /json/asn for AS15169, AS13335, the reserved AS64496 and an invalid query (error in
200), /ipasn_history for 8.8.8.8 and for an unannounced address; Shadowserver origin/prefix answers.
``peeringdb_throttled_429.json`` is the real anonymous-throttle answer (HTTP 429, Retry-After 3514) PeeringDB
returned to this egress on 2026-11-26.
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import FIXTURES, FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.ip_network.asn_context import (
    CIRCL_API,
    SRC_CIRCL,
    SRC_PDB,
    SRC_SS,
    AsnContext,
    circl_percentile,
    peeringdb_net_url,
    peeringdb_org_url,
    peeringdb_search_url,
    rank_text,
    shadowserver_origin_url,
    shadowserver_prefix_url,
)

RANK_URL = f"{CIRCL_API}/json/asn"
CHALLENGE = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body><div id=\"cf-chl-widget\"></div></body></html>"


def fx(name):
    return module_fixture("asn_context", name)


def rank_for(asn, name="circl_asn_15169_ok.json"):
    body = fx(name)
    body["meta"] = {"asn": str(asn)}
    return body


def nicbr_http():
    return (FakeHttp()
            .add("GET", peeringdb_net_url(22548), json=fx("peeringdb_net_22548_ok.json"))
            .add("GET", peeringdb_org_url(1245), json=fx("peeringdb_org_1245_ok.json"))
            .add("GET", shadowserver_prefix_url(22548), json=fx("shadowserver_prefix_22548_ok.json"))
            .add("POST", RANK_URL, json=rank_for(22548)))


def google_ip_http():
    return (FakeHttp()
            .add("GET", shadowserver_origin_url("8.8.8.8"), json=fx("shadowserver_origin_8.8.8.8_ok.json"))
            .add("GET", f"{CIRCL_API}/ipasn_history/?ip=8.8.8.8", json=fx("circl_ipasn_8.8.8.8_ok.json"))
            .add("GET", peeringdb_net_url(15169), status=404, json=fx("peeringdb_net_not_found_404.json"))
            .add("POST", RANK_URL, json=fx("circl_asn_15169_ok.json")))


def statuses(res):
    return {sid: row["status"] for sid, row in res.source_statuses.items()}


# ------------------------------------------------------------------ ASN input (c2, c3, c4, c5)
def test_asn_operator_network_type_ixps_and_prefixes():
    http = nicbr_http()
    res = run_module(AsnContext, "asn:AS22548", http)
    assert res.status is Status.OK
    net = res.attributes["peeringdb_network"]
    assert net["operator"] == "NIC.br" and net["name"] == "NIC.BR" and net["info_type"] == "Non-Profit"
    assert net["network_class"] == "non_profit" and net["policy"]["general"] == "Open"
    assert [i["ix_br"] for i in net["ixps"]] == [True, True] and net["ix_count"] == 2
    assert res.attributes["as_org"] == "NIC.br"
    assert "network_type" not in res.attributes  # non-profit has no eyeball/hosting/transit mapping
    assert res.attributes["announced_prefixes"] == ["200.160.0.0/20"]
    assert res.attributes["announced_prefix_counts"]["total"] == 1
    org = {(p.entity.type, p.entity.value): p for p in res.pivots}[(T.ORG, "NIC.br")]
    assert org.relation == "operated_by" and org.expand is False
    assert statuses(res) == {SRC_PDB: "ok", SRC_CIRCL: "ok", SRC_SS: "ok"}
    assert "PeeringDB" in res.attributes["data_attribution"]
    http.assert_hosts_within(AsnContext)
    assert "transform.shadowserver.org" not in AsnContext.hosts  # c6: report ingestion is out of scope


def test_peeringdb_contacts_are_dropped_at_ingestion():
    res = run_module(AsnContext, "asn:AS22548", nicbr_http())
    net = res.attributes["peeringdb_network"]
    assert net["poc_roles"] == ["NOC"] and net["dropped_contacts"] == 1
    blob = json.dumps([res.to_dict(), res.raw, [f.to_dict() for f in res.findings]], default=str)
    for value in ("noc-desk@example.com", "+55 11 5555-0101", "Example NOC Desk", "https://www.example.com/noc", "Example Street 100"):
        assert value not in blob, value


def test_large_network_lists_are_capped_and_flagged_truncated():
    http = (FakeHttp()
            .add("GET", peeringdb_net_url(13335), json=fx("peeringdb_net_13335_large.json"))
            .add("GET", peeringdb_org_url(4715), status=404, json=fx("peeringdb_net_not_found_404.json"))
            .add("GET", shadowserver_prefix_url(13335), json=fx("shadowserver_prefix_empty.json"))
            .add("POST", RANK_URL, json=fx("circl_asn_13335_ok.json")))
    res = run_module(AsnContext, "asn:AS13335", http)
    net = res.attributes["peeringdb_network"]
    assert net["truncated"] == {"ixps": True, "facilities": True}  # ix_count 357 / fac_count 223 vs the trimmed lists
    assert net["operator"] == "Cloudflare"  # the org answered 404: the network name stands in
    assert res.attributes["network_type"] == "hosting"
    assert res.attributes["bgp_ranking"]["percentile"] == circl_percentile(5965, 14180)
    assert statuses(res)[SRC_SS] == "empty"


def test_circl_rank_is_context_only_info_never_a_vote():
    res = run_module(AsnContext, "asn:AS22548", nicbr_http())
    rank = res.attributes["bgp_ranking"]
    assert rank["percentile"] == 13.0 and rank["position"] == 4344 and rank["total_known_asns"] == 4993
    assert rank["text"] == "rank 13.0 (higher = more malicious activity observed; position 4344 of 4993 ranked ASNs)"
    assert rank["checked_on"] == "2026-11-26"
    finding = next(f for f in res.findings if f.source == SRC_CIRCL)
    assert finding.severity.label == "info" and "context_only" in finding.tags
    assert not ({"malicious", "suspicious", "spam", "botnet"} & set(finding.tags))
    assert "Large clouds" in finding.description
    assert all(f.severity.label == "info" for f in res.findings)
    sent = [c for c in nicbr_http().calls]  # untouched: a fresh FakeHttp records nothing
    assert sent == []


def test_circl_request_body_names_the_asn():
    http = nicbr_http()
    run_module(AsnContext, "asn:AS22548", http)
    post = next(c for c in http.calls if c["method"] == "POST")
    assert json.loads(post["body"]) == {"asn": "22548"}


def test_rank_helpers():
    assert circl_percentile(1, 100) == 100.0 and circl_percentile(100, 100) == 1.0
    assert circl_percentile(None, 100) is None and circl_percentile(101, 100) is None
    assert rank_text(None).startswith("not ranked")


# ------------------------------------------------------------------ IPv4 input
def test_ip_origin_history_and_rank_without_company_pivot():
    http = google_ip_http()
    res = run_module(AsnContext, "ipv4:8.8.8.8", http)
    assert res.status is Status.OK
    assert res.attributes["asn"] == "AS15169" and res.attributes["as_org"] == "Google LLC"
    assert res.attributes["prefix"] == "8.8.8.0/24"
    assert res.attributes["ipasn_history"][0] == {"date": "2026-11-24T22:00:00", "asn": "AS15169", "prefix": "8.8.8.0/24", "source": "caida"}
    assert res.attributes["bgp_ranking"]["asn"] == "AS15169"
    assert not res.pivots  # the AS operator is the network provider, not the user of the address
    assert statuses(res) == {SRC_PDB: "empty", SRC_CIRCL: "ok", SRC_SS: "ok"}
    assert res.source_statuses[SRC_PDB]["reason"] == "no PeeringDB record for AS15169"


def test_ip_not_announced_anywhere_is_empty():
    http = (FakeHttp()
            .add("GET", shadowserver_origin_url("8.8.4.4"), json=[{"ip": "8.8.4.4"}])
            .add("GET", f"{CIRCL_API}/ipasn_history/?ip=8.8.4.4", json=fx("circl_ipasn_not_announced.json")))
    res = run_module(AsnContext, "ipv4:8.8.4.4", http)
    assert res.status is Status.EMPTY
    assert statuses(res) == {SRC_CIRCL: "empty", SRC_SS: "empty"}


def test_shadowserver_echo_of_another_query_is_error_in_200():
    http = (FakeHttp()
            .add("GET", shadowserver_origin_url("8.8.4.4"), json=fx("shadowserver_origin_error_in_200.json"))
            .add("GET", f"{CIRCL_API}/ipasn_history/?ip=8.8.4.4", json=fx("circl_ipasn_not_announced.json")))
    res = run_module(AsnContext, "ipv4:8.8.4.4", http)
    assert res.status is Status.EMPTY  # CIRCL answered (not announced); Shadowserver could not verify
    assert res.source_statuses[SRC_SS]["status"] == "error" and "could not verify" in res.source_statuses[SRC_SS]["reason"]


def test_private_ip_and_reserved_asn_are_never_queried():
    http = FakeHttp()
    for value in ("ipv4:10.0.0.1", "ipv4:192.0.2.1", "asn:AS64496", "asn:AS0", "asn:AS4200000001"):
        res = run_module(AsnContext, value, http)
        assert res.status is Status.SKIPPED and res.reason_code == "not_applicable", value
    assert http.calls == []


# ------------------------------------------------------------------ company name input
def test_company_name_lists_candidate_asns_without_expansion():
    http = FakeHttp().add("GET", peeringdb_search_url("Google"), json=fx("peeringdb_search_google_ok.json"))
    res = run_module(AsnContext, "company_name:Google", http)
    assert res.status is Status.OK
    asns = {p.entity.value: p for p in res.pivots if p.entity.type is T.ASN}
    assert set(asns) == {"AS15169", "AS19527", "AS36040"}
    assert all(p.relation == "asn_candidate" and p.expand is False and p.confidence_label.value == "possible" for p in asns.values())
    assert res.attributes["network_candidates"]["confidence"] == "possible"


def test_company_name_without_match_is_empty():
    http = FakeHttp().add("GET", peeringdb_search_url("Nonexistent Example"), json={"data": [], "meta": {}})
    assert run_module(AsnContext, "company_name:Nonexistent Example", http).status is Status.EMPTY


# ------------------------------------------------------------------ c1: one status per source
def test_throttled_peeringdb_does_not_hide_the_other_sources():
    http = (FakeHttp()
            .add("GET", peeringdb_net_url(22548), status=429, json=fx("peeringdb_throttled_429.json"))
            .add("GET", shadowserver_prefix_url(22548), json=fx("shadowserver_prefix_22548_ok.json"))
            .add("POST", RANK_URL, json=rank_for(22548)))
    res = run_module(AsnContext, "asn:AS22548", http)
    assert res.status is Status.OK
    assert statuses(res) == {SRC_PDB: "rate_limited", SRC_CIRCL: "ok", SRC_SS: "ok"}
    assert "peeringdb_network" not in res.attributes and res.attributes["bgp_ranking"]["percentile"] == 13.0


def test_every_source_failing_takes_the_first_failure():
    http = (FakeHttp()
            .add("GET", peeringdb_net_url(22548), status=429, json=fx("peeringdb_throttled_429.json"))
            .add("GET", shadowserver_prefix_url(22548), status=503, text="unavailable", times=5)
            .add("POST", RANK_URL, status=503, text="unavailable", times=5))
    res = run_module(AsnContext, "asn:AS22548", http)
    assert res.status is Status.RATE_LIMITED and "more source(s) could not verify" in res.error
    assert statuses(res) == {SRC_PDB: "rate_limited", SRC_CIRCL: "error", SRC_SS: "error"}


def test_circl_error_in_200_is_that_source_only():
    http = (FakeHttp()
            .add("GET", peeringdb_net_url(22548), json=fx("peeringdb_net_22548_ok.json"))
            .add("GET", peeringdb_org_url(1245), json=fx("peeringdb_org_1245_ok.json"))
            .add("GET", shadowserver_prefix_url(22548), json=fx("shadowserver_prefix_22548_ok.json"))
            .add("POST", RANK_URL, json=fx("circl_asn_error_in_200.json")))
    res = run_module(AsnContext, "asn:AS22548", http)
    assert res.status is Status.OK and statuses(res)[SRC_CIRCL] == "error"
    assert "bgp_ranking" not in res.attributes


def test_reserved_or_unranked_asn_answer_is_empty_for_circl():
    http = (FakeHttp()
            .add("GET", peeringdb_net_url(22548), status=404, json=fx("peeringdb_net_not_found_404.json"))
            .add("GET", shadowserver_prefix_url(22548), json=fx("shadowserver_prefix_empty.json"))
            .add("POST", RANK_URL, json=rank_for(22548, "circl_asn_64496_not_ranked.json")))
    res = run_module(AsnContext, "asn:AS22548", http)
    assert res.status is Status.EMPTY
    assert statuses(res) == {SRC_PDB: "empty", SRC_CIRCL: "empty", SRC_SS: "empty"}


def test_challenge_and_malformed_answers_are_could_not_verify():
    http = (FakeHttp()
            .add("GET", peeringdb_net_url(22548), json=fx("peeringdb_net_22548_ok.json"))
            .add("GET", peeringdb_org_url(1245), json=fx("peeringdb_org_1245_ok.json"))
            .add("GET", shadowserver_prefix_url(22548), text="{not json", headers={"content-type": "application/json"})
            .add("POST", RANK_URL, status=403, text=CHALLENGE))
    res = run_module(AsnContext, "asn:AS22548", http)
    assert res.status is Status.OK
    assert statuses(res)[SRC_CIRCL] == "blocked" and statuses(res)[SRC_SS] == "error"


def test_org_lookup_failure_keeps_the_network_record():
    http = (FakeHttp()
            .add("GET", peeringdb_net_url(22548), json=fx("peeringdb_net_22548_ok.json"))
            .add("GET", peeringdb_org_url(1245), status=503, text="unavailable", times=5)
            .add("GET", shadowserver_prefix_url(22548), json=fx("shadowserver_prefix_22548_ok.json"))
            .add("POST", RANK_URL, json=rank_for(22548)))
    res = run_module(AsnContext, "asn:AS22548", http)
    assert res.attributes["peeringdb_network"]["operator"] == "NIC.BR"
    assert statuses(res)[SRC_PDB] == "ok" and "could not verify" in res.source_statuses[SRC_PDB]["reason"]


# ------------------------------------------------------------------ c2: optional key, header only
def test_peeringdb_key_travels_only_in_the_authorization_header():
    key = "peeringdb-test-key-0123456789"
    http = nicbr_http()
    run_module(AsnContext, "asn:AS22548", http, keys={"peeringdb": key})
    pdb = [c for c in http.calls if "peeringdb.com" in c["url"]]
    assert pdb and all(key not in c["url"] for c in pdb)
    assert all(c["headers"].get("Authorization") == f"Api-Key {key}" for c in pdb)
    others = [c for c in http.calls if "peeringdb.com" not in c["url"]]
    assert all("Authorization" not in c["headers"] for c in others)


@pytest.mark.parametrize("keyed,expected", [(True, "needs_key"), (False, "blocked")])
def test_peeringdb_403_is_needs_key_when_keyed_else_blocked(keyed, expected):
    http = (FakeHttp()
            .add("GET", peeringdb_net_url(22548), status=403, json={"detail": "Invalid API key"})
            .add("GET", shadowserver_prefix_url(22548), json=fx("shadowserver_prefix_22548_ok.json"))
            .add("POST", RANK_URL, json=rank_for(22548)))
    keys = {"peeringdb": "peeringdb-test-key-0123456789"} if keyed else None
    res = run_module(AsnContext, "asn:AS22548", http, keys=keys)
    assert res.status is Status.OK and statuses(res)[SRC_PDB] == expected


# ------------------------------------------------------------------ licence gate: aggregators query allowed sources only
def test_only_allowed_sources_are_queried():
    http = FakeHttp().add("POST", RANK_URL, json=rank_for(22548))
    res = run_module(AsnContext, "asn:AS22548", http, allowed_sources={SRC_CIRCL})
    assert res.status is Status.OK and set(statuses(res)) == {SRC_CIRCL}
    assert {c["url"] for c in http.calls} == {RANK_URL}


# ------------------------------------------------------------------ offline mode: could not verify, never empty
def test_offline_mode_is_unavailable_per_source_never_empty():
    res = run_module(AsnContext, "asn:AS22548", runtime=make_runtime(FakeHttp(), offline=True))
    assert res.status is Status.UNAVAILABLE and res.reason_code == "offline"
    assert set(statuses(res).values()) == {"unavailable"}


def test_peeringdb_throttle_inside_http_200_is_rate_limited_for_that_source():
    http = (FakeHttp()
            .add("GET", peeringdb_net_url(22548), json=fx("peeringdb_throttled_429.json"))
            .add("GET", shadowserver_prefix_url(22548), json=fx("shadowserver_prefix_22548_ok.json"))
            .add("POST", RANK_URL, json=rank_for(22548)))
    res = run_module(AsnContext, "asn:AS22548", http)
    assert res.status is Status.OK and statuses(res)[SRC_PDB] == "rate_limited"


def _replay(etype, module):
    """FakeHttp with the AR21 golden-path routes of tests/fixtures/acceptance/<etype>/<module>.json."""
    import base64

    doc = json.loads((FIXTURES / "acceptance" / etype / f"{module}.json").read_text(encoding="utf-8"))
    assert doc["schema"] == "v3lum.acceptance_routes/1" and doc["module"] == module
    http = FakeHttp()
    for route in doc["routes"]:
        if "json" in route:
            body = {"json": route["json"]}
        elif "body_b64" in route:
            body = {"body": base64.b64decode(route["body_b64"])}
        else:
            body = {"text": route["text"]}
        http.add(route["method"], route["url"], status=route["status"], headers=route.get("headers") or {}, **body)
    return http, doc


def test_acceptance_routes_of_the_golden_ipv4():
    http, doc = _replay("ipv4", "asn_context")
    res = run_module(AsnContext, "ipv4:8.8.8.8", http)
    assert res.status is Status.OK and len(http.calls) == len(doc["routes"])
    assert statuses(res) == {SRC_PDB: "rate_limited", SRC_CIRCL: "ok", SRC_SS: "ok"}  # PeeringDB throttled this egress
    assert res.attributes["asn"] == "AS15169" and all(f.severity.label == "info" for f in res.findings)
