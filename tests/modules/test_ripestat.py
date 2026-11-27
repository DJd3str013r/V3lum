"""ripestat (P031): RIPEstat Data API calls, envelope checks, minimised whois, capped prefixes.

Fixtures in tests/fixtures/ripestat/ are trimmed real answers (8.8.8.8 recorded 2026-11-26 08:15 UTC
for every IP call; 1.1.1.1, 200.160.2.3, 8.8.8.0/24, AS15169, AS13335 and the company name
'cloudflare' from the research egress), with volatile envelope fields removed and contact details
of the whois objects replaced by documentation values. Synthetic files carry a top-level
``_synthetic`` key: a RIPE-RPSL answer with person objects, a LACNIC individual holder (CPF-shaped
ownerid placeholder) and a rate-limit envelope (never observed live).
"""

from __future__ import annotations

import copy
import json
from urllib.parse import parse_qs, urlsplit

import pytest

from tests.fakes import FakeHttp, make_ctx, make_runtime, module_fixture, run_module
from v3lum.core import providers
from v3lum.core.entities import EntityType as T
from v3lum.core.http import NetworkError, Response, classify
from v3lum.core.models import Status
from v3lum.modules.ip_network import ripestat as rs
from v3lum.modules.ip_network.ripestat import RipeStat, ripestat_url

IP_CALLS = ("network-info", "prefix-overview", "rir-geo", "whois", "abuse-contact-finder", "reverse-dns-ip", "dns-chain")
IP_FIXTURES = {
    "network-info": "network_info_8.8.8.8.json",
    "prefix-overview": "prefix_overview_8.8.8.8.json",
    "rir-geo": "rir_geo_8.8.8.8.json",
    "whois": "whois_8.8.8.8.json",
    "abuse-contact-finder": "abuse_contact_8.8.8.8.json",
    "reverse-dns-ip": "reverse_dns_ip_8.8.8.8.json",
    "dns-chain": "dns_chain_8.8.8.8.json",
}
CHALLENGE = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"


def fx(name):
    return module_fixture("ripestat", name)


def serve(http: FakeHttp, resource: str, calls: dict[str, dict]) -> FakeHttp:
    for call, route in calls.items():
        http.add("GET", ripestat_url(call, resource), **route)
    return http


def serve_ip(http: FakeHttp | None = None, ip: str = "8.8.8.8", **overrides: dict) -> FakeHttp:
    routes = {call: {"json": fx(name)} for call, name in IP_FIXTURES.items()}
    for call, route in overrides.items():
        routes[call.replace("_", "-")] = route
    return serve(http or FakeHttp(), ip, {c: r for c, r in routes.items() if r is not None})


def pivots(res, relation=None):
    return {(p.entity.type, p.entity.value): p for p in res.pivots if relation is None or p.relation == relation}


# ------------------------------------------------------------------ IP calls (cond 1, 2, 5, 6)
def test_ip_answers_are_parsed_attributed_and_pivoted():
    http = serve_ip()
    res = run_module(RipeStat, "ipv4:8.8.8.8", http)
    assert res.status is Status.OK and not res.error
    a = res.attributes
    assert a["asn"] == "AS15169" and a["origin_asns"] == ["AS15169"] and a["as_org"] == "GOOGLE - Google LLC"
    assert a["prefix"] == "8.8.8.0/24" and a["bgp_announced"] is True and a["iana_block"] == "8.0.0.0/8 Administered by ARIN"
    assert a["registration_country"] == "US" and "country" not in a  # rir-geo: context only (cond 6)
    assert a["rir"] == "arin" and a["org"] == "Google LLC"
    reg = a["rir_registration"]
    assert reg["cidrs"] == ["8.8.8.0/24"] and reg["netname"] == "GOGL" and reg["created"] == "2023-12-28"
    assert a["abuse_contact"] == "network-abuse@google.com"
    record = a["abuse_contacts"][0]
    assert record["kind"] == "hosting_abuse_c" and record["authority_rank"] == 2 and record["source"] == "ripestat.data_api"
    assert record["authority"] == "RIR abuse-c (ARIN)" and record["retrieved_at"] and "RIPE NCC" in record["attribution"]
    assert a["rdns"] == ["dns.google"] and a["ptr_forward_confirmed"] is True
    assert a["data_attribution"] == rs.ATTRIBUTION
    assert pivots(res, "belongs_to_asn")[(T.ASN, "AS15169")].expand is True
    assert pivots(res, "in_network")[(T.CIDR, "8.8.8.0/24")].expand is False
    email = pivots(res, "contact_email")[(T.EMAIL, "network-abuse@google.com")]
    assert email.expand is False and "never scored" in email.note
    ptr = pivots(res, "reverse_dns")[(T.DOMAIN, "dns.google")]
    assert ptr.expand is True and ptr.confidence_label.value == "confirmed"
    assert res.links == [("RIPEstat: 8.8.8.8 (data: RIPE NCC)", "https://stat.ripe.net/resource/8.8.8.8")]
    assert [c for c in res.raw["calls_answered"]] == list(IP_CALLS)
    http.assert_hosts_within(RipeStat)


def test_sourceapp_is_on_every_call():
    http = serve_ip()
    run_module(RipeStat, "ipv4:8.8.8.8", http)
    assert len(http.urls()) == len(IP_CALLS)
    for url in http.urls():
        assert parse_qs(urlsplit(url).query)["sourceapp"] == ["v3lum"]
    with pytest.raises(ValueError):
        ripestat_url("blocklist", "8.8.8.8")


def test_whois_raw_answer_never_reaches_the_http_cache():
    http = serve_ip()
    runtime = make_runtime(http, cache=True)
    run_module(RipeStat, "ipv4:8.8.8.8", runtime=runtime)
    run_module(RipeStat, "ipv4:8.8.8.8", runtime=runtime)
    counts = {call: sum(1 for u in http.urls() if f"/data/{call}/" in u) for call in IP_CALLS}
    assert counts["whois"] == 2  # cache_if veto: the raw answer (POCs, phones) is never stored (cond 5)
    assert counts["network-info"] == 1 and counts["abuse-contact-finder"] == 1  # 24 h cache for the others


def test_cidr_input_uses_the_prefix_calls_only():
    http = serve(FakeHttp(), "8.8.8.0/24", {
        "prefix-overview": {"json": fx("prefix_overview_8.8.8.0_24.json")},
        "rir-geo": {"json": fx("rir_geo_8.8.8.8.json")},
        "whois": {"json": fx("whois_8.8.8.8.json")},
        "abuse-contact-finder": {"json": fx("abuse_contact_8.8.8.8.json")},
    })
    res = run_module(RipeStat, "cidr:8.8.8.0/24", http)
    assert res.status is Status.OK and res.attributes["asn"] == "AS15169" and res.attributes["bgp_announced"] is True
    assert (T.ASN, "AS15169") in pivots(res, "belongs_to_asn")
    assert not [p for p in res.pivots if p.entity.type is T.CIDR]  # the registration block is the input itself
    assert len(http.urls()) == 4


def test_not_announced_address_gets_a_finding_never_an_absence():
    overview = copy.deepcopy(fx("prefix_overview_8.8.8.8.json"))
    overview["data"].update({"announced": False, "asns": [], "is_less_specific": False})
    http = serve_ip(ip="193.0.6.139", network_info={"json": fx("network_info_not_announced.json")},
                    prefix_overview={"json": overview})
    res = run_module(RipeStat, "ipv4:193.0.6.139", http)
    assert res.status is Status.OK and res.attributes["bgp_announced"] is False
    assert "Not announced in BGP" in {f.title for f in res.findings}
    assert not pivots(res, "belongs_to_asn")
    assert pivots(res, "reverse_dns")[(T.DOMAIN, "dns.google")].confidence_label.value == "probable"  # chain not confirmed


# ------------------------------------------------------------------ envelope checks (cond 3)
def _ripestat_markers():
    return providers.registry().get("ripestat").error_markers


def _classified(body, status=200):
    resp = Response(status, "https://stat.ripe.net/data/x/data.json", {"content-type": "application/json"}, json.dumps(body).encode())
    return classify(resp, markers=_ripestat_markers(), keyless=True)


@pytest.mark.parametrize(
    ("body_name", "status", "marker", "maps_to"),
    [
        ("network_info_error_400.json", 400, "ripestat_message_error", "error"),
        ("network_info_error_400.json", 200, "ripestat_message_error", "error"),  # the same envelope inside HTTP 200
        ("unsupported_call_404.json", 404, "ripestat_call_unsupported", "error"),
        ("unsupported_call_404.json", 200, "ripestat_call_unsupported", "error"),
        ("rate_limited_in_200_synthetic.json", 200, "ripestat_envelope_rate_limited", "rate_limited"),
    ],
)
def test_error_envelopes_match_the_provider_markers(body_name, status, marker, maps_to):
    found = _classified(fx(body_name), status)
    assert found is not None and found.marker_id == marker and found.status == maps_to


def test_remaining_markers_on_envelope_variants():
    ok = fx("network_info_8.8.8.8.json")
    assert _classified(ok) is None
    assert _classified(dict(ok, status="error")).marker_id == "ripestat_envelope_status_error"
    assert _classified(dict(ok, status_code=500)).marker_id == "ripestat_envelope_status_code"
    warned = dict(ok, messages=[["warning", "Rate limit reached: slow down"]])
    assert _classified(warned).marker_id == "ripestat_message_rate_limited"
    less_specific = fx("prefix_overview_8.8.8.8.json")  # a 'warning' message stays a warning, never an error
    assert _classified(less_specific) is None
    assert {m.id for m in _ripestat_markers()} >= {
        "ripestat_envelope_rate_limited", "ripestat_message_rate_limited", "ripestat_call_unsupported",
        "ripestat_message_error", "ripestat_envelope_status_error", "ripestat_envelope_status_code"}


def test_error_envelope_on_one_call_is_named_while_the_others_stand():
    http = serve_ip(network_info={"status": 400, "json": fx("network_info_error_400.json")},
                    whois={"json": fx("unsupported_call_404.json")})  # error inside HTTP 200
    res = run_module(RipeStat, "ipv4:8.8.8.8", http)
    assert res.status is Status.OK
    assert "network-info" in res.error and "whois" in res.error and "could not verify" in res.error
    assert res.attributes["as_org"] == "GOOGLE - Google LLC"  # prefix-overview still answered
    assert "rir_registration" not in res.attributes and "network-info" in res.raw["calls_unverified"]


def test_error_envelope_everywhere_is_error_never_empty():
    http = serve(FakeHttp(), "Acme Telecom", {"searchcomplete": {"json": fx("network_info_error_400.json")}})
    res = run_module(RipeStat, "company_name:Acme Telecom", http)
    assert res.status is Status.ERROR and res.reason_code == "error" and "searchcomplete" in res.error


def test_rate_limit_envelope_inside_200_is_rate_limited():
    http = serve_ip(network_info={"json": fx("rate_limited_in_200_synthetic.json")})
    res = run_module(RipeStat, "ipv4:8.8.8.8", http)
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited"
    assert len(http.urls()) == 1  # the host said 'slow down': no further calls


@pytest.mark.parametrize(
    ("route", "status", "code"),
    [
        ({"status": 429, "text": "too many requests"}, Status.RATE_LIMITED, "rate_limited"),
        ({"status": 403, "text": "forbidden"}, Status.BLOCKED, "challenge"),  # keyless 403: could not verify
        ({"status": 200, "text": CHALLENGE}, Status.BLOCKED, "challenge"),
    ],
)
def test_host_level_refusals_propagate(route, status, code):
    http = serve_ip(network_info=route)
    res = run_module(RipeStat, "ipv4:8.8.8.8", http)
    assert res.status is status and res.reason_code == code
    assert not res.pivots and not res.attributes


@pytest.mark.parametrize(
    "route",
    [
        {"status": 503, "text": "maintenance"},
        {"error": NetworkError("ReadTimeout contacting stat.ripe.net: timed out")},
        {"body": b"{not json", "headers": {"content-type": "application/json"}},
        {"json": ["not", "an", "envelope"]},
        {"json": {"status": "ok", "status_code": 200, "messages": []}},  # no data object
    ],
)
def test_failures_and_odd_answers_are_could_not_verify(route):
    http = serve(FakeHttp(), "Acme Telecom", {"searchcomplete": route})
    res = run_module(RipeStat, "company_name:Acme Telecom", http)
    assert res.status is Status.ERROR and "searchcomplete" in res.error


def test_nothing_found_while_a_call_failed_is_never_empty():
    from v3lum.core.entities import Entity

    module = RipeStat()
    run = rs._Run(module.result(Entity.make("asn", "AS13335")), None, "AS13335", failures={"asn-neighbours": "HTTP 503"},
                  answered=["as-overview"])
    res = module._finish(run)
    assert res.status is Status.ERROR and "asn-neighbours" in res.error and not res.attributes


def test_offline_and_uncached_is_unavailable():
    res = run_module(RipeStat, "company_name:Acme Telecom", runtime=make_runtime(FakeHttp(), offline=True))
    assert res.status is Status.UNAVAILABLE and res.reason_code == "offline"


# ------------------------------------------------------------------ person objects (cond 5)
def test_ripe_person_objects_are_dropped_at_ingestion():
    http = serve_ip(ip="193.0.6.139", whois={"json": fx("whois_person_synthetic.json")})
    res = run_module(RipeStat, "ipv4:193.0.6.139", http)
    dropped = res.raw["whois"]["dropped"]
    assert dropped["person_objects"] == 1 and dropped["other_objects"] == 1 and dropped["classes"] == ["mntner", "person"]
    dump = json.dumps(res.to_dict()) + json.dumps(res.raw) + json.dumps([f.to_dict() for f in res.findings])
    for personal in ("person@example.com", "Example Person", "+55 11 5555-01", "Rua Exemplo", "EP1-RIPE", "noc@example.com"):
        assert personal not in dump, personal
    assert res.attributes["org"] == "Example Org Ltda"
    assert (T.EMAIL, "abuse@example.com") in pivots(res, "contact_email")  # the role abuse mailbox is kept
    classes = {o["class"] for o in res.raw["whois"]["objects"]}
    assert classes == {"inetnum", "organisation", "role", "route"}


def test_lacnic_individual_holder_loses_name_and_id():
    parsed = rs.parse_whois(fx("whois_lacnic_person_synthetic.json")["data"])
    dump = json.dumps(parsed)
    for personal in ("Example Person", "111.111.111-11", "person@example.com", "Rua Exemplo", "5555", "EXP2"):
        assert personal not in dump, personal
    assert parsed["org_name"] == "" and parsed["objects"][0]["individual_holder"] is True
    assert parsed["dropped"]["person_objects"] == 1


def test_nic_br_space_answers_with_irr_routes_only():
    parsed = rs.parse_whois(fx("whois_lacnic_no_records.json")["data"])
    assert parsed["network"] is None and parsed["rir"] == "lacnic"
    assert parsed["irr_routes"] == [{"route": "200.160.0.0/20", "origin": 22548, "source": "RADB"}]
    assert "NIC.br" in parsed["note"]


def test_apnic_rpsl_record_keeps_only_allow_listed_attributes():
    parsed = rs.parse_whois(fx("whois_apnic_1.1.1.1.json")["data"])
    assert parsed["network"]["cidrs"] == ["1.1.1.0/24"] and parsed["network"]["netname"] == "APNIC-LABS"
    kept = {k.lower() for obj in parsed["objects"] for k, _v in obj["attrs"]}
    assert not kept & {"admin-c", "tech-c", "remarks", "mnt-by", "mnt-routes", "mnt-lower", "notify"}


# ------------------------------------------------------------------ ASN calls (cond 2, 4)
def _asn_routes(resource="AS13335", prefixes=None, **overrides):
    routes = {
        "as-overview": {"json": fx("as_overview_as15169.json")},
        "announced-prefixes": {"json": prefixes or fx("announced_prefixes_as13335_capped.json")},
        "asn-neighbours": {"json": fx("asn_neighbours_as13335.json")},
    }
    routes.update(overrides)
    return serve(FakeHttp(), resource, routes)


def test_announced_prefixes_are_capped_while_totals_are_kept():
    http = _asn_routes()
    res = run_module(RipeStat, "asn:AS13335", http)
    assert res.status is Status.OK
    counts = res.attributes["announced_prefix_counts"]
    assert counts == {"total": 130, "ipv4": counts["ipv4"], "ipv6": counts["ipv6"], "pivoted": 100, "capped": True, "truncated": False}
    assert counts["ipv4"] + counts["ipv6"] == 130
    announces = [p for p in res.pivots if p.relation == "announces"]
    assert len(announces) == rs.ANNOUNCED_PREFIXES_CAP and all(p.expand for p in announces)
    assert announces[0].entity.value.count(":") == 0  # IPv4 first
    upstream = [p for p in res.pivots if p.relation == "upstream_asn"]
    assert len(upstream) == 8 and all(not p.expand for p in upstream)
    assert upstream[0].entity.value == "AS1221"  # highest power first
    assert res.attributes["asn_neighbour_counts"] == {"left": 298, "right": 1050, "unique": 1536, "uncertain": 1191}
    assert res.attributes["as_org"] == "GOOGLE - Google LLC" and res.attributes["bgp_announced"] is True


def test_asn_reached_as_a_pivot_lists_prefixes_without_expanding_them():
    res = run_module(RipeStat, "asn:AS13335", _asn_routes(), is_seed=False, depth=2)
    announces = [p for p in res.pivots if p.relation == "announces"]
    assert announces and not any(p.expand for p in announces) and "pivot" in announces[0].note


def _prefix_body(n_v4: int, n_v6: int) -> dict:
    prefixes = [{"prefix": f"10{i % 10}.{i // 250 % 250}.{i % 250}.0/24", "timelines": []} for i in range(n_v4)]
    prefixes += [{"prefix": f"2001:db8:{i:x}::/48", "timelines": []} for i in range(n_v6)]
    body = copy.deepcopy(fx("announced_prefixes_as13335_capped.json"))
    body["data"]["prefixes"] = prefixes
    return body


def test_truncated_announced_prefixes_keep_partial_counts(monkeypatch):
    monkeypatch.setattr(rs, "ANNOUNCED_MAX_BYTES", 6000)
    res = run_module(RipeStat, "asn:AS13335", _asn_routes(prefixes=_prefix_body(400, 0)))
    counts = res.attributes["announced_prefix_counts"]
    assert counts["truncated"] is True and 0 < counts["total"] < 400 and counts["pivoted"] <= 100
    assert "announced-prefixes" in res.error and "cut at 6000 bytes" in res.error


@pytest.mark.parametrize("size", [1, 7, 97, 4096, 1 << 20])
def test_incremental_scan_matches_a_full_parse(size):
    body = json.dumps(_prefix_body(180, 40)).encode()
    scan = rs.count_announced_prefixes((body[i : i + size] for i in range(0, len(body), size)), cap=100)
    truth = [p["prefix"] for p in json.loads(body)["data"]["prefixes"]]
    assert (scan["total"], scan["ipv4"], scan["ipv6"]) == (len(set(truth)), 180, 40)
    assert scan["complete"] is True and scan["status"] == "ok" and len(scan["prefixes"]) == 100
    assert all(":" not in p for p in scan["prefixes"])  # IPv4 /24s sort before IPv6 /48s


def test_announced_prefixes_error_envelope_is_could_not_verify():
    http = _asn_routes(**{"announced-prefixes": {"status": 404, "json": fx("unsupported_call_404.json")}})
    res = run_module(RipeStat, "asn:AS13335", http)
    assert res.status is Status.OK and "announced-prefixes" in res.error
    assert "announced_prefix_counts" not in res.attributes and not [p for p in res.pivots if p.relation == "announces"]


# ------------------------------------------------------------------ company names (cond 2)
def test_company_name_candidates_are_low_confidence_and_not_expanded():
    http = serve(FakeHttp(), "Cloudflare", {"searchcomplete": {"json": fx("searchcomplete_cloudflare.json")}})
    res = run_module(RipeStat, "company_name:Cloudflare", http)
    candidates = pivots(res, "owns_network")
    assert set(candidates) == {(T.ASN, "AS13335"), (T.ASN, "AS14789"), (T.ASN, "AS22061"), (T.ASN, "AS132892")}
    assert all(not p.expand and p.confidence_label.value == "possible" for p in candidates.values())
    assert res.attributes["network_candidates"]["confidence"] == "low"
    assert all(c["name_match"] for c in res.attributes["network_candidates"]["asns"])
    assert res.findings[0].title == "Candidate networks for the company name (low confidence)"
    assert not res.links  # a free-text name has no RIPEstat resource page


def test_company_name_without_candidates_is_empty():
    http = serve(FakeHttp(), "zzqxv3lumnomatch", {"searchcomplete": {"json": fx("searchcomplete_empty.json")}})
    assert run_module(RipeStat, "company_name:zzqxv3lumnomatch", http).status is Status.EMPTY


# ------------------------------------------------------------------ PTR, helpers, declarations
def test_reverse_dns_failure_is_named_and_no_chain_is_requested():
    failed = copy.deepcopy(fx("reverse_dns_ip_8.8.8.8.json"))
    failed["data"].update({"result": [], "error": "SERVFAIL while resolving"})
    http = serve_ip(reverse_dns_ip={"json": failed}, dns_chain=None)
    res = run_module(RipeStat, "ipv4:8.8.8.8", http)
    assert "reverse-dns-ip" in res.error and "rdns" not in res.attributes
    nxdomain = copy.deepcopy(failed)
    nxdomain["data"]["error"] = "NXDOMAIN"
    res2 = run_module(RipeStat, "ipv4:8.8.8.8", serve_ip(reverse_dns_ip={"json": nxdomain}, dns_chain=None))
    assert not res2.error and "rdns" not in res2.attributes  # a meaningful 'no PTR'


def test_abuse_contact_helper_for_the_takedown_packet():
    parsed = rs.parse_abuse_contact_finder(fx("abuse_contact_1.1.1.1.json")["data"])
    records = rs.abuse_contact_records(parsed)
    assert records == [{
        "email": "helpdesk@apnic.net", "kind": "hosting_abuse_c", "authority_rank": 2, "authority": "RIR abuse-c (APNIC)",
        "source": "ripestat.data_api", "resource": "1.1.1.1", "retrieved_at": "2026-11-25T08:34:38", "attribution": rs.ATTRIBUTION}]
    http = serve(FakeHttp(), "1.1.1.1", {"abuse-contact-finder": {"json": fx("abuse_contact_1.1.1.1.json")}})
    looked_up = rs.lookup_abuse_contacts(make_ctx(RipeStat, http).http, "1.1.1.1")
    assert looked_up[0]["email"] == "helpdesk@apnic.net" and looked_up[0]["retrieved_at"] == "2026-11-25T21:23:20.127692"
    assert rs.abuse_contact_records(None) == []


@pytest.mark.parametrize("value", ["ipv4:10.0.0.1", "ipv4:192.0.2.1", "ipv6:2001:db8::1", "cidr:10.0.0.0/8", "asn:AS64512", "asn:AS23456"])
def test_bogons_are_never_sent(value):
    http = FakeHttp()
    res = run_module(RipeStat, value, http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and not http.calls


def test_generic_ptr_names_are_not_expanded():
    assert rs.generic_ptr("ec2-3-5-140-1.ap-northeast-2.compute.amazonaws.com", "3.5.140.1")
    assert rs.generic_ptr("1.140.5.3.example.net", "3.5.140.1")
    assert not rs.generic_ptr("dns.google", "8.8.8.8")


def test_module_declarations():
    assert RipeStat.terms == "open" and RipeStat.disclosure == "third_party" and RipeStat.hosts == ("stat.ripe.net",)
    assert RipeStat.cache_ttl == 86400 and RipeStat.default_enabled is True and RipeStat.max_requests <= 10
    assert RipeStat.trust_tier == "trusted" and RipeStat.sources == ("ripestat.data_api",)
