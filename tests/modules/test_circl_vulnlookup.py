"""circl_vulnlookup (P181): CIRCL Vulnerability-Lookup record, sightings and EPSS for the CVE card.

Fixtures in tests/fixtures/circl_vulnlookup/ (prep batch p2-G08-1, 2026-11-26): ``vuln_cve_ok.json`` (CVE
JSON 5 record, credits dropped), ``timeline_ok.json`` (live, trimmed to 17 events, post contents emptied and
account handles replaced), ``vuln_ghsa_ok.http.json`` (live OSV record), ``vuln_not_found.http.json`` (live
200 {}), ``epss_ok.json`` and ``sighting_ok.json`` (research); ``*_404``, ``rate_limited``, ``html_error``,
``epss_not_found`` and ``vuln_csaf_ok`` are doc-shaped (flagged in the prep MANIFEST).
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core.models import Opsec, Status
from v3lum.modules.vulnerability_cve import circl_vulnlookup as mod
from v3lum.modules.vulnerability_cve.circl_vulnlookup import (
    CirclVulnLookup,
    circl_exploited,
    circl_urls,
    parse_circl_epss,
    parse_circl_sightings,
    parse_circl_timeline,
    record_format,
    sighting_family,
)
from v3lum.modules.vulnerability_cve.cve_record import CASE_COUNTERS, CVE_FANOUT_SETTING

B = "https://vulnerability.circl.lu"
CVE = "CVE-2021-44228"
RECORD = B + "/api/vulnerability/{id}"
TIMELINE = B + "/api/vulnerability/{id}/timeline"
EPSS = B + "/api/epss/{id}"
SIGHTINGS = B + "/api/sighting/?vuln_id={id}&per_page=100"
RATE_OK = {"x-ratelimit-limit": "20", "x-ratelimit-remaining": "19", "x-ratelimit-reset": "1795677621", "retry-after": "60"}
CHALLENGE = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body><div id='cf-chl-widget'></div></body></html>"


@pytest.fixture(autouse=True)
def fresh_counters():
    CASE_COUNTERS.reset()
    yield
    CASE_COUNTERS.reset()


def fx(name: str):
    return module_fixture(CirclVulnLookup, name)


def exchange(name: str) -> dict:
    """status / headers / body of a recorded *.http.json exchange."""
    resp = fx(name)["response"]
    return {"status": resp["status"], "headers": resp["headers"], "body": resp["body"].encode()}


def cve_http(*, timeline="timeline_ok.json", epss="epss_ok.json", record="vuln_cve_ok.json", record_headers=None) -> FakeHttp:
    http = FakeHttp()
    http.add("GET", RECORD.format(id=CVE), json=fx(record), headers=record_headers or RATE_OK)
    if timeline is not None:
        http.add("GET", TIMELINE.format(id=CVE), json=fx(timeline), headers=RATE_OK)
    if epss is not None:
        http.add("GET", EPSS.format(id=CVE), json=fx(epss), headers=RATE_OK)
    return http


# ------------------------------------------------------------------ metadata (council values)
def test_metadata_matches_the_council_decision():
    cls = CirclVulnLookup
    assert cls.default_enabled is True and cls.terms == "open" and cls.trust_tier == "trusted"
    assert cls.opsec is Opsec.PASSIVE and cls.disclosure == "third_party" and cls.shares_input is True
    assert cls.provider == "circl_vulnlookup" and cls.hosts == ("vulnerability.circl.lu",)
    assert cls.sources == ("circl_vulnlookup.api", "circl_vulnlookup.circl_vulnlookup_sightings", "circl_vulnlookup.circl_vulnlookup_epss")
    assert cls.optional_keys == ("circl_vuln",) and cls.absent_statuses == frozenset({404})
    assert (cls.cache_ttl, cls.min_interval, cls.max_requests) == (86400, 3.0, 4)


# ------------------------------------------------------------------ CVE record + sightings + EPSS (cond 1-4)
def test_cve_record_sightings_and_epss_fill_the_card_without_kev():
    http = cve_http()
    res = run_module(CirclVulnLookup, f"cve:{CVE}", http)
    assert res.status is Status.OK, res.error
    a = res.attributes
    # the ONE shared CVE JSON 5 parser (cond 2)
    assert a["cve_state"] == "PUBLISHED" and a["cvss"] == 10.0 and "CWE-502" in a["cwe"]
    assert a["cvss_scores"][0]["source"] == "CISA-ADP" and a["cvss_vector"].startswith("CVSS:3.1/")
    # sightings -> exploited['circl'] (first date), never kev (cond 3)
    assert a["exploited"]["circl"] == "2021-12-10"
    assert "kev" not in a and "kev_date_added" not in a
    sightings = a["circl_sightings"]
    assert sightings["types"]["seen"]["count"] == 4 and sightings["total"] == 2094
    assert sightings["exploited_types"] == ["seen", "exploited", "confirmed"]
    cisa = [c for c in sightings["kev_catalogues"] if c["catalogue"] == "cisa_kev"]
    assert cisa and "kev fact comes from cisa_kev" in cisa[0]["note"]
    # EPSS relayed by CIRCL (no local EPSS file in this home)
    assert (a["epss"], a["epss_percentile"], a["epss_date"]) == (0.99999, 1.0, "2026-11-25")
    assert "relayed by CIRCL" in a["epss_text"]
    assert a["data_notices"] == ["CIRCL Vulnerability-Lookup (vulnerability.circl.lu), data CC BY 4.0 where applicable."]
    assert ("CIRCL Vulnerability-Lookup page", f"{B}/vuln/{CVE}") in res.links
    # linked advisories become analyst-selection keywords, never expanded
    linked = {p.entity.value: p for p in res.pivots}
    assert set(a["linked_advisories"]) <= set(linked) and all(p.expand is False for p in linked.values())
    assert not res.findings  # card facts with provenance, no separate findings (cond 4)
    assert res.requests == 3
    http.assert_hosts_within(CirclVulnLookup)


def test_evidence_keeps_no_sighting_contents_or_handles():
    res = run_module(CirclVulnLookup, f"cve:{CVE}", cve_http())
    dumped = json.dumps([res.raw, res.attributes])
    assert "example_channel" not in dumped and "example.bsky.social" not in dumped and "content" not in json.dumps(res.raw.get("sightings"))
    assert res.raw["format"] == "cve5" and "credits" not in json.dumps(res.raw["record"])


def test_sighting_bodies_are_never_cached_but_the_record_is():
    http = cve_http()
    rt = make_runtime(http, cache=True)
    first = run_module(CirclVulnLookup, f"cve:{CVE}", runtime=rt)
    second = run_module(CirclVulnLookup, f"cve:{CVE}", runtime=rt)
    assert first.status is Status.OK and second.status is Status.OK
    urls = http.urls()
    assert urls.count(RECORD.format(id=CVE)) == 1 and urls.count(EPSS.format(id=CVE)) == 1  # cached 24 h
    assert urls.count(TIMELINE.format(id=CVE)) == 2  # third-party handles and post texts: in memory only
    assert second.attributes["exploited"]["circl"] == "2021-12-10"


def test_exploited_types_setting_narrows_the_first_date():
    res = run_module(CirclVulnLookup, f"cve:{CVE}", cve_http(), settings={"circl_vulnlookup_exploited_types": ["confirmed"]})
    a = res.attributes
    types = a["circl_sightings"]["types"]
    if "confirmed" in types:
        assert a["exploited"]["circl"] == types["confirmed"]["first"]
    else:
        assert "circl" not in a.get("exploited", {})
    assert a["circl_sightings"]["exploited_types"] == ["confirmed"]


def test_timeline_without_sightings_sets_no_circl_exploitation():
    res = run_module(CirclVulnLookup, f"cve:{CVE}", cve_http(timeline="timeline_no_sightings.json"))
    assert res.status is Status.OK
    assert "circl" not in (res.attributes.get("exploited") or {})
    assert res.attributes["circl_sightings"]["types"] == {}


def test_local_epss_file_means_no_circl_epss_call(monkeypatch):
    monkeypatch.setattr(mod, "local_epss_state", lambda ctx, cve: ("present", "2026-11-25"))
    http = cve_http(epss=None)
    res = run_module(CirclVulnLookup, f"cve:{CVE}", http)
    assert res.status is Status.OK and "epss" not in res.attributes
    assert all("/api/epss/" not in u for u in http.urls())


def test_optional_key_goes_in_the_x_api_key_header_only():
    http = FakeHttp()
    http.add("GET", RECORD.format(id=CVE), json=fx("vuln_cve_ok.json"), headers=RATE_OK, match_headers={"X-API-KEY": "circl-test-key-123456"})
    http.add("GET", TIMELINE.format(id=CVE), json=fx("timeline_ok.json"), match_headers={"X-API-KEY": "circl-test-key-123456"})
    http.add("GET", EPSS.format(id=CVE), json=fx("epss_ok.json"))
    res = run_module(CirclVulnLookup, f"cve:{CVE}", http, keys={"circl_vuln": "circl-test-key-123456"})
    assert res.status is Status.OK
    assert "circl-test-key-123456" not in json.dumps([res.raw, res.attributes, res.error])


# ------------------------------------------------------------------ other identifiers (cond 1)
def test_ghsa_keyword_reads_the_osv_record_and_pivots_the_cve_alias():
    ex = exchange("vuln_ghsa_ok.http.json")
    http = FakeHttp()
    http.add("GET", RECORD.format(id="GHSA-jfh8-c2jp-5v3q"), body=ex["body"], headers=ex["headers"] | {"content-type": "application/json"})
    http.add("GET", TIMELINE.format(id="GHSA-jfh8-c2jp-5v3q"), json=fx("timeline_no_sightings.json"))
    res = run_module(CirclVulnLookup, "keyword:GHSA-jfh8-c2jp-5v3q", http)
    assert res.status is Status.OK, res.error
    a = res.attributes
    assert CVE in a["advisory_aliases"] and "GHSA-jfh8-c2jp-5v3q" not in a["advisory_aliases"]
    assert any(p["product"] == "org.apache.logging.log4j:log4j-core" for p in a["affected"])
    assert any(r.get("fixed") for r in a["package_ranges"]) and all("details" not in r for r in a["package_ranges"])
    cve_pivots = [p for p in res.pivots if p.entity.type.value == "cve"]
    assert [p.entity.value for p in cve_pivots] == [CVE] and cve_pivots[0].relation == "advisory_alias"
    assert all("/api/epss/" not in u for u in http.urls())  # EPSS is for CVE ids only
    assert res.raw["format"] == "osv"


def test_csaf_vendor_advisory_lists_its_cves_for_analyst_selection():
    http = FakeHttp()
    http.add("GET", RECORD.format(id="RHSA-2021%3A5093"), json=fx("vuln_csaf_ok.json"))
    http.add("GET", TIMELINE.format(id="RHSA-2021%3A5093"), status=404, json={"message": "not found"})
    res = run_module(CirclVulnLookup, "keyword:RHSA-2021:5093", http)
    assert res.status is Status.OK, res.error
    assert res.raw["format"] == "csaf" and res.raw["record"]["cves"] == [CVE]
    pivot = next(p for p in res.pivots if p.entity.value == CVE)
    assert pivot.expand is False and pivot.relation == "related"
    assert res.source_statuses["circl_vulnlookup.circl_vulnlookup_sightings"]["status"] == "empty"


@pytest.mark.parametrize("keyword", ["apache log4j", "Example Corp", "nginx 1.18"])
def test_free_keywords_are_never_sent(keyword):
    http = FakeHttp()
    res = run_module(CirclVulnLookup, f"keyword:{keyword}", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert http.calls == []


# ------------------------------------------------------------------ absences and rule 5
def test_404_is_empty():
    ex = exchange("vuln_not_found_404.http.json")
    http = FakeHttp().add("GET", RECORD.format(id="CVE-2021-9999999"), status=404, body=ex["body"], headers=ex["headers"])
    res = run_module(CirclVulnLookup, "cve:CVE-2021-9999999", http)
    assert res.status is Status.EMPTY and "404" in res.error


def test_live_200_empty_object_is_empty():
    ex = exchange("vuln_not_found.http.json")
    http = FakeHttp().add("GET", RECORD.format(id="CVE-2021-9999999"), body=ex["body"], headers=ex["headers"])
    res = run_module(CirclVulnLookup, "cve:CVE-2021-9999999", http)
    assert res.status is Status.EMPTY and res.requests == 1


def test_429_is_rate_limited_never_empty():
    ex = exchange("rate_limited.http.json")
    http = FakeHttp().add("GET", RECORD.format(id=CVE), status=429, body=ex["body"], headers=ex["headers"])
    res = run_module(CirclVulnLookup, f"cve:{CVE}", http)
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited" and not res.attributes


def test_varnish_503_is_an_error():
    ex = exchange("html_error.http.json")
    http = FakeHttp().add("GET", RECORD.format(id=CVE), status=503, body=ex["body"], headers=ex["headers"])
    res = run_module(CirclVulnLookup, f"cve:{CVE}", http)
    assert res.status is Status.ERROR


def test_challenge_page_is_blocked():
    http = FakeHttp().add("GET", RECORD.format(id=CVE), status=403, text=CHALLENGE)
    res = run_module(CirclVulnLookup, f"cve:{CVE}", http)
    assert res.status is Status.BLOCKED


def test_malformed_json_and_unknown_shapes_are_errors():
    http = FakeHttp().add("GET", RECORD.format(id=CVE), body=b'{"cveMetadata": {"cveId": "CVE-2021-44228"', headers={"content-type": "application/json"})
    assert run_module(CirclVulnLookup, f"cve:{CVE}", http).status is Status.ERROR
    http2 = FakeHttp().add("GET", RECORD.format(id=CVE), json=["not", "a", "record"])
    assert run_module(CirclVulnLookup, f"cve:{CVE}", http2).status is Status.ERROR


def test_sightings_failure_keeps_the_record_and_reports_the_source():
    ex = exchange("rate_limited.http.json")
    http = cve_http(timeline=None)
    http.add("GET", TIMELINE.format(id=CVE), status=429, body=ex["body"], headers=ex["headers"])
    res = run_module(CirclVulnLookup, f"cve:{CVE}", http)
    assert res.status is Status.OK and res.attributes["cve_state"] == "PUBLISHED"
    sighting = res.source_statuses["circl_vulnlookup.circl_vulnlookup_sightings"]
    assert sighting["status"] == "rate_limited" and "circl" not in (res.attributes.get("exploited") or {})


def test_cut_timeline_falls_back_to_the_newest_sightings_without_a_first_date(monkeypatch):
    monkeypatch.setattr(mod, "TIMELINE_MAX_BYTES", 200)
    http = cve_http()
    http.add("GET", SIGHTINGS.format(id=CVE), json=fx("sighting_ok.json"))
    res = run_module(CirclVulnLookup, f"cve:{CVE}", http)
    assert res.status is Status.OK
    a = res.attributes
    assert a["circl_sightings"]["complete"] is False and a["circl_sightings"]["total"] == 2094
    assert "circl" not in (a.get("exploited") or {})  # newest-first page: the first date is not exact
    assert "first dates not exact" in res.source_statuses["circl_vulnlookup.circl_vulnlookup_sightings"]["reason"]


def test_exhausted_window_stops_later_calls():
    headers = dict(RATE_OK, **{"x-ratelimit-remaining": "0", "x-ratelimit-reset": "4102444800"})
    http = cve_http(timeline=None, epss=None, record_headers=headers)
    res = run_module(CirclVulnLookup, f"cve:{CVE}", http)
    assert res.status is Status.OK and res.requests == 1
    assert res.source_statuses["circl_vulnlookup.circl_vulnlookup_sightings"]["status"] == "rate_limited"
    assert res.source_statuses["circl_vulnlookup.circl_vulnlookup_epss"]["status"] == "rate_limited"


def test_epss_error_inside_200_and_404_are_never_scores():
    http = cve_http(epss=None)
    http.add("GET", EPSS.format(id=CVE), json={"status": "error", "status-code": 500, "data": []})
    res = run_module(CirclVulnLookup, f"cve:{CVE}", http)
    assert res.status is Status.OK and "epss" not in res.attributes
    assert res.source_statuses["circl_vulnlookup.circl_vulnlookup_epss"]["status"] == "error"
    ex = exchange("epss_not_found.http.json")
    http2 = cve_http(epss=None)
    http2.add("GET", EPSS.format(id=CVE), status=404, body=ex["body"], headers=ex["headers"])
    res2 = run_module(CirclVulnLookup, f"cve:{CVE}", http2)
    assert res2.source_statuses["circl_vulnlookup.circl_vulnlookup_epss"]["status"] == "empty" and "epss" not in res2.attributes


def test_pivot_cves_follow_the_fan_out_rule():
    http = FakeHttp()
    res = run_module(CirclVulnLookup, f"cve:{CVE}", http, is_seed=False, case_id="case-1", settings={CVE_FANOUT_SETTING: 0})
    assert res.status is Status.QUOTA and res.reason_code == "quota" and http.calls == []


# ------------------------------------------------------------------ pure parsers
def test_parsers_on_fixtures_and_bad_input():
    timeline = parse_circl_timeline(fx("timeline_ok.json"))
    assert timeline["oldest_first"] is True and timeline["sightings"]["seen"]["families"]
    assert parse_circl_timeline({"data": "nope"}) is None and parse_circl_timeline([]) is None
    sightings = parse_circl_sightings(fx("sighting_ok.json"))
    assert sightings["complete"] is False and circl_exploited(sightings) == {}
    empty = parse_circl_sightings(fx("sighting_empty.json"))
    assert empty["complete"] is True and circl_exploited(empty) == {}
    assert parse_circl_epss(fx("epss_ok.json"))["epss"]["score"] == 0.99999
    assert parse_circl_epss({"status": "OK", "data": []})["status"] == "empty"
    assert parse_circl_epss("nope")["status"] == "error"
    assert record_format({}) == "empty" and record_format(fx("vuln_cve_ok.json")) == "cve5" and record_format({"x": 1}) == "unknown"
    assert circl_urls("apache log4j") is None and circl_urls(CVE)["epss"].endswith(CVE)
    assert sighting_family("https://t.me/x/1") == "telegram" and sighting_family("MISP/abc") == "misp"
    assert sighting_family("https://www.govcert.gov.hk/en/alerts_detail.php?id=700") == "cert"


# ------------------------------------------------------------------ the consolidated CVE card (cond 4)
def test_facts_fill_the_cve_card_with_provenance_and_never_kev():
    from v3lum.core.entities import Entity
    from v3lum.core.entities import EntityType as T
    from v3lum.core.graph import Graph
    from v3lum.correlations.g08_cve_card import build_card, card_lines

    res = run_module(CirclVulnLookup, f"cve:{CVE}", cve_http())
    graph = Graph()
    entity = Entity.make(T.CVE, CVE)
    graph.add_node(entity, depth=0, seed=True)
    graph.add_attributes(entity, res.attributes, "circl_vulnlookup")
    card = build_card(graph.get(entity.key), graph)
    assert card["kev"]["listed"] is False  # sightings and non-CISA catalogues never make a KEV listing
    assert card["exploited"]["circl [circl_vulnlookup]"] == "2021-12-10"
    lines = card_lines(card)
    assert any(line.startswith("exploitation evidence: circl [circl_vulnlookup] since 2021-12-10") for line in lines)
    assert any("[circl_vulnlookup]" in line and line.startswith("EPSS") for line in lines)
    assert "CIRCL Vulnerability-Lookup (vulnerability.circl.lu), data CC BY 4.0 where applicable." in card["notices"]
