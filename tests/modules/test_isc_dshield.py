"""Offline tests of isc_dshield (P151) with the recorded SANS ISC answers in tests/fixtures/isc_dshield/
(8.8.8.8 and 1.1.1.1 IP answers, the AS15169 '[]' answer, the research threat category and the two blockme
redirects are real; the attack-count, empty-IP, ASN-record and 429 shapes are synthetic from the ISC API page)."""

from __future__ import annotations

import json
import os
import re

import pytest

from tests.fakes import DeadHttp, FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core.context import RunInfo, ScanOptions
from v3lum.core.entities import Entity, EntityType
from v3lum.core.models import Severity, Status
from v3lum.modules.threat_intel_ioc import isc_dshield as mod
from v3lum.modules.threat_intel_ioc.isc_dshield import (
    ATTRIBUTION,
    IscDshield,
    load_json,
    normalise_ipv4,
    parse_asnum,
    parse_ip,
    parse_threatcategory,
    report_severity,
)

FIX = "isc_dshield"
IP_URL = "https://isc.sans.edu/api/ip/{ip}?json"
RESEARCH_URL = "https://isc.sans.edu/api/threatcategory/research?json"
ASN_URL = "https://isc.sans.edu/api/asnum/100/{asn}?json"
CONTACT = {"contact_email": "soc@example.com"}
TEXT_JSON = {"content-type": "text/json;charset=UTF-8"}  # ISC's real content type


def raw(name: str) -> bytes:
    data = module_fixture(FIX, name)
    return data.encode() if isinstance(data, str) else json.dumps(data).encode()


def ip_route(http: FakeHttp, ip: str, name: str, **kw) -> FakeHttp:
    return http.add("GET", IP_URL.format(ip=ip), body=raw(name), headers=TEXT_JSON, **kw)


def research_route(http: FakeHttp, records: list | None = None) -> FakeHttp:
    body = json.dumps(records).encode() if records is not None else raw("threatcategory_research_ok.json")
    return http.add("GET", RESEARCH_URL, body=body, headers=TEXT_JSON)


@pytest.fixture
def doc_ips(monkeypatch):
    """Synthetic shapes use documentation addresses: let applies() accept them in tests."""
    monkeypatch.setattr(mod, "is_public_ip", lambda value: True)


# --------------------------------------------------------------------------------------
# metadata and parsers (P151 c1-c6)
# --------------------------------------------------------------------------------------


def test_metadata_matches_the_council_decision():
    cls = IscDshield
    assert (cls.terms, cls.default_enabled, cls.trust_tier, cls.disclosure, cls.shares_input) == ("noncommercial", True, "trusted", "third_party", True)
    assert cls.min_interval >= 1.0 and cls.cache_ttl == 86400 and cls.hosts == ("isc.sans.edu",) and cls.sources == ("sans_isc.api",)
    assert cls.manual_link == "scanner_intel_g02_3:isc_ipinfo" and not cls.requires_keys and cls.produces == frozenset({EntityType.ASN})


def test_parsers_are_defensive():
    assert normalise_ipv4("203.000.113.005") == "203.0.113.5" and normalise_ipv4("256.1.1.1") is None
    assert load_json(raw("ip_xml_default_synthetic.xml"))[1].startswith("XML")
    assert load_json(b"<!doctype html><html><head></head></html>")[1] == "HTML instead of JSON"
    assert parse_ip({"ip": {"error": "bad IP"}})["error"] == "bad IP" and parse_ip(["x"])["error"]
    assert parse_asnum({"asnum": {"data": module_fixture(FIX, "asnum_docs_synthetic.json")}})["records"][1]["reports"] == 5008
    assert parse_asnum("junk")["error"]
    index = parse_threatcategory(module_fixture(FIX, "threatcategory_research_ok.json"))
    assert index["64.39.102.73"]["type"] == "qualys" and len(index) == 6
    assert parse_threatcategory({"research": [{"ipv4": "4.16.74.81", "type": "scorecard"}]})["4.16.74.81"]["type"] == "scorecard"


def test_report_severity_is_at_most_medium_and_decays():
    from datetime import datetime, timezone

    now = datetime(2026, 11, 26, tzinfo=timezone.utc)
    assert report_severity("2026-11-20", now) == ("medium", False)
    assert report_severity("2026-10-01", now) == ("low", False)
    assert report_severity("2026-01-01", now) == ("info", True)


# --------------------------------------------------------------------------------------
# recorded IP answers (P151 c3-c6)
# --------------------------------------------------------------------------------------


def test_recorded_8888_answer_with_feeds_asn_pivot_and_attribution():
    http = research_route(ip_route(FakeHttp(), "8.8.8.8", "ip_ok_8888.json", match_headers={
        "Accept": "application/json", "User-Agent": re.compile(r"^V3LUM/\S+ \(\+soc@example\.com\)$"),
    }))
    res = run_module(IscDshield, "ipv4:8.8.8.8", http, settings=CONTACT)
    assert res.status is Status.OK and not res.error
    assert res.attributes["data_attribution"] == ATTRIBUTION == "SANS ISC / DShield"
    assert res.attributes["asn"] == "AS15169" and res.attributes["as_org"] == "GOOGLE" and res.attributes["as_country"] == "US"
    assert res.attributes["abuse_contact"] == "network-abuse@google.com"
    assert res.attributes["dshield_reports"]["reports"] == 0 and res.attributes["dshield_reports"]["network"] == "8.8.8.0/24"
    assert [f["feed"] for f in res.attributes["isc_threatfeeds"]] == ["mastodon", "miner", "myip", "openresolver"]
    [feeds] = res.findings
    assert feeds.severity is Severity.INFO and "context_only" in feeds.tags  # feed membership is never a verdict
    assert [(p.entity.key, p.relation) for p in res.pivots] == [("asn:AS15169", "belongs_to_asn")]
    assert all("?json" in c["url"] for c in http.calls)
    http.assert_hosts_within(IscDshield)


def test_recorded_1111_answer():
    http = research_route(ip_route(FakeHttp(), "1.1.1.1", "ip_ok_1111.json"))
    res = run_module(IscDshield, "ipv4:1.1.1.1", http, settings=CONTACT)
    assert res.status is Status.OK and res.attributes["asn"] == "AS13335"
    assert "rosti" in {f["feed"] for f in res.attributes["isc_threatfeeds"]}


def test_attack_counts_are_scanner_medium_with_first_and_last_seen(doc_ips):
    http = research_route(ip_route(FakeHttp(), "203.0.113.77", "ip_attacks_synthetic.json"))
    res = run_module(IscDshield, "ipv4:203.0.113.77", http, settings=CONTACT)
    reported = next(f for f in res.findings if "scanner" in f.tags)
    assert reported.severity is Severity.MEDIUM and reported.criterion and "opportunistic" in reported.description
    assert str(reported.observed_first).startswith("2026-10-08") and str(reported.observed_last).startswith("2026-11-20")
    assert max(f.severity for f in res.findings) <= Severity.MEDIUM  # c5: at most MEDIUM alone
    assert res.attributes["dshield_reports"]["reports"] == 9843 and res.attributes["dshield_reports"]["targets"] == 34


def test_old_reports_are_historical_info(doc_ips):
    doc = module_fixture(FIX, "ip_attacks_synthetic.json")
    doc["ip"]["maxdate"] = "2025-12-01"
    http = research_route(FakeHttp().add("GET", IP_URL.format(ip="203.0.113.77"), body=json.dumps(doc).encode(), headers=TEXT_JSON))
    res = run_module(IscDshield, "ipv4:203.0.113.77", http, settings=CONTACT)
    reported = next(f for f in res.findings if "scanner" in f.tags)
    assert reported.severity is Severity.INFO and "historical" in reported.tags and reported.confidence_label.value == "possible"


def test_research_category_marks_a_benign_scanner():
    doc = module_fixture(FIX, "ip_ok_8888.json")
    doc["ip"]["number"] = "64.39.102.73"
    http = research_route(FakeHttp().add("GET", IP_URL.format(ip="64.39.102.73"), body=json.dumps(doc).encode(), headers=TEXT_JSON))
    res = run_module(IscDshield, "ipv4:64.39.102.73", http, settings=CONTACT)
    benign = next(f for f in res.findings if "benign_scanner" in f.tags)
    assert benign.title == "Known research scanner (qualys)" and benign.data["suppression_rule"] == "isc_research_scanner"
    assert res.attributes["isc_research_scanner"]["type"] == "qualys" and res.attributes["is_scanner"] is True


def test_empty_ip_answer_is_answered_without_reports(doc_ips):
    http = research_route(ip_route(FakeHttp(), "192.0.2.44", "ip_empty_synthetic.json"), records=[])
    res = run_module(IscDshield, "ipv4:192.0.2.44", http, settings=CONTACT)
    assert res.status is Status.OK and not res.findings and not res.pivots
    assert res.attributes["dshield_reports"]["reports"] == 0


# --------------------------------------------------------------------------------------
# could not verify (rule 5, P321 blockme)
# --------------------------------------------------------------------------------------


def test_recorded_blockme_redirect_is_blocked_and_short_circuits_the_host():
    ex = module_fixture(FIX, "blockme_redirect_threatfeeds.json")
    http = FakeHttp().add("GET", IP_URL.format(ip="8.8.8.8"), status=ex["status"], headers=ex["headers"], redirect_to=ex["headers"]["location"])
    rt = make_runtime(http, settings=CONTACT)
    res = run_module(IscDshield, "ipv4:8.8.8.8", runtime=rt)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge" and "blockme" in res.error
    again = run_module(IscDshield, "ipv4:8.8.8.8", runtime=rt)
    assert again.status is Status.BLOCKED and len(http.calls) == 1  # backoff: never retried in the run


def test_blockme_page_served_at_the_final_url_is_blocked():
    http = FakeHttp().add("GET", IP_URL.format(ip="8.8.8.8"), status=200, text=module_fixture(FIX, "blockme_page.html"), final_url="https://isc.sans.edu/blockme.html")
    res = run_module(IscDshield, "ipv4:8.8.8.8", http, settings=CONTACT)
    assert res.status is Status.BLOCKED


def test_research_list_blockme_never_hides_the_ip_answer():
    http = ip_route(FakeHttp(), "8.8.8.8", "ip_ok_8888.json")
    http.add("GET", RESEARCH_URL, status=302, redirect_to="/blockme.html")
    res = run_module(IscDshield, "ipv4:8.8.8.8", http, settings=CONTACT)
    assert res.status is Status.OK and res.attributes["asn"] == "AS15169"
    assert "research-scanner list: could not verify" in res.error


def test_429_403_5xx_xml_html_and_error_bodies_are_could_not_verify():
    ex = module_fixture(FIX, "rate_limited_429_synthetic.json")
    rate = FakeHttp().add("GET", IP_URL.format(ip="8.8.8.8"), status=429, text="", headers=ex["headers"])
    assert run_module(IscDshield, "ipv4:8.8.8.8", rate, settings=CONTACT).status is Status.RATE_LIMITED
    assert len(rate.calls) == 1  # Retry-After 300 s: no retry inside the run
    cases = {
        Status.BLOCKED: FakeHttp().add("GET", IP_URL.format(ip="8.8.8.8"), status=403, text="forbidden"),
        Status.ERROR: FakeHttp().add("GET", IP_URL.format(ip="8.8.8.8"), status=503, text="busy"),
    }
    for want, http in cases.items():
        assert run_module(IscDshield, "ipv4:8.8.8.8", http, settings=CONTACT).status is want
    for content in (raw("ip_xml_default_synthetic.xml"), b"{broken", b'{"ip": {"error": "bad IP address"}}', b"<html><body>maintenance</body></html>"):
        http = FakeHttp().add("GET", IP_URL.format(ip="8.8.8.8"), status=200, body=content, headers=TEXT_JSON)
        res = run_module(IscDshield, "ipv4:8.8.8.8", http, settings=CONTACT)
        assert res.status is Status.ERROR and "could not verify" in res.error and not res.findings, content


def test_dead_network_is_an_error():
    assert run_module(IscDshield, "ipv4:8.8.8.8", DeadHttp(), settings=CONTACT).status is Status.ERROR


def test_without_contact_email_it_is_skipped_config_before_any_request():
    http = FakeHttp()
    res = run_module(IscDshield, "ipv4:8.8.8.8", http)
    assert res.status is Status.SKIPPED and res.reason_code == "config" and not http.calls


# --------------------------------------------------------------------------------------
# ASN input
# --------------------------------------------------------------------------------------


def test_recorded_empty_asn_answer_is_empty_never_clean():
    http = FakeHttp().add("GET", ASN_URL.format(asn=15169), body=raw("asnum_empty_15169.json"), headers=TEXT_JSON)
    res = run_module(IscDshield, "asn:AS15169", http, settings=CONTACT)
    assert res.status is Status.EMPTY and res.attributes["isc_asn_reports"]["listed"] == 0 and not res.findings


def test_asn_records_are_listed_never_pivoted():
    http = FakeHttp().add("GET", ASN_URL.format(asn=64500), body=raw("asnum_docs_synthetic.json"), headers=TEXT_JSON)
    res = run_module(IscDshield, "asn:AS64500", http, settings=CONTACT)
    assert res.status is Status.OK and not res.pivots
    summary = res.attributes["isc_asn_reports"]
    assert summary["listed"] == 2 and summary["top"][0] == {"ip": "203.0.113.94", "reports": 5008, "targets": 4307, "first_seen": None, "last_seen": "2026-11-13"}
    [finding] = res.findings
    assert finding.severity is Severity.INFO and "context_only" in finding.tags


def test_recorded_asn_blockme_redirect_is_blocked():
    ex = module_fixture(FIX, "blockme_redirect_asnum.json")
    http = FakeHttp().add("GET", ASN_URL.format(asn=4837), status=302, headers=ex["headers"], redirect_to=ex["headers"]["location"])
    assert run_module(IscDshield, "asn:AS4837", http, settings=CONTACT).status is Status.BLOCKED


# --------------------------------------------------------------------------------------
# licence profile (P151 c1-c2, c4)
# --------------------------------------------------------------------------------------


def _decide(settings: dict) -> object:
    from v3lum.core import policy

    rt = make_runtime(FakeHttp(), settings=settings)
    ent = Entity.make(EntityType.IPV4, "8.8.8.8")
    return policy.decide(IscDshield, ent, policy.make_context(rt, ScanOptions(), path="run"), run=RunInfo(entity=ent, is_seed=True))


def test_corporate_profile_needs_the_licence_allow_entry(tmp_path):
    assert _decide(CONTACT).reason_code == "licence"
    allow = tmp_path / "licence_allow.json"
    allow.write_text(json.dumps({"schema": "v3lum.licence_allow/1", "entries": [{
        "source_id": "sans_isc.api", "basis": "terms_clause", "scope": "defence of the company's own networks only, no resale, no paid deliverables",
        "legal_ref": "LEGAL-TEST-1", "approver": "legal (test)", "decided_at": "2026-11-01", "review_by": "2027-05-01",
        "evidence_url": "https://isc.sans.edu/api/", "quote": "ok to use this data ... to protect your own company's network",
    }]}))
    os.chmod(allow, 0o600)
    assert _decide({**CONTACT, "licence_allow_path": str(allow)}).allowed
    no_contact = _decide({"licence_allow_path": str(allow)})
    assert not no_contact.allowed and no_contact.reason_code == "config"  # c4: ISC asks for an identifying contact


def test_acceptance_routes_of_the_golden_ipv4_replay():
    from tests.fakes import FIXTURES

    doc = json.loads((FIXTURES / "acceptance" / "ipv4" / "isc_dshield.json").read_text(encoding="utf-8"))
    assert doc["schema"] == "v3lum.acceptance_routes/1" and doc["module"] == "isc_dshield"
    http = FakeHttp()
    for r in doc["routes"]:
        http.add(r["method"], r["url"], status=r["status"], json=r["json"], headers=r.get("headers") or {})
    res = run_module(IscDshield, "ipv4:8.8.8.8", http, settings=CONTACT)
    assert res.status is Status.OK and len(http.calls) == len(doc["routes"])
    assert all(f.severity is Severity.INFO for f in res.findings)  # benign golden input: no non-info finding
