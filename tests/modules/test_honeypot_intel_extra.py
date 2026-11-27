"""Offline tests of honeypot_intel_extra (P147 c3, c4) with the HoneyLabs CVE answers and the
jamesbrine.com.au slices in tests/fixtures/honeypot_intel_extra/."""

from __future__ import annotations

import copy

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.datasets import DATASETS
from v3lum.core.models import Severity, Status
from v3lum.modules.threat_intel_ioc.honeypot_intel_extra import (
    JB_ACTIVITY,
    JB_IPLIST,
    MAX_ACTORS,
    SRC_HONEYLABS,
    SRC_JB_ACTIVITY,
    SRC_JB_IPLIST,
    HoneypotIntelExtra,
    parse_honeylabs_cve,
    parse_jb_activity,
)

FIX = "honeypot_intel_extra"
CVE_URL = "https://honeylabs.net/api/cves/{cve}"
JB = "https://jamesbrine.com.au/"


def fx(name: str):
    return module_fixture(FIX, name)


def jb_routes(http: FakeHttp | None = None) -> FakeHttp:
    http = http or FakeHttp()
    http.add("GET", JB + "iplist.txt", body=fx("jamesbrine_iplist_ok.txt").encode(), headers={"content-type": "text/plain"})
    http.add("GET", JB + "csv", body=fx("jamesbrine_csv_ok.txt").encode(), headers={"content-type": "text/csv"})
    return http


def test_unknown_terms_keep_the_module_out_of_every_default():
    cls = HoneypotIntelExtra
    assert (cls.default_enabled, cls.terms, cls.trust_tier) == (False, "unknown", "unknown")
    assert cls.max_tlp.value_str == "green"  # unknown tier: excluded at AMBER and above (A8)
    for name, source in ((JB_IPLIST, SRC_JB_IPLIST), (JB_ACTIVITY, SRC_JB_ACTIVITY)):
        assert (DATASETS[name]["source"], DATASETS[name]["terms_class"], DATASETS[name]["large"]) == (source, "unknown", False)
    assert "type_" not in DATASETS[JB_IPLIST]["url"]  # never the 14 MB JSON files (c4)


def test_honeylabs_cve_parser_caps_actors_and_drops_udp_sources():
    doc = fx("honeylabs_cve_actors_synthetic.json")
    data = parse_honeylabs_cve(doc)
    assert data["cve"] == "CVE-2021-44228" and data["actively_exploited"] is True and data["kev"] is True
    assert len(data["actors"]) == MAX_ACTORS and data["actors_total"] == 25
    assert data["actors"][0]["events"] >= data["actors"][-1]["events"] and data["window"] == "7d"
    udp = copy.deepcopy(doc)
    udp["actors"][0]["protocol"] = "udp"
    data = parse_honeylabs_cve(udp)
    assert data["actors_excluded_udp"] == 1 and "203.0.113.1" not in {a["ip"] for a in data["actors"]}  # c7


def test_cve_telemetry_lists_the_top_20_attackers_as_unexpanded_pivots():
    http = FakeHttp().add("GET", CVE_URL.format(cve="CVE-2021-44228"), json=fx("honeylabs_cve_actors_synthetic.json"))
    res = run_module(HoneypotIntelExtra, "cve:CVE-2021-44228", http)
    assert res.status is Status.OK
    [finding] = res.findings
    assert finding.title == "Exploitation attempts seen by HoneyLabs honeypots" and finding.severity is Severity.LOW
    assert "kev" in finding.tags and "malicious" not in finding.tags and finding.criterion
    assert len(res.pivots) == MAX_ACTORS
    assert all(p.relation == "exploit_attempted_by" and p.expand is False for p in res.pivots)
    activity = res.attributes["honeypot_cve_activity"]
    assert activity["events"] == 15570 and activity["patterns"] == ["jndi%3a", "jndi:"]
    assert res.attributes["exploited_in_wild"] is True
    assert res.source_statuses[SRC_JB_IPLIST]["status"] == "skipped"
    http.assert_hosts_within(HoneypotIntelExtra)


def test_cve_without_activity_in_the_window_keeps_the_facts_without_a_finding():
    http = FakeHttp().add("GET", CVE_URL.format(cve="CVE-2021-44228"), json=fx("honeylabs_cve_no_activity.json"))
    res = run_module(HoneypotIntelExtra, "cve:CVE-2021-44228", http)
    assert res.status is Status.OK and not res.findings and not res.pivots
    assert res.attributes["honeypot_cve_activity"]["events"] == 0


def test_honeylabs_failures_are_could_not_verify():
    http = FakeHttp().add("GET", CVE_URL.format(cve="CVE-2021-44228"), status=429, text="slow down")
    assert run_module(HoneypotIntelExtra, "cve:CVE-2021-44228", http).status is Status.RATE_LIMITED
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http2 = FakeHttp().add("GET", CVE_URL.format(cve="CVE-2021-44228"), status=403, text=page)
    assert run_module(HoneypotIntelExtra, "cve:CVE-2021-44228", http2).status is Status.BLOCKED
    http3 = FakeHttp().add("GET", CVE_URL.format(cve="CVE-2021-44228"), json=fx("honeylabs_cves_7d_ok.json"))  # not a CVE object
    res = run_module(HoneypotIntelExtra, "cve:CVE-2021-44228", http3)
    assert res.status is Status.ERROR and "could not verify" in res.error
    http4 = FakeHttp().add("GET", CVE_URL.format(cve="CVE-2021-44228"), json=fx("honeylabs_lookup_needs_key_401.json"))
    assert run_module(HoneypotIntelExtra, "cve:CVE-2021-44228", http4).status is Status.ERROR  # error inside HTTP 200


def test_jamesbrine_listing_is_a_low_scanner_sighting():
    http = jb_routes()
    res = run_module(HoneypotIntelExtra, "ipv4:45.133.18.54", http)
    assert res.status is Status.OK
    [finding] = res.findings
    assert finding.severity is Severity.LOW and finding.tags == ["scanner"] and finding.source == SRC_JB_IPLIST
    assert res.source_statuses[SRC_JB_IPLIST]["status"] == "ok" and res.source_statuses[SRC_JB_ACTIVITY]["status"] == "empty"
    assert res.source_statuses[SRC_HONEYLABS]["reason_code"] == "not_applicable"
    http.assert_hosts_within(HoneypotIntelExtra, extra=("jamesbrine.com.au",))


def test_jamesbrine_activity_row_gives_the_date():
    res = run_module(HoneypotIntelExtra, "ipv4:8.216.3.63", jb_routes())
    [finding] = res.findings
    assert finding.observed_last.startswith("2026-11-24") and "brute force host" in finding.description
    assert parse_jb_activity(fx("jamesbrine_csv_ok.txt"))["8.216.3.84"] == [{"activity": "brute force host", "date": "2026-11-24"}]


def test_not_listed_is_empty():
    assert run_module(HoneypotIntelExtra, "ipv4:8.8.4.4", jb_routes()).status is Status.EMPTY


def test_missing_feed_is_could_not_verify():
    http = FakeHttp().add("GET", JB + "iplist.txt", status=503, text="down")  # no local copy in this test's home
    res = run_module(HoneypotIntelExtra, "ipv4:8.8.4.4", http)
    assert res.status is Status.ERROR and "could not verify" in res.error


def test_licence_blocked_sources_are_never_used():
    http = FakeHttp()
    assert run_module(HoneypotIntelExtra, "ipv4:45.133.18.54", http, allowed_sources=()).reason_code == "licence"
    assert run_module(HoneypotIntelExtra, "cve:CVE-2021-44228", http, allowed_sources=()).reason_code == "licence"
    assert http.calls == []
