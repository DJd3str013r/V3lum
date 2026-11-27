"""Offline tests of criminalip (P048) with the fixtures in tests/fixtures/criminalip/.

nokey_error_in_200.http.json is the recorded research answer (C0099, 2026-11-25: HTTP 200 with body
status 403 'check access failed'). The report fixtures are synthetic (field names recalled from the
Criminal IP API documentation, values on documentation space): no team-key capture exists (P048
cond 5). The credit and rate-limit bodies are synthetic.
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum import config
from v3lum.core.models import Status
from v3lum.core.tlp import TLP
from v3lum.modules.ip_network.criminalip import (
    ENDPOINTS,
    SOURCE,
    CriminalIp,
    criminalip_url,
    parse_domain_report,
    parse_domain_reports,
    parse_ip_report,
    score_vote,
)
from v3lum.modules.ip_network.scan_engines import EndpointRefused

FIX = "criminalip"
KEY = "cip-test-key-0123456789abcdef"  # fake key
KEYS = {"criminalip": KEY}
IP_REPORT = "https://api.criminalip.io/v1/asset/ip/report?ip={ip}"
REPORTS = "https://api.criminalip.io/v1/domain/reports?query={d}&offset=0"
REPORT = "https://api.criminalip.io/v2/domain/report/{sid}"


def fx(name: str):
    return module_fixture(FIX, name)


def http_fx(name: str) -> dict:
    resp = fx(name)["response"]
    return {"status": resp["status"], "json": resp["body"], "headers": resp.get("headers") or {}}


def test_metadata_follows_the_council_decision():
    cls = CriminalIp
    assert (cls.terms, cls.default_enabled, cls.requires_keys, cls.opsec.label) == ("key-terms", False, ("criminalip",), "passive")
    assert cls.trust_tier == "community" and cls.max_tlp == TLP.AMBER  # registry tier (P057 stricter than P048's trusted)
    assert "V3LUM_CRIMINALIP_KEY" in config.key_registry()["criminalip"].env
    assert cls.manual_link == "https://search.criminalip.io/asset/report/{ip}"  # c4
    assert cls.hosts == ("api.criminalip.io",)


def test_scan_endpoints_cannot_be_built_in_any_mode():
    assert set(ENDPOINTS) == {"ip_report", "domain_reports", "domain_report"}
    assert not any(path.endswith("/scan") or "/scan/" in path or "status" in path or "lite" in path or "private" in path
                   for path in ENDPOINTS.values())
    for forbidden in ("domain_scan", "scan", "/v1/domain/scan", "domain_scan_private", "domain_lite_scan", "domain_status",
                      "url_scan", "/v1/domain/status/1"):
        with pytest.raises(EndpointRefused):
            criminalip_url(forbidden, "example.com")
    assert criminalip_url("ip_report", "8.8.8.8") == ("https://api.criminalip.io/v1/asset/ip/report", {"ip": "8.8.8.8"})
    for op, bad in (("ip_report", "10.0.0.1"), ("domain_reports", "not a domain"), ("domain_report", "0")):
        with pytest.raises(ValueError):
            criminalip_url(op, bad)


def test_ip_report_with_key_in_header_and_one_vote():
    http = FakeHttp().add("GET", IP_REPORT.format(ip="8.8.8.8"), json=fx("ip_report_ok_synthetic.json"), match_headers={"x-api-key": KEY})
    res = run_module(CriminalIp, "ipv4:8.8.8.8", http, keys=KEYS)
    assert res.status is Status.OK
    (call,) = http.calls
    assert KEY not in call["url"]
    a = res.attributes
    assert a["criminalip_score"] == {"inbound": "Dangerous", "outbound": "Moderate", "vote": "malicious"}
    assert a["is_hosting"] is True and a["is_scanner"] is True and "cloud" in a["context_tags"]
    assert a["open_ports"] == [22, 443] and a["asn"] == "AS64500" and a["country"] == "BR"
    assert sorted(a["vulns"]) == ["CVE-2021-23017", "CVE-2021-41617", "CVE-2023-38408"]
    assert len(a["ids_alerts"]) == 2
    by_title = {f.title: f for f in res.findings}
    vote = by_title["Criminal IP risk score (one vote)"]
    assert vote.severity.name == "MEDIUM" and "malicious" not in vote.tags and "weak_signal" in vote.tags  # c4
    vulns = by_title["CVE(s) associated with exposed software (version-inferred)"]
    assert vulns.severity.name == "HIGH" and vulns.confidence_label.value == "possible" and "version_inferred" in vulns.tags  # P291 cap
    assert all(f.source == SOURCE and f.criterion for f in res.findings)
    assert {(p.relation, p.entity.value) for p in res.pivots} == {
        ("reverse_dns", "host30.example.com"), ("hosted_domain", "www.example.com"), ("hosted_domain", "files.example.net")}
    assert all(p.expand is False for p in res.pivots)
    assert ("Criminal IP asset report (manual; foreign provider: queries are logged abroad)",
            "https://search.criminalip.io/asset/report/8.8.8.8") in res.links
    assert_no_secret(KEY, res)
    http.assert_hosts_within(CriminalIp)


def test_report_with_nothing_recorded_is_empty():
    http = FakeHttp().add("GET", IP_REPORT.format(ip="8.8.4.4"), json=fx("ip_report_empty_synthetic.json"))
    res = run_module(CriminalIp, "ipv4:8.8.4.4", http, keys=KEYS)
    assert res.status is Status.EMPTY and not res.findings


def test_domain_uses_existing_reports_only():
    http = (FakeHttp()
            .add("GET", REPORTS.format(d="example.com"), json=fx("domain_reports_ok_synthetic.json"))
            .add("GET", REPORT.format(sid=9100002), json=fx("domain_report_ok_synthetic.json")))
    res = run_module(CriminalIp, "domain:example.com", http, keys=KEYS)
    assert res.status is Status.OK
    assert all("scan" not in c["url"] for c in http.calls) and len(http.calls) == 2
    rel = {(p.relation, p.entity.value) for p in res.pivots}
    assert ("resolves_to", "198.51.100.30") in rel and ("subdomain", "mail.example.com") in rel
    assert ("links_to", "partner.example.net") in rel
    assert all(p.expand is False for p in res.pivots)
    assert res.attributes["third_party_scans"][0]["report_id"] == 9100002


def test_url_input_sends_only_its_host():
    http = FakeHttp().add("GET", REPORTS.format(d="www.example.com"), json={"data": {"count": 0, "reports": []}, "status": 200})
    res = run_module(CriminalIp, "url:https://www.example.com/login?user=x", http, keys=KEYS)
    assert res.status is Status.EMPTY and "never requests a new scan" in res.error
    (call,) = http.calls
    assert "login" not in call["url"] and "user" not in call["url"]


def test_recorded_no_key_answer_inside_200_is_needs_key_never_empty():
    http = FakeHttp().add("GET", IP_REPORT.format(ip="8.8.8.8"), **http_fx("nokey_error_in_200.http.json"))
    res = run_module(CriminalIp, "ipv4:8.8.8.8", http, keys=KEYS)
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key"


@pytest.mark.parametrize(
    ("fixture", "status", "code"),
    [
        ("quota_error_in_200_synthetic.http.json", Status.QUOTA, "quota"),
        ("rate_limited_error_in_200_synthetic.http.json", Status.RATE_LIMITED, "rate_limited"),
    ],
)
def test_credit_and_rate_limit_bodies_inside_200(fixture, status, code):
    http = FakeHttp().add("GET", IP_REPORT.format(ip="8.8.8.8"), **http_fx(fixture))
    res = run_module(CriminalIp, "ipv4:8.8.8.8", http, keys=KEYS)
    assert res.status is status and res.reason_code == code


def test_other_errors_429_5xx_and_malformed():
    body = {"data": {}, "message": "internal error", "status": 500}
    assert run_module(CriminalIp, "ipv4:8.8.8.8", FakeHttp().add("GET", IP_REPORT.format(ip="8.8.8.8"), json=body), keys=KEYS).status is Status.ERROR
    http = FakeHttp().add("GET", IP_REPORT.format(ip="8.8.8.8"), status=429, text="slow down")
    assert run_module(CriminalIp, "ipv4:8.8.8.8", http, keys=KEYS).status is Status.RATE_LIMITED
    http = FakeHttp().add("GET", IP_REPORT.format(ip="8.8.8.8"), status=503, text="down", times=3)
    assert run_module(CriminalIp, "ipv4:8.8.8.8", http, keys=KEYS).status is Status.ERROR
    http = FakeHttp().add("GET", IP_REPORT.format(ip="8.8.8.8"), json=["x"])
    assert run_module(CriminalIp, "ipv4:8.8.8.8", http, keys=KEYS).status is Status.ERROR
    http = FakeHttp().add("GET", IP_REPORT.format(ip="8.8.8.8"), status=401, json={"message": "unauthorized"})
    assert run_module(CriminalIp, "ipv4:8.8.8.8", http, keys=KEYS).status is Status.NEEDS_KEY


def test_missing_key_private_ip_and_deep_pivots_send_nothing():
    http = FakeHttp()
    assert run_module(CriminalIp, "ipv4:8.8.8.8", http).status is Status.NEEDS_KEY
    assert run_module(CriminalIp, "ipv4:192.168.1.1", http, keys=KEYS).status is Status.SKIPPED
    assert run_module(CriminalIp, "ipv4:8.8.8.8", http, keys=KEYS, is_seed=False, depth=2).status is Status.SKIPPED
    assert not http.calls


def test_vote_and_parsers_are_defensive():
    assert score_vote("Safe", "Low") == "benign" and score_vote("Moderate", "") == "suspicious"
    assert score_vote("critical", "safe") == "malicious" and score_vote("", "") == "unknown"
    for junk in (None, 1, [], {"status": 403, "message": "check access failed"}, {"unexpected": 1}):
        assert parse_ip_report(junk) is None
    for junk in (None, {}, {"data": {"reports": "x"}}, {"status": 500, "data": {"reports": []}}):
        assert parse_domain_reports(junk) is None
    assert parse_domain_report({"status": 200, "data": "x"}) is None
    parsed = parse_ip_report({"status": 200, "issues": {}, "score": {}, "port": {"data": [{"open_port_no": "x"}, 7]}})
    assert parsed["empty"] is True and parsed["ports"] == []
