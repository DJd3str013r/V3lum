"""vulncheck (P186): VulnCheck KEV lookups with the company key (default off).

Fixtures in tests/fixtures/vulncheck/: ``kev_nokey_401.http.json`` is the research answer without a key (the
only real VulnCheck body: P186 cond 4 says a success fixture is captured with the team key before merge);
``kev_ok``, ``kev_empty``, ``backup_ok`` and ``rate_limited.http`` are DOC-SHAPED from the v3 documentation
(example.com values, no real key or signature).
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core.models import Opsec, Status
from v3lum.modules.vulnerability_cve.cve_record import CASE_COUNTERS, CVE_FANOUT_SETTING
from v3lum.modules.vulnerability_cve.vulncheck import KEV_URL, VulnCheck, parse_vulncheck_kev, vulncheck_export_view

CVE = "CVE-2021-44228"
URL = KEV_URL + "?cve={cve}"
KEY = "vulncheck_test_token_0123456789abcdef"
CHALLENGE = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body><div id='cf-chl-widget'></div></body></html>"


@pytest.fixture(autouse=True)
def fresh_counters():
    CASE_COUNTERS.reset()
    yield
    CASE_COUNTERS.reset()


def fx(name: str):
    return module_fixture(VulnCheck, name)


def exchange(name: str) -> dict:
    resp = fx(name)["response"]
    return {"status": resp["status"], "headers": resp["headers"], "body": resp["body"].encode()}


def run(http: FakeHttp, cve: str = CVE, **kw):
    kw.setdefault("keys", {"vulncheck": KEY})
    return run_module(VulnCheck, f"cve:{cve}", http, **kw)


def test_metadata_matches_the_council_decision():
    cls = VulnCheck
    assert cls.default_enabled is False and cls.terms == "key-terms" and cls.trust_tier == "trusted"
    assert cls.requires_keys == ("vulncheck",) and cls.opsec is Opsec.PASSIVE and cls.disclosure == "third_party"
    assert cls.hosts == ("api.vulncheck.com",) and cls.sources == ("vulncheck.kev_index",) and cls.max_requests == 1


def test_hit_goes_to_exploited_never_kev():
    http = FakeHttp().add("GET", URL.format(cve=CVE), json=fx("kev_ok.json"), match_headers={"Authorization": f"Bearer {KEY}"})
    res = run(http)
    assert res.status is Status.OK, res.error
    a = res.attributes
    assert a["exploited"] == {"vulncheck_kev": "2021-12-06"}  # the earliest of date_added and reported dates
    assert "kev" not in a and "kev_date_added" not in a  # kev stays CISA KEV (cond 3)
    assert "https://blog.example.com/log4shell-in-the-wild" in a["exploitation_refs"]
    assert a["exploit_refs"] == ["https://vulncheck.com/xdb/0123456789ab"] and a["exploit_available"] is True
    assert a["vulncheck_kev"]["ransomware_use"] == "Known" and "not redistributed" in a["vulncheck_kev"]["note"]
    assert not res.findings
    assert_no_secret(KEY, res.raw, res.attributes, res.error)
    http.assert_hosts_within(VulnCheck)


def test_absent_is_empty_and_says_so_honestly():
    res = run(FakeHttp().add("GET", URL.format(cve=CVE), json=fx("kev_empty.json")))
    assert res.status is Status.EMPTY and "no evidence" in res.error


def test_missing_key_is_needs_key_without_a_request():
    http = FakeHttp()
    res = run_module(VulnCheck, f"cve:{CVE}", http)
    assert res.status is Status.NEEDS_KEY and http.calls == []


@pytest.mark.parametrize("status", [401, 403])
def test_refused_key_is_needs_key(status):
    ex = exchange("kev_nokey_401.http.json")
    res = run(FakeHttp().add("GET", URL.format(cve=CVE), status=status, body=ex["body"], headers=ex["headers"]))
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key"


def test_402_plan_without_the_index_is_needs_key():
    res = run(FakeHttp().add("GET", URL.format(cve=CVE), status=402, json={"error": True, "errors": ["payment required"]}))
    assert res.status is Status.NEEDS_KEY and "402" in res.error


def test_429_is_rate_limited():
    ex = exchange("rate_limited.http.json")
    res = run(FakeHttp().add("GET", URL.format(cve=CVE), status=429, body=ex["body"], headers=ex["headers"]))
    assert res.status is Status.RATE_LIMITED


def test_error_envelope_inside_200_is_an_error_never_empty():
    res = run(FakeHttp().add("GET", URL.format(cve=CVE), json={"error": True, "errors": ["internal"]}))
    assert res.status is Status.ERROR and "VulnCheck" in res.error


def test_5xx_malformed_and_challenge_are_could_not_verify():
    assert run(FakeHttp().add("GET", URL.format(cve=CVE), status=500, text="boom")).status is Status.ERROR
    malformed = FakeHttp().add("GET", URL.format(cve=CVE), body=b'{"data": [', headers={"content-type": "application/json"})
    assert run(malformed).status is Status.ERROR
    assert run(FakeHttp().add("GET", URL.format(cve=CVE), json={"data": "x"})).status is Status.ERROR
    assert run(FakeHttp().add("GET", URL.format(cve=CVE), status=403, text=CHALLENGE)).status is Status.BLOCKED


def test_answer_for_another_cve_is_not_a_hit():
    other = json.loads(json.dumps(fx("kev_ok.json")))
    other["data"][0]["cve"] = ["CVE-2020-0001"]
    res = run(FakeHttp().add("GET", URL.format(cve=CVE), json=other))
    assert res.status is Status.ERROR


def test_fan_out_rule_defers_pivot_cves():
    http = FakeHttp()
    res = run(http, is_seed=False, case_id="c1", settings={CVE_FANOUT_SETTING: 0})
    assert res.status is Status.QUOTA and http.calls == []


def test_parser_and_export_view():
    parsed = parse_vulncheck_kev(fx("kev_ok.json"))
    assert parsed["total"] == 1 and parsed["entries"][0]["cves"] == [CVE]
    assert parse_vulncheck_kev({"error": True, "errors": ["unauthorized"]}) is None
    assert parse_vulncheck_kev([{"cve": [CVE], "date_added": "2021-12-06T00:00:00Z"}])["entries"][0]["date_added"] == "2021-12-06"
    entry = parsed["entries"][0]
    assert vulncheck_export_view(CVE, entry) == {"cve": CVE, "exploited_vulncheck_kev": True}
    assert vulncheck_export_view("CVE-2020-0001", entry) is None
    # the doc-shaped backup answer is a pre-signed URL: never parsed into anything the module stores
    assert "X-Amz-Signature" in json.dumps(fx("backup_ok.json"))
