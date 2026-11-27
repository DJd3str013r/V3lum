"""csaf_redhat_vex (P354 cond 3): Red Hat VEX per in-scope CVE.

Fixtures in tests/fixtures/csaf_redhat_vex/ (prep batch p3-G08-1, live 2026-11-26): ``cve_ok.json``
(CVE-2021-44228, 3,622,781 B pruned to 2 fixed, 2 known_affected and 2 known_not_affected products with
their tree, flags, remediations, threats and scores), ``not_found.http.json`` (404 text/html 'Page not
found.' for an unassigned id) and ``changes.csv`` (shape of the 78,000-row VEX change list that is never
bulk-synced).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.models import Opsec, Status
from v3lum.modules.vulnerability_cve.csaf_redhat_vex import CsafRedhatVex, parse_vex, statuses_for, vex_url
from v3lum.modules.vulnerability_cve.cve_record import CASE_COUNTERS, CVE_FANOUT_SETTING

CVE = "CVE-2021-44228"
URL = "https://security.access.redhat.com/data/csaf/v2/vex/2021/cve-2021-44228.json"
FIX = Path(__file__).resolve().parents[1] / "fixtures" / "csaf_redhat_vex"


@pytest.fixture(autouse=True)
def fresh_counters():
    CASE_COUNTERS.reset()
    yield
    CASE_COUNTERS.reset()


def body() -> bytes:
    return (FIX / "cve_ok.json").read_bytes()


def test_metadata_matches_the_council_decision():
    cls = CsafRedhatVex
    assert cls.default_enabled is True and cls.terms == "open" and cls.trust_tier == "trusted"
    assert cls.opsec is Opsec.PASSIVE and cls.disclosure == "third_party" and cls.provider == "redhat"
    assert cls.sources == ("redhat.csaf_vex",) and cls.hosts == ("security.access.redhat.com",)
    assert cls.absent_statuses == frozenset({404}) and cls.max_requests == 1
    assert vex_url(CVE) == URL and vex_url("junk") is None


def test_vex_statuses_fixed_versions_and_errata():
    http = FakeHttp().add("GET", URL, body=body(), headers={"content-type": "application/json"})
    res = run_module(CsafRedhatVex, f"cve:{CVE}", http)
    assert res.status is Status.OK, res.error
    a = res.attributes
    vex = a["vex_statuses"]
    assert vex["vendor"] == "redhat" and vex["counts"]["fixed"] == 2 and vex["counts"]["affected"] == 2
    assert vex["counts"]["not_affected"] == 2
    not_affected = [p for p in vex["products"] if p["status"] == "not_affected"]
    assert not_affected and all(p["justification"] == "vulnerable_code_not_present" for p in not_affected)
    assert vex["products"][0]["status"] == "affected"  # affected first, not_affected last
    assert any(f["fixed"].startswith("0:3.1.16-4") for f in a["fixed_versions"])
    assert a["vendor_advisories"] == ["https://access.redhat.com/errata/RHSA-2025:1746"]
    assert a["cvss_scores"][0]["source"] == "Red Hat VEX" and a["cvss_scores"][0]["score"] == 9.8
    assert any("CC BY 4.0" in n for n in a["data_notices"])
    assert "kev" not in a and "exploited" not in a
    assert ("Red Hat CVE page", "https://access.redhat.com/security/cve/CVE-2021-44228") in res.links
    http.assert_hosts_within(CsafRedhatVex)


def test_404_page_not_found_is_no_vex_for_that_cve():
    resp = module_fixture("csaf_redhat_vex", "not_found.http.json")["response"]
    url = vex_url("CVE-2021-9999999")
    http = FakeHttp().add("GET", url, status=404, headers=resp["headers"], body=resp["body"].encode())
    res = run_module(CsafRedhatVex, "cve:CVE-2021-9999999", http)
    assert res.status is Status.EMPTY and "no Red Hat VEX" in res.error


def test_document_above_5_mb_is_too_large_not_empty():
    big = body()[:-1] + b" " * 5_000_100 + b"}"
    http = FakeHttp().add("GET", URL, body=big, headers={"content-type": "application/json"})
    res = run_module(CsafRedhatVex, f"cve:{CVE}", http)
    assert res.status is Status.ERROR and "too large" in res.error


@pytest.mark.parametrize(("status", "expected"), [(429, Status.RATE_LIMITED), (403, Status.BLOCKED), (503, Status.ERROR)])
def test_could_not_verify_statuses(status, expected):
    http = FakeHttp().add("GET", URL, status=status, text="denied", times=3)
    assert run_module(CsafRedhatVex, f"cve:{CVE}", http).status is expected


def test_wrong_cve_non_vex_and_malformed_documents_are_errors():
    doc = module_fixture("csaf_redhat_vex", "cve_ok.json")
    http = FakeHttp().add("GET", URL, json=dict(doc, vulnerabilities=[dict(doc["vulnerabilities"][0], cve="CVE-2021-45046")]))
    assert "not CVE-2021-44228" in run_module(CsafRedhatVex, f"cve:{CVE}", http).error
    advisory = dict(doc, document=dict(doc["document"], category="csaf_security_advisory"))
    http2 = FakeHttp().add("GET", URL, json=advisory)
    assert run_module(CsafRedhatVex, f"cve:{CVE}", http2).status is Status.ERROR
    http3 = FakeHttp().add("GET", URL, body=body()[:500], headers={"content-type": "application/json"})
    assert run_module(CsafRedhatVex, f"cve:{CVE}", http3).status is Status.ERROR


def test_only_in_scope_cves_are_sent():
    http = FakeHttp()
    res = run_module(CsafRedhatVex, f"cve:{CVE}", http, is_seed=False, depth=1,
                     provenance=(("keyword:log4j", "affected_by", "csaf_advisories"),))
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and not http.calls
    http2 = FakeHttp().add("GET", URL, body=body(), headers={"content-type": "application/json"})
    res2 = run_module(CsafRedhatVex, f"cve:{CVE}", http2, is_seed=False, depth=1, case_id="c1",
                      provenance=(("ipv4:203.0.113.10", "has_vuln", "shodan_internetdb"),))
    assert res2.status is Status.OK


def test_fanout_budget_applies_to_in_scope_pivots():
    http = FakeHttp()
    res = run_module(CsafRedhatVex, f"cve:{CVE}", http, is_seed=False, depth=1, case_id="c2", settings={CVE_FANOUT_SETTING: 0},
                     provenance=(("ipv4:203.0.113.10", "has_vuln", "shodan_internetdb"),))
    assert res.status is Status.QUOTA and not http.calls


def test_statuses_filter_by_component_and_platform():
    vex = parse_vex(body())
    assert {s["component"] for s in statuses_for(vex, component="eap7-apache-cxf")} == {"eap7-apache-cxf"}
    assert statuses_for(vex, component="nonexistent") == []
    assert all(s["status"] == "not_affected" for s in statuses_for(vex, component="ose-elasticsearch-operator"))
