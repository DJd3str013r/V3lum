"""euvd (P191): ENISA EU Vulnerability Database record, 1 MB cap, aliases-only EUVD ids, analyst search.

Fixtures in tests/fixtures/euvd/ (prep batch p3-G08-1, live 2026-11-26): ``enisaid_ok.json`` (log4j record
trimmed from 492,196 B: references 53 -> 4, advisories 46 -> 3), ``enisaid_truncated.json`` (the first
8 KiB of the live body: what a capped read returns), ``enisaid_large.http.json`` (live headers of the
492 KB answer), ``enisaid_not_found.http.json`` (the documented 404 body), ``search_ok.json`` and
``search_empty.json``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Opsec, Status
from v3lum.modules.vulnerability_cve.cve_record import CASE_COUNTERS, CVE_FANOUT_SETTING
from v3lum.modules.vulnerability_cve.euvd import (
    ATTRIBUTION,
    MAX_BYTES,
    Euvd,
    euvd_epss,
    parse_datetime,
    parse_item,
    search_params,
    size_problem,
)

CVE = "CVE-2021-44228"
URL = "https://euvdservices.enisa.europa.eu/api/enisaid?id={id}"
SEARCH = "https://euvdservices.enisa.europa.eu/api/search?text=log4j&size=10"
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "euvd"


@pytest.fixture(autouse=True)
def fresh_counters():
    CASE_COUNTERS.reset()
    yield
    CASE_COUNTERS.reset()


def fx(name: str):
    return module_fixture("euvd", name)


def exchange(name: str) -> dict:
    resp = fx(name)["response"]
    return {"status": resp["status"], "headers": resp["headers"], "body": (resp["body"] or "").encode()}


def test_metadata_matches_the_council_decision():
    cls = Euvd
    assert cls.default_enabled is False and cls.terms == "open" and cls.trust_tier == "trusted"
    assert cls.opsec is Opsec.PASSIVE and cls.disclosure == "third_party" and cls.shares_input is True
    assert cls.provider == "enisa" and cls.sources == ("enisa.euvd",) and cls.hosts == ("euvdservices.enisa.europa.eu",)
    assert cls.accepts == frozenset({T.CVE, T.KEYWORD}) and MAX_BYTES == 1_000_000
    assert ATTRIBUTION in cls.notice


def test_cve_record_stores_euvd_id_as_alias_and_exploited_source_euvd():
    http = FakeHttp().add("GET", URL.format(id=CVE), json=fx("enisaid_ok.json"))
    res = run_module(Euvd, f"cve:{CVE}", http)
    assert res.status is Status.OK, res.error
    a = res.attributes
    assert a["advisory_aliases"][0] == "EUVD-2021-34768" and "GHSA-jfh8-c2jp-5v3q" in a["advisory_aliases"]
    assert not res.pivots  # EUVD ids are aliases only (P191 cond 2)
    assert a["exploited"] == {"euvd": "2021-12-10"} and "kev" not in a
    assert a["epss"] == 1.0  # EUVD publishes a percentage
    score = a["cvss_scores"][0]
    assert score["source"] == "EUVD (apache)" and score["score"] == 10.0 and score["vector"].startswith("CVSS:3.1/")
    assert a["cve_published"] == "2021-12-10"
    assert any(p["product"] == "Apache Log4j2" for p in a["affected"])
    assert a["euvd_record"]["euvd_id"] == "EUVD-2021-34768" and a["euvd_record"]["advisories_total"] >= 3
    sources = {adv.get("source") for adv in a["euvd_advisories"]}
    assert {"csaf_redhat", "csaf_siemens", "csaf_cisco"} <= sources
    assert all(u.startswith("https://") for u in a["vendor_advisories"])
    assert a["data_notices"] == [ATTRIBUTION]
    assert ("ENISA EUVD record", "https://euvd.enisa.europa.eu/vulnerability/EUVD-2021-34768") in res.links
    http.assert_hosts_within(Euvd)


def test_documented_404_is_empty():
    ex = exchange("enisaid_not_found.http.json")
    http = FakeHttp().add("GET", URL.format(id="CVE-2021-9999999"), status=404, headers=ex["headers"], body=ex["body"])
    res = run_module(Euvd, "cve:CVE-2021-9999999", http)
    assert res.status is Status.EMPTY and "EUVD not found" in res.error


def test_404_without_the_marker_is_an_error():
    http = FakeHttp().add("GET", URL.format(id=CVE), status=404, text="<html><title>Not Found</title></html>")
    assert run_module(Euvd, f"cve:{CVE}", http).status is Status.ERROR


def test_content_length_above_the_cap_is_an_error_never_a_partial_parse():
    ex = exchange("enisaid_large.http.json")
    headers = dict(ex["headers"], **{"content-length": "1500000"})
    http = FakeHttp().add("GET", URL.format(id=CVE), headers=headers, json=fx("enisaid_ok.json"))
    res = run_module(Euvd, f"cve:{CVE}", http)
    assert res.status is Status.ERROR and "cap" in res.error and not res.attributes


def test_read_cut_at_the_cap_is_an_error():
    big = b'{"id": "EUVD-2021-34768", "references": "' + b"x" * (MAX_BYTES + 10) + b'"}'
    http = FakeHttp().add("GET", URL.format(id=CVE), body=big, headers={"content-type": "application/json"})
    res = run_module(Euvd, f"cve:{CVE}", http)
    assert res.status is Status.ERROR and "truncated" in res.error


def test_truncated_live_body_is_an_error():
    body = (FIXTURES / "enisaid_truncated.json").read_bytes()
    http = FakeHttp().add("GET", URL.format(id=CVE), body=body, headers={"content-type": "application/json"})
    assert run_module(Euvd, f"cve:{CVE}", http).status is Status.ERROR


def test_live_headers_of_the_log4j_answer_are_within_the_cap():
    assert size_problem(fx("enisaid_large.http.json")["response"]["headers"], None, False) is None
    assert size_problem({"content-length": "1000001"}, None, False)
    assert size_problem({}, None, True)


def test_error_in_200_and_wrong_record_are_errors():
    http = FakeHttp().add("GET", URL.format(id=CVE), json={"error": "internal failure"})
    assert run_module(Euvd, f"cve:{CVE}", http).status is Status.ERROR
    other = dict(fx("enisaid_ok.json"), aliases="CVE-2021-45046\n", enisaIdVulnerability=[])
    http2 = FakeHttp().add("GET", URL.format(id=CVE), json=other)
    res = run_module(Euvd, f"cve:{CVE}", http2)
    assert res.status is Status.ERROR and "does not carry" in res.error
    http3 = FakeHttp().add("GET", URL.format(id=CVE), json=[1, 2])
    assert run_module(Euvd, f"cve:{CVE}", http3).status is Status.ERROR


@pytest.mark.parametrize(("status", "expected"), [(429, Status.RATE_LIMITED), (403, Status.BLOCKED), (502, Status.ERROR)])
def test_could_not_verify_statuses(status, expected):
    http = FakeHttp().add("GET", URL.format(id=CVE), status=status, text="no", times=3)
    assert run_module(Euvd, f"cve:{CVE}", http).status is expected


def test_timeout_is_error():
    http = FakeHttp().add("GET", URL.format(id=CVE), error=TimeoutError("timed out"))
    assert run_module(Euvd, f"cve:{CVE}", http).status is Status.ERROR


def test_pivot_cves_follow_the_fanout_budget():
    http = FakeHttp()
    res = run_module(Euvd, f"cve:{CVE}", http, is_seed=False, case_id="case-2", settings={CVE_FANOUT_SETTING: 0})
    assert res.status is Status.QUOTA and not http.calls


def test_analyst_search_lists_hits_and_pivots_cves():
    http = FakeHttp().add("GET", SEARCH, json=fx("search_ok.json"))
    res = run_module(Euvd, "keyword:log4j", http)
    assert res.status is Status.OK, res.error
    hits = res.attributes["euvd_search_hits"]
    assert 1 <= len(hits) <= 10 and all(h["euvd_id"].startswith("EUVD-") for h in hits)
    assert all(p.entity.type is T.CVE and p.relation == "affected_by" for p in res.pivots)
    http.assert_hosts_within(Euvd)


def test_empty_search_is_empty_and_pivot_keywords_are_not_sent():
    http = FakeHttp().add("GET", SEARCH, json=fx("search_empty.json"))
    assert run_module(Euvd, "keyword:log4j", http).status is Status.EMPTY
    http2 = FakeHttp()
    res = run_module(Euvd, "keyword:log4j", http2, is_seed=False, depth=1)
    assert res.status is Status.SKIPPED and not http2.calls


def test_search_without_items_is_an_error():
    http = FakeHttp().add("GET", SEARCH, json={"total": 3})
    assert run_module(Euvd, "keyword:log4j", http).status is Status.ERROR


def test_helpers_are_defensive():
    assert parse_datetime("Dec 10, 2021, 12:00:00 AM") == "2021-12-10T00:00:00"
    assert parse_datetime("Oct 21, 2025, 11:25:23 PM") == "2025-10-21T23:25:23"
    assert parse_datetime("2026-11-26T10:00:00Z") == "2026-11-26T10:00:00"
    assert parse_datetime("yesterday") is None and parse_datetime(None) is None
    assert euvd_epss("88.69") == pytest.approx(0.8869) and euvd_epss(150) is None and euvd_epss("x") is None
    assert parse_item({"id": "nope"}) is None and parse_item([]) is None
    assert search_params("x" * 101)[0] is None and search_params("log4j", size=50)[0]["size"] == "10"
