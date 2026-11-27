"""shodan_cvedb (P189): Shodan CVEDB CVE record, KEV relay and analyst-only product search.

Fixtures in tests/fixtures/shodan_cvedb/ (prep batch p3-G08-1, live 2026-11-26 unless noted):
``cve_ok.json`` (CVE-2021-44228, references 103 -> 5, CPEs 1,600 -> 6), ``cves_kev_ok.json`` (product
search log4j, KEV only), ``cves_duplicate_rows.json`` (research 2026-11-25: the same CVE twice),
``malformed_truncated.json`` (first 700 bytes of a live body), ``not_found.http.json`` (the documented 404
absence body), ``timeout_unassigned.http.json`` (no byte within 20 s for an unassigned id) and
``challenge.http.json`` (a Cloudflare challenge recorded elsewhere, markers verbatim).
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Opsec, Status
from v3lum.modules.vulnerability_cve.cve_record import CASE_COUNTERS, CVE_FANOUT_SETTING
from v3lum.modules.vulnerability_cve.shodan_cvedb import (
    DATA_NOTICE,
    ShodanCvedb,
    parse_record,
    parse_search,
    search_params,
    search_url,
)

CVE = "CVE-2021-44228"
URL = "https://cvedb.shodan.io/cve/{cve}"
SEARCH = "https://cvedb.shodan.io/cves?product=log4j&sort_by_epss=true&limit=10"


@pytest.fixture(autouse=True)
def fresh_counters():
    CASE_COUNTERS.reset()
    yield
    CASE_COUNTERS.reset()


def fx(name: str):
    return module_fixture("shodan_cvedb", name)


def exchange(name: str) -> dict:
    resp = fx(name)["response"]
    return {"status": resp["status"], "headers": resp["headers"], "body": resp["body"].encode()}


# ------------------------------------------------------------------ council metadata
def test_metadata_matches_the_council_decision():
    cls = ShodanCvedb
    assert cls.default_enabled is False and cls.terms == "noncommercial" and cls.trust_tier == "trusted"
    assert cls.opsec is Opsec.PASSIVE and cls.disclosure == "third_party" and cls.shares_input is True
    assert cls.provider == "shodan" and cls.sources == ("shodan.cvedb",) and cls.hosts == ("cvedb.shodan.io",)
    assert cls.accepts == frozenset({T.CVE, T.KEYWORD}) and cls.absent_statuses == frozenset({404})
    assert (cls.max_requests, cls.cache_ttl, cls.min_interval, cls.daily_quota) == (1, 86400, 1.0, 1000)
    assert "licence-cleared" in cls.notice and "No fallback to active probing" in cls.notice


# ------------------------------------------------------------------ CVE record (cond 1)
def test_cve_record_fills_card_facts_and_relays_kev_as_exploitation_evidence():
    http = FakeHttp().add("GET", URL.format(cve=CVE), json=fx("cve_ok.json"))
    res = run_module(ShodanCvedb, f"cve:{CVE}", http)
    assert res.status is Status.OK, res.error
    a = res.attributes
    assert "kev" not in a  # P182 cond 4: KEV is CISA-only
    assert a["exploited"] == {"cisa_kev_via_shodan_cvedb": None}
    assert a["cvedb_kev_relay"]["listed"] is True and a["cvedb_kev_relay"]["ransomware_campaign"] == "Known"
    versions = {c["version"]: c["score"] for c in a["cvss_scores"]}
    assert versions == {"3.x": 10.0, "2.0": 9.3}
    assert all(c["source"] == "Shodan CVEDB" for c in a["cvss_scores"])
    assert a["epss"] == pytest.approx(0.99999) and a["epss_percentile"] == 1.0 and "relayed by Shodan CVEDB" in a["epss_text"]
    assert a["cve_published"] == "2021-12-10" and a["cve_description"].startswith("Apache Log4j2")
    assert {"vendor": "apache", "product": "log4j"} in a["affected"]
    assert a["cpe_total"] >= len(a["cpes"]) and all(c.startswith("cpe:2.3:") for c in a["cpes"])
    assert all(x.startswith(("EUVD-", "GHSA-")) for x in a["advisory_aliases"])
    assert a["data_notices"] == [DATA_NOTICE]
    assert not res.pivots  # aliases are never pivoted
    assert ("Shodan CVEDB record", URL.format(cve=CVE)) in res.links
    http.assert_hosts_within(ShodanCvedb)


def test_documented_404_is_empty_and_other_404s_are_errors():
    ex = exchange("not_found.http.json")
    http = FakeHttp().add("GET", URL.format(cve="CVE-2021-9999998"), status=404, headers=ex["headers"], body=ex["body"])
    res = run_module(ShodanCvedb, "cve:CVE-2021-9999998", http)
    assert res.status is Status.EMPTY and "No information available" in res.error
    http2 = FakeHttp().add("GET", URL.format(cve="CVE-2021-9999997"), status=404, text="<html>gone</html>")
    assert run_module(ShodanCvedb, "cve:CVE-2021-9999997", http2).status is Status.ERROR


def test_timeout_for_an_unassigned_id_is_could_not_verify():
    ex = fx("timeout_unassigned.http.json")
    assert ex["transport_error"]
    http = FakeHttp().add("GET", URL.format(cve="CVE-2021-9999999"), error=TimeoutError("read timed out"))
    res = run_module(ShodanCvedb, "cve:CVE-2021-9999999", http)
    assert res.status is Status.ERROR and res.reason_code in ("timeout", "error")


@pytest.mark.parametrize(("status", "expected"), [(429, Status.RATE_LIMITED), (503, Status.ERROR), (500, Status.ERROR)])
def test_rate_limits_and_server_errors_are_never_empty(status, expected):
    http = FakeHttp().add("GET", URL.format(cve=CVE), status=status, text="busy", times=3)
    assert run_module(ShodanCvedb, f"cve:{CVE}", http).status is expected


def test_cloudflare_challenge_and_keyless_403_are_blocked():
    ex = exchange("challenge.http.json")
    http = FakeHttp().add("GET", URL.format(cve=CVE), status=ex["status"], headers=ex["headers"], body=ex["body"])
    res = run_module(ShodanCvedb, f"cve:{CVE}", http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"
    http2 = FakeHttp().add("GET", URL.format(cve=CVE), status=403, json={"detail": "Forbidden"})
    assert run_module(ShodanCvedb, f"cve:{CVE}", http2).status is Status.BLOCKED


def test_error_detail_inside_http_200_is_an_error():
    http = FakeHttp().add("GET", URL.format(cve=CVE), json={"detail": "Internal error, try again later"})
    res = run_module(ShodanCvedb, f"cve:{CVE}", http)
    assert res.status is Status.ERROR


def test_malformed_truncated_body_and_wrong_record_are_errors():
    body = (fixture_dir() / "malformed_truncated.json").read_bytes()
    http = FakeHttp().add("GET", URL.format(cve=CVE), body=body, headers={"content-type": "application/json"})
    assert run_module(ShodanCvedb, f"cve:{CVE}", http).status is Status.ERROR
    other = dict(fx("cve_ok.json"), cve_id="CVE-2021-45046")
    http2 = FakeHttp().add("GET", URL.format(cve=CVE), json=other)
    res = run_module(ShodanCvedb, f"cve:{CVE}", http2)
    assert res.status is Status.ERROR and "CVE-2021-45046" in res.error
    http3 = FakeHttp().add("GET", URL.format(cve=CVE), json=["not", "a", "record"])
    assert run_module(ShodanCvedb, f"cve:{CVE}", http3).status is Status.ERROR


def test_pivot_cves_follow_the_fanout_budget():
    http = FakeHttp().add("GET", URL.format(cve=CVE), json=fx("cve_ok.json"))
    res = run_module(ShodanCvedb, f"cve:{CVE}", http, is_seed=False, case_id="case-1", settings={CVE_FANOUT_SETTING: 0})
    assert res.status is Status.QUOTA and res.reason_code == "quota" and not http.calls


# ------------------------------------------------------------------ product search (analyst-typed only)
def test_analyst_product_search_pivots_top_cves():
    http = FakeHttp().add("GET", SEARCH, json=fx("cves_kev_ok.json"))
    res = run_module(ShodanCvedb, "keyword:log4j", http)
    assert res.status is Status.OK, res.error
    hits = res.attributes["cvedb_search_hits"]
    assert hits and all(h["cve"].startswith("CVE-") for h in hits)
    assert {p.entity.value for p in res.pivots} == {h["cve"] for h in hits}
    assert all(p.relation == "affected_by" for p in res.pivots)
    http.assert_hosts_within(ShodanCvedb)


def test_kev_only_setting_sends_is_kev():
    url = "https://cvedb.shodan.io/cves?product=log4j&is_kev=true&sort_by_epss=true&limit=10"
    http = FakeHttp().add("GET", url, json=fx("cves_kev_ok.json"))
    res = run_module(ShodanCvedb, "keyword:log4j", http, settings={"shodan_cvedb_kev_only": True})
    assert res.status is Status.OK


def test_search_rows_are_deduplicated_by_cve():
    parsed = parse_search(fx("cves_duplicate_rows.json"))
    assert parsed["duplicates"] >= 1
    ids = [i["cve"] for i in parsed["items"]]
    assert len(ids) == len(set(ids))
    assert any(i["vendor_products"] for i in parsed["items"])


def test_pivot_keywords_are_never_searched():
    http = FakeHttp()
    res = run_module(ShodanCvedb, "keyword:log4j", http, is_seed=False, depth=1)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and not http.calls


def test_free_text_keywords_are_not_sent():
    http = FakeHttp()
    res = run_module(ShodanCvedb, Entity.make(T.KEYWORD, "remote code execution in apache"), http)
    assert res.status is Status.SKIPPED and not http.calls


def test_empty_search_is_empty_and_missing_list_is_error():
    http = FakeHttp().add("GET", SEARCH, json={"cves": []})
    assert run_module(ShodanCvedb, "keyword:log4j", http).status is Status.EMPTY
    http2 = FakeHttp().add("GET", SEARCH, json={"detail": "bad request"})
    assert run_module(ShodanCvedb, "keyword:log4j", http2).status is Status.ERROR
    http3 = FakeHttp().add("GET", SEARCH, json={"unexpected": []})
    assert run_module(ShodanCvedb, "keyword:log4j", http3).status is Status.ERROR


def test_search_timeout_is_could_not_verify():
    assert fx("timeout_unassigned.http.json")["response"] is None  # no byte within 20 s (live 2026-11-26)
    http = FakeHttp().add("GET", SEARCH, error=TimeoutError("read timed out"))
    assert run_module(ShodanCvedb, "keyword:log4j", http).status is Status.ERROR


# ------------------------------------------------------------------ pure helpers
def test_search_params_validate_input_and_clamp_limit():
    params, why = search_params("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", limit=500)
    assert why is None and params["cpe23"].startswith("cpe:2.3:a:apache") and params["limit"] == "50"
    assert search_params("bad product!")[0] is None
    assert search_params("")[0] is None
    assert search_url("OpenSSH") == "https://cvedb.shodan.io/cves?product=openssh&sort_by_epss=true&limit=10"


def test_parse_record_is_defensive():
    assert parse_record({"cve_id": "not-a-cve"}) is None
    assert parse_record("junk") is None
    rec = parse_record({"cve_id": "cve-2020-0001", "cvss_v3": "nan", "epss": 7, "kev": "yes", "cpes": [1, "cpe:2.3:a:x:y:1"]})
    assert rec["cve"] == "CVE-2020-0001" and rec["cvss"] == [] and rec["epss"] is None and rec["kev"] is False
    assert rec["affected"] == [{"vendor": "x", "product": "y"}]


def fixture_dir():
    from pathlib import Path

    return Path(__file__).resolve().parents[1] / "fixtures" / "shodan_cvedb"
