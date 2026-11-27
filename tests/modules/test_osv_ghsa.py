"""osv_ghsa (P185): OSV.dev records (CVE, GHSA, Debian/Ubuntu distro records) + GitHub REST advisories.

Fixtures in tests/fixtures/osv_ghsa/ (prep batch p2-G08-1, 2026-11-26): ``osv_cve_ok``, ``osv_debian_ok``,
``osv_ubuntu_ok``, ``osv_not_found.http`` (live, minimised; the Ubuntu record's individual PoC repository URL
was not kept), ``osv_ghsa_ok`` (research), ``osv_malformed.txt`` (a cut body), ``ghsa_rest_blocked_proxy.http``
(live: the research egress proxy refused api.github.com, not GitHub). ``ghsa_rest_ok``, ``ghsa_rest_empty`` and
``ghsa_rest_rate_limited.http`` are DOC-SHAPED from the GitHub REST documentation: P185 cond 1 asks for a
re-test from the team network before merge (docs/backlog/p2-G08-1.md).
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.models import Opsec, Status
from v3lum.modules.vulnerability_cve.cve_record import CASE_COUNTERS
from v3lum.modules.vulnerability_cve.g08_advisories import (
    advisory_id_kind,
    cvss_base_score,
    cvss_base_vector,
    dedupe_advisories,
    normalize_ghsa_id,
    parse_osv_record,
)
from v3lum.modules.vulnerability_cve.osv_ghsa import OsvGhsa, parse_ghsa_range, parse_ghsa_rest

CVE = "CVE-2021-44228"
GHSA = "GHSA-jfh8-c2jp-5v3q"
OSV = "https://api.osv.dev/v1/vulns/{id}"
GH = "https://api.github.com/advisories?cve_id={cve}"
GH_HEADERS = {"x-ratelimit-limit": "60", "x-ratelimit-remaining": "59", "x-ratelimit-reset": "4102444800", "x-ratelimit-resource": "core"}
CHALLENGE = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body><div id='cf-chl-widget'></div></body></html>"
SRC_OSV, SRC_GH = "osv.vulns", "github.osv_ghsa_advisories"


@pytest.fixture(autouse=True)
def fresh_counters():
    CASE_COUNTERS.reset()
    yield
    CASE_COUNTERS.reset()


def fx(name: str):
    return module_fixture(OsvGhsa, name)


def exchange(name: str) -> dict:
    resp = fx(name)["response"]
    return {"status": resp["status"], "headers": resp["headers"], "body": resp["body"].encode()}


def osv_routes(http: FakeHttp, *, cve="osv_cve_ok.json", debian="osv_debian_ok.json", ubuntu="osv_ubuntu_ok.json") -> FakeHttp:
    nf = exchange("osv_not_found.http.json")
    for ident, name in ((CVE, cve), (f"DEBIAN-{CVE}", debian), (f"UBUNTU-{CVE}", ubuntu)):
        if name is None:
            http.add("GET", OSV.format(id=ident), status=404, body=nf["body"], headers=nf["headers"])
        else:
            http.add("GET", OSV.format(id=ident), json=fx(name))
    return http


# ------------------------------------------------------------------ metadata
def test_metadata_matches_the_council_decision():
    cls = OsvGhsa
    assert cls.default_enabled is True and cls.terms == "key-terms" and cls.trust_tier == "trusted"
    assert cls.opsec is Opsec.PASSIVE and cls.disclosure == "third_party"
    assert cls.terms_sources == {SRC_OSV: "open", SRC_GH: "key-terms"}
    assert cls.hosts == ("api.osv.dev", "api.github.com") and cls.optional_keys == ("github",)
    assert cls.providers == frozenset({"osv", "github"}) and cls.max_requests == 6 and cls.cache_ttl == 86400


# ------------------------------------------------------------------ happy path (cond 1, 4, 5)
def test_cve_osv_distro_records_and_github_rest_fill_the_card():
    http = osv_routes(FakeHttp()).add("GET", GH.format(cve=CVE), json=fx("ghsa_rest_ok.json"), headers=GH_HEADERS)
    res = run_module(OsvGhsa, f"cve:{CVE}", http)
    assert res.status is Status.OK, res.error
    a = res.attributes
    # per-release distro fixes (cond 4)
    debian = [d for d in a["distro_fixes"] if d["distro"] == "debian"]
    assert {d["release"] for d in debian} >= {"12"} and all(d["fixed"] == "2.15.0-1" for d in debian)
    assert any(d["distro"] == "ubuntu" and d.get("subscription") == "pro" for d in a["distro_fixes"])
    assert any(f["product"] == "Debian 12 apache-log4j2" and f["fixed"] == "2.15.0-1" for f in a["fixed_versions"])
    # compact package ranges (cond 5) and package impact
    assert any(r["package"] == "org.apache.logging.log4j:log4j-core" and r["fixed"] == "2.15.0" for r in a["package_ranges"])
    assert a["affected"][0]["vendor"] == "maven"
    assert a["cvss_scores"][0]["score"] == 10.0 and a["cvss_scores"][0]["container"] == "osv"
    assert "cvss" not in a and "kev" not in a  # OSV never competes with the CVE record's plain cvss
    assert GHSA in a["advisory_aliases"] and f"https://github.com/advisories/{GHSA}" in a["vendor_advisories"]
    assert len(a["data_notices"]) == 2
    pivot = next(p for p in res.pivots if p.entity.value == GHSA)
    assert pivot.expand is False and pivot.relation == "advisory_alias"
    # GitHub answered: the OSV GHSA mirror is not read (4 requests, not 6)
    assert res.requests == 4 and OSV.format(id=GHSA) not in http.urls()
    # evidence holds compact views, never whole records
    dumped = json.dumps(res.raw)
    assert "details" not in dumped and "references" not in dumped
    http.assert_hosts_within(OsvGhsa)


def test_github_not_cleared_runs_osv_alone_with_the_ghsa_mirror():
    http = osv_routes(FakeHttp()).add("GET", OSV.format(id=GHSA), json=fx("osv_ghsa_ok.json"))
    res = run_module(OsvGhsa, f"cve:{CVE}", http, allowed_sources=[SRC_OSV])
    assert res.status is Status.OK
    assert all("api.github.com" not in u for u in http.urls())
    assert OSV.format(id=GHSA) in http.urls() and res.attributes["affected"]
    assert res.attributes["data_notices"] == ["OSV.dev (Google), CC BY 4.0 (per-source licences of the aggregated databases)."]


def test_egress_proxy_403_is_blocked_and_osv_still_answers():
    ex = exchange("ghsa_rest_blocked_proxy.http.json")
    http = osv_routes(FakeHttp()).add("GET", GH.format(cve=CVE), status=403, body=ex["body"], headers=ex["headers"])
    http.add("GET", OSV.format(id=GHSA), json=fx("osv_ghsa_ok.json"))
    res = run_module(OsvGhsa, f"cve:{CVE}", http)
    assert res.status is Status.OK
    gh = res.source_statuses[SRC_GH]
    assert gh["status"] == "blocked" and gh["reason_code"] == "challenge"
    assert OSV.format(id=GHSA) in http.urls()  # fallback to the OSV GHSA mirror


def test_github_rate_limit_message_is_rate_limited():
    ex = exchange("ghsa_rest_rate_limited.http.json")
    http = osv_routes(FakeHttp()).add("GET", GH.format(cve=CVE), status=403, body=ex["body"], headers=ex["headers"])
    http.add("GET", OSV.format(id=GHSA), json=fx("osv_ghsa_ok.json"))
    res = run_module(OsvGhsa, f"cve:{CVE}", http)
    assert res.status is Status.OK and res.source_statuses[SRC_GH]["status"] == "rate_limited"


def test_keyless_pivots_never_call_github():
    http = osv_routes(FakeHttp()).add("GET", OSV.format(id=GHSA), json=fx("osv_ghsa_ok.json"))
    res = run_module(OsvGhsa, f"cve:{CVE}", http, is_seed=False, case_id="case-1")
    assert res.status is Status.OK
    assert res.source_statuses[SRC_GH]["status"] == "needs_key"
    assert all("api.github.com" not in u for u in http.urls())


def test_github_token_is_a_bearer_header_to_api_github_only():
    http = osv_routes(FakeHttp())
    http.add("GET", GH.format(cve=CVE), json=fx("ghsa_rest_ok.json"), headers=GH_HEADERS, match_headers={"Authorization": "Bearer ghp_testtoken0123456789"})
    res = run_module(OsvGhsa, f"cve:{CVE}", http, keys={"github": "ghp_testtoken0123456789"}, is_seed=False, case_id="case-2")
    assert res.status is Status.OK and SRC_GH not in res.source_statuses
    osv_calls = [c for c in http.calls if "api.osv.dev" in c.get("url", "")]
    assert osv_calls and all("Authorization" not in (c.get("headers") or {}) for c in osv_calls)
    assert "ghp_testtoken0123456789" not in json.dumps([res.raw, res.attributes])


# ------------------------------------------------------------------ absences and rule 5
def test_nothing_anywhere_is_empty():
    http = osv_routes(FakeHttp(), cve=None, debian=None, ubuntu=None).add("GET", GH.format(cve=CVE), json=fx("ghsa_rest_empty.json"))
    res = run_module(OsvGhsa, f"cve:{CVE}", http)
    assert res.status is Status.EMPTY and res.source_statuses[SRC_GH]["status"] == "empty"


def test_cut_osv_body_is_an_error_never_empty():
    http = FakeHttp().add("GET", OSV.format(id=CVE), body=fx("osv_malformed.txt").encode(), headers={"content-type": "application/json"})
    nf = exchange("osv_not_found.http.json")
    http.add("GET", OSV.format(id=f"DEBIAN-{CVE}"), status=404, body=nf["body"], headers=nf["headers"])
    http.add("GET", OSV.format(id=f"UBUNTU-{CVE}"), status=404, body=nf["body"], headers=nf["headers"])
    res = run_module(OsvGhsa, f"cve:{CVE}", http, allowed_sources=[SRC_OSV])
    assert res.status is Status.ERROR and "JSON" in res.error and "could not verify" in res.error


def test_osv_failure_with_github_answer_keeps_the_github_facts():
    http = FakeHttp().add("GET", OSV.format(id=CVE), status=500, text="oops")
    nf = exchange("osv_not_found.http.json")
    http.add("GET", OSV.format(id=f"DEBIAN-{CVE}"), status=404, body=nf["body"], headers=nf["headers"])
    http.add("GET", OSV.format(id=f"UBUNTU-{CVE}"), status=404, body=nf["body"], headers=nf["headers"])
    http.add("GET", GH.format(cve=CVE), json=fx("ghsa_rest_ok.json"), headers=GH_HEADERS)
    res = run_module(OsvGhsa, f"cve:{CVE}", http)
    assert res.status is Status.OK and res.attributes["affected"]
    assert res.source_statuses[SRC_OSV]["status"] == "error"


def test_rate_limit_and_challenge_from_osv_are_could_not_verify():
    http = FakeHttp().add("GET", OSV.format(id=CVE), status=429, text="slow down", headers={"retry-after": "60"})
    http.add("GET", OSV.format(id=f"DEBIAN-{CVE}"), status=429, text="slow down", headers={"retry-after": "60"})
    http.add("GET", OSV.format(id=f"UBUNTU-{CVE}"), status=429, text="slow down", headers={"retry-after": "60"})
    res = run_module(OsvGhsa, f"cve:{CVE}", http, allowed_sources=[SRC_OSV])
    assert res.status is Status.RATE_LIMITED
    http2 = FakeHttp().add("GET", OSV.format(id=GHSA), status=403, text=CHALLENGE)
    res2 = run_module(OsvGhsa, f"keyword:{GHSA}", http2)
    assert res2.status is Status.BLOCKED


# ------------------------------------------------------------------ GHSA input, keywords (cond 1, 3)
def test_ghsa_keyword_reads_osv_and_pivots_its_cve():
    http = FakeHttp().add("GET", OSV.format(id=GHSA), json=fx("osv_ghsa_ok.json"))
    res = run_module(OsvGhsa, f"keyword:{GHSA.upper()}", http)
    assert res.status is Status.OK and res.requests == 1
    cve = next(p for p in res.pivots if p.entity.value == CVE)
    assert cve.expand is True and cve.relation == "advisory_alias"
    assert ("GitHub advisory page", f"https://github.com/advisories/{GHSA}") in res.links


@pytest.mark.parametrize("keyword", ["log4j-core@2.14.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "Apache Log4j"])
def test_package_and_free_keywords_are_never_sent(keyword):
    http = FakeHttp()
    res = run_module(OsvGhsa, f"keyword:{keyword}", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []


# ------------------------------------------------------------------ pure helpers (g08_advisories)
def test_cvss_base_scores_from_vectors():
    assert cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0
    assert cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N") == 6.5
    assert cvss_base_score("AV:N/AC:M/Au:N/C:C/I:C/A:C") == 9.3
    assert cvss_base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") is None
    assert cvss_base_score("garbage") is None and cvss_base_score(None) is None
    assert cvss_base_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H") == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"


def test_ghsa_ranges_and_rest_parser():
    assert parse_ghsa_range(">= 2.13.0, < 2.15.0") == {"introduced": "2.13.0", "fixed": "2.15.0"}
    assert parse_ghsa_range("<= 1.2") == {"last_affected": "1.2", "introduced": "0"}
    assert parse_ghsa_range("= 1.0") == {"exact": "1.0"} and parse_ghsa_range("nonsense") == {}
    advisories = parse_ghsa_rest(fx("ghsa_rest_ok.json"))
    assert advisories[0]["ghsa_id"] == GHSA and CVE in advisories[0]["ids"]
    assert parse_ghsa_rest({"message": "x"}) is None and parse_ghsa_rest([]) == []


def test_advisory_ids_and_dedupe_by_alias():
    assert normalize_ghsa_id("ghsa-JFH8-c2jp-5v3q") == GHSA and normalize_ghsa_id("GHSA-aaaa-bbbb-cccc") is None
    assert advisory_id_kind("RHSA-2021:5093") == ("csaf", "RHSA-2021:5093")
    assert advisory_id_kind("apache log4j") == (None, None)
    osv_cve = parse_osv_record(fx("osv_cve_ok.json"))
    osv_ghsa = parse_osv_record(fx("osv_ghsa_ok.json"))
    rest = parse_ghsa_rest(fx("ghsa_rest_ok.json"))
    groups = dedupe_advisories([("osv", osv_cve), ("osv", osv_ghsa), ("github", rest[0])])
    assert len(groups) == 1 and groups[0]["cves"] == [CVE] and groups[0]["ghsas"] == [GHSA]
    assert parse_osv_record({"cveMetadata": {}}) is None and parse_osv_record("not json") is None
