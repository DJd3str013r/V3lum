"""poc_index (P190 third-party part): PoC-in-GitHub + trickest/cve link indexes.

Fixtures in tests/fixtures/poc_index/ (prep batch p2-G08-2, recorded 2026-11-26 from raw.githubusercontent.com
for CVE-2021-44228; GitHub owners replaced by ``example-owner-N``): ``nomi_ok.json`` (8 of the 521 real
repository objects), ``nomi_truncated.json`` (a cut-off download), ``nomi_hostile.json`` (synthetic: javascript:,
http:, look-alike host, dot segments, credentials, deep paths, wrong types), ``trickest_ok.md`` /
``trickest_no_github.md`` (real markdown, trimmed), the real 404 exchanges and a synthetic 429.
"""

from __future__ import annotations

import pytest

from tests.fakes import FIXTURES, FakeHttp, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.vulnerability_cve.poc_index import (
    NOMI_SOURCE,
    POC_LABEL,
    TRICKEST_SOURCE,
    PocIndex,
    normalize_github_repo_url,
    parse_poc_in_github,
    parse_trickest_markdown,
    poc_claim_fields,
    poc_in_github_url,
    select_poc_links,
    trickest_url,
)

CVE = "CVE-2021-44228"
NOMI_URL = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2021/CVE-2021-44228.json"
TRICKEST_URL = "https://raw.githubusercontent.com/trickest/cve/main/2021/CVE-2021-44228.md"
NOMI_OK = module_fixture(PocIndex, "nomi_ok.json")
TRICKEST_OK = module_fixture(PocIndex, "trickest_ok.md")
TRICKEST_NO_GITHUB = module_fixture(PocIndex, "trickest_no_github.md")
NOT_FOUND = module_fixture(PocIndex, "nomi_not_found.http.json")["response"]
RATE_LIMITED = module_fixture(PocIndex, "rate_limited.http.json")["response"]
CHALLENGE = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
MD = {"content-type": "text/plain; charset=utf-8"}


def add_exchange(http: FakeHttp, url: str, response: dict) -> FakeHttp:
    return http.add("GET", url, status=response["status"], body=str(response["body"]).encode(), headers=response["headers"])


def ok_http() -> FakeHttp:
    return FakeHttp().add("GET", NOMI_URL, json=NOMI_OK).add("GET", TRICKEST_URL, body=TRICKEST_OK.encode(), headers=MD)


# ------------------------------------------------------------------ metadata (council values)
def test_metadata_is_third_party_trusted_default_and_capped():
    cls = PocIndex
    assert (cls.disclosure, cls.provider, cls.hosts) == ("third_party", "github", ("raw.githubusercontent.com",))
    assert cls.sources == (NOMI_SOURCE, TRICKEST_SOURCE) and cls.terms == "open" and cls.default_enabled is True
    assert cls.trust_tier == "trusted" and cls.shares_input is True and cls.opsec.label == "passive"
    assert cls.max_tlp.value_str == "amber+strict"  # never at TLP:RED: the CVE id leaves the machine
    assert cls.max_requests == 2 and cls.cache_ttl == 86400 and cls.min_interval == 1.0 and cls.daily_quota == 500
    assert cls.absent_statuses == frozenset({404}) and cls.max_pivots == 5


def test_urls_use_the_year_folder():
    assert poc_in_github_url("cve-2021-44228") == NOMI_URL
    assert trickest_url(CVE) == TRICKEST_URL
    assert poc_in_github_url("not-a-cve") is None


# ------------------------------------------------------------------ happy path (cond 2/3/5)
def test_claims_are_counted_capped_defanged_labelled_and_never_expanded():
    http = ok_http()
    res = run_module(PocIndex, f"cve:{CVE}", http)
    assert res.status is Status.OK
    a = res.attributes
    total = a["poc_repos_total"]
    assert total == 8 + 8  # 8 PoC-in-GitHub repos + 8 trickest-only Github links (union, case-insensitive)
    assert a["exploit_maturity"] == f"poc_claimed ({total} repos)"
    assert a["poc_confidence"] == 0.4  # <= 0.4 (cond 3)
    assert "exploit_available" not in a  # curated sources only: never from PoC claims (cond 3)
    top = a["poc_repos"]
    assert [t["repo"] for t in top] == [
        "hxxps://github[.]com/example-owner-1/log4j-scan",
        "hxxps://github[.]com/example-owner-2/log4j-shell-poc",
        "hxxps://github[.]com/example-owner-3/log4shell-vulnerable-app",
        "hxxps://github[.]com/example-owner-4/CVE-2021-44228-Apache-Log4j-Rce",
        "hxxps://github[.]com/example-owner-8/exploit-CVE-2021-44228",
    ]  # top 5 by stars then recency
    assert all(t["label"] == POC_LABEL for t in top) and top[0]["stars"] == 3424
    assert all("http" not in t["repo"].replace("hxxps", "") for t in top)
    # url pivots: the real URL as the entity, expand=False, the safety label as the note (cond 5)
    assert len(res.pivots) == 5
    for pivot in res.pivots:
        assert pivot.relation == "poc_claim" and pivot.expand is False and pivot.note == POC_LABEL
        assert pivot.entity.value.startswith("https://github.com/example-owner-")
    assert not res.findings  # never a severity (cond 4)
    assert a["poc_references"][0].startswith("http://packetstormsecurity.com/")
    http.assert_hosts_within(PocIndex)
    assert sorted(http.urls()) == sorted([NOMI_URL, TRICKEST_URL])  # only the per-CVE index files are fetched


def test_raw_evidence_keeps_counts_and_the_top_links_only():
    res = run_module(PocIndex, f"cve:{CVE}", ok_http())
    raw = res.raw["poc_index"]
    assert raw["total"] == 16 and raw["poc_in_github"] == {"tracked": True, "repos": 8, "dropped": 0}
    assert raw["trickest"]["github"] == 8 and len(raw["top"]) == 5
    assert "html_url" not in str(raw) and "owner" not in str(raw).replace("example-owner", "")


# ------------------------------------------------------------------ absences and partial answers
def test_404_on_both_indexes_is_a_documented_absence():
    http = FakeHttp()
    add_exchange(http, NOMI_URL, NOT_FOUND)
    add_exchange(http, TRICKEST_URL, NOT_FOUND)
    res = run_module(PocIndex, f"cve:{CVE}", http)
    assert res.status is Status.EMPTY and "absence is not proof" in res.error
    assert "exploit_maturity" not in res.attributes and not res.pivots


def test_trickest_without_github_and_nomi_404_is_empty():
    http = FakeHttp().add("GET", TRICKEST_URL, body=TRICKEST_NO_GITHUB.encode(), headers=MD)
    add_exchange(http, NOMI_URL, NOT_FOUND)
    res = run_module(PocIndex, f"cve:{CVE}", http)
    assert res.status is Status.EMPTY
    assert res.attributes["poc_references"]  # the reference links are kept, never expanded


def test_trickest_only_claims_have_lower_confidence():
    http = FakeHttp().add("GET", TRICKEST_URL, body=TRICKEST_OK.encode(), headers=MD)
    add_exchange(http, NOMI_URL, NOT_FOUND)
    res = run_module(PocIndex, f"cve:{CVE}", http)
    assert res.status is Status.OK
    assert res.attributes["poc_confidence"] == 0.3 and res.attributes["exploit_maturity"] == "poc_claimed (8 repos)"
    assert all(t["source"] == "trickest" and "stars" not in t for t in res.attributes["poc_repos"])


def test_one_index_failing_keeps_the_other_and_reports_could_not_verify():
    http = FakeHttp().add("GET", TRICKEST_URL, body=TRICKEST_OK.encode(), headers=MD)
    http.add("GET", NOMI_URL, status=500, text="internal error")
    res = run_module(PocIndex, f"cve:{CVE}", http)
    assert res.status is Status.OK
    entry = res.source_statuses[NOMI_SOURCE]
    assert (entry["status"], entry["reason_code"]) == ("error", "error")
    assert "could not verify" in entry["reason"]
    assert res.attributes["poc_confidence"] == 0.3  # trickest only answered


def test_a_429_backs_off_the_host_for_both_indexes():
    http = FakeHttp().add("GET", TRICKEST_URL, body=TRICKEST_OK.encode(), headers=MD)
    add_exchange(http, NOMI_URL, RATE_LIMITED)  # Retry-After 60: the second index is not even asked
    res = run_module(PocIndex, f"cve:{CVE}", http)
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited"
    assert "could not verify" in res.error and "exploit_maturity" not in res.attributes


# ------------------------------------------------------------------ rule 5: could not verify
def test_429_on_both_is_rate_limited_never_empty():
    http = FakeHttp()
    add_exchange(http, NOMI_URL, RATE_LIMITED)
    add_exchange(http, TRICKEST_URL, RATE_LIMITED)
    res = run_module(PocIndex, f"cve:{CVE}", http)
    assert res.status is Status.RATE_LIMITED and "could not verify" in res.error


def test_challenge_page_is_blocked():
    http = FakeHttp().add("GET", NOMI_URL, status=403, text=CHALLENGE).add("GET", TRICKEST_URL, status=403, text=CHALLENGE)
    res = run_module(PocIndex, f"cve:{CVE}", http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"


def test_keyless_403_is_blocked_not_needs_key():
    http = FakeHttp().add("GET", NOMI_URL, status=403, text="Forbidden").add("GET", TRICKEST_URL, status=403, text="Forbidden")
    res = run_module(PocIndex, f"cve:{CVE}", http)
    assert res.status is Status.BLOCKED


def test_5xx_is_error():
    http = FakeHttp().add("GET", NOMI_URL, status=503, text="unavailable").add("GET", TRICKEST_URL, status=502, text="bad gateway")
    res = run_module(PocIndex, f"cve:{CVE}", http)
    assert res.status is Status.ERROR


def test_html_error_page_inside_200_is_detected():
    page = "<!DOCTYPE html><html><head><title>Error</title></head><body>oops</body></html>"
    http = FakeHttp().add("GET", NOMI_URL, status=200, text=page).add("GET", TRICKEST_URL, status=200, text=page)
    res = run_module(PocIndex, f"cve:{CVE}", http)
    assert res.status is Status.ERROR and "could not verify" in res.error


def test_truncated_json_is_error_not_empty():
    truncated = (FIXTURES / "poc_index" / "nomi_truncated.json").read_bytes()
    http = FakeHttp().add("GET", NOMI_URL, body=truncated, headers={"content-type": "application/json"})
    add_exchange(http, TRICKEST_URL, NOT_FOUND)
    res = run_module(PocIndex, f"cve:{CVE}", http)
    # trickest answered (404 = none tracked) while PoC-in-GitHub could not be read: never 'no PoC'
    assert res.status is Status.EMPTY and "could not verify: PoC-in-GitHub" in res.error
    entry = res.source_statuses[NOMI_SOURCE]
    assert entry["status"] == "error"


def test_non_list_json_is_error():
    http = FakeHttp().add("GET", NOMI_URL, json={"message": "unexpected"})
    add_exchange(http, TRICKEST_URL, RATE_LIMITED)
    res = run_module(PocIndex, f"cve:{CVE}", http)
    assert res.status is Status.ERROR  # the first failure (PoC-in-GitHub: not a JSON list) decides
    assert res.source_statuses == {} and "not a JSON list" in res.error and "trickest/cve" in res.error


# ------------------------------------------------------------------ untrusted repository data (cond 5)
def test_hostile_repository_objects_are_dropped():
    parsed = parse_poc_in_github(module_fixture(PocIndex, "nomi_hostile.json"))
    assert [r["url"] for r in parsed["repos"]] == ["https://github.com/example-owner-a/ok-repo"]
    assert parsed["dropped"] == 10
    repo = parsed["repos"][0]
    assert repo["stars"] == 12 and "\x1b" not in (repo["description"] or "") and "‮" not in (repo["description"] or "")


@pytest.mark.parametrize("url", [
    "javascript:alert(1)", "http://github.com/a/b", "https://github.com.evil.example/a/b", "https://github.com/a/../b",
    "https://user:pass@github.com/a/b", "https://github.com/a", "https://github.com/a/b/tree/main", "https://github.com/a/.hidden",
])
def test_only_plain_github_repository_urls_survive(url):
    assert normalize_github_repo_url(url) is None


def test_trickest_parser_keeps_sections_apart():
    parsed = parse_trickest_markdown(TRICKEST_OK)
    assert parsed["cve"] == CVE and parsed["reason"] is None
    assert len(parsed["github"]) == 8 and all(u.startswith("https://github.com/example-owner-") for u in parsed["github"])
    assert "https://github.com/example-owner-9/CVE-mitre" not in parsed["github"]  # a Reference link is not a claim
    assert any("packetstormsecurity" in u for u in parsed["references"])
    assert parsed["products"] == ["Apache Log4j2"] and parsed["cwes"][0].startswith("CWE-20")
    assert parse_trickest_markdown("<html><head><title>x</title></head></html>")["reason"]


def test_selection_and_claim_fields_never_exceed_the_cap():
    nomi = [{"url": f"https://github.com/o{i}/r", "stars": i, "pushed_at": None, "source": "poc_in_github"} for i in range(50)]
    sel = select_poc_links(nomi, ["https://github.com/O1/R", "https://github.com/new/repo"])
    assert sel["total"] == 51 and len(sel["top"]) == 5 and sel["top"][0]["stars"] == 49
    fields = poc_claim_fields(sel)
    assert fields["confidence"] <= 0.4 and fields["exploit_maturity"] == "poc_claimed (51 repos)"
    assert poc_claim_fields({"total": 0})["exploit_maturity"] is None


# ------------------------------------------------------------------ fan-out rule (P183) and input checks
def test_pivot_cves_beyond_the_fanout_budget_are_deferred():
    res = run_module(PocIndex, f"cve:{CVE}", FakeHttp(), is_seed=False, case_id="case-poc-fanout", settings={"cve_fanout_budget": 0})
    assert res.status is Status.QUOTA and res.reason_code == "quota"


def test_request_cap_is_two():
    http = ok_http()
    res = run_module(PocIndex, f"cve:{CVE}", http)
    assert res.requests <= 2 and len(http.calls) == 2
