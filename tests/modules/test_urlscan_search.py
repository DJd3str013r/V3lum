"""urlscan_search (P066, batch p1-G03-1): search only, labelled queries, paging caps, redaction, details.

Fixtures in tests/fixtures/urlscan_search/: real keyless search answers recorded on 2026-11-26
(page.domain:example.com, the third-party query, page 2 via search_after, the empty hash query, a
capped 10000 total) trimmed to 2-3 hits with the submitter '@user' tag replaced; the keyless
result-detail 403 {"warning": "You're not logged in!"} with its headers; a derived hit carrying
documentation e-mail/token values in its URLs; an HTML page instead of JSON; and a synthetic keyed
result detail in the documented format.
"""

from __future__ import annotations

import json
from pathlib import Path

from tests.fakes import FakeClock, FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.url_web import urlscan_search as M
from v3lum.modules.url_web.urlscan_search import UrlscanSearch

SITE = 'page.domain:example.com'
THIRD = 'domain:example.com AND NOT page.domain:example.com'
KEY = "k3y-for-tests-0123456789abcdef"


def fx(name: str):
    return module_fixture(UrlscanSearch, name)


def headers_of(name: str) -> dict[str, str]:
    out = {}
    for line in fx(name).splitlines():
        if ":" in line and not line.startswith("HTTP/"):
            k, v = line.split(":", 1)
            out[k.strip().lower()] = v.strip()
    return out


def search(query: str, size: int = 100, after: str | None = None) -> str:
    return M.build_search_url(query, size, after)


def domain_routes(http: FakeHttp, site="ok.json", third="third_party_ok.json", size=100) -> FakeHttp:
    http.add("GET", search(SITE, size), json=fx(site), headers=headers_of("ok_headers.txt"))
    http.add("GET", search(THIRD, size), json=fx(third), headers=headers_of("ok_headers.txt"))
    return http


def dump(res) -> str:
    findings = [{k: v for k, v in f.to_dict().items() if k != "entity"} for f in res.findings]
    return json.dumps({"attributes": res.attributes, "raw": res.raw, "findings": findings, "pivots": [p.to_dict() for p in res.pivots],
                       "links": res.links, "error": res.error}, default=str)


# ------------------------------------------------------------------ metadata (c1, c2, c3)
def test_metadata():
    cls = UrlscanSearch
    assert (cls.terms, cls.provider, cls.sources, cls.hosts) == ("noncommercial", "urlscan", ("urlscan.search",), ("urlscan.io",))
    assert cls.disclosure == "third_party" and cls.shares_input is True and cls.publishes_queries is False
    assert cls.trust_tier == "trusted" and cls.default_enabled is True and cls.optional_keys == ("urlscan",)
    assert cls.max_requests == 8 and cls.cache_ttl == 3600 and cls.min_interval == 2.0
    assert "corporate" in cls.notice


def test_no_submission_code_path_exists():
    source = Path(M.__file__).read_text(encoding="utf-8")
    assert "api/v1/scan" not in source and "post(" not in source.lower().replace("post_json", "")


# ------------------------------------------------------------------ c4: two labelled queries per domain
def test_domain_runs_site_and_third_party_queries():
    http = domain_routes(FakeHttp())
    res = run_module(UrlscanSearch, "domain:example.com", http)
    assert res.status is Status.OK
    assert [c["method"] for c in http.calls] == ["GET", "GET"]
    assert all("/api/v1/search/" in u for u in http.urls())
    totals = res.attributes["urlscan_totals"]
    assert totals["site"]["total"] == 1908 and totals["third_party"]["total"] == 9156
    titles = sorted(f.key for f in res.findings if f.title == "Public urlscan.io scans found")
    assert titles == ["site", "third_party"]
    ips = {p.entity.value: p.relation for p in res.pivots if p.entity.type is T.IPV4}
    assert ips == {"172.66.147.243": "resolves_to", "104.20.23.154": "resolves_to"}
    third = {p.entity.value: p for p in res.pivots if p.relation == "loaded_by"}
    assert set(third) == {"bluum.ltd", "tw.yahoo.com"} and all(not p.expand for p in third.values())
    inbound = {p.entity.value for p in res.pivots if p.relation == "related"}
    assert inbound == {"toperstoffshore.org", "ww12.bankifscotland.de"}  # other domains that redirected to example.com
    assert ("urlscan.io domain page", "https://urlscan.io/domain/example.com") in res.links
    assert res.attributes["first_seen"] <= res.attributes["last_seen"]
    http.assert_hosts_within(UrlscanSearch)


def test_every_hit_is_dated_and_marked_historical_after_30_days():
    http = domain_routes(FakeHttp())
    res = run_module(UrlscanSearch, "domain:example.com", http, clock=FakeClock("2027-01-10T00:00:00Z"))
    assert all(s["scanned_at"] and s["historical"] for s in res.attributes["urlscan_scans"])
    assert all(p.confidence <= 0.4 + 1e-9 for p in res.pivots)  # historical observations are 'possible'
    assert "historical" in res.findings[0].description


# ------------------------------------------------------------------ c3: paging caps and rate-limit headers
def test_paging_uses_search_after_on_full_pages_only():
    http = FakeHttp()
    http.add("GET", search(SITE, 3), json=fx("ok.json"), headers=headers_of("ok_headers.txt"))
    http.add("GET", search(SITE, 3, "1795665202022,01a215fc-4559-72b2-8db7-dce9f86e58cf"), json=fx("page2_ok.json"))
    http.add("GET", search(THIRD, 3), json=fx("third_party_ok.json"))
    res = run_module(UrlscanSearch, "domain:example.com", http, settings={"urlscan_search_size": 3})
    assert len(http.calls) == 3 and res.attributes["urlscan_totals"]["site"]["fetched"] == 5
    assert "search_after=1795665202022%2C01a215fc" in http.urls()[1]


def test_at_most_two_search_after_pages():
    page = fx("ok.json")
    http = FakeHttp()
    http.add("GET", search(SITE, 3), json=page)
    after = "1795665202022,01a215fc-4559-72b2-8db7-dce9f86e58cf"
    http.add("GET", search(SITE, 3, after), json=page, times=2)  # every page is full and ends with the same sort
    http.add("GET", search(THIRD, 3), json={"results": [], "total": 0})
    res = run_module(UrlscanSearch, "domain:example.com", http, settings={"urlscan_search_size": 3})
    site_calls = [u for u in http.urls() if "?q=page.domain%3Aexample.com" in u]
    assert len(site_calls) == 3  # 1 + 2 search_after pages, never a third
    assert res.status is Status.OK


def test_size_is_capped_at_100():
    assert "size=100" in M.build_search_url("page.domain:example.com", size=500)


def test_rate_limit_remaining_zero_stops_paging():
    http = FakeHttp()
    hdrs = dict(headers_of("ok_headers.txt"), **{"x-rate-limit-remaining": "0"})
    http.add("GET", search(SITE, 3), json=fx("ok.json"), headers=hdrs)
    http.add("GET", search(THIRD, 3), json=fx("empty.json"))
    res = run_module(UrlscanSearch, "domain:example.com", http, settings={"urlscan_search_size": 3})
    assert len(http.calls) == 2 and res.partial and res.stop_reason == "rate_limited"
    assert res.raw["rate"]["limit"] == 30


def test_429_is_rate_limited_never_empty():
    http = FakeHttp().add("GET", search(SITE), status=429, json={"message": "Too many requests"}, headers={"x-rate-limit-reset-after": "17"})
    res = run_module(UrlscanSearch, "domain:example.com", http)
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited" and not res.findings


def test_keyless_403_is_blocked_and_keyed_403_needs_key():
    http = FakeHttp().add("GET", search('page.ip:8.8.8.8'), status=403, json={"message": "Forbidden"})
    assert run_module(UrlscanSearch, "ipv4:8.8.8.8", http).status is Status.BLOCKED
    http2 = FakeHttp().add("GET", search('page.ip:8.8.8.8'), status=403, json={"message": "API key invalid"})
    res = run_module(UrlscanSearch, "ipv4:8.8.8.8", http2, keys={"urlscan": KEY})
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key"
    assert http2.calls[0]["headers"].get("API-Key") == KEY


def test_5xx_and_timeout_are_errors():
    http = FakeHttp().add("GET", search('page.ip:8.8.8.8'), status=503, text="unavailable")
    res = run_module(UrlscanSearch, "ipv4:8.8.8.8", http)
    assert res.status is Status.ERROR and not res.findings
    from v3lum.core.http import NetworkError

    http2 = FakeHttp().add("GET", search('page.ip:8.8.8.8'), error=NetworkError("ReadTimeout contacting urlscan.io: timed out"))
    assert run_module(UrlscanSearch, "ipv4:8.8.8.8", http2).status is Status.ERROR


def test_error_object_inside_http_200_is_never_empty():
    http = FakeHttp().add("GET", search('page.ip:8.8.8.8'), json={"message": "Invalid query", "status": 400})
    res = run_module(UrlscanSearch, "ipv4:8.8.8.8", http)
    assert res.status is Status.ERROR and "could not verify" in res.error


def test_malformed_json_and_html_are_could_not_verify():
    http = FakeHttp().add("GET", search('page.ip:8.8.8.8'), body=b'{"results": [', headers={"content-type": "application/json"})
    res = run_module(UrlscanSearch, "ipv4:8.8.8.8", http)
    assert res.status is Status.ERROR and "malformed JSON" in res.error
    http2 = FakeHttp().add("GET", search('page.ip:8.8.8.8'), text=fx("html_instead_of_json.html"))
    assert run_module(UrlscanSearch, "ipv4:8.8.8.8", http2).status is Status.ERROR


def test_empty_search_is_empty():
    http = domain_routes(FakeHttp(), site="empty.json", third="empty.json")
    res = run_module(UrlscanSearch, "domain:example.com", http)
    assert res.status is Status.EMPTY and not res.findings and res.raw["totals"]["site"]["total"] == 0


# ------------------------------------------------------------------ c5: redaction before storage
def test_emails_and_tokens_in_result_urls_are_redacted():
    http = domain_routes(FakeHttp(), site="email_in_url_derived.json", third="empty.json")
    res = run_module(UrlscanSearch, "domain:example.com", http)
    blob = dump(res)
    for leak in ("victim", "dmljdGltQGV4YW1wbGUuY29t", "Zk9xQ2xWbU1hTkJ0eUR5WkE3cTN4", "@analyst-example"):
        assert leak not in blob, leak
    scan = res.attributes["urlscan_scans"][0]
    assert scan["task_url"] == "https://login.payout.example.org/auth/?email=REDACTED_EMAIL&session=REDACTED_TOKEN&lang=pt"
    assert set(scan["redactions"]) == {"email", "base64_email", "opaque_token"}


def test_capped_totals_and_query_tokens():
    http = FakeHttp().add("GET", search('page.ip:8.8.8.8'), json=fx("nokey_capped_total.json"))
    res = run_module(UrlscanSearch, "ipv4:8.8.8.8", http)
    assert res.attributes["urlscan_totals"]["page_ip"]["capped"] is True
    assert any(s.get("page_url") == "https://hk.yahoo.com/?k=REDACTED_TOKEN" for s in res.attributes["urlscan_scans"])
    assert ("urlscan.io IP page", "https://urlscan.io/ip/8.8.8.8") in res.links


# ------------------------------------------------------------------ c3/c8: result details only with a key
def test_keyless_runs_never_request_result_details():
    http = domain_routes(FakeHttp())
    run_module(UrlscanSearch, "domain:example.com", http)
    assert all("/api/v1/result/" not in u for u in http.urls())


def test_result_detail_403_keeps_the_search_results():
    http = domain_routes(FakeHttp())
    http.add("GET", "https://urlscan.io/api/v1/result/*", status=403, json=fx("result_403.json"), headers=headers_of("result_403_headers.txt"))
    res = run_module(UrlscanSearch, "domain:example.com", http, keys={"urlscan": KEY})
    assert res.status is Status.OK
    assert "refused" in res.raw["details"]["problem"]
    assert sum("/api/v1/result/" in u for u in http.urls()) == 1  # a refusal stops the details
    assert all(c["headers"].get("API-Key") == KEY for c in http.calls)


def test_keyed_result_detail_gives_a_verdict_vote_and_resource_hashes():
    http = domain_routes(FakeHttp())
    http.add("GET", "https://urlscan.io/api/v1/result/*", json=fx("result_detail_synthetic.json"))
    res = run_module(UrlscanSearch, "domain:example.com", http, keys={"urlscan": KEY})
    verdict = next(f for f in res.findings if f.title == "urlscan.io verdict: malicious")
    assert verdict.severity.label == "medium" and verdict.source == "urlscan.search" and verdict.criterion
    hashes = {p.entity.value: p for p in res.pivots if p.entity.type is T.SHA256}
    assert set(hashes) == {"aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44",
                           "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}  # jQuery skipped (c4)
    assert all(not p.expand and p.relation == "loads_resource" for p in hashes.values())
    assert "victim" not in dump(res)


# ------------------------------------------------------------------ other entity types
def test_hash_query_on_a_common_resource_gives_no_pivots():
    sha = "a" * 64
    http = FakeHttp().add("GET", search(f"hash:{sha}"), json=fx("nokey_capped_total.json"))
    res = run_module(UrlscanSearch, f"sha256:{sha}", http)
    assert not [p for p in res.pivots if p.entity.type is T.DOMAIN]
    assert any(f.title.startswith("Resource hash seen on many pages") for f in res.findings)


def test_url_query_and_recipient_bound_url_searches_the_host_only():
    http = FakeHttp().add("GET", search('page.url:"https://example.com/"'), json=fx("empty.json"))
    assert run_module(UrlscanSearch, "url:https://example.com/", http).status is Status.EMPTY
    http2 = FakeHttp().add("GET", search("page.domain:payout.example.org"), json=fx("empty.json"))
    res = run_module(UrlscanSearch, "url:https://payout.example.org/login?email=victim%40example.com", http2)
    assert res.status is Status.EMPTY and "victim" not in "".join(http2.urls())
    assert "recipient identifiers" in res.raw["note"]


def test_asn_and_ipv6_queries():
    assert M.build_queries(T.ASN, "AS13335") == [("page_asn", "page.asn:AS13335")]
    assert M.build_queries(T.IPV6, "2001:db8::1") == [("page_ip", 'page.ip:"2001:db8::1"')]
    assert M.build_queries(T.DOMAIN, "8.8.8.8") == []


def test_private_ip_and_wrapper_url_are_not_applicable():
    assert run_module(UrlscanSearch, "ipv4:10.0.0.1", FakeHttp()).status is Status.SKIPPED
    wrapped = "url:https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fpayout.example.org%2F&data=05%7C01"
    assert run_module(UrlscanSearch, wrapped, FakeHttp()).status is Status.SKIPPED


def test_third_party_pages_on_an_org_domain_are_brand_abuse_candidates():
    org = OrgProfile.from_dict({"org": {"name": "Example"}, "domains": [{"name": "example.com", "verification": "txt_verified"}]})
    http = domain_routes(FakeHttp())
    rt = make_runtime(http, org_profile=org)
    res = run_module(UrlscanSearch, "domain:example.com", runtime=rt)
    abuse = next(f for f in res.findings if "brand-abuse" in f.title)
    assert abuse.severity.label == "low" and "brand_abuse" in abuse.tags and abuse.criterion
    assert set(abuse.data["domains"]) == {"bluum.ltd", "tw.yahoo.com"}


def test_acceptance_routes_replay_the_golden_inputs():
    """AR21 golden path: the recorded routes answer every request of a default run (benign, info only)."""
    golden = {"domain": "domain:example.com", "ipv4": "ipv4:8.8.8.8", "url": "url:https://example.com/",
              "sha256": "sha256:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"}
    root = Path(__file__).resolve().parent.parent / "fixtures" / "acceptance"
    for etype, value in golden.items():
        doc = json.loads((root / etype / "urlscan_search.json").read_text(encoding="utf-8"))
        assert doc["schema"] == "v3lum.acceptance_routes/1" and doc["module"] == "urlscan_search"
        http = FakeHttp()
        for route in doc["routes"]:
            assert route["latency_ms"] > 0 and "@" not in json.dumps(route["json"])
            http.add(route["method"], route["url"], status=route["status"], json=route["json"], headers=route.get("headers"))
        res = run_module(UrlscanSearch, value, http)
        assert res.status is Status.OK and len(http.calls) == len(doc["routes"]), etype
        assert all(f.severity.label == "info" for f in res.findings) and all(c["method"] == "GET" for c in http.calls)
