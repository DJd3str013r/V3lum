"""Offline tests of the hackernews module (P109) on trimmed real Firebase/Algolia answers
(tests/fixtures/hackernews/: YC's 'whoishiring' bot account, the documented 'null' body, an HN Search author page
and a mention search with scrubbed author handles; a documentation-value 'about' text)."""

from __future__ import annotations

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.username_social.hackernews import (
    HackerNews,
    author_url,
    hn_username_ok,
    mentions_url,
    parse_about,
    parse_search,
    user_url,
    username_from_url,
)

FIREBASE = "https://hacker-news.firebaseio.com/v0/user/{u}.json"


def fx(name: str):
    return module_fixture("hackernews", name)


def pivots(res) -> dict:
    return {(p.entity.type.value, p.entity.value): p for p in res.pivots}


def org(*domains: str, brand: str = "Cloudflare") -> OrgProfile:
    return OrgProfile.from_dict({"domains": [{"name": d, "verification": "confirmed"} for d in domains or ("cloudflare.com",)],
                                 "brands": [{"keyword": brand}]})


def test_username_validation_and_urls():
    assert hn_username_ok("whoishiring") and hn_username_ok("a-b_c") and not hn_username_ok("a")
    assert not hn_username_ok("x" * 16) and not hn_username_ok("has space") and not hn_username_ok(None)
    assert user_url("whoishiring") == FIREBASE.format(u="whoishiring")
    assert author_url("whoishiring") == "https://hn.algolia.com/api/v1/search_by_date?tags=author_whoishiring&hitsPerPage=20"
    assert username_from_url("https://news.ycombinator.com/user?id=ColinWright") == "ColinWright"
    assert username_from_url("https://news.ycombinator.com/item?id=1") is None
    assert mentions_url("cloudflare.com").startswith("https://hn.algolia.com/api/v1/search?query=%22cloudflare.com%22")


def test_account_and_activity_counts_dates_and_links_only():
    http = (FakeHttp().add("GET", FIREBASE.format(u="whoishiring"), json=fx("user_ok.json"))
            .add("GET", author_url("whoishiring"), json=fx("algolia_author_ok.json")))
    res = run_module(HackerNews, "username:whoishiring", http)
    assert res.status is Status.OK, res.error
    http.assert_hosts_within(HackerNews)
    acc = res.attributes["hn_account"]
    assert acc["id"] == "whoishiring" and acc["karma"] == 50113 and acc["submitted_count"] == 5
    assert acc["created"].startswith("2010-10-20")
    assert "submitted" not in str(res.raw) or isinstance(res.raw.get("submitted_count"), int)  # never the id list (cond 3)
    act = res.attributes["hn_activity"]
    assert act["items_total"] == 514 and act["last_activity"].startswith("2026-11-02")
    assert act["first_activity_bound"] == acc["created"]
    assert [s["id"] for s in act["stories"]] == ["50338728", "50338726", "49922569"]
    assert "https://www.example.com/jobs" in act["links"]
    assert res.attributes["presence"]["state"] == "found"
    assert not res.attributes.get("org_mentions")  # no org profile: nothing is quoted
    f = res.findings[0]
    assert f.title == "Hacker News account" and f.criterion and f.source == "hacker_news.firebase_api"


def test_null_body_is_absent_decided_from_the_json():
    http = FakeHttp().add("GET", FIREBASE.format(u="qz7k2v9m4p1w8n3"), body=b"null", headers={"content-type": "application/json"})
    res = run_module(HackerNews, "username:qz7k2v9m4p1w8n3", http)
    assert res.status is Status.EMPTY
    assert res.attributes["presence"]["state"] == "absent" and "body null" in res.attributes["presence"]["marker"]
    assert "case-sensitive" in res.error
    assert len(http.calls) == 1  # no Algolia request for a missing account


def test_about_html_is_unescaped_and_links_emails_keybase_pivot_without_expansion():
    http = (FakeHttp().add("GET", FIREBASE.format(u="exampleorg"), json=fx("user_about_links.json"))
            .add("GET", author_url("exampleorg"), json=fx("algolia_author_empty.json")))
    res = run_module(HackerNews, "username:exampleorg", http)
    p = pivots(res)
    site = p[("url", "https://www.example.com/")]
    assert site.relation == "link_on_profile" and site.expand is False and site.confidence_label == "possible"
    for email in ("security@example.com", "ops@example.org"):
        e = p[("email", email)]
        assert e.relation == "email_on_profile" and e.expand is False
    kb = p[("social_account", "keybase:exampleorg")]
    assert kb.relation == "linked_account_on_profile" and kb.expand is False
    assert res.attributes["hn_activity"]["items_total"] == 0
    assert res.attributes["hn_account"]["about_email_count"] == 2


def test_exact_case_id_from_a_profile_url():
    http = (FakeHttp().add("GET", FIREBASE.format(u="ExampleOrg"), json={**fx("user_about_links.json"), "id": "ExampleOrg"})
            .add("GET", author_url("ExampleOrg"), json=fx("algolia_author_empty.json")))
    res = run_module(HackerNews, "url:https://news.ycombinator.com/user?id=ExampleOrg", http)
    assert res.status is Status.OK and res.attributes["hn_account"]["id"] == "ExampleOrg"


def test_invalid_username_is_skipped_without_a_request():
    http = FakeHttp()
    res = run_module(HackerNews, "username:a.b", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []


def test_algolia_failure_keeps_the_account_and_reports_the_source():
    http = (FakeHttp().add("GET", FIREBASE.format(u="whoishiring"), json=fx("user_ok.json"))
            .add("GET", author_url("whoishiring"), status=500, text="<!doctype html><title>500 Internal Server Error</title>", times=5))
    res = run_module(HackerNews, "username:whoishiring", http)
    assert res.status is Status.OK
    assert res.source_statuses["algolia.hn_search"]["status"] == "error"
    assert "hn_activity" not in res.attributes


def test_org_mentions_are_quoted_only_for_org_terms():
    http = (FakeHttp().add("GET", FIREBASE.format(u="whoishiring"), json=fx("user_ok.json"))
            .add("GET", author_url("whoishiring"), json=fx("algolia_author_ok.json")))
    res = run_module(HackerNews, "username:whoishiring", http, org_profile=org("example.com", brand="Example"))
    mentions = res.attributes["org_mentions"]
    assert mentions and all(len(m["quote"]) <= 200 for m in mentions)
    assert "Hacker News items mention the organisation" in {f.title for f in res.findings}


def test_domain_mentions_only_for_org_profile_domains():
    http = FakeHttp().add("GET", mentions_url("cloudflare.com"), json=fx("algolia_query_ok.json"))
    res = run_module(HackerNews, "domain:cloudflare.com", http, org_profile=org("cloudflare.com"))
    assert res.status is Status.OK
    items = res.attributes["org_mentions"]
    assert {i["id"] for i in items} == {"23313657", "42163883", "30065411"}
    assert all("author" not in i for i in items)  # hit authors are never kept (minimisation)
    assert not any(p.entity.type.value == "username" for p in res.pivots)
    http2 = FakeHttp()
    res2 = run_module(HackerNews, "domain:example.net", http2, org_profile=org("cloudflare.com"))
    assert res2.status is Status.SKIPPED and res2.reason_code == "not_applicable" and http2.calls == []
    res3 = run_module(HackerNews, "keyword:Cloudflare", FakeHttp().add("GET", mentions_url("Cloudflare"), json=fx("algolia_author_empty.json")),
                      org_profile=org("cloudflare.com"))
    assert res3.status is Status.EMPTY


def test_firebase_error_object_in_200_is_never_absent():
    http = FakeHttp().add("GET", FIREBASE.format(u="whoishiring"), json={"error": "Permission denied"})
    res = run_module(HackerNews, "username:whoishiring", http)
    assert res.status is Status.ERROR


def test_429_5xx_malformed_and_challenge_are_could_not_verify():
    http = FakeHttp().add("GET", FIREBASE.format(u="whoishiring"), status=429, text="slow down")
    assert run_module(HackerNews, "username:whoishiring", http).status is Status.RATE_LIMITED
    http = FakeHttp().add("GET", FIREBASE.format(u="whoishiring"), status=502, text="bad gateway", times=5)
    assert run_module(HackerNews, "username:whoishiring", http).status is Status.ERROR
    http = FakeHttp().add("GET", FIREBASE.format(u="whoishiring"), body=b"{\"id\": ", headers={"content-type": "application/json"})
    assert run_module(HackerNews, "username:whoishiring", http).status is Status.ERROR
    http = FakeHttp().add("GET", FIREBASE.format(u="whoishiring"), json=["unexpected"])
    assert run_module(HackerNews, "username:whoishiring", http).status is Status.ERROR
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http = FakeHttp().add("GET", FIREBASE.format(u="whoishiring"), status=403, text=page)
    assert run_module(HackerNews, "username:whoishiring", http).status is Status.BLOCKED


def test_parsers_are_defensive():
    assert parse_about(None)["urls"] == []
    assert parse_search({"hits": "no"}, [], "author") is None
    out = parse_search({"hits": [{"objectID": "1", "_tags": ["comment"], "comment_text": "nothing here"}], "nbHits": 1}, ["acme"], "author")
    assert out["unmatched_comments"] == 1 and out["stories"] == [] and out["links"] == []


def test_golden_domain_acceptance_sends_nothing_without_an_org_profile():
    from tests.fakes import fixture

    routes = fixture("acceptance/domain/hackernews.json")
    assert routes["schema"] == "v3lum.acceptance_routes/1" and routes["module"] == "hackernews" and routes["routes"] == []
    http = FakeHttp()
    res = run_module(HackerNews, "domain:example.com", http)
    assert res.status is Status.SKIPPED and http.calls == []
