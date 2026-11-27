"""Offline tests of the reddit_archive module (P108) on trimmed real Arctic Shift answers
(tests/fixtures/reddit_archive/: the official 'reddit' account's posts/comments, a live empty answer, the live 400
error objects, the README-documented 429, and documentation-value deleted/removed items)."""

from __future__ import annotations

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.username_social.reddit_archive import (
    DELETED_LABEL,
    RedditArchive,
    keyword_url,
    reduce_item,
    search_url,
    summarise,
)


def fx(name: str):
    return module_fixture("reddit_archive", name)


def env(name: str) -> dict:
    d = fx(name)
    return {"status": d["status"], "headers": d["headers"], "body": d["body"].encode()}


def run(posts, comments, entity="username:reddit", **kw):
    http = FakeHttp().add("GET", search_url("posts", entity.rsplit(":", 1)[1]), **posts)
    if comments is not None:
        http.add("GET", search_url("comments", entity.rsplit(":", 1)[1]), **comments)
    return run_module(RedditArchive, entity, http, **kw), http


def test_metadata_follows_the_council():
    assert RedditArchive.default_enabled is False and RedditArchive.terms == "unknown"  # cond 2
    assert RedditArchive.run_on == "seeds" and RedditArchive.timeout == 30.0  # cond 3/6
    assert search_url("posts", "x", 1000).endswith("limit=100")  # one page, limit <= 100 (cond 1)


def test_counts_dates_and_linked_domains_only_never_a_subreddit_profile():
    res, http = run({"json": fx("posts_ok.json")}, {"json": fx("comments_ok.json")})
    assert res.status is Status.OK, res.error
    http.assert_hosts_within(RedditArchive)
    act = res.attributes["reddit_activity"]
    assert act["posts"] == 3 and act["comments"] == 3 and act["first_activity_bound"] == "exact"
    assert act["first_activity"].startswith("2024-02-22") and act["last_activity"].startswith("2026-10-22")
    assert "youtube.com" in act["linked_domains"] and "redditinc.com" in act["linked_domains"]
    assert "reddit.com" not in act["linked_domains"] and "i.redd.it" not in act["linked_domains"]
    assert "subreddit" not in str(act).lower()  # cond 4: no per-subreddit counts or ranking
    for kind in ("posts", "comments"):  # cond 3: reduced records only
        for item in res.raw[kind]:
            assert set(item) == {"id", "kind", "subreddit", "created_utc", "created", "permalink", "excerpt", "deleted_by_author",
                                 "label", "removed", "linked_domains"}
            assert item["excerpt"] is None or len(item["excerpt"]) <= 500
    assert set(res.raw) == {"author", "posts", "comments"}  # no raw Reddit object (selftext, author fields...) is kept
    dom = {p.entity.value: p for p in res.pivots}["youtube.com"]
    assert dom.relation == "links_to" and dom.expand is False
    assert not res.attributes.get("org_mentions")  # no org profile: nothing quoted
    assert res.findings[0].title == "Archived Reddit activity" and res.findings[0].criterion


def test_org_mentions_are_quoted_at_most_200_characters():
    org = OrgProfile.from_dict({"domains": [{"name": "redditinc.com", "verification": "confirmed"}], "brands": [{"keyword": "Snoo"}]})
    res, _ = run({"json": fx("posts_ok.json")}, {"json": fx("comments_ok.json")}, org_profile=org)
    quotes = res.attributes["org_mentions"]
    assert quotes and all(len(q["quote"]) <= 200 for q in quotes)
    assert {q["id"] for q in quotes} >= {"1xc3c9z", "krnkgh9"}
    assert "Archived Reddit items mention the organisation" in {f.title for f in res.findings}


def test_deleted_by_author_is_labelled_never_quoted():
    org = OrgProfile.from_dict({"domains": [{"name": "example.com", "verification": "confirmed"}]})
    res, _ = run({"json": fx("posts_deleted.json")}, {"json": fx("comments_deleted.json")}, org_profile=org)
    assert res.status is Status.OK
    items = {i["id"]: i for i in res.raw["posts"] + res.raw["comments"]}
    assert items["1a2b3c"]["label"] == DELETED_LABEL and items["1a2b3c"]["excerpt"] is None
    assert items["k0deleted"]["deleted_by_author"] is True and items["k0deleted"]["linked_domains"] == []  # deleted later (_meta)
    assert items["1a2b3d"]["removed"] is True and items["1a2b3d"]["deleted_by_author"] is False
    assert not res.attributes.get("org_mentions")  # the deleted comment mentions example.com: never quoted
    assert res.attributes["reddit_activity"]["deleted_by_author"] == 2


def test_empty_archive_is_empty():
    res, _ = run({"json": fx("empty.json")}, {"json": fx("empty.json")}, entity="username:qz7k2v9m4p1w8n3")
    assert res.status is Status.EMPTY and "archive gap" in res.error and "presence" not in res.attributes


def test_error_json_inside_200_and_400_is_could_not_verify():
    body = fx("error_400.http.json")["body"]
    res, _ = run({"text": body, "headers": {"content-type": "application/json"}}, None)
    assert res.status is Status.ERROR
    res, _ = run(env("error_400.http.json"), None)
    assert res.status is Status.ERROR
    res, _ = run({"json": {"data": None, "error": "Query timed out"}}, None)
    assert res.status is Status.ERROR and res.reason_code == "timeout"
    res, _ = run({"json": {"unexpected": True}}, None)
    assert res.status is Status.ERROR


def test_429_is_rate_limited_and_comment_failure_is_reported_per_source():
    res, _ = run(env("rate_limited.http.json"), None)
    assert res.status is Status.RATE_LIMITED
    res, _ = run({"json": fx("posts_ok.json")}, {"status": 502, "text": "bad gateway", "times": 5})
    assert res.status is Status.OK and res.source_statuses["arctic_shift.search"]["status"] == "error"
    assert res.attributes["reddit_activity"]["comments"] == 0


def test_challenge_page_is_blocked():
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    res, _ = run({"status": 403, "text": page}, None)
    assert res.status is Status.BLOCKED


def test_keyword_needs_configured_subreddits():
    http = FakeHttp()
    res = run_module(RedditArchive, "keyword:Example Bank", http)
    assert res.status is Status.SKIPPED and res.reason_code == "config" and http.calls == []
    http = FakeHttp().add("GET", keyword_url("Example Bank", "brasil"), json=fx("posts_ok.json"))
    res = run_module(RedditArchive, "keyword:Example Bank", http, settings={"reddit_archive_subreddits": ["r/brasil", "bad name!"]})
    assert res.status is Status.OK and http.urls() == [keyword_url("Example Bank", "brasil")]
    assert res.attributes["reddit_activity"]["posts"] == 3


def test_invalid_handles_are_never_sent():
    http = FakeHttp()
    res = run_module(RedditArchive, "username:ab", http)
    assert res.status is Status.SKIPPED and http.calls == []


def test_reduction_and_summary_are_defensive():
    assert reduce_item({"id": "BAD ID"}, "post") is None and reduce_item("x", "post") is None
    item = reduce_item({"id": "abc", "subreddit": "example", "link_id": "t3_def", "body": "see https://example.org/a"}, "comment")
    assert item["permalink"] == "https://www.reddit.com/r/example/comments/def/_/abc/" and item["linked_domains"] == ["example.org"]
    full = summarise([item] * 100, [], True, False)
    assert full["first_activity_bound"] == "upper_bound" and full["posts_at_least"] is True
