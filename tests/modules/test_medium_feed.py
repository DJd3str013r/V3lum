"""Offline tests of medium_feed (P116) on tests/fixtures/medium_feed/ (found/absent are real captures of 2026-11-26:
the official @Medium feed and a random control whose ordinary 404 page embeds Cloudflare's passive precursor
script; blocked.http.json is the managed challenge p1-G05-2 captured on the same host)."""

from __future__ import annotations

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Status
from v3lum.modules.username_social.community_profiles import MediumFeed

FIX = "medium_feed"
FEED = "https://medium.com/feed/@{}"


def env(name: str) -> dict:
    d = module_fixture(FIX, name)
    return {"status": d["status"], "headers": d["headers"], "text": d["body"]}


def test_found_feed_facts_and_withheld_content():
    http = FakeHttp().add("GET", FEED.format("Medium"), **env("found.http.json"))
    res = run_module(MediumFeed, "url:https://medium.com/@Medium", http)
    assert res.status is Status.OK
    facts = res.attributes["platform_facts"]
    assert facts["display_name"] == "Medium" and facts["account_id"] == "504c7870fdb6"
    assert facts["posts_in_feed"] >= 1 and res.attributes["last_activity"].startswith("20")
    assert "posts" in res.attributes["content_withheld"]  # FC8: post titles only when relevant to the case
    assert "profile_content" not in res.attributes
    http.assert_hosts_within(MediumFeed)


def test_post_data_shown_when_it_mentions_a_case_entity():
    http = FakeHttp().add("GET", FEED.format("Medium"), **env("found.http.json"))
    res = run_module(MediumFeed, "url:https://medium.com/@Medium", http, options=ScanOptions(seed_tlp={"domain:eff.org": "amber"}))
    assert res.attributes["profile_content"]["content_link_domains"]["eff.org"] == 1


def test_ordinary_404_page_is_absent_not_a_challenge():
    http = FakeHttp().add("GET", FEED.format("blwuoyzpj4db7ad4izq9"), **env("absent.http.json"))
    res = run_module(MediumFeed, "url:https://medium.com/@blwuoyzpj4db7ad4izq9", http)
    assert res.status is Status.EMPTY and res.attributes["presence"]["state"] == "absent"


def test_managed_challenge_is_blocked_with_the_manual_link():
    http = FakeHttp().add("GET", FEED.format("medium"), **env("blocked.http.json"))
    res = run_module(MediumFeed, "url:https://medium.com/@medium/about", http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"
    assert ("Medium profile (manual check)", "https://medium.com/@medium") in [tuple(x) for x in res.links]
    assert len(http.calls) == 1  # never retried


def test_malformed_and_html_feeds_are_errors():
    http = FakeHttp().add("GET", FEED.format("Medium"), text=module_fixture(FIX, "malformed_synthetic.xml"),
                          headers={"content-type": "application/rss+xml"})
    assert run_module(MediumFeed, "url:https://medium.com/@Medium", http).status is Status.ERROR
    http = FakeHttp().add("GET", FEED.format("Medium"), text="<!DOCTYPE html><html><body>app shell</body></html>",
                          headers={"content-type": "text/html"})
    assert run_module(MediumFeed, "url:https://medium.com/@Medium", http).status is Status.ERROR
    http = FakeHttp().add("GET", FEED.format("Medium"), status=429, text="slow down")
    assert run_module(MediumFeed, "url:https://medium.com/@Medium", http).status is Status.RATE_LIMITED
