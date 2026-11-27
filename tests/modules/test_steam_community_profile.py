"""Offline tests of steam_community_profile (P116) on tests/fixtures/steam_community_profile/ (the absent answer is a
real capture of 2026-11-26; the found profiles are the research redacted sample and a synthetic public profile with
documentation values)."""

from __future__ import annotations

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.username_social.community_profiles import SteamCommunityProfile

FIX = "steam_community_profile"
BY_ID = "https://steamcommunity.com/profiles/{}/?xml=1"
BY_VANITY = "https://steamcommunity.com/id/{}/?xml=1"
XML = {"content-type": "text/xml;charset=UTF-8"}


def env(name: str) -> dict:
    d = module_fixture(FIX, name)
    return {"status": d["status"], "headers": d["headers"], "text": d["body"]}


def test_public_profile_gives_the_stable_id_and_unwrapped_links():
    http = FakeHttp().add("GET", BY_VANITY.format("exampleplayer"), text=module_fixture(FIX, "found_public_synthetic.xml"), headers=XML)
    res = run_module(SteamCommunityProfile, "url:https://steamcommunity.com/id/exampleplayer/", http)
    assert res.status is Status.OK
    assert res.attributes["account_id"] == "76561190000000001"  # steamID64 survives renames
    assert res.attributes["created"] == "2011-03-03"
    assert res.attributes["display_name"] == "Example Player"
    assert res.attributes["profile_row"]["site"] == "steam"
    links = {p.entity.value: p for p in res.pivots}
    assert "https://www.twitch.tv/exampleplayer" in links  # Steam's linkfilter unwrapped
    assert links["https://www.twitch.tv/exampleplayer"].relation == "linked_account_on_profile"
    assert all(p.expand is False for p in res.pivots)
    assert res.attributes["content_withheld"] == ["location", "real_name", "summary"]  # FC8: no case term mentioned
    assert [f.title for f in res.findings] == ["Account on Steam"]
    http.assert_hosts_within(SteamCommunityProfile)


def test_steam_profile_entity_and_private_profile():
    http = FakeHttp().add("GET", BY_VANITY.format("exampleplayer"), text=module_fixture(FIX, "found_public_synthetic.xml"), headers=XML)
    res = run_module(SteamCommunityProfile, "steam_profile:id:exampleplayer", http)
    assert res.status is Status.OK and res.attributes["account_id"] == "76561190000000001"
    http = FakeHttp().add("GET", BY_ID.format("76561190000000000"), text=module_fixture(FIX, "found_redacted.xml"), headers=XML)
    res = run_module(SteamCommunityProfile, "url:https://steamcommunity.com/profiles/76561190000000000", http)
    assert res.status is Status.OK and res.attributes["platform_facts"]["privacy_state"] == "friendsonly"
    http = FakeHttp().add("GET", BY_ID.format("76561190000000009"), text=module_fixture(FIX, "found_redacted.xml"), headers=XML)
    res = run_module(SteamCommunityProfile, "url:https://steamcommunity.com/profiles/76561190000000009", http)
    assert res.status is Status.ERROR and "handle mismatch" in res.error


def test_documented_error_in_200_is_the_only_absence():
    http = FakeHttp().add("GET", BY_VANITY.format("vsnrr8ych1ryfgwsp7pb"), **env("absent.http.json"))
    res = run_module(SteamCommunityProfile, "url:https://steamcommunity.com/id/vsnrr8ych1ryfgwsp7pb/", http)
    assert res.status is Status.EMPTY and res.attributes["presence"]["state"] == "absent"
    http = FakeHttp().add("GET", BY_VANITY.format("exampleplayer"), **env("error_in_200_synthetic.http.json"))
    res = run_module(SteamCommunityProfile, "url:https://steamcommunity.com/id/exampleplayer/", http)
    assert res.status is Status.ERROR and "Failed loading" in res.error


def test_html_dtd_and_truncated_xml_are_errors_never_absent():
    url = BY_VANITY.format("exampleplayer")
    for route in (env("html_200_synthetic.http.json"), {"text": module_fixture(FIX, "xxe_synthetic.xml"), "headers": XML},
                  {"text": module_fixture(FIX, "malformed_synthetic.xml"), "headers": XML}):
        http = FakeHttp().add("GET", url, **route)
        res = run_module(SteamCommunityProfile, "url:https://steamcommunity.com/id/exampleplayer/", http)
        assert res.status is Status.ERROR, route


def test_429_challenge_and_5xx_are_could_not_verify():
    url = BY_VANITY.format("exampleplayer")
    http = FakeHttp().add("GET", url, **env("rate_limited_synthetic.http.json"))
    assert run_module(SteamCommunityProfile, "url:https://steamcommunity.com/id/exampleplayer/", http).status is Status.RATE_LIMITED
    page = "<html><head><title>Just a moment...</title></head><body><script>window._cf_chl_opt={}</script></body></html>"
    http = FakeHttp().add("GET", url, status=403, text=page, headers={"content-type": "text/html", "cf-mitigated": "challenge"})
    res = run_module(SteamCommunityProfile, "url:https://steamcommunity.com/id/exampleplayer/", http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"
    assert ("Steam profile (manual check)", "https://steamcommunity.com/id/exampleplayer/") in [tuple(x) for x in res.links]
    http = FakeHttp().add("GET", url, status=500, text="oops")
    assert run_module(SteamCommunityProfile, "url:https://steamcommunity.com/id/exampleplayer/", http).status is Status.ERROR


def test_other_urls_are_not_applicable():
    res = run_module(SteamCommunityProfile, "url:https://steamcommunity.com/groups/example", FakeHttp())
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
