"""Offline tests of snapchat_profile (P116) on tests/fixtures/snapchat_profile/ (found_userinfo, found_public and absent
are real captures of 2026-11-26 of the official teamsnapchat and nasa profiles and a random control, minimised; the
link, layout-change and challenge pages are synthetic)."""

from __future__ import annotations

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.username_social.community_profiles import SnapchatProfile

FIX = "snapchat_profile"
PAGE = "https://www.snapchat.com/@{}"


def env(name: str) -> dict:
    d = module_fixture(FIX, name)
    return {"status": d["status"], "headers": d["headers"], "text": d["body"]}


def test_public_profile_facts():
    http = FakeHttp().add("GET", PAGE.format("nasa"), **env("found_public.http.json"))
    res = run_module(SnapchatProfile, "url:https://www.snapchat.com/@nasa", http)
    assert res.status is Status.OK
    assert res.attributes["display_name"] == "NASA" and res.attributes["created"] == "2019-05-22T17:38:27Z"
    assert res.attributes["platform_facts"]["public_profile"] is True
    assert [p.entity.value for p in res.pivots] == ["https://www.nasa.gov/"]
    http.assert_hosts_within(SnapchatProfile)


def test_user_info_profile_from_the_legacy_add_url():
    http = FakeHttp().add("GET", PAGE.format("teamsnapchat"), **env("found_userinfo.http.json"))
    res = run_module(SnapchatProfile, "url:https://www.snapchat.com/add/teamsnapchat", http)
    assert res.status is Status.OK and res.attributes["platform_facts"]["public_profile"] is False


def test_declared_links_are_expand_false_and_suggestions_only_counted():
    http = FakeHttp().add("GET", PAGE.format("exampleshop"), **env("found_links_synthetic.http.json"))
    res = run_module(SnapchatProfile, "url:https://www.snapchat.com/@exampleshop", http)
    urls = {p.entity.value: p for p in res.pivots}
    assert "https://shop.example.com/" in urls and "https://www.instagram.com/exampleshop" in urls
    assert not any(u.startswith("javascript:") for u in urls)
    assert all(p.expand is False for p in res.pivots)
    assert res.attributes["content_withheld"] == ["address", "bio"]


def test_not_found_page_type_is_the_only_absence():
    http = FakeHttp().add("GET", PAGE.format("xg9ruucev40dvl2"), **env("absent.http.json"))
    res = run_module(SnapchatProfile, "url:https://www.snapchat.com/@xg9ruucev40dvl2", http)
    assert res.status is Status.EMPTY and res.attributes["presence"]["state"] == "absent"
    http = FakeHttp().add("GET", PAGE.format("xg9ruucev40dvl2"), status=404, text="<html><body>404</body></html>",
                          headers={"content-type": "text/html"})
    assert run_module(SnapchatProfile, "url:https://www.snapchat.com/@xg9ruucev40dvl2", http).status is Status.ERROR


def test_layout_change_is_error_never_empty():
    for name in ("layout_changed_synthetic.http.json", "no_next_data_synthetic.http.json"):
        http = FakeHttp().add("GET", PAGE.format("exampleshop"), **env(name))
        res = run_module(SnapchatProfile, "url:https://www.snapchat.com/@exampleshop", http)
        assert res.status is Status.ERROR and "layout changed" in res.error, name


def test_challenge_is_blocked_never_bypassed():
    http = FakeHttp().add("GET", PAGE.format("exampleshop"), **env("challenge_synthetic.http.json"))
    res = run_module(SnapchatProfile, "url:https://www.snapchat.com/@exampleshop", http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge" and len(http.calls) == 1
    assert any(url == "https://www.snapchat.com/@exampleshop" for _label, url in res.links)


def test_terms_unknown_keeps_it_out_of_every_profile():
    assert SnapchatProfile.terms == "unknown" and SnapchatProfile.default_enabled is False
