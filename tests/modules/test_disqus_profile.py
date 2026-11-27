"""Offline tests of disqus_profile (P116) on tests/fixtures/disqus_profile/ (found/absent pages are real captures of
2026-11-26 of the official 'disqus' profile and a random control; the API answers are documentation-shaped and the
invalid-key answer is the research sample)."""

from __future__ import annotations

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.username_social.community_profiles import DisqusProfile

FIX = "disqus_profile"
PAGE = "https://disqus.com/by/{}/"
API = "https://disqus.com/api/3.0/users/details.json?user=username:{}&api_key={}"
KEY = "disqus-test-public-key-0000000000000000"


def env(name: str) -> dict:
    d = module_fixture(FIX, name)
    return {"status": d["status"], "headers": d["headers"], "text": d["body"]}


def test_profile_page_gives_existence_and_privacy():
    http = FakeHttp().add("GET", PAGE.format("disqus"), **env("found.http.json"))
    res = run_module(DisqusProfile, "url:https://disqus.com/by/disqus/", http)
    assert res.status is Status.OK and res.attributes["platform_facts"]["is_private"] is False
    http.assert_hosts_within(DisqusProfile)
    http = FakeHttp().add("GET", PAGE.format("exampleprivate"), **env("private_synthetic.http.json"))
    res = run_module(DisqusProfile, "url:https://disqus.com/by/exampleprivate/", http)
    assert res.attributes["platform_facts"]["is_private"] is True


def test_not_found_page_is_absent():
    http = FakeHttp().add("GET", PAGE.format("klqvcj4ogm7ovh6sngqi"), **env("absent.http.json"))
    res = run_module(DisqusProfile, "url:https://disqus.com/by/klqvcj4ogm7ovh6sngqi/", http)
    assert res.status is Status.EMPTY and res.attributes["presence"]["state"] == "absent"


def test_api_with_the_team_key():
    http = FakeHttp().add("GET", API.format("exampleuser", KEY), json=module_fixture(FIX, "api_ok_documented.json"))
    res = run_module(DisqusProfile, "url:https://disqus.com/by/exampleuser/", http, keys={"disqus": KEY})
    assert res.status is Status.OK and res.attributes["created"] == "2014-03-25T18:58:35Z"
    assert [p.entity.value for p in res.pivots] == ["https://example.com/blog"]
    assert KEY not in str(res.to_dict())
    http = FakeHttp().add("GET", API.format("exampleuser", KEY), **env("api_not_found_documented.http.json"))
    res = run_module(DisqusProfile, "url:https://disqus.com/by/exampleuser/", http, keys={"disqus": KEY})
    assert res.status is Status.EMPTY


def test_invalid_key_is_needs_key_never_absent():
    http = FakeHttp().add("GET", API.format("exampleuser", KEY), **env("api_invalid_key.http.json"))
    res = run_module(DisqusProfile, "url:https://disqus.com/by/exampleuser/", http, keys={"disqus": KEY})
    assert res.status is Status.NEEDS_KEY


def test_layout_change_challenge_and_rate_limit():
    http = FakeHttp().add("GET", PAGE.format("disqus"), text="<!DOCTYPE html><html><head><title>Disqus</title></head></html>",
                          headers={"content-type": "text/html"})
    assert run_module(DisqusProfile, "url:https://disqus.com/by/disqus/", http).status is Status.ERROR
    page = "<html><head><title>Just a moment...</title></head><body><script>window._cf_chl_opt={}</script></body></html>"
    http = FakeHttp().add("GET", PAGE.format("disqus"), status=403, text=page, headers={"content-type": "text/html"})
    assert run_module(DisqusProfile, "url:https://disqus.com/by/disqus/", http).status is Status.BLOCKED
    http = FakeHttp().add("GET", PAGE.format("disqus"), status=429, text="slow")
    assert run_module(DisqusProfile, "url:https://disqus.com/by/disqus/", http).status is Status.RATE_LIMITED
    http = FakeHttp().add("GET", API.format("exampleuser", KEY), json={"code": 13, "response": "rate limit"})
    res = run_module(DisqusProfile, "url:https://disqus.com/by/exampleuser/", http, keys={"disqus": KEY})
    assert res.status is Status.RATE_LIMITED
