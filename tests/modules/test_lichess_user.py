"""Offline tests of lichess_user (P116) on tests/fixtures/lichess_user/ (found/absent are real captures of
2026-11-26 of the official Lichess account and a random control; closed/ToS/429 cases are synthetic)."""

from __future__ import annotations

from tests.fakes import FakeClock, FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.username_social.community_profiles import LichessUser

FIX = "lichess_user"
API = "https://lichess.org/api/user/{}"


def env(name: str) -> dict:
    d = module_fixture(FIX, name)
    return {"status": d["status"], "headers": d["headers"], "text": d["body"]}


def test_found_user_with_declared_links():
    http = FakeHttp().add("GET", API.format("lichess"), **env("found.http.json"))
    res = run_module(LichessUser, "url:https://lichess.org/@/lichess", http)
    assert res.status is Status.OK
    assert res.attributes["created"] == "2010-11-22T21:09:36Z" and res.attributes["verified"] is True
    urls = {p.entity.value for p in res.pivots}
    assert "https://twitch.tv/lichessdotorg" in urls and "https://t.me/lichessdotorg" in urls
    assert all(p.expand is False for p in res.pivots)
    http.assert_hosts_within(LichessUser)


def test_closed_and_tos_accounts_stay_found_with_flags():
    http = FakeHttp().add("GET", API.format("ExampleClosed"), json=module_fixture(FIX, "closed_synthetic.json"))
    res = run_module(LichessUser, "url:https://lichess.org/@/ExampleClosed", http)
    assert res.status is Status.OK and res.attributes["platform_facts"]["closed"] is True
    http = FakeHttp().add("GET", API.format("ExampleTos"), json=module_fixture(FIX, "tos_synthetic.json"))
    res = run_module(LichessUser, "url:https://lichess.org/@/ExampleTos", http)
    assert res.attributes["platform_facts"]["tos_violation"] is True


def test_404_is_absent():
    http = FakeHttp().add("GET", API.format("ryveekjj4zrjtcfulgl9"), **env("absent.http.json"))
    res = run_module(LichessUser, "url:https://lichess.org/@/ryveekjj4zrjtcfulgl9", http)
    assert res.status is Status.EMPTY and res.attributes["presence"]["state"] == "absent"


def test_429_starts_a_60_second_cooldown_without_retry():
    clock = FakeClock()
    http = FakeHttp().add("GET", API.format("lichess"), **env("rate_limited_synthetic.http.json"), times=1)
    rt = make_runtime(http, clock=clock)
    res = run_module(LichessUser, "url:https://lichess.org/@/lichess", http, runtime=rt)
    assert res.status is Status.RATE_LIMITED and len(http.calls) == 1  # never retried in-run
    clock.advance(30)
    res = run_module(LichessUser, "url:https://lichess.org/@/lichess", http, runtime=make_runtime(http, clock=clock))
    assert res.status is Status.RATE_LIMITED and "nothing sent" in res.error and len(http.calls) == 1  # next run, same minute
    clock.advance(31)
    http.add("GET", API.format("lichess"), **env("found.http.json"))
    assert run_module(LichessUser, "url:https://lichess.org/@/lichess", http, runtime=make_runtime(http, clock=clock)).status is Status.OK
    assert len(http.calls) == 2


def test_challenge_and_odd_answers_are_could_not_verify():
    page = "<html><head><title>Just a moment...</title></head><body><script>window._cf_chl_opt={}</script></body></html>"
    http = FakeHttp().add("GET", API.format("lichess"), status=403, text=page, headers={"content-type": "text/html"})
    res = run_module(LichessUser, "url:https://lichess.org/@/lichess", http)
    assert res.status is Status.BLOCKED and any(url == "https://lichess.org/@/lichess" for _label, url in res.links)
    http = FakeHttp().add("GET", API.format("lichess"), text="<!DOCTYPE html><html><body>maintenance</body></html>",
                          headers={"content-type": "text/html"})
    assert run_module(LichessUser, "url:https://lichess.org/@/lichess", http).status is Status.ERROR
    http = FakeHttp().add("GET", API.format("lichess"), json={"id": "lichess"})
    assert run_module(LichessUser, "url:https://lichess.org/@/lichess", http).status is Status.ERROR
