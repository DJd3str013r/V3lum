"""Offline tests of chesscom_player (P116) on tests/fixtures/chesscom_player/ (found/absent are real captures of
2026-11-26 of the official Chess.com Team account and a random control; the streamer profile is synthetic)."""

from __future__ import annotations

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Status
from v3lum.modules.username_social.community_profiles import ChesscomPlayer

FIX = "chesscom_player"
API = "https://api.chess.com/pub/player/{}"


def env(name: str) -> dict:
    d = module_fixture(FIX, name)
    return {"status": d["status"], "headers": d["headers"], "text": d["body"]}


def test_found_player_row():
    http = FakeHttp().add("GET", API.format("chesscom"), **env("found.http.json"))
    res = run_module(ChesscomPlayer, "url:https://www.chess.com/member/CHESScom", http)
    assert res.status is Status.OK
    assert res.attributes["account_id"] == 33 and res.attributes["display_name"] == "Chess.com Team"
    assert res.attributes["created"] == "2007-05-07T08:56:39Z"
    assert res.attributes["platform_facts"]["status"] == "staff"
    assert res.attributes["profile_row"] == {"site": "chesscom", "state": "found", "created": "2007-05-07T08:56:39Z",
                                             "display_name": "Chess.com Team", "profile_url": "https://www.chess.com/member/CHESScom"}
    assert len(http.calls) == 1
    http.assert_hosts_within(ChesscomPlayer)


def test_streamer_links_are_possible_unless_already_in_the_case():
    body = module_fixture(FIX, "streamer_synthetic.json")
    http = FakeHttp().add("GET", API.format("examplestreamer"), json=body)
    res = run_module(ChesscomPlayer, "url:https://www.chess.com/member/ExampleStreamer", http)
    piv = {p.entity.value: p for p in res.pivots}
    assert piv["https://twitch.tv/examplestreamer"].relation == "linked_account_on_profile"
    assert piv["https://twitch.tv/examplestreamer"].confidence_label == "possible"
    assert all(p.expand is False for p in res.pivots)
    opts = ScanOptions(seed_tlp={"social_account:twitch:examplestreamer": "amber"})
    http = FakeHttp().add("GET", API.format("examplestreamer"), json=body)
    res = run_module(ChesscomPlayer, "url:https://www.chess.com/member/ExampleStreamer", http, options=opts)
    piv = {p.entity.value: p for p in res.pivots}
    assert piv["https://twitch.tv/examplestreamer"].confidence_label == "probable"


def test_404_json_is_absent_but_404_html_is_not():
    http = FakeHttp().add("GET", API.format("snoixp6jxo8iy12i0rau"), **env("absent.http.json"))
    res = run_module(ChesscomPlayer, "url:https://www.chess.com/member/snoixp6jxo8iy12i0rau", http)
    assert res.status is Status.EMPTY and res.attributes["presence"]["state"] == "absent"
    http = FakeHttp().add("GET", API.format("snoixp6jxo8iy12i0rau"), status=404, text="<html><body>gone</body></html>",
                          headers={"content-type": "text/html"})
    assert run_module(ChesscomPlayer, "url:https://www.chess.com/member/snoixp6jxo8iy12i0rau", http).status is Status.ERROR


def test_rate_limit_html_and_mismatch_are_could_not_verify():
    http = FakeHttp().add("GET", API.format("chesscom"), **env("rate_limited_synthetic.http.json"))
    assert run_module(ChesscomPlayer, "url:https://www.chess.com/member/chesscom", http).status is Status.RATE_LIMITED
    http = FakeHttp().add("GET", API.format("chesscom"), **env("html_200_synthetic.http.json"))
    assert run_module(ChesscomPlayer, "url:https://www.chess.com/member/chesscom", http).status is Status.ERROR
    http = FakeHttp().add("GET", API.format("someoneelse"), **env("found.http.json"))
    res = run_module(ChesscomPlayer, "url:https://www.chess.com/member/someoneelse", http)
    assert res.status is Status.ERROR and "handle mismatch" in res.error
    http = FakeHttp().add("GET", API.format("chesscom"), status=503, text="busy", times=3)
    assert run_module(ChesscomPlayer, "url:https://www.chess.com/member/chesscom", http).status is Status.ERROR
