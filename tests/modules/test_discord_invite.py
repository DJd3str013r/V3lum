"""Offline tests of discord_invite (P101) on trimmed real Discord answers (tests/fixtures/discord_invite/)."""

from __future__ import annotations

import json

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.username_social.discord_invite import DiscordInvite, invite_code, webhook_of

URL = "https://discord.com/api/v10/invites/{code}?with_counts=true&with_expiration=true"
FAKE_TOKEN = "Ex4mpleT0kenNotRealAbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdEfGh"  # synthetic, never a real webhook


def env(name: str, **override) -> dict:
    d = module_fixture("discord_invite", name)
    out = {"status": d["status"], "headers": dict(d["headers"]), "text": d["body"]}
    out.update(override)
    return out


def dump(res) -> str:
    return json.dumps(res.to_dict(), default=str)


def test_vanity_invite_resolves_with_snowflake_date():
    http = FakeHttp().add("GET", URL.format(code="discord-developers"), json=module_fixture("discord_invite", "ok.json"))
    res = run_module(DiscordInvite, "url:https://discord.gg/discord-developers", http)
    assert res.status is Status.OK
    inv = res.attributes["discord_invite"]
    assert inv["guild"]["id"] == "613425648685547541" and inv["members"] == 312492 and inv["permanent"] is True
    assert inv["guild"]["features"] == ["VANITY_URL", "COMMUNITY", "VERIFIED", "NEWS", "DISCOVERABLE"]
    dates = {d["role"]: d["created"] for d in res.attributes["snowflake_dates"]}
    assert dates["guild"] == "2019-08-20T17:34:31Z"  # shared core snowflake decoder (P314)
    kw = [p for p in res.pivots if p.entity.type is T.KEYWORD]
    assert kw and kw[0].entity.value == "Discord Developers" and kw[0].expand is False and kw[0].relation == "invite_guild"
    assert not [p for p in res.pivots if p.relation == "invite_creator"]  # vanity invites have no inviter
    assert [c["method"] for c in http.calls] == ["GET"]  # never POST (join/accept)
    http.assert_hosts_within(DiscordInvite)


def test_inviter_pivots_without_avatar():
    http = FakeHttp().add("GET", URL.format(code="AbCd2345"), json=module_fixture("discord_invite", "ok_with_inviter.json"))
    res = run_module(DiscordInvite, "discord_invite:AbCd2345", http)
    assert res.status is Status.OK
    creators = {(p.entity.type, p.entity.value): p for p in res.pivots if p.relation == "invite_creator"}
    assert creators[(T.USERNAME, "example-inviter")].expand is False
    assert creators[(T.SOCIAL_ACCOUNT, "discord:674262500000000000")].expand is False
    assert res.attributes["discord_invite"]["expires_at"] == "2026-12-03T07:00:00Z"
    assert {d["role"] for d in res.attributes["snowflake_dates"]} == {"guild", "inviter"}
    assert "0123456789abcdef0123456789abcdef" not in dump(res)  # avatar hashes are dropped (never downloaded)


def test_unknown_invite_10006_is_invalid_or_expired():
    http = FakeHttp().add("GET", URL.format(code="qz7k2v9m4p1w8n3x5c6b"), **env("expired.http.json"))
    res = run_module(DiscordInvite, "discord_invite:qz7k2v9m4p1w8n3x5c6b", http)
    assert res.status is Status.EMPTY
    assert res.error == "invalid or expired invite" and "no such server" not in dump(res)
    assert res.attributes["presence"]["state"] == "absent"


def test_other_404_is_could_not_verify():
    http = FakeHttp().add("GET", URL.format(code="AbCd2345"), status=404, json={"message": "404: Not Found", "code": 0})
    assert run_module(DiscordInvite, "discord_invite:AbCd2345", http).status is Status.ERROR


def test_long_retry_after_is_rate_limited_without_retry():
    http = FakeHttp().add("GET", URL.format(code="AbCd2345"), **env("rate_limited.http.json"))
    res = run_module(DiscordInvite, "discord_invite:AbCd2345", http)
    assert res.status is Status.RATE_LIMITED
    assert len(http.calls) == 1  # 64.57 s > 15 s: no retry


def test_short_retry_after_is_honoured_once():
    http = FakeHttp()
    http.add("GET", URL.format(code="AbCd2345"), times=1, **env("rate_limited_short.http.json"))
    http.add("GET", URL.format(code="AbCd2345"), json=module_fixture("discord_invite", "ok_with_inviter.json"))
    res = run_module(DiscordInvite, "discord_invite:AbCd2345", http)
    assert res.status is Status.OK and len(http.calls) == 2  # waited retry_after (<= 15 s), retried once


def test_short_retry_after_is_retried_only_once():
    http = FakeHttp()
    http.add("GET", URL.format(code="AbCd2345"), times=2, **env("rate_limited_short.http.json"))
    res = run_module(DiscordInvite, "discord_invite:AbCd2345", http)
    assert res.status is Status.RATE_LIMITED and "retry_after 2.5 s" in res.error
    assert len(http.calls) == 2 <= DiscordInvite.max_requests


def test_cloudflare_1015_challenge_and_5xx_are_could_not_verify():
    http = FakeHttp().add("GET", URL.format(code="AbCd2345"), **env("cloudflare_1015.http.json"))
    assert run_module(DiscordInvite, "discord_invite:AbCd2345", http).status is Status.RATE_LIMITED
    page = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http = FakeHttp().add("GET", URL.format(code="AbCd2345"), status=403, text=page)
    assert run_module(DiscordInvite, "discord_invite:AbCd2345", http).status is Status.BLOCKED
    http = FakeHttp().add("GET", URL.format(code="AbCd2345"), status=500, text="oops", times=5)
    assert run_module(DiscordInvite, "discord_invite:AbCd2345", http).status is Status.ERROR


def test_error_in_200_and_malformed_json_are_errors():
    http = FakeHttp().add("GET", URL.format(code="AbCd2345"), json={"message": "Unknown Invite", "code": 10006})
    assert run_module(DiscordInvite, "discord_invite:AbCd2345", http).status is Status.ERROR
    http = FakeHttp().add("GET", URL.format(code="AbCd2345"), body=b'{"code": "AbCd2345", "guild": {', headers={"content-type": "application/json"})
    assert run_module(DiscordInvite, "discord_invite:AbCd2345", http).status is Status.ERROR


def test_code_validation_before_any_request():
    assert invite_code(Entity.make(T.URL, "https://discord.com/invite/Example-Guild-2")) == "Example-Guild-2"
    assert invite_code(Entity.make(T.URL, "https://discordapp.com/invite/XyZ987")) == "XyZ987"
    assert invite_code(Entity.make(T.URL, "https://example.com/invite/AbCd2345")) is None
    for bad in ("https://discord.gg/a", "https://discord.gg/abc_def"):
        http = FakeHttp()
        res = run_module(DiscordInvite, f"url:{bad}", http)
        assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []


def test_invites_only_from_ioc_contexts():
    http = FakeHttp()
    res = run_module(DiscordInvite, "discord_invite:AbCd2345", http, is_seed=False, depth=1,
                     provenance=(("username:example-dev", "linked_account_on_profile", "some_profile_module"),))
    assert res.status is Status.SKIPPED and http.calls == []  # an invite on a personal profile is not resolved
    http = FakeHttp().add("GET", URL.format(code="AbCd2345"), json=module_fixture("discord_invite", "ok_with_inviter.json"))
    res = run_module(DiscordInvite, "discord_invite:AbCd2345", http, is_seed=False, depth=1,
                     provenance=(("url:https://kit.example.net/config.php", "mentions", "ioc_extract"),))
    assert res.status is Status.OK


def test_webhook_url_is_never_requested_and_token_is_masked():
    url = f"https://discord.com/api/webhooks/1046950000000000002/{FAKE_TOKEN}"
    assert webhook_of(Entity.make(T.URL, url)) == ("1046950000000000002", FAKE_TOKEN)
    http = FakeHttp()
    res = run_module(DiscordInvite, f"url:{url}", http)
    assert http.calls == []  # cond 5: never requested
    assert res.status is Status.OK
    chan = res.attributes["exfil_channels"][0]
    assert chan["channel_id"] == "1046950000000000002" and chan["requested"] is False
    assert chan["fingerprint"]["preview"] == "Ex4m…EfGh" and len(chan["fingerprint"]["sha256"]) == 64
    f = res.findings[0]
    assert "c2" in f.tags and "phishing_kit_exfil" in f.tags
    shown = [res.attributes, res.raw, [(x.title, x.description, x.criterion, x.data) for x in res.findings]]
    assert_no_secret(FAKE_TOKEN, *shown)
