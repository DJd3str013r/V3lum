"""Offline tests of the youtube module (P110) on YouTube answers (tests/fixtures/youtube/: the live Google for Developers
feed and oEmbed answer, the live 404/400 answers, and the documented Data API shapes with a fictional channel; the
consent redirect is synthetic: it was not observed from this egress)."""

from __future__ import annotations

from pathlib import Path

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.username_social.youtube import (
    API,
    YouTube,
    channel_id_ok,
    classify_input,
    oembed_url,
    parse_rss,
    rss_url,
)
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T

KEY = "AIzaSyTESTKEY000000000000000000000000000"
GOOGLE_DEV = "UC_x5XG1OV2P6uZZ5FSM9Ttw"
FICTIONAL = "UC0123456789abcdefABCDEF"
RSS_XML = (Path(__file__).resolve().parents[1] / "fixtures" / "youtube" / "rss_ok.xml").read_bytes()


def env(name: str) -> dict:
    d = module_fixture("youtube", name)
    return {"status": d["status"], "headers": d["headers"], "body": d["body"].encode()}


def api(**params: str) -> str:
    q = "&".join(f"{k}={v}" for k, v in {"part": "snippet,statistics", **params, "key": KEY}.items())
    return f"{API}?{q}"


def pivots(res) -> dict:
    return {(p.entity.type.value, p.entity.value): p for p in res.pivots}


def test_input_classification_and_channel_id_validation():
    assert channel_id_ok(GOOGLE_DEV) and not channel_id_ok("_x5XG1OV2P6uZZ5FSM9Ttw") and not channel_id_ok("UC123")
    url = lambda u: classify_input(Entity.make(T.URL, u))  # noqa: E731
    assert url(f"https://www.youtube.com/channel/{GOOGLE_DEV}") == {"kind": "channel", "channel_id": GOOGLE_DEV}
    assert url("https://youtu.be/WN5O4vWCa54") == {"kind": "video", "video_id": "WN5O4vWCa54"}
    assert url("https://m.youtube.com/watch?v=WN5O4vWCa54&t=3") == {"kind": "video", "video_id": "WN5O4vWCa54"}
    assert url("https://www.youtube.com/@GoogleDevelopers") == {"kind": "handle", "handle": "googledevelopers"}
    assert url("https://www.youtube.com/c/legacy")["kind"] == "invalid"
    assert classify_input(Entity.make(T.KEYWORD, GOOGLE_DEV))["kind"] == "channel"
    assert oembed_url("WN5O4vWCa54").endswith("watch%3Fv%3DWN5O4vWCa54&format=json")


def test_handle_without_key_is_needs_key_and_never_scrapes():
    http = FakeHttp()
    res = run_module(YouTube, "username:exampleorg", http)
    assert res.status is Status.NEEDS_KEY and http.calls == []  # no youtube.com/@handle page scrape (cond 1)


def test_handle_with_key_resolves_channel_and_reads_the_feed():
    http = (FakeHttp().add("GET", api(forHandle="@exampleorg"), json=module_fixture("youtube", "data_api_found.json"))
            .add("GET", rss_url(FICTIONAL), body=RSS_XML.replace(GOOGLE_DEV.encode(), FICTIONAL.encode()),
                 headers={"content-type": "application/atom+xml"}))
    res = run_module(YouTube, "username:exampleorg", http, keys={"youtube": KEY})
    assert res.status is Status.OK, res.error
    http.assert_hosts_within(YouTube)
    ch = res.attributes["youtube_channel"]
    assert ch["channel_id"] == FICTIONAL and ch["country"] == "BR" and ch["subscriber_count"] == 678 and ch["video_count"] == 42
    assert res.attributes["created"].startswith("2015-03-04") and res.attributes["country"] == "BR"  # cond 4
    up = res.attributes["youtube_uploads"]
    assert up["uploads_in_feed"] == 3 and up["last_upload"].startswith("2026-11-25")
    assert "description" not in str(res.raw).lower()  # redacted evidence (cond 5)
    p = pivots(res)
    assert p[("url", f"https://www.youtube.com/channel/{FICTIONAL}")].confidence_label == "confirmed"
    assert ("social_account", "youtube:exampleorg") in p
    assert_no_secret(KEY, res.to_dict(), res.raw, [f.to_dict() for f in res.findings])  # the key never leaves the request
    assert YouTube.cache_ttl <= 30 * 86400


def test_handle_not_found_is_absent():
    http = FakeHttp().add("GET", api(forHandle="@exampleorg"), json=module_fixture("youtube", "data_api_not_found.json"))
    res = run_module(YouTube, "username:exampleorg", http, keys={"youtube": KEY})
    assert res.status is Status.EMPTY and res.attributes["presence"]["state"] == "absent"


def test_permission_denied_is_needs_key_and_quota_is_quota():
    http = FakeHttp().add("GET", api(forHandle="@exampleorg"), **env("data_api_forbidden.http.json"))
    res = run_module(YouTube, "username:exampleorg", http, keys={"youtube": KEY})
    assert res.status is Status.NEEDS_KEY  # cond 3
    http = FakeHttp().add("GET", api(forHandle="@exampleorg"), **env("data_api_quota.http.json"))
    res = run_module(YouTube, "username:exampleorg", http, keys={"youtube": KEY})
    assert res.status is Status.QUOTA and res.reason_code == "quota"
    bad_key = {"error": {"code": 400, "message": "API key not valid. Please pass a valid API key.",
                         "errors": [{"reason": "badRequest"}], "status": "INVALID_ARGUMENT",
                         "details": [{"reason": "API_KEY_INVALID"}]}}
    http = FakeHttp().add("GET", api(forHandle="@exampleorg"), status=400, json=bad_key)
    assert run_module(YouTube, "username:exampleorg", http, keys={"youtube": KEY}).status is Status.NEEDS_KEY
    rate = {"error": {"code": 403, "errors": [{"reason": "rateLimitExceeded"}]}}
    http = FakeHttp().add("GET", api(forHandle="@exampleorg"), status=403, json=rate)
    assert run_module(YouTube, "username:exampleorg", http, keys={"youtube": KEY}).status is Status.RATE_LIMITED


def test_data_api_blocked_by_licence_profile_is_skipped_licence():
    http = FakeHttp()
    res = run_module(YouTube, "username:exampleorg", http, keys={"youtube": KEY}, allowed_sources=["youtube.rss", "youtube.oembed"])
    assert res.status is Status.SKIPPED and res.reason_code == "licence" and http.calls == []


def test_channel_url_keyless_feed():
    http = FakeHttp().add("GET", rss_url(GOOGLE_DEV), body=RSS_XML, headers={"content-type": "application/atom+xml"})
    res = run_module(YouTube, f"url:https://www.youtube.com/channel/{GOOGLE_DEV}", http)
    assert res.status is Status.OK
    ch = res.attributes["youtube_channel"]
    assert ch["channel_id"] == GOOGLE_DEV and ch["created"].startswith("2007-08-23") and ch["source"] == "channel feed (keyless)"
    assert [e["video_id"] for e in res.attributes["youtube_uploads"]["entries"]][0] == "WN5O4vWCa54"


def test_unknown_channel_feed_404_is_empty_not_absent():
    http = FakeHttp().add("GET", rss_url("UCqz7k2v9m4p1w8n3x5c6b9a"), **env("rss_not_found.http.json"))
    res = run_module(YouTube, "keyword:UCqz7k2v9m4p1w8n3x5c6b9a", http)
    assert res.status is Status.EMPTY and "presence" not in res.attributes


def test_video_oembed_and_bad_request():
    http = FakeHttp().add("GET", oembed_url("WN5O4vWCa54"), json=module_fixture("youtube", "oembed_ok.json"))
    res = run_module(YouTube, "url:https://youtu.be/WN5O4vWCa54", http)
    assert res.status is Status.OK
    assert res.attributes["youtube_video"]["handle"] == "googledevelopers"
    author = pivots(res)[("url", "https://www.youtube.com/@GoogleDevelopers")]
    assert author.relation == "post_author" and author.expand is False
    http = FakeHttp().add("GET", oembed_url("qz7k2v9m4p1"), **env("oembed_bad_request.http.json"))
    res = run_module(YouTube, "url:https://www.youtube.com/watch?v=qz7k2v9m4p1", http)
    assert res.status is Status.EMPTY and "400" in res.error


def test_consent_redirect_and_interstitial_are_blocked_never_empty():
    http = FakeHttp().add("GET", rss_url(GOOGLE_DEV), **env("consent_redirect.http.json"))
    res = run_module(YouTube, f"keyword:{GOOGLE_DEV}", http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"  # cond 4
    assert http.hosts() == {"www.youtube.com"}  # the consent host is never followed
    page = "<html><head><title>Before you continue to YouTube</title></head><body><form action='https://consent.youtube.com/save'></form></body></html>"
    http = FakeHttp().add("GET", oembed_url("WN5O4vWCa54"), text=page)
    res = run_module(YouTube, "url:https://youtu.be/WN5O4vWCa54", http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"
    sorry = "<html><body>Our systems have detected unusual traffic from your computer network. <div class='g-recaptcha'></div></body></html>"
    http = FakeHttp().add("GET", rss_url(GOOGLE_DEV), status=429, text=sorry)
    assert run_module(YouTube, f"keyword:{GOOGLE_DEV}", http).status is Status.BLOCKED


def test_429_5xx_and_malformed_feed_are_could_not_verify():
    http = FakeHttp().add("GET", oembed_url("WN5O4vWCa54"), status=429, text="Too Many Requests")
    assert run_module(YouTube, "url:https://youtu.be/WN5O4vWCa54", http).status is Status.RATE_LIMITED
    http = FakeHttp().add("GET", rss_url(GOOGLE_DEV), status=503, text="unavailable", times=5)
    assert run_module(YouTube, f"keyword:{GOOGLE_DEV}", http).status is Status.ERROR
    http = FakeHttp().add("GET", rss_url(GOOGLE_DEV), body=b"<feed><unclosed>", headers={"content-type": "application/atom+xml"})
    assert run_module(YouTube, f"keyword:{GOOGLE_DEV}", http).status is Status.ERROR


def test_feed_parser_refuses_entities_and_fixes_the_channel_id_prefix():
    feed, _ = parse_rss(RSS_XML)
    assert feed["channel_id"] == GOOGLE_DEV and feed["uploads_in_feed"] == 3
    evil = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><feed xmlns="http://www.w3.org/2005/Atom"><title>&a;</title></feed>'
    assert parse_rss(evil)[0] is None
    no_alt = RSS_XML.replace(b'rel="alternate" href="https://www.youtube.com/channel/' + GOOGLE_DEV.encode() + b'"', b'rel="related" href="x"')
    assert parse_rss(no_alt)[0]["channel_id"] == GOOGLE_DEV  # rebuilt from the 'UC'-less yt:channelId


def test_handle_pivots_from_other_modules_never_spend_quota():
    http = FakeHttp()
    res = run_module(YouTube, "username:exampleorg", http, keys={"youtube": KEY}, is_seed=False, depth=1)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []
