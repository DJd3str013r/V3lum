"""x_twitter_public (P119): X oEmbed for status URLs - published interface only, 404 wording, rule 5.

Fixtures in tests/fixtures/x_twitter_public/ (batch p3-G05-3 prep, 2026-11-26): ``oembed_ok``,
``oembed_redirect`` and ``oembed_not_found`` are REAL captures of the U.S. Department of the Interior post
that X's own oEmbed documentation uses (status 507185938620219395) and of the non-existent status 1 (the
404 HTML page trimmed); ``oembed_sequential_id`` is the research sample (author scrubbed to 'example');
the 429, challenge, error-in-200, malformed, 5xx and login-redirect answers are SYNTHETIC.
"""

from __future__ import annotations

from typing import Any

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.username_social import x_twitter_public as X
from v3lum.modules.username_social.x_twitter_public import XTwitterPublic

POST = "https://twitter.com/Interior/status/507185938620219395"
GONE = "https://twitter.com/Interior/status/1"
OLD = "https://x.com/example/status/20"


def fx(name: str) -> dict[str, Any]:
    return module_fixture("x_twitter_public", name)


def add(http: FakeHttp, url: str, name: str) -> FakeHttp:
    env = fx(name)
    body = env.get("body")
    return http.add("GET", url, status=int(env["status"]), body=(body or "").encode("utf-8"), headers=env.get("headers") or {})


def oembed(status_url: str, host: str = "publish.twitter.com") -> str:
    url = X.oembed_request_url(status_url, host=host)
    assert url is not None
    return url


def assert_no_bot_ua(http: FakeHttp) -> None:
    """cond 4: a test asserts that no crawler / search-engine UA is ever sent (twayback's trick excluded)."""
    assert http.calls
    for call in http.calls:
        ua = {k.lower(): v for k, v in (call.get("headers") or {}).items()}.get("user-agent", "")
        assert X.bot_user_agent_reason(ua) is None, (call["url"], ua)
        assert ua.startswith("V3LUM/")


def test_metadata_matches_the_council_decision():
    assert XTwitterPublic.terms == "unknown" and XTwitterPublic.default_enabled is False  # cond 6
    assert XTwitterPublic.provider == "x_corp" and XTwitterPublic.trust_tier == "trusted"
    assert XTwitterPublic.disclosure == "third_party" and XTwitterPublic.sources == ("x_corp.oembed",)
    assert set(XTwitterPublic.hosts) == {"publish.twitter.com", "publish.x.com"}
    assert not any("syndication" in h or h in ("twitter.com", "x.com") for h in XTwitterPublic.hosts)  # cond 2/3


def test_status_url_detector_pattern():
    cases = {
        "https://twitter.com/Interior/status/507185938620219395": ("507185938620219395", "Interior"),
        "https://mobile.twitter.com/Interior/statuses/507185938620219395/photo/1": ("507185938620219395", "Interior"),
        "https://x.com/Interior/status/507185938620219395?s=20&t=abcdefghijklmnopqrstuv": ("507185938620219395", "Interior"),
        "http://www.twitter.com/#!/Interior/status/507185938620219395": ("507185938620219395", "Interior"),
        "https://x.com/i/web/status/507185938620219395": ("507185938620219395", None),
    }
    for url, (sid, handle) in cases.items():
        p = X.parse_status_url(url)
        assert p is not None and p["status_id"] == sid and p["handle"] == handle, url
    for url in ("https://x.com/Interior", "https://example.com/Interior/status/1", "507185938620219395",
                "https://x.com/home/status/1", "https://twitter.com/Interior/status/0"):
        assert X.parse_status_url(url) is None, url
    assert oembed(POST) == ("https://publish.twitter.com/oembed?url=https%3A%2F%2Ftwitter.com%2FInterior%2Fstatus%2F"
                            "507185938620219395&omit_script=true&dnt=true")


def test_available_post_follows_the_oembed_redirect_only():
    http = FakeHttp()
    add(http, oembed(POST), "oembed_redirect.http.json")
    add(http, oembed(POST, "publish.x.com"), "oembed_ok.http.json")
    res = run_module(XTwitterPublic, f"url:{POST}", http)
    assert res.status is Status.OK, res.error
    post = res.attributes["x_post"]
    assert post["handle"] == "Interior" and post["author_name"] == "U.S. Department of the Interior"
    assert "Wilderness Act" in post["text"] and post["mentions"] == ["YosemiteNPS"] and post["hashtags"] == ["Wilderness50"]
    assert post["date_text"] == "September 3, 2014" and post["lang"] == "en"
    assert res.attributes["post_availability"] == "available"
    assert res.attributes["created"] == "2014-09-03T15:18:45.483Z"  # cond 5: P314 decoder
    assert "derived from id" in res.attributes["created_epoch"]
    assert res.attributes["presence"]["state"] == "found"
    (piv,) = res.pivots
    assert piv.entity.value == "interior" and piv.relation == "post_author" and piv.expand is False  # cond 5
    assert [f.title for f in res.findings] == ["X post available through oEmbed"]
    assert {c["url"].split("/")[2] for c in http.calls} == {"publish.twitter.com", "publish.x.com"}
    http.assert_hosts_within(XTwitterPublic)
    assert_no_bot_ua(http)


def test_404_is_no_longer_available_never_deleted():
    http = FakeHttp()
    add(http, oembed(GONE), "oembed_not_found.http.json")
    res = run_module(XTwitterPublic, f"url:{GONE}", http)
    assert res.status is Status.OK, res.error  # a meaningful answer, never ABSENT
    assert res.attributes["post_availability"] == "no longer available (deleted, protected or suspended)"
    finding = res.findings[0]
    assert finding.title == "X post no longer available" and finding.criterion
    assert "does not prove it was deleted" in finding.description and "doesn't exist" not in finding.description
    assert "presence" not in res.attributes and not res.pivots
    assert "created" not in res.attributes  # id 1 is a sequential pre-2010 id


def test_sequential_ids_are_not_decoded():
    http = FakeHttp()
    add(http, oembed(OLD), "oembed_sequential_id.http.json")
    res = run_module(XTwitterPublic, f"url:{OLD}", http)
    assert res.status is Status.OK
    assert res.attributes["x_post"]["text"] == "just setting up my twttr"
    assert "created" not in res.attributes
    assert res.raw["created_basis"].startswith("sequential id")


def test_could_not_verify_answers_are_never_empty():
    cases = {
        "oembed_rate_limited.http.json": (Status.RATE_LIMITED, "rate_limited"),
        "oembed_challenge.http.json": (Status.BLOCKED, "challenge"),
        "oembed_error_in_200.http.json": (Status.ERROR, "error"),
        "oembed_malformed.http.json": (Status.ERROR, "error"),
        "oembed_server_error.http.json": (Status.ERROR, "error"),
    }
    for name, (status, code) in cases.items():
        http = FakeHttp()
        add(http, oembed(POST), name)
        res = run_module(XTwitterPublic, f"url:{POST}", http)
        assert res.status is status and res.reason_code == code, (name, res.status, res.reason_code, res.error)
        assert "x_post" not in res.attributes and not res.findings


def test_login_redirect_is_a_login_wall_and_x_pages_are_never_requested():
    http = FakeHttp()
    add(http, oembed(POST), "oembed_login_redirect.http.json")
    res = run_module(XTwitterPublic, f"url:{POST}", http)
    assert res.status is Status.BLOCKED and res.reason_code == "login_wall"
    assert all(c["url"].startswith("https://publish.twitter.com/oembed") for c in http.calls)


def test_redirect_to_an_undeclared_host_is_could_not_verify():
    http = FakeHttp().add("GET", oembed(POST), status=301, headers={"location": "https://evil.example.net/oembed"})
    res = run_module(XTwitterPublic, f"url:{POST}", http)
    assert res.status is Status.ERROR and "could not verify" in res.error
    assert len(http.calls) == 1


def test_non_status_urls_are_not_applicable_and_send_nothing():
    http = FakeHttp()
    res = run_module(XTwitterPublic, "url:https://x.com/Interior", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert http.calls == []


def test_parse_oembed_rejects_answers_about_another_post():
    obj = {"url": "https://x.com/Interior/status/42", "html": '<blockquote class="twitter-tweet"><p>x</p></blockquote>'}
    assert X.parse_oembed(obj, "507185938620219395")["state"] == "error"
    assert X.parse_oembed({"errors": [{"code": 34}]})["state"] == "error"
    assert X.parse_oembed({"html": "<div>not an embed</div>"})["state"] == "error"
    assert X.parse_oembed(["not", "an", "object"])["state"] == "error"


def test_bot_user_agent_detector():
    assert X.bot_user_agent_reason("Mozilla/5.0 (compatible; DuckDuckBot-Https/1.1; https://duckduckgo.com/duckduckbot)")
    assert X.bot_user_agent_reason("Googlebot/2.1 (+http://www.google.com/bot.html)")
    assert X.bot_user_agent_reason("V3LUM/0.9") is None
