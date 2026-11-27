"""x_twitter_recovery (P119 cond 4/5): opt-in deleted-post recovery through the shared Wayback CDX helpers.

Fixtures in tests/fixtures/x_twitter_recovery/ (batch p3-G05-3 prep, 2026-11-26): ``cdx_ok`` is SYNTHETIC
(CDX output=json rows shaped after the IA CDX documentation; its status ids match the REAL oEmbed captures
of tests/fixtures/x_twitter_public/: 507185938620219395 available, 1 unavailable), ``cdx_empty`` and
``cdx_html`` are SYNTHETIC, ``cdx_connection_reset.json`` records the REAL transport outcome from the
datacenter egress (web.archive.org reset the connection: could not verify, never 'no archived posts').
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.http import NetworkError
from v3lum.core.models import Status
from v3lum.modules.username_social import x_twitter_public as X
from v3lum.modules.username_social.x_twitter_public import XTwitterRecovery

HANDLE = "Interior"
POST = "https://twitter.com/Interior/status/507185938620219395"
GONE = "https://twitter.com/Interior/status/1"
OPTS = ScanOptions(purpose="case 2026-0042: subject's deleted posts", include={"x_twitter_recovery"})


def fx(name: str, module: str = "x_twitter_recovery") -> dict[str, Any]:
    return module_fixture(module, name)


def add(http: FakeHttp, url: str, name: str, module: str = "x_twitter_recovery") -> FakeHttp:
    env = fx(name, module)
    return http.add("GET", url, status=int(env["status"]), body=(env.get("body") or "").encode("utf-8"), headers=env.get("headers") or {})


def cdx(host: str, limit: int = 500) -> str:
    return f"{X.CDX}?{urlencode(X.cdx_params(HANDLE.lower(), host, limit))}"


def oembed(status_url: str, host: str = "publish.twitter.com") -> str:
    url = X.oembed_request_url(status_url, host=host)
    assert url is not None
    return url


def run(http: FakeHttp, value: str = HANDLE, **kw: Any):
    return run_module(XTwitterRecovery, f"username:{value}", http, options=OPTS, **kw)


def full_http() -> FakeHttp:
    http = FakeHttp()
    add(http, cdx("twitter.com"), "cdx_ok.http.json")
    add(http, cdx("x.com"), "cdx_empty.http.json")
    add(http, oembed(POST), "oembed_redirect.http.json", "x_twitter_public")
    add(http, oembed(POST, "publish.x.com"), "oembed_ok.http.json", "x_twitter_public")
    add(http, oembed(GONE, "publish.x.com"), "oembed_not_found.http.json", "x_twitter_public")
    return http


def test_metadata_is_opt_in_and_seed_only():
    assert XTwitterRecovery.default_enabled is False and XTwitterRecovery.run_on == "seeds"  # cond 4/5
    assert XTwitterRecovery.terms == "unknown" and XTwitterRecovery.trust_tier == "trusted"  # cond 6
    assert set(XTwitterRecovery.sources) == {"internet_archive.wayback_social", "x_corp.oembed"}
    assert set(XTwitterRecovery.hosts) == {"web.archive.org", "publish.twitter.com", "publish.x.com"}
    params = X.cdx_params("interior", "twitter.com", 9999)
    assert params["collapse"] == "urlkey" and params["limit"] == "500" and params["url"] == "twitter.com/interior/status/*"


def test_recovery_lists_archived_copies_of_posts_no_longer_available():
    http = full_http()
    res = run(http)
    assert res.status is Status.OK, res.error
    rec = res.attributes["x_recovery"]
    assert rec["archived_statuses"] == 2 and rec["checked"] == 2 and rec["still_available"] == 1 and rec["unverified"] == 0
    (gone,) = rec["recovered"]
    assert gone["status_id"] == "1" and gone["label"] == "archived copy"
    assert gone["availability"] == "no longer available (deleted, protected or suspended)"
    assert gone["archived_copy_url"] == "https://web.archive.org/web/20100105000000id_/https://twitter.com/Interior/status/1"
    assert gone["created"] is None and gone["created_basis"].startswith("sequential id")  # cond 5: never a guessed date
    (piv,) = res.pivots
    assert piv.relation == "archived_copy" and piv.expand is False and piv.entity.value.startswith("https://web.archive.org/web/")
    assert res.findings[0].title == "Archived copies of X posts no longer available"
    assert "archived_copy" in res.findings[0].tags
    hosts = {c["url"].split("/")[2] for c in http.calls}
    assert hosts == {"web.archive.org", "publish.twitter.com", "publish.x.com"}  # archive hosts + oEmbed only
    assert not any("twitter.com/Interior" in c["url"].split("?")[0] for c in http.calls)  # X pages never requested
    # after the first permanent redirect the second check goes straight to publish.x.com (one hop saved)
    assert sum(1 for c in http.calls if c["url"].startswith("https://publish.twitter.com/")) == 1
    http.assert_hosts_within(XTwitterRecovery)
    for call in http.calls:  # cond 4: no crawler or search-engine UA, anywhere
        ua = {k.lower(): v for k, v in (call.get("headers") or {}).items()}.get("user-agent", "")
        assert X.bot_user_agent_reason(ua) is None, ua


def test_cdx_rows_are_normalised_and_deduplicated():
    from v3lum.modules.url_web.web_archives import parse_wayback_cdx

    parsed = parse_wayback_cdx(fx("cdx_ok.http.json")["body"])
    found = X.x_status_rows(parsed["rows"], "interior")
    ids = [s["status_id"] for s in found["statuses"]]
    assert ids == ["507185938620219395", "1"] and found["skipped"] == 1  # 'notanid' row skipped
    post = found["statuses"][0]
    assert post["captures"] == 3  # plain, /photo/1 and ?lang=pt collapse to one status
    assert post["archived_copy_url"].endswith("id_/https://twitter.com/Interior/status/507185938620219395")
    assert post["first_capture"] == "2014-09-03T16:01:02Z" and post["last_capture"] == "2015-01-01T00:00:00Z"


def test_unreachable_archive_is_could_not_verify_never_empty():
    reset = NetworkError("ConnectionResetError: [Errno 104] Connection reset by peer", kind="ConnectionResetError")
    assert fx("cdx_connection_reset.json")["status"] is None  # the recorded real outcome: no HTTP answer
    http = FakeHttp().add("GET", cdx("twitter.com"), error=reset).add("GET", cdx("x.com"), error=reset)
    res = run(http)
    assert res.status is Status.ERROR and "could not verify" in res.error and "never 'no archived posts'" in res.error
    assert "x_recovery" not in res.attributes


def test_cdx_rate_limit_and_html_answers():
    http = FakeHttp().add("GET", cdx("twitter.com"), status=429, text="slow down").add("GET", cdx("x.com"), status=429, text="slow down")
    assert run(http).status is Status.RATE_LIMITED
    http = FakeHttp()
    add(http, cdx("twitter.com"), "cdx_html.http.json")
    add(http, cdx("x.com"), "cdx_html.http.json")
    res = run(http)
    assert res.status is Status.ERROR and "could not verify" in res.error


def test_one_query_failing_is_never_reported_as_no_archived_posts():
    http = FakeHttp()
    add(http, cdx("twitter.com"), "cdx_empty.http.json")
    http.add("GET", cdx("x.com"), error=NetworkError("connection reset", kind="ConnectionResetError"))
    res = run(http)
    assert res.status is Status.ERROR and "could not verify" in res.error


def test_both_empty_is_an_empty_answer_with_its_limits():
    http = FakeHttp()
    add(http, cdx("twitter.com"), "cdx_empty.http.json")
    add(http, cdx("x.com"), "cdx_empty.http.json")
    res = run(http)
    assert res.status is Status.EMPTY and "not proof" in res.error


def test_oembed_rate_limit_stops_the_checks_and_keeps_them_unverified():
    http = FakeHttp()
    add(http, cdx("twitter.com"), "cdx_ok.http.json")
    add(http, cdx("x.com"), "cdx_empty.http.json")
    add(http, oembed(POST), "oembed_rate_limited.http.json", "x_twitter_public")
    res = run(http)
    rec = res.attributes["x_recovery"]
    assert rec["recovered"] == [] and rec["unverified"] == 2 and rec["partial"] is True
    assert res.partial and res.stop_reason == "rate_limited"
    assert res.source_statuses["x_corp.oembed"]["status"] in ("rate_limited", Status.RATE_LIMITED)
    assert not res.pivots and "could not verify" in res.error


def test_max_checks_setting_leaves_the_rest_unverified():
    http = FakeHttp()
    add(http, cdx("twitter.com"), "cdx_ok.http.json")
    add(http, cdx("x.com"), "cdx_empty.http.json")
    add(http, oembed(POST), "oembed_redirect.http.json", "x_twitter_public")
    add(http, oembed(POST, "publish.x.com"), "oembed_ok.http.json", "x_twitter_public")
    res = run(http, settings={"x_twitter_recovery_max_checks": 1})
    rec = res.attributes["x_recovery"]
    assert rec["checked"] == 1 and rec["still_available"] == 1 and rec["unverified"] == 1
    assert res.partial and res.stop_reason == "request_cap"


def test_invalid_handles_send_nothing():
    http = FakeHttp()
    res = run(http, "not.an.x.handle")
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []


def test_only_allowed_sources_are_queried():
    http = FakeHttp()
    add(http, cdx("twitter.com"), "cdx_ok.http.json")
    add(http, cdx("x.com"), "cdx_empty.http.json")
    res = run(http, allowed_sources=["internet_archive.wayback_social"])  # the licence gate kept X oEmbed out
    assert res.status is Status.OK
    assert {c["url"].split("/")[2] for c in http.calls} == {"web.archive.org"}
    assert res.attributes["x_recovery"]["unverified"] == 2 and res.attributes["x_recovery"]["recovered"] == []
    assert res.source_statuses["x_corp.oembed"]["reason_code"] == "licence"
    http = FakeHttp()
    res = run(http, allowed_sources=[])
    assert res.status is Status.SKIPPED and res.reason_code == "licence" and http.calls == []
