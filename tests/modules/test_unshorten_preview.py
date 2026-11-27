"""unshorten_preview (P070, PASSIVE, default): no-click preview pages as manual links, offline.

The module makes no request (disclosure 'none'): Bitly's terms forbid automated access and TinyURL's
terms are unrecorded, so the preview pages are manual links (A1, A9). The preview parsers are tested on
the synthetic pages in tests/fixtures/unshorten_preview/ (batch p9-G03-1 prep: TinyURL preview with
and without the redirecturl anchor, a Bitly '+' info page, a Bitly login wall) for when the terms are
recorded. Also covers the bundled shortener list (P070 c7: MISP url-shortener, CC0, plus V3LUM BR
additions and IP loggers).
"""

from __future__ import annotations

from tests.fakes import FIXTURES, FakeHttp, run_module
from v3lum.core.models import Opsec, Status
from v3lum.core.module import get_module
from v3lum.modules.url_web import unshorten as U
from v3lum.modules.url_web.unshorten import UnshortenPreview

FX = FIXTURES / "unshorten_preview"
SPEC_NAMED = ("encurtador.com.br", "cutt.ly", "rb.gy", "is.gd", "shorturl.at", "t.co", "bit.ly", "tinyurl.com")


def page(name: str) -> str:
    return (FX / name).read_text()


def test_bitly_link_gets_its_info_page_as_a_manual_link_without_any_request():
    http = FakeHttp()
    res = run_module(UnshortenPreview, "url:https://bit.ly/3Example", http)
    assert res.status is Status.OK, res.error
    assert http.calls == []
    assert ("Bitly preview page (no click-through to the destination)", "https://bit.ly/3Example+") in res.links
    link = res.attributes["short_link"]
    assert link["provider"] == "Bitly" and link["preview_automation"] == "manual_only" and link["never_contact"] is False
    assert res.pivots == []


def test_tinyurl_preview_is_pending_terms_review():
    res = run_module(UnshortenPreview, "url:https://tinyurl.com/example1", FakeHttp())
    assert res.attributes["short_link"]["preview_url"] == "https://preview.tinyurl.com/example1"
    assert res.attributes["short_link"]["preview_automation"] == "pending_terms_review"


def test_shortener_without_preview_is_left_to_the_tracer():
    res = run_module(UnshortenPreview, "url:https://cutt.ly/example2", FakeHttp())
    assert res.status is Status.OK
    assert res.attributes["short_link"]["preview_url"] is None and "unshorten_trace" in res.attributes["short_link"]["note"]
    assert res.links == []


def test_ip_logger_is_flagged():
    res = run_module(UnshortenPreview, "url:https://grabify.link/ABC123", FakeHttp())
    assert res.attributes["short_link"]["never_contact"] is True and res.attributes["short_link"]["category"] == "ip_logger"


def test_not_a_short_link_does_not_apply():
    res = run_module(UnshortenPreview, "url:https://www.example.com/landing", FakeHttp())
    assert res.status is Status.SKIPPED


def test_tinyurl_preview_parser():
    ok = U.parse_tinyurl_preview(200, {"content-type": "text/html"}, page("tinyurl_ok_synthetic.html"))
    assert ok == {"status": "ok", "reason": None, "destination": "https://www.example.com/promo?utm_source=sms"}
    noid = U.parse_tinyurl_preview(200, {}, page("tinyurl_noid_synthetic.html"))
    assert noid["destination"] == "https://www.example.org/form"  # TinyURL's own links are skipped
    assert U.parse_tinyurl_preview(404, {}, "<html></html>")["status"] == "empty"
    assert U.parse_tinyurl_preview(500, {}, "oops")["status"] == "error"
    challenge = U.parse_tinyurl_preview(403, {"cf-mitigated": "challenge"}, "<html><head><title>Just a moment...</title></head></html>")
    assert challenge["status"] == "blocked"


def test_bitly_info_parser_and_login_wall():
    ok = U.parse_bitly_info(200, {}, page("bitly_info_synthetic.html"))
    assert ok["status"] == "ok" and ok["destination"] == "https://www.example.com/landing?x=1"
    wall = U.parse_bitly_info(200, {}, page("login_wall_synthetic.html"))
    assert wall["status"] == "blocked" and wall["destination"] is None


def test_preview_plan():
    assert U.preview_plan("https://j.mp/abc")["url"] == "https://bit.ly/abc+"
    assert U.preview_plan("tinyurl.com/abc")["url"] == "https://preview.tinyurl.com/abc"
    assert U.preview_plan("https://bit.ly/") is None and U.preview_plan("https://bit.ly/a/b") is None
    assert U.preview_plan("https://is.gd/abc") is None


def test_bundled_shortener_list_covers_the_spec_and_flags_ip_loggers():
    table = U.load_shorteners()
    assert all(host in table for host in SPEC_NAMED)
    assert all(table[h].get("never_contact") for h in ("grabify.link", "iplogger.org", "iplogger.com", "2no.co", "yip.su"))
    assert U.shortener_info("https://www.bit.ly/x")["host"] == "bit.ly"
    assert U.shortener_info("https://www.example.com/") is None
    assert U.shortener_info("not a url") is None
    assert len(table) > 250


def test_contract_metadata():
    assert UnshortenPreview.disclosure == "none" and UnshortenPreview.hosts == () and UnshortenPreview.default_enabled is True
    assert UnshortenPreview.opsec is Opsec.PASSIVE and UnshortenPreview.terms == "open"
    assert get_module("unshorten_preview") is UnshortenPreview


def test_acceptance_golden_url_needs_no_route():
    """AR21 golden path: unshorten_preview is offline and example.com is no short link: nothing sent."""
    from tests.fakes import fixture

    assert fixture("acceptance/url/unshorten_preview.json") == {"schema": "v3lum.acceptance_routes/1", "module": "unshorten_preview",
                                                               "routes": []}
    http = FakeHttp()
    run_module(UnshortenPreview, "url:https://example.com/", http)
    assert http.calls == []
