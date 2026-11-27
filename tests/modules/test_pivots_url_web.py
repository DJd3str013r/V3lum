"""pivots_url_web (P083): URL & website tools, manual links only. V3LUM never fetches these URLs.

Verification records: tests/fixtures/pivots_url_web/verified_templates.json; golden URLs: render_golden.json."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from tests.fakes import FakeHttp, make_ctx, module_fixture, run_module
from v3lum.core import links
from v3lum.core.context import ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.models import Status
from v3lum.modules.url_web.pivots_url_web import PivotsUrlWeb
from v3lum.modules.utility import pivot_gated_links as pg

GOLDEN = module_fixture("pivots_url_web", "render_golden.json")
REAL_HOSTILE_REASONS = pg.hostile_reasons  # captured before the autouse stub


def urls(res):
    return [u for _l, u in res.links]


@pytest.fixture(autouse=True)
def not_hostile(monkeypatch):
    monkeypatch.setattr(pg, "hostile_reasons", lambda ctx, entity: [])


# ------------------------------------------------------------------ cond 10-11: scan-trigger pages
def test_typed_domain_at_clear_gets_both_scan_trigger_pages_with_the_warning():
    http = FakeHttp()
    res = run_module(PivotsUrlWeb, "domain:example.com", http, tlp="clear")
    assert res.status is Status.OK and http.calls == [] and res.requests == 0
    assert urls(res) == ["https://www.scamadviser.com/check-website/example.com",
                         "https://securityheaders.com/?q=example.com&hide=on&followRedirects=on"]
    for label, _u in res.links:
        assert "WARNING: opening makes" in label and "contact the target live" in label
    assert all(item["touches_target"] and not item["clickable"] for item in res.raw["links"])
    assert "anti-bot/CAPTCHA" in res.links[1][0]


def test_url_values_get_the_securityheaders_page_with_hide_on():
    res = run_module(PivotsUrlWeb, "url:https://example.com/login?next=/a", tlp="green")
    assert len(res.links) == 1
    query = parse_qs(urlsplit(urls(res)[0]).query)
    assert query == {"q": ["https://example.com/login?next=/a"], "hide": ["on"], "followRedirects": ["on"]}


@pytest.mark.parametrize("tlp", ["amber", "amber+strict", "red"])
def test_scan_trigger_pages_are_hidden_at_amber_and_above(tlp):
    res = run_module(PivotsUrlWeb, "domain:example.com", tlp=tlp)
    assert res.status is Status.SKIPPED and res.reason_code == "tlp" and res.links == []


def test_discovered_values_never_get_scan_trigger_pages():
    res = run_module(PivotsUrlWeb, "domain:example.com", tlp="clear", is_seed=False, depth=1)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and res.links == []
    assert "values the analyst typed" in res.raw["hidden"][0]["reason"]


def test_unconfirmed_seeds_count_as_not_typed():
    options = ScanOptions(tlp="clear", unconfirmed_seeds={"domain:example.com"})
    res = run_module(PivotsUrlWeb, "domain:example.com", options=options, tlp="clear")
    assert res.links == [] and res.reason_code == "not_applicable"


def test_hostile_entities_never_get_scan_trigger_pages(monkeypatch):
    monkeypatch.setattr(pg, "hostile_reasons", lambda ctx, entity: ["case-DB sighting with verdict malicious"])
    res = run_module(PivotsUrlWeb, "domain:example.com", tlp="clear")
    assert res.status is Status.SKIPPED and res.reason_code == "policy" and res.links == []
    assert "hostile entity" in res.raw["hidden"][0]["reason"]


def test_hostile_check_runs_through_the_policy_guard_without_failing():
    ctx = make_ctx(PivotsUrlWeb, entity="domain:example.com", tlp="clear")
    assert REAL_HOSTILE_REASONS(ctx, Entity.make("domain", "example.com")) == []
    assert REAL_HOSTILE_REASONS(object(), Entity.make("domain", "example.com")) == []  # cannot run: advisory only


def test_real_guard_hides_scan_triggers_for_a_hostile_shaped_domain(monkeypatch):
    monkeypatch.setattr(pg, "hostile_reasons", REAL_HOSTILE_REASONS)
    res = run_module(PivotsUrlWeb, "domain:paypal-login-secure-verify.com", tlp="clear")
    assert res.status is Status.SKIPPED and res.reason_code == "policy" and res.links == []
    assert "lure-word" in res.raw["hidden"][0]["reason"]


@pytest.mark.parametrize("value", ["domain:printer.local", "domain:intranet.corp", "url:http://10.0.0.5/admin"])
def test_internal_values_never_go_to_a_third_party_scanner(value):
    res = run_module(PivotsUrlWeb, value, tlp="clear")
    assert res.links == [] and res.reason_code == "not_applicable"


# ------------------------------------------------------------------ cond 9: legal floor (rule 7)
def test_securityheaders_always_hide_on_and_no_mdn_observatory():
    for link in links.templates():
        assert link.host != "developer.mozilla.org"
    data = pg.pack_data("url_web")
    sh = next(i for i in data[pg.EXT_KEY] if i["id"] == "securityheaders")
    assert "hide=on" in urlsplit(sh["template"]).query.split("&")
    assert any(e["id"] == "mdn_observatory" for e in data["x_excluded"])
    bad = dict(sh, template="https://securityheaders.com/?q={q}&followRedirects=on")
    assert pg.parse_module_links("url_web", {"links": [], pg.EXT_KEY: [bad]})[0] == {}


# ------------------------------------------------------------------ cond 8, 12: core pack links
def test_domain_core_links_in_curated_order_and_served_urlscan_pages():
    out = [r for r in links.pivot_links_for(Entity.make("domain", "example.com")) if r.ref.startswith("url_web:")]
    assert [r.ref.split(":")[1] for r in out] == ["builtwith_profile", "builtwith_relationships", "netcraft_site_report",
                                                  "aa419", "w3techs", "webtechsurvey", "website_informer", "crawlgraph",
                                                  "ghostarchive"]
    by_id = {r.ref.split(":")[1]: r for r in out}
    assert by_id["aa419"].url == "https://db.aa419.org/fakebankslist.php?psearch=example.com"  # no 'Submit' token
    assert by_id["netcraft_site_report"].url == "https://sitereport.netcraft.com/?url=https%3A%2F%2Fexample.com"
    for ident in ("webtechsurvey", "crawlgraph", "ghostarchive"):
        assert links.BADGE_UNKNOWN_OPERATOR in by_id[ident].badge
    assert links.render("urlscan_search:domain", Entity.make("domain", "example.com")).url == "https://urlscan.io/domain/example.com"


def test_keywords_get_google_play_search_and_aa419_only():
    out = {r.ref: r.url for r in links.pivot_links_for(Entity.make("keyword", "banco do brasil")) if r.ref.startswith("url_web:")}
    assert out == {
        "url_web:aa419": "https://db.aa419.org/fakebankslist.php?psearch=banco%20do%20brasil",
        "url_web:google_play_search": "https://play.google.com/store/search?q=banco%20do%20brasil&c=apps&hl=pt_BR&gl=BR",
    }
    pending = {p["id"] for p in pg.pack_data("url_web")["x_pending"]}
    assert pending == {"google_play_details"}  # waits for an Android package entity type (cond 12)


def test_analytics_ids_get_the_builtwith_tag_relationships():
    out = {r.ref: r.url for r in links.pivot_links_for(Entity.make("analytics_id", "GTM-5F22G6"))}
    assert out["url_web:builtwith_tag"] == "https://builtwith.com/relationships/tag/GTM-5F22G6"


def test_golden_urls():
    for g in GOLDEN:
        entity = Entity.make(g["type"], g["value"])
        pack, ident = g["ref"].split(":")
        rendered = links.render(g["ref"], entity) if g["renderer"] == "core" else pg.render(pg.module_links(pack)[ident], entity)
        assert rendered is not None and rendered.url == g["url"], g
