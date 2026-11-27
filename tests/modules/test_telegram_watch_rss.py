"""telegram_watch_rss (P357 cond 8): the Dark Web Informer RSS companion feed, headline + link only.

Fixtures in tests/fixtures/telegram_watch_rss/: ``dwi_rss_ok.xml`` (the real feed, recorded 2026-11-26 by the
prep of batch p2-G09-2 and minimised to three items with titles, links, dates and guids), ``dwi_rss_malformed_
truncated.xml`` (the real research sample cut mid-item) and ``rss_doctype_entity_docshape.xml`` (a synthetic
DOCTYPE/ENTITY document the safe XML helper must refuse). The feed's registry terms are 'unknown' (A1) and its
operator tier 'unknown': the module stays off and the dataset is not registered until legal records them.
"""

from __future__ import annotations

from tests.fakes import FIXTURES, FakeHttp, run_module
from v3lum.core.datasets import DATASETS
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.darkweb_ransomware import telegram_channel_watch as tw
from v3lum.modules.darkweb_ransomware.telegram_channel_watch import TelegramWatchRss

FX = FIXTURES / "telegram_watch_rss"
ORG = OrgProfile.from_dict({"brands": [{"keyword": "Danfoss"}], "suppliers": [{"name": "Europol"}], "card_bins": ["411111"]})


def test_metadata_off_until_legal_records_the_terms():
    cls = TelegramWatchRss
    assert cls.terms == "unknown" and cls.default_enabled is False and cls.disclosure == "none" and cls.hosts == ()
    assert {"watch_only", "watch_source"} <= set(cls.tags) and cls.sources == ("darkwebinformer.rss",)
    assert tw.dwi_registration_allowed() is False and tw.DWI_DATASET not in DATASETS  # never downloaded meanwhile


def test_headlines_only_and_safe_xml():
    ok = tw.parse_rss_headlines((FX / "dwi_rss_ok.xml").read_bytes())
    assert ok["error"] is None and len(ok["items"]) == 3
    assert set(ok["items"][0]) == {"title", "link", "published", "guid"}  # no description, content or author
    assert ok["items"][0]["published"] == "2026-11-25T23:16:26Z"
    bad = tw.parse_rss_headlines((FX / "dwi_rss_malformed_truncated.xml").read_bytes())
    assert bad["items"] == [] and bad["error"].startswith("malformed RSS")
    evil = tw.parse_rss_headlines((FX / "rss_doctype_entity_docshape.xml").read_bytes())
    assert evil["items"] == [] and "refused" in evil["error"]


def test_headline_matching_never_uses_bin_rules():
    rules = tw.build_watch_rules(ORG)
    items = tw.parse_rss_headlines((FX / "dwi_rss_ok.xml").read_bytes())["items"] + [
        {"title": "BIN 411111 card dump", "link": "https://darkwebinformer.com/x/", "published": None}]
    hits = tw.match_headlines(items, rules)
    assert [h["title"] for h in hits] == ["CISA Warns of Critical Unpatched Danfoss RCE Flaw", "Europol Traces €26M in Crypto, Disrupts 57 IPTV Services"]
    assert all(h["source"] == "darkwebinformer.rss" for h in hits)


def test_run_is_skipped_while_terms_are_unknown():
    res = run_module(TelegramWatchRss, "keyword:danfoss", FakeHttp(), org_profile=ORG)
    assert res.status is Status.SKIPPED and res.reason_code == "licence"


def test_run_once_cleared_reads_the_local_feed(clean_registry):
    tw._register_dwi()  # as if legal had recorded the terms
    http = FakeHttp().add("GET", tw.DWI_URL, body=(FX / "dwi_rss_ok.xml").read_bytes(), headers={"content-type": "application/rss+xml"})
    res = run_module(TelegramWatchRss, "keyword:danfoss", http, org_profile=ORG)
    assert res.status is Status.OK and len(res.attributes["news_watch_hits"]) == 2
    again = run_module(TelegramWatchRss, "keyword:danfoss", http, org_profile=ORG)
    assert again.status is Status.EMPTY  # first_seen: the same headline is never reported twice
