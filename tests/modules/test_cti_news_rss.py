"""cti_news_rss (P298): curated CTI feeds, local item store, offline headline matching.

Fixtures in tests/fixtures/cti_news_rss/ (prep batch p2-G11-1, captured 2026-11-26 and trimmed to 2-3
items): the real feeds of The Record, BleepingComputer, DFIR Report (Atom), Krebs, Help Net Security,
CyberScoop, Schneier (Atom), DarkFeed (stale since 2026-07-22), Dark Web Informer, ICHI (complete feed
re-fetched), DataBreaches.net and CERT.br (institutional address replaced by cert@example.com); the
truncated ICHI research sample (``ichi_truncated_malformed.xml``), the real Dark Reading Cloudflare
challenge, the CERT.br 304 and the CTIR Gov maintenance page (``*.http.json``), The Hack (stale since
2022), and two synthetic files: ``matching_pt_synthetic.xml`` (FC6/FC7 cases, documentation links) and
``doctype_entity_rejected.xml`` (safe-XML refusal).
"""

from __future__ import annotations

import subprocess
from datetime import timedelta

import pytest

from tests.fakes import FIXTURES, FakeClock, FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core import providers
from v3lum.core.datasets import DATASETS
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Severity, Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.cti_framework import cti_news_rss as mod
from v3lum.modules.cti_framework.cti_news_rss import (
    FEED_LIST,
    FEEDS,
    CtiNewsRss,
    claim_dedupe_key,
    feed_health,
    match_item,
    merge_items,
    parse_feed,
    validate_feed_list,
    watch_terms,
)

FX = FIXTURES / "cti_news_rss"
ALL_FEED_HOSTS = sorted({h for f in FEEDS.values() for h in f["hosts"]})
ORG = {"org": {"name": "Exemplo Telecom S.A."}, "domains": [{"name": "claro.com.br"}],
       "brands": [{"keyword": "Claro", "variants": ["Claro Brasil"]}],
       "suppliers": [{"name": "Exemplo Logistica", "domains": ["logistica.example.com"]}]}


def xml(name: str) -> bytes:
    return (FX / name).read_bytes()


def feeds_http(**bodies: bytes) -> FakeHttp:
    http = FakeHttp()
    for fid, body in bodies.items():
        http.add("GET", FEEDS[fid]["url"], body=body, headers={"Content-Type": "application/rss+xml", "ETag": f'"{fid}-1"'})
    return http


def run(entity: str, http: FakeHttp, feeds: list[str], **kw):
    settings = {"cti_news_rss_feeds": feeds, **kw.pop("settings", {})}
    return run_module(CtiNewsRss, entity, http, settings=settings, **kw)


# ------------------------------------------------------------------ FC1-FC3: curated list, licence floor
def test_curated_feed_list_is_valid_and_complete():
    assert validate_feed_list(FEED_LIST) == [] and mod.FEED_LIST_PROBLEMS == []
    assert set(FEEDS) == {"therecord", "bleepingcomputer", "dfirreport", "krebs", "helpnetsecurity", "darkreading", "cyberscoop",
                          "schneier", "darkfeed", "darkwebinformer", "ichi", "databreaches", "certbr"}
    assert all(f["enabled"] is False and f["terms"]["class"] == "unknown" and f["terms"]["legal_decision"] is None for f in FEEDS.values())
    assert {p["id"] for p in FEED_LIST["pending"]} == {"ctir_gov", "cais_rnp"}  # FC2
    assert {e["id"] for e in FEED_LIST["excluded"]} == {"thehack", "cisoadvisor"}
    reg = providers.registry()
    for feed in FEEDS.values():
        pid, sid = feed["source"].split(".")
        prov = reg.get(pid)
        assert prov is not None and sid in prov.sources and prov.sources[sid].terms.class_ == "unknown"
        assert all(reg.provider_for_host(h).id == pid for h in feed["hosts"])  # a registry entry for every host
        assert prov.tier == feed["tier"]  # FC9: CERT.br and The Record trusted, anonymous feeds unknown
        reg_ds = DATASETS[mod.dataset_name(feed["id"])]
        assert reg_ds["ttl"] == 3600 and reg_ds["max_bytes"] <= 2 * 1024 * 1024 and reg_ds["source"] == feed["source"]
    assert FEEDS["therecord"]["tier"] == FEEDS["certbr"]["tier"] == "trusted"
    assert FEEDS["darkwebinformer"]["label"] == "unverified source"


def test_validator_catches_broken_entries():
    bad = {"schema": "v3lum.cti_feeds/1", "feeds": [dict(FEEDS["therecord"], enabled=True, max_items=500, url="http://therecord.media/feed")]}
    problems = "\n".join(validate_feed_list(bad))
    assert "enabled=false" in problems and "max_items" in problems and "https" in problems


def test_metadata_matches_the_council_decision():
    cls = CtiNewsRss
    assert cls.terms == "unknown" and cls.default_enabled is False  # FC3
    assert cls.disclosure == "none" and cls.hosts == () and cls.trust_tier == "n/a"  # FC6/FC9
    assert cls.max_tlp.value_str == "red" and cls.max_requests == 0


def test_no_enabled_feed_is_skipped_licence():
    http = FakeHttp()
    res = run_module(CtiNewsRss, "company_name:Exemplo", http)
    assert res.status is Status.SKIPPED and res.reason_code == "licence"
    assert http.calls == []


# ------------------------------------------------------------------ FC4/FC5: fetching and parsing
def test_one_fetch_per_feed_whatever_the_number_of_entities():
    http = feeds_http(therecord=xml("therecord_ok.xml"), databreaches=xml("databreaches_ok.xml"))
    rt = make_runtime(http, clock=FakeClock(), settings={"cti_news_rss_feeds": ["therecord", "databreaches"]})
    first = run_module(CtiNewsRss, "keyword:Guadeloupe", runtime=rt)
    second = run_module(CtiNewsRss, "threat_actor:ShinyHunters", runtime=rt)
    third = run_module(CtiNewsRss, "company_name:Gleneagles Hospital", runtime=rt)
    assert first.status is Status.OK and second.status is Status.OK and third.status is Status.OK
    assert len(http.calls) == 2  # each feed once; matching is local
    assert first.requests == 0  # nothing counted against the module: datasets only
    http.assert_hosts_within(CtiNewsRss, extra=ALL_FEED_HOSTS)


def test_conditional_get_after_an_hour_keeps_the_copy():
    clock = FakeClock()
    cap = module_fixture(CtiNewsRss, "certbr_not_modified.http.json")
    http = feeds_http(certbr=xml("certbr_ok.xml"))
    http.add("GET", FEEDS["certbr"]["url"], status=cap["status"], headers=cap["headers"], match_headers={"If-None-Match": '"certbr-1"'})
    rt = make_runtime(http, clock=clock, settings={"cti_news_rss_feeds": ["certbr"]})
    assert run_module(CtiNewsRss, "keyword:Processo Seletivo", runtime=rt).status is Status.OK
    clock.advance(2 * 3600)
    res = run_module(CtiNewsRss, "keyword:Processo Seletivo", runtime=rt)
    assert res.status is Status.OK and len(http.calls) == 2  # one conditional GET answered 304
    assert http.calls[1]["headers"].get("If-None-Match") == '"certbr-1"'


def test_headlines_only_no_article_content_kept():
    parsed = parse_feed(xml("krebs_ok.xml"), "krebs")
    assert parsed["status"] == "ok" and set(parsed["items"][0]) == {"feed_id", "title", "link", "published", "guid", "cves"}
    ichi = parse_feed(xml("ichi_ok.xml"), "ichi")
    assert "CVE-2026-103406" in ichi["items"][0]["cves"]  # CVE ids read from the description as facts


@pytest.mark.parametrize("name", ["dfirreport_atom_ok.xml", "schneier_atom_ok.xml", "therecord_ok.xml", "darkwebinformer_ok.xml",
                                  "bleepingcomputer_ok.xml", "helpnetsecurity_ok.xml", "cyberscoop_ok.xml", "databreaches_ok.xml"])
def test_every_real_feed_parses(name):
    parsed = parse_feed(xml(name), "x")
    assert parsed["status"] == "ok" and parsed["items"] and all(i["link"].startswith("https://") for i in parsed["items"])


def test_safe_xml_refuses_doctype_and_malformed_and_html():
    assert "unsafe XML" in parse_feed(xml("doctype_entity_rejected.xml"), "x")["reason"]
    assert "malformed XML" in parse_feed(xml("ichi_truncated_malformed.xml"), "x")["reason"]
    page = module_fixture(CtiNewsRss, "ctir_maintenance_200.http.json")["body"]
    assert "HTML page" in parse_feed(page, "x")["reason"]
    assert "cap" in parse_feed(b"<rss>" + b" " * (2 * 1024 * 1024 + 1), "x")["reason"]


def test_item_cap_is_200():
    items = "".join(f"<item><title>t{i}</title><link>https://example.com/{i}</link></item>" for i in range(250))
    parsed = parse_feed(f"<rss><channel><title>x</title>{items}</channel></rss>", "x")
    assert len(parsed["items"]) == 200 and parsed["truncated"] is True


def test_malformed_feed_never_reads_as_no_mention():
    http = feeds_http(ichi=xml("ichi_truncated_malformed.xml"))
    res = run("cve:CVE-2026-103406", http, ["ichi"])
    assert res.status is Status.ERROR
    assert "ichi.alerts" in res.source_statuses


def test_challenge_is_blocked_never_bypassed():
    cap = module_fixture(CtiNewsRss, "darkreading_challenge.http.json")
    http = FakeHttp().add("GET", FEEDS["bleepingcomputer"]["url"], status=cap["status"], text=cap["body"], headers=cap["headers"])
    res = run("company_name:Exemplo", http, ["bleepingcomputer"])
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"
    assert len(http.calls) == 1  # never retried with other headers


def test_feed_marked_blocked_in_the_list_is_never_fetched():
    http = feeds_http(therecord=xml("therecord_ok.xml"))
    res = run("keyword:Guadeloupe", http, ["darkreading", "therecord"])
    assert res.status is Status.OK
    assert "www.darkreading.com" not in http.hosts()
    assert res.attributes["cti_feed_health"]["darkreading"]["state"] == "blocked"
    assert "darkreading.rss" in res.source_statuses


def test_maintenance_page_is_error_health():
    page = module_fixture(CtiNewsRss, "ctir_maintenance_200.http.json")
    http = FakeHttp().add("GET", FEEDS["certbr"]["url"], status=200, text=page["body"], headers=page["headers"])
    http.add("GET", FEEDS["therecord"]["url"], body=xml("therecord_ok.xml"))
    res = run("keyword:Guadeloupe", http, ["certbr", "therecord"])
    assert res.status is Status.OK and res.attributes["cti_feed_health"]["certbr"]["state"] == "error"


def test_rate_limit_and_5xx_are_could_not_verify():
    http = FakeHttp().add("GET", FEEDS["therecord"]["url"], status=429, text="slow down", times=3)
    assert run("keyword:Guadeloupe", http, ["therecord"]).status in (Status.ERROR, Status.RATE_LIMITED, Status.BLOCKED)
    http2 = FakeHttp().add("GET", FEEDS["therecord"]["url"], status=503, text="down", times=3)
    res = run("keyword:Guadeloupe", http2, ["therecord"])
    assert res.status is Status.ERROR and res.status is not Status.EMPTY


def test_stale_feed_health():
    http = feeds_http(darkfeed=xml("darkfeed_ok_stale.xml"))
    res = run("threat_actor:Everest", http, ["darkfeed"])
    health = res.attributes["cti_feed_health"]["darkfeed"]
    assert health["state"] == "stale" and health["age_days"] > 90 and health["label"] == "unverified source"
    thehack = parse_feed(xml("thehack_stale.xml"), "thehack")
    assert feed_health(thehack, FakeClock().now())["state"] == "stale"  # item dates win over lastBuildDate


# ------------------------------------------------------------------ FC6/FC7: matching
MATCHING = parse_feed(xml("matching_pt_synthetic.xml"), "synthetic")["items"]


def hits(entity: str, org: dict | None = None) -> set[str]:
    etype, value = entity.split(":", 1)
    terms = watch_terms(Entity.make(T(etype), value), OrgProfile.from_dict(org) if org else None)
    return {i["link"].rsplit("/", 1)[-1] for i in MATCHING if match_item(i, terms)}


def test_common_word_brand_needs_context():
    found = hits("company_name:Claro", ORG)
    assert "a1" not in found and "a2" not in found  # 'ficou claro', bare 'Claro:'
    assert {"a3", "a4", "a5", "a6"} <= found  # operadora, S.A., own domain, second token 'Claro Brasil'
    assert hits("company_name:Inter") == {"a7"}  # 'Banco Inter', never 'Inter de Milao'
    assert hits("company_name:Natura") == {"a14"}  # '&Co S.A.' context; bare 'NATURA' is not enough


def test_common_word_actor_needs_threat_context():
    assert hits("threat_actor:Play") == {"a16"}  # never 'Google Play'
    assert hits("threat_actor:LockBit") == {"a12"}


def test_cve_ids_match_exactly():
    assert hits("cve:CVE-2021-44228") == {"a10"}  # never CVE-2021-442281


def test_feed_context_covers_bare_group_names():
    darkfeed = parse_feed(xml("darkfeed_ok_stale.xml"), "darkfeed")["items"]
    terms = watch_terms(Entity.make(T.THREAT_ACTOR, "Everest"))
    assert not match_item(darkfeed[0], terms)
    assert match_item(darkfeed[0], terms, ["ransomware"])["why"] == "feed_context:ransomware"


def test_accents_are_folded():
    terms = watch_terms(Entity.make(T.KEYWORD, "manutencao"))
    assert match_item({"title": "Janela de manutenção programada", "link": "https://example.com/m"}, terms)


# ------------------------------------------------------------------ FC8: severities
def test_own_org_in_breach_news_is_a_medium_reported_claim():
    http = feeds_http(databreaches=xml("matching_pt_synthetic.xml"))
    res = run("company_name:Claro", http, ["databreaches"], org_profile=OrgProfile.from_dict(ORG))
    assert res.status is Status.OK
    sev = {f.severity for f in res.findings}
    assert sev == {Severity.MEDIUM}
    claim = res.findings[0]
    assert "reported claim" in claim.title.lower() and "confirmed" not in claim.title.lower()
    assert "reported_claim" in claim.tags and "unverified_source" in claim.tags
    assert claim.data["claim_key"] == claim_dedupe_key("Claro") == "claro" and claim.data["raises_risk"] is False
    assert claim.criterion


def test_own_org_in_regular_news_is_low():
    http = feeds_http(therecord=xml("matching_pt_synthetic.xml"))
    res = run("company_name:Claro", http, ["therecord"], org_profile=OrgProfile.from_dict(ORG))
    assert {f.severity for f in res.findings} == {Severity.LOW}
    assert all("context_only" in f.tags for f in res.findings)


def test_other_mentions_are_info_context():
    http2 = feeds_http(therecord=xml("therecord_ok.xml"))
    other = run("keyword:Guadeloupe", http2, ["therecord"])
    assert [f.severity for f in other.findings] == [Severity.INFO]
    assert other.links and other.links[0][1] == "https://therecord.media/guadeloupe-ransomware-hospital-cyber"
    assert all(not p.expand and p.relation == "mentioned_in_news" for p in other.pivots)


def test_terminal_shows_five_most_recent_headlines():
    http = feeds_http(therecord=xml("matching_pt_synthetic.xml"))
    res = run("keyword:claro", http, ["therecord"], org_profile=OrgProfile.from_dict(ORG))
    dates = [r["published"] for r in res.attributes["cti_news_mentions"]]
    assert dates == sorted(dates, reverse=True) and len(res.links) <= 5


def test_no_mention_is_empty():
    http = feeds_http(therecord=xml("therecord_ok.xml"))
    res = run("company_name:Exemplo Inexistente", http, ["therecord"])
    assert res.status is Status.EMPTY and "headline-only" in res.error


# ------------------------------------------------------------------ FC5: item store and retention
def test_item_store_keeps_items_across_feed_rotations():
    clock = FakeClock()
    http = feeds_http(therecord=xml("therecord_ok.xml"))
    http.add("GET", FEEDS["therecord"]["url"], body=xml("matching_pt_synthetic.xml"))
    rt = make_runtime(http, clock=clock, settings={"cti_news_rss_feeds": ["therecord"]})
    assert run_module(CtiNewsRss, "keyword:Guadeloupe", runtime=rt).status is Status.OK
    clock.advance(2 * 3600)
    res = run_module(CtiNewsRss, "keyword:Guadeloupe", runtime=rt)  # the item left the feed, kept in the store
    assert res.status is Status.OK and res.attributes["cti_news_mentions"][0]["feed"] == "therecord"


def test_retention_is_180_days():
    now = FakeClock().now()
    old = {"title": "old", "link": "https://example.com/old", "published": (now - timedelta(days=181)).strftime("%Y-%m-%dT%H:%M:%SZ")}
    new = {"title": "new", "link": "https://example.com/new", "published": None}
    merged = merge_items([old], [new], now)
    assert [m["title"] for m in merged] == ["new"] and merged[0]["first_seen"]
    assert merge_items([], [{"title": "mail x@example.com", "link": "https://example.com/e", "published": None}], now) == []


def test_module_never_spawns_a_process(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("no process may be spawned")
    monkeypatch.setattr(subprocess, "Popen", boom)
    http = feeds_http(therecord=xml("therecord_ok.xml"))
    assert run("keyword:Guadeloupe", http, ["therecord"]).status is Status.OK


def test_doctor_health_reports_every_feed():
    http = feeds_http(therecord=xml("therecord_ok.xml"), darkfeed=xml("darkfeed_ok_stale.xml"))
    rt = make_runtime(http, clock=FakeClock(), settings={"cti_news_rss_feeds": ["therecord", "darkfeed"]})
    run_module(CtiNewsRss, "keyword:Guadeloupe", runtime=rt)
    check = CtiNewsRss.health_check()
    assert check.offline is True
    from tests.fakes import make_ctx
    ctx = make_ctx(CtiNewsRss, runtime=rt)
    rows = mod.doctor_health(ctx)
    assert rows["therecord"]["state"] == "ok" and rows["darkfeed"]["state"] == "stale"
    assert rows["darkreading"]["state"] == "blocked" and rows["krebs"]["state"] == "missing"
    assert check.selftest(ctx).status == "ok"
