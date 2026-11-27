"""ransomfeed (P356): ransomfeed.it claims - hourly RSS matched offline, API for typed/org names only.

Fixtures in tests/fixtures/ransomfeed/ (prep batch p1-G09-1, cut from the live answers of 2026-11-26 in
the gap-sample format; victims replaced with documentation values): ``rss_ok.xml`` (the real channel
header and item template - CDATA HTML description with the matomo image, dc namespace, CET pubDate -
with 4 documentation items, one with UTF-8 accents; served as text/xml;charset=iso-8859-1 although the
bytes are UTF-8), ``search_ok.json`` (/search, real 14-key schema), ``search_empty.json`` (verbatim
``[]``), ``search_placeholder_website.json`` (killsec rows whose website is the placeholder
example.com), ``ganginfo_ok.json`` (/ganginfo/lockbit3 actor card) and ``gang_ok.json`` (/gang rows).
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import FIXTURES, FakeHttp, module_fixture, run_module
from v3lum.core.datasets import DATASETS
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.darkweb_ransomware import ransomfeed as rf
from v3lum.modules.darkweb_ransomware.ransomfeed import GANGINFO_URL, RSS_URL, Ransomfeed

API = "https://api.ransomfeed.it"
LOCKBIT_CARD_ONION = "lockbitapt2d73krlbewgv27tquljgxr33xbwwsp6rkyieto7u4ncead.onion"


def raw(name: str) -> bytes:
    return (FIXTURES / "ransomfeed" / name).read_bytes()


def rss_http(http: FakeHttp | None = None, body: bytes | None = None, **kw) -> FakeHttp:
    http = http or FakeHttp()
    return http.add("GET", RSS_URL, body=raw("rss_ok.xml") if body is None else body,
                    headers={"content-type": "text/xml;charset=iso-8859-1"}, **kw)


def api(http: FakeHttp, path: str, name: str, **kw) -> FakeHttp:
    return http.add("GET", f"{API}{path}", body=raw(name), headers={"content-type": "application/json; charset=UTF-8"}, **kw)


def org(**data) -> OrgProfile:
    return OrgProfile.from_dict({"org": {"name": "Exemplo Alimentos"}, **data})


# ------------------------------------------------------------------ metadata (council values)
def test_metadata_follows_the_council_decision():
    cls = Ransomfeed
    assert cls.terms == "open" and cls.default_enabled is True and cls.trust_tier == "community"
    assert cls.sources == ("ransomfeed.rss", "ransomfeed.api") and cls.provider == "ransomfeed"
    assert set(cls.hosts) == {"ransomfeed.it", "api.ransomfeed.it"} and cls.sensitive is True
    assert set(cls.produces) == {T.THREAT_ACTOR, T.DOMAIN}
    assert cls.min_interval == 13.0 and cls.max_requests == 1
    reg = DATASETS[rf.RSS_DATASET]
    assert reg["url"] == RSS_URL and reg["ttl"] == 3600 and reg["source"] == "ransomfeed.rss"  # at most hourly
    assert reg["terms_class"] == "open" and reg["licence"] == "CC-BY-4.0" and "Dario Fadda" in reg["attribution"]


# ------------------------------------------------------------------ typed seeds: API + RSS (cond 1-3)
def test_typed_company_seed_searches_the_api_and_matches_offline():
    http = api(rss_http(), "/search/exemplo%20alimentos", "search_ok.json")
    res = run_module(Ransomfeed, "company_name:Exemplo Alimentos Ltda.", http)
    assert res.status is Status.OK
    assert set(http.urls()) == {RSS_URL, f"{API}/search/exemplo%20alimentos"}
    [finding] = res.findings  # the API row and RSS item 90001 are the same claim (merged by record id)
    assert finding.title == "Possible ransomware leak-site claim (name match only)"
    assert finding.severity.label == "medium" and finding.confidence_label.value == "possible"
    assert finding.data["group"] == "lockbit3" and finding.data["claimed_date"] == "2026-11-25"
    assert finding.data["claimed_at"] == "2026-11-25T09:12:40+01:00"  # API dates are Italian local time
    assert len(finding.data["excerpt"]) <= 300 and "Source: Ransomfeed (CC BY 4.0, Dario Fadda)" in finding.description
    assert finding.references == ["https://ransomfeed.it/index.php?page=post_details&id_post=90001"]
    pivots = {(p.entity.type, p.entity.value, p.relation): p for p in res.pivots}
    assert (T.THREAT_ACTOR, "lockbit3", "victim_of") in pivots
    site = pivots[(T.DOMAIN, "exemplo-alimentos.example", "victim_website")]
    assert site.expand is False  # a name-only match: never investigate the claimed website automatically
    assert not any(p.entity.type is T.ONION for p in res.pivots)  # P356 produces threat_actor and domain only
    assert res.attributes["ransomware_mentions"] == 2  # Initech (description) and Fulano de Tal
    assert res.attributes["data_attribution"] == rf.ATTRIBUTION
    assert [d["name"] for d in res.datasets] == [rf.RSS_DATASET]
    http.assert_hosts_within(Ransomfeed)


def test_pivots_are_matched_offline_only():
    http = rss_http()
    res = run_module(Ransomfeed, "company_name:Hospital Exemplo", http, is_seed=False, depth=1)
    assert http.urls() == [RSS_URL]  # never sent to the API: not typed, not an org-profile name
    assert res.status is Status.OK and res.findings[0].data["group"] == "scarlettgroup"
    assert res.raw["rss"]["counts"]["api_rows"] == 0


def test_org_profile_names_use_the_api_even_as_pivots():
    http = api(rss_http(), "/search/exemplo%20alimentos", "search_ok.json")
    res = run_module(Ransomfeed, "company_name:Exemplo Alimentos", http, is_seed=False, depth=2, org_profile=org())
    assert f"{API}/search/exemplo%20alimentos" in http.urls() and res.status is Status.OK


def test_rss_encoding_trap_and_html_stripping():
    claims = rf.rss_claims(raw("rss_ok.xml"))
    assert [c["victim"] for c in claims][1] == "EXEMPLO SOLUÇÕES CONTÁBEIS LTDA"  # UTF-8 bytes, not the header's latin-1
    first = claims[0]
    assert first["website"] == "exemplo-alimentos.example" and first["country"] == "Brazil" and first["group"] == "lockbit3"
    assert first["claimed_at"] == "2026-11-25T09:12:40+01:00" and first["record_id"] == "90001"
    assert claims[1]["website"] is None  # 'Target victim website: N/D' is no website
    assert all(c["excerpt"] is None for c in claims)  # the feed carries a template, never kept as text
    assert "matomo" not in json.dumps(claims)


# ------------------------------------------------------------------ domains (cond 2)
def test_exact_website_match_is_high_and_critical_for_org_assets():
    http = api(rss_http(times=2), "/search/exemplo-alimentos.example", "search_empty.json", times=2)
    res = run_module(Ransomfeed, "domain:exemplo-alimentos.example", http)
    [finding] = res.findings
    assert finding.severity.label == "high" and finding.data["match_type"] == "domain" and finding.title.startswith("Claimed on")
    assert "claimed by lockbit3 on 2026-11-25 (actor claim, unverified)" in finding.description
    own = org(domains=[{"name": "exemplo-alimentos.example", "verification": "attested", "attested_by": "analyst", "attested_date": "2026-11-26"}])
    res = run_module(Ransomfeed, "domain:exemplo-alimentos.example", http, org_profile=own)
    assert res.findings[0].severity.label == "critical" and res.findings[0].data["org_relation"] == "own"


def test_placeholder_websites_never_match_but_domain_titles_do():
    http = api(rss_http(), "/search/seguros-exemplo.example", "search_placeholder_website.json")
    res = run_module(Ransomfeed, "domain:seguros-exemplo.example", http)
    [finding] = res.findings
    assert finding.data["match_type"] == "domain" and finding.data["victim"] == "seguros-exemplo.example"
    assert all(d["domain"] != "example.com" for d in finding.data["domains"])
    http = api(rss_http(), "/search/example.com", "search_placeholder_website.json")
    res = run_module(Ransomfeed, "domain:example.com", http)
    assert res.status is Status.EMPTY and not res.findings  # example.com is the tracker's placeholder, not a victim


def test_natural_person_rows_keep_no_description():
    http = api(rss_http(), "/search/fulano%20de%20tal", "search_ok.json")
    res = run_module(Ransomfeed, "company_name:Fulano de Tal", http)
    [finding] = res.findings
    assert finding.data["victim"] == "Fulano de Tal" and "excerpt" not in finding.data
    assert "tax files" not in json.dumps([f.to_dict() for f in res.findings]) + json.dumps(res.raw)


# ------------------------------------------------------------------ misses and could-not-verify (rule 5)
def test_miss_reads_not_listed():
    http = api(rss_http(), "/search/exemplo%20seguros", "search_empty.json")
    res = run_module(Ransomfeed, "company_name:Exemplo Seguros", http)
    assert res.status is Status.EMPTY
    assert res.attributes["ransomware_listing"].startswith("not listed by Ransomfeed (data as of 20")
    pivot = run_module(Ransomfeed, "company_name:Exemplo Seguros", rss_http(), is_seed=False)
    assert pivot.attributes["ransomware_listing"].endswith("hourly RSS of recent claims only")


def test_api_rate_limit_is_could_not_verify_unless_the_feed_matched():
    http = rss_http().add("GET", f"{API}/search/exemplo%20seguros", status=429, text="Too Many Requests", headers={"retry-after": "60"})
    res = run_module(Ransomfeed, "company_name:Exemplo Seguros", http)
    assert res.status is Status.RATE_LIMITED and "ransomware_listing" not in res.attributes
    http = rss_http().add("GET", f"{API}/search/hospital%20exemplo", status=429, text="Too Many Requests")
    res = run_module(Ransomfeed, "company_name:Hospital Exemplo", http)
    assert res.status is Status.OK and res.findings  # the RSS answered with a claim
    assert res.source_statuses["ransomfeed.api"]["status"] == "rate_limited"


def test_error_in_200_and_odd_api_answers_are_never_empty():
    http = rss_http().add("GET", f"{API}/search/exemplo%20seguros", json={"error": "database unavailable"})
    res = run_module(Ransomfeed, "company_name:Exemplo Seguros", http)
    assert res.status is Status.ERROR and "ransomware_listing" not in res.attributes
    http = rss_http().add("GET", f"{API}/search/exemplo%20seguros", text="<html>maintenance</html>")
    assert run_module(Ransomfeed, "company_name:Exemplo Seguros", http).status is Status.ERROR


def test_unsafe_or_broken_rss_is_refused():
    evil = b'<?xml version="1.0"?><!DOCTYPE rss [<!ENTITY x "boom">]><rss><channel><item><title>&x;</title></item></channel></rss>'
    with pytest.raises(rf.UnsafeXML):
        rf.parse_rss(evil)
    with pytest.raises(rf.UnsafeXML):
        rf.parse_rss(b"<html><body>error</body></html>")
    with pytest.raises(rf.UnsafeXML):
        rf.parse_rss(b"<rss><channel><item>")
    http = rss_http(body=evil)
    res = run_module(Ransomfeed, "company_name:Exemplo Seguros", http, is_seed=False)
    assert res.status is Status.ERROR and "could not verify" in res.error  # pivot: no API fallback


# ------------------------------------------------------------------ threat actors: actor card (cond 1)
def test_actor_seed_gets_the_card_and_recent_claims_without_onion_pivots():
    http = api(rss_http(), "/ganginfo/lockbit3", "ganginfo_ok.json")
    res = run_module(Ransomfeed, "threat_actor:LockBit 3.0", http)
    assert res.status is Status.OK
    assert GANGINFO_URL.format(gang="lockbit3") in http.urls()  # the RSS gang name, never /gang/{gang}
    profile = res.attributes["ransomware_group_profile"]
    assert profile["name"] == "lockbit3" and profile["claims_seen"] == 1 and profile["known"] is True
    assert LOCKBIT_CARD_ONION.replace(".onion", "[.]onion") in profile["leak_sites"]
    assert profile["about"].startswith("LockBit") and len(profile["about"]) <= 300
    assert not any(p.entity.type is T.ONION for p in res.pivots)
    assert ("lockbit3: CISA Alert aa23-075a", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-075a") in res.links


def test_actor_pivot_uses_the_feed_only():
    http = rss_http()
    res = run_module(Ransomfeed, "threat_actor:play", http, is_seed=False)
    assert http.urls() == [RSS_URL] and res.attributes["ransomware_group_profile"]["claims_seen"] == 1


# ------------------------------------------------------------------ offline helpers for watch / supplier screening
def test_match_feed_claims_offline():
    hits = rf.match_feed_claims(raw("rss_ok.xml"), names=["Exemplo Soluções Contábeis"], domains=["grupoexemplo.example"])
    assert {(h["victim"], h["match_type"]) for h in hits} == {
        ("EXEMPLO SOLUÇÕES CONTÁBEIS LTDA", "name"), ("grupoexemplo.example", "domain")}


def test_api_parsers():
    rows = rf.parse_api_claims(module_fixture(Ransomfeed, "gang_ok.json"))
    assert [r["victim"] for r in rows] == ["globex.example", "Umbrella Exemplo Seguros"]
    assert rf.parse_api_claims([]) == [] and rf.parse_api_claims({"x": 1}) is None
    card = rf.parse_ganginfo(module_fixture(Ransomfeed, "ganginfo_ok.json"))
    assert card["name"] == "lockbit3" and len(card["onions"]) == 2 and len(card["profile_links"]) == 2
    for bad in (None, 1, "x", [], {}, {"name": 5}, {"name": "x", "locations": "nope", "profile": [3]}):
        rf.parse_ganginfo(bad)
        rf.parse_api_claims(bad)
        rf.api_claim(bad)
