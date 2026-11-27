"""ransomlook (P196): RansomLook leak-site claims and the shared ransomware-claim helpers.

Fixtures in tests/fixtures/ransomlook/ (prep batch p1-G09-1, recorded 2026-11-26 from www.ransomlook.io,
victims replaced with documentation values - 'Exemplo ...' companies, 'Fulano de Tal', the reserved
.example TLD, CNPJ 11.222.333/0001-81; group names and leak-site onions are public IOC data):
``search_ok.json`` (/api/search?q=microsoft trimmed: 1 real group, 4 posts, a ransom note),
``search_empty.json`` (verbatim empty answer), ``recent_posts_ok.json`` (/api/posts/period shape = the
/api/last/{n} shape, 3 posts), ``groups_ok.json`` (/api/groups subset), ``html_404.html`` (HTML 404 page
served for unknown API paths) and ``search_truncated.json`` (the 2 MB cap cutting the body).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.fakes import FIXTURES, FakeHttp, module_fixture, run_module
from v3lum.core.datasets import DATASETS
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.darkweb_ransomware import ransomlook as rl
from v3lum.modules.darkweb_ransomware.ransomlook import (
    GROUPS_URL,
    RECENT_POSTS_URL,
    SEARCH_URL,
    RansomLook,
)

LOCKBIT_ONION = "lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd.onion"
DARK_ONION = "darkprn3d3udnhpuxknsrhft3376lrz5tenhgkrxge5hxqe46pkbrwid.onion"
INC_ONION = "nongzecboljwv3yfndkggsybsglfrkffw7bvk2zemuteoxe6etpusnad.onion"


def body(name: str) -> bytes:
    return (FIXTURES / "ransomlook" / name).read_bytes()


def search(http: FakeHttp, term: str, name: str = "search_ok.json", **kw) -> FakeHttp:
    return http.add("GET", f"{SEARCH_URL}?q={term}", body=body(name), headers={"content-type": "application/json"}, **kw)


def org(**data) -> OrgProfile:
    return OrgProfile.from_dict({"org": {"name": "Exemplo Alimentos"}, **data})


# ------------------------------------------------------------------ metadata (council values)
def test_metadata_follows_the_council_decision():
    cls = RansomLook
    assert cls.terms == "open" and cls.default_enabled is True and cls.opsec.label == "passive"
    assert cls.disclosure == "third_party" and cls.provider == "ransomlook"
    assert cls.sources == ("ransomlook.api", "ransomlook.ransomlook_groups_index")
    assert cls.trust_tier == "community" and cls.sensitive is True and cls.shares_input is True
    assert set(cls.hosts) == {"www.ransomlook.io", "ransomlook.io"}
    assert {T.THREAT_ACTOR, T.ONION} == set(cls.produces)
    assert {T.ORG, T.KEYWORD, T.THREAT_ACTOR, T.ONION, T.DOMAIN} <= set(cls.accepts)
    assert cls.max_requests == 1 and cls.cache_ttl == 21600 and cls.daily_quota == 300
    assert "Source: RansomLook (CC BY 4.0)" in cls.notice
    recent, groups = DATASETS[rl.RECENT_DATASET], DATASETS[rl.GROUPS_DATASET]
    assert recent["url"] == RECENT_POSTS_URL and recent["ttl"] == 86400 and recent["source"] == "ransomlook.api"
    assert groups["url"] == GROUPS_URL and groups["source"] == "ransomlook.ransomlook_groups_index"
    assert recent["terms_class"] == groups["terms_class"] == "open" and recent["licence"] == "CC-BY-4.0"
    assert "RansomLook (CC BY 4.0)" in recent["attribution"] and recent["large"] is False


def test_cond2_group_detail_posts_and_export_endpoints_are_never_built():
    source = Path(rl.__file__).read_text(encoding="utf-8")
    for forbidden in ("/api/group/", "/api/posts\"", "/api/export"):
        assert forbidden not in source.replace("``/api/group/{name}``", "").replace("``/api/posts``", "").replace("``/api/export``", "")


# ------------------------------------------------------------------ name search (cond 1, 4, 6)
def test_company_name_search_gives_possible_name_matches_and_mentions():
    http = search(FakeHttp(), "exemplo alimentos")
    res = run_module(RansomLook, "company_name:Exemplo Alimentos Ltda.", http)
    assert res.status is Status.OK
    assert http.urls() == [f"{SEARCH_URL}?q=exemplo+alimentos"]  # legal form stripped, accents folded
    findings = sorted(res.findings, key=lambda f: f.data["group"])
    assert [f.data["group"] for f in findings] == ["Dark Project", "lockbit3"]
    for f in findings:
        assert f.title == rl.TITLE_POSSIBLE and f.severity.label == "medium"  # name-only: medium at most
        assert f.confidence_label.value == "possible" and "possible match - verify victim identity" in f.description
        assert "(actor claim, unverified)" in f.description and "Source: RansomLook (CC BY 4.0)" in f.description
        assert f.source == "ransomlook.api" and "ransomware_claim" in f.tags and f.criterion
    lockbit = findings[1]
    assert lockbit.data["claimed_date"] == "2026-11-24" and lockbit.observed_first.startswith("2026-11-24T13:05:11")
    assert lockbit.data["excerpt"] and len(lockbit.data["excerpt"]) <= 300  # excerpt only (cond 6)
    assert "is a food producer" in lockbit.data["excerpt"] and "everything will be published" not in lockbit.data["excerpt"]
    a = res.attributes
    assert a["ransomware_listing"].startswith("listed by RansomLook: 2 claim(s), latest 2026-11-25")
    assert a["ransomware_mentions"] == 2  # Initech's description and Fulano's post only mention the term
    assert a["data_attribution"] == "Source: RansomLook (CC BY 4.0)"
    pivots = {(p.entity.type, p.entity.value, p.relation): p for p in res.pivots}
    assert (T.THREAT_ACTOR, "lockbit3", "victim_of") in pivots and (T.THREAT_ACTOR, "Dark Project", "victim_of") in pivots
    onion = pivots[(T.ONION, DARK_ONION, "leak_site")]
    assert onion.expand is False and onion.note.startswith("hostile")  # never visited (cond 6)
    assert all(p.entity.type in (T.THREAT_ACTOR, T.ONION) for p in res.pivots)  # P196 produces threat_actor, onion
    http.assert_hosts_within(RansomLook)


def test_claim_links_and_screenshots_are_never_fetched_and_shown_defanged():
    http = search(FakeHttp(), "exemplo alimentos")
    res = run_module(RansomLook, "company_name:Exemplo Alimentos", http)
    dark = next(f for f in res.findings if f.data["group"] == "Dark Project")
    assert dark.data["claim_url_display"].startswith("hxxp://") and "[.]onion" in dark.data["claim_url_display"]
    assert len(http.calls) == 1  # the onion, the /blog link and the screenshot path are never requested
    text = json.dumps([f.to_dict() for f in res.findings]) + json.dumps(res.raw) + json.dumps(res.attributes)
    assert "screenshots/" not in text and "magnet" not in text


def test_cnpj_of_the_organisation_makes_a_critical_claim():
    http = search(FakeHttp(), "exemplo alimentos")
    res = run_module(RansomLook, "company_name:Exemplo Alimentos", http, org_profile=org(cnpj_roots=["11222333"]))
    crit = [f for f in res.findings if f.severity.label == "critical"]
    assert len(crit) == 1 and crit[0].data["match_type"] == "cnpj" and crit[0].data["group"] == "lockbit3"
    assert crit[0].title == rl.TITLE_CLAIM and crit[0].confidence_label.value == "probable"
    assert "organisation's CNPJ root" in crit[0].criterion


# ------------------------------------------------------------------ domain search (cond 4)
def test_exact_domain_match_is_high_and_critical_for_org_assets_and_suppliers():
    http = search(FakeHttp(), "exemplo-alimentos.example", times=1)
    res = run_module(RansomLook, "domain:exemplo-alimentos.example", http)
    by_group = {f.data["group"]: f for f in res.findings}
    dark = by_group["Dark Project"]  # the victim title is the domain itself
    assert dark.severity.label == "high" and dark.data["match_type"] == "domain" and dark.confidence_label.value == "probable"
    assert dark.title == rl.TITLE_CLAIM and "claimed by Dark Project on 2026-11-25 (actor claim, unverified)" in dark.description
    assert by_group["lockbit3"].severity.label == "medium"  # the same company by name only
    own = org(domains=[{"name": "exemplo-alimentos.example", "verification": "confirmed"}])
    res = run_module(RansomLook, "domain:exemplo-alimentos.example", search(FakeHttp(), "exemplo-alimentos.example"), org_profile=own)
    crit = next(f for f in res.findings if f.data["group"] == "Dark Project")
    assert crit.severity.label == "critical" and crit.data["org_relation"] == "own"
    supplier = org(suppliers=[{"name": "Initech", "domains": ["initech.example"]}])
    res = run_module(RansomLook, "company_name:Initech", search(FakeHttp(), "initech"), org_profile=supplier)
    initech = next(f for f in res.findings if f.data["group"] == "the gentlemen")
    assert initech.severity.label == "critical" and initech.data["org_relation"] == "supplier"  # description lead domain


def test_natural_person_victims_get_no_description_text():
    http = search(FakeHttp(), "fulano de tal")
    res = run_module(RansomLook, "company_name:Fulano de Tal", http)
    fulano = next(f for f in res.findings if f.data["group"] == "leakeddata")
    assert "excerpt" not in fulano.data and "tax files" not in fulano.description and "Post excerpt" not in fulano.description
    assert "tax files" not in json.dumps(res.raw)


# ------------------------------------------------------------------ misses and could-not-verify (cond 5, rule 5)
def test_miss_reads_not_listed_with_the_data_date_never_not_breached():
    http = search(FakeHttp(), "exemplo seguros", "search_empty.json")
    res = run_module(RansomLook, "company_name:Exemplo Seguros S.A.", http)
    assert res.status is Status.EMPTY and not res.findings
    listing = res.attributes["ransomware_listing"]
    assert listing.startswith("not listed by RansomLook (data as of 20") and "breach" not in listing


@pytest.mark.parametrize(
    "status,text,expected",
    [
        (429, "slow down", Status.RATE_LIMITED),
        (403, "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>", Status.BLOCKED),
        (503, "upstream down", Status.ERROR),
        (500, "boom", Status.ERROR),
    ],
)
def test_refusals_and_failures_are_could_not_verify(status, text, expected):
    http = FakeHttp().add("GET", f"{SEARCH_URL}?q=exemplo", status=status, text=text, times=3)
    res = run_module(RansomLook, "company_name:Exemplo", http)
    assert res.status is expected and not res.findings and "ransomware_listing" not in res.attributes


def test_html_404_page_and_odd_bodies_are_errors_never_empty():
    http = FakeHttp().add("GET", f"{SEARCH_URL}?q=exemplo", status=404, body=body("html_404.html"), headers={"content-type": "text/html; charset=utf-8"})
    assert run_module(RansomLook, "company_name:Exemplo", http).status is Status.ERROR
    http = FakeHttp().add("GET", f"{SEARCH_URL}?q=exemplo", text="<html><body>maintenance</body></html>")
    assert run_module(RansomLook, "company_name:Exemplo", http).status is Status.ERROR
    http = FakeHttp().add("GET", f"{SEARCH_URL}?q=exemplo", json=["not", "a", "search"])
    res = run_module(RansomLook, "company_name:Exemplo", http)
    assert res.status is Status.ERROR and "could not verify" in res.error


def test_answer_cut_by_the_2mb_cap_is_could_not_verify(monkeypatch):
    monkeypatch.setattr(rl, "SEARCH_MAX_BYTES", 700)
    full = body("search_ok.json")
    http = FakeHttp().add("GET", f"{SEARCH_URL}?q=exemplo", body=full, headers={"content-type": "application/json"})
    res = run_module(RansomLook, "company_name:Exemplo", http)
    assert res.status is Status.ERROR and "larger than 2 MB" in res.error
    assert http.calls[0]["max_bytes"] == 700  # the cap is sent to the transport (bounded read)
    assert body("search_truncated.json") == full[:700]  # the recorded truncation fixture is this cut


def test_inputs_without_a_searchable_term_are_not_applicable():
    for value in ("company_name:S/A", "company_name:LTDA", "company_name:Grupo", "keyword:ab"):
        http = FakeHttp()
        res = run_module(RansomLook, value, http)
        assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and not http.calls


# ------------------------------------------------------------------ threat actors: offline index (cond 1)
def index_http(groups: str = "groups_ok.json", posts: str = "recent_posts_ok.json") -> FakeHttp:
    http = FakeHttp()
    http.add("GET", GROUPS_URL, body=body(groups), headers={"content-type": "application/json"})
    http.add("GET", RECENT_POSTS_URL, body=body(posts), headers={"content-type": "application/json"})
    return http


def test_threat_actor_is_answered_offline_from_the_daily_index():
    http = index_http()
    res = run_module(RansomLook, "threat_actor:Inc Ransom", http)
    assert res.status is Status.OK
    assert set(http.urls()) == {GROUPS_URL, RECENT_POSTS_URL}  # datasets only: the actor name is never sent
    profile = res.attributes["ransomware_group_profile"]
    assert profile["name"] == "inc ransom" and profile["known"] is True and profile["claims_seen"] == 1
    assert profile["window_days"] == 30 and profile["latest_claim"] == "2026-11-24"
    assert profile["leak_sites"] == [INC_ONION.replace(".onion", "[.]onion")]
    assert res.attributes["ransomware_group"] == "inc ransom"
    onion = next(p for p in res.pivots if p.entity.type is T.ONION)
    assert onion.entity.value == INC_ONION and onion.expand is False and onion.relation == "leak_site"
    info = next(f for f in res.findings if f.title == "Ransomware group tracked by RansomLook")
    assert info.severity.label == "info"
    assert {d["name"] for d in res.datasets} == {rl.GROUPS_DATASET, rl.RECENT_DATASET}


def test_actor_claims_on_org_assets_are_critical():
    own = org(domains=[{"name": "grupoexemplo.example", "verification": "confirmed"}])
    res = run_module(RansomLook, "threat_actor:play", index_http(), org_profile=own)
    crit = [f for f in res.findings if f.severity.label == "critical"]
    assert len(crit) == 1 and crit[0].data["victim"] == "Grupo Exemplo S/A" and crit[0].data["match_type"] == "domain"


def test_unknown_actor_with_no_recent_claims_is_empty():
    res = run_module(RansomLook, "threat_actor:Nonexistent Crew", index_http())
    assert res.status is Status.EMPTY
    assert res.attributes["ransomware_listing"].startswith("group not tracked by RansomLook (data as of")


def test_actor_falls_back_to_the_api_when_the_index_cannot_be_read():
    http = FakeHttp().add("GET", GROUPS_URL, status=500, text="down", times=3).add("GET", RECENT_POSTS_URL, status=500, text="down", times=3)
    search(http, "lockbit3")
    res = run_module(RansomLook, "threat_actor:lockbit3", http)
    assert res.status is Status.OK
    assert f"{SEARCH_URL}?q=lockbit3" in http.urls()
    assert res.attributes["ransomware_group_profile"]["claims_seen"] == 1


# ------------------------------------------------------------------ onion inputs
def test_onion_input_names_the_group_whose_posts_link_to_it():
    http = search(FakeHttp(), DARK_ONION)
    res = run_module(RansomLook, f"onion:{DARK_ONION}", http)
    assert res.status is Status.OK
    actor = next(p for p in res.pivots if p.entity.type is T.THREAT_ACTOR)
    assert actor.entity.value == "Dark Project" and actor.relation == "leak_site_of"
    finding = res.findings[0]
    assert finding.severity.label == "high" and "malicious" in finding.tags and "[.]onion" in finding.description
    http2 = search(FakeHttp(), LOCKBIT_ONION, "search_empty.json")
    assert run_module(RansomLook, f"onion:{LOCKBIT_ONION}", http2).status is Status.EMPTY


# ------------------------------------------------------------------ sanitizer (A4)
def test_raw_evidence_keeps_claim_metadata_only():
    http = search(FakeHttp(), "exemplo alimentos")
    res = run_module(RansomLook, "company_name:Exemplo Alimentos", http)
    raw = res.raw["api"]
    assert raw["query"] == "exemplo alimentos" and raw["counts"]["matched"] == 2
    assert {c["victim"] for c in raw["claims"]} == {"Exemplo Alimentos Ltda.", "exemplo-alimentos.example"}
    assert "description" not in json.dumps(raw)


# ------------------------------------------------------------------ offline matching for watch / supplier screening
def test_match_recent_claims_is_offline():
    posts = module_fixture(RansomLook, "recent_posts_ok.json")
    hits = rl.match_recent_claims(posts, names=["EXEMPLO ALIMENTOS LTDA"], domains=["https://grupoexemplo.example/"], cnpj_roots=["11.222.333"])
    kinds = {(h["victim"], h["match_type"]) for h in hits}
    assert kinds == {("Exemplo Alimentos Ltda.", "cnpj"), ("Grupo Exemplo S/A", "domain")}
    globex = rl.match_recent_claims(posts, names=["Globex"])  # 'Globex Corporation' -> 'globex' (legal form stripped)
    assert [(h["victim"], h["match_type"]) for h in globex] == [("Globex Corporation", "name")]
    assert rl.match_recent_claims(posts, names=["Umbrella"], domains=["example.com"]) == []  # placeholder domain never matches
    assert rl.match_recent_claims("not a list", names=["x"]) == []


# ------------------------------------------------------------------ shared helpers (cond 3)
@pytest.mark.parametrize(
    "name,expected",
    [
        ("Exemplo Alimentos Ltda.", "exemplo alimentos"),
        ("EXEMPLO ALIMENTOS LTDA", "exemplo alimentos"),
        ("Grupo Exemplo S/A", "exemplo"),
        ("Grupo Exemplo S.A.", "exemplo"),
        ("Transportes Exemplo EIRELI - ME", "transportes exemplo"),
        ("Padaria Exemplo EPP", "padaria exemplo"),
        ("Initech, Inc.", "initech"),
        ("EXEMPLO SOLUÇÕES CONTÁBEIS LTDA", "exemplo solucoes contabeis"),
        ("NAVEXEMPLO s.r.o.", "navexemplo"),
        ("The Exemplo Pvt Ltd", "exemplo"),
        ("LTDA", "ltda"),
        ("", ""),
    ],
)
def test_normalize_victim_name(name, expected):
    assert rl.normalize_victim_name(name) == expected


@pytest.mark.parametrize(
    "a,b",
    [("The Gentlemen", "thegentlemen"), ("Inc Ransom", "incransom"), ("LockBit 3.0", "lockbit3"), ("LockBit Black", "lockbit3"),
     ("ALPHV", "BlackCat"), ("Cl0p", "clop"), ("Vexy Ransomware", "vexy"), ("Dark Project", "darkproject")],
)
def test_normalize_group_alias(a, b):
    assert rl.normalize_group_alias(a) == rl.normalize_group_alias(b)
    assert rl.normalize_group_alias("Medusa") != rl.normalize_group_alias("MedusaLocker")


@pytest.mark.parametrize(
    "value,expected",
    [
        ("example.com", None), ("www.example.com", None), ("N/D", None), ("", None), (None, None),
        ("https://www.Exemplo-Alimentos.example/contato?x=1", "exemplo-alimentos.example"),
        ("grupoexemplo.example.", "grupoexemplo.example"), ("192.0.2.10", None), ("not a domain", None), (LOCKBIT_ONION, None),
    ],
)
def test_victim_domain(value, expected):
    assert rl.victim_domain(value) == expected


def test_victim_domain_idna_cnpj_and_onions():
    assert rl.victim_domain("exemplo-açúcar.example").startswith("xn--")
    text = "CNPJ 11.222.333/0001-81, wrong 11.222.333/0001-82, bare 00000000000191."
    assert rl.extract_cnpjs(text) == ["11222333000181", "00000000000191"]
    assert rl.onion_host("http://" + LOCKBIT_ONION + "/post/x") == LOCKBIT_ONION
    assert rl.onion_host(LOCKBIT_ONION.replace("ykyd", "ykye")) is None and rl.onion_host("expyuzz4wqqyqhjn.onion") is None
    assert rl.extract_onions("see http://" + LOCKBIT_ONION + "/x and " + LOCKBIT_ONION) == [LOCKBIT_ONION]


@pytest.mark.parametrize(
    "name,domains,expected",
    [
        ("Fulano de Tal", [], False), ("Maria da Silva", [], False), ("Fulano de Tal", ["fulano.example"], False),
        ("Exemplo Alimentos Ltda.", [], True), ("Hospital Exemplo", [], True), ("globex.example", [], True),
        ("Initech", [], True), ("Company #286", [], True), ("Umbrella exemplo", ["umbrella.example"], True),
        ("Umbrella exemplo", [], False), ("Umbrella Exemplo", ["umbrella.example"], False),
    ],
)
def test_is_probably_organisation_fails_safe(name, domains, expected):
    assert rl.is_probably_organisation(name, domains) is expected


def test_excerpt_dates_and_search_terms():
    out = rl.excerpt("<b>Bold</b> " + "word " * 120 + '<img src="https://tracker.example/p.gif">')
    assert len(out) <= 300 and out.endswith("…") and "<" not in out and "tracker" not in out
    assert rl.excerpt("# TITLE — DATA\r\n\r\n## Part\r\n**1 TB** files") == "TITLE — DATA Part 1 TB files"
    assert rl.excerpt("") is None
    assert rl.iso_or_none("2026-11-25 22:18:40.220849") == "2026-11-25T22:18:40.220849+00:00"
    assert rl.iso_or_none("2026-07-01 12:00:00", "Europe/Rome") == "2026-07-01T12:00:00+02:00"
    assert rl.iso_or_none("2026-01-15 00:30:00", "Europe/Rome") == "2026-01-15T00:30:00+01:00"
    assert rl.iso_or_none("Wed, 25 Nov 2026 02:36:32 CET") == "2026-11-25T02:36:32+01:00"
    assert rl.iso_or_none(1795656819000) == "2026-11-26T01:33:39+00:00"
    assert rl.iso_or_none("garbage") is None and rl.iso_or_none(True) is None
    make = Entity.make
    assert rl.search_term(make(T.ORG, "Exemplo Alimentos Ltda.")) == "exemplo alimentos"
    assert rl.search_term(make(T.ORG, "https://www.Exemplo-Alimentos.example/")) == "exemplo-alimentos.example"
    assert rl.search_term(make(T.DOMAIN, "www.exemplo.example")) == "exemplo.example"
    assert rl.search_term(make(T.THREAT_ACTOR, "LockBit 3.0")) == "lockbit 3.0"
    assert rl.search_term(make(T.ORG, "S/A")) is None and rl.search_term(make(T.ORG, "Grupo")) is None


def test_domains_match_uses_label_boundaries():
    assert rl.domains_match("www.acme.com.br", "acme.com.br") and rl.domains_match("portal.acme.com.br", "acme.com.br")
    assert not rl.domains_match("evilacme.com.br", "acme.com.br") and not rl.domains_match("a.acme.com.br", "b.acme.com.br")


def test_cross_tracker_corroboration_rule_helpers():
    a = rl.make_claim("ransomlook", victim="Exemplo Alimentos Ltda.", group="LockBit 3.0", claimed_at="2026-11-24 13:05:11")
    b = rl.make_claim("ransomfeed", victim="EXEMPLO ALIMENTOS LTDA", group="lockbit3", claimed_at="Wed, 25 Nov 2026 09:12:40 CET")
    c = rl.make_claim("ransomware_live", victim="exemplo-alimentos.example", group="lockbit3", claimed_at="2026-11-30T00:00:00+00:00")
    assert rl.claims_corroborate(a, b) and not rl.claims_corroborate(a, c)  # 6 days apart
    d = dict(c, claimed_date="2026-11-26")
    assert rl.claims_corroborate(a, d)  # compact key 'exemploalimentos' of the domain-shaped victim
    assert rl.corroboration_groups([a, b, c]) == [[0, 1], [2]]
    assert rl.corroboration_text(["ransomfeed", "ransomlook"]) == "corroborated by 2 trackers: RansomLook, Ransomfeed"
    assert rl.not_listed_wording(["ransomlook", "ransomfeed"], "2026-11-26") == "not listed by RansomLook, Ransomfeed (data as of 2026-11-26)"
    assert rl.claim_key(a) == "exemplo alimentos|lockbit3|2026-11-24"


def test_parsers_never_raise_on_bad_input():
    for bad in (None, 1, "x", [], {}, [None, 3, "a"], {"posts": "nope"}, {"posts": [{"post_title": 5}]}):
        rl.parse_search(bad)
        rl.parse_posts(bad)
        rl.parse_groups(bad)
        rl.normalize_post(bad)
        rl.match_recent_claims(bad, names=["x"])
