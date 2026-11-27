"""url_domain_blocklists (P071, batch p1-G03-1): datasets installed through the real dataset manager,
the on-disk index, verdict scope, fidelity, history and 'not checked'.

Fixtures in tests/fixtures/url_domain_blocklists/ (P071 cond 2: HaGeZi, ScamSniffer, OpenPhish and
Phishing Army fixtures are synthetic; the others are real slices of the 2026-11-26 lists, minimised):
CERT.PL CSV (4 real rows + documentation rows dated around the frozen test clock, and a second
snapshot for the removal diff), Phishing.Database domains and links (shared platforms included, the
SharePoint tenant and personal path scrubbed to contoso-example / user_example_com), StevenBlack,
Botvrij, MetaMask config, spmedia, Procon-SP (the real error-in-200 body and a synthetic record list
with documentation CNPJ/CPF values) and the GitHub raw 501 page.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from tests.fakes import FakeClock, FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core import datasets
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.url_web import url_domain_blocklists as B
from v3lum.modules.url_web.url_domain_blocklists import UrlDomainBlocklists, UrlDomainBlocklistsC2

CERTPL = "url_domain_blocklists.certpl.csv"
PDB_DOMAINS = "url_domain_blocklists.phishing_database.domains.txt"
PDB_LINKS = "url_domain_blocklists.phishing_database.links.txt"
OPENPHISH = "url_domain_blocklists.openphish.txt"
ARMY = "url_domain_blocklists.phishing_army.txt"
HAGEZI = "url_domain_blocklists.hagezi_tif.txt"
STEVEN = "url_domain_blocklists.stevenblack.hosts"
BOTVRIJ = "url_domain_blocklists.botvrij.csv"
METAMASK = "url_domain_blocklists.metamask.config.json"
SPMEDIA = "url_domain_blocklists.spmedia.txt"
SCAM = "url_domain_blocklists.scamsniffer.domains.json"
PROCON = "url_domain_blocklists.procon_sp.json"
CYBER = "url_domain_blocklists.cybercrime_tracker.txt"


def fx(name: str):
    return module_fixture(UrlDomainBlocklists, name)


def raw_fx(name: str) -> str:
    return (Path(__file__).resolve().parent.parent / "fixtures" / "url_domain_blocklists" / name).read_text(encoding="utf-8")


@pytest.fixture()
def env(monkeypatch):
    """A runtime over FakeHttp (frozen clock 2026-11-26T12:00Z) and an installer that serves a feed body
    at its registered URL and runs the real `v3lum data update` path (download, validator = index build)."""
    http = FakeHttp()
    rt = make_runtime(http, clock=FakeClock())

    def install(dataset: str, body: str | bytes, *, expect_ok: bool = True):
        _feed, part = B.PARTS[dataset]
        monkeypatch.setitem(datasets.DATASETS[dataset], "min_bytes", 1)  # fixtures are slices of multi-MB lists
        http.add("GET", part.url, body=body.encode("utf-8") if isinstance(body, str) else body, times=1)
        result = rt.data.update(dataset)
        assert result.ok is expect_ok, result.reason
        return result

    return http, rt, install


def run(entity, rt, *, settings=None, keys=None, **kw):
    """Run through the engine on the shared runtime (settings/keys are applied to its configuration)."""
    saved = (dict(rt.config.settings), dict(rt.config.file_keys))
    rt.config.settings.update(settings or {})
    rt.config.file_keys.update(keys or {})
    try:
        return run_module(UrlDomainBlocklists, entity, runtime=rt, **kw)
    finally:
        rt.config.settings.clear()
        rt.config.settings.update(saved[0])
        rt.config.file_keys.clear()
        rt.config.file_keys.update(saved[1])


def hits(res):
    return res.attributes.get("blocklist_hits", [])


# ------------------------------------------------------------------ metadata (cond 2-4, 10)
def test_metadata():
    cls = UrlDomainBlocklists
    assert (cls.disclosure, cls.hosts, cls.provider, cls.terms) == ("none", (), "", "noncommercial")
    assert cls.default_enabled is True and cls.trust_tier == "n/a" and cls.max_tlp.value_str == "red"
    assert {"openphish.community_feed", "phishing_army.blocklist", "cert_pl.hole_domains", "procon_sp.evite_sites",
            "phishtank.online_valid", "github.url_domain_blocklists_phishing_database_links"} <= set(cls.sources)
    assert "cybercrime_tracker.panel_list" not in cls.sources  # unknown-tier provider: the c2 class (A3)
    c2 = UrlDomainBlocklistsC2
    assert c2.default_enabled is False and c2.terms == "open" and c2.sources == ("cybercrime_tracker.panel_list",)
    for feed in B.FEEDS.values():
        for part in feed.parts:
            reg = datasets.DATASETS[part.dataset]
            assert reg["large"] is True, part.dataset  # never fetched mid-scan (cond 1, A6)
            assert reg["terms_class"] == ("noncommercial" if feed.id in ("openphish", "phishing_army") else "open")


# ------------------------------------------------------------------ cond 8: missing/stale lists are 'not checked'
def test_missing_lists_read_not_checked_and_nothing_is_downloaded(env):
    http, rt, _install = env
    res = run("domain:login-bank.example.net", rt)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert "not checked" in res.error and "not listed" not in res.error
    assert http.calls == []  # never fetched mid-scan
    assert res.source_statuses["cert_pl.hole_domains"]["status"] == "unavailable"
    assert "run v3lum data update" in res.source_statuses["cert_pl.hole_domains"]["reason"]


def test_stale_list_reads_not_checked(env):
    _http, rt, install = env
    install(CERTPL, raw_fx("certpl_slice_derived.tsv"))
    install(SPMEDIA, raw_fx("spmedia_ok.txt"))
    assert run("domain:login-bank.example.net", rt).status is Status.OK
    rt.clock.advance(80 * 3600)  # CERT.PL is stale after 72 h; spmedia (168 h) is still usable
    res = run("domain:login-bank.example.net", rt)
    assert res.status is Status.EMPTY  # absent from the lists that WERE checked ...
    assert res.source_statuses["cert_pl.hole_domains"]["status"] == "unavailable"  # ... CERT.PL reads 'not checked'
    assert any(n["list"] == "CERT.PL warning list" and "h old" in n["reason"] for n in res.raw["not_checked"])
    rt.clock.advance(200 * 3600)
    gone = run("domain:login-bank.example.net", rt)
    assert gone.status is Status.UNAVAILABLE and "not checked" in gone.error


# ------------------------------------------------------------------ cond 1: index built at data update, lookups read keys only
def test_index_is_built_at_data_update_and_lookups_read_it(env, monkeypatch):
    _http, rt, install = env
    install(CERTPL, raw_fx("certpl_slice_derived.tsv"))
    path = B.index_path()
    assert path.is_file() and oct(path.stat().st_mode & 0o777) == "0o600"
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT feed, count FROM feed_meta WHERE dataset = ?", (CERTPL,)).fetchone() == ("certpl", 7)
    monkeypatch.setattr(B, "PARSERS", {})  # a lookup never parses a list again
    res = run("domain:login-bank.example.net", rt)
    assert res.status is Status.OK
    hit = hits(res)[0]
    assert (hit["list"], hit["match"], hit["listed_at"], hit["historical"]) == ("CERT.PL warning list", "domain", "2026-11-25T08:00:00Z", False)
    assert hit["dataset_sha256"] and hit["terms"] == "open"
    finding = res.findings[0]
    assert finding.title == "Listed on phishing blocklist(s)" and finding.severity.label == "high"
    assert {"phishing", "malicious"} <= set(finding.tags) and finding.criterion and finding.source == "cert_pl.hole_domains"
    assert res.attributes["blocklists"] == ["CERT.PL warning list"] and res.attributes["malicious"] is True
    assert any(d["name"] == CERTPL for d in res.datasets)  # provenance: dataset citation


def test_lost_index_is_rebuilt_from_the_local_copy(env):
    _http, rt, install = env
    install(CERTPL, raw_fx("certpl_slice_derived.tsv"))
    B.index_path().unlink()
    res = run("domain:login-bank.example.net", rt)
    assert res.status is Status.OK and hits(res)[0]["feed"] == "certpl"


def test_large_copies_are_reindexed_in_the_background(env, monkeypatch):
    _http, rt, install = env
    install(CERTPL, raw_fx("certpl_slice_derived.tsv"))
    B.index_path().unlink()
    monkeypatch.setattr(B, "SYNC_REINDEX_BYTES", 0)
    first = run("domain:login-bank.example.net", rt)
    assert first.status is Status.UNAVAILABLE and "being rebuilt" in first.error, (first.status, first.error)
    for thread in list(B._BACKGROUND.values()):
        thread.join(timeout=30)
    assert run("domain:login-bank.example.net", rt).status is Status.OK


def test_parent_domains_match_but_never_a_public_suffix(env):
    _http, rt, install = env
    install(CERTPL, raw_fx("certpl_slice_derived.tsv"))
    parent = run("domain:www.login-bank.example.net", rt)
    assert hits(parent)[0]["match"] == "parent" and hits(parent)[0]["key"] == "login-bank.example.net"
    assert run("domain:other.example.net", rt).status is Status.EMPTY
    assert B.domain_lookup_keys("a.b.evil.example.com.br") == ["a.b.evil.example.com.br", "b.evil.example.com.br", "evil.example.com.br",
                                                             "example.com.br"]


# ------------------------------------------------------------------ cond 6/10: verdict scope on shared platforms
def test_shared_platform_listing_flags_only_the_url(env):
    _http, rt, install = env
    install(PDB_DOMAINS, raw_fx("phishing_database_domains_ok.txt"))
    install(PDB_LINKS, raw_fx("phishing_database_links_ok.txt"))
    listed_sp = ("https://contoso-example-my.sharepoint.com/:b:/g/personal/user_example_com/"
                 "EaBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdefghij?e=AbC123")
    res = run(Entity.make(T.URL, listed_sp), rt)
    assert [(h["feed"], h["match"]) for h in hits(res)] == [("phishing_database", "url")]
    assert res.findings[0].severity.label == "medium"  # one phishing list (not CERT.PL): MEDIUM
    for unlisted in ("https://contoso-example-my.sharepoint.com/personal/other_example_com/Documents/x.pdf",
                     "https://sites.google.com/view/legit-team-site/home", "https://79.docs.google.com/x",
                     "https://contoso-example.sharepoint.com/sites/Finance"):
        assert run(Entity.make(T.URL, unlisted), rt).status is Status.EMPTY, unlisted
    assert [h["match"] for h in hits(run(Entity.make(T.URL, "https://sites.google.com/view/345678987655/home"), rt))] == ["url"]
    for dom in ("sites.google.com", "contoso-example.sharepoint.com", "storage.cloud.google.com"):
        assert run(f"domain:{dom}", rt).status is Status.EMPTY, dom  # listed in the domain list itself: never a domain verdict


def test_psl_private_tenants_get_tenant_verdicts_only(env):
    _http, rt, install = env
    install(PDB_DOMAINS, raw_fx("phishing_database_domains_ok.txt"))
    install(PDB_LINKS, raw_fx("phishing_database_links_ok.txt"))
    assert hits(run(Entity.make(T.URL, "https://0penseanft.pages.dev/claim"), rt))[0]["match"] == "domain"
    assert hits(run(Entity.make(T.URL, "https://preview.0penseanft.pages.dev/"), rt))[0]["match"] == "parent"
    assert run(Entity.make(T.URL, "https://other-tenant.pages.dev/"), rt).status is Status.EMPTY
    # a URL listing on a tenant host never propagates to the host (cond 6)
    assert run(Entity.make(T.URL, "https://apply-daybreakcenter.pages.dev/other"), rt).status is Status.EMPTY
    assert B.host_scope("apply-daybreakcenter.pages.dev") == "tenant" and B.host_scope("sites.google.com") == "platform"


def test_url_listing_flags_an_ordinary_host(env):
    _http, rt, install = env
    install(PDB_LINKS, raw_fx("phishing_database_links_ok.txt"))
    res = run("domain:016614590390149677279078-dot-my-project-45bb.ey.r.appspot.com", rt)
    assert res.status is Status.EMPTY  # appspot.com tenants are PSL private: no host propagation
    assert B.url_key("HTTPS://Evil.Example.COM:443/Login?A=1#frag") == "evil.example.com/Login?A=1"
    assert B.url_key("ftp://user:pass@files.example.net/x") == "files.example.net/x"


# ------------------------------------------------------------------ cond 3/4/10: licence and consent per feed
def test_openphish_entry_skipped_under_corporate(env, monkeypatch):
    _http, rt, install = env
    url = Entity.make(T.URL, "https://login.payout.example.org/")
    install(OPENPHISH, raw_fx("openphish_synthetic.txt"), expect_ok=False)  # no consent recorded: never installed
    assert not datasets.DataStore(rt).info(OPENPHISH).present
    monkeypatch.setattr(B, "openphish_consent", lambda: "LEGAL-2026-OPH-1")
    install(OPENPHISH, raw_fx("openphish_synthetic.txt"))
    corporate = [s for s in UrlDomainBlocklists.sources if s not in ("openphish.community_feed", "phishing_army.blocklist")]
    res = run(url, rt, allowed_sources=corporate, settings={"url_domain_blocklists_openphish_consent_ref": "LEGAL-2026-OPH-1"})
    assert res.status is Status.UNAVAILABLE and not hits(res)  # the policy gate removed it: the entry is skipped
    no_consent = run(url, rt)  # allowed by the gate but no consent reference: still skipped
    assert no_consent.source_statuses["openphish.community_feed"]["reason_code"] == "licence" and not hits(no_consent)
    cleared = run(url, rt, settings={"url_domain_blocklists_openphish_consent_ref": "LEGAL-2026-OPH-1"})
    assert [h["feed"] for h in hits(cleared)] == ["openphish"] and hits(cleared)[0]["terms"] == "noncommercial"


def test_phishing_army_drops_its_filtering_test_domains(env):
    _http, rt, install = env
    install(ARMY, raw_fx("phishing_army_synthetic.txt"))
    assert hits(run("domain:phish-login.example.net", rt))[0]["feed"] == "phishing_army"
    assert run("domain:amiprotected.it", rt).status is Status.EMPTY


def test_phishtank_is_disabled_until_reachable(env):
    _http, rt, install = env
    install(SPMEDIA, raw_fx("spmedia_ok.txt"))
    res = run("domain:example.org", rt)
    assert res.source_statuses["phishtank.online_valid"]["status"] == "needs_key"
    keyed = run("domain:example.org", rt, keys={"phishtank": "app-key-for-tests-0001"})
    assert keyed.source_statuses["phishtank.online_valid"]["status"] == "unavailable"


def test_feeds_can_be_disabled(env):
    _http, rt, install = env
    install(CERTPL, raw_fx("certpl_slice_derived.tsv"))
    res = run("domain:login-bank.example.net", rt, settings={"url_domain_blocklists_disabled_feeds": ["certpl"]})
    assert res.status is Status.UNAVAILABLE and res.source_statuses["cert_pl.hole_domains"]["reason_code"] == "config"


# ------------------------------------------------------------------ cond 7: category and fidelity per list
def test_ads_and_aggregate_lists_are_tag_only(env):
    _http, rt, install = env
    install(STEVEN, raw_fx("stevenblack_ok.txt"))
    install(HAGEZI, raw_fx("hagezi_tif_synthetic.txt"))
    ads = run("domain:ck.getcookiestxt.com", rt)
    assert ads.findings[0].severity.label == "info" and "ads_tracking" in ads.findings[0].tags
    assert "phishing" not in ads.findings[0].tags and "malicious" not in ads.attributes
    agg = run("domain:www.malware-c2.example.net", rt)
    assert agg.findings[0].title.startswith("Listed on an aggregated threat blocklist") and "aggregate_list" in agg.findings[0].tags
    assert "phishing" not in agg.findings[0].tags


def test_crypto_scam_lists_and_metamask_lookalikes(env):
    _http, rt, install = env
    install(METAMASK, raw_fx("metamask_config_ok.json"))
    install(SCAM, raw_fx("scamsniffer_synthetic.json"))
    install(SPMEDIA, raw_fx("spmedia_ok.txt"))
    black = run("domain:app.breakoutpropfirm.com", rt)
    assert black.findings[0].title == "Listed on crypto-scam blocklist(s)" and black.findings[0].severity.label == "medium"
    fuzzy = run("domain:metamsk.io", rt)
    hit = hits(fuzzy)[0]
    assert (hit["match"], hit["lookalike_of"]) == ("fuzzy", "metamask.io") and "typosquat" in fuzzy.findings[0].tags
    assert run("domain:metamask.io", rt).status is Status.EMPTY  # whitelisted (MetaMask algorithm)
    assert hits(run("domain:claim-airdrop.example.net", rt))[0]["feed"] == "scamsniffer"
    assert hits(run("domain:coinbene.io", rt))[0]["feed"] == "spmedia"


def test_phishing_fidelity_needs_certpl_or_independent_families():
    pdb = {"feed": "phishing_database", "category": "phishing"}
    army = {"feed": "phishing_army", "category": "phishing"}
    assert UrlDomainBlocklists._fidelity("phishing", [pdb]) == "MEDIUM"
    assert UrlDomainBlocklists._fidelity("phishing", [pdb, army]) == "MEDIUM"  # both may re-serve PhishTank/OpenPhish (P171)
    assert UrlDomainBlocklists._fidelity("phishing", [{"feed": "certpl", "category": "phishing"}]) == "HIGH"
    assert B._independent([frozenset({"a"}), frozenset({"b"})]) == 2 and B._independent([frozenset({"a", "x"}), frozenset({"x"})]) == 1


# ------------------------------------------------------------------ cond 8: listing dates and history
def test_old_removed_and_frozen_listings_are_historical(env):
    http, rt, install = env
    install(CERTPL, raw_fx("certpl_slice_derived.tsv"))
    old = run("domain:0-ll1xpl-sasa7-web.d6rbpf.cfd", rt)  # listed 2026-05-29: historical, severity lowered
    assert hits(old)[0]["historical"] is True and old.findings[0].severity.label == "medium" and "historical" in old.findings[0].tags
    _f, part = B.PARTS[CERTPL]
    http.add("GET", part.url, body=raw_fx("certpl_snapshot2_derived.tsv").encode(), times=1)
    assert rt.data.update(CERTPL).status == "updated"
    removed = run("domain:phish.example.org", rt)  # in snapshot 1, gone from snapshot 2: removal history
    h = hits(removed)[0]
    assert h["deleted_at"] and h["historical"] and h["listed_at"] == "2026-11-20T10:30:00Z"
    assert hits(run("domain:new-phish.example.net", rt))[0]["historical"] is False
    install(BOTVRIJ, raw_fx("botvrij_ok.csv"))
    bv = run("domain:covid19.egreen.io", rt)
    assert hits(bv)[0]["historical"] is True and bv.findings[0].severity.label == "low"  # frozen list
    assert hits(bv)[0]["context"]["event_info"] == "AVAST COVID-19 response efforts"


# ------------------------------------------------------------------ cond 5: Procon-SP error-in-200, scrubbing and manual link
def test_procon_backend_error_in_200_is_rejected_and_emits_the_manual_link(env):
    _http, rt, install = env
    result = install(PROCON, raw_fx("procon_error_in_200.txt"), expect_ok=False)
    assert "Procon-SP" in result.reason and ("PHP warning" in result.reason or "backend error" in result.reason)
    install(SPMEDIA, raw_fx("spmedia_ok.txt"))
    res = run("domain:loja-falsa.example.com.br", rt)
    assert ("Procon-SP 'Evite estes sites' (manual check)", B.PROCON_MANUAL_URL) in res.links
    assert res.source_statuses["procon_sp.evite_sites"]["status"] == "unavailable"


def test_procon_records_are_scrubbed_before_storage(env):
    _http, rt, install = env
    install(PROCON, raw_fx("procon_records_synthetic.json"))
    stored = datasets.DataStore(rt).path(PROCON).read_text(encoding="utf-8")
    assert "123.456.789" not in stored and "12345678909" not in stored and "Fulano" not in stored
    assert "***.456.789-**" in stored and "11222333000181" in stored
    res = run("domain:loja-falsa.example.com.br", rt)
    hit = hits(res)[0]
    assert hit["feed"] == "procon_sp" and hit["context"]["status"] == "NO AR" and hit["context"]["cnpj"] == "11222333000181"
    assert res.findings[0].title == "Listed by Procon-SP as a fraudulent store"
    assert hits(run("domain:ofertas.example.net", rt))[0]["context"].get("company") in (None, "")


def test_html_instead_of_a_list_keeps_the_previous_copy(env):
    http, rt, install = env
    install(SPMEDIA, raw_fx("spmedia_ok.txt"))
    _f, part = B.PARTS[SPMEDIA]
    http.add("GET", part.url, text=raw_fx("github_raw_501_range.html"), times=1)
    assert rt.data.update(SPMEDIA).status == "failed"
    assert hits(run("domain:coinbene.io", rt))[0]["feed"] == "spmedia"


def test_main_module_ignores_the_c2_feed(env):
    _http, rt, install = env
    install(CYBER, module_fixture(UrlDomainBlocklistsC2, "cybercrime_tracker_ok.txt"))
    install(SPMEDIA, raw_fx("spmedia_ok.txt"))
    assert run("domain:matix.cf", rt).status is Status.EMPTY


def test_raw_and_attributes_are_json_safe(env):
    _http, rt, install = env
    install(CERTPL, raw_fx("certpl_slice_derived.tsv"))
    res = run(Entity.make(T.URL, "https://login-bank.example.net/x?y=1"), rt)
    json.dumps({"raw": res.raw, "attributes": res.attributes})
    assert hits(res)[0]["match"] == "domain"


def test_acceptance_golden_inputs_need_no_route(env):
    """AR21 golden path: the large lists are never fetched mid-scan, so the default run sends nothing."""
    http, rt, _install = env
    root = Path(__file__).resolve().parent.parent / "fixtures" / "acceptance"
    for etype, value in (("domain", "domain:example.com"), ("url", "url:https://example.com/")):
        doc = json.loads((root / etype / "url_domain_blocklists.json").read_text(encoding="utf-8"))
        assert doc == {"schema": "v3lum.acceptance_routes/1", "module": "url_domain_blocklists", "routes": []}
        res = run(value, rt)
        assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset" and http.calls == []


def test_psl_private_section_from_the_stripped_bundled_list(monkeypatch):
    """The bundled PSL has no section markers: the private section starts after the last single-label rule."""
    exact, wild = B._psl_private()
    assert {"pages.dev", "github.io", "blogspot.com"} <= exact and "r.appspot.com" in wild
    assert not {"com.br", "co.uk", "k12.ca.us", "sp.gov.br", "ac.jp"} & exact
    scopes = {h: B.host_scope(h) for h in ("foo.github.io", "x.k12.ca.us", "portal.sp.gov.br", "www.example.com.br", "a.b.r.appspot.com")}
    assert scopes == {"foo.github.io": "tenant", "x.k12.ca.us": "", "portal.sp.gov.br": "", "www.example.com.br": "",
                      "a.b.r.appspot.com": "tenant"}
    monkeypatch.setattr(B, "_psl_private", lambda: (frozenset(), frozenset()))  # no usable section: label heuristic
    assert B._private_tenant("foo.github.io") is True and B._private_tenant("www.example.com.br") is False


def test_reader_tolerates_an_index_still_being_created(tmp_path):
    """A background rebuild creates the file before its schema commits: reads are empty, never an error."""
    path = tmp_path / "idx.sqlite"
    path.write_bytes(b"")
    idx = B.BlocklistIndex(path)
    try:
        assert idx.feed_meta() == {} and idx.dom(["example.com"]) == {} and idx.url("example.com/x") == 0
        assert idx.urlhost("example.com") == 0 and idx.info("d", "dom", "k") is None and idx.removed("certpl", ["k"]) == []
        assert idx.aux("d", "whitelist", ["k"]) == [] and idx.aux("d", "fuzzylist") == [] and idx.urls_for_host("d", "h") == []
    finally:
        idx.close()
