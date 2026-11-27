"""pivots_darkweb (P203): ransomware group pages and clearnet onion search, manual links only.

The maintainer verification records are tests/fixtures/pivots_darkweb/verified_templates.json (status and
title per check, no page bodies: victim lists never enter the repository). V3LUM never fetches these URLs."""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, make_ctx, module_fixture, run_module
from v3lum.core import links
from v3lum.core.entities import Entity
from v3lum.core.http import PolicyError
from v3lum.core.models import Status
from v3lum.modules.darkweb_ransomware import pivots_darkweb as pd
from v3lum.modules.darkweb_ransomware.pivots_darkweb import PivotsDarkweb
from v3lum.modules.utility import pivot_pack_render as pr

VERIFIED = module_fixture("pivots_darkweb", "verified_templates.json")
ONION = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"


def urls(res):
    return [url for _label, url in res.links]


def labels(res):
    return {url: label for label, url in res.links}


# ------------------------------------------------------------------ cond 8: per-site slugs, search fallback
def test_known_group_gets_both_group_pages_with_the_tracker_slug():
    res = run_module(PivotsDarkweb, "threat_actor:LockBit Black", FakeHttp(), tlp="clear")
    assert res.status is Status.OK and res.requests == 0
    assert urls(res) == ["https://www.ransomlook.io/group/lockbit3", "https://www.ransomware.live/group/lockbit3"]
    assert res.raw["slugs"] == {"ransomlook": "lockbit3", "ransomware_live": "lockbit3"}
    assert all(item["clickable"] for item in res.raw["links"])


@pytest.mark.parametrize("name", ["Akira", "qilin", "Agenda", "PLAY", "Medusa", "SafePay", "LockBit 3.0", "lockbit3"])
def test_curated_slugs_resolve_case_and_spacing_insensitively(name):
    slugs, _note = pd.resolve_slugs(name)
    assert set(slugs) == {"ransomlook", "ransomware_live"}


def test_alias_index_canonical_names_reach_the_table(monkeypatch):
    """Trackers name groups differently: a P295 alias resolves to the canonical name that the table knows."""
    monkeypatch.setattr(pd, "candidate_names", lambda value: [value, "Qilin"])
    slugs, note = pd.resolve_slugs("Water Galura")
    assert slugs == {"ransomlook": "qilin", "ransomware_live": "qilin"} and "Qilin" in note


def test_unknown_group_gets_the_search_url_never_a_guessed_path():
    res = run_module(PivotsDarkweb, "threat_actor:Conti", tlp="clear")
    assert urls(res) == ["https://www.ransomware.live/search?q=Conti"]
    hidden = {h["id"]: h["reason"] for h in res.raw["hidden"]}
    assert "RansomLook has no GET search URL" in hidden["ransomlook_group"]
    assert hidden["rlive_group"] == "no known slug"


def test_partial_slug_renders_the_known_site_and_the_other_site_search():
    res = run_module(PivotsDarkweb, "threat_actor:INC Ransom", tlp="clear")
    assert urls(res) == ["https://www.ransomlook.io/group/inc%20ransom", "https://www.ransomware.live/search?q=INC%20Ransom"]


def test_a_name_claimed_by_two_groups_gets_no_slug():
    table = pd.tracker_table({"x_tracker_slugs": {"groups": [
        {"names": ["Shared"], "ransomlook": "one"}, {"names": ["Shared"], "ransomlook": "two"}, {"names": ["Other"], "ransomlook": "three"},
    ]}})
    assert "shared" not in table and table["other"] == {"ransomlook": "three"}
    slugs, _note = pd.resolve_slugs("Shared", table)
    assert slugs == {}


def test_tracker_table_drops_unsafe_slugs():
    table = pd.tracker_table({"x_tracker_slugs": {"groups": [{"names": ["Evil"], "ransomlook": "../admin", "ransomware_live": "a/b"}]}})
    assert table == {}


def test_verified_slug_records_cover_every_table_slug():
    checked = {c["url"] for c in VERIFIED["checks"] if c["status"] == 200}
    for group in pr.pack_data("darkweb")["x_tracker_slugs"]["groups"]:
        if "ransomlook" in group:
            slug = pr.encode_value("ransomlook_slug", group["ransomlook"])
            assert f"https://www.ransomlook.io/group/{slug}" in checked, group
        if "ransomware_live" in group:
            assert f"https://www.ransomware.live/group/{group['ransomware_live']}" in checked, group


# ------------------------------------------------------------------ cond 9: rule 3
def test_no_claim_leak_or_victim_paths_in_the_pack():
    for item in [*pr.pack_data("darkweb")["links"], *pr.pack_data("darkweb")[pr.EXT_KEY]]:
        assert not pr.RULE3_PATH_RE.search(item["template"].split("?", 1)[0].replace("https://" + item["host"], ""))


# ------------------------------------------------------------------ cond 10-11: onion search
def test_onion_search_is_hidden_at_amber_and_above():
    for level in ("amber", "amber+strict"):
        res = run_module(PivotsDarkweb, f"onion:{ONION}", tlp=level)
        assert res.status is Status.SKIPPED and res.reason_code == "tlp" and not res.links
        assert "max_tlp" in res.raw["hidden"][0]["reason"]


@pytest.mark.parametrize("entity", [f"onion:{ONION}", "domain:example.com"])
def test_onion_search_at_green_carries_the_badge_and_the_csam_warning(entity):
    res = run_module(PivotsDarkweb, entity, tlp="green")
    assert res.status is Status.OK
    (label, url), = res.links
    assert url.startswith("https://onionsearchengine.com/search.php?search=")
    assert "unknown operator" in label and "unverified" in label
    assert "child sexual abuse material" in label and "ECA art. 241-B" in label and "isolated browsing environment" in label
    assert ".onion/" not in url.split("?", 1)[0]  # the onion address is a query value, never a host


def test_onion_search_never_takes_company_names_or_keywords():
    ml = pr.module_links("darkweb")["onionsearch"]
    assert set(t.value for t in ml.link.entity_types) == {"domain", "onion"}
    assert pr.render(ml, Entity.make("company_name", "Banco do Brasil")) is None
    assert pr.render(ml, Entity.make("keyword", "lockbit")) is None


# ------------------------------------------------------------------ cond 2: TLP
def test_amber_labels_carry_the_disclosure_with_the_slug_actually_sent():
    res = run_module(PivotsDarkweb, "threat_actor:LockBit Black")  # default TLP:AMBER
    by_url = labels(res)
    assert by_url["https://www.ransomlook.io/group/lockbit3"].endswith("opening sends lockbit3 (for LockBit Black) to www.ransomlook.io")
    assert not any(item["clickable"] for item in res.raw["links"])
    fallback = run_module(PivotsDarkweb, "threat_actor:Conti")
    assert fallback.links[0][0].endswith("opening sends Conti to www.ransomware.live")


def test_red_emits_nothing():
    res = run_module(PivotsDarkweb, "threat_actor:LockBit Black", tlp="red")
    assert res.status is Status.SKIPPED and res.reason_code == "tlp" and not res.links


def test_unreadable_tlp_fails_closed_to_red():
    ctx = make_ctx(PivotsDarkweb, tlp="purple")
    assert pr.tlp_level(ctx).value_str == "red"


# ------------------------------------------------------------------ pack link for company names / keywords
def test_core_pack_search_link_for_company_names_and_keywords():
    for entity in (Entity.make("company_name", "Banco do Brasil"), Entity.make("keyword", "lockbit")):
        out = links.pivot_links_for(entity)
        assert any(r.ref == "darkweb:rlive_search" and r.url.startswith("https://www.ransomware.live/search?q=") for r in out)
    assert not [r for r in links.pivot_links_for(Entity.make("threat_actor", "Conti")) if r.ref.startswith("darkweb:")]


def test_never_fetches_anything():
    ctx = make_ctx(PivotsDarkweb, FakeHttp())
    with pytest.raises(PolicyError):
        ctx.http.get("https://www.ransomlook.io/group/lockbit3")


def test_missing_module_links_degrade_to_empty(monkeypatch):
    monkeypatch.setattr(pr, "module_links", lambda pack: {})
    res = run_module(PivotsDarkweb, "threat_actor:LockBit Black", tlp="clear")
    assert res.status is Status.EMPTY and not res.links
    assert {h["id"] for h in res.raw["hidden"]} == {"ransomlook_group", "rlive_group"}
