"""pivots_cti (P300): MITRE ATT&CK, Malpedia and D3FEND reference pages, manual links only.

Vectors: tests/fixtures/pivots_cti/mitre_vectors.json; maintainer checks (status and title only):
tests/fixtures/pivots_cti/verified_templates.json. V3LUM never fetches these URLs."""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, make_ctx, module_fixture, run_module
from v3lum.core import links
from v3lum.core.entities import Entity
from v3lum.core.http import PolicyError
from v3lum.core.models import Status
from v3lum.modules.cti_framework import pivots_cti as pv
from v3lum.modules.cti_framework.pivots_cti import PivotsCti
from v3lum.modules.utility import pivot_pack_render as pr

VECTORS = module_fixture("pivots_cti", "mitre_vectors.json")
VERIFIED = module_fixture("pivots_cti", "verified_templates.json")


def urls(res):
    return [url for _label, url in res.links]


# ------------------------------------------------------------------ cond 8: {mitre_path}
@pytest.mark.parametrize(("value", "path"), sorted(VECTORS["valid"].items()))
def test_mitre_path_vectors(value, path):
    assert pv.mitre_path(value) == path


@pytest.mark.parametrize("value", VECTORS["invalid"])
def test_mitre_path_refuses_non_techniques(value):
    assert pv.mitre_path(value) is None


def test_dotted_technique_path_is_the_404_the_placeholder_avoids():
    dotted = next(c for c in VERIFIED["checks"] if c["case"] == "attack_technique_dotted_not_found")
    ok = next(c for c in VERIFIED["checks"] if c["case"] == "attack_technique_ok")
    assert dotted["status"] == 404 and ok["status"] == 200
    res = run_module(PivotsCti, "mitre_technique:T1059.001", FakeHttp(), tlp="clear")
    assert res.status is Status.OK and res.requests == 0
    assert urls(res) == [ok["url"]]


def test_revoked_technique_links_the_replacement_with_the_label():
    revoked = VECTORS["revoked_example"]
    res = run_module(PivotsCti, f"mitre_technique:{revoked['id']}", tlp="clear")
    assert urls(res) == ["https://attack.mitre.org/techniques/T1684/001/"]
    assert f"revoked -> replaced by {revoked['replacement']}" in res.links[0][0]


def test_tactic_and_mitigation_ids_get_no_technique_page():
    for value in ("TA0001", "M1036"):
        res = run_module(PivotsCti, f"mitre_technique:{value}", tlp="clear")
        assert res.status is Status.EMPTY and not res.links and "not an ATT&CK technique id" in res.raw["note"]


def test_d3fend_is_a_core_pack_link_and_dotted_ids_work():
    assert links.render("cti:d3fend_technique", Entity.make("mitre_technique", "T1059.001")).url == \
        "https://d3fend.mitre.org/offensive-technique/attack/T1059.001/"
    assert links.render("cti:d3fend_technique", Entity.make("mitre_technique", "T1059")).url == \
        "https://d3fend.mitre.org/offensive-technique/attack/T1059/"


# ------------------------------------------------------------------ cond 8-9: alias-index ids, never the raw name
def test_actor_gets_the_attack_group_page_from_the_alias_index():
    res = run_module(PivotsCti, "threat_actor:Fancy Bear", tlp="clear")  # an alias, not the canonical name
    assert urls(res) == ["https://attack.mitre.org/groups/G0007/"]


def test_malware_gets_software_and_malpedia_pages():
    res = run_module(PivotsCti, "malware_family:Emotet", tlp="clear")
    assert urls(res) == ["https://attack.mitre.org/software/S0367/", "https://malpedia.caad.fkie.fraunhofer.de/details/win.emotet"]


def test_umbrella_and_unknown_names_get_no_link():
    lazarus = run_module(PivotsCti, "threat_actor:Lazarus", tlp="clear")
    assert lazarus.status is Status.EMPTY and "umbrella" in lazarus.raw["note"]
    unknown = run_module(PivotsCti, "threat_actor:Totally Unknown Group 4242", tlp="clear")
    assert unknown.status is Status.EMPTY and not unknown.links


def test_actor_malpedia_ids_use_the_actor_route(monkeypatch):
    """Actors live under /actor/{id}: /details/apt28 answers 404 (2026-11-26)."""
    assert next(c for c in VERIFIED["checks"] if c["case"] == "malpedia_details_actor_not_found")["status"] == 404
    monkeypatch.setattr(pv, "alias_ids", lambda value, ns: (["G0007"], ["actor:apt28"], "resolved to APT28"))
    res = run_module(PivotsCti, "threat_actor:APT28", tlp="clear")
    assert urls(res) == ["https://attack.mitre.org/groups/G0007/", "https://malpedia.caad.fkie.fraunhofer.de/actor/apt28"]


def test_several_ids_mean_no_link(monkeypatch):
    monkeypatch.setattr(pv, "alias_ids", lambda value, ns: (["S0001", "S0002"], ["win.a", "win.b"], "resolved to X, Y"))
    res = run_module(PivotsCti, "malware_family:Ambiguous", tlp="clear")
    assert res.status is Status.EMPTY and not res.links
    assert {h["id"] for h in res.raw["hidden"]} == {"attack_software", "malpedia_family"}


def test_malpedia_ids_are_validated_per_namespace():
    assert pv.malpedia_value(["win.emotet"], "malware") == "win.emotet"
    assert pv.malpedia_value(["actor:apt28"], "malware") is None
    assert pv.malpedia_value(["actor:lazarus_group"], "actor") == "lazarus_group"
    assert pv.malpedia_value(["win.emotet"], "actor") is None
    assert pv.malpedia_value(["../etc"], "malware") is None


def test_alias_index_unavailable_is_reported_not_guessed(monkeypatch):
    def broken(value, ns):
        raise LookupError("the P295 alias index is unusable")

    monkeypatch.setattr(pv, "alias_ids", broken)
    res = run_module(PivotsCti, "malware_family:Emotet", tlp="clear")
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset" and not res.links


def test_resolver_links_reject_raw_names():
    ml = pr.module_links("cti")["malpedia_family"]
    assert pr.render(ml, Entity.make("malware_family", "Emotet"), {"malpedia_id": "Emotet loader/../x"}) is None
    assert pr.render(ml, Entity.make("malware_family", "Emotet")) is None  # no id from the index: no link


# ------------------------------------------------------------------ TLP
def test_amber_labels_name_the_id_actually_sent():
    res = run_module(PivotsCti, "malware_family:Emotet")
    by_url = {u: lab for lab, u in res.links}
    assert by_url["https://attack.mitre.org/software/S0367/"].endswith("opening sends S0367 (for Emotet) to attack.mitre.org")


def test_red_emits_nothing():
    res = run_module(PivotsCti, "mitre_technique:T1059.001", tlp="red")
    assert res.status is Status.SKIPPED and res.reason_code == "tlp" and not res.links


def test_never_fetches_anything():
    ctx = make_ctx(PivotsCti, FakeHttp())
    with pytest.raises(PolicyError):
        ctx.http.get("https://attack.mitre.org/techniques/T1059/001/")
