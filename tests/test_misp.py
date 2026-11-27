"""MISP event export (WP21, P303): golden events, tlp:* tags, distribution 0, unpublished, to_ids
gating shared with STIX, galaxy tags with cluster uuids, personal-data stripping, cross-case
omission and the PyMISP oracle (skipped when PyMISP is not installed).

Goldens live in ``tests/fixtures/misp/`` (``V3LUM_UPDATE_GOLDEN=1`` rewrites them); the input case
is the STIX fixture ``tests/fixtures/stix/case_phishing.json``."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from tests.test_stix_v2 import OTHER_CASE, load_case, pinned_indexes  # noqa: F401 - autouse fixture
from v3lum.report.misp import DISTRIBUTION_ORG_ONLY, counts, event, tlp_tag

FIX = Path(__file__).parent / "fixtures" / "misp"
UPDATE = os.environ.get("V3LUM_UPDATE_GOLDEN") == "1"
HASH = "a3f1" * 16


def golden(name: str, data: dict) -> dict:
    path = FIX / name
    if UPDATE or not path.exists():
        path.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    return json.loads(path.read_text(encoding="utf-8"))


def attrs(ev: dict) -> dict[str, dict]:
    return {a["value"]: a for a in ev["Event"]["Attribute"]}


def tags(ev: dict) -> list[str]:
    return [t["name"] for t in ev["Event"]["Tag"]]


def test_golden_default_event():
    ev = event(load_case())
    assert ev == golden("event_default.golden.json", ev)


def test_golden_personal_event():
    ev = event(load_case(), include_personal=True)
    assert ev == golden("event_personal.golden.json", ev)


@pytest.mark.parametrize("tlp", ["clear", "green", "amber", "amber+strict", "red"])
def test_tlp_tag_distribution_0_and_unpublished_at_every_tlp(tlp):
    ev = event(load_case(tlp=tlp))
    body = ev["Event"]
    assert tags(ev)[0] == f"tlp:{tlp}" == tlp_tag(tlp)
    assert body["distribution"] == DISTRIBUTION_ORG_ONLY == "0"
    assert body["published"] is False
    assert "sharing_group_id" not in body and "SharingGroup" not in body
    assert all(a["distribution"] == "5" for a in body["Attribute"])  # inherit the event (org only)


def test_to_ids_follows_the_indicator_gating():
    a = attrs(event(load_case()))
    assert a["login-acme.example"]["to_ids"] is True  # CR27 consensus
    assert "consensus (CR27)" in a["login-acme.example"]["comment"]
    assert a[HASH]["to_ids"] is True and "analyst-confirmed" in a[HASH]["comment"]
    assert a["203.0.113.10"]["to_ids"] is False  # one upstream family: observable only
    assert a["AS64500"]["to_ids"] is False and a["CVE-2024-3400"]["type"] == "vulnerability"
    # a single-module finding never sets to_ids
    case = load_case(correlations=[])
    case["findings"] = [f for f in case["findings"] if f["id"] == "f0dom0000000001"]
    assert attrs(event(case))["login-acme.example"]["to_ids"] is False


def test_weak_iocs_need_include_weak():
    case = load_case()
    case["correlations"][0]["confidence_label"] = "possible"
    weak = attrs(event(case))["login-acme.example"]
    assert weak["to_ids"] is False and "observable only (possible)" in weak["comment"]
    assert attrs(event(case, include_weak=True))["login-acme.example"]["to_ids"] is True


def test_galaxy_tags_and_cluster_uuids():
    ev = event(load_case())
    names = tags(ev)
    assert 'misp-galaxy:threat-actor="APT28"' in names
    assert 'misp-galaxy:malpedia="V3lumTestLoader"' in names
    assert 'misp-galaxy:mitre-attack-pattern="Phishing - T1566"' in names
    assert 'workflow:state="draft"' in names
    galaxy = ev["Event"]["Galaxy"]
    assert galaxy == [{
        "type": "threat-actor", "uuid": "698774c7-8022-42c4-917f-8d6e4f06ada3",
        "GalaxyCluster": [{"uuid": "11111111-2222-4333-8444-555555555555", "value": "APT28", "type": "threat-actor", "tag_name": 'misp-galaxy:threat-actor="APT28"'}],
    }]  # derived (non-galaxy) clusters get a tag but never a fake cluster uuid


def test_personal_data_stripped_by_default():
    case = load_case()
    ev = event(case)
    text = json.dumps(ev, ensure_ascii=False)
    for value in ("joao.silva", "Joao Silva", "jsilva_teste", "+5511987654321", "52998224725", "529.982.247-25", "invoice-joao", "/home/analyst"):
        assert value not in text
    assert {a["type"] for a in ev["Event"]["Attribute"]}.isdisjoint({"email", "phone-number", "full-name", "text"})
    assert ev["Event"]["info"] == "V3LUM case 20261126-100000-a1b2: domain:login-acme.example"
    assert ev["Event"]["threat_level_id"] == "4"  # a person's score is never exported


def test_include_personal_adds_people_but_never_cpf():
    ev = event(load_case(), include_personal=True)
    a = attrs(ev)
    assert a["joao.silva@acme-corp.example"]["type"] == "email"
    assert a["Joao Silva Teste"]["type"] == "full-name" and a["Joao Silva Teste"]["category"] == "Person"
    assert a["+5511987654321"]["type"] == "phone-number"
    assert a["jsilva_teste"]["type"] == "text" and a["jsilva_teste"]["comment"] == "username"
    text = json.dumps(ev, ensure_ascii=False)
    assert "52998224725" not in text and "529.982.247-25" not in text
    assert "PRIVATE ANALYST NOTE" not in text
    assert "email:" not in ev["Event"]["info"]


def test_threat_level_from_the_risk_of_an_ioc_case():
    case = load_case(seeds=["domain:login-acme.example"])
    case["risk"]["no_export"] = []
    assert event(case)["Event"]["threat_level_id"] == "1"
    # a score that rests on personal entities is never exported: the automation view is used
    case["risk"]["no_export"] = ["email:joao.silva@acme-corp.example"]
    case["risk"]["automation"] = {"score": 20.0, "level": "low"}
    assert event(case)["Event"]["threat_level_id"] == "3"
    del case["risk"]["automation"]
    assert event(case)["Event"]["threat_level_id"] == "4"


def test_restricted_cross_case_counts_never_travel():
    case = load_case()
    case["entities"][1]["attributes"]["sightings"][0]["value"].update(count=0, restricted=2)
    case["findings"][3]["data"].update(count=0, restricted=2)
    text = json.dumps(event(case, include_personal=True), ensure_ascii=False)
    assert "restricted" not in text and "previous case" not in text and "earlier" not in text


@pytest.mark.parametrize("tlp", ["clear", "green", "amber", "amber+strict"])
def test_no_cross_case_reference_in_an_event(tlp):
    text = json.dumps(event(load_case(tlp=tlp), include_personal=True), ensure_ascii=False)
    assert OTHER_CASE not in text and "2026-10-01" not in text and "MISP event #4211" not in text


def test_privacy_tagged_correlations_excluded_by_default():
    case = load_case()
    case["correlations"][3]["override"] = {"label": "confirmed", "verdict": "right"}
    case["correlations"][3]["tags"] = ["privacy", "identity_link", "malicious"]
    case["correlations"][3]["entities"] = ["ipv4:203.0.113.10"]
    assert attrs(event(case))["203.0.113.10"]["to_ids"] is False  # excluded: no confirmed indicator
    assert attrs(event(case, include_personal=True))["203.0.113.10"]["to_ids"] is True


def test_research_case_carries_the_licence_banner():
    ev = event(load_case(licence_profile="research"))
    banner = [a for a in ev["Event"]["Attribute"] if a["type"] == "comment"]
    assert banner and banner[0]["value"].startswith("LICENCE: research profile") and banner[0]["to_ids"] is False


def test_counts_give_the_dry_run_numbers():
    ev = event(load_case())
    assert counts(ev) == {"events": 1, "attributes": len(ev["Event"]["Attribute"]), "to_ids": 2}


def test_attribute_uuids_are_deterministic_per_case():
    a1 = attrs(event(load_case()))
    a2 = attrs(event(load_case()))
    other = attrs(event(load_case(case_id="20261127-120000-ffee")))
    assert {k: v["uuid"] for k, v in a1.items()} == {k: v["uuid"] for k, v in a2.items()}
    assert a1["login-acme.example"]["uuid"] != other["login-acme.example"]["uuid"]  # MISP attribute uuids are per event


def test_pymisp_oracle_loads_the_event():
    pymisp = pytest.importorskip("pymisp")
    for ev in (event(load_case()), event(load_case(tlp="amber+strict"), include_personal=True, include_weak=True)):
        loaded = pymisp.MISPEvent()
        loaded.load(json.loads(json.dumps(ev)))
        assert int(loaded.distribution) == 0 and not loaded.published
        assert len(loaded.attributes) == len(ev["Event"]["Attribute"])
        assert {t.name for t in loaded.tags} >= {tags(ev)[0]}
