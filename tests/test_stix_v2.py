"""STIX 2.1 export v2 (WP21, P303): golden bundles, deterministic ids, TLP 2.0 markings on every
object, indicator gating, personal-data stripping, escaping, cross-case omission and the stix2
oracle (skipped when stix2 is not installed).

Golden files live in ``tests/fixtures/stix/``; regenerate them with ``V3LUM_UPDATE_GOLDEN=1``
after an intended output change (and review the diff). The ATT&CK index and the galaxy fragments
are pinned to test copies so module-batch data fragments never change the goldens."""

from __future__ import annotations

import copy
import json
import os
import re
import shutil
import uuid
from pathlib import Path

import pytest

from v3lum.core import attack, galaxy
from v3lum.core.entities import PERSONAL_TYPES, EntityType
from v3lum.report import stix
from v3lum.report.stix import MARKINGS, bundle, pattern_literal, prepare, sco_id

FIX = Path(__file__).parent / "fixtures" / "stix"
UPDATE = os.environ.get("V3LUM_UPDATE_GOLDEN") == "1"
OTHER_CASE = "20261001-090000-ffff"


@pytest.fixture(autouse=True)
def pinned_indexes(tmp_path):
    """ATT&CK index = the core fragment only; galaxy = the synthetic test fragment (+ its notice)."""
    attack_dir = tmp_path / "attack"
    attack_dir.mkdir()
    shutil.copy(Path(attack.__file__).resolve().parent.parent / "data" / "attack" / "core_min.json", attack_dir / "core_min.json")
    old_attack, old_frag, old_notice = attack.FRAGMENT_DIR, galaxy.FRAGMENT_DIR, galaxy.NOTICE_DIR
    attack.FRAGMENT_DIR = attack_dir
    attack.reload()
    galaxy.FRAGMENT_DIR = tmp_path / "no_galaxy"
    galaxy.NOTICE_DIR = FIX / "notices"
    galaxy.reload([FIX / "galaxy"])
    try:
        yield
    finally:
        attack.FRAGMENT_DIR = old_attack
        attack.reload()
        galaxy.FRAGMENT_DIR, galaxy.NOTICE_DIR = old_frag, old_notice
        galaxy.reload()


def load_case(**changes) -> dict:
    case = json.loads((FIX / "case_phishing.json").read_text(encoding="utf-8"))
    case.update(changes)
    return case


def golden(name: str, data: dict) -> dict:
    path = FIX / name
    if UPDATE or not path.exists():
        path.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    return json.loads(path.read_text(encoding="utf-8"))


def objects(b: dict, kind: str | None = None) -> list[dict]:
    return [o for o in b["objects"] if kind is None or o["type"] == kind]


def text_of(b: dict) -> str:
    return json.dumps(b, ensure_ascii=False)


# --------------------------------------------------------------------------------------
# golden files
# --------------------------------------------------------------------------------------


def test_golden_default_bundle():
    b = bundle(load_case())
    assert b == golden("bundle_default.golden.json", b)


def test_golden_personal_bundle():
    b = bundle(load_case(), include_personal=True)
    assert b == golden("bundle_personal.golden.json", b)


def test_bundle_is_deterministic_and_does_not_change_the_case():
    case = load_case()
    before = copy.deepcopy(case)
    assert bundle(case) == bundle(case)
    assert case == before


# --------------------------------------------------------------------------------------
# deterministic ids (AR09)
# --------------------------------------------------------------------------------------


def test_sco_ids_match_the_stix2_algorithm():
    assert sco_id("ipv4-addr", {"value": "8.8.8.8"}) == "ipv4-addr--2f689bf9-0ff2-545f-aa61-e495eb8cecc7"
    assert sco_id("domain-name", {"value": "example.com"}) == "domain-name--bedb4899-d24b-5401-bc86-8f6b4cc18ec7"
    # whole objects: only the id-contributing properties count
    assert sco_id("domain-name", {"type": "domain-name", "value": "example.com", "object_marking_refs": ["x"]}) == sco_id("domain-name", {"value": "example.com"})


def test_file_ids_prefer_md5_then_sha1_sha256_sha512():
    md5, sha1, sha256, sha512 = "b" * 32, "c" * 40, "d" * 64, "e" * 128
    both = sco_id("file", {"hashes": {"SHA-256": sha256, "MD5": md5}})
    assert both == sco_id("file", {"hashes": {"MD5": md5}})
    assert sco_id("file", {"hashes": {"SHA-512": sha512, "SHA-1": sha1, "SHA-256": sha256}}) == sco_id("file", {"hashes": {"SHA-1": sha1}})
    assert sco_id("file", {"hashes": {"SHA-512": sha512, "SHA-256": sha256}}) == sco_id("file", {"hashes": {"SHA-256": sha256}})
    canon = stix.jcs({"hashes": {"MD5": md5}})
    assert both == f"file--{uuid.uuid5(stix.STIX_NS, canon)}"


def test_ids_are_stable_across_runs_and_cases():
    a = bundle(load_case())
    b = bundle(load_case(case_id="20261127-120000-ffee", created="2026-11-27T12:00:00+00:00"))
    ids_a = {o["id"] for o in a["objects"]}
    ids_b = {o["id"] for o in b["objects"]}
    for kind in ("domain-name", "ipv4-addr", "url", "file", "autonomous-system", "vulnerability", "attack-pattern", "threat-actor", "malware", "indicator", "note", "relationship", "identity", "marking-definition"):
        assert {o["id"] for o in objects(a, kind)} == {o["id"] for o in objects(b, kind)}, kind
    # only the report (and the bundle) are case-scoped
    assert objects(a, "report")[0]["id"] != objects(b, "report")[0]["id"]
    assert ids_a - ids_b == {objects(a, "report")[0]["id"]}


def test_global_sdos_have_stable_well_known_ids():
    b = bundle(load_case())
    vuln = objects(b, "vulnerability")[0]
    assert vuln["id"] == f"vulnerability--{uuid.uuid5(stix.V3LUM_NS, 'vulnerability|CVE-2024-3400')}"
    ap = objects(b, "attack-pattern")[0]
    assert ap["id"] == attack.stix_id("T1566") and ap["external_references"][0]["external_id"] == "T1566"
    actor = objects(b, "threat-actor")[0]
    assert actor["id"] == "threat-actor--11111111-2222-4333-8444-555555555555"  # the galaxy cluster uuid
    assert actor["name"] == "APT28" and "Sofacy" in actor["aliases"]
    malware = objects(b, "malware")[0]
    derived = uuid.uuid5(galaxy.DERIVED_NS, "malware_family|v3lumtestloader")
    assert malware["id"] == f"malware--{derived}" and malware["is_family"] is True


def test_galaxy_lookup_by_synonym_and_derived_fallback():
    assert galaxy.lookup("threat_actor", " fancy   BEAR ").uuid == "11111111-2222-4333-8444-555555555555"
    assert galaxy.lookup(EntityType.THREAT_ACTOR, "APT28").tag == 'misp-galaxy:threat-actor="APT28"'
    derived = galaxy.lookup("malware_family", "V3lumTestLoader")
    assert derived.source == "derived" and derived.stix_id.startswith("malware--")
    assert derived.uuid == galaxy.lookup("malware_family", "v3lumtestloader").uuid  # case-insensitive, stable
    assert galaxy.lookup("username", "x") is None and galaxy.lookup("threat_actor", "  ") is None
    assert galaxy.errors() == []


def test_galaxy_fragment_without_notice_is_rejected(tmp_path):
    bad = tmp_path / "bad"
    bad.mkdir()
    frag = json.loads((FIX / "galaxy" / "test_threat_actor.json").read_text())
    frag["notice"] = "no_such_notice"
    frag["clusters"] = {"Lazarus Test": {"uuid": "22222222-2222-4333-8444-555555555555"}}
    (bad / "bad.json").write_text(json.dumps(frag))
    galaxy.reload([FIX / "galaxy", bad])
    assert any("notice" in e for e in galaxy.errors())
    assert galaxy.lookup("threat_actor", "Lazarus Test").source == "derived"


# --------------------------------------------------------------------------------------
# markings (A2)
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("tlp", ["clear", "green", "amber", "amber+strict", "red"])
def test_every_object_carries_the_case_marking(tlp):
    b = bundle(load_case(tlp=tlp), include_personal=True, include_weak=True)
    marking = MARKINGS[tlp]
    assert b["objects"][0] == marking
    assert marking["extensions"][stix.TLP_EXTENSION]["tlp_2_0"] == tlp
    assert [o for o in b["objects"] if o["type"] == "marking-definition"] == [marking]
    for obj in b["objects"]:
        if obj["type"] != "marking-definition":
            assert obj.get("object_marking_refs") == [marking["id"]], obj["id"]


def test_tlp2_marking_definitions_are_the_published_ones():
    assert MARKINGS["amber+strict"]["id"] == "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003"
    assert MARKINGS["clear"]["name"] == "TLP:CLEAR" and MARKINGS["red"]["created"] == "2022-10-01T00:00:00.000Z"
    assert stix.marking_for("TLP:AMBER+STRICT") == MARKINGS["amber+strict"]


def test_missing_tlp_is_amber_and_unreadable_tlp_fails_closed_to_red():
    case = load_case()
    case.pop("tlp")
    case["options"].pop("tlp")
    assert bundle(case)["objects"][0]["name"] == "TLP:AMBER"
    assert bundle(load_case(tlp="purple"))["objects"][0]["name"] == "TLP:RED"


# --------------------------------------------------------------------------------------
# personal data (A4/A8, AR24) - acceptance: no PERSONAL_TYPES value or seed in a default export
# --------------------------------------------------------------------------------------


def _personal_values(case: dict) -> set[str]:
    values = set()
    for node in case["entities"]:
        if EntityType(node["type"]) in PERSONAL_TYPES:
            values |= {node["value"], node["display"]}
    for seed in case["seeds"]:
        etype, _, value = seed.partition(":")
        if EntityType(etype) in PERSONAL_TYPES:
            values |= {seed, value}
    return {v for v in values if v and "*" not in v}


def test_no_personal_value_or_seed_in_a_default_export():
    case = load_case()
    text = text_of(bundle(case))
    for value in _personal_values(case):
        assert value.lower() not in text.lower(), value
    for fragment in ("529.982.247-25", "52998224725", "98765-4321", "joao.silva", "Joao Silva"):
        assert fragment not in text
    for kind in ("email-addr", "user-account"):
        assert not objects(bundle(case), kind)
    assert not [o for o in objects(bundle(case), "identity") if o.get("identity_class") == "individual"]


def test_report_description_lists_no_personal_seed_and_no_person_score():
    report = objects(bundle(load_case()), "report")[0]
    assert "Seeds: domain:login-acme.example." in report["description"]
    assert "email:" not in report["description"] and "cpf:" not in report["description"]
    assert "Risk score withheld" in report["description"] and "72" not in report["description"]
    # an IOC-only case keeps its score
    ioc = load_case(seeds=["domain:login-acme.example"])
    ioc["risk"]["no_export"] = []
    assert "(72.0/100, without personal-data entities)" in objects(bundle(ioc), "report")[0]["description"]


def test_exported_score_never_rests_on_personal_entities():
    """P302 cond 10: an IOC seed whose case score includes personal entities exports the automation
    score (without them); a stored case without that view exports none."""
    case = load_case(seeds=["domain:login-acme.example"])
    case["risk"]["no_export"] = ["email:joao.silva@acme-corp.example"]
    case["risk"]["automation"] = {"score": 31.5, "level": "medium", "basis": "case score without personal-data entities"}
    desc = objects(bundle(case), "report")[0]["description"]
    assert "Risk medium (31.5/100" in desc and "72" not in desc
    del case["risk"]["automation"]
    assert "Risk score withheld" in objects(bundle(case), "report")[0]["description"]
    assert stix.export_risk(prepare(case)) is None


def test_only_exported_ioc_seeds_are_listed():
    case = load_case(seeds=[
        "domain:login-acme.example", "file:/home/analyst/cases/evidence/invoice-joao.pdf",
        "text_blob:call Joao at the office", "keyword:Joao Silva Teste", "url:https://login-acme.example/reset?email=joao.silva@acme-corp.example",
    ])
    desc = objects(bundle(case), "report")[0]["description"]
    assert "Seeds: domain:login-acme.example." in desc and "4 other seed(s) not listed" in desc
    for leak in ("/home/analyst", "invoice", "call Joao", "keyword:", "reset?email"):
        assert leak not in desc
    from v3lum.report.misp import event

    assert event(case)["Event"]["info"] == "V3LUM case 20261126-100000-a1b2: domain:login-acme.example"


def test_free_form_values_carrying_personal_data_are_withheld():
    case = load_case()
    case["entities"] += [
        {"key": "user_agent:ScanBot/1.0 (+ops-contact@acme-corp.example)", "type": "user_agent", "value": "ScanBot/1.0 (+ops-contact@acme-corp.example)", "display": "ScanBot"},
        {"key": "company_name:JOAO SILVA TESTE 52998224725", "type": "company_name", "value": "JOAO SILVA TESTE 52998224725", "display": "JOAO SILVA TESTE"},
        {"key": "company_name:Acme Corp Ltda", "type": "company_name", "value": "Acme Corp Ltda", "display": "Acme Corp Ltda"},
    ]
    for b in (bundle(case), bundle(case, include_personal=True)):
        text = text_of(b)
        assert "52998224725" not in text and "529.982.247" not in text  # an MEI name carries its owner's CPF: never exported
        assert [o["name"] for o in objects(b, "identity") if o.get("identity_class") == "organization"] == ["Acme Corp Ltda"]
    assert "ops-contact@" not in text_of(bundle(case))
    from v3lum.report.misp import event

    assert "ops-contact@" not in json.dumps(event(case)) and "ops-contact@" in json.dumps(event(case, include_personal=True))


def test_include_personal_exports_people_but_cpf_stays_masked():
    b = bundle(load_case(), include_personal=True)
    text = text_of(b)
    assert objects(b, "email-addr")[0]["value"] == "joao.silva@acme-corp.example"
    assert any(o.get("account_login") == "jsilva_teste" for o in objects(b, "user-account"))
    person = [o for o in objects(b, "identity") if o.get("identity_class") == "individual"]
    assert person and person[0]["name"] == "Joao Silva Teste"
    assert "52998224725" not in text and "529.982.247-25" not in text
    assert "***.982.247-**" in text
    # the report still never lists personal seeds
    assert "email:" not in objects(b, "report")[0]["description"]


def test_urls_carrying_personal_data_are_withheld():
    b = bundle(load_case())
    assert not [o for o in objects(b, "url") if "reset" in o["value"]]
    assert "1 url with personal data" in objects(b, "report")[0]["description"]
    with_personal = bundle(load_case(), include_personal=True)
    assert [o for o in objects(with_personal, "url") if "reset" in o["value"]]


def test_analyst_notes_local_paths_and_file_names_never_exported():
    for b in (bundle(load_case()), bundle(load_case(), include_personal=True)):
        text = text_of(b)
        for secret in ("PRIVATE ANALYST NOTE", "PRIVATE FEEDBACK NOTE", "analyst remark", "/home/analyst", "invoice-joao", ".v3lum/cases"):
            assert secret not in text


def test_privacy_tagged_items_need_include_personal():
    default = text_of(bundle(load_case()))
    assert "breach index" not in default and "Identity link" not in default
    personal = text_of(bundle(load_case(), include_personal=True))
    assert "breach index" in personal and "Identity link" in personal


def test_secret_types_are_never_exported():
    case = load_case()
    case["entities"].append({"key": "secret:aws_key:AKIA…MPLE:0123456789abcdef", "type": "secret", "value": "aws_key:AKIA…MPLE:0123456789abcdef", "display": "AKIA…MPLE (aws_key)"})
    text = text_of(bundle(case, include_personal=True))
    assert "AKIA" not in text


# --------------------------------------------------------------------------------------
# indicator gating (P303 cond 5)
# --------------------------------------------------------------------------------------


def _indicator_patterns(b: dict) -> set[str]:
    return {o["pattern"] for o in objects(b, "indicator")}


def test_consensus_and_confirmed_findings_are_the_only_indicators():
    b = bundle(load_case())
    patterns = _indicator_patterns(b)
    assert patterns == {"[domain-name:value = 'login-acme.example']", f"[file:hashes.'SHA-256' = '{'a3f1' * 16}']"}
    dom = next(o for o in objects(b, "indicator") if "domain-name" in o["pattern"])
    assert dom["confidence"] == 70 and dom["valid_from"] == "2026-11-20T00:00:00.000Z"
    assert dom["valid_until"] == "2027-02-18T00:00:00.000Z"  # domain tau 90 days (P302)
    assert dom["external_references"][0]["external_id"] == "c0cr270000000001"
    file_ind = next(o for o in objects(b, "indicator") if "file:" in o["pattern"])
    assert file_ind["confidence"] == 90 and "valid_until" not in file_ind  # hashes do not decay
    ap = attack.stix_id("T1566")
    rels = {(r["source_ref"], r["relationship_type"], r["target_ref"]) for r in objects(b, "relationship")}
    assert (dom["id"], "indicates", ap) in rels
    malware = objects(b, "malware")[0]["id"]
    assert (file_ind["id"], "indicates", malware) in rels
    # the single-family CR27 on the IP is not a consensus: observable only
    assert not any("203.0.113.10" in p for p in patterns)
    assert objects(b, "ipv4-addr")


def test_single_module_finding_is_an_observable_not_an_indicator():
    case = load_case(correlations=[])
    case["findings"] = [f for f in case["findings"] if f["id"] == "f0dom0000000001"]
    b = bundle(case)
    assert not objects(b, "indicator")
    assert objects(b, "domain-name")[0]["value"] == "login-acme.example"


def test_rejected_consensus_is_no_indicator():
    case = load_case()
    case["correlations"][0]["override"] = {"verdict": "false_positive", "label": None, "note": "fp"}
    assert "[domain-name:value = 'login-acme.example']" not in _indicator_patterns(bundle(case))


def test_possible_and_warninglisted_iocs_need_include_weak():
    case = load_case()
    case["correlations"][0]["confidence_label"] = "possible"
    assert "[domain-name:value = 'login-acme.example']" not in _indicator_patterns(bundle(case))
    weak = bundle(case, include_weak=True)
    dom = next(o for o in objects(weak, "indicator") if "domain-name" in o["pattern"])
    assert dom["confidence"] == 40
    listed = load_case()
    listed["findings"][0]["suppressed_by"] = [{"rule": "SUP-warninglist", "reason": "on warninglist alexa-top", "from": "probable"}]
    assert "[domain-name:value = 'login-acme.example']" not in _indicator_patterns(bundle(listed))
    assert "[domain-name:value = 'login-acme.example']" in _indicator_patterns(bundle(listed, include_weak=True))


def test_context_only_items_are_always_observables():
    case = load_case()
    case["correlations"][0]["tags"] = ["suspicious", "weak_signal", "context_only"]
    assert "[domain-name:value = 'login-acme.example']" not in _indicator_patterns(bundle(case, include_weak=True))


def test_noise_listed_iocs_are_weak():
    """A consensus on a CDN/resolver/sinkhole-listed value stays an observable unless --include-weak."""
    case = load_case()
    case["entities"][0].update(noise=True, noise_kind="cdn")
    assert "[domain-name:value = 'login-acme.example']" not in _indicator_patterns(bundle(case))
    assert prepare(case).indicators["domain:login-acme.example"].weak == "noise"
    assert "[domain-name:value = 'login-acme.example']" in _indicator_patterns(bundle(case, include_weak=True))


def test_hostile_analyst_verdict_confirms_an_indicator():
    """An override verdict 'malicious' (no label) on a single-module finding makes an indicator;
    'false_positive' never does, whatever the label."""
    case = load_case(correlations=[])
    case["findings"] = [f for f in case["findings"] if f["id"] == "f0dom0000000002"]
    case["findings"][0]["tags"] = ["listed"]
    case["findings"][0]["override"] = {"verdict": "malicious", "label": None}
    ind = [o for o in objects(bundle(case), "indicator") if "domain-name" in o["pattern"]]
    assert ind and ind[0]["confidence"] == 90 and ind[0]["description"].startswith("Analyst-confirmed")
    case["findings"][0]["override"] = {"verdict": "false_positive", "label": "confirmed"}
    case["findings"][0]["tags"] = ["phishing"]
    assert not objects(bundle(case), "indicator")


def test_revoked_techniques_resolve_and_invalid_ones_are_dropped():
    case = load_case()
    case["correlations"][0]["attack"] = ["T1656"]  # revoked -> T1684.001
    case["entities"].append({"key": "mitre_technique:not-a-technique", "type": "mitre_technique", "value": "not-a-technique", "display": "x"})
    b = bundle(case)
    names = {o["external_references"][0]["external_id"] for o in objects(b, "attack-pattern")}
    assert "T1684.001" in names and "T1656" not in names and "NOT-A-TECHNIQUE" not in names
    assert attack.stix_id("T1684.001") in {o["id"] for o in objects(b, "attack-pattern")}
    from v3lum.report.misp import event

    tags = [t["name"] for t in event(case)["Event"]["Tag"]]
    assert 'misp-galaxy:mitre-attack-pattern="Impersonation - T1684.001"' in tags


def test_cidr_indicators_use_issubset():
    case = load_case()
    case["entities"].append({"key": "cidr:198.51.100.0/24", "type": "cidr", "value": "198.51.100.0/24", "display": "198.51.100.0/24"})
    case["correlations"][0]["entities"].append("cidr:198.51.100.0/24")
    assert "[ipv4-addr:value ISSUBSET '198.51.100.0/24']" in _indicator_patterns(bundle(case))


def test_view_exposes_the_gating_for_other_exporters():
    view = prepare(load_case())
    assert view.is_indicator("domain:login-acme.example")
    assert not view.is_indicator("ipv4:203.0.113.10")
    assert view.indicators["domain:login-acme.example"].basis == "consensus"
    assert view.indicators["sha256:" + "a3f1" * 16].basis == "confirmed"


# --------------------------------------------------------------------------------------
# escaping (P303 cond 7)
# --------------------------------------------------------------------------------------


def test_pattern_literals_escape_quotes_and_backslashes():
    assert pattern_literal("it's\\x") == "'it\\'s\\\\x'"
    case = load_case()
    case["correlations"][0]["entities"].append("url:https://login-acme.example/it's\\path?x=1")
    ind = [o for o in objects(bundle(case), "indicator") if o["pattern"].startswith("[url:")]
    assert ind[0]["pattern"] == "[url:value = 'https://login-acme.example/it\\'s\\\\path?x=1']"


def test_email_with_a_quote_cannot_break_the_pattern():
    case = load_case()
    value = "o'brien\\x@acme-corp.example"
    case["entities"].append({"key": f"email:{value}", "type": "email", "value": value, "display": value})
    case["correlations"].append({
        "id": "c0cr27email0001", "rule": "multi_source_malicious", "title": "sender listed by 3 independent upstream families",
        "severity": "high", "entities": [f"email:{value}"], "tags": ["malicious"], "confidence_label": "confirmed",
        "criterion": "3 independent upstream families", "evidence": [],
    })
    ind = [o for o in objects(bundle(case, include_personal=True), "indicator") if o["pattern"].startswith("[email-addr:")]
    assert ind[0]["pattern"] == "[email-addr:value = 'o\\'brien\\\\x@acme-corp.example']"
    assert ind[0]["confidence"] == 90
    assert not [o for o in objects(bundle(case), "indicator") if "email-addr" in o["pattern"]]


# --------------------------------------------------------------------------------------
# cross-case references (A2 BR10, P375 cond 3) and platform markings (A12)
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("tlp", ["clear", "green"])
def test_cross_case_references_omitted_at_clear_and_green(tlp):
    text = text_of(bundle(load_case(tlp=tlp), include_personal=True))
    assert OTHER_CASE not in text and "previous case" not in text and "Recurrent" not in text
    assert "MISP event #4211" not in text and "2026-10-01" not in text


@pytest.mark.parametrize("tlp", ["amber", "amber+strict"])
def test_amber_exports_carry_counts_only(tlp):
    text = text_of(bundle(load_case(tlp=tlp), include_personal=True))
    assert "seen in 2 previous cases" in text
    assert OTHER_CASE not in text and "2026-10-01" not in text and "verdict malicious" not in text
    assert "MISP event #4211" not in text  # internal platforms' event ids are cross-case references too


def test_results_marked_above_the_case_tlp_are_withheld():
    b = bundle(load_case())
    text = text_of(b)
    assert "RED-marked platform hit" not in text
    desc = objects(b, "report")[0]["description"]
    assert "above the case TLP" not in desc and "internal sighting" not in desc  # not even a count of them
    assert "RED-marked platform hit" in text_of(bundle(load_case(tlp="red")))


def test_amber_exports_carry_the_visible_count_only():
    """A2 BR10 / P375 cond 3: the restricted count never travels, and an item resting only on
    restricted (higher-TLP) cases is dropped."""
    b = bundle(load_case())
    notes = {o["abstract"]: o["content"] for o in objects(b, "note")}
    assert notes["[MEDIUM/probable] Recurrent infrastructure"].startswith("The same indicator appears in 2 earlier V3LUM cases")
    assert "[LOW/confirmed] seen in 2 previous cases" in notes
    restricted_only = load_case()
    restricted_only["entities"][1]["attributes"]["sightings"][0]["value"].update(count=0, restricted=3)
    restricted_only["findings"][3]["data"].update(count=0, restricted=3)
    text = text_of(bundle(restricted_only))
    assert "restricted" not in text and "previous case" not in text and "Recurrent infrastructure" not in text
    view = prepare(load_case())
    sightings = view.nodes["ipv4:203.0.113.10"]["attributes"]["sightings"]
    assert sightings == [{"value": {"count": 2}, "source": "case_sightings"}]


def test_stable_ids_keep_one_created_time_across_cases():
    """STIX versioning: an object id shared by several cases keeps its ``created``; a later case
    is a newer ``modified`` version."""
    a = {o["id"]: o for o in bundle(load_case())["objects"]}
    b = {o["id"]: o for o in bundle(load_case(case_id="20261127-120000-ffee", created="2026-11-27T12:00:00+00:00"))["objects"]}
    for oid in set(a) & set(b):
        if "created" in a[oid]:
            assert a[oid]["created"] == b[oid]["created"], oid
            assert a[oid].get("modified", "") <= b[oid].get("modified", ""), oid
    ind = next(o for o in a.values() if o["type"] == "indicator")
    assert ind["created"] == stix.GLOBAL_TS and ind["modified"] == "2026-11-26T10:00:00.000Z"
    old = bundle(load_case(created="2025-03-01T00:00:00+00:00"))
    for o in objects(old):
        if "created" in o and "modified" in o:
            assert o["modified"] >= o["created"], o["id"]


# --------------------------------------------------------------------------------------
# licence banner (A1)
# --------------------------------------------------------------------------------------


def test_research_cases_carry_the_licence_banner():
    case = load_case(licence_profile="research", licence_used={"sansisc.api": {"class": "noncommercial", "basis": "research:LEGAL-7"}})
    report = objects(bundle(case), "report")[0]
    assert "LICENCE: research profile" in report["description"] and "sansisc.api (noncommercial, research:LEGAL-7)" in report["description"]
    assert "LICENCE" not in objects(bundle(load_case()), "report")[0]["description"]


# --------------------------------------------------------------------------------------
# oracle (dev only)
# --------------------------------------------------------------------------------------


def test_stix2_oracle_validates_the_bundles():
    stix2 = pytest.importorskip("stix2")
    for b in (bundle(load_case()), bundle(load_case(tlp="amber+strict"), include_personal=True, include_weak=True)):
        parsed = stix2.parse(b, allow_custom=False)
        assert len(parsed.objects) == len(b["objects"])
        for obj in b["objects"]:
            if obj["type"] in ("domain-name", "ipv4-addr", "url", "file", "autonomous-system", "email-addr", "user-account", "x509-certificate", "mac-addr"):
                assert stix2.parse(obj).id == obj["id"]


def test_stix2_patterns_oracle_accepts_every_pattern():
    validate = pytest.importorskip("stix2patterns.validator").run_validator
    for o in objects(bundle(load_case(), include_weak=True), "indicator"):
        assert validate(o["pattern"], stix_version="2.1") == [], o["pattern"]


def test_bundle_text_never_contains_control_characters():
    case = load_case()
    case["findings"][1]["description"] = "evil\x1b[31m text\x07"
    assert not re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "".join(o.get("content", "") for o in objects(bundle(case), "note")))


def test_engine_case_with_personal_seeds_exports_no_personal_value(clean_registry):
    """Acceptance on a real engine case: an e-mail and a CPF seed, a module that names the e-mail in
    its finding text and pivots to a domain - the default export carries neither value."""
    from tests.fakes import FakeHttp, define_module, make_runtime
    from v3lum.core.context import ScanOptions
    from v3lum.core.engine import Engine
    from v3lum.core.entities import Entity

    def run(self, entity, ctx):
        res = self.result(entity)
        res.finding(f"Mailbox {entity.value} exposed on a paste site", "medium", criterion="synthetic paste match", tags=["exposure"])
        res.pivot(EntityType.DOMAIN, "acme-corp.example", "email_domain")
        return res

    define_module("t_wp21_mail", [EntityType.EMAIL], run)
    rt = make_runtime(FakeHttp())
    options = ScanOptions(include={"t_wp21_mail"}, tlp="amber", purpose="phishing report")
    case = Engine(rt, options).investigate([Entity.make("email", "maria.teste@acme-corp.example"), Entity.make("cpf", "52998224725")]).to_dict()
    text = text_of(bundle(case))
    for value in ("maria.teste", "52998224725", "529.982.247-25"):
        assert value not in text
    assert objects(bundle(case), "domain-name")[0]["value"] == "acme-corp.example"
    assert all(o.get("object_marking_refs") for o in bundle(case)["objects"] if o["type"] != "marking-definition")
