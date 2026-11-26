"""Bundled ATT&CK index (WP01): canonical ids, validation, STIX ids and fragment merging."""

from __future__ import annotations

import json

import pytest

from v3lum.core import attack


@pytest.fixture()
def fragments(tmp_path, monkeypatch):
    directory = tmp_path / "attack"
    directory.mkdir()
    monkeypatch.setattr(attack, "FRAGMENT_DIR", directory)
    attack.reload()
    yield directory
    monkeypatch.undo()
    attack.reload()


def write(directory, name, doc):
    (directory / name).write_text(doc if isinstance(doc, str) else json.dumps(doc), encoding="utf-8")


def entry(name, stix="", revoked=False, deprecated=False, replaced_by=None):
    return {"name": name, "stix_id": stix, "revoked": revoked, "deprecated": deprecated, "replaced_by": replaced_by}


def test_shipped_core_index():
    attack.reload()
    assert attack.errors() == []
    for tid in ("T1566", "T1566.001", "T1566.002", "T1684.001", "T1656"):
        assert attack.lookup(tid) is not None, tid
    assert attack.lookup("T1566").name == "Phishing"
    assert attack.lookup("T1656").revoked and attack.lookup("T1656").replaced_by == "T1684.001"


def test_canonical_follows_replacements():
    assert attack.canonical("T1656") == "T1684.001"
    assert attack.canonical(" t1656 ") == "T1684.001"
    assert attack.canonical("T1566.001") == "T1566.001"
    assert attack.canonical("T9999") == "T9999"  # unknown ids come back normalized


def test_validate_and_is_valid():
    assert attack.validate(["T1566", "T1566.002", "T1656"]) == []  # revoked with a replacement is fine
    errs = attack.validate(["T9999"])
    assert len(errs) == 1 and "T9999" in errs[0]
    assert attack.validate(["phishing"]) and attack.validate("T9999")
    assert attack.is_valid("T1566") and not attack.is_valid("T1656") and not attack.is_valid("T9999")


def test_stix_ids():
    assert attack.stix_id("T1566") == "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b"
    assert attack.stix_id("T1656") == attack.stix_id("T1684.001")  # revoked -> replacement's object
    assert attack.stix_id("T9999") is None
    assert attack.name("T1656") == "Impersonation"


def test_fragment_merge_first_wins(fragments):
    write(fragments, "a_core.json", {"schema": "v3lum.attack_index/1", "version": "x", "techniques": {
        "T1000": entry("First name"),
        "T1001": entry("Old", revoked=True, replaced_by="T1002"),
    }})
    write(fragments, "b_pack.json", {"schema": "v3lum.attack_index/1", "version": "y", "techniques": {
        "T1000": entry("Second name"),
        "T1002": entry("New"),
        "T1003": entry("Gone", deprecated=True),
        "T1004": entry("Revoked, no replacement", revoked=True),
    }})
    attack.reload()
    assert attack.lookup("T1000").name == "First name"
    assert attack.duplicates() == [("T1000", "b_pack.json")]
    assert attack.canonical("T1001") == "T1002" and attack.validate(["T1001"]) == []
    assert attack.validate(["T1003"]) and attack.validate(["T1004"])
    assert set(attack.techniques()) == {"T1000", "T1001", "T1002", "T1003", "T1004"}
    assert attack.errors() == []


def test_malformed_fragments_reported(fragments):
    write(fragments, "broken.json", "{")
    write(fragments, "schema.json", {"schema": "nope", "techniques": {}})
    write(fragments, "entries.json", {"schema": "v3lum.attack_index/1", "techniques": {
        "t1000": entry("lower-case id"),
        "T1000": {"stix_id": "attack-pattern--x"},
        "T1001": entry("bad stix", stix="indicator--1"),
        "T1002": entry("dangling", revoked=True, replaced_by="T1999"),
        "T1003": entry("self", replaced_by="T1003"),
        "T1004": entry("bool", revoked="yes"),
    }})
    attack.reload()
    errs = "\n".join(attack.errors())
    for needle in ("broken.json", "schema.json", "'t1000'", "'T1000'", "'T1001'", "T1999", "'T1003'", "'T1004'"):
        assert needle in errs, needle


def test_cycle_safe(fragments):
    write(fragments, "cycle.json", {"schema": "v3lum.attack_index/1", "techniques": {
        "T1100": entry("a", revoked=True, replaced_by="T1101"),
        "T1101": entry("b", revoked=True, replaced_by="T1100"),
    }})
    attack.reload()
    assert attack.canonical("T1100") in ("T1100", "T1101")
    assert attack.validate(["T1100"])
