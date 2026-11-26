"""Vocabulary v2 (WP01): core names, fragments, re-declarations, errors, strict checks, timeline."""

from __future__ import annotations

import json
import logging

import pytest

from v3lum.core import vocab


@pytest.fixture()
def fragments(tmp_path, monkeypatch):
    """A temporary fragment directory; the real merge is restored afterwards."""
    directory = tmp_path / "vocab"
    directory.mkdir()
    monkeypatch.setattr(vocab, "FRAGMENT_DIR", directory)
    vocab.reload()
    yield directory
    monkeypatch.undo()
    vocab.reload()


def write(directory, name, doc):
    path = directory / name
    path.write_text(doc if isinstance(doc, str) else json.dumps(doc), encoding="utf-8")
    return path


def test_core_v2_names_present():
    for name in ("presence", "sightings", "is_sinkhole", "is_parked", "intercepted_by", "generic_address", "watch_hits"):
        assert vocab.is_known_attribute(name), name
    for name in ("own_asset", "third_party", "hosted_on_legit_platform", "sinkhole", "parked", "benign_scanner", "recipient_token",
                 "version_inferred", "high_collision", "weak_signal", "verified_fi", "unknown_operator", "context_only"):
        assert vocab.is_known_tag(name), name
    for name in ("similar_to", "same_m365_tenant"):
        assert vocab.is_known_relation(name), name
    assert "never scored" in vocab.TAGS["context_only"]


def test_core_names_follow_the_pattern():
    for table in (vocab.ATTRIBUTES, vocab.TAGS, vocab.RELATIONS):
        for name, desc in table.items():
            assert vocab.NAME_RE.match(name), name
            assert desc.strip(), name


def test_shipped_tree_has_no_vocab_errors():
    vocab.reload()
    assert vocab.errors() == []


def test_fragment_merge_in_file_order(fragments):
    write(fragments, "b_pack.json", {
        "schema": "v3lum.vocab/1",
        "attributes": {"zz_second": "from b", "zz_first": "b redeclares it"},
        "tags": {"zz_tag": "a pack tag"},
    })
    write(fragments, "a_pack.json", {
        "schema": "v3lum.vocab/1",
        "attributes": {"zz_first": "from a", "country": "pack re-declares a core name"},
        "relations": {"zz_rel": "x -> y"},
    })
    vocab.reload()
    attrs = vocab.attributes()
    assert attrs["zz_first"] == "from a"  # a_pack is read first: first description wins
    assert attrs["zz_second"] == "from b"
    assert attrs["country"] == vocab.ATTRIBUTES["country"]  # core first
    assert vocab.is_known_tag("zz_tag") and vocab.is_known_relation("zz_rel")
    assert "zz_tag" in vocab.tags() and "zz_rel" in vocab.relations()
    assert set(vocab.redeclarations()) == {("attribute", "country", "a_pack.json"), ("attribute", "zz_first", "b_pack.json")}
    assert vocab.errors() == []
    assert vocab.fragment_files() == ["a_pack.json", "b_pack.json"]


def test_malformed_fragments_are_reported_not_raised(fragments):
    write(fragments, "broken.json", "{not json")
    write(fragments, "wrong_schema.json", {"schema": "v3lum.vocab/0", "attributes": {"zz_a": "x"}})
    write(fragments, "list.json", [1, 2])
    write(fragments, "bad_entries.json", {
        "schema": "v3lum.vocab/1",
        "attributes": {"Bad-Name": "x", "zz_empty": "", "zz_ok": "fine", "zz_num": 3},
        "tags": ["not", "an", "object"],
        "surprise": {},
    })
    vocab.reload()
    errs = "\n".join(vocab.errors())
    assert "broken.json" in errs and "invalid JSON" in errs
    assert "wrong_schema.json" in errs and "list.json" in errs
    assert "'Bad-Name'" in errs and "'zz_empty'" in errs and "'zz_num'" in errs
    assert "'tags' must be an object" in errs and "'surprise'" in errs
    assert vocab.is_known_attribute("zz_ok")  # the valid entries of a partly bad file still load
    assert not vocab.is_known_attribute("zz_a")


def test_timeline_section(fragments):
    write(fragments, "breach_pack.json", {
        "schema": "v3lum.vocab/1",
        "attributes": {"first_seen_breach": "ISO date of the oldest breach listing the entity"},
        "timeline": {"first_seen_breach": "first seen in a breach", "zz_unknown_date": "nope", "created": "overridden label"},
    })
    vocab.reload()
    timeline = vocab.timeline_attributes()
    assert timeline["first_seen_breach"] == "first seen in a breach"
    assert timeline["created"] == "registered/created"  # core labels win
    assert "zz_unknown_date" not in timeline
    assert any("zz_unknown_date" in e and "not in the merged vocabulary" in e for e in vocab.errors())
    assert set(vocab.CORE_TIMELINE) <= set(timeline)


def test_check_strict_raises(monkeypatch):
    monkeypatch.setenv("V3LUM_STRICT", "1")
    assert vocab.strict_enabled()
    assert vocab.check("attribute", "country")
    with pytest.raises(vocab.UnknownVocab) as info:
        vocab.check("tag", "no_such_tag_xyz", module="m")
    assert info.value.kind == "tag" and info.value.name == "no_such_tag_xyz"
    assert isinstance(info.value, vocab.ContractViolation)
    with pytest.raises(ValueError):
        vocab.check("colour", "red")


def test_check_non_strict_logs_once(monkeypatch, caplog):
    monkeypatch.setenv("V3LUM_STRICT", "0")
    assert not vocab.strict_enabled()
    caplog.set_level(logging.WARNING, logger="v3lum.contract")
    assert vocab.check("relation", "no_such_rel_xyz", module="t_mod_a") is False
    assert vocab.check("relation", "no_such_rel_xyz", module="t_mod_a") is False
    assert vocab.check("relation", "no_such_rel_xyz", module="t_mod_b") is False
    logged = [r.getMessage() for r in caplog.records if "no_such_rel_xyz" in r.getMessage()]
    assert len(logged) == 2  # once per (module, name)


def test_core_tables_are_consulted_live():
    # tests.fakes.allow_vocab extends the core tables without a reload
    vocab.TAGS["zz_live_tag"] = "temporary"
    try:
        assert vocab.is_known_tag("zz_live_tag") and "zz_live_tag" in vocab.tags()
    finally:
        del vocab.TAGS["zz_live_tag"]
    assert not vocab.is_known_tag("zz_live_tag")


def test_a_first_load_inside_a_temporary_extension_does_not_keep_the_name(monkeypatch):
    """The fragment state never snapshots the core tables: when the vocabulary is first loaded
    while allow_vocab-style names are present, removing them still makes them unknown (no leak
    into later tests, whatever the test order)."""
    monkeypatch.setattr(vocab, "_STATE", vocab._State())  # not loaded yet
    vocab.ATTRIBUTES["zz_first_load_attr"] = "temporary"
    try:
        assert "zz_first_load_attr" in vocab.attributes()  # triggers the first load
        assert vocab.is_known_attribute("zz_first_load_attr")
    finally:
        del vocab.ATTRIBUTES["zz_first_load_attr"]
    assert not vocab.is_known_attribute("zz_first_load_attr")
    assert "zz_first_load_attr" not in vocab.attributes()
    assert list(vocab.attributes())[: len(vocab.ATTRIBUTES)] == list(vocab.ATTRIBUTES)  # core first
