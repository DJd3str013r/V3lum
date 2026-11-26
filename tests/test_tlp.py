"""FIRST TLP 2.0 model (WP01, A2): parsing, ordering, markings and the per-module ceiling."""

from __future__ import annotations

import itertools

import pytest

from v3lum.core import tlp
from v3lum.core.tlp import TLP, TLP_VALUES, highest, max_tlp, max_tlp_for_target, parse


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("clear", TLP.CLEAR), ("green", TLP.GREEN), ("amber", TLP.AMBER), ("amber+strict", TLP.AMBER_STRICT), ("red", TLP.RED),
        ("TLP:AMBER+STRICT", TLP.AMBER_STRICT), ("tlp:red", TLP.RED), (" TLP:Green ", TLP.GREEN), ("TLP-AMBER", TLP.AMBER),
        ("amber_strict", TLP.AMBER_STRICT), ("Amber-Strict", TLP.AMBER_STRICT), ("white", TLP.CLEAR), ("TLP:WHITE", TLP.CLEAR),
        (TLP.RED, TLP.RED), (2, TLP.AMBER),
    ],
)
def test_parse_variants(raw, expected):
    assert parse(raw) is expected


@pytest.mark.parametrize("bad", ["", "purple", "amber strict", "TLP:", None, 7, -1, True, 2.0])
def test_parse_rejects(bad):
    with pytest.raises(ValueError):
        parse(bad)


def test_ordering_and_markings():
    assert TLP.CLEAR < TLP.GREEN < TLP.AMBER < TLP.AMBER_STRICT < TLP.RED
    assert TLP_VALUES == ("clear", "green", "amber", "amber+strict", "red")
    assert [t.value_str for t in TLP] == list(TLP_VALUES)
    assert [t.label for t in TLP] == ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"]
    assert TLP.AMBER_STRICT.file_tag == "TLP-AMBER+STRICT" and TLP.RED.file_tag == "TLP-RED"
    assert [t.color for t in TLP] == ["#FFFFFF", "#33FF00", "#FFC000", "#FFC000", "#FF2B2B"]
    for t in TLP:
        assert parse(t.value_str) is t and parse(t.label) is t and parse(t.file_tag) is t


def test_highest():
    assert highest("green", "TLP:AMBER", "clear") is TLP.AMBER
    assert highest("amber+strict", "red", "amber") is TLP.RED
    assert highest() is TLP.CLEAR
    assert highest("", None, "green") is TLP.GREEN
    with pytest.raises(ValueError):
        highest("green", "purple")


def _expected(disclosure, tier, publishes, reuses):
    if publishes:
        return None
    if disclosure in ("none", "internal"):
        return TLP.RED
    if disclosure == "target":
        return TLP.AMBER
    if reuses or tier == "unknown":
        return TLP.GREEN
    return {"trusted": TLP.AMBER_STRICT, "community": TLP.AMBER}[tier]


@pytest.mark.parametrize(
    ("disclosure", "tier", "publishes", "reuses"),
    list(itertools.product(["none", "internal", "third_party", "target"], ["trusted", "community", "unknown"], [False, True], [False, True])),
)
def test_max_tlp_full_table(disclosure, tier, publishes, reuses):
    assert max_tlp(disclosure, tier, publishes_queries=publishes, reuses_queries=reuses) is _expected(disclosure, tier, publishes, reuses)


def test_max_tlp_spot_checks_and_errors():
    assert max_tlp("third_party", "trusted", publishes_queries=False, reuses_queries=False) is TLP.AMBER_STRICT
    assert max_tlp("third_party", "trusted", publishes_queries=False, reuses_queries=True) is TLP.GREEN
    assert max_tlp("third_party", "n/a", publishes_queries=False, reuses_queries=False) is TLP.GREEN  # unknown tier: most restrictive
    assert max_tlp("none", "n/a", publishes_queries=False, reuses_queries=False) is TLP.RED
    assert max_tlp("third_party", "trusted", publishes_queries=True, reuses_queries=False) is None
    with pytest.raises(ValueError):
        max_tlp("somewhere", "trusted", publishes_queries=False, reuses_queries=False)


def test_max_tlp_for_target():
    assert max_tlp_for_target(True, False) is TLP.RED
    assert max_tlp_for_target(True, True) is TLP.AMBER
    assert max_tlp_for_target(False, False) is TLP.AMBER
    assert max_tlp_for_target(False, True) is TLP.AMBER


def test_module_exports():
    for name in ("TLP", "TLP_VALUES", "parse", "highest", "max_tlp", "max_tlp_for_target"):
        assert hasattr(tlp, name)
