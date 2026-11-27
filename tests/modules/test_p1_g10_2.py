"""Offline tests of the p1-G10-2 correlation pack (v3lum/correlations/p1_g10_2.py) over synthetic graph
fixtures (tests/fixtures/rules/g10_*; the CNPJs are documentation values, the names synthetic)."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from tests.fakes import FIXTURES, graph_fixture
from v3lum.core import correlate
from v3lum.core.models import Severity
from v3lum.correlations import p1_g10_2 as pack
from v3lum.correlations.p1_g10_2 import RULE_DEDUP, RULE_HOMONYM

HOMONYM_POSITIVE = FIXTURES / "rules" / RULE_HOMONYM / "positive_common_name_lowered.json"
HOMONYM_NEGATIVE = FIXTURES / "rules" / RULE_HOMONYM / "negative_identifier_match.json"
DEDUP_POSITIVE = FIXTURES / "rules" / RULE_DEDUP / "positive_bulk_file_and_tcu_certificate.json"
DEDUP_NEGATIVE = FIXTURES / "rules" / RULE_DEDUP / "negative_different_lists.json"
OVERRIDE = {"label": "confirmed", "by": "analyst", "reason": "checked by hand (synthetic)", "at": "2026-11-26T12:00:00Z"}


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def run(rule_id: str, doc: dict[str, Any] | Path, tmp_path: Path | None = None, *, times: int = 1):
    if isinstance(doc, dict):
        assert tmp_path is not None
        path = tmp_path / "positive_variant.json"
        path.write_text(json.dumps(doc), encoding="utf-8")
    else:
        path = doc
    graph, results, rctx = graph_fixture(path)
    corrs: list[Any] = []
    for _ in range(times):
        corrs = correlate.run_rules(graph, results, only={rule_id}, rctx=rctx)
    assert rule_id not in correlate.RULE_ERRORS
    return graph, corrs


def findings(graph: Any) -> list[Any]:
    return [f for node in graph.nodes.values() for f in node.findings]


# --------------------------------------------------------------------------------------
# g10_homonym_name_match (P252 cond 1)
# --------------------------------------------------------------------------------------


def test_common_name_match_is_lowered_by_the_documented_curve():
    graph, corrs = run(RULE_HOMONYM, HOMONYM_POSITIVE)
    assert corrs == []  # the rule never emits a correlation of its own
    (f,) = findings(graph)
    assert f.confidence == pytest.approx(0.16)  # 0.5 x (0.4 JOSE >= 1M bearers x 0.8 common surname SILVA)
    assert f.label.value == "possible"
    assert f.data["homonym"] == {"risk": "high", "factor": 0.32, "phrase": "very common name: name-only matches are unreliable"}
    assert [s["rule"] for s in f.suppressed_by] == [RULE_HOMONYM]
    assert "very common name" in f.criterion
    assert f.severity is Severity.MEDIUM  # only the confidence moves


def test_the_curve_is_applied_once():
    graph, _corrs = run(RULE_HOMONYM, HOMONYM_POSITIVE, times=2)
    (f,) = findings(graph)
    assert f.confidence == pytest.approx(0.16) and len(f.suppressed_by) == 1


def test_identifier_matches_are_untouched():
    graph, corrs = run(RULE_HOMONYM, HOMONYM_NEGATIVE)
    (f,) = findings(graph)
    assert corrs == [] and f.suppressed_by == [] and "homonym" not in f.data
    assert f.confidence == pytest.approx(load(HOMONYM_NEGATIVE)["nodes"][0]["findings"][0]["confidence"])


def test_a_rare_name_keeps_its_confidence(tmp_path):
    doc = load(HOMONYM_POSITIVE)
    node = doc["nodes"][0]
    node["key"] = "person_name:TEODORICO EXEMPLAR"
    node["attributes"]["first_name_frequency"][0]["value"] = {"first_name": "TEODORICO", "frequency": 1165, "source": "IBGE nomes API"}
    node["findings"][0]["data"]["matched_name"] = "TEODORICO EXEMPLAR"
    graph, _corrs = run(RULE_HOMONYM, doc, tmp_path)
    (f,) = findings(graph)
    assert f.confidence == pytest.approx(0.5) and f.suppressed_by == []
    assert f.data["homonym"]["risk"] == "low" and f.data["homonym_applied"] is True


def test_the_offline_table_is_used_when_the_node_has_no_frequency(tmp_path, monkeypatch):
    monkeypatch.setattr(pack, "offline_table", lambda *a, **k: {"JOSE": 5754529})
    doc = load(HOMONYM_POSITIVE)
    doc["nodes"][0]["attributes"] = {}
    graph, _corrs = run(RULE_HOMONYM, doc, tmp_path)
    (f,) = findings(graph)
    assert f.confidence == pytest.approx(0.16)


def test_unknown_first_name_without_common_surname_is_neutral(tmp_path, monkeypatch):
    monkeypatch.setattr(pack, "offline_table", lambda *a, **k: {})
    doc = load(HOMONYM_POSITIVE)
    doc["nodes"][0]["attributes"] = {}
    doc["nodes"][0]["key"] = "person_name:XQZVKW EXEMPLAR"
    graph, _corrs = run(RULE_HOMONYM, doc, tmp_path)
    (f,) = findings(graph)
    assert f.confidence == pytest.approx(0.5) and f.data["homonym"]["risk"] == "unknown"


@pytest.mark.parametrize("data", [{"name_type": "company_name"}, {"homonym_applied": True}])
def test_company_names_and_curves_already_applied_are_left_alone(tmp_path, data):
    doc = load(HOMONYM_POSITIVE)
    doc["nodes"][0]["findings"][0]["data"].update(data)
    graph, _corrs = run(RULE_HOMONYM, doc, tmp_path)
    (f,) = findings(graph)
    assert f.confidence == pytest.approx(0.5) and f.suppressed_by == [] and "homonym" not in f.data


def test_an_analyst_override_is_never_crossed(tmp_path):
    doc = load(HOMONYM_POSITIVE)
    doc["nodes"][0]["findings"][0]["override"] = dict(OVERRIDE)
    graph, _corrs = run(RULE_HOMONYM, doc, tmp_path)
    (f,) = findings(graph)
    assert f.confidence == pytest.approx(0.5)
    assert f.suppressed_by and f.suppressed_by[0]["blocked_by"] == "analyst"


# --------------------------------------------------------------------------------------
# g10_sanction_dedup (P239 / P240 cond 4)
# --------------------------------------------------------------------------------------


def test_one_listing_from_two_sources_is_one_finding_of_record():
    graph, corrs = run(RULE_DEDUP, DEDUP_POSITIVE)
    (corr,) = corrs
    assert corr.severity is Severity.INFO and corr.label.value == "confirmed"
    assert corr.title == "One CEIS listing reported by 2 sources"
    bulk, tcu = findings(graph)
    assert bulk.module == "cgu_sanctions_bulk" and bulk.severity is Severity.HIGH and bulk.suppressed_by == []
    assert bulk.data["sources"] == ["cgu_sanctions_bulk", "tcu_certidoes"]
    assert tcu.severity is Severity.INFO and "context_only" in tcu.tags
    assert tcu.data["merged_into"] == bulk.id and tcu.data["severity_before_merge"] == "high"
    assert [s["rule"] for s in tcu.suppressed_by] == [RULE_DEDUP]
    assert sorted(corr.evidence) == sorted([bulk.id, tcu.id])


def test_different_lists_are_never_merged():
    graph, corrs = run(RULE_DEDUP, DEDUP_NEGATIVE)
    assert corrs == []
    assert all(f.severity is Severity.HIGH and f.suppressed_by == [] for f in findings(graph))


def test_a_rerun_keeps_the_correlation_and_never_lowers_twice():
    graph, corrs = run(RULE_DEDUP, DEDUP_POSITIVE, times=2)
    assert len(corrs) == 1
    _bulk, tcu = findings(graph)
    assert [s["rule"] for s in tcu.suppressed_by] == [RULE_DEDUP] and tcu.data["severity_before_merge"] == "high"


def test_an_overridden_duplicate_is_never_merged(tmp_path):
    doc = load(DEDUP_POSITIVE)
    doc["nodes"][0]["findings"][1]["override"] = dict(OVERRIDE)
    graph, corrs = run(RULE_DEDUP, doc, tmp_path)
    assert corrs == []
    _bulk, tcu = findings(graph)
    assert tcu.severity is Severity.HIGH and "merged_into" not in tcu.data


def test_a_certificate_without_id_joins_one_listing_only(tmp_path):
    doc = load(DEDUP_POSITIVE)
    other = copy.deepcopy(doc["nodes"][0]["findings"][0])
    other["key"] = "ceis:900002:11222333000181"
    other["data"].update({"sanction_id": "900002", "dedup_key": "ceis|11222333000181|900002"})
    doc["nodes"][0]["findings"].append(other)
    graph, corrs = run(RULE_DEDUP, doc, tmp_path)
    assert len(corrs) == 1 and "sanction 900001" in corrs[0].description
    bulk1, tcu, bulk2 = findings(graph)
    assert tcu.data["merged_into"] == bulk1.id
    assert bulk2.severity is Severity.HIGH and bulk2.suppressed_by == []  # a second sanction stays a finding


def test_findings_without_the_sanctions_tag_or_key_are_ignored(tmp_path):
    doc = load(DEDUP_POSITIVE)
    doc["nodes"][0]["findings"][1]["tags"] = []
    graph, corrs = run(RULE_DEDUP, doc, tmp_path)
    assert corrs == [] and all(f.suppressed_by == [] for f in findings(graph))
