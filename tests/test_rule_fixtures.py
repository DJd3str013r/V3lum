"""Rule-fixture harness (WP01, module_author_contract section 16).

Every ``tests/fixtures/rules/<rule_id>/positive_*.json`` and ``negative_*.json`` graph fixture
(schema ``v3lum.graph_fixture/1``) is run through ``correlate.run_rules(graph, results,
only={rule_id}, rctx=rctx)``: a positive fixture needs at least ``expect.min`` (default 1) and at
most ``expect.max`` correlations of the rule (each matching ``expect.severity`` /
``expect.confidence_label`` when given); a negative fixture needs none. The format is documented
in tests/fixtures/rules/README.md.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

from v3lum.core import correlate
from v3lum.core.correlate import RULE_ERRORS, RULES, check_fixture, load_graph_fixture, rule
from v3lum.core.entities import Entity, EntityType
from v3lum.core.models import Correlation, ModuleResult, Severity

RULE_FIXTURES = Path(__file__).parent / "fixtures" / "rules"


def discover() -> list[tuple[str, Path]]:
    if not RULE_FIXTURES.is_dir():
        return []
    out = []
    for directory in sorted(p for p in RULE_FIXTURES.iterdir() if p.is_dir()):
        for path in sorted(directory.glob("*.json")):
            if path.name.startswith(("positive_", "negative_")):
                out.append((directory.name, path))
    return out


CASES = discover()


@pytest.mark.parametrize(("rule_id", "path"), CASES, ids=[f"{r}/{p.name}" for r, p in CASES])
def test_rule_fixture(rule_id: str, path: Path) -> None:
    problems = check_fixture(rule_id, path)
    assert not problems, f"{rule_id}/{path.name}: " + "; ".join(problems)


def test_every_fixture_dir_has_positive_and_negative() -> None:
    if not RULE_FIXTURES.is_dir():
        pytest.skip("no rule fixtures yet")
    for directory in sorted(p for p in RULE_FIXTURES.iterdir() if p.is_dir()):
        names = [p.name for p in directory.glob("*.json")]
        assert any(n.startswith("positive_") for n in names), f"{directory.name}: no positive_*.json fixture"
        assert any(n.startswith("negative_") for n in names), f"{directory.name}: no negative_*.json fixture"
        stray = [n for n in names if not n.startswith(("positive_", "negative_"))]
        assert not stray, f"{directory.name}: fixture files start with positive_ or negative_: {stray}"


# ------------------------------------------------------------------ the harness itself (sample pair)
@pytest.fixture()
def sample_rule():
    """A context-aware sample rule: own domains with >= 2 malicious findings (min 2 sources)."""
    correlate.load_rules()
    saved_rules, saved_errors = dict(RULES), dict(RULE_ERRORS)

    @rule("t_sample_rule", "Own domain flagged twice", version="2", severity="high", criterion="two feeds flag an own domain")
    def sample(graph, results, rctx):
        threshold = int(rctx.meta.get("min_sources", 2))
        for node in graph.of_type(EntityType.DOMAIN):
            mods = {f.module for f in node.findings if "malicious" in f.tags}
            if node.ownership == "own_asset" and len(mods) >= threshold and rctx.now.year >= 2026:
                yield Correlation(
                    "t_sample_rule", f"{node.entity.display} flagged by {len(mods)} sources", Severity.HIGH, "d",
                    entities=[node.entity], confidence="probable", evidence=sorted(mods),
                )

    yield "t_sample_rule"
    RULES.clear()
    RULES.update(saved_rules)
    RULE_ERRORS.clear()
    RULE_ERRORS.update(saved_errors)


def fixture_doc(*, ownership: str, flagged_by: list[str], expect: dict | None = None) -> dict:
    findings = [
        {"title": f"flagged by {m}", "severity": "high", "confidence": 0.9, "tags": ["malicious"], "module": m, "criterion": "feed verdict"}
        for m in flagged_by
    ]
    return {
        "schema": "v3lum.graph_fixture/1",
        "now": "2026-11-26T12:00:00Z",
        "options": {"mode": "passive", "tlp": "amber", "depth": 1},
        "meta": {"min_sources": 2},
        "nodes": [
            {
                "key": "domain:corp.example", "depth": 0, "seed": True, "ownership": ownership, "criticality": "high", "tlp": "amber",
                "path_confidence": 1.0, "tags": [ownership] if ownership else [],
                "attributes": {"registrar": [{"value": "Example Registrar", "source": "rdap"}], "open_ports": [22, 443]},
                "findings": findings,
            },
            {"key": "ipv4:203.0.113.10", "depth": 1},
        ],
        "edges": [{"src": "domain:corp.example", "dst": "ipv4:203.0.113.10", "relation": "resolves_to", "module": "dns_records", "confidence": 0.9}],
        "results": [{"module": "dns_records", "entity": "domain:corp.example", "status": "ok", "attributes": {"a_records": ["203.0.113.10"]}}],
        "expect": expect or {},
    }


def write(tmp_path: Path, name: str, doc: dict) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def test_sample_positive_and_negative_pair(sample_rule, tmp_path):
    pos = write(tmp_path, "positive_two_feeds.json", fixture_doc(
        ownership="own_asset", flagged_by=["feed_a", "feed_b"],
        expect={sample_rule: {"min": 1, "max": 1, "severity": "high", "confidence_label": "probable"}},
    ))
    neg = write(tmp_path, "negative_third_party.json", fixture_doc(ownership="third_party", flagged_by=["feed_a", "feed_b"]))
    neg_one = write(tmp_path, "negative_one_feed.json", fixture_doc(ownership="own_asset", flagged_by=["feed_a"]))
    assert check_fixture(sample_rule, pos) == []
    assert check_fixture(sample_rule, neg) == []
    assert check_fixture(sample_rule, neg_one) == []


def test_harness_reports_failed_expectations(sample_rule, tmp_path):
    wrong_sev = write(tmp_path, "positive_wrong.json", fixture_doc(
        ownership="own_asset", flagged_by=["feed_a", "feed_b"], expect={sample_rule: {"severity": "critical", "confidence_label": "confirmed", "min": 2}},
    ))
    problems = check_fixture(sample_rule, wrong_sev)
    assert any("severity" in p for p in problems) and any("confidence_label" in p for p in problems) and any("at least 2" in p for p in problems)
    missing = write(tmp_path, "positive_missing.json", fixture_doc(ownership="third_party", flagged_by=["feed_a", "feed_b"]))
    assert check_fixture(sample_rule, missing) == ["expected at least 1 correlation(s), got 0"]
    bad_neg = write(tmp_path, "negative_hit.json", fixture_doc(ownership="own_asset", flagged_by=["feed_a", "feed_b"]))
    assert check_fixture(sample_rule, bad_neg)
    assert check_fixture("t_no_such_rule", bad_neg) == ["no rule registered with id 't_no_such_rule'"]


def test_harness_reports_every_failing_fixture_of_a_broken_rule(tmp_path):
    """An identical error recorded by an earlier fixture (or run) must not hide a later failure."""
    correlate.load_rules()
    saved_rules, saved_errors = dict(RULES), dict(RULE_ERRORS)

    @rule("t_broken_fixture_rule", "Always raises")
    def broken(graph, results):
        raise RuntimeError("boom")

    try:
        first = write(tmp_path, "positive_one.json", fixture_doc(ownership="own_asset", flagged_by=["feed_a"]))
        second = write(tmp_path, "negative_two.json", fixture_doc(ownership="own_asset", flagged_by=["feed_a"]))
        assert any("boom" in p for p in check_fixture("t_broken_fixture_rule", first))
        assert any("boom" in p for p in check_fixture("t_broken_fixture_rule", second))  # same message, still reported
        assert "boom" in RULE_ERRORS["t_broken_fixture_rule"]  # and still visible to the contract test
    finally:
        RULES.clear()
        RULES.update(saved_rules)
        RULE_ERRORS.clear()
        RULE_ERRORS.update(saved_errors)


def test_load_graph_fixture_builds_graph_results_and_context(tmp_path):
    path = write(tmp_path, "positive_x.json", fixture_doc(ownership="own_asset", flagged_by=["feed_a", "feed_b"], expect={"r": {"min": 1}}))
    fx = load_graph_fixture(path)
    node = fx.graph.get("domain:corp.example")
    assert node.seed and node.ownership == "own_asset" and node.criticality == "high" and node.tlp == "amber"
    assert node.tagged("own_asset") and node.tagged("malicious") and not node.tagged("phishing")
    assert node.attr("registrar") == "Example Registrar" and node.attr_sources("registrar") == ["rdap"]
    assert node.attr("open_ports") == [22, 443]  # a bare value is one value from 'fixture'
    assert [f.module for f in node.findings] == ["feed_a", "feed_b"] and all(len(f.id) == 16 for f in node.findings)
    assert fx.graph.edges[0].relation == "resolves_to" and fx.graph.edges[0].confidence_label.value == "confirmed"
    assert isinstance(fx.results[0], ModuleResult) and fx.results[0].entity == Entity.make("domain", "corp.example")
    assert fx.rctx.now == dt.datetime(2026, 11, 26, 12, 0, tzinfo=dt.timezone.utc)
    assert fx.rctx.options.tlp == "amber" and fx.rctx.options.depth == 1 and fx.rctx.meta == {"min_sources": 2}
    assert fx.rctx.org is None and fx.expect == {"r": {"min": 1}}


def test_load_graph_fixture_org_profile(tmp_path):
    orgprofile = pytest.importorskip("v3lum.core.orgprofile")
    doc = fixture_doc(ownership="own_asset", flagged_by=[])
    doc["org_profile"] = {"name": "Corp", "domains": [{"name": "corp.example", "verification": "txt_verified"}]}
    fx = load_graph_fixture(write(tmp_path, "positive_org.json", doc))
    assert isinstance(fx.rctx.org, orgprofile.OrgProfile)


def test_load_graph_fixture_rejects_bad_documents(tmp_path):
    with pytest.raises(ValueError):
        load_graph_fixture(write(tmp_path, "positive_a.json", {"schema": "v3lum.case/1"}))
    doc = fixture_doc(ownership="", flagged_by=[])
    del doc["now"]
    with pytest.raises(ValueError, match="now"):
        load_graph_fixture(write(tmp_path, "positive_b.json", doc))
    doc = fixture_doc(ownership="", flagged_by=[])
    doc["edges"].append({"src": "domain:corp.example", "dst": "domain:missing.example", "relation": "related"})
    with pytest.raises(ValueError, match="unknown node"):
        load_graph_fixture(write(tmp_path, "positive_c.json", doc))
    doc = fixture_doc(ownership="", flagged_by=[])
    doc["nodes"].append({"key": "not_a_type:x"})
    with pytest.raises(ValueError, match="invalid node"):
        load_graph_fixture(write(tmp_path, "positive_d.json", doc))
