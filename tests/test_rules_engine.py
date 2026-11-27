"""Correlation engine v2 (P301, WP22): data rules ``v3lum.rule/1`` compiled into RuleInfo, one per
analysis method over the graph fixture of tests/fixtures/rules_data/, schema errors, the ReDoS guard,
per-rule precision demotion, the P258 natural-person cap, user rule directories (AR12), the
read-only guarantee and the 500-node time budget."""

from __future__ import annotations

import copy
import dataclasses
import datetime as dt
import json
import os
import sys
import time
from pathlib import Path

import pytest

from v3lum.core import correlate, rules_engine
from v3lum.core.correlate import RULE_ERRORS, RULES, RuleContext, RuleInfo, load_graph_fixture, rule, run_rules
from v3lum.core.entities import Entity, EntityType
from v3lum.core.graph import Graph
from v3lum.core.models import Confidence, Correlation, Finding, Severity
from v3lum.core.rules_engine import RULE_SCHEMA, RuleSchemaError, compile_rule, load_data_rules, regex_problems, validate_rule

DATA = Path(__file__).parent / "fixtures" / "rules_data"
GRAPH = DATA / "graph_infra.json"
NOW = dt.datetime(2026, 11, 26, 12, tzinfo=dt.timezone.utc)


def rule_doc(name: str) -> dict:
    return json.loads((DATA / f"{name}.json").read_text(encoding="utf-8"))


def minimal(**over) -> dict:
    doc = {
        "schema": RULE_SCHEMA, "id": "t_min", "version": "1", "title": "Minimal", "severity": "low", "criterion": "c",
        "collections": [{"name": "domains", "entity_types": ["domain"], "filters": []}],
        "analysis": {"method": "threshold"}, "headline": "{value}", "recommendation": "r",
    }
    doc.update(over)
    return doc


@pytest.fixture()
def fx():
    return load_graph_fixture(GRAPH)


@pytest.fixture()
def rules_sandbox(clean_registry):
    """Rules registered inside the test are dropped afterwards (registry_snapshot); the user-rule
    report of the last load is restored too."""
    saved = list(correlate._USER_REPORT)
    yield RULES
    correlate._USER_REPORT[:] = saved


def run_doc(doc: dict, fixture, *, purpose: str = "") -> list[Correlation]:
    info = compile_rule(doc)
    if purpose:
        fixture.rctx.options.purpose = purpose
    return info.fn(fixture.graph, fixture.results, fixture.rctx)


# ------------------------------------------------------------------ one data rule per analysis method
def test_threshold_rule_buckets_by_relation(fx):
    [corr] = run_doc(rule_doc("threshold_shared_ip"), fx)
    keys = corr.entity_keys()
    assert keys[0] == "ipv4:198.51.100.7"  # the shared neighbour first
    assert set(keys[1:]) == {"domain:own.example", "domain:d01.example.org", "domain:d02.example.org", "domain:d03.example.org", "domain:d06.example.org"}
    assert corr.title == "5 domains resolve to 198.51.100.7" and corr.rule == "t_threshold_shared_ip"
    assert corr.why.startswith("threshold: relation:resolves_to '198.51.100.7' holds 5 entities")
    assert "relation:resolves_to=198.51.100.7" in corr.evidence and "count=5" in corr.evidence
    assert corr.recommendation and "test rule (threshold)" in corr.criterion and corr.tags == ["infrastructure"]
    # the parked member triggers the named suppression: downgraded with a visible label, never deleted
    assert corr.label is Confidence.POSSIBLE and corr.severity is Severity.LOW
    # the severity change is part of the visible label (from/to), next to the label change
    assert corr.suppressed_by == [{"rule": "t_threshold_shared_ip:parked", "reason": "a parked domain shares hosting by design",
                                   "from": "medium", "to": "low"}]
    assert "a parked domain shares hosting by design" in corr.criterion


def test_threshold_maximum_and_minimum(fx):
    doc = rule_doc("threshold_shared_ip")
    doc["analysis"] = {"method": "threshold", "minimum": 6}
    assert run_doc(doc, fx) == []
    doc["analysis"] = {"method": "threshold", "minimum": 1, "maximum": 1}
    [single] = run_doc(doc, fx)
    assert single.entity_keys() == ["ipv4:203.0.113.9", "domain:d07.example.org"]


def test_outlier_rule_and_noisy_guard(fx):
    [corr] = run_doc(rule_doc("outlier_registrar"), fx)
    assert corr.entity_keys() == ["domain:d00.example.org"]
    assert corr.title == "1 domain(s) use the rare registrar Rare Registrar Ltd (8.3% of 12)"
    assert "share=8.3%" in corr.evidence and corr.why.startswith("outlier:")
    doc = rule_doc("outlier_registrar")
    doc["analysis"]["minimum"] = 13  # fewer entities than the minimum: no analysis at all
    assert run_doc(doc, fx) == []
    doc = rule_doc("outlier_registrar")
    doc["analysis"]["noisy_percent"] = 60  # 2 buckets -> average share 50% < 60%: too flat to call outliers
    assert run_doc(doc, fx) == []


def test_first_collection_only_rule(fx):
    [corr] = run_doc(rule_doc("first_collection_only_ct"), fx)
    assert corr.entity_keys() == ["domain:d04.example.org"]
    assert corr.title == "d04.example.org appears only in ct"
    finding_ids = [f.id for f in fx.graph.get("domain:d04.example.org").findings]
    assert finding_ids and finding_ids[0] in corr.evidence  # the finding ids used, then the facts


def test_match_all_to_first_collection_subnet_rule(fx):
    [corr] = run_doc(rule_doc("match_subnet"), fx)
    assert corr.entity_keys() == ["cidr:198.51.100.0/24", "ipv4:198.51.100.7"]  # 203.0.113.9 is outside the netblock
    assert "match=subnet" in corr.evidence
    doc = rule_doc("match_subnet")
    doc["analysis"]["match"] = "exact"
    assert run_doc(doc, fx) == []


def test_both_collections_rule(fx):
    [corr] = run_doc(rule_doc("both_collections_shared_ip"), fx)
    assert corr.entity_keys() == ["ipv4:198.51.100.7", "domain:d01.example.org", "domain:own.example"]
    assert corr.severity is Severity.HIGH and corr.label is Confidence.PROBABLE
    assert corr.title == "198.51.100.7 hosts an own domain and a flagged one (d01.example.org, own.example)"


def test_context_only_and_noise_never_count(fx):
    """d06 carries only a context_only 'malicious' finding: it is no evidence for tag:malicious."""
    doc = minimal(collections=[{"name": "bad", "entity_types": ["domain"], "filters": [{"field": "tag:malicious", "op": "exists"}]}])
    [bad] = run_doc(doc, fx)
    assert bad.entity_keys() == ["domain:d01.example.org"]
    # P301 cond 6: the evidence lists the finding that carried the filtered tag (finding ids + facts)
    tagged = [f.id for f in fx.graph.get("domain:d01.example.org").findings if "malicious" in f.tags]
    assert tagged and set(tagged) <= set(bad.evidence)
    g = Graph(noise_check=False)
    node, _ = g.add_node(Entity.make("domain", "noisy.example"), 0, seed=True)
    node.noise = True
    plain = minimal()
    info = compile_rule(plain)
    assert info.fn(g, [], None) == []
    plain["collections"][0]["include_noise"] = True
    assert [c.entity_keys() for c in compile_rule(plain).fn(g, [], None)] == [["domain:noisy.example"]]


def test_filters_negate_in_regex_and_numeric(fx):
    doc = minimal(collections=[{"name": "d", "entity_types": ["domain"], "filters": [
        {"field": "attr:registrar", "op": "in", "value": ["rare registrar ltd", "other"]},
    ]}])
    assert [c.entity_keys() for c in run_doc(doc, fx)] == [["domain:d00.example.org"]]
    doc["collections"][0]["filters"] = [{"field": "attr:registrar", "op": "exists"}, {"field": "value", "op": "regex", "value": "^d0[0-2]\\."}]
    assert sorted(c.entity_keys()[0] for c in run_doc(doc, fx)) == ["domain:d00.example.org", "domain:d01.example.org", "domain:d02.example.org"]
    doc["collections"][0]["filters"][1]["negate"] = True
    assert len(run_doc(doc, fx)) == 9
    doc["collections"][0]["filters"] = [{"field": "relation:resolves_to", "op": "gte", "value": 1}, {"field": "type", "op": "in", "value": ["domain"]}]
    assert len(run_doc(doc, fx)) == 6
    doc["collections"][0]["filters"] = [{"field": "finding.severity", "op": "gte", "value": "high"}]
    assert [c.entity_keys() for c in run_doc(doc, fx)] == [["domain:d01.example.org"]]  # d06's high finding is context only


# ------------------------------------------------------------------ same shapes as Python rules (acceptance)
def test_data_rule_and_python_rule_share_ruleinfo_and_correlation_shapes(rules_sandbox, fx):
    data_info = compile_rule(rule_doc("threshold_shared_ip"), path=DATA / "threshold_shared_ip.json")
    correlate.register_rule(data_info)

    @rule("t_py_shared_ip", "Several domains share one IP (Python)", severity="medium", criterion="test rule (threshold)",
          references=("https://github.com/smicallef/spiderfoot",), false_positives="synthetic test rule")
    def py_rule(graph, results, rctx):
        for ip in graph.of_type(EntityType.IPV4):
            doms = [graph.nodes[e.src] for e in graph.in_edges(ip.key, "resolves_to")]
            if len(doms) >= 3:
                yield Correlation("t_py_shared_ip", f"{len(doms)} domains resolve to {ip.entity.display}", Severity.MEDIUM, "d",
                                  entities=[ip.entity] + [d.entity for d in doms], confidence="possible", evidence=[f"count={len(doms)}"],
                                  recommendation="Review the listed entities.", tags=["infrastructure"])

    py_info = RULES["t_py_shared_ip"]
    assert type(py_info) is type(data_info) is RuleInfo
    assert {f.name for f in dataclasses.fields(py_info)} == {f.name for f in dataclasses.fields(data_info)}
    assert (data_info.kind, py_info.kind) == ("data", "python") and data_info.takes_context and py_info.takes_context
    for name in ("version", "severity", "criterion", "references", "false_positives", "legacy"):
        assert getattr(data_info, name) == getattr(py_info, name), name
    out = run_rules(fx.graph, fx.results, only={"t_threshold_shared_ip", "t_py_shared_ip"}, rctx=fx.rctx)
    by_rule = {c.rule: c for c in out}
    data_corr, py_corr = by_rule["t_threshold_shared_ip"], by_rule["t_py_shared_ip"]
    assert type(data_corr) is type(py_corr) is Correlation
    dd, pd = data_corr.to_dict(), py_corr.to_dict()
    assert set(dd) == set(pd)
    assert {k: type(v) for k, v in dd.items()} == {k: type(v) for k, v in pd.items()}
    assert dd["entities"][0] == pd["entities"][0] == "ipv4:198.51.100.7" and len(dd["id"]) == len(pd["id"]) == 16
    assert set(dd["entities"]) == set(pd["entities"]) and dd["severity"] == "low" and pd["severity"] == "medium"  # data rule: parked suppression
    assert dd["why"] and pd["why"] == "test rule (threshold)"  # run_rules fills a one-line why for every rule
    rows = {r["id"]: r for r in correlate.rules_listing()}
    assert set(rows["t_threshold_shared_ip"]) == set(rows["t_py_shared_ip"])
    assert rows["t_threshold_shared_ip"]["kind"] == "data"


def test_compiled_rule_metadata_and_attack_canonicalised(rules_sandbox, fx):
    doc = rule_doc("threshold_shared_ip")
    doc["attack"] = ["T1656"]  # revoked -> T1684.001
    doc["code"] = "CR90"
    info = correlate.register_rule(compile_rule(doc))
    assert info.attack == ("T1684.001",) and info.code == "CR90" and info.origin == "data:t_threshold_shared_ip"
    [corr] = run_rules(fx.graph, [], only={"t_threshold_shared_ip"}, rctx=fx.rctx)
    assert corr.attack == ["T1684.001"] and corr.version == "1"
    assert "t_threshold_shared_ip" not in RULE_ERRORS


# ------------------------------------------------------------------ schema errors
@pytest.mark.parametrize(("change", "needle"), [
    ({"schema": "v3lum.rule/0"}, "schema must be"),
    ({"id": "Bad-Id"}, "id must match"),
    ({"severity": "urgent"}, "severity must be"),
    ({"criterion": ""}, "criterion is required"),
    ({"analysis": {"method": "magic"}}, "analysis.method must be one of"),
    ({"analysis": {"method": "both_collections"}}, "needs at least two collections"),
    ({"headline": "{value.__class__}"}, "placeholder"),
    ({"headline": "{secret}"}, "is not allowed"),
    ({"headline": "{value"}, "unbalanced brace"),
    ({"attack": ["T9999"]}, "not in the bundled ATT&CK index"),
    ({"aggregation": {"field": "attr:not_a_vocab_name"}}, "not in the vocabulary"),
    ({"collections": [{"name": "d", "entity_types": ["spaceship"]}]}, "unknown entity type"),
    ({"collections": [{"name": "d", "entity_types": ["domain"], "filters": [{"field": "tag:malicious", "op": "eq", "value": "x"}]}]}, "op 'exists' only"),
    ({"collections": [{"name": "d", "entity_types": ["domain"], "filters": [{"field": "value", "op": "regex", "value": "(a+)+"}]}]}, "nested quantifier"),
    ({"suppress": [{"name": "up", "when": {"field": "tag:parked", "op": "exists"}, "severity": "critical", "reason": "r"}]}, "only downgrades"),
    ({"eval": "__import__('os')"}, "unknown keys"),
    ({"references": ["http://insecure.example"]}, "https"),
    ({"references": ["https://dehashed.com/search?query=x"]}, "forbidden service"),  # people-search/leak host (P327 tables)
    ({"tags": ["analyst_confirmed"]}, "reserved"),  # a rule can never forge the analyst confirmation that lifts the P258 cap
    ({"tags": ["precision_demoted"]}, "reserved"),
    ({"collections": [{"name": "d", "entity_types": ["domain"], "filters": [{"field": "value", "op": "regex", "value": "\\w*\\w*x"}]}]},
     "adjacent unbounded repeats"),
])
def test_schema_errors_are_reported(change, needle):
    problems = validate_rule(minimal(**change))
    assert any(needle in p for p in problems), problems
    with pytest.raises(RuleSchemaError) as err:
        compile_rule(minimal(**change))
    assert needle in str(err.value) and err.value.problems


def test_schema_errors_go_to_rule_errors_and_never_stop_other_files(tmp_path, rules_sandbox):
    (tmp_path / "good.json").write_text(json.dumps(minimal(id="t_good_rule")), encoding="utf-8")
    (tmp_path / "bad.json").write_text(json.dumps(minimal(id="t_bad_rule", severity="urgent")), encoding="utf-8")
    (tmp_path / "broken.toml").write_text("not = [valid", encoding="utf-8")
    (tmp_path / "rule.yaml").write_text("schema: v3lum.rule/1\n", encoding="utf-8")  # bundled: never YAML (not even listed)
    loaded = load_data_rules(tmp_path)
    assert [i.id for i in loaded] == ["t_good_rule"] and RULES["t_good_rule"].kind == "data"
    assert "severity must be" in RULE_ERRORS["bad.json"] and "invalid TOML" in RULE_ERRORS["broken.toml"]
    assert "rule.yaml" not in RULE_ERRORS
    errors: dict[str, str] = {}
    load_data_rules(tmp_path, register=False, errors=errors)
    assert set(errors) == {"bad.json", "broken.toml"}


def test_bundled_rule_directory_is_compiled_by_load_rules(tmp_path, monkeypatch, rules_sandbox):
    (tmp_path / "t_bundled.json").write_text(json.dumps(minimal(id="t_bundled_data_rule")), encoding="utf-8")
    (tmp_path / "t_broken.json").write_text(json.dumps(minimal(id="t_broken_data_rule", analysis={})), encoding="utf-8")
    (tmp_path / "t_yaml.yaml").write_text("id: x\n", encoding="utf-8")
    monkeypatch.setattr(correlate, "RULES_DATA_DIR", tmp_path)
    correlate._load_data_rules()
    assert RULES["t_bundled_data_rule"].kind == "data" and RULES["t_bundled_data_rule"].origin.endswith("t_bundled.json")
    assert "analysis.method" in RULE_ERRORS["t_broken.json"]
    assert "JSON or TOML" in RULE_ERRORS["t_yaml.yaml"]


def test_toml_rule_file(tmp_path):
    pytest.importorskip("tomllib")
    path = tmp_path / "t_toml.toml"
    path.write_text(
        'schema = "v3lum.rule/1"\nid = "t_toml_rule"\nversion = "2"\ntitle = "TOML rule"\nseverity = "info"\ncriterion = "c"\n'
        'headline = "{value}"\nrecommendation = "r"\n[analysis]\nmethod = "threshold"\n'
        '[[collections]]\nname = "domains"\nentity_types = ["domain"]\n',
        encoding="utf-8",
    )
    [info] = load_data_rules(tmp_path, register=False)
    assert (info.id, info.version, info.kind) == ("t_toml_rule", "2", "data")


def test_yaml_needs_the_optional_extra(tmp_path, monkeypatch):
    path = tmp_path / "t.yaml"
    path.write_text("schema: v3lum.rule/1\n", encoding="utf-8")
    monkeypatch.setitem(sys.modules, "yaml", None)  # the extra is not installed
    with pytest.raises(ValueError, match="optional extra 'yaml'"):
        rules_engine.read_rule_file(path, allow_yaml=True)
    with pytest.raises(ValueError, match="JSON or TOML"):
        rules_engine.read_rule_file(path)


def test_yaml_uses_safe_load_only(tmp_path, monkeypatch):
    calls: list[str] = []

    class FakeYaml:
        @staticmethod
        def safe_load(text):
            calls.append("safe_load")
            return {"schema": RULE_SCHEMA}

        @staticmethod
        def load(text, Loader=None):  # pragma: no cover - must never be used
            raise AssertionError("yaml.load is never used")

    monkeypatch.setitem(sys.modules, "yaml", FakeYaml)
    path = tmp_path / "t.yml"
    path.write_text("schema: v3lum.rule/1\n", encoding="utf-8")
    assert rules_engine.read_rule_file(path, allow_yaml=True) == {"schema": RULE_SCHEMA} and calls == ["safe_load"]


def test_oversized_rule_file_is_refused(tmp_path):
    path = tmp_path / "big.json"
    path.write_text(json.dumps(minimal(description="x" * (rules_engine.MAX_RULE_BYTES + 10))), encoding="utf-8")
    with pytest.raises(ValueError, match="larger than"):
        rules_engine.read_rule_file(path)


# ------------------------------------------------------------------ ReDoS guard
@pytest.mark.parametrize("pattern", ["(a+)+$", "(\\w*)*x", "([a-z0-9-]+\\.)+example", "(a|aa)+", "(ab|a)*", "(\\w+)\\1", "x" * 201, "(unclosed", "",
                                     # polynomial (cubic+) backtracking: adjacent unbounded repeats over overlapping characters
                                     "\\w*\\w*x", "a*a*b", ".*.*=", "[a-z]+[a-z]+$", "\\w*\\s*\\w*x", "(?:\\w+)\\w+x", "(?i)[a-z]+[A-Z]+x",
                                     ".*foo.*bar"])
def test_redos_guard_refuses_dangerous_patterns(pattern):
    assert regex_problems(pattern)


@pytest.mark.parametrize("pattern", ["^[a-z0-9-]+\\.example\\.com$", "(?i)acme[-_]?corp", "(foo|bar)+", "^dns\\.", "\\b(?:sha|md)\\d+\\b",
                                     "\\s*\\w+\\s*=\\s*\\w+\\s*;", "^\\w+@\\w+\\.\\w+$", "[A-Z]+[a-z]+x", ".*\\.onion$", ".{0,64}foo.{0,64}bar",
                                     "\\d+\\.\\d+\\.\\d+", "\\w+(?=@)"])
def test_redos_guard_accepts_ordinary_patterns(pattern):
    assert regex_problems(pattern) == []


def test_regex_subject_is_truncated(fx):
    g = Graph(noise_check=False)
    ent = Entity.make("domain", "long.example")
    g.add_node(ent, 0, seed=True)
    g.add_attributes(ent, {"registrar": "a" * 50_000 + "MARKER"}, "rdap")
    doc = minimal(collections=[{"name": "d", "entity_types": ["domain"], "filters": [{"field": "attr:registrar", "op": "regex", "value": "MARKER"}]}])
    started = time.perf_counter()
    assert compile_rule(doc).fn(g, [], None) == []  # the marker lies beyond MAX_REGEX_INPUT characters
    assert time.perf_counter() - started < 0.5


# ------------------------------------------------------------------ precision demotion (P301 cond 8, P325)
@pytest.fixture()
def demo_rule(rules_sandbox):
    @rule("t_prec_rule", "Precision test rule", severity="high", criterion="always fires")
    def prec(graph, results):
        for node in graph.seeds():
            yield Correlation("t_prec_rule", f"{node.entity.display} flagged", Severity.HIGH, "d", entities=[node.entity], confidence="probable")

    return "t_prec_rule"


def seed_graph(*values: str) -> Graph:
    g = Graph(noise_check=False)
    for v in values:
        g.add_node(Entity.make("domain", v), 0, seed=True)
    return g


@pytest.mark.parametrize(("entry", "severity", "flagged"), [
    ((0.2, 12), "medium", True),
    ((0.29, 10), "medium", True),
    ((0.2, 9), "high", False),   # not enough votes yet
    ((0.3, 50), "high", False),  # at the threshold: kept
    ((0.9, 40), "high", False),
])
def test_precision_demotion_is_one_level_and_labelled(demo_rule, entry, severity, flagged):
    [corr] = run_rules(seed_graph("a.example"), [], only={demo_rule}, precision={demo_rule: entry})
    assert corr.severity.label == severity
    assert (correlate.PRECISION_TAG in corr.tags) is flagged
    labels = [s for s in corr.suppressed_by if s["rule"] == correlate.PRECISION_LABEL]
    assert bool(labels) is flagged
    if flagged:
        assert labels[0]["from"] == "high" and labels[0]["to"] == "medium" and f"{entry[0]:.2f}" in labels[0]["reason"]
        assert corr.label is Confidence.PROBABLE  # severity only: the label is not touched


def test_precision_never_disables_and_info_stays_info(rules_sandbox):
    @rule("t_prec_info", "Info rule")
    def info_rule(graph, results):
        yield Correlation("t_prec_info", "x", Severity.INFO, "d", entities=[n.entity for n in graph.seeds()])

    [corr] = run_rules(seed_graph("a.example"), [], only={"t_prec_info"}, precision={"t_prec_info": (0.0, 100)})
    assert corr.severity is Severity.INFO and "already at the lowest severity" in corr.suppressed_by[-1]["reason"]


def test_precision_table_sources(demo_rule):
    g = seed_graph("a.example")

    class FakeStore:
        def __init__(self):
            self.calls = 0

        def rule_precision(self):
            self.calls += 1
            return {demo_rule: (0.1, 30)}

        def sightings_for(self, *a, **k):  # pragma: no cover - only bound
            return None

    store = FakeStore()
    for meta in ({"rule_precision": store.rule_precision}, {"rule_precision": {demo_rule: (0.1, 30)}}, {"store": store},
                 {"sightings_lookup": store.sightings_for}):
        rctx = RuleContext(now=NOW, meta=meta)
        [corr] = run_rules(g, [], only={demo_rule}, rctx=rctx)
        assert corr.severity is Severity.MEDIUM, meta
    assert store.calls == 3

    class Broken:
        def rule_precision(self):
            raise RuntimeError("db locked")

    [corr] = run_rules(g, [], only={demo_rule}, rctx=RuleContext(now=NOW, meta={"store": Broken()}))
    assert corr.severity is Severity.HIGH  # no table: no demotion, never an error
    assert correlate.precision_table(None) == {}


def test_precision_applies_to_data_rules_and_listing_flags_doctor(rules_sandbox, fx):
    correlate.register_rule(compile_rule(rule_doc("both_collections_shared_ip")))
    [corr] = run_rules(fx.graph, [], only={"t_both_shared_ip"}, rctx=fx.rctx, precision={"t_both_shared_ip": (0.25, 11)})
    assert corr.severity is Severity.MEDIUM and corr.suppressed_by[-1]["rule"] == "P301-precision"
    rows = {r["id"]: r for r in correlate.rules_listing(precision={"t_both_shared_ip": (0.25, 11), "young_domain": (0.8, 3)})}
    assert rows["t_both_shared_ip"]["demoted"] and rows["t_both_shared_ip"]["precision"] == 0.25 and rows["t_both_shared_ip"]["votes"] == 11
    assert not rows["young_domain"]["demoted"] and rows["young_domain"]["votes"] == 3
    assert rows["seeds_linked"]["precision"] is None and rows["seeds_linked"]["votes"] == 0
    assert correlate.demoted_rules(precision={"t_both_shared_ip": (0.25, 11)}) == [
        {"id": "t_both_shared_ip", "precision": 0.25, "votes": 11, "registered": True}]
    assert "t_both_shared_ip" in RULES  # flagged, never disabled


def test_precision_from_a_real_store(tmp_path, demo_rule):
    from v3lum.core.store import Store

    store = Store(tmp_path / "v3lum.db")
    table = correlate.precision_table(None, store=store)
    assert table == {}  # no votes yet: nothing to demote
    rows = correlate.rules_listing(store=store)
    assert all(r["precision"] is None for r in rows)


# ------------------------------------------------------------------ P258 natural-person caps
def test_person_cap_on_python_rules(rules_sandbox):
    @rule("t_person_link", "Two people linked")
    def link(graph, results):
        people = [n.entity for n in graph.of_type(EntityType.PERSON)]
        yield Correlation("t_person_link", "same person", Severity.MEDIUM, "d", entities=people, confidence="confirmed")
        yield Correlation("t_person_link", "same person, analyst confirmed", Severity.MEDIUM, "d", entities=people,
                          confidence="confirmed", tags=[correlate.ANALYST_CONFIRMED_TAG], key="a")

    g = Graph(noise_check=False)
    for name in ("Fulano de Tal Exemplo", "Beltrano Exemplo"):
        g.add_node(Entity.make("person_name", name), 0, seed=True)
    out = {c.title: c for c in run_rules(g, [], only={"t_person_link"})}
    capped = out["same person"]
    assert capped.label is Confidence.PROBABLE and capped.suppressed_by[-1]["rule"] == "P258-person-cap"
    assert "analyst confirmation" in capped.criterion
    assert out["same person, analyst confirmed"].label is Confidence.CONFIRMED


def test_person_cap_respects_analyst_overrides_and_declared_rules(rules_sandbox):
    g = Graph(noise_check=False)
    ent = Entity.make("username", "handle_example")
    g.add_node(ent, 0, seed=True)
    f = Finding("linked profile", "info", "d", entity=ent, module="t_mod")
    g.add_finding(f)
    f.apply_override(label="confirmed", verdict="correct", analyst="ana")

    @rule("t_person_declared", "Declared person rule", person=True)
    def declared(graph, results):
        yield Correlation("t_person_declared", "linked", Severity.LOW, "d", entities=[ent], confidence="confirmed", evidence=[f.id])
        yield Correlation("t_person_declared", "linked, no evidence", Severity.LOW, "d", entities=[ent], confidence="confirmed", key="b")

    @rule("t_not_person", "Account rule")
    def account(graph, results):
        yield Correlation("t_not_person", "account fact", Severity.LOW, "d", entities=[ent], confidence="confirmed")

    assert RULES["t_person_declared"].person and not RULES["t_not_person"].person
    out = {c.title: c for c in run_rules(g, [], only={"t_person_declared", "t_not_person"})}
    assert out["linked"].label is Confidence.CONFIRMED  # evidence finding confirmed by an analyst
    assert out["linked, no evidence"].label is Confidence.PROBABLE
    assert out["account fact"].label is Confidence.CONFIRMED  # a username alone is not a natural-person rule
    ids = {c.title: c.id for c in run_rules(g, [], only={"t_person_declared"})}
    rctx = RuleContext(now=NOW, meta={"analyst_confirmed": [ids["linked, no evidence"]]})
    out = {c.title: c for c in run_rules(g, [], only={"t_person_declared"}, rctx=rctx)}
    assert out["linked, no evidence"].label is Confidence.CONFIRMED


def test_person_data_rule_needs_a_purpose_and_is_capped(rules_sandbox, fx):
    info = correlate.register_rule(compile_rule(rule_doc("person_partners")))
    assert info.person and info.kind == "data"
    assert run_rules(fx.graph, [], only={"t_person_partners"}, rctx=fx.rctx) == []  # AR16: no recorded purpose
    fx.rctx.options.purpose = "due diligence ticket 42"
    [corr] = run_rules(fx.graph, [], only={"t_person_partners"}, rctx=fx.rctx)
    assert corr.label is Confidence.PROBABLE and corr.suppressed_by[-1]["rule"] == "P258-person-cap"
    assert sorted(corr.entity_keys()) == ["person_name:Beltrano Exemplo", "person_name:Fulano de Tal Exemplo"]
    assert compile_rule(minimal(natural_person=True)).person


# ------------------------------------------------------------------ read only: rules never schedule anything
def test_rules_only_read_the_graph_and_never_touch_options(rules_sandbox, fx):
    for name in ("threshold_shared_ip", "outlier_registrar", "first_collection_only_ct", "match_subnet", "both_collections_shared_ip", "person_partners"):
        correlate.register_rule(compile_rule(rule_doc(name)))
    fx.rctx.options.purpose = "audit"
    graph_before = json.dumps(fx.graph.to_dict(), sort_keys=True, default=str)
    options_before = copy.deepcopy(vars(fx.rctx.options))
    meta_before = copy.deepcopy(fx.rctx.meta)
    ids = {"t_threshold_shared_ip", "t_outlier_registrar", "t_first_only_ct", "t_match_subnet", "t_both_shared_ip", "t_person_partners"}
    out = run_rules(fx.graph, fx.results, only=ids, rctx=fx.rctx)
    assert {c.rule for c in out} == ids
    assert json.dumps(fx.graph.to_dict(), sort_keys=True, default=str) == graph_before  # no node, edge, fact or finding added
    assert vars(fx.rctx.options) == options_before and fx.rctx.meta == meta_before  # opsec, scope, depth untouched
    for c in out:
        assert c.why and c.recommendation and c.criterion and c.evidence


def test_data_rule_function_takes_no_engine_handle():
    info = compile_rule(minimal())
    import inspect

    assert list(inspect.signature(info.fn).parameters) == ["graph", "results", "rctx"]
    assert info.fn.__module__ == "v3lum.core.rules_engine"


# ------------------------------------------------------------------ user rule directories (AR12)
def write_user_rules(home: Path, *docs: dict, mode: int = 0o700) -> Path:
    d = home / "rules"
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, mode)
    for doc in docs:
        p = d / f"{doc['id']}.json"
        p.write_text(json.dumps(doc), encoding="utf-8")
        os.chmod(p, 0o600)
    return d


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_user_rules_load_from_an_owner_only_directory(rules_sandbox, tmp_path):
    d = write_user_rules(tmp_path, minimal(id="t_user_rule"), minimal(id="young_domain"))
    loaded = correlate.load_user_rules(d)
    assert [i.id for i in loaded] == ["t_user_rule"] and RULES["t_user_rule"].user and RULES["t_user_rule"].origin.startswith("user:")
    report = {Path(r["path"]).name: r for r in correlate.user_rules_report()}
    assert report["t_user_rule.json"]["status"] == "loaded"
    assert report["young_domain.json"]["status"] == "refused" and "never replace reviewed rules" in report["young_domain.json"]["reason"]
    assert RULES["young_domain"].legacy and RULES["young_domain"].origin.startswith("v3lum.correlations.generic")
    rows = {r["id"]: r for r in correlate.rules_listing()}
    assert rows["t_user_rule"]["user"] is True


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_user_rules_refused_when_group_writable(rules_sandbox, tmp_path):
    d = write_user_rules(tmp_path, minimal(id="t_user_rule2"), mode=0o770)
    assert correlate.load_user_rules(d) == []
    [row] = correlate.user_rules_report()
    assert row["status"] == "refused" and "group-writable" in row["reason"]
    assert "t_user_rule2" not in RULES and any(k.startswith("user:") for k in RULE_ERRORS)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_user_rule_file_writable_by_others_refuses_the_directory(rules_sandbox, tmp_path):
    d = write_user_rules(tmp_path, minimal(id="t_user_rule3"))
    os.chmod(d / "t_user_rule3.json", 0o666)
    assert correlate.load_user_rules(d) == []
    assert "world-writable" in correlate.user_rules_report()[0]["reason"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_user_rules_are_linted(rules_sandbox, tmp_path, monkeypatch):
    from v3lum.core import lint

    d = write_user_rules(tmp_path, minimal(id="t_user_linted"))
    seen: list[str] = []

    def fake_lint(path, **kw):
        seen.append(Path(path).name)
        return [lint.LintIssue(str(path), 1, "LINT-03", "people-search host")]

    monkeypatch.setattr(lint, "lint_data_file", fake_lint)
    assert correlate.load_user_rules(d) == []
    assert seen == ["t_user_linted.json"]
    [row] = correlate.user_rules_report()
    assert row["status"] == "refused" and "LINT-03" in row["reason"]


def test_user_rules_dir_defaults_to_the_home_and_is_never_created(rules_sandbox):
    path = correlate.user_rules_dir()
    assert path == Path(os.environ["V3LUM_HOME"]) / "rules"
    assert correlate.load_user_rules() == [] and not path.exists()
    assert correlate.user_rules_report() == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_load_rules_force_loads_user_rules(rules_sandbox):
    home = Path(os.environ["V3LUM_HOME"])
    write_user_rules(home, minimal(id="t_user_via_load"))
    correlate.load_rules(force=True)
    assert RULES["t_user_via_load"].user


# ------------------------------------------------------------------ 500-node time budget (P301 cond 5)
def big_graph(n: int = 500) -> Graph:
    """``n`` nodes: 4/5 domains, 1/5 addresses (four domains per address), facts and findings."""
    g = Graph(noise_check=False)
    ips = n // 5
    for i in range(n - ips):
        dom = Entity.make("domain", f"host{i}.example-{i % 7}.org")
        j = i % ips
        ip = Entity.make("ipv4", f"198.51.100.{j + 1}" if j < 200 else f"203.0.113.{j - 199}")
        g.add_node(dom, 0 if i < 5 else 1, seed=i < 5)
        g.add_node(ip, 2)
        g.add_edge(dom, ip, "resolves_to", "dns_records", 0.9)
        g.add_attributes(dom, {"registrar": f"Registrar {i % 9}", "domain_age_days": i % 400}, "rdap")
        g.add_attributes(ip, {"asn": 64500 + i % 20, "open_ports": [22, 3389] if i % 10 == 0 else [443]}, "t_scan")
        if i % 5 == 0:
            g.add_finding(Finding("listed", "high", "d", confidence=0.8, tags=["malicious"], entity=dom, module=f"t_feed_{i % 3}", source="t_feed.a"))
        if i % 11 == 0:
            g.add_finding(Finding("name match", "medium", "d", confidence=0.6, tags=["sanctions", "name_only_match"], entity=dom,
                                  module="t_sanctions", data={"match_type": "name"}))
    return g


CORE_PACKS = ("generic", "threat_intel", "attack_surface", "email_spoofing", "typosquat", "breach", "web_hygiene", "sightings")


def test_correlation_adds_less_than_two_seconds_to_a_500_node_scan(rules_sandbox):
    for name in ("threshold_shared_ip", "outlier_registrar", "first_collection_only_ct", "match_subnet", "both_collections_shared_ip"):
        correlate.register_rule(compile_rule(rule_doc(name)))
    g = big_graph()
    assert len(g.nodes) == 500
    core = {rid for rid, info in RULES.items() if info.kind == "data" or info.origin.split(".")[2:3] and info.origin.split(".")[2] in CORE_PACKS}
    assert {"high_signal_tags", "seeds_linked", "multi_source_malicious", "t_threshold_shared_ip"} <= core
    rctx = RuleContext(now=NOW, meta={"rule_precision": {"t_outlier_registrar": (0.1, 20)}})
    run_rules(g, [], only=core, rctx=rctx)  # warm the lazily loaded tables (noise, providers, ATT&CK)
    started = time.perf_counter()
    out = run_rules(g, [], only=core, rctx=rctx)
    elapsed = time.perf_counter() - started
    assert elapsed < 2.0, f"correlation took {elapsed:.2f} s over 500 nodes"
    assert any(c.rule == "t_threshold_shared_ip" for c in out)
    assert not any(c.severity is Severity.CRITICAL and c.rule == "tag_sanctions" for c in out)  # name-only matches never CRITICAL


# ------------------------------------------------------------------ v3lum rules
def run_cli(capsys, *argv: str) -> tuple[int, str]:
    from v3lum.cli import main

    code = main(["rules", *argv])
    return code, capsys.readouterr().out


def test_rules_command_json_lists_both_kinds(rules_sandbox, capsys, monkeypatch):
    monkeypatch.setenv("COLUMNS", "250")
    correlate.register_rule(compile_rule(rule_doc("outlier_registrar")))
    code, out = run_cli(capsys, "--json")
    assert code == 0, out
    data = json.loads(out)
    rows = {r["id"]: r for r in data["rules"]}
    assert rows["t_outlier_registrar"]["kind"] == "data" and rows["high_signal_tags"]["kind"] == "python"
    hst = rows["high_signal_tags"]
    assert hst["legacy"] is True and hst["severity"] == "critical" and hst["precision"] is None and hst["votes"] == 0
    assert any(f.endswith("positive_homonym_name_only_sanctions.json") for f in hst["fixtures"])
    for key in ("id", "code", "version", "kind", "severity", "criterion", "attack", "precision", "votes", "demoted", "legacy", "fixtures"):
        assert key in hst
    assert data["errors"] == {} and data["user_rules"] == [] and data["precision_loaded"] is False


def test_rules_command_precision_flags_demoted_rules(rules_sandbox, capsys, monkeypatch):
    from v3lum.core.store import Store

    monkeypatch.setenv("COLUMNS", "250")
    monkeypatch.setattr(Store, "rule_precision", lambda self, now=None: {"young_domain": (0.12, 25), "seeds_linked": (0.9, 4)})
    code, out = run_cli(capsys, "young_domain", "--precision")
    assert code == 0
    assert "young_domain" in out and "0.12 (25)" in out and "demoted" in out and "seeds_linked" not in out
    code, out = run_cli(capsys, "--precision", "--json")
    rows = {r["id"]: r for r in json.loads(out)["rules"]}
    assert rows["young_domain"]["demoted"] and not rows["seeds_linked"]["demoted"] and rows["seeds_linked"]["votes"] == 4


def test_rules_command_reports_registration_errors(rules_sandbox, capsys, monkeypatch):
    monkeypatch.setenv("COLUMNS", "250")
    RULE_ERRORS["broken_rule.json"] = "data rule: severity must be info, low, medium, high or critical"
    code, out = run_cli(capsys, "zzz_no_match")
    assert code == 1 and "broken_rule.json" in out and "registration problem" in out


def test_contract_additions_names_resolve():
    """Every ``v3lum.*`` name at the start of a backticked span of docs/contract_additions/WP22.md
    resolves (module, module attribute, class attribute or dataclass field)."""
    import importlib
    import re

    doc = (Path(__file__).resolve().parent.parent / "docs" / "contract_additions" / "WP22.md").read_text(encoding="utf-8")
    names = sorted(set(re.findall(r"`(v3lum(?:\.[A-Za-z_][A-Za-z0-9_]*)+)(?![A-Za-z0-9_/])", doc)))
    assert "v3lum.core.rules_engine.compile_rule" in names and "v3lum.core.correlate.RuleInfo.person" in names
    missing = []
    for dotted in names:
        parts = dotted.split(".")
        obj, rest = None, parts
        for cut in range(len(parts), 0, -1):
            try:
                obj = importlib.import_module(".".join(parts[:cut]))
            except ImportError:
                continue
            rest = parts[cut:]
            break
        for i, attr in enumerate(rest):
            if hasattr(obj, attr):
                obj = getattr(obj, attr)
            elif dataclasses.is_dataclass(obj) and attr in {f.name for f in dataclasses.fields(obj)} and i == len(rest) - 1:
                obj = True
            else:
                missing.append(dotted)
                break
    assert not missing, missing


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_user_rules_reload_replaces_the_previous_load(rules_sandbox, tmp_path):
    d = write_user_rules(tmp_path, minimal(id="t_user_reload"))
    assert [i.id for i in correlate.load_user_rules(d)] == ["t_user_reload"]
    assert [i.id for i in correlate.load_user_rules(d)] == ["t_user_reload"]  # not refused as a duplicate of itself
    (d / "t_user_reload.json").unlink()
    assert correlate.load_user_rules(d) == [] and "t_user_reload" not in RULES  # a removed file disappears


def test_noise_neighbours_never_link_entities():
    """AR06: two domains on a CDN address are not 'sharing infrastructure' through it."""
    g = Graph(noise_check=False)
    cdn = Entity.make("ipv4", "198.51.100.99")
    node, _ = g.add_node(cdn, 1)
    node.noise, node.noise_kind = True, "cdn"
    for name in ("one.example", "two.example", "three.example"):
        dom = Entity.make("domain", name)
        g.add_node(dom, 0, seed=True)
        g.add_edge(dom, cdn, "resolves_to", "dns_records", 0.9)
    doc = rule_doc("threshold_shared_ip")
    doc["suppress"] = []
    info = compile_rule(doc)
    assert info.fn(g, [], None) == []
    doc["collections"][0]["include_noise"] = True
    [corr] = compile_rule(doc).fn(g, [], None)
    assert corr.entity_keys()[0] == "ipv4:198.51.100.99"


# ------------------------------------------------------------------ review additions (WP22 review)
@pytest.mark.parametrize("pattern", ["\\s*\\w+\\s*=\\s*\\w+\\s*;", "^[a-z0-9-]+\\.example\\.com$", "\\w+x", ".*\\.onion$", "(foo|bar)+z"])
def test_accepted_regexes_stay_fast_on_hostile_values(pattern):
    """Graph values come from the targets: an accepted pattern over a 50 000-character value (cut to
    MAX_REGEX_INPUT) must not stall the correlation pass."""
    assert regex_problems(pattern) == []
    g = Graph(noise_check=False)
    for i, value in enumerate(("a" * 50_000, " a=" * 20_000, "foo" * 20_000)):
        ent = Entity.make("domain", f"hostile{i}.example")
        g.add_node(ent, 0, seed=True)
        g.add_attributes(ent, {"registrar": value}, "rdap")
    doc = minimal(collections=[{"name": "d", "entity_types": ["domain"], "filters": [{"field": "attr:registrar", "op": "regex", "value": pattern}]}])
    info = compile_rule(doc)
    started = time.perf_counter()
    info.fn(g, [], None)
    assert time.perf_counter() - started < 0.5
    assert rules_engine.MAX_REGEX_INPUT <= 1024


def test_attack_ids_on_data_rule_correlations_are_validated_and_canonical(rules_sandbox, fx):
    """P301 cond 6 for data rules: ids are schema-validated at load (an unknown id never compiles) and
    revoked ids reach the correlation as their replacement; Python rules' run-time ids keep the
    wave-1 behaviour (canonicalised, unknown ones flagged in RULE_ERRORS - tests/test_rule_api.py)."""
    doc = rule_doc("both_collections_shared_ip")
    doc["attack"] = ["T1566", "T1656"]
    correlate.register_rule(compile_rule(doc))
    [corr] = run_rules(fx.graph, [], only={"t_both_shared_ip"}, rctx=fx.rctx)
    assert corr.attack == ["T1566", "T1684.001"] and "t_both_shared_ip" not in RULE_ERRORS
    doc["attack"] = ["T1566", "T9999"]
    with pytest.raises(RuleSchemaError, match="T9999"):
        compile_rule(doc)


def test_a_rule_that_writes_to_the_graph_is_reported(rules_sandbox):
    @rule("t_graph_writer", "Writes to the graph")
    def writer(graph, results):
        graph.add_node(Entity.make("domain", "planted.example"), 1)
        yield Correlation("t_graph_writer", "x", Severity.LOW, "d", entities=[n.entity for n in graph.seeds()])

    run_rules(seed_graph("a.example"), [], only={"t_graph_writer"})
    assert "added nodes, edges or findings" in RULE_ERRORS["t_graph_writer"]


def test_a_rule_can_never_change_the_scan_options(rules_sandbox):
    """P301 cond 5: rules get a copy of the scan options; a change never reaches the scan (opsec mode,
    scope, module selection) and is recorded; the next rule sees the original options again."""
    from v3lum.core.context import ScanOptions
    from v3lum.core.models import Opsec

    seen: list[tuple[str, bool]] = []

    @rule("t_opts_writer", "Tries to widen the scan")
    def writer(graph, results, rctx):
        rctx.options.mode = Opsec.ACTIVE
        rctx.options.include.add("port_scan")
        rctx.options.depth = 9
        return []

    @rule("t_opts_reader", "Reads the options")
    def reader(graph, results, rctx):
        seen.append((rctx.options.mode.label, "port_scan" in rctx.options.include))
        return []

    options = ScanOptions()
    before = options.to_dict()
    rctx = RuleContext(now=NOW, options=options)
    run_rules(seed_graph("a.example"), [], only={"t_opts_writer", "t_opts_reader"}, rctx=rctx)
    assert options.to_dict() == before and options.mode is Opsec.PASSIVE and "port_scan" not in options.include
    assert "changed the scan options" in RULE_ERRORS["t_opts_writer"] and "t_opts_reader" not in RULE_ERRORS
    assert seen == [(Opsec.PASSIVE.label, False)]


def test_demotion_of_emitted_correlation_names_is_listed_for_doctor(rules_sandbox, capsys, monkeypatch):
    """Votes are stored under the correlation's rule name (high_signal_tags emits tag_sanctions):
    run_rules demotes it and doctor/`v3lum rules --precision` list it."""
    g = Graph(noise_check=False)
    cnpj = Entity.make("cnpj", "11222333000181")
    g.add_node(cnpj, 0, seed=True)
    g.add_finding(Finding("listed", "critical", "d", confidence="confirmed", tags=["sanctions"], entity=cnpj, module="t_list",
                          data={"match_type": "exact_cnpj"}))
    table = {"tag_sanctions": (0.1, 20)}
    [corr] = run_rules(g, [], only={"high_signal_tags"}, precision=table)
    assert corr.rule == "tag_sanctions" and corr.severity is Severity.HIGH and correlate.PRECISION_TAG in corr.tags
    assert {"id": "tag_sanctions", "precision": 0.1, "votes": 20, "registered": False} in correlate.demoted_rules(precision=table)
    from v3lum.core.store import Store

    monkeypatch.setenv("COLUMNS", "250")
    monkeypatch.setattr(Store, "rule_precision", lambda self, now=None: dict(table))
    code, out = run_cli(capsys, "--precision")
    assert code == 0 and "tag_sanctions" in out and "demoted one severity level" in out


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_user_yaml_and_toml_rules_are_linted_as_parsed_data(rules_sandbox, tmp_path, monkeypatch):
    """lint.lint_data_file reads JSON/TOML files only: user rules are linted from the parsed document,
    so a YAML rule gets the same P327 data lint as a JSON one."""
    from v3lum.core import lint

    class FakeYaml:
        @staticmethod
        def safe_load(text):
            return minimal(id="t_user_yaml")

    monkeypatch.setitem(sys.modules, "yaml", FakeYaml)
    d = tmp_path / "rules"
    d.mkdir(mode=0o700)
    path = d / "t_user_yaml.yaml"
    path.write_text("schema: v3lum.rule/1\n", encoding="utf-8")
    os.chmod(path, 0o600)
    seen: list[object] = []

    def fake_lint(p, *, data=None, **kw):
        seen.append(data)
        return [lint.LintIssue(str(p), 1, "LINT-03", "people-search host")] if data else []

    monkeypatch.setattr(lint, "lint_data_file", fake_lint)
    assert correlate.load_user_rules(d) == []
    assert seen and isinstance(seen[0], dict) and seen[0]["id"] == "t_user_yaml"
    [row] = correlate.user_rules_report()
    assert row["status"] == "refused" and "LINT-03" in row["reason"]
