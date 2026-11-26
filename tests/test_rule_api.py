"""Correlation rule API v2 (WP01, P301): metadata, RuleContext, legacy handling, ids, data-rule hook."""

from __future__ import annotations

import datetime as dt
import json
import subprocess
import sys
from pathlib import Path

import pytest

from v3lum.core import correlate
from v3lum.core.correlate import LEGACY_RULES, RULE_ERRORS, RULE_REPLACED, RULES, RuleContext, RuleInfo, rule
from v3lum.core.entities import Entity
from v3lum.core.graph import Graph
from v3lum.core.models import Correlation, Severity, correlation_id

ROOT = Path(__file__).resolve().parent.parent
NOW = dt.datetime(2026, 11, 26, 12, 0, tzinfo=dt.timezone.utc)


@pytest.fixture()
def rules_sandbox():
    """Snapshot/restore every rule registry structure around a test."""
    correlate.load_rules()
    saved = (dict(RULES), dict(RULE_ERRORS), dict(RULE_REPLACED), dict(correlate._COMPILERS))
    yield
    RULES.clear()
    RULES.update(saved[0])
    RULE_ERRORS.clear()
    RULE_ERRORS.update(saved[1])
    RULE_REPLACED.clear()
    RULE_REPLACED.update(saved[2])
    correlate._COMPILERS.clear()
    correlate._COMPILERS.update(saved[3])


def one_node_graph(value: str = "evil.example") -> Graph:
    g = Graph()
    g.add_node(Entity.make("domain", value), 0, seed=True)
    return g


def corr_for(rule_id: str, node, **kw) -> Correlation:
    return Correlation(rule=rule_id, title=kw.pop("title", f"{rule_id} hit"), severity=kw.pop("severity", Severity.LOW), description="d", entities=[node.entity], **kw)


def test_legacy_two_argument_rule_still_runs(rules_sandbox):
    @rule("t_two_args", "Two-argument rule")
    def two(graph, results):
        for node in graph.nodes.values():
            yield corr_for("", node)  # rule filled in from the registration

    info = RULES["t_two_args"]
    assert not info.takes_context and info.kind == "python" and not info.legacy
    out = correlate.run_rules(one_node_graph(), [], only={"t_two_args"})
    assert len(out) == 1 and out[0].rule == "t_two_args" and out[0].version == "1"


def test_three_argument_rule_receives_rule_context(rules_sandbox):
    seen = []

    @rule("t_three_args", "Context rule", version="3", criterion="org-profile match", attack=("T1656",), references=("https://example.net/r",))
    def three(graph, results, rctx):
        seen.append(rctx)
        for node in graph.nodes.values():
            yield corr_for("t_three_args", node)

    assert RULES["t_three_args"].takes_context
    ctx = RuleContext(now=NOW, meta={"k": "v"})
    out = correlate.run_rules(one_node_graph(), [], only={"t_three_args"}, rctx=ctx)
    assert seen == [ctx] and ctx.setting("anything", 5) == 5
    c = out[0]
    assert c.version == "3" and c.criterion == "org-profile match"
    assert c.attack == ["T1684.001"]  # canonicalised (revoked T1656)
    assert c.references == ["https://example.net/r"]
    # without an explicit context the rule still gets one (now = current time)
    seen.clear()
    correlate.run_rules(one_node_graph(), [], only={"t_three_args"})
    assert isinstance(seen[0], RuleContext) and seen[0].now.tzinfo is not None


def test_rule_set_attack_ids_are_canonicalised(rules_sandbox):
    @rule("t_attack_corr", "Attack ids on the correlation")
    def r(graph, results):
        for node in graph.nodes.values():
            yield corr_for("t_attack_corr", node, attack=["T1656", "T1684.001", "T1566"])

    out = correlate.run_rules(one_node_graph(), [], only={"t_attack_corr"})
    assert out[0].attack == ["T1684.001", "T1566"]


def test_invalid_attack_id_recorded(rules_sandbox):
    @rule("t_bad_attack", "Bad ATT&CK id", attack=("T9999", "T1566"))
    def r(graph, results):
        return []

    assert "t_bad_attack" in RULES
    assert "T9999" in RULE_ERRORS["t_bad_attack"]


def test_registration_errors_accumulate(rules_sandbox):
    @rule("T_Bad_Id", "Bad id and bad ATT&CK", severity="extreme", attack=("T9999",))
    def r(graph, results):
        return []

    err = RULE_ERRORS["T_Bad_Id"]
    assert "invalid rule id" in err and "invalid severity" in err and "T9999" in err  # none overwritten


def test_correlation_attack_ids_are_validated_at_run_time(rules_sandbox):
    @rule("t_runtime_attack", "Emits an unknown technique")
    def r(graph, results):
        for node in graph.nodes.values():
            yield corr_for("t_runtime_attack", node, attack=["T9998", "T1656"])

    out = correlate.run_rules(one_node_graph(), [], only={"t_runtime_attack"})
    assert out[0].attack == ["T9998", "T1684.001"]  # kept (canonicalised) for the analyst, but flagged
    assert "T9998" in RULE_ERRORS["t_runtime_attack"]


def test_rules_listing_fields(rules_sandbox):
    @rule("t_listed", "Listed rule", "desc", version="2", code="CR99", severity="high", criterion="c", attack=("T1566",),
          false_positives="shared hosting", fixtures=("positive_basic.json",))
    def r(graph, results, rctx):
        return []

    rows = {row["id"]: row for row in correlate.rules_listing()}
    row = rows["t_listed"]
    for key in ("id", "code", "version", "title", "severity", "criterion", "attack", "legacy", "kind", "fixtures"):
        assert key in row
    assert (row["code"], row["version"], row["severity"], row["kind"], row["legacy"]) == ("CR99", "2", "high", "python", False)
    assert row["attack"] == ["T1566"] and row["fixtures"] == ["positive_basic.json"] and row["false_positives"] == "shared hosting"
    assert [r["id"] for r in correlate.rules_listing()] == sorted(rows)


def test_deterministic_correlation_ids(rules_sandbox):
    @rule("t_ids", "Deterministic ids")
    def r(graph, results):
        nodes = list(graph.nodes.values())
        yield Correlation("t_ids", "pair", Severity.MEDIUM, "d", entities=[n.entity for n in reversed(nodes)])
        yield Correlation("t_ids", "pair, other title", Severity.LOW, "d", entities=[n.entity for n in nodes])

    g = one_node_graph("a.example")
    g.add_node(Entity.make("domain", "b.example"), 0, seed=True)
    first = correlate.run_rules(g, [], only={"t_ids"})
    second = correlate.run_rules(g, [], only={"t_ids"})
    assert [c.id for c in first] == [c.id for c in second]
    assert first[0].id == correlation_id("t_ids", ["domain:a.example", "domain:b.example"])
    assert len({c.id for c in first}) == 2 and all(len(c.id) == 16 for c in first)  # same entities, distinct ids


def test_legacy_flag_on_the_eight_legacy_rules():
    correlate.load_rules()
    assert len(LEGACY_RULES) == 8
    for rid in LEGACY_RULES:
        info = RULES.get(rid) or RULE_REPLACED.get(rid)
        assert info is not None, rid
        if rid in RULE_REPLACED:  # a pack rule took the id over
            assert RULE_REPLACED[rid].legacy and not RULES[rid].legacy
        else:
            assert info.legacy, rid


def _legacy_fn():
    def legacy_rule(graph, results):
        for node in graph.nodes.values():
            yield corr_for("t_legacy_dup", node, title="legacy version")

    legacy_rule.__module__ = "v3lum.correlations.generic"
    return legacy_rule


def _pack_fn():
    def pack_rule(graph, results):
        for node in graph.nodes.values():
            yield corr_for("t_legacy_dup", node, title="pack version")

    return pack_rule


@pytest.mark.parametrize("order", ["legacy_first", "pack_first"])
def test_pack_rule_supersedes_legacy_rule(rules_sandbox, monkeypatch, order):
    monkeypatch.setattr(correlate, "LEGACY_RULES", LEGACY_RULES | {"t_legacy_dup"})
    legacy, pack = _legacy_fn(), _pack_fn()
    steps = [("legacy", legacy), ("pack", pack)] if order == "legacy_first" else [("pack", pack), ("legacy", legacy)]
    for _kind, fn in steps:
        rule("t_legacy_dup", "Duplicate id")(fn)
    assert not RULES["t_legacy_dup"].legacy and RULES["t_legacy_dup"].fn is pack
    assert RULE_REPLACED["t_legacy_dup"].legacy and RULE_REPLACED["t_legacy_dup"].fn is legacy
    assert "t_legacy_dup" not in RULE_ERRORS
    out = correlate.run_rules(one_node_graph(), [], only={"t_legacy_dup"})
    assert [c.title for c in out] == ["pack version"]


def test_non_legacy_duplicate_is_an_error(rules_sandbox):
    @rule("t_dup", "First")
    def first(graph, results):
        return []

    def second(graph, results):
        return []

    rule("t_dup", "Second")(second)
    assert RULES["t_dup"].fn is first
    assert "duplicate rule id" in RULE_ERRORS["t_dup"]


def test_same_function_registered_twice_is_not_a_duplicate(rules_sandbox):
    def again(graph, results):
        return []

    rule("t_again", "Again")(again)
    rule("t_again", "Again")(again)
    assert "t_again" not in RULE_ERRORS


def test_broken_rule_is_isolated(rules_sandbox):
    @rule("t_broken", "Raises")
    def broken(graph, results):
        raise RuntimeError("bug in rule")

    assert correlate.run_rules(one_node_graph(), [], only={"t_broken"}) == []
    assert "bug in rule" in RULE_ERRORS["t_broken"]


def test_existing_generic_rules_keep_working():
    correlate.load_rules()
    g = Graph()
    a, b, ip = Entity.make("domain", "a.example"), Entity.make("domain", "b.example"), Entity.make("ipv4", "45.33.40.77")
    g.add_node(a, 0, seed=True)
    g.add_node(b, 0, seed=True)
    g.add_node(ip, 1)
    g.add_edge(a, ip, "resolves_to", "t")
    g.add_edge(b, ip, "resolves_to", "t")
    out = correlate.run_rules(g, [], only={"seeds_linked", "shared_infrastructure"})
    assert {c.rule for c in out} == {"seeds_linked", "shared_infrastructure"}
    assert all(len(c.id) == 16 and c.version for c in out)


def test_register_compiler_loads_data_rules(rules_sandbox, tmp_path, monkeypatch):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "r1.json").write_text(json.dumps({"kind": "t_kind", "id": "t_data_rule", "title": "Data rule", "severity": "medium"}))
    (rules_dir / "other.json").write_text(json.dumps({"kind": "unregistered_kind", "id": "t_ignored"}))
    (rules_dir / "broken.json").write_text("{")
    monkeypatch.setattr(correlate, "RULES_DATA_DIR", rules_dir)
    calls = []

    def compile_rule(doc, *, path):
        calls.append(path.name)

        def fn(graph, results):
            for node in graph.nodes.values():
                yield corr_for(doc["id"], node, severity=doc["severity"])

        return RuleInfo(doc["id"], doc["title"], "", fn, severity=doc["severity"], kind="t_kind")

    correlate.register_compiler("t_kind", compile_rule)
    with pytest.raises(ValueError):
        correlate.register_compiler("Bad Kind", compile_rule)
    correlate.load_rules(force=True)
    assert calls == ["r1.json"]
    assert RULES["t_data_rule"].kind == "t_kind" and "t_ignored" not in RULES
    assert "broken.json" in RULE_ERRORS
    out = correlate.run_rules(one_node_graph(), [], only={"t_data_rule"})
    assert out[0].severity is Severity.MEDIUM


def test_shipped_tree_has_no_rule_errors():
    code = "import json; from v3lum.core import correlate; correlate.load_rules(); print(json.dumps(correlate.RULE_ERRORS))"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=str(ROOT), timeout=120, check=True)
    assert json.loads(out.stdout.strip().splitlines()[-1]) == {}
