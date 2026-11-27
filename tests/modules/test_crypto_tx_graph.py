"""crypto_tx_graph (P213): the transaction-graph expansion policy, the money-trail summary and the exports, plus the
batch's correlation rules (``p3g091_money_trail``, ``p3g091_ens_claim_linked_back``).

P213 is an engine policy, not a module (no host, no request): the fixtures in tests/fixtures/crypto_tx_graph/ are
SYNTHETIC normalised edges and label lookups (prep batch p3-G09-1): ``edges_ok_synthetic.json`` (3 incoming-only
senders, 8 outgoing counterparties including a mixer, a hub, a sanctioned address, two exchanges and a bridge at
hop 2, one edge beyond an exchange), ``labels_synthetic.json`` and ``edges_empty.json``. The real-shaped TON
transactions fixture of ton_explorer is also fed through the policy.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from decimal import Decimal

import pytest

from tests.fakes import FIXTURES, module_fixture
from v3lum.core import correlate
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.graph import Graph
from v3lum.modules.crypto import crypto_tx_graph as g
from v3lum.modules.crypto import ton_explorer as ton

SEED = "syn:seed"


@pytest.fixture
def graph_data():
    edges = module_fixture("crypto_tx_graph", "edges_ok_synthetic.json")
    labels = module_fixture("crypto_tx_graph", "labels_synthetic.json")
    return edges["edges"], labels["labels"], labels["sanctioned"], labels["degrees"]


# ------------------------------------------------------------------ cond 1: opt-in, depth, top-N, budget
def test_policy_is_opt_in_and_never_expands_by_default(graph_data):
    edges, labels, sanctioned, degrees = graph_data
    plan = g.plan_expansion(SEED, edges, labels=labels, sanctioned=sanctioned, degrees=degrees)
    assert plan["enabled"] is False and plan["expand"] == [] and "opt-in" in plan["reason"]
    assert g.POLICY_DEFAULTS == {"crypto_expand": False, "crypto_case_budget": 50, "crypto_depth": 1, "crypto_top_n": 5}


def test_top_n_by_value_then_frequency_skips_stop_nodes_and_victims(graph_data):
    edges, labels, sanctioned, degrees = graph_data
    plan = g.plan_expansion(SEED, edges, crypto_expand=True, top_n=3, labels=labels, sanctioned=sanctioned, degrees=degrees)
    assert plan["expand"] == ["syn:a", "syn:b", "syn:c"]  # 1.2, 0.2, 0.05 BTC
    assert plan["stop_nodes"] == {"syn:hub": "high_degree: 15000 counterparties", "syn:mixer": "mixer: ExampleMixer",
                                  "syn:sanctioned": "sanctioned"}
    victims = plan["possible_victims"]
    assert victims["count"] == 3 and victims["listed"] is False and victims["label"] == "possible victim"  # cond 3
    assert not set(victims["addresses"]) & set(plan["expand"])
    for row in plan["unselected"]:  # cond 4
        assert row["expand"] is False and row["label"] == "counterparty (role unknown)" and row["malicious_by_association"] is False
    assert {r["address"] for r in plan["unselected"]} == {"syn:d", "syn:e", "syn:f"}


def test_selection_budget_and_depth(graph_data):
    edges, labels, sanctioned, degrees = graph_data
    picked = g.plan_expansion(SEED, edges, crypto_expand=True, selected=["syn:e", "syn:mixer"], labels=labels, sanctioned=sanctioned, degrees=degrees)
    assert picked["expand"] == ["syn:e"]  # a selected stop-node is still never expanded
    budget = g.plan_expansion(SEED, edges, crypto_expand=True, budget_left=2, labels=labels, sanctioned=sanctioned, degrees=degrees)
    assert budget["expand"] == ["syn:a", "syn:b"] and budget["budget_exhausted"] is True
    assert g.plan_expansion(SEED, edges, crypto_expand=True, current_hop=2)["reason"] == "depth limit 1 reached"
    deep = g.plan_expansion(SEED, edges, crypto_expand=True, depth=2, depth_flag=True, current_hop=2)
    assert deep["max_depth"] == 2 and deep["reason"] is None
    assert g.plan_expansion(SEED, edges, crypto_expand=True, depth=5, depth_flag=True)["max_depth"] == 2  # never more than 2
    assert g.plan_expansion(SEED, edges, crypto_expand=True, depth=2)["max_depth"] == 1  # 2 only with the explicit flag


# ------------------------------------------------------------------ cond 2: stop-nodes
def test_stop_node_rules():
    labels = {"x": [{"category": "Exchange", "name": "Ex\x07ample", "source": "p358"}], "y": [{"category": "gambling"}]}
    assert g.stop_node_reason("x", labels) == "exchange: Example"
    assert g.stop_node_reason("y", labels) is None  # gambling is not a stop category
    assert g.stop_node_reason("z", {}, sanctioned={"z"}) == "sanctioned"
    assert g.stop_node_reason("h", degrees={"h": 1001}).startswith("high_degree")
    assert g.stop_node_reason("h", degrees={"h": 1000}) is None and g.stop_node_reason("h", degrees={"h": True}) is None


# ------------------------------------------------------------------ cond 5: summary and exports
def test_money_trail_summary_highlights_the_first_exchange(graph_data):
    edges, labels, sanctioned, degrees = graph_data
    one = g.money_trail_summary(SEED, edges, labels=labels, sanctioned=sanctioned, degrees=degrees)
    assert one["hops"] == 1 and one["first_exchange"] is None and one["possible_victims"] == 3
    assert {e["address"] for e in one["endpoints"]} == {"syn:mixer", "syn:hub", "syn:sanctioned"}
    two = g.money_trail_summary(SEED, edges, labels=labels, sanctioned=sanctioned, degrees=degrees, max_depth=2)
    first = two["first_exchange"]
    assert first["address"] == "syn:exchange-b" and first["hop"] == 2 and first["name"] == "OtherExchange"  # earliest in time
    assert "legal-request target" in two["text"] and two["total_out"] == "2.05 BTC"
    assert two["time_window"][0] == "2023-11-14T22:30:00Z"
    assert "syn:beyond-exchange" not in json.dumps(two)  # never traversed past a stop-node


def test_summary_never_lists_hundreds():
    edges = [{"from": SEED, "to": f"syn:ex{i}", "value": "1", "asset": "BTC", "time": 1700000000 + i} for i in range(300)]
    labels = {f"syn:ex{i}": [{"category": "exchange", "name": f"Ex{i}"}] for i in range(300)}
    summary = g.money_trail_summary(SEED, edges, labels=labels)
    assert len(summary["endpoints"]) == 10 and summary["endpoints_total"] == 300


def test_graph_export_json_and_graphml(graph_data):
    edges, labels, sanctioned, degrees = graph_data
    graph = g.graph_export(SEED, edges, labels=labels, sanctioned=sanctioned, degrees=degrees, selected=["syn:a"])
    ids = {n["id"]: n for n in graph["nodes"]}
    assert ids[SEED]["role"] == "seed" and ids["syn:a"]["selected"] is True
    assert ids["syn:exchange-a"]["role"] == "stop_node" and "syn:beyond-exchange" not in ids
    assert not any(n["role"] == "possible_victim" for n in graph["nodes"])  # counted, not listed by default
    assert graph["possible_victims"] == {"count": 3, "label": "possible victim", "listed": False}
    with_victims = g.graph_export(SEED, edges, include_victims=True)
    assert sum(1 for n in with_victims["nodes"] if n["role"] == "possible_victim") == 3
    xml = g.graph_to_graphml(graph)
    root = ET.fromstring(xml)
    ns = "{http://graphml.graphdrawing.org/xmlns}"
    assert len(root.findall(f".//{ns}node")) == len(graph["nodes"]) and len(root.findall(f".//{ns}edge")) == len(graph["edges"])
    hostile = g.graph_to_graphml({"seed": 's"<x>', "nodes": [{"id": "a&b\x07", "role": "seed", "label": "<script>"}], "edges": []})
    ET.fromstring(hostile)  # well-formed despite markup and control characters
    assert "<script>" not in hostile


def test_empty_and_bad_edges():
    empty = module_fixture("crypto_tx_graph", "edges_empty.json")
    summary = g.money_trail_summary(empty["seed"], empty["edges"])
    assert summary["hops"] == 0 and summary["text"] == "where the money went: no labelled endpoint reached"
    assert g.normalize_edge({"from": "a", "to": "a", "value": "1"}) is None
    assert g.normalize_edge({"from": "a", "to": "b", "value": "-1"}) is None
    assert g.normalize_edge({"from": "a", "to": "b", "value": "NaN"}) is None
    assert g.normalize_edge(["a", "b"]) is None
    assert g.normalize_edge({"from": "a", "to": "b", "value": "1.5", "time": "2026-11-01T00:00:00Z"})["time"] == 1793491200


def test_explorer_attributes_become_edges():
    btc = [{"address": "x", "received_from": "0.5 BTC", "sent_to": "0 BTC"}, {"address": "y", "received_from": "0 BTC", "sent_to": "1.25 BTC",
                                                                                "last_seen": "2026-11-02T00:00:00Z"}]
    edges = g.edges_from_counterparties("me", btc)
    assert [(e["from"], e["to"], e["value"], e["asset"]) for e in edges] == [("x", "me", Decimal("0.5"), "BTC"), ("me", "y", Decimal("1.25"), "BTC")]
    tron = [{"address": "t", "usdt_in": "10 USDT", "usdt_out": "3.5 USDT", "transfers": 2}]
    assert {(e["from"], e["to"]) for e in g.edges_from_counterparties("me", tron)} == {("t", "me"), ("me", "t")}
    assert g.edges_from_counterparties("me", [{"address": "z", "sent_to": "lots"}, "junk", None]) == []
    assert g.parse_amount("1e5 BTC") is None and g.parse_amount(True) is None


def test_ton_transactions_feed_the_policy():
    raw = json.loads((FIXTURES / "ton_explorer" / "transactions_ok.json").read_text())
    account = "0:83DFD552E63729B472FCBCC8C45EBCC6691702558B68EC7527E1BA403A0F31A8"
    summary = ton.summarize_transactions(account, ton.parse_transactions(raw, account)["transactions"])
    edges = g.edges_from_counterparties(account, summary["counterparties"], chain="ton")
    plan = g.plan_expansion(account, edges, crypto_expand=True)
    assert plan["expand"] == [] and plan["possible_victims"]["count"] == 1  # the only sender just paid the wallet


# ------------------------------------------------------------------ case-graph adapters and the rules
def _wallet_graph() -> Graph:
    graph = Graph(noise_check=False)
    seed = Entity.make(T.BTC, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
    ex = Entity.make(T.BTC, "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
    graph.add_node(seed, 0, seed=True)
    graph.add_node(ex, 1)
    graph.add_attributes(seed, {"top_counterparties": [{"address": ex.value, "received_from": "0 BTC", "sent_to": "2 BTC"}]}, "btc_explorers")
    graph.add_attributes(ex, {"stop_node_hint": "exchange", "wallet_labels": ["ExampleExchange"], "tx_count": 5}, "walletexplorer")
    graph.add_edge(seed, ex, "transacted_with", "btc_explorers", 0.7, expand=False)
    return graph


def test_case_inputs_read_labels_from_sibling_modules():
    inputs = g.case_inputs(_wallet_graph())
    ex = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
    assert inputs["labels"][ex][0]["category"] == "exchange" and inputs["labels"][ex][0]["name"] == "ExampleExchange"
    assert inputs["degrees"][ex] == 5 and len(inputs["edges"]) == 1


def test_money_trail_rule_on_a_case_graph():
    correlate.load_rules()
    found = list(correlate.run_rules(_wallet_graph(), [], only={"p3g091_money_trail"}))
    [c] = found
    assert c.severity.label == "info" and c.confidence_label.value == "probable"
    assert "ExampleExchange" in c.recommendation and len(c.entities) == 2


def test_ens_rule_needs_another_module_pointing_back():
    correlate.load_rules()
    graph = Graph(noise_check=False)
    name = Entity.make(T.DOMAIN, "v3lum-fixture-owner.eth")
    user = Entity.make(T.USERNAME, "example-org")
    graph.add_node(name, 0, seed=True)
    graph.add_node(user, 1)
    graph.add_attributes(name, {"ens_name": "v3lum-fixture-owner.eth"}, "ens_resolver")
    graph.add_edge(name, user, "ens_text_record", "ens_resolver", 0.4, expand=False)
    graph.add_attributes(user, {"ens_text_records": {"x": "v3lum-fixture-owner.eth"}}, "ens_resolver")  # its own echo
    assert list(correlate.run_rules(graph, [], only={"p3g091_ens_claim_linked_back"})) == []
    graph.add_attributes(user, {"website": "https://example.com/ v3lum-fixture-owner.eth"}, "github_user")
    [c] = list(correlate.run_rules(graph, [], only={"p3g091_ens_claim_linked_back"}))
    assert c.confidence_label.value == "probable" and "points back" in c.description
