"""Transaction-graph expansion policy with stop-nodes (P213) - an engine policy, not a module.

P213 is approved as an engine policy on ``transacted_with`` pivots (core expansion rules, AR07), never a module
with its own BFS: this file holds the pure policy and summary functions the engine's expansion step calls, and the
correlation rule ``p3g091_money_trail`` (v3lum/correlations/p3_g09_1.py) uses them to put the 'where the money
went' summary on every investigated wallet of a case. No host, no network, no registered Module: tier and terms
'n/a'. Orbit (GPL-3.0) inspired the idea only; no code was read into or copied from it (A6).

Final conditions (P213, council-1):

* cond 1 - depth 1 by default, 2 only with an explicit flag (``--crypto-depth 2``), top-N counterparties ranked by
  value then frequency, a per-case crypto request budget (setting ``crypto_case_budget``), no new hosts, opt-in
  (setting ``crypto_expand`` false by default): :func:`plan_expansion`. The settings and the flag belong to the
  core (engine/CLI); :data:`POLICY_DEFAULTS` are the values the core is asked to register. Until the engine wires
  the policy, every explorer emits ``transacted_with`` with ``expand=False``, which is the opt-in default.
* cond 2 - stop-nodes are never expanded: labelled exchanges, mixers, bridges and pools (crypto_address_labels
  P358, walletexplorer P208, Blockscout tags), sanctioned addresses (P205) and high-degree addresses (> 1,000
  counterparties): :func:`stop_node_reason`, :func:`labels_from_node`.
* cond 3 - direction: expansion follows outgoing flows (cash-out toward exchanges); addresses that only sent funds
  into an investigated address are 'possible victim': counted, never expanded and not listed by default.
* cond 4 - counterparties outside the analyst's selection stay ``expand=False``, labelled 'counterparty (role
  unknown)', and are never scored malicious by association (``malicious_by_association: False``).
* cond 5 - output: a 'where the money went' summary (labelled endpoints reached, hop count, amounts, time window)
  highlighting the first labelled exchange (the legal-request target) - :func:`money_trail_summary` - plus a
  JSON/GraphML export (:func:`graph_export`, :func:`graph_to_graphml`); never a list of hundreds of addresses.
"""

from __future__ import annotations

import datetime as _dt
import re
from collections.abc import Iterable, Mapping
from decimal import Decimal, InvalidOperation
from typing import Any
from xml.sax.saxutils import escape as _xml_escape

STOP_CATEGORIES = frozenset({"exchange", "mixer", "bridge", "pool", "mining_pool", "staking_pool", "liquidity_pool",
                             "custodial_service"})
HIGH_DEGREE_LIMIT = 1000
DEFAULT_DEPTH = 1
MAX_DEPTH = 2
DEFAULT_TOP_N = 5
SUMMARY_MAX_ENDPOINTS = 10
COUNTERPARTY_LABEL = "counterparty (role unknown)"
VICTIM_LABEL = "possible victim"
#: the engine settings P213 cond 1 asks the core to register (core request: engine/CLI wiring)
POLICY_DEFAULTS: dict[str, Any] = {"crypto_expand": False, "crypto_case_budget": 50, "crypto_depth": DEFAULT_DEPTH,
                                   "crypto_top_n": DEFAULT_TOP_N}
WALLET_TYPES = ("btc_address", "eth_address", "xmr_address", "other_crypto_address")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_AMOUNT_RE = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([A-Za-z][A-Za-z0-9]{0,15})?\s*$")


# --------------------------------------------------------------------------------------
# edges
# --------------------------------------------------------------------------------------


def _epoch(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 < value < 32503680000 else None
    if isinstance(value, str) and value:
        try:
            parsed = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=_dt.timezone.utc)
        return int(parsed.timestamp())
    return None


def iso(epoch: Any) -> str | None:
    value = _epoch(epoch)
    return _dt.datetime.fromtimestamp(value, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if value else None


def normalize_edge(raw: Any) -> dict[str, Any] | None:
    """Explorer edge -> {'chain', 'tx', 'time' (epoch), 'from', 'to', 'value' (Decimal), 'asset'} or None.

    The edge contract the explorer modules feed: {chain, tx, time (epoch or ISO), from, to, value (decimal string in
    native units), asset}."""
    if not isinstance(raw, Mapping):
        return None
    src, dst = raw.get("from"), raw.get("to")
    if not (isinstance(src, str) and isinstance(dst, str) and src.strip() and dst.strip()) or src.strip() == dst.strip():
        return None
    try:
        value = Decimal(str(raw.get("value", "0")))
    except InvalidOperation:
        return None
    if not value.is_finite() or value < 0:
        return None
    return {"chain": str(raw.get("chain") or "")[:16] or None, "tx": str(raw.get("tx"))[:128] if raw.get("tx") else None,
            "time": _epoch(raw.get("time")), "from": src.strip(), "to": dst.strip(), "value": value,
            "asset": str(raw.get("asset") or "")[:16] or None}


def parse_amount(text: Any) -> tuple[Decimal, str | None] | None:
    """'1.5 BTC' -> (Decimal('1.5'), 'BTC'); plain numbers too; None for anything else."""
    if isinstance(text, bool):
        return None
    if isinstance(text, (int, float)):
        text = str(text)
    if not isinstance(text, str):
        return None
    match = _AMOUNT_RE.match(text)
    if not match:
        return None
    try:
        return Decimal(match.group(1)), match.group(2)
    except InvalidOperation:
        return None


def edges_from_counterparties(focus: str, rows: Any, chain: str | None = None) -> list[dict[str, Any]]:
    """An explorer's ``top_counterparties`` attribute -> normalised edges around ``focus``.

    Shapes read: btc_explorers / evm_explorers / ton_explorer {address, received_from 'X UNIT', sent_to 'Y UNIT',
    first_seen, last_seen}; tron_explorer {address, usdt_in 'X USDT', usdt_out 'Y USDT'}. Each direction with a
    positive amount gives one aggregated edge (sent_to/usdt_out: focus -> counterparty; received_from/usdt_in:
    counterparty -> focus). Unknown shapes are skipped."""
    edges: list[dict[str, Any]] = []
    if not isinstance(rows, list):
        return edges
    for row in rows[:50]:
        if not isinstance(row, Mapping) or not isinstance(row.get("address"), str):
            continue
        other = row["address"].strip()
        when = row.get("last_seen") or row.get("first_seen")
        for key, outgoing in (("sent_to", True), ("usdt_out", True), ("received_from", False), ("usdt_in", False)):
            amount = parse_amount(row.get(key))
            if amount is None or amount[0] <= 0:
                continue
            edge = normalize_edge({"chain": chain, "from": focus if outgoing else other, "to": other if outgoing else focus,
                                   "value": str(amount[0]), "asset": amount[1], "time": when})
            if edge:
                edges.append(edge)
    return edges


# --------------------------------------------------------------------------------------
# policy (cond 1-4)
# --------------------------------------------------------------------------------------


def counterparties(edges: Iterable[dict[str, Any]], focus: str) -> dict[str, dict[str, Any]]:
    """Aggregate edges around ``focus``: {addr: {sent_to, received_from, tx_out, tx_in, first, last, direction}}.

    direction 'outgoing' (focus paid it), 'incoming_only' (it only paid the focus: possible victim, cond 3), 'both'."""
    out: dict[str, dict[str, Any]] = {}
    for edge in edges:
        if edge["from"] == focus:
            other, side = edge["to"], "out"
        elif edge["to"] == focus:
            other, side = edge["from"], "in"
        else:
            continue
        cp = out.setdefault(other, {"address": other, "sent_to": Decimal(0), "received_from": Decimal(0), "tx_out": 0,
                                    "tx_in": 0, "first": None, "last": None})
        if side == "out":
            cp["sent_to"] += edge["value"]
            cp["tx_out"] += 1
        else:
            cp["received_from"] += edge["value"]
            cp["tx_in"] += 1
        if edge["time"]:
            cp["first"] = edge["time"] if cp["first"] is None else min(cp["first"], edge["time"])
            cp["last"] = edge["time"] if cp["last"] is None else max(cp["last"], edge["time"])
    for cp in out.values():
        cp["direction"] = "both" if cp["tx_out"] and cp["tx_in"] else ("outgoing" if cp["tx_out"] else "incoming_only")
    return out


def _clean(value: Any, limit: int = 60) -> str | None:
    if not isinstance(value, str):
        return None
    text = re.sub(r"\s+", " ", _CONTROL_RE.sub("", value)).strip()
    return text[:limit] or None


def stop_node_reason(address: str, labels: Mapping[str, Any] | None = None, sanctioned: Iterable[str] = (),
                     degrees: Mapping[str, Any] | None = None, limit: int = HIGH_DEGREE_LIMIT) -> str | None:
    """Cond 2: why ``address`` is never expanded ('sanctioned', '<category>: <name>', 'high_degree: N ...'), or None.

    ``labels``: {address: [{'category', 'name', 'source'}]} reduced from crypto_address_labels (P358), walletexplorer
    (P208) and Blockscout tags; ``sanctioned``: addresses hit by P205; ``degrees``: {address: number of
    counterparties} (> ``limit`` = a high-degree hub)."""
    if address in set(sanctioned or ()):
        return "sanctioned"
    for label in (labels or {}).get(address, []) or []:
        if isinstance(label, Mapping) and str(label.get("category", "")).lower() in STOP_CATEGORIES:
            name = _clean(label.get("name"))
            return str(label["category"]).lower() + (f": {name}" if name else "")
    degree = (degrees or {}).get(address)
    if isinstance(degree, int) and not isinstance(degree, bool) and degree > limit:
        return f"high_degree: {degree} counterparties"
    return None


def rank_counterparties(cps: Mapping[str, dict[str, Any]], top_n: int = DEFAULT_TOP_N) -> list[dict[str, Any]]:
    """Outgoing counterparties ranked by value then frequency (cond 1 top-N); incoming-only senders are excluded."""
    eligible = [cp for cp in cps.values() if cp["direction"] in ("outgoing", "both")]
    eligible.sort(key=lambda cp: (-cp["sent_to"], -cp["tx_out"], cp["address"]))
    return eligible[: max(0, int(top_n))]


def plan_expansion(focus: str, edges: Iterable[Any], *, crypto_expand: bool = False, depth: int = DEFAULT_DEPTH,
                   depth_flag: bool = False, current_hop: int = 1, top_n: int = DEFAULT_TOP_N,
                   selected: Iterable[str] | None = None, labels: Mapping[str, Any] | None = None,
                   sanctioned: Iterable[str] = (), degrees: Mapping[str, Any] | None = None,
                   budget_left: int | None = None, requests_per_node: int = 1) -> dict[str, Any]:
    """The engine-policy decision for one investigated address (cond 1-4).

    Returns {'enabled', 'reason', 'max_depth', 'expand', 'stop_nodes', 'unselected', 'possible_victims',
    'budget_exhausted'}: nothing expands unless ``crypto_expand``; depth 1, 2 only with ``depth_flag``
    (``--crypto-depth 2``), never more; stop-nodes never expand; only outgoing counterparties are candidates;
    ``expand`` is the analyst's ``selected`` list when given, else the top-N; every other outgoing counterparty is
    listed in ``unselected`` with expand False, 'counterparty (role unknown)' and no maliciousness by association;
    ``budget_left`` (crypto_case_budget remaining) caps the expansion."""
    max_depth = MAX_DEPTH if (depth_flag and int(depth) >= 2) else DEFAULT_DEPTH
    norm = [e for e in (normalize_edge(x) for x in edges or ()) if e]
    cps = counterparties(norm, focus)
    victims = sorted(a for a, cp in cps.items() if cp["direction"] == "incoming_only")
    result: dict[str, Any] = {"enabled": bool(crypto_expand), "reason": None, "max_depth": max_depth, "expand": [],
                              "stop_nodes": {}, "unselected": [], "budget_exhausted": False,
                              "possible_victims": {"count": len(victims), "label": VICTIM_LABEL, "listed": False,
                                                   "addresses": victims}}
    for addr in sorted(cps):
        reason = stop_node_reason(addr, labels, sanctioned, degrees)
        if reason:
            result["stop_nodes"][addr] = reason
    if not crypto_expand:
        result["reason"] = "crypto_expand=false (opt-in engine policy)"
    elif int(current_hop) > max_depth:
        result["reason"] = f"depth limit {max_depth} reached"
    ranked = rank_counterparties({a: cp for a, cp in cps.items() if a not in result["stop_nodes"]}, top_n=len(cps))
    if selected is not None:
        chosen_set = set(selected)
        chosen = [cp for cp in ranked if cp["address"] in chosen_set]
    else:
        chosen = ranked[: max(0, int(top_n))]
    if result["reason"] is None:
        for cp in chosen:
            if budget_left is not None and (len(result["expand"]) + 1) * max(1, int(requests_per_node)) > int(budget_left):
                result["budget_exhausted"] = True
                break
            result["expand"].append(cp["address"])
    for cp in ranked:
        if cp["address"] not in result["expand"]:
            result["unselected"].append({"address": cp["address"], "label": COUNTERPARTY_LABEL, "expand": False,
                                         "sent_to": str(cp["sent_to"]), "tx_out": cp["tx_out"],
                                         "malicious_by_association": False})
    return result


# --------------------------------------------------------------------------------------
# summary and exports (cond 5)
# --------------------------------------------------------------------------------------


def money_trail_summary(seed: str, edges: Iterable[Any], *, labels: Mapping[str, Any] | None = None,
                        sanctioned: Iterable[str] = (), degrees: Mapping[str, Any] | None = None,
                        max_depth: int = DEFAULT_DEPTH, asset: str | None = None) -> dict[str, Any]:
    """'Where the money went' (cond 5): follow outgoing flows from ``seed`` up to ``max_depth`` hops (<= 2).

    Stop-nodes are endpoints, never traversed. Returns {'seed', 'hops', 'endpoints' (<= 10 labelled stop-nodes with
    hop, amount received on the traced path, first/last time), 'endpoints_total', 'first_exchange' (the earliest
    exchange reached: the legal-request target), 'total_out', 'assets', 'time_window', 'unlabelled_reached',
    'possible_victims', 'text'}. Amounts are summed per asset without conversion: call it per asset for a mixed
    graph. Never a list of hundreds of addresses."""
    norm = [e for e in (normalize_edge(x) for x in edges or ()) if e]
    if asset:
        norm = [e for e in norm if e["asset"] in (None, asset)]
    max_depth = max(1, min(int(max_depth), MAX_DEPTH))
    by_src: dict[str, list[dict[str, Any]]] = {}
    for edge in norm:
        by_src.setdefault(edge["from"], []).append(edge)
    frontier, visited = [seed], {seed}
    endpoints: dict[str, dict[str, Any]] = {}
    unlabelled: set[str] = set()
    times: list[int] = []
    hops_used = 0
    for hop in range(1, max_depth + 1):
        nxt: list[str] = []
        for node in frontier:
            for edge in sorted(by_src.get(node, []), key=lambda e: (e["time"] or 0, e["to"])):
                dst = edge["to"]
                if dst == seed:
                    continue
                if edge["time"]:
                    times.append(edge["time"])
                hops_used = max(hops_used, hop)
                reason = stop_node_reason(dst, labels, sanctioned, degrees)
                if reason:
                    ep = endpoints.setdefault(dst, {"address": dst, "label": reason, "hop": hop, "amount": Decimal(0),
                                                    "asset": edge["asset"], "first": None, "last": None,
                                                    "category": reason.split(":")[0],
                                                    "name": reason.split(": ", 1)[1] if ": " in reason else reason})
                    ep["hop"] = min(ep["hop"], hop)
                    ep["amount"] += edge["value"]
                    if edge["time"]:
                        ep["first"] = edge["time"] if ep["first"] is None else min(ep["first"], edge["time"])
                        ep["last"] = edge["time"] if ep["last"] is None else max(ep["last"], edge["time"])
                    continue
                unlabelled.add(dst)
                if dst not in visited:
                    visited.add(dst)
                    nxt.append(dst)
        frontier = nxt
    seed_cps = counterparties(norm, seed)
    outgoing = [e for e in norm if e["from"] == seed]
    totals: dict[str, Decimal] = {}
    for edge in outgoing:
        totals[edge["asset"] or ""] = totals.get(edge["asset"] or "", Decimal(0)) + edge["value"]
    victims = sum(1 for cp in seed_cps.values() if cp["direction"] == "incoming_only")
    ordered = sorted(endpoints.values(), key=lambda ep: (ep["hop"], ep["first"] or 0, ep["address"]))
    exchanges = [ep for ep in ordered if ep["category"] == "exchange"]
    first_exchange = min(exchanges, key=lambda ep: (ep["first"] or 2**62, ep["hop"], ep["address"])) if exchanges else None

    def show(ep: dict[str, Any]) -> dict[str, Any]:
        return {"address": ep["address"], "label": ep["label"], "category": ep["category"], "name": ep["name"], "hop": ep["hop"],
                "amount": f"{ep['amount']}" + (f" {ep['asset']}" if ep["asset"] else ""),
                "first": iso(ep["first"]), "last": iso(ep["last"])}

    total_text = ", ".join(f"{v} {k}".strip() for k, v in sorted(totals.items())) or "0"
    if first_exchange:
        text = (f"where the money went: {len(ordered)} labelled endpoint(s) within {hops_used} hop(s); first exchange "
                f"reached: {first_exchange['name']} at hop {first_exchange['hop']}, received {show(first_exchange)['amount']} "
                "(legal-request target)")
    elif ordered:
        text = f"where the money went: {len(ordered)} labelled endpoint(s) within {hops_used} hop(s); no exchange reached"
    else:
        text = "where the money went: no labelled endpoint reached"
    return {"seed": seed, "hops": hops_used, "endpoints": [show(ep) for ep in ordered[:SUMMARY_MAX_ENDPOINTS]],
            "endpoints_total": len(ordered), "first_exchange": show(first_exchange) if first_exchange else None,
            "total_out": total_text, "assets": sorted(k for k in totals if k),
            "time_window": [iso(min(times)), iso(max(times))] if times else [None, None],
            "unlabelled_reached": len(unlabelled), "possible_victims": victims, "text": text}


def graph_export(seed: str, edges: Iterable[Any], *, labels: Mapping[str, Any] | None = None,
                 sanctioned: Iterable[str] = (), degrees: Mapping[str, Any] | None = None,
                 selected: Iterable[str] = (), include_victims: bool = False) -> dict[str, Any]:
    """JSON-ready graph (cond 5): {'seed', 'nodes', 'edges', 'possible_victims'} sorted, values as strings.

    Node roles: seed | stop_node (with the reason) | counterparty ('counterparty (role unknown)'). Edges leaving a
    stop-node are dropped (stop-nodes are never expanded). Possible victims (incoming-only senders, cond 3) are only
    counted unless ``include_victims`` (an explicit analyst request)."""
    norm = [e for e in (normalize_edge(x) for x in edges or ()) if e]
    norm = [e for e in norm if e["from"] == seed or not stop_node_reason(e["from"], labels, sanctioned, degrees)]
    seed_cps = counterparties(norm, seed)
    victims = {a for a, cp in seed_cps.items() if cp["direction"] == "incoming_only"}
    if not include_victims:
        norm = [e for e in norm if e["from"] not in victims]
    chosen = set(selected or ())
    nodes: dict[str, dict[str, Any]] = {}
    for edge in norm:
        for addr in (edge["from"], edge["to"]):
            if addr in nodes:
                continue
            reason = stop_node_reason(addr, labels, sanctioned, degrees)
            if addr == seed:
                role, label = "seed", "investigated address"
            elif reason:
                role, label = "stop_node", reason
            elif addr in victims:
                role, label = "possible_victim", VICTIM_LABEL
            else:
                role, label = "counterparty", COUNTERPARTY_LABEL
            nodes[addr] = {"id": addr, "role": role, "label": label, "selected": addr in chosen}
    out_edges = [{"source": e["from"], "target": e["to"], "value": str(e["value"]), "asset": e["asset"],
                  "time": iso(e["time"]), "tx": e["tx"]}
                 for e in sorted(norm, key=lambda e: (e["time"] or 0, e["from"], e["to"], e["tx"] or ""))]
    return {"seed": seed, "nodes": [nodes[k] for k in sorted(nodes)], "edges": out_edges,
            "possible_victims": {"count": len(victims), "label": VICTIM_LABEL, "listed": bool(include_victims)}}


def graph_to_graphml(graph: Mapping[str, Any]) -> str:
    """:func:`graph_export` dict -> GraphML text (stdlib XML escaping, control characters removed)."""

    def attr(value: Any) -> str:
        return _xml_escape(_CONTROL_RE.sub("", "" if value is None else str(value)), {'"': "&quot;"})

    lines = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
             '  <key id="role" for="node" attr.name="role" attr.type="string"/>',
             '  <key id="label" for="node" attr.name="label" attr.type="string"/>',
             '  <key id="value" for="edge" attr.name="value" attr.type="string"/>',
             '  <key id="asset" for="edge" attr.name="asset" attr.type="string"/>',
             '  <key id="time" for="edge" attr.name="time" attr.type="string"/>',
             '  <key id="tx" for="edge" attr.name="tx" attr.type="string"/>',
             f'  <graph id="{attr(graph.get("seed"))}" edgedefault="directed">']
    for node in graph.get("nodes", []):
        lines.append(f'    <node id="{attr(node["id"])}"><data key="role">{attr(node["role"])}</data>'
                     f'<data key="label">{attr(node["label"])}</data></node>')
    for i, edge in enumerate(graph.get("edges", [])):
        lines.append(f'    <edge id="e{i}" source="{attr(edge["source"])}" target="{attr(edge["target"])}">'
                     f'<data key="value">{attr(edge["value"])}</data><data key="asset">{attr(edge["asset"])}</data>'
                     f'<data key="time">{attr(edge["time"])}</data><data key="tx">{attr(edge["tx"])}</data></edge>')
    lines += ["  </graph>", "</graphml>"]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------------------
# case-graph adapters (read-only; used by the correlation rule and the core)
# --------------------------------------------------------------------------------------

#: entity/finding tags and stop_node_hint values the sibling modules set (P208/P358/P212/P205)
_TAG_CATEGORY = {"exchange": "exchange", "mixer": "mixer", "bridge": "bridge", "pool": "pool", "mining_pool": "pool",
                 "custodial_service": "custodial_service", "crypto_service": "pool"}


def _first_label(attributes: Mapping[str, Any]) -> str | None:
    for value, _src in attributes.get("wallet_labels", []) or []:
        for item in value if isinstance(value, list) else [value]:
            if isinstance(item, str) and item.strip():
                return _clean(item)
            if isinstance(item, Mapping):
                name = item.get("name") or item.get("label")
                if isinstance(name, str) and name.strip():
                    return _clean(name)
    return None


def labels_from_node(node: Any) -> tuple[list[dict[str, Any]], bool, int | None]:
    """(labels [{category, name, source}], sanctioned, degree) of a case-graph node (cond 2 inputs).

    Reads ``stop_node_hint`` (walletexplorer, evm_explorers, crypto_address_labels), finding/entity tags exchange,
    mixer, crypto_service, the ``sanctioned`` attribute and sanctions findings (P205), and ``tx_count`` as the degree
    proxy when no counterparty count is known."""
    labels: list[dict[str, Any]] = []
    attributes = getattr(node, "attributes", {}) or {}
    for value, src in attributes.get("stop_node_hint", []) or []:
        category = _TAG_CATEGORY.get(str(value).lower(), str(value).lower())
        if category in STOP_CATEGORIES:
            labels.append({"category": category, "name": _first_label(attributes), "source": src})
    tags: set[str] = set(getattr(node, "tags", set()) or set())
    findings = list(getattr(node, "findings", []) or [])
    for f in findings:
        tags.update(getattr(f, "tags", ()) or ())
    for tag, category in _TAG_CATEGORY.items():
        if tag in tags and not any(lb["category"] == category for lb in labels):
            labels.append({"category": category, "name": None, "source": "tag"})
    sanctioned = any(v is True for v, _ in attributes.get("sanctioned", []) or []) or any(
        "sanctions" in (getattr(f, "tags", ()) or ()) and getattr(f, "module", "") in ("crypto_sanctions_offline", "crypto_sanctions_onchain")
        for f in findings)
    degrees = [v for v, _ in attributes.get("counterparty_count", []) or [] if isinstance(v, int) and not isinstance(v, bool)]
    degrees += [v for v, _ in attributes.get("tx_count", []) or [] if isinstance(v, int) and not isinstance(v, bool)]
    return labels, sanctioned, (max(degrees) if degrees else None)


def case_inputs(graph: Any) -> dict[str, Any]:
    """Edges, labels, sanctioned set and degrees of every wallet of a case graph (from explorer attributes)."""
    edges: list[dict[str, Any]] = []
    labels: dict[str, list[dict[str, Any]]] = {}
    sanctioned: set[str] = set()
    degrees: dict[str, int] = {}
    nodes = getattr(graph, "nodes", {}) or {}
    for node in nodes.values():
        entity = getattr(node, "entity", None)
        etype = getattr(getattr(entity, "type", None), "value", "")
        if etype not in WALLET_TYPES:
            continue
        address = str(entity.value)
        node_labels, is_sanctioned, degree = labels_from_node(node)
        if node_labels:
            labels[address] = node_labels
        if is_sanctioned:
            sanctioned.add(address)
        if degree is not None:
            degrees[address] = degree
        for value, _src in (getattr(node, "attributes", {}) or {}).get("top_counterparties", []) or []:
            edges.extend(edges_from_counterparties(address, value, chain=etype))
    unique: dict[tuple[Any, ...], dict[str, Any]] = {}
    for edge in edges:
        unique.setdefault((edge["from"], edge["to"], edge["asset"], str(edge["value"])), edge)
    return {"edges": list(unique.values()), "labels": labels, "sanctioned": sanctioned, "degrees": degrees}


__all__ = [
    "COUNTERPARTY_LABEL",
    "HIGH_DEGREE_LIMIT",
    "POLICY_DEFAULTS",
    "STOP_CATEGORIES",
    "VICTIM_LABEL",
    "case_inputs",
    "counterparties",
    "edges_from_counterparties",
    "graph_export",
    "graph_to_graphml",
    "labels_from_node",
    "money_trail_summary",
    "normalize_edge",
    "parse_amount",
    "plan_expansion",
    "rank_counterparties",
    "stop_node_reason",
]
