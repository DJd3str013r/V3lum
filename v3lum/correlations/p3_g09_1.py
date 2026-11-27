"""Correlation rules of batch p3-G09-1 (ENS resolution P209, transaction-graph policy P213).

* ``p3g091_money_trail`` - P213 cond 5: the 'where the money went' summary of every investigated wallet that has
  outgoing flows in the case (explorer ``top_counterparties``): labelled endpoints reached (exchanges, mixers,
  bridges, pools, sanctioned, high-degree hubs), hop count, amounts, time window, and the first exchange reached -
  the legal-request target. Possible victims (addresses that only paid the wallet) are counted, never listed;
  counterparties stay 'counterparty (role unknown)' and nothing is scored malicious by association (cond 3-4).
  It follows flows only through wallets the case already investigated (no BFS, no request: cond 1), up to setting
  ``crypto_depth`` hops (1 by default, 2 at most).
* ``p3g091_ens_claim_linked_back`` - P209 cond 2: an ENS text-record claim (self-asserted, POSSIBLE) becomes
  PROBABLE when the linked profile, found by ANOTHER module in the case, points back to the ENS name or one of
  its wallets. Rules never change edges: the upgrade is this correlation (PROBABLE) on the claim.

Both only read the graph.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from v3lum.core.correlate import rule
from v3lum.core.entities import Entity, EntityType
from v3lum.core.graph import Graph
from v3lum.core.models import Correlation, ModuleResult, Severity
from v3lum.modules.crypto.crypto_tx_graph import (
    COUNTERPARTY_LABEL,
    DEFAULT_DEPTH,
    MAX_DEPTH,
    WALLET_TYPES,
    case_inputs,
    money_trail_summary,
)
from v3lum.modules.crypto.ens_resolver import SELF_ASSERTED, ens_claim_confidence

MONEY_RULE = "p3g091_money_trail"
ENS_RULE = "p3g091_ens_claim_linked_back"
MAX_CORRELATIONS = 25
MAX_TEXTS = 200
MAX_TEXT_LEN = 2000
_CLAIM_TYPES = frozenset({EntityType.USERNAME, EntityType.EMAIL, EntityType.URL, EntityType.DOMAIN})


def _setting(rctx: Any, name: str, default: Any) -> Any:
    try:
        value = rctx.setting(name, default) if rctx is not None else default
    except Exception:  # noqa: BLE001 - an unregistered setting reads as its default
        return default
    return default if value is None else value


def _wallet_entity(graph: Graph, address: str) -> Entity | None:
    for etype in WALLET_TYPES:
        node = graph.get(f"{etype}:{address}")
        if node is not None:
            return node.entity
    return None


@rule(
    MONEY_RULE,
    "Where the money went (transaction-graph summary)",
    "For each investigated wallet with outgoing flows, follows the outgoing counterparties reported by the explorer "
    "modules (through wallets the case already investigated, up to setting crypto_depth hops, 1 by default) and "
    "summarises the labelled endpoints reached - exchanges, mixers, bridges, pools, sanctioned addresses, high-degree "
    "hubs - with hop count, amounts and time window, highlighting the first exchange (the legal-request target). "
    "Possible victims are counted, never listed (P213 cond 3-5).",
    version="1",
    severity="info",
    criterion="outgoing transacted_with flows of an investigated wallet (explorer top_counterparties) followed to labelled stop-nodes",
    false_positives="Explorer counterparties are a sample of the newest transactions; exchange deposit addresses are often shared "
    "(the exchange is the legal-request target, not the owner). Amounts are per asset, not converted.",
    fixtures=(
        f"tests/fixtures/rules/{MONEY_RULE}/positive_exchange_reached.json",
        f"tests/fixtures/rules/{MONEY_RULE}/negative_incoming_only.json",
    ),
)
def money_trail(graph: Graph, results: list[ModuleResult], rctx: Any = None) -> Iterable[Correlation]:
    inputs = case_inputs(graph)
    if not inputs["edges"]:
        return
    try:
        depth = int(_setting(rctx, "crypto_depth", DEFAULT_DEPTH))
    except (TypeError, ValueError):
        depth = DEFAULT_DEPTH
    depth = max(1, min(depth, MAX_DEPTH))
    emitted = 0
    for node in sorted(graph.nodes.values(), key=lambda n: n.key):
        if emitted >= MAX_CORRELATIONS:
            return
        if node.entity.type.value not in WALLET_TYPES or not (node.seed or node.investigated):
            continue
        seed = str(node.entity.value)
        assets = sorted({e["asset"] or "" for e in inputs["edges"] if e["from"] == seed})
        for asset in assets:
            summary = money_trail_summary(seed, inputs["edges"], labels=inputs["labels"], sanctioned=inputs["sanctioned"],
                                          degrees=inputs["degrees"], max_depth=depth, asset=asset or None)
            if not summary["hops"]:
                continue
            entities = [node.entity]
            first = summary["first_exchange"]
            if first:
                target = _wallet_entity(graph, first["address"])
                if target is not None:
                    entities.append(target)
            evidence = [summary["text"], f"total out {summary['total_out']}"]
            window = summary["time_window"]
            if window[0]:
                evidence.append(f"time window {window[0]} .. {window[1]}")
            evidence += [f"hop {ep['hop']}: {ep['address']} ({ep['label']}) received {ep['amount']}" for ep in summary["endpoints"]]
            if summary["endpoints_total"] > len(summary["endpoints"]):
                evidence.append(f"{summary['endpoints_total'] - len(summary['endpoints'])} more labelled endpoint(s) not listed")
            evidence.append(f"{summary['unlabelled_reached']} unlabelled counterparties: {COUNTERPARTY_LABEL}, never scored by association")
            evidence.append(f"{summary['possible_victims']} possible victim(s) (only paid this wallet): counted, not listed")
            recommendation = (f"Send a legal request to {first['name']} for the deposit account behind {first['address']} "
                              f"(first exchange reached at hop {first['hop']})." if first else
                              "No exchange reached within the depth: investigate the top outgoing counterparties manually "
                              "(select them explicitly) or raise the depth to 2 with --crypto-depth 2.")
            yield Correlation(
                rule=MONEY_RULE,
                title="Where the money went (transaction-graph summary)",
                severity=Severity.INFO,
                description=(f"{summary['text']}. Outgoing flows of {seed} followed up to {depth} hop(s) through investigated "
                             f"wallets only; {summary['endpoints_total']} labelled endpoint(s); {summary['possible_victims']} "
                             "possible victim(s) counted, not listed. A summary of explorer samples, not a full trace."),
                entities=entities,
                confidence="probable",
                evidence=evidence[:20],
                recommendation=recommendation,
                tags=[],
                criterion=f"outgoing flows of an investigated wallet followed {depth} hop(s) to labelled stop-nodes",
                key=f"{seed}|{asset}",
            )
            emitted += 1


def _texts(value: Any, out: list[str], depth: int = 0) -> None:
    if len(out) >= MAX_TEXTS or depth > 3:
        return
    if isinstance(value, str):
        out.append(value[:MAX_TEXT_LEN])
    elif isinstance(value, dict):
        for item in list(value.values())[:50]:
            _texts(item, out, depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in list(value)[:50]:
            _texts(item, out, depth + 1)


def _profile_texts(graph: Graph, node: Any) -> list[str]:
    """Strings other modules recorded about the claimed profile (never ens_resolver's own records)."""
    nodes = [node]
    if node.entity.type is EntityType.USERNAME:
        handle = str(node.entity.value).lower()
        nodes += [n for n in graph.of_type(EntityType.SOCIAL_ACCOUNT) if str(n.entity.value).lower().split(":", 1)[-1] == handle]
    out: list[str] = []
    for n in nodes:
        for values in n.attributes.values():
            for value, src in values:
                if src != "ens_resolver":
                    _texts(value, out)
        for f in n.findings:
            if f.module != "ens_resolver":
                _texts(f.description, out)
                _texts(f.data, out)
    return out[:MAX_TEXTS]


@rule(
    ENS_RULE,
    "ENS text-record claim linked back by the profile",
    "An ENS text record (twitter, github, url, email...) is self-asserted by the ENS owner and only POSSIBLE; when the "
    "linked profile, found by another module in the case, mentions the ENS name or one of its wallets, the link holds "
    "both ways and the claim becomes PROBABLE (P209 cond 2).",
    version="1",
    severity="info",
    criterion="ens_text_record claim + the claimed profile (another module) contains the ENS name or a wallet of it",
    false_positives="A profile can quote someone else's ENS name (a tip jar, a mention): read the matching text before relying on it.",
    fixtures=(
        f"tests/fixtures/rules/{ENS_RULE}/positive_profile_points_back.json",
        f"tests/fixtures/rules/{ENS_RULE}/negative_claim_only.json",
    ),
)
def ens_claim_linked_back(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    emitted = 0
    for edge in sorted(graph.edges, key=lambda e: (e.src, e.dst)):
        if edge.relation != "ens_text_record" or emitted >= MAX_CORRELATIONS:
            continue
        src, dst = graph.get(edge.src), graph.get(edge.dst)
        if src is None or dst is None or dst.entity.type not in _CLAIM_TYPES:
            continue
        names = [v for v in src.attr_values("ens_name") if isinstance(v, str)]
        if src.entity.type is EntityType.DOMAIN and str(src.entity.value).endswith(".eth"):
            names.append(str(src.entity.value))
        wallets: list[str] = []
        for value in src.attr_values("ens_wallets"):
            if isinstance(value, dict):
                wallets += [str(v) for v in value.values() if isinstance(v, str)]
        if src.entity.type in (EntityType.ETH, EntityType.BTC, EntityType.CRYPTO):
            wallets.append(str(src.entity.value))
        wallets += [str(e.dst.split(":", 1)[1]) for e in graph.out_edges(src.key, "ens_resolves_to")]
        texts = _profile_texts(graph, dst)
        if not texts:
            continue
        found = None
        for name in sorted(set(names)) or [None]:
            label, evidence = ens_claim_confidence(texts, name, wallets)
            if label == "probable":
                found = evidence
                break
        if not found:
            continue
        emitted += 1
        yield Correlation(
            rule=ENS_RULE,
            title="ENS text-record claim linked back by the profile",
            severity=Severity.INFO,
            description=(f"{src.entity.display} lists {dst.entity.display} in an ENS text record ({SELF_ASSERTED}); the "
                         f"profile recorded by another module points back ({found}). The link holds both ways: PROBABLE, "
                         "still not identity proof."),
            entities=[src.entity, dst.entity],
            confidence="probable",
            evidence=[found],
            recommendation="Treat the ENS name and the profile as the same operator for pivoting; confirm with a third source before attribution.",
            tags=[],
            criterion="self-asserted ENS text record + reciprocal mention on the linked profile",
            key=dst.key,
        )


__all__ = ["ENS_RULE", "MONEY_RULE", "ens_claim_linked_back", "money_trail"]
