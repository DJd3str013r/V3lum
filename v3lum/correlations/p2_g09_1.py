"""Correlation rules of batch p2-G09-1 (Chainabuse, GoPlus, WalletExplorer).

* ``p2g09_chainabuse_corroborated`` - P204 cond 4: Chainabuse community reports never go above medium on
  their own; with independent corroboration on the same wallet - an OFAC/Chainalysis sanctions finding
  (P205), a GoPlus malicious-address flag (phishing, theft, cybercrime, money laundering, extortion), a
  ransomware finding from another module (e.g. a payment-address tracker) or an explorer label naming a
  scam/phishing/hack/market/ransomware wallet - this rule raises the case to HIGH. It only reads the graph.
* ``p2g09_walletexplorer_lag`` - P208 cond 3: WalletExplorer's ``updated_to_block`` is compared with the
  chain tip btc_explorers reports for the same address (``data_freshness.provider_tip_height``): the line
  shows how many blocks (~hours) of transactions WalletExplorer has not clustered yet.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from v3lum.core.correlate import rule
from v3lum.core.entities import EntityType
from v3lum.core.graph import Graph
from v3lum.core.models import Correlation, ModuleResult, Severity

CHAINABUSE_RULE = "p2g09_chainabuse_corroborated"
LAG_RULE = "p2g09_walletexplorer_lag"
WALLET_TYPES = frozenset({EntityType.BTC, EntityType.ETH, EntityType.XMR, EntityType.CRYPTO})
SANCTIONS_MODULES = frozenset({"crypto_sanctions_offline", "crypto_sanctions_onchain"})
GOPLUS_TAGS = frozenset({"phishing", "theft", "cybercrime", "money_laundering", "extortion", "crypto_scam"})
LABEL_TAGS = frozenset({"darknet_market", "ransomware", "fraud"})
_BAD_LABEL_RE = re.compile(r"scam|phish|fraud|hack|exploit|heist|drain|fake|ransom|market|launder|stolen|theft", re.I)
MINUTES_PER_BLOCK = 10


def _values(node: Any, name: str) -> list[tuple[Any, str]]:
    return [(value, str(src)) for value, src in node.attributes.get(name, [])]


def _corroboration(node: Any) -> dict[str, list[str]]:
    """Independent signals on the node, by kind -> evidence finding ids / labels."""
    out: dict[str, list[str]] = {}
    for f in node.findings:
        tags = set(f.tags or ())
        if f.module in SANCTIONS_MODULES and "sanctions" in tags:
            out.setdefault("sanctions list", []).append(f.id or f.title)
        elif f.module == "goplus_security" and tags & GOPLUS_TAGS:
            out.setdefault("GoPlus flag", []).append(f.id or f.title)
        elif f.module not in ("chainabuse", "goplus_security") and "ransomware" in tags:
            out.setdefault("ransomware finding", []).append(f.id or f.title)
        elif f.module == "walletexplorer" and tags & LABEL_TAGS:
            out.setdefault("explorer label", []).append(f.id or f.title)
    for value, src in _values(node, "wallet_labels"):
        if src == "chainabuse":
            continue
        labels = value if isinstance(value, list) else [value]
        bad = [str(v) for v in labels if isinstance(v, str) and _BAD_LABEL_RE.search(v)]
        if bad:
            out.setdefault("explorer label", []).extend(bad)
    return out


@rule(
    CHAINABUSE_RULE,
    "Chainabuse reports corroborated by an independent source",
    "Community scam reports on Chainabuse (unverified, at most medium on their own) are corroborated on the same wallet by "
    "a sanctions list, a GoPlus malicious-address flag, a ransomware finding of another module or an explorer label naming "
    "a scam, phishing, hack, market or ransomware wallet (P204 cond 4).",
    version="1",
    severity="high",
    criterion="a chainabuse finding (fraud or suspicious) plus at least one independent corroborating signal on the same wallet",
    false_positives="Reused deposit addresses of large services can collect both community reports and labels; check the explorer labels before acting.",
    fixtures=(
        f"tests/fixtures/rules/{CHAINABUSE_RULE}/positive_goplus_theft.json",
        f"tests/fixtures/rules/{CHAINABUSE_RULE}/negative_reports_only.json",
    ),
)
def chainabuse_corroborated(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    for node in graph.nodes.values():
        if node.entity.type not in WALLET_TYPES:
            continue
        reports = [f for f in node.findings if f.module == "chainabuse" and {"fraud", "suspicious"} & set(f.tags or ())]
        if not reports:
            continue
        signals = _corroboration(node)
        if not signals:
            continue
        kinds = sorted(signals)
        yield Correlation(
            rule=CHAINABUSE_RULE,
            title="Chainabuse reports corroborated by an independent source",
            severity=Severity.HIGH,
            description=(
                f"Chainabuse community reports on this wallet are corroborated by: {', '.join(kinds)}. The reports alone are "
                "user-submitted and unverified; together with the independent signal the wallet is very likely involved in "
                "fraud. Corroboration is not attribution of the owner."
            ),
            entities=[node.entity],
            confidence="probable",
            evidence=[f.id for f in reports if f.id] + [e for v in signals.values() for e in v if re.fullmatch(r"[0-9a-f]{16}", str(e))],
            recommendation="Treat the wallet as malicious for blocking and reporting; escalate sanctions hits to compliance.",
            tags=["fraud"],
            criterion="chainabuse reports + " + ", ".join(kinds),
        )


@rule(
    LAG_RULE,
    "WalletExplorer data lags the chain tip",
    "WalletExplorer clusters only up to its updated_to_block; btc_explorers reports the current chain tip for the same "
    "address. The difference is the number of recent blocks whose transactions are not in the WalletExplorer cluster yet "
    "(P208 cond 3).",
    version="1",
    severity="info",
    criterion="wallet_cluster.updated_to_block (walletexplorer) < data_freshness.provider_tip_height (btc_explorers) on the same address",
    false_positives="None: the line states the data age only.",
    fixtures=(
        f"tests/fixtures/rules/{LAG_RULE}/positive_lagging_cluster.json",
        f"tests/fixtures/rules/{LAG_RULE}/negative_no_chain_tip.json",
    ),
)
def walletexplorer_lag(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    for node in graph.nodes.values():
        if node.entity.type is not EntityType.BTC:
            continue
        blocks = [v.get("updated_to_block") for v, src in _values(node, "wallet_cluster") if src == "walletexplorer" and isinstance(v, dict)]
        blocks = [b for b in blocks if isinstance(b, int) and not isinstance(b, bool)]
        tips = [
            (v.get("provider_tip_height"), str(v.get("provider") or src))
            for v, src in _values(node, "data_freshness")
            if isinstance(v, dict) and src != "walletexplorer"
        ]
        tips = [(t, p) for t, p in tips if isinstance(t, int) and not isinstance(t, bool)]
        if not blocks or not tips:
            continue
        block = max(blocks)
        tip, provider = max(tips)
        lag = tip - block
        if lag <= 0:
            continue
        hours = round(lag * MINUTES_PER_BLOCK / 60.0, 1)
        yield Correlation(
            rule=LAG_RULE,
            title="WalletExplorer data lags the chain tip",
            severity=Severity.INFO,
            description=(
                f"WalletExplorer data is as of block {block}; the chain tip per {provider} is {tip}: {lag} blocks (~{hours:g} h) "
                "of recent transactions are not clustered by WalletExplorer yet."
            ),
            entities=[node.entity],
            confidence="confirmed",
            evidence=[],
            recommendation="Read recent activity from the block explorers; use the WalletExplorer cluster for history only.",
            tags=[],
            criterion=f"updated_to_block {block} < chain tip {tip} ({provider})",
            key=str(block),
        )
