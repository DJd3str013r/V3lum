"""Recurrent infrastructure across cases (P375 cond 4-5): rule ``recurrent_infrastructure``.

The rule reads the ``sightings`` attribute the ``case_sightings`` module records from the local case
DB (``{count, last, verdict, restricted}``, TLP-filtered: v3lum/modules/utility/case_sightings.py) and
fires when the same IOC - a domain or onion, a URL, an IP address, a file hash or a wallet - appears in
at least two cases: this one and at least one earlier case (visible or restricted). It never applies
to natural persons or to PERSONAL_TYPES (e-mail, username, phone, CPF, PIX keys, handles...), and it
ignores noise (public resolvers, CDNs, big providers, sinkholes, parking, benign scanners,
warninglisted values) and own org assets. A recurrence is a lead for the analyst, not a verdict:
severity follows the verdict an earlier visible case recorded (malicious/c2/phishing/compromised ->
medium, benign -> info, otherwise low). The rule makes no lookup itself and never names an earlier
case (no ids or dates of restricted cases).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from v3lum.core.correlate import rule
from v3lum.core.entities import PERSONAL_TYPES, EntityType
from v3lum.core.graph import Graph, Node
from v3lum.core.models import Correlation, ModuleResult, Severity
from v3lum.core.store import NOISE_TAGS

#: Listed in ``store.CROSS_CASE_RULES``: exports omit the rule's correlations at CLEAR/GREEN (A2).
RULE_ID = "recurrent_infrastructure"
#: IOC types the rule covers: domain/onion, URL, IP, file hashes and wallets (P375 cond 5).
RECURRENT_TYPES: frozenset[EntityType] = frozenset({
    EntityType.DOMAIN, EntityType.ONION, EntityType.URL, EntityType.IPV4, EntityType.IPV6,
    EntityType.MD5, EntityType.SHA1, EntityType.SHA256, EntityType.SHA512, EntityType.SSDEEP, EntityType.IMPHASH,
    EntityType.TLSH, EntityType.TELFHASH, EntityType.GIMPHASH, EntityType.AUTHENTIHASH,
    EntityType.BTC, EntityType.ETH, EntityType.XMR, EntityType.CRYPTO,
}) - PERSONAL_TYPES
#: Earlier verdicts that raise a recurrence to medium.
HOSTILE_VERDICTS: frozenset[str] = frozenset({"malicious", "c2", "phishing", "compromised"})
CRITERION = "same indicator in >= 2 V3LUM cases (case-DB sightings, TLP-filtered)"


def _sightings(node: Node) -> dict[str, Any] | None:
    """The node's sightings attribute (the first readable one)."""
    for value in node.attr_values("sightings"):
        if isinstance(value, Mapping):
            return dict(value)
    return None


def _count(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _excluded(node: Node) -> bool:
    """Noise, warninglisted, allow-listed or own org asset."""
    if node.noise or node.noise_kind or node.ownership == "own_asset" or "own_asset" in node.tags:
        return True
    if NOISE_TAGS & set(node.tags):
        return True
    if any(str(s.get("rule", "")) in ("SUP-warninglist", "SUP-sinkhole") for f in node.findings for s in f.suppressed_by if isinstance(s, dict)):
        return True
    try:
        from v3lum.core import noise

        return bool(noise.warninglists(node.entity))
    except Exception:  # noqa: BLE001 - an unusable list never invents a recurrence
        return False


@rule(
    RULE_ID,
    "Recurrent infrastructure across cases",
    "The same IOC (domain, URL, IP, file hash or wallet) appears in at least two V3LUM cases (case-DB sightings).",
    code="P375",
    severity="low",
    criterion=CRITERION,
    false_positives=(
        "Shared hosting, CDNs and benign infrastructure not on a noise list recur across unrelated cases; earlier "
        "verdicts may be automatic. A recurrence is a lead: open the earlier cases before linking them."
    ),
)
def recurrent_infrastructure(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    for node in graph.nodes.values():
        if node.entity.type not in RECURRENT_TYPES or _excluded(node):
            continue
        seen = _sightings(node)
        if seen is None:
            continue
        visible, restricted = _count(seen.get("count")), _count(seen.get("restricted"))
        if visible + restricted < 1:
            continue
        verdict = str(seen.get("verdict") or "").strip().lower() if visible else ""
        if verdict in HOSTILE_VERDICTS:
            severity = Severity.MEDIUM
        elif verdict == "benign":
            severity = Severity.INFO
        else:
            severity = Severity.LOW
        parts = []
        if visible:
            parts.append(f"{visible} earlier case{'s' if visible != 1 else ''} (last {seen.get('last') or 'unknown'}, verdict: {verdict or 'none'})")
        if restricted:
            parts.append(f"{restricted} restricted case{'s' if restricted != 1 else ''} (higher TLP: counted only)")
        evidence = [f"seen in {' and '.join(parts)}"]
        evidence += [f.id for f in node.findings if f.module == "case_sightings" and f.id]
        yield Correlation(
            rule=RULE_ID,
            title="Recurrent infrastructure across cases",
            severity=severity,
            description=(
                f"{node.entity.display} ({node.entity.type.value}) also appears in {' and '.join(parts)}: the same "
                "infrastructure recurs across investigations."
            ),
            entities=[node.entity],
            confidence="confirmed",
            evidence=evidence,
            recommendation=(
                "Review the earlier cases (v3lum cases list --search) before linking the investigations; long-lived IOC "
                "memory belongs in the team's MISP/OpenCTI."
            ),
            tags=["infrastructure"],
            criterion=CRITERION,
            why=f"same {node.entity.type.value} in this case and {visible + restricted} earlier case{'s' if visible + restricted != 1 else ''}",
            key=node.key,
        )
