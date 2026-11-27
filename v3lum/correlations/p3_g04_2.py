"""Correlation rule of batch p3-G04-2: Leak-Lookup breach names merged with the other breach sources (P140 cond 4).

``p3g042_leaklookup_breach_merge``: ``leak_lookup_public`` emits one finding per breach NAME (tag
``breach``) whose ``data['breach_key']`` is the normalised name resolved through the shared HIBP catalogue
(P132 helper), exactly like ``hibp_account``, ``xposedornot`` and ``leakcheck_public`` (P133). On one
identity node, a Leak-Lookup finding that shares its key with a finding of one of those modules is the
same breach: it becomes INFO ``context_only`` context of the strongest partner finding (the finding of
record, chosen like ``p2g04_breach_merge`` chooses it: severity, then HIBP, XposedOrNot, LeakCheck), whose
``data['sources']`` gains ``leaklookup.search``. Leak-Lookup only names breaches (no dates, no data classes
of its own), so it never adds a second scored finding for a breach another source already reported, and
the noisy-OR counts the breach once. One INFO correlation per merged breach documents the merge.
Sensitive breaches merge on their masked key and stay masked; analyst overrides are never crossed; a
finding merged by an earlier run of the same case is never lowered twice.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from v3lum.core.correlate import rule
from v3lum.core.graph import Graph
from v3lum.core.models import Correlation, Finding, ModuleResult, Severity

RULE_LEAKLOOKUP_MERGE = "p3g042_leaklookup_breach_merge"
LEAKLOOKUP_MODULE = "leak_lookup_public"
LEAKLOOKUP_SOURCE = "leaklookup.search"
#: partner modules (P133 merge set) in finding-of-record order
PARTNER_ORDER = {"hibp_account": 0, "xposedornot": 1, "leakcheck_public": 2}


def _key(f: Finding) -> str:
    data = f.data if isinstance(f.data, dict) else {}
    key = data.get("breach_key")
    if not isinstance(key, str) or not key or "breach" not in (f.tags or ()):
        return ""
    return key if f.module == LEAKLOOKUP_MODULE or f.module in PARTNER_ORDER else ""


def _already_merged(f: Finding) -> bool:
    return any(isinstance(s, dict) and s.get("rule") == RULE_LEAKLOOKUP_MERGE for s in (f.suppressed_by or ()))


def _data(f: Finding) -> dict[str, Any]:
    return f.data if isinstance(f.data, dict) else {}


@rule(
    RULE_LEAKLOOKUP_MERGE,
    "Leak-Lookup breach also reported by another source",
    "A leak_lookup_public breach-name finding that shares the normalised breach name with a hibp_account, xposedornot or "
    "leakcheck_public finding on the same identity is the same breach: the partner finding stays the finding of record and "
    "lists Leak-Lookup among its sources; the Leak-Lookup finding becomes INFO context so the breach is scored once.",
    version="1",
    severity="info",
    criterion="leak_lookup_public and hibp_account/xposedornot/leakcheck_public breach findings sharing data.breach_key "
    "(normalised name joined through the shared HIBP catalogue)",
    false_positives="Two different breaches of one service in the same year with the same name (HIBP names them apart, e.g. 'Zacks2024').",
    fixtures=(
        f"tests/fixtures/rules/{RULE_LEAKLOOKUP_MERGE}/positive_leaklookup_and_hibp_same_breach.json",
        f"tests/fixtures/rules/{RULE_LEAKLOOKUP_MERGE}/negative_leaklookup_alone_or_other_breach.json",
    ),
)
def leaklookup_breach_merge(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    for node in graph.nodes.values():
        groups: dict[str, dict[str, list[Finding]]] = {}
        for f in node.findings:
            key = _key(f)
            if key:
                side = "ll" if f.module == LEAKLOOKUP_MODULE else "partners"
                groups.setdefault(key, {"ll": [], "partners": []})[side].append(f)
        for key in sorted(groups):
            ll, partners = groups[key]["ll"], groups[key]["partners"]
            if not ll or not partners:
                continue
            primary = max(partners, key=lambda f: (int(f.severity), -PARTNER_ORDER.get(f.module, 9)))
            merged: list[Finding] = []
            for f in ll:
                if f.override:
                    continue  # analyst overrides are never crossed
                data = _data(f)
                if _already_merged(f):
                    merged.append(f)
                    continue
                before = f.severity.label
                f.downgrade(RULE_LEAKLOOKUP_MERGE, f"same breach as the {primary.module} finding {primary.id}: Leak-Lookup names it too")
                f.data = {**data, "merged_into": primary.id, "severity_before_merge": before}
                f.severity = Severity.INFO
                if "context_only" not in f.tags:
                    f.tags.append("context_only")
                merged.append(f)
            if not merged:
                continue
            pdata = _data(primary)
            sources = [s for s in pdata.get("sources") or [primary.source] if isinstance(s, str) and s]
            if LEAKLOOKUP_SOURCE not in sources:
                sources.append(LEAKLOOKUP_SOURCE)
            primary.data = {**pdata, "sources": sources}
            name = pdata.get("name") or key
            yield Correlation(
                rule=RULE_LEAKLOOKUP_MERGE,
                title=f"Breach also reported by Leak-Lookup: {name}",
                severity=Severity.INFO,
                description=f"Leak-Lookup names the same breach ({name}) for {node.entity.display} as {primary.module}: the finding of "
                f"record is '{primary.title}' ({primary.module}); the Leak-Lookup report is kept as context and not scored again.",
                entities=[node.entity],
                confidence="confirmed",
                evidence=[primary.id, *(f.id for f in merged)],
                recommendation="Read the finding of record: its date, data classes and next step apply once for this breach.",
                tags=["breach", "privacy"],
                criterion=f"breach findings of {LEAKLOOKUP_MODULE} and {primary.module} sharing breach_key {key}",
                key=key,
            )


__all__ = ["RULE_LEAKLOOKUP_MERGE", "leaklookup_breach_merge"]
