"""Correlation rule of batch p2-G04-1: one breach, one finding (P133 cond 7, P135 cond 7, P137 cond 7).

``p2g04_breach_merge``: the per-account breach modules (``hibp_account``, ``xposedornot``,
``leakcheck_public``) each emit one finding per breach (tag ``breach``) whose ``data['breach_key']`` is
the normalised breach name, resolved through the shared HIBP catalogue (P132 helper) so that the same
breach carries the same key whichever source reported it. On one identity node, findings of DIFFERENT
modules with the same key are one breach: the strongest finding stays the finding of record (ties:
HIBP, then XposedOrNot, then LeakCheck) and lists every source, the most precise breach date and the
union of data classes; the others become INFO ``context_only`` context (their original severity kept in
``data``), so the noisy-OR never counts one breach 3-4 times (LeakCheck alone never adds a second scored
finding for a breach already reported). One INFO correlation per merged breach documents the merge.
Sensitive breaches merge on their masked key and stay masked. Analyst overrides are never crossed.
The P146 pack (CR10) counts breaches per normalised name independently of this rule.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from v3lum.core.correlate import rule
from v3lum.core.graph import Graph
from v3lum.core.models import Correlation, Finding, ModuleResult, Severity

RULE_BREACH_MERGE = "p2g04_breach_merge"
MODULE_ORDER = {"hibp_account": 0, "xposedornot": 1, "leakcheck_public": 2}
_DATE_RANK = {10: 3, 7: 2, 4: 1}


def _key(f: Finding) -> str:
    data = f.data if isinstance(f.data, dict) else {}
    key = data.get("breach_key")
    return key if isinstance(key, str) and key and f.module in MODULE_ORDER and "breach" in (f.tags or ()) else ""


def _better_date(a: Any, b: Any) -> Any:
    """The more precise date (YYYY-MM-DD over YYYY-MM over YYYY); on equal precision the earlier one."""
    a = a if isinstance(a, str) and a else None
    b = b if isinstance(b, str) and b else None
    if not a or not b:
        return a or b
    ra, rb = _DATE_RANK.get(len(a), 0), _DATE_RANK.get(len(b), 0)
    if ra != rb:
        return a if ra > rb else b
    return min(a, b)


@rule(
    RULE_BREACH_MERGE,
    "One breach reported by several sources",
    "Per-breach findings of hibp_account, xposedornot and leakcheck_public that share the normalised breach name on one "
    "identity are one breach: the strongest finding lists every source and the breach date, the others become INFO "
    "context so the score counts the breach once.",
    version="1",
    severity="info",
    criterion="two or more breach findings of different modules sharing data.breach_key (normalised name, joined through "
    "the shared HIBP catalogue)",
    false_positives="Two different breaches of one service in the same year with the same name (HIBP names them apart, "
    "e.g. 'Zacks2024').",
    fixtures=(
        f"tests/fixtures/rules/{RULE_BREACH_MERGE}/positive_three_sources_one_finding.json",
        f"tests/fixtures/rules/{RULE_BREACH_MERGE}/negative_single_source_and_different_breaches.json",
    ),
)
def breach_merge(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    for node in graph.nodes.values():
        groups: dict[str, list[Finding]] = {}
        for f in node.findings:
            key = _key(f)
            if key:
                groups.setdefault(key, []).append(f)
        for key in sorted(groups):
            members = groups[key]
            if len({m.module for m in members}) < 2:
                continue
            primary = max(members, key=lambda f: (int(f.severity), -MODULE_ORDER.get(f.module, 9)))
            sources: list[str] = []
            date = None
            classes: set[str] = set()
            merged: list[Finding] = []
            for f in members:
                data = f.data if isinstance(f.data, dict) else {}
                for s in data.get("sources") or [f.source]:
                    if isinstance(s, str) and s and s not in sources:
                        sources.append(s)
                date = _better_date(date, data.get("date"))
                classes.update(c for c in data.get("data_classes") or [] if isinstance(c, str))
                if f is primary or f.override:
                    continue
                if any(isinstance(s, dict) and s.get("rule") == RULE_BREACH_MERGE for s in f.suppressed_by):
                    merged.append(f)  # merged by an earlier run of the same case: never lowered twice
                    continue
                before = f.severity.label
                f.downgrade(RULE_BREACH_MERGE, f"same breach as the {primary.module} finding {primary.id}: one breach, several sources")
                f.data = {**data, "merged_into": primary.id, "severity_before_merge": before}
                f.severity = Severity.INFO
                if "context_only" not in f.tags:
                    f.tags.append("context_only")
                merged.append(f)
            if not merged:
                continue
            pdata = primary.data if isinstance(primary.data, dict) else {}
            primary.data = {**pdata, "sources": sources, "date": date or pdata.get("date"), "data_classes": sorted(classes)}
            name = pdata.get("name") or key
            modules = sorted({m.module for m in members}, key=lambda m: MODULE_ORDER.get(m, 9))
            yield Correlation(
                rule=RULE_BREACH_MERGE,
                title=f"One breach reported by {len(modules)} sources: {name}",
                severity=Severity.INFO,
                description=f"{', '.join(modules)} list {node.entity.display} in the same breach ({name}, "
                f"{date or 'date unknown'}): the finding of record is '{primary.title}' ({primary.module}, sources "
                f"{', '.join(sources)}); the other reports are kept as context and not scored again.",
                entities=[node.entity],
                confidence="confirmed",
                evidence=[m.id for m in members],
                recommendation="Read the finding of record: its next step applies once for this breach.",
                tags=["breach", "privacy"],
                criterion=f"breach findings of {', '.join(modules)} sharing breach_key {key}",
                key=key,
            )


__all__ = ["RULE_BREACH_MERGE", "breach_merge"]
