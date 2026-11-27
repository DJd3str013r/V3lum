"""Secondary CVE source vs the CVE card (P188 cond 4, batch p2-G08-1): rule ``g08_cve_secondary_conflicts``.

``securitycontext_cve`` (unknown terms and tier, opt-in) records its values only in the comparison
attribute ``cve_secondary``: it is never the sole source of a card fact. This rule compares those values
with the primary modules' facts on the same CVE node - CVSS (CVE record/NVD/OSV), EPSS (FIRST), CISA KEV
(cisa_kev and the CISA relays), CWE and the record state - and emits ONE informational correlation per CVE
listing the conflicts. Agreement, or nothing to compare, emits nothing. Never scored (``context_only``).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from v3lum.core.correlate import rule
from v3lum.core.entities import EntityType
from v3lum.core.graph import Graph, Node
from v3lum.core.models import Correlation, ModuleResult, Severity
from v3lum.modules.vulnerability_cve.cve_record import KEV_RELAY_MODULES, merge_cvss

RULE_ID = "g08_cve_secondary_conflicts"
SECONDARY_ATTR = "cve_secondary"
EPSS_TOLERANCE = 0.05
CVSS_TOLERANCE = 0.1


def _float(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _primary(node: Node, key: str, secondary_modules: set[str]) -> list[tuple[Any, str]]:
    return [(v, str(m)) for v, m in node.attributes.get(key, []) if str(m) not in secondary_modules and v not in (None, "", [], {})]


def conflict_lines(node: Node) -> list[str]:
    """Plain conflict lines between the secondary values and the primary modules' facts of one CVE node."""
    secondaries = [(v, str(m)) for v, m in node.attributes.get(SECONDARY_ATTR, []) if isinstance(v, dict)]
    if not secondaries:
        return []
    sec_modules = {m for _v, m in secondaries}
    lines: list[str] = []
    for sec, module in secondaries:
        label = f"{sec.get('provider') or module} [{module}]"
        # CVSS: the best primary score (CNA, NVD primary, ADP, OSV...) vs the secondary one
        scores = []
        for value, mod in _primary(node, "cvss_scores", sec_modules):
            for item in value if isinstance(value, list) else []:
                if isinstance(item, dict) and _float(item.get("score")) is not None:
                    scores.append(dict(item, module=mod))
        best = (merge_cvss(scores) or [None])[0]
        sec_cvss = _float((sec.get("cvss") or {}).get("score") if isinstance(sec.get("cvss"), dict) else None)
        if best is not None and sec_cvss is not None and abs(sec_cvss - float(best["score"])) >= CVSS_TOLERANCE:
            lines.append(f"CVSS: card {float(best['score']):.1f} ({best.get('source') or '?'} v{best.get('version') or '?'} [{best['module']}]) "
                         f"vs {label} {sec_cvss:.1f}")
        # EPSS: the newest primary score
        epss_rows = []
        for value, mod in _primary(node, "epss", sec_modules):
            score = _float(value)
            if score is not None:
                date = next((d for d, m in node.attributes.get("epss_date", []) if str(m) == mod), None)
                epss_rows.append((str(date or ""), score, mod))
        sec_epss = _float((sec.get("epss") or {}).get("score") if isinstance(sec.get("epss"), dict) else None)
        if epss_rows and sec_epss is not None:
            date, score, mod = max(epss_rows)
            if abs(sec_epss - score) > EPSS_TOLERANCE:
                lines.append(f"EPSS: card {score:.5f} ({date or 'undated'} [{mod}]) vs {label} {sec_epss:.5f}")
        # CISA KEV: only the CISA relays count as KEV on the card
        card_kev = any(v is True and str(m) in KEV_RELAY_MODULES for v, m in node.attributes.get("kev", []))
        kev_checked = any(str(m) == "cisa_kev" for _v, m in node.attributes.get("kev_status", [])) or card_kev
        sec_lists = sec.get("kev_lists") if isinstance(sec.get("kev_lists"), list) else []
        if "cisa" in sec_lists and not card_kev and kev_checked:
            lines.append(f"KEV: {label} lists the CVE in CISA KEV, the local CISA KEV copy does not (stale copy?)")
        elif card_kev and "cisa" not in sec_lists:
            lines.append(f"KEV: CISA KEV lists the CVE, {label} does not (its dataset may lag)")
        # CWE
        card_cwe = {c for v, _m in _primary(node, "cwe", sec_modules) for c in (v if isinstance(v, list) else [v]) if isinstance(c, str)}
        sec_cwe = {c for c in sec.get("cwe") or [] if isinstance(c, str)}
        if card_cwe and sec_cwe and card_cwe != sec_cwe:
            lines.append(f"CWE: card {', '.join(sorted(card_cwe))} vs {label} {', '.join(sorted(sec_cwe))}")
        # record state
        states = {str(v).upper() for v, _m in _primary(node, "cve_state", sec_modules)}
        if sec.get("rejected_by_nvd") is True and "PUBLISHED" in states and "REJECTED" not in states:
            lines.append(f"State: {label} marks the CVE rejected by NVD, the CVE record is published")
    return lines


@rule(
    RULE_ID,
    "Secondary CVE source disagrees with the CVE card",
    "Lists where a comparison-only CVE source (SecurityContext, unknown terms) disagrees with the primary CVE modules "
    "(CVSS, EPSS, CISA KEV, CWE, record state); the card keeps the primary values (P188 cond 4).",
    version="1",
    severity="info",
    criterion="secondary source values (attribute cve_secondary) differ from the primary modules' facts on the same CVE node",
    false_positives="different dataset refresh dates (EPSS is daily, KEV copies age); CVSS versions chosen differently",
    fixtures=("tests/fixtures/rules/g08_cve_secondary_conflicts/",),
)
def g08_cve_secondary_conflicts(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    for node in graph.of_type(EntityType.CVE):
        lines = conflict_lines(node)
        if not lines:
            continue
        yield Correlation(
            rule=RULE_ID,
            title=f"{node.entity.value}: secondary CVE source disagrees with the CVE card ({len(lines)} point(s))",
            severity=Severity.INFO,
            description="The CVE card keeps the primary values; the secondary source is comparison-only (unknown terms, never the "
                        "sole source of a card fact). Differences usually come from dataset refresh dates.",
            entities=[node.entity],
            confidence=0.7,
            evidence=lines,
            recommendation="Check the primary sources (CVE record, FIRST EPSS, CISA KEV) when a difference matters for patch priority.",
            tags=["context_only"],
            criterion="comparison of cve_secondary with the primary modules' cvss_scores, epss, kev, cwe and cve_state",
        )
