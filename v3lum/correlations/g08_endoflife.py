"""End-of-life software on an asset (P187, batch p2-G08-1): rule ``g08_endoflife``.

A registered-dataset + correlation-rule design (P187 cond 1): the rule reads the versions other modules
detected on an asset (Server banners, scanner service banners, technology fingerprints, CPEs) and the
LOCAL endoflife.date product copies (datasets ``endoflife.<slug>``, fetched by ``v3lum data update``). It
never downloads anything and never sends the investigated stack anywhere. The pure logic lives in
:mod:`v3lum.modules.vulnerability_cve.endoflife`.

One grouped correlation per asset lists every EOL component (cond 5): MEDIUM (end of life) or LOW
(security fixes only) on own or in-scope assets; INFO with tag ``context_only`` on third-party or attacker
infrastructure; INFO, confidence <= 0.4 and the 'version-inferred' label for inferred or major-only
versions (cond 3). Distro builds with backports are never reported as upstream EOL (cond 4). Each line
names the version's source. Attribution: endoflife.date (MIT data).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from v3lum.core.correlate import RuleContext, rule
from v3lum.core.entities import EntityType
from v3lum.core.graph import Graph, Node
from v3lum.core.models import Correlation, ModuleResult
from v3lum.modules.vulnerability_cve.endoflife import (
    ATTRIBUTION,
    components_from_values,
    eol_group,
    evaluate_components,
    products_for,
)

RULE_ID = "g08_endoflife"
ASSET_TYPES = (EntityType.DOMAIN, EntityType.IPV4, EntityType.IPV6, EntityType.URL)
#: attributes the rule reads from asset nodes (what web/scanner modules report)
READS = ("server", "homepage_snapshot", "services", "technologies", "cpes")
#: rctx.meta key with pre-loaded raw product documents {slug: document} (graph fixtures, engine preload)
PRELOAD_META = "endoflife_products"
_RECOMMENDATION = {
    "medium": "Upgrade the end-of-life component to a supported release cycle (or isolate it); confirm the version on the host first.",
    "low": "Plan the upgrade: the release cycle only receives security fixes now.",
    "info": "Context only: confirm the version on the host before acting (third-party asset or version not read from the asset itself).",
}


def asset_scope(node: Node, rctx: RuleContext | None) -> str:
    """'own' | 'in_scope' | 'third_party' from the engine's ownership tags, the in_scope tag or the org profile."""
    if getattr(node, "ownership", "") == "own_asset":
        return "own"
    if node.tagged("in_scope"):
        return "in_scope"
    org = getattr(rctx, "org", None)
    if org is not None and not getattr(node, "ownership", ""):
        try:
            if getattr(org.owns(node.entity), "own", False):
                return "own"
        except Exception:  # noqa: BLE001 - an unreadable profile simply means 'not an own asset'
            return "third_party"
    return "third_party"


def node_values(node: Node) -> list[tuple[str, Any]]:
    return [(name, value) for name in READS for value, _module in node.attributes.get(name, [])]


@rule(
    RULE_ID,
    "End-of-life software on an asset",
    "One grouped finding per asset listing the detected components whose release cycle is past its end of life "
    "(endoflife.date, local weekly copies; P187).",
    version="1",
    severity="medium",
    criterion="explicit version string (banner, header, meta generator) mapped through the pinned product table to an "
              "endoflife.date release cycle past its EOL date; inferred/major-only versions and third-party assets are INFO",
    references=("https://endoflife.date/",),
    false_positives="distro packages with backported fixes (never reported as upstream EOL); banners that lie about the version",
    fixtures=("tests/fixtures/rules/g08_endoflife/",),
)
def g08_endoflife(graph: Graph, results: list[ModuleResult], rctx: RuleContext) -> Iterable[Correlation]:
    preloaded = (getattr(rctx, "meta", None) or {}).get(PRELOAD_META)
    today = rctx.now.date().isoformat()
    for etype in ASSET_TYPES:
        for node in graph.of_type(etype):
            if getattr(node, "noise", False):
                continue  # CDN/SaaS edges are context, never an asset finding
            components = components_from_values(node_values(node))
            if not components:
                continue
            products = products_for((c["slug"] for c in components), preloaded)
            if not products:
                continue
            scope = asset_scope(node, rctx)
            group = eol_group(node.entity.value, evaluate_components(components, products, today, scope))
            if group is None:
                continue
            tags = ["end_of_life"]
            if group["inferred"]:
                tags.append("version_inferred")
            if scope == "third_party" or group["severity"] == "info":
                tags.append("context_only")
            names = ", ".join(f"{c['product_label']} {c['version']}" for c in group["components"][:5])
            yield Correlation(
                rule=RULE_ID,
                title=f"End-of-life software on {node.entity.value}: {names}",
                severity=group["severity"],
                description=(
                    f"{len(group['components'])} component(s) past end of life or active support per endoflife.date "
                    f"({scope.replace('_', '-')} asset). Labels: {', '.join(group['labels'])}. {ATTRIBUTION['endoflife']}"
                ),
                entities=[node.entity],
                confidence=round(min(group["confidence"], 0.8), 2),
                evidence=group["lines"],
                recommendation=_RECOMMENDATION.get(group["severity"], _RECOMMENDATION["info"]),
                tags=tags,
                criterion=("version-inferred: " if group["inferred"] else "")
                + "detected version mapped to an endoflife.date release cycle (version source shown per line)",
                references=["https://endoflife.date/"],
                why=group["severity"],
            )
