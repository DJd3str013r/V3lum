"""Correlation rules of batch p1-G11-1 (CTI framework): sinkholed domains (P169 FC7).

A domain whose A/AAAA records point to a known sinkhole (an address tagged ``sinkhole`` by the core noise
lists - the MISP warninglists 'sinkholes' list ships as v3lum/data/noise/misp_wl_sinkholes.json - or
flagged ``is_sinkhole`` by the warninglists module) was taken over by researchers or law enforcement:
it is *formerly* malicious. Hits on it are infected clients, not attacker infrastructure, so it is never
counted as live C2. The rule only states that context (severity info, tags ``sinkholed`` and
``context_only``); it never deletes or rewrites another module's finding (P169 FC6).
"""

from __future__ import annotations

from collections.abc import Iterable

from v3lum.core.correlate import rule
from v3lum.core.entities import EntityType
from v3lum.core.graph import Graph, Node
from v3lum.core.models import Correlation, ModuleResult, Severity

RULE_ID = "g11_sinkholed_domain"
#: Edges from a domain to the addresses it resolves to.
ADDRESS_RELATIONS = ("resolves_to",)
NOTE = "hits = infected clients, not attacker infrastructure; never counted as live C2"


def is_sinkhole(node: Node) -> bool:
    """A sinkhole address: core noise tag ``sinkhole`` (entity or finding tag) or the ``is_sinkhole`` fact."""
    if node.tagged("sinkhole"):
        return True
    return any(v is True for v, _src in node.attributes.get("is_sinkhole", []))


@rule(
    RULE_ID,
    "Domain resolves to a sinkhole (sinkholed, formerly malicious)",
    "A domain whose A/AAAA records point to a known sinkhole address (MISP warninglists 'sinkholes', P169 FC7): the "
    "domain was taken over; traffic to it comes from infected clients, it is never live attacker infrastructure.",
    version="1",
    severity="info",
    criterion="a resolves_to edge from the domain to an address tagged 'sinkhole' (core noise list misp.sinkholes) or with is_sinkhole",
    references=("https://github.com/MISP/misp-warninglists/tree/main/lists/sinkholes",),
    false_positives="A sinkhole operator may share an address range with other services; an old resolution recorded by a passive "
    "DNS source can predate the takeover - check the observation date.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_ID}/positive_resolves_to_sinkhole.json",
        f"tests/fixtures/rules/{RULE_ID}/negative_live_address.json",
    ),
)
def g11_sinkholed_domain(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    for domain in graph.of_type(EntityType.DOMAIN):
        sinks: list[Node] = []
        for relation in ADDRESS_RELATIONS:
            for node in graph.neighbors(domain.key, relation=relation, direction="out"):
                if node.entity.type in (EntityType.IPV4, EntityType.IPV6) and is_sinkhole(node) and all(n.key != node.key for n in sinks):
                    sinks.append(node)
        if not sinks:
            continue
        addresses = ", ".join(n.entity.value for n in sinks)
        yield Correlation(
            rule=RULE_ID,
            title="Domain resolves to a sinkhole (sinkholed)",
            severity=Severity.INFO,
            description=(
                f"{domain.entity.value} resolves to the sinkhole address(es) {addresses}: the domain is sinkholed (formerly "
                f"malicious) - {NOTE}."
            ),
            entities=[domain.entity, *(n.entity for n in sinks)],
            confidence="probable",
            evidence=[f"{domain.entity.value} resolves_to {n.entity.value} (sinkhole)" for n in sinks],
            recommendation="Treat connections to this domain as infected-client telemetry (look for the infected hosts), not as contact "
            "with live attacker infrastructure; do not block or report the sinkhole operator.",
            tags=["sinkholed", "sinkhole", "context_only"],
            criterion="A/AAAA record on a known sinkhole (MISP warninglists 'sinkholes'): " + NOTE,
            key=domain.key,
        )
