"""Correlation rules of batch p2-G12-1 (P271 c7: PE packer hints are context, downgraded by known-good sources).

pe_triage reports packer/obfuscation hints and high entropy as low-severity context (tag ``packer_hint``,
``context_only``), never as a verdict. When a known-good source in the case marks the file's hash - CIRCL
hashlookup ``known_good`` (NSRL/OS-package set without a KnownMalicious field) or a P169 known-good list
(attribute ``known_good`` on the hash node) - this rule reports the hints as downgraded to info with the
reason. A hashlookup hit alone is not proof of good: when any source on those hashes lists KnownMalicious,
nothing is downgraded. The rule only reads the graph; it never changes a finding.
"""

from __future__ import annotations

from collections.abc import Iterable

from v3lum.core.correlate import rule
from v3lum.core.entities import EntityType
from v3lum.core.graph import Graph
from v3lum.core.models import Correlation, ModuleResult, Severity

RULE_ID = "p2g12_pe_hints_known_good"
HASH_TYPES = frozenset({EntityType.MD5, EntityType.SHA1, EntityType.SHA256, EntityType.SHA512})


def _values(node, name: str) -> list:
    return [value for value, _src in node.attributes.get(name, [])]


def _sources(node, name: str) -> list[str]:
    return sorted({str(src) for value, src in node.attributes.get(name, []) if value is True and src})


@rule(
    RULE_ID,
    "PE packer hints downgraded: hash listed as known software",
    "pe_triage packer/entropy hints on a file whose hash a known-good source in the case lists (CIRCL hashlookup "
    "without KnownMalicious, known-good lists): the hints are context and read as info. A hashlookup hit alone is "
    "not proof of good.",
    version="1",
    severity="info",
    criterion="a pe_triage finding tagged packer_hint on a file whose has_hash node carries known_good=true and no "
    "known_malicious source",
    false_positives="Known-file sets also list legitimate packed software and dual-use tools; the downgrade never "
    "applies when a KnownMalicious source is present.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_ID}/positive_upx_installer_in_nsrl.json",
        f"tests/fixtures/rules/{RULE_ID}/negative_known_malicious_present.json",
    ),
)
def pe_hints_known_good(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    for node in graph.nodes.values():
        if node.entity.type is not EntityType.FILE:
            continue
        hints = [f for f in node.findings if "packer_hint" in set(f.tags or ())]
        if not hints:
            continue
        hashes = [graph.get(edge.dst) for edge in graph.out_edges(node.key) if edge.relation == "has_hash"]
        hashes = [h for h in hashes if h is not None and h.entity.type in HASH_TYPES]
        good = [h for h in hashes if any(v is True for v in _values(h, "known_good"))]
        bad = [h for h in hashes if any(v for v in _values(h, "known_malicious"))]
        if not good or bad:
            continue
        sources = sorted({s for h in good for s in _sources(h, "known_good")}) or ["a known-good source"]
        yield Correlation(
            rule=RULE_ID,
            title="PE packer hints downgraded: hash listed as known software",
            severity=Severity.INFO,
            description=(
                f"downgraded: {', '.join(sources)} lists this hash as known software (a hashlookup hit alone is not proof "
                f"of good). The {len(hints)} packer/entropy hint finding(s) of pe_triage read as info context."
            ),
            entities=[node.entity, *[h.entity for h in good]],
            confidence="probable",
            evidence=[f.id for f in hints if f.id],
            recommendation="Treat the packer hints as context; judge any specific listing of the hash on its own merits.",
            tags=["known_good", "context_only"],
            criterion="known_good on the file's hash (no KnownMalicious) plus pe_triage packer hints",
        )
