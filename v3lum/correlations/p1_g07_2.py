"""Correlation rules of batch p1-G07-2 (hash chain): a known file that a specific source lists.

P173 FC3/FC4: a CIRCL hashlookup hit (``known_good``: NSRL/OS-package set, no KnownMalicious) never
suppresses specific listings - KnownMalicious, MalwareBazaar, ThreatFox, LOLDrivers (BYOVD), YARA
family hits or internal sightings (P348). When both meet on one hash the analyst sees one line,
'conflict: known file vs listed', and every listing keeps its own severity and confidence (the rule
only reads the graph; it never changes a finding). LOLBAS/LOLRMM/HijackLibs context and findings
marked context-only are expected on known files (legitimate binaries that can be abused) and never
produce the conflict line.
"""

from __future__ import annotations

from collections.abc import Iterable

from v3lum.core.correlate import rule
from v3lum.core.entities import EntityType
from v3lum.core.graph import Graph
from v3lum.core.models import Correlation, Finding, ModuleResult, Severity

RULE_ID = "hashlookup_known_file_conflict"
HASH_TYPES = frozenset({EntityType.MD5, EntityType.SHA1, EntityType.SHA256, EntityType.SHA512})
#: finding tags of specific listings (P173 FC3): malware/abuse listings, vulnerable or malicious
#: drivers (LOLDrivers, BYOVD), YARA family hits and internal TIP sightings
LISTING_TAGS = frozenset({
    "malicious", "malware", "c2", "botnet", "ransomware", "phishing", "vulnerable", "byovd",
    "vulnerable_driver", "malicious_driver", "internal_sighting",
})
#: context markers: these findings are expected on known files and never raise the conflict line
CONTEXT_TAGS = frozenset({"context_only", "lolbas", "lolrmm", "hijacklibs", "test_file", "false_positive", "warninglist"})


def _known_good(node) -> bool:
    return any(value is True for value, _src in node.attributes.get("known_good", []))


def _listings(findings: Iterable[Finding]) -> list[Finding]:
    out = []
    for f in findings:
        tags = set(f.tags or ())
        if f.severity >= Severity.LOW and tags & LISTING_TAGS and not tags & CONTEXT_TAGS:
            out.append(f)
    return out


@rule(
    RULE_ID,
    "Known file vs listed: sources disagree",
    "A hash in a known-file set (NSRL/OS packages, CIRCL hashlookup) that a specific source lists as malicious, "
    "vulnerable (BYOVD) or known internally. The known-file entry never suppresses the listing.",
    version="1",
    severity="info",
    criterion="attribute known_good (known-file set without KnownMalicious) and a finding of severity >= low tagged "
    "as a specific listing (malicious, malware, vulnerable/BYOVD, internal sighting)",
    false_positives="Legitimate signed software that is vulnerable (BYOVD drivers) is expected to be both a known file and listed.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_ID}/positive_byovd_driver_in_nsrl.json",
        f"tests/fixtures/rules/{RULE_ID}/negative_lolbas_context_only.json",
    ),
)
def known_file_conflict(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    for node in graph.nodes.values():
        if node.entity.type not in HASH_TYPES or not _known_good(node):
            continue
        listings = _listings(node.findings)
        if not listings:
            continue
        modules = sorted({f.module or "?" for f in listings})
        labels = [str(v) for v, _src in node.attributes.get("known_file", []) if v]
        label = labels[0] if labels else "known file"
        worst = max(f.severity for f in listings)
        yield Correlation(
            rule=RULE_ID,
            title="conflict: known file vs listed",
            severity=Severity.INFO,
            description=(
                f"{label}, yet listed by {', '.join(modules)} (highest listing severity: {worst.label}). The known-file "
                "entry never suppresses a specific listing: a legitimate, known file can still be a vulnerable driver "
                "abused for BYOVD, a dual-use tool or a trojanised build."
            ),
            entities=[node.entity],
            confidence="probable",
            evidence=[f.id for f in listings if f.id],
            recommendation="Judge the listing on its own merits; the known-file entry only says the file ships with some software.",
            tags=["conflict"],
            criterion="known_good from a known-file set plus a specific listing on the same hash",
        )
