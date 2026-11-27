"""Correlation rules of batch p2-G02-3 (scanner intelligence: GreyNoise Community, SANS ISC / DShield).

``g02_scanner_intel_dampening`` (P148 cond 5-7; P151 research-scanner category): an IP that GreyNoise lists
in RIOT (finding tag ``known_good`` from ``greynoise_community``), classifies as a benign scanner (tag
``benign_scanner`` from ``greynoise_community``) or that SANS ISC lists in its 'research' threat category
(tag ``benign_scanner`` from ``isc_dshield``) gets its blocklist-derived findings from *other* sources
capped at LOW through the named suppression rules ``greynoise_riot``, ``greynoise_benign_scanner`` and
``isc_research_scanner``:

* only the IP itself (ipv4/ipv6 node) is dampened - never URLs or domains hosted on it, which keep their
  own verdicts (P148 c5);
* findings are lowered, never deleted: severity capped at LOW (the previous severity is kept in
  ``data['severity_before_dampening']``), the confidence label one level down through
  ``Finding.downgrade`` (recorded in ``suppressed_by``) - the rule names carry no ``SUP-`` prefix, so the
  findings stay evidence and the CR27 consensus keeps its own (downgraded) correlation;
* blocklist-derived = findings tagged ``blocklisted``, ``spam``, ``scanner``, ``malicious``,
  ``suspicious`` or ``botnet`` (reputation/blocklist listings); ``c2``, ``malware`` and ``phishing``
  findings (specific evidence) are left alone;
* no dampening when GreyNoise itself reports malicious scanning of the IP (conflicting signals) or for
  findings carrying an analyst override; each rule applies once per finding.

One INFO correlation per dampened IP documents what was lowered. Offline: it reads the graph only.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from v3lum.core.correlate import rule
from v3lum.core.entities import EntityType
from v3lum.core.graph import Graph
from v3lum.core.models import Correlation, Finding, ModuleResult, Severity

RULE_ID = "g02_scanner_intel_dampening"
#: (module, finding tag) -> named suppression rule (P322 naming; P148 c7)
DAMPENERS: dict[tuple[str, str], str] = {
    ("greynoise_community", "known_good"): "greynoise_riot",
    ("greynoise_community", "benign_scanner"): "greynoise_benign_scanner",
    ("isc_dshield", "benign_scanner"): "isc_research_scanner",
}
#: blocklist/reputation listing tags that are dampened (specific evidence such as c2/malware/phishing is not)
BLOCKLIST_TAGS = frozenset({"blocklisted", "spam", "scanner", "malicious", "suspicious", "botnet"})
IP_TYPES = (EntityType.IPV4, EntityType.IPV6)
CAP = Severity.LOW


def _dampeners(findings: Iterable[Finding]) -> list[tuple[str, Finding]]:
    out = []
    for f in findings:
        for tag in f.tags or ():
            name = DAMPENERS.get((f.module or "", tag))
            if name:
                out.append((name, f))
    return out


def _greynoise_malicious(findings: Iterable[Finding]) -> bool:
    for f in findings:
        data = f.data if isinstance(f.data, dict) else {}
        if f.module == "greynoise_community" and (data.get("classification") == "malicious" or data.get("state") == "mass_scanner"):
            return True
    return False


def _dampenable(f: Finding) -> bool:
    """A blocklist-derived finding of another source (GreyNoise's own verdicts are never lowered)."""
    return f.module != "greynoise_community" and bool(BLOCKLIST_TAGS & set(f.tags or ()))


@rule(
    RULE_ID,
    "Scanner intelligence dampens blocklist listings of a known-good or benign-scanner IP",
    "GreyNoise RIOT (known business service), GreyNoise 'benign' scanner classification and the SANS ISC research-scanner "
    "category cap blocklist-derived findings of other sources on that IP at LOW through the named suppression rules "
    "greynoise_riot, greynoise_benign_scanner and isc_research_scanner. Only the IP is dampened (never URLs or domains "
    "on it) and nothing is deleted.",
    version="1",
    severity="info",
    criterion="ipv4/ipv6 node with a greynoise_community finding tagged known_good/benign_scanner or an isc_dshield finding "
    "tagged benign_scanner, and findings of other sources tagged blocklisted/spam/scanner/malicious/suspicious/botnet above LOW",
    false_positives="A RIOT service or research scanner that is compromised keeps its c2/malware/phishing findings undampened; "
    "analyst overrides always win.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_ID}/positive_riot_caps_blocklist_listing.json",
        f"tests/fixtures/rules/{RULE_ID}/positive_benign_scanner_caps_scanner_listing.json",
        f"tests/fixtures/rules/{RULE_ID}/negative_domain_on_riot_ip_untouched.json",
        f"tests/fixtures/rules/{RULE_ID}/negative_greynoise_malicious_conflict.json",
    ),
)
def scanner_intel_dampening(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    for key in sorted(graph.nodes):
        node: Any = graph.nodes[key]
        if node.entity.type not in IP_TYPES or not node.findings:
            continue
        dampeners = _dampeners(node.findings)
        if not dampeners or _greynoise_malicious(node.findings):
            continue
        names = sorted({name for name, _ in dampeners})
        reason_by_rule = {
            "greynoise_riot": "known good service per GreyNoise RIOT",
            "greynoise_benign_scanner": "known benign scanner per GreyNoise",
            "isc_research_scanner": "known research scanner per SANS ISC",
        }
        lowered: list[Finding] = []
        for f in node.findings:
            if not _dampenable(f):
                continue
            for name in names:
                if any(s.get("rule") == name for s in f.suppressed_by):
                    continue
                if f.override:
                    f.downgrade(name, reason_by_rule[name])  # records the blocked attempt only
                    continue
                before = f.severity
                f.downgrade(name, f"{reason_by_rule[name]}: blocklist-derived listing of this IP capped at LOW")
                if f.severity > CAP:
                    if isinstance(f.data, dict):
                        f.data.setdefault("severity_before_dampening", before.label)
                    f.severity = CAP
                if f not in lowered:
                    lowered.append(f)
        if not lowered:
            continue
        sources = sorted({d.module for _, d in dampeners if d.module})
        yield Correlation(
            rule=RULE_ID,
            title="Blocklist listings of a known-good or benign-scanner IP dampened",
            severity=Severity.INFO,
            description=(
                f"{len(lowered)} blocklist-derived finding(s) on {node.entity.display} were capped at LOW "
                f"({', '.join(names)}; scanner intelligence from {', '.join(sources)}). Only this IP is dampened: URLs and "
                "domains hosted on it keep their own verdicts, and no finding was deleted."
            ),
            entities=[node.entity],
            confidence="probable",
            evidence=[f.id for f in lowered] + [d.id for _, d in dampeners],
            recommendation="Treat blocklist hits on this IP as likely noise; review any c2/malware/phishing evidence separately.",
            tags=["context_only"],
            criterion=f"named suppression rules {', '.join(names)} applied to {len(lowered)} finding(s)",
            key=",".join(names),
        )
