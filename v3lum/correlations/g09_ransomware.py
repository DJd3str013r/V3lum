"""Correlation rules of batch p1-G09-1 (ransomware trackers and crypto sanctions).

* ``g09_ransomware_corroborated`` - the ONE cross-tracker dedupe rule of P196 cond 3 (also P197 cond 4
  and P356 cond 2): leak-site claims reported by RansomLook, ransomware.live and Ransomfeed describe
  the same victim claim when the group alias, the victim (normalised name, compact name or a shared
  victim domain) and the claim date (+/- 3 days) agree - the shared helpers of
  ``v3lum.modules.darkweb_ransomware.ransomlook``. Each victim claim seen by two or more trackers
  becomes one 'corroborated by N trackers' line (P196 cond 5: one grouped item per victim; the
  scoring of the group once is P335/P302's job). It only reads the graph: every tracker finding keeps
  its own severity and confidence.
* ``g09_sanctions_non_authoritative`` - P205 cond 6: a 'sanctions' tag or ``sanctioned`` attribute on
  a wallet from any source other than crypto_sanctions_offline/crypto_sanctions_onchain (e.g. GoPlus
  flags) is not authoritative: the line says so and points to the OFAC lists, unless one of the two
  authoritative modules confirmed the listing.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from v3lum.core.correlate import rule
from v3lum.core.entities import EntityType
from v3lum.core.graph import Graph
from v3lum.core.models import Correlation, ModuleResult, Severity
from v3lum.modules.darkweb_ransomware.ransomlook import claim_wording, corroboration_groups, corroboration_text

RANSOMWARE_RULE = "g09_ransomware_corroborated"
SANCTIONS_RULE = "g09_sanctions_non_authoritative"
TRACKER_MODULES = frozenset({"ransomlook", "ransomware_live", "ransomfeed"})
SANCTIONS_MODULES = frozenset({"crypto_sanctions_offline", "crypto_sanctions_onchain"})
WALLET_TYPES = frozenset({EntityType.BTC, EntityType.ETH, EntityType.XMR, EntityType.CRYPTO})


def _claims(graph: Graph) -> list[tuple[Any, Any, dict[str, Any]]]:
    """(node, finding, claim record) of every tracker claim finding in the graph."""
    out = []
    for node in graph.nodes.values():
        for finding in node.findings:
            if finding.module not in TRACKER_MODULES or "ransomware_claim" not in set(finding.tags or ()):
                continue
            data = finding.data if isinstance(finding.data, dict) else {}
            tracker = data.get("tracker") or finding.module
            if not data.get("group_key") or not data.get("claimed_date") or not (data.get("victim_key") or data.get("victim")):
                continue
            claim = {
                "tracker": tracker,
                "victim": data.get("victim") or "",
                "victim_key": data.get("victim_key") or "",
                "group": data.get("group") or "",
                "group_key": data.get("group_key"),
                "claimed_date": data.get("claimed_date"),
                "domains": [d for d in data.get("domains") or [] if isinstance(d, dict)],
            }
            out.append((node, finding, claim))
    return out


@rule(
    RANSOMWARE_RULE,
    "Ransomware claim corroborated by several trackers",
    "The same leak-site claim (victim + group alias + date +/- 3 days) reported by two or more independent "
    "trackers (RansomLook, Ransomware.live, Ransomfeed). The claim stays an actor statement; corroboration only "
    "shows the post exists on the leak site.",
    version="1",
    severity="info",
    criterion="claims of >= 2 trackers with the same normalised group alias, the same victim (normalised name, compact "
    "name or a shared victim domain) and claim dates within +/- 3 days (P196 cond 3)",
    false_positives="Two different companies with the same normalised name claimed by the same group within 3 days.",
    fixtures=(
        f"tests/fixtures/rules/{RANSOMWARE_RULE}/positive_three_trackers_one_claim.json",
        f"tests/fixtures/rules/{RANSOMWARE_RULE}/negative_one_tracker_reposts.json",
        f"tests/fixtures/rules/{RANSOMWARE_RULE}/negative_dates_too_far_apart.json",
    ),
)
def ransomware_corroborated(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    items = _claims(graph)
    for group in corroboration_groups([claim for _n, _f, claim in items]):
        trackers = {items[i][2]["tracker"] for i in group}
        if len(trackers) < 2:
            continue
        members = [items[i] for i in group]
        nodes = []
        for node, _f, _c in members:
            if node.entity not in nodes:
                nodes.append(node.entity)
        dates = sorted({c["claimed_date"] for _n, _f, c in members})
        lead = max(members, key=lambda m: (m[1].severity, m[2]["claimed_date"]))
        claim = lead[2]
        worst = max(f.severity for _n, f, _c in members)
        yield Correlation(
            rule=RANSOMWARE_RULE,
            title="Ransomware claim corroborated by several trackers",
            severity=Severity.INFO,
            description=(
                f"{claim['victim']}: {claim_wording(claim)} - {corroboration_text(trackers)} "
                f"(claim dates {', '.join(dates)}). One victim claim, counted once; the highest tracker severity is "
                f"{worst.label}. Corroboration shows the post exists on the leak site, not that the breach happened."
            ),
            entities=nodes,
            confidence="probable",
            evidence=[f.id for _n, f, _c in members if f.id],
            recommendation="Treat the trackers' findings as one claim; verify it with the victim before acting on it.",
            tags=["ransomware", "ransomware_claim"],
            criterion=f"{len(trackers)} trackers report the claim: same group alias {claim['group_key']!r}, same victim, dates within +/- 3 days",
            key=f"{claim['victim_key'] or claim['victim']}|{claim['group_key']}|{dates[0]}",
        )


def _authoritative(node: Any) -> bool:
    return any(f.module in SANCTIONS_MODULES and "sanctions" in set(f.tags or ()) for f in node.findings)


@rule(
    SANCTIONS_RULE,
    "Sanctions flag from a non-authoritative source",
    "A wallet carries a 'sanctions' tag or a 'sanctioned' attribute from a source other than the OFAC lists and the "
    "Chainalysis checks (e.g. GoPlus flags): it is not a sanctions determination until crypto_sanctions_offline or "
    "crypto_sanctions_onchain confirms it.",
    version="1",
    severity="info",
    criterion="finding tag 'sanctions' or attribute sanctioned=True on a wallet from a module other than "
    "crypto_sanctions_offline/crypto_sanctions_onchain, with no confirming finding of those two (P205 cond 6)",
    false_positives="None by design: the line only labels the flag's authority.",
    fixtures=(
        f"tests/fixtures/rules/{SANCTIONS_RULE}/positive_goplus_flag_only.json",
        f"tests/fixtures/rules/{SANCTIONS_RULE}/negative_confirmed_by_ofac_list.json",
    ),
)
def sanctions_non_authoritative(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    for node in graph.nodes.values():
        if node.entity.type not in WALLET_TYPES or _authoritative(node):
            continue
        flagged = [f for f in node.findings if f.module not in SANCTIONS_MODULES and "sanctions" in set(f.tags or ())]
        attr_sources = sorted({str(src) for value, src in node.attributes.get("sanctioned", []) if value is True and src not in SANCTIONS_MODULES})
        sources = sorted({f.module or "?" for f in flagged} | set(attr_sources))
        if not sources:
            continue
        yield Correlation(
            rule=SANCTIONS_RULE,
            title="Sanctions flag from a non-authoritative source",
            severity=Severity.INFO,
            description=(
                f"{', '.join(sources)} flags this wallet as sanctioned, but no authoritative check confirmed it (OFAC address "
                "lists, Chainalysis sanctions oracle/API). Such flags are not a sanctions determination: the 'sanctions' "
                "label comes only from crypto_sanctions_offline / crypto_sanctions_onchain (P205 cond 6)."
            ),
            entities=[node.entity],
            confidence="probable",
            evidence=[f.id for f in flagged if f.id],
            recommendation="Run crypto_sanctions_offline (OFAC lists) and crypto_sanctions_onchain before treating the wallet as sanctioned.",
            tags=["sanctions"],
            criterion="sanctions flag from " + ", ".join(sources) + " without an authoritative confirmation",
        )
