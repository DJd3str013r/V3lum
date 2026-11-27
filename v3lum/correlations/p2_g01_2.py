"""Correlation rules of batch p2-G01-2 (P010 tranco_rank, P011 m365_tenant).

* ``m365_shared_tenant`` (P011 cond 8): the same Entra ID (Microsoft 365) tenant id on several
  registrable domains (attribute ``m365_tenant_id`` from m365_tenant / m365_tenant_azmap) feeds the
  company correlation as a PROBABLE same-organisation link, worded 'N domains share Microsoft 365
  tenant <name>'. When one of the domains is flagged hostile (phishing, malicious, suspicious...) the
  cluster is an attacker-infrastructure candidate (PROBABLE), never proof of ownership. A tenant that
  is unmanaged/test (GetUserRealm federation to a Microsoft STS host, observed for example.com) claims
  domains without DNS proof: the link is then POSSIBLE only.
* ``tranco_young_unpopular`` (P010 cond 6): a registrable domain registered at most 30 days ago that
  is not in the Tranco top 1M contributes at most LOW. 'Not in top 1M' alone is never a finding; shared
  platforms and public-suffix hosts are left out.

Rules only read the graph: they never change a finding, schedule a module or touch scope.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from v3lum.core import psl
from v3lum.core.correlate import rule
from v3lum.core.entities import EntityType
from v3lum.core.graph import Graph, Node
from v3lum.core.models import Correlation, ModuleResult, Severity
from v3lum.correlations.generic import evidence_finding

RULE_TENANT = "m365_shared_tenant"
RULE_YOUNG = "tranco_young_unpopular"
#: Finding or entity tags that make a cluster member hostile (the P376 guard's hostile set).
HOSTILE_TAGS = frozenset({"malicious", "phishing", "c2", "suspicious", "phishing_kit_exfil", "crypto_scam", "fraud", "typosquat", "brand_abuse"})
YOUNG_DAYS = 30
NOT_RANKED = "not in top 1M"


def _tenant_domain(node: Node) -> str | None:
    value = str(node.entity.value or "")
    if node.entity.type is EntityType.EMAIL:
        value = value.rsplit("@", 1)[-1]
    return psl.registrable_domain(value) if value else None


def _hostile(node: Node) -> bool:
    if HOSTILE_TAGS & set(node.tags):
        return True
    return any(evidence_finding(f) and f.severity >= Severity.LOW and HOSTILE_TAGS.intersection(f.tags) for f in node.findings)


def _unmanaged(node: Node) -> bool:
    if any("unmanaged" in str(a).lower() for value in node.attr_values("m365_anomalies") for a in (value if isinstance(value, list) else [value])):
        return True
    return any(isinstance(v, dict) and v.get("kind") == "microsoft_sts" for v in node.attr_values("m365_identity_provider"))


@rule(
    RULE_TENANT,
    "Domains share a Microsoft 365 tenant",
    "Several registrable domains are verified in the same Microsoft Entra ID (Microsoft 365) tenant: a PROBABLE "
    "same-organisation link (subsidiaries, brands, acquisitions). With a hostile member the cluster is an "
    "attacker-infrastructure candidate. Never proof of ownership: unmanaged or test tenants can claim domains (P011 c8).",
    version="1",
    severity="info",
    criterion="the same m365_tenant_id attribute (m365_tenant / m365_tenant_azmap) on at least two distinct registrable domains",
    false_positives="Unmanaged (self-service) or test tenants claiming domains without DNS proof; shared Microsoft service domains.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_TENANT}/positive_two_brands_one_tenant.json",
        f"tests/fixtures/rules/{RULE_TENANT}/positive_phishing_domain_in_the_tenant.json",
        f"tests/fixtures/rules/{RULE_TENANT}/positive_unmanaged_tenant_is_possible.json",
        f"tests/fixtures/rules/{RULE_TENANT}/negative_one_domain_or_two_tenants.json",
    ),
)
def shared_tenant(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    groups: dict[str, dict[str, Any]] = {}
    for node in graph.of_type(EntityType.DOMAIN, EntityType.EMAIL):
        domain = _tenant_domain(node)
        if not domain:
            continue
        for value in node.attr_values("m365_tenant_id"):
            tid = str(value or "").strip().lower()
            if len(tid) != 36:
                continue
            group = groups.setdefault(tid, {"domains": {}, "names": [], "hostile": set(), "unmanaged": False})
            group["domains"].setdefault(domain, node)
            names = [str(v) for key in ("m365_brand_name", "m365_tenant_name") for v in node.attr_values(key) if v]
            group["names"].extend(n for n in names if n not in group["names"])
            if _hostile(node):
                group["hostile"].add(domain)
            group["unmanaged"] = group["unmanaged"] or _unmanaged(node)
    for tid, group in sorted(groups.items()):
        domains = sorted(group["domains"])
        if len(domains) < 2:
            continue
        name = group["names"][0] if group["names"] else tid
        hostile = sorted(group["hostile"])
        confidence = "possible" if group["unmanaged"] else "probable"
        description = (
            f"{len(domains)} domains share Microsoft 365 tenant {name} ({tid}): {', '.join(domains[:10])}"
            + (" ..." if len(domains) > 10 else "")
            + ". A shared tenant is a PROBABLE same-organisation link, never proof of ownership."
        )
        if group["unmanaged"]:
            description += " The tenant looks unmanaged or test-only (federated to a Microsoft STS host): the link is POSSIBLE only."
        if hostile:
            description += (
                f" {', '.join(hostile)} is flagged hostile: the tenant is an attacker-infrastructure cluster candidate; "
                "verify before treating the other domains as attacker-controlled."
            )
        yield Correlation(
            rule=RULE_TENANT,
            title=f"{len(domains)} domains share Microsoft 365 tenant {name}",
            severity=Severity.LOW if hostile else Severity.INFO,
            description=description,
            entities=[group["domains"][d].entity for d in domains[:25]],
            confidence=confidence,
            evidence=[f"m365_tenant_id={tid}"],
            recommendation=(
                "Review the other tenant domains as possible attacker infrastructure (passive lookups only)." if hostile
                else "Treat the domains as candidate assets of one organisation (v3lum org seed: analyst confirms); never as an ACTIVE scope."
            ),
            tags=["infrastructure"] + (["suspicious"] if hostile else []),
            criterion=f"m365_tenant_id {tid} on {len(domains)} registrable domains",
            key=tid,
        )


def _age_days(node: Node, now: datetime) -> int | None:
    for value in node.attr_values("domain_age_days"):
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
            return int(value)
    for value in node.attr_values("created"):
        try:
            when = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            continue
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        days = (now - when).total_seconds() / 86400
        if days >= 0:
            return int(days)
    return None


@rule(
    RULE_YOUNG,
    "Young and unpopular domain",
    "A registrable domain registered at most 30 days ago that is not in the Tranco top 1M: a weak phishing-triage signal "
    "that contributes at most LOW (P010 cond 6). 'Not in top 1M' alone is never a finding.",
    version="1",
    severity="low",
    criterion="domain_age_days <= 30 (or a creation date at most 30 days old) and tranco_popularity 'not in top 1M' (tranco_rank)",
    false_positives="New legitimate sites (campaign pages, start-ups) are young and unpopular too.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_YOUNG}/positive_registered_9_days_ago.json",
        f"tests/fixtures/rules/{RULE_YOUNG}/negative_ranked_or_old_or_shared.json",
    ),
)
def young_unpopular(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterable[Correlation]:
    now = getattr(rctx, "now", None) or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    for node in graph.of_type(EntityType.DOMAIN):
        if node.noise or NOT_RANKED not in [str(v) for v in node.attr_values("tranco_popularity")]:
            continue
        if node.attr_values("shared_platform"):
            continue
        age = _age_days(node, now)
        if age is None or age > YOUNG_DAYS:
            continue
        yield Correlation(
            rule=RULE_YOUNG,
            title=f"{node.entity.display}: young and unpopular domain",
            severity=Severity.LOW,
            description=f"Registered {age} day(s) ago and not in the Tranco top 1M: a weak triage signal (at most LOW), never a verdict.",
            entities=[node.entity],
            confidence="possible",
            recommendation="Check the domain's content and reputation sources before acting.",
            tags=["newly_registered", "weak_signal"],
            criterion=f"registered {age} day(s) ago (<= {YOUNG_DAYS}) and not in the Tranco top 1M",
        )
