"""Microsoft 365 tenant domain map from azmap.dev, with DNS confirmation of related domains (P011 cond 6-7).

Batch p2-G01-2, proposal P011 ``m365_tenant``: the separate adapter the chair kept out of the default
module. Final conditions implemented here:

* c6 - azmap.dev has no published terms and an unknown operator: terms 'unknown', tier 'unknown',
  ``default_enabled = False``. It stays disabled until legal records its terms and a promotion; the
  unknown tier keeps it out of TLP:AMBER and above (IOC values only, ``--allow-unknown`` at
  CLEAR/GREEN). One call per registrable domain, cached 24 h.
* c7 - the full related-domain list is the attribute ``m365_related_domains`` with its count. A related
  domain pivots only after DNS confirmation through the core DoH resolver (MX under
  ``*.mail.protection.outlook.com`` - or the GCC High / 21Vianet equivalents - or a TXT ``MS=``
  verification record): at most 50 domains checked within 100 DoH queries and 10 pivots per tenant,
  relation ``same_m365_tenant`` (core vocabulary), confidence PROBABLE at most.
* c8/c9 - the tenant id feeds the company correlation ``m365_shared_tenant`` (PROBABLE same
  organisation, never proof of ownership); related domains are candidate own assets for
  ``v3lum org seed`` (analyst confirms) and never join an ACTIVE scope. bbot's azure_tenant module
  (AGPL) was not copied: the technique is re-implemented (A6).
"""

from __future__ import annotations

import re
from typing import Any

from v3lum.core import psl
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.domain_dns.m365_tenant import _DOMAIN, _GUID, _json

SOURCE = "azmap.tenant"
API = "https://azmap.dev/api/tenant?domain={domain}&extract=true"
#: P011 c7 caps (per tenant, i.e. per run of this module).
MAX_CONFIRMATIONS = 50
MAX_DOH_QUERIES = 100
MAX_PIVOTS = 10
#: Stored related-domain list cap (the count is always the provider's total).
MAX_LISTED = 1000
#: MX hosts of Exchange Online (commercial, GCC High, 21Vianet).
M365_MX_SUFFIXES = (".mail.protection.outlook.com", ".mail.protection.office365.us", ".mail.protection.partner.outlook.cn")
#: Domain-verification TXT records of Microsoft 365 ('MS=ms12345678' or 'MS=' + 40 hex).
_MS_TXT = re.compile(r"^ms=(?:ms\d{6,10}|[0-9a-f]{40})$", re.I)


def parse_tenant(content: Any) -> dict[str, Any]:
    """azmap /api/tenant answer: state 'tenant' | 'no_tenant' (DOMAIN_NOT_FOUND) | 'error'."""
    data = _json(content)
    if not isinstance(data, dict):
        return {"state": "error", "reason": "the azmap.dev answer is not a JSON object"}
    if data.get("error") == "DOMAIN_NOT_FOUND":
        return {"state": "no_tenant", "reason": str(data.get("message") or "domain not found")[:160]}
    tid = data.get("tenant_id")
    if not (isinstance(tid, str) and _GUID.match(tid.strip().lower())):
        return {"state": "error", "reason": "no tenant_id GUID in the azmap.dev answer (schema changed?)"}
    related: list[str] = []
    seen: set[str] = set()
    for item in data.get("related_domains") if isinstance(data.get("related_domains"), list) else []:
        if not isinstance(item, str):
            continue
        name = item.strip().lower().rstrip(".")
        if _DOMAIN.match(name) and name not in seen:
            seen.add(name)
            related.append(name)
    count = data.get("related_count")
    return {
        "state": "tenant",
        "tenant_id": tid.strip().lower(),
        "tenant_name": data["tenant_name"].strip()[:120] if isinstance(data.get("tenant_name"), str) and data["tenant_name"].strip() else None,
        "brand_name": data["brand_name"].strip()[:120] if isinstance(data.get("brand_name"), str) and data["brand_name"].strip() else None,
        "related_domains": related,
        "related_count": count if isinstance(count, int) and not isinstance(count, bool) and count >= 0 else len(related),
    }


def dns_evidence(mx_records: list[str], txt_records: list[str]) -> list[str]:
    """Evidence that a domain uses Microsoft 365: MX under Exchange Online or a TXT MS= record. An SPF
    include of spf.protection.outlook.com alone is not confirmation (any tenant can add it)."""
    out: list[str] = []
    for record in mx_records:
        host = str(record).split()[-1].lower().rstrip(".") if str(record).strip() else ""
        if host.endswith(M365_MX_SUFFIXES):
            out.append(f"MX {host}")
    for record in txt_records:
        text = str(record).strip()
        if _MS_TXT.match(text):
            out.append(f"TXT {text}")
    return out


def confirm_related(ctx: Any, seed: str, related: list[str]) -> dict[str, Any]:
    """DNS confirmation of related domains (P011 c7): MX first, TXT only when MX does not confirm;
    at most MAX_CONFIRMATIONS domains, MAX_DOH_QUERIES queries, MAX_PIVOTS confirmed pivots."""
    todo = [d for d in related if d != seed and d != "onmicrosoft.com" and not d.endswith(".onmicrosoft.com")]
    queries = 0
    checked = 0
    confirmed: list[dict[str, Any]] = []
    unconfirmed: list[str] = []
    unverified: list[str] = []
    stop = ""
    for domain in todo:
        if len(confirmed) >= MAX_PIVOTS:
            stop = "max_pivots"
            break
        if checked >= MAX_CONFIRMATIONS:
            stop = "max_confirmations"
            break
        if queries >= MAX_DOH_QUERIES:
            stop = "max_doh_queries"
            break
        if ctx.cancelled():
            stop = "cancelled"
            break
        remaining = ctx.remaining()
        if remaining is not None and remaining < 3.0:
            stop = "deadline"
            break
        checked += 1
        queries += 1
        mx = ctx.dns.query(domain, "MX")
        evidence = dns_evidence(mx.records if mx.ok else [], [])
        txt = None
        if not evidence and queries < MAX_DOH_QUERIES:
            queries += 1
            txt = ctx.dns.query(domain, "TXT")
            evidence = dns_evidence([], txt.records if txt.ok else [])
        if evidence:
            confirmed.append({"domain": domain, "evidence": evidence})
        elif mx.could_not_verify or (txt is not None and txt.could_not_verify) or txt is None:
            unverified.append(domain)  # SERVFAIL/timeout: could not verify, never 'not in the tenant'
        else:
            unconfirmed.append(domain)
    return {
        "checked": checked,
        "doh_queries": queries,
        "confirmed": confirmed,
        "unconfirmed": unconfirmed,
        "could_not_verify": unverified,
        "not_checked": max(0, len(todo) - checked),
        "stop_reason": stop,
    }


@register
class M365TenantAzmap(Module):
    name = "m365_tenant_azmap"
    title = "Microsoft 365 tenant domains (azmap.dev)"
    description = (
        "Every domain verified in the same Microsoft 365 / Entra ID tenant according to the third-party azmap.dev map; "
        "related domains pivot only after DNS confirmation (Exchange Online MX or TXT MS=)."
    )
    category = "domain_dns"
    accepts = {T.DOMAIN}
    produces = {T.DOMAIN}
    tags = {"free"}
    reference = "https://azmap.dev/"
    terms = "unknown"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "azmap"
    sources = (SOURCE,)
    hosts = ("azmap.dev",)
    access_model = "free_noauth_limited"
    max_requests = 1
    expected_latency = 3.0
    timeout = 60.0
    min_interval = 2.0
    cache_ttl = 86400
    max_pivots = MAX_PIVOTS
    default_enabled = False
    notice = (
        "azmap.dev publishes no terms and its operator is unknown: the queried domain is disclosed to it (OPSEC). Disabled "
        "until legal records its terms and a promotion; excluded at TLP:AMBER and above. Related domains pivot only after DNS "
        "confirmation (MX *.mail.protection.outlook.com or TXT MS=), at most 10 per tenant; they are candidate own assets "
        "for `v3lum org seed` (analyst confirms), never an ACTIVE scope."
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return psl.registrable_domain(entity.value) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        domain = psl.registrable_domain(entity.value)
        if domain is None or not _DOMAIN.match(domain):
            return res.mark("skipped", "no registrable domain to look up", reason_code="not_applicable")
        resp = ctx.http.get(API.format(domain=domain), source=SOURCE)
        if resp.status == 404:
            answer = parse_tenant(resp.content)
            if answer["state"] == "no_tenant":
                res.raw = {"domain": domain, "azmap": {"status": 404, "error": "DOMAIN_NOT_FOUND"}}
                return res.mark("empty", f"azmap.dev knows no Microsoft 365 tenant for {domain}")
            ctx.http.check(resp)
            return res.mark("error", "unexpected azmap.dev 404 answer: could not verify")
        ctx.http.check(resp)  # 429, challenges (azmap.dev is behind Cloudflare), 5xx: could not verify
        answer = parse_tenant(resp.content)
        if answer["state"] == "no_tenant":
            return res.mark("empty", f"azmap.dev knows no Microsoft 365 tenant for {domain}")
        if answer["state"] != "tenant":
            return res.mark("error", f"{answer['reason']}: could not verify")
        related = answer["related_domains"]
        confirmation = confirm_related(ctx, domain, related)
        res.raw = {"domain": domain, "azmap": {k: v for k, v in answer.items() if k != "related_domains"},
                   "related_domains": related[:MAX_LISTED], "dns_confirmation": confirmation}
        res.attr("m365_tenant_id", answer["tenant_id"])
        res.attr("m365_tenant_name", answer["tenant_name"])
        res.attr("m365_brand_name", answer["brand_name"])
        res.attr("m365_related_domains", {
            "count": answer["related_count"],
            "domains": related[:MAX_LISTED],
            "listed": min(len(related), MAX_LISTED),
            "source": "azmap.dev",
            "note": "candidate own assets for `v3lum org seed` (analyst confirms), never an ACTIVE scope",
        })
        res.attr("m365_dns_confirmation", {
            "checked": confirmation["checked"],
            "confirmed": [c["domain"] for c in confirmation["confirmed"]],
            "unconfirmed": len(confirmation["unconfirmed"]),
            "could_not_verify": len(confirmation["could_not_verify"]),
            "not_checked": confirmation["not_checked"],
            "doh_queries": confirmation["doh_queries"],
            "stop_reason": confirmation["stop_reason"],
            "evidence": {c["domain"]: c["evidence"] for c in confirmation["confirmed"]},
        })
        name = answer["brand_name"] or answer["tenant_name"] or answer["tenant_id"]
        total = answer["related_count"]
        res.finding(
            "Domains share a Microsoft 365 tenant (azmap.dev)",
            "info",
            f"{total} domains share Microsoft 365 tenant {name}: azmap.dev lists them as verified in Entra ID tenant {answer['tenant_id']}; "
            f"{len(confirmation['confirmed'])} of {confirmation['checked']} checked were confirmed by DNS. A shared tenant is a "
            "PROBABLE same-organisation link (subsidiaries, brands, acquisitions), never proof of ownership; the list comes "
            "from an unknown-tier third party.",
            confidence="possible",
            data={"tenant_id": answer["tenant_id"], "related_count": total, "confirmed": [c["domain"] for c in confirmation["confirmed"]]},
            source=SOURCE,
            key="azmap",
        )
        for item in confirmation["confirmed"][:MAX_PIVOTS]:
            res.pivot(T.DOMAIN, item["domain"], "same_m365_tenant", confidence="probable",
                      note=f"same Microsoft 365 tenant (azmap.dev), DNS-confirmed: {'; '.join(item['evidence'][:2])}")
        return res


__all__ = ["M365TenantAzmap", "confirm_related", "dns_evidence", "parse_tenant"]
