"""zoomeye: ZoomEye API v2 host/service search for IOC selectors, keyed (P053).

Batch p3-G02-2, proposal P053. Final conditions implemented here:

* FC1 - registry tier unknown (Chinese operator; queries reveal targets; the LGPD art. 33 transfer
  is not reviewed): the policy gate excludes it at AMBER, AMBER+STRICT and RED and needs
  ``--allow-unknown`` at CLEAR/GREEN. Only IOC_TYPES selectors are accepted (ipv4, ipv6, cidr,
  domain, favicon_hash); 'keyword' was dropped from the inputs (free text is not an infrastructure
  selector) and :func:`zoomeye_query` refuses any other type. Legal/procurement record the
  data-transfer decision; a promotion keeps the AMBER+ exclusion.
* FC2 - key ``zoomeye`` (alias ``V3LUM_ZOOMEYE_KEY``) sent only in the ``API-KEY`` header (never
  in the URL or the body); key-terms (company/team account, plan recorded by legal);
  ``default_enabled=False``.
* FC3 - ``POST https://api.zoomeye.ai/v2/search`` with the base64-encoded query; 401
  'login_required' -> NEEDS_KEY; code/error bodies -> ERROR (provider P321 marker), credits/points
  -> QUOTA; never EMPTY. Error bodies are never cached.
* FC4 - CDN/shared-hosting noise rules (P034): no domain pivots for CDN/cloud/hosting addresses or
  when more than :data:`MANY_DOMAINS` distinct names share the selector (count only, attribute
  ``cohosting``); pivots are capped (:data:`PIVOT_CAP`) and ``expand=False``; honeypot rows never
  yield pivots.
* FC5 - the web deep link (``https://www.zoomeye.ai/searchResult?q=<base64>``) is a manual link
  only (never requested). The success fixture is documentation-shaped until a trimmed real capture
  made with the company key replaces it (merge precondition, docs/backlog/p3-G02-2.md); the 401
  fixture is the real research capture.
"""

from __future__ import annotations

import base64
import ipaddress
import re
from typing import Any
from urllib.parse import urlencode

from v3lum.core import noise
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.ip_network.ip_geolocation import (
    EndpointRefused,
    bogon_reason,
    flag,
    integer,
    json_ok,
    normalize_domain,
    normalize_ip,
    parse_asn,
    text,
)

SOURCE = "zoomeye.search"
SEARCH_URL = "https://api.zoomeye.ai/v2/search"
WEB_SEARCH = "https://www.zoomeye.ai/searchResult"
OK_CODE = 60000
#: fields available to every plan (docs 'Permission: All users'); keeps the answer small
FIELDS = "ip,port,domain,hostname,service,title,product,update_time,asn,honeypot,idc,url"
SELECTORS = {T.IPV4: "ip", T.IPV6: "ip", T.CIDR: "cidr", T.DOMAIN: "domain", T.FAVICON_HASH: "iconhash"}
PAGE_SIZE = 20
PIVOT_CAP = 25  # FC4
MANY_DOMAINS = 20  # FC4: above this many distinct names the selector is shared hosting (count only)
MAX_ROWS = 25


def zoomeye_query(etype: T, value: str) -> str:
    """ZoomEye v2 dork for one IOC selector (FC1). Values are validated, so quotes or operators can
    never be injected into the query language; every other type raises :class:`EndpointRefused`."""
    field = SELECTORS.get(etype)
    if field is None:
        raise EndpointRefused(f"ZoomEye selector {getattr(etype, 'value', etype)!r} refused: only IOC_TYPES selectors (P053 FC1)")
    if etype in (T.IPV4, T.IPV6):
        if bogon_reason(value):
            raise ValueError(f"refusing {bogon_reason(value)} address for ZoomEye")
        v = normalize_ip(value)
    elif etype == T.CIDR:
        try:
            net = ipaddress.ip_network(str(value).strip(), strict=False)
        except ValueError:
            raise ValueError("invalid CIDR for ZoomEye") from None
        if bogon_reason(net.network_address) or bogon_reason(net.broadcast_address):
            raise ValueError("refusing a non-public CIDR for ZoomEye")
        v = str(net)
    elif etype == T.DOMAIN:
        v = normalize_domain(value)
    else:
        s = str(value or "").strip().lower()
        v = s if re.fullmatch(r"-?\d{1,11}", s) else None
    if not v:
        raise ValueError(f"invalid {etype.value} selector for ZoomEye")
    return f'{field}="{v}"'


def search_body(query: str, page: int = 1, pagesize: int = PAGE_SIZE) -> dict[str, Any]:
    """POST /v2/search body (FC3): the query base64-encoded into 'qbase64'. Never holds the key."""
    return {"qbase64": base64.b64encode(query.encode("utf-8")).decode("ascii"), "page": max(1, int(page)),
            "pagesize": min(max(1, int(pagesize)), 100), "fields": FIELDS, "sub_type": "all"}


def web_link(query: str) -> str:
    """Manual deep link only (FC5): never requested by V3LUM."""
    return WEB_SEARCH + "?" + urlencode({"q": base64.b64encode(query.encode("utf-8")).decode("ascii")})


def parse_search(doc: Any) -> dict[str, Any] | None:
    """Search answer -> {total, assets, domains}; None when the answer is not a success (code 60000)."""
    if not isinstance(doc, dict) or integer(doc.get("code")) != OK_CODE:
        return None
    rows = doc.get("data")
    if rows is not None and not isinstance(rows, list):
        return None
    assets: list[dict[str, Any]] = []
    domains: list[str] = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        title = row.get("title")
        if isinstance(title, list):
            title = next((t for t in title if isinstance(t, str) and t.strip()), None)
        asn = parse_asn(row.get("asn"))
        asset = {"ip": normalize_ip(row.get("ip")), "port": integer(row.get("port")), "service": text(row.get("service")),
                 "product": text(row.get("product")), "title": (text(title) or "")[:160] or None,
                 "domain": normalize_domain(row.get("domain")), "update_time": text(row.get("update_time")),
                 "asn": f"AS{asn}" if asn else None, "honeypot": flag(row.get("honeypot")) is True}
        assets.append({k: v for k, v in asset.items() if v is not None})
        if asset["domain"] and not asset["honeypot"] and asset["domain"] not in domains:
            domains.append(asset["domain"])
    return {"total": integer(doc.get("total")), "assets": assets, "domains": domains}


@register
class ZoomEye(Module):
    name = "zoomeye"
    title = "ZoomEye host/service search"
    description = (
        "Hosts, open services and web names ZoomEye observed for an IOC selector (public IP, CIDR, domain or "
        "favicon MMH3 hash); keyed, unknown-tier provider, infrastructure selectors only."
    )
    category = "ip_network"
    accepts = {T.IPV4, T.IPV6, T.CIDR, T.DOMAIN, T.FAVICON_HASH}
    produces = {T.DOMAIN}
    reference = "https://www.zoomeye.ai/doc"
    notice = (
        "Tier unknown (Chinese operator; queries reveal targets; LGPD art. 33 transfer not reviewed): excluded at "
        "TLP:AMBER and above, --allow-unknown at CLEAR/GREEN, infrastructure selectors only. Key-terms: a company/team "
        "account recorded by legal. Pivots are capped and never expanded automatically."
    )
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "zoomeye"
    sources = (SOURCE,)
    hosts = ("api.zoomeye.ai",)
    access_model = "free_auth_limited"
    requires_keys = ("zoomeye",)
    max_requests = 1
    expected_latency = 2.0
    timeout = 30.0
    min_interval = 2.0
    cache_ttl = 86400
    max_pivots = PIVOT_CAP
    default_enabled = False  # FC2 (tier unknown also forbids it, A3)

    def applies(self, entity: Entity, ctx: Any) -> bool:
        try:
            zoomeye_query(entity.type, entity.value)
        except ValueError:
            return False
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        key = str(ctx.key("zoomeye") or "").strip()
        if not key:
            return res.mark(Status.NEEDS_KEY, "ZoomEye needs the key 'zoomeye' (V3LUM_ZOOMEYE_KEY)", reason_code="needs_key")
        query = zoomeye_query(entity.type, entity.value)
        doc = ctx.http.post_json(SEARCH_URL, json_body=search_body(query), headers={"API-KEY": key}, ttl=self.cache_ttl,
                                 source=SOURCE, cache_if=json_ok(lambda d: isinstance(d, dict) and integer(d.get("code")) == OK_CODE))
        parsed = parse_search(doc)
        if parsed is None:
            code = integer(doc.get("code")) if isinstance(doc, dict) else None
            return res.mark(Status.ERROR, f"unexpected ZoomEye answer (code {code}): could not verify", reason_code="error")
        assets = parsed["assets"]
        res.raw = {"query": query, "total": parsed["total"], "assets": assets[:MAX_ROWS]}
        # FC5: manual deep link only (added after the answer so a refusal never looks like data)
        res.link("ZoomEye web search (manual; unknown-tier operator, opening it discloses the selector)", web_link(query))
        if not assets:
            return res.mark(Status.EMPTY, f"ZoomEye answered with no asset for {query}")
        res.attr("zoomeye_assets", {"total": parsed["total"], "rows": assets[:MAX_ROWS], "capped": len(assets) > MAX_ROWS})
        if entity.type in (T.IPV4, T.IPV6):
            ports = sorted({a["port"] for a in assets if isinstance(a.get("port"), int) and not a.get("honeypot")})
            res.attr("open_ports", ports)
        services = sorted({f"{a.get('port')}/{a.get('service') or '?'}{' ' + a['product'] if a.get('product') else ''}"
                           for a in assets if a.get("port") is not None and not a.get("honeypot")})
        res.attr("services", services[:50])
        honeypots = sum(1 for a in assets if a.get("honeypot"))
        self._pivots(res, entity, parsed["domains"])
        res.finding(
            "ZoomEye observations",
            "info",
            f"{parsed['total'] if parsed['total'] is not None else len(assets)} asset record(s) for {query}"
            f"{f'; {honeypots} flagged as honeypot by ZoomEye (never pivoted)' if honeypots else ''}. "
            "Scan-engine observations of varying age from an unknown-tier provider.",
            confidence="possible",
            data={"total": parsed["total"], "rows": len(assets), "honeypots": honeypots},
            tags=["unknown_operator"],
            source=SOURCE,
        )
        return res

    def _pivots(self, res: ModuleResult, entity: Entity, domains: list[str]) -> None:
        """FC4: capped, expand=False pivots; CDN/shared-hosting selectors give a count only."""
        if entity.type == T.DOMAIN:
            return  # the names are the selector's own hosts
        shared = entity.type in (T.IPV4, T.IPV6) and noise.is_cdn(entity)
        if shared or len(domains) > MANY_DOMAINS:
            res.attr("cohosting", {"count": len(domains), "mode": "count_only", "sources": ["zoomeye"],
                                   "reason": "CDN/cloud/hosting address (noise lists)" if shared else f"more than {MANY_DOMAINS} names: shared hosting"})
            return
        relation = "related" if entity.type == T.FAVICON_HASH else "hosted_domain"
        for name in domains[:PIVOT_CAP]:
            res.pivot(T.DOMAIN, name, relation, confidence=0.4, expand=False,
                      note="ZoomEye observation (unknown-tier provider): listed for the analyst, never expanded automatically")
