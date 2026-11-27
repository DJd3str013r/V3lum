"""fofa: FOFA search for IOC selectors - domain, IP, certificate, favicon hash (paid key) (P049).

Batch p3-G02-1, proposal P049 (approved, P3). Final conditions implemented here:

* c1 - paid licence bought by the company after a legal/procurement review, including the LGPD art. 33
  transfer to a Chinese provider, and recorded in licence_allow. The source ``fofa.search_api`` is
  'license', so the policy gate runs the module only with that entry. Keys: P049 names ``fofa_email``
  and ``fofa_key``. The ``fofa`` provider (another batch's seed) declares only ``fofa_key`` (one key per
  provider; the current API authenticates with the key alone), so only ``fofa_key`` is used. FOFA takes
  the key in the URL (``key=``): the central redactor (AR01) masks the ``key`` parameter and the
  configured value in URLs, logs, errors, cache rows and evidence, and the module never copies a request
  URL into its results.
* c2 - registry tier unknown (Chinese operator; its query logs reveal our targets). Because of the tier,
  the gate excludes FOFA at AMBER, AMBER+STRICT and RED and needs ``--allow-unknown`` at CLEAR/GREEN.
  Only IOC_TYPES selectors are accepted (IP, domain, certificate, favicon hash). :func:`fofa_query`
  refuses every other type (e-mails, names, phones, keywords...) and any value that could inject query
  syntax.
* c3 - ``default_enabled=False``. Own-asset targets (org profile) and engagement targets (a LIGHT/ACTIVE
  mode, an authorization reference or a scope) are never sent. The council's per-scan opt-in flag
  recorded in the case does not exist in the core yet, so these runs are always SKIPPED ``own_asset``
  (core request in docs/backlog/p3-G02-1.md).
* c4 - base64-encoded queries (``qbase64``: ``domain=``, ``ip=``, ``cert=``, ``icon_hash=``). Results
  are pivots with expand=False.
* c5 - without a key only the FOFA manual pivot links of the G14 pack exist (``pivots_ip_network``).
  This module reports NEEDS_KEY and builds no link itself.
* c6 - merge gate: no paid-key capture exists. The success fixtures are documentation-shaped from the
  official fofa-py client, and the error codes inside HTTP 200 are unverified. docs/backlog/p3-G02-1.md
  records this, and the unverified semantics of ``cert=`` with a SHA-256.
"""

from __future__ import annotations

import base64
import re
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.ip_network.scan_engines import (
    EndpointRefused,
    fetch_json,
    integer,
    json_cache_veto,
    normalize_domain,
    normalize_ip,
    port,
    public_ip,
    text,
)

SOURCE = "fofa.search_api"
KEY = "fofa_key"
SEARCH_URL = "https://fofa.info/api/v1/search/all"
FIELDS = ("host", "ip", "port", "title")
PAGE_SIZE = 100
SELECTORS = {T.DOMAIN: "domain", T.IPV4: "ip", T.CERT_FP: "cert", T.FAVICON_HASH: "icon_hash"}
NEEDS_KEY_MARKERS = frozenset({"fofa_account_invalid"})
PIVOT_CAP = 25
ROW_CAP = 50
_HEX = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")
_ICON = re.compile(r"^-?\d{1,11}$")


def fofa_query(etype: T, value: str) -> str:
    """The FOFA expression of one IOC selector (c2/c4). Values are validated, so quotes or operators can
    never reach the query language. Non-IOC types raise EndpointRefused; invalid values raise ValueError."""
    field = SELECTORS.get(etype)
    if field is None:
        raise EndpointRefused(f"FOFA selector {getattr(etype, 'value', etype)!r} refused: IOC_TYPES selectors only (IP, domain, "
                              "certificate, favicon hash) - never e-mails, names or other personal data (P049 cond 2)")
    s = str(value or "").strip().lower()
    if etype is T.IPV4:
        v = public_ip(s)
    elif etype is T.DOMAIN:
        v = normalize_domain(s)
    elif etype is T.CERT_FP:
        hexval = s.replace(":", "")
        v = hexval if _HEX.match(hexval) else None
    else:
        v = s if _ICON.match(s) and -(2**31) <= int(s) < 2**31 else None
    if not v:
        raise ValueError(f"invalid {etype.value} selector for FOFA")
    return f'{field}="{v}"'


def search_params(query: str, key: str) -> dict[str, str]:
    """GET /api/v1/search/all parameters (c4): the query base64-encoded into ``qbase64``. The key goes in
    the URL because FOFA accepts nothing else (redacted centrally, AR01)."""
    return {"key": key, "qbase64": base64.b64encode(query.encode("utf-8")).decode("ascii"),
            "fields": ",".join(FIELDS), "size": str(PAGE_SIZE), "page": "1"}


def parse_search(data: Any) -> dict[str, Any] | None:
    """{error:false, size, results:[[host, ip, port, title], ...]} -> {total, rows}; None for anything else."""
    if not isinstance(data, dict) or data.get("error") is not False or not isinstance(data.get("results"), list):
        return None
    rows: list[dict[str, Any]] = []
    for raw in data["results"]:
        row = raw if isinstance(raw, list) else [raw]
        cells = dict(zip(FIELDS, row))
        host = text(cells.get("host"), 300)
        hostname = normalize_domain(re.sub(r"^[a-z]+://", "", host).split("/")[0].rsplit(":", 1)[0]) if host else None
        entry = {"host": host, "hostname": hostname, "ip": normalize_ip(cells.get("ip")), "port": port(cells.get("port")),
                 "title": text(cells.get("title"), 160)}
        rows.append({k: v for k, v in entry.items() if v not in (None, "")})
    total = integer(data.get("size"))
    return {"total": total if total is not None else len(rows), "rows": rows}


def _engagement(ctx: Any) -> bool:
    options = getattr(ctx, "options", None)
    mode = getattr(options, "mode", None)
    return bool(getattr(options, "authorization_ref", "") or getattr(options, "scope", None) or getattr(options, "scope_path", "")
                or getattr(mode, "label", "passive") != "passive")


@register
class Fofa(Module):
    name = "fofa"
    title = "FOFA search (IOC selectors)"
    description = (
        "Hosts, IPs, ports and page titles FOFA indexed for a public IP, a domain, a certificate fingerprint or a favicon "
        "hash (paid licence, unknown-tier Chinese provider, infrastructure selectors only)."
    )
    category = "ip_network"
    accepts = {T.IPV4, T.DOMAIN, T.CERT_FP, T.FAVICON_HASH}
    produces = {T.IPV4, T.DOMAIN}
    reference = "https://en.fofa.info/api"
    notice = (
        "Paid licence recorded in licence_allow after a legal/procurement review (LGPD art. 33: queries go to a Chinese "
        "provider whose logs reveal our targets). Tier unknown: excluded at TLP:AMBER and above, --allow-unknown at "
        "CLEAR/GREEN, IOC selectors only; own-asset and engagement targets are never sent. Results are never expanded."
    )
    terms = "license"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "fofa"
    sources = (SOURCE,)
    hosts = ("fofa.info",)
    access_model = "commercial_only"
    requires_keys = (KEY,)
    max_requests = 1
    expected_latency = 3.0
    timeout = 30.0
    min_interval = 2.0
    daily_quota = 20  # fallback until the licence's F-point budget is recorded as a quota block (P334)
    cache_ttl = 604800  # fewer repeat queries to the provider
    max_pivots = PIVOT_CAP * 2
    default_enabled = False

    def applies(self, entity: Entity, ctx: Any) -> bool:
        try:
            fofa_query(entity.type, entity.value)
        except ValueError:
            return False
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        key = str(ctx.key(KEY) or "").strip()
        if not key:
            return res.mark(Status.NEEDS_KEY, "FOFA needs the paid key 'fofa_key' (V3LUM_FOFA_KEY); without it only the FOFA "
                            "manual pivot links exist", reason_code="needs_key")
        org = getattr(ctx, "org", None)
        try:
            own = bool(getattr(org.owns(entity), "own", False)) if org is not None else False
        except Exception:  # noqa: BLE001 - an unreadable profile fails closed
            own = True
        if own or _engagement(ctx):
            return res.mark(Status.SKIPPED, "FOFA: own-asset and engagement targets are never sent to this provider without a "
                            "per-scan opt-in recorded in the case (P049 cond 3)", reason_code="own_asset")
        query = fofa_query(entity.type, entity.value)
        data = fetch_json(ctx, "GET", SEARCH_URL, source=SOURCE, params=search_params(query, key),
                          needs_key_markers=NEEDS_KEY_MARKERS, ttl=self.cache_ttl,
                          cache_if=json_cache_veto(lambda d: parse_search(d) is not None), provider_label="FOFA")
        parsed = parse_search(data)
        if parsed is None:
            return res.mark(Status.ERROR, "unexpected FOFA answer (no 'error: false' result set): could not verify", reason_code="error")
        rows = parsed["rows"]
        res.raw = {"query": query, "total": parsed["total"], "rows": rows[:ROW_CAP]}
        if not rows:
            return res.mark(Status.EMPTY, f"FOFA indexes nothing for {query}")
        res.attr("fofa_assets", {"total": parsed["total"], "rows": rows[:ROW_CAP], "capped": len(rows) > ROW_CAP})
        if entity.type is T.IPV4:
            res.attr("open_ports", sorted({r["port"] for r in rows if r.get("port")}))
        self._pivots(res, entity, rows)
        res.finding(
            "FOFA observations",
            "info",
            f"{parsed['total']} result(s) for {query} from an unknown-tier provider; observations of varying age, listed for "
            "the analyst and never expanded automatically.",
            confidence="possible",
            data={"total": parsed["total"], "rows": len(rows)},
            tags=["unknown_operator"],
            source=SOURCE,
        )
        return res

    def _pivots(self, res: ModuleResult, entity: Entity, rows: list[dict[str, Any]]) -> None:
        """c4: every pivot is expand=False."""
        ip_rel = {T.DOMAIN: "resolves_to"}.get(entity.type, "scanner_match")
        name_rel = {T.IPV4: "hosted_domain"}.get(entity.type, "scanner_match")
        ips = sorted({r["ip"] for r in rows if r.get("ip")})
        names = sorted({r["hostname"] for r in rows if r.get("hostname")})
        note = "FOFA observation (unknown-tier provider): listed for the analyst, never expanded automatically (P049 cond 4)"
        if entity.type is not T.IPV4:
            for ip in ips[:PIVOT_CAP]:
                res.pivot(T.IPV4, ip, ip_rel, confidence="possible", expand=False, note=note)
        for name in names[:PIVOT_CAP]:
            if name == entity.value:
                continue
            res.pivot(T.DOMAIN, name, name_rel, confidence="possible", expand=False, note=note)


__all__ = ["Fofa", "fofa_query", "parse_search", "search_params"]
