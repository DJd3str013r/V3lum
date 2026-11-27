"""onyphe: ONYPHE Summary API v2 for an IP, a domain or a host name (keyed) (P042).

Batch p3-G02-1, proposal P042 (approved, P3). Final conditions implemented here:

* c1 - key ``onyphe`` (alias ``V3LUM_ONYPHE_KEY``), declared in the ``onyphe`` provider fragment this
  batch owns. It is sent only in the ``Authorization: bearer`` header. Without the key the run is
  NEEDS_KEY before anything is sent.
* c2 - key-terms: a company/team account on a plan whose terms permit internal business use. The policy
  gate runs it under the corporate profile only with ``key_plans.onyphe='business'`` (legal records the
  plan and the terms URL). ``default_enabled=False`` (opt-in as drafted).
* c3 - summary endpoints only (:func:`onyphe_url`; the simple API is on the allow-list but not called,
  because the summary already covers every category). Search, export, discovery, alert, bulk, user, the
  'unrated' endpoint (key in the URL) and the v3 on-demand Scope APIs (which make ONYPHE scan on request)
  cannot be built. Budget: the monthly credits of the recorded plan are not published in a verified
  source, so the provider has no quota block yet; ``daily_quota`` is a conservative fallback (P334
  budget: docs/backlog/p3-G02-1.md). Only analyst-typed seeds and depth-1 pivots spend credits.
* c4 - JSON error bodies (``status: nok``) go through the provider markers. Error 2 'No API key given'
  and refused keys give NEEDS_KEY (mapped here from the marker ids), credit exhaustion gives QUOTA,
  'rate limit' gives RATE_LIMITED and any other 'nok' gives ERROR. None of them is ever EMPTY. The web
  search requires sign-in, so there is no manual link.
* c5 - merge gate: the success fixture is documentation-shaped (no team-key capture exists). The
  recorded no-key 400 fixture is real. docs/backlog/p3-G02-1.md records the missing capture.

ONYPHE echoes the caller's egress IP in ``myip``. The module never copies it into results or evidence.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.ip_network.scan_engines import (
    VERSION_INFERRED_CRITERION,
    EndpointRefused,
    apex_of,
    as_dict,
    as_list,
    cve_id,
    fetch_json,
    in_apex,
    integer,
    json_cache_veto,
    normalize_domain,
    normalize_ip,
    port,
    public_ip,
    str_list,
    text,
)

SOURCE = "onyphe.summary_api"
KEY = "onyphe"
BASE = "https://www.onyphe.io/api/v2"
SUMMARY_KINDS = frozenset({"ip", "domain", "hostname"})
#: c3: the simple API categories that may be built (not called by this module: the summary covers them)
SIMPLE_CATEGORIES = frozenset({"geoloc", "inetnum", "threatlist", "datascan", "resolver", "ctl", "synscan", "vulnscan"})
NEEDS_KEY_MARKERS = frozenset({"onyphe_no_api_key", "onyphe_invalid_api_key"})
NAME_PIVOT_CAP = 20
CERT_PIVOT_CAP = 10
SERVICE_CAP = 50


def onyphe_url(op: str, kind_or_category: str, value: str) -> str:
    """URL of one wired endpoint (c3): ``summary/{ip|domain|hostname}/{value}`` or
    ``simple/{category}/{ip}``. Raises EndpointRefused for anything else (search, export, discovery,
    alert, bulk, user, unrated, on-demand scope)."""
    op = str(op or "").strip().lower()
    kind = str(kind_or_category or "").strip().lower()
    if op == "summary" and kind in SUMMARY_KINDS:
        target = normalize_ip(value) if kind == "ip" else normalize_domain(value)
    elif op == "simple" and kind in SIMPLE_CATEGORIES:
        target = normalize_ip(value)
    else:
        raise EndpointRefused(f"ONYPHE endpoint {op}/{kind} is never wired: summary/simple endpoints only (P042 cond 3)")
    if not target:
        raise ValueError(f"invalid value for ONYPHE {op}/{kind}")
    return f"{BASE}/{op}/{kind}/{quote(target, safe=':')}"


def summary_kind(entity: Entity) -> str:
    if entity.type in (T.IPV4, T.IPV6):
        return "ip"
    apex = apex_of(entity)
    return "domain" if apex == entity.value else "hostname"


def _names(value: Any) -> list[str]:
    raw = value if isinstance(value, list) else [value]
    return [n for n in (normalize_domain(x) for x in raw) if n]


def parse_summary(data: Any) -> dict[str, Any] | None:
    """Summary envelope -> grouped facts; None unless ``status == 'ok'`` with a results list."""
    if not isinstance(data, dict) or data.get("status") != "ok" or not isinstance(data.get("results"), list):
        return None
    out: dict[str, Any] = {"total": integer(data.get("total")), "categories": {}, "geo": {}, "inetnum": {}, "services": [],
                           "ports": set(), "cpes": [], "products": [], "vulns": {}, "threatlists": [], "threat_tags": set(),
                           "names": [], "ips": [], "certs": [], "last_seen": ""}
    for row in data["results"]:
        row = as_dict(row)
        cat = text(row.get("@category"), 30).lower()
        if not cat:
            continue
        out["categories"][cat] = out["categories"].get(cat, 0) + 1
        stamp = text(row.get("@timestamp"), 40)
        if stamp > out["last_seen"]:
            out["last_seen"] = stamp
        if cat == "geoloc" and not out["geo"]:
            asn = text(row.get("asn"), 16).upper()
            out["geo"] = {"country": text(row.get("country"), 2).upper(), "city": text(row.get("city"), 80),
                          "asn": asn if asn.startswith("AS") and asn[2:].isdigit() else "", "org": text(row.get("organization"), 160),
                          "subnet": text(row.get("subnet"), 50)}
        elif cat == "inetnum" and not out["inetnum"]:
            out["inetnum"] = {k: v for k, v in {"name": text(row.get("netname"), 120), "organization": text(row.get("organization"), 160),
                                                "country": text(row.get("country"), 2).upper(), "cidrs": str_list([row.get("subnet")], 5, 50),
                                                "registry": text(row.get("source"), 20)}.items() if v}
        elif cat in ("datascan", "synscan", "vulnscan"):
            p = port(row.get("port"))
            if p is not None:
                out["ports"].add(p)
            product = text(row.get("product"), 80)
            version = text(row.get("productversion"), 40)
            if cat == "datascan" and p is not None and len(out["services"]) < SERVICE_CAP:
                label = f"{p}/{text(row.get('transport'), 8) or 'tcp'} {text(row.get('protocol'), 30) or '?'}"
                label += f" {product}{' ' + version if version else ''}" if product else ""
                out["services"].append(label)
            if product:
                full = f"{product}{' ' + version if version else ''}"
                if full not in out["products"]:
                    out["products"].append(full)
            for cpe in str_list(row.get("cpe"), 5, 200):
                if cpe.startswith("cpe:") and cpe not in out["cpes"]:
                    out["cpes"].append(cpe)
            for raw in as_list(row.get("cve")):
                cid = cve_id(raw)
                if cid:
                    out["vulns"].setdefault(cid, {"cve": cid, "port": p, "product": product, "version": version})
        elif cat == "threatlist":
            name = text(row.get("threatlist"), 80)
            if name and name not in out["threatlists"]:
                out["threatlists"].append(name)
            out["threat_tags"].update(t.lower() for t in str_list(row.get("tag"), 10, 40))
        if cat == "ctl":
            sha = text(as_dict(row.get("fingerprint")).get("sha256"), 64).lower()
            if len(sha) == 64 and all(c in "0123456789abcdef" for c in sha) and sha not in out["certs"]:
                out["certs"].append(sha)
        if cat in ("resolver", "datascan", "ctl"):
            for name in _names(row.get("hostname")) + _names(row.get("domain")):
                if name not in out["names"]:
                    out["names"].append(name)
        if cat == "resolver":
            ip = normalize_ip(row.get("ip"))
            if ip and ip not in out["ips"]:
                out["ips"].append(ip)
    out["ports"] = sorted(out["ports"])
    out["threat_tags"] = sorted(out["threat_tags"])
    out["empty"] = not out["categories"]
    return out


def _ok(data: Any) -> bool:
    return parse_summary(data) is not None


@register
class Onyphe(Module):
    name = "onyphe"
    title = "ONYPHE summary"
    description = (
        "Geolocation, network, open services, version-inferred CVEs, threat-list entries, resolver names and CT "
        "certificates ONYPHE recorded in the last 30 days for an IP, a domain or a host name (Summary API, keyed)."
    )
    category = "ip_network"
    accepts = {T.IPV4, T.IPV6, T.DOMAIN}
    produces = {T.DOMAIN, T.IPV4, T.IPV6, T.CERT_FP}
    reference = "https://search.onyphe.io/docs/general-apis/summary"
    notice = (
        "Keyed (onyphe): key-terms - a company/team ONYPHE account whose plan permits internal business use, recorded "
        "by legal (key_plans.onyphe='business'). Summary endpoint only; the web search needs sign-in (no manual link)."
    )
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "onyphe"
    sources = (SOURCE,)
    hosts = ("www.onyphe.io",)
    access_model = "free_auth_limited"
    requires_keys = (KEY,)
    max_requests = 1
    expected_latency = 2.0
    timeout = 30.0
    min_interval = 2.0
    daily_quota = 20  # conservative fallback until the plan's monthly credits are recorded (P334)
    cache_ttl = 86400
    max_pivots = 50
    default_enabled = False

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if int(getattr(ctx, "depth", 0) or 0) > 1:
            return False  # credits: seeds and first-level pivots only
        if entity.type in (T.IPV4, T.IPV6):
            return public_ip(entity.value) is not None
        return normalize_domain(entity.value) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        key = str(ctx.key(KEY) or "").strip()
        if not key:
            return res.mark(Status.NEEDS_KEY, "ONYPHE needs the key 'onyphe' (V3LUM_ONYPHE_KEY)", reason_code="needs_key")
        kind = summary_kind(entity)
        data = fetch_json(ctx, "GET", onyphe_url("summary", kind, entity.value), source=SOURCE,
                          headers={"Authorization": f"bearer {key}"}, needs_key_markers=NEEDS_KEY_MARKERS,
                          ttl=self.cache_ttl, cache_if=json_cache_veto(_ok), provider_label="ONYPHE")
        parsed = parse_summary(data)
        if parsed is None:
            return res.mark(Status.ERROR, "unexpected ONYPHE answer (no 'status: ok' envelope): could not verify", reason_code="error")
        summary = {"provider": "onyphe", "endpoint": f"summary/{kind}", "window": "last 30 days",
                   "categories": parsed["categories"], "totals": {"results": parsed["total"]}}
        res.raw = {"summary": summary, "facts": {k: v for k, v in parsed.items() if k not in ("empty",)}}  # never 'myip'
        res.attr("scan_engine_summary", summary)
        if parsed["empty"]:
            return res.mark(Status.EMPTY, f"ONYPHE holds no record of the last 30 days for {entity.value}")
        geo = parsed["geo"]
        res.attr("country", geo.get("country"))
        res.attr("city", geo.get("city"))
        res.attr("asn", geo.get("asn"))
        res.attr("as_org", geo.get("org"))
        if parsed["inetnum"]:
            res.attr("whois_network", {**parsed["inetnum"], "source": "onyphe"})
        res.attr("open_ports", parsed["ports"])
        res.attr("services", parsed["services"])
        res.attr("cpes", parsed["cpes"][:50])
        res.attr("technologies", parsed["products"][:50])
        self._vulns(res, entity, parsed)
        self._threats(res, parsed)
        self._pivots(res, entity, parsed)
        return res

    def _vulns(self, res: ModuleResult, entity: Entity, parsed: dict[str, Any]) -> None:
        vulns = list(parsed["vulns"].values())
        if not vulns:
            return
        res.attr("vulns", [v["cve"] for v in vulns][:100])
        products = sorted({f"{v['product']} {v['version']}".strip() for v in vulns if v.get("product")})
        res.finding(
            "CVE(s) associated with exposed software (version-inferred)",
            "medium",
            f"ONYPHE vulnscan lists {len(vulns)} CVE(s) for {entity.value}"
            f"{' (' + ', '.join(products[:5]) + ')' if products else ''}. Version-inferred: distro backports are not "
            "considered; confirm on the host.",
            confidence="possible",
            criterion=VERSION_INFERRED_CRITERION,
            data={"vulns": [{**v, "verified": False} for v in vulns[:50]]},
            tags=["vulnerable", "version_inferred"],
            source=SOURCE,
            observed_last=parsed["last_seen"] or None,
        )

    def _threats(self, res: ModuleResult, parsed: dict[str, Any]) -> None:
        if not parsed["threatlists"]:
            return
        res.attr("tags", parsed["threat_tags"])
        res.finding(
            "Listed in ONYPHE threat lists",
            "low",
            f"ONYPHE threat list(s): {', '.join(parsed['threatlists'][:10])}. One vote, never a verdict on its own.",
            confidence="possible",
            criterion="ONYPHE 'threatlist' category entry of the last 30 days (aggregated third-party list: one vote)",
            data={"threatlists": parsed["threatlists"][:20], "tags": parsed["threat_tags"]},
            tags=["blocklisted", "third_party_verdict"],
            source=SOURCE,
            observed_last=parsed["last_seen"] or None,
        )

    def _pivots(self, res: ModuleResult, entity: Entity, parsed: dict[str, Any]) -> None:
        is_ip = entity.type in (T.IPV4, T.IPV6)
        apex = None if is_ip else apex_of(entity)
        for name in parsed["names"][:NAME_PIVOT_CAP]:
            if name == entity.value:
                continue
            if is_ip:
                res.pivot(T.DOMAIN, name, "hosted_domain", confidence="possible", expand=False,
                          note="name ONYPHE saw on the address (last 30 days): listed for the analyst, not expanded")
            else:
                inside = in_apex(name, apex)
                res.pivot(T.DOMAIN, name, "subdomain" if inside else "related", confidence="possible", expand=False,
                          note="name from ONYPHE resolver/CT data: listed for the analyst, not expanded")
        if not is_ip:
            for ip in parsed["ips"][:NAME_PIVOT_CAP]:
                etype = T.IPV6 if ":" in ip else T.IPV4
                res.pivot(etype, ip, "resolves_to", confidence="possible", expand=False,
                          note="resolution ONYPHE recorded in the last 30 days: re-resolve before acting")
        relation = "serves_certificate" if is_ip else "has_certificate"
        for sha in parsed["certs"][:CERT_PIVOT_CAP]:
            res.pivot(T.CERT_FP, sha, relation, confidence="possible", expand=False,
                      note="certificate from ONYPHE CT data: listed, not expanded")


__all__ = ["Onyphe", "onyphe_url", "parse_summary", "summary_kind"]
