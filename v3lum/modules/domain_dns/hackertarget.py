"""HackerTarget free API: host search, reverse IP, ASN and reverse analytics lookups (P014).

Batch p2-G01-2, proposal P014 ``hackertarget``. Final conditions implemented here:

* c1 - passive endpoints only, held in the code allow-list :data:`ENDPOINTS` (hostsearch,
  reverseiplookup, aslookup, dnslookup, analyticslookup): :func:`build_url` refuses every other
  endpoint, so the tools that make HackerTarget probe the target (nmap, zonetransfer, mtr,
  httpheaders, pagelinks, nping) cannot be built (test-asserted).
* c2 - plain-text errors inside HTTP 200 are matched before parsing: 'API count exceeded' -> QUOTA with
  the provider marked exhausted for the day (provider marker, P321/P334), 'error check your search
  parameter' -> ERROR (provider marker), any other one-line 'error ...' body -> ERROR (module marker),
  'no records found' / 'no results found' -> EMPTY.
* c3 - the provider-keyed P334 block of ``hackertarget`` (50/day per egress IP, budget 80%) is
  shared by every module calling api.hackertarget.com. Keyless use runs only on analyst-typed seeds;
  pivots use it only with a key (SKIPPED 'not_applicable' otherwise).
* c4 - optional key ``hackertarget`` (V3LUM_HACKERTARGET_KEY), sent only as the documented ``apikey``
  query parameter, which the central redactor masks everywhere (AR01). Its plan (key_plans) and the
  keyless business-use decision (free_plan_business_use) are the licence gate's (A1).
* c5 - analyticslookup answers go through the P061 shared-id rule: more than 50 domains or a
  template/placeholder id -> 'shared ID' (info, no pivots, no same-owner correlation, confidence
  <= 0.3); otherwise same_analytics pivots with expand=False, confidence <= 0.7, at most 10.
* c6 - reverse-IP answers with more than 50 domains, or for CDN/shared-hosting/resolver addresses (core
  noise kinds, P034), become a count attribute only: no pivots, no co-hosting correlation.
* c7 - an exhausted quota ends the run QUOTA with the one wording 'HackerTarget free quota used for
  this egress IP: add a key' (the core prints one quota line per provider per scan).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import quote

from v3lum.core import noise
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import QuotaExceeded
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register

SOURCE = "hackertarget.api"
BASE = "https://api.hackertarget.com"
#: P014 c1: the code allow-list of passive endpoints (endpoint -> accepted entity types).
ENDPOINTS: dict[str, frozenset[T]] = {
    "hostsearch": frozenset({T.DOMAIN}),
    "dnslookup": frozenset({T.DOMAIN}),
    "reverseiplookup": frozenset({T.IPV4}),
    "aslookup": frozenset({T.IPV4, T.ASN}),
    "analyticslookup": frozenset({T.ANALYTICS_ID}),
}
QUOTA_LINE = "HackerTarget free quota used for this egress IP: add a key"
QUOTA_LINE_KEYED = "HackerTarget quota of the configured key is used up for today"
NO_RECORDS = ("no records found", "no results found", "no dns records found")
#: P014 c6 / P015 c7: more co-hosted names than this (or a CDN/shared address) -> counts only.
COHOST_LIMIT = 50
#: co-hosted names that auto-expand on a dedicated IP (the rest are listed for the analyst).
EXPAND_COHOSTED = 10
#: P061 c5: shared-id threshold and the reverse-lookup pivot cap.
SHARED_ID_LIMIT = 50
ANALYTICS_PIVOTS = 10
#: The free tier stops hostsearch at about 50 rows (registro.br answered 51 rows in tree order).
TRUNCATION_ROWS = 50
MAX_SUBDOMAIN_PIVOTS = 60
SHARED_KINDS = frozenset({"cdn", "cloud", "hosting", "saas", "resolver"})
_ANALYTICS = re.compile(r"^(?:UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{6,12}|GTM-[A-Z0-9]{4,9}|(?:ca-)?pub-\d{16})$")
#: Placeholder/template ids copied from tutorials and themes (P061 c5 'known template id').
_TEMPLATE_ID = re.compile(r"^(?:UA-(?:0{4,10}|1234|12345|123456|1234567|12345678|123456789|1{4,10}|X+)-\d{1,4}|G-X{6,12}|GTM-X{4,9}|(?:ca-)?pub-(?:0{16}|1234567890123456))$", re.I)
_HOST = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
_CSV_FIELD = re.compile(r'"[^"]*"|[^,]+')


# ======================================================================================
# URL builder (P014 c1, c4)
# ======================================================================================


def build_url(endpoint: str, etype: T, value: str, key: str = "") -> str:
    """URL of one allow-listed passive endpoint; ValueError for any other endpoint or an invalid value.
    The key goes only into the documented ``apikey`` parameter (masked by the central redactor)."""
    allowed = ENDPOINTS.get(endpoint) if isinstance(endpoint, str) else None
    if allowed is None:
        raise ValueError(f"hackertarget: endpoint {endpoint!r} is not in the passive allow-list")
    if etype not in allowed:
        raise ValueError(f"hackertarget: {endpoint} does not take {getattr(etype, 'value', etype)!r}")
    q = _query_value(etype, value)
    if not q:
        raise ValueError(f"hackertarget: invalid {getattr(etype, 'value', etype)} value")
    url = f"{BASE}/{endpoint}/?q={quote(q, safe='')}"
    if key:
        url += "&apikey=" + quote(str(key), safe="")
    return url


def _query_value(etype: T, value: str) -> str:
    text = str(value or "").strip()
    if etype is T.DOMAIN:
        text = text.lower().rstrip(".")
        return text if _HOST.match(text) else ""
    if etype is T.IPV4:
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            return ""
        return str(ip) if ip.version == 4 and ip.is_global else ""
    if etype is T.ASN:
        m = re.fullmatch(r"(?i)(?:AS)?(\d{1,10})", text)
        return f"AS{int(m.group(1))}" if m and 0 < int(m.group(1)) < 4_294_967_296 else ""
    if etype is T.ANALYTICS_ID:
        return text if _ANALYTICS.match(text) else ""
    return ""


# ======================================================================================
# parsers (plain text; every parser assumes the error markers already ran)
# ======================================================================================


def body_text(content: Any) -> str:
    if isinstance(content, (bytes, bytearray)):
        return bytes(content[:2_000_000]).decode("utf-8", errors="replace").lstrip("﻿")
    return str(content or "")[:2_000_000]


def empty_answer(text: str) -> bool:
    """'no records found' / 'no results found' (P014 c2: EMPTY, a documented absence)."""
    first = text.strip().splitlines()[0].strip().lower() if text.strip() else ""
    return first in NO_RECORDS or (len(text.strip()) < 120 and bool(re.match(r"^no (?:dns )?(?:records|results)(?: found)?\b", first)))


def looks_like_html(text: str) -> bool:
    head = text.lstrip()[:512].lower()
    return head.startswith("<") and any(t in head for t in ("<!doctype html", "<html", "<head", "<body", "<title"))


def _lines(text: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def _host(value: str) -> str | None:
    text = str(value or "").strip().lower().rstrip(".")
    return text if _HOST.match(text) else None


def _ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return None


def parse_hostsearch(text: str) -> dict[str, Any]:
    """'host,ip' lines -> {records [{host, ip}], malformed, rows}; >= 50 rows is possibly truncated."""
    records: list[dict[str, str | None]] = []
    seen: set[tuple[str, str | None]] = set()
    malformed = 0
    rows = _lines(text)
    for line in rows:
        parts = [p.strip() for p in line.split(",")]
        host = _host(parts[0]) if parts else None
        ip = _ip(parts[1]) if len(parts) > 1 and parts[1] else None
        if not host or len(parts) > 2:
            malformed += 1
            continue
        if (host, ip) not in seen:
            seen.add((host, ip))
            records.append({"host": host, "ip": ip})
    return {"records": records, "malformed": malformed, "rows": len(rows), "possibly_truncated": len(rows) >= TRUNCATION_ROWS}


def parse_names(text: str) -> list[str]:
    """One name per line (reverseiplookup) -> unique host names."""
    out: list[str] = []
    for line in _lines(text):
        host = _host(line.split(",")[0])
        if host and host not in out:
            out.append(host)
    return out


def parse_aslookup(text: str) -> dict[str, Any]:
    """IP form '"8.8.8.8","15169","8.8.8.0/24","GOOGLE, US"'; ASN form '"15169","GOOGLE, US"' plus prefix lines."""
    out: dict[str, Any] = {"ip": None, "asn": None, "prefix": None, "name": None, "country": None, "prefixes": []}
    label = None
    for line in _lines(text):
        fields = [f.strip().strip('"').strip() for f in _CSV_FIELD.findall(line)]
        if len(fields) == 4 and _ip(fields[0]) and fields[1].isdigit():
            out["ip"], out["asn"] = _ip(fields[0]), int(fields[1])
            try:
                out["prefix"] = str(ipaddress.ip_network(fields[2], strict=False))
            except ValueError:
                out["prefix"] = None
            label = fields[3]
        elif len(fields) == 2 and re.fullmatch(r"(?i)(?:AS)?\d{1,10}", fields[0]):
            out["asn"] = int(re.sub(r"(?i)^AS", "", fields[0]))
            label = fields[1]
        else:
            try:
                net = str(ipaddress.ip_network(line.strip().strip('"'), strict=False))
            except ValueError:
                continue
            if net not in out["prefixes"]:
                out["prefixes"].append(net)
    if label:
        m = re.match(r"^(.*?),\s*([A-Z]{2})$", label)
        out["name"], out["country"] = (m.group(1).strip()[:120], m.group(2)) if m else (label[:120], None)
    return out


def parse_dnslookup(text: str) -> list[dict[str, Any]]:
    """'TYPE : value' lines -> [{type, value, host?}] (a null MX '0 .' keeps host '.')."""
    out: list[dict[str, Any]] = []
    for line in _lines(text):
        m = re.match(r"^([A-Z]{1,10})\s*:\s*(.*)$", line)
        if not m:
            continue
        rtype, value = m.group(1), m.group(2).strip()[:500]
        rec: dict[str, Any] = {"type": rtype, "value": value}
        if rtype == "MX":
            parts = value.split()
            if len(parts) == 2 and parts[0].isdigit():
                rec["host"] = parts[1].rstrip(".").lower() or "."
        elif rtype in ("NS", "CNAME"):
            rec["host"] = value.rstrip(".").lower()
        elif rtype in ("A", "AAAA"):
            rec["value"] = _ip(value) or value
        out.append(rec)
    return out


def parse_analytics(text: str) -> list[str]:
    """'domain<TAB>kind' lines (observed) or 'id,domain' lines -> unique domains."""
    out: list[str] = []
    for line in _lines(text):
        for part in re.split(r"[\t,]", line):
            host = _host(part)
            if host and not _ANALYTICS.match(part.strip()):
                if host not in out:
                    out.append(host)
                break
    return out


def shared_analytics_id(aid: str, domains: list[str]) -> str:
    """P061 c5: reason why the id is a shared id ('' when it is not)."""
    if _TEMPLATE_ID.match(aid):
        return "template or placeholder id copied from examples"
    if len(domains) > SHARED_ID_LIMIT:
        return f"more than {SHARED_ID_LIMIT} domains"
    return ""


def quota_headers(headers: Any) -> dict[str, int]:
    """x-api-quota / x-api-count / x-api-boost (per endpoint and egress IP) for the evidence."""
    out: dict[str, int] = {}
    for name in ("x-api-quota", "x-api-count", "x-api-boost"):
        value = str((headers or {}).get(name, "") or "").strip()
        if value.isdigit():
            out[name] = int(value)
    return out


@register
class HackerTarget(Module):
    name = "hackertarget"
    title = "HackerTarget host search, reverse IP and ASN"
    description = (
        "Passive HackerTarget lookups: subdomains with their IPs (hostsearch), domains co-hosted on an IP (reverse IP), "
        "ASN and prefix of an IP or the prefixes of an ASN, and the sites sharing an analytics id."
    )
    category = "domain_dns"
    accepts = {T.DOMAIN, T.IPV4, T.ASN, T.ANALYTICS_ID}
    produces = {T.DOMAIN, T.IPV4, T.CIDR, T.ASN}
    tags = {"free"}
    reference = "https://hackertarget.com/ip-tools/"
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "hackertarget"
    sources = (SOURCE,)
    hosts = ("api.hackertarget.com",)
    access_model = "free_noauth_limited"
    optional_keys = ("hackertarget",)
    max_requests = 2
    expected_latency = 0.8
    timeout = 25.0
    min_interval = 2.0
    cache_ttl = 86400
    max_pivots = 100
    default_enabled = True
    error_markers = (
        {
            "id": "hackertarget_error_body",
            "statuses": [200],
            "json_path": None,
            "equals": None,
            "regex": r"\A\s*error(?:\s|:|$)",
            "final_url_regex": None,
            "maps_to": "error",
            "reason_code": "error",
            "reason": "HackerTarget: error message in an HTTP 200 body",
        },
    )
    settings = {"hackertarget_dnslookup": False}
    notice = (
        "Passive endpoints only (hostsearch, reverseiplookup, aslookup, dnslookup, analyticslookup): the tools that make "
        "HackerTarget probe the target are never built. Free quota: 50 requests/day per egress IP shared by every module "
        "(budget 40); keyless use runs only on analyst-typed seeds. Key-terms: a company/team membership recorded by legal "
        "(key_plans.hackertarget); keyless business use needs free_plan_business_use recorded by legal."
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        etype = entity.type
        if etype is T.IPV4:
            return noise.is_public_ip(entity.value)
        if etype is T.ANALYTICS_ID:
            return bool(_ANALYTICS.match(entity.value))
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        key = ctx.key("hackertarget")
        if not ctx.is_seed and not key:
            # P014 c3: keyless use only on analyst-typed seeds; pivots only with a key
            return res.mark(
                "skipped",
                "keyless HackerTarget runs on analyst-typed seeds only (free quota 50/day per egress IP): add a key (hackertarget) to use it on pivots",
                reason_code="not_applicable",
            )
        res.raw = {"queries": []}
        try:
            if entity.type is T.DOMAIN:
                self._domain(entity, ctx, res, key)
            elif entity.type is T.IPV4:
                self._ipv4(entity, ctx, res, key)
            elif entity.type is T.ASN:
                self._asn(entity, ctx, res, key)
            else:
                self._analytics(entity, ctx, res, key)
        except QuotaExceeded:
            line = QUOTA_LINE_KEYED if key else QUOTA_LINE
            if res.has_data:
                res.error = line
                return res.stop("quota")
            return res.mark("quota", line)
        return res

    # ------------------------------------------------------------------ plumbing
    def _get(self, ctx: Any, res: ModuleResult, endpoint: str, etype: T, value: str, key: str) -> str | None:
        """Text answer of one endpoint, or None for 'no records found' (EMPTY). Error-in-200 markers and
        classifications raise before parsing (P014 c2): quota, rate limits, challenges, error bodies."""
        resp = ctx.http.get(build_url(endpoint, etype, value, key), source=SOURCE)
        ctx.http.check(resp)
        text = body_text(resp.content)
        res.raw["queries"].append({"endpoint": endpoint, "status": resp.status, "bytes": len(resp.content or b""), **quota_headers(resp.headers)})
        if not text.strip():
            raise _Unusable(f"HackerTarget {endpoint}: empty body")
        if looks_like_html(text):
            raise _Unusable(f"HackerTarget {endpoint}: an HTML page instead of text")
        if empty_answer(text):
            return None
        return text

    # ------------------------------------------------------------------ domain: hostsearch (+ dnslookup)
    def _domain(self, entity: Entity, ctx: Any, res: ModuleResult, key: str) -> None:
        domain = entity.value
        try:
            text = self._get(ctx, res, "hostsearch", T.DOMAIN, domain, key)
        except _Unusable as exc:
            res.mark("error", f"{exc}: could not verify")
            return
        if text is not None:
            parsed = parse_hostsearch(text)
            records = [r for r in parsed["records"] if r["host"] == domain or str(r["host"]).endswith("." + domain)]
            res.raw["hostsearch"] = {"rows": parsed["rows"], "records": len(records), "malformed": parsed["malformed"]}
            names = sorted({r["host"] for r in records if r["host"] != domain})
            res.attr("subdomains", names)
            res.attr("passive_dns", [
                {"hostname": r["host"], "address": r["ip"], "record_type": "A", "source": "hackertarget hostsearch"}
                for r in records if r["ip"]
            ][:200])
            if parsed["possibly_truncated"]:
                res.attr("truncated_answer", f"HackerTarget hostsearch answered {parsed['rows']} rows (free-tier cap ~50): the list is possibly incomplete")
            for name in names[:MAX_SUBDOMAIN_PIVOTS]:
                res.pivot(T.DOMAIN, name, "subdomain", confidence="probable", note="seen by HackerTarget host search")
            ips = sorted({r["ip"] for r in records if r["ip"]})
            for ip in ips[:25]:
                hosts = sorted({str(r["host"]) for r in records if r["ip"] == ip})
                res.pivot(T.IPV4 if ":" not in ip else T.IPV6, ip, "related", confidence="possible", expand=False,
                          note=f"address of {', '.join(hosts[:3])}{' ...' if len(hosts) > 3 else ''} (HackerTarget host search)")
        dns_text = None
        if ctx.setting("hackertarget_dnslookup", False):
            try:
                dns_text = self._get(ctx, res, "dnslookup", T.DOMAIN, domain, key)
            except _Unusable as exc:
                res.source_status(SOURCE, "error", reason=f"{exc}: could not verify")
            if dns_text is not None:
                records = parse_dnslookup(dns_text)
                res.raw["dnslookup"] = records[:100]
                res.attr("a_records", sorted({r["value"] for r in records if r["type"] == "A" and _ip(r["value"])}))
                res.attr("aaaa_records", sorted({r["value"] for r in records if r["type"] == "AAAA" and _ip(r["value"])}))
                res.attr("nameservers", sorted({r["host"] for r in records if r["type"] == "NS" and r.get("host")}))
        if text is None and dns_text is None and not res.has_data:
            res.mark("empty")

    # ------------------------------------------------------------------ IPv4: reverse IP + ASN
    def _ipv4(self, entity: Entity, ctx: Any, res: ModuleResult, key: str) -> None:
        ip = entity.value
        answered = False
        try:
            text = self._get(ctx, res, "reverseiplookup", T.IPV4, ip, key)
            answered = True
        except _Unusable as exc:
            res.source_status(SOURCE, "error", reason=f"{exc}: could not verify")
            text = None
        if text is not None:
            names = parse_names(text)
            kinds = sorted(noise.noise_kinds(entity) & SHARED_KINDS)
            shared = bool(kinds) or len(names) > COHOST_LIMIT
            reason = f"{'/'.join(kinds)} address" if kinds else (f"more than {COHOST_LIMIT} names" if shared else "")
            res.attr("cohosting", {
                "count": len(names),
                "mode": "count_only" if shared else "pivot",
                "reason": reason,
                "sources": ["hackertarget reverseiplookup"],
                "exclude_from_shared_infra": shared,
            })
            res.raw["reverseiplookup"] = {"names": len(names)}
            if shared:
                res.attr("shared_ip", True)  # P014 c6: a count only, no pivots, no co-hosting correlation
            else:
                for i, name in enumerate(names):
                    res.pivot(T.DOMAIN, name, "hosted_domain", confidence=0.6, expand=i < EXPAND_COHOSTED,
                              note="co-hosted on a dedicated IP (HackerTarget reverse IP)")
        try:
            as_text = self._get(ctx, res, "aslookup", T.IPV4, ip, key)
            answered = True
        except _Unusable as exc:
            res.source_status(SOURCE, "error", reason=f"{exc}: could not verify")
            as_text = None
        if as_text is not None:
            self._as_facts(ctx, res, parse_aslookup(as_text))
        if not answered:
            res.mark("error", "HackerTarget answered with unusable bodies: could not verify")
        elif text is None and as_text is None and not res.has_data:
            res.mark("empty")

    def _as_facts(self, ctx: Any, res: ModuleResult, info: dict[str, Any]) -> None:
        res.raw["aslookup"] = info
        if info["asn"]:
            res.attr("asn", f"AS{info['asn']}")
            res.pivot(T.ASN, f"AS{info['asn']}", "belongs_to_asn", confidence="probable", expand=bool(ctx.is_seed), note="origin AS (HackerTarget)")
        res.attr("as_org", info["name"])
        res.attr("as_country", info["country"])
        if info["prefix"]:
            res.attr("prefix", info["prefix"])
            res.pivot(T.CIDR, info["prefix"], "in_network", confidence="probable", expand=False, note="BGP prefix (HackerTarget)")

    # ------------------------------------------------------------------ ASN: name + prefixes
    def _asn(self, entity: Entity, ctx: Any, res: ModuleResult, key: str) -> None:
        try:
            text = self._get(ctx, res, "aslookup", T.ASN, entity.value, key)
        except _Unusable as exc:
            res.mark("error", f"{exc}: could not verify")
            return
        if text is None:
            res.mark("empty")
            return
        info = parse_aslookup(text)
        res.raw["aslookup"] = info
        res.attr("as_org", info["name"])
        res.attr("as_country", info["country"])
        prefixes = info["prefixes"]
        if prefixes:
            v4 = sum(1 for p in prefixes if ":" not in p)
            res.attr("announced_prefix_counts", {"total": len(prefixes), "ipv4": v4, "ipv6": len(prefixes) - v4,
                                                 "pivoted": min(len(prefixes), 25), "capped": len(prefixes) > 25, "truncated": False})
        for prefix in prefixes[:25]:
            res.pivot(T.CIDR, prefix, "announces", confidence="probable", expand=False, note="announced prefix (HackerTarget)")

    # ------------------------------------------------------------------ analytics id: P061 shared-id rule
    def _analytics(self, entity: Entity, ctx: Any, res: ModuleResult, key: str) -> None:
        aid = entity.value
        try:
            text = self._get(ctx, res, "analyticslookup", T.ANALYTICS_ID, aid, key)
        except _Unusable as exc:
            res.mark("error", f"{exc}: could not verify")
            return
        if text is None:
            res.mark("empty")
            return
        domains = parse_analytics(text)
        if not domains:
            res.mark("error", "HackerTarget analyticslookup answered without domains: could not verify")
            return
        shared = shared_analytics_id(aid, domains)
        res.raw["analyticslookup"] = {"domains": len(domains), "shared": bool(shared)}
        res.attr("analytics_shared_id", {
            "id": aid,
            "domains": len(domains),
            "shared": bool(shared),
            "label": f"shared ID {aid}: {len(domains)} domains" if shared else "",
            "reason": shared,
        })
        if shared:
            # P061 c5: info only, no pivots, no same-owner correlation, confidence <= 0.3
            res.finding(
                "Shared analytics ID (no ownership link)",
                "info",
                f"shared ID {aid}: {len(domains)} domains ({shared}). Agencies, themes and site builders reuse such ids: they "
                "never link the sites to one owner.",
                confidence=0.3,
                data={"id": aid, "domains": len(domains), "reason": shared, "sample": domains[:10]},
                source=SOURCE,
            )
            return
        res.finding(
            "Sites sharing the analytics ID",
            "info",
            f"{len(domains)} domain(s) carry {aid} according to HackerTarget: a same-owner lead (POSSIBLE to PROBABLE), never "
            "proof on its own.",
            confidence=0.7,
            data={"id": aid, "domains": domains[:50]},
            source=SOURCE,
        )
        for name in domains[:ANALYTICS_PIVOTS]:
            res.pivot(T.DOMAIN, name, "same_analytics", confidence=0.7, expand=False, note=f"site carrying {aid} (HackerTarget)")


class _Unusable(Exception):
    """An HTTP 200 answer that is neither data nor a documented absence (empty body, HTML page)."""


__all__ = ["ENDPOINTS", "HackerTarget", "QUOTA_LINE", "build_url", "parse_analytics", "parse_aslookup", "parse_dnslookup",
           "parse_hostsearch", "parse_names", "shared_analytics_id"]
