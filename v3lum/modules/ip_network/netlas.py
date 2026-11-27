"""netlas: Netlas host summaries and domain index lookups for IPs, domains and keywords (P037).

Batch p3-G02-1, proposal P037 (approved, P3). Final conditions implemented here:

* c1 - licence. Keyless use and the free Community plan are noncommercial (source ``netlas.api``). A
  paid-plan key is key-terms (source ``netlas.netlas_paid_plan``, added by this batch's provider
  extension). Under the corporate profile the policy gate therefore lets the module run only with
  ``key_plans.netlas='business'`` (paid source) or a licence_allow entry (api source). The module uses
  only the sources the gate hands it (``ctx.allowed_sources``) and names that source on every request.
* c2 - key ``netlas`` (alias ``V3LUM_NETLAS_KEY``), sent only in the ``X-API-Key`` header. In a default
  scan run without the key the module reports NEEDS_KEY. Keyless requests happen only when the module is
  selected explicitly (``-M netlas`` or ``v3lum run netlas``), and only where the licence profile allows
  them. The netlas provider's quota block budgets them (P334, 80% of the published 50/day); the
  daily_quota fallback carries the same figure.
* c3 - host and domain endpoints only: ``/api/host/{ip_or_domain}/``, ``/api/domains_count/`` and the
  first page of ``/api/domains/``. :func:`netlas_url` refuses everything else, including responses
  search, certificate and WHOIS search, downloads and the scanner. A keyword job is sized with the free
  ``domains_count`` before the paid page is fetched. A domain job uses the ``related_domains_count`` of
  the host answer as its count, and only analyst-typed seeds get the extra domains page (seeds first,
  P334).
* c4 - error bodies inside HTTP 200 go through the provider markers of
  ``netlas__p3-G02-1.json``: quota gives QUOTA, throttling gives RATE_LIMITED, an authentication type
  gives NEEDS_KEY (mapped here from marker ``netlas_auth_in_body``) and any other error body gives
  ERROR. None of them is ever read as EMPTY. A truncated or malformed body is ERROR as well.
* c5 - co-hosted ``domains[]`` of an IP give only a count (attribute ``cohosting``, mode count_only)
  when the IP is CDN/cloud/hosting noise (P034 noise lists) or holds more than 50 names. Otherwise at
  most 10 ``hosted_domain`` pivots are listed, auto-expanded only when 10 or fewer names share the IP.
* c6 - the web UI is behind a Cloudflare challenge: only a manual link to ``app.netlas.io/host/...``,
  never requested.
* c7 - the fixtures are trimmed real answers: the keyless host answers for an IP (research
  2026-11-25) and for a domain, the domains_count answers and the domains page (live, 2026-11-26).

IOC entries are one weak vote. Netlas flags most of them itself as false-positive alarms
(``fp.alarm``); those stay context. The others become one 'low' finding tagged ``weak_signal`` that
goes through warninglist suppression and is never a verdict.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from v3lum.core import noise
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.ip_network.scan_engines import (
    EndpointRefused,
    apex_of,
    as_dict,
    as_list,
    explicitly_selected,
    fetch_json,
    flag,
    in_apex,
    integer,
    json_cache_veto,
    normalize_domain,
    normalize_ip,
    number,
    port,
    public_ip,
    str_list,
    text,
)

SOURCE_API = "netlas.api"  # keyless and Community key: noncommercial (c1)
SOURCE_PAID = "netlas.netlas_paid_plan"  # paid-plan key: key-terms (c1)
KEY = "netlas"
BASE = "https://app.netlas.io"
WEB_HOST = "https://app.netlas.io/host/{q}/"
#: c3: the only endpoints this module builds (op -> path). Everything else raises EndpointRefused.
ENDPOINTS: dict[str, str] = {
    "host": "/api/host/{value}/",
    "domains_count": "/api/domains_count/",
    "domains": "/api/domains/",
}
NEEDS_KEY_MARKERS = frozenset({"netlas_auth_in_body"})
KEYWORD_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,62}$")
SHARED_THRESHOLD = 50  # c5: more co-hosted names than this = shared hosting (count only)
COHOST_PIVOT_CAP = 10
COHOST_EXPAND_MAX = 10
SUBDOMAIN_PIVOT_CAP = 20
KEYWORD_PIVOT_CAP = 20
KEYWORD_COUNT_CAP = 2000  # a keyword matching more names than this is too broad to page through
RECORD_CAP = 20


def netlas_url(op: str, value: str = "") -> str:
    """The URL of one wired endpoint (c3). Raises EndpointRefused for any other endpoint (scanner,
    responses search, downloads...) and ValueError for an invalid host value."""
    name = str(op or "").strip()
    if name not in ENDPOINTS:
        raise EndpointRefused(f"Netlas endpoint {name!r} is never wired: host and domain endpoints only (P037 cond 3)")
    path = ENDPOINTS[name]
    if "{value}" in path:
        target = normalize_ip(value) or normalize_domain(value)
        if not target:
            raise ValueError("Netlas host lookups take an IP address or a domain")
        return BASE + path.format(value=quote(target, safe=":"))
    return BASE + path


def domain_query(entity: Entity) -> str:
    """Netlas query for the domain endpoints: ``domain:*.{domain}`` or ``domain:*{keyword}*``."""
    if entity.type is T.KEYWORD:
        kw = str(entity.value or "").strip().lower()
        if not KEYWORD_RE.match(kw):
            raise ValueError("Netlas keyword searches take 3-63 characters of [a-z0-9-]")
        return f"domain:*{kw}*"
    name = normalize_domain(entity.value)
    if not name:
        raise ValueError("Netlas domain searches take a domain")
    return f"domain:*.{name}"


# --------------------------------------------------------------------------------------
# parsers (untrusted data: every field is type-checked)
# --------------------------------------------------------------------------------------


def parse_host(data: Any) -> dict[str, Any] | None:
    """GET /api/host/{value}/ -> normalised facts; None when the body is not a host answer."""
    if not isinstance(data, dict):
        return None
    kind = data.get("type")
    if kind not in ("ip", "domain") and not any(k in data for k in ("ip", "domain", "ports", "whois", "dns")):
        return None
    out: dict[str, Any] = {"kind": kind if kind in ("ip", "domain") else ("ip" if data.get("ip") else "domain")}
    out["organization"] = text(data.get("organization"), 200)
    out["ptr"] = [n for n in (normalize_domain(p) for p in as_list(data.get("ptr"))) if n][:20]
    ports: list[dict[str, Any]] = []
    for item in as_list(data.get("ports")):
        item = as_dict(item)
        p = port(item.get("port"))
        if p is None:
            continue
        ports.append({"port": p, "transport": text(item.get("prot4"), 8), "protocol": text(item.get("protocol"), 40),
                      "app_protocol": text(item.get("prot7"), 40)})
    out["ports"] = ports[:100]
    products: list[str] = []
    cdn = False
    for sw in as_list(data.get("software"))[:200]:
        for tag in as_list(as_dict(sw).get("tag")):
            tag = as_dict(tag)
            name = tag.get("name")
            if not isinstance(name, str) or not name:
                continue
            cats = [c.lower() for c in str_list(tag.get("category"), 10, 60)]
            cdn = cdn or "cdn" in cats
            version = text(as_dict(tag.get(name)).get("version"), 40)
            label = (text(tag.get("fullname"), 80) or text(name, 80)) + (f" {version}" if version else "")
            if label and label not in products:
                products.append(label)
    out["products"], out["cdn"] = products[:50], cdn
    whois = as_dict(data.get("whois"))
    net = as_dict(whois.get("net"))
    out["whois_network"] = {k: v for k, v in {
        "name": text(net.get("name"), 120), "handle": text(net.get("handle"), 80), "range": text(net.get("range"), 80),
        "cidrs": str_list(net.get("cidr"), 10, 50), "organization": text(net.get("organization"), 160),
        "country": text(net.get("country"), 2).upper()}.items() if v}
    asn = as_dict(whois.get("asn"))
    numbers = [n for n in (integer(x) for x in as_list(asn.get("number"))) if n is not None and n > 0]
    out["asn"] = f"AS{numbers[0]}" if numbers else ""
    out["as_org"] = text(asn.get("name"), 160)
    abuse = whois.get("abuse")
    out["abuse_contact"] = text(abuse, 120) if isinstance(abuse, str) and "@" in abuse else ""
    out["created"] = text(whois.get("created_date"), 40) if out["kind"] == "domain" else ""
    dns = as_dict(data.get("dns"))
    out["dns"] = {
        "a": [ip for ip in (normalize_ip(x) for x in as_list(dns.get("a"))) if ip][:30],
        "aaaa": [ip for ip in (normalize_ip(x) for x in as_list(dns.get("aaaa"))) if ip][:30],
        "ns": [n for n in (normalize_domain(x) for x in as_list(dns.get("ns"))) if n][:20],
        "mx": [n for n in (normalize_domain(x) for x in as_list(dns.get("mx"))) if n][:20],
        "txt": str_list(dns.get("txt"), 20, 500),
    }
    geo = as_dict(data.get("geo"))
    out["country"] = text(geo.get("country"), 2).upper()
    priv = as_dict(data.get("privacy"))
    out["privacy"] = {k: flag(priv.get(f"is_{k}")) for k in ("vpn", "proxy", "tor")}
    iocs: list[dict[str, Any]] = []
    for item in as_list(data.get("ioc"))[:100]:
        item = as_dict(item)
        iocs.append({"threats": str_list(item.get("threat"), 10, 80), "tags": str_list(item.get("tags"), 10, 60),
                     "score": number(as_dict(item.get("score")).get("total")),
                     "first_seen": text(item.get("fseen"), 40), "last_seen": text(item.get("lseen"), 40),
                     "fp_alarm": flag(as_dict(item.get("fp")).get("alarm")) is True})
    out["ioc"] = iocs
    out["domains"] = [n for n in (normalize_domain(x) for x in as_list(data.get("domains"))) if n]
    out["domains_count"] = integer(data.get("domains_count"))
    out["related_domains"] = [n for n in (normalize_domain(x) for x in as_list(data.get("related_domains"))) if n]
    out["related_domains_count"] = integer(data.get("related_domains_count"))
    out["scan_labels"] = sorted({text(as_dict(s).get("scan_label"), 20) for s in as_list(data.get("source"))} - {""})[:5]
    has_data = any((out["organization"], out["ptr"], ports, products, out["whois_network"], out["asn"], out["created"],
                    any(out["dns"].values()), iocs, out["domains"], (out["domains_count"] or 0) > 0,
                    out["related_domains"], (out["related_domains_count"] or 0) > 0))
    out["empty"] = not has_data
    return out


def parse_count(data: Any) -> int | None:
    """GET /api/domains_count/ -> the count; None when the body is not a count answer."""
    count = integer(data.get("count")) if isinstance(data, dict) else None
    return count if count is not None and count >= 0 else None


def parse_domains(data: Any) -> list[dict[str, Any]] | None:
    """GET /api/domains/ (first page) -> [{domain, a, aaaa, cname, seen}]; None when not a domains page."""
    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        return None
    records: list[dict[str, Any]] = []
    for item in data["items"]:
        rec = as_dict(as_dict(item).get("data"))
        name = normalize_domain(rec.get("domain"))
        if not name:
            continue
        records.append({k: v for k, v in {
            "domain": name,
            "a": [ip for ip in (normalize_ip(x) for x in as_list(rec.get("a"))) if ip][:10],
            "aaaa": [ip for ip in (normalize_ip(x) for x in as_list(rec.get("aaaa"))) if ip][:10],
            "cname": [n for n in (normalize_domain(x) for x in as_list(rec.get("cname"))) if n][:5],
            "seen": text(rec.get("@timestamp"), 40)}.items() if v})
    return records


def ioc_summary(iocs: list[dict[str, Any]]) -> dict[str, Any]:
    credible = [i for i in iocs if not i.get("fp_alarm")]
    return {"total": len(iocs), "fp_flagged": len(iocs) - len(credible),
            "credible": [{k: v for k, v in i.items() if k != "fp_alarm" and v not in ("", [], None)} for i in credible][:10]}


def cohost_plan(entity: Entity, parsed: dict[str, Any]) -> dict[str, Any]:
    """c5 / P034: count-only or capped pivots for the co-hosted names of an IP."""
    names = parsed.get("domains") or []
    count = parsed.get("domains_count")
    count = len(names) if count is None else count
    reason = ""
    if noise.is_cdn(entity):
        reason = "CDN/cloud/hosting address (noise lists, P034)"
    elif count > SHARED_THRESHOLD:
        reason = f"more than {SHARED_THRESHOLD} names on the address: shared hosting"
    if reason:
        return {"count": count, "mode": "count_only", "reason": reason, "sources": ["netlas"], "pivots": [], "expand": False}
    return {"count": count, "mode": "pivot", "reason": "", "sources": ["netlas"], "pivots": names[:COHOST_PIVOT_CAP],
            "expand": count <= COHOST_EXPAND_MAX}


def _ok_host(data: Any) -> bool:
    return parse_host(data) is not None


@register
class Netlas(Module):
    name = "netlas"
    title = "Netlas host and domain index"
    description = (
        "Open ports, software tags, WHOIS network, IOC records and co-hosted domains of an IP, DNS, WHOIS and "
        "subdomains of a domain, and domains matching a keyword, from the Netlas index (app.netlas.io)."
    )
    category = "ip_network"
    accepts = {T.IPV4, T.DOMAIN, T.KEYWORD}
    produces = {T.DOMAIN, T.IPV4, T.IPV6}
    reference = "https://docs.netlas.io/"
    notice = (
        "Netlas keyless use and the free Community plan are 'for your own personal needs (non-commercial use only)': "
        "off under the corporate profile until licence-cleared (key_plans.netlas='business' for a paid plan, or a "
        "licence_allow entry). Default runs need the key 'netlas'; keyless calls only with -M. The web UI is a "
        "manual link (Cloudflare challenge)."
    )
    terms = "noncommercial"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "netlas"
    sources = (SOURCE_API, SOURCE_PAID)
    hosts = ("app.netlas.io",)
    access_model = "free_auth_limited"
    optional_keys = (KEY,)
    max_requests = 3
    expected_latency = 3.0
    timeout = 30.0
    min_interval = 2.0
    daily_quota = 40
    cache_ttl = 86400
    max_pivots = 60
    manual_link = WEB_HOST
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.IPV4:
            return public_ip(entity.value) is not None  # private/reserved addresses are never sent
        if entity.type is T.KEYWORD:
            return bool(KEYWORD_RE.match(str(entity.value).strip().lower())) and bool(getattr(ctx, "is_seed", True))
        return normalize_domain(entity.value) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        key = str(ctx.key(KEY) or "").strip()
        if not key and not explicitly_selected(self.name, ctx):
            return res.mark(Status.NEEDS_KEY, "Netlas runs by default only with the key 'netlas' (V3LUM_NETLAS_KEY); "
                            "keyless lookups need -M netlas (P037 cond 2)", reason_code="needs_key")
        allowed = set(getattr(ctx, "allowed_sources", ()) or self.sources)
        if key and SOURCE_PAID in allowed and (ctx.key_plan(KEY) == "business" or SOURCE_API not in allowed):
            source = SOURCE_PAID
        elif SOURCE_API in allowed:
            source = SOURCE_API
        else:
            return res.mark(Status.SKIPPED, "Netlas: no licensed access mode for this run (keyless and Community use are "
                            "noncommercial; a paid plan needs key_plans.netlas='business')", reason_code="licence")
        headers = {"X-API-Key": key} if key else {}
        if entity.type is T.KEYWORD:
            return self._keyword(res, entity, ctx, source, headers)
        data = fetch_json(ctx, "GET", netlas_url("host", entity.value), source=source, headers=headers,
                          needs_key_markers=NEEDS_KEY_MARKERS, ttl=self.cache_ttl, cache_if=json_cache_veto(_ok_host),
                          provider_label="Netlas")
        parsed = parse_host(data)
        if parsed is None:
            return res.mark(Status.ERROR, "unexpected Netlas host answer: could not verify", reason_code="error")
        res.link("Netlas host page (manual: Cloudflare challenge, opened by the analyst)", WEB_HOST.format(q=quote(entity.value, safe=":")))
        res.raw = {"source": source, "keyless": not key, "host": {k: v for k, v in parsed.items() if k != "abuse_contact"}}
        res.attr("scan_engine_summary", {"provider": "netlas", "endpoint": "host", "scan_labels": parsed["scan_labels"],
                                         "keyless": not key})
        if parsed["empty"]:
            return res.mark(Status.EMPTY, f"Netlas holds no host data for {entity.value}")
        self._common(res, parsed)
        if entity.type is T.IPV4:
            self._ip(res, entity, parsed)
        else:
            self._domain(res, entity, ctx, parsed, source, headers)
        self._ioc(res, parsed, source)
        return res

    # ---- shared facts -----------------------------------------------------------------

    def _common(self, res: ModuleResult, parsed: dict[str, Any]) -> None:
        ports = parsed["ports"]
        res.attr("open_ports", sorted({p["port"] for p in ports}))
        res.attr("services", [f"{p['port']}/{p['transport'] or '?'} {p['protocol'] or p['app_protocol'] or '?'}" for p in ports][:50])
        res.attr("technologies", parsed["products"])
        if parsed["cdn"]:
            res.attr("is_cdn", True)

    def _ip(self, res: ModuleResult, entity: Entity, parsed: dict[str, Any]) -> None:
        res.attr("org", parsed["organization"])
        res.attr("asn", parsed["asn"])
        res.attr("as_org", parsed["as_org"])
        res.attr("country", parsed["country"])
        if parsed["whois_network"]:
            res.attr("whois_network", {**parsed["whois_network"], "source": "netlas"})
        res.attr("abuse_contact", parsed["abuse_contact"])  # role address: attribute only, never a pivot
        res.attr("rdns", parsed["ptr"])
        privacy = parsed["privacy"]
        if privacy.get("vpn"):
            res.attr("is_vpn", True)
        if privacy.get("proxy"):
            res.attr("is_proxy", True)
        if privacy.get("tor"):
            res.attr("context_tags", ["tor"])
        shared = noise.is_cdn(entity)
        for name in parsed["ptr"]:
            res.pivot(T.DOMAIN, name, "reverse_dns", confidence="probable", expand=not shared,
                      note="" if not shared else "PTR of a CDN/cloud/hosting address: listed, not expanded")
        plan = cohost_plan(entity, parsed)
        res.attr("cohosted_count", plan["count"])
        res.attr("cohosting", {k: plan[k] for k in ("count", "mode", "reason", "sources") if plan[k] not in ("", None)})
        for name in plan["pivots"]:
            res.pivot(T.DOMAIN, name, "hosted_domain", confidence="possible", expand=plan["expand"],
                      note="" if plan["expand"] else "co-hosted name from the Netlas index: listed for the analyst, not expanded (P037 cond 5)")

    def _domain(self, res: ModuleResult, entity: Entity, ctx: Any, parsed: dict[str, Any], source: str, headers: dict[str, str]) -> None:
        dns = parsed["dns"]
        res.attr("a_records", dns["a"])
        res.attr("aaaa_records", dns["aaaa"])
        res.attr("nameservers", dns["ns"])
        res.attr("mx", dns["mx"])
        res.attr("txt", dns["txt"])
        res.attr("created", parsed["created"])
        for ip in dns["a"]:
            res.pivot(T.IPV4, ip, "resolves_to", confidence="possible", expand=False,
                      note="A record from the Netlas DNS index (may be weeks old): re-resolve before acting")
        for ip in dns["aaaa"]:
            res.pivot(T.IPV6, ip, "resolves_to", confidence="possible", expand=False,
                      note="AAAA record from the Netlas DNS index (may be weeks old): re-resolve before acting")
        for name in dns["ns"]:
            res.pivot(T.DOMAIN, name, "nameserver", confidence="probable", expand=False)
        for name in dns["mx"]:
            res.pivot(T.DOMAIN, name, "mx_host", confidence="probable", expand=False)
        apex = apex_of(entity) or entity.value
        count = parsed["related_domains_count"]
        res.attr("subdomain_count", count)
        names = list(parsed["related_domains"])
        if ctx.is_seed and (count or 0) > 0:  # seeds first (P334): the count of the host answer sizes the job
            page = fetch_json(ctx, "GET", netlas_url("domains"), source=source, headers=headers,
                              params={"q": domain_query(entity)}, needs_key_markers=NEEDS_KEY_MARKERS, ttl=self.cache_ttl,
                              cache_if=json_cache_veto(lambda d: parse_domains(d) is not None), provider_label="Netlas")
            records = parse_domains(page)
            if records is None:  # the host facts stand; the extra page is reported, never read as 'no subdomains'
                ctx.log("Netlas: unexpected domains page: subdomain records could not be verified", level="warning")
                if isinstance(res.raw, dict):
                    res.raw["domains_page"] = "unexpected answer: could not verify"
            else:
                res.attr("subdomain_records", records[:RECORD_CAP])
                names.extend(r["domain"] for r in records)
        seen: set[str] = set()
        for name in names:
            if name in seen or name == entity.value:
                continue
            seen.add(name)
            if len(seen) > SUBDOMAIN_PIVOT_CAP:
                break
            inside = in_apex(name, apex)
            res.pivot(T.DOMAIN, name, "subdomain" if inside else "related", confidence="probable" if inside else "possible",
                      expand=inside, note="" if inside else "name outside the queried apex: listed, not expanded")

    def _ioc(self, res: ModuleResult, parsed: dict[str, Any], source: str) -> None:
        if not parsed["ioc"]:
            return
        summary = ioc_summary(parsed["ioc"])
        res.attr("netlas_ioc", summary)
        credible = summary["credible"]
        if not credible:
            return
        threats = sorted({t for i in credible for t in i.get("threats", [])})[:10]
        tags = sorted({t for i in credible for t in i.get("tags", [])})[:10]
        last = max((i.get("last_seen") or "" for i in credible), default="") or None
        res.finding(
            "Netlas IOC records (weak vote)",
            "low",
            f"{len(credible)} Netlas IOC record(s) without Netlas' own false-positive alarm"
            f"{' (' + ', '.join(threats) + ')' if threats else ''}; {summary['fp_flagged']} other record(s) carry the "
            "alarm and are context only. One weak vote, never a verdict on its own.",
            confidence="possible",
            criterion="Netlas IOC entry whose fp.alarm is not 'true' (one weak vote; goes through warninglist suppression)",
            data={"threats": threats, "tags": tags, "credible": len(credible), "fp_flagged": summary["fp_flagged"]},
            tags=["weak_signal", "third_party_verdict"],
            source=source,
            observed_last=last,
        )

    # ---- keyword ----------------------------------------------------------------------

    def _keyword(self, res: ModuleResult, entity: Entity, ctx: Any, source: str, headers: dict[str, str]) -> ModuleResult:
        query = domain_query(entity)
        data = fetch_json(ctx, "GET", netlas_url("domains_count"), source=source, headers=headers, params={"q": query},
                          needs_key_markers=NEEDS_KEY_MARKERS, ttl=self.cache_ttl,
                          cache_if=json_cache_veto(lambda d: parse_count(d) is not None), provider_label="Netlas")
        count = parse_count(data)
        if count is None:
            return res.mark(Status.ERROR, "unexpected Netlas domains_count answer: could not verify", reason_code="error")
        res.raw = {"source": source, "keyless": not headers, "query": query, "count": count}
        res.attr("scan_engine_summary", {"provider": "netlas", "endpoint": "domains_count", "totals": {"domains": count},
                                         "keyless": not headers})
        if count == 0:
            return res.mark(Status.EMPTY, f"Netlas indexes no domain matching {query}")
        if count > KEYWORD_COUNT_CAP:
            res.finding("Keyword too broad for a Netlas domain search", "info",
                        f"{count} indexed names match {query}: the page was not fetched (budget). Refine the keyword.",
                        confidence="probable", data={"count": count}, source=source)
            return res
        page = fetch_json(ctx, "GET", netlas_url("domains"), source=source, headers=headers, params={"q": query},
                          needs_key_markers=NEEDS_KEY_MARKERS, ttl=self.cache_ttl,
                          cache_if=json_cache_veto(lambda d: parse_domains(d) is not None), provider_label="Netlas")
        records = parse_domains(page)
        if records is None:
            return res.mark(Status.ERROR, "unexpected Netlas domains answer: could not verify", reason_code="error")
        res.attr("keyword_domains", [{"domain": r["domain"]} for r in records[:RECORD_CAP]])
        res.attr("subdomain_records", records[:RECORD_CAP])
        for rec in records[:KEYWORD_PIVOT_CAP]:
            res.pivot(T.DOMAIN, rec["domain"], "scanner_match", confidence="possible", expand=False,
                      note="name matching the keyword in the Netlas index: a candidate to verify, never expanded automatically")
        res.finding("Domains matching the keyword (Netlas index)", "info",
                    f"{count} indexed name(s) match {query}; the first {len(records)} are listed as candidates.",
                    confidence="possible", data={"count": count, "listed": len(records)}, source=source)
        return res


__all__ = ["Netlas", "cohost_plan", "domain_query", "ioc_summary", "netlas_url", "parse_count", "parse_domains", "parse_host"]
