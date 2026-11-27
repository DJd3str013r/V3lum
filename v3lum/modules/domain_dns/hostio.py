"""host.io domain relations (P004): keyed lookups of a seed domain or tracking id.

Final conditions (council #1, P004) and where they live:

1. Key ``hostio`` (provider fragment ``hostio.json``: env ``V3LUM_KEY_HOSTIO``, aliases
   ``V3LUM_HOSTIO_TOKEN``/``V3LUM_HOSTIO_KEY``); without it NEEDS_KEY before the run. host.io documents
   Basic, Bearer and ``?token=`` authentication (https://host.io/docs, read 2026-11-26): the token goes in
   the ``Authorization: Bearer`` header (:func:`_get`), never in the URL, and redirects are not followed.
2. Key-terms: the licence gate runs it under the corporate profile only with ``key_plans.hostio =
   'business'`` (team account, plan and terms recorded by legal).
3. Endpoints (:data:`BASE`): ``/api/full/{domain}`` - documented as the union of ``/api/web``, ``/api/dns``,
   ``/api/related`` and IPinfo, so one request carries the web, related and ipinfo data of the condition -
   then ``/api/domains/{field}/{value}`` for redirects, backlinks and the googleanalytics / adsense / gtm
   reverse lookups. ``run_on='seeds'``; at most 5 requests per entity (``max_requests``); cache 7 days.
   No P334 quota block exists for host.io yet: ``daily_quota`` 25 keeps the module under 80% of the free
   plan's 1,000 requests per month (https://host.io/pricing) until legal records the team plan.
4. Reverse analytics/AdSense/GTM results follow P061 (:func:`reverse_decision`): an id seen on more than 50
   domains is a shared agency/platform id (no same_analytics link, no reverse call spent when the related
   count already says so); an id shared with an org_profile own site on a non-own site is a clone
   indicator (``copied_tracking_id``, tag ``brand_abuse``), never a same-owner link; same_analytics
   pivots are at most PROBABLE (0.7) and capped.
5. Redirect relations are recorded with their dates (attribute ``redirect_relations``: the homepage scrape
   date for the domain's own redirect, the fetch date for reverse redirects - host.io publishes no
   per-redirect date). Backlinks pivot with ``expand=False`` (relation ``linked_from``: the backlink
   domain links to the seed; ``links_to`` keeps the seed's own outbound links). Every result is an
   ownership candidate for the analyst, never scope.
6. Errors in bodies map through P321 markers (:attr:`HostIo.error_markers`: quota -> QUOTA, throttling ->
   RATE_LIMITED) plus the key check of :func:`_get` (missing/invalid token -> NEEDS_KEY); never EMPTY.
   A documented 404 ``{"error": "No details found ..."}`` is the only absence.
7. Fixtures: the real research error answer (400 'API Access Token Required') and host.io's own
   documentation samples; success fixtures captured with the team key are still owed (merge gate,
   docs/backlog/p2-G01-1.md). The web view ``https://host.io/{domain}`` is the manual link.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import quote, urlsplit

from v3lum.config import SettingSpec
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register

SOURCE = "hostio.api"
HOST = "host.io"
BASE = "https://host.io/api"
KEY_NAME = "hostio"
#: P061: an id seen on more than this many domains is a shared agency/platform id
SHARED_THRESHOLD = 50
#: pivots kept per relation list (same_analytics, linked_from, redirected_from, links_to)
PIVOT_CAP = 10
#: reverse id lookups per domain run: full + redirects + backlinks + 2 = max_requests 5
MAX_REVERSE = 2
#: host.io page sizes (docs: 'limit' must be one of these; the free plan allows 5)
LIMITS = (1, 5, 10, 25, 100, 250, 1000)
#: /api/domains fields of tracking ids (P061 reverse lookups)
ID_FIELDS = ("googleanalytics", "adsense", "gtm")
NO_DATA_RE = re.compile(r"(?i)\bno details\b")
TOKEN_RE = re.compile(r"(?i)token|unauthori[sz]ed|forbidden|invalid (?:api )?key|authenticat")

_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_UA_RE = re.compile(r"^UA-(\d{4,10})(?:-\d{1,4})?$", re.I)
_G_RE = re.compile(r"^G-[A-Z0-9]{6,12}$", re.I)
_GTM_RE = re.compile(r"^GTM-[A-Z0-9]{4,10}$", re.I)
_PUB_RE = re.compile(r"^(?:ca-)?pub-(\d{10,20})$", re.I)


class _NeedsKey(Exception):
    """host.io refused the token (missing, invalid, unauthorised)."""


class _Absent(Exception):
    """Documented 404 'No details found': host.io has no data for the value."""


class _Unusable(Exception):
    """An answer that cannot be read as the documented format: could not verify (ERROR)."""


def _text(value: Any, limit: int = 200) -> str:
    if value is None or isinstance(value, (dict, list, bool)):
        return ""
    return re.sub(r"\s+", " ", _CTRL_RE.sub("", str(value))).strip()[:limit]


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _domain(value: Any) -> str | None:
    """Untrusted host name (or URL) -> canonical domain through Entity.try_make, else None."""
    text = _text(value, 300)
    if not text:
        return None
    if "://" in text:
        try:
            text = urlsplit(text).hostname or ""
        except ValueError:
            return None
    ent = Entity.try_make(T.DOMAIN, text.rstrip("."))
    return str(ent.value) if ent is not None and "." in str(ent.value) else None


def id_field(value: Any) -> str | None:
    """host.io /api/domains field of a tracking id: googleanalytics (UA-/G-), adsense (pub-), gtm (GTM-)."""
    text = _text(value, 40)
    if _UA_RE.match(text) or _G_RE.match(text):
        return "googleanalytics"
    if _PUB_RE.match(text):
        return "adsense"
    if _GTM_RE.match(text):
        return "gtm"
    return None


def hostio_id(value: Any) -> str | None:
    """The form host.io indexes: UA account ids without the property suffix ('UA-12345678-1' ->
    'UA-12345678'), AdSense as 'pub-N', GA4/GTM ids upper-case."""
    text = _text(value, 40)
    m = _UA_RE.match(text)
    if m:
        return f"UA-{m.group(1)}"
    m = _PUB_RE.match(text)
    if m:
        return f"pub-{m.group(1)}"
    if _G_RE.match(text) or _GTM_RE.match(text):
        return text.upper()
    return None


def full_url(domain: str) -> str:
    return f"{BASE}/full/{domain}"


def domains_url(field: str, value: str, limit: int) -> str:
    return f"{BASE}/domains/{field}/{quote(value, safe='-.')}?limit={limit}"


# --------------------------------------------------------------------------------------
# parsers (pure; untrusted data: never raise)
# --------------------------------------------------------------------------------------


def parse_web(doc: Any) -> dict[str, Any]:
    """/api/web (or the 'web' block of /api/full) -> {url, ip, date, rank, title, server, links}."""
    web = doc if isinstance(doc, Mapping) else {}
    ip = _text(web.get("ip"), 64)
    try:
        ip = str(ipaddress.ip_address(ip)) if ip else ""
    except ValueError:
        ip = ""
    links: list[str] = []
    raw_links = web.get("links")
    for item in raw_links if isinstance(raw_links, list) else []:
        host = _domain(item)
        if host and host not in links:
            links.append(host)
    date = _text(web.get("date"), 40)
    return {
        "url": _text(web.get("url"), 500) or None,
        "ip": ip or None,
        "date": date if re.match(r"^\d{4}-\d{2}-\d{2}", date) else None,
        "rank": _int(web.get("rank")),
        "title": _text(web.get("title"), 200) or None,
        "server": _text(web.get("server"), 80) or None,
        "links": links,
    }


def parse_related(doc: Any) -> dict[str, list[dict[str, Any]]]:
    """/api/related (or the 'related' block) -> {field: [{value, count}]} for every field present."""
    out: dict[str, list[dict[str, Any]]] = {}
    if not isinstance(doc, Mapping):
        return out
    for field, rows in doc.items():
        if not isinstance(field, str) or not re.fullmatch(r"[a-z]{2,20}", field) or not isinstance(rows, list):
            continue
        kept = []
        for row in rows[:50]:
            if not isinstance(row, Mapping):
                continue
            value = _text(row.get("value"), 120)
            if value:
                kept.append({"value": value, "count": _int(row.get("count"))})
        out[field] = kept
    return out


def parse_ipinfo(doc: Any) -> dict[str, dict[str, Any]]:
    """The 'ipinfo' block -> {ip: {country, region, city, asn, as_name, route}} (no coordinates or postal codes)."""
    out: dict[str, dict[str, Any]] = {}
    if not isinstance(doc, Mapping):
        return out
    for ip, info in list(doc.items())[:20]:
        try:
            addr = str(ipaddress.ip_address(_text(ip, 64)))
        except ValueError:
            continue
        if not isinstance(info, Mapping):
            continue
        asn = info.get("asn") if isinstance(info.get("asn"), Mapping) else {}
        entry = {
            "country": _text(info.get("country"), 2).upper() or None,
            "region": _text(info.get("region"), 80) or None,
            "city": _text(info.get("city"), 80) or None,
            "asn": _text(asn.get("asn"), 16).upper() or None,
            "as_name": _text(asn.get("name"), 120) or None,
            "route": _text(asn.get("route"), 64) or None,
        }
        out[addr] = {k: v for k, v in entry.items() if v}
    return out


def parse_domains(doc: Any) -> dict[str, Any] | None:
    """/api/domains/{field}/{value} -> {total, domains [...]} or None when the body is not that answer."""
    if not isinstance(doc, Mapping) or "error" in doc:
        return None
    raw = doc.get("domains")
    if not isinstance(raw, list):
        return None
    domains: list[str] = []
    for item in raw[:1000]:
        host = _domain(item)
        if host and host not in domains:
            domains.append(host)
    total = _int(doc.get("total"))
    return {"total": total if total is not None else len(domains), "domains": domains}


def reverse_decision(id_value: str, total: int, domains: list[str], subject: str | None, is_own: Any) -> dict[str, Any]:
    """P061 rules over one reverse id answer (cond 4). ``is_own(domain) -> bool`` is the org-profile check.

    * total > 50 -> ``shared``: an agency/platform id, no pivots.
    * the id is on own site(s) and on non-own site(s) -> ``clone``: the non-own sites (or the non-own
      subject) carry a copied tracking id - a clone indicator, never a same-owner link.
    * otherwise -> ``same_analytics`` ownership candidates (at most PROBABLE, capped)."""
    others = [d for d in domains if d != subject]
    if total > SHARED_THRESHOLD:
        return {"decision": "shared", "id": id_value, "total": total, "own": [], "clones": [], "candidates": []}
    own = [d for d in domains if is_own(d)]
    subject_own = bool(subject) and bool(is_own(subject))
    if own and subject and not subject_own:
        return {"decision": "clone", "id": id_value, "total": total, "own": own, "clones": [subject], "candidates": []}
    if (own or subject_own) and any(not is_own(d) for d in others):
        clones = [d for d in others if not is_own(d)]
        return {"decision": "clone", "id": id_value, "total": total, "own": own or [subject], "clones": clones, "candidates": []}
    return {"decision": "same_analytics", "id": id_value, "total": total, "own": own, "clones": [], "candidates": others[:PIVOT_CAP]}


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


@register
class HostIo(Module):
    name = "hostio"
    title = "host.io domain relations"
    description = (
        "host.io (keyed): homepage snapshot, related-domain counts and IP registration facts of a seed domain, the "
        "domains redirecting and linking to it, and reverse Google Analytics / AdSense / GTM lookups (P061 rules)."
    )
    category = "domain_dns"
    accepts = {T.DOMAIN, T.ANALYTICS_ID}
    produces = {T.DOMAIN, T.IPV4, T.ANALYTICS_ID}
    run_on = "seeds"
    tags = {"free"}
    reference = "https://host.io/docs"
    notice = (
        "host.io terms are 'key-terms': under the corporate profile it runs only with a company/team key whose plan "
        "permits internal business use (key_plans.hostio='business'). Shared tracking ids (> 50 domains) never link "
        "owners; every result is an ownership candidate, never scope."
    )
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "hostio"
    sources = (SOURCE,)
    hosts = (HOST,)
    access_model = "free_auth_limited"
    requires_keys = (KEY_NAME,)
    max_requests = 5  # cond 3
    expected_latency = 1.5
    timeout = 45.0
    min_interval = 1.0
    daily_quota = 25  # cond 3 interim budget: <= 80% of the free plan's 1,000 requests/month until a quota block exists
    cache_ttl = 604800  # cond 3: 7 days
    max_pivots = 60
    manual_link = "https://host.io/{domain}"
    default_enabled = True
    error_markers = (
        {"id": "hostio_quota", "statuses": [200, 400, 402, 403, 429], "json_path": "error",
         "regex": r"(?i)quota|request limit|limit (?:reached|exceeded)|exceeded (?:your |the )?(?:monthly |plan )?(?:request )?limit|upgrade (?:your )?plan|payment required",
         "maps_to": "quota", "reason_code": "quota", "reason": "host.io: plan request quota exhausted (could not verify)"},
        {"id": "hostio_rate_limited", "statuses": [200, 400, 403, 429], "json_path": "error",
         "regex": r"(?i)rate[- ]?limit|too many requests|slow down|throttl",
         "maps_to": "rate_limited", "reason_code": "rate_limited", "reason": "host.io: throttled (could not verify)"},
    )
    settings = {
        "hostio_limit": SettingSpec(5, "hostio: domains per /api/domains page (the free plan allows 5; paid plans 50-1000)", choices=list(LIMITS)),
    }

    # ---- HTTP ----------------------------------------------------------------------------
    def _get(self, ctx: Any, url: str, key: str) -> Mapping[str, Any]:
        resp = ctx.http.get(
            url,
            headers={"Authorization": f"Bearer {key}", "Accept": "application/json"},
            allow_redirects=False,  # keyed request: never follow a redirect with the token (AR01)
            source=SOURCE,
        )
        if resp.classification is not None:
            ctx.http.check(resp)  # P321 markers (quota, throttling) and challenge pages raise
        try:
            doc = resp.json()
        except ValueError:
            doc = None
        message = _text(doc.get("error"), 200) if isinstance(doc, Mapping) else ""
        if resp.status == 404 and (not message or NO_DATA_RE.search(message)):
            raise _Absent(message or "HTTP 404")
        if resp.status in (400, 401, 403) and (resp.status != 400 or TOKEN_RE.search(message or "token")):
            raise _NeedsKey(message or f"HTTP {resp.status}")
        ctx.http.check(resp)  # 429 RateLimited, other non-2xx HttpError
        if resp.truncated:
            raise _Unusable("host.io answer truncated at the size cap: not parsed (could not verify)")
        if not isinstance(doc, Mapping):
            raise _Unusable("host.io answer is not a JSON object: could not verify")
        if "error" in doc:
            if TOKEN_RE.search(message):
                raise _NeedsKey(message)
            raise _Unusable(f"host.io error inside an HTTP 200 answer ({message or 'unspecified'}): could not verify")
        return doc

    def _limit(self, ctx: Any) -> int:
        try:
            value = int(ctx.setting("hostio_limit", 5))
        except (TypeError, ValueError):
            value = 5
        return value if value in LIMITS else 5

    @staticmethod
    def _owner(ctx: Any) -> Any:
        org = getattr(ctx, "org", None)

        def is_own(domain: str) -> bool:
            if org is None or not domain:
                return False
            try:
                return bool(org.owns(Entity.make(T.DOMAIN, domain)).own)
            except Exception:  # noqa: BLE001 - an odd value is never 'own'
                return False

        return is_own

    # ---- run -----------------------------------------------------------------------------
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        key = ctx.key(KEY_NAME)
        if not key:
            return res.mark("needs_key", "needs the host.io API token (company/team account): v3lum keys setup", reason_code="needs_key")
        try:
            if entity.type is T.ANALYTICS_ID:
                self._run_id(entity, ctx, res, key)
            else:
                self._run_domain(entity, ctx, res, key)
        except _NeedsKey as exc:
            return res.mark("needs_key", f"host.io refused the API token ({_text(str(exc), 120)}): check the key", reason_code="needs_key")
        except _Absent:
            if res.attributes or res.findings or res.pivots:
                return res
            return res.mark("empty", "host.io has no data for this value (documented 404 'No details found')")
        except _Unusable as exc:
            return res.mark("error", _text(str(exc), 200))
        return res

    def _run_id(self, entity: Entity, ctx: Any, res: ModuleResult, key: str) -> None:
        field, value = id_field(entity.value), hostio_id(entity.value)
        if field is None or value is None:
            res.mark("skipped", "not a host.io-indexed tracking id (UA-/G-, pub-, GTM-)", reason_code="not_applicable")
            return
        answer = parse_domains(self._get(ctx, domains_url(field, value, self._limit(ctx)), key))
        if answer is None:
            raise _Unusable(f"unexpected host.io /api/domains/{field} answer (no domains list): could not verify")
        self._apply_reverse(entity, ctx, res, field, value, answer, subject=None)
        res.raw = {"field": field, "value": value, **answer}

    def _run_domain(self, entity: Entity, ctx: Any, res: ModuleResult, key: str) -> None:
        domain = entity.value
        doc = self._get(ctx, full_url(domain), key)
        web = parse_web(doc.get("web"))
        related = parse_related(doc.get("related"))
        ipinfo = parse_ipinfo(doc.get("ipinfo"))
        if not (web["url"] or web["ip"] or related or ipinfo or isinstance(doc.get("dns"), Mapping)):
            raise _Unusable("unexpected host.io /api/full answer (no web, dns, related or ipinfo block): could not verify")
        raw: dict[str, Any] = {"web": web, "related": related, "ipinfo": ipinfo}
        fetched = ctx.now().strftime("%Y-%m-%d")
        snapshot = {k: web[k] for k in ("url", "ip", "date", "rank", "title", "server") if web[k] is not None}
        if snapshot:
            res.attr("homepage_snapshot", {**snapshot, "links": len(web["links"]), "source": "host.io"})
        res.attr("title", web["title"])
        res.attr("server", web["server"])
        res.attr("related_domain_counts", related)
        res.attr("ip_registration_info", ipinfo)
        if web["ip"]:
            etype = T.IPV4 if ":" not in web["ip"] else T.IPV6
            res.pivot(etype, web["ip"], "resolves_to", confidence="possible", expand=False,
                      note=f"address host.io scraped the homepage from on {web['date'] or 'an unknown date'} (not necessarily current)")
        for host in web["links"][:PIVOT_CAP]:
            if host != domain and not host.endswith("." + domain):
                res.pivot(T.DOMAIN, host, "links_to", confidence="probable", expand=False, note="outbound link on the homepage (host.io)")
        redirects = self._own_redirect(domain, web, fetched)
        for rel in redirects:
            res.pivot(T.DOMAIN, rel["to"], "redirects_to", confidence="probable", expand=False,
                      note=f"homepage redirected there when host.io scraped it ({rel['observed_at']})")
        # tracking ids on the homepage (related block): shared ids never link owners (P061)
        ids: list[tuple[str, str, int | None]] = []
        for field in ID_FIELDS:
            for row in related.get(field) or []:
                value = hostio_id(row["value"])
                if value:
                    ids.append((field, value, row["count"]))
        res.attr("analytics_ids", sorted({value for _f, value, _c in ids}))
        shared = sorted({value for _f, value, count in ids if count is not None and count > SHARED_THRESHOLD})
        res.attr("shared_tracking_ids", shared)
        for field, value, count in ids:
            # cond 4: every same_analytics edge stays at most PROBABLE (host.io crawl data, possibly stale)
            res.pivot(T.ANALYTICS_ID, value, "same_analytics", confidence="probable", expand=count is not None and count <= SHARED_THRESHOLD,
                      note=f"{field} id on the homepage; host.io counts {count if count is not None else '?'} domain(s) with it")
        if shared:
            res.finding(
                "Shared tracking id (agency or platform)",
                "info",
                f"{', '.join(shared)} appear on more than {SHARED_THRESHOLD} domains each (host.io related counts): an agency, CMS "
                "or platform id - never a same-owner link (P061).",
                confidence="probable",
                tags=["shared_tracking_id"],
                data={"ids": shared},
                source=SOURCE,
            )
        budget = int(self.max_requests) - 1
        limit = self._limit(ctx)
        for field, label, relation in (("redirects", "redirect to", "redirected_from"), ("backlinks", "link to", "linked_from")):
            count = sum((row["count"] or 0) for row in related.get(field) or [] if _domain(row["value"]) == domain)
            if count <= 0 or budget <= 0:
                continue
            budget -= 1
            try:
                answer = parse_domains(self._get(ctx, domains_url(field, domain, limit), key))
            except _Absent:
                continue
            if answer is None:
                continue
            raw[field] = answer
            others = [d for d in answer["domains"] if d != domain]
            for host in others[:PIVOT_CAP]:
                res.pivot(T.DOMAIN, host, relation, confidence="probable", expand=False,
                          note=f"homepage {label}s {domain} (host.io, read {fetched}): ownership candidate, never scope")
            if field == "redirects":
                redirects += [{"from": host, "to": domain, "observed_at": fetched, "date_source": "fetch"} for host in others[:PIVOT_CAP]]
        res.attr("redirect_relations", redirects)
        reverse = [(f, v, c) for f, v, c in ids if c is not None and 2 <= c <= SHARED_THRESHOLD]
        reverse.sort(key=lambda t: (ID_FIELDS.index(t[0]), t[2] or 0, t[1]))
        for field, value, _count in reverse[: min(MAX_REVERSE, budget)]:
            try:
                answer = parse_domains(self._get(ctx, domains_url(field, value, limit), key))
            except _Absent:
                continue
            if answer is None:
                continue
            raw.setdefault("reverse", {})[value] = answer
            self._apply_reverse(entity, ctx, res, field, value, answer, subject=domain)
        res.raw = raw

    @staticmethod
    def _own_redirect(domain: str, web: Mapping[str, Any], fetched: str) -> list[dict[str, Any]]:
        final = _domain(web.get("url"))
        if not final or final == domain or final.endswith("." + domain) or domain.endswith("." + final):
            return []
        return [{"from": domain, "to": final, "observed_at": (web.get("date") or "")[:10] or fetched,
                 "date_source": "hostio_web_date" if web.get("date") else "fetch"}]

    def _apply_reverse(self, entity: Entity, ctx: Any, res: ModuleResult, field: str, value: str, answer: Mapping[str, Any], *, subject: str | None) -> None:
        decision = reverse_decision(value, int(answer["total"]), list(answer["domains"]), subject, self._owner(ctx))
        shown = ", ".join(answer["domains"][:5]) + (" ..." if len(answer["domains"]) > 5 else "")
        if decision["decision"] == "shared":
            res.attr("shared_tracking_ids", sorted({*(res.attributes.get("shared_tracking_ids") or []), value}))
            res.finding(
                "Shared tracking id (agency or platform)",
                "info",
                f"{value} is on {decision['total']} domains (more than {SHARED_THRESHOLD}): an agency, CMS or platform id - "
                "never a same-owner link (P061).",
                confidence="probable",
                tags=["shared_tracking_id"],
                data={"id": value, "field": field, "total": decision["total"]},
                source=SOURCE,
                key=value,
            )
            return
        if decision["decision"] == "clone":
            own = ", ".join(decision["own"][:3])
            for clone in decision["clones"][:PIVOT_CAP]:
                ent = Entity.try_make(T.DOMAIN, clone)
                if ent is None:
                    continue
                finding = res.finding(
                    "Organisation tracking id on a non-own site (possible clone)",
                    "medium",
                    f"{clone} carries the {field} id {value} that the organisation's site(s) {own} use, on {decision['total']} "
                    "domain(s) in total: a copied tracking id is a clone/phishing indicator, never a same-owner link (P061).",
                    confidence="possible",
                    criterion=f"P061: tracking id {value} shared by org_profile site(s) {own} and the non-own site {clone} "
                              f"(<= {SHARED_THRESHOLD} domains: not an agency id)",
                    tags=["brand_abuse"],
                    data={"id": value, "field": field, "own_sites": decision["own"][:5], "total": decision["total"]},
                    source=SOURCE,
                    key=f"{value}:{clone}",
                )
                if clone != entity.value:
                    finding.entity = ent
                    finding.ensure_id()
                    res.pivot(T.DOMAIN, clone, "copied_tracking_id", confidence="possible", expand=False,
                              note=f"non-own site carrying the organisation {field} id {value} (clone indicator)")
            return
        candidates = decision["candidates"]
        if not candidates:
            return
        for host in candidates:
            res.pivot(T.DOMAIN, host, "same_analytics", confidence="probable", expand=False,
                      note=f"also carries {value} ({field}; {decision['total']} domain(s) in total): ownership candidate, never scope")
        res.finding(
            "Domains sharing a tracking id (ownership candidates)",
            "info",
            f"{value} ({field}) is on {decision['total']} domain(s): {shown}. Same-owner candidates for the analyst, at most "
            "PROBABLE and never scope (P061).",
            confidence="probable",
            data={"id": value, "field": field, "total": decision["total"], "domains": candidates},
            source=SOURCE,
            key=value,
        )
