"""urlscan.io Search API - existing public scans only, never a submission (P066, batch p1-G03-1).

Final conditions implemented (P066):

* c1 - search only: this file builds ``/api/v1/search/`` and (with a key) ``/api/v1/result/{uuid}/``
  URLs and nothing else; there is no scan-submission code path (a test asserts the submission
  endpoint is never requested). The search source does not publish, so it is not flagged
  ``publishes_queries``.
* c2 - terms ``noncommercial`` (urlscan's free service is for personal use only): off under the
  corporate profile until licence-cleared (a company key under urlscan's commercial terms, or
  urlscan's written approval recorded in licence_allow).
* c3 - ``API-Key`` header when key ``urlscan`` is configured; ``X-Rate-Limit-Remaining: 0`` stops
  paging (partial, stop reason ``rate_limited``) and a 429 is RATE_LIMITED; ``size`` <= 100 and at most
  2 ``search_after`` pages; result details only with a key (a 403 'not logged in' stops the details
  and is reported, the search results stay).
* c4 - two labelled queries per domain: ``site`` (``page.domain:d``) and ``third_party``
  (``domain:d AND NOT page.domain:d``: pages elsewhere that loaded the domain's resources - brand-abuse
  candidates for org-profile domains); ``hash:`` searches pivot with ``expand=False`` and skip common
  library/CDN resources (a hash seen on >= 1000 pages is a shared library).
* c5 - e-mails, recipient identifiers and token-like values in result URLs are redacted (url_unwrap's
  ``redact_url_values`` plus the core key redactor ``redact_url``) before attributes, ``res.raw`` and
  evidence; submitter tags of the form ``@user`` are dropped.
* c6 - every hit carries its scan date; hits older than 30 days are historical; a urlscan verdict is
  one vote (``source='urlscan.search'``).
* c7 - screenshots are only ever urlscan-hosted URLs (``https://urlscan.io/screenshots/...``); nothing
  is fetched from the scanned target.
* c8 - report links ``urlscan.io/domain/{domain}`` and ``urlscan.io/ip/{ip}`` (also the
  ``urlscan_search`` pivot pack).
"""

from __future__ import annotations

import ipaddress
import json
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import AuthRequired, Blocked, HttpError, RateLimited
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.core.noise import is_cdn, is_public_ip
from v3lum.core.redact import redact_url
from v3lum.modules.url_web.url_unwrap import is_wrapper_host, match_wrapper, redact_url_values

SOURCE = "urlscan.search"
SEARCH = "https://urlscan.io/api/v1/search/"
RESULT = "https://urlscan.io/api/v1/result/{uuid}/"
MAX_SIZE = 100
MAX_AFTER_PAGES = 2
HISTORICAL_DAYS = 30
COMMON_RESOURCE_TOTAL = 1000
UTC = timezone.utc
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_DOMAIN_Q = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")

COMMON_LIBRARY_HOSTS = frozenset({
    "cdnjs.cloudflare.com", "ajax.googleapis.com", "code.jquery.com", "cdn.jsdelivr.net", "unpkg.com", "fonts.googleapis.com",
    "fonts.gstatic.com", "stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com", "cdn.bootcdn.net", "www.google-analytics.com",
    "www.googletagmanager.com", "connect.facebook.net", "static.cloudflareinsights.com", "use.fontawesome.com", "kit.fontawesome.com",
    "www.gstatic.com", "www.google.com", "challenges.cloudflare.com", "cdn.shopify.com", "s.w.org",
})
_LIB_FILE = re.compile(
    r"(?i)(?:^|/)(?:jquery(?:[.-]ui)?|bootstrap|popper|font-?awesome|lodash|underscore|moment|vue|react(?:-dom)?|angular|axios|modernizr|"
    r"swiper|slick|select2|gtag|analytics|recaptcha__[a-z_-]+|wp-emoji-release)[\w.-]*\.(?:min\.)?(?:js|css)(?:$|\?)"
)


# =============================================================================================
# pure helpers (ported from the batch prep parsers)
# =============================================================================================


def _parse_time(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    try:
        dt = datetime.fromisoformat(s[:-1] + "+00:00" if s.endswith("Z") else s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _iso(dt: datetime | None) -> str | None:
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z") if dt else None


def _int(value: Any) -> int | None:
    try:
        return int(value) if not isinstance(value, bool) else None
    except (TypeError, ValueError):
        return None


def _asn(value: Any) -> int | None:
    m = re.fullmatch(r"(?i)\s*(?:AS)?(\d{1,10})\s*", str(value)) if value is not None else None
    return int(m.group(1)) if m else None


def _host(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    h = value.strip().strip("[]").rstrip(".").lower()
    try:
        return ipaddress.ip_address(h).compressed
    except ValueError:
        pass
    try:
        h = h.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return h if _DOMAIN_Q.match(h) else None


def _is_ip(value: Any) -> bool:
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


def phrase(value: str) -> str:
    """A quoted phrase for urlscan's Elasticsearch query_string syntax."""
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_queries(etype: T, value: str) -> list[tuple[str, str]]:
    """c4: labelled search queries; invalid values give [] (never sent)."""
    if etype is T.DOMAIN:
        d = _host(value)
        if not d or _is_ip(d):
            return []
        return [("site", f"page.domain:{d}"), ("third_party", f"domain:{d} AND NOT page.domain:{d}")]
    if etype in (T.IPV4, T.IPV6):
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return []
        return [("page_ip", f"page.ip:{phrase(ip.compressed)}" if ip.version == 6 else f"page.ip:{ip}")]
    if etype is T.ASN:
        n = _asn(value)
        return [("page_asn", f"page.asn:AS{n}")] if n is not None else []
    if etype is T.URL:
        return [("page_url", f"page.url:{phrase(value)}")] if re.match(r"(?i)^https?://", value or "") else []
    if etype is T.SHA256:
        return [("hash", f"hash:{value.lower()}")] if re.fullmatch(r"[0-9a-fA-F]{64}", value or "") else []
    return []


def build_search_url(query: str, size: int = MAX_SIZE, search_after: str | None = None) -> str:
    """c3: the GET search URL (size capped at 100)."""
    params = {"q": query, "size": str(max(1, min(int(size), MAX_SIZE)))}
    if search_after:
        params["search_after"] = search_after
    return SEARCH + "?" + urllib.parse.urlencode(params, quote_via=urllib.parse.quote)


def rate_headers(headers: Any) -> dict[str, Any]:
    """c3: X-Rate-Limit-* headers (missing -> None)."""
    h = {str(k).lower(): str(v) for k, v in dict(headers or {}).items()}

    def num(name: str) -> int | None:
        try:
            return int(float(h[name])) if name in h else None
        except ValueError:
            return None

    return {"scope": h.get("x-rate-limit-scope"), "action": h.get("x-rate-limit-action"), "window": h.get("x-rate-limit-window"),
            "limit": num("x-rate-limit-limit"), "remaining": num("x-rate-limit-remaining"), "reset": h.get("x-rate-limit-reset"),
            "reset_after_s": num("x-rate-limit-reset-after")}


def _safe_url(value: Any) -> tuple[str | None, list[str]]:
    """c5: e-mails, recipient and token-like values redacted, then API keys (core redactor)."""
    if not isinstance(value, str) or not value:
        return None, []
    red, kinds = redact_url_values(value)
    return redact_url(red), kinds


def parse_hit(r: Any, now: datetime, label: str) -> dict[str, Any] | None:
    """One search result -> a storage-safe, dated hit (c5-c7)."""
    if not isinstance(r, dict):
        return None
    task = r.get("task") if isinstance(r.get("task"), dict) else {}
    page = r.get("page") if isinstance(r.get("page"), dict) else {}
    stats = r.get("stats") if isinstance(r.get("stats"), dict) else {}
    uid = r.get("_id") or task.get("uuid")
    uid = uid if isinstance(uid, str) and _UUID_RE.match(uid) else None
    task_url, k1 = _safe_url(task.get("url"))
    page_url, k2 = _safe_url(page.get("url"))
    scanned = _parse_time(task.get("time"))
    age = round((now - scanned).total_seconds() / 86400, 2) if scanned else None
    shot = r.get("screenshot")
    if not (isinstance(shot, str) and shot.startswith("https://urlscan.io/screenshots/")):
        shot = None
    tags = [t for t in (task.get("tags") or []) if isinstance(t, str) and not t.startswith("@")][:10] if isinstance(task.get("tags"), list) else []
    verdicts = r.get("verdicts") if isinstance(r.get("verdicts"), dict) else {}
    overall = verdicts.get("overall") if isinstance(verdicts.get("overall"), dict) else {}
    page_ip = page.get("ip") if _is_ip(page.get("ip") or "") else None
    title = page.get("title")
    hit = {
        "uuid": uid, "label": label, "scanned_at": _iso(scanned), "age_days": age, "historical": age is None or age > HISTORICAL_DAYS,
        "visibility": task.get("visibility") if isinstance(task.get("visibility"), str) else None,
        "method": task.get("method") if isinstance(task.get("method"), str) else None, "tags": tags,
        "task_url": task_url, "task_domain": _host(task.get("domain")), "page_url": page_url, "page_domain": _host(page.get("domain")),
        "page_ip": ipaddress.ip_address(page_ip).compressed if page_ip else None, "asn": _asn(page.get("asn")),
        "asn_name": str(page.get("asnname"))[:120] if page.get("asnname") else None,
        "country": str(page.get("country"))[:2] if isinstance(page.get("country"), str) else None,
        "server": str(page.get("server"))[:80] if page.get("server") else None, "title": str(title)[:200] if title else None,
        "status": _int(page.get("status")), "tls_issuer": str(page.get("tlsIssuer"))[:120] if page.get("tlsIssuer") else None,
        "tls_age_days": _int(page.get("tlsAgeDays")), "domain_age_days": _int(page.get("domainAgeDays")),
        "requests": _int(stats.get("requests")), "verdict_malicious": overall.get("malicious") if isinstance(overall.get("malicious"), bool) else None,
        "verdict_score": _int(overall.get("score")), "screenshot_url": shot,
        "report_url": f"https://urlscan.io/result/{uid}/" if uid else None,
        "sort": r.get("sort") if isinstance(r.get("sort"), list) else None, "redactions": sorted(set(k1 + k2)),
    }
    hit["redirects_off_domain"] = bool(hit["task_domain"] and hit["page_domain"] and hit["task_domain"] != hit["page_domain"])
    return hit


def parse_search(data: Any, now: datetime, label: str) -> dict[str, Any]:
    """A search body -> ``{ok, error, total, capped, has_more, hits[]}``. ``has_more`` is informative
    only: paging follows full pages (it was False with total 1908 > size on 2026-11-26)."""
    out: dict[str, Any] = {"ok": False, "error": None, "total": None, "capped": False, "has_more": None, "hits": [], "limit_days": None}
    if not isinstance(data, dict):
        out["error"] = f"unexpected JSON {type(data).__name__}"
        return out
    if not isinstance(data.get("results"), list):
        out["error"] = str(data.get("message") or data.get("description") or data.get("warning") or "no results list")[:200]
        return out
    out.update(ok=True, total=_int(data.get("total")), has_more=data.get("has_more"), limit_days=_int(data.get("search_date_limit_days")))
    out["capped"] = bool(out["total"] is not None and out["total"] >= 10000)
    out["hits"] = [h for h in (parse_hit(r, now, label) for r in data["results"]) if h]
    return out


def next_search_after(parsed: dict[str, Any], size: int, after_pages_done: int) -> str | None:
    """c3: the last hit's ``sort`` joined by ',' when the page was full and fewer than 2 follow-up pages
    were fetched; else None."""
    hits = parsed.get("hits") or []
    if not hits or after_pages_done >= MAX_AFTER_PAGES or len(hits) < int(size):
        return None
    srt = hits[-1].get("sort")
    if not srt or not all(isinstance(x, (int, str)) and not isinstance(x, bool) for x in srt):
        return None
    return ",".join(str(x) for x in srt)


def is_common_library_resource(url: Any) -> bool:
    """c4: common library/CDN files (their hashes are noise)."""
    try:
        parts = urllib.parse.urlsplit(str(url))
    except ValueError:
        return False
    return (parts.hostname or "").lower() in COMMON_LIBRARY_HOSTS or bool(_LIB_FILE.search(parts.path or ""))


def parse_result(data: Any) -> dict[str, Any]:
    """A result-detail body (key only) -> ``{verdict, resource_hashes[{sha256, url}]}`` (URLs redacted)."""
    out: dict[str, Any] = {"verdict": None, "resource_hashes": []}
    if not isinstance(data, dict):
        return out
    verdicts = data.get("verdicts") if isinstance(data.get("verdicts"), dict) else {}
    overall = verdicts.get("overall") if isinstance(verdicts.get("overall"), dict) else {}
    if isinstance(overall.get("malicious"), bool):
        cats = overall.get("categories") if isinstance(overall.get("categories"), list) else []
        brands = overall.get("brands") if isinstance(overall.get("brands"), list) else []
        out["verdict"] = {"malicious": overall["malicious"], "score": _int(overall.get("score")),
                          "categories": [str(c)[:40] for c in cats[:5]], "brands": [str(b)[:60] for b in brands[:5] if isinstance(b, (str, int))]}
    reqs = (data.get("data") or {}).get("requests") if isinstance(data.get("data"), dict) else None
    seen: set[str] = set()
    for item in reqs if isinstance(reqs, list) else []:
        if not isinstance(item, dict):
            continue
        response = item.get("response") if isinstance(item.get("response"), dict) else {}
        sha = response.get("hash")
        inner = response.get("response") if isinstance(response.get("response"), dict) else {}
        req = (item.get("request") or {}).get("request") if isinstance(item.get("request"), dict) else None
        url = inner.get("url") or (req.get("url") if isinstance(req, dict) else None)
        if not (isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha)) or sha in seen or not isinstance(url, str):
            continue
        if is_common_library_resource(url):
            continue
        seen.add(sha)
        out["resource_hashes"].append({"sha256": sha, "url": _safe_url(url)[0]})
    return out


# =============================================================================================
# the module
# =============================================================================================
_PUBLIC_FIELDS = ("uuid", "label", "scanned_at", "historical", "task_url", "page_url", "page_domain", "page_ip", "asn", "country", "server",
                  "title", "status", "tls_issuer", "tags", "verdict_malicious", "screenshot_url", "report_url", "redactions")


def _summary(hit: dict[str, Any]) -> dict[str, Any]:
    return {k: hit[k] for k in _PUBLIC_FIELDS if hit.get(k) not in (None, [], "")}


@register
class UrlscanSearch(Module):
    name = "urlscan_search"
    title = "urlscan.io search (existing public scans)"
    description = (
        "Searches existing public urlscan.io scans of a domain, IP, URL, ASN or resource hash (never submits a scan): dated hits, "
        "redirects, hosting, third-party pages loading the domain's resources (brand abuse) and urlscan verdicts as one vote."
    )
    category = "url_web"
    accepts = {T.DOMAIN, T.IPV4, T.IPV6, T.URL, T.ASN, T.SHA256}
    produces = {T.URL, T.DOMAIN, T.IPV4, T.IPV6, T.SHA256}
    terms = "noncommercial"  # free use is personal only (P066 cond 2): off under corporate until licence-cleared
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # urlscan.io receives the searched value (search only: nothing is published)
    provider = "urlscan"
    sources = (SOURCE,)
    hosts = ("urlscan.io",)
    access_model = "free_noauth_limited"
    optional_keys = ("urlscan",)
    max_requests = 8  # domain: 2 labelled queries x (1 + 2 search_after pages) + 2 result details (key only)
    expected_latency = 2.0
    cache_ttl = 3600
    min_interval = 2.0
    daily_quota = 1000
    timeout = 60.0
    max_pivots = 60
    default_enabled = True
    tags = {"reputation"}
    manual_link = "https://urlscan.io/search/#{q}"
    reference = "https://urlscan.io/docs/api/"
    notice = (
        "urlscan.io terms: the free service is for personal use only - off under the corporate profile until licence-cleared (a company "
        "key under urlscan's commercial terms or its written approval in licence_allow). Search only: V3LUM never submits scans."
    )
    error_markers = (
        {"id": "urlscan_search_error_body", "statuses": [200], "json_path": "status", "regex": "^[45][0-9][0-9]$", "maps_to": "error",
         "reason": "urlscan.io: error object inside HTTP 200 (could not verify)"},
    )
    settings = {"urlscan_search_size": 100, "urlscan_search_result_details": 2}

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type in (T.IPV4, T.IPV6):
            return is_public_ip(entity.value)
        if entity.type is T.DOMAIN:
            return not is_wrapper_host(entity.value)
        if entity.type is T.URL:
            return match_wrapper(entity.value) is None  # url_unwrap decodes wrappers offline; the wrapper itself is noise
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        now = ctx.now() if callable(getattr(ctx, "now", None)) else datetime.now(UTC)
        queries, note = self._queries(entity)
        if not queries:
            return res.mark("skipped", "no searchable value", reason_code="not_applicable")
        key = ctx.key("urlscan") or ""
        headers = {"API-Key": key} if key else None
        size = max(1, min(int(ctx.setting("urlscan_search_size", MAX_SIZE) or MAX_SIZE), MAX_SIZE))
        hits: list[dict[str, Any]] = []
        totals: dict[str, dict[str, Any]] = {}
        rate: dict[str, Any] = {}
        for label, query in queries:
            after: str | None = None
            pages = 0
            while True:
                resp = ctx.http.get(build_search_url(query, size, after), headers=headers, source=SOURCE)
                ctx.http.check(resp)  # 403/429/5xx/challenge/error-in-200 raise: could not verify (rule 5)
                try:
                    data = json.loads(resp.text)
                except ValueError:
                    return res.mark("error", "urlscan.io answered with malformed JSON: could not verify")
                parsed = parse_search(data, now, label)
                if not parsed["ok"]:
                    return res.mark("error", f"unexpected urlscan.io answer ({parsed['error']}): could not verify")
                hits.extend(parsed["hits"])
                slot = totals.setdefault(label, {"total": parsed["total"], "capped": parsed["capped"], "fetched": 0, "limit_days": parsed["limit_days"]})
                slot["fetched"] += len(parsed["hits"])
                current = rate_headers(resp.headers)
                if any(v is not None for v in current.values()):
                    rate = current  # the newest answer that carried X-Rate-Limit-* headers
                nxt = next_search_after(parsed, size, pages)
                if not nxt:
                    break
                if current.get("remaining") == 0:
                    res.stop("rate_limited")  # c3: honour X-Rate-Limit-Remaining
                    break
                after, pages = nxt, pages + 1
        details = self._details(res, ctx, hits, headers, key) if key else {}
        return self._report(res, entity, ctx, hits, totals, details, note, rate)

    # ------------------------------------------------------------------ queries
    @staticmethod
    def _queries(entity: Entity) -> tuple[list[tuple[str, str]], str]:
        if entity.type is T.URL:
            red, kinds = redact_url_values(entity.value)
            if kinds:  # c5/A7: a URL carrying recipient identifiers is never sent as such: search its host only
                host = urllib.parse.urlsplit(entity.value).hostname or ""
                return build_queries(T.DOMAIN, host)[:1], "the URL carries recipient identifiers: searched by host (page.domain) only"
        return build_queries(entity.type, entity.value), ""

    # ------------------------------------------------------------------ result details (key only)
    def _details(self, res: ModuleResult, ctx: Any, hits: list[dict[str, Any]], headers: dict[str, str] | None, key: str) -> dict[str, Any]:
        wanted = int(ctx.setting("urlscan_search_result_details", 2) or 0)
        out: dict[str, Any] = {"fetched": 0, "verdicts": {}, "resource_hashes": [], "problem": ""}
        if wanted <= 0 or not key:
            return out
        targets = [h for h in hits if h["uuid"] and not h["historical"] and h["label"] in ("site", "page_url")][:wanted]
        for hit in targets:
            try:
                resp = ctx.http.get(RESULT.format(uuid=hit["uuid"]), headers=headers, source=SOURCE)
                ctx.http.check(resp)
                data = json.loads(resp.text)
            except AuthRequired:
                out["problem"] = "result details refused (HTTP 401/403 'not logged in'): check the urlscan key"
                break
            except RateLimited:
                out["problem"] = "result details rate limited: stopped"
                res.stop("rate_limited")
                break
            except (Blocked, HttpError, ValueError) as exc:
                out["problem"] = f"result details could not be read: {str(exc)[:120]}"
                continue
            parsed = parse_result(data)
            out["fetched"] += 1
            if parsed["verdict"] is not None:
                out["verdicts"][hit["uuid"]] = parsed["verdict"]
                hit["verdict_malicious"] = parsed["verdict"]["malicious"]
            for item in parsed["resource_hashes"]:
                if item["sha256"] not in {x["sha256"] for x in out["resource_hashes"]}:
                    out["resource_hashes"].append(item)
        return out

    # ------------------------------------------------------------------ report
    def _report(self, res: ModuleResult, entity: Entity, ctx: Any, hits: list[dict[str, Any]], totals: dict[str, dict[str, Any]],
                details: dict[str, Any], note: str, rate: dict[str, Any]) -> ModuleResult:
        value = entity.value
        if entity.type is T.DOMAIN:
            res.link("urlscan.io domain page", f"https://urlscan.io/domain/{value}")
        elif entity.type in (T.IPV4, T.IPV6):
            res.link("urlscan.io IP page", f"https://urlscan.io/ip/{value}")
        res.raw = {"labels": list(totals), "totals": totals, "note": note,
                   "hits": [_summary(h) for h in hits[:100]], "details": {k: v for k, v in details.items() if v}, "rate": rate}
        if not hits:
            return res.mark("empty")
        hits.sort(key=lambda h: h["scanned_at"] or "", reverse=True)
        res.attr("urlscan_scans", [_summary(h) for h in hits[:30]])
        res.attr("urlscan_totals", totals)
        dated = [h["scanned_at"] for h in hits if h["scanned_at"]]
        if dated and entity.type is T.DOMAIN:
            res.attr("first_seen", min(dated))
            res.attr("last_seen", max(dated))
        self._pivots(res, entity, hits, totals, details)
        for label in totals:
            lhits = [h for h in hits if h["label"] == label]
            if not lhits:
                continue
            total = totals[label]["total"]
            current = [h for h in lhits if not h["historical"]]
            desc = (f"{len(lhits)} scan(s) shown of {total if total is not None else '?'}{'+' if totals[label]['capped'] else ''} "
                    f"for {self._label_text(label)}; newest {lhits[0]['scanned_at'] or '?'}; {len(lhits) - len(current)} older than "
                    f"{HISTORICAL_DAYS} days (historical, not current state). Existing public scans only (nothing was submitted).")
            if note:
                desc += f" Note: {note}."
            res.finding(
                "Public urlscan.io scans found", "info", desc,
                data={"label": label, "total": total, "capped": totals[label]["capped"], "hits": [_summary(h) for h in lhits[:20]]},
                tags=["info"], source=SOURCE, observed_first=min((h["scanned_at"] for h in lhits if h["scanned_at"]), default=None),
                observed_last=lhits[0]["scanned_at"], key=label,
            )
        self._brand_abuse(res, entity, ctx, hits)
        self._verdicts(res, hits)
        return res

    @staticmethod
    def _label_text(label: str) -> str:
        return {"site": "pages of the domain itself (page.domain)", "third_party": "third-party pages that loaded the domain's resources",
                "page_ip": "pages served from the IP", "page_asn": "pages served from the AS", "page_url": "scans of this exact URL",
                "hash": "pages that loaded a resource with this SHA-256"}.get(label, label)

    def _pivots(self, res: ModuleResult, entity: Entity, hits: list[dict[str, Any]], totals: dict[str, dict[str, Any]], details: dict[str, Any]) -> None:
        etype, value = entity.type, entity.value
        cdn_ip = etype in (T.IPV4, T.IPV6) and is_cdn(entity)
        common_hash = etype is T.SHA256 and any((t.get("total") or 0) >= COMMON_RESOURCE_TOTAL for t in totals.values())
        for h in hits[:100]:
            conf = "possible" if h["historical"] else "probable"
            dom = h["page_domain"]
            usable_dom = dom and not is_wrapper_host(dom) and dom != value
            if h["label"] in ("site", "page_url"):
                ours = etype is not T.DOMAIN or _within(h["task_domain"], value)
                if h["page_ip"]:
                    res.pivot(T.IPV4 if ":" not in h["page_ip"] else T.IPV6, h["page_ip"], "resolves_to", confidence=conf,
                              note=f"served the page when urlscan scanned it ({h['scanned_at']})")
                if h["redirects_off_domain"] and usable_dom and ours:
                    res.pivot(T.DOMAIN, dom, "redirects_to", confidence=conf, note=f"urlscan scan {h['scanned_at']}: off-domain redirect")
                elif h["redirects_off_domain"] and not ours and h["task_domain"] and not is_wrapper_host(h["task_domain"]):
                    res.pivot(T.DOMAIN, h["task_domain"], "related", confidence="possible", expand=False,
                              note=f"redirected to {value} when urlscan scanned it ({h['scanned_at']})")
                if h["label"] == "site" and ours and h["task_url"] and "REDACTED" not in h["task_url"]:
                    res.pivot(T.URL, h["task_url"], "archived_url", confidence=conf, expand=False, note=f"URL scanned on {h['scanned_at']}")
            elif h["label"] == "third_party" and usable_dom:
                res.pivot(T.DOMAIN, dom, "loaded_by", confidence="possible", expand=False,
                          note=f"page loaded resources from {value} (urlscan scan {h['scanned_at']}): review (brand abuse candidate or legitimate partner)")
            elif h["label"] == "page_ip" and usable_dom:
                res.pivot(T.DOMAIN, dom, "hosted_domain", confidence=conf, expand=not cdn_ip and not h["historical"],
                          note=f"served from the IP when urlscan scanned it ({h['scanned_at']})" + ("; shared CDN/cloud edge: not expanded" if cdn_ip else ""))
            elif h["label"] == "page_asn" and usable_dom:
                res.pivot(T.DOMAIN, dom, "related", confidence="possible", expand=False, note=f"served from the AS (urlscan scan {h['scanned_at']})")
            elif h["label"] == "hash" and usable_dom and not common_hash:
                res.pivot(T.DOMAIN, dom, "related", confidence="possible", expand=False,
                          note=f"page loaded a resource with this SHA-256 (urlscan scan {h['scanned_at']})")
        for item in (details.get("resource_hashes") or [])[:15]:
            res.pivot(T.SHA256, item["sha256"], "loads_resource", confidence="probable", expand=False,
                      note=f"resource loaded by the page (urlscan result): {item['url']}")
        if common_hash:
            res.finding("Resource hash seen on many pages (common library)", "info",
                        f"urlscan reports {max(t.get('total') or 0 for t in totals.values())}+ pages loading this resource: a shared library or CDN "
                        "file, so its pages are not pivoted (P066 cond 4).", tags=["info", "noise"])

    @staticmethod
    def _brand_abuse(res: ModuleResult, entity: Entity, ctx: Any, hits: list[dict[str, Any]]) -> None:
        if entity.type is not T.DOMAIN:
            return
        third = [h for h in hits if h["label"] == "third_party" and not h["historical"] and h["page_domain"] and h["page_domain"] != entity.value]
        if not third:
            return
        org = getattr(ctx, "org", None)
        try:
            own = bool(org is not None and not org.is_empty and org.owns(entity).own)
        except Exception:  # noqa: BLE001 - a broken org profile never breaks the module
            own = False
        if not own:
            return
        domains = sorted({h["page_domain"] for h in third})
        res.finding(
            "Third-party pages loaded resources from an organisation domain (brand-abuse candidates)",
            "low",
            f"{len(domains)} domain(s) outside the organisation loaded resources from {entity.value} in public urlscan scans of the last "
            f"{HISTORICAL_DAYS} days: {', '.join(domains[:10])}. Review them (phishing kits hotlink logos/CSS; partners and aggregators do too).",
            confidence="possible",
            criterion="urlscan query 'domain:<org domain> AND NOT page.domain:<org domain>' on an org-profile domain (P066 cond 4): resource reuse only",
            data={"domains": domains[:50], "hits": [_summary(h) for h in third[:20]]},
            tags=["brand_abuse"],
            source=SOURCE,
            observed_last=max((h["scanned_at"] for h in third if h["scanned_at"]), default=None),
        )

    @staticmethod
    def _verdicts(res: ModuleResult, hits: list[dict[str, Any]]) -> None:
        bad = [h for h in hits if h.get("verdict_malicious") is True and h["label"] in ("site", "page_url", "page_ip")]
        if not bad:
            return
        current = [h for h in bad if not h["historical"]]
        res.finding(
            "urlscan.io verdict: malicious",
            "medium" if current else "low",
            f"urlscan.io classified {len(bad)} scan(s) as malicious (newest {bad[0]['scanned_at']}). One vote in the consensus; "
            + ("" if current else "historical only (older than 30 days)."),
            confidence="possible",
            criterion="urlscan.io overall verdict 'malicious' on a public scan (one vote, P066 cond 6)" + ("" if current else "; historical"),
            data={"scans": [_summary(h) for h in bad[:10]]},
            tags=["malicious"] + ([] if current else ["historical"]),
            source=SOURCE,
            observed_last=bad[0]["scanned_at"],
        )


def _within(host: str | None, domain: str) -> bool:
    return bool(host) and (host == domain or str(host).endswith("." + domain))
