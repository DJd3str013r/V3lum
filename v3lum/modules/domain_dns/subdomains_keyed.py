"""Keyed subdomain sources (P007): ProjectDiscovery Chaos, DNSDumpster, FullHunt and BeVigil
(``subdomains_keyed``, default candidate) and BufferOver and jsmon (``subdomains_keyed_minor``, opt-in).

Final conditions (council #1, P007) and where they live:

1. One adapter per provider (:data:`ADAPTERS`, :data:`MINOR_ADAPTERS`), each with its own key, registry
   source and terms label (provider fragments under v3lum/data/providers/), its own pacing (provider
   ``http_profile.min_interval``), its own P334 budget (provider ``quota`` block, enforced by the core per
   provider) and its own status (``res.source_statuses``). ``subdomains_keyed``: Chaos (trusted),
   DNSDumpster, FullHunt and BeVigil (community) - the module keeps the community tier.
   ``subdomains_keyed_minor`` (default_enabled=False): BufferOver and jsmon, unknown tier (the policy
   gate excludes them at TLP:AMBER and above and asks --allow-unknown at CLEAR/GREEN).
2. Each adapter runs only when its own key is configured (``optional_keys``): without it the source
   reports NEEDS_KEY (never EMPTY), and a run with no key at all ends NEEDS_KEY. Keys are declared in the
   provider fragments (``V3LUM_KEY_<NAME>`` plus the ``V3LUM_<NAME>_KEY`` aliases) and travel in headers
   only (:func:`auth_headers`; DNSDumpster ``X-API-Key`` on api.dnsdumpster.com), never in a URL.
3. Key-terms per adapter: every source is ``key-terms`` with ``free_plan_business_use: null``, so under
   the corporate profile the licence gate runs an adapter only once legal records its plan
   (``key_plans.<key> = 'business'``); a source outside ``ctx.allowed_sources`` is never queried.
4. Chaos labels come back without the apex ('.{domain}' is appended, :func:`chaos_label_to_fqdn`);
   BufferOver records are comma-separated 'ip,...,hostname' (:func:`split_bufferover_record`);
   DNSDumpster keeps one request per 2 s (provider min_interval 2.0). Every name goes through the P001
   shared hostname sink (:class:`~v3lum.modules.domain_dns.ct_logs.HostnameSink`: validation,
   provenance per name, dedupe) and the P016 pipeline (wildcard probe, capped DoH resolution,
   confirmation, capped pivots) of :class:`~v3lum.modules.domain_dns.subdomains_passive.PassiveRun`.
5. Per-source cap of 5000 names (``Feed.add``), per-provider budget (quota blocks, one request per
   adapter, DNSDumpster Plus pages capped at 3). Runs once per registrable domain (a subdomain is not
   applicable); seeds go first through the core P334 seed reserve (``quota.SEED_RESERVE``).
6. 401/403 map to NEEDS_KEY 'invalid key', credit/quota exhaustion (402, quota words, 'Limit
   Exceeded') to QUOTA, throttling (429, rate words) to RATE_LIMITED, error bodies inside HTTP 200 the
   same way (:func:`classify_refusal`); never EMPTY.
7. Merge gate: trimmed real success fixtures captured with the team keys are still owed (only the
   DNSDumpster and FullHunt 401 bodies are real; they drive the NEEDS_KEY tests) - docs/backlog/p3-G01-1.md.

No code was copied from subfinder or chaos-client (MIT; read for response shapes only).
"""

from __future__ import annotations

import concurrent.futures
import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from v3lum.config import SettingSpec
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import (
    AuthRequired,
    Blocked,
    Cancelled,
    ConfigError,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    PolicyError,
    QuotaExceeded,
    RateLimited,
    RequestCapReached,
)
from v3lum.core.models import ModuleResult, Opsec, Status, valid_reason
from v3lum.core.module import Module, register
from v3lum.modules.domain_dns.ct_logs import HostnameSink, in_apex, looks_like_html
from v3lum.modules.domain_dns.subdomains_passive import (
    DEFAULT_BUDGET,
    DOH_NAME_CAP,
    PIVOT_CAP,
    Feed,
    PassiveRun,
    UnexpectedAnswer,
    budget_of,
    is_registrable_apex,
    resolve_cap_of,
)

__all__ = [
    "ADAPTERS",
    "MINOR_ADAPTERS",
    "Adapter",
    "KeyedFeed",
    "KeyedRun",
    "SubdomainsKeyed",
    "SubdomainsKeyedMinor",
    "auth_headers",
    "chaos_label_to_fqdn",
    "classify_refusal",
    "limit_kind",
    "sanitize_found_url",
    "split_bufferover_record",
]

SRC_CHAOS = "projectdiscovery.subdomains"
SRC_DNSDUMPSTER = "dnsdumpster.domain"
SRC_FULLHUNT = "fullhunt.subdomains"
SRC_BEVIGIL = "bevigil.subdomains"
SRC_BUFFEROVER = "bufferover.dns"
SRC_JSMON = "jsmon.domain"

CHAOS_URL = "https://dns.projectdiscovery.io/dns/{apex}/subdomains"
DNSDUMPSTER_URL = "https://api.dnsdumpster.com/domain/{apex}"
FULLHUNT_URL = "https://fullhunt.io/api/v1/domain/{apex}/subdomains"
BEVIGIL_SUBDOMAINS_URL = "https://osint.bevigil.com/api/{apex}/subdomains/"
BEVIGIL_URLS_URL = "https://osint.bevigil.com/api/{apex}/urls/"
BUFFEROVER_URL = "https://tls.bufferover.run/dns"
JSMON_URL = "https://subdomains.jsmon.sh/api/domain/{apex}"

CACHE_TTL = 86400
DNSDUMPSTER_PAGE_SIZE = 200  # Plus plan page; the free plan returns at most 50 records
DNSDUMPSTER_MAX_PAGES = 3
URL_CAP = 1000  # BeVigil URLs kept in the evidence/attribute
URL_PIVOT_CAP = 25
FACT_HOST_CAP = 500
_SHORT = 160

_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]+")
_QUOTA_STRONG = re.compile(r"quota|credits?\b|daily|monthly|per[ -]day|per[ -]month|/day\b|/month\b|plan limit", re.I)
_RATE_TEXT = re.compile(r"rate[ _-]?limit|too many requests|throttl|slow down", re.I)
_QUOTA_WEAK = re.compile(r"limit (?:exceeded|reached)", re.I)
_KEYISH_TEXT = re.compile(r"api[ _-]?key|unauthori[sz]ed|forbidden|credential|authenticat|invalid key|access token", re.I)
_SECRET_PARAM = re.compile(
    r"^(?:key|api[_-]?key|apikey|token|access[_-]?token|id[_-]?token|auth|authorization|sig|signature|secret|"
    r"client[_-]?secret|password|passwd|pwd|session|sessionid|sid|code|x-amz-signature|x-amz-credential)$",
    re.I,
)


def _short(value: Any, limit: int = _SHORT) -> str:
    text = _CTRL.sub(" ", str(value or "")).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ======================================================================================
# keys, refusals and error bodies (P007 cond 2, 6)
# ======================================================================================


def auth_headers(header: str, fmt: str, key: Any) -> dict[str, str]:
    """``{header: value}`` for a configured key, ``{}`` without a usable one (the adapter then reports
    NEEDS_KEY). The key only ever travels in this header, never in the URL (the cache stores URLs)."""
    if not isinstance(key, str) or not key.strip() or any(c in key for c in "\r\n\x00"):
        return {}
    return {header: fmt.replace("{key}", key.strip())}


def limit_kind(text: Any, status: int | None = None) -> str | None:
    """'quota' | 'rate_limited' | None for a refusal text (P007 cond 6): quota words (quota, credits,
    daily, monthly) beat rate words; a bare 'Limit Exceeded' (API gateways) is quota; a bare 429 is
    rate_limited."""
    text = str(text or "")
    if _QUOTA_STRONG.search(text):
        return "quota"
    if _RATE_TEXT.search(text):
        return "rate_limited"
    if _QUOTA_WEAK.search(text):
        return "quota"
    if status == 429:
        return "rate_limited"
    return None


def error_message(obj: Any) -> str:
    """Short printable message of an error body (error / message / detail / errors / Meta.Errors)."""
    parts: list[str] = []
    if isinstance(obj, Mapping):
        for k in ("error", "message", "detail", "msg", "reason", "errors"):
            v = obj.get(k)
            if isinstance(v, str) and v.strip():
                parts.append(v.strip())
            elif isinstance(v, Mapping) and isinstance(v.get("message"), str):
                parts.append(str(v["message"]).strip())
            elif isinstance(v, list):
                parts.extend(x.strip() for x in v if isinstance(x, str) and x.strip())
        meta = obj.get("Meta")
        if isinstance(meta, Mapping) and isinstance(meta.get("Errors"), list):
            parts.extend(e.strip() for e in meta["Errors"] if isinstance(e, str) and e.strip())
    elif isinstance(obj, str):
        parts.append(obj.strip())
    return _short(" | ".join(dict.fromkeys(p for p in parts if p)))


def _body_message(resp: Any) -> str:
    content = getattr(resp, "content", b"") or b""
    head = bytes(content[:8192]).decode("utf-8", "replace") if isinstance(content, (bytes, bytearray, memoryview)) else str(content)[:8192]
    try:
        return error_message(json.loads(head))
    except (ValueError, RecursionError):
        m = re.search(r"<title[^>]*>(.*?)</title>", head, re.I | re.S)
        if m:
            return _short(re.sub(r"\s+", " ", m.group(1)))
        return _short(head[:120]) if head.strip() and not looks_like_html(head) else ""


def classify_refusal(label: str, status: int, message: str, url: str = "") -> HttpError:
    """The core exception for a keyed refusal (P007 cond 6): QuotaExceeded for 402 and quota words,
    RateLimited for 429 and throttling words, AuthRequired ('invalid key') for 401/403."""
    detail = f"HTTP {status}" + (f": {message}" if message else "")
    kind = limit_kind(message, status)
    if status == 402 or kind == "quota":
        return QuotaExceeded(f"{label}: credits or quota exhausted ({detail}): could not verify", status, url)
    if kind == "rate_limited":
        return RateLimited(f"{label}: throttled ({detail}): could not verify", status, url)
    return AuthRequired(f"{label}: invalid key or a plan without access to this endpoint ({detail})", status, url)


def check_error_body(label: str, obj: Any, data_keys: Iterable[str]) -> None:
    """Error-in-200 (P007 cond 6, rule 5): an error object without the provider's data keys raises the
    matching core exception (quota, throttling, invalid key) or UnexpectedAnswer - never EMPTY."""
    if not isinstance(obj, Mapping):
        return
    meta = obj.get("Meta")
    errs = meta.get("Errors") if isinstance(meta, Mapping) else None
    if isinstance(errs, list) and any(isinstance(e, str) and e.strip() for e in errs):
        text = error_message({"errors": errs})
        kind = limit_kind(text)
        if kind:
            raise classify_refusal(label, 200, text)
        raise UnexpectedAnswer(f"{label}: Meta.Errors in an HTTP 200 ({text})")
    if any(k in obj for k in data_keys):
        return
    if obj.get("error") or obj.get("errors") or obj.get("success") is False or obj.get("message"):
        text = error_message(obj)
        if limit_kind(text) or _KEYISH_TEXT.search(text):
            raise classify_refusal(label, 200, text)
        raise UnexpectedAnswer(f"{label}: error body in an HTTP 200 ({text or 'no message'})")


def keyed_get(ctx: Any, feed: Feed, url: str, *, headers: Mapping[str, str], deadline: float, params: Mapping[str, str] | None = None) -> tuple[Any, Any]:
    """One keyed GET -> ``(parsed JSON, response)``. Redirects are never followed with a key (AR01);
    challenge and geo pages raise Blocked; 401/402/403/429 raise the P007 cond 6 exceptions; 5xx and
    other non-2xx HttpError; HTML, empty or malformed bodies UnexpectedAnswer (never EMPTY)."""
    resp = ctx.http.get(url, params=dict(params) if params else None, headers=dict(headers), source=feed.source, ttl=CACHE_TTL,
                        allow_redirects=False, deadline=deadline)
    status = int(getattr(resp, "status", 0) or 0)
    found = getattr(resp, "classification", None)
    if found is not None and getattr(found, "status", "") == "blocked":
        ctx.http.check(resp)  # Blocked (challenge, geo_block, login_wall): could not verify
    kind = getattr(found, "status", "") if found is not None else ""
    if kind == "quota":
        ctx.http.check(resp)  # QuotaExceeded
    if kind == "rate_limited":
        message = _body_message(resp)
        if limit_kind(message, 429) == "quota":  # a 429 whose text speaks of daily/monthly limits or credits
            raise QuotaExceeded(f"{feed.label}: quota exhausted (HTTP {status}: {message}): could not verify", status, url)
        ctx.http.check(resp)  # RateLimited
    if status in (401, 402, 403, 429):
        raise classify_refusal(feed.label, status, _body_message(resp), url)
    if 300 <= status < 400:
        raise UnexpectedAnswer(f"{feed.label}: unexpected redirect (HTTP {status}); keyed requests never follow redirects")
    ctx.http.check(resp)  # remaining classifications, 5xx and other non-2xx: HttpError (could not verify)
    if getattr(resp, "truncated", False):
        ctx.http.evict(resp)
        raise UnexpectedAnswer(f"{feed.label}: answer cut at the size cap: not parsed")
    text = bytes(resp.content or b"").decode("utf-8", "replace").lstrip("﻿").strip()
    if not text:
        ctx.http.evict(resp)
        raise UnexpectedAnswer(f"{feed.label}: empty body in an HTTP {status}")
    if looks_like_html(text):
        ctx.http.evict(resp)
        raise UnexpectedAnswer(f"{feed.label}: HTML page instead of JSON (HTTP {status}, error-in-200)")
    try:
        return json.loads(text), resp
    except (ValueError, RecursionError):
        ctx.http.evict(resp)
        raise UnexpectedAnswer(f"{feed.label}: malformed JSON (answer cut or corrupted)") from None


def _parse_or_evict(ctx: Any, resp: Any, fn: Callable[[], None]) -> None:
    """Run a parser; an unusable answer is evicted from the cache before the error propagates."""
    try:
        fn()
    except (UnexpectedAnswer, HttpError):
        ctx.http.evict(resp)
        raise


# ======================================================================================
# per-source outcome (KeyedFeed) and runner
# ======================================================================================


@dataclass
class KeyedFeed(Feed):
    """A keyed adapter's outcome: P016's Feed plus the needs_key state, provider facts and URLs."""

    urls: list[dict[str, Any]] = field(default_factory=list)
    out_of_apex_urls: int = 0
    rejected_urls: int = 0

    @property
    def failed(self) -> bool:
        return self.status in ("error", "timeout", "rate_limited", "quota", "blocked", "needs_key")


STATUS_FOR: dict[str, Status] = {
    "error": Status.ERROR,
    "timeout": Status.ERROR,
    "rate_limited": Status.RATE_LIMITED,
    "quota": Status.QUOTA,
    "blocked": Status.BLOCKED,
    "needs_key": Status.NEEDS_KEY,
}
FAILURE_ORDER = ("rate_limited", "quota", "needs_key", "blocked", "timeout", "error")


def _has_data(feed: Feed) -> bool:
    return feed.sink is not None and bool(feed.sink.names or feed.sink.wildcards or feed.sink.out_of_apex)


def run_keyed_feed(feed: KeyedFeed, fn: Callable[[KeyedFeed], None]) -> KeyedFeed:
    """Run one adapter and translate the core's exceptions into its outcome (P007 cond 6, rule 5). A
    failure after data was collected (a later DNSDumpster page, BeVigil URLs) keeps the data, flagged
    partial. Cancelled/RequestCapReached are kept in ``feed.stop`` (re-raised after merging);
    PolicyError/ConfigError propagate (SKIPPED by the engine)."""

    def keep(status: str, reason: str, code: str, partial_reason: str) -> None:
        feed.reason, feed.reason_code = reason, code
        if _has_data(feed):
            feed.status = "ok"
            feed.flag(partial_reason)
        else:
            feed.status = status

    try:
        fn(feed)
    except Cancelled as exc:
        feed.stop = exc
        keep("error", f"{feed.label}: stopped (kill switch or scan deadline)", "error", "cancelled")
    except RequestCapReached as exc:
        keep("error", f"{feed.label}: request cap reached ({_short(exc)})", "error", "request_cap")
    except RateLimited as exc:
        keep("rate_limited", f"{feed.label}: rate limited ({_short(exc)}): could not verify", "rate_limited", "rate_limited")
    except QuotaExceeded as exc:
        keep("quota", f"{feed.label}: quota exhausted ({_short(exc)}): could not verify", "quota", "quota")
    except AuthRequired as exc:
        keep("needs_key", f"{feed.label}: invalid key ({_short(exc)})", "needs_key", "needs_key")
    except Blocked as exc:
        code = str(getattr(exc, "reason_code", "") or "challenge")
        if code not in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host"):
            code = "challenge"
        keep("blocked", f"{feed.label}: blocked ({_short(exc)}): could not verify", code, "blocked")
    except DeadlineExceeded as exc:
        keep("timeout", f"{feed.label}: no answer within the budget ({_short(exc)}): could not verify", "timeout", "deadline")
    except (PolicyError, ConfigError):
        raise
    except NetworkError as exc:
        timed_out = "timeout" in str(getattr(exc, "kind", "") or "").lower() or "timed out" in str(exc).lower()
        keep("timeout" if timed_out else "error", f"{feed.label}: {_short(exc)}: could not verify", "timeout" if timed_out else "error", "page_failed")
    except HttpError as exc:
        code = str(getattr(exc, "reason_code", "") or "error")
        keep("timeout" if code == "timeout" else "error", f"{feed.label}: {_short(exc)}: could not verify",
             code if code in ("timeout", "error") else "error", "page_failed")
    except UnexpectedAnswer as exc:
        keep("error", f"{_short(exc)}: could not verify", "error", "page_failed")
    except Exception as exc:  # noqa: BLE001 - untrusted data: a parser surprise is 'could not verify', never a crash
        keep("error", f"{feed.label}: unexpected answer ({type(exc).__name__}): could not verify", "error", "page_failed")
    if feed.status == "not_run":
        feed.status = "ok" if (feed.sink is not None and (feed.sink.names or feed.sink.wildcards or feed.urls)) else "empty"
    return feed


def record_keyed_status(res: ModuleResult, feed: KeyedFeed) -> None:
    """Per-source outcome in ``res.source_statuses`` (P007 cond 1, 2, 6): NEEDS_KEY for a missing or
    invalid key, QUOTA / RATE_LIMITED / BLOCKED / ERROR for refusals - never zero names."""
    if feed.status == "not_run":
        return
    if feed.status == "skipped":
        code = feed.reason_code if valid_reason(Status.SKIPPED, feed.reason_code) else "config"
        res.source_status(feed.source, Status.SKIPPED, reason_code=code, reason=feed.reason)
        return
    if feed.answered:
        note = feed.reason or ""
        if feed.partial_reasons:
            note = (note + "; " if note else "") + "partial: " + ", ".join(feed.partial_reasons)
        res.source_status(feed.source, Status.OK if feed.status == "ok" else Status.EMPTY, reason=note)
        return
    status = STATUS_FOR.get(feed.status, Status.ERROR)
    code = feed.reason_code if valid_reason(status, feed.reason_code) else ""
    res.source_status(feed.source, status, reason_code=code, reason=feed.reason)


# ======================================================================================
# parsers (pure: feed + decoded JSON; untrusted data, never raise anything but UnexpectedAnswer
# and the cond 6 exceptions)
# ======================================================================================


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _answered_other_domain(obj: Any, apex: str) -> bool:
    answered = obj.get("domain") if isinstance(obj, Mapping) else None
    return isinstance(answered, str) and bool(answered.strip()) and answered.strip().lower().rstrip(".") != apex


def _require_usable(feed: Feed) -> None:
    """Every record unusable (junk, other domains' names only being fine) -> could not verify."""
    if feed.raw_count and not _has_data(feed) and not getattr(feed, "urls", None):
        raise UnexpectedAnswer(f"{feed.label}: all {feed.raw_count} returned record(s) were unusable")


def chaos_label_to_fqdn(label: Any, apex: str) -> str | None:
    """P007 cond 4: Chaos labels come back without the apex -> 'label.apex'; '*' -> '*.apex' (a wildcard
    record of the parent); an already-suffixed name is kept; empty labels give None."""
    if not isinstance(label, str) or not apex:
        return None
    lab = _CTRL.sub("", label).strip().lower().rstrip(".")
    if not lab:
        return None
    if lab == "*":
        return "*." + apex
    if lab == apex or lab.endswith("." + apex):
        return lab
    return lab + "." + apex


def parse_chaos(feed: Feed, obj: Any, apex: str) -> None:
    """Chaos ``{domain, subdomains[labels], count}`` -> names (cond 4); count above the labels -> partial."""
    check_error_body(feed.label, obj, ("subdomains",))
    if not isinstance(obj, Mapping) or not isinstance(obj.get("subdomains"), list):
        raise UnexpectedAnswer(f"{feed.label}: answer without a 'subdomains' list")
    if _answered_other_domain(obj, apex):
        raise UnexpectedAnswer(f"{feed.label}: answer for another domain ({_short(obj.get('domain'), 80)})")
    labels = obj["subdomains"]
    for label in labels:
        fqdn = chaos_label_to_fqdn(label, apex)
        if fqdn is None:
            feed.raw_count += 1
            if feed.sink is not None:
                feed.sink.rejected["empty"] += 1
            continue
        feed.add(fqdn)
    count = _int(obj.get("count"))
    if count is not None:
        feed.meta["reported_total"] = count
        if count > len(labels):
            feed.flag("provider_truncated")
    _require_usable(feed)


def _dd_ip(row: Any) -> dict[str, Any] | None:
    if not isinstance(row, Mapping):
        return None
    ip = row.get("ip")
    ent = Entity.try_make(T.IPV6 if isinstance(ip, str) and ":" in ip else T.IPV4, ip) if isinstance(ip, str) else None
    if ent is None:
        return None
    out: dict[str, Any] = {"ip": str(ent.value)}
    for k in ("asn", "asn_name", "asn_range", "country", "country_code", "ptr"):
        v = row.get(k)
        if isinstance(v, (str, int)) and not isinstance(v, bool) and str(v).strip():
            out[k] = _short(v, 120)
    return out


DNSDUMPSTER_SECTIONS = ("a", "mx", "ns", "cname")


def parse_dnsdumpster(feed: Feed, obj: Any, apex: str) -> int:
    """DNSDumpster ``{a[], mx[], ns[], cname[] of {host, ips[]}, txt[], total_a_recs}`` -> names; IP/ASN
    facts of in-apex hosts are evidence only (``ipv4`` is not produced); banners are never kept.
    Returns the A records on this page (plan truncation when total_a_recs is higher)."""
    check_error_body(feed.label, obj, DNSDUMPSTER_SECTIONS)
    if not isinstance(obj, Mapping) or not any(isinstance(obj.get(k), list) for k in DNSDUMPSTER_SECTIONS):
        raise UnexpectedAnswer(f"{feed.label}: answer without a/mx/ns/cname lists")
    facts = feed.meta.setdefault("host_ips", {})
    for section in DNSDUMPSTER_SECTIONS:
        entries = obj.get(section)
        for entry in entries if isinstance(entries, list) else ():
            if not isinstance(entry, Mapping):
                feed.raw_count += 1
                continue
            label = feed.add(entry.get("host"))
            if not label or label.startswith("*.") or not in_apex(label, apex):
                continue
            ips = entry.get("ips")
            rows = [r for r in (_dd_ip(x) for x in (ips if isinstance(ips, list) else [])) if r]
            if rows and (label in facts or len(facts) < FACT_HOST_CAP):
                bucket = facts.setdefault(label, [])
                for r in rows[:8]:
                    if r not in bucket:
                        bucket.append(r)
    returned = len(obj.get("a")) if isinstance(obj.get("a"), list) else 0
    total = _int(obj.get("total_a_recs"))
    if total is not None:
        feed.meta["reported_total"] = total
    return returned


def dnsdumpster_next_page(returned: int, total: int | None, page: int, max_pages: int = DNSDUMPSTER_MAX_PAGES) -> int | None:
    """Next ``?page=`` (Plus plan only): only after a full page of 200 A records with more reported."""
    if total is None or returned < DNSDUMPSTER_PAGE_SIZE or total <= DNSDUMPSTER_PAGE_SIZE * page or page >= max_pages:
        return None
    return page + 1


def parse_fullhunt(feed: Feed, obj: Any, apex: str) -> None:
    """FullHunt ``{domain, hosts[], metadata{all_results_count, available_results_for_user}, status}``;
    a body status other than 200 is mapped like the HTTP status (cond 6); fewer hosts than
    all_results_count (community accounts) -> partial."""
    if isinstance(obj, Mapping):
        st = _int(obj.get("status"))
        if st is not None and st >= 300:
            text = error_message(obj)
            if st in (401, 402, 403, 429) or limit_kind(text):
                raise classify_refusal(feed.label, st, text)
            raise UnexpectedAnswer(f"{feed.label}: status {st} inside an HTTP 200 ({text or 'no message'})")
    check_error_body(feed.label, obj, ("hosts",))
    if not isinstance(obj, Mapping) or not isinstance(obj.get("hosts"), list):
        raise UnexpectedAnswer(f"{feed.label}: answer without a 'hosts' list")
    if _answered_other_domain(obj, apex):
        raise UnexpectedAnswer(f"{feed.label}: answer for another domain ({_short(obj.get('domain'), 80)})")
    hosts = obj["hosts"]
    for host in hosts:
        feed.add(host)
    meta = obj.get("metadata") if isinstance(obj.get("metadata"), Mapping) else {}
    total, available = _int(meta.get("all_results_count")), _int(meta.get("available_results_for_user"))
    if total is not None:
        feed.meta["reported_total"] = total
    if (total is not None and total > len(hosts)) or (total is not None and available is not None and available < total):
        feed.flag("provider_plan")
    _require_usable(feed)


def parse_bevigil_subdomains(feed: Feed, obj: Any, apex: str) -> None:
    """BeVigil ``{domain, subdomains[] full names}`` from Android app assets."""
    check_error_body(feed.label, obj, ("subdomains",))
    if not isinstance(obj, Mapping) or not isinstance(obj.get("subdomains"), list):
        raise UnexpectedAnswer(f"{feed.label}: answer without a 'subdomains' list")
    if _answered_other_domain(obj, apex):
        raise UnexpectedAnswer(f"{feed.label}: answer for another domain ({_short(obj.get('domain'), 80)})")
    for host in obj["subdomains"]:
        feed.add(host)
    _require_usable(feed)


def sanitize_found_url(raw: Any) -> dict[str, Any] | None:
    """An untrusted URL from provider data -> ``{url, host, redacted_params}`` or None: http/https only,
    a DNS host name, user-info and fragment dropped, values of key-like query parameters replaced by
    'REDACTED' (secrets never travel as pivots, A8)."""
    if not isinstance(raw, str):
        return None
    s = _CTRL.sub("", raw).strip()
    if not s or len(s) > 2048 or any(c.isspace() for c in s):
        return None
    try:
        parts = urlsplit(s)
        port = parts.port
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not host:
        return None
    ent = Entity.try_make(T.DOMAIN, host)
    if ent is None:
        return None
    host = str(ent.value)
    redacted = 0
    query: list[tuple[str, str]] = []
    for k, v in parse_qsl(parts.query, keep_blank_values=True):
        if _SECRET_PARAM.match(k):
            query.append((k, "REDACTED"))
            redacted += 1
        else:
            query.append((k, v))
    netloc = host + (f":{port}" if port else "")
    url = urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", urlencode(query, safe="/:,"), ""))
    return {"url": url, "host": host, "redacted_params": redacted}


def parse_bevigil_urls(feed: KeyedFeed, obj: Any, apex: str) -> None:
    """BeVigil ``{domain, urls[]}`` -> in-apex URLs (sanitized, capped) and their host names; out-of-apex
    URLs are only counted."""
    check_error_body(feed.label, obj, ("urls",))
    if not isinstance(obj, Mapping) or not isinstance(obj.get("urls"), list):
        raise UnexpectedAnswer(f"{feed.label}: answer without a 'urls' list")
    if _answered_other_domain(obj, apex):
        raise UnexpectedAnswer(f"{feed.label}: answer for another domain ({_short(obj.get('domain'), 80)})")
    seen = {u["url"] for u in feed.urls}
    for raw in obj["urls"]:
        clean = sanitize_found_url(raw)
        if clean is None:
            feed.rejected_urls += 1
            continue
        if not in_apex(clean["host"], apex):
            feed.out_of_apex_urls += 1
            continue
        feed.add(clean["host"])
        if clean["url"] in seen:
            continue
        if len(feed.urls) >= URL_CAP:
            feed.flag("url_cap")
            continue
        seen.add(clean["url"])
        feed.urls.append({"url": clean["url"], "redacted_params": clean["redacted_params"], "source": feed.source})


_IP_TOKEN = re.compile(r"^[0-9a-fA-F:.]+$")


def split_bufferover_record(record: Any) -> tuple[list[str], list[str]]:
    """P007 cond 4: one BufferOver 'ip,...,hostname' record -> (ips, host names). Tokens are classified
    one by one (column order does not matter); hashes, organisation strings and junk are ignored."""
    if not isinstance(record, str):
        return [], []
    ips: list[str] = []
    hosts: list[str] = []
    for token in (t.strip() for t in record.split(",")):
        if not token:
            continue
        if _IP_TOKEN.match(token):
            ent = Entity.try_make(T.IPV6 if ":" in token else T.IPV4, token)
            if ent is not None:
                ips.append(str(ent.value))
                continue
        if "." in token and not any(c.isspace() for c in token):
            hosts.append(token)
    return ips, hosts


def parse_bufferover(feed: Feed, obj: Any, apex: str) -> None:
    """BufferOver ``{Meta{Errors[]}, Results[] | FDNS_A[] + RDNS[]}`` -> names; IPs are evidence only."""
    check_error_body(feed.label, obj, ("Results", "FDNS_A", "RDNS"))
    if not isinstance(obj, Mapping):
        raise UnexpectedAnswer(f"{feed.label}: answer is not a JSON object")
    fdns, rdns, results = obj.get("FDNS_A"), obj.get("RDNS"), obj.get("Results")
    if isinstance(fdns, list) and fdns:
        records = list(fdns) + (list(rdns) if isinstance(rdns, list) else [])
    elif isinstance(results, list):
        records = results
    elif any(isinstance(obj.get(k), list) for k in ("Results", "FDNS_A", "RDNS")):
        records = []
    else:
        raise UnexpectedAnswer(f"{feed.label}: answer without Results/FDNS_A lists")
    facts = feed.meta.setdefault("host_ips", {})
    skipped = 0
    for record in records:
        ips, hosts = split_bufferover_record(record)
        if not hosts:
            skipped += 1
            feed.raw_count += 1
            continue
        for host in hosts:
            label = feed.add(host)
            if label and not label.startswith("*.") and in_apex(label, apex) and ips and (label in facts or len(facts) < FACT_HOST_CAP):
                bucket = facts.setdefault(label, [])
                for ip in ips:
                    if {"ip": ip} not in bucket and len(bucket) < 8:
                        bucket.append({"ip": ip})
    if skipped:
        feed.meta["records_skipped"] = skipped
    _require_usable(feed)


def parse_jsmon(feed: Feed, obj: Any, apex: str) -> None:
    """jsmon ``{domain, total, subdomains[]}`` (items may be {subdomain|host|name}); total above the names
    returned (Free: 100 results) -> partial."""
    check_error_body(feed.label, obj, ("subdomains", "results", "data"))
    subs = next((obj[k] for k in ("subdomains", "results", "data") if isinstance(obj.get(k), list)), None) if isinstance(obj, Mapping) else None
    if subs is None:
        raise UnexpectedAnswer(f"{feed.label}: answer without a 'subdomains' list")
    if _answered_other_domain(obj, apex):
        raise UnexpectedAnswer(f"{feed.label}: answer for another domain ({_short(obj.get('domain'), 80)})")
    for item in subs:
        if isinstance(item, Mapping):
            item = next((item[k] for k in ("subdomain", "host", "name") if isinstance(item.get(k), str)), None)
        feed.add(item)
    total = _int(obj.get("total"))
    if total is not None:
        feed.meta["reported_total"] = total
        if total > len(subs):
            feed.flag("provider_plan")
    _require_usable(feed)


# ======================================================================================
# fetchers (one per adapter): (feed, ctx, apex, deadline, key)
# ======================================================================================


def fetch_chaos(feed: KeyedFeed, ctx: Any, apex: str, deadline: float, key: str) -> None:
    feed.sink = HostnameSink(apex)
    obj, resp = keyed_get(ctx, feed, CHAOS_URL.format(apex=apex), headers=auth_headers("Authorization", "{key}", key), deadline=deadline)
    feed.pages += 1
    _parse_or_evict(ctx, resp, lambda: parse_chaos(feed, obj, apex))


def fetch_dnsdumpster(feed: KeyedFeed, ctx: Any, apex: str, deadline: float, key: str) -> None:
    feed.sink = HostnameSink(apex)
    headers = auth_headers("X-API-Key", "{key}", key)
    page, seen_a = 1, 0
    while True:
        params = {"page": str(page)} if page > 1 else None
        obj, resp = keyed_get(ctx, feed, DNSDUMPSTER_URL.format(apex=apex), headers=headers, deadline=deadline, params=params)
        feed.pages += 1
        returned: list[int] = []
        _parse_or_evict(ctx, resp, lambda o=obj, out=returned: out.append(parse_dnsdumpster(feed, o, apex)))
        seen_a += returned[0] if returned else 0
        total = feed.meta.get("reported_total")
        total = total if isinstance(total, int) and not isinstance(total, bool) else None
        nxt = dnsdumpster_next_page(returned[0] if returned else 0, total, page)
        if nxt is None:
            if total is not None and total > seen_a:
                feed.flag("provider_plan")  # Free plan: 50 records; Plus: the 3-page cap was reached
            break
        page = nxt
    _require_usable(feed)


def fetch_fullhunt(feed: KeyedFeed, ctx: Any, apex: str, deadline: float, key: str) -> None:
    feed.sink = HostnameSink(apex)
    obj, resp = keyed_get(ctx, feed, FULLHUNT_URL.format(apex=apex), headers=auth_headers("X-API-KEY", "{key}", key), deadline=deadline)
    feed.pages += 1
    _parse_or_evict(ctx, resp, lambda: parse_fullhunt(feed, obj, apex))


def fetch_bevigil(feed: KeyedFeed, ctx: Any, apex: str, deadline: float, key: str, *, urls: bool = True) -> None:
    feed.sink = HostnameSink(apex)
    headers = auth_headers("X-Access-Token", "{key}", key)
    obj, resp = keyed_get(ctx, feed, BEVIGIL_SUBDOMAINS_URL.format(apex=apex), headers=headers, deadline=deadline)
    feed.pages += 1
    _parse_or_evict(ctx, resp, lambda: parse_bevigil_subdomains(feed, obj, apex))
    if urls:
        obj2, resp2 = keyed_get(ctx, feed, BEVIGIL_URLS_URL.format(apex=apex), headers=headers, deadline=deadline)
        feed.pages += 1
        _parse_or_evict(ctx, resp2, lambda: parse_bevigil_urls(feed, obj2, apex))


def fetch_bufferover(feed: KeyedFeed, ctx: Any, apex: str, deadline: float, key: str) -> None:
    feed.sink = HostnameSink(apex)
    obj, resp = keyed_get(ctx, feed, BUFFEROVER_URL, headers=auth_headers("x-api-key", "{key}", key), deadline=deadline,
                          params={"q": "." + apex})  # leading dot: names under the apex
    feed.pages += 1
    _parse_or_evict(ctx, resp, lambda: parse_bufferover(feed, obj, apex))


def fetch_jsmon(feed: KeyedFeed, ctx: Any, apex: str, deadline: float, key: str) -> None:
    feed.sink = HostnameSink(apex)
    obj, resp = keyed_get(ctx, feed, JSMON_URL.format(apex=apex), headers=auth_headers("Api-Key", "{key}", key), deadline=deadline)
    feed.pages += 1
    _parse_or_evict(ctx, resp, lambda: parse_jsmon(feed, obj, apex))


@dataclass(frozen=True)
class Adapter:
    """One keyed provider (P007 cond 1): registry source, label, key name and fetcher."""

    source: str
    label: str
    key: str
    fetch: Callable[..., None]
    noisy: bool = False  # unknown tier: single-source names stay unconfirmed until they resolve (P016 cond 7)


ADAPTERS: tuple[Adapter, ...] = (
    Adapter(SRC_CHAOS, "Chaos", "chaos", fetch_chaos),
    Adapter(SRC_DNSDUMPSTER, "DNSDumpster", "dnsdumpster", fetch_dnsdumpster),
    Adapter(SRC_FULLHUNT, "FullHunt", "fullhunt", fetch_fullhunt),
    Adapter(SRC_BEVIGIL, "BeVigil", "bevigil", fetch_bevigil),
)
MINOR_ADAPTERS: tuple[Adapter, ...] = (
    Adapter(SRC_BUFFEROVER, "BufferOver", "bufferover", fetch_bufferover, noisy=True),
    Adapter(SRC_JSMON, "jsmon", "jsmon", fetch_jsmon, noisy=True),
)


# ======================================================================================
# the keyed run: P016's pipeline with NEEDS_KEY, provider facts and BeVigil URLs
# ======================================================================================


class KeyedRun(PassiveRun):
    """:class:`PassiveRun` for keyed adapters: per-source NEEDS_KEY, the cond 6 status mapping, provider
    facts (IPs/ASNs, evidence only) and in-apex URL pivots (expand=False)."""

    summary_title = "Subdomains from keyed sources"

    def add_keyed(self, feed: KeyedFeed, fn: Callable[[KeyedFeed, Any, str, float], None]) -> None:
        self.feeds.append((feed, lambda f, fn=fn: fn(f, self.ctx, self.apex, self.adapter_deadline)))

    def execute(self) -> ModuleResult:
        res = self.res
        if not self.feeds:
            for feed in self.skipped:
                record_keyed_status(res, feed)
            waiting = [f for f in self.skipped if f.status == "needs_key"]
            if waiting:
                names = ", ".join(f.label for f in waiting)
                return res.mark("needs_key", f"no key configured for {names}: each adapter runs only with its own key "
                                             "(company/team account; v3lum keys set <name>)", reason_code="needs_key")
            why = "; ".join(f.reason for f in self.skipped + self.unrecorded if f.reason) or "no source"
            code = "licence" if self.unrecorded and not self.skipped else "config"
            return res.mark("skipped", f"no keyed subdomain source is allowed or enabled for this run ({why})", reason_code=code)
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.feeds), thread_name_prefix=self.prefix) as pool:
            futures = [pool.submit(run_keyed_feed, feed, fn) for feed, fn in self.feeds]
            for fut in futures:
                fut.result()  # workers never raise, except PolicyError/ConfigError (engine: SKIPPED)
        feeds = [f for f, _fn in self.feeds]
        self.stop = next((f.stop for f in feeds if f.stop is not None), None)
        for feed in feeds + self.skipped:
            record_keyed_status(res, feed)
        answered = [f for f in feeds if f.answered]
        if not answered:
            self._mark_no_answer(feeds)
            self._raw(feeds, HostnameSink(self.apex))
            return self._finish()
        sink = HostnameSink(self.apex)
        for feed in answered:
            if feed.sink is not None:
                sink.merge(feed.sink)
        names = sink.subdomains()
        if names and self.stop is None:
            self._resolve(names)
        self._output(feeds, sink, names)
        self._urls(answered)
        return self._finish()

    def _mark_no_answer(self, feeds: list[Feed]) -> None:
        """Rule 5: no adapter answered - could not verify (or NEEDS_KEY), never 'no subdomains'."""
        failures = [f for f in feeds if f.failed]
        reasons = "; ".join(f.reason for f in failures if f.reason) or "no keyed subdomain source answered"
        for wanted in FAILURE_ORDER:
            hit = next((f for f in failures if f.status == wanted), None)
            if hit is not None:
                status = STATUS_FOR[wanted]
                code = hit.reason_code if valid_reason(status, hit.reason_code) else ""
                self.res.mark(status, f"could not verify: {reasons}", reason_code=code)
                return
        self.res.mark("error", f"could not verify: {reasons}", reason_code="error")

    def _urls(self, answered: list[Feed]) -> None:
        """BeVigil URLs (cond 'produces url'): attribute + in-apex URL pivots, expand=False (fetching them
        would be LIGHT), key-like query values already redacted."""
        rows: list[dict[str, Any]] = []
        for feed in answered:
            rows.extend(getattr(feed, "urls", []) or [])
        if not rows:
            return
        rows = sorted(rows, key=lambda r: (r["url"].count("/"), r["url"]))
        self.res.attr("mobile_app_urls", rows[:URL_CAP])
        for row in rows[:URL_PIVOT_CAP]:
            self.res.pivot(T.URL, row["url"], "hosts_url", confidence="possible", expand=False,
                           note="URL referenced by a mobile app (APK assets, BeVigil): listed for the analyst, never fetched")

    def _summary_finding(self, answered: list[Feed], coverage: Mapping[str, Any], assets: list[str], historical: list[str],
                         unconfirmed: list[str], dropped: list[str]) -> None:
        live = sum(1 for n in assets if self._state(n) == "live")
        desc = (
            f"{len(assets)} subdomain name(s) from keyed sources ({coverage['line']}): {live} resolve, "
            f"{len(historical)} historical (NXDOMAIN), {coverage['not_resolved']} not resolved (DoH cap or budget), "
            f"{len(unconfirmed)} unconfirmed single-source name(s) listed apart, {len(dropped)} wildcard-only name(s) dropped. "
            "A name seen by a provider is not proof that it belongs to the organisation today."
        )
        self.res.finding(
            self.summary_title,
            "info",
            desc,
            confidence="probable",
            data={k: coverage[k] for k in ("line", "names", "assets", "unconfirmed", "resolved", "not_resolved", "wildcard_only_dropped")},
            tags=["info"],
            source=answered[0].source if answered else "",
        )

    def _raw(self, feeds: list[Feed], sink: HostnameSink) -> None:
        super()._raw(feeds, sink)
        raw = self.res.raw if isinstance(self.res.raw, dict) else {}
        raw["provider_facts"] = {
            f.source: {"host_ips": dict(list((f.meta.get("host_ips") or {}).items())[:FACT_HOST_CAP])}
            for f in feeds if f.meta.get("host_ips")
        }
        raw["urls"] = {
            f.source: {"kept": len(getattr(f, "urls", []) or []), "out_of_apex": getattr(f, "out_of_apex_urls", 0),
                       "rejected": getattr(f, "rejected_urls", 0)}
            for f in feeds if isinstance(f, KeyedFeed) and (f.urls or f.out_of_apex_urls or f.rejected_urls)
        }
        for f in feeds:
            src = raw.get("sources", {}).get(f.source)
            if isinstance(src, dict) and isinstance(src.get("meta"), dict):
                src["meta"] = {k: v for k, v in src["meta"].items() if k != "host_ips"}
        self.res.raw = raw


def plan_run(module: Module, res: ModuleResult, ctx: Any, apex: str, adapters: Iterable[Adapter], *, budget_setting: str,
             resolve_setting: str, prefix: str, options: Mapping[str, Any] | None = None) -> KeyedRun:
    """Build the run: an adapter outside ``ctx.allowed_sources`` is left to the engine (licence, cond 3);
    one without its own key reports NEEDS_KEY (cond 2); the others are queued."""
    run = KeyedRun(module, res, ctx, apex, budget=budget_of(ctx, budget_setting), resolve_cap=resolve_cap_of(ctx, resolve_setting),
                   setting_prefix=prefix)
    allowed = ctx.allowed_sources
    opts = dict(options or {})
    for adapter in adapters:
        feed = KeyedFeed(adapter.source, adapter.label, noisy=adapter.noisy)
        if adapter.source not in allowed:
            run.skip_feed(feed, f"{adapter.label} is not allowed for this run (licence profile or policy)", "licence", record=False)
            continue
        key = ctx.key(adapter.key)
        if not auth_headers("X", "{key}", key):
            feed.status, feed.reason, feed.reason_code = (
                "needs_key", f"{adapter.label}: no '{adapter.key}' key configured (V3LUM_KEY_{adapter.key.upper()} or "
                             f"V3LUM_{adapter.key.upper()}_KEY; company/team account, key-terms)", "needs_key")
            run.skipped.append(feed)
            continue
        extra = opts.get(adapter.key) or {}
        run.add_keyed(feed, lambda f, c, a, d, fn=adapter.fetch, k=key, kw=extra: fn(f, c, a, d, k, **kw))
    return run


# ======================================================================================
# modules
# ======================================================================================

_NOTICE_TERMS = (
    "Each adapter runs only with its own key (a company/team account on a plan whose terms permit internal business use, "
    "never an analyst's personal free account) and, under the corporate profile, only once legal records the plan "
    "(key_plans.<key>='business'). Keys travel in headers only. "
)


@register
class SubdomainsKeyed(Module):
    name = "subdomains_keyed"
    title = "Keyed subdomain sources (Chaos, DNSDumpster, FullHunt, BeVigil)"
    description = (
        "Subdomains of a registrable domain from keyed providers (ProjectDiscovery Chaos, DNSDumpster, FullHunt, BeVigil), "
        "each with its own key, budget and status, merged through the shared hostname sink, wildcard-checked and resolved "
        "through DoH (capped); BeVigil also lists in-apex URLs found in mobile apps."
    )
    category = "domain_dns"
    accepts = {T.DOMAIN}
    produces = {T.DOMAIN, T.URL}
    tags = {"free"}
    reference = "https://docs.projectdiscovery.io/tools/chaos"
    terms = "key-terms"  # every adapter is key-terms (P007 cond 3)
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # each provider receives the registrable domain; DoH resolvers receive discovered names
    provider = "projectdiscovery"
    sources = (SRC_CHAOS, SRC_DNSDUMPSTER, SRC_FULLHUNT, SRC_BEVIGIL)
    hosts = ("dns.projectdiscovery.io", "api.dnsdumpster.com", "fullhunt.io", "osint.bevigil.com")
    access_model = "free_auth_limited"
    optional_keys = ("chaos", "dnsdumpster", "fullhunt", "bevigil")
    max_requests = 1 + DNSDUMPSTER_MAX_PAGES + 1 + 2  # Chaos, DNSDumpster (Plus pages), FullHunt, BeVigil subdomains + urls
    expected_latency = 4.0
    timeout = DEFAULT_BUDGET + 8.0
    min_interval = 1.0  # DNSDumpster: 2 s through its provider profile (P007 cond 4)
    cache_ttl = CACHE_TTL
    max_pivots = PIVOT_CAP + URL_PIVOT_CAP
    default_enabled = True  # key-required sources may be default (A3 BR5); NEEDS_KEY without keys
    notice = _NOTICE_TERMS + (
        "Discovered names are resolved through the core DoH resolvers (the resolver operators see them) and only resolving, "
        "non-CDN names pivot; BeVigil URLs are listed, never fetched."
    )
    settings = {
        "subdomains_keyed_budget": SettingSpec(int(DEFAULT_BUDGET), "subdomains_keyed: seconds for the keyed adapters and the DoH resolution (30)"),
        "subdomains_keyed_resolve": SettingSpec(DOH_NAME_CAP, "subdomains_keyed: names resolved through DoH per run (at most 300)"),
        "subdomains_keyed_bevigil_urls": SettingSpec(True, "subdomains_keyed: also ask BeVigil for in-apex URLs from mobile apps (one more monthly credit per domain)"),
    }

    def applies(self, entity: Entity, ctx: Any) -> bool:
        """Once per registrable domain (P007 cond 5): a subdomain is covered by its apex run."""
        return is_registrable_apex(str(entity.value))

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        apex = str(entity.value).strip().lower().rstrip(".")
        urls = bool(ctx.setting("subdomains_keyed_bevigil_urls", True))
        run = plan_run(self, res, ctx, apex, ADAPTERS, budget_setting="subdomains_keyed_budget", resolve_setting="subdomains_keyed_resolve",
                       prefix="subdomains_keyed", options={"bevigil": {"urls": urls}})
        return run.execute()


@register
class SubdomainsKeyedMinor(Module):
    name = "subdomains_keyed_minor"
    title = "Keyed subdomain sources, unknown tier (BufferOver, jsmon)"
    description = (
        "Opt-in keyed subdomain providers of unknown tier (BufferOver TLS records, jsmon), each with its own key, budget and "
        "status, merged through the shared hostname sink; single-source names stay unconfirmed until they resolve."
    )
    category = "domain_dns"
    accepts = {T.DOMAIN}
    produces = {T.DOMAIN}
    tags = {"free"}
    reference = "https://tls.bufferover.run/"
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "bufferover"
    sources = (SRC_BUFFEROVER, SRC_JSMON)
    hosts = ("tls.bufferover.run", "subdomains.jsmon.sh")
    access_model = "free_auth_limited"
    optional_keys = ("bufferover", "jsmon")
    max_requests = 2
    expected_latency = 3.0
    timeout = DEFAULT_BUDGET + 8.0
    min_interval = 1.0
    cache_ttl = CACHE_TTL
    max_pivots = PIVOT_CAP
    default_enabled = False  # unknown tier (P007 cond 1, A3 BR2, A8 BR12)
    notice = _NOTICE_TERMS + (
        "Unknown-tier providers: opt-in, excluded at TLP:AMBER and above, --allow-unknown at CLEAR/GREEN; names seen only here "
        "stay unconfirmed until they resolve."
    )
    settings = {
        "subdomains_keyed_minor_budget": SettingSpec(int(DEFAULT_BUDGET), "subdomains_keyed_minor: seconds for the adapters and the DoH resolution (30)"),
        "subdomains_keyed_minor_resolve": SettingSpec(DOH_NAME_CAP, "subdomains_keyed_minor: names resolved through DoH per run (at most 300)"),
    }

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return is_registrable_apex(str(entity.value))

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        apex = str(entity.value).strip().lower().rstrip(".")
        run = plan_run(self, res, ctx, apex, MINOR_ADAPTERS, budget_setting="subdomains_keyed_minor_budget",
                       resolve_setting="subdomains_keyed_minor_resolve", prefix="subdomains_keyed_minor")
        run.summary_title = "Subdomains from keyed sources (unknown tier)"
        return run.execute()
